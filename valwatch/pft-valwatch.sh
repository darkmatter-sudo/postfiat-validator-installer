#!/usr/bin/env bash
# pft-valwatch: per-UNL-validator validation participation, validation delay and quorum margin for a Post Fiat node
# (read-only). Other add-ons watch the node's own state (statewatch, slo, divergence) and the validator LIST
# (vlwatch); none of them sees a trusted validator that goes silent or late, or the margin above quorum shrinking,
# until the node itself loses sync. This records the node's `validations` + `ledger` streams and grades them.
#
# Usage: sudo pft-valwatch run --container NAME          long-running collector (pft-valwatch@NAME.service)
#        sudo pft-valwatch endpoint --container NAME     print the resolved wss endpoint + UNL cache path, exit
#        sudo pft-valwatch textfile --container NAME [--stdout]   build DIR/pft_valwatch_NAME.prom (timer, 1 min)
#        sudo pft-valwatch report --container NAME [--from EPOCH] [--to EPOCH] [--json|--detail]
#        pft-valwatch compare A.json B.json [--json] [--tolerance-part F] [--tolerance-delay-ms N] [--tolerance-margin N]
#        sudo pft-valwatch pull --container NAME         (validator: copy the sentry's textfile)
#        pft-valwatch validate FILE NAME                 exit 0 if FILE is an acceptable textfile for NAME
#        pft-valwatch version
#
#  run       resolves the node's PUBLIC WebSocket port without entering the container: `docker port NAME 6005/tcp`
#            when it is published on 127.0.0.1 (validator), else the container's bridge IP from `docker inspect`
#            (sentry, no host mapping). The UNL is read from the node's own publisher-list cache file
#            (`cache.<publisher>` in the volume mounted at /var/lib/postfiatd/db, found via `docker inspect`), so no
#            admin RPC and no `docker exec` are needed. Then execs `valwatch.py collect`: it subscribes to
#            validations + ledger, samples server_info (validation_quorum) every 20 ledgers, writes hourly JSONL
#            files under DATA_DIR/NAME (RETAIN_HOURS, MAX_DIR_BYTES) and reconnects with 1..60 s backoff.
#            valwatch.py refuses any host that is not loopback or private.
#  textfile  grades the last WINDOW_SEC of records (default 900) and writes pft_valwatch_* metrics atomically; at
#            most 64 validators get per-validator series. On any failure the file holds pft_valwatch_up 0.
#  report    deterministic text/JSON report over everything retained (or --from/--to): same input, same bytes.
#  compare   cross-host agreement of two `report --detail` files on the ledger indexes both hosts graded.
#
# Exit codes: 0 ok; 1 failed (textfile up 0, fetch failed, compare DISAGREE); 2 validation failed;
#             3 usage/config error; 4 report: no graded ledgers.
# Conf: PFT_VW_CONF (/etc/pft-valwatch.env, root-owned): DATA_DIR (/var/lib/pft-valwatch), TEXTFILE_DIR
#       (/var/lib/pft-exporter/textfile), WS_PORT (6005), WS_HOST (empty = resolve), RETAIN_HOURS (24),
#       MAX_DIR_BYTES (536870912), WINDOW_SEC (900), WARN_DELAY_MS (3000), MIN_PARTICIPATION (0.9),
#       MIN_MARGIN (2), MAX_BYTES (61440), PULL_SSH, REMOTE_DIR (/var/lib/pft-exporter/textfile), PULL_TIMEOUT (20),
#       RUN_DURATION (0 = run until stopped; seconds, for bounded captures)
# Test hooks: PFT_VW_DOCKER (docker)  PFT_VW_NOW (epoch)  PFT_VW_HELPER (/usr/local/lib/pft-valwatch/valwatch.py)
#             PFT_VW_EXEC (exec; tests set it to a stub that prints the collect argv)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_VW_CONF:-/etc/pft-valwatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
DATA_DIR="${DATA_DIR:-/var/lib/pft-valwatch}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
WS_PORT="${WS_PORT:-6005}"
WS_HOST="${WS_HOST:-}"
RETAIN_HOURS="${RETAIN_HOURS:-24}"
MAX_DIR_BYTES="${MAX_DIR_BYTES:-536870912}"
WINDOW_SEC="${WINDOW_SEC:-900}"
WARN_DELAY_MS="${WARN_DELAY_MS:-3000}"
MIN_PARTICIPATION="${MIN_PARTICIPATION:-0.9}"
MIN_MARGIN="${MIN_MARGIN:-2}"
MAX_BYTES="${MAX_BYTES:-61440}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
RUN_DURATION="${RUN_DURATION:-0}"
HELPER="${PFT_VW_HELPER:-/usr/local/lib/pft-valwatch/valwatch.py}"
read -r -a DOCKER <<< "${PFT_VW_DOCKER:-docker}"
read -r -a EXEC <<< "${PFT_VW_EXEC:-exec}"
DB_MOUNT=/var/lib/postfiatd/db
CONTAINER=postfiatd

die() { printf 'pft-valwatch: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }
is_uint() { [[ "$1" =~ ^[0-9]{1,12}$ ]]; }

in_range() { is_uint "$1" && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]; } # VALUE MIN MAX

check_conf() {
  in_range "$WS_PORT" 1 65535 || die "bad WS_PORT"
  in_range "$RETAIN_HOURS" 3 8760 || die "bad RETAIN_HOURS (3..8760)"
  in_range "$MAX_DIR_BYTES" 1048576 1099511627776 || die "bad MAX_DIR_BYTES (>= 1 MiB)"
  in_range "$WINDOW_SEC" 120 86400 || die "bad WINDOW_SEC (120..86400)"
  is_uint "$WARN_DELAY_MS" || die "bad WARN_DELAY_MS"
  is_uint "$MIN_MARGIN" || die "bad MIN_MARGIN"
  [[ "$MIN_PARTICIPATION" =~ ^(0(\.[0-9]+)?|1(\.0+)?)$ ]] || die "bad MIN_PARTICIPATION (0..1)"
  in_range "$MAX_BYTES" 4096 65000 || die "bad MAX_BYTES (4096..65000)"
  is_uint "$RUN_DURATION" || die "bad RUN_DURATION"
  [ -r "$HELPER" ] || die "helper not found: $HELPER"
}

thresholds() { printf '%s\n' --warn-delay-ms "$WARN_DELAY_MS" --min-participation "$MIN_PARTICIPATION" \
  --min-margin "$MIN_MARGIN"; }

parse_container() { # sets CONTAINER and REST (remaining args)
  REST=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      *) REST+=("$1") ;;
    esac
    shift
  done
  valid_name "$CONTAINER" || die "bad container name"
}

# resolve -> prints "HOST PORT CACHEFILE", rc 1 with a reason on stderr
resolve() {
  local host="$WS_HOST" port="$WS_PORT" pub ip src caches line
  if [ -z "$host" ]; then
    pub="$(timeout 15 "${DOCKER[@]}" port "$CONTAINER" "$WS_PORT/tcp" 2>/dev/null)"
    while IFS= read -r line; do # one "ADDR:PORT" per line; only a loopback publication is used
      if [[ "$line" =~ ^127\.0\.0\.1:([0-9]{1,5})$ ]]; then host=127.0.0.1; port="${BASH_REMATCH[1]}"; break; fi
    done <<< "$pub"
    if [ -z "$host" ]; then
      ip="$(timeout 15 "${DOCKER[@]}" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "$CONTAINER" 2>/dev/null)"
      ip="${ip%% *}"
      [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "no published 127.0.0.1 port and no bridge IP" >&2; return 1; }
      host="$ip"
    fi
  fi
  src="$(timeout 15 "${DOCKER[@]}" inspect -f \
    "{{range .Mounts}}{{if eq .Destination \"$DB_MOUNT\"}}{{.Source}}{{end}}{{end}}" "$CONTAINER" 2>/dev/null)"
  [ -d "${src:-/nonexistent}" ] || { echo "no volume mounted at $DB_MOUNT in $CONTAINER" >&2; return 1; }
  caches=("$src"/cache.*)
  [ -f "${caches[0]}" ] || { echo "no validator-list cache file in the $DB_MOUNT volume" >&2; return 1; }
  [ "${#caches[@]}" = 1 ] || { echo "${#caches[@]} publisher caches; valwatch supports one publisher" >&2; return 1; }
  printf '%s %s %s\n' "$host" "$port" "${caches[0]}"
}

run() {
  local r host port cache
  parse_container "$@"
  [ "${#REST[@]}" = 0 ] || die "unknown argument: ${REST[0]}"
  check_conf
  r="$(resolve)" || die "endpoint: cannot resolve for $CONTAINER" 1
  read -r host port cache <<< "$r"
  mkdir -p "$DATA_DIR/$CONTAINER" || die "cannot create $DATA_DIR/$CONTAINER" 1
  "${EXEC[@]}" python3 -I "$HELPER" collect --host "$host" --port "$port" --out "$DATA_DIR/$CONTAINER" \
    --unl-cache "$cache" --retain-hours "$RETAIN_HOURS" --max-dir-bytes "$MAX_DIR_BYTES" --duration "$RUN_DURATION"
}

endpoint() {
  local r host port cache
  parse_container "$@"
  [ "${#REST[@]}" = 0 ] || die "unknown argument: ${REST[0]}"
  check_conf
  r="$(resolve)" || die "endpoint: cannot resolve for $CONTAINER" 1
  read -r host port cache <<< "$r"
  printf 'host %s\nport %s\nunl_cache %s\n' "$host" "$port" "$cache"
}

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

textfile() {
  local stdout=0 now text rc err="" file size L t
  parse_container "$@"
  for t in "${REST[@]}"; do
    case "$t" in
      --stdout) stdout=1 ;;
      *) die "unknown argument: $t" ;;
    esac
  done
  check_conf
  now="${PFT_VW_NOW:-$(date +%s)}"
  file="pft_valwatch_$CONTAINER.prom"
  L="node=\"$CONTAINER\""
  if [ ! -d "$DATA_DIR/$CONTAINER" ]; then
    err="no data dir $DATA_DIR/$CONTAINER"
  else
    mapfile -t th < <(thresholds)
    text="$(python3 -I "$HELPER" textfile --dir "$DATA_DIR/$CONTAINER" --name "$CONTAINER" --now "$now" \
      --window "$WINDOW_SEC" "${th[@]}" 2>&1)"; rc=$?
    [ "$rc" = 0 ] || err="helper rc $rc: $(printf '%s' "$text" | grep -m1 -v '^#\|^pft_' | head -c 160)"
    text+=$'\n'
    size="$(printf '%s' "$text" | wc -c)"
    [ -n "$err" ] || [ "$size" -le "$MAX_BYTES" ] || err="textfile $size B is over MAX_BYTES $MAX_BYTES"
  fi
  if [ -n "$err" ]; then
    text="# HELP pft_valwatch_up 1 if the window holds at least one validated ledger with UNL and quorum known
# TYPE pft_valwatch_up gauge
pft_valwatch_up{$L} 0
# HELP pft_valwatch_collect_timestamp_seconds time this textfile was built
# TYPE pft_valwatch_collect_timestamp_seconds gauge
pft_valwatch_collect_timestamp_seconds{$L} $now
"
  fi
  if [ "$stdout" = 1 ]; then printf '%s' "$text"
  else write_atomic "$TEXTFILE_DIR" "$file" "$text" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ -n "$err" ]; then printf 'pft-valwatch: %s: up 0\n' "$err" >&2; return 1; fi
  return 0
}

report() {
  parse_container "$@"
  check_conf
  [ -d "$DATA_DIR/$CONTAINER" ] || die "no data dir $DATA_DIR/$CONTAINER" 4
  mapfile -t th < <(thresholds)
  python3 -I "$HELPER" report --dir "$DATA_DIR/$CONTAINER" "${th[@]}" "${REST[@]}"
}

# validate FILE NAME -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" name="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$name" '
    BEGIN { pre = "node=\"" n "\"" }
    /^# (HELP|TYPE) pft_valwatch_[a-z0-9_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_valwatch_[a-z0-9_]+\{/) == 0) { printf "line %d: not a pft_valwatch_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_valwatch_up\{/) up = 1
      if ($0 ~ /^pft_valwatch_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_valwatch_up sample"; exit 1 }
      if (!ts) { print "no pft_valwatch_collect_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  CONTAINER=postfiatd-sentry
  parse_container "$@"
  [ "${#REST[@]}" = 0 ] || die "unknown argument: ${REST[0]}"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-valwatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-valwatch-$CONTAINER.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_valwatch_$CONTAINER.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_valwatch_$CONTAINER.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$CONTAINER")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_valwatch_$CONTAINER.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  run) run "$@" ;;
  endpoint) endpoint "$@" ;;
  textfile) textfile "$@" ;;
  report) report "$@" ;;
  compare) [ -r "$HELPER" ] || die "helper not found: $HELPER"; python3 -I "$HELPER" compare "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-valwatch validate FILE NAME"; valid_name "$2" || die "bad container name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-valwatch $VERSION" ;;
  *) die "usage: pft-valwatch run|endpoint|textfile|report|compare|pull|validate|version (see the header)" ;;
esac
