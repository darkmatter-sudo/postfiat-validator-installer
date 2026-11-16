#!/usr/bin/env bash
# pft-internals: postfiatd internal-health metrics for a Post Fiat validator or sentry (read-only).
# The exporter reads server_info basics and statewatch its state accounting; neither looks inside the node. This
# samples the admin `get_counts` and `server_info {"counters": true}` answers every minute and exports NodeStore
# I/O, cache sizes and hit ratios, SQLite sizes, live object counts, per-job-type queue counters and load, and
# per-RPC-method counters as pft_internals_* textfile metrics (bounded label sets, under the exporter's 64 KiB cap).
#
# Usage: sudo pft-internals collect [--container NAME] [--textfile-dir DIR] [--stdout]
#        sudo pft-internals status [--container NAME] [--json]    exit 0 ok, 4 no/stale data
#        sudo pft-internals pull [--container NAME]              (validator: copy the sentry's textfile)
#        pft-internals validate FILE NAME                        exit 0 if FILE is an acceptable textfile for NAME
#        pft-internals version
#
#  collect  runs `docker exec NAME curl ... get_counts` and `... server_info` (params {"counters":true}) against the
#           admin RPC on the CONTAINER's loopback (the exec shape pft-statewatch/pft-peerwatch use; curl is the
#           exec'd binary, no shell in the container). internals_parse.py validates every exported field (fail
#           closed), compares counters with STATE_DIR/state-NAME.json (restart / anomaly counts) and prints the
#           body. DIR/pft_internals_NAME.prom is written atomically with pft_internals_up 1. On ANY failure (RPC,
#           invalid field, body over MAX_BYTES) the file holds only pft_internals_up 0, the collect timestamp and
#           the last success time; the previous good file is kept as STATE_DIR/last-good-NAME.prom; exit 1.
#  status   prints the state of the last sample (or --json); a sample older than STALE_SEC is reported STALE.
#  pull     "$PULL_SSH cat -- REMOTE_DIR/pft_internals_NAME.prom", validated all-or-nothing, renamed into DIR.
#
# Exit codes: collect/pull 0 ok, 1 collection/fetch failed, 2 validation failed, 3 usage/config error;
#             status 0 ok, 3 usage, 4 no state or stale.
# Conf: PFT_IN_CONF (/etc/pft-internals.env, root-owned; sourced for the shell keys below, read as KEY=VALUE text by
#       internals_parse.py for its keys): CONTAINER (postfiatd), TEXTFILE_DIR (/var/lib/pft-exporter/textfile),
#       STATE_DIR (/var/lib/pft-internals), RPC_TIMEOUT (8), PULL_SSH, REMOTE_DIR, PULL_TIMEOUT (20),
#       MAX_BYTES (61440; the exporter skips textfiles over 65536 bytes)
# Test hooks: PFT_IN_DOCKER (docker)  PFT_IN_NOW (epoch)  PFT_IN_PARSER (/usr/local/lib/pft-internals/internals_parse.py)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_IN_CONF:-/etc/pft-internals.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
CONTAINER="${CONTAINER:-postfiatd}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-internals}"
RPC_TIMEOUT="${RPC_TIMEOUT:-8}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-61440}"
PARSER="${PFT_IN_PARSER:-/usr/local/lib/pft-internals/internals_parse.py}"
read -r -a DOCKER <<< "${PFT_IN_DOCKER:-docker}"

die() { printf 'pft-internals: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }
conf_arg() { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && printf '%s' "$CONF"; }

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

# rpc METHOD PARAMS OUTFILE ERRFILE: the answer goes to OUTFILE, stderr (docker CLI warnings) never into the answer
rpc() {
  timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" curl -s --max-time "$RPC_TIMEOUT" \
    -H 'Content-Type: application/json' -d "{\"method\":\"$1\",\"params\":[$2]}" http://127.0.0.1:5005/ > "$3" 2>"$4"
}

collect() {
  local stdout=0 now L err="" work text="" rc head last file size
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --stdout) stdout=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_name "$CONTAINER" || die "bad container name"
  [[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad RPC_TIMEOUT"
  if ! [[ "$MAX_BYTES" =~ ^[1-9][0-9]{3,4}$ ]] || [ "$MAX_BYTES" -lt 4096 ] || [ "$MAX_BYTES" -gt 65000 ]; then
    die "bad MAX_BYTES (4096..65000)"
  fi
  [ -r "$PARSER" ] || die "parser not found: $PARSER"
  [ -d "$STATE_DIR" ] || die "state dir missing: $STATE_DIR"
  now="${PFT_IN_NOW:-$(date +%s)}"
  L="container=\"$CONTAINER\""
  file="pft_internals_$CONTAINER.prom"
  work="$(mktemp -d "$STATE_DIR/.collect.XXXXXX")" || die "mktemp failed" 1
  if ! rpc get_counts '{}' "$work/counts.json" "$work/err"; then
    err="get_counts via docker exec $CONTAINER failed: $(head -c 120 "$work/err")"
  elif ! rpc server_info '{"counters":true}' "$work/info.json" "$work/err"; then
    err="server_info via docker exec $CONTAINER failed: $(head -c 120 "$work/err")"
  else
    text="$(python3 -I "$PARSER" collect --counts "$work/counts.json" --server-info "$work/info.json" \
        --state "$STATE_DIR/state-$CONTAINER.json" --container "$CONTAINER" --conf "$(conf_arg)" \
        --max-bytes "$MAX_BYTES" --reserve 1024 --now "$now" 2>"$work/err")"; rc=$?
    if [ "$rc" != 0 ]; then err="$(head -c 200 "$work/err")"; err="${err:-parser failed (rc $rc)}"
    elif [ -s "$work/err" ]; then cat "$work/err" >&2
    fi
  fi
  rm -rf "$work"
  last="$(python3 -I "$PARSER" last-success --state "$STATE_DIR/state-$CONTAINER.json" 2>/dev/null)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  head="# HELP pft_internals_up 1 if the last get_counts + server_info collection succeeded and every field was valid
# TYPE pft_internals_up gauge
pft_internals_up{$L} $([ -z "$err" ] && echo 1 || echo 0)
# HELP pft_internals_collect_timestamp_seconds Unix time of the last collection attempt
# TYPE pft_internals_collect_timestamp_seconds gauge
pft_internals_collect_timestamp_seconds{$L} $now
# HELP pft_internals_last_success_timestamp_seconds Unix time of the last successful collection (0 = never)
# TYPE pft_internals_last_success_timestamp_seconds gauge
pft_internals_last_success_timestamp_seconds{$L} $last
"
  if [ -z "$err" ]; then
    head+="$text"$'\n'  # $(...) dropped the final newline
    size="$(printf '%s' "$head" | wc -c)"
    if [ "$size" -gt "$MAX_BYTES" ]; then # the parser keeps a reserve for these lines; this is the hard gate
      err="textfile $size B is over MAX_BYTES $MAX_BYTES"
      head="${head%%"# HELP pft_internals_node_uptime"*}"
      head="${head/pft_internals_up\{$L\} 1/pft_internals_up\{$L\} 0}"
    fi
  fi
  if [ "$stdout" = 1 ]; then printf '%s' "$head"
  else
    # keep the last good file for diagnosis before a failure overwrites it
    if [ -n "$err" ] && grep -qx "pft_internals_up{$L} 1" "$TEXTFILE_DIR/$file" 2>/dev/null; then
      cp -f "$TEXTFILE_DIR/$file" "$STATE_DIR/last-good-$CONTAINER.prom" 2>/dev/null || true
    fi
    write_atomic "$TEXTFILE_DIR" "$file" "$head" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ -n "$err" ]; then printf 'pft-internals: %s: up 0\n' "$err" >&2; return 1; fi
  return 0
}

status() {
  local json=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --json) json=(--json) ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_name "$CONTAINER" || die "bad container name"
  [ -r "$PARSER" ] || die "parser not found: $PARSER"
  python3 -I "$PARSER" status --state "$STATE_DIR/state-$CONTAINER.json" --conf "$(conf_arg)" \
    --now "${PFT_IN_NOW:-$(date +%s)}" "${json[@]}"
}

# validate FILE NAME -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" name="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$name" '
    BEGIN { pre = "container=\"" n "\"" }
    /^# (HELP|TYPE) pft_internals_[a-z0-9_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_internals_[a-z0-9_]+\{/) == 0) { printf "line %d: not a pft_internals_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_internals_up\{/) up = 1
      if ($0 ~ /^pft_internals_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_internals_up sample"; exit 1 }
      if (!ts) { print "no pft_internals_collect_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local name=postfiatd-sentry tmp why
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) name="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_name "$name" || die "bad container name"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-internals.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-internals-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_internals_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_internals_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_internals_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  status) status "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-internals validate FILE NAME"; valid_name "$2" || die "bad container name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-internals $VERSION" ;;
  *) die "usage: pft-internals collect|status|pull|validate|version (see the header of this script)" ;;
esac
