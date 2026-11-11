#!/usr/bin/env bash
# pft-peerwatch: continuous peer-quality monitoring for a Post Fiat validator or sentry (read-only).
# ../peers/pft-peers.py is a one-shot diagnosis and the exporter only counts peers. This samples the node's `peers`
# and `server_info` admin answers every minute and grades churn (by public key), latency, build-version mix,
# inbound/outbound split, outbound-prefix diversity, ledger agreement and the fixed/cluster links, keeps a bounded
# history and exports pft_peerwatch_* textfile metrics.
#
# Usage: sudo pft-peerwatch collect [--container NAME] [--textfile-dir DIR] [--stdout]
#        sudo pft-peerwatch status [--container NAME] [--json]    exit 0 PASS, 1 WARN, 2 FAIL, 4 no/stale data
#        sudo pft-peerwatch pull [--container NAME]              (validator: copy the sentry's textfile)
#        pft-peerwatch validate FILE NAME                        exit 0 if FILE is an acceptable textfile for NAME
#        pft-peerwatch version
#
#  collect  runs `docker exec NAME curl ... peers` and `... server_info` against the admin RPC on the CONTAINER's
#           loopback (the same exec shape pft-statewatch uses; curl is the exec'd binary, no shell in the container).
#           peerwatch_parse.py validates both answers, updates STATE_DIR/state-NAME.json (last pubkey set, churn
#           events of the window, check results) and appends one line to STATE_DIR/history-NAME.jsonl (trimmed to
#           HISTORY_MAX lines). DIR/pft_peerwatch_NAME.prom is written atomically with pft_peerwatch_up 1. On ANY
#           failure the file holds only pft_peerwatch_up 0 and the collect timestamp, state is left alone, exit 1.
#  status   prints the checks of the last sample (or --json); a sample older than STALE_SEC is reported STALE.
#  pull     "$PULL_SSH cat -- REMOTE_DIR/pft_peerwatch_NAME.prom", validated all-or-nothing, renamed into DIR.
#
# Exit codes: collect/pull 0 ok, 1 collection/fetch failed, 2 validation failed, 3 usage/config error;
#             status 0 PASS, 1 WARN, 2 FAIL, 3 usage, 4 no state or stale.
# Conf: PFT_PW_CONF (/etc/pft-peerwatch.env, root-owned; sourced for the shell keys below, read as KEY=VALUE text by
#       peerwatch_parse.py for the thresholds): CONTAINER (postfiatd), TEXTFILE_DIR (/var/lib/pft-exporter/textfile),
#       STATE_DIR (/var/lib/pft-peerwatch), RPC_TIMEOUT (8), PULL_SSH, REMOTE_DIR, PULL_TIMEOUT (20), MAX_BYTES (16384)
# Test hooks: PFT_PW_DOCKER (docker)  PFT_PW_NOW (epoch)  PFT_PW_PARSER (/usr/local/lib/pft-peerwatch/peerwatch_parse.py)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_PW_CONF:-/etc/pft-peerwatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
CONTAINER="${CONTAINER:-postfiatd}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-peerwatch}"
RPC_TIMEOUT="${RPC_TIMEOUT:-8}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-16384}"
PARSER="${PFT_PW_PARSER:-/usr/local/lib/pft-peerwatch/peerwatch_parse.py}"
read -r -a DOCKER <<< "${PFT_PW_DOCKER:-docker}"

die() { printf 'pft-peerwatch: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }
conf_arg() { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && printf '%s' "$CONF"; }

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

# rpc METHOD OUTFILE ERRFILE: the answer goes to OUTFILE, stderr (docker CLI warnings) never into the answer
rpc() {
  timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" curl -s --max-time "$RPC_TIMEOUT" \
    -H 'Content-Type: application/json' -d "{\"method\":\"$1\",\"params\":[{}]}" http://127.0.0.1:5005/ > "$2" 2>"$3"
}

collect() {
  local stdout=0 now L err="" work text rc head
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
  [ -r "$PARSER" ] || die "parser not found: $PARSER"
  [ -d "$STATE_DIR" ] || die "state dir missing: $STATE_DIR"
  now="${PFT_PW_NOW:-$(date +%s)}"
  L="container=\"$CONTAINER\""
  work="$(mktemp -d "$STATE_DIR/.collect.XXXXXX")" || die "mktemp failed" 1
  if ! rpc peers "$work/peers.json" "$work/err"; then
    err="peers via docker exec $CONTAINER failed: $(head -c 120 "$work/err")"
  elif ! rpc server_info "$work/info.json" "$work/err"; then
    err="server_info via docker exec $CONTAINER failed: $(head -c 120 "$work/err")"
  else
    text="$(python3 -I "$PARSER" collect --peers "$work/peers.json" --server-info "$work/info.json" \
        --state "$STATE_DIR/state-$CONTAINER.json" --history "$STATE_DIR/history-$CONTAINER.jsonl" \
        --container "$CONTAINER" --conf "$(conf_arg)" --now "$now" 2>"$work/err")"; rc=$?
    if [ "$rc" != 0 ]; then err="$(head -c 200 "$work/err")"; err="${err:-parser failed (rc $rc)}"
    elif [ -s "$work/err" ]; then cat "$work/err" >&2
    fi
  fi
  rm -rf "$work"
  head="# HELP pft_peerwatch_up 1 if the last peers + server_info collection succeeded and every field was valid
# TYPE pft_peerwatch_up gauge
pft_peerwatch_up{$L} $([ -z "$err" ] && echo 1 || echo 0)
# HELP pft_peerwatch_collect_timestamp_seconds Unix time of the last collection attempt
# TYPE pft_peerwatch_collect_timestamp_seconds gauge
pft_peerwatch_collect_timestamp_seconds{$L} $now
"
  [ -z "$err" ] && head+="$text"$'\n'
  if [ "$stdout" = 1 ]; then printf '%s' "$head"
  else
    write_atomic "$TEXTFILE_DIR" "pft_peerwatch_$CONTAINER.prom" "$head" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ -n "$err" ]; then printf 'pft-peerwatch: %s: up 0\n' "$err" >&2; return 1; fi
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
    --now "${PFT_PW_NOW:-$(date +%s)}" "${json[@]}"
}

# validate FILE NAME -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" name="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$name" '
    BEGIN { pre = "container=\"" n "\"" }
    /^# (HELP|TYPE) pft_peerwatch_[a-z0-9_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_peerwatch_[a-z0-9_]+\{/) == 0) { printf "line %d: not a pft_peerwatch_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_peerwatch_up\{/) up = 1
      if ($0 ~ /^pft_peerwatch_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_peerwatch_up sample"; exit 1 }
      if (!ts) { print "no pft_peerwatch_collect_timestamp_seconds sample"; exit 1 }
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
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-peerwatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-peerwatch-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_peerwatch_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_peerwatch_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_peerwatch_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  status) status "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-peerwatch validate FILE NAME"; valid_name "$2" || die "bad container name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-peerwatch $VERSION" ;;
  *) die "usage: pft-peerwatch collect|status|pull|validate|version (see the header of this script)" ;;
esac
