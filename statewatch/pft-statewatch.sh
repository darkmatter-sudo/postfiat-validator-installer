#!/usr/bin/env bash
# pft-statewatch: postfiatd internal state and health COUNTERS as Prometheus textfile metrics (validator or sentry).
# The pft exporter (../exporter) only sees server_state at scrape time, so a node that drops out of full for 20 s
# between two scrapes, or a job queue that overflows, is invisible. server_info's state_accounting, jq_trans_overflow
# and peer_disconnects* are cumulative counters kept by postfiatd itself; this tool exports them every minute.
#
# Usage: sudo pft-statewatch collect [--container NAME] [--textfile-dir DIR] [--history FILE] [--stdout]
#        sudo pft-statewatch pull [--container NAME]       (validator: copy the sentry's textfile, see below)
#        pft-statewatch validate FILE NAME                 exit 0 if FILE is an acceptable textfile for NAME
#        pft-statewatch version
#
#  collect  runs `docker exec NAME curl ... server_info` against the node's admin RPC on the CONTAINER's loopback
#           (127.0.0.1:5005 inside the container: works the same on a validator and on a sentry, which maps no admin
#           port to the host). statewatch_parse.py validates every field; on success DIR/pft_statewatch_NAME.prom is
#           written atomically (temp file in DIR + rename) with pft_statewatch_up 1. On ANY failure (docker, curl,
#           timeout, non-JSON, rpc error, missing or malformed field) the file holds only pft_statewatch_up 0 and the
#           collect timestamp, never stale values, and the exit code is 1.
#  pull     runs "$PULL_SSH cat -- REMOTE_DIR/pft_statewatch_NAME.prom" (timeout PULL_TIMEOUT), validates it and renames
#           it into TEXTFILE_DIR, so the validator's single Prometheus + Alertmanager (../alerts) also alerts on the
#           sentry. Validation is all-or-nothing: <= MAX_BYTES, every line a "# HELP/TYPE pft_statewatch_*" comment or a
#           pft_statewatch_* sample whose FIRST label is container="NAME" with a numeric value, and the file carries
#           pft_statewatch_up and pft_statewatch_collect_timestamp_seconds for NAME. On failure the old copy stays,
#           its timestamp ages and PFTStatewatchStale fires.
#
# Exit codes: 0 ok, 1 collection/fetch failed, 2 validation failed, 3 usage/config error.
# Conf: PFT_SW_CONF (/etc/pft-statewatch.env, root-owned, sourced first): CONTAINER (postfiatd), TEXTFILE_DIR
#       (/var/lib/pft-exporter/textfile), HISTORY (empty = none), RPC_TIMEOUT (10), PULL_SSH (pull only, e.g.
#       "runuser -u OPERATOR -- ssh -o BatchMode=yes -o ConnectTimeout=10 relay"), REMOTE_DIR
#       (/var/lib/pft-exporter/textfile), PULL_TIMEOUT (20), MAX_BYTES (65536)
# Test hooks: PFT_SW_DOCKER (docker)  PFT_SW_NOW (epoch)  PFT_SW_PARSER (/usr/local/lib/pft-statewatch/statewatch_parse.py)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_SW_CONF:-/etc/pft-statewatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
CONTAINER="${CONTAINER:-postfiatd}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
HISTORY="${HISTORY:-}"
RPC_TIMEOUT="${RPC_TIMEOUT:-10}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"
PARSER="${PFT_SW_PARSER:-/usr/local/lib/pft-statewatch/statewatch_parse.py}"
read -r -a DOCKER <<< "${PFT_SW_DOCKER:-docker}"

die() { printf 'pft-statewatch: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }

# atomic write: CONTENT -> DIR/FILE via a temp file in the same dir (removed on any failure)
write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

collect() {
  local stdout=0 now body raw text rc L err errf
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --history) HISTORY="${2:?}"; shift ;;
      --stdout) stdout=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_name "$CONTAINER" || die "bad container name"
  [[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad RPC_TIMEOUT"
  [ -r "$PARSER" ] || die "parser not found: $PARSER"
  now="${PFT_SW_NOW:-$(date +%s)}"
  L="container=\"$CONTAINER\""
  body='{"method":"server_info","params":[{}]}'
  err=""
  # curl's own --max-time ends the request inside the container; the outer timeout only guards a hung docker exec
  if ! raw="$(timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" curl -s --max-time "$RPC_TIMEOUT" \
        -H 'Content-Type: application/json' -d "$body" http://127.0.0.1:5005/ 2>&1)"; then
    err="server_info via docker exec $CONTAINER failed: ${raw:0:120}"
  else
    errf="$(mktemp)" || die "mktemp failed" 1
    text="$(printf '%s' "$raw" | python3 -I "$PARSER" --container "$CONTAINER" --now "$now" \
        ${HISTORY:+--history "$HISTORY"} 2>"$errf")"; rc=$?
    if [ "$rc" != 0 ]; then err="$(head -c 200 "$errf")"; err="${err:-parser failed (rc $rc)}"
    elif [ -s "$errf" ]; then cat "$errf" >&2  # warnings only (history not written)
    fi
    rm -f "$errf"
  fi
  local head
  head="# HELP pft_statewatch_up 1 if the last server_info collection succeeded and every field was valid
# TYPE pft_statewatch_up gauge
pft_statewatch_up{$L} $([ -z "$err" ] && echo 1 || echo 0)
# HELP pft_statewatch_collect_timestamp_seconds Unix time of the last collection attempt
# TYPE pft_statewatch_collect_timestamp_seconds gauge
pft_statewatch_collect_timestamp_seconds{$L} $now
"
  [ -z "$err" ] && head+="$text"$'\n' # $(...) dropped the final newline
  if [ "$stdout" = 1 ]; then printf '%s' "$head"
  else
    write_atomic "$TEXTFILE_DIR" "pft_statewatch_$CONTAINER.prom" "$head" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ -n "$err" ]; then printf 'pft-statewatch: %s: up 0\n' "$err" >&2; return 1; fi
  return 0
}

# validate FILE NAME -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" name="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$name" '
    BEGIN { pre = "container=\"" n "\"" }
    /^# (HELP|TYPE) pft_statewatch_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_statewatch_[a-z_]+\{/) == 0) { printf "line %d: not a pft_statewatch_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_statewatch_up\{/) up = 1
      if ($0 ~ /^pft_statewatch_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_statewatch_up sample"; exit 1 }
      if (!ts) { print "no pft_statewatch_collect_timestamp_seconds sample"; exit 1 }
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
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-statewatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-statewatch-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_statewatch_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_statewatch_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_statewatch_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-statewatch validate FILE NAME"; valid_name "$2" || die "bad container name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-statewatch $VERSION" ;;
  *) die "usage: pft-statewatch collect|pull|validate|version (see the header of this script)" ;;
esac
