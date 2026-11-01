#!/usr/bin/env bash
# pft-feewatch: transaction-queue (TxQ), open-ledger fee escalation and per-source load_factor of a postfiatd node as
# Prometheus textfile metrics (validator or sentry). Read-only: two RPC reads per minute, never a transaction.
# The pft exporter (../exporter) only exports the total load_factor; statewatch (../statewatch) covers state/IO
# counters. Neither sees the `fee` RPC (queue size and capacity, open-ledger fee) or WHICH source raised the load.
#
# Usage: sudo pft-feewatch collect [--container NAME] [--textfile-dir DIR] [--history FILE] [--stdout]
#        sudo pft-feewatch pull [--container NAME]       (validator: copy the sentry's textfile, see below)
#        pft-feewatch replay --container drill-NAME --fee FILE --info FILE [--textfile-dir DIR] [--now EPOCH]
#        pft-feewatch validate FILE NAME                 exit 0 if FILE is an acceptable textfile for NAME
#        pft-feewatch version
#
#  collect  runs `docker exec NAME curl ... fee` and `... server_info` against the node's admin RPC on the
#           CONTAINER's loopback (127.0.0.1:5005 inside the container: the same on a validator and on a sentry,
#           which maps no admin port to the host). feewatch_parse.py checks every field; on success
#           DIR/pft_feewatch_NAME.prom is written atomically (temp file in DIR + rename) with pft_feewatch_up 1. On ANY
#           failure (docker, curl, timeout, non-JSON, rpc error, missing or malformed field) the file holds only
#           pft_feewatch_up 0 and the collect timestamp, never stale values, and the exit code is 1.
#  pull     runs "$PULL_SSH cat -- REMOTE_DIR/pft_feewatch_NAME.prom" (timeout PULL_TIMEOUT), validates it and renames
#           it into TEXTFILE_DIR, so the validator's single Prometheus + Alertmanager (../alerts) also alerts on the
#           sentry. All-or-nothing validation: <= MAX_BYTES, every line a "# HELP/TYPE pft_feewatch_*" comment or a
#           pft_feewatch_* sample whose FIRST label is container="NAME" with a numeric value, plus pft_feewatch_up
#           and pft_feewatch_collect_timestamp_seconds. On failure the old copy stays and PFTFeewatchStale fires.
#  replay   drill/test mode: the same parser and textfile format, but the two answers come from FILES (recorded or
#           synthetic fixtures), so alerts can be proven without generating any network load. The name must start
#           with "drill-", so a replay can never overwrite a real node's textfile. An unparseable fixture gives up 0.
#
# Exit codes: 0 ok, 1 collection/fetch failed, 2 validation failed, 3 usage/config error.
# Conf: PFT_FW_CONF (/etc/pft-feewatch.env, root-owned, sourced first): CONTAINER (postfiatd), TEXTFILE_DIR
#       (/var/lib/pft-exporter/textfile), HISTORY (empty = none), RPC_TIMEOUT (10), ESCALATION_THRESHOLD (4),
#       PULL_SSH (pull only, e.g. "runuser -u OPERATOR -- ssh -o BatchMode=yes -o ConnectTimeout=10 relay"),
#       REMOTE_DIR (/var/lib/pft-exporter/textfile), PULL_TIMEOUT (20), MAX_BYTES (65536)
# Test hooks: PFT_FW_DOCKER (docker)  PFT_FW_NOW (epoch)  PFT_FW_PARSER (/usr/local/lib/pft-feewatch/feewatch_parse.py)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_FW_CONF:-/etc/pft-feewatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
CONTAINER="${CONTAINER:-postfiatd}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
HISTORY="${HISTORY:-}"
RPC_TIMEOUT="${RPC_TIMEOUT:-10}"
ESCALATION_THRESHOLD="${ESCALATION_THRESHOLD:-4}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"
PARSER="${PFT_FW_PARSER:-/usr/local/lib/pft-feewatch/feewatch_parse.py}"
read -r -a DOCKER <<< "${PFT_FW_DOCKER:-docker}"

die() { printf 'pft-feewatch: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }

# atomic write: CONTENT -> DIR/FILE via a temp file in the same dir (removed on any failure)
write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

# rpc METHOD OUTFILE ERRFILE: the answer (stdout only) into OUTFILE. stderr stays out of the answer: under the unit's
# sandbox the docker CLI warns "Error loading config file" on stderr (statewatch runlog 02).
rpc() {
  timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" curl -s --max-time "$RPC_TIMEOUT" \
    -H 'Content-Type: application/json' -d "{\"method\":\"$1\",\"params\":[{}]}" http://127.0.0.1:5005/ \
    > "$2" 2> "$3"
}

# emit NOW ERR TEXT STDOUT: write (or print) the textfile; up 1 + TEXT when ERR is empty, else only up 0 + timestamp
emit() {
  local L="container=\"$CONTAINER\"" head
  head="# HELP pft_feewatch_up 1 if the last fee + server_info collection succeeded and every field was valid
# TYPE pft_feewatch_up gauge
pft_feewatch_up{$L} $([ -z "$2" ] && echo 1 || echo 0)
# HELP pft_feewatch_collect_timestamp_seconds Unix time of the last collection attempt
# TYPE pft_feewatch_collect_timestamp_seconds gauge
pft_feewatch_collect_timestamp_seconds{$L} $1
"
  [ -z "$2" ] && head+="$3"$'\n' # $(...) dropped the final newline
  if [ "$4" = 1 ]; then printf '%s' "$head"
  else
    write_atomic "$TEXTFILE_DIR" "pft_feewatch_$CONTAINER.prom" "$head" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ -n "$2" ]; then printf 'pft-feewatch: %s: up 0\n' "$2" >&2; return 1; fi
  return 0
}

# parse NOW FEEFILE INFOFILE [HISTORY] -> TEXT on stdout, rc of the parser; first error line in $ERRF
parse() {
  python3 -I "$PARSER" --container "$CONTAINER" --now "$1" --fee "$2" --info "$3" \
    --threshold "$ESCALATION_THRESHOLD" ${4:+--history "$4"} 2> "$ERRF"
}

check_common() {
  valid_name "$CONTAINER" || die "bad container name"
  [[ "$ESCALATION_THRESHOLD" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "bad ESCALATION_THRESHOLD"
  [ -r "$PARSER" ] || die "parser not found: $PARSER"
}

collect() {
  local stdout=0 now text rc err="" d
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
  check_common
  [[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad RPC_TIMEOUT"
  now="${PFT_FW_NOW:-$(date +%s)}"
  d="$(mktemp -d)" || die "mktemp failed" 1
  ERRF="$d/err"
  if ! rpc fee "$d/fee" "$ERRF"; then
    err="fee via docker exec $CONTAINER failed: $(head -c 120 "$ERRF")"
  elif ! rpc server_info "$d/info" "$ERRF"; then
    err="server_info via docker exec $CONTAINER failed: $(head -c 120 "$ERRF")"
  else
    text="$(parse "$now" "$d/fee" "$d/info" "$HISTORY")"; rc=$?
    if [ "$rc" != 0 ]; then err="$(head -c 200 "$ERRF")"; err="${err:-parser failed (rc $rc)}"
    elif [ -s "$ERRF" ]; then cat "$ERRF" >&2  # warnings only (history not written)
    fi
  fi
  rm -rf "$d"
  emit "$now" "$err" "${text:-}" "$stdout"
}

replay() {
  local fee="" info="" now text rc err=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --fee) fee="${2:?}"; shift ;;
      --info) info="${2:?}"; shift ;;
      --now) PFT_FW_NOW="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_common
  [[ "$CONTAINER" == drill-* ]] || die "replay names must start with drill- (never a real node's textfile)"
  if [ ! -r "$fee" ] || [ ! -r "$info" ]; then die "replay needs readable --fee and --info files"; fi
  [[ "${PFT_FW_NOW:-0}" =~ ^[0-9]+$ ]] || die "bad --now"
  now="${PFT_FW_NOW:-$(date +%s)}"
  ERRF="$(mktemp)" || die "mktemp failed" 1
  text="$(parse "$now" "$fee" "$info" "")"; rc=$?
  if [ "$rc" != 0 ]; then err="$(head -c 200 "$ERRF")"; err="${err:-parser failed (rc $rc)}"; fi
  rm -f "$ERRF"
  emit "$now" "$err" "${text:-}" 0
}

# validate FILE NAME -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" name="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$name" '
    BEGIN { pre = "container=\"" n "\"" }
    /^# (HELP|TYPE) pft_feewatch_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_feewatch_[a-z_]+\{/) == 0) { printf "line %d: not a pft_feewatch_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_feewatch_up\{/) up = 1
      if ($0 ~ /^pft_feewatch_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_feewatch_up sample"; exit 1 }
      if (!ts) { print "no pft_feewatch_collect_timestamp_seconds sample"; exit 1 }
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
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-feewatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-feewatch-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_feewatch_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_feewatch_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_feewatch_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  replay) replay "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-feewatch validate FILE NAME"; valid_name "$2" || die "bad container name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-feewatch $VERSION" ;;
  *) die "usage: pft-feewatch collect|pull|replay|validate|version (see the header of this script)" ;;
esac
