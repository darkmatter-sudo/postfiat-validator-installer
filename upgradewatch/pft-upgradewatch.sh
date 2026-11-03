#!/usr/bin/env bash
# pft-upgradewatch: amendment-block risk and upgrade readiness of a postfiatd node as Prometheus textfile metrics
# (validator or sentry). Turns the one-shot ../amendments check into a continuous monitor: unsupported amendments
# holding a majority, the source-derived time until they can activate, amendment_blocked, and how this build
# compares with the foundation RPC and with the node's peers. Read-only: four admin RPC reads, one grep of the node
# config (only section headers and duration-shaped lines leave the container) and one public server_info per run.
#
# Usage: sudo pft-upgradewatch collect [--container NAME] [--textfile-dir DIR] [--stdout]
#        sudo pft-upgradewatch pull [--container NAME]      (validator: copy the sentry's textfile, see below)
#        pft-upgradewatch replay --container drill-NAME --fixtures DIR [--textfile-dir DIR] [--now EPOCH]
#        pft-upgradewatch validate FILE NAME                exit 0 if FILE is an acceptable textfile for NAME
#        pft-upgradewatch version
#
#  collect  runs `docker exec NAME curl ...` for server_info, feature, peers and ledger_entry(Amendments, validated)
#           on the CONTAINER's loopback admin port (127.0.0.1:5005, the same on a validator and on a sentry), greps
#           [amendment_majority_time] from the node config and reads build_version from FOUNDATION_URL.
#           upgradewatch_parse.py checks every field; on success DIR/pft_upgradewatch_NAME.prom is written atomically
#           with pft_upgradewatch_up 1. On ANY node-side failure (docker, curl, timeout, non-JSON, rpc error, missing or
#           malformed field) the file holds only pft_upgradewatch_up 0 and the collect timestamp, never stale values,
#           and the exit code is 1. A foundation RPC failure is not a node failure: it only sets foundation_known 0.
#  pull     runs "$PULL_SSH cat -- REMOTE_DIR/pft_upgradewatch_NAME.prom" (timeout PULL_TIMEOUT), validates it and
#           renames it into TEXTFILE_DIR, so the validator's single Prometheus + Alertmanager also alerts on the sentry.
#  replay   drill/test mode: the same parser and textfile, but the answers come from FILES in DIR (info.json
#           feature.json amendments.json peers.json cfg.txt [foundation.json]). The name must start with "drill-", so a
#           replay can never overwrite a real node's textfile.
#
# Exit codes: 0 ok, 1 collection/fetch failed, 2 validation failed, 3 usage/config error.
# Conf: PFT_UW_CONF (/etc/pft-upgradewatch.env, root-owned, sourced first): CONTAINER (postfiatd), TEXTFILE_DIR
#       (/var/lib/pft-exporter/textfile), NODE_CFG (/etc/postfiatd/postfiatd.cfg, path inside the container),
#       RPC_TIMEOUT (10), FOUNDATION_URL (https://rpc.testnet.postfiat.org, empty = never asked), FOUNDATION_TIMEOUT
#       (15), PULL_SSH (pull only), REMOTE_DIR (/var/lib/pft-exporter/textfile), PULL_TIMEOUT (20), MAX_BYTES (65536)
# Test hooks: PFT_UW_DOCKER (docker)  PFT_UW_CURL (curl)  PFT_UW_NOW (epoch)
#             PFT_UW_PARSER (/usr/local/lib/pft-upgradewatch/upgradewatch_parse.py)

set -uo pipefail
umask 022
VERSION=1
AMENDMENTS_INDEX=7DB0788C020F02780A673DC74757F23823FA3014C1866E72CC4CD8B226CD6EF4

CONF="${PFT_UW_CONF:-/etc/pft-upgradewatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
CONTAINER="${CONTAINER:-postfiatd}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
NODE_CFG="${NODE_CFG:-/etc/postfiatd/postfiatd.cfg}"
RPC_TIMEOUT="${RPC_TIMEOUT:-10}"
FOUNDATION_URL="${FOUNDATION_URL-https://rpc.testnet.postfiat.org}"
FOUNDATION_TIMEOUT="${FOUNDATION_TIMEOUT:-15}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"
PARSER="${PFT_UW_PARSER:-/usr/local/lib/pft-upgradewatch/upgradewatch_parse.py}"
read -r -a DOCKER <<< "${PFT_UW_DOCKER:-docker}"
read -r -a CURL <<< "${PFT_UW_CURL:-curl}"
# a section header, or a value shaped like Config.cpp:876's duration; nothing else of the config is read
CFG_RE='^[[:space:]]*(\[[^]]*\]|[0-9]+[[:space:]]*(minutes|hours|days|weeks)([[:space:]].*)?)[[:space:]]*$'

die() { printf 'pft-upgradewatch: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

body() { # KEY -> JSON-RPC body (allowlist: nothing else is ever sent)
  case "$1" in
    server_info|feature|peers) printf '{"method":"%s","params":[{}]}' "$1" ;;
    amendments) printf '{"method":"ledger_entry","params":[{"index":"%s","ledger_index":"validated"}]}' \
                  "$AMENDMENTS_INDEX" ;;
    *) return 1 ;;
  esac
}

# rpc KEY OUTFILE ERRFILE: the answer (stdout only) into OUTFILE; stderr stays out of the answer (lesson: under the
# unit's sandbox the docker CLI warns on stderr)
rpc() {
  local b
  b="$(body "$1")" || return 1
  timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" curl -s --max-time "$RPC_TIMEOUT" \
    -H 'Content-Type: application/json' -d "$b" http://127.0.0.1:5005/ > "$2" 2> "$3"
}

# cfg OUTFILE ERRFILE: grep rc 1 (no line matched) is fine: the parser then uses the 2 week default
cfg() {
  local rc
  timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" grep -E "$CFG_RE" "$NODE_CFG" > "$1" 2> "$2"
  rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 1 ]
}

foundation() { # OUTFILE -> rc 0 if an answer was saved
  [ -n "$FOUNDATION_URL" ] || return 1
  timeout "$((FOUNDATION_TIMEOUT + 5))" "${CURL[@]}" -s --max-time "$FOUNDATION_TIMEOUT" \
    -H 'Content-Type: application/json' -d "$(body server_info)" "$FOUNDATION_URL" > "$1" 2>/dev/null && [ -s "$1" ]
}

emit() { # NOW ERR TEXT STDOUT
  local L="container=\"$CONTAINER\"" head
  head="# HELP pft_upgradewatch_up 1 if the last collection succeeded and every node field was valid
# TYPE pft_upgradewatch_up gauge
pft_upgradewatch_up{$L} $([ -z "$2" ] && echo 1 || echo 0)
# HELP pft_upgradewatch_collect_timestamp_seconds Unix time of the last collection attempt
# TYPE pft_upgradewatch_collect_timestamp_seconds gauge
pft_upgradewatch_collect_timestamp_seconds{$L} $1
"
  [ -z "$2" ] && head+="$3"$'\n'
  if [ "$4" = 1 ]; then printf '%s' "$head"
  else
    write_atomic "$TEXTFILE_DIR" "pft_upgradewatch_$CONTAINER.prom" "$head" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ -n "$2" ]; then printf 'pft-upgradewatch: %s: up 0\n' "$2" >&2; return 1; fi
  return 0
}

parse() { # DIR [FOUNDATION_FILE] -> TEXT on stdout, rc of the parser; errors in $ERRF
  python3 -I "$PARSER" --container "$CONTAINER" --info "$1/info.json" --feature "$1/feature.json" \
    --amendments "$1/amendments.json" --peers "$1/peers.json" --cfg "$1/cfg.txt" ${2:+--foundation "$2"} 2> "$ERRF"
}

check_common() {
  valid_name "$CONTAINER" || die "bad container name"
  [ -r "$PARSER" ] || die "parser not found: $PARSER"
}

collect() {
  local stdout=0 now text rc err="" d k f=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --stdout) stdout=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_common
  [[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad RPC_TIMEOUT"
  [[ "$FOUNDATION_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad FOUNDATION_TIMEOUT"
  [[ "$NODE_CFG" =~ ^/[A-Za-z0-9_./-]+$ ]] || die "bad NODE_CFG"
  now="${PFT_UW_NOW:-$(date +%s)}"
  d="$(mktemp -d)" || die "mktemp failed" 1
  ERRF="$d/err"
  for k in server_info feature peers amendments; do
    if ! rpc "$k" "$d/$k.json" "$ERRF"; then
      err="$k via docker exec $CONTAINER failed: $(head -c 120 "$ERRF")"; break
    fi
  done
  [ -z "$err" ] && mv "$d/server_info.json" "$d/info.json"
  if [ -z "$err" ] && ! cfg "$d/cfg.txt" "$ERRF"; then
    err="config grep via docker exec $CONTAINER failed: $(head -c 120 "$ERRF")"
  fi
  if [ -z "$err" ]; then
    foundation "$d/foundation.json" && f="$d/foundation.json"
    text="$(parse "$d" "$f")"; rc=$?
    if [ "$rc" != 0 ]; then err="$(head -c 200 "$ERRF")"; err="${err:-parser failed (rc $rc)}"
    elif [ -s "$ERRF" ]; then cat "$ERRF" >&2  # warnings only (foundation unknown)
    fi
  fi
  rm -rf "$d"
  emit "$now" "$err" "${text:-}" "$stdout"
}

replay() {
  local dir="" now text rc err="" f=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --fixtures) dir="${2:?}"; shift ;;
      --now) PFT_UW_NOW="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_common
  [[ "$CONTAINER" == drill-* ]] || die "replay names must start with drill- (never a real node's textfile)"
  [ -d "$dir" ] || die "replay needs --fixtures DIR"
  [[ "${PFT_UW_NOW:-0}" =~ ^[0-9]+$ ]] || die "bad --now"
  now="${PFT_UW_NOW:-$(date +%s)}"
  ERRF="$(mktemp)" || die "mktemp failed" 1
  [ -r "$dir/foundation.json" ] && f="$dir/foundation.json"
  text="$(parse "$dir" "$f")"; rc=$?
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
    /^# (HELP|TYPE) pft_upgradewatch_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_upgradewatch_[a-z_]+\{/) == 0) { printf "line %d: not a pft_upgradewatch_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_upgradewatch_up\{/) up = 1
      if ($0 ~ /^pft_upgradewatch_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_upgradewatch_up sample"; exit 1 }
      if (!ts) { print "no pft_upgradewatch_collect_timestamp_seconds sample"; exit 1 }
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
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-upgradewatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-upgradewatch-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_upgradewatch_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_upgradewatch_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_upgradewatch_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  replay) replay "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-upgradewatch validate FILE NAME"; valid_name "$2" || die "bad container name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-upgradewatch $VERSION" ;;
  *) die "usage: pft-upgradewatch collect|pull|replay|validate|version (see the header of this script)" ;;
esac
