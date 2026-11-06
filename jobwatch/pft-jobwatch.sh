#!/usr/bin/env bash
# pft-jobwatch: scheduled-job outcome monitor for a postfiatd validator or sentry, as Prometheus textfile metrics.
# Every add-on in this repo reports through a timer; a timer that is disabled, removed, failing or no longer firing
# leaves its last textfile in place, so the stale numbers still look healthy. jobwatch watches the timers themselves.
# Read-only: the only command it runs is `systemctl show` (it never starts, stops, enables or resets a unit).
#
# Usage: sudo pft-jobwatch collect [--textfile-dir DIR] [--stdout]
#        sudo pft-jobwatch inventory [--format tsv|json]   table of every watched job (state not written)
#        sudo pft-jobwatch forget JOB.timer                drop a removed job from the state (clears its alert)
#        sudo pft-jobwatch pull [--host NAME]              (validator: copy the sentry's textfile, see below)
#        pft-jobwatch validate FILE HOST                   exit 0 if FILE is an acceptable textfile for HOST
#        pft-jobwatch version
#
#  collect  jobwatch_lib.py lists the loaded timers matching JOB_GLOBS plus every job already in STATE_DIR/state.json
#           (so a timer that was disabled and unloaded, or deleted, stays visible as present 0 / disabled 1 until
#           `forget`), reads each timer and its service with `systemctl show`, and writes
#           DIR/pft_jobwatch_HOST.prom atomically: per job present, disabled, running, never_run, failed,
#           consecutive_failures, missed, interval, last trigger, last success, next elapse, observed run counters.
#           If systemctl fails the file holds only pft_jobwatch_up 0 (+ timestamp) and the state is untouched; exit 1.
#  pull     runs "$PULL_SSH cat -- REMOTE_DIR/pft_jobwatch_NAME.prom" (timeout PULL_TIMEOUT), validates it and
#           renames it into TEXTFILE_DIR, so the validator's single Prometheus + Alertmanager also alerts on the sentry.
#
# Exit codes: 0 ok, 1 systemctl / fetch failed, 2 validation failed, 3 usage/config error.
# Conf: PFT_JW_CONF (/etc/pft-jobwatch.env, root-owned, sourced first): HOST_LABEL (validator; [a-z][a-z0-9_-]*,
#       never a hostname), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), STATE_DIR (/var/lib/pft-jobwatch),
#       JOB_GLOBS ("pft-*.timer postfiat*.timer"), RUN_TIMEOUT (90), PULL_SSH (pull only),
#       REMOTE_DIR (/var/lib/pft-exporter/textfile), PULL_TIMEOUT (20), MAX_BYTES (65536: the pft exporter skips
#       bigger textfiles), TEXT_BUDGET (61440: collect writes up 0 instead of a file the exporter would drop)
# Test hooks: PFT_JW_HELPER (/usr/local/lib/pft-jobwatch/jobwatch_lib.py)  PFT_JW_NOW (epoch)
#             PFT_JW_SYSTEMCTL (passed through to the helper)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_JW_CONF:-/etc/pft-jobwatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
HOST_LABEL="${HOST_LABEL:-validator}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-jobwatch}"
JOB_GLOBS="${JOB_GLOBS:-pft-*.timer postfiat*.timer}"
RUN_TIMEOUT="${RUN_TIMEOUT:-90}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"
TEXT_BUDGET="${TEXT_BUDGET:-61440}"
HELPER="${PFT_JW_HELPER:-/usr/local/lib/pft-jobwatch/jobwatch_lib.py}"

die() { printf 'pft-jobwatch: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_host() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,30}$ ]]; }
posint() { [[ "$1" =~ ^[1-9][0-9]{0,8}$ ]]; }

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

check_common() {
  valid_host "$HOST_LABEL" || die "bad HOST_LABEL"
  posint "$RUN_TIMEOUT" || die "bad RUN_TIMEOUT"
  posint "$TEXT_BUDGET" || die "bad TEXT_BUDGET"
  [ -r "$HELPER" ] || die "helper not found: $HELPER"
  globs=()
  local g
  for g in $JOB_GLOBS; do
    [[ "$g" =~ ^[A-Za-z0-9_.@*?-]+\.timer$ ]] || die "bad JOB_GLOBS entry: $g"
    globs+=(--glob "$g")
  done
  [ "${#globs[@]}" -gt 0 ] || die "JOB_GLOBS is empty"
  now="${PFT_JW_NOW:-$(date +%s)}"
  [[ "$now" =~ ^[0-9]+$ ]] || die "bad PFT_JW_NOW"
}

lock_state() {
  { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"; } || die "cannot create $STATE_DIR" 1
  exec 9> "$STATE_DIR/lock" || die "cannot open $STATE_DIR/lock" 1
  flock -w 30 9 || die "another pft-jobwatch run holds the lock" 1
}

collect() {
  local stdout=0 text rc errf err
  while [ $# -gt 0 ]; do
    case "$1" in
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --stdout) stdout=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_common
  lock_state
  errf="$(mktemp)" || die "mktemp failed" 1
  text="$(timeout "$RUN_TIMEOUT" python3 -I "$HELPER" collect --host "$HOST_LABEL" --state "$STATE_DIR/state.json" \
    --now "$now" "${globs[@]}" 2> "$errf")"
  rc=$?
  err="$(head -c 300 "$errf")"; rm -f "$errf"
  if [ "$rc" = 0 ] && [ "${#text}" -gt "$TEXT_BUDGET" ]; then
    # the exporter skips a textfile over 64 KiB WHOLE, which would make every jobwatch series vanish silently
    # (update run 09); publish up 0 instead, so PFTJobwatchStale fires
    err="textfile would be ${#text} bytes, over TEXT_BUDGET $TEXT_BUDGET (narrow JOB_GLOBS)"; rc=1; text=""
  fi
  if [ "$rc" != 0 ] || [ -z "$text" ]; then
    # systemctl failure, timeout or a helper crash: still publish up 0 so a broken collector is visible
    # (the helper writes the state only after a complete inventory)
    [ "$rc" = 124 ] && err="helper timed out after ${RUN_TIMEOUT}s"
    text="# HELP pft_jobwatch_up 1 if the last systemctl inventory succeeded
# TYPE pft_jobwatch_up gauge
pft_jobwatch_up{host=\"$HOST_LABEL\"} 0
# HELP pft_jobwatch_collect_timestamp_seconds Unix time of the last collection attempt
# TYPE pft_jobwatch_collect_timestamp_seconds gauge
pft_jobwatch_collect_timestamp_seconds{host=\"$HOST_LABEL\"} $now
"
    [ "$rc" = 0 ] && rc=1
  fi
  if [ "$stdout" = 1 ]; then printf '%s' "$text"
  else write_atomic "$TEXTFILE_DIR" "pft_jobwatch_$HOST_LABEL.prom" "$text" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ "$rc" = 3 ]; then die "helper refused: ${err:-usage}" 3; fi
  if [ "$rc" != 0 ]; then printf 'pft-jobwatch: %s: up 0\n' "${err:-helper failed (rc $rc)}" >&2; return 1; fi
  return 0
}

inventory() {
  check_common
  timeout "$RUN_TIMEOUT" python3 -I "$HELPER" inventory --host "$HOST_LABEL" --state "$STATE_DIR/state.json" \
    --now "$now" "${globs[@]}" "$@"
}

forget() {
  [ $# -eq 1 ] || die "usage: pft-jobwatch forget JOB.timer"
  [[ "$1" =~ ^[A-Za-z0-9:_.@-]+\.timer$ ]] || die "bad job name"
  [ -r "$HELPER" ] || die "helper not found: $HELPER"
  lock_state
  python3 -I "$HELPER" forget --state "$STATE_DIR/state.json" "$1"
}

# validate FILE HOST -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" host="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$host" '
    BEGIN { pre = "host=\"" n "\"" }
    /^# (HELP|TYPE) pft_jobwatch_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_jobwatch_[a-z_]+\{/) == 0) { printf "line %d: not a pft_jobwatch_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_jobwatch_up\{/) up = 1
      if ($0 ~ /^pft_jobwatch_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_jobwatch_up sample"; exit 1 }
      if (!ts) { print "no pft_jobwatch_collect_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local name=sentry tmp why
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) name="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_host "$name" || die "bad host name"
  [ "$name" != "$HOST_LABEL" ] || die "refusing to pull over this host's own textfile ($name)"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-jobwatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-jobwatch-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_jobwatch_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_jobwatch_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_jobwatch_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

globs=(); now=0
cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  inventory) inventory "$@" ;;
  forget) forget "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-jobwatch validate FILE HOST"; valid_host "$2" || die "bad host name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-jobwatch $VERSION" ;;
  *) die "usage: pft-jobwatch collect|inventory|forget|pull|validate|version (see the header of this script)" ;;
esac
