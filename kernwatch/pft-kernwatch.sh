#!/usr/bin/env bash
# pft-kernwatch: host kernel-log monitor for a postfiatd validator or sentry, as Prometheus textfile metrics.
# Catches what the debug.log, cgroup and server_info monitors cannot see: OOM kills, hung tasks, soft/hard lockups,
# RCU stalls, oopses, block I/O and filesystem errors, machine checks, conntrack/SYN floods, NIC link loss,
# clocksource fallback and lost audit records. Read-only: one bounded `journalctl -k -o json` read per run.
#
# Usage: sudo pft-kernwatch collect [--textfile-dir DIR] [--stdout] [--from-boot-start]
#        sudo pft-kernwatch report [--since S] [--until S] [--boot B|all] [--format tsv|json]
#        sudo pft-kernwatch pull [--host NAME]          (validator: copy the sentry's textfile, see below)
#        pft-kernwatch validate FILE HOST               exit 0 if FILE is an acceptable textfile for HOST
#        pft-kernwatch check-catalogue                  validate the installed pattern catalogue
#        pft-kernwatch version
#
#  collect  kernwatch_parse.py reads the kernel journal after the cursor in STATE_DIR/state.json (at most
#           MAX_RECORDS records per run; pft_kernwatch_backlog 1 says the next run continues), classifies each record
#           with CATALOGUE (first match wins) and writes DIR/pft_kernwatch_HOST.prom atomically: per-pattern counters,
#           newest match time per class, records/malformed/cursor-reset/boot-change counters. A boot change finishes
#           the old boot after its cursor, then reads the new boot from its start. With no state the first run only
#           seeds the cursor at the newest record (no history is counted) unless --from-boot-start. If journalctl fails
#           the file holds only pft_kernwatch_up 0 (+ timestamp, catalogue info) and the state is not touched; exit 1.
#  report   read-only per-pattern summary of a journal range (count, first/last UTC, one redacted excerpt). No raw
#           kernel line, host name, IP or MAC address is ever printed. Exit 2 if MAX_REPORT records were reached.
#  pull     runs "$PULL_SSH cat -- REMOTE_DIR/pft_kernwatch_NAME.prom" (timeout PULL_TIMEOUT), validates it and
#           renames it into TEXTFILE_DIR, so the validator's single Prometheus + Alertmanager also alerts on the sentry.
#
# Exit codes: 0 ok, 1 journal read / fetch failed, 2 validation failed (or report truncated), 3 usage/config error.
# Conf: PFT_KW_CONF (/etc/pft-kernwatch.env, root-owned, sourced first): HOST_LABEL (validator; [a-z][a-z0-9_-]*,
#       never a hostname), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), STATE_DIR (/var/lib/pft-kernwatch),
#       MAX_RECORDS (20000), MAX_REPORT (500000), RUN_TIMEOUT (120), CATALOGUE
#       (/usr/local/lib/pft-kernwatch/catalogue.tsv), PULL_SSH (pull only), REMOTE_DIR (/var/lib/pft-exporter/textfile),
#       PULL_TIMEOUT (20), MAX_BYTES (65536)
# Test hooks: PFT_KW_HELPER (/usr/local/lib/pft-kernwatch/kernwatch_parse.py)  PFT_KW_NOW (epoch)
#             PFT_KW_JOURNALCTL and PFT_KW_BOOT_ID_FILE (passed through to the helper)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_KW_CONF:-/etc/pft-kernwatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
HOST_LABEL="${HOST_LABEL:-validator}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-kernwatch}"
MAX_RECORDS="${MAX_RECORDS:-20000}"
MAX_REPORT="${MAX_REPORT:-500000}"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"
LIBDIR=/usr/local/lib/pft-kernwatch
CATALOGUE="${CATALOGUE:-$LIBDIR/catalogue.tsv}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"
HELPER="${PFT_KW_HELPER:-$LIBDIR/kernwatch_parse.py}"

die() { printf 'pft-kernwatch: %s\n' "$1" >&2; exit "${2:-3}"; }
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
  posint "$MAX_RECORDS" || die "bad MAX_RECORDS"
  posint "$MAX_REPORT" || die "bad MAX_REPORT"
  posint "$RUN_TIMEOUT" || die "bad RUN_TIMEOUT"
  [ -r "$HELPER" ] || die "helper not found: $HELPER"
  [ -r "$CATALOGUE" ] || die "catalogue not found: $CATALOGUE"
}

collect() {
  local stdout=0 from=() text rc errf err now lock
  while [ $# -gt 0 ]; do
    case "$1" in
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --stdout) stdout=1 ;;
      --from-boot-start) from=(--from-boot-start) ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  check_common
  now="${PFT_KW_NOW:-$(date +%s)}"
  [[ "$now" =~ ^[0-9]+$ ]] || die "bad PFT_KW_NOW"
  { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"; } || die "cannot create $STATE_DIR" 1
  lock="$STATE_DIR/lock"
  exec 9> "$lock" || die "cannot open $lock" 1
  flock -n 9 || die "another collect is running" 1
  errf="$(mktemp)" || die "mktemp failed" 1
  text="$(timeout "$RUN_TIMEOUT" python3 -I "$HELPER" collect --catalogue "$CATALOGUE" --state "$STATE_DIR/state.json" \
    --host "$HOST_LABEL" --max "$MAX_RECORDS" --now "$now" "${from[@]}" 2> "$errf")"
  rc=$?
  err="$(head -c 300 "$errf")"; rm -f "$errf"
  if [ "$rc" = 124 ] || [ -z "$text" ]; then
    # timeout or a helper crash: still publish up 0 so a stuck collector is visible (the state file is untouched:
    # the helper writes it atomically, and only after a complete read)
    [ "$rc" = 124 ] && err="helper timed out after ${RUN_TIMEOUT}s"
    text="# HELP pft_kernwatch_up 1 if the last kernel journal read succeeded
# TYPE pft_kernwatch_up gauge
pft_kernwatch_up{host=\"$HOST_LABEL\"} 0
# HELP pft_kernwatch_collect_timestamp_seconds Unix time of the last collection attempt
# TYPE pft_kernwatch_collect_timestamp_seconds gauge
pft_kernwatch_collect_timestamp_seconds{host=\"$HOST_LABEL\"} $now
"
    [ "$rc" = 0 ] && rc=1
  else
    text+=$'\n'
  fi
  if [ "$stdout" = 1 ]; then printf '%s' "$text"
  else write_atomic "$TEXTFILE_DIR" "pft_kernwatch_$HOST_LABEL.prom" "$text" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ "$rc" = 3 ]; then die "helper refused: ${err:-usage}" 3; fi
  if [ "$rc" != 0 ]; then printf 'pft-kernwatch: %s: up 0\n' "${err:-helper failed (rc $rc)}" >&2; return 1; fi
  return 0
}

report() {
  check_common
  timeout "$RUN_TIMEOUT" python3 -I "$HELPER" report --catalogue "$CATALOGUE" --max "$MAX_REPORT" "$@"
}

# validate FILE HOST -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" host="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$host" '
    BEGIN { pre = "host=\"" n "\"" }
    /^# (HELP|TYPE) pft_kernwatch_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_kernwatch_[a-z_]+\{/) == 0) { printf "line %d: not a pft_kernwatch_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_kernwatch_up\{/) up = 1
      if ($0 ~ /^pft_kernwatch_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_kernwatch_up sample"; exit 1 }
      if (!ts) { print "no pft_kernwatch_collect_timestamp_seconds sample"; exit 1 }
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
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-kernwatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-kernwatch-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_kernwatch_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_kernwatch_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_kernwatch_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  report) report "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-kernwatch validate FILE HOST"; valid_host "$2" || die "bad host name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  check-catalogue) [ -r "$HELPER" ] || die "helper not found: $HELPER"
                   python3 -I "$HELPER" check-catalogue --catalogue "$CATALOGUE" ;;
  version) echo "pft-kernwatch $VERSION" ;;
  *) die "usage: pft-kernwatch collect|report|pull|validate|check-catalogue|version (see the header of this script)" ;;
esac
