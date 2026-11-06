#!/usr/bin/env bash
# pft-schedaudit: scheduled-execution entry-point audit for a postfiatd validator or sentry, as a table/JSON report and
# Prometheus textfile metrics. ../jobwatch watches the OUTCOME of the pft-*/postfiat* timers; schedaudit inventories
# EVERY way root (or anyone) can get code run on a schedule: /etc/crontab, /etc/cron.d, user crontab spools,
# /etc/cron.{hourly,daily,weekly,monthly} (run-parts), /etc/anacrontab, at spools and all systemd timers (enabled,
# disabled, masked; plus timer files in user-unit dirs), including commented-out cron lines and run-parts names that
# run-parts skips, and checks each one (schedaudit_lib.py CHECKS):
#   chain_writable / chain_owner  a file the job runs or reads, or a parent dir, is writable by / owned by non-root
#   writable_dir                  the job runs something under /tmp, /var/tmp, /dev/shm, /home, ...
#   pkg_modified                  a packaged script/unit/conffile differs from dpkg's md5sum
#   untracked                     an unpackaged file nobody tracks (fixed by the pft-integrity scope hook below)
#   nonsystem_user                the job runs as a login user (uid >= UID_MIN) or comes from a user crontab
#   timer_target                  a timer whose unit is missing/masked or whose ExecStart binary is missing
# and compares the entry set with the last `accept` (a changed line = one new + one removed id).
#
# Usage: sudo pft-schedaudit collect [--textfile-dir DIR] [--stdout]   write pft_schedaudit_HOST.prom atomically
#        sudo pft-schedaudit audit [--format tsv|json]                 findings table; exit 1 if anything unexpected
#        sudo pft-schedaudit inventory [--format tsv|json]             every entry (no checks)
#        sudo pft-schedaudit apply [--dry-run]                         chmod go-w on fixable chain_writable paths
#        sudo pft-schedaudit accept --reason "why"                     record the current entry set as expected
#        sudo pft-schedaudit scope                                     files pft-integrity tracks as sched:* items
#        sudo pft-schedaudit pull [--host NAME]                        (validator: copy the sentry's textfile)
#        pft-schedaudit validate FILE HOST                             exit 0 if FILE is an acceptable textfile
#        pft-schedaudit version
#
#  apply   is permissions-only: it never edits, moves or deletes a file and never changes an owner. Every change is
#          appended to STATE_DIR/apply.log (time, path, old -> new mode); the audit is re-run afterwards.
#  accept  appends time + reason to STATE_DIR/accept.log. Until the first accept, unexpected{kind="unaccepted"} is 1.
#  scope   ../integrity/pft-integrity.sh (collect_sched) adds every listed file as a sched:PATH item and every listed
#          directory as a listing item, so a new or edited cron job changes the integrity manifest too. When the
#          installed pft-integrity has that hook, audit/collect pass --integrity-hook and `untracked` clears.
#
# Exit codes: 0 ok, 1 findings / unexpected entries (collect: still 0 if the file was written), 2 collection or
#             validation failed, 3 usage/config error.
# Conf: PFT_SA_CONF (/etc/pft-schedaudit.env, root-owned, sourced first): HOST_LABEL (validator; never a hostname),
#       TEXTFILE_DIR (/var/lib/pft-exporter/textfile), STATE_DIR (/var/lib/pft-schedaudit),
#       ALLOW_FILE (/etc/pft-schedaudit.allow: "CHECK ENTRY_GLOB PATH_GLOB REASON", reason required),
#       INTEGRITY_BIN (/usr/local/bin/pft-integrity), RUN_TIMEOUT (120), PULL_SSH (pull only),
#       REMOTE_DIR (/var/lib/pft-exporter/textfile), PULL_TIMEOUT (20), MAX_BYTES (65536), TEXT_BUDGET (61440)
# Test hooks: PFT_SA_HELPER (/usr/local/lib/pft-schedaudit/schedaudit_lib.py)  PFT_SA_NOW (epoch)
#             PFT_SA_ROOT (/)  PFT_SA_SYSTEMCTL (systemctl)  PFT_SA_TRUSTED_UID (0)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_SA_CONF:-/etc/pft-schedaudit.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = "${PFT_SA_TRUSTED_UID:-0}" ] && . "$CONF"
HOST_LABEL="${HOST_LABEL:-validator}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-schedaudit}"
ALLOW_FILE="${ALLOW_FILE:-/etc/pft-schedaudit.allow}"
INTEGRITY_BIN="${INTEGRITY_BIN:-/usr/local/bin/pft-integrity}"
RUN_TIMEOUT="${RUN_TIMEOUT:-120}"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"
TEXT_BUDGET="${TEXT_BUDGET:-61440}"
HELPER="${PFT_SA_HELPER:-/usr/local/lib/pft-schedaudit/schedaudit_lib.py}"

die() { printf 'pft-schedaudit: %s\n' "$1" >&2; exit "${2:-3}"; }
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
  now="${PFT_SA_NOW:-$(date +%s)}"
  [[ "$now" =~ ^[0-9]+$ ]] || die "bad PFT_SA_NOW"
  common=(--root "${PFT_SA_ROOT:-/}" --state "$STATE_DIR/state.json" --allow "$ALLOW_FILE"
          --systemctl "${PFT_SA_SYSTEMCTL:-systemctl}" --trusted-uid "${PFT_SA_TRUSTED_UID:-0}" --now "$now")
  # the installed pft-integrity tracks `scope` output only if it carries the collect_sched hook
  if [ -r "$INTEGRITY_BIN" ] && grep -q '^collect_sched()' "$INTEGRITY_BIN"; then common+=(--integrity-hook); fi
}

lock_state() {
  { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"; } || die "cannot create $STATE_DIR" 1
  exec 9> "$STATE_DIR/lock" || die "cannot open $STATE_DIR/lock" 1
  flock -w 30 9 || die "another pft-schedaudit run holds the lock" 1
}

helper() { timeout "$RUN_TIMEOUT" python3 -I "$HELPER" "$@" < /dev/null; }

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
  text="$(helper prom --host "$HOST_LABEL" "${common[@]}" 2> "$errf")"
  rc=$?
  err="$(head -c 300 "$errf")"; rm -f "$errf"
  [ "$rc" = 1 ] && rc=0   # findings are data here, not a collector failure
  if [ "$rc" = 0 ] && [ "${#text}" -gt "$TEXT_BUDGET" ]; then
    err="textfile would be ${#text} bytes, over TEXT_BUDGET $TEXT_BUDGET"; rc=2; text=""
  fi
  if [ "$rc" != 0 ] || ! grep -q '^pft_schedaudit_up{' <<<"$text"; then
    [ "$rc" = 124 ] && err="helper timed out after ${RUN_TIMEOUT}s"
    text="# HELP pft_schedaudit_up 1 if the last audit could read every scheduling source.
# TYPE pft_schedaudit_up gauge
pft_schedaudit_up{host=\"$HOST_LABEL\"} 0
# HELP pft_schedaudit_collect_timestamp_seconds Unix time of the last audit run.
# TYPE pft_schedaudit_collect_timestamp_seconds gauge
pft_schedaudit_collect_timestamp_seconds{host=\"$HOST_LABEL\"} $now
"
    [ "$rc" = 0 ] && rc=2
  fi
  if [ "$stdout" = 1 ]; then printf '%s' "$text"
  else write_atomic "$TEXTFILE_DIR" "pft_schedaudit_$HOST_LABEL.prom" "$text" || die "cannot write $TEXTFILE_DIR" 1
  fi
  if [ "$rc" = 3 ]; then die "helper refused: ${err:-usage}" 3; fi
  if [ "$rc" != 0 ]; then printf 'pft-schedaudit: %s: up 0\n' "${err:-helper failed (rc $rc)}" >&2; return 2; fi
  return 0
}

apply() {
  local dry=() out rc
  case "${1:-}" in --dry-run) dry=(--dry-run) ;; "") ;; *) die "usage: pft-schedaudit apply [--dry-run]" ;; esac
  check_common
  lock_state
  out="$(helper apply "${dry[@]}" "${common[@]}")"; rc=$?
  printf '%s\n' "$out"
  if grep -qE '^(FIXED|FAILED)' <<<"$out"; then   # only a real apply prints these (--dry-run prints PLAN)
    grep -E '^(FIXED|FAILED)' <<<"$out" | sed "s/^/$(date -u +%FT%TZ) by ${SUDO_USER:-$(id -un)}\t/" >> "$STATE_DIR/apply.log"
  fi
  return "$rc"
}

accept() {
  if [ $# -ne 2 ] || [ "$1" != --reason ] || [ -z "$2" ]; then die 'usage: pft-schedaudit accept --reason "why"'; fi
  check_common
  lock_state
  local out rc
  out="$(helper accept --reason "$2" "${common[@]}")"; rc=$?
  printf '%s\n' "$out"
  [ "$rc" = 0 ] && printf '%s\tby %s\t%s\n' "$(date -u +%FT%TZ)" "${SUDO_USER:-$(id -un)}" "$out" >> "$STATE_DIR/accept.log"
  return "$rc"
}

# validate FILE HOST -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" host="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$host" '
    BEGIN { pre = "host=\"" n "\"" }
    /^# (HELP|TYPE) pft_schedaudit_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_schedaudit_[a-z_]+\{/) == 0) { printf "line %d: not a pft_schedaudit_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_schedaudit_up\{/) up = 1
      if ($0 ~ /^pft_schedaudit_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_schedaudit_up sample"; exit 1 }
      if (!ts) { print "no pft_schedaudit_collect_timestamp_seconds sample"; exit 1 }
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
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-schedaudit.env)"
  posint "$PULL_TIMEOUT" || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-schedaudit-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_schedaudit_$name.prom" > "$tmp" 2>/dev/null < /dev/null; then
    rm -f "$tmp"; die "fetch of pft_schedaudit_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_schedaudit_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

common=(); now=0
cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  audit|inventory)
    check_common
    helper "$cmd" "${common[@]}" "$@" ;;
  scope) [ $# -eq 0 ] || die "usage: pft-schedaudit scope"; check_common; helper scope "${common[@]}" ;;
  apply) apply "$@" ;;
  accept) accept "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-schedaudit validate FILE HOST"; valid_host "$2" || die "bad host name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-schedaudit $VERSION" ;;
  *) die "usage: pft-schedaudit collect|audit|inventory|apply|accept|scope|pull|validate|version (see the header)" ;;
esac
