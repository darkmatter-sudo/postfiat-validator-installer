#!/usr/bin/env bash
# pft-budget: measured resource budgets for the pft-* systemd units of a Post Fiat validator or sentry.
# Every add-on unit carries a MemoryMax picked at install time; nothing measured whether it still fits. The
# sampler (pft-budget-sampler.service, budget.py sample) polls the cgroup v2 files of every pft-*.service cgroup each
# second (kernel 5.15 has no memory.peak) and writes one JSONL record per invocation: peak memory (total and
# unreclaimable), CPU, IO, OOM kills, runtime, systemd Result and the caps in force. `report` turns the window into
# per-unit p50/max peaks, cap headroom and 30/90-day growth projections with OK/WARN/FAIL/UNCAPPED verdicts; `plan`,
# `apply` and `rollback` right-size MemoryMax through drop-ins, only inside a pft-maint window.
#
# Usage: sudo pft-budget report [--json] [--now EPOCH] [--data FILE...]   exit 0 OK, 2 WARN, 1 FAIL
#        sudo pft-budget collect [--stdout]           write DIR/pft_budget_HOST.prom (the report as metrics)
#        sudo pft-budget status                       sampler heartbeat age; exit 4 if stale or missing
#        sudo pft-budget plan [--allow-lower]         proposed MemoryMax drop-ins (JSON lines)
#        sudo pft-budget apply [--yes] [--allow-lower] write them (dry run without --yes; needs pft-maint active)
#        sudo pft-budget rollback [--yes]             undo the last apply (needs pft-maint active)
#        sudo pft-budget pull --host NAME             (validator: copy the peer's textfile through PULL_SSH)
#        pft-budget validate FILE NAME                exit 0 if FILE is an acceptable textfile for host NAME
#        pft-budget version
#
# Exit codes: 0 ok, 1 FAIL verdict / failed write / failed check, 2 WARN verdict / validation failed,
#             3 usage/config error, 4 refused or stale.
# Conf: PFT_BUD_CONF (/etc/pft-budget.env, root-owned, KEY=VALUE): HOST (validator|sentry), DATA_DIR
#       (/var/lib/pft-budget), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), PULL_SSH, REMOTE_DIR, PULL_TIMEOUT (20),
#       TEXT_MAX_BYTES (61440); the helper's keys are listed in budget.py (DEFAULTS).
# Test hooks: PFT_BUD_HELPER (/usr/local/lib/pft-budget/budget.py)  PFT_BUD_NOW  PFT_BUD_SYSTEMCTL  PFT_BUD_MAINT
#             PFT_BUD_HOST PFT_BUD_DATA_DIR PFT_BUD_TEXTFILE_DIR PFT_BUD_PULL_SSH PFT_BUD_REMOTE_DIR PFT_BUD_TEXT_MAX_BYTES PFT_BUD_STALE_SEC

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_BUD_CONF:-/etc/pft-budget.env}"
HELPER="${PFT_BUD_HELPER:-/usr/local/lib/pft-budget/budget.py}"
conf_get() { # KEY DEFAULT: read one KEY=VALUE from the root-owned conf (never sourced: the helper parses it too)
  local v=""
  if [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ]; then
    v="$(sed -n "s/^$1=//p" "$CONF" | tail -n 1)"; v="${v%\"}"; v="${v#\"}"
  fi
  printf '%s' "${v:-$2}"
}
HOST="${PFT_BUD_HOST:-$(conf_get HOST local)}"
DATA_DIR="${PFT_BUD_DATA_DIR:-$(conf_get DATA_DIR /var/lib/pft-budget)}"
TEXTFILE_DIR="${PFT_BUD_TEXTFILE_DIR:-$(conf_get TEXTFILE_DIR /var/lib/pft-exporter/textfile)}"
PULL_SSH="${PFT_BUD_PULL_SSH:-$(conf_get PULL_SSH "")}"
REMOTE_DIR="${PFT_BUD_REMOTE_DIR:-$(conf_get REMOTE_DIR /var/lib/pft-exporter/textfile)}"
PULL_TIMEOUT="$(conf_get PULL_TIMEOUT 20)"
TEXT_MAX_BYTES="${PFT_BUD_TEXT_MAX_BYTES:-$(conf_get TEXT_MAX_BYTES 61440)}"
STALE_SEC="${PFT_BUD_STALE_SEC:-$(conf_get STALE_SEC 300)}"

die() { printf 'pft-budget: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_host() { [[ "$1" =~ ^[a-z][a-z0-9-]{0,31}$ ]]; }
helper() { python3 -I "$HELPER" --conf "$CONF" "$@"; }

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

collect() {
  local stdout=0 text rc size file
  while [ $# -gt 0 ]; do
    case "$1" in
      --stdout) stdout=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_host "$HOST" || die "bad HOST in $CONF"
  if ! [[ "$TEXT_MAX_BYTES" =~ ^[1-9][0-9]{3,4}$ ]] || [ "$TEXT_MAX_BYTES" -gt 65000 ]; then die "bad TEXT_MAX_BYTES (<= 65000)"; fi
  file="pft_budget_$HOST.prom"
  text="$(helper metrics)"; rc=$?
  text+=$'\n'
  if [ "$rc" != 0 ]; then
    text="# HELP pft_budget_up 1 when the report was built from readable data
# TYPE pft_budget_up gauge
pft_budget_up{host=\"$HOST\"} 0
"
  fi
  size="$(printf '%s' "$text" | wc -c)"
  if [ "$size" -gt "$TEXT_MAX_BYTES" ]; then
    rc=1
    text="# HELP pft_budget_up 1 when the report was built from readable data
# TYPE pft_budget_up gauge
pft_budget_up{host=\"$HOST\"} 0
"
    printf 'pft-budget: textfile %s B is over TEXT_MAX_BYTES %s: up 0\n' "$size" "$TEXT_MAX_BYTES" >&2
  fi
  if [ "$stdout" = 1 ]; then printf '%s' "$text"
  else write_atomic "$TEXTFILE_DIR" "$file" "$text" || die "cannot write $TEXTFILE_DIR" 1
  fi
  [ "$rc" = 0 ] || return 1
}

status() {
  local hb now age
  now="${PFT_BUD_NOW:-$(date +%s)}"; now="${now%.*}"
  hb="$(cat "$DATA_DIR/heartbeat" 2>/dev/null)"
  if ! [[ "$hb" =~ ^[0-9]+$ ]]; then echo "sampler: no heartbeat in $DATA_DIR (not running?)"; return 4; fi
  age=$(( now - hb ))
  if [ "$age" -gt "$STALE_SEC" ]; then echo "sampler: STALE, last scan ${age}s ago (> ${STALE_SEC}s)"; return 4; fi
  echo "sampler: ok, last scan ${age}s ago; data $(du -sh "$DATA_DIR" 2>/dev/null | cut -f1) in $DATA_DIR"
}

# validate FILE NAME -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" name="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$TEXT_MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v n="$name" '
    BEGIN { pre = "host=\"" n "\"" }
    /^# (HELP|TYPE) pft_budget_[a-z0-9_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_budget_[a-z0-9_]+\{/) == 0) { printf "line %d: not a pft_budget_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_budget_up\{/) up = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_budget_up sample"; exit 1 }
    }' "$f"
}

pull() {
  local name="" tmp why
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) name="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_host "$name" || die "pull needs --host NAME (e.g. sentry)"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-budget-$name.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_budget_$name.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_budget_$name.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_budget_$name.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  report|plan|apply|rollback|metrics) [ -r "$HELPER" ] || die "helper not found: $HELPER"; helper "$cmd" "$@" ;;
  collect) [ -r "$HELPER" ] || die "helper not found: $HELPER"; collect "$@" ;;
  status) status ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-budget validate FILE NAME"; valid_host "$2" || die "bad host name"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-budget $VERSION" ;;
  *) die "usage: pft-budget report|collect|status|plan|apply|rollback|pull|validate|version (see the header)" ;;
esac
