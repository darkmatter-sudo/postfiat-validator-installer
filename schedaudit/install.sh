#!/usr/bin/env bash
# Install / uninstall pft-schedaudit (+ 5-minute sandboxed timer). Idempotent: a second run changes nothing.
#   sudo ./install.sh [--host NAME] [--reason TEXT]   script -> /usr/local/bin/pft-schedaudit, helper ->
#       /usr/local/lib/pft-schedaudit/, pft-schedaudit.service/.timer, state dir /var/lib/pft-schedaudit (0700),
#       an empty allowlist /etc/pft-schedaudit.allow (0600, only if missing).
#       NAME (default validator; sentry on the sentry) goes to HOST_LABEL in /etc/pft-schedaudit.env (0600 root).
#       First install (no accepted entry set yet): --reason is required and becomes the first `accept` (review
#       `sudo pft-schedaudit audit` first: accept blesses what is there). Runs one collection through the sandboxed
#       unit (must give up 1), then enables pft-schedaudit.timer (every 5 min at :20) and collects once more so the
#       new timer is in the accepted set.
#   sudo ./install.sh --pull [--host sentry] [--reason TEXT]   on the host that runs ../alerts: pft-schedaudit-pull.service/.timer;
#       needs PULL_SSH in /etc/pft-schedaudit.env (see pft-schedaudit.env.example). Runs one pull (must exit 0), then
#       enables pft-schedaudit-pull.timer (:01:50, :06:50, ...; the peer collects at :00:20, :05:20, ...).
#   sudo ./install.sh --uninstall | --pull --uninstall   disable the timer, remove the textfile (keeps state + conf)
# Alert rules: ../alerts/schedaudit.rules.yml, listed in ../alerts/prometheus.yml. rulecheck lines: see README.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, helper, units, conf).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-schedaudit
LIBDIR=/usr/local/lib/pft-schedaudit
CONF=/etc/pft-schedaudit.env
host=""; uninstall=false; pull=false; reason=""
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    --reason) reason="${2:?}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
if [ -z "$host" ]; then if $pull; then host=sentry; else host=validator; fi; fi
[[ "$host" =~ ^[a-z][a-z0-9_-]{0,30}$ ]] || { echo "bad host label" >&2; exit 3; }

same() { [ -f "$2" ] && cmp -s "$1" "$2"; }
put() { # SRC DST MODE: install only if the bytes differ, report either way
  if same "$1" "$2" && [ "$(stat -c %a "$2")" = "$3" ]; then log "unchanged $2"; else
    install -D -m "$3" "$1" "$2"; log "installed $2 (sha256 $(sha256sum < "$1" | cut -c1-64))"; changed=true; fi
}
changed=false
install_bin() {
  put "$HERE/pft-schedaudit.sh" /usr/local/bin/pft-schedaudit 755
  put "$HERE/schedaudit_lib.py" "$LIBDIR/schedaudit_lib.py" 644
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}
conf_set() { # KEY VALUE: set KEY in the root-owned conf (create it 0600)
  [ -f "$CONF" ] || { install -m 600 /dev/null "$CONF"; echo "# pft-schedaudit settings (see schedaudit/pft-schedaudit.env.example)" > "$CONF"; }
  if grep -qx "$1=$2" "$CONF"; then return 0; fi
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
  log "set $1=$2 in $CONF"; changed=true
}
run_unit() { # UNIT: start it, print this run's journal (a finished oneshot has no InvocationID left), fail if it failed
  local t0; t0="$(date -u +%s)"
  systemctl start "$1" || true
  journalctl -u "$1" --since "@$t0" --no-pager --utc -o cat | grep -v 'pam_limits\|pam_unix' || true
  if systemctl is-failed -q "$1"; then log "ERROR: $1 failed"; exit 1; fi
}

if $pull; then
  if $uninstall; then
    systemctl disable --now pft-schedaudit-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_schedaudit_$host.prom"
    log "disabled pft-schedaudit-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-schedaudit.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  [ "$host" = sentry ] || { echo "the pull unit is for --host sentry" >&2; exit 3; }
  install_bin
  put "$HERE/systemd/pft-schedaudit-pull.service" /etc/systemd/system/pft-schedaudit-pull.service 644
  put "$HERE/systemd/pft-schedaudit-pull.timer" /etc/systemd/system/pft-schedaudit-pull.timer 644
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  run_unit pft-schedaudit-pull.service
  grep -E '^pft_schedaudit_(up|collect_timestamp_seconds|unexpected)\{' "$TEXTDIR/pft_schedaudit_$host.prom"
  systemctl enable --now pft-schedaudit-pull.timer 2>&1 | sed 's/^/  /'
  log "pft-schedaudit-pull.timer $(systemctl is-active pft-schedaudit-pull.timer) (:01:50 every 5 min); changed=$changed"
  # the pull timer is itself a new scheduled entry on this host
  if [ -n "$reason" ] && [ -s "$STATEDIR/state.json" ]; then
    /usr/local/bin/pft-schedaudit accept --reason "$reason"
    run_unit pft-schedaudit.service
  else
    log "NOTE: pft-schedaudit-pull.timer is a new scheduled entry here: review 'pft-schedaudit audit', then accept it"
  fi
  /usr/local/bin/pft-schedaudit audit | grep -E '^(NEW|REMOVED|SUMMARY)' || true
  exit 0
fi
if $uninstall; then
  systemctl disable --now pft-schedaudit.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_schedaudit_$host.prom"
  log "disabled pft-schedaudit.timer, removed its textfile (kept $STATEDIR, $CONF and the script/units)"
  exit 0
fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
command -v systemctl >/dev/null || { echo "systemctl missing" >&2; exit 3; }
install_bin
install -d -m 700 "$STATEDIR"
conf_set HOST_LABEL "$host"
if [ ! -f /etc/pft-schedaudit.allow ]; then
  install -m 600 /dev/null /etc/pft-schedaudit.allow
  printf '%s\n' "# pft-schedaudit allowlist: CHECK ENTRY_GLOB PATH_GLOB REASON (reason required; see README)" > /etc/pft-schedaudit.allow
  log "created empty /etc/pft-schedaudit.allow"; changed=true
fi
if [ ! -s "$STATEDIR/state.json" ] && [ -z "$reason" ]; then
  echo "first install: pass --reason TEXT (it becomes the first accept; review 'pft-schedaudit audit' first)" >&2; exit 3
fi
put "$HERE/systemd/pft-schedaudit.service" /etc/systemd/system/pft-schedaudit.service 644
put "$HERE/systemd/pft-schedaudit.timer" /etc/systemd/system/pft-schedaudit.timer 644
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
run_unit pft-schedaudit.service
grep -E '^pft_schedaudit_(up|collect_timestamp_seconds)\{' "$TEXTDIR/pft_schedaudit_$host.prom"
grep -qx "pft_schedaudit_up{host=\"$host\"} 1" "$TEXTDIR/pft_schedaudit_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-schedaudit.timer 2>&1 | sed 's/^/  /'
log "pft-schedaudit.timer $(systemctl is-active pft-schedaudit.timer) (every 5 min at :20); changed=$changed"
if [ -n "$reason" ]; then
  # after the enable, so the schedaudit timer itself is part of the accepted set
  /usr/local/bin/pft-schedaudit accept --reason "$reason"
fi
log "second collection (accepted set in place):"
run_unit pft-schedaudit.service
grep -E '^pft_schedaudit_(up|unexpected|allowlist_unused)\{' "$TEXTDIR/pft_schedaudit_$host.prom"
log "remember: sudo pft-integrity accept --reason 'pft-schedaudit installed'"
