#!/usr/bin/env bash
# Install / uninstall pft-backfill (+ 5-minute status timer, opt-in hourly repair timer). Installing changes neither
# postfiatd.cfg nor the node, and runs no repair.
#   sudo ./install.sh [--host LABEL] [--container NAME] [--enable-repair]
#       script -> /usr/local/bin/pft-backfill, parser -> /usr/local/lib/pft-backfill/, writes HOST_LABEL/CONTAINER
#       into /etc/pft-backfill.env, adds the textfile line to /etc/pft-rulecheck.conf if pft-rulecheck is installed,
#       runs one status check through the sandboxed unit (its textfile must pass `validate`), enables
#       pft-backfill.timer. --enable-repair also installs + enables pft-backfill-repair.timer (hourly, default caps).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-backfill-pull.service/.timer; needs
#       PULL_SSH (and PEER_LABEL, default sentry) in /etc/pft-backfill.env. One pull (must exit 0), then the timer.
#   sudo ./install.sh --uninstall | --pull --uninstall   disables the timers and removes the textfiles.
# Alert rules: ../alerts/backfill.rules.yml, listed in ../alerts/prometheus.yml.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, units, env).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
CONF=/etc/pft-backfill.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_backfill_*.prom  20m  pft_backfill_status_timestamp_seconds'
label=""; container=""; uninstall=false; pull=false; repair=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) label="${2:?}"; shift ;;
    --container) container="${2:?}"; shift ;;
    --enable-repair) repair=true ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
[ -z "$label" ] || [[ "$label" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || { echo "bad host label" >&2; exit 3; }
[ -z "$container" ] || [[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { echo "bad container" >&2; exit 3; }
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }
conf_set() { # conf_set KEY VALUE
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
}
install_bin() {
  install -m 755 "$HERE/pft-backfill.sh" /usr/local/bin/pft-backfill
  install -d -m 755 /usr/local/lib/pft-backfill
  install -m 644 "$HERE/backfill_parse.py" /usr/local/lib/pft-backfill/backfill_parse.py
  log "installed /usr/local/bin/pft-backfill (sha256 $(sha256sum < "$HERE/pft-backfill.sh" | cut -c1-64))"
  log "installed /usr/local/lib/pft-backfill/backfill_parse.py (sha256 $(sha256sum < "$HERE/backfill_parse.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-backfill-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_backfill_$peer.prom" "$TEXTDIR/pft_backfill_repair_$peer.prom"
    log "disabled pft-backfill-pull.timer, removed the pulled textfiles"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-backfill.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  install -m 644 "$HERE/systemd/pft-backfill-pull.service" "$HERE/systemd/pft-backfill-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-backfill-pull.service || true
  if systemctl is-failed -q pft-backfill-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-backfill-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_backfill_(up|missing_ledgers)\{" "$TEXTDIR/pft_backfill_$peer.prom"
  systemctl enable --now pft-backfill-pull.timer
  log "enabled pft-backfill-pull.timer (every 5 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  systemctl disable --now pft-backfill.timer pft-backfill-repair.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_backfill.prom" "$TEXTDIR/pft_backfill_repair.prom"
  log "disabled pft-backfill(.repair).timer, removed their textfiles"
  exit 0
fi
install_bin
[ -f "$CONF" ] || printf '# pft-backfill config (see pft-backfill.env.example)\n' > "$CONF"
conf_set HOST_LABEL "$host"
[ -n "$container" ] && conf_set CONTAINER "$container"
[ -n "$(conf_get CONTAINER)" ] || conf_set CONTAINER "$([ "$host" = sentry ] && echo postfiatd-sentry || echo postfiatd)"
chown root:root "$CONF"; chmod 600 "$CONF"
if [ -f "$RC_CONF" ] && ! grep -q 'pft_backfill_' "$RC_CONF"; then
  printf '# pft-backfill (status every 5 min; sentry copy pulled every 5 min)\n%s\n' "$RC_LINE" >> "$RC_CONF"
  log "added the pft_backfill textfile line to $RC_CONF"
fi
install -m 644 "$HERE/systemd/pft-backfill.service" "$HERE/systemd/pft-backfill.timer" \
  "$HERE/systemd/pft-backfill-repair.service" "$HERE/systemd/pft-backfill-repair.timer" /etc/systemd/system/
systemctl daemon-reload
log "first status check (through the sandboxed unit, HOST_LABEL=$host, CONTAINER=$(conf_get CONTAINER)):"
systemctl start pft-backfill.service || true
if systemctl is-failed -q pft-backfill.service; then
  log "ERROR: first status check failed"; journalctl -u pft-backfill.service -n 5 --no-pager --utc; exit 1
fi
/usr/local/bin/pft-backfill validate "$TEXTDIR/pft_backfill.prom" "$host" || { log "ERROR: textfile rejected"; exit 1; }
grep -E "^pft_backfill_(up|node_full|missing_ledgers)\{" "$TEXTDIR/pft_backfill.prom"
systemctl enable --now pft-backfill.timer
log "enabled pft-backfill.timer (every 5 min)"
if $repair; then
  systemctl enable --now pft-backfill-repair.timer
  log "enabled pft-backfill-repair.timer (hourly, default caps; dry runs: sudo pft-backfill repair)"
else
  log "pft-backfill-repair.timer installed, NOT enabled (opt-in: --enable-repair)"
fi
log "remember: sudo pft-integrity accept --reason 'pft-backfill installed'"
