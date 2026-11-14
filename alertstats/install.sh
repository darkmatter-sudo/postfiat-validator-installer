#!/usr/bin/env bash
# Install / uninstall pft-alertstats (daily read-only alert behaviour report) on the host that runs ../alerts.
#   sudo ./install.sh              pft-alertstats.sh -> /usr/local/bin/pft-alertstats, alertstats_build.py ->
#       /usr/local/lib/pft-alertstats/, pft-alertstats.service/.timer, adds
#       `textfile pft_alertstats.prom 30h pft_alertstats_last_run_timestamp_seconds` + `require pft_alertstats.prom`
#       to /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one report through the sandboxed unit (must
#       write pft_alertstats_up 1), then enables the timer (daily 05:23 UTC).
#   sudo ./install.sh --uninstall  disables the timer, removes the textfile and the rulecheck lines (keeps the script,
#       the helper and /var/lib/pft-alertstats).
# Alert rule: ../alerts/alertstats.rules.yml (PFTAlertFlapping), listed in ../alerts/prometheus.yml.
# Fleet installs go through ../fleet (manifest rows `alertstats`) inside a pft-maint window.
# Afterwards: sudo pft-integrity accept --reason "<why>"; pft-schedaudit accept + collect; pft-jobwatch inventory.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-alertstats
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_alertstats.prom    30h  pft_alertstats_last_run_timestamp_seconds'
uninstall=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) uninstall=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done

rc_add() { # $1 = exact line; appended once to the pft-rulecheck conf if pft-rulecheck is installed
  [ -f "$RC_CONF" ] || return 0
  grep -qxF "$1" "$RC_CONF" || { echo "$1" >> "$RC_CONF"; log "added to $RC_CONF: $1"; }
}

if $uninstall; then
  systemctl disable --now pft-alertstats.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_alertstats.prom"
  [ ! -f "$RC_CONF" ] || sed -i '/pft_alertstats/d' "$RC_CONF"
  log "disabled pft-alertstats.timer, removed the textfile and rulecheck lines (kept the script, $LIBDIR, /var/lib/pft-alertstats)"
  exit 0
fi

for c in python3 docker; do command -v "$c" >/dev/null || { echo "$c is required" >&2; exit 3; }; done
install -m 755 "$HERE/pft-alertstats.sh" /usr/local/bin/pft-alertstats
install -d -m 755 "$LIBDIR"
install -m 644 "$HERE/alertstats_build.py" "$LIBDIR/alertstats_build.py"
for f in pft-alertstats.sh alertstats_build.py; do
  log "installed $f (sha256 $(sha256sum < "$HERE/$f" | cut -c1-64))"
done
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
install -m 644 "$HERE/systemd/pft-alertstats.service" "$HERE/systemd/pft-alertstats.timer" /etc/systemd/system/
systemctl daemon-reload
rc_add "$RC_LINE"
rc_add "require pft_alertstats.prom"
log "first report (through the sandboxed unit):"
systemctl start pft-alertstats.service || true
if systemctl is-failed -q pft-alertstats.service; then
  log "ERROR: pft-alertstats.service failed"; journalctl -u pft-alertstats.service -n 12 --no-pager --utc; exit 1
fi
grep -E '^pft_alertstats_(up|rules|prometheus_gap_seconds)\{' "$TEXTDIR/pft_alertstats.prom"
grep -qx 'pft_alertstats_up{host="validator"} 1' "$TEXTDIR/pft_alertstats.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-alertstats.timer
log "enabled pft-alertstats.timer (daily 05:23 UTC + up to 120 s)"
log "remember: sudo pft-integrity accept --reason 'pft-alertstats installed'; pft-schedaudit accept + collect; pft-jobwatch inventory"
