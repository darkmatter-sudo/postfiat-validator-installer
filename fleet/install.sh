#!/usr/bin/env bash
# Install / uninstall pft-fleet on the host that runs ../alerts (the validator).
#   sudo ./install.sh          pft-fleet.sh -> /usr/local/sbin/pft-fleet, fleet_lib.py + manifest.tsv ->
#       /usr/local/lib/pft-fleet/, pft-fleet.service/.timer. Needs /etc/pft-fleet/fleet.conf (REPO, SSH_AS; see
#       fleet.conf.example) and /etc/pft-fleet/hosts.conf (see hosts.conf.example), both root-owned. Runs one skew
#       through the sandboxed unit (the textfile must appear with pft_fleet_up 1), then enables the hourly timer.
#   sudo ./install.sh --uninstall   disables the timer and removes the textfile (keeps config, state and backups).
# Alert rules: ../alerts/fleet.rules.yml (listed in ../alerts/prometheus.yml; reload Prometheus).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXT=/var/lib/pft-exporter/textfile/pft_fleet.prom
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
case "${1:-}" in
  --uninstall)
    systemctl disable --now pft-fleet.timer 2>/dev/null || true
    rm -f "$TEXT"; log "disabled pft-fleet.timer, removed $TEXT"; exit 0 ;;
  "") ;;
  *) echo "unknown argument: $1" >&2; exit 3 ;;
esac
for f in /etc/pft-fleet/fleet.conf /etc/pft-fleet/hosts.conf; do
  if [ ! -f "$f" ] || [ "$(stat -c %u "$f")" != 0 ] || [ -n "$(find "$f" -perm /022)" ]; then
    echo "$f missing, not root-owned or group/other-writable (see $(basename "$f").example)" >&2; exit 3
  fi
done
install -m 755 "$HERE/pft-fleet.sh" /usr/local/sbin/pft-fleet
install -d -m 755 /usr/local/lib/pft-fleet
install -m 644 "$HERE/fleet_lib.py" "$HERE/manifest.tsv" /usr/local/lib/pft-fleet/
install -d -m 755 /var/lib/pft-fleet /var/lib/pft-exporter/textfile
for f in pft-fleet.sh fleet_lib.py manifest.tsv; do log "installed $f sha256 $(sha256sum < "$HERE/$f" | cut -c1-64)"; done
install -m 644 "$HERE/systemd/pft-fleet.service" "$HERE/systemd/pft-fleet.timer" /etc/systemd/system/
systemctl daemon-reload
log "first skew through the sandboxed unit:"
systemctl start pft-fleet.service || true
journalctl -u pft-fleet.service -n 60 --no-pager -o cat --since "-2min" | tail -45
if ! grep -qx 'pft_fleet_up 1' "$TEXT" 2>/dev/null; then
  echo "first run did not write pft_fleet_up 1 to $TEXT - timer NOT enabled" >&2; exit 1
fi
systemctl enable --now pft-fleet.timer
log "pft-fleet.timer enabled: $(systemctl show -p NextElapseUSecRealtime --value pft-fleet.timer)"
