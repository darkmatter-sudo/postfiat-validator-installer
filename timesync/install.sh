#!/usr/bin/env bash
# Install / uninstall pft-timesync (script + 1-minute metrics timer). Does NOT migrate the time daemon: that is
# `sudo pft-timesync apply --yes`, which needs the script installed here first (chrony.service's boot-gate
# drop-in runs /usr/local/sbin/pft-timesync).
#   sudo ./install.sh              script -> /usr/local/sbin/pft-timesync, pft-timesync.service/.timer;
#                                  runs one metrics collection in the foreground (must exit 0), then enables the timer
#   sudo ./install.sh --uninstall  disables the timer, removes units + textfile (refuses while the chrony drop-in exists:
#                                  run `sudo pft-timesync rollback --yes` first)
#   sudo ./install.sh --pull       on the host that runs ../alerts: pft-timesync-pull -> /usr/local/sbin,
#                                  pft-timesync-pull.service/.timer; needs /etc/pft-timesync-pull.env (root-owned, see
#                                  pft-timesync-pull.env.example). Runs one pull in the foreground (must exit 0), then
#                                  enables the timer (every minute). `--pull --uninstall` removes it and the pulled file.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN=/usr/local/sbin/pft-timesync
UNITS=/etc/systemd/system
TEXT=/var/lib/pft-exporter/textfile/pft_timesync.prom
log() { echo "install: $*"; }
[ "$(id -u)" = 0 ] || { echo "install: run as root" >&2; exit 4; }
if [ "${1:-}" = --pull ]; then
  PULLED=/var/lib/pft-exporter/textfile/pft_timesync_peer_sentry.prom
  if [ "${2:-}" = --uninstall ]; then
    systemctl disable --now pft-timesync-pull.timer 2>/dev/null || true
    rm -f "$UNITS/pft-timesync-pull.service" "$UNITS/pft-timesync-pull.timer" /usr/local/sbin/pft-timesync-pull "$PULLED"
    systemctl daemon-reload; log "removed pft-timesync-pull, its units and $PULLED"; exit 0
  fi
  if ! { [ -f /etc/pft-timesync-pull.env ] && [ "$(stat -c %u /etc/pft-timesync-pull.env)" = 0 ]; }; then
    echo "install: /etc/pft-timesync-pull.env missing or not root-owned (see pft-timesync-pull.env.example)" >&2; exit 4
  fi
  install -m 0755 -o root -g root "$HERE/pft-timesync-pull.sh" /usr/local/sbin/pft-timesync-pull
  install -m 0644 -o root -g root "$HERE/systemd/pft-timesync-pull.service" "$HERE/systemd/pft-timesync-pull.timer" "$UNITS/"
  systemctl daemon-reload
  systemctl start pft-timesync-pull.service || { echo "install: first pull failed (journalctl -u pft-timesync-pull)" >&2; exit 1; }
  systemctl enable --now pft-timesync-pull.timer >/dev/null 2>&1
  log "installed /usr/local/sbin/pft-timesync-pull ($(sha256sum /usr/local/sbin/pft-timesync-pull | cut -c1-64)), timer enabled; first pull: $(grep '^pft_timesync_state' "$PULLED")"
  exit 0
fi
if [ "${1:-}" = --uninstall ]; then
  [ -e /etc/systemd/system/chrony.service.d/50-pft-timesync.conf ] && { echo "install: chrony drop-in present; run 'pft-timesync rollback --yes' first" >&2; exit 4; }
  systemctl disable --now pft-timesync.timer 2>/dev/null || true
  rm -f "$UNITS/pft-timesync.service" "$UNITS/pft-timesync.timer" "$BIN" "$TEXT"
  systemctl daemon-reload; log "removed $BIN, units and $TEXT"; exit 0
fi
install -m 0755 -o root -g root "$HERE/pft-timesync.sh" "$BIN"
install -m 0644 -o root -g root "$HERE/systemd/pft-timesync.service" "$HERE/systemd/pft-timesync.timer" "$UNITS/"
mkdir -p "$(dirname "$TEXT")"; chmod 0755 "$(dirname "$TEXT")"
systemctl daemon-reload
systemctl start pft-timesync.service
[ -s "$TEXT" ] || { echo "install: first collection wrote no $TEXT" >&2; exit 1; }
systemctl enable --now pft-timesync.timer >/dev/null 2>&1
log "installed $BIN ($(sha256sum "$BIN" | cut -c1-64)), pft-timesync.timer enabled; first collection: $(grep '^pft_timesync_state ' "$TEXT")"
