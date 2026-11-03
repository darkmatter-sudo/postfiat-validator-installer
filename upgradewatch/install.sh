#!/usr/bin/env bash
# Install / uninstall pft-upgradewatch (+ per-container 5-minute timer).
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-upgradewatch, parser ->
#       /usr/local/lib/pft-upgradewatch/upgradewatch_parse.py, pft-upgradewatch@.service/.timer, textfile dir
#       /var/lib/pft-exporter/textfile (0755).
#       Runs one collection through the sandboxed unit (must give up 1), then enables pft-upgradewatch@NAME.timer.
#       NAME defaults to postfiatd (use postfiatd-sentry on a sentry from ../sentry).
#   sudo ./install.sh --uninstall [--container NAME]   disables the timer, removes the .prom file
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-upgradewatch-pull@.service/.timer; needs
#       PULL_SSH in /etc/pft-upgradewatch.env (see pft-upgradewatch.env.example). Runs one pull (must exit 0), then
#       enables pft-upgradewatch-pull@NAME.timer (every 5 min at :50; the peer collects at :25).
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Alert rules: ../alerts/upgradewatch.rules.yml, listed in ../alerts/prometheus.yml (mounted as /etc/pft-alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-upgradewatch
name=postfiatd; uninstall=false; pull=""
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --container) name="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull="${2:?}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
valid() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "bad container name" >&2; exit 3; }; }
valid "$name"

install_bin() {
  install -m 755 "$HERE/pft-upgradewatch.sh" /usr/local/bin/pft-upgradewatch
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/upgradewatch_parse.py" "$LIBDIR/upgradewatch_parse.py"
  log "installed /usr/local/bin/pft-upgradewatch (sha256 $(sha256sum < "$HERE/pft-upgradewatch.sh" | cut -c1-64))"
  log "installed $LIBDIR/upgradewatch_parse.py (sha256 $(sha256sum < "$HERE/upgradewatch_parse.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-upgradewatch-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_upgradewatch_$pull.prom"
    log "disabled pft-upgradewatch-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  c=/etc/pft-upgradewatch.env
  if ! { [ -f "$c" ] && [ "$(stat -c %u "$c")" = 0 ] && grep -q '^PULL_SSH=' "$c"; }; then
    echo "$c missing, not root-owned or without PULL_SSH (see pft-upgradewatch.env.example)" >&2; exit 3
  fi
  chmod 600 "$c"
  install_bin
  install -m 644 "$HERE/systemd/pft-upgradewatch-pull@.service" "$HERE/systemd/pft-upgradewatch-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-upgradewatch-pull@$pull.service" || true
  if systemctl is-failed -q "pft-upgradewatch-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-upgradewatch-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_upgradewatch_(up|collect_timestamp_seconds)\{" "$TEXTDIR/pft_upgradewatch_$pull.prom"
  systemctl enable --now "pft-upgradewatch-pull@$pull.timer"
  log "enabled pft-upgradewatch-pull@$pull.timer (every 5 min at :50)"
  log "remember: sudo pft-integrity accept --reason 'pft-upgradewatch pull installed'"
  exit 0
fi
if $uninstall; then
  systemctl disable --now "pft-upgradewatch@$name.timer" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_upgradewatch_$name.prom"
  log "disabled pft-upgradewatch@$name.timer, removed its textfile (kept the shared units/script)"
  exit 0
fi
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
docker exec "$name" sh -c 'command -v curl && command -v grep' >/dev/null 2>&1 || { echo "no curl/grep inside $name" >&2; exit 3; }

install_bin
install -m 644 "$HERE/systemd/pft-upgradewatch@.service" "$HERE/systemd/pft-upgradewatch@.timer" /etc/systemd/system/
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
systemctl start "pft-upgradewatch@$name.service" || true
if systemctl is-failed -q "pft-upgradewatch@$name.service"; then
  log "ERROR: first collection failed"; journalctl -u "pft-upgradewatch@$name.service" -n 5 --no-pager --utc; exit 1
fi
grep -E "^pft_upgradewatch_(up|amendment_blocked|majority_amendments|majority_time_seconds|unsupported_activation_eta_seconds|build_info|foundation_known|behind_foundation|peers_versioned|peers_newer)\{" "$TEXTDIR/pft_upgradewatch_$name.prom"
grep -qx "pft_upgradewatch_up{container=\"$name\"} 1" "$TEXTDIR/pft_upgradewatch_$name.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now "pft-upgradewatch@$name.timer"
log "enabled pft-upgradewatch@$name.timer (every 5 min at :25)"
log "remember: sudo pft-integrity accept --reason 'pft-upgradewatch installed'"
