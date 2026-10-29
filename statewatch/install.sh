#!/usr/bin/env bash
# Install / uninstall pft-statewatch (+ per-container 1-minute timer).
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-statewatch, parser ->
#       /usr/local/lib/pft-statewatch/statewatch_parse.py, pft-statewatch@.service/.timer, textfile dir
#       /var/lib/pft-exporter/textfile (0755), history dir /var/lib/pft-statewatch (0750).
#       Runs one collection through the sandboxed unit (must give up 1), then enables pft-statewatch@NAME.timer.
#       NAME defaults to postfiatd (use postfiatd-sentry on a sentry from ../sentry).
#   sudo ./install.sh --uninstall [--container NAME]   disables the timer, removes the .prom file (keeps history)
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-statewatch-pull@.service/.timer; needs
#       PULL_SSH in /etc/pft-statewatch.env (see pft-statewatch.env.example). Runs one pull (must exit 0), then
#       enables pft-statewatch-pull@NAME.timer (every minute at :45; the peer collects at :15).
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Alert rules: copy ../alerts/statewatch.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
HISTDIR=/var/lib/pft-statewatch
LIBDIR=/usr/local/lib/pft-statewatch
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
  install -m 755 "$HERE/pft-statewatch.sh" /usr/local/bin/pft-statewatch
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/statewatch_parse.py" "$LIBDIR/statewatch_parse.py"
  log "installed /usr/local/bin/pft-statewatch (sha256 $(sha256sum < "$HERE/pft-statewatch.sh" | cut -c1-64))"
  log "installed $LIBDIR/statewatch_parse.py (sha256 $(sha256sum < "$HERE/statewatch_parse.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-statewatch-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_statewatch_$pull.prom"
    log "disabled pft-statewatch-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  c=/etc/pft-statewatch.env
  if ! { [ -f "$c" ] && [ "$(stat -c %u "$c")" = 0 ] && grep -q '^PULL_SSH=' "$c"; }; then
    echo "$c missing, not root-owned or without PULL_SSH (see pft-statewatch.env.example)" >&2; exit 3
  fi
  chmod 600 "$c"
  install_bin
  install -m 644 "$HERE/systemd/pft-statewatch-pull@.service" "$HERE/systemd/pft-statewatch-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-statewatch-pull@$pull.service" || true
  if systemctl is-failed -q "pft-statewatch-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-statewatch-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_statewatch_(up|collect_timestamp_seconds)\{" "$TEXTDIR/pft_statewatch_$pull.prom"
  systemctl enable --now "pft-statewatch-pull@$pull.timer"
  log "enabled pft-statewatch-pull@$pull.timer (every minute at :45)"
  log "remember: sudo pft-integrity accept --reason 'pft-statewatch pull installed'"
  exit 0
fi
if $uninstall; then
  systemctl disable --now "pft-statewatch@$name.timer" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_statewatch_$name.prom"
  log "disabled pft-statewatch@$name.timer, removed its textfile (kept $HISTDIR and the shared units/script)"
  exit 0
fi
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
docker exec "$name" sh -c 'command -v curl' >/dev/null 2>&1 || { echo "no curl inside $name" >&2; exit 3; }

install_bin
mkdir -p "$HISTDIR"; chmod 750 "$HISTDIR"
install -m 644 "$HERE/systemd/pft-statewatch@.service" "$HERE/systemd/pft-statewatch@.timer" /etc/systemd/system/
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
systemctl start "pft-statewatch@$name.service" || true
if systemctl is-failed -q "pft-statewatch@$name.service"; then
  log "ERROR: first collection failed"; journalctl -u "pft-statewatch@$name.service" -n 5 --no-pager --utc; exit 1
fi
grep -E "^pft_statewatch_(up|server_state_duration_seconds|full_exits_total|io_latency_ms)\{" "$TEXTDIR/pft_statewatch_$name.prom"
grep -qx "pft_statewatch_up{container=\"$name\"} 1" "$TEXTDIR/pft_statewatch_$name.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now "pft-statewatch@$name.timer"
log "enabled pft-statewatch@$name.timer (every minute at :15)"
log "remember: sudo pft-integrity accept --reason 'pft-statewatch installed'"
