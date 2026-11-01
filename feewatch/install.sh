#!/usr/bin/env bash
# Install / uninstall pft-feewatch (+ per-container 1-minute timer).
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-feewatch, parser ->
#       /usr/local/lib/pft-feewatch/feewatch_parse.py, pft-feewatch@.service/.timer, textfile dir
#       /var/lib/pft-exporter/textfile (0755), history dir /var/lib/pft-feewatch (0750).
#       Runs one collection through the sandboxed unit (must give up 1), then enables pft-feewatch@NAME.timer.
#       NAME defaults to postfiatd (use postfiatd-sentry on a sentry from ../sentry).
#   sudo ./install.sh --uninstall [--container NAME]   disables the timer, removes the .prom file (keeps history)
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-feewatch-pull@.service/.timer; needs
#       PULL_SSH in /etc/pft-feewatch.env (see pft-feewatch.env.example). Runs one pull (must exit 0), then
#       enables pft-feewatch-pull@NAME.timer (every minute at :50; the peer collects at :25).
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Alert rules: copy ../alerts/feewatch.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
HISTDIR=/var/lib/pft-feewatch
LIBDIR=/usr/local/lib/pft-feewatch
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
  install -m 755 "$HERE/pft-feewatch.sh" /usr/local/bin/pft-feewatch
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/feewatch_parse.py" "$LIBDIR/feewatch_parse.py"
  log "installed /usr/local/bin/pft-feewatch (sha256 $(sha256sum < "$HERE/pft-feewatch.sh" | cut -c1-64))"
  log "installed $LIBDIR/feewatch_parse.py (sha256 $(sha256sum < "$HERE/feewatch_parse.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-feewatch-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_feewatch_$pull.prom"
    log "disabled pft-feewatch-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  c=/etc/pft-feewatch.env
  if ! { [ -f "$c" ] && [ "$(stat -c %u "$c")" = 0 ] && grep -q '^PULL_SSH=' "$c"; }; then
    echo "$c missing, not root-owned or without PULL_SSH (see pft-feewatch.env.example)" >&2; exit 3
  fi
  chmod 600 "$c"
  install_bin
  install -m 644 "$HERE/systemd/pft-feewatch-pull@.service" "$HERE/systemd/pft-feewatch-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-feewatch-pull@$pull.service" || true
  if systemctl is-failed -q "pft-feewatch-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-feewatch-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_feewatch_(up|collect_timestamp_seconds)\{" "$TEXTDIR/pft_feewatch_$pull.prom"
  systemctl enable --now "pft-feewatch-pull@$pull.timer"
  log "enabled pft-feewatch-pull@$pull.timer (every minute at :50)"
  log "remember: sudo pft-integrity accept --reason 'pft-feewatch pull installed'"
  exit 0
fi
if $uninstall; then
  systemctl disable --now "pft-feewatch@$name.timer" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_feewatch_$name.prom"
  log "disabled pft-feewatch@$name.timer, removed its textfile (kept $HISTDIR and the shared units/script)"
  exit 0
fi
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
docker exec "$name" sh -c 'command -v curl' >/dev/null 2>&1 || { echo "no curl inside $name" >&2; exit 3; }

install_bin
mkdir -p "$HISTDIR"; chmod 750 "$HISTDIR"
install -m 644 "$HERE/systemd/pft-feewatch@.service" "$HERE/systemd/pft-feewatch@.timer" /etc/systemd/system/
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
systemctl start "pft-feewatch@$name.service" || true
if systemctl is-failed -q "pft-feewatch@$name.service"; then
  log "ERROR: first collection failed"; journalctl -u "pft-feewatch@$name.service" -n 5 --no-pager --utc; exit 1
fi
grep -E "^pft_feewatch_(up|admin|current_queue_size|queue_fill_ratio|escalation_multiple|load_factor)\{" "$TEXTDIR/pft_feewatch_$name.prom"
grep -qx "pft_feewatch_up{container=\"$name\"} 1" "$TEXTDIR/pft_feewatch_$name.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now "pft-feewatch@$name.timer"
log "enabled pft-feewatch@$name.timer (every minute at :25)"
log "remember: sudo pft-integrity accept --reason 'pft-feewatch installed'"
