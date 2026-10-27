#!/usr/bin/env bash
# Install / uninstall pft-resources (+ per-container 1-minute timer).
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-resources, pft-resources@.service/.timer,
#       textfile dir /var/lib/pft-exporter/textfile (0755), history dir /var/lib/pft-resources (0750).
#       Runs one collection in the foreground (must exit 0), then enables pft-resources@NAME.timer.
#       NAME defaults to postfiatd (use postfiatd-sentry on a sentry from ../sentry).
#   sudo ./install.sh --uninstall [--container NAME]   disables the timer, removes the .prom file (keeps history)
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
HISTDIR=/var/lib/pft-resources
name=postfiatd; uninstall=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --container) name="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "bad container name" >&2; exit 3; }
if $uninstall; then
  systemctl disable --now "pft-resources@$name.timer" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_resources_$name.prom"
  log "disabled pft-resources@$name.timer, removed its textfile (kept $HISTDIR and the shared units/script)"
  exit 0
fi
[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || { echo "cgroup v2 (unified) required" >&2; exit 3; }
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }

install -m 755 "$HERE/pft-resources.sh" /usr/local/bin/pft-resources
log "installed /usr/local/bin/pft-resources (sha256 $(sha256sum "$HERE/pft-resources.sh" | cut -c1-12))"
mkdir -p "$TEXTDIR" "$HISTDIR"; chmod 755 "$TEXTDIR"; chmod 750 "$HISTDIR"
install -m 644 "$HERE/pft-resources@.service" "$HERE/pft-resources@.timer" /etc/systemd/system/
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
systemctl start "pft-resources@$name.service"
systemctl is-failed -q "pft-resources@$name.service" && { log "ERROR: first collection failed"; journalctl -u "pft-resources@$name.service" -n 5 --no-pager --utc; exit 1; }
grep -E "^pft_resources_(up|memory_current_bytes|pids_current|fd_open)\{" "$TEXTDIR/pft_resources_$name.prom"
grep -qx "pft_resources_up{container=\"$name\"} 1" "$TEXTDIR/pft_resources_$name.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now "pft-resources@$name.timer"
log "enabled pft-resources@$name.timer (every minute at :00)"
log "remember: sudo pft-integrity accept --reason 'pft-resources installed'"
