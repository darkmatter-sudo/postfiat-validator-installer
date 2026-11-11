#!/usr/bin/env bash
# Install / uninstall pft-peerwatch (+ per-container 1-minute timer).
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-peerwatch, parser ->
#       /usr/local/lib/pft-peerwatch/peerwatch_parse.py, pft-peerwatch@.service/.timer, textfile dir
#       /var/lib/pft-exporter/textfile (0755), state dir /var/lib/pft-peerwatch (0700: holds peer keys/addresses).
#       Runs one collection through the sandboxed unit (must give up 1), then enables pft-peerwatch@NAME.timer.
#       NAME defaults to postfiatd (postfiatd-sentry on a sentry from ../sentry). No ad-hoc `docker exec` into the
#       (AppArmor/seccomp-confined) node: the first collection IS the access check.
#   sudo ./install.sh --uninstall [--container NAME]   disables the timer, removes the .prom file (keeps state)
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-peerwatch-pull@.service/.timer; needs
#       PULL_SSH in /etc/pft-peerwatch.env. Runs one pull (must exit 0), then enables pft-peerwatch-pull@NAME.timer
#       (every minute at :55; the peer collects at :25).
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Conf: /etc/pft-peerwatch.env (root-owned) from pft-peerwatch.env.example if absent; never overwritten.
# Alert rules: ../alerts/peerwatch.rules.yml, listed in ../alerts/prometheus.yml in the same commit as the install.
# Afterwards (fleet installs do this themselves): pft-integrity accept, pft-schedaudit accept + collect,
# pft-jobwatch inventory (new timers), pft-rulecheck lines for pft_peerwatch_*.prom.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-peerwatch
LIBDIR=/usr/local/lib/pft-peerwatch
CONF=/etc/pft-peerwatch.env
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
  install -m 755 "$HERE/pft-peerwatch.sh" /usr/local/bin/pft-peerwatch
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/peerwatch_parse.py" "$LIBDIR/peerwatch_parse.py"
  log "installed /usr/local/bin/pft-peerwatch (sha256 $(sha256sum < "$HERE/pft-peerwatch.sh" | cut -c1-64))"
  log "installed $LIBDIR/peerwatch_parse.py (sha256 $(sha256sum < "$HERE/peerwatch_parse.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
  if [ ! -e "$CONF" ]; then
    install -m 644 "$HERE/pft-peerwatch.env.example" "$CONF"
    log "created $CONF from pft-peerwatch.env.example"
  fi
  [ "$(stat -c %u "$CONF")" = 0 ] || { echo "$CONF is not root-owned" >&2; exit 3; }
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-peerwatch-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_peerwatch_$pull.prom"
    log "disabled pft-peerwatch-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  install_bin
  c="$(sed -n 's/^PULL_SSH=//p' "$CONF")"
  [ -n "$c" ] || { echo "no PULL_SSH= line in $CONF (see pft-peerwatch.env.example)" >&2; exit 3; }
  install -m 644 "$HERE/systemd/pft-peerwatch-pull@.service" "$HERE/systemd/pft-peerwatch-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-peerwatch-pull@$pull.service" || true
  if systemctl is-failed -q "pft-peerwatch-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-peerwatch-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_peerwatch_(up|collect_timestamp_seconds|status)\{" "$TEXTDIR/pft_peerwatch_$pull.prom"
  systemctl enable --now "pft-peerwatch-pull@$pull.timer"
  log "enabled pft-peerwatch-pull@$pull.timer (every minute at :55)"
  exit 0
fi
if $uninstall; then
  systemctl disable --now "pft-peerwatch@$name.timer" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_peerwatch_$name.prom"
  log "disabled pft-peerwatch@$name.timer, removed its textfile (kept $STATEDIR and the shared units/script)"
  exit 0
fi
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }

install_bin
mkdir -p "$STATEDIR"; chmod 700 "$STATEDIR"
install -m 644 "$HERE/systemd/pft-peerwatch@.service" "$HERE/systemd/pft-peerwatch@.timer" /etc/systemd/system/
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
systemctl start "pft-peerwatch@$name.service" || true
if systemctl is-failed -q "pft-peerwatch@$name.service"; then
  log "ERROR: first collection failed"; journalctl -u "pft-peerwatch@$name.service" -n 5 --no-pager --utc; exit 1
fi
f="$TEXTDIR/pft_peerwatch_$name.prom"
grep -E "^pft_peerwatch_(up|peers|fixed_link_up|status)\{" "$f"
grep -qx "pft_peerwatch_up{container=\"$name\"} 1" "$f" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now "pft-peerwatch@$name.timer"
log "enabled pft-peerwatch@$name.timer (every minute at :25)"
