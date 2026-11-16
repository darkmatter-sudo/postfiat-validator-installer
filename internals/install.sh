#!/usr/bin/env bash
# Install / uninstall pft-internals (+ per-container 1-minute timer): postfiatd get_counts + server_info counters.
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-internals, parser ->
#       /usr/local/lib/pft-internals/internals_parse.py, pft-internals@.service/.timer, textfile dir
#       /var/lib/pft-exporter/textfile (0755), state dir /var/lib/pft-internals (0700).
#       Runs one collection through the sandboxed unit (must give up 1), then enables pft-internals@NAME.timer.
#       NAME defaults to postfiatd (postfiatd-sentry on a sentry from ../sentry). No ad-hoc `docker exec` into the
#       (AppArmor/seccomp-confined) node: the first collection IS the access check.
#   sudo ./install.sh --uninstall [--container NAME]   disables the timer, removes the .prom file (keeps state)
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-internals-pull@.service/.timer; needs
#       PULL_SSH in /etc/pft-internals.env. Runs one pull (must exit 0), then enables pft-internals-pull@NAME.timer
#       (every minute at :52; the peer collects at :40).
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Conf: /etc/pft-internals.env (root-owned) from pft-internals.env.example if absent; never overwritten.
# Alert rules: ../alerts/internals.rules.yml, listed in ../alerts/prometheus.yml in the same commit as the install.
# pft-rulecheck: if /etc/pft-rulecheck.conf exists, the textfile age line (5m) and `require pft_internals_NAME.prom`
# are appended once (uninstall removes the require line).
# Afterwards: pft-integrity accept, pft-schedaudit accept + collect, pft-jobwatch inventory (new timers).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-internals
LIBDIR=/usr/local/lib/pft-internals
CONF=/etc/pft-internals.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE="textfile pft_internals_*.prom   5m   pft_internals_collect_timestamp_seconds"
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

rc_add() { # $1 = exact line; appended once to the pft-rulecheck conf if pft-rulecheck is installed
  [ -f "$RC_CONF" ] || return 0
  grep -qxF "$1" "$RC_CONF" || { echo "$1" >> "$RC_CONF"; log "added to $RC_CONF: $1"; }
}
rc_del() { # $1 = container: drop its require line (the shared textfile line stays)
  [ ! -f "$RC_CONF" ] || sed -i "/^require pft_internals_$1\.prom\$/d" "$RC_CONF"
}

install_bin() {
  install -m 755 "$HERE/pft-internals.sh" /usr/local/bin/pft-internals
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/internals_parse.py" "$LIBDIR/internals_parse.py"
  log "installed /usr/local/bin/pft-internals (sha256 $(sha256sum < "$HERE/pft-internals.sh" | cut -c1-64))"
  log "installed $LIBDIR/internals_parse.py (sha256 $(sha256sum < "$HERE/internals_parse.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
  if [ ! -e "$CONF" ]; then
    sed "s/^CONTAINER=.*/CONTAINER=$name/" "$HERE/pft-internals.env.example" > "$CONF.tmp" && chmod 644 "$CONF.tmp" && mv -f "$CONF.tmp" "$CONF"
    log "created $CONF from pft-internals.env.example (CONTAINER=$name)"
  fi
  [ "$(stat -c %u "$CONF")" = 0 ] || { echo "$CONF is not root-owned" >&2; exit 3; }
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-internals-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_internals_$pull.prom"; rc_del "$pull"
    log "disabled pft-internals-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  install_bin
  c="$(sed -n 's/^PULL_SSH=//p' "$CONF")"
  [ -n "$c" ] || { echo "no PULL_SSH= line in $CONF (see pft-internals.env.example)" >&2; exit 3; }
  install -m 644 "$HERE/systemd/pft-internals-pull@.service" "$HERE/systemd/pft-internals-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-internals-pull@$pull.service" || true
  if systemctl is-failed -q "pft-internals-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-internals-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_internals_(up|collect_timestamp_seconds|node_uptime_seconds)\{" "$TEXTDIR/pft_internals_$pull.prom"
  systemctl enable --now "pft-internals-pull@$pull.timer"
  grep -qF 'pft_internals_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
  rc_add "require pft_internals_$pull.prom"
  log "enabled pft-internals-pull@$pull.timer (every minute at :52)"
  exit 0
fi
if $uninstall; then
  systemctl disable --now "pft-internals@$name.timer" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_internals_$name.prom"; rc_del "$name"
  log "disabled pft-internals@$name.timer, removed its textfile (kept $STATEDIR and the shared units/script)"
  exit 0
fi
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }

install_bin
mkdir -p "$STATEDIR"; chmod 700 "$STATEDIR"
install -m 644 "$HERE/systemd/pft-internals@.service" "$HERE/systemd/pft-internals@.timer" /etc/systemd/system/
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
systemctl start "pft-internals@$name.service" || true
if systemctl is-failed -q "pft-internals@$name.service"; then
  log "ERROR: first collection failed"; journalctl -u "pft-internals@$name.service" -n 5 --no-pager --utc; exit 1
fi
f="$TEXTDIR/pft_internals_$name.prom"
grep -E "^pft_internals_(up|last_success_timestamp_seconds|node_uptime_seconds|nodestore_reads_total)\{" "$f"
grep -qx "pft_internals_up{container=\"$name\"} 1" "$f" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now "pft-internals@$name.timer"
log "enabled pft-internals@$name.timer (every minute at :40)"
grep -qF 'pft_internals_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
rc_add "require pft_internals_$name.prom"
