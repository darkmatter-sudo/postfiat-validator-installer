#!/usr/bin/env bash
# Install / uninstall pft-valwatch (+ per-container collector service and 1-minute textfile timer).
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-valwatch, helper ->
#       /usr/local/lib/pft-valwatch/valwatch.py, pft-valwatch@.service, pft-valwatch-textfile@.service/.timer,
#       data dir /var/lib/pft-valwatch (0750). Checks the endpoint (`pft-valwatch endpoint`), starts
#       pft-valwatch@NAME.service, waits up to 90 s for graded ledgers, builds the first textfile through the
#       sandboxed unit (must give up 1), then enables pft-valwatch-textfile@NAME.timer. NAME defaults to postfiatd
#       (postfiatd-sentry on a sentry from ../sentry). No `docker exec` into the (AppArmor/seccomp-confined) node.
#   sudo ./install.sh --uninstall [--container NAME]   stops the collector + timer, removes the .prom (keeps data)
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-valwatch-pull@.service/.timer; needs
#       PULL_SSH in /etc/pft-valwatch.env. Runs one pull (must exit 0), then enables pft-valwatch-pull@NAME.timer
#       (every minute at :45; the peer builds at :30).
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Conf: /etc/pft-valwatch.env (root-owned) from pft-valwatch.env.example if absent; never overwritten.
# Alert rules: ../alerts/valwatch.rules.yml, listed in ../alerts/prometheus.yml in the same commit as the install.
# pft-rulecheck: if /etc/pft-rulecheck.conf exists, the textfile age line (5m) and `require pft_valwatch_NAME.prom`
# are appended once (uninstall removes the require line).
# Afterwards: pft-integrity accept, pft-schedaudit accept + collect, pft-jobwatch inventory (new timers).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
DATADIR=/var/lib/pft-valwatch
LIBDIR=/usr/local/lib/pft-valwatch
CONF=/etc/pft-valwatch.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE="textfile pft_valwatch_*.prom   5m   pft_valwatch_collect_timestamp_seconds"
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
  [ ! -f "$RC_CONF" ] || sed -i "/^require pft_valwatch_$1\.prom\$/d" "$RC_CONF"
}

install_bin() {
  install -m 755 "$HERE/pft-valwatch.sh" /usr/local/bin/pft-valwatch
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/valwatch.py" "$LIBDIR/valwatch.py"
  log "installed /usr/local/bin/pft-valwatch (sha256 $(sha256sum < "$HERE/pft-valwatch.sh" | cut -c1-64))"
  log "installed $LIBDIR/valwatch.py (sha256 $(sha256sum < "$HERE/valwatch.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
  if [ ! -e "$CONF" ]; then
    install -o root -g root -m 644 "$HERE/pft-valwatch.env.example" "$CONF"
    log "created $CONF from pft-valwatch.env.example"
  fi
  [ "$(stat -c %u "$CONF")" = 0 ] || { echo "$CONF is not root-owned" >&2; exit 3; }
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-valwatch-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_valwatch_$pull.prom"; rc_del "$pull"
    log "disabled pft-valwatch-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  install_bin
  c="$(sed -n 's/^PULL_SSH=//p' "$CONF")"
  [ -n "$c" ] || { echo "no PULL_SSH= line in $CONF (see pft-valwatch.env.example)" >&2; exit 3; }
  install -m 644 "$HERE/systemd/pft-valwatch-pull@.service" "$HERE/systemd/pft-valwatch-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-valwatch-pull@$pull.service" || true
  if systemctl is-failed -q "pft-valwatch-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-valwatch-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_valwatch_(up|collect_timestamp_seconds|ledgers|quorum_margin_min)\{" "$TEXTDIR/pft_valwatch_$pull.prom"
  systemctl enable --now "pft-valwatch-pull@$pull.timer"
  grep -qF 'pft_valwatch_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
  rc_add "require pft_valwatch_$pull.prom"
  log "enabled pft-valwatch-pull@$pull.timer (every minute at :45)"
  exit 0
fi
if $uninstall; then
  systemctl disable --now "pft-valwatch-textfile@$name.timer" "pft-valwatch@$name.service" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_valwatch_$name.prom"; rc_del "$name"
  log "stopped pft-valwatch@$name + its textfile timer, removed its textfile (kept $DATADIR and the shared units)"
  exit 0
fi
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }

install_bin
mkdir -p "$DATADIR"; chmod 750 "$DATADIR"
pft-valwatch endpoint --container "$name"
install -m 644 "$HERE/systemd/pft-valwatch@.service" "$HERE/systemd/pft-valwatch-textfile@.service" \
  "$HERE/systemd/pft-valwatch-textfile@.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now "pft-valwatch@$name.service"
log "collector started; waiting for graded ledgers (up to 90 s)"
ok=false
for _ in $(seq 1 18); do
  sleep 5
  if pft-valwatch textfile --container "$name" --stdout 2>/dev/null | grep -qx "pft_valwatch_up{node=\"$name\"} 1"; then ok=true; break; fi
done
$ok || { log "ERROR: no graded ledger after 90 s"; journalctl -u "pft-valwatch@$name.service" -n 5 --no-pager --utc; exit 1; }
log "first textfile (through the sandboxed unit):"
systemctl start "pft-valwatch-textfile@$name.service" || true
if systemctl is-failed -q "pft-valwatch-textfile@$name.service"; then
  log "ERROR: first textfile failed"; journalctl -u "pft-valwatch-textfile@$name.service" -n 5 --no-pager --utc; exit 1
fi
f="$TEXTDIR/pft_valwatch_$name.prom"
grep -E "^pft_valwatch_(up|ledgers|unl_size|quorum|quorum_margin_min)\{" "$f"
grep -qx "pft_valwatch_up{node=\"$name\"} 1" "$f" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now "pft-valwatch-textfile@$name.timer"
log "enabled pft-valwatch-textfile@$name.timer (every minute at :30)"
grep -qF 'pft_valwatch_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
rc_add "require pft_valwatch_$name.prom"
