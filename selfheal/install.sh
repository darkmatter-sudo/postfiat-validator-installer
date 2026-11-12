#!/usr/bin/env bash
# Install / uninstall pft-selfheal (+ per-container 1-minute timer).
#   sudo ./install.sh [--container NAME]   script -> /usr/local/bin/pft-selfheal, decision core ->
#       /usr/local/lib/pft-selfheal/selfheal_decide.py, pft-selfheal@.service/.timer, textfile dir
#       /var/lib/pft-exporter/textfile (0755), state dir /var/lib/pft-selfheal (0700).
#       Runs one decision through the sandboxed unit (must give up 1), then enables pft-selfheal@NAME.timer.
#       NAME defaults to postfiatd (postfiatd-sentry on a sentry from ../sentry). The conf is created with
#       MODE=dryrun and never overwritten: switching to enforce is a separate, deliberate edit (README runbook).
#   sudo ./install.sh --uninstall [--container NAME]   disables the timer, removes the .prom file (keeps state/journal)
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-selfheal-pull@.service/.timer; needs
#       PULL_SSH in /etc/pft-selfheal.env. Runs one pull (must exit 0), then enables pft-selfheal-pull@NAME.timer
#       (every minute at :58; the peer decides at :40).
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Conf: /etc/pft-selfheal.env (root-owned) from pft-selfheal.env.example if absent; never overwritten.
# Alert rules: ../alerts/selfheal.rules.yml, listed in ../alerts/prometheus.yml in the same commit as the install.
# pft-rulecheck: if /etc/pft-rulecheck.conf exists, the textfile age line (5m) and `require pft_selfheal_NAME.prom`
# are appended once (uninstall removes the require line).
# Afterwards: pft-integrity accept, pft-schedaudit accept + collect, pft-jobwatch inventory (new timers).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-selfheal
LIBDIR=/usr/local/lib/pft-selfheal
CONF=/etc/pft-selfheal.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE="textfile pft_selfheal_*.prom   5m   pft_selfheal_run_timestamp_seconds"
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
  [ ! -f "$RC_CONF" ] || sed -i "/^require pft_selfheal_$1\.prom\$/d" "$RC_CONF"
}

install_bin() {
  install -m 755 "$HERE/pft-selfheal.sh" /usr/local/bin/pft-selfheal
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/selfheal_decide.py" "$LIBDIR/selfheal_decide.py"
  log "installed /usr/local/bin/pft-selfheal (sha256 $(sha256sum < "$HERE/pft-selfheal.sh" | cut -c1-64))"
  log "installed $LIBDIR/selfheal_decide.py (sha256 $(sha256sum < "$HERE/selfheal_decide.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
  if [ ! -e "$CONF" ]; then
    sed "s/^CONTAINER=.*/CONTAINER=$name/" "$HERE/pft-selfheal.env.example" > "$CONF.tmp" && chmod 644 "$CONF.tmp" && mv -f "$CONF.tmp" "$CONF"
    log "created $CONF from pft-selfheal.env.example (CONTAINER=$name, MODE=dryrun)"
  fi
  [ "$(stat -c %u "$CONF")" = 0 ] || { echo "$CONF is not root-owned" >&2; exit 3; }
  log "$CONF: $(grep -E '^MODE=' "$CONF" || echo 'MODE unset (dryrun)')"
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-selfheal-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_selfheal_$pull.prom"; rc_del "$pull"
    log "disabled pft-selfheal-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  install_bin
  c="$(sed -n 's/^PULL_SSH=//p' "$CONF")"
  [ -n "$c" ] || { echo "no PULL_SSH= line in $CONF (see pft-selfheal.env.example)" >&2; exit 3; }
  install -m 644 "$HERE/systemd/pft-selfheal-pull@.service" "$HERE/systemd/pft-selfheal-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-selfheal-pull@$pull.service" || true
  if systemctl is-failed -q "pft-selfheal-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-selfheal-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_selfheal_(up|run_timestamp_seconds|enforce)\{" "$TEXTDIR/pft_selfheal_$pull.prom"
  systemctl enable --now "pft-selfheal-pull@$pull.timer"
  grep -qF 'pft_selfheal_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
  rc_add "require pft_selfheal_$pull.prom"
  log "enabled pft-selfheal-pull@$pull.timer (every minute at :58)"
  exit 0
fi
if $uninstall; then
  systemctl disable --now "pft-selfheal@$name.timer" 2>/dev/null || true
  rm -f "$TEXTDIR/pft_selfheal_$name.prom"; rc_del "$name"
  log "disabled pft-selfheal@$name.timer, removed its textfile (kept $STATEDIR and the shared units/script)"
  exit 0
fi
docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true || { echo "container $name not running" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
command -v jq >/dev/null || { echo "jq missing" >&2; exit 3; }

install_bin
mkdir -p "$STATEDIR"; chmod 700 "$STATEDIR"
install -m 644 "$HERE/systemd/pft-selfheal@.service" "$HERE/systemd/pft-selfheal@.timer" /etc/systemd/system/
systemctl daemon-reload
log "first decision (through the sandboxed unit):"
systemctl start "pft-selfheal@$name.service" || true
if systemctl is-failed -q "pft-selfheal@$name.service"; then
  log "ERROR: first decision failed"; journalctl -u "pft-selfheal@$name.service" -n 5 --no-pager --utc; exit 1
fi
f="$TEXTDIR/pft_selfheal_$name.prom"
grep -E "^pft_selfheal_(up|enforce|actions_24h|breaker_open)\{" "$f"
grep -qx "pft_selfheal_up{container=\"$name\"} 1" "$f" || { log "ERROR: up != 1"; exit 1; }
# the guards as the SANDBOXED run saw them must match the host: a lock or window the host does not have means the unit
# cannot read pft-maint's state (sentry drill run 13: read-only /var/lib/pft-maint -> every action suppressed)
if command -v pft-maint >/dev/null; then
  host_locks="$(pft-maint lock list 2>&1)"; host_maint=false; pft-maint active >/dev/null 2>&1 && host_maint=true
  g="$(jq -c '.observation.guards | {maint_active, locks}' "$STATEDIR/last-$name.json" 2>/dev/null)"
  log "guards seen by the unit: ${g:-unreadable}; host: maint_active=$host_maint, lock list: $host_locks"
  if [ "$host_locks" = "no data-collection locks" ] && [ "$g" != "{\"maint_active\":$host_maint,\"locks\":[]}" ]; then
    log "ERROR: the sandboxed run sees maintenance guards the host does not have"; exit 1
  fi
fi
systemctl enable --now "pft-selfheal@$name.timer"
log "enabled pft-selfheal@$name.timer (every minute at :40)"
grep -qF 'pft_selfheal_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
rc_add "require pft_selfheal_$name.prom"
