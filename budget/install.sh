#!/usr/bin/env bash
# Install / uninstall pft-budget: the per-unit cgroup sampler and the 5-minute report textfile.
#   sudo ./install.sh --host validator|sentry   script -> /usr/local/bin/pft-budget, helper ->
#       /usr/local/lib/pft-budget/budget.py, pft-budget-sampler.service (system user pft-budget, data dir
#       /var/lib/pft-budget 0755), pft-budget-collect.service/.timer, conf /etc/pft-budget.env (0644, HOST set).
#       Starts the sampler, waits for its first heartbeat, runs one collection through the sandboxed unit (must give
#       up 1), then enables the timer.
#   sudo ./install.sh --uninstall   stops/disables the sampler and timer, removes the .prom file (keeps the data)
#   sudo ./install.sh --pull NAME   on the host that runs ../alerts: pft-budget-pull@.service/.timer; needs PULL_SSH
#       in /etc/pft-budget.env. Runs one pull (must exit 0), then enables pft-budget-pull@NAME.timer.
#   sudo ./install.sh --pull NAME --uninstall   disables that timer and removes the pulled textfile
# Conf: /etc/pft-budget.env from pft-budget.env.example if absent; never overwritten (HOST must match --host).
# Alert rules: ../alerts/budget.rules.yml, listed in ../alerts/prometheus.yml in the same commit as the install.
# pft-rulecheck: if /etc/pft-rulecheck.conf exists, the textfile age line (15m) and `require pft_budget_NAME.prom`
# are appended once (uninstall removes the require line).
# Afterwards: pft-integrity accept, pft-schedaudit accept + collect, pft-jobwatch inventory (new timers).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
DATADIR=/var/lib/pft-budget
LIBDIR=/usr/local/lib/pft-budget
CONF=/etc/pft-budget.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE="textfile pft_budget_*.prom   15m   pft_budget_report_timestamp_seconds"
# PFTBudgetCapReached reads the projection series, which exists only once a unit has PROJ_MIN_SPAN_DAYS of runs
# (8aef64d); without this pft-rulecheck reports the rule PARTIAL and PFTRuleDead fires (2026-11-18)
RC_IGNORE="ignore-metric pft_budget_projected_30d_bytes no series until a unit has MIN_RUNS runs spanning PROJ_MIN_SPAN_DAYS (3 d)"
host=""; uninstall=false; pull=""
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull="${2:?}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
valid() { [[ "$1" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "bad host name: $1" >&2; exit 3; }; }

rc_add() { # $1 = exact line; appended once to the pft-rulecheck conf if pft-rulecheck is installed
  [ -f "$RC_CONF" ] || return 0
  grep -qxF "$1" "$RC_CONF" || { echo "$1" >> "$RC_CONF"; log "added to $RC_CONF: $1"; }
}
rc_del() { # $1 = host: drop its require line (the shared textfile line stays)
  [ ! -f "$RC_CONF" ] || sed -i "/^require pft_budget_$1\.prom\$/d" "$RC_CONF"
}
conf_host() { sed -n 's/^HOST=//p' "$CONF" | tail -n 1; }

install_bin() {
  install -m 755 "$HERE/pft-budget.sh" /usr/local/bin/pft-budget
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/budget.py" "$LIBDIR/budget.py"
  log "installed /usr/local/bin/pft-budget (sha256 $(sha256sum < "$HERE/pft-budget.sh" | cut -c1-64))"
  log "installed $LIBDIR/budget.py (sha256 $(sha256sum < "$HERE/budget.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
  if [ ! -e "$CONF" ]; then
    [ -n "$host" ] || { echo "$CONF missing: give --host validator|sentry" >&2; exit 3; }
    sed "s/^HOST=.*/HOST=$host/" "$HERE/pft-budget.env.example" > "$CONF.tmp" && chmod 644 "$CONF.tmp" && mv -f "$CONF.tmp" "$CONF"
    log "created $CONF from pft-budget.env.example (HOST=$host)"
  fi
  [ "$(stat -c %u "$CONF")" = 0 ] || { echo "$CONF is not root-owned" >&2; exit 3; }
  # an empty report (no data files) exits 0 unless the conf is refused (exit 3)
  python3 -I "$LIBDIR/budget.py" --conf "$CONF" report --data >/dev/null || { echo "$CONF refused" >&2; exit 3; }
}

if [ -n "$pull" ]; then
  valid "$pull"
  if $uninstall; then
    systemctl disable --now "pft-budget-pull@$pull.timer" 2>/dev/null || true
    rm -f "$TEXTDIR/pft_budget_$pull.prom"; rc_del "$pull"
    log "disabled pft-budget-pull@$pull.timer, removed the pulled textfile"
    exit 0
  fi
  install_bin
  c="$(sed -n 's/^PULL_SSH=//p' "$CONF")"
  [ -n "$c" ] || { echo "no PULL_SSH= line in $CONF (see pft-budget.env.example)" >&2; exit 3; }
  install -m 644 "$HERE/systemd/pft-budget-pull@.service" "$HERE/systemd/pft-budget-pull@.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start "pft-budget-pull@$pull.service" || true
  if systemctl is-failed -q "pft-budget-pull@$pull.service"; then
    log "ERROR: first pull failed"; journalctl -u "pft-budget-pull@$pull.service" -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_budget_(up|sampler_heartbeat_timestamp_seconds|report_timestamp_seconds)\{" "$TEXTDIR/pft_budget_$pull.prom"
  systemctl enable --now "pft-budget-pull@$pull.timer"
  grep -qF 'pft_budget_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
  rc_add "require pft_budget_$pull.prom"
  log "enabled pft-budget-pull@$pull.timer (every 5 minutes at :50)"
  exit 0
fi
if $uninstall; then
  systemctl disable --now pft-budget-collect.timer pft-budget-sampler.service 2>/dev/null || true
  h=""; [ ! -f "$CONF" ] || h="$(conf_host)"
  if [ -n "$h" ]; then rm -f "$TEXTDIR/pft_budget_$h.prom"; rc_del "$h"; fi
  log "disabled pft-budget-sampler.service and pft-budget-collect.timer, removed the textfile (kept $DATADIR)"
  exit 0
fi
[ -n "$host" ] || { echo "give --host validator|sentry" >&2; exit 3; }
valid "$host"
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
[ -f /sys/fs/cgroup/cgroup.controllers ] || { echo "needs the unified cgroup v2 hierarchy" >&2; exit 3; }

install_bin
[ "$(conf_host)" = "$host" ] || { echo "$CONF has HOST=$(conf_host), not $host" >&2; exit 3; }
getent passwd pft-budget >/dev/null || {
  useradd --system --no-create-home --home-dir "$DATADIR" --shell /usr/sbin/nologin pft-budget
  log "created system user pft-budget"
}
install -d -m 755 -o pft-budget -g pft-budget "$DATADIR"
install -m 644 "$HERE/systemd/pft-budget-sampler.service" "$HERE/systemd/pft-budget-collect.service" \
  "$HERE/systemd/pft-budget-collect.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pft-budget-sampler.service
log "sampler started; waiting for its first heartbeat"
for _ in $(seq 1 30); do
  [ -s "$DATADIR/heartbeat" ] && break
  sleep 1
done
pft-budget status || { log "ERROR: no sampler heartbeat"; journalctl -u pft-budget-sampler -n 5 --no-pager --utc; exit 1; }
log "first collection (through the sandboxed unit):"
systemctl start pft-budget-collect.service || true
if systemctl is-failed -q pft-budget-collect.service; then
  log "ERROR: first collection failed"; journalctl -u pft-budget-collect.service -n 5 --no-pager --utc; exit 1
fi
f="$TEXTDIR/pft_budget_$host.prom"
grep -E "^pft_budget_(up|sampler_heartbeat_timestamp_seconds|report_timestamp_seconds)\{" "$f"
grep -qx "pft_budget_up{host=\"$host\"} 1" "$f" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-budget-collect.timer
log "enabled pft-budget-collect.timer (every 5 minutes at :20)"
grep -qF 'pft_budget_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
rc_add "require pft_budget_$host.prom"
[ "$host" != validator ] || rc_add "$RC_IGNORE"  # the rules are evaluated on the validator only
