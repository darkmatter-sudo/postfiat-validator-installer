#!/usr/bin/env bash
# Install / uninstall pft-peertls (+ weekly read-only TLS audit timer). Installing changes NO node config; only
# `pft-peertls-fix apply --yes` inside a pft-maint window does.
#   sudo ./install.sh --role validator|sentry [--container NAME]   pft-peertls.sh -> /usr/local/bin/pft-peertls,
#       pft-peertls-fix.sh -> /usr/local/bin/pft-peertls-fix, peertls_eval.py and policy/*.policy ->
#       /usr/local/lib/pft-peertls/, pft-peertls.service/.timer, writes ROLE + HOST_LABEL into /etc/pft-peertls.env,
#       creates /etc/pft-peertls.targets with this host's own loopback target (`ROLE 127.0.0.1 2559 local CONTAINER`)
#       unless it exists (remote lines for cross-host runs are added by hand; the timer audits local targets only),
#       adds `textfile pft_peertls_*.prom 8d pft_peertls_last_run_timestamp_seconds` + `require pft_peertls_ROLE.prom`
#       to /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one audit through the sandboxed unit (must
#       write up 1), then enables the timer.
#   sudo ./install.sh --pull     on the host that runs ../alerts (after the line above): pft-peertls-pull.service/
#       .timer (weekly Mon 05:33 UTC, 10 min after the peer's audit) and `require pft_peertls_PEER.prom`. Needs PULL_SSH
#       (and PEER_LABEL, default sentry) in /etc/pft-peertls.env. Runs the pull unit once (must succeed).
#   sudo ./install.sh --uninstall   disables the timers, removes this host's textfile(s) and the pft_peertls lines in
#       /etc/pft-rulecheck.conf (keeps the scripts, policies, env, targets and state).
# Alert rule: ../alerts/peertls.rules.yml (PFTPeerTLSPosture), listed in ../alerts/prometheus.yml.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binaries + units), pft-schedaudit accept + collect,
#   pft-jobwatch inventory (interval 604800 both; validator pft-peertls-pull.timer 604800).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
CONF=/etc/pft-peertls.env
TARGETS=/etc/pft-peertls.targets
LIBDIR=/usr/local/lib/pft-peertls
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_peertls_*.prom   8d   pft_peertls_last_run_timestamp_seconds'
role=""; container=""; uninstall=false; pull=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --role) role="${2:?}"; shift ;;
    --container) container="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }
host="$(conf_get HOST_LABEL)"; host="${host:-${role:-validator}}"

rc_add() { # $1 = exact line; appended once to the pft-rulecheck conf if pft-rulecheck is installed
  [ -f "$RC_CONF" ] || return 0
  grep -qxF "$1" "$RC_CONF" || { echo "$1" >> "$RC_CONF"; log "added to $RC_CONF: $1"; }
}

run_unit() { # UNIT: one run through the sandboxed unit; must not fail
  systemctl start "$1" || true
  if systemctl is-failed -q "$1"; then
    log "ERROR: $1 failed"; journalctl -u "$1" -n 8 --no-pager --utc; exit 1
  fi
}

if $uninstall; then
  systemctl disable --now pft-peertls.timer 2>/dev/null || true
  systemctl disable --now pft-peertls-pull.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_peertls_$host.prom"
  [ -z "$(conf_get PULL_SSH)" ] || { peer="$(conf_get PEER_LABEL)"; rm -f "$TEXTDIR/pft_peertls_${peer:-sentry}.prom"; }
  [ ! -f "$RC_CONF" ] || sed -i '/pft_peertls_/d' "$RC_CONF"
  log "disabled the pft-peertls timers, removed textfile(s) and rulecheck lines (kept the scripts, $LIBDIR, $CONF, $TARGETS)"
  exit 0
fi

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-peertls.env.example)" >&2; exit 3
  fi
  [ -x /usr/local/bin/pft-peertls ] || { echo "run ./install.sh --role ... first" >&2; exit 3; }
  install -m 644 "$HERE/systemd/pft-peertls-pull.service" "$HERE/systemd/pft-peertls-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "pull (through the pull unit):"
  run_unit pft-peertls-pull.service
  grep -E "^pft_peertls_(up|verdict|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_peertls_$peer.prom"
  rc_add "require pft_peertls_$peer.prom"
  systemctl enable --now pft-peertls-pull.timer
  log "pft-peertls-pull.timer copies pft_peertls_$peer.prom weekly (Mon 05:33 UTC)"
  exit 0
fi

[ -n "$role" ] || { echo "--role validator|sentry is required" >&2; exit 3; }
{ [[ "$role" =~ ^[a-z][a-z0-9-]*$ ]] && [ -f "$HERE/policy/$role.policy" ]; } || { echo "no policy/$role.policy" >&2; exit 3; }
[ -n "$container" ] || { [ "$role" = sentry ] && container=postfiatd-sentry || container=postfiatd; }
[[ "$container" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || { echo "bad --container $container" >&2; exit 3; }
for c in python3 openssl timeout docker; do command -v "$c" >/dev/null || { echo "$c is required" >&2; exit 3; }; done
install -m 755 "$HERE/pft-peertls.sh" /usr/local/bin/pft-peertls
install -m 755 "$HERE/pft-peertls-fix.sh" /usr/local/bin/pft-peertls-fix
install -d -m 755 "$LIBDIR" "$LIBDIR/policy"
install -m 644 "$HERE/peertls_eval.py" "$LIBDIR/peertls_eval.py"
install -m 644 "$HERE/policy/validator.policy" "$HERE/policy/sentry.policy" "$LIBDIR/policy/"
for f in pft-peertls.sh pft-peertls-fix.sh peertls_eval.py policy/validator.policy policy/sentry.policy; do
  log "installed $f (sha256 $(sha256sum < "$HERE/$f" | cut -c1-64))"
done
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
if [ -f "$CONF" ]; then
  for kv in "ROLE=$role" "HOST_LABEL=$host"; do
    k="${kv%%=*}"
    if grep -q "^$k=" "$CONF"; then sed -i "s/^$k=.*/$kv/" "$CONF"; else echo "$kv" >> "$CONF"; fi
  done
else
  install -o root -g root -m 600 /dev/null "$CONF"
  printf '# pft-peertls config (see pft-peertls.env.example)\nROLE=%s\nHOST_LABEL=%s\n' "$role" "$host" > "$CONF"
fi
chown root:root "$CONF"; chmod 600 "$CONF"
if [ ! -f "$TARGETS" ]; then
  install -o root -g root -m 600 /dev/null "$TARGETS"
  printf '# NAME ADDR PORT local|remote [CONTAINER] (see pft-peertls.targets.example)\n%s 127.0.0.1 2559 local %s\n' \
    "$host" "$container" > "$TARGETS"
  log "created $TARGETS ($host 127.0.0.1 2559 local $container)"
fi
chown root:root "$TARGETS"; chmod 600 "$TARGETS"
install -m 644 "$HERE/systemd/pft-peertls.service" "$HERE/systemd/pft-peertls.timer" /etc/systemd/system/
systemctl daemon-reload
grep -qF 'pft_peertls_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
rc_add "require pft_peertls_$host.prom"
log "first audit (through the sandboxed unit, ROLE=$role HOST_LABEL=$host):"
run_unit pft-peertls.service
grep -E "^pft_peertls_(up|verdict|handshakes)\{" "$TEXTDIR/pft_peertls_$host.prom"
grep -qx "pft_peertls_up{host=\"$host\"} 1" "$TEXTDIR/pft_peertls_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-peertls.timer
log "enabled pft-peertls.timer (weekly Mon 05:23 UTC + up to 60 s)"
log "remember: sudo pft-integrity accept --reason 'pft-peertls installed'; pft-schedaudit accept + collect; pft-jobwatch inventory"
