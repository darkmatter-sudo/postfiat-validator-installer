#!/usr/bin/env bash
# Install / uninstall pft-fwaudit (+ hourly read-only audit timer). Installing changes NO firewall rule; only
# `pft-fwaudit apply --yes` inside a pft-maint window does.
#   sudo ./install.sh --role validator|sentry   pft-fwaudit.sh -> /usr/local/bin/pft-fwaudit, fwaudit_eval.py and
#       policy/*.policy -> /usr/local/lib/pft-fwaudit/, pft-fwaudit.service/.timer, writes ROLE + HOST_LABEL into
#       /etc/pft-fwaudit.env, adds `textfile pft_fwaudit_*.prom 3h pft_fwaudit_last_run_timestamp_seconds` +
#       `require pft_fwaudit_ROLE.prom` to /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one audit
#       through the sandboxed unit (must write up 1), then enables the timer. Needs /etc/pft-fwaudit.peers
#       (NAME=CIDR[,CIDR], root-owned) when the role's policy names @peers.
#   sudo ./install.sh --pull     on the host that runs ../alerts (after the line above): pft-fwaudit-pull.service/
#       .timer (hourly :16 UTC, 5 min after the peer's :11 audit) and `require pft_fwaudit_PEER.prom`. Needs PULL_SSH
#       (and PEER_LABEL, default sentry) in /etc/pft-fwaudit.env. Runs the pull unit once (must succeed).
#   sudo ./install.sh --uninstall   refuses while an apply is pending its dead-man; disables the timers, removes this
#       host's textfile(s) and the pft_fwaudit lines in /etc/pft-rulecheck.conf (keeps the script, policies, env).
# Alert rule: ../alerts/fwaudit.rules.yml (PFTFwauditExposure), listed in ../alerts/prometheus.yml.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units), pft-schedaudit accept + collect,
#   pft-jobwatch inventory (interval 3600 both; validator pft-fwaudit-pull.timer 3600).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
CONF=/etc/pft-fwaudit.env
PEERS=/etc/pft-fwaudit.peers
LIBDIR=/usr/local/lib/pft-fwaudit
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_fwaudit_*.prom   3h   pft_fwaudit_last_run_timestamp_seconds'
role=""; uninstall=false; pull=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --role) role="${2:?}"; shift ;;
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
  if [ -f /var/lib/pft-fwaudit/state.json ] && grep -q '"result":"pending"' /var/lib/pft-fwaudit/state.json; then
    echo "an apply is pending its dead-man: wait for it or sudo pft-fwaudit rollback --yes" >&2; exit 4
  fi
  systemctl disable --now pft-fwaudit.timer 2>/dev/null || true
  systemctl disable --now pft-fwaudit-pull.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_fwaudit_$host.prom"
  [ -z "$(conf_get PULL_SSH)" ] || { peer="$(conf_get PEER_LABEL)"; rm -f "$TEXTDIR/pft_fwaudit_${peer:-sentry}.prom"; }
  [ ! -f "$RC_CONF" ] || sed -i '/pft_fwaudit_/d' "$RC_CONF"
  log "disabled the pft-fwaudit timers, removed textfile(s) and rulecheck lines (kept the script, $LIBDIR, $CONF)"
  exit 0
fi

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-fwaudit.env.example)" >&2; exit 3
  fi
  [ -x /usr/local/bin/pft-fwaudit ] || { echo "run ./install.sh --role ... first" >&2; exit 3; }
  install -m 644 "$HERE/systemd/pft-fwaudit-pull.service" "$HERE/systemd/pft-fwaudit-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "pull (through the sandboxed pull unit):"
  run_unit pft-fwaudit-pull.service
  grep -E "^pft_fwaudit_(up|verdict|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_fwaudit_$peer.prom"
  rc_add "require pft_fwaudit_$peer.prom"
  systemctl enable --now pft-fwaudit-pull.timer
  log "pft-fwaudit-pull.timer copies pft_fwaudit_$peer.prom hourly (:16 UTC)"
  exit 0
fi

[ -n "$role" ] || { echo "--role validator|sentry is required" >&2; exit 3; }
{ [[ "$role" =~ ^[a-z][a-z0-9-]*$ ]] && [ -f "$HERE/policy/$role.policy" ]; } || { echo "no policy/$role.policy" >&2; exit 3; }
for c in python3 jq ss iptables-save ip6tables-save nft ufw; do command -v "$c" >/dev/null || { echo "$c is required" >&2; exit 3; }; done
if grep -qE '^allow .* @[a-z]' "$HERE/policy/$role.policy"; then
  { [ -f "$PEERS" ] && [ "$(stat -c %u "$PEERS")" = 0 ]; } || { echo "$PEERS missing or not root-owned (policy names @peers)" >&2; exit 3; }
  chmod 600 "$PEERS"
fi
install -m 755 "$HERE/pft-fwaudit.sh" /usr/local/bin/pft-fwaudit
install -d -m 755 "$LIBDIR" "$LIBDIR/policy"
install -m 644 "$HERE/fwaudit_eval.py" "$LIBDIR/fwaudit_eval.py"
install -m 644 "$HERE/policy/validator.policy" "$HERE/policy/sentry.policy" "$LIBDIR/policy/"
for f in pft-fwaudit.sh fwaudit_eval.py policy/validator.policy policy/sentry.policy; do
  log "installed $f (sha256 $(sha256sum < "$HERE/$f" | cut -c1-64))"
done
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
if [ -f "$CONF" ]; then
  for kv in "ROLE=$role" "HOST_LABEL=$host"; do
    k="${kv%%=*}"
    if grep -q "^$k=" "$CONF"; then sed -i "s/^$k=.*/$kv/" "$CONF"; else echo "$kv" >> "$CONF"; fi
  done
else
  printf '# pft-fwaudit config (see pft-fwaudit.env.example)\nROLE=%s\nHOST_LABEL=%s\n' "$role" "$host" > "$CONF"
fi
chown root:root "$CONF"; chmod 600 "$CONF"
install -m 644 "$HERE/systemd/pft-fwaudit.service" "$HERE/systemd/pft-fwaudit.timer" /etc/systemd/system/
systemctl daemon-reload
grep -qF 'pft_fwaudit_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
rc_add "require pft_fwaudit_$host.prom"
log "first audit (through the sandboxed unit, ROLE=$role HOST_LABEL=$host):"
run_unit pft-fwaudit.service
grep -E "^pft_fwaudit_(up|verdict|findings)\{" "$TEXTDIR/pft_fwaudit_$host.prom"
grep -qx "pft_fwaudit_up{host=\"$host\"} 1" "$TEXTDIR/pft_fwaudit_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-fwaudit.timer
log "enabled pft-fwaudit.timer (hourly :11 UTC + up to 60 s)"
log "remember: sudo pft-integrity accept --reason 'pft-fwaudit installed'; pft-schedaudit accept + collect; pft-jobwatch inventory"
