#!/usr/bin/env bash
# Install / uninstall pft-sshcrypto (+ hourly audit timer). Installing changes NO sshd setting; `apply` does.
#   sudo ./install.sh [--host LABEL]   script -> /usr/local/bin/pft-sshcrypto, grader + hardened.conf ->
#       /usr/local/lib/pft-sshcrypto/, writes HOST_LABEL into /etc/pft-sshcrypto.env (validator by default; use
#       --host sentry on a sentry), creates the loopback-only confirm key (see below), adds
#       `textfile pft_sshcrypto_*.prom 3h ...` to /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one
#       audit through the sandboxed unit (must write up 1), then enables pft-sshcrypto.timer (hourly).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-sshcrypto-pull.service/.timer; needs
#       PULL_SSH (and PEER_LABEL, default sentry) in /etc/pft-sshcrypto.env. One pull (must exit 0), then enables
#       pft-sshcrypto-pull.timer (every 15 min).
#   sudo ./install.sh --uninstall | --pull --uninstall   refuses while a policy is applied or a revert is armed;
#       disables the timer, removes the textfile, the confirm key and its authorized_keys line.
# Confirm key: /var/lib/pft-sshcrypto/confirm_ed25519 (root 0600, created under umask 077). Its public half goes
# into /root/.ssh/authorized_keys as
#   restrict,from="127.0.0.1,::1",command="echo pft-sshcrypto-confirm-ok" ssh-ed25519 ... pft-sshcrypto-confirm
# so it can only log in from loopback and can only print the token (no shell, pty or forwarding). known_hosts for
# the confirm session is built from this host's own /etc/ssh/ssh_host_*_key.pub (strict host key checking).
# Alert rules: copy ../alerts/sshcrypto.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, units, authorized_keys).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-sshcrypto
STATE=/var/lib/pft-sshcrypto
CONF=/etc/pft-sshcrypto.env
AK=/root/.ssh/authorized_keys
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_sshcrypto_*.prom   3h   pft_sshcrypto_last_run_timestamp_seconds'
label=""; uninstall=false; pull=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) label="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
[ -z "$label" ] || [[ "$label" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || { echo "bad host label" >&2; exit 3; }
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }

install_bin() {
  install -m 755 "$HERE/pft-sshcrypto.sh" /usr/local/bin/pft-sshcrypto
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/sshcrypto_grade.py" "$LIBDIR/sshcrypto_grade.py"
  install -m 644 "$HERE/hardened.conf" "$LIBDIR/hardened.conf"
  log "installed /usr/local/bin/pft-sshcrypto (sha256 $(sha256sum < "$HERE/pft-sshcrypto.sh" | cut -c1-64))"
  log "installed $LIBDIR/sshcrypto_grade.py (sha256 $(sha256sum < "$HERE/sshcrypto_grade.py" | cut -c1-64))"
  log "installed $LIBDIR/hardened.conf (sha256 $(sha256sum < "$HERE/hardened.conf" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-sshcrypto-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_sshcrypto_$peer.prom"
    log "disabled pft-sshcrypto-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-sshcrypto.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  install -m 644 "$HERE/systemd/pft-sshcrypto-pull.service" "$HERE/systemd/pft-sshcrypto-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-sshcrypto-pull.service || true
  if systemctl is-failed -q pft-sshcrypto-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-sshcrypto-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_sshcrypto_(up|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_sshcrypto_$peer.prom"
  systemctl enable --now pft-sshcrypto-pull.timer
  log "enabled pft-sshcrypto-pull.timer (every 15 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  if [ -f "$STATE/applied" ] || [ -f "$STATE/pending" ]; then
    echo "a policy is applied or a revert is armed: run 'sudo pft-sshcrypto rollback' first" >&2; exit 3
  fi
  systemctl disable --now pft-sshcrypto.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_sshcrypto_$host.prom" "$STATE/confirm_ed25519" "$STATE/confirm_ed25519.pub" "$STATE/known_hosts"
  [ -f "$AK" ] && sed -i '/ pft-sshcrypto-confirm$/d' "$AK"
  log "disabled pft-sshcrypto.timer, removed its textfile, the confirm key and its authorized_keys line"
  exit 0
fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
install_bin
if [ -f "$CONF" ]; then
  if grep -q '^HOST_LABEL=' "$CONF"; then sed -i "s/^HOST_LABEL=.*/HOST_LABEL=$host/" "$CONF"; else echo "HOST_LABEL=$host" >> "$CONF"; fi
else
  printf '# pft-sshcrypto config (see pft-sshcrypto.env.example)\nHOST_LABEL=%s\n' "$host" > "$CONF"
fi
chown root:root "$CONF"; chmod 600 "$CONF"
install -d -m 700 "$STATE"
if [ ! -f "$STATE/confirm_ed25519" ]; then
  (umask 077; ssh-keygen -q -t ed25519 -N '' -C pft-sshcrypto-confirm -f "$STATE/confirm_ed25519")
  log "created the loopback-only confirm key"
fi
install -d -m 700 /root/.ssh
touch "$AK"; chmod 600 "$AK"
if ! grep -q ' pft-sshcrypto-confirm$' "$AK"; then
  printf 'restrict,from="127.0.0.1,::1",command="echo pft-sshcrypto-confirm-ok" %s\n' \
    "$(cut -d' ' -f1-2 "$STATE/confirm_ed25519.pub") pft-sshcrypto-confirm" >> "$AK"
  log "added the restricted confirm key to root's authorized_keys (loopback only, forced command)"
fi
(umask 077; for p in /etc/ssh/ssh_host_*_key.pub; do printf 'pft-sshcrypto-loopback %s\n' "$(cut -d' ' -f1-2 "$p")"; done > "$STATE/known_hosts")
if [ -f "$RC_CONF" ] && ! grep -q 'pft_sshcrypto_' "$RC_CONF"; then
  printf '# pft-sshcrypto (hourly audit; sentry copy pulled every 15 min)\n%s\n' "$RC_LINE" >> "$RC_CONF"
  log "added the pft_sshcrypto textfile line to $RC_CONF"
fi
install -m 644 "$HERE/systemd/pft-sshcrypto.service" "$HERE/systemd/pft-sshcrypto.timer" /etc/systemd/system/
systemctl daemon-reload
log "confirm session (new loopback login with the confirm key):"
out="$(ssh -F /dev/null -i "$STATE/confirm_ed25519" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$STATE/known_hosts" -o GlobalKnownHostsFile=/dev/null \
  -o HostKeyAlias=pft-sshcrypto-loopback -o LogLevel=ERROR -l root 127.0.0.1 2>&1 < /dev/null || true)"
[ "$(printf '%s' "$out" | tr -d '\r' | tail -1)" = pft-sshcrypto-confirm-ok ] || { log "ERROR: confirm login failed: $out"; exit 1; }
log "confirm login OK"
log "first audit (through the sandboxed unit, HOST_LABEL=$host):"
systemctl start pft-sshcrypto.service || true
if systemctl is-failed -q pft-sshcrypto.service; then
  log "ERROR: first audit failed"; journalctl -u pft-sshcrypto.service -n 5 --no-pager --utc; exit 1
fi
grep -qx "pft_sshcrypto_up{host=\"$host\"} 1" "$TEXTDIR/pft_sshcrypto_$host.prom" || { log "ERROR: up != 1"; exit 1; }
grep -E "^pft_sshcrypto_(up|probes|probe_mismatches|policy_applied)\{" "$TEXTDIR/pft_sshcrypto_$host.prom"
systemctl enable --now pft-sshcrypto.timer
log "enabled pft-sshcrypto.timer (hourly + up to 10 min)"
log "remember: sudo pft-integrity accept --reason 'pft-sshcrypto installed'"
