#!/usr/bin/env bash
# Install / verify pft-sshban: fail2ban sshd jail for a keys-only Post Fiat validator or sentry (Ubuntu 22.04).
#   sudo ./install.sh [--ignore CIDR]...   apt-get install fail2ban (Ubuntu archive), write
#        /etc/fail2ban/jail.d/pft-sshd.local = pft-sshd.jail + "ignoreip = 127.0.0.1/8 ::1 CIDR...", disable the
#        distro's defaults-debian sshd jail, restart fail2ban, then check the jail is up with the systemd backend.
#        Pass the peer host's address (and your own admin sources) with --ignore. Idempotent.
#   sudo ./install.sh --check              print the jail status (no changes)
#   sudo ./install.sh --uninstall          remove the jail file and stop fail2ban (package kept)
# Never touches sshd_config: password/key settings stay as they are.
# Afterwards: sudo pft-integrity accept --reason "<why>".
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAIL=/etc/fail2ban/jail.d/pft-sshd.local
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
ignore=(); mode=install
while [ $# -gt 0 ]; do
  case "$1" in
    --ignore) [[ "${2:-}" =~ ^[0-9a-fA-F.:]+(/[0-9]{1,3})?$ ]] || { echo "bad --ignore CIDR" >&2; exit 3; }
              ignore+=("$2"); shift ;;
    --check) mode=check ;;
    --uninstall) mode=uninstall ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
check() {
  fail2ban-client ping
  fail2ban-client get sshd backend 2>/dev/null | sed 's/^/backend: /' || true
  fail2ban-client get sshd maxretry | sed 's/^/maxretry: /'
  fail2ban-client get sshd findtime | sed 's/^/findtime: /'
  fail2ban-client get sshd bantime | sed 's/^/bantime: /'
  echo "ignoreip entries: $(fail2ban-client get sshd ignoreip | grep -cE '[0-9a-fA-F]+[.:]')"
  fail2ban-client status sshd | sed -E 's/(Banned IP list:).*/\1 <redacted>/'
}
case "$mode" in
  check) check; exit 0 ;;
  uninstall) rm -f "$JAIL"; systemctl disable --now fail2ban 2>&1 | sed 's/^/  /'; log "removed $JAIL, fail2ban stopped"; exit 0 ;;
esac
if ! dpkg -s fail2ban >/dev/null 2>&1; then
  log "installing fail2ban from the Ubuntu archive"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q fail2ban 2>&1 | tail -3
fi
log "fail2ban $(dpkg-query -W -f '${Version}' fail2ban)"
tmp="$(mktemp)"
cat "$HERE/pft-sshd.jail" > "$tmp"
echo "ignoreip = 127.0.0.1/8 ::1${ignore[*]:+ ${ignore[*]}}" >> "$tmp"
if [ -f "$JAIL" ] && cmp -s "$tmp" "$JAIL"; then log "unchanged $JAIL"; rm -f "$tmp"; else
  install -m 644 "$tmp" "$JAIL"; rm -f "$tmp"; log "installed $JAIL (+${#ignore[@]} ignore entries)"; fi
# jail.d/*.local is read after defaults-debian.conf, so this [sshd] overrides the distro's backend/limits
fail2ban-client -t >/dev/null || { log "ERROR: fail2ban config test failed"; fail2ban-client -t; exit 1; }
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban
for _ in $(seq 1 20); do fail2ban-client ping >/dev/null 2>&1 && break; sleep 1; done
check
log "remember: sudo pft-integrity accept --reason 'pft-sshban installed'"
