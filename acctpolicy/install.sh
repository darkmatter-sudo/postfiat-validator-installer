#!/usr/bin/env bash
# Install / uninstall pft-acctpolicy. Installing changes NO account, PAM or login.defs setting; `pft-acctpolicy apply`
# does (and only after its self-test).
#   sudo ./install.sh              script -> /usr/local/bin/pft-acctpolicy (skipped if pft-fleet already installed the
#       same bytes), state dir /var/lib/pft-acctpolicy 0700, the self-test key STATE_DIR/selftest_ed25519 (root 0600,
#       accepted only by the throwaway 127.0.0.1 sshd of the self-test, never added to any authorized_keys file), and
#       its fingerprint in the pft-authwatch allowlist if pft-authwatch is installed (the self-test logs to a private
#       file, so this is a second guard against a PFTAuthUnknownKeyLogin page). Then one read-only audit.
#   sudo ./install.sh --uninstall  refuses while an apply is in place (rollback first); removes the allowlist entry
#       and the self-test key (keeps the script: pft-fleet owns it).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary; allowlist file if authwatch is installed).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=/usr/local/bin/pft-acctpolicy
STATE=/var/lib/pft-acctpolicy
KEY="$STATE/selftest_ed25519"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
uninstall=false
case "${1:-}" in --uninstall) uninstall=true ;; "") ;; *) echo "unknown argument: $1" >&2; exit 3 ;; esac
fp() { ssh-keygen -lf "$KEY.pub" | awk '{ print $2 }'; }

if $uninstall; then
  [ ! -f "$STATE/apply.json" ] || { echo "an apply is in place: sudo pft-acctpolicy rollback --yes first" >&2; exit 4; }
  if [ -f "$KEY.pub" ] && command -v pft-authwatch >/dev/null; then
    f="$(fp)"
    if pft-authwatch allow list 2>/dev/null | grep -qF "$f"; then pft-authwatch allow remove "$f" >/dev/null; log "authwatch allowlist: self-test key removed"; fi
  fi
  rm -f "$KEY" "$KEY.pub"
  log "removed the self-test key (kept $BIN and $STATE backups)"
  exit 0
fi

if [ -f "$BIN" ] && cmp -s "$HERE/pft-acctpolicy.sh" "$BIN"; then log "$BIN already current"
else install -o root -g root -m 0755 "$HERE/pft-acctpolicy.sh" "$BIN"; log "installed $BIN"; fi
install -d -o root -g root -m 0700 "$STATE"
if [ ! -f "$KEY" ]; then
  ssh-keygen -q -t ed25519 -N '' -C pft-acctpolicy-selftest -f "$KEY"; chmod 600 "$KEY"; chmod 644 "$KEY.pub"
  log "created the self-test key"
fi
if command -v pft-authwatch >/dev/null; then
  f="$(fp)"
  if pft-authwatch allow list 2>/dev/null | grep -qF "$f"; then log "authwatch allowlist: self-test key already listed"
  else pft-authwatch allow add "$f" "pft-acctpolicy self-test (throwaway 127.0.0.1 sshd only)" >/dev/null
    log "authwatch allowlist: self-test key added"; fi
fi
log "audit:"
"$BIN" audit || true
