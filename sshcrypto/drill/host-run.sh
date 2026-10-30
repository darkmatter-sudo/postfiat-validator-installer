#!/usr/bin/env bash
# host-run: live proof of pft-sshcrypto on ONE host, run as root on that host.
#   sudo bash sshcrypto/drill/host-run.sh LABEL [REVERT_SECS]      LABEL = validator | sentry (log label only)
# 0 preflight: installed, nothing applied, no snapshot, no armed timer; record the sha256 manifest of sshd_config +
#   sshd_config.d/* (M0) and the sha256 of `sshd -T` (E0).
# 1 before audit (exit 1 expected: the stock OpenSSH 8.9 lists carry FAIL/WARN items).
# 2 apply the hardened policy (exit 0: reload, new session confirmed, timer stopped). 3 after audit (exit 0).
# 4 rollback: manifest and sshd -T sha256 must equal M0/E0 again.
# 5 login-breaking drill: open a lifeline session (ssh ControlMaster over loopback, confirm key, no command), apply
#   tests/fixtures/policy-broken.conf (Ciphers aes128-cbc: sshd -t accepts it, no default client can connect) with
#   --revert-after REVERT_SECS (60). Checks: apply exits 3 without committing; a NEW session fails with "no matching
#   cipher"; the EXISTING session still runs commands; the transient timer fires by itself and its journal shows
#   ROLLBACK OK; manifest + sshd -T equal M0/E0; a new session works again; the lifeline is still up.
# The host ends in its pre-apply state; the alert drill (live-alert-drill.sh) applies the policy for good.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/.." || exit 3       # relative paths in every printed command (no home directory in the log)
FIX=tests/fixtures
LABEL="${1:?usage: host-run.sh LABEL [REVERT_SECS]}"; RS="${2:-60}"
ST=/var/lib/pft-sshcrypto
SOCK="$(mktemp -u /run/pft-sshcrypto-lifeline.XXXXXX)"
HN="$(hostname)"
FAILS=0
ts() { date -u +%FT%TZ; }
red() { sed -e "s/$HN/<host>/g"; }
check() { # NAME 0|1 [DETAIL]
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
XRC=0; XOUT=""
x() { # print the exact command, run it, print its output and exit code; output kept in XOUT
  echo "\$ $*"
  XOUT="$(eval "$*" 2>&1 < /dev/null)"; XRC=$?
  printf '%s\n' "$XOUT" | red | sed 's/^/  /'
  echo "  (exit $XRC)"
}
manifest() { (cd /etc/ssh && sha256sum sshd_config sshd_config.d/*); }
eff() { sshd -T 2>/dev/null | sha256sum | cut -c1-64; }
port() { sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}'; }
CK=(-F /dev/null -i "$ST/confirm_ed25519" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$ST/known_hosts" -o GlobalKnownHostsFile=/dev/null
    -o HostKeyAlias=pft-sshcrypto-loopback -o ConnectTimeout=10)
newsession() { ssh "${CK[@]}" -o ControlPath=none -o LogLevel=INFO -p "$(port)" -l root 127.0.0.1; }
lifeline() { ssh "${CK[@]}" -S "$SOCK" -o LogLevel=ERROR -p "$(port)" -l root 127.0.0.1 "$@"; }
open_lifeline() { ssh "${CK[@]}" -S "$SOCK" -M -fN -o LogLevel=ERROR -p "$(port)" -l root 127.0.0.1; }
cleanup() { [ -S "$SOCK" ] && ssh -S "$SOCK" -O exit x 2>/dev/null; rm -f "$SOCK"; }
trap cleanup EXIT

echo "pft-sshcrypto host run ($LABEL) - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - $(ssh -V 2>&1)"
echo "sha256: host-run.sh $(sha256sum < "$HERE/host-run.sh" | cut -c1-64)"
echo "        installed pft-sshcrypto $(sha256sum < /usr/local/bin/pft-sshcrypto | cut -c1-64)"
echo "        installed sshcrypto_grade.py $(sha256sum < /usr/local/lib/pft-sshcrypto/sshcrypto_grade.py | cut -c1-64)"
echo "        installed hardened.conf $(sha256sum < /usr/local/lib/pft-sshcrypto/hardened.conf | cut -c1-64)"
echo "        policy-broken.conf $(sha256sum < "$FIX/policy-broken.conf" | cut -c1-64)"

echo; echo "== 0. preflight"
x "pft-sshcrypto status"
check "0a nothing applied, no snapshot, no armed timer" "$(grep -qx 'state: none' <<<"$XOUT" && grep -qx 'snapshot: none' <<<"$XOUT" && grep -qx 'revert timer: not armed' <<<"$XOUT" && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "not in the pre-apply state - stopping before any change"; exit 4; }
M0="$(manifest)"; E0="$(eff)"
echo "M0 (sha256 of sshd_config + sshd_config.d/*):"; printf '%s\n' "$M0" | sed 's/^/  /'
echo "E0 (sha256 of sshd -T): $E0"

echo; echo "== 1. before audit"
x "pft-sshcrypto audit"
check "1a before: exit 1 (findings)" "$([ "$XRC" = 1 ] && echo 0 || echo 1)" "$(tail -1 <<<"$XOUT")"

echo; echo "== 2. apply the hardened policy"
x "pft-sshcrypto apply"
check "2a apply exit 0, APPLIED" "$([ "$XRC" = 0 ] && grep -q '^.* APPLIED: ' <<<"$XOUT" && echo 0 || echo 1)"
x "cat /etc/ssh/sshd_config.d/10-pft-sshcrypto.conf"

echo; echo "== 3. after audit"
x "pft-sshcrypto audit"
check "3a after: exit 0, RESULT OK, 0 warn, 0 fail, 0 mismatches" "$([ "$XRC" = 0 ] && grep -q '^RESULT: OK - .* 0 warn, 0 fail, .* 0 probe mismatches, 0 errors -> exit 0$' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 4. rollback (byte-identical)"
x "pft-sshcrypto rollback"
check "4a rollback exit 0, ROLLBACK OK" "$([ "$XRC" = 0 ] && grep -q 'ROLLBACK OK' <<<"$XOUT" && echo 0 || echo 1)"
M1="$(manifest)"; E1="$(eff)"
echo "M1:"; printf '%s\n' "$M1" | sed 's/^/  /'; echo "E1: $E1"
check "4b manifest after rollback == M0" "$([ "$M1" = "$M0" ] && echo 0 || echo 1)"
check "4c sshd -T sha256 after rollback == E0" "$([ "$E1" = "$E0" ] && echo 0 || echo 1)"
check "4d drop-in gone" "$([ ! -e /etc/ssh/sshd_config.d/10-pft-sshcrypto.conf ] && echo 0 || echo 1)"

echo; echo "== 5. login-breaking drill (automatic revert after ${RS}s)"
x "open_lifeline && ssh -S \$SOCK -O check x"
check "5a lifeline session open (ControlMaster over loopback)" "$([ "$XRC" = 0 ] && echo 0 || echo 1)"
x "lifeline"
check "5b lifeline runs a command before the drill" "$([ "$(tail -1 <<<"$XOUT" | tr -d '\r')" = pft-sshcrypto-confirm-ok ] && echo 0 || echo 1)"
t0="$(date -u +%s)"
x "pft-sshcrypto apply --policy $FIX/policy-broken.conf --revert-after $RS"
check "5c broken policy: apply exit 3, CONFIRM FAILED (no matching cipher), not committed" "$([ "$XRC" = 3 ] && grep -q 'CONFIRM FAILED: new session: Unable to negotiate .*no matching cipher found' <<<"$XOUT" && grep -q 'not committed' <<<"$XOUT" && echo 0 || echo 1)"
x "pft-sshcrypto status"
check "5d pending, revert timer armed" "$(grep -q '^state: pending' <<<"$XOUT" && grep -qx 'revert timer: armed' <<<"$XOUT" && echo 0 || echo 1)"
x "newsession | sed 's/Their offer:.*/Their offer: .../'"
check "5e a NEW session fails while the broken policy is live" "$([ "$XRC" != 0 ] && grep -q 'no matching cipher found' <<<"$XOUT" && echo 0 || echo 1)"
x "ssh -S \$SOCK -O check x && lifeline"
check "5f the EXISTING session still runs commands" "$([ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT" | tr -d '\r')" = pft-sshcrypto-confirm-ok ] && echo 0 || echo 1)"
echo "  waiting for the timer (no command from here until the revert)"
while [ $(( $(date -u +%s) - t0 )) -lt $((RS + 90)) ]; do
  [ -f "$ST/pending" ] || break
  sleep 5
done
echo "  $(ts) pending cleared $(( $(date -u +%s) - t0 ))s after the apply started"
x "journalctl --utc -o short-iso --no-pager -u pft-sshcrypto-revert.service --since @$t0"
check "5g the timer ran rollback --auto by itself: ROLLBACK OK in its journal" "$(grep -q 'automatic revert (timer)' <<<"$XOUT" && grep -q 'ROLLBACK OK' <<<"$XOUT" && echo 0 || echo 1)"
M2="$(manifest)"; E2="$(eff)"
echo "M2:"; printf '%s\n' "$M2" | sed 's/^/  /'; echo "E2: $E2"
check "5h manifest after the automatic revert == M0" "$([ "$M2" = "$M0" ] && echo 0 || echo 1)"
check "5i sshd -T sha256 after the automatic revert == E0" "$([ "$E2" = "$E0" ] && echo 0 || echo 1)"
x "newsession"
check "5j a NEW session works again" "$([ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT" | tr -d '\r')" = pft-sshcrypto-confirm-ok ] && echo 0 || echo 1)"
x "ssh -S \$SOCK -O check x && lifeline"
check "5k lifeline still up after the revert" "$([ "$XRC" = 0 ] && echo 0 || echo 1)"
x "pft-sshcrypto status"
check "5l state none, timer gone" "$(grep -qx 'state: none' <<<"$XOUT" && grep -qx 'revert timer: not armed' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "host run ($LABEL) done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
