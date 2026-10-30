#!/usr/bin/env bash
# Stubbed tests for pft-sshcrypto.sh + sshcrypto_grade.py. No root, no real sshd/ssh/systemd, no host is touched.
# Each case gets a fresh fake root (PFT_SC_ROOT: etc/ssh, var/lib/pft-sshcrypto) and stubs.py stands in for sshd,
# ssh, ssh-keygen, systemctl and systemd-run (see its docstring). One PASS/FAIL line per check; exit 1 if any failed.
#   Usage: tests/run-tests.sh [PFT_SSHCRYPTO_SH] [SSHCRYPTO_GRADE_PY]
# shellcheck disable=SC2016,SC2034  # check conditions are single-quoted and eval'd by check(), which reads D, sha_before, ...
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$(readlink -f "${1:-$HERE/../pft-sshcrypto.sh}")"
GRADEPY="$(readlink -f "${2:-$HERE/../sshcrypto_grade.py}")"
FIX="$HERE/fixtures"
T="$(mktemp -d)"
trap 'rm -rf "${T:?}"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
# check NAME 'CONDITION' : condition runs in a subshell, so an exit inside it cannot end the suite
check() { if (eval "$2") >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

mkdir -p "$T/bin" "$T/lib"
for s in sshd ssh ssh-keygen systemctl systemd-run; do
  printf '#!/bin/sh\nexec python3 %q %s "$@"\n' "$HERE/stubs.py" "$s" > "$T/bin/$s"; chmod +x "$T/bin/$s"
done
cp "$GRADEPY" "$T/lib/sshcrypto_grade.py"; cp "$HERE/../hardened.conf" "$T/lib/hardened.conf"
export PFT_SC_SSHD="$T/bin/sshd" PFT_SC_SSH="$T/bin/ssh" PFT_SC_KEYGEN="$T/bin/ssh-keygen" \
  PFT_SC_SYSTEMCTL="$T/bin/systemctl" PFT_SC_SYSTEMD_RUN="$T/bin/systemd-run" PFT_SC_LIB="$T/lib" \
  PFT_SC_NOW=1800000000 PFT_SC_SELF="$TOOL" PFT_SC_CONF="$T/env"
: > "$T/env"

# fresh BASE_FIXTURE [MODULI] : new fake root R, textfile dir TF, running daemon = the effective config
fresh() {
  R="$T/root.$((++N))"; TF="$R/textfile"
  mkdir -p "$R/etc/ssh/sshd_config.d" "$R/var/lib/pft-sshcrypto" "$TF"
  printf 'Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\n' > "$R/etc/ssh/sshd_config"
  printf 'X11Forwarding no\n' > "$R/etc/ssh/sshd_config.d/40-other.conf"
  cp "$FIX/${2:-moduli-2048}" "$R/etc/ssh/moduli"
  : > "$R/var/lib/pft-sshcrypto/confirm_ed25519"; : > "$R/var/lib/pft-sshcrypto/known_hosts"
  local base="$1"; [ -f "$base" ] || base="$FIX/$1"
  export PFT_SC_ROOT="$R" STUB_BASE="$base"
  printf 'TEXTFILE_DIR=%s\n' "$TF" > "$T/env"   # never the real textfile dir
  python3 "$HERE/stubs.py" systemctl reload ssh; : > "$R/calls.log"
}
N=0
sc() { bash "$TOOL" "$@"; }
audit_to() { sc audit --textfile-dir "$TF" "$@" > "$T/out" 2>&1; echo $? > "$T/rc"; }
rc() { cat "$T/rc"; }
prom() { cat "$TF/pft_sshcrypto_validator.prom"; }

echo "== audit: Ubuntu 22.04 / OpenSSH 8.9 defaults"
fresh sshdT-default.txt
audit_to
check "A1 defaults: exit 1, RESULT FAIL" '[ "$(rc)" = 1 ] && grep -q "^RESULT: FAIL - " "$T/out"'
check "A2 hmac-sha1 and hmac-sha1-etm graded FAIL" 'grep -qE "mac +FAIL +hmac-sha1 " "$T/out" && grep -qE "mac +FAIL +hmac-sha1-etm@openssh.com" "$T/out"'
check "A3 umac-64@openssh.com FAIL, umac-64-etm WARN" 'grep -qE "mac +FAIL +umac-64@openssh.com" "$T/out" && grep -qE "mac +WARN +umac-64-etm@openssh.com" "$T/out"'
check "A4 ecdh-sha2-nistp256 and group14-sha256 WARN" 'grep -qE "kex +WARN +ecdh-sha2-nistp256" "$T/out" && grep -qE "kex +WARN +diffie-hellman-group14-sha256" "$T/out"'
check "A5 group-exchange WARN with 2048-bit moduli" 'grep -qE "kex +WARN +diffie-hellman-group-exchange-sha256 +group exchange can use 2048-bit moduli" "$T/out"'
check "A6 curve25519/sntrup/chacha20/etm OK" 'grep -qE "kex +OK +curve25519-sha256 " "$T/out" && grep -qE "kex +OK +sntrup761" "$T/out" && grep -qE "cipher +OK +chacha20" "$T/out" && grep -qE "mac +OK +hmac-sha2-512-etm" "$T/out"'
check "A7 host key files: RSA 3072 OK, ECDSA 256 WARN, ED25519 OK" 'grep -qE "hostkey-file OK +RSA 3072" "$T/out" && grep -qE "hostkey-file WARN +ECDSA 256" "$T/out" && grep -qE "hostkey-file OK +ED25519 256" "$T/out"'
check "A8 counts: 3 fail (hmac-sha1, hmac-sha1-etm, umac-64)" 'grep -q "^RESULT: FAIL - .* 3 fail," "$T/out"'
check "A9 27 probes, 0 mismatches, 0 errors" 'grep -q " 27 probes, 0 probe mismatches, 0 errors -> exit 1$" "$T/out"'
check "A10 probe positive controls negotiated (hostkey control is ssh-ed25519, not a cert)" 'grep -qE "probe +hostkey ssh-ed25519 +expected offered, negotiated: match" "$T/out" && grep -qE "probe +kex +curve25519-sha256 +expected offered, negotiated" "$T/out"'
check "A11 absent weak algorithms rejected by the handshake" 'grep -qE "probe +cipher +aes128-cbc +expected absent, rejected: match" "$T/out" && grep -qE "probe +kex +diffie-hellman-group1-sha1 +expected absent, rejected" "$T/out"'
check "A12 offered weak MAC negotiated over a non-AEAD cipher" 'grep -qE "probe +mac +hmac-sha1 +expected offered, negotiated: match" "$T/out"'
check "A13 ecdsa-sha2-nistp384 listed but no P-384 key: expected absent, rejected (no false mismatch)" 'grep -qE "probe +hostkey ecdsa-sha2-nistp384 +expected absent, rejected: match" "$T/out"'
check "A14 output never prints host key paths or fingerprints" '! grep -qE "/etc/ssh|SHA256:|stubhost" "$T/out"'
check "A15 metrics: up 1, mac fail 3, probes 27, mismatches 0, policy_applied 0, pending 0" 'prom | grep -qx "pft_sshcrypto_up{host=\"validator\"} 1" && prom | grep -qx "pft_sshcrypto_findings{host=\"validator\",kind=\"mac\",grade=\"fail\"} 3" && prom | grep -qx "pft_sshcrypto_probes{host=\"validator\"} 27" && prom | grep -qx "pft_sshcrypto_probe_mismatches{host=\"validator\"} 0" && prom | grep -qx "pft_sshcrypto_policy_applied{host=\"validator\"} 0" && prom | grep -qx "pft_sshcrypto_revert_pending{host=\"validator\"} 0"'
check "A16 metrics: hostkey_bits for offered keys only" 'prom | grep -qx "pft_sshcrypto_hostkey_bits{host=\"validator\",type=\"rsa\"} 3072" && prom | grep -qx "pft_sshcrypto_hostkey_bits{host=\"validator\",type=\"ecdsa\"} 256"'
check "A17 textfile passes validate for its host and fails for another" 'sc validate "$TF/pft_sshcrypto_validator.prom" validator && ! sc validate "$TF/pft_sshcrypto_validator.prom" sentry'
check "A18 no temp file left in the textfile dir" '[ "$(ls -A "$TF" | wc -l)" = 1 ]'
sc audit --json --textfile-dir "$TF" > "$T/json" 2>&1; echo $? > "$T/rc"
check "A19 --json: valid JSON, result FAIL, exit field = rc 1, counts.FAIL 3" '[ "$(rc)" = 1 ] && python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d[\"result\"]==\"FAIL\" and d[\"exit\"]==1 and d[\"counts\"][\"FAIL\"]==3 and d[\"probes_run\"]==27" "$T/json"'
check "A20 --json: hostkeys carry type/bits only (no path)" 'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert all(set(k)=={\"type\",\"bits\",\"offered\",\"grade\",\"reason\"} for k in d[\"hostkeys\"])" "$T/json"'

echo "== audit: moduli >= 3072, legacy config, key sizes"
fresh sshdT-default.txt moduli-3072
audit_to --no-probe
check "B1 group-exchange OK when every modulus >= 3072 bits" 'grep -qE "kex +OK +diffie-hellman-group-exchange-sha256 +group exchange, smallest modulus 3072 bits" "$T/out"'
check "B2 --no-probe: 0 probes, still graded" 'grep -q " 0 probes, " "$T/out" && ! grep -q "^  probe " "$T/out"'
fresh sshdT-legacy.txt
STUB_KEYS="RSA:1024,DSA:1024" audit_to
check "B3 legacy: CBC, 3DES, group1/14-sha1, hmac-md5 FAIL" 'grep -qE "cipher +FAIL +aes128-cbc" "$T/out" && grep -qE "cipher +FAIL +3des-cbc" "$T/out" && grep -qE "kex +FAIL +diffie-hellman-group1-sha1" "$T/out" && grep -qE "mac +FAIL +hmac-md5" "$T/out"'
check "B4 legacy: ssh-rsa / ssh-dss host key algorithms FAIL" 'grep -qE "hostkey +FAIL +ssh-rsa " "$T/out" && grep -qE "hostkey +FAIL +ssh-dss" "$T/out"'
check "B5 legacy: RSA 1024 and DSA host key files FAIL" 'grep -qE "hostkey-file FAIL +RSA 1024 +RSA < 2048" "$T/out" && grep -qE "hostkey-file FAIL +DSA 1024" "$T/out"'
check "B6 legacy: user-key ssh-rsa and CA ssh-dss FAIL, ssh-ed25519 user key OK" 'grep -qE "pubkey +FAIL +ssh-rsa" "$T/out" && grep -qE "casig +FAIL +ssh-dss" "$T/out" && grep -qE "pubkey +OK +ssh-ed25519" "$T/out"'
check "B7 legacy: probes on the configured port 2222 / 127.0.0.1, offered CBC negotiated" 'grep -qE "probe +cipher +aes128-cbc +expected offered, negotiated: match" "$T/out"'
fresh sshdT-default.txt
STUB_KEYS="RSA:2048,ECDSA:256,ED25519:256" audit_to --no-probe
check "B8 RSA 2048 graded WARN" 'grep -qE "hostkey-file WARN +RSA 2048 +RSA < 3072" "$T/out"'
fresh sshdT-default.txt
cp "$HERE/../hardened.conf" "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf"
python3 "$HERE/stubs.py" systemctl reload ssh
audit_to
check "B9 hardened policy: exit 0, RESULT OK, 0 warn, 0 fail, 0 mismatches" '[ "$(rc)" = 0 ] && grep -q "^RESULT: OK - .* 0 warn, 0 fail, .* 0 probe mismatches, 0 errors -> exit 0$" "$T/out"'
check "B10 hardened: ECDSA key file UNUSED (not offered, not counted)" 'grep -qE "hostkey-file UNUSED +ECDSA 256" "$T/out" && ! prom | grep -q "type=\"ecdsa\""'
check "B11 hardened: every weak probe rejected (ecdh, hmac-sha1, umac-64, ecdsa host key)" 'grep -qE "probe +kex +ecdh-sha2-nistp256 +expected absent, rejected: match" "$T/out" && grep -qE "probe +mac +hmac-sha1 +expected absent, rejected: match" "$T/out" && grep -qE "probe +hostkey ecdsa-sha2-nistp256 +expected absent, rejected: match" "$T/out"'
printf 'kexalgorithms curve25519-sha256,made-up-kex@example.com\n' > "$T/unk.txt"; grep -v '^kexalgorithms' "$FIX/sshdT-default.txt" >> "$T/unk.txt"
fresh "$T/unk.txt"; audit_to --no-probe
check "B12 unknown algorithm graded WARN (not in policy)" 'grep -qE "kex +WARN +made-up-kex@example.com +not in policy" "$T/out"'

echo "== audit: errors and mismatches"
fresh sshdT-default.txt
STUB_SSHD_T_FAIL=1 audit_to
check "C1 sshd -T fails: exit 2, RESULT ERROR" '[ "$(rc)" = 2 ] && grep -q "^RESULT: ERROR" "$T/out"'
check "C2 sshd -T fails: up 0 and no findings series" 'prom | grep -qx "pft_sshcrypto_up{host=\"validator\"} 0" && ! prom | grep -q "^pft_sshcrypto_findings"'
STUB_KEYGEN_FAIL=1 audit_to --no-probe
check "C3 host key unreadable: exit 2" '[ "$(rc)" = 2 ] && grep -q "ssh-keygen -l failed" "$T/out"'
STUB_SSH_REFUSE=1 audit_to
check "C4 probe cannot connect: exit 2 with the reason" '[ "$(rc)" = 2 ] && grep -q "could not run: ssh: connect to host 127.0.0.1 port 22: Connection refused" "$T/out"'
grep -v '^listenaddress' "$FIX/sshdT-default.txt" > "$T/nolb.txt"; echo "listenaddress 192.0.2.10:22" >> "$T/nolb.txt"
STUB_BASE="$T/nolb.txt" audit_to
check "C5 no loopback/wildcard listener: exit 2" '[ "$(rc)" = 2 ] && grep -q "no loopback or wildcard address" "$T/out"'
STUB_BASE="$T/nolb.txt" audit_to --no-probe
check "C6 same with --no-probe: graded, exit 1" '[ "$(rc)" = 1 ]'
grep -v '^listenaddress' "$FIX/sshdT-default.txt" > "$T/v6.txt"; echo "listenaddress [::]:22" >> "$T/v6.txt"
STUB_BASE="$T/v6.txt" audit_to
check "C7 IPv6-only wildcard listener: probes run against ::1" '[ "$(rc)" = 1 ] && grep -q " 27 probes, 0 probe mismatches, 0 errors" "$T/out"'
fresh sshdT-default.txt
cp "$HERE/../hardened.conf" "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf"   # on disk, NOT reloaded
audit_to
check "C8 config on disk not reloaded: probe MISMATCH, exit 1, RESULT FAIL" '[ "$(rc)" = 1 ] && grep -q "MISMATCH" "$T/out" && grep -q "^RESULT: FAIL - .* 0 fail, " "$T/out"'
check "C9 mismatch counted in metrics" 'prom | grep -qE "^pft_sshcrypto_probe_mismatches\{host=\"validator\"\} [1-9]"'
fresh sshdT-default.txt
STUB_CLIENT_LACKS="3des-cbc,hmac-md5" audit_to
check "C10 algorithm the local client lacks: skipped, not a mismatch" 'grep -qE "probe +cipher +3des-cbc +expected absent, skipped: match" "$T/out" && grep -q " 25 probes, 0 probe mismatches" "$T/out"'
grep -v '^ciphers' "$FIX/sshdT-default.txt" > "$T/aead.txt"; echo "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" >> "$T/aead.txt"
fresh "$T/aead.txt"; audit_to
check "C11 AEAD-only ciphers: MAC probes skipped (MACs never negotiated)" 'grep -qE "probe +mac +hmac-sha1 +expected offered, skipped: match" "$T/out" && ! grep -q MISMATCH "$T/out"'

echo "== apply / confirm / commit"
fresh sshdT-default.txt
sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
D="$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf"
check "D1 apply hardened: exit 0, APPLIED" '[ "$(rc)" = 0 ] && grep -q "APPLIED: revert timer stopped" "$T/out"'
cp "$D" "$T/dropin1"
check "D2 drop-in = header + hardened.conf directives" '[ "$(grep -vc "^#" "$D")" = 4 ] && diff <(grep -v "^#" "$D") <(grep -vE "^(#|$)" "$HERE/../hardened.conf")'
check "D3 revert timer armed before the reload, 120 s, runs rollback --auto" 'grep -n "" "$R/calls.log" | grep -m1 "systemd-run" | grep -q -- "--on-active=120s .* rollback --auto" && [ "$(grep -n "systemd-run" "$R/calls.log" | cut -d: -f1)" -lt "$(grep -n "systemctl reload ssh" "$R/calls.log" | cut -d: -f1)" ]'
check "D4 reload, never restart" 'grep -q "systemctl reload ssh" "$R/calls.log" && ! grep -q "restart" "$R/calls.log"'
check "D5 confirmed: timer stopped, no pending, applied recorded" '[ ! -f "$R/armed" ] && [ ! -f "$R/var/lib/pft-sshcrypto/pending" ] && [ -s "$R/var/lib/pft-sshcrypto/applied" ]'
check "D6 snapshot: manifest of 2 files + drop-in absent + sshd -T sha" '[ "$(wc -l < "$R/var/lib/pft-sshcrypto/pre/manifest")" = 2 ] && [ -f "$R/var/lib/pft-sshcrypto/pre/dropin.absent" ] && grep -qE "^[0-9a-f]{64}$" "$R/var/lib/pft-sshcrypto/pre/effective.sha256"'
check "D7 metrics after apply: policy_applied 1, fail 0" 'prom | grep -qx "pft_sshcrypto_policy_applied{host=\"validator\"} 1" && prom | grep -qx "pft_sshcrypto_findings{host=\"validator\",kind=\"mac\",grade=\"fail\"} 0"'
sc status > "$T/status" 2>&1
check "D8 status: applied, drop-in present" 'grep -qx "state: applied" "$T/status" && grep -q "^drop-in: present" "$T/status"'
sc rollback > "$T/out2" 2>&1; echo $? > "$T/rc"
sc apply > /dev/null 2>&1
check "D2b a second apply writes the same bytes (deterministic drop-in)" 'cmp -s "$D" "$T/dropin1"'
sc rollback > "$T/out2" 2>&1; echo $? > "$T/rc"
check "D9 rollback: exit 0, 3 checks logged, drop-in gone" '[ "$(rc)" = 0 ] && grep -q "files: 2 sha256-identical to the snapshot" "$T/out2" && grep -q "ROLLBACK OK" "$T/out2" && [ ! -e "$D" ]'
check "D10 rollback: sshd -T identical, applied cleared, snapshot kept as last-rollback" 'grep -q "sshd -T sha256 [0-9a-f]\{64\} identical" "$T/out2" && [ ! -f "$R/var/lib/pft-sshcrypto/applied" ] && [ -d "$R/var/lib/pft-sshcrypto/last-rollback" ] && [ ! -d "$R/var/lib/pft-sshcrypto/pre" ]'
sc rollback > "$T/out" 2>&1; echo $? > "$T/rc"
check "D11 second rollback: nothing to roll back, exit 2" '[ "$(rc)" = 2 ] && grep -q "nothing to roll back" "$T/out"'

echo "== login-breaking policy: confirm fails, timer reverts"
fresh sshdT-default.txt
sha_before="$(cd "$R/etc/ssh" && sha256sum sshd_config sshd_config.d/*)"
sc apply --policy "$FIX/policy-broken.conf" --revert-after 60 > "$T/out" 2>&1; echo $? > "$T/rc"
check "E1 broken policy: exit 3, CONFIRM FAILED: no matching cipher" '[ "$(rc)" = 3 ] && grep -q "CONFIRM FAILED: new session: Unable to negotiate .* no matching cipher found" "$T/out"'
check "E2 not committed: timer still armed, pending set, drop-in still in place" '[ -f "$R/armed" ] && [ -f "$R/var/lib/pft-sshcrypto/pending" ] && [ -f "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf" ] && ! grep -q "systemctl stop" "$R/calls.log"'
check "E3 timer armed for 60 s" 'grep -q -- "--on-active=60s" "$R/calls.log"'
sc audit --no-probe --textfile-dir "$TF" > /dev/null 2>&1
check "E4 metrics while waiting: revert_pending 1" 'prom | grep -qx "pft_sshcrypto_revert_pending{host=\"validator\"} 1"'
sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "E5 apply refused while a revert is armed" '[ "$(rc)" = 2 ] && grep -q "already armed" "$T/out"'
read -r -a cmd < "$R/armed"   # what the transient timer would run
bash "${cmd[@]}" > "$T/out" 2>&1; echo $? > "$T/rc"
check "E6 timer action = rollback --auto: exit 0, automatic revert logged" '[ "$(rc)" = 0 ] && grep -q "automatic revert (timer)" "$T/out" && grep -q "ROLLBACK OK" "$T/out"'
check "E7 after revert: sshd_config(.d) sha256 identical to before apply" '[ "$(cd "$R/etc/ssh" && sha256sum sshd_config sshd_config.d/*)" = "$sha_before" ]'
check "E8 after revert: new session confirmed, pending cleared" 'grep -q "confirmed: new session logged in after the rollback" "$T/out" && [ ! -f "$R/var/lib/pft-sshcrypto/pending" ]'
check "E9 --auto does not stop its own (already elapsed) timer" '! grep -q "systemctl stop" "$R/calls.log"'

echo "== refusals and restores"
fresh sshdT-default.txt
printf 'Ciphers aes256-ctr\nBogus yes\n' > "$T/bogus.conf"
sc apply --policy "$T/bogus.conf" > "$T/out" 2>&1; echo $? > "$T/rc"
check "F1 policy with a non-crypto directive refused before writing" '[ "$(rc)" = 2 ] && grep -q "may only set" "$T/out" && [ ! -e "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf" ]'
fresh sshdT-default.txt
printf 'Bogus yes\n' > "$R/etc/ssh/sshd_config.d/45-broken.conf"
sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "F2 sshd -t fails: exit 2, drop-in removed again, no timer, no reload" '[ "$(rc)" = 2 ] && grep -q "sshd -t rejected" "$T/out" && [ ! -e "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf" ] && ! grep -qE "systemd-run|reload" "$R/calls.log"'
fresh sshdT-default.txt
printf 'Ciphers aes256-ctr\n' > "$R/etc/ssh/sshd_config.d/05-early.conf"
sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "F3 policy shadowed by an earlier drop-in: exit 2, restored, no reload" '[ "$(rc)" = 2 ] && grep -q "effective Ciphers differs" "$T/out" && [ ! -e "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf" ] && ! grep -q reload "$R/calls.log"'
fresh sshdT-default.txt
printf 'KbdInteractiveAuthentication no\n' > "$R/etc/ssh/sshd_config"
sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "F4 sshd_config without the Include: refused" '[ "$(rc)" = 2 ] && grep -q "does not Include" "$T/out"'
fresh sshdT-default.txt
sc apply --revert-after 10 > "$T/out" 2>&1; echo $? > "$T/rc"
check "F5 --revert-after below 30 s refused" '[ "$(rc)" = 2 ] && grep -q ">= 30" "$T/out"'
fresh sshdT-default.txt
STUB_RUN_FAIL=1 sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "F6 revert timer cannot be armed: exit 2, restored, no reload" '[ "$(rc)" = 2 ] && grep -q "could not arm" "$T/out" && [ ! -e "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf" ] && ! grep -q reload "$R/calls.log"'
fresh sshdT-default.txt
STUB_RELOAD_NOOP=1 sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "F7 daemon did not pick up the change (probe mismatch): exit 3, not committed" '[ "$(rc)" = 3 ] && grep -q "post-reload audit" "$T/out" && [ -f "$R/armed" ] && [ ! -f "$R/var/lib/pft-sshcrypto/applied" ]'
fresh sshdT-default.txt
STUB_CONFIRM_DENY=1 sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "F8 new session denied: exit 3, timer left armed" '[ "$(rc)" = 3 ] && grep -q "CONFIRM FAILED: new session: .*Permission denied" "$T/out" && [ -f "$R/armed" ]'
fresh sshdT-default.txt
STUB_RELOAD_FAIL=1 sc apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "F9 reload fails: exit 3, timer left armed to restore" '[ "$(rc)" = 3 ] && grep -q "reload failed" "$T/out" && [ -f "$R/armed" ]'

echo "== rollback byte-identity"
fresh sshdT-default.txt
printf '# operator file with the same name\nCiphers aes256-gcm@openssh.com\n' > "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf"
touch -d '2026-01-02 03:04:05 UTC' "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf"
pre_sha="$(sha256sum < "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf")"
sc apply > /dev/null 2>&1; sc apply > "$T/out" 2>&1
check "G1 second apply keeps the first snapshot" 'grep -q "snapshot kept from" "$T/out"'
sc rollback > "$T/out" 2>&1; echo $? > "$T/rc"
check "G2 pre-existing file restored byte-identically with its mtime" '[ "$(rc)" = 0 ] && [ "$(sha256sum < "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf")" = "$pre_sha" ] && [ "$(stat -c %Y "$R/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf")" = "$(date -u -d "2026-01-02 03:04:05" +%s)" ]'
fresh sshdT-default.txt
sc apply > /dev/null 2>&1
printf 'MaxAuthTries 3\n' > "$R/etc/ssh/sshd_config.d/50-later.conf"
sc rollback > "$T/out" 2>&1; echo $? > "$T/rc"
check "G3 someone else changed sshd_config.d meanwhile: ROLLBACK FAILED, exit 2, diff shown" '[ "$(rc)" = 2 ] && grep -q "ROLLBACK FAILED: sshd config files differ" "$T/out" && grep -q "50-later.conf" "$T/out"'
fresh sshdT-default.txt
sc apply > /dev/null 2>&1
STUB_CONFIRM_DENY=1 sc rollback > "$T/out" 2>&1; echo $? > "$T/rc"
check "G4 restored but new session fails: exit 2" '[ "$(rc)" = 2 ] && grep -q "ROLLBACK FAILED: restored, but a new session failed" "$T/out"'

fresh sshdT-default.txt
sc apply > /dev/null 2>&1
STUB_BASE="$FIX/sshdT-legacy.txt" sc rollback > "$T/out" 2>&1; echo $? > "$T/rc"
check "G5 files identical but sshd -T differs from the snapshot (defaults changed): ROLLBACK FAILED, exit 2" '[ "$(rc)" = 2 ] && grep -q "ROLLBACK FAILED: sshd -T differs from the snapshot" "$T/out"'

echo "== config, validate, pull"
printf 'HOST_LABEL=validator\nSURPRISE=1\n' > "$T/env"
sc version > "$T/out" 2>&1; echo $? > "$T/rc"
check "H1 unknown key in the env file refused" '[ "$(rc)" = 2 ] && grep -q "unknown key SURPRISE" "$T/out"'
printf 'HOST_LABEL=validator\nREVERT_AFTER=5\n' > "$T/env"
check "H2 REVERT_AFTER below 30 refused" '! sc version'
: > "$T/env"
fresh sshdT-default.txt; audit_to --no-probe
cp "$TF/pft_sshcrypto_validator.prom" "$T/good.prom"
sed 's/host="validator"/host="sentry"/' "$T/good.prom" > "$T/sentry.prom"
check "H3 validate accepts a sentry file for sentry" 'sc validate "$T/sentry.prom" sentry'
{ cat "$T/sentry.prom"; echo 'node_load1{host="sentry"} 1'; } > "$T/foreign.prom"
check "H4 validate rejects a foreign metric" '! sc validate "$T/foreign.prom" sentry'
grep -v '^pft_sshcrypto_up' "$T/sentry.prom" > "$T/noup.prom"
check "H5 validate rejects a file without the up sample" '! sc validate "$T/noup.prom" sentry'
mkdir -p "$T/peer" "$T/tf2"; cp "$T/sentry.prom" "$T/peer/pft_sshcrypto_sentry.prom"
printf 'HOST_LABEL=validator\nTEXTFILE_DIR=%s\nREMOTE_DIR=%s\nPULL_SSH=env\n' "$T/tf2" "$T/peer" > "$T/env"
sc pull > "$T/out" 2>&1; echo $? > "$T/rc"
check "H6 pull copies a valid peer file into place" '[ "$(rc)" = 0 ] && cmp -s "$T/tf2/pft_sshcrypto_sentry.prom" "$T/sentry.prom"'
cp "$T/foreign.prom" "$T/peer/pft_sshcrypto_sentry.prom"
sc pull > "$T/out" 2>&1; echo $? > "$T/rc"
check "H7 pull of an invalid file: exit 2, old copy kept, no temp left" '[ "$(rc)" = 2 ] && cmp -s "$T/tf2/pft_sshcrypto_sentry.prom" "$T/sentry.prom" && [ "$(ls -A "$T/tf2" | wc -l)" = 1 ]'
printf 'HOST_LABEL=validator\nTEXTFILE_DIR=%s\nREMOTE_DIR=%s\nPULL_SSH=false\n' "$T/tf2" "$T/peer" > "$T/env"
sc pull > /dev/null 2>&1; echo $? > "$T/rc"
check "H8 pull transport failure: exit 1" '[ "$(rc)" = 1 ]'
printf '#!/bin/sh\nsleep 30\n' > "$T/bin/hang"; chmod +x "$T/bin/hang"
printf 'HOST_LABEL=validator\nTEXTFILE_DIR=%s\nREMOTE_DIR=%s\nPULL_SSH=%s\nPULL_TIMEOUT=2\n' "$T/tf2" "$T/peer" "$T/bin/hang" > "$T/env"
s0=$SECONDS; sc pull > /dev/null 2>&1; echo $? > "$T/rc"; el=$((SECONDS - s0))
check "H9 hanging pull is cut by PULL_TIMEOUT (exit 1 within 10 s)" '[ "$(rc)" = 1 ] && [ "$el" -lt 10 ]'
: > "$T/env"
python3 "$GRADEPY" table > "$T/table"
check "H10 policy table lists every policy row + fallback" '[ "$(grep -c "^| " "$T/table")" -ge 48 ] && grep -q "| any | anything else | WARN |" "$T/table"'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
