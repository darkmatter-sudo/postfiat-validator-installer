#!/usr/bin/env bash
# Offline checks for logship/: shellcheck, the stub suite, and one mutation control (M1: sign trusts the exit code
# of 'openssl req -verify', which is 0 on a bad self-signature in OpenSSL 3.0.2). The mutant must FAIL the suite on
# exactly the bad-signature test. No root, no network, no host change.
# Usage: bash logship/check.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 3
S=logship/pft-logship.sh
rc=0
echo "\$ shellcheck $S logship/tests/run-tests.sh logship/check.sh"
shellcheck "$S" logship/tests/run-tests.sh logship/check.sh && echo "shellcheck clean" || rc=1
echo "\$ bash logship/tests/run-tests.sh"
bash logship/tests/run-tests.sh || rc=1
M="$(mktemp)"; trap 'rm -f "$M"' EXIT
sed "s#2>&1 | grep -q 'self-signature verify OK' || die \"CSR signature#>/dev/null 2>\&1 || die \"CSR signature#" "$S" > "$M"
echo
echo "== M1 mutant: sign trusts 'openssl req -verify' exit code (diff vs $S)"
diff "$S" "$M" | grep '^[<>]'
out="$(PFT_LS_SCRIPT="$M" bash logship/tests/run-tests.sh 2>&1)"; mrc=$?
grep -E '^FAIL|passed,' <<<"$out"
if [ "$mrc" -ne 0 ] && [ "$(grep -c '^FAIL' <<<"$out")" -eq 1 ] && grep -q '^FAIL - bad sig csr: rc=1' <<<"$out"; then
  echo "M1 caught (only the bad-self-signature test fails)"
else echo "M1 NOT caught as expected"; rc=1; fi
echo "RESULT: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL)"
exit "$rc"
