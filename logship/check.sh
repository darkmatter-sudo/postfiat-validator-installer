#!/usr/bin/env bash
# Offline checks for logship/: shellcheck, ruff, both stub suites, and two mutation controls. M1: sign trusts the
# exit code of 'openssl req -verify', which is 0 on a bad self-signature in OpenSSL 3.0.2. M2: the docker log bridge
# skips every line at the saved timestamp on resume (drops same-timestamp lines). Each mutant must FAIL its suite on
# exactly the one test written for it. No root, no network, no host change.
# Usage: bash logship/check.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 3
S=logship/pft-logship.sh
rc=0
D=logship/pft-logship-dockerlog.py
echo "\$ shellcheck $S logship/tests/run-tests.sh logship/tests/test-dockerlog.sh logship/smoke-bridge.sh logship/check.sh"
shellcheck "$S" logship/tests/run-tests.sh logship/tests/test-dockerlog.sh logship/smoke-bridge.sh logship/check.sh && echo "shellcheck clean" || rc=1
echo "\$ ruff check logship/"
ruff check logship/ || rc=1
echo "\$ bash logship/tests/run-tests.sh"
bash logship/tests/run-tests.sh || rc=1
echo "\$ bash logship/tests/test-dockerlog.sh"
bash logship/tests/test-dockerlog.sh || rc=1
M="$(mktemp)"; M2="$(mktemp)"; trap 'rm -f "$M" "$M2"' EXIT
sed "s#2>&1 | grep -q 'self-signature verify OK' || die \"CSR signature#>/dev/null 2>\&1 || die \"CSR signature#" "$S" > "$M"
echo
echo "== M1 mutant: sign trusts 'openssl req -verify' exit code (diff vs $S)"
diff "$S" "$M" | grep '^[<>]'
out="$(PFT_LS_SCRIPT="$M" bash logship/tests/run-tests.sh 2>&1)"; mrc=$?
grep -E '^FAIL|passed,' <<<"$out"
if [ "$mrc" -ne 0 ] && [ "$(grep -c '^FAIL' <<<"$out")" -eq 1 ] && grep -q '^FAIL - bad sig csr: rc=1' <<<"$out"; then
  echo "M1 caught (only the bad-self-signature test fails)"
else echo "M1 NOT caught as expected"; rc=1; fi
sed 's#if ns < skip_ns or (ns == skip_ns and skip_n > 0):#if ns <= skip_ns:#' "$D" > "$M2"
echo
echo "== M2 mutant: bridge resume skips every line at the saved timestamp (diff vs $D)"
diff "$D" "$M2" | grep '^[<>]'
out="$(PFT_LS_DL_SCRIPT="$M2" bash logship/tests/test-dockerlog.sh 2>&1)"; mrc=$?
grep -E '^FAIL|passed,' <<<"$out"
if [ "$mrc" -ne 0 ] && [ "$(grep -c '^FAIL' <<<"$out")" -eq 1 ] && grep -q '^FAIL - same-ts: ' <<<"$out"; then
  echo "M2 caught (only the same-timestamp resume test fails)"
else echo "M2 NOT caught as expected"; rc=1; fi
echo "RESULT: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL)"
exit "$rc"
