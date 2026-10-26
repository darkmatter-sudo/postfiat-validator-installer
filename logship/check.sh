#!/usr/bin/env bash
# Offline checks for logship/: shellcheck, ruff, both stub suites, and two mutation controls. M1: sign trusts the
# exit code of 'openssl req -verify', which is 0 on a bad self-signature in OpenSSL 3.0.2. M2: the docker log bridge
# skips every line at the saved timestamp on resume (drops same-timestamp lines). Each mutant must FAIL its suite on
# exactly the one test written for it. M3: the host key is created under the default umask (world-readable until chmod).
# M4: check --textfile reports pft_logship_up 1 although the check failed. Also: promtool check + test of
# alerts/logship.rules.yml (docker, prom/prometheus image as in alerts/run-stack.sh). No root, no network, no host change.
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
M="$(mktemp)"; M2="$(mktemp)"; M3="$(mktemp)"; M4="$(mktemp)"; trap 'rm -f "$M" "$M2" "$M3" "$M4"' EXIT
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
# shellcheck disable=SC2016  # literal $OPENSSL in the pattern is intended
sed 's#else run_private "$OPENSSL" genpkey#else run "$OPENSSL" genpkey#' "$S" > "$M3"
echo
echo "== M3 mutant: host key created under the default umask (diff vs $S)"
diff "$S" "$M3" | grep '^[<>]'
out="$(PFT_LS_SCRIPT="$M3" bash logship/tests/run-tests.sh 2>&1)"; mrc=$?
grep -E '^FAIL|passed,' <<<"$out" | cut -c1-160
if [ "$mrc" -ne 0 ] && [ "$(grep -c '^FAIL' <<<"$out")" -eq 1 ] && grep -q '^FAIL - key umask: rc=4 umask=0022' <<<"$out"; then
  echo "M3 caught (only the key-umask test fails)"
else echo "M3 NOT caught as expected"; rc=1; fi
# shellcheck disable=SC2016  # literal $((rc == 0)) in the pattern is intended
sed 's#write_textfile "$(render_metrics "$((rc == 0))"#write_textfile "$(render_metrics 1#' "$S" > "$M4"
echo
echo "== M4 mutant: check --textfile writes pft_logship_up 1 even when the check fails (diff vs $S)"
diff "$S" "$M4" | grep '^[<>]'
out="$(PFT_LS_SCRIPT="$M4" bash logship/tests/run-tests.sh 2>&1)"; mrc=$?
grep -E '^FAIL|passed,' <<<"$out" | cut -c1-160
if [ "$mrc" -ne 0 ] && [ "$(grep -c '^FAIL' <<<"$out")" -eq 1 ] && grep -q '^FAIL - up on failed check: rc=1' <<<"$out"; then
  echo "M4 caught (only the up-on-failed-check test fails)"
else echo "M4 NOT caught as expected"; rc=1; fi
read -ra DK <<<"${DOCKER:-sudo docker}"
PI="${PROM_IMAGE:-prom/prometheus:v3.5.0}"
echo
echo "\$ promtool check rules logship.rules.yml && promtool test rules logship.tests.yml   (in $PI)"
"${DK[@]}" run --rm -v "$PWD/alerts:/w:ro" -w /w --entrypoint promtool "$PI" check rules logship.rules.yml || rc=1
"${DK[@]}" run --rm -v "$PWD/alerts:/w:ro" -w /w --entrypoint promtool "$PI" test rules logship.tests.yml || rc=1
MD="$(mktemp -d)"; trap 'rm -f "$M" "$M2" "$M3" "$M4"; rm -rf "$MD"' EXIT
cp alerts/logship.tests.yml "$MD/"; grep -v 'or time() - pft_textfile_mtime_seconds' alerts/logship.rules.yml > "$MD/logship.rules.yml"
chmod 755 "$MD"; chmod 644 "$MD"/*
echo
echo "== M5 mutant: rule without the stale-metrics branch (diff vs alerts/logship.rules.yml)"
diff alerts/logship.rules.yml "$MD/logship.rules.yml" | grep '^[<>]'
out="$("${DK[@]}" run --rm -v "$MD:/w:ro" -w /w --entrypoint promtool "$PI" test rules logship.tests.yml 2>&1)"; mrc=$?
grep -E 'FAILED|SUCCESS|metrics stale' <<<"$out" | head -5
if [ "$mrc" -ne 0 ] && grep -q 'metrics stale' <<<"$out" && [ "$(grep -c '^ *name: ' <<<"$out")" -le 1 ]; then
  echo "M5 caught (the stale-metrics test fails)"
else echo "M5 NOT caught as expected"; rc=1; fi
echo "RESULT: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL)"
exit "$rc"
