#!/usr/bin/env bash
# Recorded 24-hour baseline for feewatch at the current HEAD (task_448dd0bfb8860c914e018ceba393cdf5). Read-only:
# nothing on either host is changed, no node is stopped, no notifier is touched.
#   bash feewatch/baseline/run-baseline.sh START END 2>&1 | tee LOG   (repo root, agent user, HEAD clean + pushed)
# 1. offline suites (report/crosscheck/direct + collector), 2. direct `fee` + `server_info` answers from both nodes,
# fetched by hand (not through pft-feewatch), 3. both history files copied into feewatch/data/, 4. direct answers vs
# the newest history line (+ negative control), 5. public RPC probe, 6. report over [START, END), 7. seeded public-RPC
# crosscheck (+ negative control) and the --offline re-check of both recorded runs.
# server_info carries host-identifying fields (hostid, ports, pubkeys): the raw answers stay in the private run dir,
# and only {result:{info:{load_factor}}} is published; the direct check runs on the published reduced copy.
set -uo pipefail
START="${1:?START epoch}"; END="${2:?END epoch}"
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"
PUB=https://rpc.testnet.postfiat.org/
ME="$(id -un)"
D=feewatch/data
PRIV="$(mktemp -d)"; trap 'rm -rf "${PRIV:?}"' EXIT
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
rc0() { [ "$XRC" = 0 ] && echo 0 || echo 1; }
BODY_FEE='{"method":"fee","params":[{}]}'; BODY_INFO='{"method":"server_info","params":[{}]}'
CURL="curl -s --max-time 10 -H Content-Type:application/json -d"

echo "feewatch 24h baseline - $(date -u +%FT%TZ) - $(lsb_release -ds) - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
echo "window [$START, $END) = $(date -u -d "@$START" +%FT%TZ) .. $(date -u -d "@$END" +%FT%TZ)"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }
[ "$(date +%s)" -ge "$END" ] || { echo "window has not ended yet - stopping"; exit 3; }
mkdir -p "$D"

echo; echo "== 1. offline suites"
x "sha256sum feewatch/report_feewatch.py feewatch/tests/test_report_feewatch.py feewatch/pft-feewatch.sh feewatch/feewatch_parse.py feewatch/baseline/run-baseline.sh"
x "python3 -u feewatch/tests/test_report_feewatch.py | tail -3"
check "report/crosscheck/direct suite passes" "$(rc0)" "$(tail -1 <<<"$XOUT")"
x "bash feewatch/tests/run-tests.sh | tail -1"
check "collector suite passes" "$(rc0)" "$(tail -1 <<<"$XOUT")"
x "shellcheck feewatch/baseline/run-baseline.sh feewatch/pft-feewatch.sh && echo shellcheck clean"
check "shellcheck clean" "$(rc0)"

echo; echo "== 2. direct answers, fetched by hand from each node's admin RPC (container loopback)"
x "sudo -n docker exec postfiatd $CURL '$BODY_FEE' http://127.0.0.1:5005/ > \$PRIV/validator-fee.json && sudo -n docker exec postfiatd $CURL '$BODY_INFO' http://127.0.0.1:5005/ > \$PRIV/validator-info.json && date +%s > \$PRIV/validator-now"
check "validator answers fetched" "$(rc0)"
x "R 'sudo -n docker exec -i postfiatd-sentry $CURL @- http://127.0.0.1:5005/' <<< '$BODY_FEE' > \$PRIV/sentry-fee.json && R 'sudo -n docker exec -i postfiatd-sentry $CURL @- http://127.0.0.1:5005/' <<< '$BODY_INFO' > \$PRIV/sentry-info.json && date +%s > \$PRIV/sentry-now"
check "sentry answers fetched" "$(rc0)"
for h in validator sentry; do
  x "jq -e '.result.status == \"success\"' \$PRIV/$h-fee.json \$PRIV/$h-info.json && cp \$PRIV/$h-fee.json $D/direct-$h-fee.json && jq '{result: {info: {load_factor: .result.info.load_factor}}}' \$PRIV/$h-info.json > $D/direct-$h-info-reduced.json && cat $D/direct-$h-fee.json && echo && cat $D/direct-$h-info-reduced.json && echo now=\$(cat \$PRIV/$h-now)"
  check "$h answers are status success, published copies written" "$(rc0)"
done

echo; echo "== 3. history files copied from both hosts (root-only dirs)"
x "sudo -n cat /var/lib/pft-feewatch/history-postfiatd.jsonl > $D/history-postfiatd.jsonl && R 'sudo -n cat /var/lib/pft-feewatch/history-postfiatd-sentry.jsonl' > $D/history-postfiatd-sentry.jsonl && wc -l $D/history-*.jsonl && sha256sum $D/history-*.jsonl"
check "history files copied" "$(rc0)"
x "grep -Ec '([0-9]{1,3}\.){3}[0-9]{1,3}|/home/|$ME' $D/history-*.jsonl $D/direct-*.json; echo positive control: \$(echo 'x 10.1.2.3 /home/x' | grep -Ec '([0-9]{1,3}\.){3}[0-9]{1,3}|/home/')"
check "no IPv4 / home path / username in the published data (positive control matches 1)" "$(grep -q '^positive control: 1$' <<<"$XOUT" && ! grep -E ':[1-9][0-9]*$' <<<"$XOUT" | grep -q . && echo 0 || echo 1)"

echo; echo "== 4. direct answers vs the newest history line"
for h in validator sentry; do
  c=postfiatd; [ "$h" = sentry ] && c=postfiatd-sentry
  x "python3 -u feewatch/report_feewatch.py direct --history $D/history-$c.jsonl --container $c --fee $D/direct-$h-fee.json --info $D/direct-$h-info-reduced.json --now \$(cat \$PRIV/$h-now)"
  check "$h direct RPC = newest history line" "$(rc0)" "$(tail -1 <<<"$XOUT")"
  x "python3 -u feewatch/report_feewatch.py direct --history $D/history-$c.jsonl --container $c --fee $D/direct-$h-fee.json --info $D/direct-$h-info-reduced.json --now \$(cat \$PRIV/$h-now) --negative"
  check "$h direct negative control: every check MISMATCH" "$(rc0)" "$(tail -1 <<<"$XOUT")"
done

echo; echo "== 5. public RPC probe (one server_info, 20 s timeout)"
x "curl -s --max-time 20 -H Content-Type:application/json -d '$BODY_INFO' $PUB | jq -c '{build: .result.info.build_version, complete_ledgers: .result.info.complete_ledgers, state: .result.info.server_state}'"
check "public RPC answers" "$(rc0)"

echo; echo "== 6. 24h report over [START, END)"
x "python3 -u feewatch/report_feewatch.py report --history $D/history-postfiatd.jsonl $D/history-postfiatd-sentry.jsonl --start $START --end $END --json $D/baseline-24h.json --md $D/baseline-24h.md"
check "report written" "$(rc0)"

echo; echo "== 7. public-RPC crosscheck (seeded sample of 30) + negative control + offline re-checks"
H="$D/history-postfiatd.jsonl $D/history-postfiatd-sentry.jsonl"
x "python3 -u feewatch/report_feewatch.py crosscheck --history $H --start $START --end $END --rpc $PUB --sample 30 --seed 1 --json $D/crosscheck-24h.json"
check "crosscheck: every check OK" "$(rc0)" "$(tail -1 <<<"$XOUT")"
x "python3 -u feewatch/report_feewatch.py crosscheck --history $H --start $START --end $END --rpc $PUB --sample 30 --seed 1 --negative --json $D/crosscheck-24h-negative.json"
check "crosscheck negative control: every check MISMATCH" "$(rc0)" "$(tail -1 <<<"$XOUT")"
x "python3 -u feewatch/report_feewatch.py crosscheck --offline $D/crosscheck-24h.json --history $H"
check "offline re-check of the crosscheck" "$(rc0)" "$(tail -1 <<<"$XOUT")"
x "python3 -u feewatch/report_feewatch.py crosscheck --offline $D/crosscheck-24h-negative.json --history $H"
check "offline re-check of the negative control" "$(rc0)" "$(tail -1 <<<"$XOUT")"
x "sha256sum $D/*"

echo; echo "RESULT: $FAILS failed checks"
exit "$([ "$FAILS" = 0 ] && echo 0 || echo 1)"
