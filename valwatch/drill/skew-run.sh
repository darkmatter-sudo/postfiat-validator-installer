#!/usr/bin/env bash
# shellcheck disable=SC2016  # commands are single-quoted on purpose and run through x()
# Recorded runs of the cross-host skew fix of PFTValwatchHostsDisagree / ...Late (task_535bbb77fac242fcac666662f3c6a2d9).
#   bash valwatch/drill/skew-run.sh collect   validator: read-only Prometheus queries over the retained history ->
#                                              valwatch/data/skew/ + valwatch/reports/skew.txt (then commit them)
#   bash valwatch/drill/skew-run.sh offline   anywhere with docker + python3 (also a fresh public clone): generator
#                                              in sync, promtool (v3.5.0 + v3.16.0), old-rules control, pytest, lint,
#                                              offline replay of the committed data = committed report
#   bash valwatch/drill/skew-run.sh reload    validator: rules-only reload of the live Prometheus (HUP, no restart),
#                                              loaded rule = repo, rulecheck, integrity + fleet unchanged, node full
# Nothing here touches postfiatd, the sentry, units or installed files. From the repo root: ... 2>&1 | tee LOG
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
MODE="${1:-}"
SHA="$(git rev-parse HEAD)"
ME="$(id -un)"; HN="$(hostname)"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#127\.0\.0\.1#LOOPBACK#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#LOOPBACK#127.0.0.1#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
V=valwatch; A=alerts; DS=$V/data/skew; OLD=496470f052ac5058fe0759cd6ffb3ccd381004b9
PROM=http://127.0.0.1:9090
echo "valwatch skew $MODE - $(date -u +%FT%TZ) - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
x "sha256sum $A/valwatch.rules.yml $A/valwatch.tests.yml $V/skewreplay.py $V/tests/gen_rule_tests.py $V/tests/mutate.py $V/tests/test_skewreplay.py $V/drill/skew-run.sh"
# scratch under ~/.cache like README "Tests": the stub-node tests do not pass with TMPDIR=/tmp (11 fail there)
mkdir -p "$HOME/.cache"; SCR="$(mktemp -d "$HOME/.cache/vwskew.XXXXXX")"; trap 'rm -rf "$SCR"' EXIT

case "$MODE" in
collect)
  echo; echo "== 1. old rules ($OLD) and new rules (HEAD)"
  git show "$OLD:$A/valwatch.rules.yml" > "$SCR/old.rules.yml"
  x "sha256sum $SCR/old.rules.yml $A/valwatch.rules.yml"
  echo; echo "== 2. collect (read-only query_range over the retained history, 15 s step)"
  rm -rf "$DS"; mkdir -p "$DS"
  x "python3 -u $V/skewreplay.py collect --prom $PROM --old-rules $SCR/old.rules.yml --new-rules $A/valwatch.rules.yml --out $DS"
  check "collect" "$XRC"
  gzip -n "$DS/skew.json"
  x "ls -l $DS; sha256sum $DS/*"
  echo; echo "== 3. analyze"
  x "python3 -u $V/skewreplay.py analyze $DS --out $V/reports/skew.txt"
  check "analyze: every old-only interval attributed skew, new-only 0" "$XRC"
  ;;
offline)
  echo; echo "== 1. generated rule tests in sync with the generator"
  x "python3 $V/tests/gen_rule_tests.py | cmp - $A/valwatch.tests.yml && echo in-sync"
  check "valwatch.tests.yml = gen_rule_tests.py output" "$XRC"
  x "grep -c '^- name: ' $A/valwatch.tests.yml; grep -c 'interval: 15s' $A/valwatch.tests.yml; grep -c 'expr: ALERTS' $A/valwatch.tests.yml"
  echo; echo "== 2. promtool test rules (new rules)"
  for img in prom/prometheus:v3.5.0 prom/prometheus:v3.16.0; do
    x "docker run --rm --network none --entrypoint promtool -v $REPO/$A:/w:ro -w /w $img test rules valwatch.tests.yml"
    check "promtool $img: SUCCESS" "$([ "$XRC" = 0 ] && grep -q SUCCESS <<<"$XOUT" && echo 0 || echo 1)"
  done
  echo; echo "== 3. control: the same generator over the OLD rules ($OLD) must fail the skew cases"
  mkdir -p "$SCR/c/$A" "$SCR/c/$V/tests"
  cp $V/tests/gen_rule_tests.py "$SCR/c/$V/tests/"
  git show "$OLD:$A/valwatch.rules.yml" > "$SCR/c/$A/valwatch.rules.yml"
  python3 "$SCR/c/$V/tests/gen_rule_tests.py" > "$SCR/c/$A/valwatch.tests.yml"
  chmod -R a+rX "$SCR"
  docker run --rm --network none --entrypoint promtool -v "$SCR/c/$A:/w:ro" -w /w prom/prometheus:v3.5.0 \
    test rules valwatch.tests.yml > "$SCR/old.out" 2>&1; orc=$?
  echo "  promtool on old rules: exit $orc"
  x "grep -oE 'ALERTS\{alertname=..(PFTValwatchHostsDisagree|PFTValwatchHostsDisagreeLate)..\}\", time: [0-9ms]+' $SCR/old.out | sed 's/ALERTS{alertname=..//; s/..}\", time: / @/' | sort | uniq -c | sort -k2,2 -k3,3V"
  nf="$(grep -cE 'expr: "ALERTS\{alertname=' "$SCR/old.out")"
  x "grep -E '^ +name: ' $SCR/old.out | sed 's/^ *//'"
  check "old rules FAIL the new skew assertions (exit 1, >= 1 failing ALERTS assertion)" "$([ "$orc" = 1 ] && [ "$nf" -ge 1 ] && echo 0 || echo 1)" "$nf failing ALERTS assertions"
  echo; echo "== 4. pytest (unit + shell + stub-node + skewreplay offline tests)"
  x "cd $V && TMPDIR=$SCR python3 -m pytest -q -p no:cacheprovider tests 2>&1 | tail -3"
  check "pytest: 0 failed" "$(grep -qE '^[0-9]+ passed' <<<"$XOUT" && ! grep -q failed <<<"$XOUT" && echo 0 || echo 1)"
  echo; echo "== 5. lint"
  x "shellcheck $V/pft-valwatch.sh $V/install.sh $V/drill/skew-run.sh && echo shellcheck-ok"
  check "shellcheck" "$XRC"
  x "cd $V && ruff check . && ruff format --check ."
  check "ruff" "$XRC"
  echo; echo "== 6. offline replay of the committed data = committed report"
  x "python3 -I $V/skewreplay.py analyze $DS --out $SCR/skew.txt > /dev/null; echo analyze-exit \$?; cmp $SCR/skew.txt $V/reports/skew.txt && echo identical"
  check "offline analyze byte-identical to reports/skew.txt" "$(grep -q '^identical$' <<<"$XOUT" && echo 0 || echo 1)"
  x "grep -nE '^(SKEW (min|window|max)|SKEW_OUTSIDE|REPLAY|OLD_ONLY|NEW_ONLY|RESULT)' $V/reports/skew.txt"
  check "report RESULT: PASS" "$(grep -q '^RESULT: PASS' $V/reports/skew.txt && echo 0 || echo 1)"
  ;;
reload)
  echo; echo "== 1. before: node, loaded rule, integrity"
  x "sudo postfiat-health 2>&1 | grep -E 'server_state|RESULT'"
  q() { curl -s "$PROM/api/v1/rules?type=alert" | python3 -c '
import json, sys
for g in json.load(sys.stdin)["data"]["groups"]:
    for r in g["rules"]:
        if r["name"] in ("PFTValwatchHostsDisagree", "PFTValwatchHostsDisagreeLate"):
            print(r["name"], r["health"], r["state"], "|", " ".join(r["query"].split()))'; }
  x q
  x "curl -s $PROM/api/v1/status/config | python3 -c 'import json,sys; print(len(json.load(sys.stdin)[\"data\"][\"yaml\"]))'"
  x "sudo pft-integrity verify 2>&1 | tail -1"
  echo; echo "== 2. rules-only reload: SIGHUP to pft-prometheus (no restart; Alertmanager, postfiatd untouched)"
  before="$(docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' pft-prometheus postfiatd)"
  x "docker kill -s HUP pft-prometheus"
  sleep 5
  x "curl -s $PROM/api/v1/status/runtimeinfo | python3 -c 'import json,sys; d=json.load(sys.stdin)[\"data\"]; print(\"reloadConfigSuccess\", d[\"reloadConfigSuccess\"], \"lastConfigTime\", d[\"lastConfigTime\"])'"
  check "reloadConfigSuccess true" "$(grep -q 'reloadConfigSuccess True' <<<"$XOUT" && echo 0 || echo 1)"
  x "docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' pft-prometheus postfiatd"
  check "pft-prometheus and postfiatd not restarted (StartedAt/RestartCount unchanged)" "$([ "$XOUT" = "$before" ] && echo 0 || echo 1)"
  echo; echo "== 3. loaded rules = repo (after the first evaluation: health is 'unknown' until then)"
  for _ in $(seq 1 12); do
    sleep 5
    [ "$(q | grep -c ' ok ')" = 2 ] && break
  done
  x q
  want="$(python3 -c '
import sys, yaml
for r in yaml.safe_load(open(sys.argv[1]))["groups"][0]["rules"]:
    if r["alert"].startswith("PFTValwatchHostsDisagree"):
        print(r["alert"], " ".join(r["expr"].split()))' $A/valwatch.rules.yml)"
  # shellcheck disable=SC2001  # multi-line output
  got="$(sed 's/ ok [a-z]* |//' <<<"$XOUT" | sort)"
  check "both loaded expressions = repo (min/max_over_time [2m]), health ok" "$([ "$got" = "$(sort <<<"$want")" ] && [ "$(grep -c ' ok ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
  x "curl -s '$PROM/api/v1/rules' | python3 -c 'import json,sys; g=json.load(sys.stdin)[\"data\"][\"groups\"]; r=[x for y in g for x in y[\"rules\"]]; print(len(r), \"rules,\", sum(x[\"health\"]!=\"ok\" for x in r), \"not ok\")'"
  check "every loaded rule health ok" "$(grep -q ', 0 not ok' <<<"$XOUT" && echo 0 || echo 1)"
  echo; echo "== 4. rulecheck, integrity, fleet, node"
  x "sudo pft-rulecheck check 2>&1 | grep -E 'HostsDisagree|^RESULT' | head -4"
  check "pft-rulecheck: HostsDisagree* not DEAD" "$(grep -E 'HostsDisagree' <<<"$XOUT" | grep -q DEAD && echo 1 || echo 0)"
  x "sudo pft-rulecheck check >/dev/null 2>&1; echo rulecheck-exit \$?"
  check "pft-rulecheck exit 0" "$(grep -q 'rulecheck-exit 0' <<<"$XOUT" && echo 0 || echo 1)"
  x "sudo pft-integrity verify 2>&1 | tail -1; ssh -o BatchMode=yes relay 'sudo pft-integrity verify 2>&1 | tail -1' </dev/null"
  check "integrity PASS on both hosts (rules are read from the repo bind mount: no installed file changed)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
  x "sudo pft-fleet skew 2>&1 | grep -E '^ref|^HOST|valwatch|DIVERGED'"
  check "fleet: valwatch CURRENT on both hosts, DIVERGED=0" "$([ "$(grep -cE '^(sentry|validator) +valwatch +CURRENT' <<<"$XOUT")" = 2 ] && grep -q 'DIVERGED=0' <<<"$XOUT" && echo 0 || echo 1)"
  x "sudo postfiat-health 2>&1 | grep -E 'server_state|RESULT'"
  check "validator postfiatd full / HEALTHY" "$(grep -q 'RESULT: HEALTHY' <<<"$XOUT" && echo 0 || echo 1)"
  ;;
*) echo "usage: $0 collect|offline|reload"; exit 3 ;;
esac
echo
if [ "$FAILS" = 0 ]; then echo "RESULT: PASS ($MODE)"; else echo "RESULT: FAIL - $FAILS check(s) failed ($MODE)"; exit 1; fi
