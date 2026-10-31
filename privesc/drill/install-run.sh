#!/usr/bin/env bash
# Recorded two-host install of privesc at the current HEAD (task_0ea90375dd468168616469f8689db69a).
#   bash ~/work/scripts/privesc-install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
# Leaves the rollout silence in place (its id goes to /tmp/pft-privesc-rollout.sil) for the drills that follow;
# privesc-post-run.sh expires it.
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
trap 'R "rm -rf /tmp/pft-privesc-$SHORT" || true' EXIT
echo "privesc two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
x "ls /usr/local/bin/pft-privesc /etc/pft-privesc.env 2>&1; R 'ls /usr/local/bin/pft-privesc /etc/pft-privesc.env 2>&1'"
check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"

echo; echo "== 1. rollout silence (new rules + install + both drills; rulecheck/fleet see new files)"
ends="$(date -u -d '+80 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "task_0ea90375 privesc rollout + drills $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTPrivesc.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "privesc-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
printf '%s\n' "$SIL" > /tmp/pft-privesc-rollout.sil
check "Alertmanager silence created (PFTPrivesc*, PFTRuleDead, PFTTextfileStale, PFTRulecheck*, PFTFleet*) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. sentry: install"
x "git archive $SHA privesc | R 'rm -rf /tmp/pft-privesc-$SHORT && mkdir -m 700 /tmp/pft-privesc-$SHORT && tar -x -C /tmp/pft-privesc-$SHORT'"
x "R 'sudo -n /tmp/pft-privesc-$SHORT/privesc/install.sh --host sentry'"
check "sentry install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_privesc_up{host="sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n /tmp/pft-privesc-$SHORT/privesc/install.sh --host sentry'"
check "sentry second install exit 0 (idempotent)" "$XRC"
x "R 'sudo -n stat -c \"%a %U %n\" /etc/pft-privesc.env /usr/local/bin/pft-privesc /usr/local/lib/pft-privesc/privesc_classify.py; sudo -n grep -c ^AGENT_USER= /etc/pft-privesc.env; sudo -n grep -n privesc /etc/pft-rulecheck.conf'"

echo; echo "== 3. validator: install"
x "sudo -n privesc/install.sh"
check "validator install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_privesc_up{host="validator"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n privesc/install.sh"
check "validator second install exit 0 (idempotent)" "$XRC"
x "sudo -n stat -c '%a %U %n' /etc/pft-privesc.env /usr/local/bin/pft-privesc /usr/local/lib/pft-privesc/privesc_classify.py; sudo -n grep -n privesc /etc/pft-rulecheck.conf"

echo; echo "== 4. validator: pull of the sentry file (PULL_SSH copied from /etc/pft-statewatch.env, not printed)"
x "sudo -n grep -q '^PULL_SSH=' /etc/pft-privesc.env || sudo -n sh -c 'grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-privesc.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-privesc.env; sudo -n stat -c '%a %U' /etc/pft-privesc.env"
x "sudo -n privesc/install.sh --pull"
check "pull install exit 0, sentry file present on the validator" "$([ "$XRC" = 0 ] && grep -q 'pft_privesc_up{host="sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "for f in validator sentry; do sudo -n grep -qx \"require pft_privesc_\$f.prom\" /etc/pft-rulecheck.conf || echo \"require pft_privesc_\$f.prom\" | sudo -n tee -a /etc/pft-rulecheck.conf; done; sudo -n grep -n privesc /etc/pft-rulecheck.conf"
x "R \"sudo -n grep -qx 'require pft_privesc_sentry.prom' /etc/pft-rulecheck.conf || echo 'require pft_privesc_sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf; sudo -n grep -n privesc /etc/pft-rulecheck.conf\""

echo; echo "== 5. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-privesc\") | .rules[] | [.name, .health, .state] | @tsv'"
check "4 privesc rules loaded, health ok" "$([ "$(grep -c '	ok	' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_privesc_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "Prometheus scrapes pft_privesc_up for validator and sentry" "$([ "$(grep -cE '^(validator|sentry) 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=sum by (host, grade) (pft_privesc_findings)' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.grade) \(.value[1])\"' | sort"

echo; echo "== 6. integrity: accept the new files on both hosts, verify"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "sudo -n pft-integrity accept --reason 'task_0ea90375: privesc $SHORT installed (script, classifier, units, env, rulecheck.conf)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "R \"sudo -n pft-integrity accept --reason 'task_0ea90375: privesc $SHORT installed (script, classifier, units, env, rulecheck.conf)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 7. fleet: sync the fleet add-on (manifest.tsv) to HEAD, then skew"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason 'task_0ea90375 privesc manifest lines'"
check "fleet sync exit 0" "$XRC"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0 (privesc CURRENT on both hosts)" "$([ "$XRC" = 0 ] && grep -qE 'privesc' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK (privesc rules LIVE, textfiles FRESH)" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after the sync" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "TZ=UTC systemctl is-active pft-privesc.timer pft-privesc-pull.timer; R 'systemctl is-active pft-privesc.timer'"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
