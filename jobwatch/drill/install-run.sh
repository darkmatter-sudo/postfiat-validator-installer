#!/usr/bin/env bash
# shellcheck disable=SC1091
# Recorded two-host install of jobwatch at the current HEAD (task_de7c65f8535e68b146f171bcec90b36b, step 4), through
# pft-fleet inside a pft-maint window (built from ../../kernwatch/drill/install-run.sh, PASS). Restore re-runs
# pft-keyescrow and checks drift 0 (it fingerprints the pft-maint ntfy.env that the window swaps).
# Nothing is restarted. pft-maint's [MAINT] start/end messages go to a throwaway topic; the real target is restored
# and compared at the end. The rollout silence names only the jobwatch/rulecheck/fleet alerts (never the watchdog).
#   bash jobwatch/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
# HEAD must already carry the fleet/manifest.tsv lines, the prometheus.yml rule line and the rulecheck example lines.
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_de7c65f8
TT="pft-drill-jobwatch-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-jobwatch
SWAPPED=0; MAINT=0; HAD=0
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
  R "rm -rf /tmp/pft-jobwatch-$SHORT" || true
}
trap restore EXIT
echo "jobwatch two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight"
x "sha256sum jobwatch/pft-jobwatch.sh jobwatch/jobwatch_lib.py jobwatch/install.sh jobwatch/drill/install-run.sh jobwatch/systemd/* alerts/jobwatch.rules.yml"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-jobwatch /etc/pft-jobwatch.env 2>&1; R 'ls /usr/local/bin/pft-jobwatch 2>&1'"
check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "grep -n jobwatch alerts/prometheus.yml fleet/manifest.tsv rulecheck/pft-rulecheck.conf.example rulecheck/pft-rulecheck.sentry.conf.example 2>&1 | cut -c1-150"
check "HEAD lists the rule file, 6 manifest lines and the rulecheck example lines" "$([ "$(grep -c 'manifest.tsv' <<<"$XOUT")" = 6 ] && grep -q 'prometheus.yml' <<<"$XOUT" && [ "$(grep -c 'rulecheck' <<<"$XOUT")" = 7 ] && echo 0 || echo 1)"
x "sudo -n grep -c '^PULL_SSH=' /etc/pft-authwatch.env"
check "a PULL_SSH line to copy exists (/etc/pft-authwatch.env, not printed)" "$([ "$XOUT" = 1 ] && echo 0 || echo 1)"

echo; echo "== 1. rollout silence (new rules; rulecheck/fleet see new files during the install)"
ends="$(date -u -d '+45 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK jobwatch rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTJobFailed|PFTJobMissed|PFTJobDisabled|PFTJobwatchStale|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "jobwatch-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (jobwatch rules, PFTRuleDead, PFTTextfileStale, PFTRulecheck*, PFTFleet*; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK jobwatch install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: manifest (fleet add-on) to HEAD, then the jobwatch files to HEAD on both hosts"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK jobwatch manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon jobwatch --to $SHA --apply --reason '$TASK jobwatch $SHORT first install'"
check "jobwatch sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum jobwatch/pft-jobwatch.sh jobwatch/jobwatch_lib.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-jobwatch /usr/local/lib/pft-jobwatch/jobwatch_lib.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-jobwatch /usr/local/lib/pft-jobwatch/jobwatch_lib.py | cut -c1-64'"
check "installed script + helper = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 2 ] && echo 0 || echo 1)"

echo; echo "== 4. sentry: install.sh (same bytes; first collection through the sandboxed unit, enable the timer, collect again)"
x "git archive $SHA jobwatch | R 'rm -rf /tmp/pft-jobwatch-$SHORT && mkdir -m 700 /tmp/pft-jobwatch-$SHORT && tar -x -C /tmp/pft-jobwatch-$SHORT'"
x "R 'sudo -n bash /tmp/pft-jobwatch-$SHORT/jobwatch/install.sh --host sentry'"
check "sentry install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_jobwatch_up{host="sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 5. validator: install.sh, then the pull of the sentry file (PULL_SSH copied from /etc/pft-authwatch.env, not printed)"
x "sudo -n bash jobwatch/install.sh --host validator"
check "validator install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_jobwatch_up{host="validator"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n grep -q '^PULL_SSH=' /etc/pft-jobwatch.env || { sudo -n grep '^PULL_SSH=' /etc/pft-authwatch.env | sudo -n tee -a /etc/pft-jobwatch.env >/dev/null; }; sudo -n chmod 600 /etc/pft-jobwatch.env; sudo -n grep -c '^PULL_SSH=' /etc/pft-jobwatch.env; sudo -n stat -c '%a %U' /etc/pft-jobwatch.env"
check "validator conf: one PULL_SSH line, 600 root" "$([ "$(head -1 <<<"$XOUT")" = 1 ] && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash jobwatch/install.sh --pull --host sentry"
check "pull install exit 0, sentry file on the validator" "$([ "$XRC" = 0 ] && grep -q 'pft_jobwatch_up{host="sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 6. rulecheck inputs: append the jobwatch lines (idempotent; the live confs carry earlier add-ons' lines)"
RC_TF='textfile pft_jobwatch_*.prom   15m   pft_jobwatch_collect_timestamp_seconds'
x "sudo -n grep -qF 'pft_jobwatch_' /etc/pft-rulecheck.conf || printf '%s\n' '# pft-jobwatch (2-minute collector; sentry copy pulled every 2 min)' '$RC_TF' 'require pft_jobwatch_validator.prom' 'require pft_jobwatch_sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n jobwatch /etc/pft-rulecheck.conf"
check "validator rulecheck.conf has the 4 jobwatch lines" "$([ "$(grep -c jobwatch <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "R \"sudo -n grep -qF 'pft_jobwatch_' /etc/pft-rulecheck.conf || printf '%s\\n' '# pft-jobwatch (2-minute collector)' '$RC_TF' 'require pft_jobwatch_sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n jobwatch /etc/pft-rulecheck.conf\""
check "sentry rulecheck.conf has the 3 jobwatch lines" "$([ "$(grep -c jobwatch <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 7. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-jobwatch\") | .rules[] | [.name, .health, .state] | @tsv'"
check "4 jobwatch rules loaded, health ok, all inactive" "$([ "$(grep -c '	ok	inactive' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sleep 30; curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_jobwatch_(up|jobs)\"}' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.__name__) \(.metric.state // \"-\") \(.value[1])\"' | sort"
check "Prometheus scrapes pft_jobwatch_up 1 for both hosts" "$([ "$(grep -cE ' pft_jobwatch_up - 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
check "both hosts: jobs total > 0, 0 failed, 0 missed, 0 disabled (any non-zero is a finding to fix first)" "$([ "$(grep -cE ' pft_jobwatch_jobs (failed|missed|disabled) 0$' <<<"$XOUT")" = 6 ] && [ "$(grep -cE ' pft_jobwatch_jobs total [1-9][0-9]*$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 8. integrity: accept what pft-fleet did not write (env file, state dir, enabled timer links, rulecheck.conf), verify"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "sudo -n pft-integrity accept --reason '$TASK: jobwatch $SHORT installed (env, timers enabled, rulecheck.conf)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "R \"sudo -n pft-integrity accept --reason '$TASK: jobwatch $SHORT installed (env, timer enabled, rulecheck.conf)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 9. fleet skew and rulecheck"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, jobwatch CURRENT on both hosts" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +jobwatch +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK (jobwatch rules LIVE, textfiles FRESH)" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-active pft-jobwatch.timer pft-jobwatch-pull.timer; R 'systemctl is-active pft-jobwatch.timer'"
check "3 timers active" "$([ "$(grep -cx active <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 10. end window, restore the real target, compare, read back the throwaway topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' /var/lib/pft-exporter/textfile/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=40m\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"PFTJob|RuleDead|TextfileStale|Rulecheck|Fleet\"))] | length'"
check "no jobwatch/rulecheck/fleet alert pending or firing (silence left to run out on its own, lesson 185)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
