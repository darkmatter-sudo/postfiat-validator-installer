#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host install of histarchive at the current HEAD (task_e9cfe999f0e4a09fca9ef3de8dee03ae), through pft-fleet
# inside a pft-maint window. Built from ../../backupwatch/drill/install-run.sh (PASS). Nothing is restarted; the node
# is only read (public RPC server_info/ledger on 127.0.0.1 by the follower; server_info here).
#   0. preflight: integrity PASS, nodes full, not installed, HEAD carries the manifest/prometheus/rulecheck lines,
#      PEER_SSH in the keyescrow conf, age/python3 on both hosts, jobwatch textfile budget, the adopt dir verifies.
#   3. pft-fleet writes the manifest and the histarchive files on both hosts (and accepts them in pft-integrity).
#   4. sentry: install.sh --role replica.  5. validator: install.sh --role archive --adopt ADOPT (follower starts,
#      first periodic: verify + replicate).  6. rulecheck lines.  7. rules loaded.  8. schedaudit + integrity accept.
#   9. VERIFIED: verify, verify-replica, restore-verify, follower advancing, Prometheus.  10. skew, rulecheck, jobwatch.
# pft-maint's [MAINT] messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow is
# re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the histarchive/rulecheck/fleet/schedaudit/jobwatch/keyescrow alerts (never the pipeline
# watchdog) and is left to run out.
#   ADOPT=DIR bash histarchive/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 ADOPT=DIR bash histarchive/drill/install-run.sh  (step 0 only; changes nothing)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_e9cfe999
ADOPT="${ADOPT:?set ADOPT=<archive dir to adopt> (a copy of the live run)}"
TT="pft-drill-histarchive-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#age1[a-z0-9]{58}#<age-recipient>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-histarchive
SWAPPED=0; MAINT=0; HAD=0
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
  R "rm -rf ~/pft-histarchive-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
echo "histarchive two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum histarchive/pft-histarchive.sh histarchive/histarchive.py histarchive/lib_hashverify.py histarchive/install.sh histarchive/drill/install-run.sh histarchive/systemd/* alerts/histarchive.rules.yml"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-histarchive /etc/pft-histarchive.env 2>&1; R 'ls /usr/local/bin/pft-histarchive /etc/pft-histarchive.env 2>&1'"
check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "grep -c '^histarchive ' fleet/manifest.tsv; grep -c histarchive.rules.yml alerts/prometheus.yml; grep -c pft_histarchive rulecheck/pft-rulecheck.conf.example; grep -c pft_histarchive rulecheck/pft-rulecheck.sentry.conf.example"
check "HEAD lists 6 manifest lines, the rule file and 6 + 0 rulecheck lines" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "6 1 6 0 " ] && echo 0 || echo 1)"
x "sudo -n grep -c '^PEER_SSH=' /etc/pft-keyescrow.env; R 'command -v age age-keygen python3 sha256sum tar | wc -l'; command -v age age-keygen python3 sha256sum tar | wc -l"
check "PEER_SSH in the keyescrow conf; age, age-keygen, python3, sha256sum, tar on both hosts" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "1 5 5 " ] && echo 0 || echo 1)"
x "sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout 2>/dev/null | wc -c; sudo -n sed -n 's/^TEXT_BUDGET=//p' /etc/pft-jobwatch.env"
JW_NOW="$(sed -n 1p <<<"$XOUT")"; JW_BUDGET="$(sed -n 2p <<<"$XOUT")"; JW_BUDGET="${JW_BUDGET:-61440}"
check "jobwatch textfile has room for one more timer (now $JW_NOW + 1200 <= budget $JW_BUDGET)" "$([ $((JW_NOW + 1200)) -le "$JW_BUDGET" ] && echo 0 || echo 1)"
x "python3 histarchive/histarchive.py verify --dir '$ADOPT' | tail -n 2"
check "FOUND: the archive to adopt verifies with the HEAD code" "$([ "$XRC" = 0 ] && grep -q '^RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "python3 -c 'import json; s=json.load(open(\"$ADOPT/status.json\")); print(s[\"last\"])'; curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.complete_ledgers"
ALAST="$(sed -n 1p <<<"$XOUT")"; OLDEST="$(sed -n 2p <<<"$XOUT" | tr ',' '\n' | head -1 | cut -d- -f1)"
check "the node still holds the ledger after the adopted archive's last ($((ALAST + 1)) >= oldest $OLDEST): no gap at adoption" "$([ $((ALAST + 1)) -ge "${OLDEST:-999999999}" ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[].labels.alertname' | sort | uniq -c"
check "no active silence; only the pipeline watchdog pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$(sed 1d <<<"$XOUT" | grep -vc PFTAlertPipelineWatchdog)" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (new rules; rulecheck/fleet/schedaudit/jobwatch/keyescrow see new files and timers; not the watchdog)"
ends="$(date -u -d '+60 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK histarchive rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTHistarchive.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "histarchive-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (histarchive rules, rulecheck, fleet, schedaudit, jobwatch, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK histarchive install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: manifest (fleet add-on), then the histarchive files"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK histarchive manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon histarchive --to $SHA --apply --reason '$TASK histarchive $SHORT first install'"
check "histarchive sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum histarchive/pft-histarchive.sh histarchive/histarchive.py histarchive/lib_hashverify.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-histarchive /usr/local/lib/pft-histarchive/histarchive.py /usr/local/lib/pft-histarchive/lib_hashverify.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-histarchive /usr/local/lib/pft-histarchive/histarchive.py /usr/local/lib/pft-histarchive/lib_hashverify.py | cut -c1-64'"
check "installed script + helper + lib = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 3 ] && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 4. sentry: install.sh --role replica"
x "git archive $SHA histarchive | R 'rm -rf ~/pft-histarchive-$SHORT && mkdir -m 700 ~/pft-histarchive-$SHORT && tar -x -C ~/pft-histarchive-$SHORT'"
x "R 'sudo -n bash ~/pft-histarchive-$SHORT/histarchive/install.sh --role replica --host sentry'"
check "sentry install exit 0, replica dir ready" "$([ "$XRC" = 0 ] && grep -q 'replica role ready' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 5. validator: install.sh --role archive --adopt (follower starts; first periodic: verify + replicate)"
x "sudo -n bash histarchive/install.sh --role archive --host validator --adopt '$ADOPT'"
check "validator install exit 0, verify_ok 1, replica_ok 1" "$([ "$XRC" = 0 ] && grep -q 'pft_histarchive_verify_ok{host="validator"} 1' <<<"$XOUT" && grep -q 'pft_histarchive_replica_ok{host="validator"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash -c 'grep -E \"^HOST_LABEL=\" /etc/pft-histarchive.env; grep -c \"^PEER_SSH=\" /etc/pft-histarchive.env; stat -c \"%a %U\" /etc/pft-histarchive.env /var/lib/pft-histarchive/age.key; stat -c \"%a %U\" /var/lib/pft-histarchive/archive'"
check "validator conf: HOST_LABEL validator, one PEER_SSH, conf + key 600 root, archive dir owned by pft-histarchive" "$(grep -qx HOST_LABEL=validator <<<"$XOUT" && grep -qx 1 <<<"$XOUT" && [ "$(grep -cx '600 root' <<<"$XOUT")" = 2 ] && grep -qx '755 pft-histarchive' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash histarchive/install.sh --role archive --host validator --adopt '$ADOPT' 2>&1 | grep -E 'installed|set |adopt|changed='"
check "second install run is idempotent (changed=false, nothing installed, set or adopted)" "$(grep -q 'changed=false' <<<"$XOUT" && ! grep -qE ' installed | set |adopted' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 6. rulecheck inputs: append the histarchive lines on the validator (idempotent; the sentry writes no textfile)"
x "sudo -n grep -qF 'pft_histarchive' /etc/pft-rulecheck.conf || sed -n '/^# pft-histarchive/,/^require pft_histarchive_replica.prom/p' rulecheck/pft-rulecheck.conf.example | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n histarchive /etc/pft-rulecheck.conf"
check "validator rulecheck.conf has the 7 histarchive lines" "$([ "$(grep -c histarchive <<<"$XOUT")" = 7 ] && echo 0 || echo 1)"

echo; echo "== 7. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 40 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name | test(\"histarchive\")) | .rules[] | [.name, .health, .state] | @tsv'"
check "3 histarchive rules loaded, health ok, none firing" "$([ "$(grep -c '	ok	' <<<"$XOUT")" = 3 ] && ! grep -q 'firing' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 8. new units/timer + conf: pft-schedaudit accept + collect, jobwatch inventory, then pft-integrity accept, both hosts"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160"
x "sudo -n pft-schedaudit accept --reason '$TASK: pft-histarchive-periodic.timer installed' | tail -2; sudo -n pft-schedaudit collect | tail -1"
x "sudo -n pft-jobwatch inventory 2>&1 | grep -E 'histarchive|SUMMARY' | cut -c1-200"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "sudo -n pft-integrity accept --reason '$TASK: histarchive $SHORT installed (env, units, timer, user, state dir, rulecheck.conf, sched items)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "R \"sudo -n pft-integrity accept --reason '$TASK: histarchive $SHORT installed (env, state + replica dirs)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit.service; sudo -n pft-schedaudit audit | grep -E '^SUMMARY'"
check "validator schedaudit: 0 unexpected, 0 new/removed" "$(grep -q '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "sentry schedaudit: 0 unexpected, 0 new/removed (no unit there)" "$(grep -q '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 9. VERIFIED: verify, verify-replica, restore-verify, follower advancing, Prometheus"
x "sudo -n pft-histarchive verify | tail -n 3"
check "local verify PASS" "$([ "$XRC" = 0 ] && grep -q '^RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive verify-replica"
check "verify-replica PASS (sentry index == local, sentry's own check ok)" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n pft-histarchive replica-check'"
check "sentry replica-check PASS (ciphertext only, no key there)" "$([ "$XRC" = 0 ] && grep -q '^RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n test -e /var/lib/pft-histarchive/age.key && echo KEY PRESENT || echo no key on the sentry'"
check "no histarchive identity on the sentry" "$(grep -qx 'no key on the sentry' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive restore-verify"
check "restore-verify from the sentry PASS" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS - restore-verify fails 0' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive status | jq -c '.status | {last, lag, gaps}'; sleep 20; sudo -n pft-histarchive status | jq -c '.status | {last, lag, gaps}'"
check "follower advancing (last grows in 20 s), gaps 0" "$([ "$(sed -n 2p <<<"$XOUT" | jq .last)" -gt "$(sed -n 1p <<<"$XOUT" | jq .last)" ] && [ "$(sed -n 2p <<<"$XOUT" | jq .gaps)" = 0 ] && echo 0 || echo 1)"
x "sleep 30; curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_histarchive_.*\"}' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.__name__) \(.value[1])\"' | sort"
check "Prometheus: verify_ok 1, replica_ok 1, follow_gaps 0 for the validator" "$(grep -q '^validator pft_histarchive_verify_ok 1$' <<<"$XOUT" && grep -q '^validator pft_histarchive_replica_ok 1$' <<<"$XOUT" && grep -q '^validator pft_histarchive_follow_gaps 0$' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 10. fleet skew, rulecheck, units, jobwatch"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, histarchive CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +histarchive +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT |histarchive'"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-active pft-histarchive.service pft-histarchive-periodic.timer"
check "follower + timer active" "$([ "$(grep -cx active <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*histarchive' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees the histarchive timer: not failed, missed or disabled" "$([ "$(grep -cE 'histarchive.* 0$' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 11. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Histarchive|RuleDead|TextfileStale|Rulecheck|Fleet|Sched|PFTJob|KeyEscrow|Integrity\"))] | length'"
check "no histarchive/rulecheck/fleet/schedaudit/jobwatch/keyescrow alert pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n find /var/lib/pft-histarchive -maxdepth 1 -name 'restore.*' | wc -l; systemctl list-units --all --no-legend 'run-u*' | wc -l"
check "no restore scratch left, no transient run-u units" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
