#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host install of budget at the current HEAD (task_9fb56f105f2b404c135135b0e6ff456e), through pft-fleet
# inside a pft-maint window. Built from ../../internals/drill/install-run.sh (PASS, internals log 07). Installing
# changes NO node config, restarts nothing and caps nothing: it adds the read-only cgroup sampler (system user
# pft-budget, no capabilities) and the 5-minute report textfile on both hosts, the validator's pull of the sentry
# textfile and the two alert rules. Right-sizing (apply) is a separate, later step.
#   0. preflight: integrity PASS, nodes full, not installed, HEAD carries the manifest/prometheus/rulecheck lines,
#      tools + cgroup v2 on both hosts, jobwatch budget, the pull's ssh source, operator topics, Prometheus, alerts.
#   3. pft-fleet writes the manifest copy (fleet), the budget files on both hosts, then aptrust's allowlist copy.
#   5. sentry: install.sh --host sentry.  6. validator: install.sh --host validator, PULL_SSH, install.sh --pull.
#   7. rulecheck lines.  8. rules loaded.  9. schedaudit + jobwatch + integrity accept, both hosts.
#  10. VERIFIED: sampler running under its caps, records written, textfiles valid, Prometheus series, aptrust 0/0,
#      confinement 0 denials.  11. skew, rulecheck, timers, jobwatch.  12. restore + read-back.
# pft-maint's [MAINT] messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow is
# re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the budget/rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow alerts (never the pipeline
# watchdog) and is left to run out.
#   bash budget/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash budget/drill/install-run.sh  (step 0 only; changes nothing)
# KNOWN_PENDING: alert names already pending (long `for:`) before the run that the preflight accepts (each is printed).
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_9fb56f10
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-budget-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-budget
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
  R "rm -rf ~/pft-budget-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
srv_state() { # both nodes' server_state, validator first (same exec shape as selfheal/install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
tf_check() { # NAME BYTES SAMPLES valid, per textfile on the validator (local + pulled sentry copy)
  local n f
  for n in validator sentry; do
    f="$TF/pft_budget_$n.prom"
    echo "$n $(stat -c %s "$f") $(grep -vc '^#' "$f") $(pft-budget validate "$f" "$n" >/dev/null && echo valid)"
  done
}
prom_check() { # series per host, then up per host
  curl -s "$PROM/api/v1/query" --data-urlencode 'query=count by (host) ({__name__=~"pft_budget_.+"})' \
    | jq -r '.data.result[] | "\(.metric.host) \(.value[1])"' | sort
  curl -s "$PROM/api/v1/query" --data-urlencode 'query=pft_budget_up' \
    | jq -r '.data.result[] | "\(.metric.host) \(.metric.__name__) \(.value[1])"' | sort
}
echo "budget two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum budget/pft-budget.sh budget/budget.py budget/install.sh budget/drill/install-run.sh budget/systemd/* alerts/budget.rules.yml alerts/budget.tests.yml fleet/manifest.tsv"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-budget /etc/pft-budget.env /var/lib/pft-budget 2>&1; R 'ls /usr/local/bin/pft-budget /etc/pft-budget.env /var/lib/pft-budget 2>&1'; getent passwd pft-budget | wc -l; R 'getent passwd pft-budget | wc -l'"
check "not installed yet on either host (no files, no pft-budget user)" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 6 ] && [ "$(grep -cx 0 <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "grep -c '^budget ' fleet/manifest.tsv; grep -c budget.rules.yml alerts/prometheus.yml; grep -c pft_budget rulecheck/pft-rulecheck.conf.example; grep -c pft_budget rulecheck/pft-rulecheck.sentry.conf.example"
check "HEAD lists 7 budget manifest lines, the rule file and 3 + 2 rulecheck lines" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "7 1 3 2 " ] && echo 0 || echo 1)"
x "for h in L R; do if [ \$h = L ]; then bash -c 'for c in python3 jq awk timeout useradd; do command -v \$c; done | wc -l; test -f /sys/fs/cgroup/cgroup.controllers && echo cgroup2; sudo -n test -f /etc/pft-rulecheck.conf && echo rc-conf'; else R 'for c in python3 jq awk timeout useradd; do command -v \$c; done | wc -l; test -f /sys/fs/cgroup/cgroup.controllers && echo cgroup2; sudo -n test -f /etc/pft-rulecheck.conf && echo rc-conf'; fi; done"
check "python3 jq awk timeout useradd, cgroup v2 and a pft-rulecheck conf on both hosts" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "5 cgroup2 rc-conf 5 cgroup2 rc-conf " ] && echo 0 || echo 1)"
x "sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout 2>/dev/null | wc -c; R 'sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout 2>/dev/null | wc -c'; sudo -n sed -n 's/^TEXT_BUDGET=//p' /etc/pft-jobwatch.env"
JW_V="$(sed -n 1p <<<"$XOUT")"; JW_S="$(sed -n 2p <<<"$XOUT")"; JW_BUDGET="$(sed -n 3p <<<"$XOUT")"; JW_BUDGET="${JW_BUDGET:-61440}"
check "jobwatch textfiles have room for the new timers (validator $JW_V + 2x1200, sentry $JW_S + 1200 <= budget $JW_BUDGET / 61440)" "$([ $((JW_V + 2400)) -le "$JW_BUDGET" ] && [ $((JW_S + 1200)) -le 61440 ] && echo 0 || echo 1)"
pull_probe() { # run pft-statewatch's PULL_SSH (as root, like the unit) with `true`; prints nothing of the command
  sudo -n grep -c '^PULL_SSH=' /etc/pft-statewatch.env
  sudo -n bash -c 'c="$(sed -n "s/^PULL_SSH=//p" /etc/pft-statewatch.env | tr -d "\"")"; [ -n "$c" ] && $c true' >/dev/null 2>&1 && echo pull-ssh-ok
}
x "pull_probe"
check "the pull's ssh command (pft-statewatch's PULL_SSH, non-empty) reaches the sentry when run as root" "$(grep -qx 1 <<<"$XOUT" && grep -qx pull-ssh-ok <<<"$XOUT" && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s --max-time 10 $PROM/api/v1/alerts | jq -r .status; curl -s --max-time 10 $AM/api/v2/status | jq -r 'if (.uptime // \"\") != \"\" then \"up\" else \"down\" end'"
check "Prometheus and Alertmanager answer (alert gates below fail closed)" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "success up " ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
echo "known pending before the run (accepted by the preflight): ${KNOWN_PENDING:-none}"
UNK="$(sed 1d <<<"$XOUT" | awk '{print $2}' | grep -vx PFTAlertPipelineWatchdog | while read -r a; do case " $KNOWN_PENDING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "no active silence; only the pipeline watchdog (+ KNOWN_PENDING) pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$UNK" = 0 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.state == \"firing\" and .labels.alertname != \"PFTAlertPipelineWatchdog\")] | length'"
check "nothing but the watchdog FIRING (KNOWN_PENDING may only be pending)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (new rules; rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow see new files and timers; not the watchdog)"
ends="$(date -u -d '+60 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK budget rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTBudget.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "budget-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (budget rules, rulecheck, fleet, aptrust, schedaudit, jobwatch, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK budget install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: manifest (fleet add-on), budget, then aptrust's allowlist copy"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK budget manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon budget --to $SHA --apply --reason '$TASK budget $SHORT first install'"
check "budget sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust allowlist copy += budget rows'"
check "aptrust sync exit 0 (its manifest copy follows the new rows)" "$XRC"
x "sha256sum budget/pft-budget.sh budget/budget.py budget/systemd/pft-budget-sampler.service budget/systemd/pft-budget-collect.service budget/systemd/pft-budget-collect.timer | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-budget /usr/local/lib/pft-budget/budget.py /etc/systemd/system/pft-budget-sampler.service /etc/systemd/system/pft-budget-collect.service /etc/systemd/system/pft-budget-collect.timer | cut -c1-64; R 'sha256sum /usr/local/bin/pft-budget /usr/local/lib/pft-budget/budget.py /etc/systemd/system/pft-budget-sampler.service /etc/systemd/system/pft-budget-collect.service /etc/systemd/system/pft-budget-collect.timer | cut -c1-64'"
check "installed script + helper + units = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 5 ] && echo 0 || echo 1)"
x "sha256sum budget/systemd/pft-budget-pull@.service budget/systemd/pft-budget-pull@.timer | cut -c1-64; sudo -n sha256sum /etc/systemd/system/pft-budget-pull@.service /etc/systemd/system/pft-budget-pull@.timer | cut -c1-64; R 'ls /etc/systemd/system/pft-budget-pull@.service 2>&1'"
check "pull units = repo bytes on the validator, absent on the sentry (role validator)" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 2' | wc -l)" = 2 ] && grep -q 'No such file' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 5. sentry: install.sh --host sentry"
x "git archive $SHA budget | R 'rm -rf ~/pft-budget-$SHORT && mkdir -m 700 ~/pft-budget-$SHORT && tar -x -C ~/pft-budget-$SHORT'"
x "R 'sudo -n bash ~/pft-budget-$SHORT/budget/install.sh --host sentry'"
check "sentry install exit 0, sampler heartbeat, first collection up 1, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'sampler: ok, last scan' <<<"$XOUT" && grep -q 'pft_budget_up{host="sentry"} 1' <<<"$XOUT" && grep -q 'enabled pft-budget-collect.timer' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 6. validator: install.sh --host validator, then PULL_SSH and install.sh --pull sentry"
x "sudo -n bash budget/install.sh --host validator"
check "validator install exit 0, sampler heartbeat, first collection up 1, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'sampler: ok, last scan' <<<"$XOUT" && grep -q 'pft_budget_up{host="validator"} 1' <<<"$XOUT" && grep -q 'enabled pft-budget-collect.timer' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash -c 'grep -q \"^PULL_SSH=\" /etc/pft-budget.env || grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-budget.env; grep -c \"^PULL_SSH=\" /etc/pft-budget.env; stat -c \"%a %U\" /etc/pft-budget.env'"
check "validator conf: one PULL_SSH (copied, not printed), root-owned 644 (no secret in it)" "$(grep -qx 1 <<<"$XOUT" && grep -qx '644 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash budget/install.sh --pull sentry"
check "validator --pull exit 0, pulled sentry textfile has up 1, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'pft_budget_up{host="sentry"} 1' <<<"$XOUT" && grep -q 'enabled pft-budget-pull@sentry.timer' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash budget/install.sh --host validator 2>&1 | grep -E 'added to|ERROR|created'"
check "second install run adds no rulecheck line, creates nothing and reports no error" "$([ "$(grep -cE 'added to|ERROR|created' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 7. rulecheck inputs (written by install.sh)"
x "sudo -n grep -n pft_budget /etc/pft-rulecheck.conf; R 'sudo -n grep -n pft_budget /etc/pft-rulecheck.conf'"
check "validator 3 + sentry 2 pft_budget rulecheck lines" "$([ "$(grep -c pft_budget <<<"$XOUT")" = 5 ] && [ "$(grep -c 'require pft_budget_sentry.prom' <<<"$XOUT")" = 2 ] && grep -q 'require pft_budget_validator.prom' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 8. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 40 && curl -s $PROM/api/v1/status/runtimeinfo | jq -r .data.reloadConfigSuccess && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-budget\") | .rules[] | [.name, .health, .state] | @tsv'"
check "config reload ok, 2 budget rules loaded, health ok, inactive" "$(grep -qx true <<<"$XOUT" && [ "$(grep -c '	ok	inactive' <<<"$XOUT")" = 2 ] && [ "$(grep -c '^PFTBudget' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 9. new units/timers/user + conf: pft-schedaudit accept + collect, jobwatch inventory, then pft-integrity accept, both hosts"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160; R 'sudo -n pft-schedaudit audit' | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160"
x "sudo -n pft-schedaudit accept --reason '$TASK: pft-budget-sampler + pft-budget-collect + pft-budget-pull@sentry installed' | tail -2; sudo -n pft-schedaudit collect | tail -1"
x "R \"sudo -n pft-schedaudit accept --reason '$TASK: pft-budget-sampler + pft-budget-collect installed' | tail -2; sudo -n pft-schedaudit collect | tail -1\""
x "sudo -n pft-jobwatch inventory 2>&1 | grep -E 'budget|SUMMARY' | cut -c1-200; R 'sudo -n pft-jobwatch inventory 2>&1' | grep -E 'budget|SUMMARY' | cut -c1-200"
check "jobwatch learns a 300 s interval for the 3 budget timers (validator 2, sentry 1)" "$([ "$(grep -E 'budget' <<<"$XOUT" | grep -cw 300)" = 3 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "sudo -n pft-integrity accept --reason '$TASK: budget $SHORT installed (pft-budget user, conf, data dir, units, timers, rulecheck.conf, sched items)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "R \"sudo -n pft-integrity accept --reason '$TASK: budget $SHORT installed (pft-budget user, conf, data dir, units, timer, rulecheck.conf, sched items)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit on both hosts: 0 unexpected, 0 new/removed" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit-pull.service; grep -h '^pft_schedaudit_unexpected' $TF/pft_schedaudit_*.prom | grep -vc ' 0$'"
check "schedaudit textfiles: every pft_schedaudit_unexpected series 0 (validator + pulled sentry copy)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 10. VERIFIED: sampler under its caps, records, textfiles on both hosts, Prometheus series, aptrust, confinement"
x "TZ=UTC systemctl show -p ActiveState -p User -p MemoryMax -p CPUQuotaPerSecUSec -p CapabilityBoundingSet -p NRestarts pft-budget-sampler.service; R 'TZ=UTC systemctl show -p ActiveState -p User -p MemoryMax -p CPUQuotaPerSecUSec -p CapabilityBoundingSet -p NRestarts pft-budget-sampler.service'"
check "sampler active as pft-budget, MemoryMax 64M, CPU 10%, no capabilities, 0 restarts, both hosts" "$([ "$(grep -cx 'ActiveState=active' <<<"$XOUT")" = 2 ] && [ "$(grep -cx 'User=pft-budget' <<<"$XOUT")" = 2 ] && [ "$(grep -cx 'MemoryMax=67108864' <<<"$XOUT")" = 2 ] && [ "$(grep -cx 'CPUQuotaPerSecUSec=100ms' <<<"$XOUT")" = 2 ] && [ "$(grep -cx 'CapabilityBoundingSet=' <<<"$XOUT")" = 2 ] && [ "$(grep -cx 'NRestarts=0' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sleep 60; sudo -n pft-budget status; sudo -n wc -l /var/lib/pft-budget/samples.jsonl; R 'sudo -n pft-budget status; sudo -n wc -l /var/lib/pft-budget/samples.jsonl'"
check "both samplers fresh and have written records" "$([ "$(grep -c '^sampler: ok' <<<"$XOUT")" = 2 ] && [ "$(awk '/samples.jsonl/ && $1 > 0' <<<"$XOUT" | wc -l)" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-budget-collect.service; R 'sudo -n systemctl start pft-budget-collect.service'; sudo -n systemctl start pft-budget-pull@sentry.service; tf_check"
check "both textfiles valid and under 61440 bytes" "$([ "$(awk '$2 < 61440 && $3 > 3 && $4 == "valid"' <<<"$XOUT" | wc -l)" = 2 ] && echo 0 || echo 1)"
x "sleep 45; prom_check"
check "Prometheus has pft_budget series for validator and sentry, up 1 each" "$([ "$(awk 'NF == 2 && $2 > 3' <<<"$XOUT" | wc -l)" = 2 ] && [ "$(grep -cE '^(validator|sentry) pft_budget_up 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^RESULT'"
check "aptrust audit on both hosts: 0 warn, 0 fail (new binaries are in its allowlist copy)" "$([ "$(grep -c ' 0 warn, 0 fail -> exit 0' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust.service; R 'sudo -n systemctl start pft-aptrust.service'; sudo -n systemctl start pft-aptrust-pull.service; grep -hE '^pft_aptrust_checks\{.*result=\"(warn|fail)\"' $TF/pft_aptrust_*.prom"
check "aptrust textfiles (validator + pulled sentry): warn 0, fail 0" "$([ "$(grep -c '} 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts with 0 denials (budget never enters the containers)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 11. fleet skew, rulecheck, timers, jobwatch"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, budget CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +budget +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-jobwatch.service'; sudo -n systemctl start pft-jobwatch-pull.service; echo pulled"
x "s=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat | grep -E '^RESULT |budget'"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 's=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat' | grep -E '^RESULT |budget'"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck-pull.service; echo pulled"
x "systemctl is-active pft-budget-sampler.service pft-budget-collect.timer pft-budget-pull@sentry.timer; R 'systemctl is-active pft-budget-sampler.service pft-budget-collect.timer'; systemctl is-failed pft-budget-collect.service pft-budget-pull@sentry.service; R 'systemctl is-failed pft-budget-collect.service'"
check "sampler + timers active and services not failed on both hosts" "$([ "$(grep -cx active <<<"$XOUT")" = 5 ] && [ "$(grep -cx failed <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "TZ=UTC systemctl show -p TimersCalendar pft-budget-collect.timer pft-budget-pull@sentry.timer"
check "timer calendars: collect every 5 minutes at :20, pull at :50" "$(grep -q 'OnCalendar=\*-\*-\* \*:00/5:20' <<<"$XOUT" && grep -q 'OnCalendar=\*-\*-\* \*:00/5:50' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*budget' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees both validator budget timers: not failed, missed or disabled" "$([ "$(grep -cE 'budget.* 0$' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"

echo; echo "== 12. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Budget|RuleDead|TextfileStale|Rulecheck|Fleet|Aptrust|Sched|PFTJob|KeyEscrow|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no budget/rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow/confinement alert pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R 'ls -d ~/pft-budget-* 2>/dev/null | wc -l'"
check "no transient run-u services/timers, no install copy left on the sentry" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
