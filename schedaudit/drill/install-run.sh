#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host install of schedaudit at the current HEAD (task_63b12600036365c3f4249ba43596cd52, step 5), through
# pft-fleet inside a pft-maint window. Built from ../../jobwatch/drill/install-run.sh (PASS) + the operator-topic
# read-back of ../../jobwatch/drill/update-run.sh. Nothing is restarted.
#   0. FOUND: the HEAD helper audits both hosts read-only (python3 - < schedaudit_lib.py, no --integrity-hook: the
#      installed pft-integrity has no collect_sched yet), before anything changes.
#   3. pft-fleet writes the manifest, the pft-integrity hook (collect_sched) and the schedaudit files on both hosts.
#   4-6. install.sh on each host (first accept with a reason after review of step 0), allowlist on the validator for the
#      operator's own unprivileged agent cron (nonsystem_user by design), the validator's pull of the sentry file.
#   8. integrity accepts the new sched:* items (+ env/allowlist/timer links) on both hosts: this is the FIX for every
#      `untracked` finding of step 0.  9. VERIFIED: pft-schedaudit audit on both hosts = 0 unexpected findings.
# pft-maint's [MAINT] start/end messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow
# is re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the schedaudit/rulecheck/fleet alerts (never the pipeline watchdog) and is left to run out.
#   bash schedaudit/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash schedaudit/drill/install-run.sh   (step 0 only; changes nothing)
# HEAD must already carry the fleet/manifest.tsv lines, the prometheus.yml rule line and the rulecheck example lines.
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_63b12600
TT="pft-drill-schedaudit-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
# the operator's own agent (cron.d file + its script dir) is internal: never named in a published log
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g; s#cron\.d/pft-agent#cron.d/<operator-agent>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-schedaudit
SWAPPED=0; MAINT=0; HAD=0
since="$(date -u +%s)"
OPS="$(mktemp)"; chmod 600 "$OPS"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
  R "rm -rf /tmp/pft-schedaudit-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
echo "schedaudit two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight + FOUND (read-only audit of both hosts with the HEAD helper, nothing installed)"
x "sha256sum schedaudit/pft-schedaudit.sh schedaudit/schedaudit_lib.py schedaudit/install.sh schedaudit/drill/install-run.sh schedaudit/systemd/* alerts/schedaudit.rules.yml integrity/pft-integrity.sh"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-schedaudit /etc/pft-schedaudit.env 2>&1; R 'ls /usr/local/bin/pft-schedaudit 2>&1'"
check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "grep -c '^collect_sched()' /usr/local/bin/pft-integrity; R 'grep -c ^collect_sched\(\) /usr/local/bin/pft-integrity'"
check "installed pft-integrity has no collect_sched hook yet (both hosts)" "$([ "$(grep -cx 0 <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "grep -n schedaudit alerts/prometheus.yml fleet/manifest.tsv rulecheck/pft-rulecheck.conf.example rulecheck/pft-rulecheck.sentry.conf.example 2>&1 | cut -c1-150"
check "HEAD lists the rule file, 6 manifest lines and the 7 rulecheck example lines" "$([ "$(grep -c 'manifest.tsv' <<<"$XOUT")" = 6 ] && grep -q 'prometheus.yml' <<<"$XOUT" && [ "$(grep -c 'rulecheck' <<<"$XOUT")" = 7 ] && echo 0 || echo 1)"
x "sudo -n grep -c '^PULL_SSH=' /etc/pft-jobwatch.env"
check "a PULL_SSH line to copy exists (/etc/pft-jobwatch.env, not printed)" "$([ "$XOUT" = 1 ] && echo 0 || echo 1)"
x "sudo -n python3 -I - audit < schedaudit/schedaudit_lib.py | grep -vE '^(INFO|ALLOWED)'"
VF="$XOUT"
check "FOUND validator: audit ran (SUMMARY line, baseline=no)" "$(grep -q '^SUMMARY .*baseline=no' <<<"$VF" && echo 0 || echo 1)"
x "R 'sudo -n python3 -I - audit' < schedaudit/schedaudit_lib.py | grep -vE '^(INFO|ALLOWED)'"
SF="$XOUT"
check "FOUND sentry: audit ran (SUMMARY line, baseline=no)" "$(grep -q '^SUMMARY .*baseline=no' <<<"$SF" && echo 0 || echo 1)"
FOUND_V="$(grep -cE '^(CRIT|WARN)	' <<<"$VF")"; FOUND_S="$(grep -cE '^(CRIT|WARN)	' <<<"$SF")"
echo "found: validator $FOUND_V finding(s) ($(grep -E '^(CRIT|WARN)	' <<<"$VF" | cut -f2 | sort | uniq -c | xargs)), sentry $FOUND_S ($(grep -E '^(CRIT|WARN)	' <<<"$SF" | cut -f2 | sort | uniq -c | xargs))"
UNEXP="$(grep -E '^(CRIT|WARN)	' <<<"$VF$SF" | cut -f2 | grep -vxE 'untracked|nonsystem_user' | sort -u | xargs)"
check "every finding is a class this run fixes (untracked -> integrity hook) or allowlists (operator agent nonsystem_user)" "$([ -z "$UNEXP" ] && echo 0 || echo 1)" "${UNEXP:-none other}"
NSU="$(grep -E '^WARN	nonsystem_user	' <<<"$VF$SF" | cut -f3 | sed 's/@.*//' | sort -u | xargs)"
check "the only nonsystem_user entry is the operator agent cron on the validator" "$([ -z "$NSU" ] || [ "$NSU" = cron.d/pft-agent ] && echo 0 || echo 1)" "$(red <<<"${NSU:-none}")"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $AM/api/v2/alerts | jq -r '.[].labels.alertname' | sort | uniq -c"
check "no active silence; only the pipeline watchdog active in Alertmanager" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$(sed 1d <<<"$XOUT" | grep -vc PFTAlertPipelineWatchdog)" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (new rules; rulecheck/fleet see new files during the install; not the watchdog)"
ends="$(date -u -d '+45 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK schedaudit rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTSchedEntryUnexpected|PFTSchedauditStale|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "schedaudit-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (schedaudit rules, PFTRuleDead, PFTTextfileStale, PFTRulecheck*, PFTFleet*; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK schedaudit install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: manifest (fleet add-on), the pft-integrity hook (integrity add-on), the schedaudit files"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK schedaudit manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon integrity --to $SHA --apply --reason '$TASK pft-integrity collect_sched hook'"
check "integrity sync exit 0 (pft-integrity.sh with collect_sched on both hosts)" "$XRC"
x "sudo -n pft-fleet sync --addon schedaudit --to $SHA --apply --reason '$TASK schedaudit $SHORT first install'"
check "schedaudit sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum schedaudit/pft-schedaudit.sh schedaudit/schedaudit_lib.py integrity/pft-integrity.sh | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-schedaudit /usr/local/lib/pft-schedaudit/schedaudit_lib.py /usr/local/bin/pft-integrity | cut -c1-64; R 'sha256sum /usr/local/bin/pft-schedaudit /usr/local/lib/pft-schedaudit/schedaudit_lib.py /usr/local/bin/pft-integrity | cut -c1-64'"
check "installed script + helper + pft-integrity = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 3 ] && echo 0 || echo 1)"

echo; echo "== 4. sentry: install.sh (first accept after the step-0 review; collect through the sandboxed unit)"
x "git archive $SHA schedaudit | R 'rm -rf /tmp/pft-schedaudit-$SHORT && mkdir -m 700 /tmp/pft-schedaudit-$SHORT && tar -x -C /tmp/pft-schedaudit-$SHORT'"
x "R \"sudo -n bash /tmp/pft-schedaudit-$SHORT/schedaudit/install.sh --host sentry --reason '$TASK first install: step-0 audit reviewed, only untracked findings (fixed by the integrity hook)'\""
check "sentry install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_schedaudit_up{host="sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 5. validator: allowlist (operator agent cron), install.sh, then the pull of the sentry file"
x "sudo -n test -e /etc/pft-schedaudit.allow || { printf '%s\n' '# pft-schedaudit allowlist: CHECK ENTRY_GLOB PATH_GLOB REASON (reason required; see README)' 'nonsystem_user cron.d/pft-agent@* /etc/cron.d/pft-agent operator task agent: an unprivileged cron job that runs as its own login user by design' | sudo -n tee /etc/pft-schedaudit.allow >/dev/null && sudo -n chmod 600 /etc/pft-schedaudit.allow; }; sudo -n grep -vc '^#' /etc/pft-schedaudit.allow; sudo -n stat -c '%a %U' /etc/pft-schedaudit.allow"
check "validator allowlist: 1 reasoned line, 600 root" "$([ "$(head -1 <<<"$XOUT")" = 1 ] && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash schedaudit/install.sh --host validator --reason '$TASK first install: step-0 audit reviewed, untracked findings fixed by the integrity hook, operator agent cron allowlisted'"
check "validator install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_schedaudit_up{host="validator"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n grep -q '^PULL_SSH=' /etc/pft-schedaudit.env || { sudo -n grep '^PULL_SSH=' /etc/pft-jobwatch.env | sudo -n tee -a /etc/pft-schedaudit.env >/dev/null; }; sudo -n chmod 600 /etc/pft-schedaudit.env; sudo -n grep -c '^PULL_SSH=' /etc/pft-schedaudit.env; sudo -n stat -c '%a %U' /etc/pft-schedaudit.env"
check "validator conf: one PULL_SSH line, 600 root" "$([ "$(head -1 <<<"$XOUT")" = 1 ] && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash schedaudit/install.sh --pull --host sentry --reason '$TASK pft-schedaudit-pull.timer installed'"
check "pull install exit 0, sentry file on the validator, pull timer accepted (0 new)" "$([ "$XRC" = 0 ] && grep -q 'pft_schedaudit_up{host="sentry"} 1' "/var/lib/pft-exporter/textfile/pft_schedaudit_sentry.prom" 2>/dev/null && grep -q '^SUMMARY .* new=0 removed=0 ' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 6. rulecheck inputs: append the schedaudit lines (idempotent; the live confs carry earlier add-ons' lines)"
RC_TF='textfile pft_schedaudit_*.prom   20m   pft_schedaudit_collect_timestamp_seconds'
x "sudo -n grep -qF 'pft_schedaudit_' /etc/pft-rulecheck.conf || printf '%s\n' '# pft-schedaudit (5-minute collector; sentry copy pulled every 5 min)' '$RC_TF' 'require pft_schedaudit_validator.prom' 'require pft_schedaudit_sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n schedaudit /etc/pft-rulecheck.conf"
check "validator rulecheck.conf has the 4 schedaudit lines" "$([ "$(grep -c schedaudit <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "R \"sudo -n grep -qF 'pft_schedaudit_' /etc/pft-rulecheck.conf || printf '%s\\n' '# pft-schedaudit (5-minute collector)' '$RC_TF' 'require pft_schedaudit_sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n schedaudit /etc/pft-rulecheck.conf\""
check "sentry rulecheck.conf has the 3 schedaudit lines" "$([ "$(grep -c schedaudit <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 7. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-schedaudit\") | .rules[] | [.name, .health, .state] | @tsv'"
check "2 schedaudit rules loaded, health ok" "$([ "$(grep -c '	ok	' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 8. FIX: the untracked files are now pft-integrity sched:* items (pft-fleet's post-sync accept took the first"
echo "   set in with its own reason; anything install.sh added since is accepted here), then PASS on both hosts"
x "sudo -n tail -n 4 /var/lib/pft-integrity/accept.log | cut -c1-200"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -60"
x "sudo -n pft-integrity accept --reason '$TASK: schedaudit $SHORT installed (sched:* scope items, env, allowlist, timers, rulecheck.conf)' | tail -2"
x "R 'sudo -n tail -n 4 /var/lib/pft-integrity/accept.log' | cut -c1-200"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -60"
x "R \"sudo -n pft-integrity accept --reason '$TASK: schedaudit $SHORT installed (sched:* scope items, env, timer, rulecheck.conf)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify --verbose | grep -c 'sched:'; R 'sudo -n pft-integrity verify --verbose | grep -c sched:'"
check "both hosts now track sched:* items" "$([ "$(grep -cE '^[1-9][0-9]*$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 9. VERIFIED: audit both hosts with the installed tool (hook on), collect, Prometheus"
x "sudo -n systemctl start pft-schedaudit.service; sudo -n pft-schedaudit audit | grep -vE '^INFO'"
check "validator: 0 unexpected findings, 0 new/removed, baseline yes (found $FOUND_V)" "$(grep -q '^SUMMARY .* unexpected_findings=0 new=0 removed=0 baseline=yes' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-schedaudit.service; sudo -n pft-schedaudit audit' | grep -vE '^INFO'"
check "sentry: 0 unexpected findings, 0 new/removed, baseline yes (found $FOUND_S)" "$(grep -q '^SUMMARY .* unexpected_findings=0 new=0 removed=0 baseline=yes' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit-pull.service; sleep 40; curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_schedaudit_(up|unexpected)\"}' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.__name__) \(.metric.kind // \"-\") \(.value[1])\"' | sort"
check "Prometheus: pft_schedaudit_up 1 for both hosts" "$([ "$(grep -cE ' pft_schedaudit_up - 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
check "Prometheus: all 8 unexpected series 0" "$([ "$(grep -cE ' pft_schedaudit_unexpected [a-z]+ 0$' <<<"$XOUT")" = 8 ] && echo 0 || echo 1)"

echo; echo "== 10. fleet skew, rulecheck, timers"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, schedaudit + integrity CURRENT on both hosts" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +(schedaudit|integrity) +CURRENT' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-active pft-schedaudit.timer pft-schedaudit-pull.timer; R 'systemctl is-active pft-schedaudit.timer'"
check "3 timers active" "$([ "$(grep -cx active <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 11. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' /var/lib/pft-exporter/textfile/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"PFTSched|RuleDead|TextfileStale|Rulecheck|Fleet|Integrity\"))] | length'"
check "no schedaudit/rulecheck/fleet alert pending or firing (silence left to run out, lesson 185)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
