#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host UPDATE of an installed jobwatch to the current HEAD (task_de7c65f8535e68b146f171bcec90b36b), through
# pft-fleet inside a pft-maint window. Built from ../../kernwatch/drill/update-run.sh for the drill run 07 fix
# (6b3087e: per-job label `job` -> `timer`). Only files pft-fleet tracks are written; nothing is restarted or
# re-enabled. Prometheus is sent SIGHUP to load the updated rule file (alerts/ is mounted at /etc/pft-alerts).
# Restore re-runs pft-keyescrow and checks drift 0; the run's own silence is expired at the end (run 06 lesson).
# Run 22 (2026-11-11, task_2fac2360 textfile headroom): writes jobwatch_lib.py only; the textfile drops the per-job
# series no rule or drill reads (job_info, never_run, interval_seconds, last_trigger/last_success timestamps; still in
# `inventory --format json`), so the validator's file (64425 B of the interim 65000 budget) must shrink below 40000 B.
# Run 20 (2026-11-09, calendar period fix): writes jobwatch_lib.py only; calendar intervals now come from the OnCalendar
# spec (systemd-analyze calendar), so the sentry's pft-kmod.timer (learned 700 s -> false PFTJobMissed) must read 3600.
# Run 17 (operator-topic fix, 2026-11-06): writes jobwatch_lib.py only; PFTJobFailed rule now needs consecutive > 0.
# Run 10 (3ec4c00, size fix after update run 09): writes pft-jobwatch.sh + jobwatch_lib.py; checks the validator's
# series are back in Prometheus and the textfile is under 64 KiB.
# pft-maint's [MAINT] start/end messages go to a throwaway topic; the real target is restored and compared at the end,
# and every operator topic is read back (must be 0 messages, kmsg drill run 06 lesson).
#   bash jobwatch/drill/update-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_2fac2360
WHY="textfile keeps only the per-job series rules/drills read (budget headroom before new timers)"
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
since="$(date -u +%s)"
OPS="$(mktemp)"; chmod 600 "$OPS"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap 'restore; rm -f "$OPS"' EXIT
echo "jobwatch two-host update - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight"
x "sha256sum jobwatch/pft-jobwatch.sh jobwatch/jobwatch_lib.py jobwatch/drill/update-run.sh alerts/jobwatch.rules.yml"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the update" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet sync --addon jobwatch --to $SHA | grep -E '^PLAN .* (write|keep)$' | awk '{print \$2, \$4, \$6, \$NF}'"
# run 17 (2026-11-06 operator-topic fix): only jobwatch_lib.py changed (consecutive_failures >= 1 while failed == 1)
check "dry run: jobwatch_lib.py written on both hosts, nothing else (2 writes)" "$([ "$(grep -c ' write$' <<<"$XOUT")" = 2 ] && [ "$(grep ' write$' <<<"$XOUT" | grep -c 'jobwatch_lib.py')" = 2 ] && echo 0 || echo 1)"
x "grep -c ',job=\"' /var/lib/pft-exporter/textfile/pft_jobwatch_validator.prom /var/lib/pft-exporter/textfile/pft_jobwatch_sentry.prom"
x "stat -c '%s %n' /var/lib/pft-exporter/textfile/pft_jobwatch_validator.prom /var/lib/pft-exporter/textfile/pft_jobwatch_sentry.prom; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_jobwatch_up' | jq -r '.data.result[] | .metric.host' | sort"
check "before: both textfiles under 65536 bytes, both hosts in Prometheus" "$([ "$(awk '$1 < 65536' <<<"$XOUT" | wc -l)" = 2 ] && grep -qx validator <<<"$XOUT" && grep -qx sentry <<<"$XOUT" && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }

echo; echo "== 1. rollout silence (pft-fleet/rulecheck see a changed file during the update; not the watchdog)"
ends="$(date -u -d '+30 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK jobwatch update $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTJob.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "jobwatch-update", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (PFTJob*, PFTRuleDead, PFTTextfileStale, PFTRulecheck*, PFTFleet*) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
[ "$SWAPPED" = 1 ] || { echo "no throwaway target - stopping before the window"; exit 3; }
x "sudo -n pft-maint start --ttl 30m --reason '$TASK jobwatch update $SHORT'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: jobwatch files to HEAD on both hosts (writes + integrity accept by pft-fleet)"
x "sudo -n pft-fleet sync --addon jobwatch --to $SHA --apply --reason '$TASK: $WHY ($SHORT)'"
check "jobwatch sync exit 0" "$XRC"
x "sha256sum jobwatch/pft-jobwatch.sh jobwatch/jobwatch_lib.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-jobwatch /usr/local/lib/pft-jobwatch/jobwatch_lib.py | cut -c1-64; R 'sudo -n sha256sum /usr/local/bin/pft-jobwatch /usr/local/lib/pft-jobwatch/jobwatch_lib.py | cut -c1-64'"
check "installed script + helper = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 2 ] && echo 0 || echo 1)"

echo; echo "== 4. behaviour: collect, label is timer= everywhere, rules reloaded and healthy"
x "R 'sudo -n systemctl start pft-jobwatch.service; systemctl show -p Result --value pft-jobwatch.service' && sudo -n systemctl start pft-jobwatch.service pft-jobwatch-pull.service; systemctl show -p Result --value pft-jobwatch.service pft-jobwatch-pull.service"
check "collector (both hosts) + pull: Result success x3" "$([ "$(grep -cx success <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "for f in validator sentry; do echo \"\$f job= \$(grep -c ',job=\"' /var/lib/pft-exporter/textfile/pft_jobwatch_\$f.prom) timer= \$(grep -c ',timer=\"' /var/lib/pft-exporter/textfile/pft_jobwatch_\$f.prom)\"; done"
check "both textfiles: 0 job= labels, timer= labels present" "$([ "$(grep -cE ' job= 0 timer= [1-9][0-9]*$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 75 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-jobwatch\") | .rules[] | [.name, .health, .state, (.query | contains(\"on (host, timer)\"))] | @tsv'"
check "4 jobwatch rules loaded, health ok, inactive; PFTJobFailed joins on (host, timer)" "$([ "$(grep -c '	ok	inactive' <<<"$XOUT")" = 4 ] && grep -q '^PFTJobFailed	ok	inactive	true$' <<<"$XOUT" && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=count by (host) (pft_jobwatch_job_present{timer!=\"\"})' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort; curl -s $PROM/api/v1/query --data-urlencode 'query=count(pft_jobwatch_job_present{exported_job!=\"\"}) or vector(0)' | jq -r '.data.result[0].value[1]'"
check "Prometheus: timer-labelled series for both hosts, 0 exported_job series" "$(grep -qE '^sentry [1-9][0-9]*$' <<<"$XOUT" && grep -qE '^validator [1-9][0-9]*$' <<<"$XOUT" && [ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
# run 22: the fix itself. version 2 on both hosts, no dropped series left, validator file well under budget
x "grep -h '^pft_jobwatch_version' /var/lib/pft-exporter/textfile/pft_jobwatch_validator.prom /var/lib/pft-exporter/textfile/pft_jobwatch_sentry.prom; grep -cE '^pft_jobwatch_job_(info|never_run|interval_seconds|last_trigger_timestamp_seconds|last_success_timestamp_seconds)[{]' /var/lib/pft-exporter/textfile/pft_jobwatch_validator.prom /var/lib/pft-exporter/textfile/pft_jobwatch_sentry.prom; stat -c '%s %n' /var/lib/pft-exporter/textfile/pft_jobwatch_validator.prom"
check "version 2 on both hosts, 0 dropped series in both textfiles, validator textfile < 40000 B" "$([ "$(grep -cE '^pft_jobwatch_version\{host="(validator|sentry)"\} 2$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE ':0$' <<<"$XOUT")" = 2 ] && awk '$2 ~ /validator.prom$/ && $1 + 0 < 40000 { ok = 1 } END { exit !ok }' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-jobwatch inventory --format json | jq -r '.[0] | [has(\"interval_seconds\"), has(\"last_success_timestamp_seconds\"), has(\"service\")] | @tsv'"
check "inventory --format json still has the dropped fields" "$(grep -qx 'true	true	true' <<<"$XOUT" && echo 0 || echo 1)"
x "for h in validator sentry; do echo \"\$h missed \$(grep -E '^pft_jobwatch_jobs\\{host=\"'\$h'\",state=\"missed\"\\}' /var/lib/pft-exporter/textfile/pft_jobwatch_\$h.prom | awk '{print \$2}')\"; done"
check "0 missed jobs on both hosts" "$([ "$(grep -cE '^(validator|sentry) missed 0$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "stat -c '%s %n' /var/lib/pft-exporter/textfile/pft_jobwatch_validator.prom /var/lib/pft-exporter/textfile/pft_jobwatch_sentry.prom"
check "both textfiles under the exporter's 65536-byte limit" "$([ "$(awk '$1 < 65536' <<<"$XOUT" | wc -l)" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_jobwatch_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "Prometheus: pft_jobwatch_up 1 for both hosts" "$([ "$(grep -cE '^(sentry|validator) 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 5. integrity and fleet skew"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E 'jobwatch|SUMMARY'"
check "jobwatch CURRENT on both hosts" "$([ "$(grep -cE '^ *(validator|sentry) +jobwatch +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 6. end window, restore the real target, compare, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' /var/lib/pft-exporter/textfile/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"PFTJob|RuleDead|TextfileStale|Rulecheck|Fleet\"))] | length'"
curl -s --max-time 10 -o /dev/null -w "  rollout silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
check "no jobwatch/rulecheck/fleet alert pending or firing; rollout silence expired" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
echo; echo "update-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
