#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded install of alertstats on the validator at the current HEAD (task_61903325930686240eb75d20003170a5), through
# pft-fleet inside a pft-maint window, plus the first real 7-day report. Built from ../../fwaudit/drill/install-run.sh
# (PASS, fwaudit log 08). alertstats is validator-only (the host that runs ../alerts); the sentry only gets aptrust's
# refreshed allowlist copy of fleet/manifest.tsv (lesson: every new manifest row needs `--addon aptrust` too).
#   0. preflight: integrity PASS, nodes full, not installed, HEAD carries the manifest/prometheus/rulecheck lines,
#      jobwatch budget, operator topics, alerts.
#   1. rollout silence (not the watchdog).  2. pft-maint window, [MAINT] to a throwaway topic.
#   3. pft-fleet: fleet (manifest copy), alertstats, aptrust.  4. install.sh (first report through the unit).
#   5. rulecheck lines.  6. rule loaded.  7. schedaudit + jobwatch + integrity accept.
#   8. VERIFIED: textfile/Prometheus series, aptrust, confinement, skew, rulecheck, timer.
#   9. the 7-day report: every headline number re-derived with jq from the JSON report; offline rebuild of the
#      installed bundle is byte-identical to the unit's reports (md, json, csv).
#  10. restore + read-back of every operator topic (must be 0 messages).
#   bash alertstats/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash alertstats/drill/install-run.sh  (step 0 only; changes nothing)
#   UPGRADE=1 OUT=alertstats/logs/report-7d-NAME bash alertstats/drill/install-run.sh   same steps for an installed
#       alertstats whose helper or script differs from HEAD (preflight requires that instead of "not installed").
# KNOWN_PENDING: alert names already pending (long `for:`) before the run that the preflight accepts (each is printed).
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_61903325
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-alertstats-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
SD=/var/lib/pft-alertstats
OUT="${OUT:-$REPO/alertstats/logs/report-7d}"; case "$OUT" in /*) ;; *) OUT="$REPO/$OUT" ;; esac
UPGRADE="${UPGRADE:-0}"
MODE="first install"; [ "$UPGRADE" = 1 ] && MODE=upgrade
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#<redacted-ip>(:9[0-9]{3})#127.0.0.1\1#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-alertstats
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
}
trap 'restore; rm -f "$OPS"' EXIT
srv_state() { # both nodes' server_state, validator first (same exec shape as fwaudit/drill/install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
echo "alertstats $MODE + 7-day report - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum alertstats/pft-alertstats.sh alertstats/alertstats_build.py alertstats/install.sh alertstats/drill/install-run.sh alertstats/systemd/* alerts/alertstats.rules.yml fleet/manifest.tsv"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-alertstats /usr/local/lib/pft-alertstats /etc/systemd/system/pft-alertstats.timer 2>&1"
if [ "$UPGRADE" = 1 ]; then
  check "UPGRADE: installed (bin, lib, timer present)" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
  x "sha256sum alertstats/pft-alertstats.sh alertstats/alertstats_build.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-alertstats /usr/local/lib/pft-alertstats/alertstats_build.py | cut -c1-64"
  check "UPGRADE: installed script/helper differ from HEAD (the sync has something to do)" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 2' | wc -l)" -lt 2 ] && echo 0 || echo 1)"
else
  check "not installed yet" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
fi
x "grep -c '^alertstats ' fleet/manifest.tsv; grep -c alertstats.rules.yml alerts/prometheus.yml; grep -c pft_alertstats rulecheck/pft-rulecheck.conf.example"
check "HEAD lists 4 alertstats manifest lines, the rule file and 2 rulecheck lines" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "4 1 2 " ] && echo 0 || echo 1)"
x "for c in python3 docker jq; do command -v \$c; done | wc -l; sudo -n test -f /etc/pft-rulecheck.conf && echo rc-conf"
check "python3 docker jq and a pft-rulecheck conf on the validator" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "3 rc-conf " ] && echo 0 || echo 1)"
x "sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout 2>/dev/null | wc -c; sudo -n sed -n 's/^TEXT_BUDGET=//p' /etc/pft-jobwatch.env"
JW_V="$(sed -n 1p <<<"$XOUT")"; JW_BUDGET="$(sed -n 2p <<<"$XOUT")"; JW_BUDGET="${JW_BUDGET:-61440}"
check "jobwatch textfile has room for the new timer (validator $JW_V + 1200 <= budget $JW_BUDGET)" "$([ $((JW_V + 1200)) -le "$JW_BUDGET" ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
echo "known pending before the run (accepted by the preflight): ${KNOWN_PENDING:-none}"
UNK="$(sed 1d <<<"$XOUT" | awk '{print $2}' | grep -vx PFTAlertPipelineWatchdog | while read -r a; do case " $KNOWN_PENDING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "no active silence; only the pipeline watchdog (+ KNOWN_PENDING) pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$UNK" = 0 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.state == \"firing\" and .labels.alertname != \"PFTAlertPipelineWatchdog\")] | length'"
check "nothing but the watchdog FIRING (KNOWN_PENDING may only be pending)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (new rule; rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow see new files and timers; not the watchdog)"
ends="$(date -u -d '+50 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK alertstats rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTAlertFlapping|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "alertstats-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (alertstats rule, rulecheck, fleet, aptrust, schedaudit, jobwatch, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"
gate

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && sudo -n install -o root -g root -m 600 /dev/null \$NE && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed (600 root)" "$([ "$XRC" = 0 ] && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
gate
x "sudo -n pft-maint start --ttl 40m --reason '$TASK alertstats install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
gate

echo; echo "== 3. pft-fleet: manifest (fleet add-on), alertstats, then aptrust's allowlist copy"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK alertstats manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
gate
x "sudo -n pft-fleet sync --addon alertstats --to $SHA --apply --reason '$TASK alertstats $SHORT $MODE'"
check "alertstats sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
gate
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust allowlist copy += alertstats rows'"
check "aptrust sync exit 0 (its manifest copy follows the new rows, both hosts)" "$XRC"
gate
x "sha256sum alertstats/pft-alertstats.sh alertstats/alertstats_build.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-alertstats /usr/local/lib/pft-alertstats/alertstats_build.py | cut -c1-64"
check "installed script + helper = repo bytes" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 2' | wc -l)" = 2 ] && echo 0 || echo 1)"
gate

echo; echo "== 4. install.sh (first 7-day report through the sandboxed unit, then the timer)"
x "sudo -n bash alertstats/install.sh"
check "install exit 0, up 1, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'pft_alertstats_up{host="validator"} 1' <<<"$XOUT" && grep -q 'enabled pft-alertstats.timer' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash alertstats/install.sh 2>&1 | grep -E 'added to|ERROR'"
check "second install run adds no rulecheck line and reports no error" "$([ "$(grep -cE 'added to|ERROR' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
gate

echo; echo "== 5. rulecheck inputs (written by install.sh)"
x "sudo -n grep -n pft_alertstats /etc/pft-rulecheck.conf"
check "2 pft_alertstats rulecheck lines" "$([ "$(grep -c pft_alertstats <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 6. load the alert rule (alerts/ is mounted at /etc/pft-alerts) and check it"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 40 && curl -s $PROM/api/v1/status/runtimeinfo | jq -r .data.reloadConfigSuccess && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-alertstats\") | .rules[] | [.name, .health, .state] | @tsv'"
check "config reload ok, 1 alertstats rule loaded, health ok, inactive" "$(grep -qx true <<<"$XOUT" && [ "$(grep -c '	ok	inactive' <<<"$XOUT")" = 1 ] && [ "$(grep -c '^PFTAlertFlapping' <<<"$XOUT")" = 1 ] && echo 0 || echo 1)"

echo; echo "== 7. new unit/timer: pft-schedaudit accept + collect, jobwatch inventory, then pft-integrity accept, both hosts"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160"
x "sudo -n pft-schedaudit accept --reason '$TASK: pft-alertstats timer installed' | tail -2; sudo -n pft-schedaudit collect | tail -1"
x "sudo -n pft-jobwatch inventory 2>&1 | grep -E 'alertstats|SUMMARY' | cut -c1-200"
check "jobwatch learns an 86400 s interval for pft-alertstats.timer" "$([ "$(grep -E 'alertstats' <<<"$XOUT" | grep -cw 86400)" = 1 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "sudo -n pft-integrity accept --reason '$TASK: alertstats $SHORT installed (bin, lib, units, timer, rulecheck.conf, sched items)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "R \"sudo -n pft-integrity accept --reason '$TASK: aptrust allowlist copy += alertstats rows ($SHORT)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit on both hosts: 0 unexpected, 0 new/removed" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 8. VERIFIED: textfile + Prometheus series, aptrust, confinement, skew, rulecheck, timer"
x "sleep 45; curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_alertstats_(up|rules|window_seconds)\"} or sum by (host) (pft_alertstats_flapping)' | jq -r '.data.result[] | \"\(.metric.__name__ // \"sum_flapping\") \(.value[1])\"' | sort"
check "Prometheus: up 1, window 604800 s, rules > 100, flapping sum present" "$(grep -qx 'pft_alertstats_up 1' <<<"$XOUT" && grep -qx 'pft_alertstats_window_seconds 604800' <<<"$XOUT" && awk '$1 == "pft_alertstats_rules" && $2 > 100 {f=1} END {exit !f}' <<<"$XOUT" && grep -q '^sum_flapping ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^RESULT'"
check "aptrust audit on both hosts: 0 warn, 0 fail (new files are in its allowlist copy)" "$([ "$(grep -c ' 0 warn, 0 fail -> exit 0' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust.service; R 'sudo -n systemctl start pft-aptrust.service'; sudo -n systemctl start pft-aptrust-pull.service; grep -hE '^pft_aptrust_checks\{.*result=\"(warn|fail)\"' $TF/pft_aptrust_*.prom"
check "aptrust textfiles (validator + pulled sentry): warn 0, fail 0" "$([ "$(grep -c '} 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'"
check "AppArmor + seccomp audits PASS on the validator with 0 denials (alertstats only reads the bridge's docker logs)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 1 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, alertstats CURRENT, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *validator +alertstats +CURRENT' <<<"$XOUT")" = 1 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "s=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat | grep -E '^RESULT |alertstats'"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-active pft-alertstats.timer; systemctl is-failed pft-alertstats.service; TZ=UTC systemctl show -p TimersCalendar pft-alertstats.timer; systemd-analyze verify /etc/systemd/system/pft-alertstats.service /etc/systemd/system/pft-alertstats.timer 2>&1 | grep pft-alertstats"
check "timer active (daily 05:23 UTC), service not failed, installed units verify clean" "$(grep -qx active <<<"$XOUT" && ! grep -qx failed <<<"$XOUT" && grep -q 'OnCalendar=\*-\*-\* 05:23:00 UTC' <<<"$XOUT" && [ "$(grep -c 'pft-alertstats\.' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*alertstats' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees pft-alertstats.timer: not failed, missed or disabled" "$([ "$(grep -cE 'alertstats.* 0$' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 9. the real 7-day report (the unit's first run): headline numbers re-derived, offline rebuild byte-identical"
x "sudo -n ls $SD/bundles $SD/reports"
B="$(sudo -n ls $SD/bundles | tail -1)"; STAMP="${B#alertstats-}"; STAMP="${STAMP%.json.gz}"
check "one bundle + md/json/csv report from the install run" "$([ -n "$B" ] && [ "$(grep -c "alertstats-$STAMP\." <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
mkdir -p "$OUT"
x "for f in bundles/$B reports/alertstats-$STAMP.md reports/alertstats-$STAMP.json reports/alertstats-$STAMP.csv; do sudo -n cat $SD/\$f > $OUT/\$(basename \$f); done; sha256sum $OUT/*"
x "PFT_RED_NAMES=\"$ME,$HN,$RHN\" python3 -I alertstats/tests/redaction_gate.py $OUT"
check "published bundle + reports pass the redaction gate (no public IP, no topic, no home path, no user/host name)" "$XRC"
J="$OUT/alertstats-$STAMP.json"
x "jq -c '.headline' $J"
x "jq '[.episodes[]] | length' $J; jq '[.episodes[] | select(.kind == \"fired\")] | length' $J; jq '[.episodes[] | select(.kind == \"pending_only\")] | length' $J; jq '[.episodes[] | select(.open)] | length' $J; jq '[.episodes[] | select(.gap_split_before or .gap_split_after)] | length' $J; jq '[.alerts[].flaps] | add' $J; jq '[.alerts[] | select(.flapping)] | length' $J; jq '.alerts | length' $J; jq '[.hygiene[] | select(.severity == \"warn\")] | length' $J; jq '[.hygiene[] | select(.severity == \"info\")] | length' $J; jq '[.prometheus_gaps[].seconds] | add // 0' $J"
H="$(jq -r '.headline | [.episodes, .fired, .pending_only, .open, .gap_split, .flaps, .flapping_alertnames, .active_alertnames, .hygiene_warn, .hygiene_info, .prometheus_gap_s] | map(tostring) | join(" ")' "$J")"
check "every headline number equals its jq re-derivation from the episode/alert/hygiene/gap lists" "$([ "$(tr '\n' ' ' <<<"$XOUT" | sed 's/ $//')" = "$H" ] && echo 0 || echo 1)" "$H"
x "csvc=\$(tail -n +2 $OUT/alertstats-$STAMP.csv | wc -l); echo \"csv rows \$csvc\"; jq '[.episodes[]] | length' $J"
check "CSV has one row per episode" "$([ "$(sed -n 's/^csv rows //p' <<<"$XOUT")" = "$(tail -1 <<<"$XOUT")" ] && echo 0 || echo 1)"
for f in md json csv; do
  x "python3 -I alertstats/alertstats_build.py report --offline $OUT/$B --format $f | cmp - $OUT/alertstats-$STAMP.$f && echo identical"
  check "offline rebuild ($f) from the published bundle is byte-identical to the unit's report" "$XRC"
done
x "python3 -I alertstats/alertstats_build.py report --offline $OUT/$B --format textfile --now \$(sudo -n stat -c %Y $TF/pft_alertstats.prom) | grep -v '^pft_alertstats_last_run' | sha256sum; grep -v '^pft_alertstats_last_run' $TF/pft_alertstats.prom | sha256sum"
check "offline textfile rebuild = live textfile (timestamp line excluded)" "$([ "$(awk '{print $1}' <<<"$XOUT" | sort -u | wc -l)" = 1 ] && echo 0 || echo 1)"
x "sed -n '/^## Headline/,/^## Per alert/p' $OUT/alertstats-$STAMP.md"

echo; echo "== 10. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"AlertFlapping|RuleDead|TextfileStale|Rulecheck|Fleet|Aptrust|Sched|PFTJob|KeyEscrow|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no alertstats/rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow/confinement alert pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l"
check "no transient run-u services/timers" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
