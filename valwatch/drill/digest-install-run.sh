#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded install of the daily other-validators digest (pft-valwatch-digest.service/.timer, validator only) and the
# pft-valwatch script that carries `digest` (both hosts), through pft-fleet inside a pft-maint window. Operator rule
# of 2026-11-19: other validators missing/late never page; they are summed up in at most one low message a day.
#   0. preflight: clean pushed HEAD, integrity PASS, nodes full, Prometheus/AM up, nothing firing but the watchdog
#      and the digest-only PFTValwatchValidatorLow/Late, the only active silence is the interim one (SIL_OK).
#   1. rollout silence (fleet/aptrust/schedaudit/jobwatch/keyescrow/budget/rulecheck; never the watchdog).
#   2. pft-maint window, [MAINT] to a throwaway topic.  3. pft-fleet sync fleet (manifest), valwatch, aptrust.
#   4. install.sh --digest: dry run exit 0, timer enabled for 07:05 UTC, the service has NOT run (nothing sent).
#   5. send drill through the real sandboxed unit with a RUNTIME drop-in (/run, gone after) pointing NTFY_ENV at a
#      throwaway topic and DIGEST_STAMP at a drill stamp: exactly 1 low message; a 2nd start sends nothing (stamp).
#   6. schedaudit accept + collect, jobwatch inventory, integrity accept, both hosts.  7. restore + read-backs.
#   bash valwatch/drill/digest-install-run.sh 2>&1 | tee LOG    (repo root, agent user)
#   PREFLIGHT_ONLY=1 bash valwatch/drill/digest-install-run.sh
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=op-rule-valwatch
SIL_OK="${SIL_OK:-}"
TT="pft-drill-valwatch-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TD="pft-drill-digest-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
U=pft-valwatch-digest
DROP=/run/systemd/system/$U.service.d; DENV=/run/pft-valwatch-drill.env; DSTAMP=/var/lib/pft-valwatch/digest-drill
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#$TD#<throwaway-digest-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-valwatch-digest
SWAPPED=0; MAINT=0; HAD=0; DRILL=0
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
undrill() {
  sudo -n rm -rf "$DROP" "$DENV" "$DSTAMP"; sudo -n systemctl daemon-reload; DRILL=0
}
restore() {
  if [ "$DRILL" = 1 ]; then echo "\$ undrill   (runtime drop-in, drill env + stamp removed, daemon-reload)"; undrill; fi
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap 'restore; rm -f "$OPS"' EXIT
srv_state() {
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
echo "valwatch digest install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum valwatch/pft-valwatch.sh valwatch/install.sh valwatch/systemd/$U.service valwatch/systemd/$U.timer fleet/manifest.tsv | cut -c1-64"
x "grep -c '^valwatch ' fleet/manifest.tsv; grep -cE '^valwatch .*$U\\.(service|timer) .* validator\$' fleet/manifest.tsv"
check "HEAD lists 9 valwatch manifest lines, the 2 digest units role validator" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "9 2 " ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-unit-files --no-legend '$U.*' | wc -l; sudo -n pft-fleet skew | grep -E ' valwatch '"
check "digest units not installed yet" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n grep -cE '^(NTFY_ENV|DIGEST_STAMP)=' /etc/pft-valwatch.env"
check "/etc/pft-valwatch.env sets neither NTFY_ENV nor DIGEST_STAMP (the drill drop-in's values win)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout 2>/dev/null | wc -c; sudo -n sed -n 's/^TEXT_BUDGET=//p' /etc/pft-jobwatch.env"
JW_V="$(sed -n 1p <<<"$XOUT")"; JW_BUDGET="$(sed -n 2p <<<"$XOUT")"; JW_BUDGET="${JW_BUDGET:-61440}"
check "jobwatch validator textfile has room for one more timer ($JW_V + 1200 <= $JW_BUDGET)" "$([ $((JW_V + 1200)) -le "$JW_BUDGET" ] && echo 0 || echo 1)"
x "PROM_URL=$PROM NTFY_ENV=/nonexistent DIGEST_STAMP=/nonexistent bash valwatch/pft-valwatch.sh digest --dry-run"
check "HEAD digest dry run against live Prometheus: exit 0, at least one validator line (today's alerts)" "$([ "$XRC" = 0 ] && grep -qE '^(Low|Late) .* min$' <<<"$XOUT" && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s --max-time 10 $PROM/api/v1/alerts | jq -r .status; curl -s --max-time 10 $AM/api/v2/status | jq -r 'if (.uptime // \"\") != \"\" then \"up\" else \"down\" end'"
check "Prometheus and Alertmanager answer" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "success up " ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | .id[0:8]'"
check "active silences: none, or only the interim one (SIL_OK=${SIL_OK:-none})" "$(grep -vxF "${SIL_OK:-none}" <<<"$XOUT" | grep -q . && echo 1 || echo 0)"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | .labels.alertname as \$n | \"\(\$n) \(.state) \(.labels.notify // \"-\")\"' | sort | uniq -c"
UNK="$(awk '{print $2, $4}' <<<"$XOUT" | grep -vE '^PFTAlertPipelineWatchdog |^PFTValwatchValidator(Low|Late) digest$' | grep -c .)"
check "only the watchdog and digest-only PFTValwatchValidatorLow/Late active" "$([ "$UNK" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (fleet/aptrust/schedaudit/jobwatch/keyescrow/budget/rulecheck see new files and a timer; not the watchdog)"
ends="$(date -u -d '+45 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK digest rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*|PFTBudget.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "valwatch-digest-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence ${SIL:0:8} created until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; else ORIG_SHA=absent; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK valwatch digest install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || { echo "a step failed - stopping before any host change (restore runs)"; exit 1; }

echo; echo "== 3. pft-fleet: manifest (fleet add-on), valwatch, then aptrust's allowlist copy"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK manifest += valwatch digest units'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon valwatch --to $SHA --apply --reason '$TASK valwatch $SHORT digest script + units'"
check "valwatch sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust allowlist copy += digest rows'"
check "aptrust sync exit 0" "$XRC"
x "sha256sum valwatch/pft-valwatch.sh valwatch/systemd/$U.service valwatch/systemd/$U.timer | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-valwatch /etc/systemd/system/$U.service /etc/systemd/system/$U.timer | cut -c1-64; R 'sha256sum /usr/local/bin/pft-valwatch | cut -c1-64; ls /etc/systemd/system/$U.timer 2>&1'"
check "script = repo bytes on both hosts, digest units = repo bytes on the validator, absent on the sentry" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 1 ] && [ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 2' | wc -l)" = 2 ] && grep -q 'No such file' <<<"$XOUT" && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }

echo; echo "== 4. validator: install.sh --digest (dry run, timer only; the service must not run)"
x "sudo -n bash valwatch/install.sh --digest"
check "install exit 0, dry run printed the digest, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'Other validators digest' <<<"$XOUT" && grep -q "enabled $U.timer" <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-enabled $U.timer; systemctl is-active $U.timer; systemctl show -p TimersCalendar -p NextElapseUSecRealtime $U.timer; systemctl show -p ExecMainStartTimestampMonotonic -p NRestarts $U.service; sudo -n test -e /var/lib/pft-valwatch/digest-last && echo stamp || echo no-stamp"
check "timer enabled + active at 07:05 UTC, next run tomorrow, service never started, no stamp written" "$(grep -qx enabled <<<"$XOUT" && grep -qx active <<<"$XOUT" && grep -q 'OnCalendar=\*-\*-\* 07:05:00 UTC' <<<"$XOUT" && grep -q "NextElapseUSecRealtime=.* $(date -u -d tomorrow +%F) 07:05" <<<"$XOUT" && grep -qx 'ExecMainStartTimestampMonotonic=0' <<<"$XOUT" && grep -qx no-stamp <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 5. send drill through the sandboxed unit, runtime drop-in -> throwaway digest topic"
DRILL=1
x "printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TD\" | sudo -n tee \$DENV >/dev/null && sudo -n chmod 600 \$DENV && sudo -n mkdir -p \$DROP && printf '[Service]\nEnvironment=NTFY_ENV=%s DIGEST_STAMP=%s\n' \$DENV \$DSTAMP | sudo -n tee \$DROP/50-drill.conf && sudo -n systemctl daemon-reload && systemctl show -p DropInPaths $U.service"
check "runtime drop-in loaded (under /run only)" "$([ "$XRC" = 0 ] && grep -q "DropInPaths=$DROP/50-drill.conf\$" <<<"$XOUT" && echo 0 || echo 1)"
t0="$(date -u +%s)"
x "sudo -n systemctl start $U.service; systemctl show -p Result -p ExecMainStatus $U.service; sudo -n journalctl -u $U.service --since @$t0 --no-pager -o cat | grep -E '^(digest|pft-valwatch):'"
check "1st start: Result=success, 'digest: sent'" "$(grep -qx 'Result=success' <<<"$XOUT" && grep -q '^digest: sent for ' <<<"$XOUT" && echo 0 || echo 1)"
t1="$(date -u +%s)"
x "sudo -n systemctl start $U.service; systemctl show -p Result $U.service; sudo -n journalctl -u $U.service --since @$t1 --no-pager -o cat | grep -E '^(digest|pft-valwatch):'"
check "2nd start the same day: success, 'already sent' (stamp honoured)" "$(grep -qx 'Result=success' <<<"$XOUT" && grep -q '^digest: already sent for ' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TD/json?poll=1&since=$since\" | jq -r 'select(.event == \"message\") | \"\(.title) | priority \(.priority) | \(.message | split(\"\n\") | length) lines\"'; curl -s --max-time 15 \"https://ntfy.sh/\$TD/json?poll=1&since=$since\" | jq -r 'select(.event == \"message\") | .message' | sed 's/^/    /'"
check "throwaway digest topic got exactly 1 message, priority 2 (low)" "$([ "$(grep -c '^Other validators digest .* | priority 2 |' <<<"$XOUT")" = 1 ] && echo 0 || echo 1)"
x "undrill; systemctl show -p DropInPaths $U.service; sudo -n ls $DROP $DENV $DSTAMP 2>&1 | grep -c 'No such file'"
check "drill drop-in, env and stamp gone, unit back to its installed form" "$(grep -qx 'DropInPaths=' <<<"$XOUT" && grep -qx 3 <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 6. schedaudit accept + collect, jobwatch inventory, pft-integrity accept, both hosts"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|CHANGED|SUMMARY)' | cut -c1-160; R 'sudo -n pft-schedaudit audit' | grep -E '^(NEW|REMOVED|CHANGED|SUMMARY)' | cut -c1-160"
x "sudo -n pft-schedaudit accept --reason '$TASK: $U.timer installed, pft-valwatch $SHORT' | tail -2; sudo -n pft-schedaudit collect | tail -1"
x "R \"sudo -n pft-schedaudit accept --reason '$TASK: pft-valwatch $SHORT (digest subcommand)' | tail -2; sudo -n pft-schedaudit collect | tail -1\""
x "sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit on both hosts: 0 unexpected, 0 new/removed" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit-pull.service; grep -h '^pft_schedaudit_unexpected' $TF/pft_schedaudit_*.prom | grep -vc ' 0$'"
check "schedaudit textfiles: every pft_schedaudit_unexpected series 0" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-jobwatch inventory 2>&1 | grep -E 'valwatch-digest|SUMMARY' | cut -c1-200; sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\\{.*valwatch-digest' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees $U.timer: not failed, missed or disabled; textfile under budget" "$([ "$(grep -cE 'valwatch-digest.* 0$' <<<"$XOUT")" = 3 ] && [ "$(tail -1 <<<"$XOUT")" -le "$JW_BUDGET" ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E 'WARN|FAIL|RESULT' | red | cut -c1-160; R 'sudo -n pft-integrity verify' | grep -E 'WARN|FAIL|RESULT' | cut -c1-160"
x "sudo -n pft-integrity accept --reason '$TASK: valwatch $SHORT digest units + timer, sched state' | tail -2; R \"sudo -n pft-integrity accept --reason '$TASK: valwatch $SHORT digest script, sched state'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after accept" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E ' (valwatch|fleet|aptrust) |^SUMMARY'"
check "fleet skew: valwatch, fleet, aptrust CURRENT on both hosts" "$([ "$(grep -cE ' (valwatch|fleet|aptrust) +CURRENT' <<<"$XOUT")" = "$(grep -cE ' (valwatch|fleet|aptrust) ' <<<"$XOUT")" ] && echo 0 || echo 1)"

echo; echo "== 7. end window, restore the real target, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow after the restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r 'select(.event == \"message\") | .title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Budget|RuleDead|TextfileStale|Rulecheck|Fleet|Aptrust|Sched|PFTJob|KeyEscrow|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no fleet/aptrust/schedaudit/jobwatch/keyescrow/budget/rulecheck/integrity/confinement alert pending or firing" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "digest-install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
