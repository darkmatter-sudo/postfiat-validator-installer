#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host UPDATE of selfheal to the current HEAD (task_29073d4c5d752dc0d42b5f9bafe85732) through pft-fleet in a
# pft-maint window, after sentry drill run 13 found the unit could not take pft-maint's lock. Built from install-run.sh
# (PASS, log 09). Nothing is restarted; both hosts stay in MODE=dryrun.
#   0. preflight: installed on both hosts, integrity PASS, nodes full, the unit's guards are WRONG before (locks
#      ["lock state unreadable"] although the host has none: the control for step 4), operator topics, alerts.
#   1. rollout silence (selfheal/fleet/rulecheck/schedaudit/jobwatch/keyescrow, never the watchdog).
#   2. pft-maint window, [MAINT] messages to a throwaway topic.  3. pft-fleet sync --addon selfheal, both hosts.
#   4. install.sh again on both hosts (idempotent: same bytes, conf kept; its new guard check must pass) and the
#      unit's guards are RIGHT after: maint_active false, locks [].  5. integrity/schedaudit/skew/rulecheck/jobwatch.
#   6. restore + read-back (operator topics 0 messages).
#   bash selfheal/drill/update-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash selfheal/drill/update-run.sh
# Active silences are printed, not refused (the previous drill's catch-all may still run out).
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_29073d4c
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-selfheal-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-selfheal
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
  R "rm -rf ~/pft-selfheal-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
echo "selfheal two-host update - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }
guards() { # -> "validator <json>" and "sentry <json>": the maintenance guards the last sandboxed run observed
  echo "validator $(sudo -n jq -c '.observation.guards | {maint_active, locks}' /var/lib/pft-selfheal/last-postfiatd.json)"
  echo "sentry $(R "sudo -n jq -c '.observation.guards | {maint_active, locks}' /var/lib/pft-selfheal/last-postfiatd-sentry.json")"
}

echo; echo "== 0. preflight (read-only)"
x "sha256sum selfheal/pft-selfheal.sh selfheal/selfheal_decide.py selfheal/install.sh selfheal/drill/update-run.sh selfheal/systemd/*"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the update" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl is-active pft-selfheal@postfiatd.timer pft-selfheal-pull@postfiatd-sentry.timer; R 'systemctl is-active pft-selfheal@postfiatd-sentry.timer'; sudo -n grep -c '^MODE=dryrun$' /etc/pft-selfheal.env; R 'sudo -n grep -c ^MODE=dryrun\$ /etc/pft-selfheal.env'"
check "installed: 3 timers active, both confs MODE=dryrun" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "active active active 1 1 " ] && echo 0 || echo 1)"
x "sudo -n pft-maint lock list; R 'sudo -n pft-maint lock list'; sudo -n pft-maint active; echo \"validator active rc \$?\"; R 'sudo -n pft-maint active; echo sentry active rc \$?'"
check "host truth: no lock, no window on either host" "$([ "$(grep -c '^no data-collection locks$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE 'active rc 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "guards"
check "control: before the update the sandboxed unit sees locks [\"lock state unreadable\"] on both hosts (the run-13 bug)" "$([ "$(grep -c '"locks":\["lock state unreadable"\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"active silence until \(.endsAt): \(.comment)\"'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
UNK="$(grep -vE 'active silence' <<<"$XOUT" | awk '{print $2}' | grep -vx PFTAlertPipelineWatchdog | while read -r a; do case " $KNOWN_PENDING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "only the pipeline watchdog (+ KNOWN_PENDING) pending/firing in Prometheus" "$([ "$UNK" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (not the watchdog)"
ends="$(date -u -d '+40 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK selfheal update $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTSelfheal.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "selfheal-update", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK selfheal update'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet sync --addon selfheal"
x "sudo -n pft-fleet sync --addon selfheal --to $SHA --apply --reason '$TASK selfheal $SHORT: unit may take the pft-maint lock'"
check "selfheal sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sudo -n grep -c '/var/lib/pft-maint' /etc/systemd/system/pft-selfheal@.service; R 'grep -c /var/lib/pft-maint /etc/systemd/system/pft-selfheal@.service'"
check "installed unit on both hosts carries /var/lib/pft-maint in ReadWritePaths" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "2 2 " ] && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 4. install.sh again on both hosts (daemon-reload, first decision through the unit, new guard check)"
x "git archive $SHA selfheal | R 'rm -rf ~/pft-selfheal-$SHORT && mkdir -m 700 ~/pft-selfheal-$SHORT && tar -x -C ~/pft-selfheal-$SHORT'"
x "R 'sudo -n bash ~/pft-selfheal-$SHORT/selfheal/install.sh --container postfiatd-sentry'"
check "sentry install exit 0, no conf created, guard line printed, up 1" "$([ "$XRC" = 0 ] && ! grep -q 'created ' <<<"$XOUT" && grep -q 'guards seen by the unit: {"maint_active":true,"locks":\[\]}' <<<"$XOUT" && grep -q 'pft_selfheal_up{container="postfiatd-sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash selfheal/install.sh"
check "validator install exit 0, no conf created, guard line printed, up 1" "$([ "$XRC" = 0 ] && ! grep -q 'created ' <<<"$XOUT" && grep -q 'guards seen by the unit: {"maint_active":true,"locks":\[\]}' <<<"$XOUT" && grep -q 'pft_selfheal_up{container="postfiatd"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "guards"
check "the sandboxed unit now sees the window and no lock on both hosts (maint_active true, locks [])" "$([ "$(grep -c '{"maint_active":true,"locks":\[\]}' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 5. integrity, schedaudit, skew, rulecheck, jobwatch"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -20"
[ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 1 ] || x "sudo -n pft-integrity accept --reason '$TASK: selfheal $SHORT unit update' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -20"
[ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 1 ] || x "R \"sudo -n pft-integrity accept --reason '$TASK: selfheal $SHORT unit update'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit collect >/dev/null; R 'sudo -n pft-schedaudit collect >/dev/null'; sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit on both hosts: 0 unexpected, 0 new/removed" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, selfheal CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +selfheal +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "s=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-active pft-selfheal@postfiatd.timer pft-selfheal-pull@postfiatd-sentry.timer; R 'systemctl is-active pft-selfheal@postfiatd-sentry.timer'; systemctl is-failed pft-selfheal@postfiatd.service pft-selfheal-pull@postfiatd-sentry.service; R 'systemctl is-failed pft-selfheal@postfiatd-sentry.service'"
check "timers active and services not failed on both hosts" "$([ "$(grep -cx active <<<"$XOUT")" = 3 ] && [ "$(grep -cx failed <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts with 0 denials" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 6. end window, restore the real target, keyescrow, read back"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
w=0; until ! R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
x "sleep 75; guards"
check "after the window: the unit sees maint_active false, locks [] on both hosts" "$([ "$(grep -c '{"maint_active":false,"locks":\[\]}' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Selfheal|RuleDead|TextfileStale|Rulecheck|Fleet|Sched|PFTJob|KeyEscrow|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no selfheal/rulecheck/fleet/schedaudit/jobwatch/keyescrow/confinement alert pending or firing" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R 'ls -d ~/pft-selfheal-* 2>/dev/null | wc -l'"
check "no transient run-u services/timers, no update copy left on the sentry" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "update-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
