#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host UPGRADE of budget to the current HEAD (task_9fb56f105f2b404c135135b0e6ff456e), through pft-fleet
# inside a pft-maint window. Built from ./install-run.sh (logs/02: 51/52, the one FAIL is the defect fixed here).
# Ships the projection-span fix (8aef64d: no 30/90-day projection unless the runs span PROJ_MIN_SPAN_DAYS): helper +
# README only; units, timers, conf and rules unchanged. Restarts no node; restarts pft-budget-sampler on both hosts
# so the running sampler is the shipped helper too.
#   0. preflight: integrity PASS, nodes full, installed helper != HEAD helper, nothing but the watchdog firing except
#      PFTBudgetCapReached (any unit: the same short-span defect), which must be covered by its defect silence.
#   3. pft-fleet sync budget; bytes = repo on both hosts.  4. sampler restart + collect on both hosts, pull.
#  10. VERIFIED: report verdicts (no FAIL), the collect unit's verdict 0 in Prometheus, PFTBudgetCapReached inactive.
#  11. integrity, skew, timers.  12. restore, read back every operator topic (0 messages).
#   bash budget/drill/upgrade-run.sh 2>&1 | tee LOG    (repo root, agent user; run detached)
#   PREFLIGHT_ONLY=1 bash budget/drill/upgrade-run.sh
# Parameters (defaults = run 05): FROM (installed commit), EXPECT (non-test budget files changed since FROM, sorted,
# space-terminated), DEFECT (createdBy of the defect silence that must be active), ALLOW_RE (the defect's alert line
# that may be pending/firing while suppressed). Run 09 ships a97de5d (sampler ENODEV crash, sentry):
#   FROM=8aef64d EXPECT='budget/budget.py ' DEFECT=budget-sampler-enodev ALLOW_RE='^PFTRuleDead (pending|firing) - (suppressed|none)$'
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_9fb56f10
FROM="${FROM:-835ae15}"; EXPECT="${EXPECT:-budget/README.md budget/budget.py budget/pft-budget.env.example }"
DEFECT="${DEFECT:-budget-fix}"; ALLOW_RE="${ALLOW_RE:-^PFTBudgetCapReached (pending|firing) pft-[a-z0-9@.-]+\.service (suppressed|none)\$}"
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
}
trap 'restore; rm -f "$OPS"' EXIT
srv_state() {
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
# alerts other than the watchdog, with whether AM suppresses them: "NAME STATE UNIT SUPPRESSED"
other_alerts() {
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/alerts")"
  if [ -z "$p" ] || ! jq -e 'type == "object"' <<<"$p" >/dev/null; then echo query-error; return; fi
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts")"
  if [ -z "$a" ] || ! jq -e 'type == "array"' <<<"$a" >/dev/null; then echo query-error; return; fi
  jq -r --argjson am "$a" '.data.alerts[] | select(.labels.alertname != "PFTAlertPipelineWatchdog")
    | .labels.alertname as $n | (.labels.unit // "-") as $u
    | ([$am[] | select(.labels.alertname == $n and (.labels.unit // "-") == $u) | .status.state] | first // "none") as $s
    | "\($n) \(.state) \($u) \($s)"' <<<"$p"
}
echo "budget two-host upgrade - $(date -u +%FT%TZ) - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum budget/budget.py budget/pft-budget.sh budget/drill/upgrade-run.sh | cut -c1-64; sudo -n sha256sum /usr/local/lib/pft-budget/budget.py | cut -c1-64; R 'sha256sum /usr/local/lib/pft-budget/budget.py | cut -c1-64'"
NEW="$(sed -n 1p <<<"$XOUT")"
check "installed helper on both hosts differs from HEAD (upgrade pending)" "$([ "$(grep -cx "$NEW" <<<"$XOUT")" = 1 ] && [ "$(sed -n 4p <<<"$XOUT")" = "$(sed -n 5p <<<"$XOUT")" ] && echo 0 || echo 1)"
x "git diff --stat $FROM $SHA -- budget/systemd budget/pft-budget.sh alerts/budget.rules.yml fleet/manifest.tsv | tail -1; git diff --name-only $FROM $SHA -- budget | grep -vE '^budget/(logs|tests|drill)/' "
check "installed helper = $FROM bytes on both hosts" "$([ "$(git show "$FROM":budget/budget.py | sha256sum | cut -c1-64)" = "$(sudo -n sha256sum /usr/local/lib/pft-budget/budget.py | cut -c1-64)" ] && [ "$(git show "$FROM":budget/budget.py | sha256sum | cut -c1-64)" = "$(R 'sha256sum /usr/local/lib/pft-budget/budget.py' | cut -c1-64)" ] && echo 0 || echo 1)"
check "since the installed commit $FROM only: $EXPECT(no unit/script/rule/manifest change)" "$([ "$(sort <<<"$XOUT" | grep -v '^$' | tr '\n' ' ')" = "$EXPECT" ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "other_alerts; curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"\(.createdBy) \(.endsAt)\"'"
check "alert queries answered" "$(grep -q query-error <<<"$XOUT" && echo 1 || echo 0)"
BAD="$(grep -vE "^(budget-install|$DEFECT) " <<<"$XOUT" | grep -vE "$ALLOW_RE" | grep -c .)"
check "nothing but the watchdog, and the defect's alert ($ALLOW_RE: pending, or firing only while suppressed)" "$([ "$BAD" = 0 ] && echo 0 || echo 1)"
check "the defect silence ($DEFECT) is active" "$(grep -q "^$DEFECT " <<<"$XOUT" && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (fleet/aptrust/jobwatch/keyescrow see a rewritten file + a restarted service; not the watchdog)"
ends="$(date -u -d '+40 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK budget upgrade $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTBudget.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "budget-upgrade", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created until $ends (not the watchdog)" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK budget upgrade'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window after ${w}s" "$?"

echo; echo "== 3. pft-fleet sync budget"
x "sudo -n pft-fleet sync --addon budget --to $SHA --apply --reason '$TASK budget $SHORT projection-span fix'"
check "budget sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum budget/budget.py | cut -c1-64; sudo -n sha256sum /usr/local/lib/pft-budget/budget.py | cut -c1-64; R 'sha256sum /usr/local/lib/pft-budget/budget.py | cut -c1-64'"
check "installed helper = HEAD bytes on both hosts" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping (restore runs)"; exit 1; }
echo; echo "== 4. restart the samplers (load the shipped helper), collect on both hosts, pull the sentry"
x "sudo -n systemctl restart pft-budget-sampler.service && R 'sudo -n systemctl restart pft-budget-sampler.service' && sleep 5 && systemctl is-active pft-budget-sampler.service && R 'systemctl is-active pft-budget-sampler.service'"
check "both samplers restarted and active" "$([ "$XRC" = 0 ] && [ "$(grep -cx active <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-budget-collect.service && R 'sudo -n systemctl start pft-budget-collect.service' && sudo -n systemctl start pft-budget-pull@sentry.service && echo collected"
check "collect on both hosts + pull exit 0" "$XRC"

echo; echo "== 10. VERIFIED: verdicts, Prometheus, alert"
x "sudo -n pft-budget report | grep -E 'pft-budget-|histarchive|RESULT'; R 'sudo -n pft-budget report' | grep -E 'pft-budget-|histarchive|RESULT'"
check "no FAIL verdict on either host; the collect unit no longer projected (span < 3 d)" "$([ "$(grep -c '^RESULT: .* 0 FAIL,' <<<"$XOUT")" = 2 ] && grep -qE '^validator +pft-budget-collect\.service .* - +- .* OK$' <<<"$XOUT" && echo 0 || echo 1)"
x "grep -h '^pft_budget_verdict' $TF/pft_budget_validator.prom $TF/pft_budget_sentry.prom | grep -c ' 2$'; grep -h 'pft_budget_projected_30d_bytes' $TF/pft_budget_validator.prom $TF/pft_budget_sentry.prom | grep -vc '^#'"
check "textfiles: 0 FAIL verdicts, no 30-day projection series yet (all units < 3 days of data)" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 240); do n=\$(other_alerts | grep -c '^PFTBudget'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "PFTBudgetCapReached (and every PFTBudget alert) inactive in Prometheus" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sleep 60; systemctl show -p NRestarts -p ActiveState pft-budget-sampler.service; R 'systemctl show -p NRestarts -p ActiveState pft-budget-sampler.service'"
check "both samplers still active 60 s after the restart, NRestarts=0" "$([ "$(grep -cx 'NRestarts=0' <<<"$XOUT")" = 2 ] && [ "$(grep -cx 'ActiveState=active' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-budget-collect.service && R 'sudo -n systemctl start pft-budget-collect.service' && sudo -n systemctl start pft-budget-pull@sentry.service && R 'sudo -n systemctl start pft-rulecheck.service' && sudo -n systemctl start pft-rulecheck.service pft-rulecheck-pull.service && for i in \$(seq 0 15 300); do n=\$(curl -s $PROM/api/v1/query --data-urlencode 'query=pft_rulecheck_rule_dead{rule=~\"PFTBudget.*\"} == 1' | jq '.data.result | length'); a=\$(other_alerts | grep -c '^PFTRuleDead'); echo \"+\${i}s: dead \$n alert \$a\"; [ \"\$n\$a\" = 00 ] && break; sleep 15; done"
check "rulecheck: no PFTBudget rule dead/partial, PFTRuleDead inactive" "$(tail -1 <<<"$XOUT" | grep -q 'dead 0 alert 0$' && echo 0 || echo 1)"

echo; echo "== 11. integrity, skew, timers"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, budget CURRENT on both hosts" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +budget +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl is-active pft-budget-collect.timer pft-budget-pull@sentry.timer; R 'systemctl is-active pft-budget-collect.timer'; systemctl is-failed pft-budget-sampler.service pft-budget-collect.service; R 'systemctl is-failed pft-budget-sampler.service pft-budget-collect.service'"
# is-failed prints each unit's state (the sampler's "active" too): read the first 3 lines for the timers, then no "failed"
check "timers active, nothing failed" "$([ "$(head -3 <<<"$XOUT" | grep -cx active)" = 3 ] && [ "$(grep -cx failed <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 12. end window, restore, read back"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "other_alerts"
check "nothing but the watchdog pending/firing at the end" "$(grep -q . <<<"$XOUT" && echo 1 || echo 0)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "upgrade-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
