#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host UPGRADE of backfill to the current HEAD through pft-fleet inside a pft-maint window. Built from
# ../../budget/drill/upgrade-run.sh (budget/logs/15 PASS). Ships the tip-race fix (46890ac: a <= TIP_GRACE tail up to
# the validated seq is kind="tip", not interior): parser + status line + README only; units, timers, conf, rules and
# manifest unchanged. Restarts no node and no long-running service (pft-backfill is a oneshot on a timer).
#   0. preflight: clean pushed HEAD, installed parser + script = FROM bytes on both hosts, only EXPECT files changed,
#      integrity PASS, nodes full, nothing but the watchdog (+ KNOWN_RE digest-only, + ALLOW_RE) active.
#   1. rollout silence.  2. pft-maint window with [MAINT] to a throwaway topic.  3. pft-fleet sync backfill.
#   4. status run on both hosts + pull.  5. VERIFIED: the INSTALLED parser on each host classifies both live tip-race
#      captures as tip (nothing planned) and a 3-ledger control tail as interior; status PASS with the tip field on both
#      hosts; Prometheus has the kind="tip" series for both nodes.  11. integrity, skew, timers.
#  12. restore, keyescrow, throwaway read-back, nothing active, silence expired, nodes full, operator topics 0 messages.
#   bash backfill/drill/upgrade-run.sh 2>&1 | tee LOG    (repo root, agent user; run detached)
#   PREFLIGHT_ONLY=1 bash backfill/drill/upgrade-run.sh
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK="${TASK:-task_df1c7e56}"
# FROM: parent of the fix 46890ac (= the installed bytes; 00f3b33 predates the manifest rows)
FROM="${FROM:-943f7f4}"; EXPECT="${EXPECT:-backfill/README.md backfill/backfill_parse.py backfill/pft-backfill.sh }"
KNOWN_RE="${KNOWN_RE:-^PFTValwatchValidator(Low|Late) (pending|firing) - (active|suppressed|none)\$}"
# a tip race seen by the OLD parser right before the sync makes PFTBackfillGap pending (never firing: for 20m)
ALLOW_RE="${ALLOW_RE:-^PFTBackfillGap pending - (active|none)\$}"
TT="pft-drill-backfill-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
LIB=/usr/local/lib/pft-backfill/backfill_parse.py BIN=/usr/local/bin/pft-backfill
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-backfill
SWAPPED=0; MAINT=0; HAD=0; SIL=""
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
PROBE="$(mktemp -p "$HOME/.cache" bf-probe.XXXXXX)"; chmod 644 "$PROBE"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap 'restore; rm -f "$OPS" "$PROBE"' EXIT
srv_state() {
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
# alerts other than the watchdog, with whether AM suppresses them: "NAME STATE UNIT SUPPRESSED"
other_alerts() {
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/alerts")"
  if [ -z "$p" ] || ! jq -e 'type == "object"' <<<"$p" >/dev/null 2>&1; then echo query-error; return; fi
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts")"
  if [ -z "$a" ] || ! jq -e 'type == "array"' <<<"$a" >/dev/null 2>&1; then echo query-error; return; fi
  jq -r --argjson am "$a" '.data.alerts[] | select(.labels.alertname != "PFTAlertPipelineWatchdog")
    | .labels.alertname as $n | (.labels.unit // "-") as $u
    | ([$am[] | select(.labels.alertname == $n and (.labels.unit // "-") == $u) | .status.state] | first // "none") as $s
    | "\($n) \(.state) \($u) \($s)"' <<<"$p"
}
# the probe: the INSTALLED parser on the two live tip-race shapes (journal 2026-11-21T08:15Z, 2026-11-22T05:00Z) and a
# 3-ledger control tail; prints "<validated> <kinds> <missing_interior> <missing_tip> <planned count>" per input
cat > "$PROBE" <<'PROBE_EOF'
set -u
d="$(mktemp -d -p "$HOME/.cache")"; trap 'rm -rf "$d"' EXIT
printf '[node_db]\ntype=NuDB\nonline_delete=512\n' > "$d/cfg"
for c in "8235722-8236315 8236316" "8260298-8260988 8260989" "8260298-8260986 8260989"; do
  set -- $c
  printf '{"result":{"info":{"server_state":"full","complete_ledgers":"%s","validated_ledger":{"seq":%s}}}}\n' "$1" "$2" > "$d/i.json"
  s="$(python3 -I /usr/local/lib/pft-backfill/backfill_parse.py summary --info "$d/i.json" --cfg "$d/cfg")" || { echo "$2 parser-error"; continue; }
  p="$(python3 -I /usr/local/lib/pft-backfill/backfill_parse.py plan --info "$d/i.json" --cfg "$d/cfg" --max-ledgers 16 | grep -c .)"
  echo "$2 $(jq -r '[.gaps[].kind] | join(",")' <<<"$s") $(jq -r '.missing_interior' <<<"$s") $(jq -r '.missing_tip // "absent"' <<<"$s") $p"
done
PROBE_EOF
PEXP="8236316 tip 0 1 0|8260989 tip 0 1 0|8260989 interior 3 0 3|"

echo "backfill two-host upgrade - $(date -u +%FT%TZ) - repo HEAD $SHA (clean: $([ -z "$(git status --short -- backfill alerts fleet)" ] && echo yes || echo NO))"
[ -z "$(git status --short -- backfill alerts fleet)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum backfill/backfill_parse.py backfill/pft-backfill.sh backfill/drill/upgrade-run.sh | cut -c1-64; git show $FROM:backfill/backfill_parse.py | sha256sum | cut -c1-64; git show $FROM:backfill/pft-backfill.sh | sha256sum | cut -c1-64; sudo -n sha256sum $LIB $BIN | cut -c1-64; R 'sha256sum $LIB $BIN | cut -c1-64'"
mapfile -t H <<<"$XOUT"
check "installed parser + script = $FROM bytes on both hosts, != HEAD (upgrade pending)" "$([ "${#H[@]}" = 9 ] && [ "${H[3]}${H[4]}" = "${H[5]}${H[6]}" ] && [ "${H[3]}${H[4]}" = "${H[7]}${H[8]}" ] && [ "${H[0]}" != "${H[3]}" ] && [ "${H[1]}" != "${H[4]}" ] && echo 0 || echo 1)"
x "git diff --stat $FROM $SHA -- backfill/systemd alerts/backfill.rules.yml backfill/pft-backfill.env.example backfill/install.sh | tail -1; git diff -U0 $FROM $SHA -- fleet/manifest.tsv | grep -E '^[+-]backfill[[:space:]]'; git diff --name-only $FROM $SHA -- backfill | grep -vE '^backfill/(logs|tests|drill)/'"
check "since the installed commit $FROM only: $EXPECT(no unit/rule/conf/manifest change)" "$([ "$(sort <<<"$XOUT" | grep -v '^$' | tr '\n' ' ')" = "$EXPECT" ] && echo 0 || echo 1)"
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
x "other_alerts; curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"silence \(.createdBy) \(.endsAt)\"'"
check "alert queries answered" "$(grep -q query-error <<<"$XOUT" && echo 1 || echo 0)"
BAD="$(grep -vE "$KNOWN_RE" <<<"$XOUT" | grep -vE "$ALLOW_RE" | grep -c .)"
check "nothing but the watchdog, digest-only valwatch ($KNOWN_RE) and $ALLOW_RE active; no active silence" "$([ "$BAD" = 0 ] && echo 0 || echo 1)"
x "R 'bash -s' < '$PROBE'"
check "control: the INSTALLED (old) parser on the sentry still reads both live tip races as interior" "$([ "$(head -2 <<<"$XOUT" | awk '$2 == "interior" && $3 == 1 && $4 == "absent" && $5 == 1' | wc -l)" = 2 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (fleet/aptrust/jobwatch/keyescrow see rewritten files; not the watchdog)"
ends="$(date -u -d '+30 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK backfill upgrade $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTBackfill.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "backfill-upgrade", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created until $ends (not the watchdog)" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK backfill upgrade'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window after ${w}s" "$?"
[ "$FAILS" = 0 ] || { echo "a step failed - stopping (restore runs)"; exit 1; }

echo; echo "== 3. pft-fleet sync backfill"
x "sudo -n pft-fleet sync --addon backfill --to $SHA --apply --reason '$TASK backfill $SHORT tip-race classification'"
check "backfill sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum backfill/backfill_parse.py backfill/pft-backfill.sh | cut -c1-64; sudo -n sha256sum $LIB $BIN | cut -c1-64; R 'sha256sum $LIB $BIN | cut -c1-64'"
mapfile -t H <<<"$XOUT"
check "installed parser + script = HEAD bytes on both hosts" "$([ "${#H[@]}" = 6 ] && [ "${H[0]}${H[1]}" = "${H[2]}${H[3]}" ] && [ "${H[0]}${H[1]}" = "${H[4]}${H[5]}" ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "a step failed - stopping (restore runs)"; exit 1; }

echo; echo "== 4. status run on both hosts (timer's own unit), pull the sentry copy"
x "R 'sudo -n systemctl start pft-backfill.service' && sudo -n systemctl start pft-backfill.service && sudo -n systemctl start pft-backfill-pull.service && grep -h 'kind=\"tip\"' $TF/pft_backfill.prom $TF/pft_backfill_sentry.prom"
check "both status units + pull exit 0; tip series in the validator's and the pulled sentry textfile (4 lines)" "$([ "$XRC" = 0 ] && [ "$(grep -c 'kind="tip"' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"

echo; echo "== 5. VERIFIED: installed parser on both hosts, status, Prometheus"
x "bash '$PROBE'; R 'bash -s' < '$PROBE'"
check "installed parser on BOTH hosts: both live tip races = tip (0 interior, 1 tip, 0 planned); 3-ledger tail = interior 3, planned 3" "$([ "$(tr '\n' '|' <<<"$XOUT")" = "$PEXP$PEXP" ] && echo 0 || echo 1)"
x "sudo -n pft-backfill status | grep -E 'missing|RESULT'; R 'sudo -n pft-backfill status' | grep -E 'missing|RESULT'"
check "pft-backfill status on both hosts: the missing line carries the tip field" "$([ "$(grep -cE '^ +missing +interior [0-9]+, edge [0-9]+, tip [0-9]+$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 180); do n=\$(curl -s $PROM/api/v1/query --data-urlencode 'query=pft_backfill_missing_ledgers{kind=\"tip\"}' | jq -r '[.data.result[].metric.node] | sort | join(\",\")'); echo \"+\${i}s: \$n\"; [ \"\$n\" = sentry,validator ] && break; sleep 15; done"
check "Prometheus scraped pft_backfill_missing_ledgers{kind=\"tip\"} for both nodes" "$(tail -1 <<<"$XOUT" | grep -q ': sentry,validator$' && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-rulecheck.service' && sudo -n systemctl start pft-rulecheck.service pft-rulecheck-pull.service && for i in \$(seq 0 15 300); do n=\$(curl -s $PROM/api/v1/query --data-urlencode 'query=pft_rulecheck_rule_dead{rule=~\"PFTBackfill.*\"} == 1' | jq '.data.result | length'); a=\$(other_alerts | grep -c '^PFTRuleDead'); echo \"+\${i}s: dead \$n alert \$a\"; [ \"\$n\$a\" = 00 ] && break; sleep 15; done"
check "rulecheck: no PFTBackfill rule dead, PFTRuleDead inactive" "$(tail -1 <<<"$XOUT" | grep -q 'dead 0 alert 0$' && echo 0 || echo 1)"

echo; echo "== 11. integrity, skew, timers"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, backfill CURRENT on both hosts" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +backfill +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl is-active pft-backfill.timer pft-backfill-pull.timer; R 'systemctl is-active pft-backfill.timer'; systemctl is-failed pft-backfill.service pft-backfill-pull.service; R 'systemctl is-failed pft-backfill.service'"
check "timers active, nothing failed" "$([ "$(head -3 <<<"$XOUT" | grep -cx active)" = 3 ] && [ "$(grep -cx failed <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 12. end window, restore, read back"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 300); do n=\$(other_alerts | grep -vE \"\$KNOWN_RE\" | grep -c .); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; other_alerts"
check "nothing but the watchdog (and KNOWN_RE digest-only alerts) pending/firing at the end" "$(grep -E '^[A-Z]' <<<"$XOUT" | grep -qvE "$KNOWN_RE" && echo 1 || echo 0)"
x "curl -s --max-time 10 -X DELETE $AM/api/v2/silence/$SIL -o /dev/null -w '%{http_code}\n'"
check "rollout silence expired" "$(grep -qx 200 <<<"$XOUT" && echo 0 || echo 1)"
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
