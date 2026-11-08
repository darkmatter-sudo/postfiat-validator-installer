#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host UPDATE of the installed pft-apparmor script to the current HEAD through pft-fleet inside a
# pft-maint window. Built from ../../jobwatch/drill/update-run.sh (proven framework). For the 2026-11-08 cron.weekly
# fix (9de2234): pft-apparmor.sh's generator default changed (EXTRA_FILE); the profile itself was reloaded in place
# by reload-run.sh (logs 27-28). Only files pft-fleet tracks are written; nothing is restarted or re-enabled.
# pft-maint's [MAINT] start/end messages go to a throwaway topic; the real target is restored and compared at the end,
# pft-keyescrow is re-run (drift 0), and every operator topic is read back. PFTAppArmorDrift was a REAL alert before
# this run (fixed by the reload), so its [RESOLVED] may reach the operator during the run: such messages are listed
# and counted separately, every other operator message fails the run.
#   bash apparmor/drill/update-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093
ME="$(id -un)"; HN="$(hostname)"
TASK="${TASK:-task_e65845e5}"
TT="pft-drill-aaupd-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-aaupd
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
echo "apparmor two-host update - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight"
x "sha256sum apparmor/pft-apparmor.sh apparmor/profile/pft-postfiatd apparmor/drill/update-run.sh"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the update" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet sync --addon apparmor --to $SHA | grep -E '^PLAN .* (write|keep)$' | awk '{print \$2, \$4, \$6, \$NF}'"
check "dry run: /usr/local/bin/pft-apparmor written on both hosts, nothing else (2 writes)" "$([ "$(grep -c ' write$' <<<"$XOUT")" = 2 ] && [ "$(grep ' write$' <<<"$XOUT" | grep -c '/usr/local/bin/pft-apparmor ')" = 2 ] && echo 0 || echo 1)"
x "sudo -n sha256sum /etc/apparmor.d/pft-postfiatd | cut -c1-64; R 'sha256sum /etc/apparmor.d/pft-postfiatd | cut -c1-64'; sha256sum apparmor/profile/pft-postfiatd | cut -c1-64"
check "installed profile = repo profile on both hosts (reloaded before this run)" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"
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
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK apparmor update $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "apparmor-update", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (PFTRuleDead, PFTTextfileStale, PFTRulecheck*, PFTFleet*) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
[ "$SWAPPED" = 1 ] || { echo "no throwaway target - stopping before the window"; exit 3; }
x "sudo -n pft-maint start --ttl 30m --reason '$TASK apparmor update $SHORT'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: pft-apparmor to HEAD on both hosts (writes + integrity accept by pft-fleet)"
x "sudo -n pft-fleet sync --addon apparmor --to $SHA --apply --reason '$TASK: pft-apparmor generator default EXTRA_FILE += cron.weekly/monthly ($SHORT)'"
check "apparmor sync exit 0" "$XRC"
x "sha256sum apparmor/pft-apparmor.sh | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-apparmor | cut -c1-64; R 'sha256sum /usr/local/bin/pft-apparmor | cut -c1-64'"
check "installed pft-apparmor = repo bytes on both hosts" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && [ "$(wc -l <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 4. behaviour: audit units + pull with the new script"
x "R 'sudo -n systemctl start pft-apparmor.service; systemctl show -p Result --value pft-apparmor.service' && sudo -n systemctl start pft-apparmor.service pft-apparmor-pull.service && for u in pft-apparmor.service pft-apparmor-pull.service; do systemctl show -p Result --value \$u; done"
check "audit (both hosts) + pull: Result success x3" "$([ "$(grep -cx success <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "grep -chE 'status=\"(WARN|FAIL)\"\\} 1' /var/lib/pft-exporter/textfile/pft_apparmor_validator.prom /var/lib/pft-exporter/textfile/pft_apparmor_sentry.prom"
check "both textfiles: 0 WARN/FAIL checks" "$([ "$(awk '{s += $1} END {print s + 0}' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 5. integrity and fleet skew"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E 'apparmor|SUMMARY'"
check "apparmor CURRENT on both hosts" "$([ "$(grep -cE '^ *(validator|sentry) +apparmor +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 6. end window, restore the real target, compare, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' /var/lib/pft-exporter/textfile/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
i=0; OPN=0; OPA=0
while read -r t; do
  i=$((i + 1)); m="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -r 'select(.event == "message") | .title')"
  n="$(grep -c . <<<"$m")"; a="$(grep -c 'AppArmor' <<<"$m")"
  echo "  operator #$i topic: $n message(s), $a about the AppArmor alert this fix cleared"
  [ -z "$m" ] || printf '%s\n' "$m" | red | sed 's/^/    title: /'
  OPA=$((OPA + a)); [ "$((n - a))" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing from this run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s); $OPA message(s) about the real PFTAppArmorDrift (expected [RESOLVED]), $OPN topic(s) with other messages"
x "curl -s http://127.0.0.1:9090/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"AppArmor|RuleDead|TextfileStale|Rulecheck|Fleet\"))] | length'"
curl -s --max-time 10 -o /dev/null -w "  rollout silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
check "no apparmor/rulecheck/fleet alert pending or firing; rollout silence expired" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
echo; echo "update-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
