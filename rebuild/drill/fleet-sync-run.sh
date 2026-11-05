#!/usr/bin/env bash
# shellcheck disable=SC2016  # some commands are single-quoted on purpose (expand inside x)
# Recorded pft-fleet sync of ONE validator add-on file set to the repo HEAD inside a pft-maint window
# (task_b225ea764b647efec4fd390933356511). Generic form of backup-sync-run.sh (PASS, log 11) for repo fixes the rebuild
# drill finds in files pft-fleet tracks (first use: fleet's own manifest.tsv after d50e433 added the exporter program).
# Writes only what the dry run plans (must be exactly EXPECT); nothing is restarted. [MAINT] messages go to a throwaway
# topic, the real target is restored and compared, and every operator topic is read back (must be 0).
#   ADDON=fleet EXPECT=manifest.tsv bash rebuild/drill/fleet-sync-run.sh 2>&1 | tee LOG   (repo root, agent user)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_b225ea76
ADDON="${ADDON:?ADDON=name}"; EXPECT="${EXPECT:?EXPECT=basename of the one file the sync must write}"
TT="pft-drill-rebuild-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-rebuild
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
echo "pft-fleet sync --addon $ADDON - $(date -u +%FT%TZ) - $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"') - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight"
x "sha256sum rebuild/drill/fleet-sync-run.sh"
x "sudo -n pft-integrity verify | tail -1"
check "pft-integrity PASS before the update" "$(grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
check "node full or proposing" "$(grep -qxE '(full|proposing)' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E ' $ADDON |SUMMARY'"
check "before: $ADDON BEHIND on the validator" "$(grep -qE "^ *validator +$ADDON +BEHIND" <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-fleet sync --addon $ADDON --to $SHA | grep -E '^PLAN .* (write|keep)$' | awk '{print \$2, \$4, \$6, \$NF}'"
WPATH="$(grep ' write$' <<<"$XOUT" | awk '{print $2}')"
check "dry run: only $EXPECT is written, on the validator only" "$([ "$(grep -c ' write$' <<<"$XOUT")" = 1 ] && grep ' write$' <<<"$XOUT" | grep -q "^validator .*/$EXPECT " && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
  ssh -o LogLevel=ERROR -o BatchMode=yes relay 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }

echo; echo "== 1. rollout silence (pft-fleet/rulecheck see a changed file during the update; not the watchdog)"
ends="$(date -u -d '+30 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK $ADDON sync $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "rebuild-fleet-sync", comment: $c}')"
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
x "sudo -n pft-maint start --ttl 30m --reason '$TASK $ADDON sync $SHORT'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"

echo; echo "== 3. pft-fleet: $ADDON to HEAD on the validator (write + integrity accept by pft-fleet)"
x "sudo -n pft-fleet sync --addon $ADDON --to $SHA --apply --reason '$TASK: $ADDON $EXPECT to $SHORT (rebuild drill finding)'"
check "$ADDON sync exit 0" "$XRC"
SRC="$(awk -v a="$ADDON" -v p="$WPATH" '$1 == a && $3 == p {print $2}' fleet/manifest.tsv)"
x "sha256sum '$SRC' | cut -c1-64; sudo -n sha256sum '$WPATH' | cut -c1-64"
check "installed $WPATH = repo bytes ($SRC)" "$([ -n "$SRC" ] && [ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"

echo; echo "== 5. integrity and fleet skew"
x "sudo -n pft-integrity verify | tail -1"
check "pft-integrity PASS" "$(grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E ' $ADDON |SUMMARY'"
check "$ADDON CURRENT on the validator, fleet BEHIND=0" "$(grep -qE "^ *validator +$ADDON +CURRENT" <<<"$XOUT" && grep -q 'BEHIND=0' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 6. end window, restore the real target, compare, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"RuleDead|TextfileStale|Rulecheck|Fleet\"))] | length'"
check "no rulecheck/fleet alert pending or firing (silence left to run out on its own)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
echo; echo "fleet-sync-run ($ADDON) done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
