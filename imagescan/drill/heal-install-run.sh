#!/usr/bin/env bash
# heal-install-run.sh: two-host install of the imagescan fetch retry/outcomes + pft-imagescan-heal.service and the
# per-fetcher upstreamwatch heal through ../fleet. pft-fleet sync of fleet (its manifest lists
# pft-imagescan-heal.service), aptrust (its allowlist is a copy of that manifest), imagescan and upstreamwatch at TO,
# sentry first, inside ONE pft-maint window whose [MAINT] notices go to a throwaway topic. pft-fleet accepts every
# rewritten file into pft-integrity in the same step. No alert rule changes and no Prometheus reload: no rule reads
# the new series (checked). Then schedaudit/integrity/skew/rulecheck/jobwatch checks, postfiatd container ID and
# StartedAt unchanged on both hosts, and both operator topics (monitor + alert bridge) read back for 0 messages.
# Already-synced files are kept (sync prints "keep"), so a re-run is a read-mostly verification.
# Usage (validator): TO=<sha> bash imagescan/drill/heal-install-run.sh 2>&1 | tee runlog
#        PREFLIGHT_ONLY=1 TO=<sha> ...   dry: pft-fleet sync plans only, no window, nothing written
set -uo pipefail
TO="${TO:?}"; REASON="task_cb7b8dacdef0ebcd45ce6bdf6631708e: imagescan cache-busting fetch + bounded imagescan heal"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-isheal
TT="pft-drill-isheal-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
OPS="$(sudo -n sed -n 's/^NTFY_TOPIC=//p' /etc/postfiat-monitor.env | head -1)"
BRIDGE_URL="$(sed -n 's/^NTFY_URL=//p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null | tr -d '"' | head -1)"
BRT="${BRIDGE_URL##*/}"
since="$(date -u +%s)"; HAD=0; MADE=0; MSTART=0; FAILS=0
red() { sed -E "s#$TT#<throwaway-topic>#g; s#${OPS:-@@none@@}#<redacted>#g; s#${BRT:-@@none@@}#<redacted>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#/home/[a-z0-9_-]+#~#g"; }
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
gate() { if [ "$1" = 0 ]; then echo "GATE PASS $2"; else echo "GATE FAIL $2"; FAILS=$((FAILS + 1)); fi; }
restore() {
  [ "$MSTART" = 1 ] && sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MSTART=0
  if [ "$MADE" = 1 ]; then if [ "$HAD" = 1 ]; then sudo -n mv -f "$BK" "$NE"; else sudo -n rm -f "$NE"; fi; MADE=0
    sudo -n systemctl start pft-keyescrow.service; fi
}
trap restore EXIT
# node_ids -> one line per host: container name, full container ID, StartedAt (docker inspect, read-only)
node_ids() {
  docker inspect -f '{{.Name}} {{.Id}} {{.State.StartedAt}} {{.State.Status}}' postfiatd
  ssh -o BatchMode=yes relay "docker inspect -f '{{.Name}} {{.Id}} {{.State.StartedAt}} {{.State.Status}}' postfiatd-sentry" </dev/null
}
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 3
echo "isheal deploy fleet+aptrust+imagescan+upstreamwatch@$TO - $(date -u +%FT%TZ)$([ "$PREFLIGHT_ONLY" = 1 ] && echo ' (PREFLIGHT_ONLY)')"
x "git cat-file -t $TO && git merge-base --is-ancestor $TO origin/main && echo ancestor-of-origin/main"
gate "$XRC" "TO is a pushed commit"
x "git diff --stat ddc18b9692656c8dde98e7a2cca08bfe80d6520f $TO -- alerts | tail -1; grep -hE '^ *expr:' alerts/*.yml | grep -cE 'pft_imagescan_feed_(fetch_outcome|upstream_timestamp|outcome_timestamp)|pft_upstreamwatch_heal_'"
[ "$(tail -1 <<< "$XOUT")" = 0 ] && ! grep -q 'changed' <<< "$XOUT"; gate $? "no alert rule changed and none reads the new series"
x "sudo -n pft-maint status | head -1"
grep -q 'no maintenance window' <<< "$XOUT" || { echo "a window is open - stopping"; exit 1; }
x "node_ids"
PRE_IDS="$XOUT"
grep -q ' running$' <<< "$PRE_IDS" && [ "$(grep -c ' running$' <<< "$PRE_IDS")" = 2 ]; gate $? "both postfiatd containers running before"
if [ "$PREFLIGHT_ONLY" = 1 ]; then
  for a in fleet aptrust imagescan upstreamwatch; do x "sudo -n pft-fleet sync --addon $a --to $TO"; done
  echo "PREFLIGHT_ONLY: nothing written. RESULT: $FAILS gate(s) failed"; trap - EXIT; exit 0
fi
sudo -n test -e "$NE" && HAD=1
{ [ "$HAD" = 0 ] || sudo -n cp -p "$NE" "$BK"; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$TT" | sudo -n tee "$NE" >/dev/null && sudo -n chmod 600 "$NE" && MADE=1
[ "$MADE" = 1 ] || exit 1
x "sudo -n pft-maint start --ttl 25m --reason 'pft-fleet sync imagescan+upstreamwatch (task_cb7b)'"; [ "$XRC" = 0 ] && MSTART=1 || exit 1
sleep 70
x "ssh -o BatchMode=yes relay 'sudo -n pft-maint active && echo active' </dev/null"
[ "$XOUT" = active ] || { echo "window not on sentry"; exit 1; }
# fleet first: pft-fleet reads its INSTALLED manifest, which must list imagescan/systemd/pft-imagescan-heal.service
for a in fleet aptrust imagescan upstreamwatch; do
  x "sudo -n pft-fleet sync --addon $a --to $TO"
  x "sudo -n pft-fleet sync --addon $a --to $TO --apply --reason '$REASON'"; gate "$XRC" "fleet sync $a both hosts (integrity accepted in the same step)"
done
x "systemctl cat pft-imagescan-heal.service | grep -E '^(ExecStart|InaccessiblePaths|ProtectSystem)='; systemctl show -p LoadState --value pft-imagescan-heal.service; ssh -o BatchMode=yes relay 'systemctl show -p LoadState --value pft-imagescan-heal.service' </dev/null"
[ "$(grep -c '^loaded$' <<< "$XOUT")" = 2 ]; gate $? "heal unit loaded on both hosts"
x "pft-imagescan version; pft-upstreamwatch version; ssh -o BatchMode=yes relay 'pft-imagescan version; pft-upstreamwatch version' </dev/null"
[ "$(grep -cE '^pft-imagescan 1\.1\.0 |^pft-upstreamwatch 1\.2\.0$' <<< "$XOUT")" = 4 ]; gate $? "imagescan 1.1.0 + upstreamwatch 1.2.0 on both hosts"
restore
x "sudo -n pft-schedaudit audit | tail -2; ssh -o BatchMode=yes relay 'sudo -n pft-schedaudit audit | tail -2' </dev/null"
gate "$XRC" "schedaudit clean both hosts (the heal unit has no timer)"
x "sudo -n pft-integrity verify | tail -1; ssh -o BatchMode=yes relay 'sudo -n pft-integrity verify | tail -1' </dev/null"
[ "$(grep -c 'RESULT: PASS' <<< "$XOUT")" = 2 ]; gate $? "integrity PASS both hosts"
x "sudo -n pft-fleet skew | grep -E 'fleet|aptrust|imagescan|upstreamwatch|^RESULT|DIVERGED'; echo skew_rc=\${PIPESTATUS[0]}"
grep -q 'skew_rc=0' <<< "$XOUT"; gate $? "fleet skew rc 0"
x "sudo -n systemctl start pft-rulecheck.service; systemctl is-failed pft-rulecheck.service; grep -E '^pft_rulecheck_(up|problems)' /var/lib/pft-exporter/textfile/pft_rulecheck*.prom | head -4"
x "sudo -n pft-jobwatch collect >/dev/null && sudo -n pft-jobwatch inventory | grep -E 'imagescan|upstreamwatch'"
x "node_ids"
[ "$XOUT" = "$PRE_IDS" ]; gate $? "postfiatd container IDs + StartedAt unchanged on both hosts"
x "curl -s -m 10 http://127.0.0.1:5005 -d '{\"method\":\"server_info\"}' | jq -r .result.info.server_state"
[ "$XOUT" = full ] || [ "$XOUT" = proposing ]; gate $? "validator server_state full"
sleep 20
x "curl -s -m 15 'https://ntfy.sh/$TT/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title'"
x "curl -s -m 15 'https://ntfy.sh/$OPS/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title' | wc -l"
[ "$XOUT" = 0 ]; gate $? "operator monitor topic: 0 messages since the run started"
x "curl -s -m 15 '$BRIDGE_URL/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title' | wc -l"
[ -n "$BRT" ] && [ "$XOUT" = 0 ]; gate $? "operator alert-bridge topic: 0 messages since the run started"
echo "RESULT: $FAILS gate(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
