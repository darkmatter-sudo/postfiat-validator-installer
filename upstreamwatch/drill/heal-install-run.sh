#!/usr/bin/env bash
# heal-install-run.sh: two-host install of local_lagging + the bounded heal through ../fleet. pft-fleet sync of fleet
# (its manifest lists pft-vulnscan-heal.service), aptrust (its allowlist is a copy of that manifest), vulnscan and
# upstreamwatch at TO, sentry first, inside ONE pft-maint window whose [MAINT] notices go to a throwaway topic; then
# Prometheus reload (PFTUpstreamFeedLagging loaded), schedaudit/integrity/skew/rulecheck/jobwatch/keyescrow checks,
# postfiatd untouched, and both operator topics (monitor + alert bridge) read back for 0 messages.
# Already-synced files are kept (sync prints "keep"), so a re-run is a read-mostly verification.
# Usage (validator): TO=<sha> bash upstreamwatch/drill/heal-install-run.sh 2>&1 | tee runlog
set -uo pipefail
TO="${TO:?}"; REASON="task_dfa49345fcc602ce6d66553813e99516: local_lagging + bounded vulnscan heal"
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-uwheal
TT="pft-drill-uwheal-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
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
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 3
echo "uwheal deploy vulnscan+upstreamwatch@$TO - $(date -u +%FT%TZ)"
x "git cat-file -t $TO && git merge-base --is-ancestor $TO origin/main && echo ancestor-of-origin/main"
gate "$XRC" "TO is a pushed commit"
x "sudo -n pft-maint status | head -1"
grep -q 'no maintenance window' <<< "$XOUT" || { echo "a window is open - stopping"; exit 1; }
x "for h in local relay; do if [ \$h = local ]; then docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep -E '^postfiatd '; else ssh -o BatchMode=yes relay \"docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep -E '^postfiatd-sentry '\" </dev/null; fi; done"
PRE_PS="$(printf '%s\n' "$XOUT" | sed -E 's/Up [^ ]+ [a-z]+$//')"
sudo -n test -e "$NE" && HAD=1
{ [ "$HAD" = 0 ] || sudo -n cp -p "$NE" "$BK"; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$TT" | sudo -n tee "$NE" >/dev/null && sudo -n chmod 600 "$NE" && MADE=1
[ "$MADE" = 1 ] || exit 1
x "sudo -n pft-maint start --ttl 25m --reason 'pft-fleet sync vulnscan+upstreamwatch (task_dfa49)'"; [ "$XRC" = 0 ] && MSTART=1 || exit 1
sleep 70
x "ssh -o BatchMode=yes relay 'sudo -n pft-maint active && echo active' </dev/null"
[ "$XOUT" = active ] || { echo "window not on sentry"; exit 1; }
# fleet first: pft-fleet reads its INSTALLED manifest, which must list vulnscan/systemd/pft-vulnscan-heal.service
for a in fleet aptrust vulnscan upstreamwatch; do
  x "sudo -n pft-fleet sync --addon $a --to $TO"
  x "sudo -n pft-fleet sync --addon $a --to $TO --apply --reason '$REASON'"; gate "$XRC" "fleet sync $a both hosts"
done
x "systemctl cat pft-vulnscan-heal.service | grep -E '^(ExecStart|ProtectSystem|CacheDirectory)='; ssh -o BatchMode=yes relay 'systemctl show -p LoadState --value pft-vulnscan-heal.service' </dev/null"
gate "$XRC" "heal unit loaded on both hosts"
x "systemctl show -p TimeoutStartUSec --value pft-upstreamwatch.service; ssh -o BatchMode=yes relay 'systemctl show -p TimeoutStartUSec --value pft-upstreamwatch.service' </dev/null"
x "pft-upstreamwatch version; grep -c local_lagging /usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py; ssh -o BatchMode=yes relay 'grep -c local_lagging /usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py; grep -c force-fetch /usr/local/bin/pft-vulnscan' </dev/null"
x "git -C \"$REPO\" status --short -- alerts | wc -l; sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 5 && curl -s -m 10 http://127.0.0.1:9090/api/v1/status/runtimeinfo | jq -r .data.reloadConfigSuccess && curl -s -m 10 http://127.0.0.1:9090/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-upstreamwatch\") | .rules[] | select(.name == \"PFTUpstreamFeedLagging\") | \"\\(.name) for=\\(.duration) notify=\\(.labels.notify)\"'"
grep -q 'PFTUpstreamFeedLagging for=10800 notify=digest' <<< "$XOUT" && grep -q '^true$' <<< "$XOUT"; gate $? "Prometheus reloaded: PFTUpstreamFeedLagging loaded (for 3h, notify digest)"
restore
x "sudo -n pft-schedaudit audit | tail -2; ssh -o BatchMode=yes relay 'sudo -n pft-schedaudit audit | tail -2' </dev/null"
if [ "$XRC" != 0 ]; then
  x "sudo -n pft-schedaudit accept --reason '$REASON' && sudo -n pft-schedaudit collect; ssh -o BatchMode=yes relay \"sudo -n pft-schedaudit accept --reason 'task_dfa49 heal unit' && sudo -n pft-schedaudit collect\" </dev/null"
  x "sudo -n pft-schedaudit audit | tail -1; ssh -o BatchMode=yes relay 'sudo -n pft-schedaudit audit | tail -1' </dev/null"
fi
gate "$XRC" "schedaudit clean both hosts"
x "sudo -n pft-integrity verify | tail -1; ssh -o BatchMode=yes relay 'sudo -n pft-integrity verify | tail -1' </dev/null"
gate "$XRC" "integrity PASS both hosts"
x "sudo -n pft-fleet skew | grep -E 'fleet|aptrust|vulnscan|upstreamwatch|^RESULT|DIVERGED'; echo skew_rc=\${PIPESTATUS[0]}"
grep -q 'skew_rc=0' <<< "$XOUT"; gate $? "fleet skew rc 0"
x "sudo -n systemctl start pft-rulecheck.service; systemctl is-failed pft-rulecheck.service; grep -E '^pft_rulecheck_(up|problems)' /var/lib/pft-exporter/textfile/pft_rulecheck*.prom | head -4"
x "sudo -n pft-jobwatch collect >/dev/null && sudo -n pft-jobwatch inventory | grep -E 'vulnscan|upstreamwatch'; TEXT_BUDGET=999999 sudo -n pft-jobwatch collect --stdout | wc -c"
x "sudo -n pft-keyescrow inventory | tail -1"
x "for h in local relay; do if [ \$h = local ]; then docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep -E '^postfiatd '; else ssh -o BatchMode=yes relay \"docker ps --format '{{.Names}} {{.Image}} {{.Status}}' | grep -E '^postfiatd-sentry '\" </dev/null; fi; done"
[ "$(printf '%s\n' "$XOUT" | sed -E 's/Up [^ ]+ [a-z]+$//')" = "$PRE_PS" ]; gate $? "postfiatd containers unchanged (same name/image, still Up)"
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
