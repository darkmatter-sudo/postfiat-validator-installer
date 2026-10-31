#!/usr/bin/env bash
# Recorded post-drill state for privesc (task_0ea90375dd468168616469f8689db69a): accept the intended permission
# changes into pft-integrity, pull the sentry file, Prometheus sees 0 findings for both hosts, no privesc alert,
# agent sudo intact, nodes full, rollout silence expired.
#   bash ~/work/scripts/privesc-post-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
echo "privesc post-drill - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $(git rev-parse HEAD)"

echo; echo "== 1. state after the drills: apply manifest present, nothing to fix, agent sudo intact"
x "sudo -n pft-privesc status; R 'sudo -n pft-privesc status'"
x "sudo -n pft-privesc apply --dry-run | tail -2; R 'sudo -n pft-privesc apply --dry-run | tail -2'"
x "sudo -n true && echo validator sudo ok; R 'sudo -n true && echo sentry sudo ok'"
check "agent sudo works on both hosts" "$([ "$(grep -c 'sudo ok' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "dpkg-statoverride --list | sort; R 'dpkg-statoverride --list | sort'"

echo; echo "== 2. integrity: the WARN items are exactly the permission changes apply made; accept them"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//'"
x "sudo -n pft-integrity accept --reason 'task_0ea90375: privesc $SHORT apply (SUID off chfn chsh pkexec fusermount3 ssh-keysign polkit-agent-helper-1 via statoverride, setcap -r gst-ptp-helper)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//'"
x "R \"sudo -n pft-integrity accept --reason 'task_0ea90375: privesc $SHORT apply (SUID off chfn chsh pkexec fusermount3 ssh-keysign polkit-agent-helper-1 via statoverride, setcap -r gst-ptp-helper)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 3. fresh audit through the units, pull, Prometheus"
x "sudo -n systemctl start pft-privesc.service; R 'sudo -n systemctl start pft-privesc.service'; sudo -n systemctl start pft-privesc-pull.service; echo started"
x "sleep 75; curl -s $PROM/api/v1/query --data-urlencode 'query=sum by (host, grade) (pft_privesc_findings)' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.grade) \(.value[1])\"' | sort"
check "Prometheus: 0 fail and 0 warn findings for validator and sentry" "$([ "$(grep -cE '^(validator|sentry) (fail|warn) 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_privesc_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "pft_privesc_up 1 for both hosts" "$([ "$(grep -cE '^(validator|sentry) 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTPrivesc.*|PFTRuleDead|PFTTextfileStale|PFTFleet.*\"}' | jq -r '.data.result | length'"
check "no PFTPrivesc*/PFTRuleDead/PFTTextfileStale/PFTFleet* alert pending or firing" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 4. expire the rollout silence, nodes full"
SIL="$(cat /tmp/pft-privesc-rollout.sil 2>/dev/null)"
x "curl -s --max-time 10 -o /dev/null -w 'HTTP %{http_code}\n' -X DELETE $AM/api/v2/silence/$SIL"
check "rollout silence expired" "$(grep -q 'HTTP 200' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full" "$([ "$(grep -cx '  *full\|full' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo; echo "post-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
