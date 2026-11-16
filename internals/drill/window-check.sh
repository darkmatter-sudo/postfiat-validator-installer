#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016
# window-check: read-only state check inside the 24-hour two-host window, plus the one planned change: expire the
# agent's own defect silence (createdBy internals-defect, alertname=PFTInternalsCounterAnomaly) once the rule is
# inactive and pft_internals_counter_anomalies_total has not increased for 30m on either container.
# SINCE = window start epoch (operator topics are read back from then).
#   SINCE=EPOCH bash internals/drill/window-check.sh 2>&1 | tee LOG
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-internals-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
since="${SINCE:?set SINCE to the install start epoch}"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
trap 'rm -f "$OPS"' EXIT
srv_state() { # both nodes' server_state, validator first (same exec shape as selfheal/install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
tf_check() { # NAME BYTES SAMPLES valid, per textfile on the validator (local + pulled sentry copy)
  local n f
  for n in postfiatd postfiatd-sentry; do
    f="$TF/pft_internals_$n.prom"
    echo "$n $(stat -c %s "$f") $(grep -vc '^#' "$f") $(pft-internals validate "$f" "$n" >/dev/null && echo valid)"
  done
}
prom_check() { # series per container, then up / restarts / anomalies per container
  curl -s "$PROM/api/v1/query" --data-urlencode 'query=count by (container) ({__name__=~"pft_internals_.+"})' \
    | jq -r '.data.result[] | "\(.metric.container) \(.value[1])"' | sort
  curl -s "$PROM/api/v1/query" \
    --data-urlencode 'query={__name__=~"pft_internals_(up|node_restarts_total|counter_anomalies_total)"}' \
    | jq -r '.data.result[] | "\(.metric.container) \(.metric.__name__) \(.value[1])"' | sort
}
echo "internals window check - $(date -u +%FT%TZ) - repo HEAD $SHA - reading back from $(date -u -d @"$since" +%FT%TZ)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
x "pft-internals version; sudo -n pft-internals status; R 'sudo -n pft-internals status --container postfiatd-sentry'"
check "pft-internals status OK on both hosts, 0 restarts, 0 anomalies" "$([ "$(grep -c 'RESULT: OK' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^ +anomalies +0$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "tf_check"
check "both textfiles valid on the validator" "$([ "$(grep -c ' valid$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "prom_check"
check "Prometheus: pft_internals_up 1 for both containers" "$([ "$(grep -c ' pft_internals_up 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=increase(pft_internals_counter_anomalies_total[30m])' | jq -r '.data.result[] | \"\(.metric.container) \(.value[1])\"' | sort"
check "increase(counter_anomalies_total[30m]) is 0 on both containers" "$([ "$(grep -cE ' 0$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[].rules[] | select(.name == \"PFTInternalsCounterAnomaly\") | \"\(.health) \(.state) alerts=\(.alerts | length)\"'"
check "PFTInternalsCounterAnomaly rule ok and inactive" "$([ "$XOUT" = 'ok inactive alerts=0' ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/alerts | jq -r '[.[] | select(.labels.alertname == \"PFTInternalsCounterAnomaly\")] | length'"
check "Alertmanager holds no PFTInternalsCounterAnomaly alert (silenced included)" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"\(.id) \(.createdBy) \(.matchers | map(.name + \"=\" + .value) | join(\",\")) ends \(.endsAt)\"'"
SID="$(curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == "active" and .createdBy == "internals-defect") | .id')"
check "exactly one active internals-defect silence, scoped to alertname=PFTInternalsCounterAnomaly" "$([ "$(wc -w <<<"$SID")" = 1 ] && grep -q 'internals-defect alertname=PFTInternalsCounterAnomaly ends' <<<"$XOUT" && echo 0 || echo 1)"
if [ "$FAILS" = 0 ]; then
  x "curl -s -o /dev/null -w '%{http_code}\n' -X DELETE $AM/api/v2/silence/$SID"
  check "defect silence expired (HTTP 200)" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"
else
  echo "STOP: a gate failed, the defect silence is left in place"
fi
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"\(.createdBy) \(.matchers | map(.name + \"=\" + .value) | join(\",\"))\"'"
x "for i in \$(seq 0 15 90); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | .labels.alertname | select(. != \"PFTAlertPipelineWatchdog\")] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] || break; sleep 15; done; echo \$n"
check "for 90 s after expiry nothing but the watchdog is pending or firing in Prometheus" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/alerts | jq -r '.[] | .labels.alertname' | sort | uniq -c"
check "Alertmanager holds only the watchdog" "$([ "$(awk '{print $2}' <<<"$XOUT" | tr '\n' ' ')" = 'PFTAlertPipelineWatchdog ' ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 60 s (group_interval + 30 s after expiry)"; sleep 60
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing since the window start" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "window-check done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
