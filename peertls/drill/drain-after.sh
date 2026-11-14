#!/usr/bin/env bash
# shellcheck disable=SC2015  # A && B || C: C (fail closed) is wanted when either fails
# drain-after: finish a fix-run.sh whose drain timed out (an alert with a long fixed window, e.g. PFTHistarchiveIntegrity
# `delta(pft_histarchive_follow_gaps[1h]) > 0` after a validator restart, outlived DRAIN_MAX). Read-only apart from
# expiring the run's own outer silence: wait until nothing but the watchdog is pending/firing in Prometheus, expire
# every active silence created by pft-peertls-fix-run, wait group_interval + 30 s, then count messages on every
# operator topic since SINCE (topics never printed) and list Alertmanager alerts.
#   SINCE=<epoch of the fix-run start> bash peertls/drill/drain-after.sh 2>&1 | tee LOG
# Env: SINCE (required)  WAIT_MAX (70, min)  NTFY (https://ntfy.sh)
set -uo pipefail
export TZ=UTC
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090; NTFY="${NTFY:-https://ntfy.sh}"; WD=PFTAlertPipelineWatchdog
SINCE="${SINCE:?SINCE=<epoch> required}"; WAIT_MAX="${WAIT_MAX:-70}"
ts() { date -u +%FT%TZ; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes relay "$@" </dev/null; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
others() { # Prometheus pending+firing except the watchdog; a failed query prints "query-error" (fail closed)
  local j; j="$(curl -s -m 10 "$PROM/api/v1/alerts")"
  [ -n "$j" ] && jq -e '.data.alerts | type == "array"' <<<"$j" >/dev/null 2>&1 || { echo query-error; return; }
  jq -r --arg w "$WD" '.data.alerts[] | select(.labels.alertname != $w)
    | "\(.labels.alertname) \(.labels.host // "-") \(.state) since \(.activeAt | sub("\\.[0-9]+Z$"; "Z"))"' <<<"$j"
}
echo "drain-after - $(ts) - fix-run start $(date -u -d "@$SINCE" +%FT%TZ) - sha256 $(sha256sum < "$0" | cut -c1-64)"
echo "== silences of the run"
curl -s -m 10 "$AM/api/v2/silences" | jq -r '.[] | select(.status.state == "active") | "  \(.id[0:8]) by \(.createdBy) until \(.endsAt)"'
echo "== wait: nothing but the watchdog in Prometheus (max $WAIT_MAX min)"
deadline=$(( $(date +%s) + WAIT_MAX * 60 )); last=""
while :; do
  o="$(others)"
  [ "$o" = "$last" ] || { echo "  $(ts) active: $(paste -sd';' <<<"${o:-none}")"; last="$o"; }
  [ -n "$o" ] || break
  [ "$(date +%s)" -lt "$deadline" ] || break
  sleep 30
done
check "drained (only the watchdog in Prometheus)" "$([ -z "$o" ] && echo 0 || echo 1)" "$(paste -sd';' <<<"${o:-none}")"
if [ -z "$o" ]; then
  for id in $(curl -s -m 10 "$AM/api/v2/silences" | jq -r '.[] | select(.status.state == "active" and (.createdBy == "pft-peertls-fix-run" or .createdBy == "pft-peertls-fix-guard")) | .id'); do
    curl -s -m 10 -o /dev/null -w "  silence ${id:0:8} expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$id"
  done
  sleep 90
else echo "  silences kept (alerts still active)"; fi
n="$(curl -s -m 10 "$AM/api/v2/silences" | jq '[.[] | select(.status.state == "active")] | length')"
check "no active silence left" "$([ "$n" = 0 ] && echo 0 || echo 1)" "$n"
echo "== operator topics since the fix-run start (not printed)"
OPS="$( { for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f"; done
  for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env"; sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u)"
i=0; OPN=0
for t in $OPS; do
  i=$((i + 1)); c="$(curl -s -m 20 "$NTFY/$t/json?poll=1&since=$SINCE" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i: $c message(s)"; [ "$c" = 0 ] || OPN=$((OPN + 1))
done
check "operator topics received nothing since the fix-run start" "$([ "$OPN" = 0 ] && [ "$i" -gt 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo "== Alertmanager"; curl -s -m 10 "$AM/api/v2/alerts" | jq -r '.[] | "  \(.labels.alertname) \(.status.state)"'
echo "drain-after done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
