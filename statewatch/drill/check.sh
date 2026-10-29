#!/usr/bin/env bash
# statewatch drill evidence checker: reads Prometheus over a drill window and prints one PASS/FAIL line per
# criterion for a planned postfiatd restart of one container.
#   check.sh --container postfiatd-sentry --since <epoch> [--until <epoch>] [--prom http://127.0.0.1:9090]
# Criteria (window = since..until):
#   C0 series present    pft_statewatch_up has samples for this container in the window (guards C5 against
#                        passing vacuously on a wrong --container)
#   C1 restart seen      resets(pft_statewatch_node_uptime_seconds) >= 1
#   C2 back to full      pft_statewatch_server_state{state="full"} == 1 at --until
#   C3 no full exit      increase(pft_statewatch_full_exits_total) == 0 (reset-safe)
#   C4 collector up      pft_statewatch_up == 1 at --until
#   C5 no state alerts   no ALERTS{alertstate="firing"} for the statewatch rules on this container in the window
# --alerts REGEX replaces the alert-name set (used only by the positive control for C5).
# Exit 0 only if every criterion passes; 1 if any fails; 2 on usage or Prometheus errors.
set -euo pipefail

PROM="http://127.0.0.1:9090"
CONTAINER=""
SINCE=""
UNTIL=""
STATE_ALERTS='PFTStatewatchCollectorFailing|PFTStatewatchStale|PFTNodeBriefFullExit|PFTNodeStateFlapping|PFTJobQueueOverflow|PFTIOLatencyHigh|PFTPeerDisconnectRateHigh'

while [ $# -gt 0 ]; do
  case "$1" in
    --container) CONTAINER="${2:-}"; shift 2 ;;
    --since) SINCE="${2:-}"; shift 2 ;;
    --until) UNTIL="${2:-}"; shift 2 ;;
    --prom) PROM="${2:-}"; shift 2 ;;
    --alerts) STATE_ALERTS="${2:-}"; shift 2 ;;
    *) echo "usage: $0 --container NAME --since EPOCH [--until EPOCH] [--prom URL] [--alerts REGEX]" >&2; exit 2 ;;
  esac
done
if [ -z "$CONTAINER" ] || ! [[ "$SINCE" =~ ^[0-9]+$ ]]; then
  echo "need --container and a numeric --since" >&2; exit 2
fi
[ -n "$UNTIL" ] || UNTIL="$(date -u +%s)"
if ! [[ "$UNTIL" =~ ^[0-9]+$ ]] || [ "$UNTIL" -le "$SINCE" ]; then
  echo "--until must be a number > --since" >&2; exit 2
fi
WIN="$((UNTIL - SINCE))s"
SEL="container=\"$CONTAINER\""

# q QUERY -> prints the single scalar result, "none" for an empty vector; rc 2 on an API error
q() {
  local out
  out="$(curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" --data-urlencode "time=$UNTIL")" \
    || { echo "prometheus request failed: $1" >&2; return 2; }
  [ "$(jq -r '.status' <<<"$out")" = success ] || { echo "prometheus error: $1" >&2; return 2; }
  jq -r 'if (.data.result|length)==0 then "none" else (.data.result|map(.value[1]|tonumber)|add|tostring) end' <<<"$out"
}

FAILED=0
verdict() { # name ok(0/1) detail
  if [ "$2" = 1 ]; then echo "PASS $1: $3"; else echo "FAIL $1: $3"; FAILED=1; fi
}
num_ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a != "none" && a + 0 >= b + 0) }'; }
num_eq() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a != "none" && a + 0 == b + 0) }'; }

echo "statewatch drill check: container=$CONTAINER since=$SINCE until=$UNTIL window=$WIN"

SAMPLES="$(q "count_over_time(pft_statewatch_up{$SEL}[$WIN])")" || exit 2
if num_ge "$SAMPLES" 1; then verdict C0-series-present 1 "up samples=$SAMPLES"; else verdict C0-series-present 0 "up samples=$SAMPLES (no statewatch data for this container)"; fi

v="$(q "resets(pft_statewatch_node_uptime_seconds{$SEL}[$WIN])")" || exit 2
if num_ge "$v" 1; then verdict C1-restart-seen 1 "uptime resets=$v"; else verdict C1-restart-seen 0 "uptime resets=$v (expected >= 1)"; fi

v="$(q "pft_statewatch_server_state{$SEL,state=\"full\"}")" || exit 2
if num_eq "$v" 1; then verdict C2-back-to-full 1 "server_state{full}=$v"; else verdict C2-back-to-full 0 "server_state{full}=$v (expected 1)"; fi

v="$(q "increase(pft_statewatch_full_exits_total{$SEL}[$WIN])")" || exit 2
if num_eq "$v" 0; then verdict C3-no-full-exit 1 "full_exits increase=$v"; else verdict C3-no-full-exit 0 "full_exits increase=$v (expected 0)"; fi

v="$(q "pft_statewatch_up{$SEL}")" || exit 2
if num_eq "$v" 1; then verdict C4-collector-up 1 "up=$v"; else verdict C4-collector-up 0 "up=$v (expected 1)"; fi

v="$(q "count(max_over_time(ALERTS{alertstate=\"firing\",alertname=~\"$STATE_ALERTS\",$SEL}[$WIN]))")" || exit 2
if ! num_ge "$SAMPLES" 1; then verdict C5-no-state-alerts 0 "not judged: no statewatch series (C0)"
elif [ "$v" = none ]; then verdict C5-no-state-alerts 1 "0 statewatch alerts fired"; else verdict C5-no-state-alerts 0 "$v statewatch alert series fired"; fi

if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; exit 0; fi
echo "RESULT: FAIL"; exit 1
