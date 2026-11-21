#!/usr/bin/env bash
# Sourced by live-run.sh (and run standalone for replays). Natural cross-host lateness, lesson of run 14:
# PFTValwatchHostsDisagreeLate compares one node's p95 delay with the other's at one instant, but the sentry's
# textfile is pulled ~15 s after the validator's, so ONE external validator going late on both nodes can look like
# a disagreement for one or two evals. A PENDING series counts as natural only if, at EVERY one of its evals, that
# validator's p95 was above 3000 ms on BOTH nodes within LB_SKEW_S (60) of the eval. Firing series, missing data or
# a query error or an empty response never count as natural (fails closed; jq 1.6 -e exits 0 on empty input).
#   late_both PROM WINDOW_S END_EPOCH   -> one line per pending series: "validator node evals both_late"
#                                          or "query-error"; exit 0 only if every series is natural (none = 0)
LB_SKEW_S="${LB_SKEW_S:-60}"
lb_ok() { [ -n "$1" ] && jq -e '.status == "success"' >/dev/null 2>&1 <<<"$1"; }   # non-empty Prometheus success
late_both() {
  local prom="$1" win="$2" end="$3" a d vre out
  a="$(curl -s --max-time 20 "$prom/api/v1/query" --data-urlencode "time=$end" \
    --data-urlencode "query=ALERTS{alertname=\"PFTValwatchHostsDisagreeLate\",alertstate=\"pending\"}[${win}s]")"
  lb_ok "$a" || { echo query-error; return 1; }
  vre="$(jq -r '[.data.result[].metric.validator // empty] | unique | join("|")' <<<"$a")"
  [ -n "$vre" ] || return 0
  d="$(curl -s --max-time 20 "$prom/api/v1/query" --data-urlencode "time=$((end + LB_SKEW_S))" \
    --data-urlencode "query=pft_valwatch_validator_delay_p95_ms{validator=~\"$vre\"}[$((win + 2 * LB_SKEW_S))s]")"
  lb_ok "$d" || { echo query-error; return 1; }
  out="$(jq -nr --argjson a "$a" --argjson d "$d" --argjson k "$LB_SKEW_S" '
    $a.data.result[] | .metric.validator as $v | (.metric.node // "-") as $n | [.values[][0] | tonumber] as $ts
    | [$d.data.result[] | select(.metric.validator == $v)] as $s
    | [$ts[] as $t | [$s[] | select(any(.values[]; ((.[0] | tonumber) - $t) as $dt
        | $dt >= -$k and $dt <= $k and (.[1] | tonumber) > 3000)) | .metric.node] | unique | length >= 2]
    | "\($v) \($n) \($ts | length) \(map(select(.)) | length)"')" || { echo query-error; return 1; }
  printf '%s\n' "$out"
  awk '{ if ($3 != $4 || $3 == 0) bad = 1 } END { exit bad }' <<<"$out"
}
if [ "${BASH_SOURCE[0]}" = "$0" ]; then late_both "$@"; fi
