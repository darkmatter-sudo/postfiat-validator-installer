#!/usr/bin/env bash
# promtool check + unit tests for alerts/resources.rules.yml, then rule mutants that resources.tests.yml must catch.
#   bash resources/tests/check-rules.sh        (needs docker + prom/prometheus:v3.5.0; DOCKER="sudo docker" if needed)
# shellcheck disable=SC2016  # the sed expressions are meant literally
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A="$(cd "$HERE/../../alerts" && pwd)"
read -r -a DOCKER <<< "${DOCKER:-docker}"
IMG="${PROM_IMAGE:-prom/prometheus:v3.5.0}"
W="$(mktemp -d)"; trap 'rm -rf "${W:?}"' EXIT
promtool() { "${DOCKER[@]}" run --rm -v "$1:/w:ro" -w /w --entrypoint promtool "$IMG" "${@:2}"; }

echo "== real rules"
promtool "$A" check rules resources.rules.yml || exit 1
promtool "$A" test rules resources.tests.yml || exit 1
caught=0; n=0
mutant() { # ID DESCRIPTION SED-EXPR
  local id="$1" d="$W/$1"; n=$((n + 1)); mkdir -p "$d"
  cp "$A/resources.tests.yml" "$d/"; sed "$3" "$A/resources.rules.yml" > "$d/resources.rules.yml"
  if cmp -s "$A/resources.rules.yml" "$d/resources.rules.yml"; then echo "$id NOT APPLIED: $2"; return; fi
  if promtool "$d" test rules resources.tests.yml > "$d/out" 2>&1; then echo "$id SURVIVED: $2"
  elif grep -q 'FAILED:' "$d/out"; then caught=$((caught + 1))
    echo "$id CAUGHT: $2 -> $(grep -c 'alertname:' "$d/out") failing eval(s), first: $(grep -m1 'alertname:' "$d/out" | sed 's/^ *//')"
  else echo "$id ERROR (promtool did not run the tests): $2"; sed 's/^/    /' "$d/out" | head -5; fi
}
mutant R1 "memory threshold 0.90 -> 0.99" 's/pft_resources_memory_max_bytes > 0.90/pft_resources_memory_max_bytes > 0.99/'
mutant R2 "memory alert ignores up (blind collector still alerts)" 's/ > 0.90 and pft_resources_up == 1/ > 0.90/'
mutant R3 "OOM alert without the docker OOMKilled branch" '/or max by (instance, job, container) (pft_resources_container_oom_killed == 1/d'
mutant R4 "OOM alert window 10m -> 1m (kill missed between scrapes)" 's/event="oom_kill"}\[10m\]/event="oom_kill"}[1m]/'
mutant R5 "fd alert guard on the left again (\$value = the limit)" 's/expr: pft_resources_fd_open \/ pft_resources_fd_limit_soft > 0.80 and pft_resources_fd_limit_soft > 0/expr: pft_resources_fd_limit_soft > 0 and pft_resources_fd_open \/ pft_resources_fd_limit_soft > 0.80/'
mutant R6 "fd alert without the unlimited-limit guard" 's/ > 0.80 and pft_resources_fd_limit_soft > 0/ > 0.80/'
mutant R7 "pids for: 5m -> 0m" '/alert: PFTPidsNearLimit/,/for:/ s/for: 5m/for: 0m/'
mutant R8 "staleness threshold 300 -> 900" 's/pft_resources_collect_timestamp_seconds > 300/pft_resources_collect_timestamp_seconds > 900/'
mutant R9 "throttling threshold 0.25 -> 0.60 (50% case missed)" 's/rate(pft_resources_cpu_periods_total\[10m\]) > 0.25/rate(pft_resources_cpu_periods_total[10m]) > 0.60/'
mutant R10 "growth alert without the 50% floor" '/and pft_resources_memory_current_bytes \/ pft_resources_memory_max_bytes > 0.50/d'
mutant R11 "memory PSI uses kind full too (any kind)" 's/{resource="memory", kind="some"}/{resource="memory"}/'
mutant R12 "collector-failing for: 5m -> 1m" '/alert: PFTResourcesCollectorFailing/,/for:/ s/for: 5m/for: 1m/'
mutant R13 "docker OOMKilled branch without the change check (stays firing forever)" 's/(pft_resources_container_oom_killed == 1 and changes(pft_resources_container_oom_killed\[10m\]) > 0)/(pft_resources_container_oom_killed) == 1/'
echo "RULE MUTANTS: $caught/$n caught"
[ "$caught" = "$n" ]
