#!/usr/bin/env bash
# promtool check + unit tests for alerts/timesync.rules.yml, then rule mutants that timesync.tests.yml must catch.
#   bash timesync/tests/check-rules.sh        (needs docker + prom/prometheus:v3.5.0; DOCKER="sudo docker" if needed)
# shellcheck disable=SC2016  # the sed expressions are meant literally
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A="$(cd "$HERE/../../alerts" && pwd)"
read -r -a DOCKER <<< "${DOCKER:-docker}"
IMG="${PROM_IMAGE:-prom/prometheus:v3.5.0}"
W="$(mktemp -d)"; trap 'rm -rf "${W:?}"' EXIT
promtool() { "${DOCKER[@]}" run --rm -v "$1:/w:ro" -w /w --entrypoint promtool "$IMG" "${@:2}"; }

echo "== real rules"
promtool "$A" check rules timesync.rules.yml || exit 1
promtool "$A" test rules timesync.tests.yml || exit 1
caught=0; n=0
mutant() { # ID DESCRIPTION SED-EXPR
  local id="$1" d="$W/$1"; n=$((n + 1)); mkdir -p "$d"
  cp "$A/timesync.tests.yml" "$d/"; sed "$3" "$A/timesync.rules.yml" > "$d/timesync.rules.yml"
  if cmp -s "$A/timesync.rules.yml" "$d/timesync.rules.yml"; then echo "$id NOT APPLIED: $2"; return; fi
  if promtool "$d" test rules timesync.tests.yml > "$d/out" 2>&1; then echo "$id SURVIVED: $2"
  elif grep -q 'FAILED:' "$d/out"; then caught=$((caught + 1))
    echo "$id CAUGHT: $2 -> $(grep -c 'alertname:' "$d/out") failing eval(s), first: $(grep -m1 'alertname:' "$d/out" | sed 's/^ *//')"
  else echo "$id ERROR (promtool did not run the tests): $2"; sed 's/^/    /' "$d/out" | head -5; fi
}
mutant R1 "offset threshold 0.05 -> 0.1 (80 ms missed)" 's/abs(pft_timesync_offset_seconds) > 0.05/abs(pft_timesync_offset_seconds) > 0.1/'
mutant R2 "offset without abs() (slow clock never alerts)" 's/expr: abs(pft_timesync_offset_seconds) > 0.05/expr: pft_timesync_offset_seconds > 0.05/'
mutant R3 "NTS threshold < 4 -> < 3" 's/pft_timesync_nts_sources < 4/pft_timesync_nts_sources < 3/'
mutant R4 "audit alert fires on WARN too" 's/pft_timesync_state == 2/pft_timesync_state >= 1/'
mutant R5 "unsynced for: 5m -> 0m" '/alert: PFTClockNotSynchronised/,/for:/ s/for: 5m/for: 0m/'
mutant R6 "staleness 300 -> 900" 's/pft_timesync_collect_timestamp_seconds > 300/pft_timesync_collect_timestamp_seconds > 900/'
mutant R7 "offset for: 10m -> 30m" '/alert: PFTClockOffsetHigh/,/for:/ s/for: 10m/for: 30m/'
mutant R8 "synced alert inverted" 's/expr: pft_timesync_synced == 0/expr: pft_timesync_synced == 1/'
mutant R9 "summary drops the host (sentry alert reads as the validator)" '/alert: PFTTimesyncStale/,/summary:/ s/{{ or $labels.host \\"validator\\" }}/validator/'
echo "RULE MUTANTS: $caught/$n caught"
[ "$caught" = "$n" ]
