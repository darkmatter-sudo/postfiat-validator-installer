#!/usr/bin/env bash
# Mutation controls for drill/check-drill.sh: each mutant weakens one check, and test-check-drill.sh must FAIL on it.
# sed programs are single-quoted on purpose (\$ and $ are sed, not shell).
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../drill/check-drill.sh"
MUTANTS=(
  'C1 validator StartedAt check always true|s/ck "validator StartedAt unchanged" .*/ck "validator StartedAt unchanged" true/'
  'C2 alert topic check always true|s/ck "throwaway alert topic received nothing" .*/ck "throwaway alert topic received nothing" true/'
  'C3 validator audit-event check always true|s/ck "validator: no audit event" .*/ck "validator: no audit event" true/'
  'C4 exit code ignored (badimage)|s/ck "exit code 1" .*/ck "exit code 1" true/'
  'C5 no-op target check always true|s/ck "\$h target == recorded prev (no-op)" .*/ck "$h target == recorded prev (no-op)" true/'
  'C6 run id filter dropped|s/select(.run == \$r)/select(true)/'
  'C7 sentry final image check always true|s/ck "sentry ends on recorded image" .*/ck "sentry ends on recorded image" true/'
  'C8 RESULT always PASS|s/^echo "RESULT: FAIL (\$P\/\$N)"; exit 1$/echo "RESULT: PASS ($P\/$N)"; exit 0/'
)
MC=0
for m in "${MUTANTS[@]}"; do
  name="${m%%|*}"; expr="${m#*|}"
  mf="$(mktemp --suffix=.sh)"; sed "$expr" "$SRC" > "$mf"
  if cmp -s "$mf" "$SRC"; then echo "MUTANT $name: sed changed nothing - INVALID"; MC=$((MC + 1)); rm -f "$mf"; continue; fi
  out="$(CHECK="$mf" bash "$HERE/test-check-drill.sh" 2>&1)"; rc=$?
  rm -f "$mf"
  if [ "$rc" -ne 0 ]; then echo "MUTANT $name: CAUGHT by $(grep -c '^FAIL ' <<<"$out") test(s): $(grep '^FAIL ' <<<"$out" | sed 's/^FAIL //; s/ (rc=.*//' | paste -sd ';')"
  else echo "MUTANT $name: NOT CAUGHT"; MC=$((MC + 1)); fi
done
echo "mutants not caught/invalid: $MC"
[ "$MC" -eq 0 ]
