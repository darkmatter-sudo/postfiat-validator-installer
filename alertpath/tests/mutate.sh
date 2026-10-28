#!/usr/bin/env bash
# Mutation controls for pft-alertpath.sh: each line of mutants.tsv (id, what, exact old text, new text) is applied
# to a temporary copy (the old text must occur exactly once), then tests/test-alertpath.sh runs against it.
# A mutant counts as CAUGHT only if the suite ran to its RESULT line and reported at least one FAIL; the FAIL
# lines are printed so each catch can be checked against what the mutant claims to break.
# A control run of the unmutated script must pass first, or nothing is counted.
# Usage: bash tests/mutate.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../pft-alertpath.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "# pft-alertpath.sh sha256 $(sha256sum < "$SCRIPT" | cut -c1-64)"
echo "# control: unmutated script"
if ! out="$(APB="$SCRIPT" bash "$HERE/test-alertpath.sh" 2>&1)"; then
  printf '%s\n' "$out" | grep -E '^(FAIL|RESULT)'; echo "CONTROL FAILED - no mutant counted"; exit 1
fi
printf '%s\n' "$out" | grep '^RESULT'

caught=0 total=0 notapplied=0
while IFS=$'\t' read -r id what old new; do
  [ -n "$id" ] || continue
  total=$((total + 1))
  m="$WORK/$id.sh"
  if ! python3 -I - "$SCRIPT" "$m" "$old" "$new" <<'PY'
import sys
src, dst, old, new = sys.argv[1:5]
s = open(src).read()
n = s.count(old)
if n != 1:
    print("count=%d" % n)
    sys.exit(1)
open(dst, "w").write(s.replace(old, new))
PY
  then echo "$id NOT APPLIED ($what)"; notapplied=$((notapplied + 1)); continue; fi
  chmod +x "$m"
  out="$(APB="$m" bash "$HERE/test-alertpath.sh" 2>&1)"
  fails="$(printf '%s\n' "$out" | grep -c '^FAIL')"
  if printf '%s\n' "$out" | grep -q '^RESULT' && [ "$fails" -gt 0 ]; then
    caught=$((caught + 1)); echo "$id CAUGHT ($what) by $fails test(s):"
    printf '%s\n' "$out" | grep '^FAIL' | cut -c1-160 | sed 's/^/    /'
  else
    echo "$id SURVIVED ($what)"; printf '%s\n' "$out" | grep '^RESULT' | sed 's/^/    /'
  fi
done < "$HERE/mutants.tsv"
echo "MUTANTS: $caught/$total caught, $notapplied not applied"
[ "$caught" -eq "$total" ]
