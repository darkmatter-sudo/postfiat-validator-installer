#!/usr/bin/env bash
# Mutation check for ../../alerts/dnsaudit.rules.yml: each sed mutant changes one threshold, `for`, aggregation, term
# or the digest label of the rule; `promtool test rules dnsaudit.tests.yml` must FAIL on every mutant (copies in a
# private temp dir; the unmutated rules must pass first).
#   bash dnsaudit/tests/rules-mutants.sh [PROMTOOL...]   (default: promtool from the local prom/prometheus:v3.5.0 image)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A="$HERE/../../alerts"
D="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}")"; trap 'rm -rf "${D:?}"' EXIT
if [ $# -gt 0 ]; then PT=("$@"); else PT=(sudo -n docker run --rm -v "$D:/w" -w /w --entrypoint promtool prom/prometheus:v3.5.0); fi
MUTANTS=(
  's/check_status) >= 2$/check_status) >= 3/'
  's/check_status) >= 2$/check_status) >= 1/'
  's/max by (host) (pft_dnsaudit_check_status)/min by (host) (pft_dnsaudit_check_status)/'
  's/for: 30m/for: 5m/'
  's/for: 30m/for: 60m/'
  's/(pft_dnsaudit_up) == 0$/(pft_dnsaudit_up) == 5/'
  's/^ *or max by (host) (pft_dnsaudit_up) == 0$//'
  's/notify: digest/notify: page/'
)
chmod 755 "$D"   # the promtool container runs as nobody: a 0700 mktemp dir is unreadable
cp "$A/dnsaudit.tests.yml" "$A/dnsaudit.rules.yml" "$D/"; chmod 644 "$D"/*.yml
if ! "${PT[@]}" test rules dnsaudit.tests.yml >/dev/null 2>&1; then echo "unmutated rules fail their tests - stopping"; exit 2; fi
echo "unmutated: SUCCESS"
n=0; k=0
for m in "${MUTANTS[@]}"; do
  n=$((n + 1))
  sed "$m" "$A/dnsaudit.rules.yml" > "$D/dnsaudit.rules.yml"; chmod 644 "$D/dnsaudit.rules.yml"
  if cmp -s "$A/dnsaudit.rules.yml" "$D/dnsaudit.rules.yml"; then echo "NOOP     [$m] (pattern not found)"; continue; fi
  if "${PT[@]}" test rules dnsaudit.tests.yml >/dev/null 2>&1; then echo "SURVIVED [$m]"; else echo "KILLED   [$m]"; k=$((k + 1)); fi
done
echo "RULE MUTANTS: killed $k/$n"
[ "$k" = "$n" ]
