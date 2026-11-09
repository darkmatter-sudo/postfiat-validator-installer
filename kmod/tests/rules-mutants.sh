#!/usr/bin/env bash
# Mutation check for ../../alerts/kmod.rules.yml: each sed mutant changes one threshold, `for` or term of a rule;
# `promtool test rules kmod.tests.yml` must FAIL on every mutant (copies in a private temp dir).
#   bash kmod/tests/rules-mutants.sh [PROMTOOL...]   (default: promtool from the prom/prometheus:v3.5.0 image via docker)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A="$HERE/../../alerts"
D="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}")"; trap 'rm -rf "${D:?}"' EXIT
if [ $# -gt 0 ]; then PT=("$@"); else PT=(sudo -n docker run --rm -v "$D:/w" -w /w --entrypoint promtool prom/prometheus:v3.5.0); fi
MUTANTS=(
  's/> 0$/> 100/'
  's/for: 15m/for: 1m/'
  's/for: 10m/for: 30m/'
  's/> 3 \* 3600/> 6 * 3600/'
  's/loaded|loadable/loadable/'
  's/ + on (host) max by (host) (pft_kmod_required_blocked)//'
  's/ + on (host) (1 - max by (host) (pft_kmod_autoload_ok))//'
  's/max by (host) (pft_kmod_up) == 0/max by (host) (pft_kmod_up) == 5/'
)
chmod 755 "$D"   # the promtool container runs as nobody: a 0700 mktemp dir is unreadable (every run would "fail")
cp "$A/kmod.tests.yml" "$D/"
cp "$A/kmod.rules.yml" "$D/"; chmod 644 "$D"/*.yml
if ! "${PT[@]}" test rules kmod.tests.yml >/dev/null 2>&1; then echo "unmutated rules fail their tests - stopping"; exit 2; fi
echo "unmutated: SUCCESS"
n=0; k=0
for m in "${MUTANTS[@]}"; do
  n=$((n + 1))
  sed "$m" "$A/kmod.rules.yml" > "$D/kmod.rules.yml"; chmod 644 "$D/kmod.rules.yml"
  if cmp -s "$A/kmod.rules.yml" "$D/kmod.rules.yml"; then echo "NOOP     [$m] (pattern not found)"; continue; fi
  if "${PT[@]}" test rules kmod.tests.yml >/dev/null 2>&1; then echo "SURVIVED [$m]"; else echo "KILLED   [$m]"; k=$((k + 1)); fi
done
echo "RULE MUTANTS: killed $k/$n"
[ "$k" = "$n" ]
