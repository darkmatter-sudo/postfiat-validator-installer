#!/usr/bin/env bash
# Mutation check for pft-resources.sh: every mutant must make tests/run-tests.sh FAIL (CAUGHT); the real script must pass.
#   bash resources/tests/check.sh
# Prints the sed edit of each mutant, proves the edit changed the file, and "MUTANTS: N/M caught".
# shellcheck disable=SC2016  # the sed expressions are meant literally
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../pft-resources.sh"
W="$(mktemp -d)"; trap 'rm -rf "${W:?}"' EXIT
caught=0; n=0

echo "== baseline: real script"
if bash "$HERE/run-tests.sh" "$S" > "$W/base.out" 2>&1; then tail -1 "$W/base.out"; else
  grep '^FAIL' "$W/base.out"; echo "baseline FAILED - mutants meaningless"; exit 1; fi

mutant() { # ID DESCRIPTION SED-EXPR
  local id="$1" desc="$2" expr="$3" m="$W/$1.sh" res
  n=$((n + 1))
  sed "$expr" "$S" > "$m"
  if cmp -s "$S" "$m"; then echo "$id NOT APPLIED (sed matched nothing): $desc"; return; fi
  # CAUGHT needs a finished suite (RESULT line) with at least one FAIL; an aborted suite is an ERROR, not a catch
  if bash "$HERE/run-tests.sh" "$m" > "$W/$id.out" 2>&1; then res="SURVIVED"
  elif grep -q '^RESULT: ' "$W/$id.out" && grep -q '^FAIL' "$W/$id.out"; then res="CAUGHT"; caught=$((caught + 1))
  else res="ERROR (suite aborted without a FAIL line)"; fi
  printf '%s %s: %s (%s)\n' "$id" "$res" "$desc" "$(grep -c '^FAIL' "$W/$id.out") failing assertions"
  grep '^FAIL' "$W/$id.out" | head -3 | sed 's/^/    /'
}

mutant M1 "readers call fail() inside the \$(...) subshell again (build-1 bug: malformed file -> up 1)" \
  's/{ printf .%s. \("[^"]*"\); return 1; }/{ fail \1; return 1; }/; s/then printf .%s. "cannot read $1"; return 1; fi/then fail "cannot read $1"; return 1; fi/'
mutant M2 "collection error does not set up 0" 's/\[ "\$FAILED" = 0 \] || up=0/true/'
mutant M3 "render keeps the metric lines when up is 0 (stale values)" 's/\[ "\$up" = 1 \] || return 0/true/'
mutant M4 "memory.max = max not mapped to MemTotal" 's/if \[ "\$max" = max \]; then/if [ "$max" = nomatch ]; then/'
mutant M5 "missing PSI file treated as an error" 's/if \[ "\$rc" = 2 \]; then/if [ "$rc" = 9 ]; then/'
mutant M6 "fd count includes the fd dir itself" 's/-mindepth 1 -maxdepth 1/-mindepth 0 -maxdepth 1/'
mutant M7 "docker OOMKilled ignored" 's/\[ "\$oomk" = true \] \&\& echo 1 || echo 0/echo 0/'
mutant M8 "history appended on failed runs too" 's/if \[ "\$up" = 1 \] \&\& \[ -n "\$HISTORY" \]; then/if [ -n "$HISTORY" ]; then/'
mutant M9 "PSI percent not converted to a ratio" 's#x / 100#x / 1#g'
mutant M10 "metric families not grouped (duplicate TYPE lines)" 's/if (!(n in seen)) { seen\[n\] = ++k; names\[k\] = n }/seen[n] = ++k; names[k] = n/'
mutant M11 "cgroup path taken from the first /proc line of any hierarchy (v1 accepted)" "s/\$1 == \"0\" \&\& \$2 == \"\"/1/"
mutant M12 "fds of the first process in cgroup.procs instead of PROC_NAME" 's/= "\$PROC_NAME" \] \&\& { main="\$p"; break; }/!= x ] \&\& { main="$p"; break; }/'
mutant M13 "pids.max = max not mapped to kernel.pid_max" 's/if \[ "\$pmax" = max \]; then/if [ "$pmax" = nomatch ]; then/'
mutant M14 "throttled_usec not converted to seconds" 's/cpu_throttled_seconds_total{$L} $(usec_to_s "$tusec")/cpu_throttled_seconds_total{$L} $tusec/'

echo "MUTANTS: $caught/$n caught"
[ "$caught" = "$n" ]
