#!/usr/bin/env bash
# Mutation check for pft-resources-pull.sh: every mutant must make tests/test-pull.sh FAIL (CAUGHT); the real script
# must pass.   bash resources/tests/check-pull.sh
# Prints the description of each mutant, proves the edit changed the file, and "MUTANTS: N/M caught".
# shellcheck disable=SC2016  # the sed expressions are meant literally
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../pft-resources-pull.sh"
W="$(mktemp -d)"; trap 'rm -rf "${W:?}"' EXIT
caught=0; n=0

echo "== baseline: real script"
if bash "$HERE/test-pull.sh" "$S" > "$W/base.out" 2>&1; then tail -1 "$W/base.out"; else
  grep '^FAIL' "$W/base.out"; echo "baseline FAILED - mutants meaningless"; exit 1; fi

mutant() { # ID DESCRIPTION SED-EXPR
  local id="$1" desc="$2" expr="$3" m="$W/$1.sh" res
  n=$((n + 1))
  sed "$expr" "$S" > "$m"
  if cmp -s "$S" "$m"; then echo "$id NOT APPLIED (sed matched nothing): $desc"; return; fi
  # CAUGHT needs a finished suite (RESULT line) with at least one FAIL; an aborted suite is an ERROR, not a catch
  if bash "$HERE/test-pull.sh" "$m" > "$W/$id.out" 2>&1; then res="SURVIVED"
  elif grep -q '^RESULT: ' "$W/$id.out" && grep -q '^FAIL' "$W/$id.out"; then res="CAUGHT"; caught=$((caught + 1))
  else res="ERROR (suite aborted without a FAIL line)"; fi
  printf '%s %s: %s (%s)\n' "$id" "$res" "$desc" "$(grep -c '^FAIL' "$W/$id.out") failing assertions"
  grep '^FAIL' "$W/$id.out" | head -3 | sed 's/^/    /'
}

mutant P1 "validation result ignored (any fetched file installed)" 's/if ! why="$(validate "$tmp" "$name")"; then/if false; then/'
mutant P2 "fetch failure ignored (partial/empty output validated instead)" 's/if ! timeout "$PULL_TIMEOUT" $PULL_SSH/if ! true || timeout "$PULL_TIMEOUT" $PULL_SSH/'
mutant P3 "no timeout around ssh" 's/timeout "$PULL_TIMEOUT" $PULL_SSH/$PULL_SSH/'
mutant P4 "foreign metric names accepted" 's/if (substr($0, 1, 14) != "pft_resources_")/if (0)/'
mutant P5 "first-label container check dropped" 's/if (index(rest, c) != 1)/if (0)/'
mutant P6 "closing quote dropped from the container matcher (every real file then fails to parse)" 's/container=\\"$name\\""/container=\\"$name"/'
mutant P7 "HELP/TYPE for foreign metrics accepted as plain comments" '/foreign metric", NR; bad = 1; exit }/d'
mutant P8 "value regex not anchored at the end" 's/(\[eE\]\[-+\]?\[0-9\]+)?\$\//([eE][-+]?[0-9]+)?\//'
mutant P9 "label values may contain an escaped quote" 's/lbl = "\[a-z_\]+=\\"\[^\\"\\\\\\\\\\n\]\*\\""/lbl = "[a-z_]+=\\".*\\""/'
mutant P10 "missing up sample accepted" 's/if (!up) { printf "no pft_resources_up sample"; exit 1 }//'
mutant P11 "missing timestamp sample accepted" 's/if (!ts) { printf "no pft_resources_collect_timestamp_seconds sample"; exit 1 }//'
mutant P12 "MAX_BYTES not enforced" 's/\[ "$size" -le "$MAX_BYTES" \] ||/true ||/'
mutant P13 "temp file not removed on rejection" 's/    rm -f "$tmp"; die "rejected/    die "rejected/'
mutant P14 "written in place (no temp + rename): failed pulls clobber the previous copy" 's/tmp="$(mktemp "$TEXTFILE_DIR\/.pull-$name.XXXXXX")"/tmp="$dst"/'
mutant P15 "empty file accepted" 's/\[ "$size" -gt 0 \] ||/true ||/'
mutant P16 "container name not validated" 's/    valid_name "$name" || die "bad container name"/    true/'

echo "MUTANTS: $caught/$n caught"
[ "$caught" = "$n" ]
