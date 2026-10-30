#!/usr/bin/env bash
# Mutation controls for pft-fleet.sh + fleet_lib.py: each mutant is one exact text replacement in one file (it must
# match exactly once, else NOT APPLIED counts as a harness failure). The mutated copy is run through run-tests.sh;
# the mutant is CAUGHT when the suite fails. The unmutated copies run first as a control and must pass.
# Usage: [JOBS=N] tests/mutate.sh        exit 0 only when every mutant applied and was caught
# Mutant texts are literal code, single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/.."
W="$(mktemp -d)"; trap 'rm -rf "${W:?}"' EXIT
JOBS="${JOBS:-4}"
echo "sha256 pft-fleet.sh $(sha256sum < "$SRC/pft-fleet.sh" | cut -c1-64)"
echo "sha256 fleet_lib.py $(sha256sum < "$SRC/fleet_lib.py" | cut -c1-64)"
echo "sha256 run-tests.sh $(sha256sum < "$HERE/run-tests.sh" | cut -c1-64)"

mkdir -p "$W/control"; cp "$SRC/pft-fleet.sh" "$SRC/fleet_lib.py" "$W/control/"
if bash "$HERE/run-tests.sh" "$W/control/pft-fleet.sh" "$W/control/fleet_lib.py" > "$W/control.out" 2>&1; then
  echo "control: unmutated copy $(tail -1 "$W/control.out")"
else
  echo "control: FAILED - harness invalid"; grep '^FAIL' "$W/control.out" | head; exit 2
fi

IDS=()
mutant() { # ID FILE DESCRIPTION OLD NEW
  local id="$1" file="$2" desc="$3" n
  IDS+=("$id")
  mkdir -p "$W/$id"; cp "$SRC/pft-fleet.sh" "$SRC/fleet_lib.py" "$W/$id/"
  n="$(OLD="$4" NEW="$5" F="$W/$id/$file" python3 -I -c '
import os; p=os.environ["F"]; s=open(p).read(); o=os.environ["OLD"]; c=s.count(o)
if c==1: open(p,"w").write(s.replace(o, os.environ["NEW"]))
print(c)')"
  if [ "$n" != 1 ]; then echo "NOTAPPLIED $id NOT APPLIED (matches=$n) - $file: $desc" > "$W/$id.res"; return; fi
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
  (
    if bash "$HERE/run-tests.sh" "$W/$id/pft-fleet.sh" "$W/$id/fleet_lib.py" > "$W/$id.out" 2>&1; then
      echo "SURVIVED $id SURVIVED - $file: $desc"
    else
      echo "CAUGHT $id CAUGHT - $file: $desc :: $(grep -c '^FAIL ' "$W/$id.out") failing, e.g. $(grep '^FAIL ' "$W/$id.out" | head -2 | cut -c6-80 | paste -sd ';' -)"
    fi > "$W/$id.res"
  ) &
}

L=fleet_lib.py; S=pft-fleet.sh
mutant M01 $L "CURRENT for any present expected file" \
  '    if ref_sha is not None and sha == ref_sha:' '    if ref_sha is not None:'
mutant M02 $L "no BEHIND: older committed bytes fall through to MODIFIED" \
  '    if sha in known:
        commit, newer, _ = known[sha]' '    if False:
        commit, newer, _ = known[sha]'
mutant M03 $L "no UNEXPECTED: role check ignored for present files" \
  '    if not expected:
        return "UNEXPECTED"' '    if False:
        return "UNEXPECTED"'
mutant M04 $L "absent expected file is skipped instead of MISSING" \
  'return ("MISSING", None, None) if expected else' 'return (None, None, None) if expected else'
mutant M05 $L "DIVERGED needs three different versions" \
  'len(set(per.values())) > 1' 'len(set(per.values())) > 2'
mutant M06 $L "MISSING no longer exit 2" \
  'if states & {"MODIFIED", "MISSING"}:' 'if states & {"MODIFIED"}:'
mutant M07 $L "best file state wins instead of worst" \
  'RANK[st] > RANK[addons[key]]' 'RANK[st] < RANK[addons[key]]'
mutant M08 $L "drift clock restarts every run" \
  '            new[k] = since.get(k, now)
    for d in' '            new[k] = now
    for d in'
# (A mutant dropping `or rep["diverged"]` from the exit code is equivalent: a DIVERGED file always leaves at least one
#  host's copy BEHIND, MODIFIED or UNEXPECTED, which already gives exit >= 1. Kept in the code as documentation.)
mutant M09 $L "UNEXPECTED no longer exit 1" \
  'if states & {"BEHIND", "UNEXPECTED"} or rep["diverged"]:' 'if states & {"BEHIND"} or rep["diverged"]:'
mutant M10 $S "validator synced before the sentry" \
  'for h in "${HOSTS[@]}"; do [ "${H_ROLE[$h]}" = sentry ] && order+=("$h"); done' \
  'for h in "${HOSTS[@]}"; do [ "${H_ROLE[$h]}" = validator ] && order+=("$h"); done'
mutant M11 $S "maintenance window not enforced" \
  'if ! hx "$h" pft-maint active >/dev/null 2>&1; then' 'if false; then'
mutant M12 $S "rollback does not restore the backup" \
  'if [ "${W_CUR[$i]}" != - ]; then restore_file "$h" "$p" "$bdir"; else remove_file "$h" "$p"; fi' \
  'if [ "${W_CUR[$i]}" != - ]; then :; else remove_file "$h" "$p"; fi'
mutant M13 $S "rollback reported as success (exit 0)" \
  '      exit 5' '      exit 0'
mutant M14 $S "gate ignores the installed sha256" \
  'if [ "$s" = "${W_TGT[$i]}" ]; then echo "GATE $h sha256' 'if true; then echo "GATE $h sha256'
mutant M15 $S "commits outside REF accepted" \
  'git -c safe.directory='"'"'*'"'"' -C "$REPO" merge-base --is-ancestor "$commit" "$refc" ||' \
  'true ||'
mutant M16 $S "unrelated integrity findings allowed" \
  'grep -vxF -f <(printf' 'grep -xF -f <(printf'
mutant M17 $S "backup made without cp -p (mtime/mode lost on rollback)" \
  'install -d -m 700 "$2"; cp -p "$1"' 'install -d -m 700 "$2"; cp "$1"'
mutant M18 $S "bash -n syntax gate disabled" \
  'if hx "$h" bash -n "${H_ROOT[$h]}$p" >/dev/null 2>&1; then' 'if true; then'
mutant M19 $S "rollback mismatch reported as a clean rollback" \
  'fix by hand from $bdir"; exit 6; fi' 'fix by hand from $bdir"; exit 5; fi'
mutant M20 $S "post-write node check ignored" \
  'if node_ok "$h"; then echo "GATE $h node' 'if true; then echo "GATE $h node'
wait

C=0; SV=0; NA=0
for id in "${IDS[@]}"; do
  r="$(cat "$W/$id.res")"; echo "${r#* }"
  case "$r" in CAUGHT*) C=$((C + 1)) ;; SURVIVED*) SV=$((SV + 1)) ;; *) NA=$((NA + 1)) ;; esac
done
echo "MUTANTS ${#IDS[@]}: caught $C, survived $SV, not applied $NA"
[ "$SV" = 0 ] && [ "$NA" = 0 ]
