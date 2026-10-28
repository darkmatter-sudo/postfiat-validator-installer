#!/usr/bin/env bash
# Mutation controls for drill/live-run.sh: each mutant removes one safety property, and test-live-run.sh must FAIL on it.
# sed programs are single-quoted on purpose ($ is sed/shell text, not expanded here).
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../drill/live-run.sh"
MUTANTS=(
  'W1 restore skips the backed-up env files|s/^  for k in "${MOVED\[@\]}"; do$/  for k in; do/'
  'W2 no EXIT trap (early stop leaves notifiers redirected)|s/^trap .restore. EXIT$/:/'
  'W3 unreadable ntfy counted as 0 alerts|s/N_MSG=null; echo/N_MSG=0; echo/'
  'W4 pft-maint lock not checked|s/\[ "$locks" = "no data-collection locks" \] ||/true ||/'
  'W5 NTFY_TOKEN kept in redirected files|s/(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)/(NTFY_TOPIC|NTFY_SERVER)/'
  'W6 drill image not removed|s/R "sudo -n docker rmi $DRILL_TAG"/true/'
  'W7 drill-only maint files on the ALERT topic|s/$NTFY $MAINT > $d/$NTFY $ALERT > $d/'
  'W9 remote journal read oldest-first (no -r)|s/-t $SENTRY_C -r -n 1/-t $SENTRY_C -n 1/'
  'W10 logship facts not recorded|s/--argjson ls "$LS"/--argjson ls null/'
  'W8 existing relay pft-maint ntfy.env overwritten|s/^! R "sudo -n test -e $MAINT_DIR_R\/ntfy.env" ||/true ||/'
  'W11 local lock list without sudo (root-only tool)|s/locks="$(sudo -n pft-maint lock list/locks="$(pft-maint lock list/'
  'W12 local integrity verify without sudo|s/; sudo -n "$INTEGRITY_CMD" verify/; "$INTEGRITY_CMD" verify/'
  'W13 no passwordless-sudo preflight|s/^sudo -n true || /true || /'
  'W14 pre-drill hash read through an unprivileged < redirect|s/fsha() { on "$1" "sudo -n sha256sum $2"/fsha() { on "$1" "sudo -n sha256sum < $2"/'
  'W15 empty pre-drill hash accepted|s/^  \[\[ "${SHA\["$h:$f"\]}" =~ ^\[0-9a-f\]{64}$ \]\] || /  true || /'
)
# Not a mutant here: dropping the `[ -n "$now_sha" ]` guard in restore() (tried as W16 in run -23, NOT CAUGHT) is an
# equivalent change. redirect() stops unless the pre-drill hash is 64 hex (W15), and a key enters MOVED only after that,
# so an empty now_sha never equals ${SHA[$k]}. The guard stays as defence in depth; W15 is the control that matters.
MC=0
for m in "${MUTANTS[@]}"; do
  name="${m%%|*}"; expr="${m#*|}"
  mf="$(mktemp --suffix=.sh)"; sed "$expr" "$SRC" > "$mf"
  if cmp -s "$mf" "$SRC"; then echo "MUTANT $name: sed changed nothing - INVALID"; MC=$((MC + 1)); rm -f "$mf"; continue; fi
  out="$(LIVE="$mf" PFT_ROLLOUT="$HERE/../pft-rollout.sh" CHECK_DRILL="$HERE/../drill/check-drill.sh" bash "$HERE/test-live-run.sh" 2>&1)"; rc=$?
  rm -f "$mf"
  if [ "$rc" -ne 0 ]; then echo "MUTANT $name: CAUGHT by $(grep -c '^FAIL ' <<<"$out") test(s): $(grep '^FAIL ' <<<"$out" | sed 's/^FAIL //; s/:.*//' | paste -sd ';')"
  else echo "MUTANT $name: NOT CAUGHT"; MC=$((MC + 1)); fi
done
echo "mutants not caught/invalid: $MC"
[ "$MC" -eq 0 ]
