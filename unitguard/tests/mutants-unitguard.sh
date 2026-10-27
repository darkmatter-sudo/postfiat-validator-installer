#!/usr/bin/env bash
# Mutation controls for pft-unitguard.sh: each mutant removes one safety property, and test-unitguard.sh must FAIL on it.
# Usage: bash tests/mutants-unitguard.sh   (offline, no root; same stubs as test-unitguard.sh)
# sed programs are single-quoted on purpose ($ is sed/shell text, not expanded here).
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../pft-unitguard.sh"
MUTANTS=(
  'U1 no automatic rollback on failure|s/^  if ! undo_apply "$u" "$prev"; then/  if false; then/'
  'U2 no daemon-reload after writing the drop-in|/render "$p" > "$dp.tmp"/{n;s/^  "$SYSTEMCTL" daemon-reload$/  :/}'
  'U3 functional check skipped|s/if run_unit "$u" && run_check "$p"; then/if run_unit "$u"; then/'
  'U4 exposure target not enforced|s/^    if meets /    if true || meets /'
  'U5 parent dir not permission-checked|s/for f in "$(readlink -f "$1")" "$(dirname "$(readlink -f "$1")")"; do/for f in "$(readlink -f "$1")"; do/'
  'U6 HOLD_UNITS/--skip ignored|s/^  held "$u" && {/  false \&\& {/'
  'U7 docker/iptables target accepts an unchanged score|s/ && lt "$1" "$b"/ \&\& lt_eq "$1" "$b"/'
  'U8 earlier foreign drop-in not backed up|s/&& cp -p "$dp" "$bk"$/\&\& true/'
  'U9 profile metadata copied into the drop-in|s/grep -v .^#@. "$1"/cat "$1"/'
  'U10 oneshot Result not checked|s/^    \[ "$res" = success \]$/    true/'
  'U11 NRestarts change not checked|s/\[ "$active" = active \] && \[ "$before" = "$after" \]/[ "$active" = active ]/'
  'U12 drop-in written group-writable|s/chmod 0644 "$dp.tmp"/chmod 0664 "$dp.tmp"/'
  'U13 unit not re-run after rollback|s/if run_unit "$u"; then log "ROLLED-BACK/if true; then log "ROLLED-BACK/'
  'U14 root check bypassed|s/\[ "$(id -u)" = 0 \] ||/true ||/'
  'U15 rollback deletes an earlier unitguard drop-in instead of restoring it|s/^  \[ -f "$prev" \] || { remove_dropin "$u"; return; }$/  remove_dropin "$u"; return/'
  'U16 RemainAfterExit=yes oneshot only started (no-op), never re-run|s/\] \&\& verb=restart$/] \&\& verb=start/'
)
MC=0
for m in "${MUTANTS[@]}"; do
  name="${m%%|*}"; expr="${m#*|}"
  mf="$(mktemp --suffix=.sh)"; sed "$expr" "$SRC" > "$mf"
  if cmp -s "$mf" "$SRC"; then echo "MUTANT $name: sed changed nothing - INVALID"; MC=$((MC + 1)); rm -f "$mf"; continue; fi
  out="$(bash "$HERE/test-unitguard.sh" "$mf" 2>&1)"; rc=$?
  rm -f "$mf"
  if [ "$rc" -ne 0 ]; then echo "MUTANT $name: CAUGHT by $(grep -c '^FAIL ' <<<"$out") test(s): $(grep '^FAIL ' <<<"$out" | sed 's/^FAIL //; s/:.*//' | paste -sd ';')"
  else echo "MUTANT $name: NOT CAUGHT"; MC=$((MC + 1)); fi
done
echo "mutants not caught/invalid: $MC"
[ "$MC" -eq 0 ]
