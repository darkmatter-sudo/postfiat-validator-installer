#!/usr/bin/env bash
# Mutation controls for pft-timesync.sh: each mutant is one exact text replacement (must match exactly once,
# else "NOT APPLIED" counts as a failure of this harness). A copy of the tool is mutated in a temp dir and
# run-tests.sh is run against it; the mutant is CAUGHT when the suite fails. The unmutated copy runs first
# as a control and must pass. Prints the failing test names for each mutant.
# Usage: tests/mutate.sh
# Mutant texts are literal code, single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_TOOL="$HERE/../pft-timesync.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
CAUGHT=0; SURVIVED=0; NOTAPPLIED=0; TOTAL=0

cp "$SRC_TOOL" "$W/pft-timesync.sh"
if bash "$HERE/run-tests.sh" "$W/pft-timesync.sh" > "$W/control.out" 2>&1; then
  echo "control: unmutated copy $(tail -1 "$W/control.out")"
else
  echo "control: FAILED - harness invalid"; tail -5 "$W/control.out"; exit 2
fi

mutant() { # ID DESCRIPTION OLD NEW
  local id="$1" desc="$2" n
  TOTAL=$((TOTAL + 1))
  cp "$SRC_TOOL" "$W/pft-timesync.sh"
  n="$(OLD="$3" NEW="$4" F="$W/pft-timesync.sh" python3 -c '
import os; p=os.environ["F"]; s=open(p).read(); o=os.environ["OLD"]; c=s.count(o)
if c==1: open(p,"w").write(s.replace(o, os.environ["NEW"]))
print(c)')"
  if [ "$n" != 1 ]; then NOTAPPLIED=$((NOTAPPLIED + 1)); echo "$id NOT APPLIED (matches=$n) - $desc"; return; fi
  if bash "$HERE/run-tests.sh" "$W/pft-timesync.sh" > "$W/$id.out" 2>&1; then
    SURVIVED=$((SURVIVED + 1)); echo "$id SURVIVED - $desc"
  else
    CAUGHT=$((CAUGHT + 1))
    echo "$id CAUGHT - $desc :: $(grep -c '^FAIL ' "$W/$id.out") failing: $(grep '^FAIL ' "$W/$id.out" | head -3 | cut -c6-70 | paste -sd ';' -)"
  fi
}

mutant M01 "NTS source counted without an established NTS key (KLen 0)" \
  '$2=="NTS" && $5+0 > 0 && ($1 in reach){n++}' '$2=="NTS" && ($1 in reach){n++}'
mutant M02 "NTS source counted although unreachable" \
  '$2=="NTS" && $5+0 > 0 && ($1 in reach){n++}' '$2=="NTS" && $5+0 > 0{n++}'
mutant M03 "chrony offset sign not flipped (slow read as fast)" \
  '$3, -$5, $12, $14' '$3, $5, $12, $14'
mutant M04 "offset graded without abs()" \
  'local a; a="$(abs "$1")"' 'local a; a="$1"'
mutant M05 "conflicting daemons not detected" \
  'if [ "$n" -gt 1 ]; then' 'if false; then'
mutant M06 "leap Not synchronised read as Normal" \
  'Normal) res PASS leap "Normal" ;;' 'Normal|"Not synchronised") res PASS leap "Normal" ;;'
mutant M07 "makestep in chrony.conf not detected" \
  "grep -qE '^[[:space:]]*makestep' \"\$CHRONY_CONF\"" "grep -qE '^NOMATCH' \"\$CHRONY_CONF\""
mutant M08 "commented-out makestep counted as a step" \
  "grep -qE '^[[:space:]]*makestep' \"\$CHRONY_CONF\"" "grep -qE 'makestep' \"\$CHRONY_CONF\""
mutant M09 "boot-gate ignores uptime (steps allowed at every start)" \
  'if [ "${up:-999999}" -lt "$BOOT_WINDOW" ]; then' 'if true; then'
mutant M10 "policy-rc.d not written (package starts chrony with the default makestep config)" \
  '> "$POLICY_RC"; chmod 0755 "$POLICY_RC"' '> /dev/null'
mutant M11 "policy-rc.d left behind after the install" \
  '  rm -f "$POLICY_RC"' '  :'
mutant M12 "candidate chrony.conf installed without chronyd -p" \
  'if ! "$CHRONYD" -p -f' 'if false && ! "$CHRONYD" -p -f'
mutant M13 "sync gate ignores the NTS count" \
  '&& [ "$(get nts "$f")" -ge "$MIN_NTS" ]' ''
mutant M14 "sync gate ignores a changed postfiatd StartedAt" \
  '&& [ "$sa" = "$st0" ] && [ "$st" = full ]; then' '&& [ "$st" = full ]; then'
mutant M15 "sync gate ignores server_state" \
  '&& [ "$sa" = "$st0" ] && [ "$st" = full ]; then' '&& [ "$sa" = "$st0" ]; then'
mutant M16 "sync gate ignores the offset" \
  '&& num_le "$(abs "${off:-9}")" "$OFFSET_WARN"' ''
mutant M17 "no rollback after a sync-gate miss" \
  'apply: sync gate missed -> automatic rollback"; do_rollback "$b" || return 5' 'apply: sync gate missed -> automatic rollback"'
mutant M18 "rollback does not purge chrony" \
  '"$APTGET" purge -y -q chrony' 'true'
mutant M19 "rollback does not reinstall the cached timesyncd" \
  '"$DPKG" -i --force-confold' 'true'
mutant M20 "rollback leaves files that were absent before" \
  'if [ "$st" = absent ]; then rm -f "$f";' 'if [ "$st" = absent ]; then :;'
mutant M21 "restore check does not compare sha256" \
  'if [ "$now" = "$h" ]; then' 'if true; then'
mutant M22 "rollback verdict ignores packages and active daemon" \
  '[ "$now_c" = "$want_c" ] && [ "$now_t" = "$want_t" ] && [ "$now_a" = "$want_a" ] || bad=1' ':'
mutant M23 "apply proceeds without a cached timesyncd .deb" \
  'ls "$b"/systemd-timesyncd_*.deb >/dev/null 2>&1 || die' 'true || die'
mutant M24 "timesyncd not stopped before the install" \
  '  "$SYSTEMCTL" stop systemd-timesyncd 2>/dev/null' '  :'
mutant M25 "apply without --yes allowed" \
  '[ "$yes" = 1 ] || die "apply changes' 'true || die "apply changes'
mutant M26 "idempotence check removed (re-installs and restarts every time)" \
  '[ "$(dropin_text)" = "$(cat "$DROPIN" 2>/dev/null)" ]; then' 'false; then'
mutant M27 "slew bound not compared" \
  'num_le "$slew" 1000' 'true'
mutant M28 "metrics report synced 1 when unsynchronised" \
  'else echo "pft_timesync_synced 0"; fi' 'else echo "pft_timesync_synced 1"; fi'
mutant M29 "any source counts as selected" \
  'if ($2=="*") s=$3' 's=$3'
mutant M30 "timesyncd ms dispersion scaled as us" \
  '($2=="ms") ? 1e-3' '($2=="ms") ? 1e-6'

echo "RESULT: $CAUGHT/$TOTAL caught, $SURVIVED survived, $NOTAPPLIED not applied"
[ "$SURVIVED" = 0 ] && [ "$NOTAPPLIED" = 0 ]
