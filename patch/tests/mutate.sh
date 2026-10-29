#!/usr/bin/env bash
# Mutation controls for pft-patch.sh: each mutant is one exact text replacement (must match exactly once,
# else "NOT APPLIED" counts as a failure of this harness). A copy of the tool is mutated in a temp dir and
# run-tests.sh is run against it; the mutant is CAUGHT when the suite fails. The unmutated copy runs first
# as a control and must pass. Prints the failing test names for each mutant.
# Usage: tests/mutate.sh
# Mutant texts are literal code, single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_TOOL="$HERE/../pft-patch.sh"
W="$(mktemp -d)"; trap 'rm -rf "${W:?}"' EXIT
CAUGHT=0; SURVIVED=0; NOTAPPLIED=0; TOTAL=0

cp "$SRC_TOOL" "$W/pft-patch.sh"
if bash "$HERE/run-tests.sh" "$W/pft-patch.sh" > "$W/control.out" 2>&1; then
  echo "control: unmutated copy $(tail -1 "$W/control.out")"
else
  echo "control: FAILED - harness invalid"; tail -5 "$W/control.out"; exit 2
fi

mutant() { # ID DESCRIPTION OLD NEW
  local id="$1" desc="$2" n
  TOTAL=$((TOTAL + 1))
  cp "$SRC_TOOL" "$W/pft-patch.sh"
  n="$(OLD="$3" NEW="$4" F="$W/pft-patch.sh" python3 -c '
import os; p=os.environ["F"]; s=open(p).read(); o=os.environ["OLD"]; c=s.count(o)
if c==1: open(p,"w").write(s.replace(o, os.environ["NEW"]))
print(c)')"
  if [ "$n" != 1 ]; then NOTAPPLIED=$((NOTAPPLIED + 1)); echo "$id NOT APPLIED (matches=$n) - $desc"; return; fi
  if bash "$HERE/run-tests.sh" "$W/pft-patch.sh" > "$W/$id.out" 2>&1; then
    SURVIVED=$((SURVIVED + 1)); echo "$id SURVIVED - $desc"
  else
    CAUGHT=$((CAUGHT + 1))
    echo "$id CAUGHT - $desc :: $(grep -c '^FAIL ' "$W/$id.out") failing: $(grep '^FAIL ' "$W/$id.out" | head -3 | cut -c6-70 | paste -sd ';' -)"
  fi
}

mutant M01 "security pocket not recognised (everything is 'other')" \
  'cls = (m ~ /-security[ ,)\/]/) ? "security" : "other"' 'cls = "other"'
mutant M02 "pending security updates only WARN" \
  'add CRIT updates "$sec security update(s) pending' 'add WARN updates "$sec security update(s) pending'
mutant M03 "kernel packages not counted" \
  '$1 ~ /^linux-(image|modules|headers)?/' '$1 ~ /^kernel-/'
mutant M04 "held package with a pending update only WARN" \
  'add CRIT holds "held with an update pending' 'add WARN holds "held with an update pending'
mutant M05 "reboot-required flag ignored" \
  'if [ -e "$REBOOT_FILE" ]; then' 'if false; then'
mutant M06 "KSTA 2/3 treated as current" \
  '2|3) add WARN kernel' '2|3) add OK kernel'
mutant M07 "needrestart output trusted without KSTA (non-root partial run)" \
  ' && grep -q '"'"'^NEEDRESTART-KSTA:'"'"' <<<"$nr"; then' '; then'
mutant M08 "services on old libraries not reported" \
  'if [ -n "$svc" ]; then add WARN services' 'if false; then add WARN services'
mutant M09 "blacklist matched as substring instead of re.match" \
  're.match(e, sys.argv[1])' 're.search(e, sys.argv[1])'
mutant M10 "unattended-off check inverted" \
  'if [ "${uu:-0}" = 0 ]; then' 'if [ "${uu:-0}" != 0 ]; then'
mutant M11 "Automatic-Reboot true not reported" \
  'true|1|yes) add WARN autoreboot' 'true|1|yes) add OK autoreboot'
mutant M12 "WARN does not raise the exit code" \
  'WARN) [ "$rc" -lt 1 ] && rc=1 ;;' 'WARN) : ;;'
mutant M13 "status simulation without -s (would really upgrade)" \
  '"$APT_GET" -s -o Debug::NoLocking=1 dist-upgrade' '"$APT_GET" -o Debug::NoLocking=1 dist-upgrade'
mutant M14 "apply without --yes allowed" \
  '[ "$yes" = 1 ] || { echo "pft-patch: policy apply changes' 'true || { echo "pft-patch: policy apply changes'
mutant M15 "apply does not check the EFFECTIVE config" \
  'if ! probs="$(policy_effective)"; then' 'if ! probs="$(true)"; then'
mutant M16 "refused apply does not restore the previous state" \
  '    restore_from "$b"; rm -rf "$b"' '    rm -rf "$b"'
mutant M17 "Automatic-Reboot not part of the effective check" \
  'case "${ar:-false}" in false|0|no) ;; *) echo "Automatic-Reboot is' 'case "false" in false|0|no) ;; *) echo "Automatic-Reboot is'
mutant M18 "no backup of an existing drop-in" \
  'if [ -f "$POLICY_FILE" ]; then cp -p "$POLICY_FILE" "$b/previous"' 'if false; then cp -p "$POLICY_FILE" "$b/previous"'
mutant M19 "restore copies without preserving mode" \
  'else cp -p "$1/previous" "$POLICY_FILE"; fi' 'else cp "$1/previous" "$POLICY_FILE"; fi'
mutant M20 "rollback does not compare the effective apt-config" \
  'echo "apt-config dump sha256 $now (recorded $want)"; [ "$now" = "$want" ] || ok=0' 'echo "apt-config dump sha256 $now (recorded $want)"'
mutant M21 "rollback reuses an already rolled-back backup" \
  '[ -d "$d" ] && [ "${d%.rolled-back}" = "$d" ] && b="$d"' '[ -d "$d" ] && b="$d"'
mutant M22 "idempotence check skipped (new backup every apply)" \
  'if [ -f "$POLICY_FILE" ] && cmp -s "$cand" "$POLICY_FILE" && policy_effective >/dev/null; then' 'if false; then'
mutant M23 "drop-in installed with mode 0600" \
  'install -m 0644 "$cand" "$POLICY_FILE"' 'install -m 0600 "$cand" "$POLICY_FILE"'
mutant M24 "runtime package not installed counted as exposed" \
  '| cut -c1-2)" = "ii" ] && echo "$p"' '| cut -c1-2)" = "ii" ] || true; echo "$p"'

echo "RESULT: $CAUGHT/$TOTAL caught, $SURVIVED survived, $NOTAPPLIED not applied"
[ "$SURVIVED" = 0 ] && [ "$NOTAPPLIED" = 0 ]
