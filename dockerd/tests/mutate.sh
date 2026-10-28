#!/usr/bin/env bash
# Mutation controls for pft-dockerd.sh: each mutant is one exact text replacement (must match exactly once,
# else "NOT APPLIED" counts as a failure of this harness). A copy of the tool is mutated in a temp dir and
# run-tests.sh is run against it; the mutant is CAUGHT when the suite fails. The unmutated copy runs first
# as a control and must pass. Prints the failing test names for each mutant.
# Usage: tests/mutate.sh
# Mutant texts are literal code, single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_TOOL="$HERE/../pft-dockerd.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
CAUGHT=0; SURVIVED=0; NOTAPPLIED=0; TOTAL=0

cp "$SRC_TOOL" "$W/pft-dockerd.sh"
if bash "$HERE/run-tests.sh" "$W/pft-dockerd.sh" > "$W/control.out" 2>&1; then
  echo "control: unmutated copy $(tail -1 "$W/control.out")"
else
  echo "control: FAILED - harness invalid"; tail -5 "$W/control.out"; exit 2
fi

mutant() { # ID DESCRIPTION OLD NEW
  local id="$1" desc="$2" n
  TOTAL=$((TOTAL + 1))
  cp "$SRC_TOOL" "$W/pft-dockerd.sh"
  n="$(OLD="$3" NEW="$4" F="$W/pft-dockerd.sh" python3 -c '
import os; p=os.environ["F"]; s=open(p).read(); o=os.environ["OLD"]; c=s.count(o)
if c==1: open(p,"w").write(s.replace(o, os.environ["NEW"]))
print(c)')"
  if [ "$n" != 1 ]; then NOTAPPLIED=$((NOTAPPLIED + 1)); echo "$id NOT APPLIED (matches=$n) - $desc"; return; fi
  if bash "$HERE/run-tests.sh" "$W/pft-dockerd.sh" > "$W/$id.out" 2>&1; then
    SURVIVED=$((SURVIVED + 1)); echo "$id SURVIVED - $desc"
  else
    CAUGHT=$((CAUGHT + 1))
    echo "$id CAUGHT - $desc :: $(grep -c '^FAIL ' "$W/$id.out") failing: $(grep '^FAIL ' "$W/$id.out" | head -3 | cut -c6-70 | paste -sd ';' -)"
  fi
}

mutant M01 "live-restore check always PASS" \
  '[ "$(jq -r '"'"'.LiveRestoreEnabled'"'"' <<<"$i")" = true ]' 'true'
mutant M02 "no-new-privileges default ignored" \
  '[ "$(jq -r '"'"'."no-new-privileges" // false'"'"' <<<"$d")" = true ]' 'true'
mutant M03 "TCP listener not checked" \
  '|| [ -n "$tcp" ]; then res FAIL 2.7' '; then res FAIL 2.7'
mutant M04 "-H tcp on the command line ignored" \
  "grep -oE -- '(-H|--host)[= ]*tcp://[^ ]+'" "grep -oE -- 'NOMATCH'"
mutant M05 "insecure registry names (IndexConfigs) ignored" \
  '+ [.RegistryConfig.IndexConfigs[]? | select(.Secure==false) | .Name]' ''
mutant M06 "back to the jq // trap for iptables" \
  'if has("iptables") then .iptables else true end' '.iptables // true'
mutant M07 "perm: owner not compared" \
  'if [ "$owner" != "$want_owner" ]; then' 'if false; then'
mutant M08 "perm: mode bits not compared" \
  '(( (8#$mode & ~8#$max) != 0 ))' 'false'
mutant M09 "audit watch matched as a prefix (runcx covers runc)" \
  'grep -qE -- "^-w ${p//./\\.}( |$)" <<<"$rules" || covered_by_dir' 'grep -qE -- "^-w ${p//./\\.}" <<<"$rules" || covered_by_dir'
mutant M10 "staged-until-boot not distinguished" \
  'elif [ "$enabled" = 2 ] && staged "$p"; then' 'elif false; then'
mutant M11 "docker group prints member names" \
  'res INFO 1.1.2 docker-group "$(tr '"','"' '"'\n'"' <<<"$members" | grep -c .) member(s)' 'res INFO 1.1.2 docker-group "$members member(s)'
mutant M12 "merge overwrites existing values" \
  'if has($e.key) and (.[$e.key] != $e.value) then . else .[$e.key] = $e.value end' '.[$e.key] = $e.value'
mutant M13 "dockerd --validate result ignored" \
  'if [ "$rc" != 0 ]; then' 'if false; then'
mutant M14 "live-restore not enabled by reload first" \
  'if [ "$live" != true ]; then # step 2' 'if false; then # step 2'
mutant M15 "health gate ignores changed StartedAt / DOCKER-USER" \
  '[ "$snap" = "$before" ] && [ "$st" = full ]' '[ "$st" = full ]'
mutant M16 "health gate ignores server_state" \
  '[ "$snap" = "$before" ] && [ "$st" = full ]' '[ "$snap" = "$before" ]'
mutant M17 "health gate ignores the peer listener" \
  '&& "$SS" -Hltn 2>/dev/null | awk '"'"'{print $4}'"'"' | grep -qE ":$PEER_PORT\$"; then' '; then'
mutant M18 "no rollback after a health miss" \
  'echo "$(ts) apply: health gate missed -> automatic rollback"; do_rollback "$b" || return 5; return 1;' 'echo "$(ts) apply: health gate missed -> automatic rollback"; return 1;'
mutant M19 "rollback to an absent file leaves the new file" \
  'if [ "$b" = absent ]; then rm -f "$DJSON"; else' 'if [ "$b" = absent ]; then :; else'
mutant M20 "augenrules --load run even when immutable" \
  'if [ "$("$AUDITCTL" -s | awk '"'"'$1=="enabled"{print $2}'"'"')" = 2 ]; then' 'if false; then'
mutant M21 "apply without --yes allowed" \
  '[ "$dry" = 1 ] || [ "$yes" = 1 ] || die' '[ "$dry" = 1 ] || true || die'
mutant M22 "dry run writes the file" \
  'if [ "$dry" = 1 ]; then rm -f "$tmp"; echo "$(ts) apply: dry run, nothing changed"; return 0; fi' ':'
mutant M23 "idempotence check removed (always restarts)" \
  'if cmp -s "$tmp" "$DJSON" 2>/dev/null; then' 'if false; then'
mutant M24 "swarm state not checked" \
  '[ "$(jq -r '"'"'.Swarm.LocalNodeState'"'"' <<<"$i")" = inactive ]' 'true'
mutant M25 "health drill does not change the candidate (no restart on an applied host)" \
  '[ "$INJECT" = health ] && cand="$(jq '"'"'. + {"labels": ["pft.dockerd-drill=1"]}'"'"' <<<"$cand")"' ':'
mutant M26 "no warning when the rollback target lacks live-restore" \
  '&& echo "$(ts) rollback: WARNING the restored daemon.json' '&& : "$(ts) rollback: WARNING the restored daemon.json'

echo "RESULT: $CAUGHT/$TOTAL caught, $SURVIVED survived, $NOTAPPLIED not applied"
[ "$SURVIVED" = 0 ] && [ "$NOTAPPLIED" = 0 ]
