#!/usr/bin/env bash
# Mutation controls for pft-patch.sh: each mutant is one exact text replacement (must match exactly once,
# else "NOT APPLIED" counts as a failure of this harness). A copy of the tool is mutated in a temp dir and
# run-tests.sh is run against it; the mutant is CAUGHT when the suite fails. The unmutated copy runs first
# as a control and must pass. Prints the failing test names for each mutant.
# Usage: [JOBS=N] tests/mutate.sh
# Mutant texts are literal code, single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_TOOL="$HERE/../pft-patch.sh"
W="$(mktemp -d)"; trap 'rm -rf "${W:?}"' EXIT
CAUGHT=0; SURVIVED=0; NOTAPPLIED=0; TOTAL=0
JOBS="${JOBS:-1}"

cp "$SRC_TOOL" "$W/pft-patch.sh"
if bash "$HERE/run-tests.sh" "$W/pft-patch.sh" > "$W/control.out" 2>&1; then
  echo "control: unmutated copy $(tail -1 "$W/control.out")"
else
  echo "control: FAILED - harness invalid"; tail -5 "$W/control.out"; exit 2
fi

IDS=()
mutant() { # ID DESCRIPTION OLD NEW  (up to JOBS mutants run at once; results are printed in ID order at the end)
  local id="$1" desc="$2" n
  IDS+=("$id")
  mkdir -p "$W/$id"; cp "$SRC_TOOL" "$W/$id/pft-patch.sh"
  n="$(OLD="$3" NEW="$4" F="$W/$id/pft-patch.sh" python3 -c '
import os; p=os.environ["F"]; s=open(p).read(); o=os.environ["OLD"]; c=s.count(o)
if c==1: open(p,"w").write(s.replace(o, os.environ["NEW"]))
print(c)')"
  if [ "$n" != 1 ]; then echo "NOTAPPLIED $id NOT APPLIED (matches=$n) - $desc" > "$W/$id.res"; return; fi
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
  (
    if bash "$HERE/run-tests.sh" "$W/$id/pft-patch.sh" > "$W/$id.out" 2>&1; then
      echo "SURVIVED $id SURVIVED - $desc"
    else
      echo "CAUGHT $id CAUGHT - $desc :: $(grep -c '^FAIL ' "$W/$id.out") failing: $(grep '^FAIL ' "$W/$id.out" | head -3 | cut -c6-70 | paste -sd ';' -)"
    fi > "$W/$id.res"
  ) &
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
  'rb=0; rbp=""
  if [ -e "$REBOOT_FILE" ]; then' 'rb=0; rbp=""
  if false; then'
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

mutant M25 "--hosts order used instead of config order (validator first)" \
  '{ [ -z "$hosts" ] || [ "$found" = 1 ]; } && SEL+=("$h")' '{ [ -z "$hosts" ] || [ "$found" = 1 ]; } && SEL=("$h" "${SEL[@]}")'
mutant M26 "post-gate failure does not stop the run" \
  '  [ "$(started_at "$h")" = "$s0" ] || rs=1
  if ! gate "$h" post; then window_close "$h" fail; status_line "$h" after; stop_run "$h" "post-gate"; fi' \
  '  [ "$(started_at "$h")" = "$s0" ] || rs=1
  if ! gate "$h" post; then window_close "$h" fail; status_line "$h" after; fi'
mutant M27 "failure injection ignored" \
  'if [ "$INJECT" = "$h-postgate" ]; then' 'if false; then'
mutant M28 "pre-gate failure ignored" \
  'gate "$h" pre || stop_run "$h" "pre-gate"' 'gate "$h" pre || true'
mutant M29 "maintenance window failure ignored" \
  'window_open "$h" || stop_run "$h" "maintenance window"' 'window_open "$h" || true'
mutant M30 "Alertmanager silence failure ignored" \
  '[ -n "$SIL" ] || { log "WINDOW $1: Alertmanager silence failed"; window_close "$1" fail; return 1; }' 'true'
mutant M31 "host upgrade failure ignored" \
  '[ -n "$dec" ] || { window_close "$h" fail; stop_run "$h" "upgrade failed"; }' '[ -n "$dec" ] || dec=none'
mutant M32 "node gate passes any server_state" \
  'case "$st" in full|proposing) ;; *) why+=("state=$st") ;; esac' ':'
mutant M33 "node gate ignores peers" \
  '[ "$p" -ge "${H_PEERS[$1]}" ] || why+=' 'true || why+='
mutant M34 "node gate ignores validated ledger age" \
  '[ "$age" -le "$MAX_LEDGER_AGE" ] || why+=' 'true || why+='
mutant M35 "integrity result ignored" \
  'if [ "$rc" = 0 ]; then log "GATE $ph $h integrity: PASS' 'if true; then log "GATE $ph $h integrity: PASS'
mutant M36 "audittrail result ignored" \
  'if hx "$h" pft-audittrail check >/dev/null 2>&1; then' 'if true; then'
mutant M37 "egress result ignored" \
  'if hx "$h" pft-egress check --container "${H_CONT[$h]}" >/dev/null 2>&1; then' 'if true; then'
mutant M38 "reboot flag not part of the post-gate" \
  'if [[ "$out" == *reboot=0* ]]; then' 'if true; then'
mutant M39 "post hook not run after a reboot" \
  '      post_hook "$h" || { window_close "$h" fail; stop_run "$h" "post hook"; } ;;' '      ;;'
mutant M40 "later hosts not checked for changes on stop" \
  '[ "$seen" = 1 ] && { untouched "$h" || bad=1; }' '[ "$seen" = 1 ] && { untouched "$h" || true; }'
mutant M41 "security-only filter dropped (other updates installed)" \
  '[ "$all" = 1 ] || [ "$cls" = security ] ||' 'true ||'
mutant M42 "Docker runtime not excluded without --runtime" \
  'if [ "$rt" = 0 ] && is_runtime "$p"; then' 'if false; then'
mutant M43 "held packages not excluded" \
  'if grep -qxF -- "$p" <<<"$hl"; then echo "SKIP $p held"' 'if false; then echo "SKIP $p held"'
mutant M44 "reboot-required after install ignored" \
  '  if [ -e "$REBOOT_FILE" ]; then
    echo "DECISION reboot' '  if false; then
    echo "DECISION reboot'
mutant M45 "newer kernel (KSTA 2/3) after install ignored" \
  'case "$ksta" in 2|3) echo "DECISION reboot' 'case "$ksta" in 9) echo "DECISION reboot'
mutant M46 "docker/containerd restarted like any service" \
  'if [[ "$s" =~ $NO_RESTART_RE ]]; then' 'if false; then'
mutant M47 "service restart failure ignored" \
  '"$SYSTEMCTL" restart "$s" || { echo "UPGRADE FAIL systemctl restart $s"; return 2; }' '"$SYSTEMCTL" restart "$s" || true'
mutant M48 "local host allowed before the sentry" \
  '[ "${H_MODE[$h]}" = local ] && [ "$h" != "$l" ] && {' 'false && {'
mutant M49 "run lock not enforced" \
  'flock -n 9 || {' 'true || {'
mutant M50 "pft-maint data-collection lock ignored" \
  '[ "$a" = "no data-collection locks" ] || {' 'true || {'
mutant M51 "failed host keeps its silence (alerts stay muted)" \
  '  if [ "$2" = restarted ]; then' '  if [ "$2" != ok ]; then'
mutant M52 "local reboot without a resume record" \
  "'{run:\$run, host:\$h, silence:\$sil, silence_body:\$body}' > \"\$RESUME_FILE\"" "'{run:\$run, host:\$h, silence:\$sil, silence_body:\$body}' > /dev/null"
mutant M53 "upgrade without --yes allowed" \
  '[ "$yes" = 1 ] || { echo "pft-patch: upgrade installs' 'true || { echo "pft-patch: upgrade installs'
mutant M54 "run without --yes allowed" \
  '[ "$yes" = 1 ] || { echo "pft-patch: run installs' 'true || { echo "pft-patch: run installs'
mutant M55 "apt-get install failure ignored" \
  '[ "$rc" = 0 ] || { echo "UPGRADE FAIL apt-get install exit $rc"; return 2; }' 'true'
mutant M56 "pending resume record ignored by run" \
  '[ -e "$RESUME_FILE" ] && { log "REFUSED' 'false && { log "REFUSED'

wait
for id in "${IDS[@]}"; do
  read -r kind line < "$W/$id.res"; echo "$line"
  TOTAL=$((TOTAL + 1))
  case "$kind" in CAUGHT) CAUGHT=$((CAUGHT + 1)) ;; SURVIVED) SURVIVED=$((SURVIVED + 1)) ;; *) NOTAPPLIED=$((NOTAPPLIED + 1)) ;; esac
done
echo "RESULT: $CAUGHT/$TOTAL caught, $SURVIVED survived, $NOTAPPLIED not applied"
[ "$SURVIVED" = 0 ] && [ "$NOTAPPLIED" = 0 ]
