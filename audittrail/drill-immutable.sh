#!/usr/bin/env bash
# Tamper drill 3 for pft-audittrail: with --immutable (-e 2) the kernel refuses audit rule changes until reboot.
# Run from a host that reaches the target with `ssh HOST` (target user root or passwordless sudo). No postfiatd
# restart and no reboot: the target is LEFT immutable (the intended end state of --immutable); undoing it needs a
# reboot, then `pft-audittrail apply --yes` without --immutable.
# Pass/fail is the kernel state after each attempt (loaded rule count, the canary watch still loaded, enabled 2),
# never the wording of an error message and never auditctl's exit status alone: live run 1 showed `auditctl -W`
# printing "The audit system is in immutable mode, no rule changes allowed" yet exiting 0 (exit codes are printed).
# Usage: bash drill-immutable.sh --ssh relay --label sentry-host [--already-immutable]
#  --already-immutable: the target was made immutable by an earlier run; skip apply, require enabled 2 at start.
# /etc/os-release is the host's; single-quoted remote commands expand on the target (SC2016).
# shellcheck disable=SC1091,SC2016
set -uo pipefail
SSH=""; LABEL=""; ALREADY=0
while [ $# -gt 0 ]; do
  case "$1" in --ssh) SSH="$2"; shift ;; --label) LABEL="$2"; shift ;; --already-immutable) ALREADY=1 ;; *) echo "unknown option $1" >&2; exit 3 ;; esac; shift
done
if [ -z "$SSH" ] || [ -z "$LABEL" ]; then echo "usage: $0 --ssh HOST --label NAME" >&2; exit 3; fi
T() { ssh -o BatchMode=yes "$SSH" "$1" </dev/null; }
TOOL=/usr/local/sbin/pft-audittrail
pass=0; fail=0
res() { if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "  -> PASS: $2"; else fail=$((fail + 1)); echo "  -> FAIL: $2"; fi; }
enabled() { T 'sudo auditctl -s' | awk '$1=="enabled"{print $2}'; }
npft() { T 'sudo auditctl -l' | grep -c 'pft-'; }
canary_loaded() { T 'sudo auditctl -l' | grep -qx -- '-w /var/lib/pft-audittrail/canary -p wa -k pft-canary'; }

echo "# OS: $(T '. /etc/os-release; echo "$PRETTY_NAME"') | $(date -u +%FT%TZ) | $LABEL: pft-audittrail immutable drill (-e 2)"
echo "script sha256: drill-immutable.sh $(sha256sum "$0" | cut -c1-64) | target pft-audittrail $(T "sha256sum $TOOL" | cut -c1-64)"
C0="$(T 'c=$(sudo docker ps --format "{{.Names}}" | grep -m1 "^postfiatd"); sudo docker inspect "$c" --format "{{.Name}} {{.State.StartedAt}} restarts={{.RestartCount}}"')"
echo "container before: $C0"

echo; echo "== before"
E0="$(enabled)"; N0="$(npft)"; echo "auditctl -s enabled=$E0 | loaded pft-* rules: $N0"
if [ "$ALREADY" = 0 ]; then
[ "$E0" = 1 ]; res $? "starts mutable (enabled 1)"

echo; echo "== apply --immutable (re-apply: existing FSS key kept, no new key)"
echo "\$ sudo pft-audittrail apply --yes --immutable"; T "sudo $TOOL apply --yes --immutable"; rc=$?; echo "exit $rc"
[ "$rc" = 0 ]; res $? "apply --immutable exit 0"
E1="$(enabled)"; N1="$(npft)"; echo "auditctl -s enabled=$E1 | loaded pft-* rules: $N1"
[ "$E1" = 2 ] && [ "$N1" = "$N0" ]; res $? "enabled 2 (immutable), same rule count"
else
[ "$E0" = 2 ]; res $? "already immutable (enabled 2) from an earlier run (--already-immutable: apply skipped)"
fi
echo "\$ sudo pft-audittrail check"; T "sudo $TOOL check" | sed 's/^/  /'; res "${PIPESTATUS[0]}" "check PASS (expects enabled 2 after --immutable)"

echo; echo "== tamper attempts (must be refused)"
echo "\$ sudo auditctl -D"; T 'sudo auditctl -D 2>&1; echo "exit $?"' | sed 's/^/  /'
N2="$(npft)"; echo "loaded pft-* rules after: $N2"
[ "$N2" = "$N0" ] && canary_loaded; res $? "auditctl -D refused (all $N0 pft-* rules still loaded)"
echo "loaded canary rule (the -W below matches it exactly): $(T 'sudo auditctl -l' | grep 'k pft-canary$')"
echo "\$ sudo auditctl -W /var/lib/pft-audittrail/canary -p wa -k pft-canary   (remove one watch)"
T 'sudo auditctl -W /var/lib/pft-audittrail/canary -p wa -k pft-canary 2>&1; echo "exit $?"' | sed 's/^/  /'
N3="$(npft)"; echo "loaded pft-* rules after: $N3"
[ "$N3" = "$N0" ] && canary_loaded; res $? "removing a single watch refused (canary watch still loaded, whatever the exit code)"
echo "\$ sudo auditctl -e 0   (disable auditing)"
T 'sudo auditctl -e 0 2>&1; echo "exit $?"' | sed 's/^/  /'
E3="$(enabled)"; echo "auditctl -s enabled=$E3"
[ "$E3" = 2 ]; res $? "disabling auditing refused (still enabled 2)"

echo; echo "== audit pipeline still records (canary write after the refused attempts)"
T 'echo "pft-audittrail immutable drill $(date -u +%FT%TZ)" | sudo tee -a /var/lib/pft-audittrail/canary >/dev/null'; sleep 2
T "sudo $TOOL report --since recent" | grep -E '^\| (key|pft-canary) '
T "sudo $TOOL report --since recent" | grep -qE '^\| pft-canary \| [1-9]'; res $? "canary event recorded"
echo "\$ sudo ausearch --input-logs -m CONFIG_CHANGE -ts recent -i | grep -c 'res=no'   (refused changes are audited too)"
T "sudo ausearch --input-logs -m CONFIG_CHANGE -ts recent -i 2>/dev/null | grep -c 'res=no'"

C1="$(T 'c=$(sudo docker ps --format "{{.Names}}" | grep -m1 "^postfiatd"); sudo docker inspect "$c" --format "{{.Name}} {{.State.StartedAt}} restarts={{.RestartCount}}"')"
echo; echo "container after: $C1 ($([ "$C0" = "$C1" ] && echo "unchanged: no node restart" || echo CHANGED))"
[ "$C0" = "$C1" ]; res $? "no postfiatd restart"
echo "state: $LABEL left IMMUTABLE (enabled 2) until its next reboot; rollback before then exits 2 (rollback pending reboot)"
echo; echo "drill-immutable: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
