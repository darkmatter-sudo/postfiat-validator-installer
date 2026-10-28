#!/usr/bin/env bash
# check-drill: PASS/FAIL verdict for one live pft-peerexpose drill, computed only from what live-run.sh recorded.
#   check-drill.sh STEPS_JSONL FACTS_JSON
# STEPS_JSONL  one {"step","exit","result","violations"} per pft-peerexpose call, in run order
# FACTS_JSON   {"alert_msgs":N, "maint_msgs":N, "restore_ok":bool, "redaction_control":rc, "dry":bool,
#               "final":{"validator":{"state","peers","has_other"}, "sentry":{...}}}
# Expected: the 12 steps exactly once each and in order; both initial audits find violations (exit 1); every apply
# APPLIED (exit 0) and every audit after it 0 violations (exit 0); the sentry rollback ROLLED BACK and its audit is
# back to the initial violation count; both nodes full|proposing at the end with the sentry<->validator link seen
# from both sides; the throwaway ALERT topic got nothing, the MAINT topic got the windows; notifiers restored;
# redaction positive control passed. Prints "PASS|FAIL <check>" per check and "RESULT: PASS|FAIL (n/m)".
# shellcheck disable=SC2016
set -uo pipefail
[ $# -eq 2 ] || { echo "usage: $0 STEPS_JSONL FACTS_JSON" >&2; exit 3; }
STEPS_F="$1" FACTS_F="$2"
jq -e 'type == "object"' "$FACTS_F" >/dev/null 2>&1 || { echo "facts not a JSON object: $FACTS_F" >&2; exit 3; }
ST="$(jq -sc . "$STEPS_F" 2>/dev/null)" || ST='[]'
[ -n "$ST" ] || ST='[]'
P=0; N=0
ck() { # NAME JQ_BOOL (evaluated with $st = steps array, $f = facts)
  N=$((N + 1))
  if [ "$(jq -n --argjson st "$ST" --slurpfile f "$FACTS_F" "\$f[0] as \$f | ($2)" 2>/dev/null)" = true ]; then
    P=$((P + 1)); echo "PASS $1"
  else
    echo "FAIL $1"
  fi
}
s() { printf '([$st[] | select(.step == "%s")] | if length == 1 then .[0] else null end)' "$1"; }  # the step, null unless once
audit_bad() { ck "$1 finds violations (exit 1)" "$(s "$1") as \$x | \$x != null and \$x.exit == 1 and (\$x.violations | type) == \"number\" and \$x.violations >= 1"; }
audit_ok() { ck "$1 0 violations (exit 0)" "$(s "$1") as \$x | \$x != null and \$x.exit == 0 and \$x.violations == 0"; }
result() { ck "$1 $2 (exit 0)" "$(s "$1") as \$x | \$x != null and \$x.exit == 0 and \$x.result == \"$2\""; }

ORDER='["audit-sentry-initial","audit-validator-initial","apply-sentry","audit-sentry-applied","rollback-sentry",
  "audit-sentry-rolledback","reapply-sentry","audit-sentry-reapplied","apply-validator","audit-validator-applied",
  "audit-sentry-final","audit-validator-final"]'
ck "not a dry run" '$f.dry == false'
ck "12 steps, each once, in order (sentry first)" "[\$st[].step] == $ORDER"
audit_bad audit-sentry-initial
audit_bad audit-validator-initial
result apply-sentry APPLIED
audit_ok audit-sentry-applied
result rollback-sentry "ROLLED BACK"
audit_bad audit-sentry-rolledback
ck "sentry rollback restores the initial exposure (same violation count)" \
  "$(s audit-sentry-rolledback) as \$r | $(s audit-sentry-initial) as \$i | \$r != null and \$i != null and \$r.violations == \$i.violations"
result reapply-sentry APPLIED
audit_ok audit-sentry-reapplied
result apply-validator APPLIED
audit_ok audit-validator-applied
audit_ok audit-sentry-final
audit_ok audit-validator-final
for h in validator sentry; do
  ck "$h full|proposing at the end" "(\$f.final.$h.state == \"full\" or \$f.final.$h.state == \"proposing\")"
  ck "$h sees the other host as a connected peer" "\$f.final.$h.has_other == true"
done
ck "throwaway ALERT topic received nothing" '($f.alert_msgs | type) == "number" and $f.alert_msgs == 0'
ck "throwaway MAINT topic received the windows" '($f.maint_msgs | type) == "number" and $f.maint_msgs >= 1'
ck "notifiers restored (sha256 match, drill files removed)" '$f.restore_ok == true'
ck "redaction positive control passed" '$f.redaction_control == 0'
if [ "$P" -eq "$N" ]; then echo "RESULT: PASS ($P/$N)"; exit 0; fi
echo "RESULT: FAIL ($P/$N)"; exit 1
