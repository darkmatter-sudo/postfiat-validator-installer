#!/usr/bin/env bash
# check-drill: PASS/FAIL verdict for a live pft-rollout run, computed only from what the run left behind.
#   check-drill.sh noop|badimage AUDIT_JSONL RUN_ID FACTS_JSON
# AUDIT_JSONL  pft-rollout audit log (only lines with "run" == RUN_ID are read)
# FACTS_JSON   written by the drill wrapper around the run:
#   {"exit":N, "alert_msgs":N,
#    "sentry":   {"before":{"id":"sha256:..","started":".."}, "after":{...}},
#    "validator":{"before":{...}, "after":{...}}}
#   id = container .Image (image ID), started = .State.StartedAt, alert_msgs = messages on the throwaway ALERT topic
#   (the pft-maint [MAINT] topic is a separate throwaway and not counted).
# noop:     exit 0; both hosts host_start, target == recorded prev, gate_pass, soak_pass, host_done promoted, in
#           order sentry then validator; no rollback event; both containers restarted (StartedAt changed) on the
#           same image ID.
# badimage: exit 1; sentry deployed, gate_fail, rollback_done; no promotion; validator has NO audit event and its
#           image ID and StartedAt are unchanged; sentry ends on its recorded image; alert topic received nothing.
# Prints one "PASS|FAIL <check>" line per check and "RESULT: PASS|FAIL (n/m)"; exits 0 only when all pass.
# shellcheck disable=SC2016
set -uo pipefail
[ $# -eq 4 ] || { echo "usage: $0 noop|badimage AUDIT_JSONL RUN_ID FACTS_JSON" >&2; exit 3; }
MODE="$1" AUDIT="$2" RUN="$3" FACTS="$4"
case "$MODE" in noop|badimage) ;; *) echo "unknown mode $MODE" >&2; exit 3 ;; esac
[ -n "$RUN" ] || { echo "empty RUN_ID" >&2; exit 3; }
jq -e . "$FACTS" >/dev/null 2>&1 || { echo "facts not JSON: $FACTS" >&2; exit 3; }

EV="$(jq -c --arg r "$RUN" 'select(.run == $r)' "$AUDIT" 2>/dev/null | jq -sc .)"
[ -n "$EV" ] || EV='[]'
P=0; N=0
ck() { # NAME JQ_BOOL (evaluated with $ev = this run's events, $f = facts)
  N=$((N + 1))
  if [ "$(jq -n --argjson ev "$EV" --slurpfile f "$FACTS" "\$f[0] as \$f | ($2)" 2>/dev/null)" = true ]; then
    P=$((P + 1)); echo "PASS $1"
  else
    echo "FAIL $1"
  fi
}
has() { printf '([$ev[] | select(.host == "%s" and .event == "%s")] | length) %s' "$1" "$2" "${3:->= 1}"; }

ck "audit has events for run $RUN" '($ev | length) > 0'
ck "audit run_start and run_end present" '([$ev[] | .event] | index("run_start") != null and index("run_end") != null)'
if [ "$MODE" = noop ]; then
  ck "exit code 0" '$f.exit == 0'
  for h in sentry validator; do
    ck "$h host_start" "$(has $h host_start)"
    ck "$h target == recorded prev (no-op)" "[\$ev[] | select(.host == \"$h\")] as \$e | ([\$e[] | select(.event == \"host_start\") | .prev][0]) as \$p | (\$p != null and \$p != \"\" and ([\$e[] | select(.event == \"target\") | .target][0]) == \$p)"
    ck "$h gate_pass" "$(has $h gate_pass)"
    ck "$h soak_pass" "$(has $h soak_pass)"
    ck "$h host_done promoted" "([\$ev[] | select(.host == \"$h\" and .event == \"host_done\" and .result == \"promoted\")] | length) == 1"
    ck "$h no rollback event" "([\$ev[] | select(.host == \"$h\" and (.event | startswith(\"rollback\")))] | length) == 0"
    ck "$h restarted (StartedAt changed)" "\$f.$h.before.started != null and \$f.$h.after.started != null and \$f.$h.before.started != \$f.$h.after.started"
    ck "$h same image ID before/after" "(\$f.$h.before.id | startswith(\"sha256:\")) and \$f.$h.before.id == \$f.$h.after.id"
  done
  ck "sentry promoted before validator started" '([$ev | to_entries[] | select(.value.host == "sentry" and .value.event == "host_done") | .key][0]) as $a
    | ([$ev | to_entries[] | select(.value.host == "validator" and .value.event == "host_start") | .key][0]) as $b | ($a != null and $b != null and $a < $b)'
else
  ck "exit code 1" '$f.exit == 1'
  ck "sentry deployed" "$(has sentry deployed)"
  ck "sentry gate_fail" "$(has sentry gate_fail)"
  ck "sentry rollback_done" "$(has sentry rollback_done)"
  ck "sentry not promoted" '([$ev[] | select(.host == "sentry" and .event == "host_done")] | length) == 0'
  ck "sentry no rollback_fail" "$(has sentry rollback_fail '== 0')"
  ck "sentry ends on recorded image" '([$ev[] | select(.host == "sentry" and .event == "host_start") | .prev][0]) as $p | ($p != null and $p != "" and $f.sentry.before.id == $p and $f.sentry.after.id == $p)'
  ck "sentry target differs from recorded image" '([$ev[] | select(.host == "sentry" and .event == "target") | .target][0]) as $t | ($t != null and $t != $f.sentry.before.id)'
  ck "validator: no audit event" '([$ev[] | select(.host == "validator")] | length) == 0'
  ck "validator image ID unchanged" '($f.validator.before.id | startswith("sha256:")) and $f.validator.before.id == $f.validator.after.id'
  ck "validator StartedAt unchanged" '$f.validator.before.started != null and $f.validator.before.started != "" and $f.validator.before.started == $f.validator.after.started'
  ck "throwaway alert topic received nothing" '($f.alert_msgs | type) == "number" and $f.alert_msgs == 0'
fi
if [ "$P" -eq "$N" ]; then echo "RESULT: PASS ($P/$N)"; exit 0; fi
echo "RESULT: FAIL ($P/$N)"; exit 1
