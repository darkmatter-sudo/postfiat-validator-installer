#!/usr/bin/env bash
# Offline tests for drill/check-drill.sh, the PASS/FAIL checker of the live no-op run and bad-image drill.
# The audit logs it reads come from real pft-rollout.sh runs against the stubs of test-rollout.sh (no hand-written
# audit lines); facts are built from the stub hosts' container state before/after. Every negative case asserts the
# exact FAIL line it must produce, and each positive case is paired with a negative from the same run.
# jq programs are single-quoted on purpose ($b is a jq variable).
# shellcheck disable=SC2016,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHECK="${CHECK:-$HERE/../drill/check-drill.sh}"
# shellcheck source-path=SCRIPTDIR source=test-rollout.sh
. "$HERE/test-rollout.sh"
NP=0; NF=0

cfact() { jq -c --arg c "$2" '.containers[$c] | {id: .Image, started: .State.StartedAt}' "$T/hosts/$1/state.json"; }
snap() { S_SB="$(cfact relay postfiatd-sentry)"; S_VB="$(cfact local postfiatd)"; }
facts() { # EXIT ALERT_MSGS -> $T/facts.json from the snapshot + current stub state
  jq -n --argjson e "$1" --argjson a "$2" --argjson sb "$S_SB" --argjson sa "$(cfact relay postfiatd-sentry)" \
    --argjson vb "$S_VB" --argjson va "$(cfact local postfiatd)" \
    '{exit: $e, alert_msgs: $a, sentry: {before: $sb, after: $sa}, validator: {before: $vb, after: $va},
      logship: {unit: "active", nrestarts: 1, newest_us: 1800000400000001, after_us: 1800000400000000}}' > "$T/facts.json"
}
runid() { jq -r 'select(.event == "run_start") | .run' "$T/state/audit.jsonl" | tail -1; }
tweak() { local prog="$1"; shift; jq "$@" "$prog" "$T/facts.json" > "$T/f2.json"; }
expect() { # DESC WANT_RC MUST_CONTAIN MODE FACTS [AUDIT] [RUN]
  local d="$1" want="$2" line="$3" out rc
  out="$(bash "$CHECK" "$4" "${6:-$T/state/audit.jsonl}" "${7:-$(runid)}" "$5" 2>&1)"; rc=$?
  if [ "$rc" = "$want" ] && grep -qxF -- "$line" <<<"$out"; then NP=$((NP + 1)); echo "PASS $d"
  else NF=$((NF + 1)); echo "FAIL $d (rc=$rc, want $want + line '$line')"; sed 's/^/    | /' <<<"$out"; fi
}

echo "== no-op run (target == running image) =="
fixture; rm -f "$T/hosts/relay/pull_to" "$T/hosts/local/pull_to"; snap
ro run --yes; facts "$RC" 0
expect "noop run checked as noop -> PASS" 0 "RESULT: PASS (21/21)" noop "$T/facts.json"
expect "noop run checked as badimage -> FAIL" 1 "FAIL sentry gate_fail" badimage "$T/facts.json"
tweak '.validator.after.started = .validator.before.started'
expect "noop: validator not restarted -> FAIL" 1 "FAIL validator restarted (StartedAt changed)" noop "$T/f2.json"
tweak '.sentry.after.id = "sha256:other"'
expect "noop: sentry image changed -> FAIL" 1 "FAIL sentry same image ID before/after" noop "$T/f2.json"
tweak '.exit = 1'
expect "noop: exit 1 -> FAIL" 1 "FAIL exit code 0" noop "$T/f2.json"
LSF="FAIL sentry log forwarded after the run (logship re-attached)"
tweak '.logship.newest_us = .logship.after_us'
expect "noop: newest line == run end (not newer) -> FAIL" 1 "$LSF" noop "$T/f2.json"
tweak '.logship.unit = "activating"'
expect "noop: bridge unit activating -> FAIL" 1 "$LSF" noop "$T/f2.json"
tweak '.logship.newest_us = null'
expect "noop: no forwarded line (null) -> FAIL" 1 "$LSF" noop "$T/f2.json"
tweak 'del(.logship)'
expect "noop: facts without logship -> FAIL" 1 "$LSF" noop "$T/f2.json"
expect "noop: wrong run id -> FAIL" 1 "FAIL audit has events for run 19700101T000000Z" noop "$T/facts.json" "" 19700101T000000Z
grep -v '"event":"soak_pass","host":"validator"' "$T/state/audit.jsonl" > "$T/a2.jsonl"
expect "noop: validator soak_pass missing -> FAIL" 1 "FAIL validator soak_pass" noop "$T/facts.json" "$T/a2.jsonl"
rm -rf "$T"

echo "== real upgrade (new image promoted) is not a no-op =="
fixture; snap; ro run --yes; facts "$RC" 0
expect "upgrade run checked as noop -> FAIL" 1 "FAIL sentry target == recorded prev (no-op)" noop "$T/facts.json"
rm -rf "$T"

echo "== bad-image drill on the sentry canary =="
fixture
jq --arg b "$BAD" '.images[$b] = {Id:$b, RepoDigests:[], Config:{Env:["PATH=/usr/bin"],Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"]}} | .tags["pft-rollout-drill:bad"] = $b' \
  "$T/hosts/relay/state.json" > "$T/x" && mv "$T/x" "$T/hosts/relay/state.json"
gens relay good down good; snap
ro run --yes --no-pull --target pft-rollout-drill:bad; facts "$RC" 0
expect "drill checked as badimage -> PASS" 0 "RESULT: PASS (15/15)" badimage "$T/facts.json"
expect "drill checked as noop -> FAIL" 1 "FAIL exit code 0" noop "$T/facts.json"
tweak '.alert_msgs = 1'
expect "drill: alert topic got a message -> FAIL" 1 "FAIL throwaway alert topic received nothing" badimage "$T/f2.json"
tweak '.alert_msgs = null'
expect "drill: alert topic unread (null) -> FAIL" 1 "FAIL throwaway alert topic received nothing" badimage "$T/f2.json"
tweak '.validator.after.started = "gen-9"'
expect "drill: validator restarted -> FAIL" 1 "FAIL validator StartedAt unchanged" badimage "$T/f2.json"
tweak '.validator.before.started = "" | .validator.after.started = ""'
expect "drill: validator StartedAt empty on both sides -> FAIL" 1 "FAIL validator StartedAt unchanged" badimage "$T/f2.json"
tweak '.logship.newest_us = 1000000000000000'
expect "drill: stale forwarded line -> FAIL" 1 "$LSF" badimage "$T/f2.json"
tweak '.sentry.after.id = $b' --arg b "$BAD"
expect "drill: sentry left on bad image -> FAIL" 1 "FAIL sentry ends on recorded image" badimage "$T/f2.json"
grep -v '"event":"rollback_done"' "$T/state/audit.jsonl" > "$T/a2.jsonl"
expect "drill: rollback_done missing -> FAIL" 1 "FAIL sentry rollback_done" badimage "$T/facts.json" "$T/a2.jsonl"
{ cat "$T/state/audit.jsonl"; jq -c '.host = "validator" | .event = "host_start"' <(grep '"event":"host_start"' "$T/state/audit.jsonl"); } > "$T/a2.jsonl"
expect "drill: validator has an audit event -> FAIL" 1 "FAIL validator: no audit event" badimage "$T/facts.json" "$T/a2.jsonl"
rm -rf "$T"

echo "== bad-image drill whose rollback re-gate also fails =="
fixture
jq --arg b "$BAD" '.images[$b] = {Id:$b, RepoDigests:[], Config:{Env:["PATH=/usr/bin"],Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"]}} | .tags["pft-rollout-drill:bad"] = $b' \
  "$T/hosts/relay/state.json" > "$T/x" && mv "$T/x" "$T/hosts/relay/state.json"
gens relay good down down; snap
ro run --yes --no-pull --target pft-rollout-drill:bad; facts "$RC" 0
expect "drill with failed rollback (exit $RC) -> FAIL" 1 "FAIL exit code 1" badimage "$T/facts.json"
rm -rf "$T"

echo "== usage errors =="
T="$(mktemp -d)"; echo '{}' > "$T/f.json"; : > "$T/a.jsonl"
out="$(bash "$CHECK" sideways "$T/a.jsonl" r "$T/f.json" 2>&1)"; rc=$?
if [ "$rc" = 3 ] && grep -qF "unknown mode sideways" <<<"$out"; then NP=$((NP + 1)); echo "PASS unknown mode -> exit 3"; else NF=$((NF + 1)); echo "FAIL unknown mode (rc=$rc): $out"; fi
echo 'not json' > "$T/f.json"
out="$(bash "$CHECK" noop "$T/a.jsonl" r "$T/f.json" 2>&1)"; rc=$?
if [ "$rc" = 3 ] && grep -qF "facts not JSON" <<<"$out"; then NP=$((NP + 1)); echo "PASS facts not JSON -> exit 3"; else NF=$((NF + 1)); echo "FAIL facts not JSON (rc=$rc): $out"; fi
rm -rf "$T"

echo "TOTAL: $NP passed, $NF failed"
[ "$NF" -eq 0 ]
