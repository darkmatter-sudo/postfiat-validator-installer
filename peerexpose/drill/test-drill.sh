#!/usr/bin/env bash
# Offline tests for the live drill's own logic, run BEFORE the live drill:
#   1 lib.sh parsers on the real output format: synthetic audit summaries in fixtures/ (4 and 11
#     violations = one- and two-digit) and every "RESULT:" line format taken from pft-peerexpose.sh's source
#   2 check-drill.sh: a good synthetic run passes all checks; each negative fails exactly the check it names
#   3 redact.py: positive control passes; a planted leak is found by check; a clean file passes check
# No network, no docker, no root. Usage: bash drill/test-drill.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh source-path=SCRIPTDIR
. "$HERE/lib.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok() { if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "ok   $1"; else FAIL=$((FAIL + 1)); echo "FAIL $1 (got '$2', want '$3')"; fi; }

echo "== 1. parsers"
ok "audit sentry fixture: violations" "$(parse_viol "$HERE/fixtures/audit-sentry-4viol.txt")" 4
ok "audit validator fixture: violations (two digits)" "$(parse_viol "$HERE/fixtures/audit-validator-11viol.txt")" 11
ok "audit fixture: no RESULT verdict word" "$(parse_result "$HERE/fixtures/audit-sentry-4viol.txt")" ""
n=0
while IFS= read -r msg; do
  n=$((n + 1))
  want="$(sed -E 's/^RESULT: ([A-Z][A-Z ]*[A-Z]).*/\1/' <<<"$msg")"
  { echo "2026-10-28T06:30:00Z   gate: state=full peers=11 required_peers=1/1 audit_violations=0"
    echo "2026-10-28T06:30:01Z $msg"; } > "$T/out"
  ok "RESULT line from source: $want" "$(parse_result "$T/out")" "$want"
done < <(grep -oE 'log "RESULT: [^"]*"' "$HERE/../pft-peerexpose.sh" | sed -E 's/^log "//; s/"$//' | sort -u)
ok "RESULT formats found in pft-peerexpose.sh" "$([ "$n" -ge 7 ] && echo yes || echo "no ($n)")" yes
printf 'REFUSED: pft-maint data-collection lock held: x\n' > "$T/out"
ok "REFUSED (no RESULT line) parses empty" "$(parse_result "$T/out")" ""

echo "== 1b. peer_has (shape of the live sentry's peers answer: the validator connects inbound via docker-proxy)"
K1=n94YefruMzW9LEkaLZDrjb7oksDCQzWJpiaHRczyPMwwamiEWJBQ; K2=n9Lkb3sHf7kVQx2pR8mYc4dTzN6aWuE1gJhX5vB9rCnD2eFqGtUs
cat > "$T/peers.json" <<JSON
{"result":{"peers":[{"address":"172.17.0.1:43120","public_key":"$K1","inbound":true},{"address":"198.51.100.7:2559","public_key":"$K2"},{"address":"[::ffff:192.0.2.20]:2559","public_key":"n9Other"}],"status":"success"}}
JSON
ok "inbound validator: real address not listed, key matches" "$(peer_has 203.0.113.5 "$K1" < "$T/peers.json")" true
ok "inbound validator: address only (no key) does not match" "$(peer_has 203.0.113.5 "" < "$T/peers.json")" false
ok "outbound peer: address matches without a key" "$(peer_has 198.51.100.7 "" < "$T/peers.json")" true
ok "IPv4-mapped address matches" "$(peer_has 192.0.2.20 "" < "$T/peers.json")" true
ok "address prefix does not match (192.0.2.2 vs 192.0.2.20)" "$(peer_has 192.0.2.2 "" < "$T/peers.json")" false
ok "key is exact, not a prefix" "$(peer_has 203.0.113.5 "${K1:0:20}" < "$T/peers.json")" false
ok "one changed key char does not match" "$(peer_has 203.0.113.5 "${K1%?}x" < "$T/peers.json")" false
ok "empty / error answer -> false" "$(peer_has 198.51.100.7 "$K1" <<<'{"error":"x"}')" false

echo "== 2. check-drill.sh"
good_steps() {
  jq -nc '
    def a(s; e; v): {step: s, exit: e, result: null, violations: v};
    def r(s; w): {step: s, exit: 0, result: w, violations: null};
    a("audit-sentry-initial"; 1; 4), a("audit-validator-initial"; 1; 11), r("apply-sentry"; "APPLIED"),
    a("audit-sentry-applied"; 0; 0), r("rollback-sentry"; "ROLLED BACK"), a("audit-sentry-rolledback"; 1; 4),
    r("reapply-sentry"; "APPLIED"), a("audit-sentry-reapplied"; 0; 0), r("apply-validator"; "APPLIED"),
    a("audit-validator-applied"; 0; 0), a("audit-sentry-final"; 0; 0), a("audit-validator-final"; 0; 0)'
}
good_facts() {
  jq -nc '{alert_msgs: 0, maint_msgs: 8, restore_ok: true, redaction_control: 0, dry: false, reset: false,
    final: {validator: {state: "full", peers: 11, has_other: true}, sentry: {state: "full", peers: 11, has_other: true}}}'
}
run_case() { # NAME STEPS_JQ FACTS_JQ EXPECT_FAIL_CHECK ("" = expect PASS)
  good_steps | jq -c "$2" > "$T/steps.jsonl"; good_facts | jq -c "$3" > "$T/facts.json"
  local out rc fails
  out="$(bash "$HERE/check-drill.sh" "$T/steps.jsonl" "$T/facts.json")"; rc=$?
  fails="$(grep '^FAIL ' <<<"$out" | sed 's/^FAIL //')"
  if [ -z "$4" ]; then
    ok "$1: PASS, exit 0, $(grep -c '^PASS ' <<<"$out") checks" "$rc:$(grep -c '^RESULT: PASS' <<<"$out")" "0:1"
  else
    ok "$1: exit 1 and fails only '$4'" "$rc|$fails" "1|$4"
  fi
}
run_case "good run" . . ""
run_case "validator applied before sentry" \
  'if .step == "apply-sentry" then .step = "apply-validator" elif .step == "apply-validator" then .step = "apply-sentry" else . end' . \
  "12 steps, each once, in order (sentry first)"
run_case "rollback did not bring exposure back" 'if .step == "audit-sentry-rolledback" then .exit = 0 | .violations = 0 else . end' . \
  "$(printf '%s\n' "audit-sentry-rolledback finds violations (exit 1)" "sentry rollback restores the initial exposure (same violation count)")"
run_case "rollback exposure differs (11 vs 4, two digits)" 'if .step == "audit-sentry-rolledback" then .violations = 11 else . end' . \
  "sentry rollback restores the initial exposure (same violation count)"
run_case "apply auto-rolled back (ROLLED BACK, exit 2)" 'if .step == "apply-validator" then .exit = 2 | .result = "ROLLED BACK" else . end' . \
  "apply-validator APPLIED (exit 0)"
run_case "manual rollback exit 2" 'if .step == "rollback-sentry" then .exit = 2 else . end' . "rollback-sentry ROLLED BACK (exit 0)"
run_case "audit summary not parsed (violations null)" 'if .step == "audit-validator-final" then .violations = null else . end' . \
  "audit-validator-final 0 violations (exit 0)"
run_case "initial audit unreachable (exit 2)" 'if .step == "audit-validator-initial" then .exit = 2 | .violations = 0 else . end' . \
  "audit-validator-initial finds violations (exit 1)"
run_case "step recorded twice" '., (select(.step == "audit-sentry-final"))' . \
  "$(printf '%s\n' "12 steps, each once, in order (sentry first)" "audit-sentry-final 0 violations (exit 0)")"
run_case "an alert reached the throwaway topic" . '.alert_msgs = 1' "throwaway ALERT topic received nothing"
run_case "ALERT topic unreadable (null)" . '.alert_msgs = null' "throwaway ALERT topic received nothing"
run_case "no MAINT messages" . '.maint_msgs = 0' "throwaway MAINT topic received the windows"
run_case "sentry lost the validator link" . '.final.sentry.has_other = false' "sentry sees the other host as a connected peer"
run_case "validator still syncing" . '.final.validator.state = "syncing"' "validator full|proposing at the end"
run_case "notifier restore mismatch" . '.restore_ok = false' "notifiers restored (sha256 match, drill files removed)"
run_case "redaction control failed" . '.redaction_control = 1' "redaction positive control passed"
run_case "dry run" . '.dry = true' "not a dry run"
RS='{step: "reset-sentry", exit: 0, result: "ROLLED BACK", violations: null}'
run_case "reset first, reset=true" "if .step == \"audit-sentry-initial\" then $RS, . else . end" '.reset = true' ""
run_case "reset recorded but reset=false" "if .step == \"audit-sentry-initial\" then $RS, . else . end" . \
  "$(printf '%s\n' "reset-sentry recorded iff the sentry carried a block (facts.reset is a bool)" "12 steps, each once, in order (sentry first)")"
run_case "reset=true but no reset step" . '.reset = true' \
  "$(printf '%s\n' "reset-sentry recorded iff the sentry carried a block (facts.reset is a bool)" "reset-sentry ROLLED BACK (exit 0)" "12 steps, each once, in order (sentry first)")"
run_case "reset failed (exit 2)" "if .step == \"audit-sentry-initial\" then ($RS | .exit = 2), . else . end" '.reset = true' \
  "reset-sentry ROLLED BACK (exit 0)"
run_case "reset after the initial audit" "if .step == \"audit-sentry-initial\" then ., $RS else . end" '.reset = true' \
  "12 steps, each once, in order (sentry first)"
run_case "reset fact missing" . 'del(.reset)' "reset-sentry recorded iff the sentry carried a block (facts.reset is a bool)"
: > "$T/empty.jsonl"; good_facts > "$T/facts.json"
out="$(bash "$HERE/check-drill.sh" "$T/empty.jsonl" "$T/facts.json")"; rc=$?
ok "no steps at all: exit 1, RESULT FAIL" "$rc:$(grep -c '^RESULT: FAIL' <<<"$out")" "1:1"

echo "== 2b. has_block (pft-peerexpose MARK line)"
MARKL="$(grep -oE '^MARK="[^"]*"' "$HERE/../pft-peerexpose.sh" | sed -E 's/^MARK="//; s/"$//')"
ok "MARK found in pft-peerexpose.sh" "$([ -n "$MARKL" ] && echo yes || echo no)" yes
ok "config with the MARK line -> true" "$(printf '[server]\nport_peer\n\n%s\n[crawl]\noverlay=0\n' "$MARKL" | has_block)" true
ok "original config (no block) -> false" "$(printf '[server]\nport_peer\n[crawl]\noverlay=0\n' | has_block)" false
ok "indented/quoted mention is not a block" "$(printf '  # pft-peerexpose managed block\nx=\"# pft-peerexpose managed block\"\n' | has_block)" false
ok "empty input -> false" "$(has_block < /dev/null)" false

echo "== 3. redact.py"
printf 'ip\t203.0.113.77\nip\t198.51.100.9\nkey\tn9KfakeKEYfakeKEYfakeKEYfakeKEYfakeKEYfakeKEYfake12\ntopic\tpeerdrill-0123456789abcdef01234567\nuser\tdrilluser\n' > "$T/lit"
python3 -u "$HERE/redact.py" control --literals "$T/lit" > "$T/ctl"; rc=$?
ok "positive control: exit 0, all PASS" "$rc:$(grep -c '^  FAIL' "$T/ctl"):$(grep -c 'REDACTION CONTROL: PASS' "$T/ctl")" "0:0:1"
printf 'audit https://203.0.113.77:2559\npeer 198.51.100.9:51235 key n9KfakeKEYfakeKEYfakeKEYfakeKEYfakeKEYfakeKEYfake12\nby drilluser\n' > "$T/raw"
python3 "$HERE/redact.py" filter --literals "$T/lit" < "$T/raw" > "$T/red"
python3 "$HERE/redact.py" check --literals "$T/lit" "$T/raw" > "$T/c1"; rc1=$?
python3 "$HERE/redact.py" check --literals "$T/lit" "$T/red" > "$T/c2"; rc2=$?
ok "check finds the planted leaks in the raw file" "$rc1:$(grep -c 'REDACTION: LEAK' "$T/c1")" "1:1"
ok "check is clean on the filtered file" "$rc2:$(grep -c 'REDACTION: CLEAN' "$T/c2")" "0:1"
ok "filtered file keeps the port and the structure" "$(head -1 "$T/red")" "audit https://<redacted-ip>:2559"
echo 'other 192.0.2.44 unlisted' > "$T/raw2"
python3 "$HERE/redact.py" check --literals "$T/lit" "$T/raw2" > /dev/null; ok "unlisted IPv4 is still a leak (pattern)" "$?" 1
ok "check output never prints a value" "$(grep -cE '203\.0\.113|198\.51\.100|n9Kfake' "$T/c1")" 0

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
