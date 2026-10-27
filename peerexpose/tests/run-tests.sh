#!/usr/bin/env bash
# Offline tests for pft-peerexpose.sh: curl, sudo and docker are PATH stubs that answer from tests/fixtures/<case>/.
# No network, no docker, no root. Usage: bash tests/run-tests.sh [path/to/pft-peerexpose.sh]
# Conditions are single-quoted on purpose: check() evals them after run() has set RC and $OUT.
# shellcheck disable=SC2016,SC2034
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${1:-$HERE/../pft-peerexpose.sh}"
FIX="$HERE/fixtures"
STUBS="$(mktemp -d)"
trap 'rm -rf "$STUBS"' EXIT

cat > "$STUBS/curl" <<'EOF'
#!/usr/bin/env bash
# stub: -o FILE, -w FMT (only %{http_code}), last arg = URL (or admin RPC POST through docker exec)
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift ;; -w|-m|-d) shift ;; -*) ;; *) url="$1" ;; esac
  shift
done
echo "$url" >> "$STUB_LOG"
path="/${url#*://*/}"
case "$path" in /crawl) ep=crawl ;; /vl/*) ep=vl ;; /health) ep=health ;; *) ep=none ;; esac
code="$(cat "$CASE_DIR/$ep.code" 2>/dev/null || echo 404)"
if [ "$code" = 000 ]; then printf '000'; exit 7; fi
if [ -n "$out" ]; then cat "$CASE_DIR/$ep.body" > "$out"; else cat "$CASE_DIR/$ep.body"; fi
printf '%s' "$code"
EOF
cat > "$STUBS/sudo" <<'EOF'
#!/usr/bin/env bash
[ "$1" = -n ] && shift
exec "$@"
EOF
cat > "$STUBS/docker" <<'EOF'
#!/usr/bin/env bash
# stub: docker exec CONTAINER cat CFG -> postfiatd.cfg of the case (missing = exit 1);
#       docker exec CONTAINER curl ... -> validators.json of the case
echo "docker $*" >> "$STUB_LOG"
[ "$1" = exec ] || exit 0
if [ "$3" = cat ]; then cat "$CASE_DIR/postfiatd.cfg" 2>/dev/null; exit; fi
cat "$CASE_DIR/validators.json"
EOF
cat > "$STUBS/ssh" <<'EOF'
#!/usr/bin/env bash
# stub: record the full ssh command line, then run the remote command string locally
echo "ssh $*" >> "$STUB_LOG"
eval "${*: -1}"
EOF
chmod +x "$STUBS"/*

PASS=0; FAIL=0
OUT="$STUBS/out"; export STUB_LOG="$STUBS/calls"

# run CASE ARGS... -> sets RC, output in $OUT
run() {
  local c="$1"; shift
  : > "$STUB_LOG"
  CASE_DIR="$FIX/$c" PATH="$STUBS:$PATH" bash "$SCRIPT" "$@" > "$OUT" 2>&1
  RC=$?
}
ok() { PASS=$((PASS + 1)); echo "PASS $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; sed 's/^/    | /' "$OUT"; }
# check NAME CONDITION (evaluated in a subshell, so an exit inside cannot abort the suite)
check() {
  local name="$1" cond="$2"
  if (eval "$cond") >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
# field FIELD -> "status count policy" from the last --json run
field() { jq -r --arg f "$1" '.fields[] | select(.field == $f) | "\(.status) \(.count) \(.policy)"' "$OUT"; }

# --- validator, fully open, 12 peers (two-digit count)
run open12 audit --role validator --json
check "open12 validator exit 1" '[ "$RC" -eq 1 ]'
check "open12 peer_ip disclosed n=12 VIOLATION" '[ "$(field crawl.overlay.peer_ip)" = "disclosed 12 VIOLATION" ]'
check "open12 peer_pubkey n=12" '[ "$(field crawl.overlay.peer_pubkey)" = "disclosed 12 VIOLATION" ]'
check "open12 pubkey_node VIOLATION" '[ "$(field crawl.server.pubkey_node)" = "disclosed 1 VIOLATION" ]'
check "open12 vl served VIOLATION" '[ "$(field vl.list)" = "disclosed 1 VIOLATION" ]'
check "open12 counts restricted ok" '[ "$(field crawl.counts)" = "restricted 0 ok" ]'
check "open12 health allowed" '[ "$(field health.details)" = "restricted 0 ok" ]'
check "open12 violations=11" '[ "$(jq .violations "$OUT")" = 11 ]'
check "open12 vl key taken from local admin RPC" 'grep -q "/vl/EDFAKEPUB$" "$STUB_LOG"'
check "open12 no address or key in output" '! grep -E "192\.0\.2|FAKEPEERKEY|FAKENODEKEY" "$OUT"'

# --- one peer (lower boundary of "disclosed")
run open1 audit --role validator --json
check "open1 peer_ip disclosed n=1" '[ "$(field crawl.overlay.peer_ip)" = "disclosed 1 VIOLATION" ]'

# --- same open node judged as a sentry: only overlay/counts are violations
run open12 audit --role sentry --json
check "open12 sentry exit 1" '[ "$RC" -eq 1 ]'
check "open12 sentry violations=4 (overlay only)" '[ "$(jq .violations "$OUT")" = 4 ]'
check "open12 sentry pubkey_node allowed" '[ "$(field crawl.server.pubkey_node)" = "disclosed 1 ok" ]'
check "open12 sentry vl allowed" '[ "$(field vl.list)" = "disclosed 1 ok" ]'

# --- hardened sentry: server + unl + vl public, no overlay
run sentry_hardened audit --role sentry --json
check "sentry_hardened exit 0" '[ "$RC" -eq 0 ]'
check "sentry_hardened peer_ip restricted" '[ "$(field crawl.overlay.peer_ip)" = "restricted 0 ok" ]'
run sentry_hardened audit --role validator --json
check "sentry_hardened as validator exit 1" '[ "$RC" -eq 1 ]'
run sentry_counts audit --role sentry --json
check "sentry counts disclosed = VIOLATION" '[ "$(field crawl.counts)" = "disclosed 1 VIOLATION" ] && [ "$RC" -eq 1 ]'

# --- hardened validator: /crawl 403, /vl 404
run restricted audit --role validator --json
check "restricted validator exit 0" '[ "$RC" -eq 0 ]'
check "restricted crawl.endpoint restricted (http 403)" '[ "$(field crawl.endpoint)" = "restricted 0 ok" ] && grep -q "http 403" "$OUT"'
check "restricted vl restricted" '[ "$(field vl.list)" = "restricted 0 ok" ]'
run restricted audit --role validator
check "restricted text output RESULT line" 'grep -q "^RESULT: 0 violation(s), 0 error(s)$" "$OUT"'

# --- errors
run unreachable audit --role validator --json
check "unreachable exit 2" '[ "$RC" -eq 2 ] && grep -q "unreachable" "$OUT"'
run crawl_nonjson audit --role validator
check "crawl 200 non-JSON exit 2" '[ "$RC" -eq 2 ] && grep -q "non-JSON" "$OUT"'

# --- /vl answering 200 without a blob is not a served list
run vl_no_blob audit --role validator --json
check "vl 200 without blob = restricted" '[ "$(field vl.list)" = "restricted 0 ok" ] && [ "$RC" -eq 0 ]'

# --- /health with details (unhealthy node) is reported but allowed for both roles
run health_details audit --role validator --json
check "health details disclosed, allowed" '[ "$(field health.details)" = "disclosed 2 ok" ] && [ "$RC" -eq 0 ]'

# --- key sources
run no_rpc_keys audit --role validator --json
check "no RPC keys -> dummy key probed" 'grep -q "/vl/ED0000" "$STUB_LOG"'
run open12 audit --role validator --vl-key EDGIVEN --url https://203.0.113.9:2559 --json
check "--vl-key and --url used, RPC not called" 'grep -q "^https://203.0.113.9:2559/vl/EDGIVEN$" "$STUB_LOG" && ! grep -q "^docker" "$STUB_LOG"'

# --- usage
run open12 audit
check "missing --role exit 3" '[ "$RC" -eq 3 ]'
run open12 audit --role relay
check "bad role exit 3" '[ "$RC" -eq 3 ]'

# --- render / effective / plan
R="$STUBS/rendered.cfg"
want_v="crawl=0 overlay=1 server=1 counts=0 unl=1 vl=0"
want_s="crawl=1 overlay=0 server=1 counts=0 unl=1 vl=1"
run cfg_stock plan --role validator
check "plan stock validator: CHANGE NEEDED, exit 0" '[ "$RC" -eq 0 ] && grep -q "^RESULT: CHANGE NEEDED" "$OUT"'
check "plan stock validator: effective now = defaults" 'grep -q "effective now:   crawl=1 overlay=1 server=1 counts=0 unl=1 vl=1$" "$OUT"'
check "plan stock validator: effective after = policy" 'grep -q "effective after: $want_v$" "$OUT"'
check "plan stock validator: validate OK" 'grep -q "validate: OK" "$OUT"'
check "plan output has no address" '! grep -q "192\.0\.2" "$OUT"'
run cfg_stock plan --role sentry
check "plan stock sentry: effective after = policy" 'grep -q "effective after: $want_s$" "$OUT" && [ "$RC" -eq 0 ]'
check "plan reads the cfg through docker exec" 'grep -q "^docker exec postfiatd cat /etc/postfiatd/postfiatd.cfg$" "$STUB_LOG"'

PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator < "$FIX/cfg_stock/postfiatd.cfg" > "$R"
check "render keeps every non-blank line outside the block" '[ "$(diff <(grep -v "^$" "$FIX/cfg_stock/postfiatd.cfg") <(grep -v "^$" "$R") | grep -c "^<")" = 0 ]'
check "render keeps the commented # [crawl] docs" '[ "$(grep -c "^#.*\[crawl\]" "$R")" = 2 ]'
check "render validator: one [crawl] with bare 0, [vl] enable=0" '[ "$(grep -c "^\[crawl\]$" "$R")" = 1 ] && grep -A1 "^\[crawl\]$" "$R" | grep -qx 0 && grep -A1 "^\[vl\]$" "$R" | grep -qx "enable=0"'
check "render is idempotent" 'PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator < "$R" | cmp -s - "$R"'
check "render sentry then validator = validator" 'PATH="$STUBS:$PATH" bash "$SCRIPT" render --role sentry < "$R" | PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator | cmp -s - "$R"'

# a cfg that is already rendered: plan says NO CHANGE (case dir built on the fly)
mkdir -p "$STUBS/cfg_done"; cp "$R" "$STUBS/cfg_done/postfiatd.cfg"
: > "$STUB_LOG"; CASE_DIR="$STUBS/cfg_done" PATH="$STUBS:$PATH" bash "$SCRIPT" plan --role validator > "$OUT" 2>&1; RC=$?
check "plan on rendered cfg: NO CHANGE" '[ "$RC" -eq 0 ] && grep -q "^RESULT: NO CHANGE" "$OUT"'
: > "$STUB_LOG"; CASE_DIR="$STUBS/cfg_done" PATH="$STUBS:$PATH" bash "$SCRIPT" plan --role sentry > "$OUT" 2>&1; RC=$?
check "plan validator-rendered cfg as sentry: CHANGE NEEDED" '[ "$RC" -eq 0 ] && grep -q "^RESULT: CHANGE NEEDED" "$OUT"'

# operator-made [Crawl]/[VL] sections (mixed case, mid-file) are replaced, not duplicated
run cfg_existing plan --role validator
check "existing sections: effective now parsed (counts = 1 with spaces)" 'grep -q "effective now:   crawl=1 overlay=1 server=1 counts=1 unl=1 vl=1$" "$OUT"'
check "existing sections: validate OK, after = policy" 'grep -q "validate: OK" "$OUT" && grep -q "effective after: $want_v$" "$OUT"'
check "existing sections: diff removes the old lines" 'grep -q "^    < counts = 1$" "$OUT"'
PATH="$STUBS:$PATH" bash "$SCRIPT" render --role sentry < "$FIX/cfg_existing/postfiatd.cfg" > "$R"
check "existing sections: exactly one [crawl] and one [vl] after render" '[ "$(grep -ciE "^\[crawl\]$" "$R")" = 1 ] && [ "$(grep -ciE "^\[vl\]$" "$R")" = 1 ]'
check "existing sections: [ips_fixed] kept" 'grep -A1 "^\[ips_fixed\]$" "$R" | grep -q "^192.0.2.20 2559$"'

run cfg_unreadable plan --role validator
check "plan with unreadable cfg exit 2" '[ "$RC" -eq 2 ] && grep -q "cannot read" "$OUT"'

# validate: positive (rendered stock) and one negative per rule, each asserting its own reason
V="$FIX/cfg_validate"
vrun() { PATH="$STUBS:$PATH" bash "$SCRIPT" validate "$@" > "$OUT" 2>&1; RC=$?; }
PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator < "$V/old.cfg" > "$R"
vrun --role validator --old "$V/old.cfg" --new "$R"
check "validate rendered cfg: exit 0, OK" '[ "$RC" -eq 0 ] && grep -q "^validate: OK" "$OUT"'
vrun --role validator --old "$V/old.cfg" --new "$V/extra-change.cfg"
check "validate rejects a change outside [crawl]/[vl]" '[ "$RC" -eq 1 ] && grep -q "lines outside \[crawl\]/\[vl\] would change" "$OUT"'
vrun --role validator --old "$V/old.cfg" --new "$V/two-crawl.cfg"
check "validate rejects two [crawl] sections" '[ "$RC" -eq 1 ] && grep -q "exactly one \[crawl\] section, found 2" "$OUT"'
vrun --role validator --old "$V/old.cfg" --new "$V/no-vl.cfg"
check "validate rejects a missing [vl] section" '[ "$RC" -eq 1 ] && grep -q "exactly one \[vl\] section, found 0" "$OUT"'
vrun --role sentry --old "$V/old.cfg" --new "$R"
check "validate rejects the validator block for a sentry" '[ "$RC" -eq 1 ] && grep -q "effective settings crawl=0 .* != wanted crawl=1 overlay=0" "$OUT"'
vrun --role validator --old "$V/old.cfg"
check "validate without --new exit 3" '[ "$RC" -eq 3 ]'

# remote target through ssh
run cfg_stock plan --role sentry --ssh relayhost --container postfiatd-sentry
check "plan --ssh uses ssh BatchMode + sudo -n docker exec" 'grep -q "^ssh -o BatchMode=yes -o ConnectTimeout=10 relayhost sudo -n docker exec postfiatd-sentry cat /etc/postfiatd/postfiatd.cfg" "$STUB_LOG" && [ "$RC" -eq 0 ]'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
