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
# stub: docker exec CONTAINER curl ... -> validators.json of the case
echo "docker $*" >> "$STUB_LOG"
[ "$1" = exec ] && cat "$CASE_DIR/validators.json"
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

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
