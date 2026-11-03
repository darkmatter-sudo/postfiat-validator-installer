#!/usr/bin/env bash
# Offline suite for pft-backfill.sh status/plan: a stub docker answers `inspect` with a fake config-volume path and
# `exec CONTAINER curl ...` with a server_info file (or a failure mode); no root, docker or network.
# Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on hosts hardened by ../mounts.
#   bash backfill/tests/run-tests.sh
# Test conditions are single-quoted on purpose (check() evals them); OUT/RC are read inside them.
# shellcheck disable=SC2016,SC2034
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${SCRIPT:-$HERE/../pft-backfill.sh}"
FX="$HERE/fixtures/live"
BASE="${TEST_TMPDIR:-$HOME/.cache}"
mkdir -p "$BASE"
T="$(mktemp -d "$BASE/pft-backfill-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1${2:+ ($2)}"; }
check() { local name="$1"; shift; if ( eval "$*" ) >/dev/null 2>&1; then ok "$name"; else bad "$name" "$*"; fi; }

# fake root: config volume at /vol/cfg with postfiatd.cfg; textfile dir; conf
R="$T/root"; mkdir -p "$R/vol/cfg" "$R/textfile" "$R/etc" "$T/bin"
SEED_LINE="sBADSEEDNEVERPRINTEDxxxxxxxxx"
make_cfg() { # ONLINE_DELETE (empty = no line)
  { echo "[server]"; echo "port_rpc_admin_local"; echo; echo "[node_seed]"; echo "$SEED_LINE"; echo
    echo "[node_db]"; echo "type=NuDB"; echo "path=/var/lib/postfiatd/db/nudb"
    [ -n "$1" ] && echo "online_delete=$1"; echo "advisory_delete=0"; echo; echo "[ledger_history]"; echo "256"; } > "$R/vol/cfg/postfiatd.cfg"
}
cat > "$T/bin/docker" <<'STUBDOCKER'
#!/usr/bin/env bash
# stub docker: STUB_INFO = server_info file; STUB_MODE = ok|execfail|empty|garbage|inspectfail|nomount
echo "$*" >> "$STUB_CALLS"
case "$1" in
  inspect)
    [ "${STUB_MODE:-ok}" = inspectfail ] && { echo "Error: No such object" >&2; exit 1; }
    [ "${STUB_MODE:-ok}" = nomount ] && { echo ""; exit 0; }
    echo "/vol/cfg" ;;
  exec)
    shift; c="$1"; shift
    [ "$c" = "${STUB_CONTAINER:-postfiatd}" ] || { echo "Error: No such container: $c" >&2; exit 1; }
    [ "$1" = curl ] || { echo "stub: only curl is allowed as the exec target, got $1" >&2; exit 126; }
    case "${STUB_MODE:-ok}" in
      execfail) echo "curl: (7) Failed to connect" >&2; exit 7 ;;
      empty) exit 0 ;;
      garbage) echo "<html>Forbidden</html>"; exit 0 ;;
      *) cat "$STUB_INFO" ;;
    esac ;;
  *) echo "stub docker: unexpected $1" >&2; exit 2 ;;
esac
STUBDOCKER
chmod +x "$T/bin/docker"
export PFT_BACKFILL_ROOT="$R" PFT_BACKFILL_DOCKER="$T/bin/docker" PFT_BACKFILL_CONF="$R/etc/pft-backfill.env"
export TEXTFILE_DIR="$R/textfile" TMPDIR="$T" STUB_CALLS="$T/calls"
printf 'CONTAINER=postfiatd\nHOST_LABEL=validator\n' > "$R/etc/pft-backfill.env"

info_with() { # COMPLETE_LEDGERS SEQ STATE -> file path
  local f="$T/info-$RANDOM.json"
  jq --arg cl "$1" --argjson seq "$2" --arg st "$3" \
    '.result.info.complete_ledgers = $cl | .result.info.validated_ledger.seq = $seq | .result.info.server_state = $st' \
    "$FX/validator-server_info.json" > "$f"
  echo "$f"
}
run() { # -> OUT, RC
  OUT="$(bash "$SCRIPT" "$@" 2>&1)"; RC=$?
}

make_cfg 512
# 1. the real captured fixture: one contiguous range covering the window
export STUB_INFO="$FX/validator-server_info.json" STUB_MODE=ok
run status
check "live fixture: exit 0" '[ "$RC" = 0 ]'
check "live fixture: RESULT PASS" 'grep -q "^RESULT: PASS" <<<"$OUT"'
check "live fixture: window = validated-511..validated" 'grep -qE "window +7728938-7729449" <<<"$OUT"'
check "live fixture: missing 0/0" 'grep -q "missing          interior 0, edge 0" <<<"$OUT"'
check "only curl is exec'd in the container (no sh, no cat)" '! grep -E "^exec " "$STUB_CALLS" | grep -vqE "^exec postfiatd curl "'
run status --json
check "json: host label + fields" 'jq -e ".host == \"validator\" and .online_delete == 512 and .held == 512" <<<"$OUT"'
check "control: the fake cfg does hold the seed" 'grep -q "$SEED_LINE" "$R/vol/cfg/postfiatd.cfg"'
cat > "$T/bin/spy-parser" <<'STUBPARSER'
#!/usr/bin/env bash
# spy: keep a copy of the cfg the parser is given, then run the real parser
prev=""; for a in "$@"; do [ "$prev" = --cfg ] && cp "$a" "$SPY_CFG"; prev="$a"; done
exec python3 "$REAL_PARSER" "$@"
STUBPARSER
chmod +x "$T/bin/spy-parser"
SPY_CFG="$T/spy-cfg" PFT_BACKFILL_PYTHON=bash REAL_PARSER="$HERE/../backfill_parse.py" PFT_BACKFILL_PARSER="$T/bin/spy-parser" bash "$SCRIPT" status >/dev/null 2>&1
check "parser gets [node_db] only (seed section never copied)" 'grep -qx "online_delete=512" "$T/spy-cfg" && ! grep -q "$SEED_LINE" "$T/spy-cfg" && ! grep -q "node_seed" "$T/spy-cfg"'
check "seed never in output (text or json)" '! grep -q "$SEED_LINE" <<<"$OUT" && ! bash "$SCRIPT" status 2>&1 | grep -q "$SEED_LINE"'

# 2. interior gap
export STUB_INFO; STUB_INFO="$(info_with "7728769-7729000,7729010-7729449" 7729449 full)"
run status
check "interior gap: exit 1" '[ "$RC" = 1 ]'
check "interior gap: 9 missing" 'grep -q "missing          interior 9, edge 0" <<<"$OUT"'
check "interior gap: listed" 'grep -q "gap              interior 7729001-7729009 (9)" <<<"$OUT"'
run status --prom "$R/textfile/x.prom"
check "prom: file written 0644" '[ "$(stat -c %a "$R/textfile/x.prom")" = 644 ]'
check "prom: interior 9" 'grep -qx "pft_backfill_missing_ledgers{node=\"validator\",kind=\"interior\"} 9" "$R/textfile/x.prom"'
check "prom: up 1" 'grep -qx "pft_backfill_up{node=\"validator\"} 1" "$R/textfile/x.prom"'
check "prom: no temp file left" '[ "$(ls "$R/textfile" | wc -l)" = 1 ]'
run plan --max-ledgers 3
check "plan: newest first, capped" '[ "$OUT" = "$(printf "7729009\n7729008\n7729007")" ]'
run plan --max-ledgers 50
check "plan: interior before edge, all 9" '[ "$(wc -l <<<"$OUT")" = 9 ] && [ "$(tail -1 <<<"$OUT")" = 7729001 ]'

# 3. edge gap (restart, history not yet acquired)
STUB_INFO="$(info_with "7729300-7729449" 7729449 full)"
run status
check "edge gap: exit 1, edge 362" '[ "$RC" = 1 ] && grep -q "interior 0, edge 362" <<<"$OUT"'

# 4. node not full, no gap
STUB_INFO="$(info_with "7728769-7729449" 7729449 syncing)"
run status
check "not full: exit 1 even without a gap" '[ "$RC" = 1 ] && grep -q "server_state     syncing" <<<"$OUT"'

# 5. online_delete unset = full history: nothing to account
make_cfg ""
STUB_INFO="$FX/validator-server_info.json"
run status
check "no online_delete: exit 0, nothing to account" '[ "$RC" = 0 ] && grep -q "unset (full history" <<<"$OUT"'
make_cfg 512

# 6. failures: every one exits 2, and --textfile records up 0
for m in execfail empty garbage inspectfail nomount; do
  export STUB_MODE="$m"
  rm -f "$R/textfile/pft_backfill.prom"
  run status --textfile
  check "$m: exit 2" '[ "$RC" = 2 ]'
  check "$m: textfile up 0" 'grep -qx "pft_backfill_up{node=\"validator\"} 0" "$R/textfile/pft_backfill.prom"'
done
STUB_MODE=garbage; run status
check "garbage answer: message names the RPC" 'grep -q "rpc server_info: not a JSON result" <<<"$OUT"'
STUB_MODE=ok
mv "$R/vol/cfg/postfiatd.cfg" "$R/vol/cfg/x"; run status
check "cfg missing: exit 2" '[ "$RC" = 2 ] && grep -q "no postfiatd.cfg" <<<"$OUT"'
mv "$R/vol/cfg/x" "$R/vol/cfg/postfiatd.cfg"

# 7. config / usage guards
printf 'CONTAINER=postfiatd\nHOST_LABEL=Bad Label\n' > "$R/etc/pft-backfill.env"; run status
check "bad HOST_LABEL: exit 2" '[ "$RC" = 2 ] && grep -q "bad HOST_LABEL" <<<"$OUT"'
printf 'CONTAINER=x;rm\nHOST_LABEL=validator\n' > "$R/etc/pft-backfill.env"; run status
check "bad CONTAINER: exit 2" '[ "$RC" = 2 ] && grep -q "bad CONTAINER" <<<"$OUT"'
printf 'CONTAINER=postfiatd-sentry\nHOST_LABEL=sentry\n' > "$R/etc/pft-backfill.env"
export STUB_CONTAINER=postfiatd-sentry STUB_INFO="$FX/sentry-server_info.json"; run status --json
check "sentry conf: container + label used" '[ "$RC" = 0 ] && jq -e ".host == \"sentry\"" <<<"$OUT"'
export STUB_CONTAINER=postfiatd STUB_INFO="$FX/validator-server_info.json"
printf 'CONTAINER=postfiatd\nHOST_LABEL=validator\n' > "$R/etc/pft-backfill.env"
run; check "no command: exit 3" '[ "$RC" = 3 ]'
run bogus; check "unknown command: exit 3" '[ "$RC" = 3 ]'
run status --nope; check "unknown option: exit 3" '[ "$RC" = 3 ]'
run plan --max-ledgers x; check "plan non-numeric cap: exit 3" '[ "$RC" = 3 ]'
run plan --max-ledgers 0; check "plan cap 0: exit 2 (parser range 1..10000)" '[ "$RC" = 2 ]'
check "no work dir left behind" '[ -z "$(find "$T" -maxdepth 1 -name "pft-backfill.*")" ]'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
