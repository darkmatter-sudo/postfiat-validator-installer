#!/usr/bin/env bash
# Offline suite for `pft-backfill repair`: a stub docker hands every `exec CONTAINER curl -d BODY` to stub_node.py
# (state in a JSON file), a stub curl plays the public RPC, a stub pft-maint reports the window, and a fake clock
# advances only when the script sleeps. No root, docker, network or real waiting.
# Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on hosts hardened by ../mounts.
#   bash backfill/tests/run-repair-tests.sh
# Test conditions are single-quoted on purpose (check() evals them); OUT/RC are read inside them.
# shellcheck disable=SC2016,SC2034
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${SCRIPT:-$HERE/../pft-backfill.sh}"
STUB="$HERE/stub_node.py"
BASE="${TEST_TMPDIR:-$HOME/.cache}"
mkdir -p "$BASE"
T="$(mktemp -d "$BASE/pft-backfill-rtest.XXXXXX")"
trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1${2:+ ($2)}"; }
check() { local name="$1"; shift; if ( eval "$*" ) >/dev/null 2>&1; then ok "$name"; else bad "$name" "$*"; fi; }

R="$T/root"; mkdir -p "$R/vol/cfg" "$R/textfile" "$R/etc" "$T/bin"
printf '[node_seed]\nsNEVERPRINTED\n\n[node_db]\ntype=NuDB\nonline_delete=512\n' > "$R/vol/cfg/postfiatd.cfg"
printf 'CONTAINER=postfiatd\nHOST_LABEL=sentry\nPUBLIC_RPC=https://rpc.example.invalid/\n' > "$R/etc/pft-backfill.env"

cat > "$T/bin/docker" <<'STUBDOCKER'
#!/usr/bin/env bash
echo "$*" >> "$STUB_CALLS"
case "$1" in
  inspect) echo "/vol/cfg" ;;
  exec)
    shift; [ "$1" = postfiatd ] || exit 1; shift
    [ "$1" = curl ] || { echo "stub: only curl may be exec'd" >&2; exit 126; }
    body=""; prev=""; for a in "$@"; do [ "$prev" = -d ] && body="$a"; prev="$a"; done
    exec python3 "$STUB" "$STATE" node "$body" ;;
  *) exit 2 ;;
esac
STUBDOCKER
cat > "$T/bin/curl" <<'STUBCURL'
#!/usr/bin/env bash
echo "curl $*" >> "$STUB_CALLS"
body=""; prev=""; for a in "$@"; do [ "$prev" = -d ] && body="$a"; prev="$a"; done
exec python3 "$STUB" "$STATE" public "$body"
STUBCURL
cat > "$T/bin/sleep" <<'STUBSLEEP'
#!/usr/bin/env bash
echo "sleep $1" >> "$STUB_CALLS"
echo $(( $(cat "$CLOCK") + $1 )) > "$CLOCK"
STUBSLEEP
cat > "$T/bin/now" <<'STUBNOW'
#!/usr/bin/env bash
cat "$CLOCK"
STUBNOW
cat > "$T/bin/pft-maint" <<'STUBMAINT'
#!/usr/bin/env bash
case "${STUB_MAINT:-none}" in
  fail) exit 1 ;;
  garbage) echo "not json" ;;
  *) printf '{"time":"x","window":"%s","locks":[]}\n' "$STUB_MAINT" ;;
esac
STUBMAINT
chmod +x "$T/bin/"*
export PFT_BACKFILL_ROOT="$R" PFT_BACKFILL_DOCKER="$T/bin/docker" PFT_BACKFILL_CONF="$R/etc/pft-backfill.env"
export PFT_BACKFILL_CURL="$T/bin/curl" PFT_BACKFILL_SLEEP="$T/bin/sleep" PFT_BACKFILL_NOW="$T/bin/now"
export PFT_BACKFILL_MAINT="$T/bin/pft-maint" PFT_BACKFILL_LOCK="$T/lock/pft-backfill.lock"
export TEXTFILE_DIR="$R/textfile" TMPDIR="$T" STUB_CALLS="$T/calls" STATE="$T/state.json" CLOCK="$T/clock" STUB

V=7729449
setup() { # MODE TARGET ARRIVE_AFTER [STATE] [HELD_JSON]
  printf '%s\n' "{\"validated\":$V,\"held\":${5:-[[7728938,7729000],[7729010,$V]]},\"state\":\"${4:-full}\",\"arrive_after\":$3,\"mode\":\"$1\",\"target\":$2}" > "$STATE"
  echo 1000 > "$CLOCK"; : > "$STUB_CALLS"; export STUB_MAINT=none
}
run() { OUT="$(bash "$SCRIPT" "$@" 2>&1)"; RC=$?; }
lr_calls() { grep -c '"method":"ledger_request"' "$STUB_CALLS"; }
methods_ok() { ! grep '^exec ' "$STUB_CALLS" | grep -o '"method":"[a-z_]*"' | grep -vqE '"(server_info|ledger|ledger_request)"'; }

# 1. dry run is the default: plan printed, nothing requested
setup ok 0 2
run repair --max-ledgers 3
check "dry run: exit 0, DRY RUN result" '[ "$RC" = 0 ] && grep -q "^RESULT: DRY RUN" <<<"$OUT"'
check "dry run: plan newest first" 'grep -q "plan: 3 ledger(s), newest first: 7729009 7729008 7729007" <<<"$OUT"'
check "dry run: 0 ledger_request calls" '[ "$(lr_calls)" = 0 ]'
check "dry run: before line shows the gap" 'grep -q "before: complete_ledgers 7728938-7729000,7729010-7729449 .* missing interior 9, edge 0" <<<"$OUT"'

# 2. apply: every ledger arrives after 2 polls and verifies
setup ok 0 2
run repair --apply --max-ledgers 3
check "apply: exit 0 PASS" '[ "$RC" = 0 ] && grep -q "^RESULT: PASS - every planned ledger" <<<"$OUT"'
check "apply: counts" 'grep -q "counts: planned 3 fetched 3 verified 3 failed 0 timeout 0 skipped 0" <<<"$OUT"'
check "apply: first seq links to held seq+1, prev n/a" 'grep -A1 "seq 7729009 fetched" <<<"$OUT" | grep -q "chain ok prev n/a next ok public ok"'
check "apply: after shows fewer missing" 'grep -q "after:  complete_ledgers 7728938-7729000,7729007-7729449 | missing interior 6" <<<"$OUT"'
check "apply: only allowlisted methods reach the node" 'methods_ok'
check "apply: only curl is exec'd" '! grep "^exec " "$STUB_CALLS" | grep -vq "^exec postfiatd curl "'
check "apply: public rpc asked once per ledger" '[ "$(grep -c "^curl " "$STUB_CALLS")" = 3 ]'
check "apply: interval sleeps happen (rate cap)" '[ "$(grep -c "^sleep 2$" "$STUB_CALLS")" -ge 3 ]'

# 3. full interior gap with --max-ledgers 50: all 9, last one links both ways
setup ok 0 1
run repair --apply --max-ledgers 50
check "all 9: PASS + after has no interior gap" '[ "$RC" = 0 ] && grep -q "missing interior 0, edge 0" <<<"$OUT"'
check "all 9: oldest links prev and next" 'grep -A1 "seq 7729001 fetched" <<<"$OUT" | grep -q "prev ok next ok public ok"'

# 4. ledger_request is re-sent at most every 5 polls
setup ok 0 12
run repair --apply --max-ledgers 1
check "rate: 3 ledger_request calls for 13 polls" '[ "$(lr_calls)" = 3 ] && [ "$RC" = 0 ]'

# 5. faults: each one is a MISMATCH / failure with exit 2
setup badhash 7729009 1
run repair --apply --max-ledgers 2
check "badhash: exit 2 + chain MISMATCH" '[ "$RC" = 2 ] && grep -q "chain MISMATCH" <<<"$OUT" && grep -q "^RESULT: FAIL" <<<"$OUT"'
check "badhash: next link MISMATCH too" 'grep -q "next MISMATCH" <<<"$OUT"'
check "badhash: other seq still verified" 'grep -q "verified 1 failed 1" <<<"$OUT"'
setup badlink 7729010 1
run repair --apply --max-ledgers 1
check "badlink: held seq+1 parent mismatch -> exit 2" '[ "$RC" = 2 ] && grep -q "next MISMATCH(seq+1 parent" <<<"$OUT"'
setup pubmismatch 7729009 1
run repair --apply --max-ledgers 1
check "public mismatch: exit 2" '[ "$RC" = 2 ] && grep -q "public MISMATCH" <<<"$OUT"'
setup lrerror 7729009 1
run repair --apply --max-ledgers 2
check "ledger_request error: exit 2, named" '[ "$RC" = 2 ] && grep -q "seq 7729009 failed: ledger_request: internal" <<<"$OUT"'
setup chainflip 7729009 7
run repair --apply --max-ledgers 1
check "hash changed between ledger_request calls: exit 2" '[ "$RC" = 2 ] && grep -q "ledger_request hash changed" <<<"$OUT"'

# 6. public RPC unavailable: retried 3 times, then n/a (still verified locally)
setup pubdown 0 1
run repair --apply --max-ledgers 1
check "public down: 3 tries printed, n/a, exit 0" '[ "$RC" = 0 ] && [ "$(grep -c "public rpc try [123]/3 for 7729009: no answer" <<<"$OUT")" = 3 ] && grep -q "public n/a" <<<"$OUT"'
setup pubnotfound 0 1
run repair --apply --max-ledgers 1
check "public lgrNotFound: retried, n/a" 'grep -q "public rpc try 3/3 for 7729009: lgrNotFound" <<<"$OUT" && [ "$RC" = 0 ]'

# 7. no validated-chain hash (ledger_request only ever says "acquiring" another ledger): UNVERIFIED, exit 1
setup lrnotfound 0 1
run repair --apply --max-ledgers 1
check "no chain hash: UNVERIFIED, exit 1" '[ "$RC" = 1 ] && grep -q "UNVERIFIED" <<<"$OUT" && grep -q "chain n/a" <<<"$OUT"'

# 8. never arrives: per-ledger wait, then the runtime cap
setup ok 0 -1
run repair --apply --max-ledgers 2 --wait 10
check "timeout: exit 1 INCOMPLETE, 2 timeouts" '[ "$RC" = 1 ] && grep -q "timeout 2 skipped 0" <<<"$OUT" && grep -q "not servable after 10 s" <<<"$OUT"'
setup ok 0 -1
run repair --apply --max-ledgers 3 --wait 600 --max-runtime 20
check "runtime cap: first skipped while waiting, rest skipped" '[ "$RC" = 1 ] && grep -q "runtime cap reached while waiting" <<<"$OUT" && grep -q "timeout 0 skipped 3" <<<"$OUT"'
check "runtime cap: fake clock stopped near the cap" '[ "$(cat "$CLOCK")" -le 1030 ]'

# 9. refusals (exit 4) send no ledger_request
setup ok 0 1 syncing
run repair --apply
check "not full: refused, 0 requests" '[ "$RC" = 4 ] && grep -q "refused: server_state is syncing" <<<"$OUT" && [ "$(lr_calls)" = 0 ]'
for w in active expired; do
  setup ok 0 1; export STUB_MAINT="$w"; run repair --apply
  check "maint window $w: refused" '[ "$RC" = 4 ] && grep -q "pft-maint window is open (window=$w)" <<<"$OUT" && [ "$(lr_calls)" = 0 ]'
done
setup ok 0 1; export STUB_MAINT=fail; run repair --apply
check "pft-maint fails: refused (fail closed)" '[ "$RC" = 4 ] && grep -q "pft-maint status --json failed" <<<"$OUT"'
setup ok 0 1; export STUB_MAINT=garbage; run repair --apply
check "pft-maint garbage: refused" '[ "$RC" = 4 ] && grep -q "no window field" <<<"$OUT"'
setup ok 0 1
OUT="$(PFT_BACKFILL_MAINT="$T/bin/no-such-maint" bash "$SCRIPT" repair --apply 2>&1)"; RC=$?
check "pft-maint missing: refused" '[ "$RC" = 4 ] && grep -q "pft-maint not installed" <<<"$OUT"'
mkdir -p "$T/lock"; exec 7>>"$T/lock/pft-backfill.lock"; flock 7
setup ok 0 1
run repair --apply --max-ledgers 1
check "concurrent repair (lock held): refused, 0 requests" '[ "$RC" = 4 ] && grep -q "another pft-backfill repair is running" <<<"$OUT" && [ "$(lr_calls)" = 0 ]'
flock -u 7; exec 7>&-
run repair --apply --max-ledgers 1
check "control: same run once the lock is free" '[ "$RC" = 0 ]'

# 10. caps and usage
setup ok 0 1
for a in "--max-ledgers 257" "--max-ledgers 0" "--interval 0" "--interval 61" "--wait 601" "--max-runtime 1801" "--wait x" "--bogus"; do
  # shellcheck disable=SC2086
  run repair --apply $a
  check "cap/usage '$a': exit 3, nothing requested" '[ "$RC" = 3 ] && [ "$(lr_calls)" = 0 ]'
done
run repair --apply --max-ledgers 256 --interval 1
check "cap edge: 256 accepted" '[ "$RC" = 0 ]'

# 11. nothing to repair, textfile output
setup ok 0 1 full "[[7728938,$V]]"
run repair --apply --textfile
check "no gap: PASS nothing to repair" '[ "$RC" = 0 ] && grep -q "^RESULT: PASS - nothing to repair" <<<"$OUT" && [ "$(lr_calls)" = 0 ]'
setup ok 0 1
run repair --apply --max-ledgers 2 --textfile
P="$R/textfile/pft_backfill_repair.prom"
check "textfile: verified 2, exit 0, dry_run 0" 'grep -qx "pft_backfill_repair_ledgers{node=\"sentry\",result=\"verified\"} 2" "$P" && grep -qx "pft_backfill_repair_exit_code{node=\"sentry\"} 0" "$P" && grep -qx "pft_backfill_repair_dry_run{node=\"sentry\"} 0" "$P"'
setup ok 0 -1
run repair --apply --max-ledgers 1 --wait 4 --textfile
check "textfile: timeout run exit_code 1" 'grep -qx "pft_backfill_repair_exit_code{node=\"sentry\"} 1" "$P" && grep -qx "pft_backfill_repair_ledgers{node=\"sentry\",result=\"timeout\"} 1" "$P"'
setup ok 0 1
run repair --textfile
check "textfile: dry run marked" 'grep -qx "pft_backfill_repair_dry_run{node=\"sentry\"} 1" "$P"'
check "seed never printed" '! grep -q sNEVERPRINTED <<<"$OUT"'
check "public rpc off: PUBLIC_RPC=none" 'setup ok 0 1; printf "CONTAINER=postfiatd\nHOST_LABEL=sentry\nPUBLIC_RPC=none\n" > "$R/etc/pft-backfill.env"; run repair --apply --max-ledgers 1; [ "$RC" = 0 ] && grep -q "public off" <<<"$OUT" && ! grep -q "^curl " "$STUB_CALLS"'

# 12. pull (validator side): copy + validate the sentry's textfiles through PULL_SSH
P2="$T/peer"; mkdir -p "$P2"
cat > "$T/bin/fakessh" <<'STUBSSH'
#!/usr/bin/env bash
[ "${STUB_SSH:-ok}" = down ] && exit 255
c="$*"; exec bash -c "${c//\/var\/lib\/pft-exporter\/textfile/$PEERDIR}"
STUBSSH
chmod +x "$T/bin/fakessh"
export PEERDIR="$P2"
printf 'CONTAINER=postfiatd\nHOST_LABEL=validator\nPEER_LABEL=sentry\nPULL_SSH=%s\n' "$T/bin/fakessh" > "$R/etc/pft-backfill.env"
setup ok 0 1 full "[[7728938,$V]]"
printf 'CONTAINER=postfiatd\nHOST_LABEL=sentry\n' > "$T/sentry.env"
PFT_BACKFILL_CONF="$T/sentry.env" bash "$SCRIPT" status --prom "$P2/pft_backfill.prom" >/dev/null 2>&1
rm -f "$R/textfile/"pft_backfill_*sentry.prom
run pull
check "pull: status file installed, no repair file yet" '[ "$RC" = 0 ] && [ -f "$R/textfile/pft_backfill_sentry.prom" ] && grep -q "pft_backfill_repair: none on sentry yet" <<<"$OUT" && [ ! -e "$R/textfile/pft_backfill_repair_sentry.prom" ]'
check "pull: pulled file is byte-identical" 'cmp -s "$P2/pft_backfill.prom" "$R/textfile/pft_backfill_sentry.prom"'
setup ok 0 1
PFT_BACKFILL_CONF="$T/sentry.env" TEXTFILE_DIR="$P2" bash "$SCRIPT" repair --apply --max-ledgers 1 --textfile >/dev/null 2>&1
run pull
check "pull: repair file installed too" '[ "$RC" = 0 ] && grep -qx "pft_backfill_repair_ledgers{node=\"sentry\",result=\"verified\"} 1" "$R/textfile/pft_backfill_repair_sentry.prom"'
cp "$P2/pft_backfill.prom" "$T/good.prom"
check "validate: a real status textfile passes" 'bash "$SCRIPT" validate "$T/good.prom" sentry'
check "validate: wrong node fails exit 1" 'bash "$SCRIPT" validate "$T/good.prom" validator; [ $? = 1 ]'
echo 'node_load1 9' >> "$P2/pft_backfill.prom"; cp "$R/textfile/pft_backfill_sentry.prom" "$T/before.prom"
run pull
check "pull: foreign metric line rejected, old file kept" '[ "$RC" = 2 ] && grep -q "pulled pft_backfill rejected: 1 unexpected lines" <<<"$OUT" && cmp -s "$T/before.prom" "$R/textfile/pft_backfill_sentry.prom" && [ -z "$(ls -A "$R/textfile" | grep "\.pull$")" ]'
sed 's/node="sentry"/node="validator"/' "$T/good.prom" > "$P2/pft_backfill.prom"; run pull
check "pull: wrong node label rejected" '[ "$RC" = 2 ] && grep -q "unexpected lines" <<<"$OUT"'
grep -v '^pft_backfill_status_timestamp_seconds' "$T/good.prom" > "$P2/pft_backfill.prom"; run pull
check "pull: missing timestamp sample rejected" '[ "$RC" = 2 ] && grep -q "no pft_backfill_status_timestamp_seconds sample" <<<"$OUT"'
cp "$T/good.prom" "$P2/pft_backfill.prom"
OUT="$(STUB_SSH=down bash "$SCRIPT" pull 2>&1)"; RC=$?
check "pull: ssh down -> exit 1" '[ "$RC" = 1 ] && grep -q "pull of pft_backfill from sentry failed (rc 255)" <<<"$OUT"'
rm "$P2/pft_backfill.prom"; run pull
check "pull: status file absent on peer -> exit 1" '[ "$RC" = 1 ]'
printf 'CONTAINER=postfiatd\nHOST_LABEL=validator\n' > "$R/etc/pft-backfill.env"; run pull
check "pull: PULL_SSH unset -> exit 2" '[ "$RC" = 2 ] && grep -q "PULL_SSH not set" <<<"$OUT"'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
