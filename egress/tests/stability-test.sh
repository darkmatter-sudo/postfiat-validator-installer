#!/usr/bin/env bash
# stability.sh against stubs: docker (inspect / exec grep on tests/fixtures/heartbeat.log, real sentry lines /
# exec curl server_info), iptables (DROP counter). One fault per case. Run: bash tests/stability-test.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 3
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/state"
cat > "$T/bin/docker" <<'S'
#!/usr/bin/env bash
case "$1" in
  inspect) echo "$STUB_STARTED 0" ;;
  exec) case "$*" in *grep*) cat "$FIX" ;; *server_info*) printf '{"result":{"info":{"server_state":"%s","peers":%s,"complete_ledgers":"1-2"}}}\n' "$STUB_STATE" "$STUB_PEERS" ;; esac ;;
esac
S
printf '#!/bin/sh\nprintf "Chain PFT-EGRESS\\n pkts bytes target\\n  7  420 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\\n"\n' > "$T/bin/iptables"
chmod +x "$T/bin/docker" "$T/bin/iptables"
echo '{"baseline_peers":11,"applied_at":"2026-10-25T05:00:00Z","deadman_passed_at":"2026-10-25T05:10:00Z"}' > "$T/state/c.json"
export PATH="$T/bin:$PATH" PFT_EGRESS_TEST=1 STATE_DIR="$T/state" FIX="$PWD/tests/fixtures/heartbeat.log"
pass=0; fail=0
run() { # name expected_rc expected_grep [env...] -- args
  local name="$1" want="$2" pat="$3"; shift 3; local envs=(); while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
  out="$(env STUB_STARTED=2026-10-24T20:00:00Z PFT_EGRESS_NOW=1792904995 STUB_STATE=full STUB_PEERS=12 "${envs[@]}" bash stability.sh --container c "$@" 2>&1)"; rc=$?
  if [ "$rc" -eq "$want" ] && grep -qE "$pat" <<<"$out"; then pass=$((pass + 1)); echo "ok   $name (exit $rc)"
  else fail=$((fail + 1)); echo "FAIL $name (exit $rc, want $want, /$pat/)"; printf '%s\n' "$out" | while IFS= read -r l; do echo "     $l"; done; fi
}
run "all full since applied_at"         0 "total 2 heartbeats, 0 not full, 0 empty"  --
run "DISCONNECTED line counted, not skipped" 1 "no-mode-field=1" PFT_EGRESS_NOW=1792881000 -- --since 2026-10-24T22:25:00Z
run "connected + DISCONNECTED not full" 1 "total 3 heartbeats, 3 not full, 0 empty" PFT_EGRESS_NOW=1792881000 -- --since 2026-10-24T22:25:00Z
run "empty bucket is a gap"             1 "1 empty buckets"               PFT_EGRESS_NOW=1792905060 -- --since 2026-10-25T05:00:00Z
run "container restarted in window"     1 "FAIL container \(re\)started"  STUB_STARTED=2026-10-25T05:05:00Z --
run "peers below baseline"              1 "FAIL state full     peers  10" STUB_PEERS=10 --
run "node not full"                     1 "FAIL state syncing"            STUB_STATE=syncing --
run "no heartbeats in window"           1 "no heartbeat lines"            -- --since 2026-10-25T06:00:00Z
run "timestamps read as UTC (TZ=Asia/Tokyo)" 0 "total 1 heartbeats.*first 2026-10-25T05:09:50Z" TZ=Asia/Tokyo -- --since 2026-10-25T05:09:50Z
run "timestamps read as UTC (TZ=Europe/London)" 0 "total 1 heartbeats.*first 2026-10-25T05:09:50Z" TZ=Europe/London -- --since 2026-10-25T05:09:50Z
run "DROP counter read"                 0 "egress DROP pkts 7"            --
echo "stability-test: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
