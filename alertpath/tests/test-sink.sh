#!/usr/bin/env bash
# shellcheck disable=SC2015  # ok() always returns 0, so "cond && ok || bad" is a safe if/else here
# Offline tests for alertpath_sink.py: runs it on a spare loopback port with a temp state dir and posts
# Alertmanager-shaped webhooks. Usage: bash tests/test-sink.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SB="$(mktemp -d)"
PORT="${PORT:-19096}"
STATE_DIR="$SB" SINK_PORT="$PORT" python3 -I -u "$HERE/../alertpath_sink.py" > "$SB/sink.out" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null; rm -rf "$SB"' EXIT
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }
post() { curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "$2" "http://127.0.0.1:$PORT$1"; }
wd='{"alerts":[{"status":"firing","labels":{"alertname":"PFTAlertPipelineWatchdog"},"startsAt":"2026-10-28T00:00:00Z"}]}'
other='{"alerts":[{"status":"firing","labels":{"alertname":"PFTNodeRPCDown"}}]}'

[ "$(post /watchdog "$wd")" = 200 ] && [ "$(jq -r '[.count,.status,.unexpected] | @csv' "$SB/last.json")" = '1,"firing",0' ] \
  && ok "watchdog delivery recorded" || bad "watchdog delivery: $(cat "$SB/last.json" 2>/dev/null)"
t1="$(jq .received "$SB/last.json")"; now="$(date -u +%s)"
[ $((now - t1)) -le 2 ] && ok "received timestamp is now (+-2s)" || bad "received $t1 vs now $now"
[ "$(post /watchdog "$other")" = 200 ] && ok "mis-routed delivery answered 200" || bad "mis-routed code"
[ "$(jq .count "$SB/last.json")" = 1 ] && ok "mis-routed delivery does not refresh the heartbeat" || bad "count changed"
post /watchdog "${wd/firing/resolved}" >/dev/null
[ "$(jq -r '[.count,.status,.unexpected] | @csv' "$SB/last.json")" = '2,"resolved",1' ] \
  && ok "resolved status + unexpected counter carried" || bad "after resolved: $(cat "$SB/last.json")"
[ "$(post /other "$wd")" = 404 ] && ok "wrong path -> 404" || bad "wrong path"
[ "$(post /watchdog 'not json')" = 400 ] && ok "malformed body -> 400" || bad "malformed body"
[ "$(post /watchdog '[1,2]')" = 400 ] && ok "non-object JSON -> 400" || bad "non-object JSON"
[ "$(jq .count "$SB/last.json")" = 2 ] && ok "bad requests leave state unchanged" || bad "state changed"
ss -Htln "sport = :$PORT" | awk '{print $4}' | grep -qx "127.0.0.1:$PORT" && ok "listens on 127.0.0.1 only" || bad "listener"
grep -q 'unexpected delivery without PFTAlertPipelineWatchdog: PFTNodeRPCDown' "$SB/sink.out" && ok "mis-route logged" || bad "log"
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
