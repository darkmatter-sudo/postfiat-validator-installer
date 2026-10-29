#!/usr/bin/env bash
# Offline tests for pft-statewatch.sh + statewatch_parse.py: stub docker, fixture server_info answers, no root,
# nothing on the host is read or changed.
#   bash statewatch/tests/run-tests.sh [SCRIPT [PARSER]]   (defaults ../pft-statewatch.sh ../statewatch_parse.py;
#                                                          tests/mutate.sh passes mutants)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; L, PV, s0, s1 are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-statewatch.sh}"
P="${2:-$HERE/../statewatch_parse.py}"
FX="$HERE/fixtures/server_info_full.json"
T="$(mktemp -d)"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }   # NAME CONDITION (subshell: an exit in it is a FAIL)
has()   { grep -qxF -- "$2" "$1"; }                              # FILE LINE (exact)

# stub docker: `docker exec NAME curl ...` records its args, then prints $T/answer (exit 1 if $T/fail exists,
# hangs if $T/hang exists)
mkdir -p "$T/bin" "$T/tf"
cat > "$T/bin/docker" <<EOF
#!/bin/sh
printf '%s\n' "\$*" > "$T/args"
[ "\$1" = exec ] || exit 1
[ -e "$T/hang" ] && sleep 60
[ -e "$T/fail" ] && { echo "Error response from daemon: container is not running" >&2; exit 1; }
[ -e "$T/warn" ] && echo "WARNING: Error loading config file: open /root/.docker/config.json: permission denied" >&2
cat "$T/answer"
EOF
chmod +x "$T/bin/docker"

# answer PYTHON-STATEMENT: write $T/answer = fixture modified by a statement on d / i (= d["result"]["info"])
answer() {
  python3 -I - "$FX" "$T/answer" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); i = d["result"]["info"]; sa = i["state_accounting"]
exec(sys.argv[3])
open(sys.argv[2], "w").write(json.dumps(d) if not isinstance(d, str) else d)
PY
}
run() { # [collect args] -> $OUT (textfile), $T/rc, $T/err
  rm -f "$T/err"
  PFT_SW_CONF=/nonexistent PFT_SW_DOCKER="$T/bin/docker" PFT_SW_NOW=1700000000 PFT_SW_PARSER="$P" RPC_TIMEOUT=2 \
    bash "$S" collect --container postfiatd --textfile-dir "$T/tf" "$@" 2> "$T/err"
  echo $? > "$T/rc"
}
OUT="$T/tf/pft_statewatch_postfiatd.prom"
samples() { grep -vc '^#' "$OUT"; }
L='container="postfiatd"'

echo "== 1. healthy full node (real field shapes)"
answer 'pass'; run --history "$T/hist.jsonl"
check "rc 0" '[ "$(cat "$T/rc")" = 0 ]'
check "up 1" 'has "$OUT" "pft_statewatch_up{$L} 1"'
check "timestamp from PFT_SW_NOW" 'has "$OUT" "pft_statewatch_collect_timestamp_seconds{$L} 1700000000"'
check "state one-hot: full 1" 'has "$OUT" "pft_statewatch_server_state{$L,state=\"full\"} 1"'
check "state one-hot: exactly one 1 of 7" '[ "$(grep -c "^pft_statewatch_server_state{.*} 1$" "$OUT")" = 1 ] && [ "$(grep -c "^pft_statewatch_server_state{" "$OUT")" = 7 ]'
check "state duration in seconds" 'has "$OUT" "pft_statewatch_server_state_duration_seconds{$L} 40292.883489"'
check "accounting duration (us -> s, 6 decimals)" 'has "$OUT" "pft_statewatch_state_duration_seconds_total{$L,state=\"tracking\"} 0.000267"'
check "transitions disconnected 2" 'has "$OUT" "pft_statewatch_state_transitions_total{$L,state=\"disconnected\"} 2"'
check "transitions for all 5 modes" '[ "$(grep -c "^pft_statewatch_state_transitions_total{" "$OUT")" = 5 ]'
check "full_exits 0 (in full, 1 transition)" 'has "$OUT" "pft_statewatch_full_exits_total{$L} 0"'
check "io_latency_ms 1" 'has "$OUT" "pft_statewatch_io_latency_ms{$L} 1"'
check "jq overflow 0" 'has "$OUT" "pft_statewatch_jq_trans_overflow_total{$L} 0"'
check "peer_disconnects 29 (string field)" 'has "$OUT" "pft_statewatch_peer_disconnects_total{$L} 29"'
check "peer_disconnects_resources 0" 'has "$OUT" "pft_statewatch_peer_disconnects_resources_total{$L} 0"'
check "uptime + peers" 'has "$OUT" "pft_statewatch_node_uptime_seconds{$L} 40330" && has "$OUT" "pft_statewatch_peers{$L} 16"'
check "27 samples" '[ "$(samples)" = 27 ]'
check "file ends with a newline" '[ "$(tail -c1 "$OUT" | od -An -c | tr -d " ")" = "\n" ]'
check "file mode 644" '[ "$(stat -c %a "$OUT")" = 644 ]'
check "no temp files left" '[ -z "$(find "$T/tf" -name ".*" -type f)" ]'
check "admin RPC on the container loopback with --max-time" 'grep -q "^exec postfiatd curl -s --max-time 2 .*http://127.0.0.1:5005/$" "$T/args"'
check "history: one JSON line with ts + state" '[ "$(wc -l < "$T/hist.jsonl")" = 1 ] && grep -q "\"state\":\"full\"" "$T/hist.jsonl" && grep -q "\"ts\":1700000000" "$T/hist.jsonl"'
check "validate accepts own output" 'PFT_SW_CONF=/nonexistent bash "$S" validate "$OUT" postfiatd'

echo "== 2. full_exits (derived, reset-safe)"
answer 'i["server_state"] = "tracking"; sa["full"]["transitions"] = "2"'; run
check "left full twice, now tracking -> 2" 'has "$OUT" "pft_statewatch_full_exits_total{$L} 2"'
answer 'i["server_state"] = "full"; sa["full"]["transitions"] = "3"'; run
check "back in full, 3 transitions -> 2 (no change on re-entry)" 'has "$OUT" "pft_statewatch_full_exits_total{$L} 2"'
answer 'i["server_state"] = "proposing"; sa["full"]["transitions"] = "4"'; run
check "proposing counts as mode full -> 3" 'has "$OUT" "pft_statewatch_full_exits_total{$L} 3" && has "$OUT" "pft_statewatch_server_state{$L,state=\"proposing\"} 1"'
answer 'i["server_state"] = "connected"; sa["full"]["transitions"] = "0"'; run
check "fresh start, never full -> 0" 'has "$OUT" "pft_statewatch_full_exits_total{$L} 0" && has "$OUT" "pft_statewatch_up{$L} 1"'
answer 'i["server_state"] = "full"; sa["full"]["transitions"] = "0"'; run
check "full with 0 full transitions is inconsistent -> up 0" 'has "$OUT" "pft_statewatch_up{$L} 0" && [ "$(cat "$T/rc")" = 1 ]'

echo "== 3. every required field: missing or malformed -> up 0, no stale values, rc 1"
for f in server_state server_state_duration_us state_accounting io_latency_ms jq_trans_overflow peer_disconnects \
         peer_disconnects_resources uptime peers; do
  answer 'pass'; run                                        # a good file first: the failure must replace it
  answer "del i['$f']"; run
  check "missing $f: up 0 + timestamp only, rc 1, reason logged" '[ "$(samples)" = 2 ] && has "$OUT" "pft_statewatch_up{$L} 0" && [ "$(cat "$T/rc")" = 1 ] && grep -q "$f\|state_accounting\|server_state" "$T/err"'
done
for m in disconnected connected syncing tracking full; do
  for k in duration_us transitions; do
    answer "del sa['$m']['$k']"; run
    check "missing state_accounting.$m.$k -> up 0" '[ "$(samples)" = 2 ] && grep -q "state_accounting.$m.$k" "$T/err"'
  done
done
answer 'del sa["full"]'; run
check "missing state_accounting.full object -> up 0" '[ "$(samples)" = 2 ] && grep -q "missing state_accounting.full" "$T/err"'
for bad in '"abc"' '-1' 'True' '"-5"' '"1.5"' 'None' '"1e3"' '""'; do
  answer "i['jq_trans_overflow'] = $bad"; run
  check "malformed jq_trans_overflow $bad -> up 0" '[ "$(samples)" = 2 ] && grep -q "jq_trans_overflow" "$T/err"'
done
answer 'i["io_latency_ms"] = 7'; run
check "io_latency int accepted" 'has "$OUT" "pft_statewatch_io_latency_ms{$L} 7"'
answer 'i["server_state"] = "booting"'; run
check "unknown server_state -> up 0" '[ "$(samples)" = 2 ] && grep -q "unknown server_state" "$T/err"'

echo "== 4. RPC/transport failures -> up 0"
answer 'd["result"] = {"status": "error", "error": "noPermission"}'; run
check "rpc error status -> up 0" '[ "$(samples)" = 2 ] && grep -q "noPermission" "$T/err"'
answer 'd = "<html>502</html>"'; run
check "non-JSON -> up 0" '[ "$(samples)" = 2 ] && grep -q "not JSON" "$T/err"'
answer 'd = ""'; run
check "empty answer -> up 0" '[ "$(samples)" = 2 ] && [ "$(cat "$T/rc")" = 1 ]'
answer 'pass'; touch "$T/fail"; run; rm -f "$T/fail"
check "docker exec fails (container stopped) -> up 0, reason" '[ "$(samples)" = 2 ] && grep -q "docker exec postfiatd failed" "$T/err"'
touch "$T/hang"; s0=$(date +%s); run; s1=$(date +%s); rm -f "$T/hang"
check "hung docker exec ends by timeout (< 15 s) -> up 0" '[ $((s1 - s0)) -lt 15 ] && [ "$(samples)" = 2 ] && [ "$(cat "$T/rc")" = 1 ]'
answer 'pass'; run
check "recovery: next good answer -> up 1, 27 samples" 'has "$OUT" "pft_statewatch_up{$L} 1" && [ "$(samples)" = 27 ]'

answer 'pass'; touch "$T/warn"; run; rm -f "$T/warn"
check "docker CLI warning on stderr (exit 0) is not part of the answer -> up 1" 'has "$OUT" "pft_statewatch_up{$L} 1" && [ "$(samples)" = 27 ]'

echo "== 5. history is best-effort"
answer 'pass'; run --history "$T/nodir/hist.jsonl"
check "unwritable history: still up 1, rc 0, warning" 'has "$OUT" "pft_statewatch_up{$L} 1" && [ "$(cat "$T/rc")" = 0 ] && grep -q "history not written" "$T/err"'
answer 'del i["peers"]'; run --history "$T/hist2.jsonl"
check "failed parse writes no history line" '[ ! -s "$T/hist2.jsonl" ]'

echo "== 6. --stdout and usage"
answer 'pass'
check "--stdout prints, writes no file" 'rm -f "$OUT"; PFT_SW_CONF=/nonexistent PFT_SW_DOCKER="$T/bin/docker" PFT_SW_PARSER="$P" bash "$S" collect --stdout | grep -q "^pft_statewatch_up{container=\"postfiatd\"} 1$" && [ ! -e "$OUT" ]'
check "bad container name -> rc 3" 'PFT_SW_CONF=/nonexistent bash "$S" collect --container "a;b" 2>/dev/null; [ $? = 3 ]'
check "unknown command -> rc 3" 'PFT_SW_CONF=/nonexistent bash "$S" frobnicate 2>/dev/null; [ $? = 3 ]'

echo "== 7. validate (what the validator accepts from the sentry)"
answer 'pass'; run; G="$T/good.prom"; sed 's/container="postfiatd"/container="postfiatd-sentry"/' "$OUT" > "$G"
v() { PFT_SW_CONF=/nonexistent MAX_BYTES="${MB:-65536}" bash "$S" validate "$1" postfiatd-sentry > "$T/vout" 2>&1; echo $? > "$T/vrc"; }
v "$G"; check "good sentry file -> 0" '[ "$(cat "$T/vrc")" = 0 ]'
v "$OUT"; check "other container's file -> 2 (first label)" '[ "$(cat "$T/vrc")" = 2 ] && grep -q "first label" "$T/vout"'
{ cat "$G"; echo 'node_load1{container="postfiatd-sentry"} 1'; } > "$T/x1"; v "$T/x1"
check "foreign metric name -> 2" '[ "$(cat "$T/vrc")" = 2 ] && grep -q "not a pft_statewatch_ sample" "$T/vout"'
{ cat "$G"; echo 'pft_statewatch_up{container="postfiatd-sentry"} 1 # x'; } > "$T/x2"; v "$T/x2"
check "trailing junk after value -> 2" '[ "$(cat "$T/vrc")" = 2 ] && grep -q "malformed sample" "$T/vout"'
{ cat "$G"; echo 'pft_statewatch_up{container="postfiatd-sentry"} NaNx'; } > "$T/x3"; v "$T/x3"
check "non-numeric value -> 2" '[ "$(cat "$T/vrc")" = 2 ] && grep -q "malformed sample" "$T/vout"'
grep -v '^pft_statewatch_up{' "$G" > "$T/x4"; v "$T/x4"
check "no up sample -> 2" '[ "$(cat "$T/vrc")" = 2 ] && grep -q "no pft_statewatch_up" "$T/vout"'
grep -v '^pft_statewatch_collect_timestamp_seconds{' "$G" > "$T/x5"; v "$T/x5"
check "no timestamp sample -> 2" '[ "$(cat "$T/vrc")" = 2 ] && grep -q "no pft_statewatch_collect_timestamp" "$T/vout"'
{ cat "$G"; echo '# random comment'; } > "$T/x6"; v "$T/x6"
check "non-HELP/TYPE comment -> 2" '[ "$(cat "$T/vrc")" = 2 ]'
{ cat "$G"; echo '# TYPE node_load1 gauge'; } > "$T/x7"; v "$T/x7"
check "HELP/TYPE for a foreign metric -> 2" '[ "$(cat "$T/vrc")" = 2 ]'
{ cat "$G"; echo 'pft_statewatch_up{container="postfiatd-sentry"} 1}'; } > "$T/x8"; v "$T/x8"
check "brace injection -> 2" '[ "$(cat "$T/vrc")" = 2 ]'
MB=100 v "$G"; check "over MAX_BYTES -> 2" '[ "$(cat "$T/vrc")" = 2 ] && grep -q "too big" "$T/vout"'
: > "$T/x9"; v "$T/x9"; check "empty file -> 2" '[ "$(cat "$T/vrc")" = 2 ]'

echo "== 8. pull (stub PULL_SSH: cat of a staged remote dir)"
R="$T/remote"; mkdir -p "$R" "$T/vtf"; cp "$G" "$R/pft_statewatch_postfiatd-sentry.prom"
pl() { PFT_SW_CONF=/nonexistent PULL_SSH="${PS:-}" REMOTE_DIR="$R" TEXTFILE_DIR="$T/vtf" PULL_TIMEOUT=3 \
         bash "$S" pull --container postfiatd-sentry 2> "$T/perr"; echo $? > "$T/prc"; }
PV="$T/vtf/pft_statewatch_postfiatd-sentry.prom"
PS="env" pl
check "pull ok -> 0, file identical, mode 644" '[ "$(cat "$T/prc")" = 0 ] && cmp -s "$G" "$PV" && [ "$(stat -c %a "$PV")" = 644 ]'
cp "$T/x1" "$R/pft_statewatch_postfiatd-sentry.prom"; PS="env" pl
check "invalid remote file -> 2, previous copy kept" '[ "$(cat "$T/prc")" = 2 ] && cmp -s "$G" "$PV" && grep -q "validation failed" "$T/perr"'
PS="false" pl
check "ssh failure -> 1, previous copy kept" '[ "$(cat "$T/prc")" = 1 ] && cmp -s "$G" "$PV"'
PS="sleep 30 ;" pl
check "hung ssh -> 1 after PULL_TIMEOUT" '[ "$(cat "$T/prc")" = 1 ] && cmp -s "$G" "$PV"'
check "no pull temp files left" '[ -z "$(find "$T/vtf" -name ".pull-*")" ]'
PS="" pl
check "PULL_SSH unset -> 3" '[ "$(cat "$T/prc")" = 3 ]'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
