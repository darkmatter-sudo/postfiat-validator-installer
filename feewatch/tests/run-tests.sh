#!/usr/bin/env bash
# Offline tests for pft-feewatch.sh + feewatch_parse.py: a stub docker answers `fee` and `server_info` from fixture
# files (real answers captured by capture_fixtures.sh, then modified per case). No root, no network, nothing on the
# host is read or changed.
#   bash feewatch/tests/run-tests.sh [SCRIPT [PARSER]]   (defaults ../pft-feewatch.sh ../feewatch_parse.py)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; OUT, L, R, why are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-feewatch.sh}"
P="${2:-$HERE/../feewatch_parse.py}"
FXD="$HERE/fixtures"
T="$(mktemp -d)"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }   # NAME CONDITION (subshell: an exit in it is a FAIL)
has()   { grep -qxF -- "$2" "$1"; }                              # FILE LINE (exact)

# stub docker: `docker exec NAME curl ... -d BODY URL` appends its args to $T/args and prints $T/fee or $T/info by
# the method in BODY. $T/fail-<method> -> exit 1 with a daemon error; $T/hang -> sleeps 60 (a real hang);
# $T/warn -> a docker CLI warning on stderr before the answer.
mkdir -p "$T/bin" "$T/tf"
cat > "$T/bin/docker" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >> "$T/args"
[ "\$1" = exec ] || exit 1
case "\$*" in *'"method":"fee"'*) m=fee ;; *'"method":"server_info"'*) m=info ;; *) exit 1 ;; esac
[ -e "$T/hang" ] && sleep 60
[ -e "$T/fail-\$m" ] && { echo "Error response from daemon: container is not running" >&2; exit 1; }
[ -e "$T/warn" ] && echo "WARNING: Error loading config file: open /root/.docker/config.json: permission denied" >&2
cat "$T/\$m"
STUB
chmod +x "$T/bin/docker"

# answer HOST FEE-STATEMENT INFO-STATEMENT: $T/fee and $T/info = HOST's fixtures modified by python statements on
# f (= fee result) and i (= server_info result.info); a statement may also rebind fd / id (the whole documents)
answer() {
  python3 -I - "$FXD/$1_fee.json" "$FXD/${4:-$1_server_info}.json" "$T" "$2" "$3" <<'PY'
import json, sys
fd = json.load(open(sys.argv[1])); id = json.load(open(sys.argv[2]))
f = fd["result"]; i = id["result"]["info"]
exec(sys.argv[4]); exec(sys.argv[5])
for name, d in (("fee", fd), ("info", id)):
    open(sys.argv[3] + "/" + name, "w").write(d if isinstance(d, str) else json.dumps(d))
PY
}
run() { # [collect args] -> $OUT (textfile), $T/rc, $T/err; env overrides via RUNENV
  rm -f "$T/err" "$T/args"
  env PFT_FW_CONF=/nonexistent PFT_FW_DOCKER="$T/bin/docker" PFT_FW_NOW=1700000000 PFT_FW_PARSER="$P" RPC_TIMEOUT=2 \
    ${RUNENV:+"$RUNENV"} bash "$S" collect --container postfiatd --textfile-dir "$T/tf" "$@" 2> "$T/err"
  echo $? > "$T/rc"
}
OUT="$T/tf/pft_feewatch_postfiatd.prom"
L='container="postfiatd"'
rc() { [ "$(cat "$T/rc")" = "$1" ]; }
down() { # assertions for a failed collection; $1 = reason substring expected on stderr, $2 = case name
  why="$1"
  check "$2: rc 1" 'rc 1'
  check "$2: up 0" 'has "$OUT" "pft_feewatch_up{$L} 0"'
  check "$2: timestamp still written" 'has "$OUT" "pft_feewatch_collect_timestamp_seconds{$L} 1700000000"'
  check "$2: no stale values (only up + timestamp samples)" '[ "$(grep -vc "^#" "$OUT")" = 2 ]'
  check "$2: reason on stderr ($1)" 'grep -qF -- "$why" "$T/err"'
}

echo "== 1. validator, real idle answers (admin)"
answer validator 'pass' 'pass'; run --history "$T/hist.jsonl"
check "rc 0" 'rc 0'
check "up 1" 'has "$OUT" "pft_feewatch_up{$L} 1"'
check "timestamp from PFT_FW_NOW" 'has "$OUT" "pft_feewatch_collect_timestamp_seconds{$L} 1700000000"'
check "admin 1 (info.load present)" 'has "$OUT" "pft_feewatch_admin{$L} 1"'
check "queue size 0 / max 2000 / fill 0" 'has "$OUT" "pft_feewatch_current_queue_size{$L} 0" && has "$OUT" "pft_feewatch_max_queue_size{$L} 2000" && has "$OUT" "pft_feewatch_queue_fill_ratio{$L} 0"'
check "expected_ledger_size 32" 'has "$OUT" "pft_feewatch_expected_ledger_size{$L} 32"'
check "drops: base 10, median 5000, open_ledger 10" 'has "$OUT" "pft_feewatch_fee_drops{$L,kind=\"base\"} 10" && has "$OUT" "pft_feewatch_fee_drops{$L,kind=\"median\"} 5000" && has "$OUT" "pft_feewatch_fee_drops{$L,kind=\"open_ledger\"} 10"'
check "levels: reference 256, median 128000" 'has "$OUT" "pft_feewatch_fee_level{$L,kind=\"reference\"} 256" && has "$OUT" "pft_feewatch_fee_level{$L,kind=\"median\"} 128000"'
check "escalation multiple 1, threshold 4 (default)" 'has "$OUT" "pft_feewatch_escalation_multiple{$L} 1" && has "$OUT" "pft_feewatch_escalation_alert_threshold{$L} 4"'
check "all 7 load_factor sources = 1 (omitted fields read as default)" '[ "$(grep -c "^pft_feewatch_load_factor{$L,source=\"[a-z_]*\"} 1$" "$OUT")" = 7 ]'
check "local_load_exceeds_net 0" 'has "$OUT" "pft_feewatch_local_load_exceeds_net{$L} 0"'
check "28 samples" '[ "$(grep -vc "^#" "$OUT")" = 28 ]'
check "file ends with a newline, mode 644, no temp files" '[ "$(tail -c1 "$OUT" | od -An -c | tr -d " ")" = "\n" ] && [ "$(stat -c %a "$OUT")" = 644 ] && [ -z "$(find "$T/tf" -name ".*" -type f)" ]'
check "both RPCs on the container loopback with --max-time" '[ "$(grep -c "^exec postfiatd curl -s --max-time 2 .*http://127.0.0.1:5005/$" "$T/args")" = 2 ]'
check "history: one JSON line with ts, queue, multiple, sources" '[ "$(wc -l < "$T/hist.jsonl")" = 1 ] && python3 -I -c "import json,sys; d=json.loads(open(sys.argv[1]).read()); assert d[\"ts\"]==1700000000 and d[\"queue\"]==0 and d[\"multiple\"]==1 and d[\"sources\"][\"net\"]==1" "$T/hist.jsonl"'
check "validate accepts own output" 'PFT_FW_CONF=/nonexistent bash "$S" validate "$OUT" postfiatd'

echo "== 2. sentry, real idle answers"
answer sentry 'pass' 'pass'; run
check "rc 0 + up 1 + admin 1" 'rc 0 && has "$OUT" "pft_feewatch_up{$L} 1" && has "$OUT" "pft_feewatch_admin{$L} 1"'

echo "== 3. non-admin server_info (real answer from the host-mapped port): admin-only fields absent"
answer validator 'pass' 'pass' validator_server_info_nonadmin; run
check "rc 0, up 1" 'rc 0 && has "$OUT" "pft_feewatch_up{$L} 1"'
check "admin 0" 'has "$OUT" "pft_feewatch_admin{$L} 0"'
check "no guessed local/net/cluster/fee_escalation" '! grep -qE "source=\"(local|net|cluster|fee_escalation)\"" "$OUT"'
check "total/server/fee_queue still exported" '[ "$(grep -cE "^pft_feewatch_load_factor\{$L,source=\"(total|server|fee_queue)\"\} 1$" "$OUT")" = 3 ]'
check "no local_load_exceeds_net" '! grep -q "^pft_feewatch_local_load_exceeds_net" "$OUT"'
answer validator 'pass' 'i["load_factor"] = 3; i["load_factor_fee_escalation"] = 3' validator_server_info_nonadmin; run
check "non-admin: present breakdown field is exported, server = total when omitted" 'has "$OUT" "pft_feewatch_load_factor{$L,source=\"fee_escalation\"} 3" && has "$OUT" "pft_feewatch_load_factor{$L,source=\"server\"} 3"'

echo "== 4. loaded node: escalation, queue, local overload (synthetic values in real field shapes)"
answer validator 'f["current_queue_size"] = "1700"; f["drops"]["open_ledger_fee"] = "52"; f["levels"]["open_ledger_level"] = "1331"' \
  'i["load_factor"] = 5.2; i["load_factor_server"] = 2.5; i["load_factor_local"] = 2.5; i["load_factor_fee_escalation"] = 5.19921875; i["load_factor_fee_queue"] = 1.5'
run
check "rc 0" 'rc 0'
check "fill 0.85" 'has "$OUT" "pft_feewatch_queue_fill_ratio{$L} 0.85"'
check "multiple 5.2 (open_ledger_fee / base_fee)" 'has "$OUT" "pft_feewatch_escalation_multiple{$L} 5.2"'
check "local 2.5, net 1 (omitted), exceeds 1" 'has "$OUT" "pft_feewatch_load_factor{$L,source=\"local\"} 2.5" && has "$OUT" "pft_feewatch_load_factor{$L,source=\"net\"} 1" && has "$OUT" "pft_feewatch_local_load_exceeds_net{$L} 1"'
check "total 5.2, server 2.5, fee_escalation 5.199219, fee_queue 1.5" 'has "$OUT" "pft_feewatch_load_factor{$L,source=\"total\"} 5.2" && has "$OUT" "pft_feewatch_load_factor{$L,source=\"server\"} 2.5" && has "$OUT" "pft_feewatch_load_factor{$L,source=\"fee_escalation\"} 5.199219" && has "$OUT" "pft_feewatch_load_factor{$L,source=\"fee_queue\"} 1.5"'
answer validator 'pass' 'i["load_factor"] = 3; i["load_factor_local"] = 3; i["load_factor_net"] = 3'; run
check "network-wide load (local == net): exceeds 0" 'has "$OUT" "pft_feewatch_local_load_exceeds_net{$L} 0"'
answer validator 'f["drops"]["base_fee"] = "0"; f["drops"]["open_ledger_fee"] = "6"; f["levels"]["open_ledger_level"] = "1536"' 'pass'; run
check "base_fee 0: multiple from levels (1536/256 = 6)" 'rc 0 && has "$OUT" "pft_feewatch_escalation_multiple{$L} 6"'
answer validator 'del f["max_queue_size"]' 'pass'; run
check "no max_queue_size (unlimited queue): up 1, queue_limited 0, no fill ratio" 'rc 0 && has "$OUT" "pft_feewatch_queue_limited{$L} 0" && ! grep -q "^pft_feewatch_queue_fill_ratio" "$OUT" && ! grep -q "^pft_feewatch_max_queue_size" "$OUT"'
answer validator 'pass' 'pass'; RUNENV="ESCALATION_THRESHOLD=10" run
check "ESCALATION_THRESHOLD=10 is exported" 'has "$OUT" "pft_feewatch_escalation_alert_threshold{$L} 10"'
RUNENV="ESCALATION_THRESHOLD=1" run
check "ESCALATION_THRESHOLD=1 (would always fire): up 0, rc 1" 'rc 1 && has "$OUT" "pft_feewatch_up{$L} 0"'
RUNENV="ESCALATION_THRESHOLD=abc" run
check "ESCALATION_THRESHOLD=abc: usage error rc 3" 'rc 3'

echo "== 5. malformed JSON"
answer validator 'fd = "{\"result\": {\"status\": \"succ"' 'pass'; run; down "fee: not JSON" "truncated fee answer"
answer validator 'pass' 'id = "<html>502 Bad Gateway</html>"'; run; down "server_info: not JSON" "HTML instead of server_info JSON"
answer validator 'fd = "[]"' 'pass'; run; down "fee: no result object" "fee answer is a JSON list"
answer validator 'pass' 'id = ""'; run; down "server_info: not JSON (0 bytes)" "empty server_info answer"

echo "== 6. missing or malformed fields"
answer validator 'del f["current_queue_size"]' 'pass'; run; down "missing fee.current_queue_size" "fee without current_queue_size"
answer validator 'del f["drops"]' 'pass'; run; down "missing fee.drops" "fee without drops"
answer validator 'del f["levels"]["reference_level"]' 'pass'; run; down "missing fee.levels.reference_level" "fee without levels.reference_level"
answer validator 'f["drops"]["open_ledger_fee"] = "-5"' 'pass'; run; down "malformed fee.drops.open_ledger_fee" "negative open_ledger_fee"
answer validator 'f["expected_ledger_size"] = True' 'pass'; run; down "malformed fee.expected_ledger_size" "boolean expected_ledger_size"
answer validator 'f["max_queue_size"] = "0"' 'pass'; run; down "malformed fee.max_queue_size: 0" "max_queue_size 0 (division)"
answer validator 'f["levels"]["reference_level"] = "0"' 'pass'; run; down "reference_level: 0" "reference_level 0 (division)"
answer validator 'pass' 'del i["load_factor"]'; run; down "missing info.load_factor" "server_info without load_factor"
answer validator 'pass' 'i["load_factor_local"] = "2"'; run; down "malformed info.load_factor_local" "load_factor_local as a string"
answer validator 'pass' 'i["load_factor_net"] = -1'; run; down "malformed info.load_factor_net" "negative load_factor_net"
answer validator 'pass' 'del id["result"]["info"]'; run; down "missing result.info" "server_info without info"

echo "== 7. RPC errors and outages"
answer validator 'fd = {"result": {"error": "noPermission", "status": "error"}}' 'pass'; run; down "fee: status 'error' (error 'noPermission')" "fee rpc error (non-admin)"
answer validator 'pass' 'id = {"result": {"error": "noNetwork", "status": "error"}}'; run; down "server_info: status 'error'" "server_info rpc error"
answer validator 'pass' 'pass'; touch "$T/fail-fee"; run; down "fee via docker exec postfiatd failed" "container stopped (fee)"
check "container stopped: server_info not attempted after fee failed" '[ "$(wc -l < "$T/args")" = 1 ]'
rm -f "$T/fail-fee"; touch "$T/fail-info"; run; down "server_info via docker exec postfiatd failed" "server_info call fails after fee succeeded"
rm -f "$T/fail-info"
touch "$T/hang"; s=$(date +%s); run; e=$(( $(date +%s) - s )); rm -f "$T/hang"
down "fee via docker exec postfiatd failed" "hung docker exec"
check "hung docker exec ended by the timeout (RPC_TIMEOUT 2 + 5 s): ${e}s < 15s" '[ "$e" -ge 6 ] && [ "$e" -lt 15 ]'
answer validator 'pass' 'pass'; touch "$T/warn"; run; rm -f "$T/warn"
check "docker CLI warning on stderr is not glued to the JSON: up 1" 'rc 0 && has "$OUT" "pft_feewatch_up{$L} 1"'

echo "== 8. after a failure the next good run restores every value"
answer validator 'pass' 'pass'; run
check "recovered: up 1, 28 samples" 'rc 0 && has "$OUT" "pft_feewatch_up{$L} 1" && [ "$(grep -vc "^#" "$OUT")" = 28 ]'

echo "== 9. replay (drill mode: fixture files, no RPC)"
rm -f "$T/args"
PFT_FW_CONF=/nonexistent PFT_FW_PARSER="$P" bash "$S" replay --container drill-fw --fee "$FXD/validator_fee.json" \
  --info "$FXD/validator_server_info.json" --textfile-dir "$T/tf" --now 1700000123 2> "$T/err"; echo $? > "$T/rc"
R="$T/tf/pft_feewatch_drill-fw.prom"
check "replay: rc 0, up 1, label drill-fw, given timestamp" 'rc 0 && has "$R" "pft_feewatch_up{container=\"drill-fw\"} 1" && has "$R" "pft_feewatch_collect_timestamp_seconds{container=\"drill-fw\"} 1700000123"'
check "replay: no RPC (docker never called)" '[ ! -e "$T/args" ]'
PFT_FW_CONF=/nonexistent PFT_FW_PARSER="$P" bash "$S" replay --container postfiatd --fee "$FXD/validator_fee.json" \
  --info "$FXD/validator_server_info.json" --textfile-dir "$T/tf" 2> "$T/err"; echo $? > "$T/rc"
check "replay refuses a real node name (rc 3, real textfile untouched)" 'rc 3 && grep -q "must start with drill-" "$T/err" && has "$OUT" "pft_feewatch_up{$L} 1"'
printf '{"result":' > "$T/broken.json"
PFT_FW_CONF=/nonexistent PFT_FW_PARSER="$P" bash "$S" replay --container drill-fw --fee "$T/broken.json" \
  --info "$FXD/validator_server_info.json" --textfile-dir "$T/tf" 2> "$T/err"; echo $? > "$T/rc"
check "replay of a broken fixture: rc 1, up 0" 'rc 1 && has "$R" "pft_feewatch_up{container=\"drill-fw\"} 0"'

echo "== 10. pull + validate (sentry textfile copied to the validator)"
answer sentry 'pass' 'pass'
env PFT_FW_CONF=/nonexistent PFT_FW_DOCKER="$T/bin/docker" PFT_FW_NOW=1700000000 PFT_FW_PARSER="$P" \
  bash "$S" collect --container postfiatd-sentry --textfile-dir "$T/tf" 2> /dev/null
mkdir -p "$T/remote"; mv "$T/tf/pft_feewatch_postfiatd-sentry.prom" "$T/remote/"
pull() { env PFT_FW_CONF=/nonexistent PULL_SSH="${PSSH:-env}" REMOTE_DIR="$T/remote" TEXTFILE_DIR="$T/tf" PULL_TIMEOUT=3 \
  bash "$S" pull --container postfiatd-sentry 2> "$T/err"; echo $? > "$T/rc"; }
PF="$T/tf/pft_feewatch_postfiatd-sentry.prom"
pull
check "pull: rc 0, file copied byte for byte" 'rc 0 && cmp -s "$PF" "$T/remote/pft_feewatch_postfiatd-sentry.prom"'
cp "$PF" "$T/good.prom"
printf 'pft_feewatch_up{container="postfiatd"} 1\n' >> "$T/remote/pft_feewatch_postfiatd-sentry.prom"; pull
check "pull: a sample for another container is rejected (rc 2), old copy kept" 'rc 2 && cmp -s "$PF" "$T/good.prom"'
cp "$T/good.prom" "$T/remote/pft_feewatch_postfiatd-sentry.prom"; printf 'node_load1 99\n' >> "$T/remote/pft_feewatch_postfiatd-sentry.prom"; pull
check "pull: a foreign metric is rejected (rc 2)" 'rc 2 && grep -q "not a pft_feewatch_ sample" "$T/err"'
grep -v "^pft_feewatch_up" "$T/good.prom" > "$T/remote/pft_feewatch_postfiatd-sentry.prom"; pull
check "pull: a file without pft_feewatch_up is rejected (rc 2)" 'rc 2 && grep -q "no pft_feewatch_up sample" "$T/err"'
cp "$T/good.prom" "$T/remote/pft_feewatch_postfiatd-sentry.prom"; printf 'pft_feewatch_admin{container="postfiatd-sentry"} NaN\n' >> "$T/remote/pft_feewatch_postfiatd-sentry.prom"; pull
check "pull: a non-numeric value is rejected (rc 2)" 'rc 2 && grep -q "malformed sample" "$T/err"'
rm -f "$T/remote/pft_feewatch_postfiatd-sentry.prom"; pull
check "pull: unreachable/missing remote file -> rc 1, old copy kept, no temp files" 'rc 1 && cmp -s "$PF" "$T/good.prom" && [ -z "$(find "$T/tf" -name ".pull-*")" ]'
printf '#!/bin/sh\nsleep 30\n' > "$T/bin/slowssh"; chmod +x "$T/bin/slowssh"
s=$(date +%s); PSSH="$T/bin/slowssh" pull; e=$(( $(date +%s) - s ))
check "pull: hung ssh ended by PULL_TIMEOUT (3 s): rc 1 after ${e}s" 'rc 1 && [ "$e" -ge 3 ] && [ "$e" -lt 10 ]'

echo "== 11. lint"
check "shellcheck pft-feewatch.sh" 'shellcheck "$S"'
check "parser compiles" 'python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$P"'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
