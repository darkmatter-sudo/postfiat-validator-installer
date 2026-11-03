#!/usr/bin/env bash
# Offline tests for pft-upgradewatch.sh (+ upgradewatch_parse.py through it): a stub docker answers the four RPCs and
# the config grep from fixture files (real answers from tests/fixtures), a stub curl answers the foundation RPC and a
# stub ssh serves a sentry textfile. No root, no network, nothing on the host is read or changed.
#   bash upgradewatch/tests/run-tests.sh [SCRIPT [PARSER]]   (defaults ../pft-upgradewatch.sh ../upgradewatch_parse.py)
# Temp files live under ${TEST_TMPDIR:-~/.cache} (/tmp is noexec on these hosts, so stubs could not run there).
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; OUT, L, why are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-upgradewatch.sh}"
P="${2:-$HERE/../upgradewatch_parse.py}"
FXD="$HERE/fixtures"
TROOT="${TEST_TMPDIR:-$HOME/.cache}"; mkdir -p "$TROOT"
T="$(mktemp -d "$TROOT/uw-sh.XXXXXX")"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }   # NAME CONDITION (subshell: an exit in it is a FAIL)
has()   { grep -qxF -- "$2" "$1"; }                              # FILE LINE (exact)

# stub docker: `docker exec NAME curl ... -d BODY URL` prints $T/a/<key>.json by the method in BODY;
# `docker exec NAME grep -E RE FILE` prints $T/a/cfg.txt with grep's exit code in $T/a/cfg.rc (default 0).
# $T/fail-<key> -> exit 1 with a daemon error; $T/hang-<key> -> really sleeps 60; $T/warn -> a CLI warning on stderr.
mkdir -p "$T/bin" "$T/tf" "$T/a"
cat > "$T/bin/docker" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >> "$T/args"
[ "\$1" = exec ] || exit 1
[ -e "$T/warn" ] && echo "WARNING: Error loading config file: open /root/.docker/config.json: permission denied" >&2
case "\$3" in
  grep)
    [ -e "$T/hang-cfg" ] && sleep 60
    [ -e "$T/fail-cfg" ] && { echo "grep: /etc/postfiatd/postfiatd.cfg: No such file or directory" >&2; exit 2; }
    cat "$T/a/cfg.txt"; exit "\$(cat "$T/a/cfg.rc" 2>/dev/null || echo 0)" ;;
  curl) ;;
  *) exit 1 ;;
esac
case "\$*" in
  *'"method":"server_info"'*) k=server_info ;;
  *'"method":"feature"'*) k=feature ;;
  *'"method":"peers"'*) k=peers ;;
  *'"method":"ledger_entry"'*) k=amendments ;;
  *) exit 1 ;;
esac
[ -e "$T/hang-\$k" ] && sleep 60
[ -e "$T/fail-\$k" ] && { echo "Error response from daemon: container is not running" >&2; exit 1; }
cat "$T/a/\$k.json"
STUB
cat > "$T/bin/curl" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >> "$T/curlargs"
[ -e "$T/fail-foundation" ] && exit 7
cat "$T/a/foundation.json"
STUB
cat > "$T/bin/fakessh" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >> "$T/sshargs"
[ -e "$T/fail-ssh" ] && exit 255
cat "$T/remote.prom"
STUB
chmod +x "$T/bin/docker" "$T/bin/curl" "$T/bin/fakessh"

reset() { # fresh answers = the validator's real fixtures
  rm -f "$T"/fail-* "$T"/hang-* "$T/warn" "$T/a/cfg.rc"
  for k in server_info feature peers amendments; do cp "$FXD/validator_$k.json" "$T/a/$k.json"; done
  cp "$FXD/validator_majority_cfg.txt" "$T/a/cfg.txt"
  cp "$FXD/foundation_server_info.json" "$T/a/foundation.json"
}
run() { # [collect args] -> $OUT, $T/rc, $T/err
  rm -f "$T/err" "$T/args" "$T/curlargs"
  env PFT_UW_CONF="${CONFX:-/nonexistent}" PFT_UW_DOCKER="$T/bin/docker" PFT_UW_CURL="$T/bin/curl" \
    PFT_UW_NOW=1700000000 PFT_UW_PARSER="$P" RPC_TIMEOUT=1 FOUNDATION_TIMEOUT=1 ${RUNENV:+"$RUNENV"} \
    bash "$S" collect --container postfiatd --textfile-dir "$T/tf" "$@" > "$T/out" 2> "$T/err"
  echo $? > "$T/rc"
}
OUT="$T/tf/pft_upgradewatch_postfiatd.prom"
L='container="postfiatd"'
rc() { [ "$(cat "$T/rc")" = "$1" ]; }
samples() { grep -vc '^#' "$OUT"; }
down() { # REASON CASE: assertions for a failed collection
  why="$1"
  check "$2: rc 1" 'rc 1'
  check "$2: up 0" 'has "$OUT" "pft_upgradewatch_up{$L} 0"'
  check "$2: only up + timestamp (no stale values)" '[ "$(samples)" = 2 ]'
  check "$2: reason on stderr" 'grep -qF -- "$why" "$T/err"'
}

echo "== happy path (real validator answers)"
reset; run
check "rc 0" 'rc 0'
check "up 1" 'has "$OUT" "pft_upgradewatch_up{$L} 1"'
check "timestamp = PFT_UW_NOW" 'has "$OUT" "pft_upgradewatch_collect_timestamp_seconds{$L} 1700000000"'
check "majority time 3 days from config" 'has "$OUT" "pft_upgradewatch_majority_time_seconds{$L} 259200" && has "$OUT" "pft_upgradewatch_majority_time_from_config{$L} 1"'
check "no unsupported ETA" 'has "$OUT" "pft_upgradewatch_unsupported_activation_eta_seconds{$L} 0"'
check "build and foundation versions" 'has "$OUT" "pft_upgradewatch_build_info{$L,version=\"1.0.9\"} 1" && has "$OUT" "pft_upgradewatch_foundation_build_info{$L,version=\"1.0.9\"} 1"'
check "19 versioned peers" 'has "$OUT" "pft_upgradewatch_peers_versioned{$L} 19"'
check "textfile passes validate" 'bash "$S" validate "$OUT" postfiatd'
check "exactly 4 RPC calls + 1 config grep" '[ "$(grep -c " curl " "$T/args")" = 4 ] && [ "$(grep -c " grep " "$T/args")" = 1 ]'
check "only allowlisted methods sent" '! grep -oE "\"method\":\"[a-z_]+\"" "$T/args" | grep -vqE "\"(server_info|feature|peers|ledger_entry)\""'
check "ledger_entry asks the validated Amendments object" 'grep -qF "\"index\":\"7DB0788C020F02780A673DC74757F23823FA3014C1866E72CC4CD8B226CD6EF4\",\"ledger_index\":\"validated\"" "$T/args"'
check "config grep reads only headers + duration lines" 'grep " grep " "$T/args" | grep -qF -- "-E ^[[:space:]]*(\[[^]]*\]|[0-9]+[[:space:]]*(minutes|hours|days|weeks)([[:space:]].*)?)[[:space:]]*\$ /etc/postfiatd/postfiatd.cfg"'
check "foundation asked once at the default URL" '[ "$(wc -l < "$T/curlargs")" = 1 ] && grep -qF "https://rpc.testnet.postfiat.org" "$T/curlargs"'
check "no temp files left in the textfile dir" '[ -z "$(find "$T/tf" -name ".*")" ]'
check "nothing on stderr" '[ ! -s "$T/err" ]'

echo "== --stdout writes nothing"
rm -f "$OUT"; reset; run --stdout
check "--stdout: rc 0, file absent" 'rc 0 && [ ! -e "$OUT" ]'
check "--stdout: up 1 printed" 'grep -qxF "pft_upgradewatch_up{$L} 1" "$T/out"'

echo "== each node-side failure gives up 0"
for k in server_info feature peers amendments; do
  reset; run; reset; touch "$T/fail-$k"; run   # a good file first, so "no stale values" is meaningful
  down "$k via docker exec postfiatd failed" "fail-$k"
done
reset; touch "$T/fail-cfg"; run
down "config grep via docker exec postfiatd failed" "config grep rc 2"
reset; echo 'not json' > "$T/a/feature.json"; run
down "feature: not readable JSON" "non-JSON feature answer"
reset; printf '{"result":{"status":"error","error":"noPermission"}}' > "$T/a/peers.json"; run
down "peers: rpc error 'noPermission'" "rpc error answer"
reset; printf '[amendment_majority_time]\n10 minutes\n' > "$T/a/cfg.txt"; run
down "below the 15 minute minimum" "majority time below the node's minimum"

echo "== hang is bounded by timeout (RPC_TIMEOUT=1 -> 6 s)"
reset; touch "$T/hang-feature"; t0=$(date +%s); run; el=$(( $(date +%s) - t0 ))
down "feature via docker exec postfiatd failed" "hang-feature"
check "hang-feature: finished in < 15 s (took ${el}s)" '[ "$el" -lt 15 ]'
reset; touch "$T/hang-cfg"; t0=$(date +%s); run; el=$(( $(date +%s) - t0 ))
down "config grep via docker exec postfiatd failed" "hang-cfg"
check "hang-cfg: finished in < 15 s (took ${el}s)" '[ "$el" -lt 15 ]'

echo "== tolerated conditions keep up 1"
reset; touch "$T/warn"; run
check "docker CLI warning on stderr: up 1" 'rc 0 && has "$OUT" "pft_upgradewatch_up{$L} 1"'
reset; : > "$T/a/cfg.txt"; echo 1 > "$T/a/cfg.rc"; run
check "section absent (grep rc 1): up 1, 2 week default" 'rc 0 && has "$OUT" "pft_upgradewatch_majority_time_seconds{$L} 1209600" && has "$OUT" "pft_upgradewatch_majority_time_from_config{$L} 0"'
reset; touch "$T/fail-foundation"; run
check "foundation down: up 1, foundation_known 0, behind 0" 'rc 0 && has "$OUT" "pft_upgradewatch_up{$L} 1" && has "$OUT" "pft_upgradewatch_foundation_known{$L} 0" && has "$OUT" "pft_upgradewatch_behind_foundation{$L} 0"'
check "foundation down: no answer file passed to the parser (no warning)" '[ ! -s "$T/err" ]'
reset; : > "$T/a/foundation.json"; run
check "foundation empty answer: foundation_known 0" 'rc 0 && has "$OUT" "pft_upgradewatch_foundation_known{$L} 0"'
check "foundation empty answer: not passed to the parser (no warning)" '[ ! -s "$T/err" ]'
reset; RUNENV="FOUNDATION_URL=" run
check "FOUNDATION_URL empty: curl never called, known 0" 'rc 0 && [ ! -e "$T/curlargs" ] && has "$OUT" "pft_upgradewatch_foundation_known{$L} 0"'
reset; python3 -I - "$T/a/foundation.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1])); d["result"]["info"]["build_version"] = "1.0.10"
json.dump(d, open(sys.argv[1], "w"))
PYEOF
run
check "foundation on 1.0.10: behind_foundation 1" 'rc 0 && has "$OUT" "pft_upgradewatch_behind_foundation{$L} 1"'

echo "== injected unsupported majority through the real collector path"
reset; python3 -I - "$T/a/amendments.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["result"]["node"]["Majorities"] = [{"Majority": {"Amendment": "AB" * 32, "CloseTime": 815000000}}]
json.dump(d, open(sys.argv[1], "w"))
PYEOF
run
check "unsupported majority counted" 'has "$OUT" "pft_upgradewatch_majority_amendments{$L,supported=\"no\"} 1"'
check "ETA = 815000000 + 946684800 + 259200 = 1761944000" 'has "$OUT" "pft_upgradewatch_unsupported_activation_eta_seconds{$L} 1761944000"'

echo "== config and argument guards"
# FOUNDATION_URL: a conf value no command-line flag overrides (--container would hide a sourced CONTAINER=)
reset; printf 'FOUNDATION_URL=https://evil.example\n' > "$T/conf"; CONFX="$T/conf" run
check "non-root-owned conf is ignored" 'rc 0 && grep -qF "https://rpc.testnet.postfiat.org" "$T/curlargs" && ! grep -q evil "$T/curlargs"'
reset; rm -f "$T/err"
for a in "--container bad/name" "--bogus"; do
  # shellcheck disable=SC2086
  env PFT_UW_CONF=/nonexistent PFT_UW_PARSER="$P" bash "$S" collect $a --textfile-dir "$T/tf" 2>/dev/null; r=$?
  check "collect $a: rc 3" '[ "$r" = 3 ]'
done
for e in RPC_TIMEOUT=0 RPC_TIMEOUT=abc FOUNDATION_TIMEOUT=100 "NODE_CFG=rel/path" "NODE_CFG=/etc/x;id"; do
  env PFT_UW_CONF=/nonexistent PFT_UW_PARSER="$P" PFT_UW_DOCKER="$T/bin/docker" "$e" bash "$S" collect \
    --textfile-dir "$T/tf" 2>/dev/null; r=$?
  check "$e: rc 3" '[ "$r" = 3 ]'
done
env PFT_UW_CONF=/nonexistent PFT_UW_PARSER=/nonexistent bash "$S" collect 2>/dev/null; r=$?
check "missing parser: rc 3" '[ "$r" = 3 ]'

echo "== replay (drill mode)"
reset; mkdir -p "$T/fx"
for k in feature peers amendments; do cp "$T/a/$k.json" "$T/fx/$k.json"; done
cp "$T/a/server_info.json" "$T/fx/info.json"; cp "$T/a/cfg.txt" "$T/fx/cfg.txt"
env PFT_UW_CONF=/nonexistent PFT_UW_PARSER="$P" bash "$S" replay --container postfiatd --fixtures "$T/fx" \
  --textfile-dir "$T/tf" 2>/dev/null; r=$?
check "replay to a real node name refused (rc 3)" '[ "$r" = 3 ]'
env PFT_UW_CONF=/nonexistent PFT_UW_PARSER="$P" bash "$S" replay --container drill-x --fixtures "$T/nope" \
  --textfile-dir "$T/tf" 2>/dev/null; r=$?
check "replay without a fixture dir: rc 3" '[ "$r" = 3 ]'
env PFT_UW_CONF=/nonexistent PFT_UW_PARSER="$P" bash "$S" replay --container drill-x --fixtures "$T/fx" \
  --textfile-dir "$T/tf" --now 1700000123 2>/dev/null; r=$?
D="$T/tf/pft_upgradewatch_drill-x.prom"
check "replay drill-x: rc 0, up 1, --now stamped, foundation unknown" '[ "$r" = 0 ] && has "$D" "pft_upgradewatch_up{container=\"drill-x\"} 1" && has "$D" "pft_upgradewatch_collect_timestamp_seconds{container=\"drill-x\"} 1700000123" && has "$D" "pft_upgradewatch_foundation_known{container=\"drill-x\"} 0"'
cp "$T/a/foundation.json" "$T/fx/foundation.json"
env PFT_UW_CONF=/nonexistent PFT_UW_PARSER="$P" bash "$S" replay --container drill-x --fixtures "$T/fx" \
  --textfile-dir "$T/tf" 2>/dev/null
check "replay reads fx/foundation.json when present" 'has "$D" "pft_upgradewatch_foundation_known{container=\"drill-x\"} 1"'
echo garbage > "$T/fx/peers.json"
env PFT_UW_CONF=/nonexistent PFT_UW_PARSER="$P" bash "$S" replay --container drill-x --fixtures "$T/fx" \
  --textfile-dir "$T/tf" 2>/dev/null; r=$?
check "replay of a broken fixture: rc 1, up 0" '[ "$r" = 1 ] && has "$D" "pft_upgradewatch_up{container=\"drill-x\"} 0"'

echo "== validate"
reset; run
v() { bash "$S" validate "$1" "$2" > "$T/vout" 2>&1; echo $?; }
check "valid file, right name: 0" '[ "$(v "$OUT" postfiatd)" = 0 ]'
check "valid file, other name: 2" '[ "$(v "$OUT" postfiatd-sentry)" = 2 ] && grep -q "first label" "$T/vout"'
{ cat "$OUT"; echo 'node_load1{container="postfiatd"} 1'; } > "$T/x1"
check "foreign metric: 2" '[ "$(v "$T/x1" postfiatd)" = 2 ] && grep -q "not a pft_upgradewatch_ sample" "$T/vout"'
grep -v '^pft_upgradewatch_up{' "$OUT" > "$T/x2"
check "no up sample: 2" '[ "$(v "$T/x2" postfiatd)" = 2 ] && grep -q "no pft_upgradewatch_up" "$T/vout"'
grep -v '^pft_upgradewatch_collect_timestamp_seconds{' "$OUT" > "$T/x3"
check "no timestamp sample: 2" '[ "$(v "$T/x3" postfiatd)" = 2 ] && grep -q "no pft_upgradewatch_collect_timestamp" "$T/vout"'
{ cat "$OUT"; echo 'pft_upgradewatch_up{container="postfiatd"} NaN'; } > "$T/x4"
check "non-numeric value: 2" '[ "$(v "$T/x4" postfiatd)" = 2 ] && grep -q "malformed sample" "$T/vout"'
{ cat "$OUT"; head -c 70000 /dev/zero | tr '\0' '#'; } > "$T/x5"
check "too big: 2" '[ "$(v "$T/x5" postfiatd)" = 2 ] && grep -q "too big" "$T/vout"'

echo "== pull (validator copies the sentry textfile)"
SN="$T/tf/pft_upgradewatch_postfiatd-sentry.prom"
pullrun() {
  env PFT_UW_CONF=/nonexistent PULL_SSH="$T/bin/fakessh relay" TEXTFILE_DIR="$T/tf" REMOTE_DIR=/var/lib/x \
    bash "$S" pull --container postfiatd-sentry 2> "$T/perr"; echo $? > "$T/prc"
}
rm -f "$T/sshargs"
sed 's/container="postfiatd"/container="postfiatd-sentry"/' "$OUT" > "$T/remote.prom"; pullrun
check "pull good file: rc 0, copied byte-identical" '[ "$(cat "$T/prc")" = 0 ] && cmp -s "$T/remote.prom" "$SN"'
check "pull asked for the right remote file" 'grep -qxF "relay cat -- /var/lib/x/pft_upgradewatch_postfiatd-sentry.prom" "$T/sshargs"'
cp "$SN" "$T/before"; cp "$OUT" "$T/remote.prom"; pullrun
check "pull wrong-container file: rc 2, old copy kept" '[ "$(cat "$T/prc")" = 2 ] && cmp -s "$T/before" "$SN"'
touch "$T/fail-ssh"; pullrun; rm -f "$T/fail-ssh"
check "pull ssh failure: rc 1, old copy kept" '[ "$(cat "$T/prc")" = 1 ] && cmp -s "$T/before" "$SN"'
check "pull leaves no temp files" '[ -z "$(find "$T/tf" -name ".pull-*")" ]'
env PFT_UW_CONF=/nonexistent PULL_SSH= TEXTFILE_DIR="$T/tf" bash "$S" pull 2>/dev/null; r=$?
check "pull without PULL_SSH: rc 3" '[ "$r" = 3 ]'

echo "== misc"
check "version" '[ "$(bash "$S" version)" = "pft-upgradewatch 1" ]'
bash "$S" bogus 2>/dev/null; r=$?
check "unknown command: rc 3" '[ "$r" = 3 ]'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
