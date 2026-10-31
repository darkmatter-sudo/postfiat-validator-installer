#!/usr/bin/env bash
# Offline tests for pft-valkeys.sh: argument parsing, sequence comparison, permission grading, key-dir and
# config-permission audits on fixtures, and every refusal case. No real docker, keys or node: stub-docker.sh fakes
# validator-keys and the node's docker exec answers. One PASS/FAIL line per check; exit 1 if any failed.
#   Usage: valkeys/tests/run-tests.sh [PFT_VALKEYS_SH]
# shellcheck disable=SC2016,SC2034  # check conditions are single-quoted and eval'd by check()
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$(readlink -f "${1:-$HERE/../pft-valkeys.sh}")"
T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf "${T:?}"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $*"; [ -z "${PFT_TEST_DEBUG:-}" ] || sed 's/^/    | /' "$T/out" | head -20; }
check() { if (eval "$2") >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
run() { "$TOOL" "$@" > "$T/out" 2>&1; RC=$?; }   # run ARGS : output in $T/out, exit code in RC

export PFT_VK_DOCKER="$HERE/stub-docker.sh" PFT_VK_NOW=1800000000
N=0
newstub() { N=$((N + 1)); STUB="$T/stub.$N"; mkdir -p "$STUB"; export STUB; }
# node fixture: node MODE CFG_SECTIONS VALIDATOR_SEQ [EPHEMERAL]  (VALIDATOR_SEQ "-" = not a validator)
MASTER=nHUnc2jFGNKsoQwbdGpiy1mpnoMJRMzwUa21oqYRD464FxG5fv5T
EPH=n9KAa2zVWjPHgfzsE3iZ8HAbzJtPrnoh4H2M2HgE7dfqtvyEb1KJ
node() {
  newstub
  echo "$1 0" > "$STUB/stat"; printf '%b\n' "$2" > "$STUB/cfg"
  if [ "$3" = - ]; then
    echo '{"result":{"info":{"server_state":"full","pubkey_validator":"none"}}}' > "$STUB/server_info.json"
    echo '{"result":{"status":"error","error":"invalidParams","error_message":"not a validator"}}' > "$STUB/validator_info.json"
  else
    echo "{\"result\":{\"info\":{\"server_state\":\"proposing\",\"pubkey_validator\":\"$MASTER\"}}}" > "$STUB/server_info.json"
    echo "{\"result\":{\"status\":\"success\",\"master_key\":\"$MASTER\",\"ephemeral_key\":\"${4-$EPH}\",\"seq\":$3}}" > "$STUB/validator_info.json"
  fi
}
TOK='[server]\n[validator_token]\neyJ...'

echo "== argument parsing"
run; check "no args -> usage exit 3" '[ $RC = 3 ] && grep -q Usage: $T/out'
run keys; check "keys without create -> 3" '[ $RC = 3 ]'
run token create --dir "$T/x"; check "token create (not rotate) -> 3" '[ $RC = 3 ]'
run keys create; check "keys create without --dir -> 3" '[ $RC = 3 ]'
run keys create --dir "$T/x" --bogus 1; check "unknown option -> 3" '[ $RC = 3 ]'
run check --bogus; check "check unknown option -> 3" '[ $RC = 3 ]'
run check --host 'bad host'; check "check bad --host label -> 3" '[ $RC = 3 ]'
run check --container ''; check "check empty --container -> 3" '[ $RC = 3 ]'
run version; check "version -> 0" '[ $RC = 0 ] && grep -q "^pft-valkeys [0-9]" $T/out'

echo "== sequence comparison / permission grading (sourced)"
# shellcheck source=/dev/null
sc() { (PFT_VK_LIB=1; . "$TOOL"; seq_compare "$1" "$2"); }
# shellcheck source=/dev/null
pg() { (PFT_VK_LIB=1; . "$TOOL"; perm_grade "$1" "$2"); }
for c in "1||first" "2|2|same" "3|2|advanced" "1|2|regression" "9|10|regression" "10|9|advanced" \
         "4294967295|3|advanced" "x|1|invalid" "1|x|invalid" "|1|invalid" "-1|2|invalid"; do
  IFS='|' read -r a b want <<<"$c"; got="$(sc "$a" "$b")"
  if [ "$got" = "$want" ]; then ok "seq_compare '$a' '$b' = $want"; else bad "seq_compare '$a' '$b' = $got, want $want"; fi
done
for c in "600|1|ok" "400|1|ok" "640|1|warn" "660|1|warn" "644|1|fail" "604|1|fail" "755|1|fail" "644|0|ok" "777|0|ok"; do
  IFS='|' read -r a b want <<<"$c"; got="$(pg "$a" "$b")"
  if [ "$got" = "$want" ]; then ok "perm_grade $a secret=$b = $want"; else bad "perm_grade $a secret=$b = $got, want $want"; fi
done

echo "== keys create / token rotate / revoke (stub validator-keys)"
newstub; K="$T/k1"
run keys create --dir "$K"
check "create: exit 0" '[ $RC = 0 ]'
check "create: dir 700, key file 600" '[ "$(stat -c %a $K)" = 700 ] && [ "$(stat -c %a $K/validator-keys.json)" = 600 ]'
check "create: prints public key" 'grep -q "public_key nHStubPublicKey" $T/out'
check "create: secret not on stdout" '! grep -q STUBSECRET $T/out'
check "create: container isolated (network none, read-only, cap-drop, no-new-privileges)" \
  'grep "create_keys" $STUB/calls | grep -q -- "--network none --read-only --cap-drop ALL --security-opt no-new-privileges"'
check "create: no temp output file left" '[ -z "$(ls -A $K | grep -v validator-keys.json)" ]'
run keys create --dir "$K"; check "create: refuse existing key file (2)" '[ $RC = 2 ] && grep -q "refusing to overwrite" $T/out'
mkdir -m 755 "$T/loose"; run keys create --dir "$T/loose"; check "create: refuse dir mode 755 (2)" '[ $RC = 2 ] && grep -q "need 700" $T/out'
ln -s "$K" "$T/klink"; run keys create --dir "$T/klink"; check "create: refuse symlinked dir (2)" '[ $RC = 2 ] && grep -q symlink $T/out'
touch "$T/afile"; run keys create --dir "$T/afile"; check "create: refuse non-directory (2)" '[ $RC = 2 ] && grep -q "not a directory" $T/out'
mkdir -m 700 "$T/kf"; touch "$STUB/vk-fail"; run keys create --dir "$T/kf"
check "create: validator-keys failure -> 2, no temp file left" '[ $RC = 2 ] && [ -z "$(ls -A $T/kf)" ]'; rm -f "$STUB/vk-fail"

run token rotate --dir "$K"
check "rotate: 0 -> 1, exit 0" '[ $RC = 0 ] && grep -q "token sequence 0 -> 1" $T/out'
check "rotate: token file 600 with header + lines" '[ "$(stat -c %a $K/token-seq1.cfg)" = 600 ] && [ "$(head -1 $K/token-seq1.cfg)" = "[validator_token]" ] && [ "$(wc -l < $K/token-seq1.cfg)" = 3 ]'
check "rotate: token not on stdout" '! grep -q STUBTOKEN $T/out'
check "rotate: only the token block is kept (no banner text)" '! grep -q -e Update -e "public key" $K/token-seq1.cfg'
run token rotate --dir "$K"; check "rotate: 1 -> 2 into token-seq2.cfg" '[ $RC = 0 ] && [ -f $K/token-seq2.cfg ]'
run token rotate --dir "$K" --out "$K/token-seq1.cfg"; check "rotate: refuse existing --out (2)" '[ $RC = 2 ] && grep -q "refusing to overwrite" $T/out'
check "rotate: refused run did not bump the sequence" '[ "$(jq .token_sequence $K/validator-keys.json)" = 2 ]'
mkdir -m 777 "$T/open"; run token rotate --dir "$K" --out "$T/open/t.cfg"; check "rotate: refuse --out in group/other-writable dir (2)" '[ $RC = 2 ] && grep -q writable $T/out'
STUB_INC=2 run token rotate --dir "$K"; check "rotate: sequence jump 2 -> 4 refused (2), no token file" '[ $RC = 2 ] && grep -q "expected 3" $T/out && [ ! -e $K/token-seq3.cfg ]'
jq '.token_sequence = 2' "$K/validator-keys.json" > "$T/j" && cat "$T/j" > "$K/validator-keys.json"
chmod 644 "$K/validator-keys.json"; run token rotate --dir "$K"; check "rotate: refuse key file mode 644 (2)" '[ $RC = 2 ] && grep -q "need 600" $T/out'
chmod 600 "$K/validator-keys.json"
run token rotate --dir "$T/nokeys"; check "rotate: refuse missing dir (2)" '[ $RC = 2 ]'
mkdir -m 700 "$T/notkeys"; echo '{"a":1}' > "$T/notkeys/validator-keys.json"; chmod 600 "$T/notkeys/validator-keys.json"
run token rotate --dir "$T/notkeys"; check "rotate: refuse non-validator-keys json (2)" '[ $RC = 2 ] && grep -q "not a validator-keys file" $T/out'

run revoke --dir "$K" </dev/null; check "revoke: no --confirm-key -> refused (2)" '[ $RC = 2 ] && grep -q confirm-key $T/out'
run revoke --dir "$K" --confirm-key nHother --confirm-phrase "REVOKE nHother" </dev/null; check "revoke: wrong key -> refused (2)" '[ $RC = 2 ]'
run revoke --dir "$K" --confirm-key nHStubPublicKey </dev/null; check "revoke: no phrase, stdin not a tty -> refused (2)" '[ $RC = 2 ] && grep -q "not a terminal" $T/out'
run revoke --dir "$K" --confirm-key nHStubPublicKey --confirm-phrase "REVOKE" </dev/null; check "revoke: wrong phrase -> refused (2)" '[ $RC = 2 ] && grep -q "does not match" $T/out'
check "revoke: refusals never called validator-keys" '! grep -q revoke_keys $STUB/calls'
run revoke --dir "$K" --confirm-key nHStubPublicKey --confirm-phrase "REVOKE nHStubPublicKey" </dev/null
check "revoke: key + phrase -> 0, revocation.cfg 600" '[ $RC = 0 ] && [ "$(stat -c %a $K/revocation.cfg)" = 600 ] && [ "$(head -1 $K/revocation.cfg)" = "[validator_key_revocation]" ]'
check "revoke: revocation blob not on stdout" '! grep -q STUBREVOKE $T/out'
run revoke --dir "$K" --confirm-key nHStubPublicKey --confirm-phrase "REVOKE nHStubPublicKey" </dev/null; check "revoke: already revoked -> refused (2)" '[ $RC = 2 ] && grep -q "already revoked" $T/out'
run token rotate --dir "$K"; check "rotate: refuse revoked key (2)" '[ $RC = 2 ] && grep -q revoked $T/out'

echo "== check: config permission / section audit (fixtures)"
node 644 '[server]' -; run check
check "no token, 644: INFO, exit 0" '[ $RC = 0 ] && grep -q "^INFO conf.perms" $T/out && grep -q "not configured as a validator" $T/out'
node 600 "$TOK" 1; run check; check "token 600: OK, exit 0" '[ $RC = 0 ] && grep -q "^OK   conf.perms" $T/out'
node 640 "$TOK" 1; run check; check "token 640: WARN group-readable, exit 1" '[ $RC = 1 ] && grep -q "^WARN conf.perms.*group-readable" $T/out'
node 644 "$TOK" 1; run check; check "token 644: FAIL world-readable, exit 2" '[ $RC = 2 ] && grep -q "^FAIL conf.perms.*world-readable" $T/out'
node 600 '[validation_seed]\nsXXX' -; run check; check "validation_seed: WARN seed online + secret perms OK" '[ $RC = 1 ] && grep -q "^WARN conf.seed" $T/out && grep -q "^OK   conf.perms" $T/out'
node 644 '[validation_seed]\nsXXX' -; run check; check "validation_seed 644: FAIL perms" '[ $RC = 2 ] && grep -q "^FAIL conf.perms" $T/out'
node 600 "$TOK"'\n[validator_token]\nx' 1; run check; check "two token sections: FAIL" '[ $RC = 2 ] && grep -q "2 \[validator_token\] sections" $T/out'
node 600 '[validator_key_revocation]\nx' -; run check; check "revocation only: WARN, exit 1" '[ $RC = 1 ] && grep -q "^WARN conf.revocation" $T/out'
node 600 "$TOK"'\n[validator_key_revocation]\nx' 1; run check; check "token + revocation: FAIL" '[ $RC = 2 ] && grep -q "both \[validator_token\] and" $T/out'
node 600 "$TOK" 1; echo 1 > "$STUB/mk"; run check; check "master key json in container: WARN keys.online" '[ $RC = 1 ] && grep -q "^WARN keys.online" $T/out'
node 600 "$TOK" 1; touch "$STUB/down"; run check --textfile-dir "$T"
check "container down: FAIL, exit 2, textfile up 0" '[ $RC = 2 ] && grep -q "^FAIL conf.read" $T/out && grep -q "^pft_valkeys_up{host=\"validator\"} 0" $T/pft_valkeys_validator.prom'
check "check: never reads config contents (no cat/sed/awk exec)" '! grep -E "^exec [^ ]+ (cat|sed|awk|head|tail)" $T/stub.*/calls'

echo "== check: key directory audit"
node 600 "$TOK" 1
KD="$T/kd"; mkdir -m 700 "$KD"; : > "$KD/validator-keys.json"; chmod 600 "$KD/validator-keys.json"
run check --keydir "$KD"; check "keydir 700/600: OK" '[ $RC = 0 ] && grep -q "^OK   keys.perms" $T/out'
: > "$KD/token-seq1.cfg"; chmod 644 "$KD/token-seq1.cfg"; run check --keydir "$KD"
check "keydir: 644 token file FAIL naming the file" '[ $RC = 2 ] && grep -q "token-seq1.cfg mode 644" $T/out'
chmod 600 "$KD/token-seq1.cfg"; chmod 750 "$KD"; run check --keydir "$KD"; check "keydir mode 750: FAIL" '[ $RC = 2 ] && grep -q "mode 750, need 700" $T/out'
chmod 700 "$KD"; : > "$KD/.vk-out.abc"; chmod 644 "$KD/.vk-out.abc"; run check --keydir "$KD"
check "keydir: leftover 644 temp output FAIL" '[ $RC = 2 ] && grep -q ".vk-out.abc mode 644" $T/out'
run check --keydir "$T/none"; check "keydir missing: FAIL" '[ $RC = 2 ] && grep -q "not a directory" $T/out'

echo "== check: manifest sequence, ephemeral key, state + textfile"
ST="$T/state.json"; TF="$T/tf"; mkdir -p "$TF"
prom() { grep "^$1{" "$TF/pft_valkeys_validator.prom" | awk '{print $2}'; }
node 600 "$TOK" 3; run check --state "$ST" --textfile-dir "$TF"
check "seq 3 first record: OK, state written" '[ $RC = 0 ] && grep -q "first record" $T/out && [ "$(jq -r ".\"$MASTER\"" $ST)" = 3 ]'
check "textfile: sequence 3, regression 0, configured 1" '[ "$(prom pft_valkeys_manifest_sequence)" = 3 ] && [ "$(prom pft_valkeys_sequence_regression)" = 0 ] && [ "$(prom pft_valkeys_validator_configured)" = 1 ]'
check "textfile: mode 644, no temp left" '[ "$(stat -c %a $TF/pft_valkeys_validator.prom)" = 644 ] && [ -z "$(ls -A $TF | grep -v "^pft_valkeys_validator.prom$")" ]'
node 600 "$TOK" 3; run check --state "$ST"; check "seq 3 again: same" '[ $RC = 0 ] && grep -q "highest seen 3" $T/out'
node 600 "$TOK" 4; run check --state "$ST" --textfile-dir "$TF"; check "seq 4: advanced, state 4" '[ $RC = 0 ] && grep -q "advanced from 3" $T/out && [ "$(jq -r ".\"$MASTER\"" $ST)" = 4 ]'
node 600 "$TOK" 3; run check --state "$ST" --textfile-dir "$TF"
check "seq 3 after 4: FAIL regression, exit 2" '[ $RC = 2 ] && grep -q "LOWER than the highest seen (4)" $T/out'
check "regression: state keeps 4, textfile regression 1 max 4" '[ "$(jq -r ".\"$MASTER\"" $ST)" = 4 ] && [ "$(prom pft_valkeys_sequence_regression)" = 1 ] && [ "$(prom pft_valkeys_manifest_sequence_max)" = 4 ]'
check "textfile findings fail = 1" '[ "$(grep "grade=\"fail\"" $TF/pft_valkeys_validator.prom | awk "{print \$2}")" = 1 ]'
node 600 "$TOK" 3; echo '{"result":{"details":{"seq":5,"master_key":"x"}}}' > "$STUB/manifest.json"; run check
check "node knows newer manifest (5 > 3) without state: FAIL seq.network" '[ $RC = 2 ] && grep -q "^FAIL seq.network" $T/out'
node 600 "$TOK" 3; echo '{"result":{"details":{"seq":3}}}' > "$STUB/manifest.json"; run check; check "manifest seq equal: no seq.network finding" '[ $RC = 0 ] && ! grep -q seq.network $T/out'
node 600 "$TOK" 4294967295; run check; check "seq 0xFFFFFFFF: FAIL revoked" '[ $RC = 2 ] && grep -q "key is revoked" $T/out'
node 600 "$TOK" 3 ""; run check; check "missing ephemeral key: FAIL" '[ $RC = 2 ] && grep -q "^FAIL ephemeral" $T/out'
node 600 "$TOK" 3 "$MASTER"; run check; check "ephemeral == master: FAIL" '[ $RC = 2 ] && grep -q "^FAIL ephemeral" $T/out'
node 600 "$TOK" -; run check; check "token configured but not loaded: FAIL" '[ $RC = 2 ] && grep -q "configured but no validator key loaded" $T/out'
node 600 "$TOK" 3; echo "{\"result\":{\"info\":{\"server_state\":\"full\",\"pubkey_validator\":\"nHother\"}}}" > "$STUB/server_info.json"
run check; check "server_info / validator_info master mismatch: FAIL" '[ $RC = 2 ] && grep -q "differs from validator_info" $T/out'
node 600 "$TOK" 3; echo 'not json' > "$ST"; run check --state "$ST"; check "unreadable state: FAIL, file untouched" '[ $RC = 2 ] && grep -q "^FAIL seq.*not a JSON object" $T/out && [ "$(cat $ST)" = "not json" ]'
node 600 "$TOK" 3; run check --host sentry --textfile-dir "$TF"; check "--host label names the textfile" '[ -f $TF/pft_valkeys_sentry.prom ] && grep -q "host=\"sentry\"" $TF/pft_valkeys_sentry.prom'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
