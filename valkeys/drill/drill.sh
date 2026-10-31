#!/usr/bin/env bash
# Isolated key-lifecycle drill for pft-valkeys (Ubuntu 22.04 host with Docker; the live nodes are only read).
#   live before -> keys create + refusals -> token seq 1 -> throwaway node (--network none) check
#   -> rotate seq 2 + restart + check -> old seq-1 token reinstalled: regression FAIL + metric
#   -> revoke (double confirmation) + node with revocation -> secret scan of this log -> destroy keys -> live after
# Every throwaway key lives in a mktemp dir and is shredded at the end (also on error, via trap).
#   Usage: valkeys/drill/drill.sh LOGFILE      (run from the repo root; uses sudo for docker on the live nodes)
set -uo pipefail
LOG="${1:?usage: drill.sh LOGFILE}"
TOOL=valkeys/pft-valkeys.sh
[ -x "$TOOL" ] || { echo "run from the repo root" >&2; exit 3; }
IMAGE="${PFT_VK_IMAGE:-agtipft/postfiatd:testnet-light-latest}"
NODE=pft-valkeys-drill
W="$(mktemp -d /tmp/valkeys-drill.XXXXXX)"; chmod 700 "$W"
K="$W/keys"
exec > >(tee "$LOG") 2>&1
PASS=0; FAILN=0
ok() { PASS=$((PASS + 1)); echo "CHECK PASS $*"; }
bad() { FAILN=$((FAILN + 1)); echo "CHECK FAIL $*"; }
x() { echo "\$ $*"; "$@"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
expect() { # expect RC NAME CMD... : run, check exit code
  local want="$1" name="$2"; shift 2
  x "$@"; local rc=$?
  if [ "$rc" = "$want" ]; then ok "$name (exit $rc)"; else bad "$name (exit $rc, want $want)"; fi
}
cleanup() {
  docker rm -f "$NODE" >/dev/null 2>&1
  find "$W" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$W"
}
trap cleanup EXIT
live() { # live TAG : server_state + integrity + config hash on validator and sentry (read-only)
  echo "--- live $1: validator"
  x sh -c "sudo docker exec postfiatd postfiatd --conf /etc/postfiatd/postfiatd.cfg server_info 2>/dev/null | jq -r '.result.info.server_state'"
  x sh -c "sudo docker exec postfiatd sha256sum /etc/postfiatd/postfiatd.cfg | cut -c1-64"
  x sh -c "sudo pft-integrity verify 2>&1 | grep RESULT"
  echo "--- live $1: sentry"
  x ssh relay "sudo docker exec postfiatd-sentry postfiatd --conf /etc/postfiatd/postfiatd.cfg server_info 2>/dev/null | jq -r '.result.info.server_state'"
  x ssh relay "sudo docker exec postfiatd-sentry sha256sum /etc/postfiatd/postfiatd.cfg | cut -c1-64"
  x ssh relay "sudo pft-integrity verify 2>&1 | grep RESULT"
}
node() { # node TOKENFILE : (re)start the throwaway node with the base config + one key section
  docker rm -f "$NODE" >/dev/null 2>&1
  [ -d "$W/node" ] || mkdir -m 700 "$W/node"
  { cat <<'EOF'
[server]
port_rpc_admin_local

[port_rpc_admin_local]
port = 5005
ip = 127.0.0.1
admin = 127.0.0.1
protocol = http

[node_db]
type=NuDB
path=/tmp/db/nudb

[database_path]
/tmp/db

[debug_logfile]
/tmp/debug.log

EOF
    cat "$1"; } > "$W/node/postfiatd.cfg"
  chmod 600 "$W/node/postfiatd.cfg"
  echo "\$ docker run -d --name $NODE --network none -v $W/node:/etc/postfiatd:ro $IMAGE (standalone, config = base + $(basename "$1"))"
  docker run -d --name "$NODE" --network none -v "$W/node:/etc/postfiatd:ro" --entrypoint postfiatd "$IMAGE" \
    --conf /etc/postfiatd/postfiatd.cfg -a --start >/dev/null || { bad "start $NODE"; return 1; }
  local i
  for i in $(seq 1 30); do
    docker exec "$NODE" postfiatd --conf /etc/postfiatd/postfiatd.cfg server_info 2>/dev/null | grep -q '"server_state"' && break
    sleep 1
  done
  echo "node up after ${i}s"
}
chk() { # chk WANT_RC NAME : read-only check against the throwaway node with state + textfile
  expect "$1" "$2" "$TOOL" check --container "$NODE" --state "$W/state.json" --textfile-dir "$W/tf" --host drill
  echo "\$ grep -v '^#' $W/tf/pft_valkeys_drill.prom"; grep -v '^#' "$W/tf/pft_valkeys_drill.prom"
}
metric() { awk -v m="$1" '$1 ~ "^"m"[{]" {print $2}' "$W/tf/pft_valkeys_drill.prom"; }

# shellcheck source=/dev/null
echo "# valkeys drill - $(date -u +%FT%TZ) - $(. /etc/os-release && echo "$PRETTY_NAME") - commit $(git rev-parse HEAD)"
echo "# sha256 $(sha256sum "$TOOL")"
echo "# sha256 $(sha256sum valkeys/drill/drill.sh)"
echo "# image $IMAGE $(docker image inspect "$IMAGE" --format '{{.Id}}')"
echo "# throwaway dir $W (mode $(stat -c %a "$W")), shredded at the end"
mkdir -m 700 "$W/tf"

echo "=== 1. live nodes before (read-only)"
live before
expect 0 "live validator check read-only" sudo "$TOOL" check --container postfiatd
echo "\$ ssh relay 'sudo bash -s -- check --container postfiatd-sentry' < $TOOL"
ssh relay 'sudo bash -s -- check --container postfiatd-sentry' < "$TOOL"; rc=$?; echo "(exit $rc)"
if [ "$rc" = 0 ]; then ok "live sentry check read-only (exit 0)"; else bad "live sentry check (exit $rc)"; fi

echo "=== 2. keys create (network-isolated container) + refusals"
expect 0 "keys create" "$TOOL" keys create --dir "$K"
PUB="$(jq -r .public_key "$K/validator-keys.json")"
x stat -c '%a %n' "$K" "$K/validator-keys.json"
if [ "$(stat -c %a "$K/validator-keys.json")" = 600 ] && [ "$(stat -c %a "$K")" = 700 ]; then ok "key dir 700, key file 600"; else bad "key modes"; fi
expect 2 "refuse overwrite of existing key file" "$TOOL" keys create --dir "$K"
mkdir -m 755 "$W/loose"; expect 2 "refuse key dir with mode 755" "$TOOL" keys create --dir "$W/loose"
ln -s "$K" "$W/link"; expect 2 "refuse symlinked key dir" "$TOOL" token rotate --dir "$W/link"

echo "=== 3. token seq 1"
expect 0 "token rotate 0 -> 1" "$TOOL" token rotate --dir "$K"
x stat -c '%a %n' "$K/token-seq1.cfg"
expect 2 "refuse overwrite of existing token file" "$TOOL" token rotate --dir "$K" --out "$K/token-seq1.cfg"
x jq -r .token_sequence "$K/validator-keys.json"
node "$K/token-seq1.cfg"
chk 0 "check seq 1 (first record)"
if [ "$(metric pft_valkeys_manifest_sequence)" = 1 ]; then ok "metric sequence 1"; else bad "metric sequence"; fi

echo "=== 4. rotate to seq 2 + restart"
expect 0 "token rotate 1 -> 2" "$TOOL" token rotate --dir "$K"
node "$K/token-seq2.cfg"
chk 0 "check seq 2 (advanced)"
if [ "$(metric pft_valkeys_manifest_sequence)" = 2 ] && [ "$(metric pft_valkeys_sequence_regression)" = 0 ]; then ok "metric sequence 2, regression 0"; else bad "metric after rotate"; fi
x jq -c 'map_values(.)' "$W/state.json"

echo "=== 5. regression: old seq-1 token reinstalled"
node "$K/token-seq1.cfg"
chk 2 "check detects old token (seq 1 < 2)"
if [ "$(metric pft_valkeys_sequence_regression)" = 1 ] && [ "$(metric pft_valkeys_manifest_sequence_max)" = 2 ]; then ok "metric regression 1, max 2"; else bad "metric after regression"; fi

echo "=== 6. revoke (double confirmation)"
expect 2 "refuse revoke without --confirm-key" "$TOOL" revoke --dir "$K" </dev/null
expect 2 "refuse revoke with wrong key" "$TOOL" revoke --dir "$K" --confirm-key nHwrongkey --confirm-phrase "REVOKE nHwrongkey" </dev/null
expect 2 "refuse revoke without phrase (stdin not a terminal)" "$TOOL" revoke --dir "$K" --confirm-key "$PUB" </dev/null
expect 2 "refuse revoke with wrong phrase" "$TOOL" revoke --dir "$K" --confirm-key "$PUB" --confirm-phrase "REVOKE" </dev/null
x jq -r .revoked "$K/validator-keys.json"
expect 0 "revoke with key + phrase" "$TOOL" revoke --dir "$K" --confirm-key "$PUB" --confirm-phrase "REVOKE $PUB" </dev/null
x stat -c '%a %n' "$K/revocation.cfg"
x jq -r .revoked "$K/validator-keys.json"
expect 2 "refuse token rotate on revoked key" "$TOOL" token rotate --dir "$K"
expect 2 "refuse second revoke" "$TOOL" revoke --dir "$K" --confirm-key "$PUB" --confirm-phrase "REVOKE $PUB" </dev/null
expect 0 "keydir audit 700/600" "$TOOL" check --container "$NODE" --keydir "$K" --host drill
chmod 644 "$K/token-seq2.cfg"; expect 2 "keydir audit flags a 644 token file" "$TOOL" check --container "$NODE" --keydir "$K" --host drill
node "$K/revocation.cfg"
chk 1 "check flags revocation config, node not validating"
if [ "$(metric pft_valkeys_validator_configured)" = 0 ]; then ok "metric validator_configured 0 after revoke"; else bad "metric after revoke"; fi

echo "=== 7. secret scan of this log"
sleep 1
SECRETS="$W/secrets.txt"
{ jq -r .secret_key "$K/validator-keys.json"
  grep -h -v '^\[' "$K"/token-seq*.cfg "$K/revocation.cfg"; } | awk 'length >= 12' > "$SECRETS"
echo "secret strings collected: $(wc -l < "$SECRETS") (master secret_key + every token/revocation line of >= 12 chars)"
hits="$(grep -c -F -f "$SECRETS" "$LOG")"
echo "exact secret matches in log: $hits"
if [ "$hits" = 0 ]; then ok "no secret string in the log"; else bad "secret string in log"; fi
b64="$(grep -o -E '[A-Za-z0-9+/=]{60,}' "$LOG" | grep -c -v -x -E '[0-9a-f]{64}')"
fld="$(grep -c -E '"secret_key"|validation_seed *=|^\[validator_token\]$|^\[validator_key_revocation\]$' "$LOG")"
gen=$((b64 + fld))
echo "generic pattern matches: $b64 base64 runs >= 60 chars (sha256 hex digests excluded) + $fld secret_key/seed/token/revocation lines"
if [ "$gen" = 0 ]; then ok "no generic secret pattern in the log"; else bad "generic secret pattern in log"; fi

echo "=== 8. destroy throwaway keys"
docker rm -f "$NODE" >/dev/null; x sh -c "docker ps -a --filter name=$NODE --format '{{.Names}}' | wc -l"
echo "files before shred: $(find "$W" -type f | wc -l)"
find "$W" -type f -exec shred -u {} +; rm -rf "$W"
if [ ! -e "$W" ]; then ok "throwaway dir shredded and removed"; else bad "throwaway dir still exists"; fi

echo "=== 9. live nodes after (read-only)"
live after
echo "DRILL RESULT: $PASS pass, $FAILN fail"
[ "$FAILN" = 0 ]
