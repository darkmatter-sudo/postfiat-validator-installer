#!/usr/bin/env bash
# test-sandbox: exercise pft-retention.sh apply/rollback against a throwaway container
# (postfiatd image, entrypoint `sleep`, stub curl), never against the live node.
# /etc/postfiatd is a named volume mounted READ-ONLY in the container (as strict as apparmor/'s profile, which
# denies the node writes to its own config), so apply/rollback must write through the volume's host path.
# The stub answers server_info with server_state "full", except "connected" while the
# config carries online_delete=2048 (simulates a config that never syncs -> auto-rollback).
#
# Usage: sudo ./test-sandbox.sh      exit 0 = all checks passed
set -euo pipefail
cd "$(dirname "$0")"
SB=pft-retention-sandbox
SBV=pft-retention-sandbox-cfg
IMAGE="${IMAGE:-agtipft/postfiatd:testnet-light-latest}"
TMP="$(mktemp -d)"
export CONTAINER=$SB BACKUP_DIR="$TMP/backups" STATE_DIR="$TMP/state"
PASS=0; FAIL=0
cleanup() { docker rm -f "$SB" >/dev/null 2>&1 || true; docker volume rm "$SBV" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
check() { # $1 name, $2 expected exit, rest = command
  local name="$1" want="$2" got=0; shift 2
  echo "---- $name: $*"
  "$@" || got=$?
  if [ "$got" -eq "$want" ]; then echo "PASS $name (exit $got)"; PASS=$((PASS + 1))
  else echo "FAIL $name (exit $got, want $want)"; FAIL=$((FAIL + 1)); fi
}
node_db() { docker exec "$SB" sed -n '/^\[node_db\]/,/^\[/p' /etc/postfiatd/postfiatd.cfg | grep -E '_delete|^type' ; }

echo "OS: $(grep ^PRETTY_NAME= /etc/os-release | cut -d= -f2- | tr -d '"')"
docker rm -f "$SB" >/dev/null 2>&1 || true
docker volume rm "$SBV" >/dev/null 2>&1 || true
docker volume create "$SBV" >/dev/null
VS="$(docker volume inspect -f '{{.Mountpoint}}' "$SBV")"
# Config skeleton: same [node_db]/[database_path] as the stock light image, no peers/keys.
install -m 644 /dev/stdin "$VS/postfiatd.cfg" <<'EOF'
[server]
port_rpc_admin_local

[node_db]
type=NuDB
path=/var/lib/postfiatd/db/nudb
online_delete=512
advisory_delete=0

[database_path]
/var/lib/postfiatd/db

[network_id]
2025
EOF
docker run -d --name "$SB" -v "$SBV:/etc/postfiatd:ro" --entrypoint sleep "$IMAGE" infinity >/dev/null
docker exec "$SB" mkdir -p /var/lib/postfiatd/db/nudb/postfiatdb.0001
docker exec -i "$SB" sh -c 'cat > /usr/local/sbin/curl && chmod 755 /usr/local/sbin/curl' <<'EOF'
#!/bin/sh
state=full
grep -q '^online_delete=2048' /etc/postfiatd/postfiatd.cfg && state=connected
printf '{"result":{"info":{"server_state":"%s","complete_ledgers":"1000-1600","validated_ledger":{"seq":1600}},"status":"success"}}\n' "$state"
EOF
echo "sandbox container up; initial [node_db]:"; node_db

check "container cannot write cfg" 0 sh -c "! docker exec $SB sh -c 'echo >> /etc/postfiatd/postfiatd.cfg' 2>/dev/null"
# shellcheck disable=SC2016  # $0 and PIPESTATUS expand in the inner bash
check "apply 1024"                0 bash -c './pft-retention.sh apply --online-delete 1024 --timeout 60 2>&1 | tee "$0"; exit "${PIPESTATUS[0]}"' "$TMP/apply1.out"
check "apply wrote via host mount" 0 grep -q "via host mount" "$TMP/apply1.out"
node_db
check "backup is 0600"            0 test "$(stat -c %a "$(cat "$BACKUP_DIR/LATEST")")" = 600
check "apply 1024 again (no-op)"  0 ./pft-retention.sh apply --online-delete 1024
check "rollback"                  0 ./pft-retention.sh rollback --timeout 60
node_db
check "rollback again (no-op)"    0 ./pft-retention.sh rollback
check "reject online_delete 100"  2 ./pft-retention.sh apply --online-delete 100
check "add advisory_delete=1"     0 ./pft-retention.sh apply --online-delete 512 --advisory-delete 1 --timeout 60
node_db
check "rollback advisory"         0 ./pft-retention.sh rollback --timeout 60
printf "\n[ledger_history]\n4000\n" >> "$VS/postfiatd.cfg"
check "reject ledger_history>od"  2 ./pft-retention.sh apply --online-delete 1024
head -n -3 "$VS/postfiatd.cfg" > "$TMP/c" && cat "$TMP/c" > "$VS/postfiatd.cfg"
check "never-full -> auto-rollback" 2 ./pft-retention.sh apply --online-delete 2048 --timeout 30
node_db
check "config back at 512"        0 sh -c "docker exec $SB grep -qx 'online_delete=512' /etc/postfiatd/postfiatd.cfg"
echo "backups kept: $(find "$BACKUP_DIR" -name 'postfiatd.cfg.*' | wc -l) (dir mode $(stat -c %a "$BACKUP_DIR"))"
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
