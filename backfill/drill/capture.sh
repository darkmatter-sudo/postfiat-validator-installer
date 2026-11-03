#!/usr/bin/env bash
# capture: record complete_ledgers + [node_db] online_delete of both nodes as test fixtures (read-only).
#   bash backfill/drill/capture.sh OUTDIR 2>&1 | tee LOG    (agent user, repo root; uses sudo -n and `ssh relay`)
# For each node: server_info (admin RPC on the container loopback via docker exec), the [node_db] and
# [ledger_history] lines of postfiatd.cfg, and three complete_ledgers samples 10 s apart. Writes
# OUTDIR/<host>-server_info.json and OUTDIR/<host>-cfg.txt. Changes nothing.
set -u
export TZ=UTC
OUT="${1:?usage: capture.sh OUTDIR}"; RELAY="${RELAY:-relay}"
mkdir -p "$OUT"
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
on() { if [ "$1" = validator ]; then shift; bash -c "$*"; else shift; R "$*"; fi; }
RPC='sh -c '\''curl -s -m 5 -d "{\"method\":\"server_info\"}" http://127.0.0.1:5005/'\'''
echo "pft-backfill capture - $(date -u +%FT%TZ) - $(lsb_release -ds) | remote: $(R lsb_release -ds)"
for h in validator:postfiatd sentry:postfiatd-sentry; do
  host="${h%%:*}"; c="${h#*:}"
  echo; echo "== $host ($c)"
  on "$host" "sudo -n docker exec $c $RPC" > "$OUT/$host-server_info.json"
  jq -c '.result.info | {server_state, complete_ledgers, validated_ledger: .validated_ledger.seq, build_version}' "$OUT/$host-server_info.json"
  on "$host" "sudo -n docker exec $c cat /etc/postfiatd/postfiatd.cfg" \
    | awk '/^\[/{s=$0} (s=="[node_db]"||s=="[ledger_history]"||s=="[fetch_depth]") && !/^[[:space:]]*#/ && NF' > "$OUT/$host-cfg.txt"
  sed 's/^/  cfg: /' "$OUT/$host-cfg.txt"
  for i in 1 2 3; do
    sleep 10
    on "$host" "sudo -n docker exec $c $RPC" | jq -r '"  sample '"$i"' \(now|todate) complete_ledgers=\(.result.info.complete_ledgers)"'
  done
done
