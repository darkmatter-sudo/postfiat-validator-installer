#!/usr/bin/env bash
# Capture real `fee` and `server_info` answers as test fixtures (read-only RPC, no transactions, no load).
#   bash feewatch/tests/capture_fixtures.sh [SSH_TARGET]   (SSH_TARGET: the sentry host alias, default relay)
# Writes tests/fixtures/{validator,sentry}_{fee,server_info}.json (admin answers, container loopback) and
# validator_server_info_nonadmin.json (the host-mapped 127.0.0.1:5005 port, which is not an admin port here).
# Volatile identifiers (hashes, pubkeys, hostid) are replaced by placeholders; numbers stay as answered.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX="$HERE/fixtures"; R="${1:-relay}"
mkdir -p "$FX"
q() { printf '{"method":"%s","params":[{}]}' "$1"; }
scrub() {
  python3 -I -c '
import json, sys
d = json.load(sys.stdin)
def walk(o):
    if isinstance(o, dict):
        for k in list(o):
            if k in ("hash", "pubkey_node", "pubkey_validator", "hostid", "node_size", "ports") or k.endswith("_hash"):
                o[k] = "<scrubbed>"
            else:
                walk(o[k])
    elif isinstance(o, list):
        for x in o:
            walk(x)
walk(d)
json.dump(d, sys.stdout, indent=1, sort_keys=True)
print()'
}
for m in fee server_info; do
  sudo docker exec postfiatd curl -s --max-time 10 -H 'Content-Type: application/json' -d "$(q $m)" \
    http://127.0.0.1:5005/ | scrub > "$FX/validator_$m.json"
  # shellcheck disable=SC2029 # the body is meant to expand locally
  ssh "$R" "sudo docker exec postfiatd-sentry curl -s --max-time 10 -H 'Content-Type: application/json' -d '$(q $m)' http://127.0.0.1:5005/" \
    | scrub > "$FX/sentry_$m.json"
done
curl -s --max-time 10 -H 'Content-Type: application/json' -d "$(q server_info)" http://127.0.0.1:5005/ \
  | scrub > "$FX/validator_server_info_nonadmin.json"
for f in "$FX"/*.json; do
  printf '%s  status=%s admin_load_object=%s load_factor_keys=%s\n' "$(basename "$f")" \
    "$(jq -r .result.status "$f")" "$(jq -r '.result.info | if . == null then "n/a" else has("load") end' "$f")" \
    "$(jq -c '[.result.info // {} | keys[] | select(startswith("load_factor"))]' "$f")"
done
