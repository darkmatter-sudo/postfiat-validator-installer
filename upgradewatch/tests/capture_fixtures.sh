#!/usr/bin/env bash
# Capture real read-only RPC answers from the validator and the sentry as upgradewatch test fixtures.
#   bash upgradewatch/tests/capture_fixtures.sh [SSH_TARGET]   (SSH_TARGET: the sentry host alias, default relay)
# Writes tests/fixtures/{validator,sentry}_{server_info,feature,amendments,peers}.json (admin answers on each
# container's loopback), {validator,sentry}_majority_cfg.txt (only the [amendment_majority_time] section of the
# node config, via grep -A) and foundation_server_info.json (the public RPC). No transactions, no load.
# Peer addresses, public keys, hashes and host ids are replaced by placeholders; versions and numbers stay as answered.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FX="$HERE/fixtures"; R="${1:-relay}"
AMENDMENTS_INDEX=7DB0788C020F02780A673DC74757F23823FA3014C1866E72CC4CD8B226CD6EF4
FOUNDATION_URL="${FOUNDATION_URL:-https://rpc.testnet.postfiat.org}"
mkdir -p "$FX"
body() {
  case "$1" in
    amendments) printf '{"method":"ledger_entry","params":[{"index":"%s","ledger_index":"validated"}]}' "$AMENDMENTS_INDEX" ;;
    *) printf '{"method":"%s","params":[{}]}' "$1" ;;
  esac
}
scrub() {
  python3 -I -c '
import json, sys
d = json.load(sys.stdin)
DROP = {"hash", "pubkey_node", "pubkey_validator", "hostid", "ports", "address", "public_key", "ip", "port",
        "validator_list", "last_close"}
def walk(o):
    if isinstance(o, dict):
        for k in list(o):
            if k in DROP or k.endswith("_hash"):
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
for m in server_info feature amendments peers; do
  sudo docker exec postfiatd curl -s --max-time 10 -H 'Content-Type: application/json' -d "$(body "$m")" \
    http://127.0.0.1:5005/ | scrub > "$FX/validator_$m.json"
  # shellcheck disable=SC2029 # the body is meant to expand locally
  ssh "$R" "sudo docker exec postfiatd-sentry curl -s --max-time 10 -H 'Content-Type: application/json' -d '$(body "$m")' http://127.0.0.1:5005/" \
    | scrub > "$FX/sentry_$m.json"
done
# shellcheck disable=SC2024 # the fixture is written as the invoking user on purpose
sudo docker exec postfiatd grep -A4 '^\[amendment_majority_time\]' /etc/postfiatd/postfiatd.cfg \
  > "$FX/validator_majority_cfg.txt"
ssh "$R" "sudo docker exec postfiatd-sentry grep -A4 '^\[amendment_majority_time\]' /etc/postfiatd/postfiatd.cfg" \
  > "$FX/sentry_majority_cfg.txt"
curl -s --max-time 20 -H 'Content-Type: application/json' -d "$(body server_info)" "$FOUNDATION_URL" \
  | scrub > "$FX/foundation_server_info.json"
for f in "$FX"/*.json; do
  printf '%s  status=%s build=%s features=%s majorities=%s peers=%s\n' "$(basename "$f")" \
    "$(jq -r .result.status "$f")" "$(jq -r '.result.info.build_version // "-"' "$f")" \
    "$(jq -r '.result.features // {} | length' "$f")" "$(jq -r '.result.node.Majorities // [] | length' "$f")" \
    "$(jq -r '.result.peers // [] | length' "$f")"
done
for f in "$FX"/*_majority_cfg.txt; do printf '%s: %s\n' "$(basename "$f")" "$(tr '\n' '|' < "$f")"; done
