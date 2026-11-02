#!/usr/bin/env bash
# identity-control: show on THROWAWAY containers (same image as the running node, --network none, a fresh anonymous
# data volume each time, never the live node or its volumes) where postfiatd's node identity comes from:
#   A, B  the stock config twice -> two different pubkey_node values (identity = a new key in a fresh wallet.db)
#   C, D  the stock config + a [node_seed] block from validation_create, twice -> the same pubkey_node both times,
#         equal to validation_public_key (identity = the seed, whatever the data volume holds)
#   E     the seeded config + a malformed [cluster_nodes] entry -> postfiatd does not start (Cluster::load fails),
#         which is why pft-cluster validates entries before writing them
# Keys are printed as fingerprints keyed with a random per-run key; the seed lives in a 0600 file in a 0700 temp dir
# and is passed to the container as a file (bind mount), never on a command line.
#   sudo bash identity-control.sh [IMAGE]     (default: the image of the running postfiatd container)
# Exit 0 = all three expectations hold.
# "A && B || C" is intended: C only reports.
# shellcheck disable=SC2015,SC2001
set -uo pipefail
DOCKER="${DOCKER:-docker}"
IMG="${1:-$("$DOCKER" inspect -f '{{.Image}}' postfiatd 2>/dev/null)}"
[ -n "$IMG" ] || { echo "no image"; exit 2; }
ts() { date -u +%FT%TZ; }
W="$(mktemp -d)"; chmod 700 "$W"
FPK="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fp() { [ -n "$1" ] && echo "node:$(printf '%s%s' "$FPK" "$1" | sha256sum | cut -c1-12)" || echo "node:none"; }
NAMES=()
cleanup() { local n; for n in "${NAMES[@]}"; do "$DOCKER" rm -f -v "$n" >/dev/null 2>&1; done; rm -rf "$W"; }
trap cleanup EXIT
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; FAILS=$((FAILS + 1)); fi; }

echo "identity-control - $(ts) - $(lsb_release -ds) - image ${IMG#sha256:}"
echo "sha256 $(sha256sum < "$0" | cut -c1-64) identity-control.sh"
"$DOCKER" run --rm --network none --entrypoint cat "$IMG" /etc/postfiatd/postfiatd.cfg > "$W/stock.cfg" || { echo "cannot read the stock config"; exit 2; }
cp "$W/stock.cfg" "$W/base.cfg"
echo "$(ts) stock config: $(wc -l < "$W/stock.cfg") lines, sha256 $(sha256sum < "$W/stock.cfg" | cut -c1-12); [node_seed] sections: $(grep -cx '\[node_seed\]' "$W/stock.cfg")"

# run CFGFILE NAME -> pubkey_node of a fresh throwaway node (empty on failure); data volume is anonymous and new
run_node() {
  local cfg="$1" n="pft-cluster-idctl-$2-$$" k=""
  NAMES+=("$n")
  "$DOCKER" run -d --name "$n" --user 0:0 --network none -v "$cfg:/etc/postfiatd/postfiatd.cfg:ro" -v /var/lib/postfiatd/db \
    --memory 2g --pids-limit 256 "$IMG" --conf /etc/postfiatd/postfiatd.cfg >/dev/null || return 1
  for _ in $(seq 60); do
    k="$("$DOCKER" exec "$n" curl -s -m 5 -d '{"method":"server_info"}' http://127.0.0.1:5005/ 2>/dev/null | jq -r '.result.info.pubkey_node // empty' 2>/dev/null)"
    [ -n "$k" ] && break
    [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$n" 2>/dev/null)" = true ] || break
    sleep 2
  done
  echo "$k"
}
stop_node() { "$DOCKER" rm -f -v "pft-cluster-idctl-$1-$$" >/dev/null 2>&1; }

A="$(run_node "$W/base.cfg" a)"; stop_node a
B="$(run_node "$W/base.cfg" b)"; stop_node b
echo "$(ts) A stock config, fresh data volume: pubkey_node $(fp "$A")"
echo "$(ts) B stock config, fresh data volume: pubkey_node $(fp "$B")"
check "A and B answered and differ (identity from a new wallet.db each time)" "$( [ -n "$A" ] && [ -n "$B" ] && [ "$A" != "$B" ]; echo $?)"

# a seed from validation_create of a throwaway node; the answer goes straight into 0600 files
n="pft-cluster-idctl-kg-$$"; NAMES+=("$n")
"$DOCKER" run -d --name "$n" --user 0:0 --network none -v "$W/base.cfg:/etc/postfiatd/postfiatd.cfg:ro" -v /var/lib/postfiatd/db "$IMG" --conf /etc/postfiatd/postfiatd.cfg >/dev/null
for _ in $(seq 60); do
  (umask 077; "$DOCKER" exec "$n" curl -s -m 5 -d '{"method":"validation_create"}' http://127.0.0.1:5005/ > "$W/vc.json" 2>/dev/null)
  [ -s "$W/vc.json" ] && jq -e '.result.validation_seed' "$W/vc.json" >/dev/null 2>&1 && break; sleep 2  # jq 1.6 -e is true on empty input
done
"$DOCKER" rm -f -v "$n" >/dev/null 2>&1
(umask 077; jq -r '.result.validation_seed' "$W/vc.json" > "$W/seed"; jq -r '.result.validation_public_key' "$W/vc.json" > "$W/pub")
V="$(cat "$W/pub")"
(umask 022; { cat "$W/base.cfg"; echo; echo "[node_seed]"; cat "$W/seed"; } > "$W/seeded.cfg")
chmod 644 "$W/seeded.cfg"   # read by the container's root through the bind mount; the dir is 0700
C="$(run_node "$W/seeded.cfg" c)"; stop_node c
D="$(run_node "$W/seeded.cfg" d)"; stop_node d
echo "$(ts) validation_create: validation_public_key $(fp "$V")"
echo "$(ts) C seeded config, fresh data volume: pubkey_node $(fp "$C")"
echo "$(ts) D seeded config, fresh data volume: pubkey_node $(fp "$D")"
check "C = D = validation_public_key (identity from [node_seed], not from the data volume)" "$( [ -n "$C" ] && [ "$C" = "$D" ] && [ "$C" = "$V" ]; echo $?)"

{ cat "$W/seeded.cfg"; printf '\n[cluster_nodes]\nnot-a-node-key x\n'; } > "$W/bad.cfg"; chmod 644 "$W/bad.cfg"
E="$(run_node "$W/bad.cfg" e)"
el="$("$DOCKER" logs "pft-cluster-idctl-e-$$" 2>&1 | grep -E 'Malformed entry|Invalid node identity|cluster' | head -3 | sed -E 's/not-a-node-key/<entry>/')"
running="$("$DOCKER" inspect -f '{{.State.Running}}' "pft-cluster-idctl-e-$$" 2>/dev/null)"; stop_node e
echo "$(ts) E malformed [cluster_nodes]: pubkey_node $(fp "$E"), running=$running"
[ -n "$el" ] && sed 's/^/  log: /' <<<"$el"
check "E: no server_info answer (postfiatd refuses a malformed [cluster_nodes]); valid only because C answered with the same config minus the entry" "$( [ -z "$E" ] && [ -n "$C" ]; echo $?)"
grep -qFf "$W/seed" <<<"$el" && check "E: seed not in the printed log lines" 1 || check "E: seed not in the printed log lines" 0
echo "identity-control done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
