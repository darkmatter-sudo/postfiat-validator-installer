#!/usr/bin/env bash
# [vl] behaviour drill: shows that pft-cfglint flags `[vl] enable=0` and that only `enabled=0` changes /vl.
# For each variant (control: no [vl] section, `enable=0`, `enabled=0`):
#   1. render BASE_CFG + the [vl] variant, lint it with pft-cfglint.sh --file (record exit + findings)
#   2. start a throwaway postfiatd container (peer port published on 127.0.0.1 only, nothing else published),
#      lint the running container with pft-cfglint.sh --container (build commit check), wait until the node has
#      loaded a publisher list, then GET https://127.0.0.1:<port>/vl/<publisher key> (HTTP code + signed blob or not)
#   3. remove the container and assert none is left
# Never touches the live node. Usage:
#   bash drill/vl-drill.sh <base.cfg> <validators.txt> [image]
# base.cfg / validators.txt: the image's stock testnet cfg (postfiatd source cfg/postfiatd-testnet-light.cfg and
# cfg/validators-testnet.txt at the registry commit). Exit 0 only if every expectation held.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LINT="$HERE/../pft-cfglint.sh"
BASE="${1:?base cfg}"; VALS="${2:?validators.txt}"
IMAGE="${3:-agtipft/postfiatd:testnet-light-latest}"
NAME=cfglint-drill
HOSTPORT=12559
WAIT_S=240
WORK="$(mktemp -d)"
chmod 755 "$WORK"
FAILS=0

cleanup() { sudo docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

expect() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 (got $2, want $3)"; FAILS=$((FAILS + 1)); fi; }

echo "== vl-drill $(date -u +%FT%TZ) image $IMAGE ($(sudo docker image inspect "$IMAGE" --format '{{.Id}}' | cut -c8-19))"
echo "== base cfg sha256 $(sha256sum < "$BASE" | cut -c1-64), validators.txt sha256 $(sha256sum < "$VALS" | cut -c1-64)"
if grep -qE '^\[(vl|validator_token|validation_seed|node_seed)\]' "$BASE"; then
  echo "base cfg already has [vl] or key material; refusing"; exit 2
fi
# `none` is the control; want_lint / want_served per variant
for variant in none enable=0 enabled=0; do
  case "$variant" in
    none)      want_lint=0; want_served=yes ;;
    enable=0)  want_lint=1; want_served=yes ;;
    enabled=0) want_lint=0; want_served=no ;;
  esac
  echo
  echo "== variant: ${variant} ($(date -u +%TZ))"
  cfg="$WORK/postfiatd.cfg"
  cp "$BASE" "$cfg"
  [ "$variant" = none ] || printf '\n[vl]\n%s\n' "$variant" >> "$cfg"
  cp "$VALS" "$WORK/validators.txt"
  chmod 644 "$cfg" "$WORK/validators.txt"
  echo "-- [vl] section of the rendered cfg:"; awk '/^\[/{s=($0=="[vl]")} s' "$cfg"; [ "$variant" != none ] || echo "   (none)"

  echo "-- pft-cfglint --file:"
  bash "$LINT" --file "$cfg" | sed 's/^/   /'; rc=${PIPESTATUS[0]}
  expect "lint exit (file)" "$rc" "$want_lint"

  sudo docker rm -f "$NAME" >/dev/null 2>&1
  sudo docker run -d --name "$NAME" -p "127.0.0.1:$HOSTPORT:2559" \
    -v "$cfg:/etc/postfiatd/postfiatd.cfg:ro" -v "$WORK/validators.txt:/etc/postfiatd/validators.txt:ro" \
    "$IMAGE" --conf /etc/postfiatd/postfiatd.cfg >/dev/null || { echo "  FAIL docker run"; FAILS=$((FAILS + 1)); continue; }
  echo "-- published ports: $(sudo docker port "$NAME" | tr '\n' ' ')"
  echo "-- pft-cfglint --container $NAME:"
  bash "$LINT" --container "$NAME" | sed 's/^/   /'; rc=${PIPESTATUS[0]}
  expect "lint exit (running container)" "$rc" "$want_lint"

  key=""; t0=$SECONDS
  while [ $((SECONDS - t0)) -lt "$WAIT_S" ]; do
    key="$(sudo docker exec "$NAME" curl -s -m3 -d '{"method":"validators"}' http://127.0.0.1:5005 2>/dev/null \
      | jq -r '.result.publisher_lists[]? | select(.available == true) | .pubkey_publisher' 2>/dev/null | head -1)"
    [ -n "$key" ] && break
    sleep 3
  done
  if [ -z "$key" ]; then echo "  FAIL no publisher list loaded within ${WAIT_S}s"; FAILS=$((FAILS + 1))
  else
    echo "-- publisher list loaded after $((SECONDS - t0))s (publisher key ${key:0:8}...)"
    code="$(curl -sk -m10 -o "$WORK/vl.body" -w '%{http_code}' "https://127.0.0.1:$HOSTPORT/vl/$key")"
    if [ "$code" = 200 ] && jq -e 'has("blob")' "$WORK/vl.body" >/dev/null 2>&1; then served=yes; else served=no; fi
    echo "-- GET /vl/<publisher key> -> HTTP $code, signed list blob: $served ($(wc -c < "$WORK/vl.body") bytes)"
    expect "/vl served" "$served" "$want_served"
  fi
  sudo docker rm -f "$NAME" >/dev/null
  left="$(sudo docker ps -a --format '{{.Names}}' | grep -cx "$NAME")"
  echo "-- throwaway container removed: $left left"
  expect "container cleanup" "$left" 0
done
echo
echo "RESULT: $FAILS failure(s)"
[ "$FAILS" -eq 0 ]
