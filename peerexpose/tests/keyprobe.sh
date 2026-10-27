#!/usr/bin/env bash
# keyprobe: prove what the managed [crawl]/[vl] blocks really do in THIS postfiatd build, without touching the live
# node. For each variant (stock config, validator block, sentry block) it starts a throwaway container from the live
# node's image with --network none (no peers, no outbound traffic) and a copy of the live config rendered by
# `pft-peerexpose render`, then prints only HTTP status codes and JSON key NAMES of /crawl, /vl and /health, and runs
# the real `pft-peerexpose audit` inside the container's network namespace.
# /vl note: with --network none no validator list is ever fetched, so /vl cannot serve a blob in any variant; the
# probe tells "handler enabled" from "handler disabled" by the answer to a well-formed unknown key.
# Usage: sudo bash tests/keyprobe.sh [SOURCE_CONTAINER (postfiatd)]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$HERE/../pft-peerexpose.sh"
SRC="${1:-postfiatd}"
NAME=pft-peerexpose-keyprobe
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 3; }
IMAGE="$(docker inspect "$SRC" --format '{{.Config.Image}}')"
WORK="$(umask 077; mktemp -d)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "keyprobe - $(date -u +%FT%TZ) - $(grep -m1 '^PRETTY_NAME=' /etc/os-release | cut -d\" -f2) - image $IMAGE ($(docker image inspect "$IMAGE" --format '{{.Id}}' | cut -c1-19))"
docker exec "$SRC" cat /etc/postfiatd/postfiatd.cfg > "$WORK/live.cfg"
docker exec "$SRC" cat /etc/postfiatd/validators.txt > "$WORK/validators.txt"
UNKNOWN_KEY=ED$(printf '%064d' 0)

for variant in stock validator sentry; do
  echo "=== variant $variant"
  mkdir -p "$WORK/$variant/etc" "$WORK/$variant/db" "$WORK/$variant/log"
  if [ "$variant" = stock ]; then cp "$WORK/live.cfg" "$WORK/$variant/etc/postfiatd.cfg"
  else bash "$TOOL" render --role "$variant" < "$WORK/live.cfg" > "$WORK/$variant/etc/postfiatd.cfg"; fi
  cp "$WORK/validators.txt" "$WORK/$variant/etc/"
  chmod -R a+rX "$WORK/$variant/etc"
  echo "[crawl]/[vl] lines: $(awk '/^\[(crawl|vl)\]/{on=1} /^\[/ && !/^\[(crawl|vl)\]/{on=0} on && !/^#/ && NF' "$WORK/$variant/etc/postfiatd.cfg" | paste -sd ' ' -)"
  docker run -d --name "$NAME" --network none --memory 2g \
    -v "$WORK/$variant/etc:/etc/postfiatd:ro" -v "$WORK/$variant/db:/var/lib/postfiatd/db" \
    -v "$WORK/$variant/log:/var/log/postfiatd" "$IMAGE" --conf /etc/postfiatd/postfiatd.cfg >/dev/null
  code=000
  for _ in $(seq 1 60); do
    code="$(docker exec "$NAME" curl -sk -m 3 -o /dev/null -w '%{http_code}' https://127.0.0.1:2559/health 2>/dev/null || true)"
    [ "$code" != 000 ] && [ -n "$code" ] && break
    sleep 2
  done
  echo "peer port up: /health http $code"
  pc() { docker exec "$NAME" curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:2559$1" 2>/dev/null || echo 000; }
  echo "/crawl http $(pc /crawl), keys: $(docker exec "$NAME" curl -sk -m 5 https://127.0.0.1:2559/crawl 2>/dev/null \
    | jq -c '{top: keys, server: (.server // {} | keys), overlay: (.overlay // {} | keys), unl: (.unl // {} | keys)}' 2>/dev/null || echo non-JSON)"
  echo "/vl/<well-formed unknown key> http $(pc "/vl/$UNKNOWN_KEY")  /vl/<malformed key> http $(pc /vl/notakey)"
  pid="$(docker inspect "$NAME" --format '{{.State.Pid}}')"
  role=validator; [ "$variant" = sentry ] && role=sentry
  echo "audit --role $role inside the probe container's netns:"
  rc=0; nsenter -t "$pid" -n bash "$TOOL" audit --role "$role" --container "$NAME" || rc=$?
  echo "audit exit $rc"
  docker rm -f "$NAME" >/dev/null
done
echo "keyprobe done; probe container removed: $(docker ps -a --filter "name=^$NAME\$" -q | wc -l | sed 's/^0$/yes/')"
