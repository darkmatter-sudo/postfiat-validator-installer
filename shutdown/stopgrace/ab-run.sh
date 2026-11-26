#!/usr/bin/env bash
# A/B stop proof on throwaway containers (runs on the sentry as root; never touches postfiatd-sentry).
# For each round r=1..N and variant v in main branch: compose up (own project, override), sync SYNC s,
# `docker compose stop` (uses the file's own stop_grace_period), record StopTimeout, wall, exit, markers, down -v.
set -uo pipefail
N=${N:-3}; SYNC=${SYNC:-180}
MAIN=0085a1ff885d6a446369cf73a4430f75af22be55
HEAD_SHA=758fc0506b6ad77ec4c7744127c865fbd3904831
F=scripts/docker-compose-external-validator.yml
W=$HOME/.cache/sg-ab; rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1
cp "$HOME/.cache/sgprobe/throwaway.override.yml" .
echo "# $(date -u +%FT%TZ) A/B N=$N SYNC=${SYNC}s file=$F"
echo "\$ docker compose version; docker image inspect agtipft/postfiatd:testnet-light-latest -f '{{.Id}}'"
docker compose version; docker image inspect agtipft/postfiatd:testnet-light-latest -f '{{.Id}}'
for v in main branch; do
  case $v in main) url=https://raw.githubusercontent.com/postfiatorg/postfiatd/$MAIN/$F ;;
             branch) url=https://raw.githubusercontent.com/darkmatter-sudo/postfiatd/$HEAD_SHA/$F ;; esac
  echo "\$ curl -fsS -o $v.yml $url"; curl -fsS -o "$v.yml" "$url" || { echo "FAIL fetch $v"; exit 1; }
  echo "  sha256 $(sha256sum < "$v.yml" | cut -c1-64)  grace_lines=$(grep -c stop_grace_period "$v.yml")"
done
echo "\$ sha256sum throwaway.override.yml; cat throwaway.override.yml"; sha256sum throwaway.override.yml; cat throwaway.override.yml
fails=0
for r in $(seq 1 "$N"); do
  for v in main branch; do
    P=sg-ab-$v-$r
    C() { NETWORK=testnet docker compose -p "$P" -f "$v.yml" -f throwaway.override.yml "$@" 2>&1 | grep -v 'is obsolete'; }
    echo "== round $r variant $v project $P"
    echo "  rendered: $(NETWORK=testnet docker compose -p "$P" -f "$v.yml" -f throwaway.override.yml config --format json 2>/dev/null | jq -c '.services.postfiatd | {stop_grace_period: (.stop_grace_period // "unset"), ports: (.ports // []), container_name: (.container_name // null), restart, volumes: [.volumes[] | .type + ":" + .source]}')"
    C up -d --quiet-pull >/dev/null; cid=$(NETWORK=testnet docker compose -p "$P" -f "$v.yml" -f throwaway.override.yml ps -q postfiatd 2>/dev/null)
    [ -n "$cid" ] || { echo "  FAIL no container"; fails=$((fails+1)); continue; }
    echo "  container ${cid:0:12} Config.StopTimeout=$(docker inspect -f '{{if .Config.StopTimeout}}{{.Config.StopTimeout}}{{else}}null{{end}}' "$cid") ports=$(docker port "$cid" | wc -l)"
    sleep "$SYNC"
    log() { docker cp "$cid":/var/log/postfiatd/debug.log - 2>/dev/null | tar -xO; }
    echo "  after ${SYNC}s: running=$(docker inspect -f '{{.State.Running}}' "$cid") validation_lines=$(log | grep -c 'RCLValidations: Recording vote') last_state=$(log | grep -o 'STATE->[a-z]*' | tail -1 || true)"
    t0=$(date +%s.%N); C stop >/dev/null; t1=$(date +%s.%N)
    wall=$(echo "$t1 - $t0" | bc | sed 's/^\./0./')
    ex=$(docker inspect -f '{{.State.ExitCode}}' "$cid"); oom=$(docker inspect -f '{{.State.OOMKilled}}' "$cid")
    rs=$(log | grep -c 'Received signal 15'); ss=$(log | grep -c 'Server stopping')
    echo "  STOP variant=$v round=$r wall=${wall}s exit=$ex oom=$oom received_signal=$rs server_stopping=$ss"
    log | grep -E 'Received signal|Server stopping' | sed 's/^/    log: /'
    C down -v >/dev/null
    left=$(docker ps -a -q --filter "label=com.docker.compose.project=$P" | wc -l); lv=$(docker volume ls -q --filter "label=com.docker.compose.project=$P" | wc -l)
    echo "  cleanup: containers=$left volumes=$lv"
    [ "$left" = 0 ] && [ "$lv" = 0 ] || fails=$((fails+1))
  done
done
echo "# end $(date -u +%FT%TZ) postfiatd-sentry: $(docker inspect -f '{{.State.Status}} StartedAt={{.State.StartedAt}}' postfiatd-sentry) throwaway containers left=$(docker ps -a -q --filter label=pft.stopgrace.throwaway=1 | wc -l)"
echo "RESULT: runner_failures=$fails"
[ "$fails" = 0 ]
