#!/usr/bin/env bash
# task_d7136 verification: staged compose core:0 overlay vs running postfiatd HostConfig.Ulimits (CD08 deferred). Read-only.
set -u
WD=/opt/postfiatd; SNAP=/var/lib/pft-coredump/snap-20261126T185243Z
echo "=== cd08-proof $(date -u +%FT%TZ) repo HEAD $(git -C "$HOME/work/postfiat-validator-installer" rev-parse HEAD)"
echo "=== 1. overlay diff: pre-apply snapshot (overlay absent) -> current $WD/docker-compose.coredump.yml"
echo "--- snapshot 'absent' list:"; sudo cat "$SNAP/absent"
sudo diff -u --label "a/docker-compose.coredump.yml (absent before apply)" --label "b/docker-compose.coredump.yml" /dev/null "$WD/docker-compose.coredump.yml"; echo "diff exit=$? (1 = differs)"
echo "=== 2. .env diff, COMPOSE_FILE line only (other .env keys not printed)"
diff -u --label "a/.env (snapshot $(basename "$SNAP"))" --label "b/.env (now)" \
  <(sudo grep '^COMPOSE_FILE=' "$SNAP/files/_opt_postfiatd_.env") <(sudo grep '^COMPOSE_FILE=' "$WD/.env"); echo "diff exit=$? (1 = differs)"
echo "=== 3. what the NEXT re-create would get: docker compose config (YAML), postfiatd ulimits block"
( cd "$WD" && sudo docker compose config 2>/dev/null | awk '/^  postfiatd:/{s=1} s&&/^    ulimits:/{u=1} u{print; if(++n>=5) exit}' )
echo "=== 4. running container: docker inspect postfiatd"
echo "\$ sudo docker inspect --format '{{json .HostConfig.Ulimits}}' postfiatd"
sudo docker inspect --format '{{json .HostConfig.Ulimits}}' postfiatd
echo "\$ sudo docker inspect postfiatd | jq '.[0] | {Created, StartedAt: .State.StartedAt, RestartCount, Ulimits: .HostConfig.Ulimits, CoreUlimit: ([.HostConfig.Ulimits[]? | select(.Name==\"core\")] | length)}'"
sudo docker inspect postfiatd | jq '.[0] | {Created, StartedAt: .State.StartedAt, RestartCount, Ulimits: .HostConfig.Ulimits, CoreUlimit: ([.HostConfig.Ulimits[]? | select(.Name=="core")] | length)}'
PID=$(sudo docker inspect --format '{{.State.Pid}}' postfiatd)
echo "=== 5. live process limit (set by apply step 3 prlimit, no restart): /proc/<pid1>/limits"
sudo grep 'Max core file size' "/proc/$PID/limits"
echo "=== 6. pft-coredump audit CD08/CD09"
sudo pft-coredump audit 2>&1 | grep -E 'CD0[89]'
echo "=== 7. server_state"
curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005/ | jq -r '.result.info | "server_state=\(.server_state) uptime=\(.uptime)s build=\(.build_version)"'
echo "=== end"
