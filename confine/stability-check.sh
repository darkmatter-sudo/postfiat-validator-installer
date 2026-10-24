#!/usr/bin/env bash
# 1-hour stability check after pft-confine apply (read-only):
#   bash stability-check.sh [--container NAME] [--relay]     (run from the confine/ directory)
# --relay runs the same checks on the sentry over `ssh relay`, piping the local pft-confine.sh (no copy on the host).
# Prints: header with the sha256 of the pft-confine.sh actually run, verify --min-uptime 3600, docker State/RestartCount,
# docker stats, pft-integrity verify. Exit = verify exit code.
set -uo pipefail
CONTAINER=postfiatd; REMOTE=0
while [ $# -gt 0 ]; do
  case "$1" in --container) CONTAINER="$2"; shift 2 ;; --relay) REMOTE=1; shift ;; *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ -f ./pft-confine.sh ] || { echo "run from the confine/ directory" >&2; exit 3; }
if [ "$REMOTE" = 1 ]; then
  X() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes relay "$@"; }; where=sentry
else
  X() { sudo bash -c "$*"; }; where=validator
fi
echo "pft-confine 1-hour stability ($where, $CONTAINER) - $(date -u +%FT%TZ) - $(X "grep PRETTY_NAME /etc/os-release" | cut -d'"' -f2)"
echo "pft-confine.sh run: sha256 $(sha256sum pft-confine.sh | cut -c1-64) (local checkout$([ "$REMOTE" = 1 ] && echo ', piped over ssh'))"
echo "\$ pft-confine verify --container $CONTAINER --min-uptime 3600"
if [ "$REMOTE" = 1 ]; then X "bash -s -- verify --container $CONTAINER --min-uptime 3600" < pft-confine.sh 2>&1
else sudo bash pft-confine.sh verify --container "$CONTAINER" --min-uptime 3600 2>&1; fi
rc=$?; echo "exit $rc"
echo "\$ docker inspect $CONTAINER (State/RestartCount)"
X "docker inspect $CONTAINER" | jq -c '.[0] | {StartedAt: .State.StartedAt, Running: .State.Running, OOMKilled: .State.OOMKilled, RestartCount}'
echo "\$ docker stats --no-stream $CONTAINER"
X "docker stats --no-stream --format '{{.Name}} mem {{.MemUsage}} ({{.MemPerc}}) pids {{.PIDs}}' $CONTAINER"
echo "\$ pft-integrity verify"
X "pft-integrity verify 2>&1"
exit "$rc"
