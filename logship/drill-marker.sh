#!/usr/bin/env bash
# marker drill (Usage: bash logship/drill-marker.sh SRC DST, hosts validator-host|sentry-host): write a unique marker on SRC, time its arrival in DST's received journal (poll 1 s, give up after 120 s)
set -uo pipefail
src="$1" dst="$2"; m="pft-logship-marker-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
# shellcheck disable=SC2029  # the command is built locally on purpose (marker text expands here)
on() { if [ "$1" = sentry-host ]; then ssh relay "$2"; else sudo bash -c "$2"; fi; }
t0=$(date +%s.%N); on "$src" "logger -t pft-logship-drill '$m'"
echo "$(date -u +%T) wrote on $src: $m"
for _ in $(seq 1 120); do
  if on "$dst" "journalctl --directory=/var/log/journal/remote -t pft-logship-drill --since -10min -o cat --no-pager" | grep -qx "$m"; then
    echo "$(date -u +%T) arrived on $dst after $(echo "$(date +%s.%N) - $t0" | bc | cut -c1-5) s (poll 1 s)"; exit 0; fi
  sleep 1
done
echo "NOT arrived on $dst within 120 s"; exit 1
