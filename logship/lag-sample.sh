#!/usr/bin/env bash
# 1h forwarding-lag sample for the README: every 60 s, 'pft-logship lag' on both hosts (validator local, sentry via
# 'ssh relay'), one line per host: UTC time, host, lag seconds (or NA + exit code). Then median / p95 / max per host.
# Usage: bash logship/lag-sample.sh [SAMPLES=60] > lag-1h.log   (run detached; needs sudo here and ssh relay)
set -uo pipefail
n="${1:-60}"; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; out="$(mktemp)"; trap 'rm -f "$out"' EXIT
# shellcheck disable=SC1091
echo "# OS: $(. /etc/os-release; echo "$PRETTY_NAME") | $(date -u +%FT%TZ) | lag-sample.sh sha256 $(sha256sum "$0" | cut -d' ' -f1) | samples $n x 60 s"
for i in $(seq 1 "$n"); do
  t="$(date -u +%FT%TZ)"
  v="$(sudo bash "$here/pft-logship.sh" lag 2>&1)"; vr=$?
  s="$(ssh relay 'cd /root/pft-ls && bash pft-logship.sh lag' 2>&1)"; sr=$?
  for h in validator-host sentry-host; do
    if [ "$h" = validator-host ]; then o="$v" r=$vr; else o="$s" r=$sr; fi
    l="$(sed -nE 's/^lag: ([0-9]+)s.*/\1/p' <<<"$o")"
    echo "$t $h ${l:-NA} exit=$r" | tee -a "$out"
  done
  [ "$i" -lt "$n" ] && sleep 60
done
echo "== summary (NA samples counted separately)"
for h in validator-host sentry-host; do
  awk -v h="$h" '$2==h && $3!="NA"{print $3}' "$out" | sort -n | awk -v h="$h" '{a[NR]=$1} END{
    if(NR==0){print h": no samples"; exit}
    m=(NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2; p=int(0.95*NR+0.999999); if(p<1)p=1
    printf "%s: n=%d median=%ss p95=%ss max=%ss\n", h, NR, m, a[p], a[NR]}'
  echo "$h NA samples: $(awk -v h="$h" '$2==h && $3=="NA"' "$out" | wc -l)"
done
