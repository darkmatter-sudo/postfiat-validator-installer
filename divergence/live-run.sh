#!/usr/bin/env bash
# Live run log: N consecutive pft-divergence checks with the host's own config, one line each, then a summary.
#   sudo bash live-run.sh [--count 60] [--interval 60] [--label validator-host] [--bin /usr/local/bin/pft-divergence]
# Uses --no-textfile --no-state, so it never touches what the timer writes. Retry/re-query lines (stderr) are
# kept inline. Public IPs are redacted on output. Exit 0 if no check was DIVERGED.
set -uo pipefail
COUNT=60; INTERVAL=60; LABEL="$(hostname -s)"; BIN=/usr/local/bin/pft-divergence
while [ $# -gt 0 ]; do
  case "$1" in --count) COUNT="$2"; shift ;; --interval) INTERVAL="$2"; shift ;; --label) LABEL="$2"; shift ;;
               --bin) BIN="$2"; shift ;; *) echo "unknown $1" >&2; exit 3 ;; esac
  shift
done
redact() { sed -E 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/<redacted-ip>/g'; }
# shellcheck source=/dev/null
echo "OS: $(. /etc/os-release; echo "$PRETTY_NAME") | $(date -u +%FT%TZ) | host: $LABEL | $(basename "$BIN") sha256 $(sha256sum "$BIN" | cut -c1-12)"
"$BIN" --check-config 2>&1 | redact
echo "\$ for i in 1..$COUNT: $(basename "$BIN") --no-textfile --no-state; sleep to a ${INTERVAL}s cadence"
a=0; u=0; d=0
for ((i = 1; i <= COUNT; i++)); do
  t0="$(date +%s)"
  out="$("$BIN" --no-textfile --no-state 2>&1)"; rc=$?
  printf '%s\n' "$out" | redact | sed "s/^/[$i\/$COUNT] /"
  case "$rc" in 0) a=$((a + 1)) ;; 1) u=$((u + 1)) ;; 2) d=$((d + 1)) ;; *) echo "[$i/$COUNT] exit $rc"; u=$((u + 1)) ;; esac
  [ "$i" -lt "$COUNT" ] || break
  s=$((INTERVAL - ($(date +%s) - t0))); [ "$s" -le 0 ] || sleep "$s"
done
echo "SUMMARY host=$LABEL checks=$COUNT AGREE=$a UNKNOWN=$u DIVERGED=$d end=$(date -u +%FT%TZ)"
[ "$d" -eq 0 ]
