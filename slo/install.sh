#!/usr/bin/env bash
# Deploy the SLO add-on on a host already running ../exporter (systemd) and ../alerts (run-stack.sh):
#   1. install the exporter with the pft_maint_active gauge and restart pft-exporter (node untouched)
#   2. recreate the alert stack with ../slo mounted at /etc/pft-slo (alerts/run-stack.sh up)
#   3. confirm the pft-slo-* rule groups are loaded and pft:sli_good:bool has samples
# Usage: sudo -E bash slo/install.sh     (or as a user with sudo; DOCKER defaults to "sudo docker")
# Env: NTFY_ENV_FILE (passed through to run-stack.sh), PROM (http://127.0.0.1:9090)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
PROM="${PROM:-http://127.0.0.1:9090}"
export DOCKER="${DOCKER:-sudo docker}"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

log "slo install: repo $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
log "1/3 exporter: install pft_exporter.py (sha256 $(sha256sum "$ROOT/exporter/pft_exporter.py" | cut -c1-12))"
sudo install -m 0644 -o root -g root "$ROOT/exporter/pft_exporter.py" /opt/pft-exporter/pft_exporter.py
sudo systemctl restart pft-exporter
for _ in $(seq 1 15); do m="$(curl -fsS --max-time 2 http://127.0.0.1:9877/metrics 2>/dev/null)" && grep -q '^pft_maint_active ' <<<"$m" && break; sleep 1; done
curl -fsS http://127.0.0.1:9877/metrics | grep -E '^pft_(up|maint_active|maint_flag_malformed) ' || die "exporter has no pft_maint_active"

log "2/3 alert stack: run-stack.sh up (SLO rules mounted)"
bash "$ROOT/alerts/run-stack.sh" up

log "3/3 rules loaded + recorded samples"
curl -fsS "$PROM/api/v1/rules" | jq -r '.data.groups[] | select(.name|startswith("pft-slo")) | "  group \(.name): \(.rules|length) rules, health \([.rules[].health]|unique|join(","))"'
n="$(curl -fsS "$PROM/api/v1/rules" | jq '[.data.groups[] | select(.name|startswith("pft-slo"))] | length')"
[ "$n" -eq 4 ] || die "expected 4 pft-slo rule groups, found $n"
for _ in $(seq 1 12); do
  now="$(date -u +%s)"
  v="$(curl -fsS "$PROM/api/v1/query_range" --data-urlencode 'query=pft:sli_good:bool' \
        --data-urlencode "start=$((now - 60))" --data-urlencode "end=$now" --data-urlencode step=15 \
       | jq -r '.data.result[0].values[-1][1] // empty')"
  [ -n "$v" ] && break
  sleep 5
done
[ -n "$v" ] || die "pft:sli_good:bool has no samples after 60s"
log "pft:sli_good:bool latest = $v (1 = good)"
log "slo install: done"
