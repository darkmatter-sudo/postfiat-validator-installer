#!/usr/bin/env bash
# alertpath live two-host drill. Runs on the validator (sudo for docker/journal), drives nothing on the sentry
# except reading `pft-alertpath status` over ssh. The sentry's pft-alertpath must already point at a THROWAWAY
# ntfy topic (its /etc/pft-alertpath/ntfy.env); this script reads that topic only to list what it received.
#
#   phase 0  baseline: sentry state must be OK
#   phase 1  stop pft-alertmanager           -> expect DEGRADED (AM unreachable), then STALE (no deliveries)
#            start it again                  -> expect OK
#   phase 2  break ../alerts/alertpath.rules.yml (PromQL syntax error) + SIGHUP Prometheus
#                                             -> reload fails, old rules keep running -> expect DEGRADED
#            restore the file + SIGHUP        -> expect OK
#   end      throwaway-topic messages (title + time), messages on the operator topics during the drill (must be 0),
#            bridge log lines mentioning the watchdog (must be 0), PASS/FAIL per check
# Latency = sentry state "since" (the check run that first saw it) minus the fault/restore time.
# A trap always restarts Alertmanager, restores the rules file and reloads Prometheus.
#
# Usage: drill.sh   Env: SSH_SENTRY ("ssh relay"), THROWAWAY_TOPIC_FILE (file with the throwaway topic name),
#        OPERATOR_TOPIC_FILES (space-separated env files holding NTFY_URL=... or NTFY_TOPIC=...; topics never printed),
#        NTFY_SERVER (https://ntfy.sh), PHASE_TIMEOUT (480)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES="$(readlink -f "$HERE/../../alerts/alertpath.rules.yml")"
read -r -a SSH_SENTRY <<< "${SSH_SENTRY:-ssh relay}"
NTFY_SERVER="${NTFY_SERVER:-https://ntfy.sh}"
PHASE_TIMEOUT="${PHASE_TIMEOUT:-480}"
BACKUP="$(mktemp)"
cp -p -- "$RULES" "$BACKUP"
fails=0

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
check() { if [ "$2" = yes ]; then log "PASS $1"; else log "FAIL $1"; fails=$((fails + 1)); fi; }
prom_reload_ok() { curl -s --max-time 5 http://127.0.0.1:9090/metrics | awk '$1 == "prometheus_config_last_reload_successful" {print $2}'; }
hup_prom() { sudo docker kill -s HUP pft-prometheus >/dev/null; }

restore() {
  sudo docker start pft-alertmanager >/dev/null 2>&1
  if ! cmp -s -- "$BACKUP" "$RULES"; then cp -- "$BACKUP" "$RULES"; hup_prom; log "trap: rules file restored + Prometheus reloaded"; fi
  rm -f -- "$BACKUP"
}
trap restore EXIT

sentry_status() { "${SSH_SENTRY[@]}" 'sudo pft-alertpath status' 2>/dev/null | jq -r '"\(.state) \(.since)"'; }

# wait_for WANT T0: poll the sentry until its state is WANT with since >= T0; prints and records the latency
wait_for() {
  local want="$1" t0="$2" end=$(( $(date -u +%s) + PHASE_TIMEOUT )) st since last=""
  while [ "$(date -u +%s)" -lt "$end" ]; do
    read -r st since <<< "$(sentry_status)"
    if [ "${st:-}" != "$last" ]; then log "  sentry state ${st:-?} (since ${since:-?})"; last="${st:-}"; fi
    if [ "${st:-}" = "$want" ] && [ "${since:-0}" -ge "$t0" ]; then
      LAT=$((since - t0)); log "  -> $want detected $LAT s after t0"; return 0
    fi
    sleep 5
  done
  LAT=-1; log "  -> $want NOT reached within ${PHASE_TIMEOUT}s"; return 1
}

topic_of() { # env file -> topic (NTFY_URL=https://host/topic or NTFY_TOPIC=topic)
  sudo sed -n -e 's|^NTFY_URL=https\{0,1\}://[^/]*/||p' -e 's|^NTFY_TOPIC=||p' "$1" | head -1 | tr -d '"[:space:]'
}
poll() { curl -s --max-time 20 "$NTFY_SERVER/$1/json?poll=1&since=$2" | jq -c 'select(.event == "message")'; }

START="$(date -u +%s)"
BRIDGE0="$(sudo docker logs pft-alert-bridge 2>&1 | grep -c PFTAlertPipelineWatchdog)"
log "drill start (rules sha256 $(sha256sum < "$RULES" | cut -c1-64))"

log "phase 0: baseline"
read -r st _ <<< "$(sentry_status)"; log "  sentry state $st"
check "baseline OK" "$([ "$st" = OK ] && echo yes || echo no)"

log "phase 1: stop pft-alertmanager"
T1="$(date -u +%s)"; sudo docker stop pft-alertmanager >/dev/null; log "  t0=$T1 pft-alertmanager stopped"
wait_for DEGRADED "$T1"; check "AM stop -> DEGRADED (latency ${LAT}s)" "$([ "$LAT" -ge 0 ] && echo yes || echo no)"
wait_for STALE "$T1"; check "AM stop -> STALE (latency ${LAT}s)" "$([ "$LAT" -ge 0 ] && echo yes || echo no)"
"${SSH_SENTRY[@]}" 'sudo pft-alertpath status' | jq -c '.last | {state, reasons, snapshot_age, delivery_age}' | sed 's/^/  /'
T2="$(date -u +%s)"; sudo docker start pft-alertmanager >/dev/null; log "  t0=$T2 pft-alertmanager started"
wait_for OK "$T2"; check "AM start -> OK (latency ${LAT}s)" "$([ "$LAT" -ge 0 ] && echo yes || echo no)"

log "phase 2: break the alertpath rules file + reload Prometheus"
T3="$(date -u +%s)"; sed -i 's/expr: vector(1)$/expr: vector(1/' "$RULES"; hup_prom
log "  t0=$T3 rules broken ($(grep -c 'expr: vector(1$' "$RULES") line changed), SIGHUP sent"
sleep 3; r="$(prom_reload_ok)"; log "  prometheus_config_last_reload_successful=$r"
check "broken rules -> reload fails" "$([ "$r" = 0 ] && echo yes || echo no)"
wait_for DEGRADED "$T3"; check "broken rules -> DEGRADED (latency ${LAT}s)" "$([ "$LAT" -ge 0 ] && echo yes || echo no)"
"${SSH_SENTRY[@]}" 'sudo pft-alertpath status' | jq -c '.last | {state, reasons}' | sed 's/^/  /'
T4="$(date -u +%s)"; cp -- "$BACKUP" "$RULES"; hup_prom; sleep 3; r="$(prom_reload_ok)"
log "  t0=$T4 rules restored, SIGHUP sent, prometheus_config_last_reload_successful=$r"
check "restored rules -> reload ok" "$([ "$r" = 1 ] && echo yes || echo no)"
wait_for OK "$T4"; check "restore -> OK (latency ${LAT}s)" "$([ "$LAT" -ge 0 ] && echo yes || echo no)"
check "rules file identical to pre-drill copy" "$(cmp -s -- "$BACKUP" "$RULES" && echo yes || echo no)"

log "end: notifications since drill start ($START)"
tt="$("${SSH_SENTRY[@]}" 'sudo sed -n "s/^NTFY_TOPIC=//p" /etc/pft-alertpath/ntfy.env' | tr -d '"[:space:]')"
want="$(tr -d '[:space:]' < "${THROWAWAY_TOPIC_FILE:-/dev/null}")"
check "sentry ntfy.env points at the throwaway topic" "$([ -n "$tt" ] && [ "$tt" = "$want" ] && echo yes || echo no)"
msgs="$(poll "$tt" "$START")"
printf '%s\n' "$msgs" | jq -r 'select(. != null) | "  throwaway <redacted>: \(.time | todate) \(.title) | \(.message)"'
n="$(printf '%s\n' "$msgs" | grep -c '"event":"message"')"
check "throwaway topic got the incident + recovery messages ($n)" "$([ "$n" -ge 4 ] && echo yes || echo no)"
for f in ${OPERATOR_TOPIC_FILES:-}; do
  ot="$(topic_of "$f")"; [ -n "$ot" ] || { check "operator topic readable from $(basename "$f")" no; continue; }
  [ "$ot" != "$tt" ] || { check "operator topic differs from throwaway" no; continue; }
  on="$(poll "$ot" "$START" | grep -c '"event":"message"')"
  check "operator topic from $(basename "$f"): $on messages during the drill" "$([ "$on" -eq 0 ] && echo yes || echo no)"
done
b="$(sudo docker logs pft-alert-bridge 2>&1 | grep -c PFTAlertPipelineWatchdog)"
check "bridge saw the watchdog 0 times (before $BRIDGE0, after $b)" "$([ "$b" -eq "$BRIDGE0" ] && [ "$b" -eq 0 ] && echo yes || echo no)"
log "RESULT: $([ "$fails" -eq 0 ] && echo PASS || echo "FAIL ($fails)")"
[ "$fails" -eq 0 ]
