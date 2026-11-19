#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs and PromQL are single-quoted on purpose
# Throwaway-topic routing drill for the 2026-11-19 valwatch paging rule (alerts about OTHER validators are digest-only;
# our two nodes disagreeing still pages). Touches nothing live: no node, no unit, no live Prometheus/Alertmanager/bridge,
# no operator topic. It starts four throwaway containers from images already on the host (host network, loopback
# ports 19090/19093/19095/19877, names pft-vwdrill-*, removed by the EXIT trap):
#   metrics     python:3.12-alpine http.server serving a fixed pft_valwatch_* exposition for BOTH nodes:
#               validator KX at 0 % on postfiatd AND postfiatd-sentry (external outage, like 2026-11-19 08:57Z)
#               validator KY at 50 % on postfiatd, 100 % on postfiatd-sentry (local fault on one node)
#   prometheus  prom/prometheus:v3.5.0 with the repo's alerts/valwatch.rules.yml unmodified (15 s scrape/eval)
#   alertmanager prom/alertmanager:v0.28.1 with the repo's alerts/alertmanager.yml, only the two webhook ports changed
#               (9095 -> 19095, 9096 -> 19096; `diff` printed below)
#   bridge      the repo's alerts/ntfy_bridge.py, NTFY_URL = a fresh random throwaway ntfy.sh topic
# Expected after the rules' 15m `for`: Prometheus fires PFTValwatchValidatorLow x3 (KX both nodes, KY postfiatd) and
# PFTValwatchHostsDisagree x1 (KY postfiatd); Alertmanager holds all 4; the bridge logs and forwards ONLY
# HostsDisagree; the throwaway topic holds exactly one [FIRING] message, for PFTValwatchHostsDisagree.
# The operator topics are only READ (count of messages since the drill start, titles shown, topics redacted).
#   bash valwatch/drill/route-drill.sh 2>&1 | tee LOG     (repo root, agent user with docker access; ~18 min)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
ME="$(id -un)"; HN="$(hostname)"
TOPIC="pftdrill-vw-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
OP_TOPIC="$(sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env)"
BR_URL="$(sed -n 's/^NTFY_URL=//p' "$HOME/.config/pft-alerts/ntfy.env")"
red() {
  sed -E -e "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$TOPIC#<redacted>#g" \
    -e "s#${OP_TOPIC:-@@none@@}#<redacted>#g; s#${BR_URL##*/}#<redacted>#g" \
    -e '/\b127\.0\.0\.1\b/!s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g'
}
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "RESULT: FAIL - $FAILS check(s) failed, stopping after step $1"; exit 1; }; }
NAMES=(pft-vwdrill-metrics pft-vwdrill-prom pft-vwdrill-am pft-vwdrill-bridge)
SCR="$(mktemp -d -p "$HOME/.cache" vwdrill.XXXXXX)"; chmod 755 "$SCR"
cleanup() { docker rm -f "${NAMES[@]}" >/dev/null 2>&1; rm -rf "$SCR"; echo "trap: removed ${NAMES[*]} and the scratch dir"; }
trap cleanup EXIT
PROM=http://127.0.0.1:19090 AM=http://127.0.0.1:19093
KX=nHBxQ3srN8ErMvfMgsJ3jycSSaMFyHMk5WbrJVUTXPZgNh1VdbHH   # the validator of the real 2026-11-19 outage
KY=nHUCEXpC5LhFAm1Mmf8TqrzVGt3QCuwWoW2V8PYynDpjZe8m8mHj   # a healthy UNL validator from the 11-18 capture
T0="$(date -u +%s)"

echo "== 1. preflight $(date -u +%FT%TZ) repo $(git rev-parse HEAD) (working tree: $(git status --short | wc -l) changed files)"
x 'sha256sum alerts/valwatch.rules.yml alerts/alertmanager.yml alerts/ntfy_bridge.py'
x 'docker image inspect -f "{{.RepoTags}}" prom/prometheus:v3.5.0 prom/alertmanager:v0.28.1 python:3.12-alpine'
check "images already on the host (no pull)" "$XRC"
x 'ss -ltnH | grep -cE "127\.0\.0\.1:(19090|19093|19095|19096|19877) " || true'
check "drill ports free" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x 'docker ps -a --format "{{.Names}}" | grep -c "^pft-vwdrill-" || true'
check "no leftover drill containers" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
[ -n "$OP_TOPIC" ] && [ -n "$BR_URL" ]; check "operator topics known (for the read-back)" "$?"
gate 1

echo "== 2. throwaway config"
mkdir -p "$SCR/m" "$SCR/p" "$SCR/a"
{
  for n in postfiatd postfiatd-sentry; do
    printf 'pft_valwatch_up{node="%s"} 1\n' "$n"
    printf 'pft_valwatch_last_record_age_seconds{node="%s"} 2\n' "$n"
    printf 'pft_valwatch_quorum_margin_min{node="%s"} 8\npft_valwatch_quorum_margin_p50{node="%s"} 8\n' "$n" "$n"
    printf 'pft_valwatch_reconnects{node="%s"} 0\n' "$n"
    printf 'pft_valwatch_validator_participation_ratio{node="%s",validator="%s"} 0\n' "$n" "$KX"
    printf 'pft_valwatch_validator_delay_p95_ms{node="%s",validator="%s"} 900\n' "$n" "$KY"
  done
  printf 'pft_valwatch_validator_participation_ratio{node="postfiatd",validator="%s"} 0.5\n' "$KY"
  printf 'pft_valwatch_validator_participation_ratio{node="postfiatd-sentry",validator="%s"} 1\n' "$KY"
} > "$SCR/m/metrics"
# collect timestamp must stay fresh (Stale rule): the server rewrites it every 10 s
cat > "$SCR/m/serve.sh" <<'EOS'
cd /m || exit 1
( while :; do t=$(date +%s); { grep -v collect_timestamp base; for n in postfiatd postfiatd-sentry; do
    echo "pft_valwatch_collect_timestamp_seconds{node=\"$n\"} $t"; done; } > metrics.tmp && mv metrics.tmp metrics
    sleep 10; done ) &
exec python3 -m http.server 19877 --bind 127.0.0.1
EOS
mv "$SCR/m/metrics" "$SCR/m/base"
cat > "$SCR/p/prometheus.yml" <<'EOP'
global: {scrape_interval: 15s, evaluation_interval: 15s}
rule_files: [/rules/valwatch.rules.yml]
alerting: {alertmanagers: [{static_configs: [{targets: ["127.0.0.1:19093"]}]}]}
scrape_configs: [{job_name: postfiat, static_configs: [{targets: ["127.0.0.1:19877"]}]}]
EOP
sed -e 's#127.0.0.1:9095/#127.0.0.1:19095/#; s#127.0.0.1:9096/#127.0.0.1:19096/#' alerts/alertmanager.yml > "$SCR/a/alertmanager.yml"
printf 'NTFY_URL=https://ntfy.sh/%s\n' "$TOPIC" > "$SCR/ntfy.env"
chmod -R a+rX "$SCR"
x "diff alerts/alertmanager.yml $SCR/a/alertmanager.yml"
check "alertmanager.yml differs only in the two webhook ports" "$([ "$(diff alerts/alertmanager.yml "$SCR/a/alertmanager.yml" | grep -c '^[<>]')" = 4 ] && echo 0 || echo 1)"
x "cat $SCR/m/base"
gate 2

echo "== 3. start throwaway stack $(date -u +%FT%TZ)"
x "docker run -d --name pft-vwdrill-metrics --network host -v $SCR/m:/m python:3.12-alpine sh /m/serve.sh"
x "docker run -d --name pft-vwdrill-bridge --network host --user 65534 -e BRIDGE_PORT=19095 -e NTFY_URL_FILE=/e/ntfy.env -v $SCR/ntfy.env:/e/ntfy.env:ro -v $REPO/alerts/ntfy_bridge.py:/b/ntfy_bridge.py:ro python:3.12-alpine python3 -u /b/ntfy_bridge.py"
x "docker run -d --name pft-vwdrill-am --network host --user 65534 --tmpfs /data:mode=1777 -v $SCR/a:/c:ro prom/alertmanager:v0.28.1 --config.file=/c/alertmanager.yml --storage.path=/data --web.listen-address=127.0.0.1:19093 --cluster.listen-address="
x "docker run -d --name pft-vwdrill-prom --network host --user 65534 --tmpfs /prometheus:mode=1777 -v $SCR/p:/etc/prometheus:ro -v $REPO/alerts/valwatch.rules.yml:/rules/valwatch.rules.yml:ro prom/prometheus:v3.5.0 --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus --web.listen-address=127.0.0.1:19090"
for _ in $(seq 1 30); do curl -fsS -o /dev/null "$PROM/-/ready" 2>/dev/null && break; sleep 2; done; sleep 20
x "curl -fsS $PROM/api/v1/rules | jq -r '.data.groups[].rules[] | \"\(.name) \(.health)\"'"
check "prometheus loaded the repo's 8 valwatch rules" "$([ "$(grep -c ' ok$' <<< "$XOUT")" = 8 ] && echo 0 || echo 1)"
x "curl -fsS $PROM/api/v1/targets | jq -r '.data.activeTargets[] | \"\(.labels.job) \(.health)\"'"
x "curl -fsS -o /dev/null -w '%{http_code}' $AM/-/ready"
check "alertmanager ready" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"
x "docker logs pft-vwdrill-bridge 2>&1 | tail -3"
[ "$FAILS" = 0 ] || x "docker logs pft-vwdrill-prom 2>&1 | tail -5; docker logs pft-vwdrill-am 2>&1 | tail -5"
gate 3

echo "== 4. wait for the 15m 'for' (poll every 60 s, up to 20 min)"
for i in $(seq 1 20); do
  sleep 60
  P="$(curl -fsS "$PROM/api/v1/alerts" | jq -r '[.data.alerts[] | "\(.labels.alertname)/\(.labels.node)=\(.state)"] | sort | join(" ")')"
  A="$(curl -fsS "$AM/api/v2/alerts" | jq -r '[.[] | "\(.labels.alertname)/\(.labels.node)"] | sort | join(" ")')"
  echo "$(date -u +%T) +${i}m prom: ${P:--} | am: ${A:--}"
  [ "$(grep -o '=firing' <<< "$P" | wc -l)" = 4 ] && [ "$(wc -w <<< "$A")" = 4 ] && break
done
sleep 45   # group_wait 10s + one group_interval for the bridge to log and forward
echo "== 5. results $(date -u +%FT%TZ)"
x "curl -fsS $PROM/api/v1/alerts | jq -r '.data.alerts[] | [.labels.alertname, .labels.node, .labels.validator, (.labels.notify // \"-\"), .state] | @tsv' | sort"
check "prometheus: ValidatorLow firing x3" "$([ "$(grep -c 'PFTValwatchValidatorLow.*digest.firing' <<< "$XOUT")" = 3 ] && echo 0 || echo 1)"
check "prometheus: HostsDisagree firing x1 (KY on postfiatd)" "$([ "$(grep -cP "PFTValwatchHostsDisagree\tpostfiatd\t$KY\t-\tfiring" <<< "$XOUT")" = 1 ] && [ "$(grep -c 'HostsDisagree' <<< "$XOUT")" = 1 ] && echo 0 || echo 1)"
x "curl -fsS $AM/api/v2/alerts/groups | jq -r '.[] | \"\(.receiver.name) \(.labels.alertname) alerts=\(.alerts | length)\"' | sort"
check "alertmanager: ValidatorLow (3 alerts) in receiver digest" "$(grep -qx 'digest PFTValwatchValidatorLow alerts=3' <<< "$XOUT"; echo $?)"
check "alertmanager: HostsDisagree (1 alert) in receiver bridge" "$(grep -qx 'bridge PFTValwatchHostsDisagree alerts=1' <<< "$XOUT"; echo $?)"
x "docker logs pft-vwdrill-bridge 2>&1"
check "bridge logged HostsDisagree" "$(grep -q 'PFTValwatchHostsDisagree' <<< "$XOUT"; echo $?)"
check "bridge never saw ValidatorLow" "$(grep -q 'PFTValwatchValidatorLow' <<< "$XOUT" && echo 1 || echo 0)"
x "curl -fsS --max-time 20 'https://ntfy.sh/$TOPIC/json?poll=1&since=$T0' | jq -r '[.time, .title // \"-\", (.message | split(\"\n\")[0])] | @tsv'"
check "throwaway topic: exactly 1 message" "$([ "$(grep -c . <<< "$XOUT")" = 1 ] && echo 0 || echo 1)"
check "throwaway topic: it is the HostsDisagree page" "$(grep -q 'PFTValwatchHostsDisagree' <<< "$XOUT"; echo $?)"
check "throwaway topic: no ValidatorLow" "$(grep -q 'PFTValwatchValidatorLow' <<< "$XOUT" && echo 1 || echo 0)"
for t in "$OP_TOPIC" "${BR_URL##*/}"; do
  x "curl -fsS --max-time 20 'https://ntfy.sh/$t/json?poll=1&since=$T0' | jq -r '[.time, .title // \"-\"] | @tsv'"
  check "operator topic: no drill message (vwdrill / HostsDisagree)" "$(grep -qE 'HostsDisagree|vwdrill' <<< "$XOUT" && echo 1 || echo 0)"
done
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS check(s) failed"
[ "$FAILS" = 0 ]
