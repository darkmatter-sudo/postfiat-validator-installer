#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs and PromQL are single-quoted on purpose
# Throwaway-topic local_stale drill for pft-upstreamwatch (task_62b5fc29b42bbe4e484a03a450c97616): a TRUNCATED local
# feed must page, then recover, while upstream_quiet feeds in the same textfile stay digest-only. Touches nothing
# live: the live feed caches are only read (the USN feed is COPIED, then the copy is truncated), the live
# upstreamwatch state/textfile, Prometheus, Alertmanager, bridge and operator topics are not used (topics only read
# back). The installed /usr/local/bin/pft-upstreamwatch (sha256 = repo, printed) runs as root, as its timer does,
# with PFT_UW_CONF pointing at a scratch config (scratch VULNSCAN_CACHE, DATA_DIR, TEXTFILE_DIR; the real
# imagescan cache read-only). Four throwaway containers from images already on the host (host network, loopback
# ports 19190/19193/19195/19877, names pft-uwdrill-*, removed by the EXIT trap):
#   metrics      python:3.12-alpine http.server serving the scratch textfile dir
#   prometheus   prom/prometheus:v3.5.0 with the repo's alerts/upstreamwatch.rules.yml unmodified (15 s scrape/eval)
#   alertmanager prom/alertmanager:v0.28.1, the repo's alerts/alertmanager.yml with only the two webhook ports changed
#   bridge       the repo's alerts/ntfy_bridge.py, NTFY_URL = a fresh random throwaway ntfy.sh topic
# Phases: (A) truncated copy -> `run` exit 1, usn-host local_stale; re-run every 15 min like the hourly timer;
# after the rules' for: 65m PFTUpstreamFeedLocalStale fires and the throwaway topic gets exactly one [FIRING] page;
# PFTUpstreamFeedQuiet fires too but only in receiver digest. (B) the copy is restored from the live cache ->
# `run` exit 0, usn-host upstream_quiet, the alert resolves and the throwaway topic gets one [RESOLVED].
#   bash upstreamwatch/drill/stale-drill.sh 2>&1 | tee LOG    (repo root, agent user with docker + sudo; ~75 min)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
ME="$(id -un)"; HN="$(hostname)"
TOPIC="pftdrill-uw-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
OP_TOPIC="$(sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env)"
BR_URL="$(sed -n 's/^NTFY_URL=//p' "$HOME/.config/pft-alerts/ntfy.env")"
red() {
  sed -E -e "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$TOPIC#<redacted>#g" \
    -e "s#${OP_TOPIC:-@@none@@}#<redacted>#g; s#${BR_URL##*/}#<redacted>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g" \
    -e '/\b127\.0\.0\.1\b/!s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g'
}
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "RESULT: FAIL - $FAILS check(s) failed, stopping after step $1"; exit 1; }; }
NAMES=(pft-uwdrill-metrics pft-uwdrill-prom pft-uwdrill-am pft-uwdrill-bridge)
SCR="$(mktemp -d -p "$HOME/.cache" uwdrill.XXXXXX)"; chmod 755 "$SCR"
cleanup() { docker rm -f "${NAMES[@]}" >/dev/null 2>&1; sudo -n rm -rf "$SCR"; echo "trap: removed ${NAMES[*]} and the scratch dir"; }
trap cleanup EXIT
PROM=http://127.0.0.1:19190 AM=http://127.0.0.1:19193
LIVE_VS=/var/cache/pft-vulnscan
UW=/usr/local/bin/pft-upstreamwatch; UWLIB=/usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py
T0="$(date -u +%s)"
uwrun() { sudo -n env PFT_UW_CONF="$SCR/uw.env" "$UW" run; }
alerts() { curl -fsS "$PROM/api/v1/alerts" | jq -r '[.data.alerts[] | "\(.labels.alertname)/\(.labels.feed)=\(.state)"] | sort | join(" ")'; }
topic() { curl -fsS --max-time 20 "https://ntfy.sh/$TOPIC/json?poll=1&since=$T0" | jq -r 'select(.event == "message") | [.time, .title // "-", (.message | split("\n")[0])] | @tsv'; }

echo "== 1. preflight $(date -u +%FT%TZ) repo $(git rev-parse HEAD) (working tree: $(git status --short | wc -l) changed files)"
x "sha256sum $UW upstreamwatch/pft-upstreamwatch.sh $UWLIB upstreamwatch/upstreamwatch_lib.py alerts/upstreamwatch.rules.yml alerts/alertmanager.yml alerts/ntfy_bridge.py"
check "installed script + helper = repo files" "$([ "$(awk '{print $1}' <<<"$XOUT" | sed -n 1p)" = "$(awk '{print $1}' <<<"$XOUT" | sed -n 2p)" ] && [ "$(awk '{print $1}' <<<"$XOUT" | sed -n 3p)" = "$(awk '{print $1}' <<<"$XOUT" | sed -n 4p)" ] && echo 0 || echo 1)"
x 'docker image inspect -f "{{.RepoTags}}" prom/prometheus:v3.5.0 prom/alertmanager:v0.28.1 python:3.12-alpine'
check "images already on the host (no pull)" "$XRC"
x 'ss -ltnH | grep -cE "127\.0\.0\.1:(19190|19193|19195|19196|19877) " || true'
check "drill ports free" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x 'docker ps -a --format "{{.Names}}" | grep -c "^pft-uwdrill-" || true'
check "no leftover drill containers" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
[ -n "$OP_TOPIC" ] && [ -n "$BR_URL" ]; check "operator topics known (for the read-back)" "$?"
x "sudo -n sha256sum $LIVE_VS/feed.xml.bz2; sudo -n cat $LIVE_VS/feed.meta"
LIVE_SHA="$(awk 'NR == 1 {print $1}' <<<"$XOUT")"
check "live USN feed intact (sha256 = feed.meta)" "$(grep -q "^sha256=$LIVE_SHA$" <<<"$XOUT" && echo 0 || echo 1)"
gate 1

echo "== 2. scratch config + truncated feed copy"
mkdir -p "$SCR/vs" "$SCR/data" "$SCR/tf" "$SCR/p" "$SCR/a"
sudo -n cp -p "$LIVE_VS/feed.xml.bz2" "$LIVE_VS/feed.meta" "$LIVE_VS/feed.etag" "$SCR/vs/"
cat > "$SCR/uw.env" <<EOF
HOST_LABEL=validator
FEEDS="usn-host ubuntu-jammy go debian-oval-bookworm"
VULNSCAN_CACHE=$SCR/vs
DATA_DIR=$SCR/data
TEXTFILE_DIR=$SCR/tf
BUILD_TEXTFILE=/var/lib/pft-exporter/textfile/pft_upgradewatch_postfiatd.prom
EOF
SIZE="$(stat -c %s "$SCR/vs/feed.xml.bz2")"
sudo -n truncate -s $((SIZE / 2)) "$SCR/vs/feed.xml.bz2"
x "cat $SCR/uw.env; ls -l $SCR/vs; sha256sum $SCR/vs/feed.xml.bz2"
check "scratch copy truncated to half ($SIZE -> $((SIZE / 2)) bytes), sha256 no longer matches feed.meta" "$(! grep -q "^$LIVE_SHA " <<<"$XOUT" && echo 0 || echo 1)"
cat > "$SCR/p/prometheus.yml" <<'EOP'
global: {scrape_interval: 15s, evaluation_interval: 15s}
rule_files: [/rules/upstreamwatch.rules.yml]
alerting: {alertmanagers: [{static_configs: [{targets: ["127.0.0.1:19193"]}]}]}
scrape_configs: [{job_name: textfile, fallback_scrape_protocol: PrometheusText0.0.4, metrics_path: /pft_upstreamwatch_validator.prom, static_configs: [{targets: ["127.0.0.1:19877"]}]}]
EOP
sed -e 's#127.0.0.1:9095/#127.0.0.1:19195/#; s#127.0.0.1:9096/#127.0.0.1:19196/#' alerts/alertmanager.yml > "$SCR/a/alertmanager.yml"
printf 'NTFY_URL=https://ntfy.sh/%s\n' "$TOPIC" > "$SCR/ntfy.env"
# the root-owned feed copies are already 644 (chmod warns about them, harmless): keep its stderr redacted
chmod -R a+rX "$SCR" 2>&1 | red
x "diff alerts/alertmanager.yml $SCR/a/alertmanager.yml"
check "alertmanager.yml differs only in the two webhook ports" "$([ "$(diff alerts/alertmanager.yml "$SCR/a/alertmanager.yml" | grep -c '^[<>]')" = 4 ] && echo 0 || echo 1)"
gate 2

echo "== 3. phase A collect (truncated copy) $(date -u +%FT%TZ)"
x uwrun
check "run exit 1 (paged state present)" "$([ "$XRC" = 1 ] && echo 0 || echo 1)"
check "usn-host local_stale: local copy unusable (sha256 differs)" "$(grep -E 'usn-host' <<<"$XOUT" | grep -q 'local_stale' && grep -q 'sha256 differs' <<<"$XOUT" && echo 0 || echo 1)"
x "grep -E '^pft_upstreamwatch_(feed_state\{.*\} 1|up|release_state\{.*\} 1)' $SCR/tf/pft_upstreamwatch_validator.prom"
check "textfile: up 1, usn-host state local_stale" "$(grep -q '^pft_upstreamwatch_up{host="validator"} 1$' <<<"$XOUT" && grep -q 'feed="usn-host".*state="local_stale"' <<<"$XOUT" && echo 0 || echo 1)"
QUIETN="$(grep -c 'state="upstream_quiet"' <<<"$XOUT")"
echo "upstream_quiet feeds in the scratch textfile: $QUIETN"
gate 3

echo "== 4. start throwaway stack $(date -u +%FT%TZ)"
x "docker run -d --name pft-uwdrill-metrics --network host --user 65534 -v $SCR/tf:/m:ro python:3.12-alpine python3 -m http.server 19877 --bind 127.0.0.1 --directory /m"
x "docker run -d --name pft-uwdrill-bridge --network host --user 65534 -e BRIDGE_PORT=19195 -e NTFY_URL_FILE=/e/ntfy.env -v $SCR/ntfy.env:/e/ntfy.env:ro -v $REPO/alerts/ntfy_bridge.py:/b/ntfy_bridge.py:ro python:3.12-alpine python3 -u /b/ntfy_bridge.py"
x "docker run -d --name pft-uwdrill-am --network host --user 65534 --tmpfs /data:mode=1777 -v $SCR/a:/c:ro prom/alertmanager:v0.28.1 --config.file=/c/alertmanager.yml --storage.path=/data --web.listen-address=127.0.0.1:19193 --cluster.listen-address="
x "docker run -d --name pft-uwdrill-prom --network host --user 65534 --tmpfs /prometheus:mode=1777 -v $SCR/p:/etc/prometheus:ro -v $REPO/alerts/upstreamwatch.rules.yml:/rules/upstreamwatch.rules.yml:ro prom/prometheus:v3.5.0 --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus --web.listen-address=127.0.0.1:19190"
for _ in $(seq 1 30); do curl -fsS -o /dev/null "$PROM/-/ready" 2>/dev/null && break; sleep 2; done; sleep 20
x "curl -fsS $PROM/api/v1/rules | jq -r '.data.groups[].rules[] | \"\(.name) \(.health)\"'"
check "prometheus loaded the repo's 6 upstreamwatch rules" "$([ "$(grep -c ' ok$' <<< "$XOUT")" = 6 ] && echo 0 || echo 1)"
x "curl -fsS $PROM/api/v1/targets | jq -r '.data.activeTargets[] | \"\(.labels.job) \(.health)\"'"
check "scrape target up" "$(grep -qx "textfile up" <<< "$XOUT"; echo $?)"
x "curl -fsS -o /dev/null -w '%{http_code}' $AM/-/ready"
check "alertmanager ready" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"
x "alerts"
check "PFTUpstreamFeedLocalStale pending for usn-host" "$(grep -q 'PFTUpstreamFeedLocalStale/usn-host=pending' <<<"$XOUT"; echo $?)"
x "docker logs pft-uwdrill-bridge 2>&1 | tail -3"
[ "$FAILS" = 0 ] || x "docker logs pft-uwdrill-prom 2>&1 | tail -5; docker logs pft-uwdrill-am 2>&1 | tail -5"
gate 4

echo "== 5. wait for the 65m 'for' (poll every 60 s, re-collect every 15 min, up to 80 min)"
for i in $(seq 1 80); do
  sleep 60
  if [ $((i % 15)) = 0 ]; then
    o="$(uwrun 2>&1)"; rc=$?
    echo "$(date -u +%T) re-collect exit $rc: $(grep -E '^ *usn-host' <<<"$o" | head -1 | red)"
  fi
  P="$(alerts)"; N="$(topic | grep -c .)"
  echo "$(date -u +%T) +${i}m prom: ${P:--} | throwaway msgs: $N"
  grep -q 'PFTUpstreamFeedLocalStale/usn-host=firing' <<<"$P" && [ "$N" -ge 1 ] && break
done
sleep 30
echo "== 6. phase A results $(date -u +%FT%TZ)"
x "curl -fsS $PROM/api/v1/alerts | jq -r '.data.alerts[] | [.labels.alertname, .labels.host, .labels.feed, (.labels.notify // \"-\"), .state] | @tsv' | sort"
check "prometheus: PFTUpstreamFeedLocalStale firing for validator/usn-host" "$(grep -qP 'PFTUpstreamFeedLocalStale\tvalidator\tusn-host\t-\tfiring' <<<"$XOUT"; echo $?)"
check "prometheus: no FetchFailing / Release / Failing / NotRunning" "$(grep -qE 'FetchFailing|ReleaseAvailable|UpstreamwatchFailing|NotRunning' <<<"$XOUT" && echo 1 || echo 0)"
x "curl -fsS $AM/api/v2/alerts/groups | jq -r '.[] | \"\(.receiver.name) \(.labels.alertname) alerts=\(.alerts | length)\"' | sort"
check "alertmanager: LocalStale (1 alert) in receiver bridge" "$(grep -qx 'bridge PFTUpstreamFeedLocalStale alerts=1' <<<"$XOUT"; echo $?)"
check "alertmanager: no PFTUpstreamFeedQuiet in receiver bridge" "$(grep -q '^bridge PFTUpstreamFeedQuiet' <<<"$XOUT" && echo 1 || echo 0)"
if [ "$QUIETN" -gt 0 ]; then
  check "alertmanager: PFTUpstreamFeedQuiet ($QUIETN) in receiver digest" "$(grep -qx "digest PFTUpstreamFeedQuiet alerts=$QUIETN" <<<"$XOUT"; echo $?)"
fi
x "topic"
check "throwaway topic: exactly 1 message, the LocalStale [FIRING] page" "$([ "$(grep -c . <<<"$XOUT")" = 1 ] && grep -q 'FIRING' <<<"$XOUT" && grep -q 'PFTUpstreamFeedLocalStale' <<<"$XOUT" && echo 0 || echo 1)"
gate 6

echo "== 7. phase B recovery: restore the copy from the live cache $(date -u +%FT%TZ)"
T1="$(date -u +%s)"
sudo -n cp -p "$LIVE_VS/feed.xml.bz2" "$SCR/vs/feed.xml.bz2"
x "sha256sum $SCR/vs/feed.xml.bz2"
check "scratch copy restored (sha256 = live)" "$(grep -q "^$LIVE_SHA " <<<"$XOUT"; echo $?)"
x uwrun
check "run exit 0 (no paged state)" "$([ "$XRC" = 0 ] && echo 0 || echo 1)"
check "usn-host back to upstream_quiet/ok" "$(grep -E 'usn-host' <<<"$XOUT" | grep -qE 'upstream_quiet|ok' && ! grep -E 'usn-host' <<<"$XOUT" | grep -q local_stale && echo 0 || echo 1)"
for i in $(seq 1 10); do
  sleep 30
  P="$(alerts)"; N="$(topic | grep -c .)"
  echo "$(date -u +%T) +$((i * 30))s prom: ${P:--} | throwaway msgs: $N"
  ! grep -q 'PFTUpstreamFeedLocalStale' <<<"$P" && [ "$N" -ge 2 ] && break
done
sleep 15
echo "== 8. phase B results $(date -u +%FT%TZ)"
x "alerts"
check "prometheus: PFTUpstreamFeedLocalStale gone" "$(grep -q 'PFTUpstreamFeedLocalStale' <<<"$XOUT" && echo 1 || echo 0)"
x "topic"
check "throwaway topic: exactly 2 messages, [FIRING] then [RESOLVED] LocalStale, no FeedQuiet" "$([ "$(grep -c . <<<"$XOUT")" = 2 ] && sed -n 2p <<<"$XOUT" | grep -q 'RESOLVED' && sed -n 2p <<<"$XOUT" | grep -q 'PFTUpstreamFeedLocalStale' && ! grep -q 'FeedQuiet' <<<"$XOUT" && echo 0 || echo 1)"
x "docker logs pft-uwdrill-bridge 2>&1"
check "bridge saw LocalStale firing + resolved" "$(grep -q 'firing.*PFTUpstreamFeedLocalStale\|PFTUpstreamFeedLocalStale.*firing' <<<"$XOUT" && grep -q 'resolved.*PFTUpstreamFeedLocalStale\|PFTUpstreamFeedLocalStale.*resolved' <<<"$XOUT" && echo 0 || echo 1)"
check "bridge never saw PFTUpstreamFeedQuiet" "$(grep -q 'PFTUpstreamFeedQuiet' <<<"$XOUT" && echo 1 || echo 0)"
x "sudo -n sha256sum $LIVE_VS/feed.xml.bz2"
check "live USN feed untouched" "$(grep -q "^$LIVE_SHA " <<<"$XOUT"; echo $?)"
echo "== 9. operator topics (read only; no drill message)"
for t in "$OP_TOPIC" "${BR_URL##*/}"; do
  x "curl -fsS --max-time 20 'https://ntfy.sh/$t/json?poll=1&since=$T0' | jq -r 'select(.event == \"message\") | [.time, .title // \"-\"] | @tsv'"
  check "operator topic: no drill message (PFTUpstream* / uwdrill)" "$(grep -qE 'PFTUpstream|uwdrill' <<<"$XOUT" && echo 1 || echo 0)"
done
echo "phase A start $(date -u -d "@$T0" +%FT%TZ), recovery start $(date -u -d "@$T1" +%FT%TZ)"
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS check(s) failed"
[ "$FAILS" = 0 ]
