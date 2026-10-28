#!/usr/bin/env bash
# Live alert drill for ../../alerts/timesync.rules.yml on a THROWAWAY ntfy topic (never the operator's).
# Runs on the validator (the host with the ../alerts stack) as the operator user; uses sudo for docker/systemctl.
#
#  1 preflight  stack ready, bridge on the real env file, no PFTTimesync*/PFTClock* alert active, node full,
#               pft-timesync.timer active; records postfiatd StartedAt and sha256 of the sentry alertpath env
#  2 redirect   pft-alert-bridge -> throwaway topic (alerts/run-stack.sh bridge; Prometheus/Alertmanager keep
#               running) and the sentry's /etc/pft-alertpath/ntfy.env -> the same throwaway topic, because the
#               ~2 s bridge recreate can make ../alertpath report DEGRADED, and that page must not reach the operator
#  3 inject     stop pft-timesync.timer (metrics only: chrony and postfiatd are not touched). The textfile keeps its
#               last collect timestamp, so PFTTimesyncStale goes pending (> 300 s) then firing (for: 2m)
#  4 expect     PFTTimesyncStale firing in Prometheus, active in Alertmanager, "[FIRING] PFTTimesyncStale" on the topic
#  5 recover    start the timer; expect the alert gone from Prometheus/Alertmanager and "[RESOLVED]" on the topic
#  6 restore    on ANY exit (trap): timer started, bridge back on the real env file (mount source checked), sentry
#               env restored and compared by sha256 with the pre-drill file, after the sentry check reports OK
#  7 verdict    one PASS/FAIL line per check; messages on the operator topics during the drill must be 0
#
# Usage: alert-drill.sh OUTDIR    Env: SSH_SENTRY ("ssh relay"), FIRE_BUDGET (900 s), RESOLVE_BUDGET (600 s)
# Output is redacted: topic names -> <redacted>, home paths -> <home>, IPv4 -> <redacted-ip>.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${1:?usage: alert-drill.sh OUTDIR}"
mkdir -p "$OUT"
read -r -a SSH_SENTRY <<< "${SSH_SENTRY:-ssh relay}"
FIRE_BUDGET="${FIRE_BUDGET:-900}"
RESOLVE_BUDGET="${RESOLVE_BUDGET:-600}"
PROM=http://127.0.0.1:9090
AM=http://127.0.0.1:9093
ALERT=PFTTimesyncStale
REAL_BRIDGE_ENV="$(readlink -f "$HOME/.config/pft-alerts/ntfy.env")"
SENTRY_ENV=/etc/pft-alertpath/ntfy.env
SENTRY_BAK=/etc/pft-alertpath/ntfy.env.pre-tsdrill

topic="tsdrill-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TDIR="$(mktemp -d)"; TBRIDGE="$TDIR/ntfy.env"
since="$(date -u +%s)"
RESTORED=0 BRIDGE_REDIR=0 SENTRY_REDIR=0 TIMER_STOPPED=0 FAILS=0
op_topics=()

ts() { date -u +%FT%TZ; }
red() { sed -E "s/$topic/<redacted>/g; s|/home/[^ ]*|<home>|g; s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/<redacted-ip>/g"; }
check() { # NAME yes|no
  if [ "$2" = yes ]; then echo "[PASS] $1"; else echo "[FAIL] $1"; FAILS=$((FAILS + 1)); fi
}
bridge_src() { sudo docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}' pft-alert-bridge 2>/dev/null || true; }
node_state() {
  sudo docker exec postfiatd curl -s -m 5 -X POST -H 'Content-Type: application/json' \
    -d '{"method":"server_info","params":[{}]}' http://127.0.0.1:5005/ 2>/dev/null \
    | jq -r '.result.info.server_state // "unreachable"' 2>/dev/null || echo unreachable
}
started_at() { sudo docker inspect -f '{{.State.StartedAt}}' postfiatd; }
prom_state() { # alert state in Prometheus: inactive|pending|firing
  curl -fsS "$PROM/api/v1/alerts" | jq -r --arg a "$ALERT" '[.data.alerts[] | select(.labels.alertname == $a) | .state] | first // "inactive"'
}
am_state() { curl -fsS "$AM/api/v2/alerts" | jq -r --arg a "$ALERT" '[.[] | select(.labels.alertname == $a) | .status.state] | first // "none"'; }
stale_age() { curl -fsS "$PROM/api/v1/query" --data-urlencode 'query=time() - pft_timesync_collect_timestamp_seconds' | jq -r '.data.result[0].value[1] // "none" | (tonumber? | floor) // .'; }
topic_titles() { # TOPIC -> one title per line for messages since the drill started
  curl -s --max-time 20 "https://ntfy.sh/$1/json?poll=1&since=$since" | jq -r 'select(.event == "message") | .title // ""' 2>/dev/null || true
}
topic_of() { sed -n -e 's|^NTFY_URL=https\{0,1\}://[^/]*/||p' -e 's|^NTFY_TOPIC=||p' | head -1 | tr -d '"[:space:]'; }
sentry_sha() { "${SSH_SENTRY[@]}" "sudo sha256sum $1 2>/dev/null | cut -d' ' -f1" </dev/null; }
sentry_check_line() { "${SSH_SENTRY[@]}" 'journalctl --utc -u pft-alertpath-check.service -n 30 --no-pager -o cat | grep -E "state=" | tail -1' </dev/null; }
sample() { echo "$(ts) node=$(node_state) stale_age=$(stale_age)s prometheus=$(prom_state) alertmanager=$(am_state)"; }

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  set +e   # a failing step must not abort the rest of the restore
  echo; echo "== 6. restore ($(ts))"
  if [ "$TIMER_STOPPED" -eq 1 ] && ! systemctl is-active -q pft-timesync.timer; then
    echo "  \$ sudo systemctl start pft-timesync.timer"; sudo systemctl start pft-timesync.timer
  fi
  echo "  pft-timesync.timer: $(systemctl is-active pft-timesync.timer)"
  if [ "$BRIDGE_REDIR" -eq 1 ]; then
    echo "  \$ NTFY_ENV_FILE=<real bridge env> alerts/run-stack.sh bridge"
    NTFY_ENV_FILE="$REAL_BRIDGE_ENV" DOCKER="sudo docker" bash "$ROOT/alerts/run-stack.sh" bridge 2>&1 | red | sed 's/^/  /'
    check "pft-alert-bridge mount source is the real env file again" "$([ "$(bridge_src)" = "$REAL_BRIDGE_ENV" ] && echo yes || echo no)"
  fi
  if [ "$SENTRY_REDIR" -eq 1 ]; then
    # let the sentry's 1-min check see the restored bridge (and send any RECOVERED to the throwaway topic) first
    local i line=""
    for i in $(seq 1 36); do
      sleep 10
      line="$(sentry_check_line)"
      [ "$i" -ge 7 ] && [[ "$line" == *"state=OK"* ]] && break
    done
    echo "  sentry alertpath check before env restore: $(printf '%s' "$line" | red)"
    "${SSH_SENTRY[@]}" "sudo mv -f $SENTRY_BAK $SENTRY_ENV" </dev/null
    local now; now="$(sentry_sha "$SENTRY_ENV")"
    check "sentry alertpath ntfy.env restored byte-identical (sha256 ${now:0:16}.. = pre-drill)" "$([ -n "$now" ] && [ "$now" = "$SENTRY_SHA" ] && echo yes || echo no)"
    check "sentry alertpath ntfy.env mode/owner $("${SSH_SENTRY[@]}" "sudo stat -c %a:%U $SENTRY_ENV" </dev/null)" \
      "$([ "$("${SSH_SENTRY[@]}" "sudo stat -c %a:%U $SENTRY_ENV" </dev/null)" = 600:root ] && echo yes || echo no)"
  fi
  rm -rf "$TDIR"
  echo; echo "== 7. verdict ($(ts))"
  mapfile -t got < <(topic_titles "$topic")
  echo "  throwaway topic <redacted>: ${#got[@]} messages"
  printf '    %s\n' "${got[@]}"
  check "throwaway topic got [FIRING] $ALERT" "$(printf '%s\n' "${got[@]}" | grep -qx "\[FIRING\] $ALERT" && echo yes || echo no)"
  check "throwaway topic got [RESOLVED] $ALERT" "$(printf '%s\n' "${got[@]}" | grep -qx "\[RESOLVED\] $ALERT" && echo yes || echo no)"
  local t n k=0
  for t in "${op_topics[@]}"; do
    k=$((k + 1))
    n="$(topic_titles "$t" | grep -c . || true)"
    check "operator topic #$k: $n messages during the drill" "$([ "$n" -eq 0 ] && echo yes || echo no)"
  done
  check "postfiatd StartedAt unchanged ($(started_at))" "$([ "$(started_at)" = "$STARTED" ] && echo yes || echo no)"
  check "postfiatd server_state full" "$([ "$(node_state)" = full ] && echo yes || echo no)"
  check "pft-timesync audit exit 0 after the drill" "$(sudo pft-timesync audit >/dev/null 2>&1 && echo yes || echo no)"
  echo "RESULT: $([ "$FAILS" -eq 0 ] && echo PASS || echo "FAIL ($FAILS)")"
  [ "$FAILS" -eq 0 ]
}
trap restore EXIT

echo "pft-timesync alert drill - $(ts) - $(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release) - alert $ALERT"
echo "sha256 $(sha256sum "$0" | cut -c1-64) timesync/drill/alert-drill.sh"
echo "sha256 $(sha256sum "$ROOT/alerts/timesync.rules.yml" | cut -c1-64) alerts/timesync.rules.yml"
echo; echo "== 1. preflight"
if ! { curl -fsS "$PROM/-/ready" >/dev/null && curl -fsS "$AM/-/ready" >/dev/null; }; then echo "  stack not ready"; exit 3; fi
[ "$(bridge_src)" = "$REAL_BRIDGE_ENV" ] || { echo "  bridge is not on the real env file - stopping"; exit 3; }
active="$(curl -fsS "$PROM/api/v1/alerts" | jq -r '[.data.alerts[] | .labels.alertname | select(test("^PFT(Timesync|Clock)"))] | join(",")')"
[ -z "$active" ] || { echo "  timesync alerts already active ($active) - stopping"; exit 3; }
[ "$(node_state)" = full ] || { echo "  node not full - stopping"; exit 3; }
systemctl is-active -q pft-timesync.timer || { echo "  pft-timesync.timer not active - stopping"; exit 3; }
STARTED="$(started_at)"
SENTRY_SHA="$(sentry_sha "$SENTRY_ENV")"
[ ${#SENTRY_SHA} -eq 64 ] || { echo "  cannot hash the sentry env file - stopping"; exit 3; }
"${SSH_SENTRY[@]}" "sudo test ! -e $SENTRY_BAK" </dev/null || { echo "  a sentry backup from an earlier drill exists - stopping"; exit 3; }
op_topics+=("$(topic_of < "$REAL_BRIDGE_ENV")")
op_topics+=("$("${SSH_SENTRY[@]}" "sudo cat $SENTRY_ENV" </dev/null | topic_of)")
for t in "${op_topics[@]}"; do
  if [ -z "$t" ] || [ "$t" = "$topic" ]; then echo "  operator topic unreadable - stopping"; exit 3; fi
done
echo "  stack ready; bridge on the real env file; no PFTTimesync*/PFTClock* alerts; node full; timer active"
echo "  postfiatd StartedAt $STARTED; sentry alertpath env sha256 ${SENTRY_SHA:0:16}..; operator topics read: ${#op_topics[@]}"
sample | sed 's/^/  /'

echo; echo "== 2. redirect to the throwaway topic <redacted>"
( umask 077; printf 'NTFY_URL=https://ntfy.sh/%s\n' "$topic" > "$TBRIDGE" )
SENTRY_REDIR=1
"${SSH_SENTRY[@]}" "sudo sed -i.pre-tsdrill 's/^NTFY_TOPIC=.*/NTFY_TOPIC=$topic/' $SENTRY_ENV" </dev/null
[ "$("${SSH_SENTRY[@]}" "sudo cat $SENTRY_ENV" </dev/null | topic_of)" = "$topic" ] || { echo "  sentry env not redirected - stopping"; exit 1; }
echo "  sentry /etc/pft-alertpath/ntfy.env -> throwaway (backup kept beside it)"
BRIDGE_REDIR=1
echo "  \$ NTFY_ENV_FILE=<throwaway env> alerts/run-stack.sh bridge"
NTFY_ENV_FILE="$TBRIDGE" DOCKER="sudo docker" bash "$ROOT/alerts/run-stack.sh" bridge 2>&1 | red | sed 's/^/  /'
[ "$(bridge_src)" = "$TBRIDGE" ] || { echo "  bridge not on the throwaway file - stopping"; exit 1; }
echo "  pft-alert-bridge -> throwaway (mount source checked); not recreated: $(sudo docker inspect -f '{{.Name}} {{.State.StartedAt}}' pft-prometheus pft-alertmanager | tr '\n' ' ')"

echo; echo "== 3. inject: stop pft-timesync.timer (metrics stop; chrony and postfiatd untouched)"
TIMER_STOPPED=1
echo "  \$ sudo systemctl stop pft-timesync.timer"; sudo systemctl stop pft-timesync.timer
t0="$(date -u +%s)"

echo; echo "== 4. expect $ALERT firing (budget ${FIRE_BUDGET}s)"
seen_pending=no seen_firing=no seen_am=no seen_topic=no
while [ $(( $(date -u +%s) - t0 )) -lt "$FIRE_BUDGET" ]; do
  s="$(sample)"; echo "  $s"
  [[ "$s" == *"prometheus=pending"* ]] && seen_pending=yes
  [[ "$s" == *"prometheus=firing"* ]] && seen_firing=yes
  [[ "$s" == *"alertmanager=active"* ]] && seen_am=yes
  topic_titles "$topic" | grep -qx "\[FIRING\] $ALERT" && seen_topic=yes
  [ "$seen_firing" = yes ] && [ "$seen_am" = yes ] && [ "$seen_topic" = yes ] && break
  sleep 30
done
echo "  firing after $(( $(date -u +%s) - t0 ))s"
check "Prometheus showed $ALERT pending" "$seen_pending"
check "Prometheus showed $ALERT firing" "$seen_firing"
check "Alertmanager showed $ALERT active" "$seen_am"
check "[FIRING] $ALERT reached the throwaway topic" "$seen_topic"

echo; echo "== 5. recover: start pft-timesync.timer (budget ${RESOLVE_BUDGET}s)"
echo "  \$ sudo systemctl start pft-timesync.timer"; sudo systemctl start pft-timesync.timer
t1="$(date -u +%s)"; resolved=no topic_res=no
while [ $(( $(date -u +%s) - t1 )) -lt "$RESOLVE_BUDGET" ]; do
  sleep 20
  s="$(sample)"; echo "  $s"
  [[ "$s" == *"prometheus=inactive alertmanager=none"* ]] && resolved=yes
  topic_titles "$topic" | grep -qx "\[RESOLVED\] $ALERT" && topic_res=yes
  [ "$resolved" = yes ] && [ "$topic_res" = yes ] && break
done
echo "  resolved after $(( $(date -u +%s) - t1 ))s"
check "$ALERT left Prometheus and Alertmanager" "$resolved"
check "[RESOLVED] $ALERT reached the throwaway topic" "$topic_res"
