#!/usr/bin/env bash
# live-run: the statewatch sentry restart drill. The sentry's postfiatd is restarted while the statewatch rules stay
# LIVE (they are under test and must NOT fire), every other alert is silenced, and every ntfy notifier on both hosts,
# including the Alertmanager bridge, points at a throwaway topic. All output is redacted on the way out.
#   bash drill/live-run.sh 2>&1 | tee LOG      (as the agent user, from statewatch/; uses sudo -n and `ssh relay`)
# 0  preflight (nothing changed yet): relay, Alertmanager and Prometheus reachable, no pft-maint window, notifier env
#    files present, no leftovers, both nodes full, statewatch series present for the sentry. Operator topics, user
#    name, host addresses and node keys go into a 0600 literals file for redact.py; its positive control runs first.
# 1  redirect: LOCAL_ENVS here and REMOTE_ENVS on the relay get the throwaway topic (sha256 recorded, restored on ANY
#    exit and compared); the bridge is recreated with a throwaway NTFY_ENV_FILE (../alerts/run-stack.sh bridge).
#    Alertmanager silence: alertname=~".+" AND alertname!~"<statewatch rules>|<pipeline watchdog>", SIL_TTL minutes.
# 2  restart: sentry container StartedAt + uptime before; `docker restart SENTRY_C` on the relay; then
#    `pft-statewatch collect --stdout` every POLL_S s (no textfile, no history: the timer keeps doing those) printing
#    state, uptime and the five transition counters until the node is full again (FULL_WAIT s max).
# 3  hold HOLD min after full (longer than every statewatch rule window that a restart could touch: brief-exit 10m,
#    collector failing for 5m, stale 300s+2m), then drill/check.sh --container SENTRY_C --since <restart> (C0..C5),
#    the per-state increase of pft_statewatch_state_transitions_total in Prometheus, and report.py on the sentry
#    history from the restart on (uptime-aware: counts the transitions of the new process).
# 4  restore env files + bridge (mount source read back); silence kept until the container start + RESTART_TAIL
#    (PFTContainerRestarted stays true 15 min after a start) then expires by itself; read back the throwaway topic
#    and count messages on every operator topic since the start (topics never printed); pft-integrity verify on both.
#    Exit 0 = every CHECK ok.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  PROM (http://127.0.0.1:9090)
#      SENTRY_C (postfiatd-sentry)  VALIDATOR_C (postfiatd)  LOCAL_ENVS  REMOTE_ENVS  BRIDGE_ENV  AGENT_ENV
#      SIL_TTL (60, min)  RESTART_TAIL (25, min)  POLL_S (5)  FULL_WAIT (900, s)  HOLD (15, min)  NTFY_WAIT (20, s)
#      WATCHDOG_ALERT (PFTAlertPipelineWatchdog)  REDACT (../../peerexpose/drill/redact.py)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SW="$(cd "$HERE/.." && pwd)"
REDACT="${REDACT:-$HERE/../../peerexpose/drill/redact.py}"
RUNSTACK="$HERE/../../alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
SENTRY_C="${SENTRY_C:-postfiatd-sentry}"; VALIDATOR_C="${VALIDATOR_C:-postfiatd}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
SIL_TTL="${SIL_TTL:-60}"; RESTART_TAIL="${RESTART_TAIL:-25}"; POLL_S="${POLL_S:-5}"; FULL_WAIT="${FULL_WAIT:-900}"
HOLD="${HOLD:-15}"; NTFY_WAIT="${NTFY_WAIT:-20}"
WATCHDOG_ALERT="${WATCHDOG_ALERT:-PFTAlertPipelineWatchdog}"
SW_ALERTS='PFTStatewatchCollectorFailing|PFTStatewatchStale|PFTNodeBriefFullExit|PFTNodeStateFlapping|PFTJobQueueOverflow|PFTIOLatencyHigh|PFTPeerDisconnectRateHigh'
SUF=.pre-statewatch-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="swdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
FAILS=0
check() { # NAME CONDITION-RESULT(0/1) DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
pq() { # QUERY -> raw Prometheus JSON result vector as "labels value" lines
  curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric | del(.__name__) | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'
}
sentry_info() { R "sudo -n docker exec $SENTRY_C curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"; }

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha src
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
    if [ "$src" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "statewatch sentry restart drill - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN"
  echo "sha256: live-run.sh $(sha256sum < "$0" | cut -c1-64) | check.sh $(sha256sum < "$HERE/check.sh" | cut -c1-64)"
  echo "        installed sentry pft-statewatch $(R 'sudo -n sha256sum /usr/local/bin/pft-statewatch' | cut -c1-64)"
  echo "        repo pft-statewatch.sh         $(sha256sum < "$SW/pft-statewatch.sh" | cut -c1-64)"
  echo "        statewatch.rules.yml (repo)    $(sha256sum < "$SW/../alerts/statewatch.rules.yml" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
echo "  pft-maint: no window open on either host"
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env $BRIDGE_ENV not readable - stopping" >&2; exit 3; }
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
# shellcheck disable=SC2016  # expands on the relay: the address it sees this host connect from
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"
[ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
# shellcheck disable=SC2016  # expands on the relay
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"
[ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
for h in relay local; do
  if [ "$h" = relay ]; then c="$SENTRY_C"; else c="$VALIDATOR_C"; fi
  si="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005")"
  k="$(jq -r '.result.info.pubkey_node // empty' <<<"$si" 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  st="$(jq -r '.result.info.server_state // "down"' <<<"$si" 2>/dev/null)"
  echo "  $c: server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
n="$(pq "count_over_time(pft_statewatch_up{container=\"$SENTRY_C\"}[10m])" | awk '{print $NF}')"
echo "  Prometheus: pft_statewatch_up samples for $SENTRY_C in the last 10 min: ${n:-0}"
[ "${n:-0}" -ge 5 ] 2>/dev/null || { echo "  statewatch series for the sentry missing - stopping" >&2; exit 3; }
echo "  firing statewatch alerts now: $(pq "ALERTS{alertstate=\"firing\",alertname=~\"$SW_ALERTS\"}" | wc -l)"
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }

echo; echo "== 1. redirect notifiers, Alertmanager silence for everything except the statewatch rules"
redirect() { # HOST PATH
  local h="$1" f="$2"
  SHA["$h:$f"]="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
  [[ "${SHA[$h:$f]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $h:$f unreadable - stopping"; exit 3; }
  echo "  $h:$f sha256 ${SHA[$h:$f]:0:12} (before)"
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $h:$f -> $NTFY/<redacted> (throwaway), original kept as $f$SUF"
}
for f in $LOCAL_ENVS; do redirect local "$f"; done
for f in $REMOTE_ENVS; do redirect relay "$f"; done
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src" = "$SEC/bridge.env" ] || { echo "  bridge not pointed at the throwaway env - stopping"; exit 3; }
echo "  bridge -> $NTFY/<redacted> (throwaway env file in a 0700 temp dir)"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "statewatch drill $RUN: unrelated alerts" --arg x "$SW_ALERTS|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "statewatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"<7 statewatch rules>|$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"
echo "  (statewatch rules NOT silenced: they are under test and must stay quiet on their own)"

echo; echo "== 2. restart $SENTRY_C"
st0="$(R "sudo -n docker inspect -f '{{.State.StartedAt}}' $SENTRY_C")"
up0="$(sentry_info | jq -r '.result.info.uptime // empty')"
echo "  before: StartedAt=$st0 uptime=${up0}s"
t_restart="$(date -u +%s)"
echo "\$ ssh relay sudo docker restart $SENTRY_C ($(ts))"
R "sudo -n docker restart $SENTRY_C" 2>&1 | red | sed 's/^/  /'
st1="$(R "sudo -n docker inspect -f '{{.State.StartedAt}}' $SENTRY_C")"
echo "  after:  StartedAt=$st1"
check "container restarted (StartedAt changed)" "$([ -n "$st1" ] && [ "$st1" != "$st0" ] && echo 0 || echo 1)"
echo "  polling: pft-statewatch collect --container $SENTRY_C --stdout every ${POLL_S}s (time up state uptime transitions d/c/s/t/f full_exits)"
reached=""; last=""
while [ $(( $(date -u +%s) - t_restart )) -lt "$FULL_WAIT" ]; do
  out="$(R "sudo -n pft-statewatch collect --container $SENTRY_C --stdout" 2>/dev/null)"
  line="$(awk -v c="$SENTRY_C" '
    $1 ~ /^pft_statewatch_up\{/ {up=$2}
    $1 ~ /^pft_statewatch_server_state\{/ && $2 == 1 {match($1, /state="[a-z]+"/); s=substr($1, RSTART+7, RLENGTH-8)}
    $1 ~ /^pft_statewatch_node_uptime_seconds\{/ {u=$2}
    $1 ~ /^pft_statewatch_state_transitions_total\{/ {match($1, /state="[a-z]+"/); t[substr($1, RSTART+7, RLENGTH-8)]=$2}
    $1 ~ /^pft_statewatch_full_exits_total\{/ {fe=$2}
    END {printf "up=%s state=%s uptime=%s transitions=%s/%s/%s/%s/%s full_exits=%s", up, (s==""?"-":s), (u==""?"-":u),
         t["disconnected"], t["connected"], t["syncing"], t["tracking"], t["full"], (fe==""?"-":fe)}' <<<"$out")"
  if [ "$line" != "$last" ]; then echo "  $(ts) $line"; last="$line"; fi
  case "$line" in *"up=1 state=full "*) reached="$(date -u +%s)"; break ;; esac
  sleep "$POLL_S"
done
check "sentry back to full within ${FULL_WAIT}s" "$([ -n "$reached" ] && echo 0 || echo 1)" \
  "${reached:+$((reached - t_restart)) s after the restart}"

echo; echo "== 3. hold ${HOLD} min, then evidence"
sleep $((HOLD * 60))
t_end="$(date -u +%s)"
echo "\$ drill/check.sh --container $SENTRY_C --since $t_restart --until $t_end"
bash "$HERE/check.sh" --container "$SENTRY_C" --since "$t_restart" --until "$t_end" 2>&1 | sed 's/^/  /'; crc="${PIPESTATUS[0]}"
check "drill/check.sh C0..C5 all pass" "$([ "$crc" = 0 ] && echo 0 || echo 1)" "exit $crc"
W="$((t_end - t_restart + 120))s"
echo "  Prometheus increase(pft_statewatch_state_transitions_total{container=\"$SENTRY_C\"}[$W]) per state:"
pq "increase(pft_statewatch_state_transitions_total{container=\"$SENTRY_C\"}[$W])" | sed 's/^/    /'
echo "  Prometheus resets(...[$W]) per state:"
pq "resets(pft_statewatch_state_transitions_total{container=\"$SENTRY_C\"}[$W])" | sed 's/^/    /'
echo "  firing statewatch alerts in the drill window (any container):"
fired="$(pq "max_over_time(ALERTS{alertstate=\"firing\",alertname=~\"$SW_ALERTS\"}[$W])")"
if [ -n "$fired" ]; then while read -r l; do echo "    $l"; done <<<"$fired"; else echo "    none"; fi
check "no statewatch alert fired on any container" "$([ -z "$fired" ] && echo 0 || echo 1)"
echo "  Alertmanager alerts now (name state silenced-by):"
curl -s --max-time 10 "$AM/api/v2/alerts" | jq -r '.[] | "    \(.labels.alertname) \(.labels.container // "-") \(.status.state) \(.status.silencedBy | length)"' | sort | uniq -c
echo "  report.py on the sentry history from the restart on (uptime-aware transitions of the new process):"
R "sudo -n cat /var/lib/pft-statewatch/history-$SENTRY_C.jsonl" \
  | jq -c --argjson s "$((t_restart - 120))" 'select(.ts >= $s)' > "$SEC/hist.jsonl"
echo "    history lines in window: $(wc -l < "$SEC/hist.jsonl")"
python3 "$SW/report/report.py" "$SEC/hist.jsonl" 2>&1 | red | sed 's/^/    /'

echo; echo "== 4. restore, silence tail, read back"
restore
check "notifier env files restored byte-identical, bridge back on the operator env" "$([ "$RESTORE_OK" = true ] && echo 0 || echo 1)"
st_epoch="$(date -u -d "$st1" +%s 2>/dev/null || echo "$t_restart")"
e="$(date -u -d "@$(( st_epoch + RESTART_TAIL * 60 ))" +%FT%TZ)"
if [ "$(date -u +%s)" -ge $(( st_epoch + RESTART_TAIL * 60 )) ]; then
  curl -s --max-time 10 -o /dev/null -w '  restart tail already over: silence expired: HTTP %{http_code}\n' -X DELETE "$AM/api/v2/silence/$SIL"
else
  curl -s --max-time 10 -o /dev/null -w "  silence kept until $e (container start + ${RESTART_TAIL} min), then expires by itself: HTTP %{http_code}\n" \
    -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$(jq -c --arg id "$SIL" --arg e "$e" '. + {id: $id, endsAt: $e}' <<<"$SBODY")"
fi
sleep "$NTFY_WAIT"
readback() { # TOPIC LABEL [quiet] -> sets N_MSG; prints messages unless quiet
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$ALERT" throwaway
SW_MSG="$(curl -s --max-time 20 "$NTFY/$ALERT/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null | grep -cE "$SW_ALERTS")"
check "throwaway topic: no statewatch alert delivered" "$([ "$SW_MSG" = 0 ] && echo 0 || echo 1)" "$SW_MSG"
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the drill" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo "  \$ pft-integrity verify (validator host)"; sudo -n pft-integrity verify 2>&1 | red | tail -4 | sed 's/^/    /'
echo "  \$ pft-integrity verify (sentry host)"; R "sudo -n pft-integrity verify" 2>&1 | red | tail -4 | sed 's/^/    /'
fs="$(sentry_info | jq -r '.result.info.server_state // "down"')"
check "sentry full at the end" "$(case "$fs" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$fs"
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
