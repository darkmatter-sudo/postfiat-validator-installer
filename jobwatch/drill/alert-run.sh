#!/usr/bin/env bash
# alert-run: recorded two-host alert drill for pft-jobwatch (task_de7c65f8535e68b146f171bcec90b36b, step 4). Runs one
# throwaway drill job on BOTH hosts at once and walks it through succeed -> fail -> disable -> hang (missed) -> remove,
# proving PFTJobFailed, PFTJobDisabled (disabled and removed) and PFTJobMissed go FIRING and then RESOLVED for both
# hosts on a throwaway ntfy topic, with zero messages on the operator topics. Built from ../../kernwatch/drill/
# kmsg-run.sh (bridge re-create on a temp env file, alertpath pause, silence, read-back, PREFLIGHT_ONLY).
#   bash jobwatch/drill/alert-run.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
# The drill job is a RUNTIME unit pair in /run/systemd/system (pft-jobwatch-drill.timer every minute ->
# pft-jobwatch-drill.service, a oneshot `sh -c` that loops while /run/pft-jobwatch-drill/hang exists and fails while
# /run/pft-jobwatch-drill/fail exists). /run is outside pft-integrity's tracked set (/etc/systemd/system), so the hourly
# integrity check does not see it, and it is gone at the next boot at the latest. Nothing else is started, stopped or
# restarted; postfiatd is never touched.
# Only the Alertmanager bridge is redirected (re-created on a 0600 temp env file; the operator env file is never
# edited, so pft-keyescrow's fingerprints stay clean). Every other alert is silenced for the run; the operator topics
# are read back at the end (must be 0 messages).
# 0  preflight (nothing changed): clean pushed HEAD; relay, AM, Prometheus reachable; pft-jobwatch + timers on both
#    hosts, up 1 for both in Prometheus, 4 rules healthy, no PFTJob* alert active; bridge on the operator env; no drill
#    unit left over; both nodes full; pft-integrity PASS on both; redaction control.
# 1  bridge -> throwaway topic (alertpath paused around the re-create); silence all but PFTAlertPipelineWatchdog|PFTJob.*
# 2  SUCCEED: install + enable --runtime the drill job on both hosts; runs succeed; jobwatch sees it (present 1,
#    failed 0, disabled 0); no PFTJob* alert for it after 4 min.
# 3  FAIL: create the fail flag -> PFTJobFailed FIRING for both hosts; remove it -> next run succeeds -> RESOLVED.
# 4  DISABLE: disable --runtime --now the timer -> PFTJobDisabled FIRING; enable --runtime --now -> RESOLVED.
# 5  HANG: create the hang flag -> the run never ends, the timer stops re-firing -> PFTJobMissed FIRING (running 1);
#    remove it -> the run ends with success, the timer fires again -> RESOLVED.
# 6  REMOVE: disable + delete the unit files + daemon-reload -> present 0 -> PFTJobDisabled FIRING (2nd time);
#    pft-jobwatch forget on both hosts -> the series disappear -> RESOLVED.
# 7  restore (drill units + flags + state entry gone, bridge, silence), read back every topic, integrity PASS, nodes full.
# Env: RELAY (relay) NTFY (https://ntfy.sh) AM PROM BRIDGE_ENV AGENT_ENV SIL_TTL (150 min) FIRE_WAIT (900 s)
#      RESOLVE_WAIT (900 s) QUIET_WAIT (240 s) PREFLIGHT_ONLY=1: step 0 only (exit 0 ready).
# shellcheck disable=SC2016,SC2015,SC2034  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
REMOTE_ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
AP_WAIT="${AP_WAIT:-180}"; SIL_TTL="${SIL_TTL:-150}"; FIRE_WAIT="${FIRE_WAIT:-900}"; RESOLVE_WAIT="${RESOLVE_WAIT:-900}"
QUIET_WAIT="${QUIET_WAIT:-240}"; PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"
TASK=task_de7c65f8
SHA_HEAD="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile
JOB=pft-jobwatch-drill.timer; SVC=pft-jobwatch-drill.service; UD=/run/systemd/system; FD=/run/pft-jobwatch-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="jwdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes "$RELAY" "$@" </dev/null; }
L() { bash -c "$1" </dev/null; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
both() { R "$1"; local a=$?; L "$1"; local b=$?; [ "$a" = 0 ] && [ "$b" = 0 ]; } # sentry first, then validator
cn() { if [ "$1" = relay ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
lb() { if [ "$1" = relay ]; then echo sentry; else echo validator; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
info() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"; }
node_state() { info "$1" | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
pq() { curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
n_msgs() { # STATUS ALERTNAME HOST PHRASE -> count of matching throwaway-topic messages about the drill job
  topic_msgs "$ALERT" | jq -r --arg t "[$1] $2" 'select(.title == $t) | .message' | grep -c "^$3: scheduled job $JOB $4"
}
collect_now() { # run both collectors and the validator's pull now (instead of waiting up to 2 + 2 min)
  R 'sudo -n systemctl start pft-jobwatch.service' && sudo -n systemctl start pft-jobwatch.service pft-jobwatch-pull.service </dev/null
}
jobline() { # print the drill job's flags for both hosts from the two textfiles on the validator
  grep -hE "^pft_jobwatch_job_(present|disabled|running|failed|consecutive_failures|missed|runs_observed_total)\{host=\"(validator|sentry)\",job=\"$JOB\"\}" \
    "$TF/pft_jobwatch_validator.prom" "$TF/pft_jobwatch_sentry.prom" 2>/dev/null | sed -E 's/^pft_jobwatch_job_//; s/,job="[^"]*"//'
}
flag() { grep -E "^$1\{host=\"$2\"\} " <<<"$XOUT" | awk '{print $2}'; } # METRIC HOST (from a jobline XOUT)
firing() { pq "ALERTS{alertname=\"$1\",alertstate=\"firing\",job=\"$JOB\"}"; }
wait_fire() { # ALERTNAME PHRASE MIN_MSGS: Prometheus firing for both hosts, then >= MIN_MSGS [FIRING] per host
  local t0 F w ok hl; t0="$(date -u +%s)"; F=""
  while [ $(( $(date -u +%s) - t0 )) -lt "$FIRE_WAIT" ]; do
    F="$(firing "$1")"; [ "$(grep -cE 'host=(sentry|validator)' <<<"$F")" -ge 2 ] && break; sleep 15
  done
  echo "  $(ts) ($(( $(date -u +%s) - t0 ))s after the change): firing in Prometheus:"; printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
  for hl in sentry validator; do check "$1{host=$hl,job=$JOB} firing in Prometheus" "$(ok_if 'grep -q "host=$hl" <<<"$F"')"; done
  w=0; while :; do
    ok=0; for hl in sentry validator; do [ "$(n_msgs FIRING "$1" "$hl" "$2")" -ge "$3" ] && ok=$((ok + 1)); done
    [ "$ok" = 2 ] && break; w=$((w + 15)); [ "$w" -le 300 ] || break; sleep 15
  done
  for hl in sentry validator; do
    check "[FIRING] $1 '$hl: scheduled job $JOB $2...' on the throwaway topic (>= $3)" "$(ok_if '[ "$(n_msgs FIRING "$1" "$hl" "$2")" -ge "$3" ]')"
  done
}
wait_resolve() { # ALERTNAME PHRASE MIN_MSGS
  local t0 F ok hl; t0="$(date -u +%s)"; F="x"
  while [ $(( $(date -u +%s) - t0 )) -lt "$RESOLVE_WAIT" ]; do
    F="$(pq "ALERTS{alertname=\"$1\",job=\"$JOB\"}")"
    ok=0; for hl in sentry validator; do [ "$(n_msgs RESOLVED "$1" "$hl" "$2")" -ge "$3" ] && ok=$((ok + 1)); done
    [ -z "$F" ] && [ "$ok" = 2 ] && break; sleep 20
  done
  echo "  $(ts) ($(( $(date -u +%s) - t0 ))s after the fix): $1 series left in Prometheus: $(grep -c . <<<"$F")"
  check "no $1 for $JOB left in Prometheus" "$(ok_if '[ -z "$F" ]')"
  for hl in sentry validator; do
    check "[RESOLVED] $1 '$hl: scheduled job $JOB $2...' on the throwaway topic (>= $3)" "$(ok_if '[ "$(n_msgs RESOLVED "$1" "$hl" "$2")" -ge "$3" ]')"
  done
}

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; DRILL_UNITS=0
ap_pause() { R 'sudo -n systemctl stop pft-alertpath-check.timer' && AP_PAUSED=1
  echo "  sentry pft-alertpath-check.timer stopped: $([ "$AP_PAUSED" = 1 ] && echo yes || echo NO)"; }
ap_resume() { # wait (<= AP_WAIT s) for a read-only check to be OK again, then start the timer whatever the result
  local t0 rc=9; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$AP_WAIT" ]; do
    R 'sudo -n pft-alertpath check >/dev/null 2>&1'; rc=$?; [ "$rc" = 0 ] && break; sleep 10
  done
  R 'sudo -n systemctl start pft-alertpath-check.timer' && AP_PAUSED=0
  echo "  sentry pft-alertpath check rc $rc after $(( $(date -u +%s) - t0 ))s; timer started again: $([ "$AP_PAUSED" = 0 ] && echo yes || echo NO)"
  [ "$rc" = 0 ] && [ "$AP_PAUSED" = 0 ]; }
bridge_src() { sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}'; }
UNDRILL="sudo -n rm -rf $FD; sudo -n systemctl disable --runtime --now $JOB >/dev/null 2>&1; sudo -n systemctl stop $SVC >/dev/null 2>&1; sudo -n rm -f $UD/$JOB $UD/$SVC; sudo -n systemctl daemon-reload; sudo -n systemctl reset-failed $SVC >/dev/null 2>&1; sudo -n pft-jobwatch forget $JOB >/dev/null 2>&1; sudo -n systemctl start pft-jobwatch.service; test ! -e $UD/$JOB && test ! -e $UD/$SVC && test ! -e $FD"
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$DRILL_UNITS" = 1 ]; then
    both "$UNDRILL" && echo "  drill units, flags and state entry removed on both hosts: yes" || { echo "  drill cleanup: NO"; RESTORE_OK=false; }
    sudo -n systemctl start pft-jobwatch-pull.service </dev/null
  fi
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  [ -n "$SIL" ] && curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-jobwatch two-host alert drill - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in jobwatch/drill/alert-run.sh jobwatch/pft-jobwatch.sh jobwatch/jobwatch_lib.py alerts/jobwatch.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
for h in local relay; do
  on "$h" "command -v pft-jobwatch >/dev/null && systemctl is-active --quiet pft-jobwatch.timer" \
    || { echo "  $(lb "$h"): pft-jobwatch or its timer missing - stopping" >&2; exit 3; }
  for f in "$UD/$JOB" "$UD/$SVC" "$FD"; do
    on "$h" "test ! -e $f" || { echo "  $(lb "$h"): $f left over from an earlier run - stopping" >&2; exit 3; }
  done
  on "$h" "sudo -n pft-jobwatch inventory --format json | jq -e 'map(select(.job == \"$JOB\")) | length == 0' >/dev/null" \
    || { echo "  $(lb "$h"): $JOB still in the jobwatch state - stopping" >&2; exit 3; }
done
echo "  pft-jobwatch + timer on both hosts; no drill unit, flag dir or state entry left over"
systemctl is-active --quiet pft-jobwatch-pull.timer || { echo "  pft-jobwatch-pull.timer not active - stopping" >&2; exit 3; }
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1' \
  || { echo "  sentry pft-alertpath-check.timer not active or check not OK - stopping" >&2; exit 3; }
echo "  sentry pft-alertpath-check.timer active, check OK"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_jobwatch_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
[ "$(grep -cE '^(sentry|validator) 1$' <<<"$XOUT")" = 2 ] || { echo "  pft_jobwatch_up is not 1 for both hosts - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_jobwatch_jobs' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.state) \(.value[1])\"' | sort"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTJob.*\"}' | jq -r '.data.result | length'"
[ "$XOUT" = 0 ] || { echo "  a PFTJob* alert is already active (investigate it first) - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-jobwatch\") | .rules[] | [.name, .health] | @tsv'"
[ "$(grep -cE '^PFTJob(Failed|Missed|Disabled|watchStale)	ok$' <<<"$XOUT")" = 4 ] || { echo "  jobwatch rules not loaded/healthy - stopping" >&2; exit 4; }
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
[ "$(bridge_src)" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; [ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
for h in relay local; do
  s="$(node_state "$h")"; echo "  $(cn "$h"): server_state=${s:-down}"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then
  echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed (ready: yes)"
  exit 0
fi

echo; echo "== 1. bridge -> throwaway topic; silence everything except PFTJob* and the watchdog"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-jobwatch alert drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTJob.*", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "jobwatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTJob.*\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. SUCCEED: runtime drill job on both hosts"
SVC_TXT="[Unit]
Description=pft-jobwatch drill job (runtime unit; $FD/hang and $FD/fail select the outcome)
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'while [ -e $FD/hang ]; do sleep 5; done; [ ! -e $FD/fail ]'
TimeoutStartSec=3600"
TMR_TXT="[Unit]
Description=pft-jobwatch drill timer (every minute)
[Timer]
OnActiveSec=5s
OnUnitActiveSec=1min
AccuracySec=1s
[Install]
WantedBy=timers.target"
echo "  $UD/$SVC:"; printf '%s\n' "$SVC_TXT" | sed 's/^/    | /'
echo "  $UD/$JOB:"; printf '%s\n' "$TMR_TXT" | sed 's/^/    | /'
B64S="$(printf '%s\n' "$SVC_TXT" | base64 -w0)"; B64T="$(printf '%s\n' "$TMR_TXT" | base64 -w0)"
DRILL_UNITS=1
x "both \"sudo -n install -d -m 755 $FD && echo $B64S | base64 -d | sudo -n tee $UD/$SVC >/dev/null && echo $B64T | base64 -d | sudo -n tee $UD/$JOB >/dev/null && sudo -n systemctl daemon-reload && sudo -n systemctl enable --runtime --now $JOB 2>&1 && systemctl show -p UnitFileState,ActiveState --value $JOB | tr '\n' ' '; echo\""
check "drill job installed + enabled (runtime) on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -c "enabled-runtime active" <<<"$XOUT")" = 2 ]')"
sleep 75
x "both \"systemctl show -p Result,ExecMainStatus --value $SVC | tr '\n' ' '; echo\"; collect_now; jobline"
for hl in sentry validator; do
  check "$hl: drill job present 1, disabled 0, failed 0, runs >= 1" "$(ok_if '[ "$(flag present "$hl")" = 1 ] && [ "$(flag disabled "$hl")" = 0 ] && [ "$(flag failed "$hl")" = 0 ] && [ "$(flag runs_observed_total "$hl")" -ge 1 ]')"
done
t_q="$(date -u +%s)"; while [ $(( $(date -u +%s) - t_q )) -lt "$QUIET_WAIT" ]; do sleep 30; done
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTJob.*\",job=\"$JOB\"}' | jq -r '.data.result | length'"
check "succeeding job: no PFTJob* alert (pending or firing) after $QUIET_WAIT s" "$(ok_if '[ "$XOUT" = 0 ]')"

echo; echo "== 3. FAIL: create $FD/fail on both hosts"
x "both 'sudo -n touch $FD/fail'"
sleep 70; x "collect_now; jobline"
for hl in sentry validator; do check "$hl: drill job failed 1, consecutive >= 1" "$(ok_if '[ "$(flag failed "$hl")" = 1 ] && [ "$(flag consecutive_failures "$hl")" -ge 1 ]')"; done
wait_fire PFTJobFailed failed 1
x "jobline | grep consecutive"
x "both 'sudo -n rm -f $FD/fail'"
sleep 70; x "collect_now; jobline"
for hl in sentry validator; do check "$hl: drill job failed 0, consecutive 0 after a successful run" "$(ok_if '[ "$(flag failed "$hl")" = 0 ] && [ "$(flag consecutive_failures "$hl")" = 0 ]')"; done
wait_resolve PFTJobFailed failed 1

echo; echo "== 4. DISABLE: systemctl disable --runtime --now $JOB on both hosts"
x "both \"sudo -n systemctl disable --runtime --now $JOB 2>&1; systemctl show -p UnitFileState,ActiveState --value $JOB | tr '\n' ' '; echo\""
x "collect_now; jobline"
for hl in sentry validator; do check "$hl: drill job disabled 1, present 1, missed 0" "$(ok_if '[ "$(flag disabled "$hl")" = 1 ] && [ "$(flag present "$hl")" = 1 ] && [ "$(flag missed "$hl")" = 0 ]')"; done
wait_fire PFTJobDisabled "is disabled" 1
x "both \"sudo -n systemctl enable --runtime --now $JOB 2>&1; systemctl show -p UnitFileState,ActiveState --value $JOB | tr '\n' ' '; echo\""
x "collect_now; jobline"
for hl in sentry validator; do check "$hl: drill job disabled 0 after enable" "$(ok_if '[ "$(flag disabled "$hl")" = 0 ]')"; done
wait_resolve PFTJobDisabled "is disabled" 1

echo; echo "== 5. HANG: create $FD/hang on both hosts (the next run never ends; the timer stops re-firing)"
x "both 'sudo -n touch $FD/hang'"
t_h="$(date -u +%s)"; MISS=""
while [ $(( $(date -u +%s) - t_h )) -lt "$FIRE_WAIT" ]; do
  collect_now >/dev/null 2>&1; MISS="$(jobline | grep -E '^missed' )"
  [ "$(grep -c ' 1$' <<<"$MISS")" = 2 ] && break; sleep 30
done
x "jobline; both \"systemctl show -p ActiveState,SubState --value $SVC | tr '\n' ' '; echo\""
for hl in sentry validator; do check "$hl: drill job missed 1, running 1, failed 0" "$(ok_if '[ "$(flag missed "$hl")" = 1 ] && [ "$(flag running "$hl")" = 1 ] && [ "$(flag failed "$hl")" = 0 ]')"; done
echo "  missed after $(( $(date -u +%s) - t_h ))s (threshold: interval 60 + accuracy 1 + 300 s from the last trigger)"
wait_fire PFTJobMissed "is overdue" 1
x "both 'sudo -n rm -f $FD/hang'"
sleep 75; x "collect_now; jobline; both \"systemctl show -p Result --value $SVC\""
for hl in sentry validator; do check "$hl: drill job missed 0, running 0, failed 0 after the run ended" "$(ok_if '[ "$(flag missed "$hl")" = 0 ] && [ "$(flag running "$hl")" = 0 ] && [ "$(flag failed "$hl")" = 0 ]')"; done
wait_resolve PFTJobMissed "is overdue" 1

echo; echo "== 6. REMOVE: disable + delete the drill unit files + daemon-reload on both hosts"
x "both \"sudo -n systemctl disable --runtime --now $JOB >/dev/null 2>&1; sudo -n rm -f $UD/$JOB $UD/$SVC && sudo -n systemctl daemon-reload && systemctl show -p LoadState --value $JOB\""
x "collect_now; jobline"
for hl in sentry validator; do check "$hl: drill job present 0, disabled 1, failed 0 (kept in the state)" "$(ok_if '[ "$(flag present "$hl")" = 0 ] && [ "$(flag disabled "$hl")" = 1 ] && [ "$(flag failed "$hl")" = 0 ]')"; done
wait_fire PFTJobDisabled "is disabled" 2
x "both 'sudo -n pft-jobwatch forget $JOB'"
check "pft-jobwatch forget on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -c "forgot $JOB" <<<"$XOUT")" = 2 ]')"
x "collect_now; jobline | wc -l"
check "the drill job's series are gone from both textfiles" "$(ok_if '[ "$XOUT" = 0 ]')"
wait_resolve PFTJobDisabled "is disabled" 2

echo; echo "== 7. restore, read back"
restore
check "drill units/flags/state gone, bridge back on the operator env, silence expired" "$(ok_if '[ "$RESTORE_OK" = true ]')"
sleep 60
readback() { # TOPIC LABEL [quiet]
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$ALERT" throwaway
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_jobwatch_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_jobwatch_jobs' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.state) \(.value[1])\"' | sort"
check "pft_jobwatch_up 1 for both hosts at the end" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 1$" <<<"$XOUT")" = 2 ]')"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  check "pft-integrity PASS on $(lb "$h") at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  s="$(node_state "$h")"
  check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "alert-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
