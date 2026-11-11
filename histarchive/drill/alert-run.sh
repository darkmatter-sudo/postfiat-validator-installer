#!/usr/bin/env bash
# alert-run: recorded two-host replica, tamper and alert drill for pft-histarchive
# (task_e9cfe999f0e4a09fca9ef3de8dee03ae, step 4). Built from ../../backupwatch/drill/alert-run.sh (PASS).
# The INSTALLED pft-histarchive runs against COPIES on tmpfs (/dev/shm/pft-ha-drill, 0700 root, removed at the end),
# never against the real archive, outbox or replica:
#   validator  STATE_DIR = a copy of the archive (one byte flipped in the newest sealed segment), the outbox and the
#              age identity; status.json in the copy is frozen, so the follower freshness it reports ages.
#   sentry     STATE_DIR = a copy of the replica dir, the newest encrypted segment with one byte flipped.
#   validator drill commands reach the sentry copy through the installed PEER_SSH with
#   PFT_HISTARCHIVE_REMOTE="sudo -n env STATE_DIR=<sentry drill dir> pft-histarchive".
# Only the metric textfiles are real (the drill writes pft_histarchive{,_follow,_replica}.prom as the timer does),
# so the real exporter, Prometheus rules, Alertmanager and bridge carry the alerts. pft-histarchive-periodic.timer is
# stopped for the run (else its 5-min metrics run would overwrite the drill textfile) and started again. The real
# follower keeps archiving the whole time; postfiatd is never touched.
#   bash histarchive/drill/alert-run.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
# 0  preflight (nothing changed): clean pushed HEAD; relay, AM, Prometheus; installed + timer; real verify,
#    verify-replica, sentry replica-check PASS; 3 rules healthy; no PFTHistarchive* alert; no drill dir; nodes full;
#    integrity PASS; only this task's rollout silences cover PFTHistarchive*; redaction control.
# 1  bridge -> throwaway topic (alertpath paused around the re-create); expire this task's rollout silences
#    (createdBy histarchive-install); silence everything but PFTAlertPipelineWatchdog|PFTHistarchive.*
# 2  BREAK: stop the timer, build the copies, then on the copies: TAMPER (verify FAIL names the segment),
#    REPLICA (sentry replica-check FAIL, verify-replica FAIL, restore-verify FAIL), STALE (frozen follower status)
#    -> PFTHistarchiveIntegrity, PFTHistarchiveStale, PFTHistarchiveReplica FIRING, each [FIRING] on the throwaway.
# 3  FIX: real metrics, verify, verify-replica -> all RESOLVED.
# 4  restore (timer started, drill dirs removed, real periodic, drain, bridge, silence), ALERTS query_range, read back
#    every topic (operator topics must hold 0 messages), integrity PASS, nodes full, real checks PASS.
# Env: RELAY (relay) NTFY AM PROM BRIDGE_ENV AGENT_ENV SIL_TTL (120 min) FIRE_WAIT (2700 s) RESOLVE_WAIT (900 s)
#      REFRESH (300 s) DRAIN_WAIT (600 s) DRAIN_SETTLE (90 s) OTHERS_WAIT (600 s) PREFLIGHT_ONLY=1: step 0 only.
# shellcheck disable=SC2016,SC2015,SC2034  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
export TZ=UTC
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
REMOTE_ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
AP_WAIT="${AP_WAIT:-180}"; SIL_TTL="${SIL_TTL:-120}"; FIRE_WAIT="${FIRE_WAIT:-2700}"; RESOLVE_WAIT="${RESOLVE_WAIT:-900}"
REFRESH="${REFRESH:-300}"; PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; DRAIN_WAIT="${DRAIN_WAIT:-600}"; OTHERS_WAIT="${OTHERS_WAIT:-600}"
TASK=task_e9cfe999
SHA_HEAD="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile
DD=/dev/shm/pft-ha-drill
SEG=""   # newest sealed segment name (set in step 2)
HA_ALERTS='PFTHistarchiveStale|PFTHistarchiveIntegrity|PFTHistarchiveReplica'
# drill command on the validator: the installed CLI with STATE_DIR on the copy and the peer side on the sentry copy
VD="sudo -n env STATE_DIR=$DD/state PFT_HISTARCHIVE_REMOTE=sudo\\ -n\\ env\\ STATE_DIR=$DD\\ pft-histarchive pft-histarchive"
SD="sudo -n env STATE_DIR=$DD pft-histarchive"

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="hadrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d -p "$HOME/.cache")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#age1[a-z0-9]{58}#<age-recipient>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes "$RELAY" "$@" </dev/null; }
L() { bash -c "$1" </dev/null; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
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
n_msgs() { # STATUS ALERTNAME HOST -> throwaway-topic message lines of that status/alert naming HOST
  # titles are "[STATUS] NAME" or "[STATUS] NAME xN"; every histarchive summary starts with "<host>: "
  topic_msgs "$ALERT" | jq -r --arg t "[$1] $2" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' \
    | grep -cE "^$3: "
}
MODE=none   # what the refresher re-writes: drill | none
refresh() { # keep the drill textfiles fresh (pft-rulecheck grades pft_histarchive_follow.prom by mtime, 15 min)
  case "$MODE" in
    drill) L "$VD metrics" >/dev/null 2>&1 ;;
  esac
}
halines() { # the drill-relevant series of the three textfiles on the validator
  sudo -n grep -hE '^pft_histarchive_(verify_ok|verify_failures|replica_ok|last_ingest_timestamp_seconds|lag_ledgers|follow_gaps)\{' \
    "$TF/pft_histarchive.prom" "$TF/pft_histarchive_follow.prom" "$TF/pft_histarchive_replica.prom" 2>/dev/null | sed -E 's/^pft_histarchive_//'
}
firing() { pq "ALERTS{alertname=\"$1\",alertstate=\"firing\"}"; }
wait_fire() { # ALERTNAME HOSTS... : Prometheus firing for every host, then >= 1 [FIRING] per host on the topic
  local an="$1" t0 F w ok hl last; shift; t0="$(date -u +%s)"; F=""; last="$t0"
  while [ $(( $(date -u +%s) - t0 )) -lt "$FIRE_WAIT" ]; do
    F="$(firing "$an")"; ok=0; for hl in "$@"; do grep -q "host=$hl" <<<"$F" && ok=$((ok + 1)); done
    [ "$ok" = "$#" ] && break
    if [ $(( $(date -u +%s) - last )) -ge "$REFRESH" ]; then refresh; last="$(date -u +%s)"; fi
    sleep 20
  done
  echo "  $(ts) ($(( $(date -u +%s) - since ))s into the run): $an firing in Prometheus:"; printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
  for hl in "$@"; do check "$an{host=$hl} firing in Prometheus" "$(ok_if 'grep -q "host=$hl" <<<"$F"')"; done
  w=0; while :; do
    ok=0; for hl in "$@"; do [ "$(n_msgs FIRING "$an" "$hl")" -ge 1 ] && ok=$((ok + 1)); done
    [ "$ok" = "$#" ] && break; w=$((w + 15)); [ "$w" -le 300 ] || break; sleep 15
  done
  for hl in "$@"; do check "[FIRING] $an '$hl: ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs FIRING "$an" "$hl")" -ge 1 ]')"; done
}
wait_resolve() { # ALERTNAME HOSTS...
  local an="$1" t0 F ok hl; shift; t0="$(date -u +%s)"; F="x"
  while [ $(( $(date -u +%s) - t0 )) -lt "$RESOLVE_WAIT" ]; do
    F="$(pq "ALERTS{alertname=\"$an\"}")"
    ok=0; for hl in "$@"; do [ "$(n_msgs RESOLVED "$an" "$hl")" -ge 1 ] && ok=$((ok + 1)); done
    [ -z "$F" ] && [ "$ok" = "$#" ] && break; sleep 20
  done
  echo "  $(ts) ($(( $(date -u +%s) - t0 ))s after the fix): $an series left in Prometheus: $(grep -c . <<<"$F")"
  check "no $an left in Prometheus" "$(ok_if '[ -z "$F" ]')"
  for hl in "$@"; do check "[RESOLVED] $an '$hl: ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs RESOLVED "$an" "$hl")" -ge 1 ]')"; done
}

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; TIMER_STOPPED=0
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
ha_active() { # PFTHistarchive* alerts pending/firing in Prometheus + active (unsilenced) in Alertmanager
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname=~"PFTHistarchive.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq '[.[] | select(.labels.alertname | test("^PFTHistarchive"))] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
others_active() { # any alert other than the watchdog and PFTHistarchive* pending/firing in Prometheus or active in AM
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname!~"PFTAlertPipelineWatchdog|PFTHistarchive.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true" | jq '[.[] | select(.labels.alertname | test("^(PFTAlertPipelineWatchdog|PFTHistarchive.*)$") | not)] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
drain() { # let every PFTHistarchive* alert resolve and its RESOLVED reach the THROWAWAY bridge before the bridge goes back
  local t0 n=1 settle="${DRAIN_SETTLE:-90}"
  t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do
    n="$(ha_active)"; [ "$n" = 0 ] && break; sleep 10
  done
  if [ "$n" = 0 ]; then
    echo "  drain: no PFTHistarchive* alert pending/firing/active after $(( $(date -u +%s) - t0 ))s; waiting ${settle}s for RESOLVED delivery to the throwaway bridge"
    sleep "$settle"; n="$(ha_active)"
  fi
  if [ "$n" = 0 ]; then echo "  drain: done, nothing left that could reach the operator topic: yes"; return 0; fi
  local e body id
  e="$(date -u -d '+60 min' +%FT%TZ)"
  body="$(jq -nc --arg s "$(ts)" --arg e "$e" --arg c "$TASK histarchive drill $RUN drain timeout" '{matchers: [{name: "alertname", value: "PFTHistarchive.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "histarchive-drill", comment: $c}')"
  id="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$body" | jq -r '.silenceID // empty')"
  echo "  drain: NO - $n PFTHistarchive* alert(s) still active after ${DRAIN_WAIT}s; silenced alertname=~PFTHistarchive.* until $e (${id:+id set}${id:-silence FAILED})"
  return 1; }
real_fix() { # real metrics, verify, verify-replica (writes the three real textfiles from the real state)
  L "sudo -n pft-histarchive metrics >/dev/null 2>&1; sudo -n pft-histarchive verify >/dev/null 2>&1; sudo -n pft-histarchive verify-replica >/dev/null 2>&1"; }
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1; MODE=none
  if [ "$TIMER_STOPPED" = 1 ]; then
    R "sudo -n rm -rf $DD; test ! -e $DD" && echo "  sentry: drill dir removed: yes" || { echo "  sentry restore: NO"; RESTORE_OK=false; }
    real_fix
    L "sudo -n rm -rf $DD; sudo -n systemctl start pft-histarchive-periodic.service; sudo -n systemctl start pft-histarchive-periodic.timer; systemctl is-active --quiet pft-histarchive-periodic.timer && test ! -e $DD" \
      && echo "  validator: drill dir removed, real metrics + verify + verify-replica + periodic, timer active: yes" || { echo "  validator restore: NO"; RESTORE_OK=false; }
  fi
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    drain || RESTORE_OK=false
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  if [ -n "$SIL" ]; then # expire the catch-all silence once nothing but the watchdog/histarchive is left (<= OTHERS_WAIT)
    local o t0; t0="$(date -u +%s)"; o="$(others_active)"
    while [ "${o:-1}" != 0 ] && [ $(( $(date -u +%s) - t0 )) -lt "$OTHERS_WAIT" ]; do sleep 20; o="$(others_active)"; done
    if [ "${o:-1}" = 0 ]; then curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired after $(( $(date -u +%s) - t0 ))s (nothing else pending/firing/active): HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
    else echo "  catch-all silence left to run out ($o other alert series pending/firing/active after ${OTHERS_WAIT}s)"; fi
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-histarchive two-host replica/tamper/alert drill - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in histarchive/drill/alert-run.sh histarchive/pft-histarchive.sh histarchive/histarchive.py alerts/histarchive.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done
  for h in local relay; do
    echo "installed on $(lb "$h"): $(on "$h" 'sha256sum /usr/local/bin/pft-histarchive /usr/local/lib/pft-histarchive/histarchive.py' | awk '{printf "%s %s  ", substr($1,1,16), $2}')"
  done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
L "command -v pft-histarchive >/dev/null && systemctl is-active --quiet pft-histarchive.service && systemctl is-active --quiet pft-histarchive-periodic.timer && test ! -e $DD" \
  || { echo "  validator: pft-histarchive/follower/timer missing or $DD left over - stopping" >&2; exit 3; }
R "command -v pft-histarchive >/dev/null && test ! -e $DD" || { echo "  sentry: pft-histarchive missing or $DD left over - stopping" >&2; exit 3; }
echo "  pft-histarchive installed on both hosts, follower + timer active on the validator, no drill dir left over"
x "sudo -n pft-histarchive verify | tail -n 1"
[ "$XRC" = 0 ] || { echo "  real verify not PASS before the drill - stopping" >&2; exit 4; }
x "sudo -n pft-histarchive verify-replica | tail -n 1"
[ "$XRC" = 0 ] || { echo "  real verify-replica not PASS before the drill - stopping" >&2; exit 4; }
x "R 'sudo -n pft-histarchive replica-check'"
[ "$XRC" = 0 ] || { echo "  sentry replica-check not PASS before the drill - stopping" >&2; exit 4; }
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1' \
  || { echo "  sentry pft-alertpath-check.timer not active or check not OK - stopping" >&2; exit 3; }
echo "  sentry pft-alertpath-check.timer active, check OK"
x "halines"
[ "$(grep -cE '^(verify_ok|replica_ok)\{host="validator"\} 1$' <<<"$XOUT")" = 2 ] || { echo "  real textfiles not OK - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTHistarchive.*\"}' | jq -r '.data.result | length'"
[ "$XOUT" = 0 ] || { echo "  a PFTHistarchive* alert is already active (investigate it first) - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-histarchive\") | .rules[] | [.name, .health] | @tsv'"
[ "$(grep -cE "^($HA_ALERTS)	ok$" <<<"$XOUT")" = 3 ] || { echo "  histarchive rules not loaded/healthy - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/query --data-urlencode 'query=count(ALERTS{alertname!=\"PFTAlertPipelineWatchdog\"})' | jq -r '.data.result[0].value[1] // 0'"
[ "$XOUT" = 0 ] || { echo "  other alerts pending/firing in Prometheus (investigate first) - stopping" >&2; exit 4; }
# active silences naming PFTHistarchive: only this task's own rollout silence (createdBy histarchive-install) may be
# expired by step 1; anything else stops the run
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | select(any(.matchers[]; .isEqual and (.value | test(\"PFTHistarchive\")))) | \"\(.createdBy) until \(.endsAt)\"'"
if grep -qv '^histarchive-install ' <<<"${XOUT:-histarchive-install }"; then echo "  a foreign silence covers PFTHistarchive* - stopping" >&2; exit 4; fi
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

echo; echo "== 1. bridge -> throwaway topic; rollout silences expired; silence everything except PFTHistarchive* and the watchdog"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-histarchive alert drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTHistarchive.*", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "histarchive-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTHistarchive.*\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
n_exp=0
for id in $(curl -s --max-time 10 "$AM/api/v2/silences" | jq -r '.[] | select(.status.state == "active" and .createdBy == "histarchive-install") | .id'); do
  [ "$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X DELETE "$AM/api/v2/silence/$id")" = 200 ] && n_exp=$((n_exp + 1))
done
echo "  rollout silences (createdBy histarchive-install) expired: $n_exp"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\") | select(any(.matchers[]; .isEqual and (.value | test(\"PFTHistarchive\"))))] | length'"
check "no active silence names PFTHistarchive* any more" "$(ok_if '[ "$XOUT" = 0 ]')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. BREAK: pft-histarchive-periodic.timer stopped; drill copies on tmpfs; the installed CLI on the copies"
TIMER_STOPPED=1
x "sudo -n systemctl stop pft-histarchive-periodic.timer; systemctl is-active pft-histarchive-periodic.timer; systemctl is-active pft-histarchive.service"
check "periodic timer stopped (the real follower keeps running)" "$(ok_if 'grep -qx inactive <<<"$XOUT" && grep -qx active <<<"$XOUT"')"
FLIP='import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); i = len(b) // 2; b[i] ^= 0xFF; open(p, "wb").write(b); print("flipped byte", i, "of", len(b), "in", p.rsplit("/", 1)[-1])'
VSETUP="set -e; sudo -n install -d -m 700 $DD $DD/state
sudo -n cp -a /var/lib/pft-histarchive/archive /var/lib/pft-histarchive/outbox $DD/state/
sudo -n cp -p /var/lib/pft-histarchive/age.key /var/lib/pft-histarchive/age.pub $DD/state/
echo \"copied: archive (\$(sudo -n find $DD/state/archive -type f | wc -l) files), outbox (\$(sudo -n find $DD/state/outbox -type f | wc -l) files), age identity (0600, never printed)\"
echo \"newest sealed segment: \$(sudo -n find $DD/state/archive/segments -name '*.jsonl.gz' -printf '%f\n' | LC_ALL=C sort | tail -n 1)\"
$VD verify | tail -n 1"
echo "  validator setup script:"; printf '%s\n' "$VSETUP" | red | sed 's/^/    | /'
x "L \"\$VSETUP\""
SEG="$(sed -nE 's/^ *newest sealed segment: //p' <<<"$XOUT")"
check "validator drill copy built and verifies before the tamper (newest sealed segment ${SEG:-none})" "$(ok_if '[ "$XRC" = 0 ] && [ -n "$SEG" ] && grep -q "RESULT: PASS" <<<"$XOUT"')"
SSETUP="set -e; sudo -n install -d -m 700 $DD; sudo -n cp -a /var/lib/pft-histarchive/replica $DD/replica
echo \"replica copy: \$(sudo -n find $DD/replica -type f | wc -l) files\"
$SD replica-check | tail -n 1"
echo "  sentry setup script:"; printf '%s\n' "$SSETUP" | red | sed 's/^/    | /'
x "R \"\$SSETUP\""
check "sentry drill copy built and passes replica-check before the tamper" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^RESULT: PASS" <<<"$XOUT"')"
x "$VD verify-replica | tail -n 1"
check "validator drill verify-replica against the sentry drill copy PASS before the tamper (path works)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "RESULT: PASS" <<<"$XOUT"')"
[ "$FAILS" = 0 ] || exit 5
t_break="$(date -u +%s)"
MODE=drill; refresh
x "halines"
echo "  frozen follower status in the copy from $(ts) on; for: windows Integrity 0m, Stale 15 min + 10m, Replica 30m"

echo; echo "-- 2a. TAMPER: flip one byte in the COPY of the newest sealed segment, verify"
x "sudo -n python3 -c \"\$FLIP\" $DD/state/archive/segments/$SEG"
x "$VD verify"
check "drill verify FAIL (exit 1), the FAIL line names segments/$SEG" "$(ok_if '[ "$XRC" = 1 ] && grep -qE "^FAIL segment segments/$SEG: " <<<"$XOUT" && grep -q "^RESULT: FAIL" <<<"$XOUT"')"
x "halines | grep -E '^verify_'"
check "textfile: verify_ok 0, verify_failures >= 1" "$(ok_if 'grep -qE "^verify_ok\{host=\"validator\"\} 0$" <<<"$XOUT" && grep -qE "^verify_failures\{host=\"validator\"\} [1-9]" <<<"$XOUT"')"
wait_fire PFTHistarchiveIntegrity validator

echo; echo "-- 2b. REPLICA TAMPER: flip one byte in the sentry COPY of the newest encrypted segment"
x "R \"sudo -n python3 -c '\$FLIP' $DD/replica/$SEG.age\""
x "R '$SD replica-check'"
check "sentry drill replica-check FAIL (exit 1): $SEG.age sha256 differs from REPLICA.json" "$(ok_if '[ "$XRC" = 1 ] && grep -qE "^FAIL $SEG\.age: sha256 differs from REPLICA.json" <<<"$XOUT"')"
x "$VD verify-replica"
check "validator drill verify-replica FAIL (exit 1): peer copy differs + peer check failed" "$(ok_if '[ "$XRC" = 1 ] && grep -qE "^FAIL $SEG\.age: peer sha256 differs from the local encrypted copy" <<<"$XOUT" && grep -q "^FAIL peer replica-check rc 1" <<<"$XOUT"')"
x "$VD restore-verify"
check "validator drill restore-verify FAIL (exit 1): fetched $SEG.age refused before decryption" "$(ok_if '[ "$XRC" = 1 ] && grep -qE "FAIL $SEG\.age: fetched copy sha256 differs from REPLICA.json" <<<"$XOUT" && grep -q "RESULT: FAIL - restore-verify" <<<"$XOUT"')"
x "sudo -n find $DD/state -maxdepth 1 -name 'restore.*' | wc -l"
check "no restore scratch left in the drill state dir" "$(ok_if '[ "$XOUT" = 0 ]')"
x "halines | grep -E '^replica_ok'"
check "textfile: replica_ok 0" "$(ok_if 'grep -qE "^replica_ok\{host=\"validator\"\} 0$" <<<"$XOUT"')"

echo; echo "-- 2c. STALE: the drill metrics keep reporting the frozen follower status of the copy"
wait_fire PFTHistarchiveStale validator
wait_fire PFTHistarchiveReplica validator
echo "  all three fired $(( $(date -u +%s) - t_break ))s after the break"

echo; echo "== 3. FIX: real metrics, verify, verify-replica (the real archive, outbox and replica were never changed)"
MODE=none
x "sudo -n pft-histarchive metrics; sudo -n pft-histarchive verify | tail -n 1; sudo -n pft-histarchive verify-replica | tail -n 1; halines"
check "real textfiles: verify_ok 1, replica_ok 1, fresh ingest" "$(ok_if 'grep -qE "^verify_ok\{host=\"validator\"\} 1$" <<<"$XOUT" && grep -qE "^replica_ok\{host=\"validator\"\} 1$" <<<"$XOUT" && [ $(( $(date -u +%s) - $(sed -nE "s/^last_ingest_timestamp_seconds\{host=\"validator\"\} ([0-9]+).*/\1/p" <<<"$XOUT") )) -lt 120 ]')"
wait_resolve PFTHistarchiveIntegrity validator
wait_resolve PFTHistarchiveStale validator
wait_resolve PFTHistarchiveReplica validator

echo; echo "== 4. restore, ALERTS query_range, read back"
restore
check "drill dirs gone, timer active, bridge back on the operator env" "$(ok_if '[ "$RESTORE_OK" = true ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"$HA_ALERTS\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=30 | jq -r '.data.result[] | \"\(.metric.alertname) host=\(.metric.host) \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
for a in PFTHistarchiveIntegrity PFTHistarchiveStale PFTHistarchiveReplica; do
  check "query_range: $a{host=validator} firing during the run" "$(ok_if 'grep -qE "^$a host=validator firing " <<<"$XOUT"')"
done
sleep 30
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
x "sudo -n pft-histarchive verify | tail -n 1; sudo -n pft-histarchive verify-replica | tail -n 1; R 'sudo -n pft-histarchive replica-check'"
check "real verify, verify-replica and sentry replica-check PASS at the end" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 3 ]')"
x "sudo -n pft-histarchive status | jq -c '.status | {last, lag, gaps}'"
check "real follower: gaps 0, lag < 30" "$(ok_if '[ "$(jq .gaps <<<"$XOUT")" = 0 ] && [ "$(jq .lag <<<"$XOUT")" -lt 30 ]')"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  check "pft-integrity PASS on $(lb "$h") at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  s="$(node_state "$h")"
  check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
x "ls -d $DD 2>&1; R 'ls -d $DD 2>&1'"
check "no drill dir left on either host" "$(ok_if '[ "$(grep -c "No such file" <<<"$XOUT")" = 2 ]')"
echo; echo "alert-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
