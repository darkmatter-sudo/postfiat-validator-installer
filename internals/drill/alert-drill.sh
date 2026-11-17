#!/usr/bin/env bash
# alert-drill: recorded FIRING -> RESOLVED drill of PFTInternalsStale on a THROWAWAY ntfy topic
# (task_e2445890523c6b89875a1d3e63b95e19, step 4). Built from ../../histarchive/drill/alert-run.sh (PASS).
# Fault: the INSTALLED pft-internals collects a drill container name that does not exist (pft-drill-<random>), once
# a minute, into the real textfile dir. That is the collector's own fail-closed path (docker exec fails -> the file
# holds only pft_internals_up 0, the collect timestamp and last success 0), so the real exporter, Prometheus rule,
# Alertmanager and bridge carry the alert. The file stays fresh (matches rulecheck's `pft_internals_*.prom 5m` line),
# no state file is written, and neither node, neither real internals textfile and no timer is touched.
# Fix: the drill textfile is removed -> the series end -> the alert resolves.
#   bash internals/drill/alert-drill.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
# 0  preflight (nothing changed): clean pushed HEAD; relay, AM, Prometheus; both real internals files valid + up 1;
#    internals rules healthy; nothing but the watchdog pending/firing; no silence names PFTInternals*; bridge on the
#    operator env; nodes full; integrity PASS; alertpath OK; redaction control.
# 1  bridge -> throwaway topic (alertpath paused around the re-create); silence everything except the watchdog and
#    PFTInternalsStale.
# 2  BREAK: drill collections every 60 s -> PFTInternalsStale{container=<drill>} firing, [FIRING] on the throwaway.
# 3  FIX: drill textfile removed -> no PFTInternalsStale left, [RESOLVED] on the throwaway.
# 4  restore (drain, bridge back, alertpath, silence expired only when nothing else is active), ALERTS query_range,
#    read back every topic (operator topics must hold 0 messages), real files still valid, integrity PASS, nodes full.
# Env: RELAY NTFY AM PROM BRIDGE_ENV AGENT_ENV SIL_TTL (60 min) FIRE_WAIT (1200 s) RESOLVE_WAIT (600 s)
#      DRAIN_WAIT (600 s) DRAIN_SETTLE (90 s) OTHERS_WAIT (600 s) PREFLIGHT_ONLY=1: step 0 only.
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
AP_WAIT="${AP_WAIT:-180}"; SIL_TTL="${SIL_TTL:-60}"; FIRE_WAIT="${FIRE_WAIT:-1200}"; RESOLVE_WAIT="${RESOLVE_WAIT:-600}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; DRAIN_WAIT="${DRAIN_WAIT:-600}"; OTHERS_WAIT="${OTHERS_WAIT:-600}"
TASK=task_e2445890
SHA_HEAD="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile; SD=/var/lib/pft-internals
AN=PFTInternalsStale

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="indrill-$(rnd)"
DC="pft-drill-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"; DF="$TF/pft_internals_$DC.prom"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d -p "$HOME/.cache")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
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
n_msgs() { # STATUS -> throwaway-topic messages "[STATUS] PFTInternalsStale[ xN]" whose body names the drill container
  topic_msgs "$ALERT" | jq -r --arg t "[$1] $AN" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' \
    | grep -c "pft-internals for $DC is failing or stale"
}
real_files() { # NAME up valid, for both real internals textfiles on the validator (local + pulled sentry copy)
  local n f
  for n in postfiatd postfiatd-sentry; do
    f="$TF/pft_internals_$n.prom"
    echo "$n $(sed -nE "s/^pft_internals_up\{container=\"$n\"\} ([01])$/up=\1/p" "$f") $(pft-internals validate "$f" "$n" >/dev/null && echo valid || echo INVALID)"
  done
}
drill_collect() { sudo -n pft-internals collect --container "$DC" 2>&1; } # exit 1 + "up 0" is the expected result
MODE=none
refresh() { [ "$MODE" = drill ] && drill_collect >/dev/null; }
in_active() { # PFTInternals* pending/firing in Prometheus + active (unsilenced) in Alertmanager
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname=~"PFTInternals.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq '[.[] | select(.labels.alertname | test("^PFTInternals"))] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
others_active() { # anything but the watchdog and PFTInternals* pending/firing in Prometheus or active (incl. silenced) in AM
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname!~"PFTAlertPipelineWatchdog|PFTInternals.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true" | jq '[.[] | select(.labels.alertname | test("^(PFTAlertPipelineWatchdog|PFTInternals.*)$") | not)] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0
ap_pause() { R 'sudo -n systemctl stop pft-alertpath-check.timer' && AP_PAUSED=1
  echo "  sentry pft-alertpath-check.timer stopped: $([ "$AP_PAUSED" = 1 ] && echo yes || echo NO)"; }
ap_resume() { # wait (<= AP_WAIT s) until a read-only check is OK on a snapshot taken AFTER the bridge re-create, then
  # start the timer whatever the result. The sentry judges the validator's pushed snapshots (every 30 s): a check that
  # still reads a pre-restart snapshot says OK, and the timer's next run then reads the one taken while the bridge was
  # down and pages "ntfy bridge not listening" to the operator (alert-drill log 10, 2026-11-17).
  local t0 v st age rc=9; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$AP_WAIT" ]; do
    v="$(R 'sudo -n pft-alertpath check --json' 2>/dev/null)"
    st="$(jq -r '.state // "?"' <<<"$v" 2>/dev/null)"; age="$(jq -r '.snapshot_age // 999999' <<<"$v" 2>/dev/null)"
    if [ "$st" = OK ] && [[ "$age" =~ ^[0-9]+$ ]] && [ "$age" -lt $(( $(date -u +%s) - t0 )) ]; then rc=0; break; fi
    sleep 5
  done
  R 'sudo -n systemctl start pft-alertpath-check.timer' && AP_PAUSED=0
  echo "  sentry pft-alertpath check ${st:-?} on a snapshot ${age:-?}s old, $(( $(date -u +%s) - t0 ))s after the bridge re-create (must be newer): $([ "$rc" = 0 ] && echo yes || echo NO); timer started again: $([ "$AP_PAUSED" = 0 ] && echo yes || echo NO)"
  [ "$rc" = 0 ] && [ "$AP_PAUSED" = 0 ]; }
bridge_src() { sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}'; }
drain() { # every PFTInternals* alert resolved and its RESOLVED delivered to the THROWAWAY bridge before it goes back
  local t0 n=1 settle="${DRAIN_SETTLE:-90}" e body id
  t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do n="$(in_active)"; [ "$n" = 0 ] && break; sleep 10; done
  if [ "$n" = 0 ]; then
    echo "  drain: no PFTInternals* alert pending/firing/active after $(( $(date -u +%s) - t0 ))s; waiting ${settle}s for RESOLVED delivery to the throwaway bridge"
    sleep "$settle"; n="$(in_active)"
  fi
  if [ "$n" = 0 ]; then echo "  drain: done, nothing left that could reach the operator topic: yes"; return 0; fi
  e="$(date -u -d '+60 min' +%FT%TZ)"
  body="$(jq -nc --arg s "$(ts)" --arg e "$e" --arg c "$TASK internals drill $RUN drain timeout" '{matchers: [{name: "alertname", value: "PFTInternals.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "internals-drill", comment: $c}')"
  id="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$body" | jq -r '.silenceID // empty')"
  echo "  drain: NO - $n PFTInternals* alert(s) still active after ${DRAIN_WAIT}s; silenced alertname=~PFTInternals.* until $e (${id:+id set}${id:-silence FAILED})"
  return 1; }
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1; MODE=none
  sudo -n rm -f "$DF"; sudo -n rm -f "$SD/state-$DC.json" "$SD/last-good-$DC.prom"
  if sudo -n test ! -e "$DF"; then echo "  drill textfile removed: yes"; else echo "  drill textfile removed: NO"; RESTORE_OK=false; fi
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    drain || RESTORE_OK=false
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  if [ -n "$SIL" ]; then # expire the catch-all silence once nothing but the watchdog/internals is left (<= OTHERS_WAIT)
    local o t0; t0="$(date -u +%s)"; o="$(others_active)"
    while [ "${o:-1}" != 0 ] && [ $(( $(date -u +%s) - t0 )) -lt "$OTHERS_WAIT" ]; do sleep 20; o="$(others_active)"; done
    if [ "${o:-1}" = 0 ]; then curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired after $(( $(date -u +%s) - t0 ))s (nothing else pending/firing/active): HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
    else echo "  catch-all silence left to run out ($o other alert series pending/firing/active after ${OTHERS_WAIT}s)"; RESTORE_OK=false; fi
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-internals PFTInternalsStale alert drill (throwaway topic) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO)) | drill container name $DC (does not exist)"
  for f in internals/drill/alert-drill.sh internals/pft-internals.sh internals/internals_parse.py alerts/internals.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done
  echo "installed on validator: $(sha256sum /usr/local/bin/pft-internals /usr/local/lib/pft-internals/internals_parse.py 2>&1 | awk '{printf "%s %s  ", substr($1,1,16), $2}')"
  echo "rules file as loaded by Prometheus: $(sudo -n docker exec pft-prometheus sha256sum /etc/pft-alerts/internals.rules.yml 2>&1 | awk '{print substr($1,1,16), $2}') (pft-prometheus mounts this repo's alerts/)"; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n docker inspect "$DC" >/dev/null 2>&1 && { echo "  a container named $DC exists - stopping" >&2; exit 3; }
sudo -n test -e "$DF" && { echo "  drill textfile exists already - stopping" >&2; exit 3; }
x "real_files"
[ "$(grep -cE '^postfiatd(-sentry)? up=1 valid$' <<<"$XOUT")" = 2 ] || { echo "  real internals textfiles not up 1 + valid - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-internals\") | .rules[] | [.name, .health] | @tsv'"
[ "$(grep -cE '^PFTInternals[A-Za-z]+	ok$' <<<"$XOUT")" = 6 ] || { echo "  internals rules not loaded/healthy - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/query --data-urlencode 'query=count(ALERTS{alertname!=\"PFTAlertPipelineWatchdog\"})' | jq -r '.data.result[0].value[1] // 0'"
[ "$XOUT" = 0 ] || { echo "  alerts other than the watchdog pending/firing in Prometheus (investigate first) - stopping" >&2; exit 4; }
x "curl -s '$AM/api/v2/alerts?active=true' | jq -r '[.[] | select(.labels.alertname != \"PFTAlertPipelineWatchdog\")] | length'"
[ "$XOUT" = 0 ] || { echo "  alerts other than the watchdog active in Alertmanager (investigate first) - stopping" >&2; exit 4; }
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
[ "$XOUT" = 0 ] || { echo "  an active silence exists - stopping" >&2; exit 4; }
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
[ "$(bridge_src)" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1' \
  || { echo "  sentry pft-alertpath-check.timer not active or check not OK - stopping" >&2; exit 3; }
echo "  sentry pft-alertpath-check.timer active, check OK"
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

echo; echo "== 1. bridge -> throwaway topic; silence everything except $AN and the watchdog"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-internals alert drill $RUN" --arg k "PFTAlertPipelineWatchdog|$AN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: $k, isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "internals-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|$AN\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
[ "$FAILS" = 0 ] || { echo "  step 1 failed - restoring and stopping"; exit 5; }

echo; echo "== 2. BREAK: the installed collector on a container name that does not exist, every 60 s"
MODE=drill
x "drill_collect; echo collect_exit=\$?; sudo -n cat $DF; sudo -n ls $SD"
check "collector failed closed: exit 1, 'up 0', last success 0, no state file for the drill name" \
  "$(ok_if 'grep -qx "collect_exit=1" <<<"$XOUT" && grep -qx "pft_internals_up{container=\"$DC\"} 0" <<<"$XOUT" && grep -qx "pft_internals_last_success_timestamp_seconds{container=\"$DC\"} 0" <<<"$XOUT" && ! grep -q "state-$DC" <<<"$XOUT"')"
x "real_files"
check "real internals textfiles untouched: both up 1 and valid" "$(ok_if '[ "$(grep -cE "^postfiatd(-sentry)? up=1 valid$" <<<"$XOUT")" = 2 ]')"
t0="$(date -u +%s)"; last="$t0"; F=""
while [ $(( $(date -u +%s) - t0 )) -lt "$FIRE_WAIT" ]; do
  F="$(pq "ALERTS{alertname=\"$AN\",alertstate=\"firing\"}")"; grep -q "container=$DC" <<<"$F" && break
  if [ $(( $(date -u +%s) - last )) -ge 60 ]; then refresh; last="$(date -u +%s)"; fi
  sleep 15
done
echo "  $(ts) ($(( $(date -u +%s) - t0 ))s after the first drill collection): $AN firing in Prometheus:"
printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
check "$AN{container=$DC} firing in Prometheus" "$(ok_if 'grep -q "container=$DC" <<<"$F"')"
check "no real container in a firing $AN" "$(ok_if '! grep -qE "container=postfiatd(-sentry)?(,| )" <<<"$F"')"
w=0; while [ "$(n_msgs FIRING)" -lt 1 ] && [ "$w" -le 300 ]; do sleep 15; w=$((w + 15)); refresh; done
check "[FIRING] $AN for $DC on the throwaway topic" "$(ok_if '[ "$(n_msgs FIRING)" -ge 1 ]')" "after ${w}s"
x "pq 'pft_rulecheck_textfile_stale{file=\"pft_internals_$DC.prom\"}'"
check "rulecheck grades the drill textfile FRESH (0) or has not run yet (no series)" "$(ok_if '! grep -qE " 1$" <<<"$XOUT"')"

echo; echo "== 3. FIX: drill textfile removed (the series end)"
MODE=none
x "sudo -n rm -f $DF; sudo -n test ! -e $DF && echo removed"
t0="$(date -u +%s)"; F="x"
while [ $(( $(date -u +%s) - t0 )) -lt "$RESOLVE_WAIT" ]; do
  F="$(pq "ALERTS{alertname=\"$AN\"}")"; [ -z "$F" ] && [ "$(n_msgs RESOLVED)" -ge 1 ] && break; sleep 15
done
echo "  $(ts) ($(( $(date -u +%s) - t0 ))s after the fix): $AN series left in Prometheus: $(grep -c . <<<"$F")"
check "no $AN left in Prometheus" "$(ok_if '[ -z "$F" ]')"
check "[RESOLVED] $AN for $DC on the throwaway topic" "$(ok_if '[ "$(n_msgs RESOLVED)" -ge 1 ]')"

echo; echo "== 4. restore, ALERTS query_range, read back"
restore
check "drill textfile gone, bridge back on the operator env, alertpath OK, silence expired" "$(ok_if '[ "$RESTORE_OK" = true ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"PFTInternals.*\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) container=\(.metric.container) \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "query_range: $AN{container=$DC} pending then firing during the run" "$(ok_if 'grep -qE "^$AN container=$DC pending " <<<"$XOUT" && grep -qE "^$AN container=$DC firing " <<<"$XOUT"')"
check "query_range: no PFTInternals* alert for a real container during the run" "$(ok_if '! grep -qE " container=postfiatd(-sentry)? " <<<"$XOUT"')"
sleep 90  # >= one more alertpath check run (timer) + ntfy delivery after the restore
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
x "real_files; sudo -n ls $SD; sudo -n pft-internals status --container postfiatd | tail -n 1"
check "real internals textfiles up 1 + valid, no drill state left" "$(ok_if '[ "$(grep -cE "^postfiatd(-sentry)? up=1 valid$" <<<"$XOUT")" = 2 ] && ! grep -q "$DC" <<<"$XOUT"')"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
check "no active Alertmanager silence left" "$(ok_if '[ "$XOUT" = 0 ]')"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  check "pft-integrity PASS on $(lb "$h") at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  s="$(node_state "$h")"
  check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "alert-drill done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
