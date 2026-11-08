#!/usr/bin/env bash
# alert-run: recorded two-host alert drill for pft-backupwatch (task_e65845e5a1921cf388ffb4d25035676e, step 4).
# Harmless config-drift and copied-archive-corruption drills: the INSTALLED pft-backupwatch collects from COPIES on
# tmpfs (/dev/shm/pft-bw-drill, 0700 root, removed at the end), never from the real archives, replicas or config:
#   validator  BACKUP_DIR = a copy of the newest pft-backup archive + sidecar with one byte flipped (sidecar, manifest,
#              content FAIL); PFT_BW_ROOT = a copy of every archived host file, one of them with a comment line
#              appended (drift); STATE_DIR = an empty drill dir (no replica record -> offhost FAIL; drift.since);
#              MAX_AGE_H 1 / FAIL_AGE_H 2 (the 4.6 h old archive reads stale) and DRIFT_GRACE_H 0 (overdue at once).
#   sentry     REPLICA_DIR = a copy of the replica dir, newest ciphertext with one byte flipped (verify SHA_MISMATCH).
# Only the metric textfiles are real (the collector writes pft_backupwatch_<host>.prom as its timer does), so the real
# exporter, Prometheus rules, Alertmanager and bridge carry the alerts. pft-backupwatch.timer is stopped on both hosts
# for the run (else its 15-min collect would overwrite the drill textfile) and started again; postfiatd is never
# touched; pft-backup, replicate and pull timers keep running.
#   bash backupwatch/drill/alert-run.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
# 0  preflight (nothing changed): clean pushed HEAD; relay, AM, Prometheus; pft-backupwatch + timers on both hosts;
#    5 rules healthy; no PFTBackup* alert; no drill dir left; both nodes full; integrity PASS; redaction control.
# 1  bridge -> throwaway topic (alertpath paused around the re-create); expire this task's own rollout silences
#    (createdBy backupwatch-install, they cover PFTBackup*); silence everything but PFTAlertPipelineWatchdog|PFTBackup.*
# 2  BREAK: stop pft-backupwatch.timer on both hosts, build the drill copies, collect with the drill conf (re-collect
#    every REFRESH s) -> PFTBackupStale, PFTBackupBroken, PFTBackupConfigDrift, PFTBackupNoOffhostCopy{validator}
#    and PFTBackupNoOffhostCopy{sentry} FIRING, each [FIRING] on the throwaway topic.
# 3  FIX: collect with the real conf on both hosts + pull -> all RESOLVED.
# 4  BLIND: collect on the validator with a drill conf whose MAX_AGE_H is invalid (check produces no result ->
#    up 0) -> PFTBackupwatchStale FIRING; real collect -> RESOLVED.
# 5  restore (timers started, drill dirs removed, real collect + pull, drain, bridge, silence), ALERTS query_range,
#    read back every topic (operator topics must hold 0 messages), integrity PASS, nodes full, real checks OK.
# Env: RELAY (relay) NTFY AM PROM BRIDGE_ENV AGENT_ENV SIL_TTL (150 min) FIRE_WAIT (2400 s) RESOLVE_WAIT (900 s)
#      REFRESH (300 s) DRAIN_WAIT (600 s) DRAIN_SETTLE (90 s) PREFLIGHT_ONLY=1: step 0 only (exit 0 ready).
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
AP_WAIT="${AP_WAIT:-180}"; SIL_TTL="${SIL_TTL:-150}"; FIRE_WAIT="${FIRE_WAIT:-2400}"; RESOLVE_WAIT="${RESOLVE_WAIT:-900}"
REFRESH="${REFRESH:-300}"; PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; DRAIN_WAIT="${DRAIN_WAIT:-600}"
TASK=task_e65845e5
SHA_HEAD="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile
DD=/dev/shm/pft-bw-drill
BW_ALERTS='PFTBackupStale|PFTBackupBroken|PFTBackupConfigDrift|PFTBackupNoOffhostCopy|PFTBackupwatchStale'

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="bwdrill-$(rnd)"
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
  # titles are "[STATUS] NAME" or, when the bridge folds several alerts into one message, "[STATUS] NAME xN"; the
  # summaries start with "<host>: " except PFTBackupwatchStale's ("pft-backupwatch on <host> is stale ...")
  topic_msgs "$ALERT" | jq -r --arg t "[$1] $2" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' \
    | grep -cE "^$3: |^pft-backupwatch on $3 "
}
# drill conf + collect commands (root-owned 0600 conf: the CLI only sources a root-owned PFT_BW_CONF)
V_DRILL_CONF="BACKUP_DIR=$DD/archives
STATE_DIR=$DD/state
MAX_AGE_H=1
FAIL_AGE_H=2
DRIFT_GRACE_H=0
ROLE=archive
HOST_LABEL=validator
OFFHOST=1"
V_BLIND_CONF="BACKUP_DIR=$DD/archives
STATE_DIR=$DD/state
MAX_AGE_H=not-a-number
ROLE=archive
HOST_LABEL=validator"
S_DRILL_CONF="ROLE=replica
HOST_LABEL=sentry
REPLICA_DIR=$DD/replicas"
V_DRILL_COLLECT="sudo -n env PFT_BW_CONF=$DD/drill.env PFT_BW_ROOT=$DD/root pft-backupwatch collect"
V_BLIND_COLLECT="sudo -n env PFT_BW_CONF=$DD/blind.env pft-backupwatch collect"
S_DRILL_COLLECT="sudo -n env PFT_BW_CONF=$DD/drill.env pft-backupwatch collect"
REAL_COLLECT="sudo -n systemctl start pft-backupwatch.service"
PULL="sudo -n systemctl start pft-backupwatch-pull.service"
MODE=none   # what the refresher re-collects: drill | blind | none
refresh() { # re-collect in the current mode so the drill textfiles stay fresh (PFTBackupwatchStale: 45 min)
  case "$MODE" in
    drill) R "$S_DRILL_COLLECT" >/dev/null 2>&1; L "$PULL"; L "$V_DRILL_COLLECT" >/dev/null 2>&1 ;;
    blind) L "$V_BLIND_COLLECT" >/dev/null 2>&1; R "$REAL_COLLECT"; L "$PULL" ;;
  esac
}
bwlines() { # the drill-relevant series of both textfiles on the validator
  sudo -n grep -hE '^pft_backupwatch_(up|check_state|drift_overdue|drift_files|replicas|replica_verify_ok)\{' \
    "$TF/pft_backupwatch_validator.prom" "$TF/pft_backupwatch_sentry.prom" 2>/dev/null | sed -E 's/^pft_backupwatch_//'
}
firing() { pq "ALERTS{alertname=\"$1\",alertstate=\"firing\"}"; }
wait_fire() { # ALERTNAME HOSTS... : Prometheus firing for every host, then >= 1 [FIRING] per host on the topic
  # ok_if evals its condition inside ok_if: the conditions use named locals (bash dynamic scope), not $1..
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
  for hl in "$@"; do check "[FIRING] $an '$hl...' on the throwaway topic" "$(ok_if '[ "$(n_msgs FIRING "$an" "$hl")" -ge 1 ]')"; done
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
  for hl in "$@"; do check "[RESOLVED] $an '$hl...' on the throwaway topic" "$(ok_if '[ "$(n_msgs RESOLVED "$an" "$hl")" -ge 1 ]')"; done
}

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; TIMERS_STOPPED=0
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
bw_active() { # PFTBackup* alerts pending/firing in Prometheus + active (unsilenced) in Alertmanager
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname=~"PFTBackup.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq '[.[] | select(.labels.alertname | test("^PFTBackup"))] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
others_active() { # any alert other than the watchdog and PFTBackup* pending/firing in Prometheus (e.g. jobwatch on
  # the stopped timer): if so the drill silence is left to run out instead of being expired
  curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname!~"PFTAlertPipelineWatchdog|PFTBackup.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null; }
drain() { # let every PFTBackup* alert resolve and its RESOLVED reach the THROWAWAY bridge before the bridge goes back
  local t0 n=1 settle="${DRAIN_SETTLE:-90}"
  t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do
    n="$(bw_active)"; [ "$n" = 0 ] && break; sleep 10
  done
  if [ "$n" = 0 ]; then
    echo "  drain: no PFTBackup* alert pending/firing/active after $(( $(date -u +%s) - t0 ))s; waiting ${settle}s for RESOLVED delivery to the throwaway bridge"
    sleep "$settle"; n="$(bw_active)"
  fi
  if [ "$n" = 0 ]; then echo "  drain: done, nothing left that could reach the operator topic: yes"; return 0; fi
  local e body id
  e="$(date -u -d '+60 min' +%FT%TZ)"
  body="$(jq -nc --arg s "$(ts)" --arg e "$e" --arg c "$TASK backupwatch drill $RUN drain timeout" '{matchers: [{name: "alertname", value: "PFTBackup.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "backupwatch-drill", comment: $c}')"
  id="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$body" | jq -r '.silenceID // empty')"
  echo "  drain: NO - $n PFTBackup* alert(s) still active after ${DRAIN_WAIT}s; silenced alertname=~PFTBackup.* until $e (${id:+id set}${id:-silence FAILED})"
  return 1; }
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1; MODE=none
  if [ "$TIMERS_STOPPED" = 1 ]; then
    R "sudo -n rm -rf $DD; $REAL_COLLECT; sudo -n systemctl start pft-backupwatch.timer; systemctl is-active --quiet pft-backupwatch.timer && test ! -e $DD" \
      && echo "  sentry: drill dir removed, real collect, pft-backupwatch.timer active: yes" || { echo "  sentry restore: NO"; RESTORE_OK=false; }
    L "sudo -n rm -rf $DD; $REAL_COLLECT; $PULL; sudo -n systemctl start pft-backupwatch.timer; systemctl is-active --quiet pft-backupwatch.timer && test ! -e $DD" \
      && echo "  validator: drill dir removed, real collect + pull, pft-backupwatch.timer active: yes" || { echo "  validator restore: NO"; RESTORE_OK=false; }
  fi
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    drain || RESTORE_OK=false
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  if [ -n "$SIL" ]; then
    local o; o="$(others_active)"
    if [ "${o:-1}" = 0 ]; then curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
    else echo "  silence left to run out ($o other alert series pending/firing in Prometheus)"; fi
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-backupwatch two-host alert drill - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in backupwatch/drill/alert-run.sh backupwatch/pft-backupwatch.sh backupwatch/backupwatch_lib.py alerts/backupwatch.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done
  for h in local relay; do
    echo "installed on $(lb "$h"): $(on "$h" 'sha256sum /usr/local/sbin/pft-backupwatch /usr/local/lib/pft-backupwatch/backupwatch_lib.py 2>/dev/null || sha256sum "$(command -v pft-backupwatch)"' | awk '{printf "%s %s  ", substr($1,1,16), $2}')"
  done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
for h in local relay; do
  on "$h" "command -v pft-backupwatch >/dev/null && systemctl is-active --quiet pft-backupwatch.timer && test ! -e $DD" \
    || { echo "  $(lb "$h"): pft-backupwatch/timer missing or $DD left over - stopping" >&2; exit 3; }
done
systemctl is-active --quiet pft-backupwatch-pull.timer || { echo "  pft-backupwatch-pull.timer not active - stopping" >&2; exit 3; }
echo "  pft-backupwatch + timer on both hosts, pull timer active, no drill dir left over"
x "sudo -n pft-backupwatch check --offhost"
[ "$XRC" = 0 ] || { echo "  validator check not OK before the drill - stopping" >&2; exit 4; }
x "R 'sudo -n pft-backupwatch collect --stdout' | grep -E '_(up|replicas|replica_verify_ok)\\{'"
grep -q 'replica_verify_ok{host="sentry"} 1' <<<"$XOUT" || { echo "  sentry replica does not verify before the drill - stopping" >&2; exit 4; }
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1' \
  || { echo "  sentry pft-alertpath-check.timer not active or check not OK - stopping" >&2; exit 3; }
echo "  sentry pft-alertpath-check.timer active, check OK"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_backupwatch_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
[ "$(grep -cE '^(sentry|validator) 1$' <<<"$XOUT")" = 2 ] || { echo "  pft_backupwatch_up is not 1 for both hosts - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTBackup.*\"}' | jq -r '.data.result | length'"
[ "$XOUT" = 0 ] || { echo "  a PFTBackup* alert is already active (investigate it first) - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-backupwatch\") | .rules[] | [.name, .health] | @tsv'"
[ "$(grep -cE "^($BW_ALERTS)	ok$" <<<"$XOUT")" = 5 ] || { echo "  backupwatch rules not loaded/healthy - stopping" >&2; exit 4; }
# active silences naming PFTBackup: only this task's own rollout silences (createdBy backupwatch-install) may be
# expired by step 1; anything else stops the run
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | select(any(.matchers[]; .isEqual and (.value | test(\"PFTBackup\")))) | \"\(.createdBy) until \(.endsAt)\"'"
if grep -qv '^backupwatch-install ' <<<"${XOUT:-backupwatch-install }"; then echo "  a foreign silence covers PFTBackup* - stopping" >&2; exit 4; fi
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

echo; echo "== 1. bridge -> throwaway topic; rollout silences expired; silence everything except PFTBackup* and the watchdog"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-backupwatch alert drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTBackup.*", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "backupwatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTBackup.*\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
n_exp=0
for id in $(curl -s --max-time 10 "$AM/api/v2/silences" | jq -r '.[] | select(.status.state == "active" and .createdBy == "backupwatch-install") | .id'); do
  [ "$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X DELETE "$AM/api/v2/silence/$id")" = 200 ] && n_exp=$((n_exp + 1))
done
echo "  rollout silences (createdBy backupwatch-install) expired: $n_exp"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\") | select(any(.matchers[]; .isEqual and (.value | test(\"PFTBackup\"))))] | length'"
check "no active silence names PFTBackup* any more" "$(ok_if '[ "$XOUT" = 0 ]')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. BREAK: pft-backupwatch.timer stopped on both hosts; drill copies on tmpfs; collect from the copies"
TIMERS_STOPPED=1
x "R 'sudo -n systemctl stop pft-backupwatch.timer; systemctl is-active pft-backupwatch.timer'; sudo -n systemctl stop pft-backupwatch.timer; systemctl is-active pft-backupwatch.timer"
check "pft-backupwatch.timer stopped on both hosts" "$(ok_if '[ "$(grep -c "^inactive$" <<<"$XOUT")" = 2 ]')"
B64V="$(printf '%s\n' "$V_DRILL_CONF" | base64 -w0)"; B64B="$(printf '%s\n' "$V_BLIND_CONF" | base64 -w0)"; B64S="$(printf '%s\n' "$S_DRILL_CONF" | base64 -w0)"
echo "  validator drill conf ($DD/drill.env; + the installed PEER_SSH/REPLICA_RECIPIENT lines, so offhost asks the real peer):"; printf '%s\n' "$V_DRILL_CONF" | sed 's/^/    | /'
echo "  validator blind conf ($DD/blind.env, step 4):"; printf '%s\n' "$V_BLIND_CONF" | sed 's/^/    | /'
echo "  sentry drill conf ($DD/drill.env):"; printf '%s\n' "$S_DRILL_CONF" | sed 's/^/    | /'
FLIP='import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); i = len(b) // 2; b[i] ^= 0xFF; open(p, "wb").write(b); print("flipped byte", i, "of", len(b))'
# validator: archive copy (one byte flipped), host-file copies (one with an appended comment line), drill confs
VSETUP="set -e; sudo -n install -d -m 700 $DD $DD/archives $DD/state $DD/root
N=\$(sudo -n find /var/backups/postfiat -maxdepth 1 -name 'pft-backup-*.tar.gz' -printf '%f\n' | LC_ALL=C sort | tail -n 1)
echo \"newest archive: \$N\"
sudo -n cp -p /var/backups/postfiat/\$N /var/backups/postfiat/\$N.sha256 $DD/archives/
echo \"copy sha256 equals sidecar: \$(sudo -n sha256sum $DD/archives/\$N | cut -c1-64 | grep -qxF \"\$(sudo -n cut -c1-64 $DD/archives/\$N.sha256)\" && echo yes || echo no)\"
P=\$(sudo -n pft-backupwatch check --json | jq -r '.drift[].path' | grep -v '^/etc/postfiatd/')
for p in \$P; do sudo -n cp -p --parents \"\$p\" $DD/root/; done
echo \"host files copied to the drill root: \$(echo \"\$P\" | grep -c .)\"
echo '# pft-backupwatch drill $RUN: harmless appended comment (copy only)' | sudo -n tee -a $DD/root/opt/postfiatd/docker-compose.resources.yml >/dev/null
echo \"drill copy differs from the live file: \$(sudo -n cmp -s $DD/root/opt/postfiatd/docker-compose.resources.yml /opt/postfiatd/docker-compose.resources.yml && echo no || echo yes)\"
echo $B64V | base64 -d | sudo -n tee $DD/drill.env >/dev/null; echo $B64B | base64 -d | sudo -n tee $DD/blind.env >/dev/null
sudo -n grep -E '^(PEER_SSH|PEER_TIMEOUT|REPLICA_RECIPIENT)=' /etc/pft-backupwatch.env | sudo -n tee -a $DD/drill.env >/dev/null
echo \"peer lines copied from the installed conf into drill.env: \$(sudo -n grep -cE '^(PEER_SSH|PEER_TIMEOUT|REPLICA_RECIPIENT)=' $DD/drill.env) (not printed)\"
sudo -n chmod 600 $DD/drill.env $DD/blind.env"
echo "  validator setup script:"; printf '%s\n' "$VSETUP" | red | sed 's/^/    | /'
x "L \"\$VSETUP\""
check "validator drill copies built (archive copy intact, one host-file copy changed)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "equals sidecar: yes" <<<"$XOUT" && grep -q "differs from the live file: yes" <<<"$XOUT"')"
SSETUP="set -e; sudo -n install -d -m 700 $DD; sudo -n cp -a /var/lib/pft-backupwatch/replicas $DD/replicas
N=\$(sudo -n find $DD/replicas -maxdepth 1 -name 'pft-backup-*.age' -printf '%f\n' | LC_ALL=C sort | tail -n 1)
echo \"newest replica copy: \$N\"; sudo -n python3 -c '$FLIP' $DD/replicas/\$N
echo $B64S | base64 -d | sudo -n tee $DD/drill.env >/dev/null; sudo -n chmod 600 $DD/drill.env
sudo -n env PFT_BW_CONF=$DD/drill.env pft-backupwatch serve status | cut -c1-60
sudo -n env PFT_BW_CONF=$DD/drill.env pft-backupwatch serve verify \"\${N%.age}\" || true"
echo "  sentry setup script:"; printf '%s\n' "$SSETUP" | red | sed 's/^/    | /'
x "R \"\$SSETUP\""
check "sentry drill copy built (newest replica copy corrupted, verify SHA_MISMATCH)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "flipped byte" <<<"$XOUT" && grep -q " SHA_MISMATCH" <<<"$XOUT"')"
[ "$FAILS" = 0 ] || exit 5
echo; echo "-- 2a. DRIFT (intact archive copy, changed host-file copy, stale thresholds, no replica record)"
x "sudo -n env PFT_BW_CONF=$DD/drill.env PFT_BW_ROOT=$DD/root pft-backupwatch check --offhost"
check "validator drill check: fresh FAIL, drift WARN (1 changed), offhost FAIL (peer reached, no record), sidecar+manifest OK (exit 2)" "$(ok_if '[ "$XRC" = 2 ] && grep -qE "^ *\[FAIL\] fresh" <<<"$XOUT" && grep -qE "^ *\[WARN\] drift .*docker-compose.resources.yml changed" <<<"$XOUT" && grep -qE "^ *\[FAIL\] offhost" <<<"$XOUT" && ! grep -q PEER_DOWN <<<"$XOUT" && grep -qE "^ *\[OK  \] sidecar" <<<"$XOUT" && grep -qE "^ *\[OK  \] manifest" <<<"$XOUT"')"
MODE=drill; refresh; refresh  # twice: the 2nd collect sees drift.since from the 1st, DRIFT_GRACE_H 0 -> overdue 1
x "bwlines"
check "textfiles: validator fresh 2, drift 1, drift_overdue 1, offhost 2, sidecar 0; sentry replica_verify_ok 0" \
  "$(ok_if 'grep -qE "^check_state\{host=\"validator\",check=\"fresh\"\} 2$" <<<"$XOUT" && grep -qE "^check_state\{host=\"validator\",check=\"drift\"\} 1$" <<<"$XOUT" && grep -qE "^drift_overdue\{host=\"validator\"\} 1$" <<<"$XOUT" && grep -qE "^check_state\{host=\"validator\",check=\"offhost\"\} 2$" <<<"$XOUT" && grep -qE "^check_state\{host=\"validator\",check=\"sidecar\"\} 0$" <<<"$XOUT" && grep -qE "^replica_verify_ok\{host=\"sentry\"\} 0$" <<<"$XOUT"')"
t_break="$(date -u +%s)"; echo "  broken at $(ts); for: windows Drift/Broken 15m, Stale/NoOffhost 30m; re-collecting every ${REFRESH}s"
wait_fire PFTBackupConfigDrift validator
echo; echo "-- 2b. CORRUPT: flip one byte in the archive COPY"
x "sudo -n python3 -c \"\$FLIP\" \"\$(sudo -n find $DD/archives -name 'pft-backup-*.tar.gz' -printf '$DD/archives/%f')\" && sudo -n env PFT_BW_CONF=$DD/drill.env PFT_BW_ROOT=$DD/root pft-backupwatch check --offhost"
check "validator drill check: sidecar FAIL, manifest FAIL, drift FAIL (archive not readable) (exit 2)" "$(ok_if '[ "$XRC" = 2 ] && grep -qE "^ *\[FAIL\] sidecar" <<<"$XOUT" && grep -qE "^ *\[FAIL\] manifest" <<<"$XOUT" && grep -qE "^ *\[FAIL\] drift" <<<"$XOUT"')"
refresh; x "bwlines | grep -E 'check=\"(sidecar|manifest|content)\"|drift_overdue'"
check "textfile: sidecar 2, manifest 2, content 2, drift_overdue still 1" "$(ok_if '[ "$(grep -cE "check=\"(sidecar|manifest|content)\"\} 2$" <<<"$XOUT")" = 3 ] && grep -qE "^drift_overdue\{host=\"validator\"\} 1$" <<<"$XOUT"')"
wait_fire PFTBackupBroken validator
wait_fire PFTBackupStale validator
wait_fire PFTBackupNoOffhostCopy validator sentry
echo "  all four fired $(( $(date -u +%s) - t_break ))s after the break"

echo; echo "== 3. FIX: real collect on both hosts + pull (the real archives, replicas and config were never changed)"
MODE=none
x "R '$REAL_COLLECT'; $REAL_COLLECT; $PULL; bwlines"
check "textfiles back to the real state: validator all check_state 0, drift_overdue 0; sentry replica_verify_ok 1" \
  "$(ok_if '! grep -qE "^check_state\{host=\"validator\".*\} [12]$" <<<"$XOUT" && grep -qE "^drift_overdue\{host=\"validator\"\} 0$" <<<"$XOUT" && grep -qE "^replica_verify_ok\{host=\"sentry\"\} 1$" <<<"$XOUT"')"
wait_resolve PFTBackupBroken validator
wait_resolve PFTBackupConfigDrift validator
wait_resolve PFTBackupStale validator
wait_resolve PFTBackupNoOffhostCopy validator sentry

echo; echo "== 4. BLIND: validator collect with an invalid drill conf (no check result -> up 0)"
x "L \"$V_BLIND_COLLECT\"; echo \"collect exit \$?\"; bwlines | grep '^up'"
check "validator collect exit 1 and up 0 (sentry up 1)" "$(ok_if 'grep -q "collect exit 1" <<<"$XOUT" && grep -qE "^up\{host=\"validator\"\} 0$" <<<"$XOUT" && grep -qE "^up\{host=\"sentry\"\} 1$" <<<"$XOUT"')"
MODE=blind
wait_fire PFTBackupwatchStale validator
MODE=none
x "$REAL_COLLECT; bwlines | grep '^up'"
check "validator up 1 after a real collect" "$(ok_if 'grep -qE "^up\{host=\"validator\"\} 1$" <<<"$XOUT"')"
wait_resolve PFTBackupwatchStale validator

echo; echo "== 5. restore, ALERTS query_range, read back"
restore
check "drill dirs gone, timers active, bridge back on the operator env" "$(ok_if '[ "$RESTORE_OK" = true ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"$BW_ALERTS\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=30 | jq -r '.data.result[] | \"\(.metric.alertname) host=\(.metric.host) check=\(.metric.check // \"-\") \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
for a in PFTBackupStale PFTBackupBroken PFTBackupConfigDrift PFTBackupwatchStale; do
  check "query_range: $a{host=validator} firing during the run" "$(ok_if 'grep -qE "^$a host=validator .* firing " <<<"$XOUT"')"
done
for hl in validator sentry; do check "query_range: PFTBackupNoOffhostCopy{host=$hl} firing during the run" "$(ok_if 'grep -qE "^PFTBackupNoOffhostCopy host=$hl .* firing " <<<"$XOUT"')"; done
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
x "sudo -n pft-backupwatch check --offhost | tail -n 1; R 'sudo -n pft-backupwatch collect --stdout' | grep -E 'replica_verify_ok'"
check "real validator check --offhost OK and sentry replica verifies at the end" "$(ok_if 'grep -q "RESULT" <<<"$XOUT" && grep -qE "replica_verify_ok\{host=\"sentry\"\} 1" <<<"$XOUT"')"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_backupwatch_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "pft_backupwatch_up 1 for both hosts at the end" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 1$" <<<"$XOUT")" = 2 ]')"
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
