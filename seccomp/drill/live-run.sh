#!/usr/bin/env bash
# live-run: recorded two-host live proof of pft-seccomp, sentry first (canary), then the validator. Built from
# ../../apparmor/drill/live-run.sh (redirect / silence / window / read-back / PREFLIGHT_ONLY) and the bridge swap +
# FIRING/RESOLVED read-back of ../../statewatch and ../../rulecheck drills. One stage per run:
#   bash seccomp/drill/live-run.sh sentry 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
#   bash seccomp/drill/live-run.sh validator 2>&1 | tee LOG   (only after the sentry stage passed: preflight checks it)
# sentry stage: install on both hosts (+ the validator's pull), host-run.sh sentry pre --drill (injected gate failure
#   -> automatic rollback, apply, positive + negative controls), alert drill, host-run.sh sentry post --drill (ack,
#   add-ons, enforced restart, explicit rollback + re-apply), RESOLVED, HOLD min hold.
# validator stage: host-run.sh validator pre, alert drill (host=validator), host-run.sh validator post, HOLD min hold
#   with both nodes enforced.
# 0  preflight (nothing changed yet): clean pushed HEAD; relay, Alertmanager, Prometheus reachable; no pft-maint window;
#    no data-collection lock on the stage host; run-commit lines present; notifier env files present, no leftovers;
#    bridge on the operator env; both nodes full; pft-integrity PASS on both; redaction control.
# 1  redirect notifiers + the Alertmanager bridge to a throwaway topic; silence alertname=~".+" except
#    PFTAlertPipelineWatchdog (dead-man switch) and PFTSeccompDenied (under test); pft-maint window (sentry gets it).
# 1b reset: an apply left in place on the stage host by an earlier run is rolled back first.
# 2  (sentry stage) install on both hosts + pull; Prometheus loads the pft-seccomp group.
# 3  host-run.sh STAGE pre.  4 alert drill: the stage host's audit exports the unacknowledged negative-control
#    denials -> PFTSeccompDenied{host=STAGE} firing -> [FIRING] on the throwaway topic.
# 5  host-run.sh STAGE post (acknowledges them).  6 audit again -> alert leaves Prometheus -> [RESOLVED].
# 7  hold HOLD min: both nodes polled every POLL min (state, peers, stored profile, unacknowledged denials).
# 8  metrics + baselines (integrity, fleet, rulecheck).  9 restore + read-back of every operator topic.
# Env: RELAY (relay) NTFY (https://ntfy.sh) AM PROM LOCAL_ENVS REMOTE_ENVS BRIDGE_ENV TTL (4h) SIL_TTL (230 min)
#      HOLD (60) POLL (5) FIRE_WAIT (420 s) NTFY_WAIT (300 s)
#      PREFLIGHT_ONLY=1: step 0 only, nothing changed; exit 0 = ready, 4 = not ready.
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
STAGE="${1:-}"; case "$STAGE" in sentry|validator) ;; *) echo "usage: live-run.sh sentry|validator" >&2; exit 3 ;; esac
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_ENV=/etc/pft-maint/ntfy.env
TTL="${TTL:-4h}"; SIL_TTL="${SIL_TTL:-230}"; HOLD="${HOLD:-60}"; POLL="${POLL:-5}"
FIRE_WAIT="${FIRE_WAIT:-420}"; NTFY_WAIT="${NTFY_WAIT:-300}"; PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; NOT_READY=0
TASK=task_d4a0a82d
SUF=.pre-seccomp-live
SHA_HEAD="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
RDIR="/var/tmp/pft-seccomp-live-$SHORT"   # sentry copy of the tree (run with bash, never executed from a noexec mount)
PROFILE_REPO=seccomp/profile/pft-postfiatd.json
P1=/var/lib/pft-seccomp/pft-postfiatd.live.json   # the profile both hosts apply (copied from the pinned tree)
[ "$STAGE" = sentry ] && SH=relay || SH=local
DRILLF=""; [ "$STAGE" = sentry ] && DRILLF=--drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="sclive-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"; LAST_START="$since"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
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
node_peers() { info "$1" | jq -r '.result.info.peers // 0' 2>/dev/null; }
node_key() { info "$1" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null; }
started() { LAST_START="$(date -u +%s)"; } # every node (re)start pushes the silence end out
pq() { curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; MAINT_STARTED=0; MAINT_ENV_MADE=0; SIL=""; BRIDGE_SWAPPED=0
bridge_src() { sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}'; }
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha left nb SIL2
  if [ "$MAINT_STARTED" = 1 ]; then echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'; fi
  if [ "$MAINT_ENV_MADE" = 1 ]; then
    sudo -n rm -f "$MAINT_ENV" && echo "  removed $MAINT_ENV (absent before the run)" || { echo "  remove $MAINT_ENV FAILED"; RESTORE_OK=false; }
  fi
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-run copy: yes"
    else echo "  restored $k: sha256 matches pre-run copy: NO"; RESTORE_OK=false; fi
  done
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ -n "$SIL" ]; then
    left=$(( LAST_START + 25 * 60 - $(date -u +%s) ))
    if [ "$left" -gt 0 ]; then
      # keep only what the restarts still need (PFTContainerRestarted looks back 15 min), never the catch-all
      nb="$(jq -nc --arg s "$(ts)" --arg e "$(date -u -d "@$(( LAST_START + 25 * 60 ))" +%FT%TZ)" --arg c "$TASK post-run: PFTContainerRestarted only" \
        '{matchers: [{name: "alertname", value: "PFTContainerRestarted", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "seccomp-live", comment: $c}')"
      SIL2="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$nb" | jq -r '.silenceID // empty')"
      if [ -n "$SIL2" ]; then
        echo "  narrow silence alertname=PFTContainerRestarted until last node start $(date -u -d "@$LAST_START" +%TZ) + 25 min (${left}s); expires by itself"
        curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
      else echo "  narrow silence FAILED: catch-all kept until its end time"; RESTORE_OK=false; fi
    else curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"; fi
  fi
  [ "$STAGE" = sentry ] && { R "rm -rf $RDIR" || true; }
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-seccomp live run, stage $STAGE - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in seccomp/drill/live-run.sh seccomp/drill/host-run.sh seccomp/pft-seccomp.sh seccomp/pft_seccomp.py seccomp/install.sh \
           "$PROFILE_REPO" alerts/seccomp.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
nl="$(on "$SH" "sudo -n pft-maint status --json" 2>/dev/null | jq -r '.locks | length' 2>/dev/null)"
if [ "${nl:-1}" != 0 ]; then
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  $STAGE: ${nl:-?} pft-maint data-collection lock(s) held - apply would refuse; a real run would stop here"; NOT_READY=1
  else echo "  $STAGE: ${nl:-?} pft-maint data-collection lock(s) held - stopping" >&2; exit 4; fi
fi
# The rule line and the manifest lines ship in the run commit (lesson: a loaded rule with no series pages PFTRuleDead).
for need in "alerts/prometheus.yml:/etc/pft-alerts/seccomp.rules.yml" "fleet/manifest.tsv:seccomp/pft-seccomp.sh"; do
  grep -qF "${need#*:}" "${need%%:*}" && continue
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  ${need%%:*} has no ${need#*:} line - a real run would stop here (add it in the run commit)"; NOT_READY=1
  else echo "  ${need%%:*} has no ${need#*:} line - stopping (add it in the run commit)" >&2; exit 3; fi
done
for h in local relay; do
  n="$(on "$h" "sudo -n docker ps --format '{{.Names}} {{.Image}}'" | awk -v c="$(cn "$h")" '$2 ~ /postfiatd/ && $1 != c' | wc -l)"
  [ "$n" = 0 ] || { echo "  $h: $n running postfiatd-image container(s) besides $(cn "$h") (learn throwaway?) - stopping" >&2; exit 3; }
done
echo "  no extra postfiatd-image container running on either host"
x "python3 -I seccomp/pft_seccomp.py canon $PROFILE_REPO; sha256sum < $PROFILE_REPO | cut -c1-64"
if [ "$STAGE" = validator ]; then
  x "R 'sudo -n pft-seccomp audit; echo audit-exit=\$?'"
  if ! { grep -qx "audit-exit=0" <<<"$XOUT" && grep -q "\[PASS\] container " <<<"$XOUT"; }; then
    if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  sentry not enforced + clean yet (sentry stage first) - a real run would stop here"; NOT_READY=1
    else echo "  sentry not enforced + clean yet - run the sentry stage first; stopping" >&2; exit 4; fi
  fi
  x "command -v pft-seccomp && systemctl is-active pft-seccomp.timer pft-seccomp-pull.timer"
  [ "$XRC" = 0 ] || { echo "  pft-seccomp not installed on the validator (the sentry stage installs it) - stopping" >&2; exit 3; }
fi
sudo -n test -e "$MAINT_ENV" && { echo "  $MAINT_ENV exists (this runner expects it absent) - stopping" >&2; exit 3; }
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
[ "$(bridge_src)" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
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
  k="$(node_key "$h")"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  s="$(node_state "$h")"; echo "  $(cn "$h"): server_state=${s:-down}, peers $(node_peers "$h")"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then
  echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed (ready: $([ "$NOT_READY" = 0 ] && echo yes || echo "no, see the would-stop lines above"))"
  exit $(( NOT_READY ? 4 : 0 ))
fi
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }

echo; echo "== 1. redirect notifiers + bridge, silence everything except the rule under test, maintenance window"
redirect() { # HOST PATH
  local h="$1" f="$2"
  SHA["$h:$f"]="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
  [[ "${SHA[$h:$f]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $h:$f unreadable - stopping"; exit 3; }
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $h:$f sha256 ${SHA[$h:$f]:0:12} -> $NTFY/<redacted> (throwaway), original kept as $f$SUF"
}
for f in $LOCAL_ENVS; do redirect local "$f"; done
for f in $REMOTE_ENVS; do redirect relay "$f"; done
sudo -n sh -c "umask 077; printf 'NTFY_SERVER=%s\nNTFY_TOPIC=%s\n' $NTFY $ALERT > $MAINT_ENV" && MAINT_ENV_MADE=1
check "$MAINT_ENV created with the throwaway topic (0600)" "$(ok_if '[ "$MAINT_ENV_MADE" = 1 ] && [ "$(sudo -n stat -c %a "$MAINT_ENV")" = 600 ]')"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
[ "$FAILS" = 0 ] || exit 3
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-seccomp live run $RUN stage $STAGE (planned re-creates/restarts)" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTSeccompDenied", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "seccomp-live", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTSeccompDenied\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
x "sudo -n pft-maint start --ttl $TTL --reason '$TASK pft-seccomp live run $RUN stage $STAGE'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 1b. reset: an apply an earlier run left in place on the $STAGE is rolled back first"
sf="/var/lib/pft-seccomp/apply-$(cn "$SH").json"
if on "$SH" "command -v pft-seccomp >/dev/null && sudo -n test -f $sf" && [ "$(on "$SH" "sudo -n jq -r '.rolled_back // false' $sf")" = false ]; then
  x "on $SH 'sudo -n pft-seccomp rollback --yes'"; started
  check "$STAGE: rollback of the earlier apply -> PASS" "$(ok_if '[ "$XRC" = 0 ]')"
else echo "  $STAGE: no apply in place (nothing to reset)"; fi
[ "$FAILS" = 0 ] || { echo "  reset failed - stopping"; exit 4; }

if [ "$STAGE" = sentry ]; then
  echo; echo "== 2. install (sentry, validator, the validator's pull of the sentry file)"
  x "git archive $SHA_HEAD seccomp | R 'rm -rf $RDIR && mkdir -m 700 $RDIR && tar -x -C $RDIR'"
  x "R 'sudo -n bash $RDIR/seccomp/install.sh --host sentry'"
  check "sentry install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_seccomp_findings{host=\"sentry\"}" <<<"$XOUT"')"
  x "sudo -n bash seccomp/install.sh"
  check "validator install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_seccomp_findings{host=\"validator\"}" <<<"$XOUT"')"
  x "sudo -n grep -q '^PULL_SSH=' /etc/pft-seccomp.env || sudo -n sh -c 'grep \"^PULL_SSH=\" /etc/pft-apparmor.env >> /etc/pft-seccomp.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-seccomp.env; sudo -n stat -c '%a %U' /etc/pft-seccomp.env"
  x "sudo -n bash seccomp/install.sh --pull"
  check "pull install exit 0, sentry file present on the validator" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_seccomp_findings{host=\"sentry\"}" <<<"$XOUT"')"
  x "sudo -n grep -n pft_seccomp /etc/pft-rulecheck.conf; R 'sudo -n grep -n pft_seccomp /etc/pft-rulecheck.conf'"
  x "grep -n seccomp.rules.yml alerts/prometheus.yml; sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-seccomp\") | .rules[] | [.name, .health] | @tsv'"
  check "PFTSeccompDrift + PFTSeccompDenied loaded, health ok" "$(ok_if 'grep -qE "^PFTSeccompDrift	ok" <<<"$XOUT" && grep -qE "^PFTSeccompDenied	ok" <<<"$XOUT"')"
  [ "$FAILS" = 0 ] || { echo "  install failed - stopping before any node change"; exit 4; }
fi

echo; echo "== 3. $STAGE: profile copy, host-run pre"
x "sudo -n install -d -m 700 /var/lib/pft-seccomp && git show $SHA_HEAD:$PROFILE_REPO | sudo -n sh -c 'umask 022; cat > $P1' && git show $SHA_HEAD:$PROFILE_REPO | R 'sudo -n install -d -m 700 /var/lib/pft-seccomp && sudo -n sh -c \"umask 022; cat > $P1\"' && sudo -n cat $P1 | sha256sum | cut -c1-64; R 'sudo -n cat $P1 | sha256sum | cut -c1-64'; sha256sum < $PROFILE_REPO | cut -c1-64"
check "profile copied from the pinned tree, sha256 identical on both hosts and in the repo" \
  "$(ok_if '[ "$XRC" = 0 ] && [ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && [ "$(wc -l <<<"$XOUT")" = 3 ]')"
[ "$FAILS" = 0 ] || { echo "  profile copy failed - stopping before any node change"; exit 4; }
if [ "$STAGE" = sentry ]; then HR="R 'sudo -n bash $RDIR/seccomp/drill/host-run.sh sentry"; else HR="L 'sudo -n bash seccomp/drill/host-run.sh validator"; fi
started
x "$HR pre --profile $P1 $DRILLF'"
started
check "$STAGE host-run pre RESULT: PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^RESULT: PASS" <<<"$XOUT"')" "$(grep -c '^PASS ' <<<"$XOUT") PASS, $(grep -c '^FAIL ' <<<"$XOUT") FAIL"
[ "$XRC" = 0 ] || { echo "  $STAGE pre did not pass - stopping (the EXIT trap restores notifiers; the host-run/apply rollbacks own the node)"; exit 1; }

echo; echo "== 4. alert drill: the negative-control denials (not yet acknowledged) -> PFTSeccompDenied{host=$STAGE}"
t_det="$(date -u +%s)"
x "on $SH 'sudo -n systemctl start pft-seccomp.service; systemctl show -p Result --value pft-seccomp.service; sudo -n grep -E \"^pft_seccomp_denied_events\" /var/lib/pft-exporter/textfile/pft_seccomp_$STAGE.prom'"
[ "$STAGE" = sentry ] && x "sudo -n systemctl start pft-seccomp-pull.service; systemctl show -p Result --value pft-seccomp-pull.service; grep -h '^pft_seccomp_denied_events' /var/lib/pft-exporter/textfile/pft_seccomp_sentry.prom"
check "textfile on the validator: pft_seccomp_denied_events{host=\"$STAGE\"} > 0" "$(ok_if 'grep -qE "^pft_seccomp_denied_events\{host=\"$STAGE\"\} [1-9]" <<<"$XOUT"')"
echo "  waiting for PFTSeccompDenied{host=$STAGE} firing in Prometheus (no for:, max ${FIRE_WAIT}s, poll 15s)"
F=""
while [ $(( $(date -u +%s) - t_det )) -lt "$FIRE_WAIT" ]; do
  F="$(pq "ALERTS{alertname=\"PFTSeccompDenied\",alertstate=\"firing\",host=\"$STAGE\"}")"; [ -n "$F" ] && break; sleep 15
done
echo "  $(ts) ($(( $(date -u +%s) - t_det ))s):"; printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
check "PFTSeccompDenied{host=$STAGE} firing" "$(ok_if '[ -n "$F" ]')"
w=0
while :; do
  nf="$(topic_msgs "$ALERT" | jq -r 'select(.title == "[FIRING] PFTSeccompDenied") | .message' | grep -c "on $STAGE")"
  [ "$nf" -ge 1 ] && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "[FIRING] PFTSeccompDenied naming $STAGE delivered to the throwaway topic" "$(ok_if '[ "$nf" -ge 1 ]')" "$nf"

echo; echo "== 5. $STAGE: host-run post"
x "$HR post --profile $P1 $DRILLF'"
started
check "$STAGE host-run post RESULT: PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^RESULT: PASS" <<<"$XOUT"')" "$(grep -c '^PASS ' <<<"$XOUT") PASS, $(grep -c '^FAIL ' <<<"$XOUT") FAIL"

echo; echo "== 6. alert drill: resolve (the acknowledged denials leave the audit)"
t_rec="$(date -u +%s)"
x "on $SH 'sudo -n systemctl start pft-seccomp.service; systemctl show -p Result --value pft-seccomp.service; sudo -n grep -E \"^pft_seccomp_(denied_events|findings)\" /var/lib/pft-exporter/textfile/pft_seccomp_$STAGE.prom'"
[ "$STAGE" = sentry ] && x "sudo -n systemctl start pft-seccomp-pull.service; grep -hE '^pft_seccomp_(denied_events|findings)' /var/lib/pft-exporter/textfile/pft_seccomp_sentry.prom"
check "textfile: findings 0 and denied_events 0 for $STAGE" \
  "$(ok_if 'grep -qE "^pft_seccomp_denied_events\{host=\"$STAGE\"\} 0$" <<<"$XOUT" && grep -qE "^pft_seccomp_findings\{host=\"$STAGE\"\} 0$" <<<"$XOUT"')"
w=0
while :; do
  F="$(pq "ALERTS{alertname=\"PFTSeccompDenied\",host=\"$STAGE\"}")"
  nr="$(topic_msgs "$ALERT" | jq -r 'select(.title == "[RESOLVED] PFTSeccompDenied") | .message' | grep -c "on $STAGE")"
  { [ -z "$F" ] && [ "$nr" -ge 1 ]; } && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "PFTSeccompDenied{host=$STAGE} gone from Prometheus" "$(ok_if '[ -z "$F" ]')"
check "[RESOLVED] PFTSeccompDenied naming $STAGE delivered to the throwaway topic" "$(ok_if '[ "$nr" -ge 1 ]')" "$nr, $(( $(date -u +%s) - t_rec ))s"

echo; echo "== 7. hold: $HOLD min under enforcement, both nodes polled every $POLL min"
echo "  columns: time | per host: state peers stored-profile unacknowledged-denials(24h)"
t_hold="$(date -u +%s)"; HBAD=0; NPOLL=0
while :; do
  line="$(ts)"
  for h in local relay; do
    s="$(node_state "$h")"; p="$(node_peers "$h")"
    a="$(on "$h" "sudo -n pft-seccomp audit --json" 2>/dev/null)"
    cs="$(jq -r '.checks[] | select(.check == "container") | .status' <<<"$a" 2>/dev/null)"; d="$(jq -r '.denied_events // "?"' <<<"$a" 2>/dev/null)"
    line+=" | $(lb "$h") $s $p container=${cs:-n/a} denied=${d:-?}"
    [ "$s" = full ] && [ "${p:-0}" -ge 5 ] 2>/dev/null || HBAD=$((HBAD + 1))
    { [ "$h" = "$SH" ] || [ "$STAGE" = validator ]; } && { [ "$cs" = PASS ] && [ "$d" = 0 ] || HBAD=$((HBAD + 1)); }
  done
  echo "  $line"; NPOLL=$((NPOLL + 1))
  [ $(( $(date -u +%s) - t_hold )) -ge $(( HOLD * 60 )) ] && break
  sleep $(( POLL * 60 ))
done
check "hold ${HOLD} min: every poll full, peers >= 5, enforced host(s) container PASS + 0 denials" "$(ok_if '[ "$HBAD" = 0 ]')" "$NPOLL polls, $HBAD bad"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=min_over_time(pft_statewatch_up[${HOLD}m])' | jq -r '.data.result[] | \"\(.metric.container) \(.value[1])\"'"

echo; echo "== 8. metrics + baselines"
x "on relay 'sudo -n systemctl start pft-seccomp.service' && sudo -n systemctl start pft-seccomp.service pft-seccomp-pull.service; grep -hE '^pft_seccomp_(findings|denied_events)' /var/lib/pft-exporter/textfile/pft_seccomp_*.prom"
x "sleep 45; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_seccomp_findings' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
if [ "$STAGE" = validator ]; then check "Prometheus: pft_seccomp_findings 0 for sentry and validator" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 0$" <<<"$XOUT")" = 2 ]')"
else check "Prometheus: pft_seccomp_findings 0 for sentry" "$(ok_if 'grep -qE "^sentry 0$" <<<"$XOUT"')"; fi
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTSeccomp.*\"}' | jq -r '.data.result | length'"
check "no PFTSeccomp* alert pending or firing" "$(ok_if '[ "$XOUT" = 0 ]')"
x "sudo -n pft-integrity verify | grep -E '^(  \[(WARN|FAIL)\]|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "sudo -n pft-integrity accept --reason '$TASK: pft-seccomp $SHORT stage $STAGE (script, lib, units, env, rulecheck.conf, profile, compose override)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(  \[(WARN|FAIL)\]|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "R \"sudo -n pft-integrity accept --reason '$TASK: pft-seccomp $SHORT stage $STAGE (script, lib, units, env, rulecheck.conf, profile, container)'\" | tail -2"
if [ "$STAGE" = sentry ]; then
  x "sudo -n pft-fleet sync --addon fleet --to $SHA_HEAD --apply --reason '$TASK seccomp manifest lines'"
  check "fleet sync of the manifest exit 0" "$XRC"
fi
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, seccomp CURRENT on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -cE "^ *(validator|sentry) +seccomp +CURRENT" <<<"$XOUT")" = 2 ]')"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "sentry pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after accept" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"

echo; echo "== 9. restore, read back"
restore
check "env files byte-identical, bridge back on the operator env, pft-maint env removed, window ended" \
  "$(ok_if '[ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && ! sudo -n test -e "$MAINT_ENV"')"
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
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  s="$(node_state "$h")"
  check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "live-run $STAGE done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
