#!/usr/bin/env bash
# link-drill: recorded two-host fixed-link drill for pft-peerwatch (task_dd37a539fab2aacc4c0703ae0ceaa689, step 4).
# Breaks ONLY the validator<->sentry peer link, without stopping either node, and lets an independent dead-man unit
# restore it. Built from ../../aptrust/drill/live-run.sh (PASS, same notifier handling).
#   break    on the validator, two rules at DOCKER-USER position 2 (right after the pft-egress jump, before the
#            RELATED,ESTABLISHED accept), both tagged with the comment "pft-peerwatch-drill":
#              -s SENTRY/32 -d CONTAINER/32 -p tcp -j REJECT --reject-with tcp-reset   (sentry -> validator container)
#              -s CONTAINER/32 -d SENTRY/32 -p tcp -j REJECT --reject-with tcp-reset   (validator container -> sentry)
#            Only packets between the validator container and the sentry's address match; every other peer, the
#            host's own SSH to the relay (OUTPUT, not FORWARD) and the sentry's other peers are untouched.
#   restore  the transient unit pft-peerwatch-drill-deadman (started BEFORE the rules go in) sleeps DEADMAN_SEC and
#            deletes exactly those two rules. The script never deletes them itself unless the run is aborted
#            (EXIT trap), so the link restoration under test is the automatic one.
# Steps
#   0  preflight (nothing changed): clean pushed HEAD, peerwatch installed + timers on both hosts, fixed_link_up 1
#      both containers, peerwatch rules healthy, no drill rule/unit left over, only known alerts, no silence, bridge
#      on the operator env, sentry alertpath OK, nodes full (StartedAt recorded), integrity PASS, pft-egress check.
#   1  Alertmanager bridge + pft-maint [MAINT] target -> throwaway topics; silence everything except the pipeline
#      watchdog and PFTPeer*; pft-maint window (validator + sentry via the watchdog channel).
#   2  dead-man unit, then the two REJECT rules -> fixed_link_up 0 for container=postfiatd and postfiatd-sentry,
#      both nodes still full with other peers; PFTPeerFixedLinkDown FIRING for both, [FIRING] on the throwaway topic.
#   3  the dead-man fires: rules gone, DOCKER-USER identical to the pre-run snapshot, the link reconnects (same
#      public key on both sides), fixed_link_up 1 both -> PFTPeerFixedLinkDown RESOLVED on the throwaway topic.
#   4  restore (window end, targets back, keyescrow re-run, drain, silence), ALERTS query_range, read back every topic
#      (operator topics must hold 0 messages), integrity PASS, pft-egress check, nodes full with unchanged StartedAt.
#   bash peerwatch/drill/link-drill.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
#   PREFLIGHT_ONLY=1 bash peerwatch/drill/link-drill.sh   (step 0 only; changes nothing)
# Env: KNOWN_PENDING (regex of alert names already pending before the run, accepted and printed) DEADMAN_SEC (600)
#      RECONNECT_WAIT (900 s) RESOLVE_WAIT (600 s) DRAIN_WAIT (600 s) SIL_TTL (90 min) OTHERS_WAIT (300 s)
# shellcheck disable=SC2016,SC2015,SC2034  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
export TZ=UTC
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
NTFY=https://ntfy.sh; AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
LOCAL_ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env /etc/pft-maint/ntfy.env"
REMOTE_ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env /etc/pft-maint/ntfy.env"
BRIDGE_ENV="$HOME/.config/pft-alerts/ntfy.env"; AGENT_ENV=/opt/pft-agent/config.env
KNOWN_PENDING="${KNOWN_PENDING:-}"; PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"
DEADMAN_SEC="${DEADMAN_SEC:-600}"; RECONNECT_WAIT="${RECONNECT_WAIT:-900}"; RESOLVE_WAIT="${RESOLVE_WAIT:-600}"
DRAIN_WAIT="${DRAIN_WAIT:-600}"; SIL_TTL="${SIL_TTL:-90}"; OTHERS_WAIT="${OTHERS_WAIT:-300}"; AP_WAIT=180
TASK=task_dd37a539
SHA="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile
VC=postfiatd; SC=postfiatd-sentry
DM=pft-peerwatch-drill-deadman; TAG=pft-peerwatch-drill
NE=/etc/pft-maint/ntfy.env; NEBK=/etc/pft-maint/ntfy.env.pre-peerwatch-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="pwdrill-$(rnd)"; MT="pwmaint-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d -p "$HOME/.cache")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\ntopic\t%s\nuser\t%s\n' "$ALERT" "$MT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes relay "$@" </dev/null; }
L() { bash -c "$1" </dev/null; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; }
cn() { if [ "$1" = relay ]; then echo "$SC"; else echo "$VC"; fi; }
lb() { if [ "$1" = relay ]; then echo sentry; else echo validator; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
node_state() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
started() { on "$1" "sudo -n docker inspect -f '{{.State.StartedAt}}' $(cn "$1")"; }
pq() { curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
# fixed_link_up of both containers as Prometheus scrapes them (validator textfile + the pulled sentry textfile)
links_prom() { pq 'pft_peerwatch_fixed_link_up' | sed -E 's/__name__=[^,]*,//' | sort; }
link_val() { sudo -n grep -h "^pft_peerwatch_fixed_link_up{" "$TF/pft_peerwatch_$1.prom" 2>/dev/null | awk '{ print $2 }'; }
DU='sudo -n iptables -S DOCKER-USER'
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
n_msgs() { # STATUS CONTAINER -> throwaway [STATUS] PFTPeerFixedLinkDown messages whose body has CONTAINER's summary
  topic_msgs "$ALERT" | jq -r --arg t "[$1] PFTPeerFixedLinkDown" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' | grep -cE "^$2 lost its fixed peer link "
}
others_re() { echo "PFTAlertPipelineWatchdog|PFTPeer.*${KNOWN_PENDING:+|$KNOWN_PENDING}"; }
pw_active() {
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname=~"PFTPeer.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq '[.[] | select(.labels.alertname | test("^PFTPeer"))] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
others_active() {
  local p a re; re="$(others_re)"
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=count(ALERTS{alertname!~\"$re\"})" | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true" | jq --arg re "^($re)\$" '[.[] | select(.labels.alertname | test($re) | not)] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; MAINT=0; NE_SWAPPED=0; HAD_NE=0; BROKEN=0
SIP=""; CIP=""; R1=(); R2=()
rules_present() { local n=0; sudo -n iptables -C DOCKER-USER "${R1[@]}" 2>/dev/null && n=$((n + 1)); sudo -n iptables -C DOCKER-USER "${R2[@]}" 2>/dev/null && n=$((n + 1)); echo "$n"; }
ap_pause() { R 'sudo -n systemctl stop pft-alertpath-check.timer' && AP_PAUSED=1
  echo "  sentry pft-alertpath-check.timer stopped: $([ "$AP_PAUSED" = 1 ] && echo yes || echo NO)"; }
ap_resume() {
  local t0 rc=9; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$AP_WAIT" ]; do
    R 'sudo -n pft-alertpath check >/dev/null 2>&1'; rc=$?; [ "$rc" = 0 ] && break; sleep 10
  done
  R 'sudo -n systemctl start pft-alertpath-check.timer' && AP_PAUSED=0
  echo "  sentry pft-alertpath check rc $rc after $(( $(date -u +%s) - t0 ))s; timer started again: $([ "$AP_PAUSED" = 0 ] && echo yes || echo NO)"
  [ "$rc" = 0 ] && [ "$AP_PAUSED" = 0 ]; }
bridge_src() { sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}'; }
drain() {
  local t0 n=1; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do n="$(pw_active)"; [ "$n" = 0 ] && break; sleep 10; done
  if [ "$n" = 0 ]; then echo "  drain: no PFTPeer* alert pending/firing/active after $(( $(date -u +%s) - t0 ))s; 90 s for RESOLVED delivery"; sleep 90; n="$(pw_active)"; fi
  if [ "$n" = 0 ]; then echo "  drain: done, nothing left that could reach the operator topic: yes"; return 0; fi
  local e body id; e="$(date -u -d '+60 min' +%FT%TZ)"
  body="$(jq -nc --arg s "$(ts)" --arg e "$e" --arg c "$TASK peerwatch drill $RUN drain timeout" '{matchers: [{name: "alertname", value: "PFTPeer.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "peerwatch-drill", comment: $c}')"
  id="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$body" | jq -r '.silenceID // empty')"
  echo "  drain: NO - $n PFTPeer* alert(s) still active; silenced alertname=~PFTPeer.* until $e (${id:+id set}${id:-silence FAILED})"
  return 1; }
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$BROKEN" = 1 ] && [ "$(rules_present)" != 0 ]; then
    echo "  ABORT PATH: drill rules still present at restore - deleting them here (not the automatic restore)"
    while sudo -n iptables -C DOCKER-USER "${R1[@]}" 2>/dev/null; do sudo -n iptables -D DOCKER-USER "${R1[@]}"; done
    while sudo -n iptables -C DOCKER-USER "${R2[@]}" 2>/dev/null; do sudo -n iptables -D DOCKER-USER "${R2[@]}"; done
    RESTORE_OK=false
  fi
  sudo -n systemctl stop "$DM.service" >/dev/null 2>&1; sudo -n systemctl reset-failed "$DM.service" >/dev/null 2>&1
  [ "$BROKEN" = 1 ] && { [ "$($DU)" = "$DU0" ] && echo "  DOCKER-USER identical to the pre-run snapshot: yes" || { echo "  DOCKER-USER identical to the pre-run snapshot: NO"; RESTORE_OK=false; }; }
  if [ "$MAINT" = 1 ]; then echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'; MAINT=0; fi
  if [ "$NE_SWAPPED" = 1 ]; then
    if [ "$HAD_NE" = 1 ]; then sudo -n mv -f "$NEBK" "$NE"; else sudo -n rm -f "$NE"; fi; NE_SWAPPED=0
    local now=absent; sudo -n test -e "$NE" && now="$(sudo -n sha256sum "$NE" | cut -c1-64)"
    [ "$now" = "$NE_SHA0" ] && echo "  pft-maint target back to its pre-run state: yes" || { echo "  pft-maint target restore: NO"; RESTORE_OK=false; }
    sudo -n systemctl start pft-keyescrow.service; echo "  pft-keyescrow re-run (it fingerprints $NE): $(grep -h '^pft_keyescrow_drift_items{node="validator"}' $TF/pft_keyescrow.prom)"
  fi
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    drain || RESTORE_OK=false
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"; BRIDGE_SWAPPED=0
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  if [ -n "$SIL" ]; then
    local o t0; t0="$(date -u +%s)"; o="$(others_active)"
    while [ "${o:-1}" != 0 ] && [ $(( $(date -u +%s) - t0 )) -lt "$OTHERS_WAIT" ]; do sleep 20; o="$(others_active)"; done
    if [ "${o:-1}" = 0 ]; then curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired after $(( $(date -u +%s) - t0 ))s (nothing else pending/firing/active): HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
    else echo "  catch-all silence left to run out ($o other alert series pending/firing/active after ${OTHERS_WAIT}s)"; fi
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-peerwatch two-host fixed-link drill - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in peerwatch/drill/link-drill.sh peerwatch/pft-peerwatch.sh peerwatch/peerwatch_parse.py alerts/peerwatch.rules.yml; do echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
git fetch -q origin; [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping"; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" && curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  AM/Prometheus not reachable - stopping"; exit 3; }
L "command -v pft-peerwatch >/dev/null && command -v pft-maint >/dev/null && systemctl is-active --quiet pft-peerwatch@$VC.timer && systemctl is-active --quiet pft-peerwatch-pull@$SC.timer" \
  || { echo "  validator: pft-peerwatch/pft-maint or its timers missing - stopping"; exit 3; }
R "command -v pft-peerwatch >/dev/null && command -v pft-maint >/dev/null && systemctl is-active --quiet pft-peerwatch@$SC.timer" \
  || { echo "  sentry: pft-peerwatch/pft-maint or its timer missing - stopping"; exit 3; }
echo "  pft-peerwatch installed, collect timers active on both hosts, sentry pull timer active on the validator"
SIP="$(ssh -G relay | awk '$1 == "hostname" { print $2 }')"
CIP="$(sudo -n docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$VC")"
[[ "$SIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && [[ "$CIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "  sentry address or container address not an IPv4 literal - stopping"; exit 3; }
printf 'ip\t%s\n' "$SIP" >> "$LIT"
for ip in "$(R 'echo "${SSH_CLIENT%% *}"')" "$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; do
  [ -z "$ip" ] || printf 'ip\t%s\n' "$ip" >> "$LIT"; done
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
sudo -n sed -n '/^\[ips_fixed\]/,/^$/p' /var/lib/docker/volumes/postfiatd_postfiatd-config/_data/postfiatd.cfg | grep -qF "$SIP 2559" \
  || { echo "  the validator's [ips_fixed] does not name the relay address - stopping"; exit 3; }
echo "  sentry address = the relay address in the validator's [ips_fixed]: yes; validator container address $CIP (private)"
R1=(-s "$SIP/32" -d "$CIP/32" -p tcp -m comment --comment "$TAG" -j REJECT --reject-with tcp-reset)
R2=(-s "$CIP/32" -d "$SIP/32" -p tcp -m comment --comment "$TAG" -j REJECT --reject-with tcp-reset)
DU0="$($DU)"
x "$DU"
check "no drill rule in DOCKER-USER, pft-egress jump at position 1" "$(ok_if '! grep -q "$TAG" <<<"$XOUT" && [ "$(sed -n 2p <<<"$XOUT" | grep -c -- "-j PFT-EGRESS")" = 1 ]')"
x "systemctl list-units --all --no-legend '$DM*' | wc -l"
check "no $DM unit left over" "$(ok_if '[ "$XOUT" = 0 ]')"
x "links_prom"
check "Prometheus: fixed_link_up 1 for container=$VC link=sentry and container=$SC link=validator" "$(ok_if 'grep -q "container=$VC,.*link=sentry 1$" <<<"$XOUT" && grep -q "container=$SC,.*link=validator 1$" <<<"$XOUT"')"
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-peerwatch\") | .rules[] | [.name, .health, .state] | @tsv'"
check "peerwatch rules loaded, healthy, inactive" "$(ok_if '[ "$(grep -cE "^PFTPeer(FixedLinkDown|QualityDegraded|watchStale)	ok	inactive$" <<<"$XOUT")" = 3 ]')"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.labels.host // .labels.container // \"-\") \(.state)\"' | sort"
UNK="$(grep -vE "^(PFTAlertPipelineWatchdog${KNOWN_PENDING:+|$KNOWN_PENDING}) " <<<"$XOUT" | grep -c .)"
[ "$UNK" = 0 ] || { echo "  alerts other than the watchdog${KNOWN_PENDING:+ and KNOWN_PENDING ($KNOWN_PENDING)} pending/firing - stopping"; exit 4; }
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
[ "$XOUT" = 0 ] || { echo "  an active silence exists - stopping"; exit 4; }
[ "$(bridge_src)" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file - stopping"; exit 3; }
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1' || { echo "  sentry alertpath not OK - stopping"; exit 3; }
echo "  bridge mounts the operator env file; sentry alertpath timer active, check OK"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null; sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"; [ -s "$OPS" ] || { echo "  no operator topic found - stopping"; exit 3; }
for h in local relay; do
  s="$(node_state "$h")"; st="$(started "$h")"; echo "  $(cn "$h"): server_state=${s:-down} StartedAt=$st"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping"; exit 4 ;; esac
  if [ "$h" = local ]; then ST_V0="$st"; else ST_S0="$st"; fi
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean - stopping"; exit 4 ;; esac
done
x "sudo -n pft-egress check --container $VC | tail -n 1"
check "pft-egress check PASS before the drill" "$XRC"
for h in local relay; do x "on $h 'sudo -n pft-maint active; echo maint-active rc \$?; sudo -n pft-maint lock list'"
  grep -qx 'maint-active rc 0' <<<"$XOUT" && { echo "  a pft-maint window is already active - stopping"; exit 4; }; done
x "on local 'sudo -n pft-peerwatch status'; on relay 'sudo -n pft-peerwatch status --container $SC'"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "  redaction control FAILED - stopping"; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed ($FAILS check(s) failed)"; [ "$FAILS" = 0 ]; exit; fi
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 1. throwaway targets, catch-all silence, pft-maint window"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-peerwatch fixed-link drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTPeer.*", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "peerwatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTPeer.*\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
NE_SHA0=absent; if sudo -n test -e "$NE"; then HAD_NE=1; NE_SHA0="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
x "{ [ $HAD_NE = 0 ] || sudo -n cp -p $NE $NEBK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$MT\" | sudo -n tee $NE >/dev/null && sudo -n chmod 600 $NE && sudo -n stat -c '%a %U' $NE"
[ "$XRC" = 0 ] && NE_SWAPPED=1; check "pft-maint [MAINT] target -> second throwaway topic (real file present before: $HAD_NE)" "$XRC"
[ "$FAILS" = 0 ] || exit 3
x "sudo -n pft-maint start --ttl 60m --reason '$TASK peerwatch fixed-link drill'"
[ "$XRC" = 0 ] && MAINT=1; check "pft-maint window open on the validator" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. break the validator<->sentry link (dead-man first, then two REJECT rules at DOCKER-USER 2)"
DMCMD="sleep $DEADMAN_SEC; n=0; while iptables -C DOCKER-USER ${R1[*]} 2>/dev/null; do iptables -D DOCKER-USER ${R1[*]} && n=\$((n+1)); done; while iptables -C DOCKER-USER ${R2[*]} 2>/dev/null; do iptables -D DOCKER-USER ${R2[*]} && n=\$((n+1)); done; echo \"pft-peerwatch-drill dead-man: deleted \$n rule(s)\""
DMARGS=(--collect --unit="$DM" --description="pft-peerwatch drill dead-man: deletes the drill REJECT rules" -p RuntimeMaxSec=$(( DEADMAN_SEC + 120 )) /bin/bash -c "$DMCMD")
echo "\$ sudo -n systemd-run ${DMARGS[*]:0:4} /bin/bash -c \"\$DMCMD\"" | red
echo "  DMCMD: $DMCMD" | red
XOUT="$(sudo -n systemd-run "${DMARGS[@]}" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"
t_dm="$(date -u +%s)"
check "dead-man unit $DM.service started (deletes the rules at $(date -u -d "@$(( t_dm + DEADMAN_SEC ))" +%TZ))" "$(ok_if '[ "$XRC" = 0 ] && systemctl is-active --quiet $DM.service')"
[ "$FAILS" = 0 ] || exit 5
BROKEN=1
x "sudo -n iptables -I DOCKER-USER 2 ${R1[*]} && sudo -n iptables -I DOCKER-USER 2 ${R2[*]} && $DU"
t_break="$(date -u +%s)"
check "two drill rules at DOCKER-USER 2-3, after the pft-egress jump and before the established accept" "$(ok_if '[ "$XRC" = 0 ] && sed -n 2p <<<"$XOUT" | grep -q -- "-j PFT-EGRESS" && [ "$(sed -n 3,4p <<<"$XOUT" | grep -c "$TAG")" = 2 ] && sed -n 5p <<<"$XOUT" | grep -q "RELATED,ESTABLISHED -j ACCEPT"')"
w=0; while :; do v="$(link_val "$VC")"; s="$(link_val "$SC")"; [ "$v" = 0 ] && [ "$s" = 0 ] && break; w=$((w + 10)); [ "$w" -le 240 ] || break; sleep 10; done
echo "  $(ts) ($(( $(date -u +%s) - t_break ))s after the break): textfiles fixed_link_up $VC=$v $SC=$s"
check "textfiles: fixed_link_up 0 for $VC (link=sentry) and $SC (link=validator, pulled)" "$(ok_if '[ "$v" = 0 ] && [ "$s" = 0 ]')"
x "on local 'sudo -n pft-peerwatch status'; on relay 'sudo -n pft-peerwatch status --container $SC'"
check "status: only the fixed check fails, the other 7 checks stay PASS on both hosts" "$(ok_if '[ "$(grep -cE "^\s+\[FAIL\] fixed\s+down: (sentry|validator)" <<<"$XOUT")" = 2 ] && [ "$(grep -cE "^\s+\[PASS\] " <<<"$XOUT")" = 14 ]')"
for h in local relay; do s="$(node_state "$h")"; check "$(cn "$h") still full with the link down" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"; done
t0="$(date -u +%s)"; F=""
while [ $(( $(date -u +%s) - t_dm )) -lt "$DEADMAN_SEC" ]; do
  F="$(pq 'ALERTS{alertname="PFTPeerFixedLinkDown",alertstate="firing"}')"
  grep -q "container=$VC," <<<"$F" && grep -q "container=$SC," <<<"$F" && break; sleep 15
done
echo "  $(ts) ($(( $(date -u +%s) - t_break ))s after the break): PFTPeerFixedLinkDown firing in Prometheus:"; printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
for c in "$VC" "$SC"; do check "PFTPeerFixedLinkDown{container=$c} firing before the dead-man fires" "$(ok_if 'grep -q "container=$c," <<<"$F"')"; done
w=0; while :; do [ "$(n_msgs FIRING "$VC")" -ge 1 ] && [ "$(n_msgs FIRING "$SC")" -ge 1 ] && break; w=$((w + 15)); [ "$w" -le 180 ] || break; sleep 15; done
for c in "$VC" "$SC"; do check "[FIRING] PFTPeerFixedLinkDown '$c lost its fixed peer link ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs FIRING "$c")" -ge 1 ]')"; done
x "$DU | grep -c '$TAG'"
check "drill rules still in place (no manual restore before the dead-man)" "$(ok_if '[ "$XOUT" = 2 ]')"

echo; echo "== 3. automatic restore by the dead-man, reconnect, RESOLVED"
w=0; while systemctl is-active --quiet "$DM.service"; do w=$((w + 5)); [ "$w" -le $(( DEADMAN_SEC + 120 )) ] || break; sleep 5; done
t_rest="$(date -u +%s)"
echo "  $(ts): $DM.service finished $(( t_rest - t_dm ))s after it started"
x "sudo -n journalctl --utc -o short-iso -u $DM.service --since @$t_dm --no-pager | grep -E 'dead-man|Started|Finished|Deactivated|Succeeded' "
check "dead-man deleted exactly 2 rules" "$(ok_if 'grep -q "dead-man: deleted 2 rule(s)" <<<"$XOUT"')"
check "DOCKER-USER identical to the pre-run snapshot after the dead-man" "$(ok_if '[ "$($DU)" = "$DU0" ]')"
t0="$(date -u +%s)"; v=""; s=""
while [ $(( $(date -u +%s) - t0 )) -lt "$RECONNECT_WAIT" ]; do v="$(link_val "$VC")"; s="$(link_val "$SC")"; [ "$v" = 1 ] && [ "$s" = 1 ] && break; sleep 10; done
echo "  $(ts) ($(( $(date -u +%s) - t_rest ))s after the dead-man): textfiles fixed_link_up $VC=$v $SC=$s"
check "link reconnected by itself: fixed_link_up 1 on both containers" "$(ok_if '[ "$v" = 1 ] && [ "$s" = 1 ]')"
x "on local 'sudo -n pft-peerwatch status'; on relay 'sudo -n pft-peerwatch status --container $SC'"
check "status: fixed up on both hosts again, RESULT PASS both" "$(ok_if '[ "$(grep -cE "^\s+\[PASS\] fixed\s+up: (sentry|validator)" <<<"$XOUT")" = 2 ] && [ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"
t0="$(date -u +%s)"; F="x"
while [ $(( $(date -u +%s) - t0 )) -lt "$RESOLVE_WAIT" ]; do
  F="$(pq 'ALERTS{alertname="PFTPeerFixedLinkDown"}')"
  [ -z "$F" ] && [ "$(n_msgs RESOLVED "$VC")" -ge 1 ] && [ "$(n_msgs RESOLVED "$SC")" -ge 1 ] && break; sleep 15
done
echo "  $(ts) ($(( $(date -u +%s) - t_rest ))s after the dead-man): PFTPeerFixedLinkDown series left: $(grep -c . <<<"$F")"
check "no PFTPeerFixedLinkDown left in Prometheus" "$(ok_if '[ -z "$F" ]')"
for c in "$VC" "$SC"; do check "[RESOLVED] PFTPeerFixedLinkDown '$c lost its fixed peer link ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs RESOLVED "$c")" -ge 1 ]')"; done

echo; echo "== 4. restore, ALERTS query_range, read back"
restore
check "window ended, targets back, bridge back, alertpath OK, no abort-path rule delete" "$(ok_if '[ "$RESTORE_OK" = true ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"PFTPeer.*\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) container=\(.metric.container) link=\(.metric.link // \"-\") check=\(.metric.check // \"-\") \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
for c in "$VC" "$SC"; do check "query_range: PFTPeerFixedLinkDown{container=$c} firing during the run" "$(ok_if 'grep -qE "^PFTPeerFixedLinkDown container=$c link=[a-z]+ check=- firing " <<<"$XOUT"')"; done
check "query_range: no PFTPeerQualityDegraded / PFTPeerwatchStale during the run" "$(ok_if '! grep -qE "^PFTPeer(QualityDegraded|watchStale)" <<<"$XOUT"')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=pft_peerwatch_fixed_link_up' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=60 | jq -r '.data.result[] | \"\(.metric.container) link=\(.metric.link) \([.values[] | .[1]] | join(\"\"))\"'"
sleep 30
readback() { # TOPIC LABEL [quiet]
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"; echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$ALERT" "throwaway (Alertmanager)"
readback "$MT" "throwaway (pft-maint)"
check "pft-maint [MAINT] start + end reached its throwaway topic" "$(ok_if '[ "$N_MSG" = 2 ]')"
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  check "pft-integrity PASS on $(lb "$h") at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
x "sudo -n pft-egress check --container $VC | tail -n 1"
check "pft-egress check PASS at the end" "$XRC"
for h in local relay; do
  s="$(node_state "$h")"; st="$(started "$h")"; s0="$ST_V0"; [ "$h" = relay ] && s0="$ST_S0"
  check "$(cn "$h") full at the end, container never restarted (StartedAt unchanged)" "$(ok_if '[[ "$s" =~ ^(full|proposing)$ ]] && [ "$st" = "$s0" ]')" "$s, StartedAt $st"
done
x "sudo -n pft-maint status --json | jq -r .window; R 'sudo -n pft-maint status --json' | jq -r .window"
check "no pft-maint window left on either host" "$(ok_if '[ "$(grep -cx none <<<"$XOUT")" = 2 ]')"
x "systemctl list-units --all --no-legend '$DM*' 'run-u*.service' 'run-u*.timer' | wc -l"
check "no dead-man or other transient unit left" "$(ok_if '[ "$XOUT" = 0 ]')"
echo; echo "link-drill done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
