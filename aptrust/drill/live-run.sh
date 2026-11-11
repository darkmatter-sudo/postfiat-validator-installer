#!/usr/bin/env bash
# live-run: recorded two-host apply / auto-rollback / rollback and throwaway-topic alert drill for pft-aptrust
# (task_2fac2360358f1030e25578f48129f812, step 4). Built from ../../histarchive/drill/alert-run.sh (PASS) and
# ./install-run.sh (PASS). The weaknesses are SEEDED by this script and removed by it; nothing the hosts trusted before
# the run is weakened beyond them:
#   both hosts  /etc/apt/apt.conf.d/99pft-aptrust-drill, a comment-only file (no APT option), root:root mode 0660:
#               a perm FAIL (group-writable APT path). Group root has no members on either host (preflight checks it),
#               so nobody but root could write it during the run.
#   validator   the GitHub CLI source loses its signed-by and its vendor keyring is copied into trusted.gpg.d: a
#               third-party source trusting every global key (WARN src + WARN global), the setup `apply` migrates.
# Steps
#   0  preflight (nothing changed): clean pushed HEAD, installed + timers, audit 0 WARN/0 FAIL both, no aptrust alert,
#      no apply on record, group root empty, nodes full, integrity PASS, apt-get update OK, operator topics, redaction.
#   0b refusals outside a window (both hosts): apply --yes (no window) and apply (no --yes) exit 4, /etc/apt unchanged.
#   1  Alertmanager bridge + pft-maint [MAINT] target -> throwaway topics; silence everything except the pipeline
#      watchdog and PFTAptrust*; pft-maint window (validator + sentry via the watchdog channel); pft-fleet sync of
#      aptrust at HEAD (pft-fleet accepts the new files in pft-integrity on both hosts = the intended rebaseline).
#   2  SEED; audit both; textfile + pull -> PFTAptrustUntrusted FIRING for host=validator and host=sentry, [FIRING]
#      on the throwaway topic.
#   3  apply --dry-run plan; VERIFY_INJECT auto-rollback (exit 1, /etc/apt byte+mode identical to the seeded state).
#   4  apply --yes (post gate apt-get update OK) -> FIXED: audit 0 WARN/0 FAIL; textfile + pull -> RESOLVED.
#   5  rollback --yes -> /etc/apt byte+mode identical to the seeded state again (audit FAILs again, no textfile).
#   6  unseed -> /etc/apt byte+mode identical to the pre-run snapshot; audit 0/0 both; textfile + pull.
#   7  restore (window end, targets back, keyescrow re-run, drain, silence), ALERTS query_range, read back every topic
#      (operator topics must hold 0 messages), integrity PASS, nodes full.
#   bash aptrust/drill/live-run.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
#   PREFLIGHT_ONLY=1 bash aptrust/drill/live-run.sh   (steps 0 + 0b only; changes nothing)
# Env: KNOWN_PENDING (regex of alert names already pending before the run, accepted and printed) FIRE_WAIT (1200 s)
#      RESOLVE_WAIT (900 s) DRAIN_WAIT (600 s) SIL_TTL (120 min) OTHERS_WAIT (300 s)
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
FIRE_WAIT="${FIRE_WAIT:-1200}"; RESOLVE_WAIT="${RESOLVE_WAIT:-900}"; DRAIN_WAIT="${DRAIN_WAIT:-600}"
SIL_TTL="${SIL_TTL:-120}"; OTHERS_WAIT="${OTHERS_WAIT:-300}"; AP_WAIT=180
TASK=task_2fac2360
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
TF=/var/lib/pft-exporter/textfile
SEED=/etc/apt/apt.conf.d/99pft-aptrust-drill
GHL=/etc/apt/sources.list.d/github-cli.list; GHK=/etc/apt/keyrings/githubcli-archive-keyring.gpg
DKEY=/etc/apt/trusted.gpg.d/pft-aptrust-drill-githubcli.gpg; NKR=/etc/apt/keyrings/pft-aptrust-cli.github.com.gpg
DD=/var/lib/pft-aptrust-drill   # validator: the original github-cli.list (root 0700), removed at the end
NE=/etc/pft-maint/ntfy.env; NEBK=/etc/pft-maint/ntfy.env.pre-aptrust-live

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="atdrill-$(rnd)"; MT="atmaint-$(rnd)"
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
cn() { if [ "$1" = relay ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
lb() { if [ "$1" = relay ]; then echo sentry; else echo validator; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
node_state() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
pq() { curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
# /etc/apt snapshot: every path with mode, owner, size, then sha256 of every file (sorted)
SNAP='sudo -n find /etc/apt -printf "%P %m %u:%g %s\n" | LC_ALL=C sort; sudo -n find /etc/apt -type f -exec sha256sum {} + | LC_ALL=C sort -k2'
snap() { on "$1" "$SNAP"; }
summ() { grep '^RESULT:' <<<"$1"; }   # audit RESULT line
nwf() { sed -nE 's/^RESULT: .* ([0-9]+) warn, ([0-9]+) fail .*/\1 \2/p' <<<"$1"; }  # "WARN FAIL" counts
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
n_msgs() { # STATUS ALERTNAME HOST -> throwaway messages of that status/alert naming HOST (summary "<host>: ...")
  topic_msgs "$ALERT" | jq -r --arg t "[$1] $2" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' | grep -cE "^$3: "
}
firing() { pq "ALERTS{alertname=\"$1\",alertstate=\"firing\"}"; }
wait_fire() { # ALERTNAME HOSTS...
  local an="$1" t0 F w ok hl; shift; t0="$(date -u +%s)"; F=""
  while [ $(( $(date -u +%s) - t0 )) -lt "$FIRE_WAIT" ]; do
    F="$(firing "$an")"; ok=0; for hl in "$@"; do grep -q "host=$hl" <<<"$F" && ok=$((ok + 1)); done
    [ "$ok" = "$#" ] && break; sleep 20
  done
  echo "  $(ts) ($(( $(date -u +%s) - t0 ))s after the textfiles): $an firing in Prometheus:"; printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
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
textfiles() { # audit --textfile on both hosts (sentry first), then the validator's pull; print the checks series
  R 'sudo -n pft-aptrust audit --textfile >/dev/null 2>&1'; L 'sudo -n pft-aptrust audit --textfile >/dev/null 2>&1'
  x "sudo -n pft-aptrust pull; grep -h '^pft_aptrust_checks{' $TF/pft_aptrust_validator.prom $TF/pft_aptrust_sentry.prom"
}

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; MAINT=0; NE_SWAPPED=0; HAD_NE=0; SEEDED=0
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
at_active() {
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname=~"PFTAptrust.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq '[.[] | select(.labels.alertname | test("^PFTAptrust"))] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
OTHER_RE="PFTAlertPipelineWatchdog|PFTAptrust.*${KNOWN_PENDING:+|$KNOWN_PENDING}"
others_active() {
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=count(ALERTS{alertname!~\"$OTHER_RE\"})" | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true" | jq --arg re "^($OTHER_RE)\$" '[.[] | select(.labels.alertname | test($re) | not)] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
drain() {
  local t0 n=1; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do n="$(at_active)"; [ "$n" = 0 ] && break; sleep 10; done
  if [ "$n" = 0 ]; then echo "  drain: no PFTAptrust* alert pending/firing/active after $(( $(date -u +%s) - t0 ))s; 90 s for RESOLVED delivery"; sleep 90; n="$(at_active)"; fi
  if [ "$n" = 0 ]; then echo "  drain: done, nothing left that could reach the operator topic: yes"; return 0; fi
  local e body id; e="$(date -u -d '+60 min' +%FT%TZ)"
  body="$(jq -nc --arg s "$(ts)" --arg e "$e" --arg c "$TASK aptrust drill $RUN drain timeout" '{matchers: [{name: "alertname", value: "PFTAptrust.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "aptrust-drill", comment: $c}')"
  id="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$body" | jq -r '.silenceID // empty')"
  echo "  drain: NO - $n PFTAptrust* alert(s) still active; silenced alertname=~PFTAptrust.* until $e (${id:+id set}${id:-silence FAILED})"
  return 1; }
unseed() { # remove what step 2 seeded (idempotent)
  R "sudo -n rm -f $SEED"
  L "sudo -n rm -f $SEED $DKEY; if sudo -n test -f $DD/github-cli.list; then sudo -n cp -p $DD/github-cli.list $GHL; fi; sudo -n rm -rf $DD"
}
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$SEEDED" = 1 ]; then
    for h in local relay; do on "$h" "sudo -n test -f /var/lib/pft-aptrust/apply.json" && { echo "  $(lb "$h"): an apply is still on record: rollback"; on "$h" "sudo -n pft-aptrust rollback --yes" 2>&1 | red | sed 's/^/    /'; }; done
    unseed; SEEDED=0
    [ "$(snap local)" = "$SNAP_V0" ] && [ "$(snap relay)" = "$SNAP_S0" ] && echo "  /etc/apt identical to the pre-run snapshot on both hosts: yes" || { echo "  /etc/apt identical to the pre-run snapshot: NO"; RESTORE_OK=false; }
    textfiles >/dev/null
  fi
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

{ echo "pft-aptrust two-host apply/rollback + alert drill - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in aptrust/drill/live-run.sh aptrust/pft-aptrust.sh alerts/aptrust.rules.yml; do echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
git fetch -q origin; [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping"; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" && curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  AM/Prometheus not reachable - stopping"; exit 3; }
for h in local relay; do
  on "$h" "command -v pft-aptrust >/dev/null && command -v pft-maint >/dev/null && systemctl is-active --quiet pft-aptrust.timer && sudo -n test ! -e /var/lib/pft-aptrust/apply.json && sudo -n test ! -e $SEED && sudo -n test ! -e $DKEY && sudo -n test ! -e $DD" \
    || { echo "  $(lb "$h"): pft-aptrust/pft-maint/timer missing, an apply on record or a drill file left over - stopping"; exit 3; }
  [ "$(on "$h" "getent group root | cut -d: -f4"; on "$h" "awk -F: '\$4 == 0 && \$1 != \"root\"' /etc/passwd")" = "" ] \
    || { echo "  $(lb "$h"): group root has members (the seeded 0660 file would be writable by them) - stopping"; exit 3; }
done
echo "  installed on both hosts, timer active, no apply on record, no drill file, group root empty on both"
L "test -f $GHL && test -f $GHK && grep -q 'signed-by=$GHK' $GHL" || { echo "  validator GitHub CLI source/keyring not as expected - stopping"; exit 3; }
for h in local relay; do
  x "on $h 'sudo -n pft-aptrust audit' | tail -n 1"
  [ "$XRC" = 0 ] && [ "$(nwf "$XOUT")" = "0 0" ] || { echo "  $(lb "$h") audit not 0 WARN / 0 FAIL before the drill - stopping"; exit 4; }
  x "on $h 'sudo -n apt-get update -q >/dev/null 2>&1; echo apt-get update rc \$?'"
  grep -qx 'apt-get update rc 0' <<<"$XOUT" || { echo "  apt-get update not OK on $(lb "$h") - stopping"; exit 4; }
done
SNAP_V0="$(snap local)"; SNAP_S0="$(snap relay)"
echo "  /etc/apt snapshots: validator $(grep -c . <<<"$SNAP_V0") lines sha $(sha256sum <<<"$SNAP_V0" | cut -c1-16), sentry $(grep -c . <<<"$SNAP_S0") lines sha $(sha256sum <<<"$SNAP_S0" | cut -c1-16)"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.labels.host // \"-\") \(.state)\"' | sort"
UNK="$(grep -vE "^(PFTAlertPipelineWatchdog${KNOWN_PENDING:+|$KNOWN_PENDING}) " <<<"$XOUT" | grep -c .)"
[ "$UNK" = 0 ] || { echo "  alerts other than the watchdog${KNOWN_PENDING:+ and KNOWN_PENDING ($KNOWN_PENDING)} pending/firing - stopping"; exit 4; }
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
[ "$XOUT" = 0 ] || { echo "  an active silence exists - stopping"; exit 4; }
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-aptrust\") | .rules[] | [.name, .health] | @tsv'"
[ "$(grep -cE '^PFTAptrust(Untrusted|Stale)	ok$' <<<"$XOUT")" = 2 ] || { echo "  aptrust rules not loaded/healthy - stopping"; exit 4; }
[ "$(bridge_src)" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file - stopping"; exit 3; }
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1' || { echo "  sentry alertpath not OK - stopping"; exit 3; }
echo "  bridge mounts the operator env file; sentry alertpath timer active, check OK"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null; sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"; [ -s "$OPS" ] || { echo "  no operator topic found - stopping"; exit 3; }
for ip in "$(R 'echo "${SSH_CLIENT%% *}"')" "$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')" "$(ssh -G relay | awk '$1 == "hostname" { print $2 }')"; do
  [ -z "$ip" ] || printf 'ip\t%s\n' "$ip" >> "$LIT"; done
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
for h in relay local; do s="$(node_state "$h")"; echo "  $(cn "$h"): server_state=${s:-down}"; case "$s" in full|proposing) ;; *) echo "  node not full - stopping"; exit 4 ;; esac; done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean - stopping"; exit 4 ;; esac
done
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "  redaction control FAILED - stopping"; exit 3; }

echo; echo "== 0b. refusals outside a pft-maint window (both hosts; nothing may be written)"
for h in local relay; do
  x "on $h 'sudo -n pft-maint active; echo maint-active rc \$?'"
  grep -qx 'maint-active rc 0' <<<"$XOUT" && { echo "  a pft-maint window is already active - stopping"; exit 4; }
  x "on $h 'sudo -n pft-aptrust apply --yes'"
  check "$(lb "$h"): apply --yes without a window: exit 4, REFUSED no active pft-maint window" "$(ok_if '[ "$XRC" = 4 ] && grep -q "REFUSED - no active pft-maint window" <<<"$XOUT"')"
  x "on $h 'sudo -n pft-aptrust apply'"
  check "$(lb "$h"): apply without --yes: exit 4" "$(ok_if '[ "$XRC" = 4 ] && grep -q "REFUSED - apply changes APT trust files: add --yes" <<<"$XOUT"')"
  x "on $h 'sudo -n pft-aptrust rollback --yes'"
  check "$(lb "$h"): rollback without a window: exit 4" "$(ok_if '[ "$XRC" = 4 ] && grep -q "REFUSED - no active pft-maint window" <<<"$XOUT"')"
done
check "/etc/apt unchanged on both hosts after the refusals" "$(ok_if '[ "$(snap local)" = "$SNAP_V0" ] && [ "$(snap relay)" = "$SNAP_S0" ]')"
if [ "$PREFLIGHT_ONLY" = 1 ]; then echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed ($FAILS check(s) failed)"; [ "$FAILS" = 0 ]; exit; fi
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 1. throwaway targets, catch-all silence, pft-maint window, pft-fleet sync of aptrust $SHORT"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-aptrust live drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTAptrust.*", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "aptrust-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTAptrust.*\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
NE_SHA0=absent; if sudo -n test -e "$NE"; then HAD_NE=1; NE_SHA0="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
x "{ [ $HAD_NE = 0 ] || sudo -n cp -p $NE $NEBK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$MT\" | sudo -n tee $NE >/dev/null && sudo -n chmod 600 $NE && sudo -n stat -c '%a %U' $NE"
[ "$XRC" = 0 ] && NE_SWAPPED=1; check "pft-maint [MAINT] target -> second throwaway topic (real file present before: $HAD_NE)" "$XRC"
[ "$FAILS" = 0 ] || exit 3
x "sudo -n pft-maint start --ttl 90m --reason '$TASK aptrust live drill'"
[ "$XRC" = 0 ] && MAINT=1; check "pft-maint window open on the validator" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
x "R 'sudo -n pft-maint status --json' | jq -c '{window, remaining_sec, locks: (.locks | length)}'"
[ "$FAILS" = 0 ] || exit 3
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust $SHORT (drop counts usable keys only)'"
check "pft-fleet sync aptrust exit 0 (files written + accepted in pft-integrity on both hosts)" "$XRC"
x "sha256sum aptrust/pft-aptrust.sh | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-aptrust | cut -c1-64; R 'sha256sum /usr/local/bin/pft-aptrust | cut -c1-64'"
check "installed pft-aptrust = HEAD bytes on both hosts" "$(ok_if '[ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ]')"
x "sudo -n pft-integrity verify | tail -n 1; R 'sudo -n pft-integrity verify | tail -n 1'"
check "pft-integrity PASS on both hosts right after the sync (rebaseline by pft-fleet)" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. SEED: perm FAIL on both hosts; validator GitHub CLI source without signed-by + its key in trusted.gpg.d"
SEEDED=1
x "R \"printf '// pft-aptrust drill $RUN: comment only, no APT option; removed at the end of the run\\n' | sudo -n tee $SEED >/dev/null && sudo -n chmod 660 $SEED && stat -c '%n %a %U:%G' $SEED\""
check "sentry: $SEED root:root 0660" "$(ok_if '[ "$XRC" = 0 ] && grep -q " 660 root:root$" <<<"$XOUT"')"
VSEED="set -e
printf '// pft-aptrust drill $RUN: comment only, no APT option; removed at the end of the run\n' | sudo -n tee $SEED >/dev/null; sudo -n chmod 660 $SEED
sudo -n install -d -m 700 $DD; sudo -n cp -p $GHL $DD/github-cli.list
sudo -n install -m 644 -o root -g root $GHK $DKEY
echo 'deb [arch=amd64] https://cli.github.com/packages stable main' | sudo -n tee $GHL >/dev/null
stat -c '%n %a %U:%G' $SEED $DKEY $GHL; cat $GHL"
echo "  validator seed script:"; printf '%s\n' "$VSEED" | red | sed 's/^/    | /'
x "L \"\$VSEED\""
check "validator seeded" "$XRC"
for h in local relay; do
  x "on $h 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL)|^RESULT'"
  if [ "$h" = local ]; then
    check "validator audit: exit 1; FAIL perm:$SEED, WARN src github-cli.list:1, WARN global drill key; 2 warn 1 fail" "$(ok_if 'grep -q "^FAIL  perm:$SEED " <<<"$XOUT" && grep -q "^WARN  src:$GHL:1 third-party source with no signed-by" <<<"$XOUT" && grep -q "^WARN  global:$DKEY " <<<"$XOUT" && [ "$(nwf "$XOUT")" = "2 1" ]')"
  else
    check "sentry audit: FAIL perm:$SEED; 0 warn 1 fail" "$(ok_if 'grep -q "^FAIL  perm:$SEED " <<<"$XOUT" && [ "$(nwf "$XOUT")" = "0 1" ]')"
  fi
done
SNAP_V1="$(snap local)"; SNAP_S1="$(snap relay)"
textfiles
check "textfiles: fail 1 for host=validator and host=sentry" "$(ok_if 'grep -q "^pft_aptrust_checks{host=\"validator\",result=\"fail\"} 1$" <<<"$XOUT" && grep -q "^pft_aptrust_checks{host=\"sentry\",result=\"fail\"} 1$" <<<"$XOUT"')"
t_seed="$(date -u +%s)"
wait_fire PFTAptrustUntrusted validator sentry
echo "  fired $(( $(date -u +%s) - t_seed ))s after the seeded textfiles (rule for: 5m)"

echo; echo "== 3. plan + VERIFY_INJECT auto-rollback (inside the window)"
x "sudo -n pft-aptrust apply --dry-run"
check "validator plan: perm $SEED 640, sign $GHL:1 -> $NKR, drop $DKEY; 0 manual" "$(ok_if 'grep -qE "plan +perm	$SEED	mode	640" <<<"$XOUT" && grep -qE "plan +sign	$GHL	1	https://cli.github.com/packages	$NKR	" <<<"$XOUT" && grep -qE "plan +drop	$DKEY" <<<"$XOUT" && grep -q "3 planned change(s), 0 manual" <<<"$XOUT"')"
x "R 'sudo -n pft-aptrust apply --dry-run'"
check "sentry plan: perm $SEED 640 only" "$(ok_if 'grep -qE "plan +perm	$SEED	mode	640" <<<"$XOUT" && grep -q "1 planned change(s), 0 manual" <<<"$XOUT"')"
for h in local relay; do
  x "on $h 'sudo -n env VERIFY_INJECT=drill pft-aptrust apply --yes'"
  check "$(lb "$h"): injected verify failure: exit 1, VERIFY FAILED injected:drill, restored" "$(ok_if '[ "$XRC" = 1 ] && grep -q "VERIFY FAILED: injected:drill -> restoring" <<<"$XOUT" && grep -q "restored; apt-get update after restore ok" <<<"$XOUT"')"
done
check "/etc/apt byte+mode identical to the seeded state on both hosts after the auto-rollback" "$(ok_if '[ "$(snap local)" = "$SNAP_V1" ] && [ "$(snap relay)" = "$SNAP_S1" ]')"
x "sudo -n test -e /var/lib/pft-aptrust/apply.json; echo validator apply.json rc \$?; R 'sudo -n test -e /var/lib/pft-aptrust/apply.json; echo sentry apply.json rc \$?'"
check "no apply on record after the auto-rollback (both hosts)" "$(ok_if '[ "$(grep -c "apply.json rc 1" <<<"$XOUT")" = 2 ]')"
[ "$FAILS" = 0 ] || exit 5

echo; echo "== 4. apply --yes -> FIXED; textfiles -> RESOLVED"
for h in local relay; do
  x "on $h 'sudo -n pft-aptrust apply --yes'"
  check "$(lb "$h"): apply exit 0, post gate verify ok" "$(ok_if '[ "$XRC" = 0 ] && grep -q "verify ok: apt-get update exit 0, no signature error" <<<"$XOUT"')"
done
x "stat -c '%n %a %U:%G' $SEED $NKR; cat $GHL; test ! -e $DKEY && echo 'drill global key removed'; gpg --batch --no-options --homedir \$(mktemp -d) --show-keys --with-colons $NKR | grep -c '^pub:'"
check "validator: $SEED 0640, source signed-by $NKR, global drill key removed, new keyring 0644 with 1 key" "$(ok_if 'grep -q "$SEED 640 root:root" <<<"$XOUT" && grep -q "$NKR 644 root:root" <<<"$XOUT" && grep -qx "deb \[signed-by=$NKR arch=amd64\] https://cli.github.com/packages stable main" <<<"$XOUT" && grep -q "drill global key removed" <<<"$XOUT" && [ "$(tail -n 1 <<<"$XOUT")" = 1 ]')"
x "R 'stat -c \"%n %a %U:%G\" $SEED'"
check "sentry: $SEED 0640" "$(ok_if 'grep -q "$SEED 640 root:root" <<<"$XOUT"')"
for h in local relay; do
  x "on $h 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL)|^RESULT|github|drill'"
  check "VERIFIED $(lb "$h"): audit exit 0, 0 warn 0 fail" "$(ok_if '[ "$XRC" = 0 ] && [ "$(nwf "$XOUT")" = "0 0" ]')"
done
textfiles
check "textfiles: fail 0 for both hosts" "$(ok_if 'grep -q "^pft_aptrust_checks{host=\"validator\",result=\"fail\"} 0$" <<<"$XOUT" && grep -q "^pft_aptrust_checks{host=\"sentry\",result=\"fail\"} 0$" <<<"$XOUT"')"
wait_resolve PFTAptrustUntrusted validator sentry

echo; echo "== 5. rollback --yes -> the seeded state again, byte+mode identical"
for h in local relay; do
  x "on $h 'sudo -n pft-aptrust rollback --yes'"
  check "$(lb "$h"): rollback exit 0, restored byte-identical, apt-get update ok" "$(ok_if '[ "$XRC" = 0 ] && grep -q "restored byte-identical" <<<"$XOUT" && grep -q "apt-get update ok" <<<"$XOUT"')"
done
check "/etc/apt byte+mode identical to the seeded state on both hosts after rollback" "$(ok_if '[ "$(snap local)" = "$SNAP_V1" ] && [ "$(snap relay)" = "$SNAP_S1" ]')"
x "sudo -n pft-aptrust audit | tail -n 1; R 'sudo -n pft-aptrust audit | tail -n 1'"
check "audit sees the seeded findings again (validator 2 warn 1 fail, sentry 0 warn 1 fail)" "$(ok_if '[ "$(nwf "$(head -n 1 <<<"$XOUT")")" = "2 1" ] && [ "$(nwf "$(sed -n 2p <<<"$XOUT")")" = "0 1" ]')"

echo; echo "== 6. unseed -> pre-run state"
unseed; SEEDED=0
check "/etc/apt byte+mode identical to the pre-run snapshot on both hosts" "$(ok_if '[ "$(snap local)" = "$SNAP_V0" ] && [ "$(snap relay)" = "$SNAP_S0" ]')"
for h in local relay; do
  x "on $h 'sudo -n pft-aptrust audit | tail -n 1; sudo -n apt-get update -q >/dev/null 2>&1; echo apt-get update rc \$?'"
  check "$(lb "$h"): audit 0 warn 0 fail, apt-get update rc 0" "$(ok_if '[ "$(nwf "$XOUT")" = "0 0" ] && grep -qx "apt-get update rc 0" <<<"$XOUT"')"
done
textfiles
check "textfiles: fail 0, warn 0 for both hosts" "$(ok_if '[ "$(grep -cE "result=\"(fail|warn)\"} 0$" <<<"$XOUT")" = 4 ]')"

echo; echo "== 7. restore, ALERTS query_range, read back"
restore
check "window ended, targets back, bridge back, alertpath OK" "$(ok_if '[ "$RESTORE_OK" = true ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"PFTAptrust.*\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=30 | jq -r '.data.result[] | \"\(.metric.alertname) host=\(.metric.host) \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
for hl in validator sentry; do check "query_range: PFTAptrustUntrusted{host=$hl} firing during the run" "$(ok_if 'grep -qE "^PFTAptrustUntrusted host=$hl firing " <<<"$XOUT"')"; done
check "query_range: no PFTAptrustStale during the run" "$(ok_if '! grep -q "^PFTAptrustStale" <<<"$XOUT"')"
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
for h in relay local; do s="$(node_state "$h")"; check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"; done
x "sudo -n pft-maint status --json | jq -r .window; R 'sudo -n pft-maint status --json' | jq -r .window"
check "no pft-maint window left on either host" "$(ok_if '[ "$(grep -cx none <<<"$XOUT")" = 2 ]')"
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
