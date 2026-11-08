#!/usr/bin/env bash
# live-run: recorded live drill of pft-migrate: the REAL validator (source, this host) is migrated to a fresh LXD
# target (rebuild/ sandbox built from migrate/drill/target.stack, kept running for this run) and rolled back.
# Built from ../../seccomp/drill/live-run.sh (redirect / silence / window / read-back / PREFLIGHT_ONLY).
#   sudo -n env RB_STACK=$PWD/migrate/drill/target.stack bash rebuild/pft-rebuild-drill.sh run --commit SHA --yes --keep
#   bash migrate/drill/live-run.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`, sudo lxc)
# 0  preflight (nothing changed yet): clean pushed HEAD; relay, Alertmanager, Prometheus; no pft-maint window or lock;
#    notifier envs present, no leftovers; bridge on the operator env; validator + sentry full; integrity PASS on both;
#    sandbox running with docker + age; no FENCED/IMPORTED record on either side; peer ports reachable both ways
#    (the target sees the live source answering, the source sees the target's port); redaction control.
# 1  redirect notifiers (both hosts) + the Alertmanager bridge to a throwaway topic; silence alertname=~".+" except
#    PFTAlertPipelineWatchdog; pft-maint window (the sentry gets it).
# 2  target: pinned pft-migrate.sh pushed, the sandbox's own fresh node stopped, age identity generated there.
# 3  export on the source (node keeps running); bundle copied; import with a WRONG identity refused (exit 2); import
#    with the target identity; a plain `docker compose up -d` on the imported target refused by the guard.
# 4  fence-source (downtime 1 starts at fenced_at); the target's probe sees the source closed; a plain `docker compose
#    up -d` on the fenced source is refused by the guard (container not running, peer port closed).
# 5  start-target (source probe + proof) and verify: full with the source's pubkey_node -> downtime_s #1; the sentry
#    lists the migrated node by public key.
# 6  rollback with the source's own proof while the target runs: refused (target answers, exit 4); fence the target;
#    rollback; verify on the source -> downtime_s #2.
# 7  aftercare: egress reapply after the re-create, AppArmor/seccomp audits, restart policy, lock gone, bundle dir
#    removed, sandbox torn down (the identity copy goes with it), pft-integrity accept (container re-create only).
# 8  restore, pft-keyescrow re-run on both hosts (it fingerprints the redirected env files; drift 0 required),
#    read-back of every operator topic.
# Any exit before step 6 finished runs the EXIT path: target stopped, source unfenced and started, sandbox torn down.
# Env: RELAY (relay) NTFY AM PROM LOCAL_ENVS REMOTE_ENVS BRIDGE_ENV SBX (pftrb-sbx) TTL (3h) SIL_TTL (180 min)
#      VERIFY_TMO (1800 s) PREFLIGHT_ONLY=1: step 0 only, nothing changed; exit 0 = ready, 4 = not ready.
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
export TZ=UTC
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_ENV=/etc/pft-maint/ntfy.env
SBX="${SBX:-pftrb-sbx}"; TTL="${TTL:-3h}"; SIL_TTL="${SIL_TTL:-180}"; VERIFY_TMO="${VERIFY_TMO:-1800}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; NOT_READY=0
TASK=task_2756079c
SUF=.pre-migrate-live
SHA_HEAD="$(git rev-parse HEAD)"
MIG=migrate/pft-migrate.sh
OUT=/var/lib/pft-migrate/drill-out      # source side (root 0700): bundle, sidecar, proofs
TD=/root/mig                            # target side (sandbox root, 0700)
CDIR=/opt/postfiatd                     # compose dir on both sides
ST=/var/lib/pft-migrate                 # pft-migrate STATE_DIR on both sides

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="miglive-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"; LAST_START="$since"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -uE "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
T() { sudo -n lxc exec "$SBX" -- bash -c "$1" </dev/null; } # target (sandbox) shell, root
on() { case "$1" in relay) R "$2" ;; target) T "$2" ;; *) L "$2" ;; esac; } # HOST CMDSTRING
cn() { if [ "$1" = relay ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
lb() { case "$1" in relay) echo sentry ;; target) echo target ;; *) echo validator ;; esac; }
dk() { if [ "$1" = target ]; then echo docker; else echo "sudo -n docker"; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
info() { on "$1" "$(dk "$1") exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" 2>/dev/null; }
node_state() { info "$1" | jq -r '.result.info.server_state // "down"' 2>/dev/null || echo down; }
node_peers() { info "$1" | jq -r '.result.info.peers // 0' 2>/dev/null; }
node_key() { info "$1" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null; }
fp() { printf '%s' "$1" | sha256sum | cut -c1-16; } # published stand-in for a (redacted) node key
running() { [ "$(on "$1" "$(dk "$1") inspect -f '{{.State.Running}}' postfiatd" 2>/dev/null)" = true ]; }
started() { LAST_START="$(date -u +%s)"; }
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
probe_from() { # WHERE HOST PORT -> 0 if a TCP connect succeeds within 3 s (same probe as pft-migrate.sh)
  on "$1" "timeout 3 bash -c 'exec 3<>/dev/tcp/$2/$3' 2>/dev/null"
}

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; MAINT_STARTED=0; MAINT_ENV_MADE=0; SIL=""; BRIDGE_SWAPPED=0
SBX_TOUCHED=0; ID=""; FENCED_SRC=0; ROLLED_BACK=0; SBX_DOWN=0; READ_BACK=0; PUB=""; HOSTIP=""; SBXIP=""
bridge_src() { sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}'; }

emergency() { # the run stopped with the source fenced: stop the target, unfence + start the source by hand
  [ "$FENCED_SRC" = 1 ] && [ "$ROLLED_BACK" = 0 ] || return 0
  echo "  EXIT path: source still fenced - stopping the target and unfencing the source"
  T "docker stop -t 60 postfiatd >/dev/null 2>&1; docker update --restart=no postfiatd >/dev/null 2>&1; true"
  if running target || probe_from local "$SBXIP" 2559; then echo "  target still runs - source NOT started (both copies would run)"; RESTORE_OK=false; return 1; fi
  echo "  target stopped, its peer port closed"
  sudo -n sh -c "set -e; cp -p $ST/env.pre-fence $CDIR/.env; rm -f $CDIR/docker-compose.migrate-fence.yml
    docker update --restart=\"\$(cat $ST/restart.pre-fence)\" postfiatd >/dev/null; cd $CDIR && docker compose up -d
    mv $ST/FENCED $ST/rolled-back-$ID; rm -f $ST/env.pre-fence $ST/restart.pre-fence; pft-maint lock rm pft-migrate || true" 2>&1 | red | sed 's/^/    /'
  started; ROLLED_BACK=1
  if running local; then echo "  source started again (manual unfence)"; else echo "  source start FAILED"; RESTORE_OK=false; fi
}
teardown_sbx() {
  [ "$SBX_DOWN" = 1 ] || [ "$SBX_TOUCHED" = 0 ] && return 0
  SBX_DOWN=1
  sudo -n bash rebuild/pft-rebuild-drill.sh teardown --yes 2>&1 | red | sed 's/^/  /'
  if sudo -n lxc info "$SBX" >/dev/null 2>&1; then echo "  sandbox teardown INCOMPLETE"; RESTORE_OK=false
  else echo "  sandbox $SBX gone (the target copy of the identity with it)"; fi
}
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha left nb SIL2
  emergency
  teardown_sbx
  [ "$SBX_TOUCHED" = 1 ] && sudo -n rm -rf "$OUT" && echo "  removed $OUT (bundle, sidecar, proofs)"
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
        '{matchers: [{name: "alertname", value: "PFTContainerRestarted", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "migrate-live", comment: $c}')"
      SIL2="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$nb" | jq -r '.silenceID // empty')"
      if [ -n "$SIL2" ]; then
        echo "  narrow silence alertname=PFTContainerRestarted until last node start $(date -u -d "@$LAST_START" +%TZ) + 25 min (${left}s); expires by itself"
        curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
      else echo "  narrow silence FAILED: catch-all kept until its end time"; RESTORE_OK=false; fi
    else curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"; fi
  fi
}
readback() { # TOPIC LABEL [quiet]
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
stop_path() {
  local i=0 opn=0 t
  [ "$READ_BACK" = 1 ] || [ "${#MOVED[@]}" = 0 ] || [ ! -s "${OPS:-/nonexistent}" ] && return 0
  echo "  stop path: operator read-back after 60 s"; sleep 60
  while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || opn=$((opn + 1)); done < "$OPS"
  echo "  stop path: operator topics received nothing during the run: $([ "$opn" = 0 ] && echo yes || echo NO) ($i topic(s), $opn with messages)"
}
cleanup() { restore; stop_path; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-migrate live drill (real validator -> fresh LXD target -> rollback) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in migrate/drill/live-run.sh "$MIG" migrate/drill/target.stack rebuild/pft-rebuild-drill.sh "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
for h in relay local; do
  nl="$(on "$h" "sudo -n pft-maint status --json" 2>/dev/null | jq -r '.locks | length' 2>/dev/null)"
  [ "${nl:-1}" = 0 ] && continue
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  $(lb "$h"): ${nl:-?} pft-maint data-collection lock(s) held - a real run would stop here"; NOT_READY=1
  else echo "  $(lb "$h"): ${nl:-?} pft-maint data-collection lock(s) held - stopping" >&2; exit 4; fi
done
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
HOSTIP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -nE 's/.* src ([0-9.]+).*/\1/p')"; [ -z "$HOSTIP" ] || printf 'ip\t%s\n' "$HOSTIP" >> "$LIT"
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; [ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
[ -n "$HOSTIP" ] || { echo "  source address unknown - stopping" >&2; exit 3; }
for h in relay local; do
  k="$(node_key "$h")"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  s="$(node_state "$h")"; echo "  $(cn "$h"): server_state=${s:-down}, peers $(node_peers "$h")"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
PUB="$(node_key local)"; [[ "$PUB" =~ ^n9 ]] || { echo "  validator pubkey_node unreadable - stopping" >&2; exit 4; }
echo "  validator pubkey_node fingerprint (sha256 of the key, first 16 hex): $(fp "$PUB")"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
sudo -n lxc info "$SBX" 2>/dev/null | grep -q '^Status: RUNNING' || { echo "  sandbox $SBX not running (build it with target.stack --keep) - stopping" >&2; exit 3; }
SBXIP="$(sudo -n lxc list "$SBX" -c4 --format csv | grep -oE '[0-9.]+ \(eth0\)' | cut -d' ' -f1)"   # not the sandbox's own docker bridges
[[ "$SBXIP" =~ ^[0-9.]+$ ]] || { echo "  sandbox address unknown - stopping" >&2; exit 3; }
x "T 'docker compose version --short; age --version; test -f $CDIR/docker-compose.yml && echo compose-dir ok; . /etc/os-release; echo \$PRETTY_NAME'"
check "target: docker compose + age present, $CDIR exists" "$(ok_if '[ "$XRC" = 0 ] && grep -q "compose-dir ok" <<<"$XOUT"')"
sudo -n test -e "$ST/FENCED" || sudo -n test -e "$ST/IMPORTED" && { echo "  source: a FENCED/IMPORTED record exists - stopping" >&2; exit 4; }
T "test -e $ST/FENCED || test -e $ST/IMPORTED" && { echo "  target: a FENCED/IMPORTED record exists - stopping" >&2; exit 4; }
sudo -n test -e "$OUT" && { echo "  leftover $OUT - stopping" >&2; exit 3; }
echo "  no FENCED/IMPORTED record on the source or the target, no leftover bundle dir"
probe_from target "$HOSTIP" 2559; check "target reaches the live source's peer port (so its 'source closed' probe is meaningful)" "$?"
running target || { echo "  sandbox's own node is not running (step 2 needs it for the source->target port check)"; NOT_READY=1; }
x "sudo -n bash $MIG plan | grep -E '^RESULT|^  (node|fenced|identity):' | sed -E 's/pubkey_node [^ ]+/pubkey_node <key>/'; sudo -n bash $MIG plan --json | jq '.files | length'"
check "source plan RESULT OK" "$(ok_if 'grep -q "^RESULT: OK" <<<"$XOUT"')"
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then
  echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed (ready: $([ "$NOT_READY" = 0 ] && [ "$FAILS" = 0 ] && echo yes || echo "no, see above"))"
  exit $(( NOT_READY || FAILS ? 4 : 0 ))
fi
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }

echo; echo "== 1. redirect notifiers + bridge, silence everything except the dead-man switch, maintenance window"
redirect() { # HOST PATH
  local h="$1" f="$2"
  SHA["$h:$f"]="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
  [[ "${SHA[$h:$f]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $h:$f unreadable - stopping"; exit 3; }
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $(lb "$h"):$f sha256 ${SHA[$h:$f]:0:12} -> $NTFY/<redacted> (throwaway), original kept as $f$SUF"
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
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-migrate live drill $RUN (planned validator stop, migration, rollback)" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog", isRegex: false, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "migrate-live", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!=\"PFTAlertPipelineWatchdog\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
x "sudo -n pft-maint start --ttl $TTL --reason '$TASK pft-migrate live drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. target preparation (sandbox)"
SBX_TOUCHED=1
# PFT-REBUILD-IN drops everything from the sandbox bridge, replies included, so the source could never see the target's
# peer port and rollback's "target closed" probe would pass vacuously (dev probe). Allow ONLY established replies from
# the target's port 2559; the sandbox still cannot open a connection to the host. Teardown flushes the chain.
x "sudo -n iptables -I PFT-REBUILD-IN 1 -s $SBXIP -p tcp --sport 2559 -m conntrack --ctstate ESTABLISHED -j ACCEPT && sudo -n iptables -S PFT-REBUILD-IN"
probe_from local "$SBXIP" 2559; check "source reaches the target's peer port (sandbox's own node; so the 'target closed' probe is meaningful)" "$?"
probe_from target 10.209.77.1 22; r=$?; check "sandbox still cannot reach the host's sshd via the bridge" "$(ok_if '[ "$r" != 0 ]')"
x "git show $SHA_HEAD:$MIG | sudo -n lxc exec $SBX -- sh -c 'install -d -m 700 $TD && cat > $TD/pft-migrate.sh' && T 'sha256sum < $TD/pft-migrate.sh | cut -c1-64'; git show $SHA_HEAD:$MIG | sha256sum | cut -c1-64"
check "pinned pft-migrate.sh pushed to the target, sha256 identical" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -cE "^[0-9a-f]{64}$" <<<"$XOUT")" = 2 ] && [ "$(grep -E "^[0-9a-f]{64}$" <<<"$XOUT" | sort -u | wc -l)" = 1 ]')"
x "T 'cd $CDIR && docker compose down 2>&1 | tail -3; docker ps -a --format \"{{.Names}} {{.State}}\"'"
check "target: the sandbox's own fresh node stopped and removed" "$(ok_if '! running target')"
x "T 'umask 077; age-keygen -o $TD/target.key 2>/dev/null; age-keygen -y $TD/target.key; stat -c \"%a %n\" $TD/target.key'"
RECIP="$(grep -oE '^age1[02-9ac-hj-np-z]{58}$' <<<"$XOUT" | head -1)"
check "target age identity generated in the sandbox (0600), recipient read" "$(ok_if '[ -n "$RECIP" ] && grep -q "^600 " <<<"$XOUT"')"
[ "$FAILS" = 0 ] || { echo "  target preparation failed - stopping before the source is touched"; exit 4; }

echo; echo "== 3. export (source keeps running), copy, import on the target"
x "sudo -n install -d -m 700 $OUT && sudo -n bash $MIG export --to $RECIP --out $OUT"
ID="$(grep -oE '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$' <<<"$XOUT" | tail -1)"
check "export exit 0, bundle id printed" "$(ok_if '[ "$XRC" = 0 ] && [ -n "$ID" ]')" "$ID"
[ -n "$ID" ] || exit 4
B="$OUT/pft-migrate-$ID.age"
x "sudo -n stat -c '%a %s %n' $B $B.sha256; sudo -n head -c 22 $B; echo; ls /dev/shm | grep -c pft-migrate; running local && echo source-running"
check "bundle 0600 age-encrypted (age-encryption.org header), RAM stage removed, source still running" \
  "$(ok_if 'grep -q "^600 .*\.age$" <<<"$XOUT" && grep -q "^age-encryption.org/v1" <<<"$XOUT" && grep -qx 0 <<<"$XOUT" && grep -q source-running <<<"$XOUT"')"
x "sudo -n lxc file push --quiet --mode 0600 $B $B.sha256 $SBX$TD/ && T 'cd $TD && sha256sum -c pft-migrate-$ID.age.sha256'"
check "bundle + sidecar copied to the target, sidecar verifies there" "$(ok_if '[ "$XRC" = 0 ]')"
x "T 'umask 077; age-keygen -o $TD/wrong.key 2>/dev/null; bash $TD/pft-migrate.sh import --bundle $TD/pft-migrate-$ID.age --identity $TD/wrong.key --replace --skip-overlay docker-compose.apparmor.yml; rc=\$?; rm -f $TD/wrong.key; exit \$rc'"
check "import with a WRONG age identity refused (exit 2, age decryption failed)" "$(ok_if '[ "$XRC" = 2 ] && grep -q "age decryption failed" <<<"$XOUT"')"
x "T 'bash $TD/pft-migrate.sh import --bundle $TD/pft-migrate-$ID.age --identity $TD/target.key --replace --skip-overlay docker-compose.apparmor.yml'"
check "import with the target identity exit 0 (AppArmor overlay skipped: nested LXD cannot load it)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "imported bundle $ID" <<<"$XOUT"')"
x "T 'bash $TD/pft-migrate.sh status; grep ^COMPOSE_FILE= $CDIR/.env'"
x "T 'cd $CDIR && docker compose up -d 2>&1 | tail -4; sleep 5; docker inspect -f \"{{.State.Status}} exit={{.State.ExitCode}} restart={{.HostConfig.RestartPolicy.Name}}\" postfiatd'"
check "plain 'docker compose up -d' on the imported target refused by the guard (container not running)" "$(ok_if '! running target')"
probe_from local "$SBXIP" 2559; r=$?; check "target peer port closed after the refused start" "$(ok_if '[ "$r" != 0 ]')"
[ "$FAILS" = 0 ] || { echo "  import stage failed - stopping before the source is touched"; exit 4; }

echo; echo "== 4. fence the source (downtime 1 starts)"
x "sudo -n bash $MIG fence-source --bundle-id $ID --proof-out $OUT/source.proof"; FENCED_SRC=1
check "fence-source exit 0 (exited, restart=no, guard on, peer port closed, RPC down)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^container_state=exited" <<<"$XOUT" && grep -q "^peer_port_local=closed" <<<"$XOUT"')"
[ "$XRC" = 0 ] || exit 4
probe_from target "$HOSTIP" 2559; r=$?; check "target's probe: source peer port now closed" "$(ok_if '[ "$r" != 0 ]')"
x "sudo -n sh -c 'cd $CDIR && docker compose up -d' 2>&1 | tail -4; sleep 5; sudo -n docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} restart={{.HostConfig.RestartPolicy.Name}}' postfiatd"
check "plain 'docker compose up -d' on the FENCED source refused by the guard (container not running)" "$(ok_if '! running local')"
probe_from target "$HOSTIP" 2559; r=$?; check "source peer port still closed after the refused start" "$(ok_if '[ "$r" != 0 ]')"
x "sudo -n bash $MIG status | sed -E 's/^(  pubkey=).*/\1<key>/'; sudo -n pft-maint status --json | jq -c '[.locks[] | .name]'"
x "sudo -n cat $OUT/source.proof | sudo -n lxc exec $SBX -- sh -c 'cat > $TD/source.proof'"
check "source fence proof copied to the target" "$XRC"

echo; echo "== 5. start the target, verify identity + full (downtime 1)"
x "T 'bash $TD/pft-migrate.sh start-target --fence-proof $TD/source.proof --source $HOSTIP:2559'"; started
check "start-target exit 0 (proof accepted, source probe closed)" "$(ok_if '[ "$XRC" = 0 ]')"
[ "$XRC" = 0 ] || exit 4
x "T 'bash $TD/pft-migrate.sh verify --expect-pubkey $PUB --since-proof $TD/source.proof --timeout $VERIFY_TMO'"
DT1="$(sed -n 's/^downtime_s=//p' <<<"$XOUT")"
check "target full with the source's pubkey_node" "$(ok_if '[ "$XRC" = 0 ] && grep -q "(matches)" <<<"$XOUT"')"
TK="$(node_key target)"; echo "  target pubkey_node fingerprint: $(fp "$TK") (source: $(fp "$PUB"))"
check "target pubkey_node == source pubkey_node (independent read)" "$(ok_if '[ "$TK" = "$PUB" ]')"
echo "DOWNTIME_1_S ${DT1:-n/a} (source fenced_at -> target full)"
w=0; SEEN=1
while [ "$w" -le 300 ]; do
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"peers\"}' http://127.0.0.1:5005" | jq -e --arg k "$PUB" '[.result.peers[]? | select(.public_key == $k)] | length > 0' >/dev/null 2>&1 && { SEEN=0; break; }
  w=$((w + 15)); sleep 15
done
check "sentry lists the migrated node by public key" "$SEEN" "after ${w}s"
x "T 'docker exec postfiatd curl -s -m 10 -d \"{\\\"method\\\":\\\"server_info\\\"}\" http://127.0.0.1:5005' | jq -c '.result.info | {server_state, peers, complete_ledgers, build_version}'"
check "source container still not running" "$(ok_if '! running local')"

echo; echo "== 6. rollback"
x "sudo -n bash $MIG rollback --bundle-id $ID --fence-proof $OUT/source.proof --target $SBXIP:2559"
check "rollback while the target runs refused (exit 4, target still answers)" "$(ok_if '[ "$XRC" = 4 ] && grep -q "target still answers" <<<"$XOUT" && ! running local')"
x "T 'bash $TD/pft-migrate.sh fence --bundle-id $ID --proof-out $TD/target.proof'"
check "target fenced (exited, restart=no, guard on, peer port closed, RPC down)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^peer_port_local=closed" <<<"$XOUT"')"
[ "$XRC" = 0 ] || exit 4
x "T 'cat $TD/target.proof' | sudo -n sh -c 'umask 022; cat > $OUT/target.proof' && sudo -n grep -c = $OUT/target.proof"
check "target fence proof copied to the source" "$XRC"
x "sudo -n bash $MIG rollback --bundle-id $ID --fence-proof $OUT/target.proof --target $SBXIP:2559"; started
check "rollback exit 0 (target proof accepted, target probe closed, source started)" "$(ok_if '[ "$XRC" = 0 ]')"
[ "$XRC" = 0 ] && ROLLED_BACK=1
[ "$ROLLED_BACK" = 1 ] || exit 4
x "sudo -n bash $MIG verify --expect-pubkey $PUB --since-proof $OUT/target.proof --timeout $VERIFY_TMO"
DT2="$(sed -n 's/^downtime_s=//p' <<<"$XOUT")"
check "source full again with its own pubkey_node" "$(ok_if '[ "$XRC" = 0 ] && grep -q "(matches)" <<<"$XOUT"')"
echo "DOWNTIME_2_S ${DT2:-n/a} (target fenced_at -> source full)"
x "T 'bash $TD/pft-migrate.sh status | sed -E \"s/^(  pubkey=).*/\\1<key>/\"; cd $CDIR && docker compose up -d 2>&1 | tail -2; sleep 5; docker inspect -f \"{{.State.Running}}\" postfiatd'"
check "target stays fenced: a plain compose up there is refused" "$(ok_if '! running target')"

echo; echo "== 7. aftercare on the source"
x "sudo -n docker inspect -f 'restart={{.HostConfig.RestartPolicy.Name}} secopt={{len .HostConfig.SecurityOpt}} cpu_shares={{.HostConfig.CpuShares}}' postfiatd; sudo -n docker inspect -f '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}' postfiatd | cut -c1-40"
check "source container: restart unless-stopped, AppArmor + seccomp + no-new-privileges, cpu_shares 8192" \
  "$(ok_if 'grep -q "restart=unless-stopped" <<<"$XOUT" && grep -q "apparmor=pft-postfiatd" <<<"$XOUT" && grep -q "^seccomp=" <<<"$XOUT" && grep -q "cpu_shares=8192" <<<"$XOUT"')"
x "sudo -n bash $MIG status | sed -E 's/^(  pubkey=).*/\1<key>/'; sudo -n ls $ST; sudo -n pft-maint status --json | jq -c '[.locks[] | .name]'; sudo -n grep -c migrate-fence $CDIR/.env"
check "source unfenced: no FENCED record, pft-migrate lock gone, guard not in COMPOSE_FILE" "$(ok_if 'grep -q "^FENCED: no" <<<"$XOUT" && grep -qx "\[\]" <<<"$XOUT" && grep -qx 0 <<<"$XOUT"')"
x "sudo -n systemctl start pft-egress-reapply@postfiatd.service; echo reapply rc \$?; sudo -n iptables -S DOCKER-USER | grep -c -- '-j PFT-EGRESS'"
check "pft-egress jump back in DOCKER-USER after the re-create" "$(ok_if 'grep -qx "[1-9]" <<<"$XOUT"')"
x "sudo -n pft-apparmor audit | grep -E '^RESULT|container'; sudo -n pft-seccomp audit | grep -E '^RESULT|container'"
check "pft-apparmor + pft-seccomp audits PASS on the source" "$(ok_if '[ "$(grep -c "^RESULT.*PASS" <<<"$XOUT")" = 2 ]')"
teardown_sbx
check "sandbox torn down" "$(ok_if '! sudo -n lxc info "$SBX" >/dev/null 2>&1')"
sudo -n rm -rf "$OUT"; check "bundle dir removed on the source" "$(ok_if '! sudo -n test -e "$OUT"')"
x "sudo -n pft-integrity verify | grep -E '^(  \[(WARN|FAIL)\]|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
ITEMS="$(grep -E '^  \[(WARN|FAIL)\]' <<<"$XOUT" | awk '{print $2}' | sort -u)"
if [ -z "$ITEMS" ]; then echo "  pft-integrity validator: nothing to accept"
elif [ "$(grep -vxc 'container:postfiatd' <<<"$ITEMS")" = 0 ]; then
  x "sudo -n pft-integrity accept --reason '$TASK: pft-migrate live drill $RUN (postfiatd re-created by guard test + rollback)' | tail -1 | sed -E 's/ by [a-z_][a-z0-9_-]*\$/ by <user>/'"
else echo "  pft-integrity validator: NOT accepted - items besides the container re-create: $(tr '\n' ' ' <<<"$ITEMS")"; FAILS=$((FAILS + 1)); fi
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after the re-baseline" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"

echo; echo "== 8. restore, key-escrow re-run, read back"
restore
check "env files byte-identical, bridge back on the operator env, pft-maint env removed, window ended" \
  "$(ok_if '[ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && ! sudo -n test -e "$MAINT_ENV"')"
x "R 'sudo -n systemctl start pft-keyescrow.service'; sudo -n systemctl start pft-keyescrow.service; sudo -n systemctl start pft-keyescrow-pull.service; grep -h '^pft_keyescrow_drift_items' /var/lib/pft-exporter/textfile/pft_keyescrow*.prom"
check "pft-keyescrow re-run on both hosts after the env restore: drift_items 0 for validator and sentry" "$(ok_if '[ "$(grep -cE "^pft_keyescrow_drift_items\{node=\"(validator|sentry)\"\} 0$" <<<"$XOUT")" = 2 ]')"
sleep 90
readback "$ALERT" throwaway
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"; READ_BACK=1
for h in relay local; do
  s="$(node_state "$h")"
  check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "DOWNTIMES: migrate ${DT1:-n/a} s, rollback ${DT2:-n/a} s"
echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
