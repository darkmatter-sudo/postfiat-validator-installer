#!/usr/bin/env bash
# sentry-drill: recorded live drills for pft-selfheal on the sentry (task_29073d4c5d752dc0d42b5f9bafe85732, step 4).
# Built from ../../patch/drill/live-run.sh (notifier env redirect, PASS logs 04/05) and
# ../../peerwatch/drill/link-drill.sh (bridge swap, dead-man, drain; PASS peerwatch log 10).
# The sentry's /etc/pft-selfheal.env is swapped for a drill conf for the run: MODE=enforce and shorter windows
# (DRILL_KEYS below) so the drills fit in one run; MAX_ACTIONS (K) stays at its production value. It is restored
# byte-identical (sha256 compared) on ANY exit. The validator's selfheal stays in dryrun and is not touched.
#   A  stopped container: `docker stop` -> pft-selfheal starts it with exactly ONE action (`docker start`, the sentry
#      is a `docker run` container), pft-egress reapply exit 0, node full again, CpuShares/MemoryReservation/Memory
#      unchanged.
#   C  maintenance window: window open (validator start, sentry via the watchdog channel), `docker stop` -> every
#      decision is suppressed_by maintenance and ZERO actions run; the drill starts the container itself, ends the
#      window.
#   B  unfixable peer fault: an independent dead-man unit on the sentry (started first) deletes two REJECT rules at
#      DOCKER-USER 2 (after the pft-egress jump, before the ESTABLISHED accept) that cut every forwarded TCP packet of
#      the sentry container after DEADMAN_SEC. Selfheal restarts it (restart cannot fix this) until the K-per-24h
#      budget is spent -> breaker OPEN after at most K actions in 24 h (A's action counts), PFTSelfhealBreakerOpen
#      FIRING on the throwaway topic, no further action; the dead-man removes the rules, the node recovers by itself,
#      the breaker stays open until `pft-selfheal reset`, then closes and the alert RESOLVES.
#   Notifiers: every ntfy env on both hosts -> throwaway ALERT topic; drill-only pft-maint ntfy.env on both hosts ->
#   throwaway MAINT topic; Alertmanager bridge -> ALERT topic (sentry alertpath paused around the bridge re-create);
#   catch-all silence except the pipeline watchdog and PFTSelfheal*, kept until the newest container start +
#   RESTART_TAIL. Every operator topic is read back at the end (must be 0 messages).
#   bash selfheal/drill/sentry-drill.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
#   PREFLIGHT_ONLY=1 bash selfheal/drill/sentry-drill.sh   (step 0 only; changes nothing)
# Env: KNOWN_PENDING (regex of alert names pending before the run)  DEADMAN_SEC (1320)  SIL_TTL (150 min)
#      RESTART_TAIL (25 min)  DRAIN_WAIT (600)  OTHERS_WAIT (300)
# shellcheck disable=SC2016,SC2015,SC2034  # ok_if conditions are evaluated later; remote commands expand on the sentry
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
export TZ=UTC
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
NTFY=https://ntfy.sh; AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
LOCAL_ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
REMOTE_ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env"
BRIDGE_ENV="$HOME/.config/pft-alerts/ntfy.env"; AGENT_ENV=/opt/pft-agent/config.env
KNOWN_PENDING="${KNOWN_PENDING:-}"; PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"
DEADMAN_SEC="${DEADMAN_SEC:-1320}"; SIL_TTL="${SIL_TTL:-150}"; RESTART_TAIL="${RESTART_TAIL:-25}"
DRAIN_WAIT="${DRAIN_WAIT:-600}"; OTHERS_WAIT="${OTHERS_WAIT:-300}"; AP_WAIT=180
TASK=task_29073d4c
SHA="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile; SD=/var/lib/pft-selfheal
SC=postfiatd-sentry; SH_CONF=/etc/pft-selfheal.env; SJ="$SD/journal-$SC.jsonl"
DM=pft-selfheal-drill-deadman; TAG=pft-selfheal-drill
SUF=.pre-selfheal-drill
DRILL_KEYS="MODE=enforce ZERO_PEERS_SEC=120 STUCK_SEC=180 STALE_SEC=180 GRACE_SEC=120 BACKOFF_SEC=60 BACKOFF_MAX_SEC=240"

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="shdrill-$(rnd)"; MT="shmaint-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d -p "$HOME/.cache")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\ntopic\t%s\nuser\t%s\n' "$ALERT" "$MT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -u -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes relay "$@" </dev/null; }
L() { bash -c "$1" </dev/null; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
si() { R "sudo -n docker exec $SC curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"; }
sstate() { si | jq -r '.result.info.server_state // "down"' 2>/dev/null || echo down; }
speers() { si | jq -r '.result.info.peers // -1' 2>/dev/null || echo -1; }
srunning() { R "sudo -n docker inspect -f '{{.State.Running}}' $SC" 2>/dev/null; }
sstarted() { R "sudo -n docker inspect -f '{{.State.StartedAt}}' $SC" 2>/dev/null; }
shcfg() { # resource settings + confinement (SecurityOpt holds the whole seccomp JSON: printed as a sha256 prefix)
  echo "$(R "sudo -n docker inspect -f 'CpuShares={{.HostConfig.CpuShares}} MemoryReservation={{.HostConfig.MemoryReservation}} Memory={{.HostConfig.Memory}} Restart={{.HostConfig.RestartPolicy.Name}} AppArmor={{.AppArmorProfile}}' $SC" 2>/dev/null) SecurityOpt-sha256=$(R "sudo -n docker inspect -f '{{json .HostConfig.SecurityOpt}}' $SC" 2>/dev/null | sha256sum | cut -c1-16)"; }
scip() { R "sudo -n docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $SC" 2>/dev/null; }
jl() { R "sudo -n cat $SJ 2>/dev/null"; }  # the sentry's selfheal journal
jcount() { # SINCE_TS EVENT -> number of journal lines of that event at/after SINCE_TS
  jl | jq -c --argjson t "$1" --arg e "$2" 'select(.ts >= $t and .event == $e)' 2>/dev/null | wc -l; }
jshow() { jl | jq -c --argjson t "$1" 'select(.ts >= $t) | {t: (.ts | todate), event, verdict, detector, action, suppressed_by, actions_24h, breaker_open, rc, egress_rc, cmd}
  | with_entries(select(.value != null))' 2>/dev/null; }
stext() { R "sudo -n grep -hE '^pft_selfheal_(up|enforce|actions_24h|breaker_open|actions_total)\{' $TF/pft_selfheal_$SC.prom" 2>/dev/null; }
sval() { stext | awk -v m="$1" 'index($0, m "{") == 1 { print $2 }'; }
sstatus() { R "sudo -n pft-selfheal status --container $SC"; }
pq() { curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
DU='sudo -n iptables -S DOCKER-USER'
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
n_msgs() { # STATUS -> [STATUS] PFTSelfhealBreakerOpen messages on the ALERT topic naming the sentry container
  topic_msgs "$ALERT" | jq -r --arg t "[$1] PFTSelfhealBreakerOpen" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' | grep -c "$SC"; }
wait_until() { # SECONDS STEP CONDITION -> 0 when CONDITION became true; prints the wait
  local t0; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$1" ]; do eval "$3" && { WAITED=$(( $(date -u +%s) - t0 )); return 0; }; sleep "$2"; done
  WAITED=$(( $(date -u +%s) - t0 )); eval "$3"; }
others_re() { echo "PFTAlertPipelineWatchdog|PFTSelfheal.*${KNOWN_PENDING:+|$KNOWN_PENDING}"; }
sh_active() {
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname=~"PFTSelfheal.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq '[.[] | select(.labels.alertname | test("^PFTSelfheal"))] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }

declare -A FSHA=()
declare -a MOVED=() CREATED=()
RESTORED=0; RESTORE_OK=true; SIL=""; SBODY=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; MAINT=0; BROKEN=0
R1=(); R2=(); DU0=""
rules_present() { R "sudo -n iptables -S DOCKER-USER" | grep -c -- "$TAG"; }
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
  while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do n="$(sh_active)"; [ "$n" = 0 ] && break; sleep 10; done
  if [ "$n" = 0 ]; then echo "  drain: no PFTSelfheal* alert pending/firing/active after $(( $(date -u +%s) - t0 ))s; 90 s for RESOLVED delivery"; sleep 90; n="$(sh_active)"; fi
  if [ "$n" = 0 ]; then echo "  drain: done, nothing left that could reach the operator topic: yes"; return 0; fi
  local e body id; e="$(date -u -d '+60 min' +%FT%TZ)"
  body="$(jq -nc --arg s "$(ts)" --arg e "$e" --arg c "$TASK selfheal drill $RUN drain timeout" '{matchers: [{name: "alertname", value: "PFTSelfheal.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "selfheal-drill", comment: $c}')"
  id="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$body" | jq -r '.silenceID // empty')"
  echo "  drain: NO - $n PFTSelfheal* alert(s) still active; silenced alertname=~PFTSelfheal.* until $e (${id:+id set}${id:-silence FAILED})"
  return 1; }
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha newest e
  if [ "$BROKEN" = 1 ] && [ "$(rules_present)" != 0 ]; then
    echo "  ABORT PATH: drill rules still present at restore - deleting them here (not the automatic restore)"
    R "while sudo -n iptables -C DOCKER-USER ${R1[*]} 2>/dev/null; do sudo -n iptables -D DOCKER-USER ${R1[*]}; done; while sudo -n iptables -C DOCKER-USER ${R2[*]} 2>/dev/null; do sudo -n iptables -D DOCKER-USER ${R2[*]}; done"
    RESTORE_OK=false
  fi
  R "sudo -n systemctl stop $DM.service >/dev/null 2>&1; sudo -n systemctl reset-failed $DM.service >/dev/null 2>&1"
  for k in "${MOVED[@]}"; do   # notifier envs + the sentry's selfheal conf (cp -p backups: bytes, mode, mtime)
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${FSHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
  MOVED=()
  if [ "$(srunning)" != true ]; then
    echo "  ABORT PATH: $SC not running at restore - docker start + pft-egress reapply here"
    R "sudo -n docker start $SC >/dev/null && sudo -n pft-egress reapply --container $SC >/dev/null"; RESTORE_OK=false
  fi
  # run 16: collectors that ran while the drill had envs redirected / the container stopped left stale textfiles
  # (PFTKeyEscrowStale drift both hosts, PFTSeccompDrift filter on the sentry): re-run them + the validator pulls
  R "sudo -n systemctl start pft-keyescrow.service pft-seccomp.service" && sudo -n systemctl start pft-keyescrow.service \
    && sudo -n systemctl start pft-keyescrow-pull.service pft-seccomp-pull.service \
    && echo "  re-ran pft-keyescrow (both) + pft-seccomp (sentry) and the validator pulls: yes" \
    || { echo "  re-ran pft-keyescrow/pft-seccomp collectors + pulls: NO"; RESTORE_OK=false; }
  if [ "$MAINT" = 1 ]; then echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'; MAINT=0; fi
  for k in "${CREATED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n rm -f $f"
    if on "$h" "sudo -n test -e $f"; then echo "  removed drill-only $k: NO"; RESTORE_OK=false; else echo "  removed drill-only $k: yes"; fi
  done
  CREATED=()
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    drain || RESTORE_OK=false
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"; BRIDGE_SWAPPED=0
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  if [ -n "$SIL" ]; then  # restart-related alerts (PFTContainerRestarted 15m, ...) stay true for a while after a start
    newest="$(date -u -d "$(sstarted)" +%s 2>/dev/null || date -u +%s)"
    e="$(date -u -d "@$(( newest + RESTART_TAIL * 60 ))" +%FT%TZ)"
    curl -s --max-time 10 -o /dev/null -w "  catch-all silence kept until $e (newest sentry container start + ${RESTART_TAIL} min): HTTP %{http_code}\n" \
      -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$(jq -c --arg id "$SIL" --arg e "$e" '. + {id: $id, endsAt: $e}' <<<"$SBODY")"
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-selfheal sentry drills (A stopped container, C maintenance window, B unfixable peer fault -> breaker) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in selfheal/drill/sentry-drill.sh selfheal/pft-selfheal.sh selfheal/selfheal_decide.py alerts/selfheal.rules.yml peerexpose/drill/redact.py; do echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
git fetch -q origin; [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping"; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" && curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  AM/Prometheus not reachable - stopping"; exit 3; }
for ip in "$(ssh -G relay | awk '$1 == "hostname" { print $2 }')" "$(R 'echo "${SSH_CLIENT%% *}"')" "$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; do
  [ -z "$ip" ] || printf 'ip\t%s\n' "$ip" >> "$LIT"; done
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
k="$(si | jq -r '.result.info.pubkey_node // empty' 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
x "sha256sum selfheal/pft-selfheal.sh selfheal/selfheal_decide.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-selfheal /usr/local/lib/pft-selfheal/selfheal_decide.py' | cut -c1-64"
check "installed pft-selfheal + decider on the sentry = this checkout" "$(ok_if '[ "$(sort <<<"$XOUT" | uniq -c | awk "\$1 == 2" | wc -l)" = 2 ]')"
x "R 'systemctl is-active pft-selfheal@$SC.timer'; systemctl is-active pft-selfheal-pull@$SC.timer; R 'sudo -n grep -E \"^(MODE|MAX_ACTIONS)=\" $SH_CONF'"
check "sentry selfheal timer + validator pull timer active, sentry conf MODE=dryrun MAX_ACTIONS=3" "$(ok_if '[ "$(grep -cx active <<<"$XOUT")" = 2 ] && grep -qx MODE=dryrun <<<"$XOUT" && grep -qx MAX_ACTIONS=3 <<<"$XOUT"')"
x "sstatus; stext"
# actions already in the 24 h budget (run 16's drill A started the container once, rc 0, before its harness broke) are
# allowed if they are all successful and leave room for B: A adds 1, B needs >= 1 restart before the breaker (K=3)
A_PRE="$(jcount $(( $(date -u +%s) - 86400 )) action)"; A_ALL="$(jcount 0 action)"
echo "  actions already in the journal: $A_ALL ($A_PRE within 24 h); failed results: $(jl | jq -c 'select(.event == "result" and .rc != 0)' 2>/dev/null | wc -l)"
check "sentry selfheal: verdict healthy, breaker closed, actions_24h = journal actions in 24 h <= 1, actions_total = journal actions, every result rc 0" "$(ok_if '[ "$XRC" = 0 ] && grep -q "verdict healthy" <<<"$XOUT" && grep -q "actions_24h $A_PRE/3 | breaker closed" <<<"$XOUT" && [ "$A_PRE" -le 1 ] && grep -q "^pft_selfheal_actions_total{container=\"$SC\"} $A_ALL$" <<<"$XOUT" && [ "$(jl | jq -c "select(.event == \"result\" and .rc != 0)" | wc -l)" = 0 ]')"
x "R 'for f in $SH_CONF $REMOTE_ENVS /etc/pft-maint/ntfy.env; do sudo -n test -e \$f$SUF && echo leftover \$f$SUF; done; sudo -n test -e /etc/pft-maint/ntfy.env && echo maint-env-present; systemctl list-units --all --no-legend \"$DM*\" | wc -l; sudo -n iptables -S DOCKER-USER | grep -c $TAG'; for f in $LOCAL_ENVS; do sudo -n test -e \$f$SUF && echo leftover \$f$SUF; done; sudo -n test -e /etc/pft-maint/ntfy.env && echo maint-env-present; echo end"
check "no leftovers: no $SUF backups, no pft-maint ntfy.env on either host, no dead-man unit, no drill rule" "$(ok_if '[ "$(tr "\n" " " <<<"$XOUT")" = "0 0 end " ]')"
DU0="$(R "$DU")"
x "R '$DU'"
check "sentry DOCKER-USER: pft-egress jump at position 1, ESTABLISHED accept next" "$(ok_if 'sed -n 2p <<<"$XOUT" | grep -q -- "-j PFT-EGRESS" && sed -n 3p <<<"$XOUT" | grep -q "RELATED,ESTABLISHED -j ACCEPT"')"
CIP="$(scip)"
[[ "$CIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "  sentry container address not an IPv4 literal - stopping"; exit 3; }
printf 'ip\t%s\n' "$CIP" >> "$LIT"
R1=(-d "$CIP/32" -p tcp -m comment --comment "$TAG" -j REJECT --reject-with tcp-reset)
R2=(-s "$CIP/32" -p tcp -m comment --comment "$TAG" -j REJECT --reject-with tcp-reset)
DMCMD="sleep $DEADMAN_SEC; n=0; while iptables -C DOCKER-USER ${R1[*]} 2>/dev/null; do iptables -D DOCKER-USER ${R1[*]} && n=\$((n+1)); done; while iptables -C DOCKER-USER ${R2[*]} 2>/dev/null; do iptables -D DOCKER-USER ${R2[*]} && n=\$((n+1)); done; echo \"pft-selfheal-drill dead-man: deleted \$n rule(s)\""
dm_remote() { printf '%s /bin/bash -c %q' "$1" "$DMCMD"; }  # LAUNCHER -> sentry command line (quoted once for the sentry shell)
# run 16: the dead-man line was nested in hand-written quotes and broke at eval (`rule(s)`); the same two quoting levels
# (x's eval + the sentry shell) are proven here with a printf launcher: the sentry must receive DMCMD byte for byte
x "R $(printf %q "$(dm_remote "printf '%s\\n'")")"
check "dead-man command reaches the sentry byte-identical through both quoting levels (printf launcher)" "$(ok_if '[ "$XRC" = 0 ] && [ "$(sed -n 3p <<<"$XOUT")" = "$DMCMD" ] && [ "$(wc -l <<<"$XOUT")" = 3 ]')"
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-selfheal\") | .rules[] | [.name, .health, .state] | @tsv'"
check "selfheal rules loaded, healthy, inactive" "$(ok_if '[ "$(grep -cE "^PFTSelfheal(BreakerOpen|Stale)	ok	inactive$" <<<"$XOUT")" = 2 ]')"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.labels.host // .labels.container // \"-\") \(.state)\"' | sort"
UNK="$(grep -vE "^(PFTAlertPipelineWatchdog${KNOWN_PENDING:+|$KNOWN_PENDING}) " <<<"$XOUT" | grep -c .)"
[ "$UNK" = 0 ] || { echo "  alerts other than the watchdog${KNOWN_PENDING:+ and KNOWN_PENDING} pending/firing - stopping"; exit 4; }
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
s="$(sstate)"; ST0="$(sstarted)"; HC0="$(shcfg)"; echo "  $SC: server_state=$s peers=$(speers) StartedAt=$ST0"; echo "  $SC: $HC0"
case "$s" in full|proposing) ;; *) echo "  sentry not full - stopping"; exit 4 ;; esac
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean - stopping"; exit 4 ;; esac
done
x "R 'sudo -n pft-egress check --container $SC | tail -n 1'"
check "sentry pft-egress check PASS before the drill" "$(ok_if 'grep -q "RESULT: PASS" <<<"$XOUT"')"   # run 13: `| tail` hid the exit code
for h in local relay; do x "on $h 'sudo -n pft-maint active; echo maint-active rc \$?; sudo -n pft-maint lock list'"
  grep -qx 'maint-active rc 0' <<<"$XOUT" && { echo "  a pft-maint window is already active - stopping"; exit 4; }
  grep -qx 'no data-collection locks' <<<"$XOUT" || { echo "  a pft-maint lock is held - stopping"; exit 4; }; done
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "  redaction control FAILED - stopping"; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed ($FAILS check(s) failed)"; [ "$FAILS" = 0 ]; exit; fi
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 1. throwaway targets, catch-all silence, drill conf on the sentry"
redirect() { # HOST PATH -> notifier env pointed at the ALERT topic, original kept as PATH$SUF (cp -p)
  local h="$1" f="$2"
  FSHA["$h:$f"]="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
  [[ "${FSHA[$h:$f]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $h:$f unreadable - stopping"; exit 3; }
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $h:$f (sha256 ${FSHA[$h:$f]:0:12}) -> $NTFY/<redacted> (ALERT), original kept as $f$SUF"
}
for f in $LOCAL_ENVS; do redirect local "$f"; done
for f in $REMOTE_ENVS; do redirect relay "$f"; done
for h in local relay; do
  CREATED+=("$h:/etc/pft-maint/ntfy.env")
  on "$h" "sudo -n sh -c 'umask 077; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $MT > /etc/pft-maint/ntfy.env'" || { echo "  $h pft-maint ntfy.env not created - stopping"; exit 3; }
  echo "  $h:/etc/pft-maint/ntfy.env created for the drill only -> $NTFY/<redacted> (MAINT)"
done
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-selfheal sentry drills $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTSelfheal.*", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "selfheal-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTSelfheal.*\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
[ "$FAILS" = 0 ] || exit 3
FSHA["relay:$SH_CONF"]="$(R "sudo -n sha256sum -- $SH_CONF" | cut -c1-64)"
R "sudo -n cp -p $SH_CONF $SH_CONF$SUF" || { echo "  backup of the sentry selfheal conf failed - stopping"; exit 3; }
MOVED+=("relay:$SH_CONF")
KRE="$(for kv in $DRILL_KEYS; do printf '%s|' "${kv%%=*}"; done)"; KRE="${KRE%|}"
{ R "sudo -n cat $SH_CONF$SUF" | grep -vE "^($KRE)="; echo "# drill conf ($TASK $RUN), restored at the end"; for kv in $DRILL_KEYS; do echo "$kv"; done; } > "$SEC/drill.conf"
ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes relay "sudo -n sh -c 'umask 022; cat > $SH_CONF.new && mv -f $SH_CONF.new $SH_CONF'" < "$SEC/drill.conf"
x "R \"sudo -n stat -c '%a %U' $SH_CONF; sudo -n grep -v '^#' $SH_CONF | grep .\""
check "sentry drill conf (root 644): $DRILL_KEYS, MAX_ACTIONS=3 unchanged" "$(ok_if '[ "$XRC" = 0 ] && grep -qx "644 root" <<<"$XOUT" && grep -qx MODE=enforce <<<"$XOUT" && grep -qx MAX_ACTIONS=3 <<<"$XOUT" && grep -qx GRACE_SEC=120 <<<"$XOUT" && [ "$(grep -c "^MODE=" <<<"$XOUT")" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
wait_until 150 10 'grep -q "mode enforce | verdict healthy" <<<"$(sstatus)"'
x "sstatus"
check "next sentry run: mode enforce, verdict healthy (after ${WAITED}s)" "$(ok_if 'grep -q "mode enforce | verdict healthy" <<<"$XOUT"')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. drill A: stopped container -> one action"
tA="$(date -u +%s)"
x "R 'sudo -n docker stop -t 60 $SC'"
check "docker stop $SC" "$XRC"
wait_until 300 10 '[ "$(jcount "$tA" result)" -ge 1 ]'
echo "  $(ts): action results since the stop: $(jcount "$tA" result) (waited ${WAITED}s)"
wait_until 600 15 'case "$(sstate)" in full|proposing) true ;; *) false ;; esac'
echo "  $(ts): $SC server_state $(sstate), peers $(speers) ($(( $(date -u +%s) - tA ))s after the stop)"
x "jshow $tA"
check "A: exactly one action, 'up' = docker start (container_down), rc 0, pft-egress reapply rc 0" "$(ok_if '[ "$(grep -c "\"event\":\"action\"" <<<"$XOUT")" = 1 ] && grep -q "\"event\":\"action\",\"action\":\"up\",\"cmd\":\"docker start $SC\"" <<<"$XOUT" && grep -q "\"event\":\"result\",\"action\":\"up\",\"rc\":0,\"egress_rc\":0" <<<"$XOUT" && grep -q "\"detector\":\"container_down\"" <<<"$XOUT"')"
s="$(sstate)"; check "A: $SC full again" "$(ok_if '[[ "$s" =~ ^(full|proposing)$ ]]')" "$s"
HC1="$(shcfg)"; echo "  after: $HC1"
check "A: CpuShares, MemoryReservation, Memory, restart policy and confinement unchanged by the start" "$(ok_if '[ "$HC1" = "$HC0" ]')"
x "R 'sudo -n pft-egress check --container $SC | tail -n 1'"
check "A: sentry pft-egress check PASS after the start" "$(ok_if 'grep -q "RESULT: PASS" <<<"$XOUT"')"   # run 13: `| tail` hid the exit code
CIP1="$(scip)"; check "A: container address unchanged (the drill B rules match it)" "$(ok_if '[ "$CIP1" = "$CIP" ]')"
[ "$FAILS" = 0 ] || exit 5

echo; echo "== 3. drill C: maintenance window -> zero actions"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK selfheal drill C (maintenance suppression)'"
[ "$XRC" = 0 ] && MAINT=1; check "pft-maint window open on the validator" "$XRC"
wait_until 420 10 'R "sudo -n pft-maint active" >/dev/null 2>&1'; check "sentry has the window (via the watchdog channel) after ${WAITED}s" "$?"
[ "$FAILS" = 0 ] || exit 5
tC="$(date -u +%s)"
x "R 'sudo -n docker stop -t 60 $SC'"
check "docker stop $SC inside the window" "$XRC"
wait_until 300 10 '[ "$(jl | jq -c --argjson t "$tC" "select(.ts >= \$t and .suppressed_by == \"maintenance\")" | wc -l)" -ge 3 ]'
echo "  $(ts): $WAITED s after the stop"
x "jshow $tC"
check "C: >= 3 decisions container_down suppressed_by maintenance, 0 actions" "$(ok_if '[ "$(grep -c "\"detector\":\"container_down\".*\"suppressed_by\":\"maintenance\"" <<<"$XOUT")" -ge 3 ] && ! grep -q "\"event\":\"action\"" <<<"$XOUT"')"
x "R 'sudo -n docker inspect -f {{.State.Running}} $SC'"
check "C: container still stopped (selfheal did not start it)" "$(ok_if '[ "$XOUT" = false ]')"
x "R 'sudo -n docker start $SC && sudo -n pft-egress reapply --container $SC | tail -n 1'"
check "C: the drill (operator) starts the container itself + pft-egress reapply" "$XRC"
wait_until 600 15 'case "$(sstate)" in full|proposing) true ;; *) false ;; esac'
echo "  $(ts): $SC server_state $(sstate), peers $(speers)"
x "sudo -n pft-maint end --reason '$TASK selfheal drill C done'"
MAINT=0; check "window ended" "$XRC"
wait_until 420 10 '! R "sudo -n pft-maint active" >/dev/null 2>&1'; check "sentry window gone after ${WAITED}s" "$?"
check "C: still 0 actions since the window opened" "$(ok_if '[ "$(jcount "$tC" action)" = 0 ]')"
CIP1="$(scip)"; check "C: container address unchanged" "$(ok_if '[ "$CIP1" = "$CIP" ]')"
[ "$FAILS" = 0 ] || exit 5

echo; echo "== 4. drill B: unfixable peer fault -> at most K actions -> breaker -> dead-man -> reset"
echo "  dead-man command: $DMCMD" | red
x "R $(printf %q "$(dm_remote "sudo -n systemd-run --collect --unit=$DM --description=$(printf %q 'pft-selfheal drill dead-man: deletes the drill REJECT rules') -p RuntimeMaxSec=$(( DEADMAN_SEC + 120 ))")")"
t_dm="$(date -u +%s)"
check "dead-man $DM.service started on the sentry (deletes the rules at $(date -u -d "@$(( t_dm + DEADMAN_SEC ))" +%TZ))" "$(ok_if '[ "$XRC" = 0 ] && R "systemctl is-active --quiet $DM.service"')"
[ "$FAILS" = 0 ] || exit 5
tB="$(date -u +%s)"; BROKEN=1
x "R 'sudo -n iptables -I DOCKER-USER 2 ${R1[*]} && sudo -n iptables -I DOCKER-USER 2 ${R2[*]} && $DU'"
check "two drill rules at DOCKER-USER 2-3, after the pft-egress jump and before the established accept" "$(ok_if '[ "$XRC" = 0 ] && sed -n 2p <<<"$XOUT" | grep -q -- "-j PFT-EGRESS" && [ "$(sed -n 3,4p <<<"$XOUT" | grep -c "$TAG")" = 2 ] && sed -n 5p <<<"$XOUT" | grep -q "RELATED,ESTABLISHED -j ACCEPT"')"
wait_until 240 10 '[ "$(speers)" = 0 ]'; echo "  $(ts): $SC peers $(speers) after ${WAITED}s"
check "B: sentry peers 0 with the fault in place" "$(ok_if '[ "$(speers)" = 0 ]')"
A0="$(jcount $(( tB - 86400 )) action)"; echo "  actions in the 24 h budget before B: $A0 (journal total $(jcount 0 action))"
wait_until $(( DEADMAN_SEC - 180 )) 15 '[ "$(sval pft_selfheal_breaker_open)" = 1 ]'
t_open="$(date -u +%s)"; echo "  $(ts): breaker_open $(sval pft_selfheal_breaker_open) $(( t_open - tB ))s after the fault"
x "jshow $tB"
NB="$(grep -c '"event":"action"' <<<"$XOUT")"
check "B: breaker OPEN before the dead-man fired" "$(ok_if '[ "$(sval pft_selfheal_breaker_open)" = 1 ] && [ "$(rules_present)" = 2 ]')"
check "B: $NB restart(s) during B, $((A0 + NB)) actions in 24 h <= K=3 when the breaker opened, every restart rc 0 + egress rc 0" "$(ok_if '[ "$NB" -ge 1 ] && [ $((A0 + NB)) -le 3 ] && [ "$(grep -c "\"event\":\"result\",\"action\":\"restart\",\"rc\":0,\"egress_rc\":0" <<<"$XOUT")" = "$NB" ]')"
CIP1="$(scip)"; check "B: container address unchanged by the restarts (fault still applies)" "$(ok_if '[ "$CIP1" = "$CIP" ]')"
wait_until 300 15 'pq "ALERTS{alertname=\"PFTSelfhealBreakerOpen\",alertstate=\"firing\"}" | grep -q "container=$SC"'
check "B: PFTSelfhealBreakerOpen{container=$SC} firing in Prometheus ($(( $(date -u +%s) - t_open ))s after the breaker opened)" "$?"
wait_until 240 15 '[ "$(n_msgs FIRING)" -ge 1 ]'; check "B: [FIRING] PFTSelfhealBreakerOpen for $SC on the throwaway topic" "$?"
x "sstatus"
check "B: status exit 2, breaker OPEN" "$(ok_if '[ "$XRC" = 2 ] && grep -q "breaker OPEN" <<<"$XOUT"')"
echo "  waiting for the dead-man ($(( t_dm + DEADMAN_SEC - $(date -u +%s) ))s left); no further action may run"
wait_until $(( DEADMAN_SEC + 180 )) 10 '! R "systemctl is-active --quiet $DM.service"'
t_rest="$(date -u +%s)"
x "R 'sudo -n journalctl --utc -o short-iso -u $DM.service --since @$t_dm --no-pager' | grep -E 'dead-man|Started|Deactivated|Finished'"
check "dead-man deleted exactly 2 rules" "$(ok_if 'grep -q "dead-man: deleted 2 rule(s)" <<<"$XOUT"')"
BROKEN=0
check "sentry DOCKER-USER identical to the pre-run snapshot after the dead-man" "$(ok_if '[ "$(R "$DU")" = "$DU0" ]')"
check "B: no action between the breaker opening and the dead-man ($(( t_rest - t_open ))s)" "$(ok_if '[ "$(jcount "$t_open" action)" = 0 ]')"
wait_until 900 15 '[ "$(speers)" -gt 0 ] 2>/dev/null && case "$(sstate)" in full|proposing) true ;; *) false ;; esac'
echo "  $(ts): $SC server_state $(sstate), peers $(speers), $(( $(date -u +%s) - t_rest ))s after the dead-man"
s="$(sstate)"; check "B: node recovered by itself (full, peers > 0) without a selfheal action" "$(ok_if '[[ "$s" =~ ^(full|proposing)$ ]] && [ "$(jcount "$t_open" action)" = 0 ]')" "$s"
sleep 70
x "sstatus"
check "B: breaker still OPEN after recovery (manual reset needed)" "$(ok_if '[ "$XRC" = 2 ] && grep -q "breaker OPEN" <<<"$XOUT"')"
x "R \"sudo -n pft-selfheal reset --container $SC --reason '$TASK drill B: fault removed by the dead-man, node full'\""
check "pft-selfheal reset exit 0" "$XRC"
wait_until 150 10 '[ "$(sval pft_selfheal_breaker_open)" = 0 ]'
x "sstatus"
check "B: after reset: breaker closed, verdict healthy, status exit 0" "$(ok_if '[ "$XRC" = 0 ] && grep -q "breaker closed" <<<"$XOUT" && grep -q "verdict healthy" <<<"$XOUT"')"
wait_until 600 15 '[ -z "$(pq "ALERTS{alertname=\"PFTSelfhealBreakerOpen\"}")" ] && [ "$(n_msgs RESOLVED)" -ge 1 ]'
check "B: PFTSelfhealBreakerOpen gone from Prometheus and [RESOLVED] on the throwaway topic" "$?"
x "jshow $tA"
echo "  journal totals since drill A: actions $(jcount "$tA" action), results $(jcount "$tA" result), resets $(jcount "$tA" reset)"

echo; echo "== 5. restore, ALERTS query_range, read back"
restore
check "drill conf + notifier envs restored byte-identical, drill-only files removed, bridge back, alertpath OK, no abort path" "$(ok_if '[ "$RESTORE_OK" = true ]')"
x "R 'sudo -n grep -E \"^MODE=\" $SH_CONF'"
check "sentry selfheal back in dryrun" "$(ok_if '[ "$XOUT" = MODE=dryrun ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"PFTSelfheal.*\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) container=\(.metric.container) \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "query_range: PFTSelfhealBreakerOpen{container=$SC} firing during the run, PFTSelfhealStale never" "$(ok_if 'grep -qE "^PFTSelfhealBreakerOpen container=$SC firing " <<<"$XOUT" && ! grep -q "^PFTSelfhealStale" <<<"$XOUT"')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=pft_selfheal_breaker_open or pft_selfheal_actions_24h' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=60 | jq -r '.data.result[] | \"\(.metric.__name__) \(.metric.container) \([.values[] | .[1]] | join(\"\"))\"'"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the env restores: drift_items 0" "$(ok_if '! grep -qv "} 0$" <<<"$XOUT" && grep -q "} 0$" <<<"$XOUT"')"
sleep 30
readback() { # TOPIC LABEL [quiet]
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"; echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message: (.message | .[0:160])}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$ALERT" "throwaway (alerts + notifiers)"
readback "$MT" "throwaway (pft-maint)"
check "pft-maint [MAINT] start + end of drill C reached its throwaway topic" "$(ok_if '[ "$N_MSG" -ge 2 ]')"
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts, 0 denials" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 4 ] && [ "$(grep -c " 0 DENIED events" <<<"$XOUT")" = 2 ]')"
x "R 'sudo -n pft-egress check --container $SC | tail -n 1'"
check "sentry pft-egress check PASS at the end" "$(ok_if 'grep -q "RESULT: PASS" <<<"$XOUT"')"   # run 13: `| tail` hid the exit code
s="$(sstate)"; HC1="$(shcfg)"
check "$SC full at the end, HostConfig/confinement as before the run" "$(ok_if '[[ "$s" =~ ^(full|proposing)$ ]] && [ "$HC1" = "$HC0" ]')" "$s"
x "sudo -n pft-maint status --json | jq -r .window; R 'sudo -n pft-maint status --json' | jq -r .window"
check "no pft-maint window left on either host" "$(ok_if '[ "$(grep -cx none <<<"$XOUT")" = 2 ]')"
x "R 'systemctl list-units --all --no-legend \"$DM*\" \"run-u*.service\" \"run-u*.timer\" | wc -l'; systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l"
check "no dead-man or other transient unit left on either host" "$(ok_if '[ "$(tr "\n" " " <<<"$XOUT")" = "0 0 " ]')"
echo; echo "sentry-drill done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
