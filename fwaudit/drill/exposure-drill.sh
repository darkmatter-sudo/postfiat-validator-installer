#!/usr/bin/env bash
# exposure-drill: recorded two-host temporary-listener / published-port drill for pft-fwaudit
# (task_32d07e3a14bbfa7a29550f1d3c287263, step 4). Built from ../../selfheal/drill/sentry-drill.sh (notifier redirect,
# bridge swap, catch-all silence, drain, quiet gate, read-back; PASS selfheal log 25).
# Two real faults, one per host, each found by the INSTALLED pft-fwaudit through its real units, textfile, pull,
# Prometheus rule, Alertmanager and bridge (pointed at a throwaway topic), then fixed and re-verified:
#   S  sentry: a temporary TCP listener (transient unit fwaudit-drill-listen, User=nobody, IPv4 0.0.0.0:LP, answers
#      one line and closes) + `ufw allow proto tcp to any port LP comment fwaudit-drill` (v4 + v6 rule).
#      Expected: FAIL undeclared-exposure v4/tcp/LP (path input) + WARN stale-allow v6/tcp/LP (no v6 listener).
#      Fix: `pft-fwaudit apply --yes` in a pft-maint window (plan deletes both UFW rules, re-audit, dead-man PASS).
#      The listener keeps running after the fix: it must then be unreachable and the audit PASS (a listener alone is
#      not exposure); then it is stopped.
#   V  validator: a throwaway container (image already on the host, `--pull never`, read-only, no capabilities,
#      uid 65534, 64 MiB, 16 pids) published on 0.0.0.0:PP. Expected: FAIL undeclared-exposure v4/tcp/PP on the
#      Docker DNAT path (UFW is not on that path). `plan` lists it as MANUAL; fix: remove the container.
#   Both: an own-host connect from the other host proves reachable during the fault and blocked after the fix;
#   PFTFwauditExposure{host=sentry} and {host=validator} FIRING then RESOLVED on the throwaway topic.
# Safety: an independent dead-man unit on each host (started before any fault) removes the drill rules / listener /
# container after DM_SEC whatever happens to this script; the EXIT trap removes them too.
# Notifiers: every ntfy env on both hosts -> throwaway ALERT topic; drill-only pft-maint ntfy.env on both hosts ->
# throwaway MAINT topic; Alertmanager bridge -> ALERT topic (sentry alertpath paused around the bridge re-create);
# catch-all silence except the pipeline watchdog and PFTFwaudit*, expired only when nothing but the watchdog
# (+ KNOWN_PENDING) is pending/firing in Prometheus and active in Alertmanager; every operator topic is read back
# after expiry + group_interval + 30 s (must be 0 messages).
#   bash fwaudit/drill/exposure-drill.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
#   PREFLIGHT_ONLY=1 bash fwaudit/drill/exposure-drill.sh   (step 0 only; changes nothing)
# Env: KNOWN_PENDING (regex of alert names pending before the run)  DM_SEC (2700)  SIL_TTL (120 min)
#      FIRE_WAIT (720)  DRAIN_WAIT (600)  QUIET_WAIT (1200)
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
DM_SEC="${DM_SEC:-2700}"; SIL_TTL="${SIL_TTL:-120}"; FIRE_WAIT="${FIRE_WAIT:-720}"
DRAIN_WAIT="${DRAIN_WAIT:-600}"; QUIET_WAIT="${QUIET_WAIT:-1200}"; AP_WAIT=180
TASK=task_32d07e3a
SHA="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile
SUF=.pre-fwaudit-drill
LU=fwaudit-drill-listen; DU=fwaudit-drill-deadman; CN=fwaudit-drill-pub; IMG=python:3.12-alpine; TAGC=fwaudit-drill
SC=postfiatd-sentry

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="fwdrill-$(rnd)"; MT="fwmaint-$(rnd)"
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
wait_until() { # SECONDS STEP CONDITION -> 0 when CONDITION became true; sets WAITED
  local t0; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$1" ]; do eval "$3" && { WAITED=$(( $(date -u +%s) - t0 )); return 0; }; sleep "$2"; done
  WAITED=$(( $(date -u +%s) - t0 )); eval "$3"; }
si() { if [ "$1" = relay ]; then R "sudo -n docker exec $SC curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"
  else sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005; fi; }
sstate() { si "$1" | jq -r '.result.info.server_state // "down"' 2>/dev/null || echo down; }
addrs() { # [remote] -> "V4 V6" (as ./tcp-crosscheck.sh: first global address of each family on the default-route interface)
  local cmd='dev=$(ip -4 route show default | awk "{print \$5; exit}"); a4=$(ip -4 -o addr show dev "$dev" scope global | awk "{print \$4; exit}"); a6=$(ip -6 -o addr show dev "$dev" scope global | awk "{print \$4; exit}"); echo "${a4%/*} ${a6%/*}"'
  if [ "${1:-}" = remote ]; then R "$cmd"; else bash -c "$cmd"; fi; }
PROBE='b=$(timeout 6 bash -c '"'"'exec 3<>"/dev/tcp/$0/$1" && timeout 3 head -c 14 <&3'"'"' "$A" "$P" 2>/dev/null); rc=$?; case $rc in 0) if [ "$b" = fwaudit-drill ]; then echo connected; else echo open-no-banner; fi ;; 124) echo timeout ;; *) echo "refused rc=$rc" ;; esac'
probe() { # FROM(local|relay) ADDR PORT -> "connected" (banner fwaudit-drill read) | "open-no-banner" | "timeout" | "refused rc=N"
  local out; out="$(on "$1" "A=$2 P=$3; $PROBE")"; echo "$out"; }
fwa() { on "$1" "sudo -n pft-fwaudit $2"; }               # HOST ARGS -> the installed pft-fwaudit
ajson() { fwa "$1" "audit --json"; }
fkeys() { jq -r '[.findings[] | select(.port) | "\(.severity) \(.class) \(.family)/\(.proto)/\(.port)"] | sort | .[]' 2>/dev/null; }
pq() { curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
n_msgs() { # STATUS HOST -> number of [STATUS] PFTFwauditExposure messages on the ALERT topic whose body names HOST
  topic_msgs "$ALERT" | jq -r --arg t "[$1] PFTFwauditExposure" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' | grep -c "^$2: inbound exposure audit"; }
fw_active() { # Prometheus ALERTS + unsilenced AM alerts named PFTFwaudit* -> count
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname=~"PFTFwaudit.*"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq '[.[] | select(.labels.alertname | test("^PFTFwaudit"))] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
others_active() { # alerts other than the watchdog + KNOWN_PENDING: Prometheus pending/firing + AM active (silenced included)
  local re p a; re="^(PFTAlertPipelineWatchdog${KNOWN_PENDING:+|$KNOWN_PENDING})\$"
  p="$(curl -s --max-time 10 "$PROM/api/v1/alerts" | jq --arg re "$re" '[.data.alerts[] | select(.labels.alertname | test($re) | not)] | length' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=true&inhibited=true" | jq --arg re "$re" '[.[] | select(.labels.alertname | test($re) | not)] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
textfiles() { # run the real audit units on both hosts, then the validator's pull of the sentry textfile
  R "sudo -n systemctl start pft-fwaudit.service" && sudo -n systemctl start pft-fwaudit.service \
    && sudo -n systemctl start pft-fwaudit-pull.service && echo "pft-fwaudit.service (both) + pft-fwaudit-pull.service: done"; }
tfval() { # HOST METRIC_WITH_LABELS -> value in the validator's textfile dir
  grep -h "^$2 " "$TF/pft_fwaudit_$1.prom" 2>/dev/null | awk '{print $2}'; }
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

# --- the faults and their removal (also used by the dead-men and the EXIT trap) ---
LISTENER_PY="$(base64 -w0 <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[-1])))
s.listen(8)
while True:
    c, _ = s.accept()
    try:
        c.sendall(b"fwaudit-drill\n")
    except OSError:
        pass
    c.close()
PY
)"
LCMD() { printf "python3 -I -c 'import base64,sys; exec(base64.b64decode(sys.argv[1]))' %s %s" "$LISTENER_PY" "$1"; }  # PORT (program via argv: no nested quotes)
UFWDEL='n=0; while :; do k=$(ufw status numbered | sed -nE "s/^\[ *([0-9]+)\] .*# fwaudit-drill *$/\1/p" | tail -n 1); [ -n "$k" ] || break; ufw --force delete "$k" >/dev/null || break; n=$((n+1)); done; echo "deleted $n fwaudit-drill ufw rule(s)"'
DMS="sleep $DM_SEC; systemctl stop $LU.service >/dev/null 2>&1; $UFWDEL; echo 'fwaudit drill dead-man (sentry) done'"
DMV="sleep $DM_SEC; docker rm -f $CN >/dev/null 2>&1 && echo 'fwaudit drill dead-man: removed $CN' || echo 'fwaudit drill dead-man: no $CN'"
dm_remote() { printf '%s /bin/bash -c %q' "$1" "$DMS"; }  # LAUNCHER -> sentry command line (quoted once for the sentry shell)
s_leftovers() { R "systemctl list-units --all --no-legend '$LU*' '$DU*' 'fwaudit-deadman*' | wc -l; sudo -n ufw status | grep -c '# $TAGC'"; }
v_leftovers() { systemctl list-units --all --no-legend "$DU*" | wc -l; sudo -n docker ps -a --filter "name=^$CN\$" -q | wc -l; }

declare -A FSHA=()
declare -a MOVED=() CREATED=()
RESTORED=0; RESTORE_OK=true; SIL=""; SBODY=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; MAINT=0; FAULTS=0
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha
  if [ "$FAULTS" = 1 ]; then
    echo "  ABORT PATH: faults still marked in place at restore - removing them here (not the drill's own fix)"
    R "sudo -n systemctl stop $LU.service >/dev/null 2>&1; sudo -n bash -c $(printf %q "$UFWDEL")"
    sudo -n docker rm -f "$CN" >/dev/null 2>&1
    RESTORE_OK=false; FAULTS=0
  fi
  R "sudo -n systemctl stop $DU.service >/dev/null 2>&1; sudo -n systemctl reset-failed $DU.service $LU.service >/dev/null 2>&1"
  sudo -n systemctl stop "$DU.service" >/dev/null 2>&1; sudo -n systemctl reset-failed "$DU.service" >/dev/null 2>&1
  for k in "${MOVED[@]}"; do   # notifier envs (cp -p backups: bytes, mode, mtime)
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${FSHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
  MOVED=()
  if [ "$MAINT" = 1 ]; then echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'; MAINT=0; fi
  for k in "${CREATED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n rm -f $f"
    if on "$h" "sudo -n test -e $f"; then echo "  removed drill-only $k: NO"; RESTORE_OK=false; else echo "  removed drill-only $k: yes"; fi
  done
  CREATED=()
  # collectors that read what the drill touched, after every env is restored/removed (selfheal runs 16/18/20):
  # keyescrow (notifier envs), fwaudit (rulesets), rulecheck (textfile freshness), and the validator pulls
  R "sudo -n systemctl start pft-keyescrow.service pft-fwaudit.service pft-integrity.service" \
    && sudo -n systemctl start pft-keyescrow.service pft-fwaudit.service pft-integrity.service \
    && sudo -n systemctl start pft-keyescrow-pull.service pft-fwaudit-pull.service \
    && R "sudo -n systemctl start pft-rulecheck.service" && sudo -n systemctl start pft-rulecheck.service \
    && sudo -n systemctl start pft-rulecheck-pull.service \
    && echo "  re-ran pft-keyescrow + pft-fwaudit + pft-integrity + pft-rulecheck (both) and the validator pulls: yes" \
    || { echo "  re-ran pft-keyescrow/pft-fwaudit/pft-rulecheck collectors + pulls: NO"; RESTORE_OK=false; }
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    local t0 n=1; t0="$(date -u +%s)"
    while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do n="$(fw_active)"; [ "$n" = 0 ] && break; sleep 10; done
    if [ "$n" = 0 ]; then echo "  drain: no PFTFwaudit* alert pending/firing/active after $(( $(date -u +%s) - t0 ))s; 90 s for RESOLVED delivery"; sleep 90; n="$(fw_active)"; fi
    if [ "$n" != 0 ]; then
      echo "  drain: NO - $n PFTFwaudit* alert(s) still active; extending the catch-all silence to cover PFTFwaudit* for 60 min"
      SBODY="$(jq -c '.matchers = [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog", isRegex: false, isEqual: false}]' <<<"$SBODY")"
      curl -s --max-time 10 -o /dev/null -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" \
        -d "$(jq -c --arg id "$SIL" --arg e "$(date -u -d '+60 min' +%FT%TZ)" '. + {id: $id, endsAt: $e}' <<<"$SBODY")"
      RESTORE_OK=false
    fi
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"; BRIDGE_SWAPPED=0
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-fwaudit exposure drill (S sentry temporary listener + UFW allow -> apply; V validator published port -> remove) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in fwaudit/drill/exposure-drill.sh fwaudit/pft-fwaudit.sh fwaudit/fwaudit_eval.py alerts/fwaudit.rules.yml peerexpose/drill/redact.py; do echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
git fetch -q origin; [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping"; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" && curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  AM/Prometheus not reachable - stopping"; exit 3; }
read -r V4 V6 <<<"$(addrs)"; read -r S4 S6 <<<"$(addrs remote)"
for ip in "$V4" "$V6" "$S4" "$S6" "$(ssh -G relay | awk '$1 == "hostname" { print $2 }')" "$(R 'echo "${SSH_CLIENT%% *}"')"; do
  [ -z "$ip" ] || printf 'ip\t%s\n' "$ip" >> "$LIT"; done
[[ "$V4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && [[ "$S4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "  a host has no global IPv4 address - stopping"; exit 3; }
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
for h in local relay; do k="$(si "$h" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"; done
x "sha256sum fwaudit/pft-fwaudit.sh fwaudit/fwaudit_eval.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-fwaudit /usr/local/lib/pft-fwaudit/fwaudit_eval.py | cut -c1-64; R 'sudo -n sha256sum /usr/local/bin/pft-fwaudit /usr/local/lib/pft-fwaudit/fwaudit_eval.py' | cut -c1-64"
check "installed pft-fwaudit + evaluator on both hosts = this checkout" "$(ok_if '[ "$(sort <<<"$XOUT" | uniq -c | awk "\$1 == 3" | wc -l)" = 2 ]')"
x "systemctl is-active pft-fwaudit.timer pft-fwaudit-pull.timer; R 'systemctl is-active pft-fwaudit.timer'"
check "fwaudit timers active (validator audit + pull, sentry audit)" "$(ok_if '[ "$(grep -cx active <<<"$XOUT")" = 3 ]')"
x "fwa local audit | tail -n 1; fwa relay audit | tail -n 1"
check "both hosts audit PASS before the drill" "$(ok_if '[ "$(grep -cx "RESULT: PASS" <<<"$XOUT")" = 2 ]')"
x "R 'sudo -n test -e /var/lib/pft-fwaudit/state.json && sudo -n jq -r .result /var/lib/pft-fwaudit/state.json || echo no-apply-state'; R 'systemctl is-active fwaudit-deadman.service'"
check "sentry: no apply pending (no state or not pending), no fwaudit-deadman running" "$(ok_if '! grep -qx pending <<<"$XOUT" && ! grep -qx active <<<"$XOUT"')"
x "s_leftovers; v_leftovers"
check "no leftovers: no drill units, no '# $TAGC' ufw rule, no $CN container" "$(ok_if '[ "$(tr "\n" " " <<<"$XOUT")" = "0 0 0 0 " ]')"
x "R 'for f in $REMOTE_ENVS /etc/pft-maint/ntfy.env; do sudo -n test -e \$f$SUF && echo leftover \$f$SUF; done; sudo -n test -e /etc/pft-maint/ntfy.env && echo maint-env-present; echo r-end'; for f in $LOCAL_ENVS; do sudo -n test -e \$f$SUF && echo leftover \$f$SUF; done; sudo -n test -e /etc/pft-maint/ntfy.env && echo maint-env-present; echo end"
check "no $SUF backups, no pft-maint ntfy.env on either host" "$(ok_if '[ "$(tr "\n" " " <<<"$XOUT")" = "r-end end " ]')"
x "sudo -n docker image inspect -f '{{.RepoTags}} {{.Id}}' $IMG | cut -c1-60"
check "image $IMG already on the validator (the drill never pulls)" "$XRC"
LP=""; PP=""
for c in $(shuf -i 18100-18899 -n 40); do  # free on both hosts, no UFW rule, not in a policy
  used="$(ss -Htan "( sport = :$c )" | wc -l) $(R "ss -Htan '( sport = :$c )' | wc -l; sudo -n ufw status | grep -c '^$c/'")"
  [ "$used" = "0 0
0" ] || continue
  if [ -z "$LP" ]; then LP="$c"; elif [ "$c" != "$LP" ]; then PP="$c"; break; fi
done
grep -qE "^allow +tcp +($LP|$PP) " fwaudit/policy/*.policy && LP=""
check "drill ports chosen: sentry listener LP=$LP, validator published PP=$PP (free on both hosts, not declared)" "$(ok_if '[ -n "$LP" ] && [ -n "$PP" ]')"
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-fwaudit\") | .rules[] | [.name, .health, .state] | @tsv'"
check "PFTFwauditExposure loaded, healthy, inactive" "$(ok_if '[ "$XOUT" = "PFTFwauditExposure	ok	inactive" ]')"
x "pq 'pft_fwaudit_findings{severity=\"fail\"} or pft_fwaudit_up' | sort"
check "Prometheus: pft_fwaudit_up 1 and 0 fail findings for host=validator and host=sentry" "$(ok_if '[ "$(grep -cE "__name__=pft_fwaudit_up,host=(validator|sentry).* 1$" <<<"$XOUT")" = 2 ] && [ "$(grep -cE "__name__=pft_fwaudit_findings,host=(validator|sentry),.*severity=fail.* 0$" <<<"$XOUT")" = 2 ]')"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.labels.host // .labels.instance // \"-\") \(.state)\"' | sort"
UNK="$(grep -vE "^(PFTAlertPipelineWatchdog${KNOWN_PENDING:+|$KNOWN_PENDING}) " <<<"$XOUT" | grep -c .)"
[ "$UNK" = 0 ] || { echo "  alerts other than the watchdog${KNOWN_PENDING:+ and KNOWN_PENDING} pending/firing - stopping"; exit 4; }
FIR="$(curl -s "$PROM/api/v1/alerts" | jq -r '[.data.alerts[] | select(.state == "firing" and .labels.alertname != "PFTAlertPipelineWatchdog")] | length')"
check "nothing but the watchdog FIRING (KNOWN_PENDING may only be pending: a firing alert would be re-sent after the bridge re-create)" "$(ok_if '[ "$FIR" = 0 ]')"
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
  s="$(sstate "$h")"; echo "  node $h: server_state=$s"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping"; exit 4 ;; esac
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean - stopping"; exit 4 ;; esac
  x "on $h 'sudo -n pft-maint active; echo maint-active rc \$?; sudo -n pft-maint lock list'"
  grep -qx 'maint-active rc 0' <<<"$XOUT" && { echo "  a pft-maint window is already active - stopping"; exit 4; }
  grep -qx 'no data-collection locks' <<<"$XOUT" || { echo "  a pft-maint lock is held - stopping"; exit 4; }
done
UFW0="$(R 'sudo -n ufw status numbered' | sha256sum | cut -c1-64)"; NAT0="$(sudo -n iptables -t nat -S DOCKER | sha256sum | cut -c1-64)"
FWD0="$(sudo -n iptables -S DOCKER | sha256sum | cut -c1-64)"
echo "  snapshots: sentry 'ufw status numbered', validator 'iptables -t nat -S DOCKER' and 'iptables -S DOCKER' (sha256 kept, compared at the end)"
x "R $(printf %q "$(dm_remote "printf '%s\\n'")")"
check "sentry dead-man command reaches the sentry byte-identical through both quoting levels (printf launcher)" "$(ok_if '[ "$XRC" = 0 ] && [ "$(sed -n 3p <<<"$XOUT")" = "$DMS" ] && [ "$(wc -l <<<"$XOUT")" = 3 ]')"
x "R \"python3 -I -c 'import base64,sys; c=base64.b64decode(sys.argv[1]); compile(c, sys.argv[2], sys.argv[2]); print(len(c.splitlines()))' $LISTENER_PY exec\""
check "listener program decodes and compiles on the sentry (12 lines)" "$(ok_if '[ "$XRC" = 0 ] && [ "$(tail -n 1 <<<"$XOUT")" = 12 ]')"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "  redaction control FAILED - stopping"; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed ($FAILS check(s) failed)"; [ "$FAILS" = 0 ]; exit; fi
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 1. throwaway targets, catch-all silence"
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
  on "$h" "sudo -n install -o root -g root -m 600 /dev/null /etc/pft-maint/ntfy.env && printf 'NTFY_SERVER=%s\nNTFY_TOPIC=%s\n' $NTFY $MT | sudo -n tee /etc/pft-maint/ntfy.env >/dev/null" \
    || { echo "  $h pft-maint ntfy.env not created - stopping"; exit 3; }
  echo "  $h:/etc/pft-maint/ntfy.env created for the drill only (600) -> $NTFY/<redacted> (MAINT)"
done
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-fwaudit exposure drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTFwaudit.*", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "fwaudit-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTFwaudit.*\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. dead-men first (remove every fault after ${DM_SEC}s whatever happens to this script)"
x "R $(printf %q "$(dm_remote "sudo -n systemd-run --collect --unit=$DU --description=fwaudit-drill-dead-man -p RuntimeMaxSec=$(( DM_SEC + 120 ))")")"
check "sentry $DU.service started" "$(ok_if '[ "$XRC" = 0 ] && R "systemctl is-active --quiet $DU.service"')"
x "sudo -n systemd-run --collect --unit=$DU --description=fwaudit-drill-dead-man -p RuntimeMaxSec=$(( DM_SEC + 120 )) /bin/bash -c \"\$DMV\""
check "validator $DU.service started" "$(ok_if '[ "$XRC" = 0 ] && systemctl is-active --quiet $DU.service')"
echo "  dead-men delete the faults at $(date -u -d "+$DM_SEC sec" +%TZ)"
[ "$FAILS" = 0 ] || exit 5

echo; echo "== 3. faults: S sentry listener + UFW allow, V validator published port"
FAULTS=1; tF="$(date -u +%s)"
x "R \"sudo -n systemd-run --collect --unit=$LU --description=fwaudit-drill-listener -p User=nobody -p NoNewPrivileges=yes -p RuntimeMaxSec=$DM_SEC $(LCMD "$LP")\""
check "S: listener unit started on the sentry" "$(ok_if '[ "$XRC" = 0 ]')"
x "R 'sudo -n ufw allow proto tcp to any port $LP comment $TAGC && sudo -n ufw status | grep \"# $TAGC\"'"
check "S: UFW allow tcp/$LP added (v4 + v6 rule, comment $TAGC)" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -c "# $TAGC" <<<"$XOUT")" = 2 ]')"
x "sudo -n docker run -d --pull never --name $CN --label pft.drill=fwaudit --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --memory 64m --pids-limit 16 -p 0.0.0.0:$PP:8080 $IMG $(LCMD 8080) | cut -c1-12"
check "V: container $CN publishes 0.0.0.0:$PP -> 8080" "$XRC"
sleep 3
x "R \"ss -Htln '( sport = :$LP )'\"; ss -Htln '( sport = :$PP )'"
check "listeners up: sentry 0.0.0.0:$LP, validator docker-proxy 0.0.0.0:$PP" "$(ok_if '[ "$(grep -c "0.0.0.0:$LP " <<<"$XOUT")" = 1 ] && [ "$(grep -c "0.0.0.0:$PP " <<<"$XOUT")" = 1 ]')"
x "probe local $S4 $LP; probe relay $V4 $PP"
check "own-host connects during the fault: validator -> sentry v4 tcp/$LP and sentry -> validator v4 tcp/$PP both connected" "$(ok_if '[ "$(grep -c "^connected" <<<"$XOUT")" = 2 ]')"
SA="$(ajson relay)"; VA="$(ajson local)"
x "fwa relay audit"
x "fkeys <<<\"\$SA\""
check "S: sentry audit FAIL: undeclared-exposure v4/tcp/$LP + stale-allow v6/tcp/$LP" "$(ok_if '[ "$(jq -r .verdict <<<"$SA")" = FAIL ] && grep -qx "FAIL undeclared-exposure v4/tcp/$LP" <<<"$XOUT" && grep -qx "WARN stale-allow v6/tcp/$LP" <<<"$XOUT" && [ "$(grep -c "/tcp/$LP$" <<<"$XOUT")" = 2 ] && [ "$(grep -c "^FAIL" <<<"$XOUT")" = 1 ]')"
x "jq -c --argjson p $LP '.exposure[] | select(.port == \$p) | {family, state, paths, owners, declared}' <<<\"\$SA\""
check "S: exposure v4/tcp/$LP open via input, owner python3, not declared" "$(ok_if 'grep -q "\"family\":\"v4\",\"state\":\"open\",\"paths\":\[\"input\"\],\"owners\":\[\"python3\"\],\"declared\":false" <<<"$XOUT"')"
x "fwa local audit"
x "fkeys <<<\"\$VA\""
check "V: validator audit FAIL: undeclared-exposure v4/tcp/$PP (only new finding)" "$(ok_if '[ "$(jq -r .verdict <<<"$VA")" = FAIL ] && grep -qx "FAIL undeclared-exposure v4/tcp/$PP" <<<"$XOUT" && [ "$(grep -c "^FAIL" <<<"$XOUT")" = 1 ]')"
x "jq -c --argjson p $PP '.exposure[] | select(.port == \$p) | {family, state, paths, owners, declared}' <<<\"\$VA\""
check "V: exposure v4/tcp/$PP open on the Docker DNAT path, not declared" "$(ok_if 'grep -q "\"family\":\"v4\",\"state\":\"open\"" <<<"$XOUT" && grep -q "docker-forward->8080" <<<"$XOUT" && grep -q "\"declared\":false" <<<"$XOUT"')"
x "fwa relay plan; fwa local plan"
x "fwa relay 'plan --json' | jq -c '[.actions[] | {op, family, port, why}]'; fwa local 'plan --json' | jq -c '[.manual[] | select(.why == \"undeclared-exposure\" and (.message | startswith(\"tcp/$PP v4 \")))] | length'"
check "plans: sentry deletes the v4 + v6 rule for tcp/$LP (2 actions, nothing else); validator lists tcp/$PP as MANUAL" "$(ok_if '[ "$(head -n 1 <<<"$XOUT" | jq "[.[] | select(.op == \"delete\" and .port == $LP)] | length")" = 2 ] && [ "$(head -n 1 <<<"$XOUT" | jq length)" = 2 ] && [ "$(tail -n 1 <<<"$XOUT")" = 1 ]')"
x "textfiles"
check "textfiles written by the real units, sentry copy pulled" "$XRC"
x "grep -h 'pft_fwaudit_findings{.*severity=\"fail\"}' $TF/pft_fwaudit_validator.prom $TF/pft_fwaudit_sentry.prom"
check "textfiles: fail findings 1 for host=validator and host=sentry" "$(ok_if '[ "$(tfval validator "pft_fwaudit_findings{host=\"validator\",severity=\"fail\"}")" = 1 ] && [ "$(tfval sentry "pft_fwaudit_findings{host=\"sentry\",severity=\"fail\"}")" = 1 ]')"
[ "$FAILS" = 0 ] || exit 5

echo; echo "== 4. PFTFwauditExposure fires for both hosts (for: 5m) and reaches the throwaway topic"
fired() { [ "$(pq 'ALERTS{alertname="PFTFwauditExposure",alertstate="firing",reason="fail-findings"}' | grep -cE 'host=(validator|sentry)')" = 2 ]; }
wait_until "$FIRE_WAIT" 15 fired; check "Prometheus: PFTFwauditExposure{reason=fail-findings} firing for host=validator and host=sentry ($(( $(date -u +%s) - tF ))s after the faults)" "$?"
wait_until 300 15 '[ "$(n_msgs FIRING validator)" -ge 1 ] && [ "$(n_msgs FIRING sentry)" -ge 1 ]'
check "throwaway topic: [FIRING] PFTFwauditExposure naming validator and sentry (after ${WAITED}s)" "$?"
x "topic_msgs \$ALERT | jq -r '\"\(.time | todate) \(.title) | \(.message | gsub(\"\\n\"; \" / \"))\"'"
[ "$FAILS" = 0 ] || exit 5

echo; echo "== 5. fix: S via pft-fwaudit apply in a pft-maint window; V by removing the container"
x "sudo -n pft-maint start --ttl 45m --reason '$TASK fwaudit exposure drill: apply on the sentry'"
[ "$XRC" = 0 ] && MAINT=1; check "pft-maint window open on the validator" "$XRC"
wait_until 420 10 'R "sudo -n pft-maint active" >/dev/null 2>&1'; check "sentry has the window (via the watchdog channel) after ${WAITED}s" "$?"
[ "$FAILS" = 0 ] || exit 5
tX="$(date -u +%s)"
x "fwa relay 'apply --yes'"
check "S: pft-fwaudit apply exit 0 (both rules deleted, re-audit clean, dead-man started)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "apply RESULT: PASS (pending dead-man)" <<<"$XOUT" && [ "$(grep -c "+ ufw --force delete" <<<"$XOUT")" = 2 ]')"
x "R 'sudo -n ufw status | grep -c \"# $TAGC\"; systemctl is-active $LU.service'"
check "S: no '# $TAGC' UFW rule left, listener still running" "$(ok_if '[ "$(tr "\n" " " <<<"$XOUT")" = "0 active " ]')"
x "probe local $S4 $LP"
check "S: validator -> sentry v4 tcp/$LP blocked while the listener still runs (UFW default deny drops)" "$(ok_if 'grep -qE "^(timeout|refused)" <<<"$XOUT"')"
x "fwa relay audit"
check "S: sentry audit PASS with the listener still up (listener alone is not exposure)" "$(ok_if '[ "$XRC" = 0 ] && grep -qx "RESULT: PASS" <<<"$XOUT"')"
x "R 'sudo -n systemctl stop $LU.service; systemctl is-active $LU.service'"
x "sudo -n docker rm -f $CN"
check "V: container removed" "$XRC"
FAULTS=0
x "probe relay $V4 $PP"
check "V: sentry -> validator v4 tcp/$PP blocked after the removal" "$(ok_if 'grep -qE "^(timeout|refused)" <<<"$XOUT"')"
x "fwa local audit | tail -n 1; fwa relay audit | tail -n 1"
check "VERIFIED: both hosts audit PASS after the fixes" "$(ok_if '[ "$(grep -cx "RESULT: PASS" <<<"$XOUT")" = 2 ]')"
x "textfiles"
check "textfiles re-written, sentry copy pulled" "$XRC"
check "textfiles: fail findings 0 for both hosts" "$(ok_if '[ "$(tfval validator "pft_fwaudit_findings{host=\"validator\",severity=\"fail\"}")" = 0 ] && [ "$(tfval sentry "pft_fwaudit_findings{host=\"sentry\",severity=\"fail\"}")" = 0 ]')"
wait_until 300 15 '[ -z "$(pq "ALERTS{alertname=\"PFTFwauditExposure\"}")" ]'; check "Prometheus: PFTFwauditExposure gone ($(( $(date -u +%s) - tX ))s after the fixes)" "$?"
wait_until 300 15 '[ "$(n_msgs RESOLVED validator)" -ge 1 ] && [ "$(n_msgs RESOLVED sentry)" -ge 1 ]'
check "throwaway topic: [RESOLVED] PFTFwauditExposure naming validator and sentry" "$?"
echo "  waiting for the sentry apply dead-man (fwaudit-deadman, DEADMAN_MIN from the sentry conf)"
wait_until 900 20 '! R "systemctl is-active --quiet fwaudit-deadman.service"'
x "R 'sudo -n jq -c \"{result, keep, baseline_peers, applied_at, deadman_passed_at}\" /var/lib/pft-fwaudit/state.json'"
check "S: apply state result kept" "$(ok_if 'grep -q "\"result\":\"kept\"" <<<"$XOUT"')"
x "R 'sudo -n journalctl --utc -o cat -u fwaudit-deadman.service --since @$tX --no-pager' | grep -E 'dead-man'"
check "S: apply dead-man PASS, every poll ok (none BAD, no rollback)" "$(ok_if 'grep -q "dead-man: PASS - changes kept" <<<"$XOUT" && [ "$(grep -c "dead-man poll: full peers [0-9]* declared ok$" <<<"$XOUT")" -ge 15 ] && ! grep -qE "BAD|TRIPPED|rollback:|rolling back" <<<"$XOUT"')"
x "sudo -n pft-maint end --reason '$TASK fwaudit exposure drill: fixes verified'"
MAINT=0; check "window ended" "$XRC"
wait_until 420 10 '! R "sudo -n pft-maint active" >/dev/null 2>&1'; check "sentry window gone after ${WAITED}s" "$?"

echo; echo "== 6. restore, query_range, final state, read back"
restore
check "notifier envs restored byte-identical, drill-only files removed, dead-men stopped, bridge back, alertpath OK, no abort path" "$(ok_if '[ "$RESTORE_OK" = true ]')"
x "s_leftovers; v_leftovers"
check "no drill unit, no '# $TAGC' ufw rule, no $CN container left" "$(ok_if '[ "$(tr "\n" " " <<<"$XOUT")" = "0 0 0 0 " ]')"
check "sentry 'ufw status numbered' identical to the pre-drill snapshot" "$(ok_if '[ "$(R "sudo -n ufw status numbered" | sha256sum | cut -c1-64)" = "$UFW0" ]')"
check "validator Docker nat/filter DOCKER chains identical to the pre-drill snapshots" "$(ok_if '[ "$(sudo -n iptables -t nat -S DOCKER | sha256sum | cut -c1-64)" = "$NAT0" ] && [ "$(sudo -n iptables -S DOCKER | sha256sum | cut -c1-64)" = "$FWD0" ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=\"PFTFwauditExposure\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) host=\(.metric.host) reason=\(.metric.reason) \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "query_range: PFTFwauditExposure fail-findings pending then firing for both hosts, never audit-error" "$(ok_if '[ "$(grep -cE "^PFTFwauditExposure host=(validator|sentry) reason=fail-findings firing " <<<"$XOUT")" = 2 ] && [ "$(grep -cE "reason=fail-findings pending " <<<"$XOUT")" = 2 ] && ! grep -q "reason=audit-error" <<<"$XOUT"')"
x "sudo -n grep -h '^pft_keyescrow_drift_items' $TF/pft_keyescrow.prom $TF/pft_keyescrow_sentry.prom"
check "pft-keyescrow after the env restores: drift_items 0 on the validator and in the pulled sentry copy" "$(ok_if '! grep -qv "} 0$" <<<"$XOUT" && grep -q "} 0$" <<<"$XOUT"')"
# run 17: `A or B or C` dropped pft_fwaudit_verdict (same {host} labels as pft_fwaudit_up; set operators ignore the name)
x "for q in pft_fwaudit_up pft_fwaudit_verdict 'pft_fwaudit_findings{severity=\"fail\"}'; do pq \"\$q\"; done | sort"
check "Prometheus: both hosts up 1, verdict 0, fail findings 0" "$(ok_if '[ "$(grep -cE "host=(validator|sentry).* 1$" <<<"$(grep pft_fwaudit_up <<<"$XOUT")")" = 2 ] && [ "$(grep pft_fwaudit_verdict <<<"$XOUT" | grep -c " 0$")" = 2 ] && [ "$(grep pft_fwaudit_findings <<<"$XOUT" | grep -c " 0$")" = 2 ]')"
for h in local relay; do
  s="$(sstate "$h")"; r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"
  check "node $h $s; pft-integrity $r" "$(ok_if '[[ "$s" =~ ^(full|proposing)$ ]] && [[ "$r" == "RESULT: PASS"* ]]')"
done
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R \"systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l\""
check "no transient run-u services/timers on either host" "$(ok_if '[ "$(tr "\n" " " <<<"$XOUT")" = "0 0 " ]')"
wait_until "$QUIET_WAIT" 20 '[ "$(others_active)" = 0 ]'
check "quiet gate: nothing but the watchdog${KNOWN_PENDING:+ + KNOWN_PENDING} pending/firing in Prometheus or active in AM (after ${WAITED}s)" "$?"
if [ -n "$SIL" ] && [ "$(others_active)" = 0 ]; then
  x "curl -s -o /dev/null -w '%{http_code}' -X DELETE $AM/api/v2/silence/$SIL"
  check "catch-all silence expired (only the watchdog left)" "$(ok_if '[ "$XOUT" = 200 ]')"
else echo "  catch-all silence left to run out at $ends (quiet gate not met)"; fi
echo "  operator topic read-back waits 90 s (group_interval + 30 s after expiry)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(topic_msgs "$t" | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
echo "  throwaway topics: ALERT $(topic_msgs "$ALERT" | wc -l) message(s), MAINT $(topic_msgs "$MT" | wc -l) message(s)"
x "topic_msgs \$MT | jq -r '\"\(.time | todate) \(.title)\"'"
echo; echo "exposure-drill done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
