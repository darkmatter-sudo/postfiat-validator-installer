#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # jq programs and remote commands are single-quoted on purpose
# Recorded live stop runs of pft-shutdown (task_32fe8c3a): `measure` (clean stops) or `kill-drill` (SIGKILL) of the
# live sentry and/or validator, sentry first, silent on the operator's phone. Built from the planned-restart runner
# of 2026-11-21 (pft-maint restart-node, PASS) and specdrill/drill/live-run.sh (read-backs).
#   0. preflight (read-only): clean pushed HEAD, run copies = HEAD bytes on both hosts, shellcheck + offline tests,
#      integrity PASS both hosts, both nodes full, no maintenance window or lock, nothing active but the watchdog
#      and digest-only alerts, no active silence, no open histarchive gap, operator topics found.
#   1. pft-maint [MAINT] target -> throwaway topic, one Alertmanager silence for every alert except the watchdog
#      and digest-only ones (both hosts are stopped), pft-maint window on both hosts (pft-watchdog, postfiat-monitor, pft-integrity and
#      pft-selfheal suppress while it is valid).
#   2. per host in HOSTS, N times: `pft-shutdown MODE --yes` (state in STATE_DIR on that host), node full again,
#      pft-egress check; validator: histarchive gap of the stop filled from the public RPC. PAUSE_S between runs.
#   3. end window, real target back, pft-keyescrow re-collected (drift 0), integrity PASS both, AppArmor/seccomp
#      PASS, drain (wait until only the watchdog/digest alerts are active), expire the silence, read back the
#      throwaway topic and every operator topic (0 messages other than the agent's own).
#   MODE=measure HOSTS="sentry validator" N=3 RUN=03 bash shutdown/drill/live-run.sh 2>&1 | tee LOG   (repo root)
#   DRY=1 MODE=measure HOSTS=sentry N=1 RUN=dry1 ...   same steps, state in STATE_DIR/dry-RUN (not the basis)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090; RPC=http://127.0.0.1:5005
ME="$(id -un)"; HN="$(hostname)"
TASK=task_32fe8c3a
RUN="${RUN:?set RUN}"; DRY="${DRY:-0}"; MODE="${MODE:-measure}"; HOSTS="${HOSTS:-sentry validator}"; N="${N:-3}"
# a validator stop records a histarchive gap: PFTHistarchiveIntegrity (delta(follow_gaps[1h]) > 0) fires for 1 h after
# it even once the gap is filled, so drain and silence must outlast that hour (dry2: 30-min drain cap, silence extended)
VX=0; case " $HOSTS " in *" validator "*) VX=75 ;; esac
PAUSE_S="${PAUSE_S:-60}"; DRAIN_MAX_S="${DRAIN_MAX_S:-$((VX > 0 ? VX * 60 : 1800))}"
case "$MODE" in measure|kill-drill) ;; *) echo "MODE must be measure or kill-drill"; exit 3 ;; esac
SD=/var/lib/pft-shutdown; [ "$DRY" = 1 ] && SD="/var/lib/pft-shutdown/dry-$RUN"
TT="pft-drill-shutdown-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
RD=".cache/shutdown-run-$RUN"   # relative to $HOME on both hosts
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@" </dev/null; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#/home/$ME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-shutdown
HAD=0; MADE=0; MSTART=0; SIL=""
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
NRUNS=0; for _ in $HOSTS; do NRUNS=$((NRUNS + N)); done
# per run: stop (<=120 s) + recovery (<=900 s budget, ~2 min seen) + settle 60 + pause; silence = runs + alert windows
SIL_MIN="${SIL_MIN:-$((NRUNS * 8 + 45 + VX))}"; TTL_MIN="$((NRUNS * 8 + 20))"

state_v() { curl -s -m 10 -d '{"method":"server_info"}' "$RPC" | jq -r '.result.info.server_state // "?"'; }
state_s() { R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r '.result.info.server_state // \"?\"'"; }
others() { # active Prometheus alerts (pending included) other than the watchdog and the digest-only ones; query-error fails closed
  local j; j="$(curl -s -m 15 "$PROM/api/v1/alerts")"
  jq -e '.data.alerts | type == "array"' >/dev/null 2>&1 <<<"$j" || { echo query-error; return; }
  jq -r '.data.alerts[] | select(.labels.alertname != "PFTAlertPipelineWatchdog" and (.labels.notify // "") != "digest")
    | "\(.labels.alertname) \(.labels.host // .labels.node // .labels.container // "-") \(.state)"' <<<"$j"
}
open_gaps() { sudo -n pft-histarchive gaps --json | jq -r '.gaps[]? | select(.state != "filled") | "\(.from)-\(.to)"'; }
restore() {
  echo; echo "== restore (trap)"
  if [ "$MSTART" = 1 ] && sudo -n pft-maint active >/dev/null 2>&1; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; fi
  MSTART=0
  if [ "$MADE" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE"; sudo -n mv -f "$BK" "$NE"; else echo "\$ sudo -n rm -f \$NE   (pft-maint falls back to the real target again)"; sudo -n rm -f "$NE"; fi
    MADE=0
    echo "\$ sudo -n systemctl start pft-keyescrow.service"; sudo -n systemctl start pft-keyescrow.service; echo "  (exit $?)"
  fi
  for c in "sudo -n docker start postfiatd" "R 'sudo -n docker start postfiatd-sentry'"; do   # never leave a node stopped
    eval "$c" >/dev/null 2>&1
  done
  [ -z "$SIL" ] || echo "silence ${SIL:0:8} left active until its end (expired only after a clean drain)"
  rm -f "$OPS"
}
trap restore EXIT

echo "pft-shutdown live run $RUN - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO)) - mode $MODE hosts '$HOSTS' n=$N dry=$DRY"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin; [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "rm -rf ~/$RD && mkdir -p ~/$RD && cp shutdown/pft-shutdown.sh ~/$RD/ && R 'rm -rf ~/$RD && mkdir -p ~/$RD' && scp -q -o BatchMode=yes shutdown/pft-shutdown.sh relay:$RD/ && sha256sum shutdown/pft-shutdown.sh ~/$RD/pft-shutdown.sh | cut -c1-64; R 'sha256sum $RD/pft-shutdown.sh' | cut -c1-64"
check "run copies on both hosts = HEAD bytes" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && [ "$(wc -l <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "shellcheck shutdown/pft-shutdown.sh shutdown/tests/run-tests.sh shutdown/drill/*.sh && echo shellcheck clean"
check "shellcheck clean" "$XRC"
x "bash shutdown/tests/run-tests.sh | tail -1"
check "offline tests pass" "$([ "$XRC" = 0 ] && grep -q ' 0 failed$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "state_v; state_s"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-maint status | head -1; sudo -n pft-maint lock list; R 'sudo -n pft-maint status | head -1'"
check "no maintenance window on either host, no lock" "$([ "$(grep -c '^no maintenance window' <<<"$XOUT")" = 2 ] && grep -q '^no data-collection locks' <<<"$XOUT" && echo 0 || echo 1)"
x "others"
check "nothing active but the watchdog and digest-only alerts" "$([ -z "$XOUT" ] && echo 0 || echo 1)"
x "curl -s -m 10 $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
check "no active silence" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x "open_gaps | wc -l"
check "no open histarchive gap" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env /etc/postfiat-monitor.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null; sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
gate

echo; echo "== 1. throwaway [MAINT] target, silence, maintenance window on both hosts"
sudo -n test -e "$NE" && HAD=1; echo "real \$NE present before: $HAD"
x "{ [ $HAD = 0 ] || sudo -n cp -p $NE $BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' '$TT' | sudo -n tee $NE >/dev/null && sudo -n chmod 600 $NE && sudo -n stat -c '%a %U' $NE"
[ "$XRC" = 0 ] && MADE=1; check "pft-maint target is the throwaway topic" "$([ "$MADE" = 1 ] && echo 0 || echo 1)"
gate
ends="$(date -u -d "+${SIL_MIN} min" +%FT%TZ)"
SBODY="$(jq -nc --arg e "$ends" --arg s "$(date -u +%FT%TZ)" --arg c "$TASK pft-shutdown $MODE run $RUN (planned stops of $HOSTS)" '{startsAt:$s, endsAt:$e, createdBy:"pft-agent", comment:$c, matchers:[
  {name:"alertname",value:".+",isRegex:true,isEqual:true},
  {name:"alertname",value:"PFTAlertPipelineWatchdog",isRegex:false,isEqual:false},
  {name:"notify",value:"digest",isRegex:false,isEqual:false}]}')"
SIL="$(curl -s -m 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
echo "silence (every alert but the watchdog and the digest-only ones, both hosts) until $ends id ${SIL:0:8}"
check "Alertmanager silence created" "$([ -n "$SIL" ] && echo 0 || echo 1)"
gate
x "sudo -n pft-maint start --ttl ${TTL_MIN}m --reason '$TASK pft-shutdown $MODE run $RUN'"
[ "$XRC" = 0 ] && MSTART=1; check "maintenance window started" "$([ "$MSTART" = 1 ] && echo 0 || echo 1)"
gate
sleep 70   # the sentry copy travels with the next watchdog heartbeat
x "R 'sudo -n pft-maint active && echo active'"
check "window valid on the sentry" "$([ "$XOUT" = active ] && echo 0 || echo 1)"
gate

echo; echo "== 2. $MODE runs"
k=0
for h in $HOSTS; do
  for i in $(seq 1 "$N"); do
    k=$((k + 1)); echo; echo "-- $h $MODE $i/$N ($(date -u +%FT%TZ))"
    if [ "$h" = sentry ]; then
      x "R 'sudo -n env STATE_DIR=$SD bash $RD/pft-shutdown.sh $MODE --yes'"
    else
      x "sudo -n env STATE_DIR=$SD bash ~/$RD/pft-shutdown.sh $MODE --yes"
    fi
    check "$h $MODE $i PASS" "$([ "$XRC" = 0 ] && grep -q '^RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
    x "state_v; state_s"
    check "$h $MODE $i: both nodes full" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
    if [ "$h" = sentry ]; then x "R 'sudo -n pft-egress check --container postfiatd-sentry | tail -1'"; else x "sudo -n pft-egress check --container postfiatd | tail -1"; fi
    check "$h $MODE $i: pft-egress check" "$XRC"
    if [ "$h" = validator ]; then
      sleep 30
      for g in $(open_gaps); do
        x "sudo -n pft-histarchive fill-gap $g --rpc https://rpc.testnet.postfiat.org/ | tail -2"
        check "histarchive fill-gap $g" "$XRC"
      done
      x "open_gaps | wc -l"; check "$h $MODE $i: no open histarchive gap" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
    fi
    gate
    [ "$k" -lt "$NRUNS" ] && sleep "$PAUSE_S"
  done
done
x "sudo -n cat $SD/measure-postfiatd.json 2>/dev/null | jq -c '.runs[] | {time, mode, stop_s, exit_code, clean, recover_s, hole_ledgers, db_error_lines}'; R 'sudo -n cat $SD/measure-postfiatd-sentry.json 2>/dev/null' | jq -c '.runs[] | {time, mode, stop_s, exit_code, clean, recover_s, hole_ledgers, db_error_lines}'"

echo; echo "== 3. end window, restore, checks, drain, read back"
x "sudo -n pft-maint end"; MSTART=0; check "window ended" "$XRC"
if [ "$HAD" = 1 ]; then x "sudo -n mv -f $BK $NE"; else x "sudo -n rm -f $NE"; fi; MADE=0
x "sudo -n systemctl start pft-keyescrow.service; sudo -n pft-keyescrow inventory | tail -1"
check "keyescrow drift 0 after the target restore" "$(grep -q 'escrow drift 0, new 0,' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "integrity PASS both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep RESULT; sudo -n pft-seccomp audit | grep RESULT; R 'sudo -n pft-apparmor audit | grep RESULT; sudo -n pft-seccomp audit | grep RESULT'"
check "AppArmor + seccomp PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "state_v; state_s"
check "both nodes full at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
t=0; while :; do o="$(others)"; [ -z "$o" ] && break; [ "$t" -ge "$DRAIN_MAX_S" ] && break; sleep 30; t=$((t + 30)); done
echo "drain after ${t}s:"; printf '%s\n' "${o:-  (nothing but the watchdog / digest-only alerts)}" | red | sed 's/^/  /'
if [ -z "$o" ]; then
  x "curl -s -m 10 -o /dev/null -w '%{http_code}' -X DELETE $AM/api/v2/silence/$SIL"
  check "silence expired after a clean drain" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"; SIL=""
else check "drained within ${DRAIN_MAX_S}s" 1; fi
sleep 30
x "curl -s -m 15 'https://ntfy.sh/$TT/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title'"
check "[MAINT] start/end reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" -ge 2 ] && echo 0 || echo 1)"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); m="$(curl -s -m 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -r 'select(.event == "message") | .title // ""')"
  n=0; [ -n "$m" ] && n="$(grep -vc '^\[pft-agent\] ' <<<"$m")"
  echo "  operator #$i topic: $n non-agent message(s)"; [ "$n" = 0 ] || { OPN=$((OPN + 1)); printf '%s\n' "$m" | red | sed 's/^/    /'; }
done < "$OPS"
check "operator topics got no alert/[MAINT] message during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s)"
x "R 'rm -rf ~/$RD'; rm -rf ~/$RD"
echo; echo "pft-shutdown live run $RUN done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
