#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # jq programs and remote commands are single-quoted on purpose
# Recorded two-host run of pft-coredump (task_d7136fac): found -> fixed -> verified on the sentry and the validator,
# silent on the operator's phone. Built from shutdown/drill/live-run.sh (apply-cycle, PASS 2026-11-24).
# The VALIDATOR's postfiatd is never stopped, restarted or re-created (operator rule until after the 2026-12-01
# reward check): on the validator pft-coredump only changes the host core handler, the live RLIMIT_CORE of the
# running processes (prlimit) and the compose files; the persistent container ulimit waits for the next planned
# re-create (CD08 WARN "pending re-create", disclosed). Its StartedAt and server_info uptime are checked throughout.
#   0. preflight (read-only): clean pushed HEAD, run copies = HEAD bytes on both hosts, shellcheck + offline tests,
#      integrity PASS both, both nodes full, no window/lock, nothing active but the watchdog and digest-only alerts,
#      no active silence, the sentry's recreate tools already copy Ulimits (fleet-synced), operator topics found.
#   1. [MAINT] target -> throwaway topic, one silence (every alert but the watchdog/digest-only), pft-maint window on
#      both hosts (the sentry is re-created 3 times).
#   2. per host, sentry first: audit (found) + crash drill (A core, B none) -> apply (sentry --recreate) -> audit +
#      drill (none, none) -> rollback -> audit + drill (core, none) = exact found state -> re-apply -> second apply
#      refused -> audit + drill (none, none). After every step: both nodes full, validator StartedAt unchanged.
#   3. install /usr/local/bin/pft-coredump on both hosts; the intended changes go into pft-integrity (accept).
#   4. end window, restore target, integrity/AppArmor/seccomp PASS, drain, expire the silence, read back topics.
#   RUN=03 bash coredump/drill/live-run.sh 2>&1 | tee LOG   (repo root)
#   DRY=1 RUN=dry1 ...   same steps, STATE_DIR /var/lib/pft-coredump/dry-RUN, and a final rollback on each host
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090; RPC=http://127.0.0.1:5005
ME="$(id -un)"; HN="$(hostname)"
TASK=task_d7136fac
RUN="${RUN:?set RUN}"; DRY="${DRY:-0}"; HOSTS="${HOSTS:-sentry validator}"
PAUSE_S="${PAUSE_S:-30}"; DRAIN_MAX_S="${DRAIN_MAX_S:-1800}"
SD=/var/lib/pft-coredump; [ "$DRY" = 1 ] && SD="/var/lib/pft-coredump/dry-$RUN"
TT="pft-drill-coredump-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
RD=".cache/coredump-run-$RUN"   # relative to $HOME on both hosts
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@" </dev/null; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#/home/$ME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-coredump
HAD=0; MADE=0; MSTART=0; SIL=""
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
SIL_MIN="${SIL_MIN:-90}"; TTL_MIN="${TTL_MIN:-75}"

info_v() { curl -s -m 10 -d '{"method":"server_info"}' "$RPC" | jq -c '.result.info // {}'; }
state_v() { info_v | jq -r '.server_state // "?"'; }
state_s() { R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r '.result.info.server_state // \"?\"'"; }
started_v() { sudo -n docker inspect -f '{{.State.StartedAt}}' postfiatd; }
others() { # active Prometheus alerts (pending included) other than the watchdog and the digest-only ones; query-error fails closed
  local j; j="$(curl -s -m 15 "$PROM/api/v1/alerts")"
  jq -e '.data.alerts | type == "array"' >/dev/null 2>&1 <<<"$j" || { echo query-error; return; }
  jq -r '.data.alerts[] | select(.labels.alertname != "PFTAlertPipelineWatchdog" and (.labels.notify // "") != "digest")
    | "\(.labels.alertname) \(.labels.host // .labels.node // .labels.container // "-") \(.state)"' <<<"$j"
}
restore() {
  echo; echo "== restore (trap)"
  if [ "$MSTART" = 1 ] && sudo -n pft-maint active >/dev/null 2>&1; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; fi
  MSTART=0
  if [ "$MADE" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE"; sudo -n mv -f "$BK" "$NE"; else echo "\$ sudo -n rm -f \$NE   (pft-maint falls back to the real target again)"; sudo -n rm -f "$NE"; fi
    MADE=0
    echo "\$ sudo -n systemctl start pft-keyescrow.service"; sudo -n systemctl start pft-keyescrow.service; echo "  (exit $?)"
  fi
  R 'sudo -n docker start postfiatd-sentry' >/dev/null 2>&1   # never leave the sentry stopped (no-op when running)
  [ -z "$SIL" ] || echo "silence ${SIL:0:8} left active until its end (expired only after a clean drain)"
  rm -f "$OPS"
}
trap restore EXIT

echo "pft-coredump live run $RUN - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO)) - hosts '$HOSTS' dry=$DRY"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin; [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "rm -rf ~/$RD && mkdir -p ~/$RD && cp coredump/pft-coredump.sh coredump/drill/crash-drill.sh ~/$RD/ && R 'rm -rf ~/$RD && mkdir -p ~/$RD' && scp -q -o BatchMode=yes coredump/pft-coredump.sh coredump/drill/crash-drill.sh relay:$RD/ && sha256sum coredump/pft-coredump.sh ~/$RD/pft-coredump.sh coredump/drill/crash-drill.sh ~/$RD/crash-drill.sh; R 'sha256sum $RD/pft-coredump.sh $RD/crash-drill.sh'"
check "run copies on both hosts = HEAD bytes" "$([ "$(awk '{ print $1 }' <<<"$XOUT" | sort -u | wc -l)" = 2 ] && [ "$(wc -l <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"
x "shellcheck coredump/pft-coredump.sh coredump/tests/run-tests.sh coredump/tests/stubs/* coredump/drill/*.sh && echo shellcheck clean"
check "shellcheck clean" "$XRC"
x "bash coredump/tests/run-tests.sh | tail -1"
check "offline tests pass" "$([ "$XRC" = 0 ] && grep -q ' 0 failed$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "state_v; state_s"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
V0="$(started_v)"; U0="$(info_v | jq -r '.uptime // 0')"; T0="$(date -u +%s)"
echo "validator postfiatd StartedAt $V0, server_info uptime ${U0}s (recorded at $(date -u +%FT%TZ))"
x "sudo -n pft-maint status | head -1; sudo -n pft-maint lock list; R 'sudo -n pft-maint status | head -1'"
check "no maintenance window on either host, no lock" "$([ "$(grep -c '^no maintenance window' <<<"$XOUT")" = 2 ] && grep -q '^no data-collection locks' <<<"$XOUT" && echo 0 || echo 1)"
x "others"
check "nothing active but the watchdog and digest-only alerts" "$([ -z "$XOUT" ] && echo 0 || echo 1)"
x "curl -s -m 10 $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
check "no active silence" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x "R 'grep -c HostConfig.Ulimits /usr/local/bin/pft-seccomp /usr/local/bin/pft-apparmor'"
check "sentry recreate tools copy Ulimits (fleet-synced)" "$([ "$XRC" = 0 ] && ! grep -q ':0$' <<<"$XOUT" && echo 0 || echo 1)"
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
SBODY="$(jq -nc --arg e "$ends" --arg s "$(date -u +%FT%TZ)" --arg c "$TASK pft-coredump run $RUN (sentry re-created 3x, validator not restarted)" '{startsAt:$s, endsAt:$e, createdBy:"pft-agent", comment:$c, matchers:[
  {name:"alertname",value:".+",isRegex:true,isEqual:true},
  {name:"alertname",value:"PFTAlertPipelineWatchdog",isRegex:false,isEqual:false},
  {name:"notify",value:"digest",isRegex:false,isEqual:false}]}')"
SIL="$(curl -s -m 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
echo "silence (every alert but the watchdog and the digest-only ones, both hosts) until $ends id ${SIL:0:8}"
check "Alertmanager silence created" "$([ -n "$SIL" ] && echo 0 || echo 1)"
gate
x "sudo -n pft-maint start --ttl ${TTL_MIN}m --reason '$TASK pft-coredump run $RUN'"
[ "$XRC" = 0 ] && MSTART=1; check "maintenance window started" "$([ "$MSTART" = 1 ] && echo 0 || echo 1)"
gate
sleep 70   # the sentry copy travels with the next watchdog heartbeat
x "R 'sudo -n pft-maint active && echo active'"
check "window valid on the sentry" "$([ "$XOUT" = active ] && echo 0 || echo 1)"
gate

echo; echo "== 2. found -> fixed -> rollback -> re-apply"
pcd() { # HOST ARGS...: pft-coredump on that host (run copy, STATE_DIR=$SD)
  local h="$1"; shift
  if [ "$h" = sentry ]; then x "R 'sudo -n env STATE_DIR=$SD bash $RD/pft-coredump.sh $*'"; else x "sudo -n env STATE_DIR=$SD bash ~/$RD/pft-coredump.sh $*"; fi
}
drill() { # HOST STAGE EXPECT_A EXPECT_B
  local h="$1" s="$2"; shift 2
  if [ "$h" = sentry ]; then x "R 'sudo -n env DRILL_DIR=$SD/drill bash $RD/crash-drill.sh $h-$s $*'"; else x "sudo -n env DRILL_DIR=$SD/drill bash ~/$RD/crash-drill.sh $h-$s $*"; fi
  check "$h $s: crash drill A=$1 B=$2" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
}
audit_is() { # HOST LABEL WANT_EXIT [STATUS-LIST e.g. "CD01=PASS CD08=WARN"]
  local h="$1" l="$2" w="$3" want="${4:-}" s got bad=""
  pcd "$h" audit
  for s in $want; do
    got="$(grep -o "\[[A-Z]*\] ${s%%=*} " <<<"$XOUT" | tr -d '[]' | cut -d' ' -f1)"; [ "$got" = "${s#*=}" ] || bad+=" ${s%%=*}=$got"
  done
  check "$l: audit exit $XRC (want $w)${want:+, $want}" "$([ "$XRC" = "$w" ] && [ -z "$bad" ] && echo 0 || echo 1)" "${bad:+got$bad}"
}
after() { # LABEL: both nodes full, validator postfiatd not restarted
  local l="$1" st u
  x "state_v; state_s"
  check "$l: both nodes full" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
  st="$(started_v)"; u="$(info_v | jq -r '.uptime // 0')"
  echo "validator postfiatd StartedAt $st, uptime ${u}s (+$((u - U0))s since preflight, wall +$(( $(date -u +%s) - T0 ))s)"
  check "$l: validator postfiatd not restarted (StartedAt unchanged, uptime grew)" "$([ "$st" = "$V0" ] && [ "$u" -ge "$U0" ] && echo 0 || echo 1)"
}
step() { # HOST LABEL ARGS... -> check the RESULT line of apply/rollback
  local h="$1" l="$2"; shift 2; pcd "$h" "$@" --yes
  check "$l" "$([ "$XRC" = 0 ] && grep -qE '(apply|rollback) RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
}
FOUND="CD01=FAIL CD02=FAIL CD06=FAIL CD08=FAIL CD09=FAIL CD13=PASS"
for h in $HOSTS; do
  echo; echo "-- $h ($(date -u +%FT%TZ))"
  if [ "$h" = sentry ]; then REC=--recreate; FIXED="CD01=PASS CD02=PASS CD06=PASS CD07=INFO CD08=PASS CD09=PASS CD13=PASS"; WF=0
  else REC=""; FIXED="CD01=PASS CD02=PASS CD06=PASS CD07=INFO CD08=WARN CD09=PASS CD13=PASS"; WF=1; fi
  audit_is "$h" "$h found" 2 "$FOUND"; pcd "$h" audit --json; drill "$h" found core none; gate
  step "$h" "$h apply PASS" apply ${REC:+"$REC"}; after "$h apply"; gate
  audit_is "$h" "$h after apply" "$WF" "$FIXED"; drill "$h" applied none none; gate
  sleep "$PAUSE_S"
  step "$h" "$h rollback PASS" rollback; after "$h rollback"; gate
  audit_is "$h" "$h after rollback (= found)" 2 "$FOUND"; drill "$h" rolled-back core none; gate
  sleep "$PAUSE_S"
  step "$h" "$h re-apply PASS" apply ${REC:+"$REC"}; after "$h re-apply"; gate
  pcd "$h" apply --yes ${REC:+"$REC"}
  check "$h second apply refused while applied (exit 4)" "$([ "$XRC" = 4 ] && grep -q 'not rolled back' <<<"$XOUT" && echo 0 || echo 1)"
  audit_is "$h" "$h after re-apply" "$WF" "$FIXED"; drill "$h" re-applied none none; gate
  if [ "$DRY" = 1 ]; then
    step "$h" "$h dry: final rollback PASS" rollback; after "$h dry final rollback"; audit_is "$h" "$h dry: after final rollback" 2 "$FOUND"; gate
  fi
  if [ "$h" = validator ]; then   # backupwatch: every COMPOSE_FILE member (the new overlay too) must be in the newest archive
    x "sudo -n systemctl start pft-backup.service && sudo -n systemctl start pft-backupwatch.service && systemctl show -p Result --value pft-backupwatch.service"
    check "validator backup + backupwatch after the change" "$([ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = success ] && echo 0 || echo 1)"
  fi
  gate
done

echo; echo "== 3. install + intended changes into pft-integrity"
if [ "$DRY" != 1 ]; then
  x "sudo -n install -m 0755 -o root -g root coredump/pft-coredump.sh /usr/local/bin/pft-coredump && R 'sudo -n install -m 0755 -o root -g root $RD/pft-coredump.sh /usr/local/bin/pft-coredump' && sha256sum coredump/pft-coredump.sh /usr/local/bin/pft-coredump | cut -c1-64; R 'sha256sum /usr/local/bin/pft-coredump' | cut -c1-64"
  check "pft-coredump installed on both hosts = HEAD bytes" "$([ "$XRC" = 0 ] && [ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"
fi
x "sudo -n pft-integrity verify | grep -vE '^ *(OK|PASS)' | tail -20; R 'sudo -n pft-integrity verify | grep -vE \"^ *(OK|PASS)\" | tail -20'"
for h in $HOSTS; do
  if [ "$h" = sentry ]; then x "R 'sudo -n pft-integrity accept --reason \"$TASK: pft-coredump run $RUN (sysctl.d core_pattern drop-in, sentry re-created with --ulimit core=0:0, /usr/local/bin/pft-coredump)\" | tail -1'"
  else x "sudo -n pft-integrity accept --reason '$TASK: pft-coredump run $RUN (sysctl.d core_pattern drop-in, .env + docker-compose.coredump.yml, /usr/local/bin/pft-coredump; postfiatd not restarted)' | tail -1"; fi
  check "$h integrity accept" "$XRC"
done
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "integrity PASS both hosts after accept" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 4. end window, restore, checks, drain, read back"
x "sudo -n pft-maint end"; MSTART=0; check "window ended" "$XRC"
if [ "$HAD" = 1 ]; then x "sudo -n mv -f $BK $NE"; else x "sudo -n rm -f $NE"; fi; MADE=0
x "sudo -n systemctl start pft-keyescrow.service; sudo -n pft-keyescrow inventory | tail -1"
check "keyescrow drift 0 after the target restore" "$(grep -q 'escrow drift 0, new 0,' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep RESULT; sudo -n pft-seccomp audit | grep RESULT; R 'sudo -n pft-apparmor audit | grep RESULT; sudo -n pft-seccomp audit | grep RESULT'"
check "AppArmor + seccomp PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
after "end"
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
echo; echo "pft-coredump live run $RUN done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
