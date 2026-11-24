#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2015,SC2016  # test && x || y chains (x always returns 0); jq programs and remote commands are single-quoted on purpose
# Recorded live runs of pft-monupgrade (task_add0edd0): plan -> apply -> rollback -> re-apply -> apply again (no-op),
# sentry first, then the validator, silent on the operator's phone. Built from ../../shutdown/drill/live-run.sh.
#   0. preflight (read-only): clean pushed HEAD, shellcheck + offline tests, integrity PASS both hosts, both nodes
#      full, no maintenance window or lock, no unsilenced alert but the watchdog and digest-only ones, operator
#      topics found; imagescan "before" (validator) for the monitoring images.
#   1. pft-maint [MAINT] target -> throwaway topic, one Alertmanager silence for every alert except the watchdog, the
#      digest-only ones and the PFTMonupgradeTest alert, pft-maint window on both hosts.
#   2. sentry (no monitoring stack of its own): canary.sh up (run copy of HEAD, the validator's CURRENT images pinned
#      to their digests, bridge -> throwaway topic), then the cycle, then canary.sh down (containers, volumes and
#      every image pulled for it removed; integrity PASS unchanged).
#      validator: the live bridge -> throwaway topic (run-stack.sh bridge), the cycle, bridge -> real target.
#      cycle = plan (exit 0) -> apply PASS -> rollback PASS -> apply PASS -> apply = NOTHING TO DO; every switch gates
#      on images, readiness, versions, rule/target/receiver parity, silences kept, watchdog unsilenced, loopback-only
#      and a test alert delivered to the throwaway topic (pft-monupgrade's own gate, automatic rollback on failure).
#   3. imagescan "after" (validator, monitoring images: counts only), integrity accept of the re-created monitoring
#      containers, end window, real targets back, integrity PASS both, both full, drain, expire the silence, read
#      back the throwaway topics and every operator topic (0 messages other than the agent's own).
#   HOSTS="sentry validator" RUN=03 bash monupgrade/drill/live-run.sh 2>&1 | tee LOG   (repo root)
#   DRY=1 HOSTS=sentry RUN=dry1 ...   same steps, state in STATE_DIR/dry-RUN (not the basis); a dry validator run
#   rolls back once more at the end, so the live stack is left on its previous images.
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090; RPC=http://127.0.0.1:5005
ME="$(id -un)"; HN="$(hostname)"
TASK=task_add0edd0
RUN="${RUN:?set RUN}"; DRY="${DRY:-0}"; HOSTS="${HOSTS:-sentry validator}"
SD=/var/lib/pft-monupgrade; [ "$DRY" = 1 ] && SD="/var/lib/pft-monupgrade/dry-$RUN"
rnd() { head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
TT="pft-drill-monupgrade-$(rnd)"     # [MAINT] start/end
TA="pft-drill-monupgrade-a-$(rnd)"   # alerts of the stack under test (canary or live bridge)
TAU="https://ntfy.sh/$TA"
RD=".cache/monupgrade-run-$RUN"      # relative to $HOME on both hosts
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@" </dev/null; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"; RME="$(R id -un 2>/dev/null)"; RME="${RME:-$ME}"; [ "$RME" = root ] && RME="$ME"   # never redact the word root
red() { sed -E "s#$HOME#~#g; s#/home/$ME#~#g; s#/home/$RME#~#g; s#\b$ME\b#<user>#g; s#\b$RME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b127\.0\.0\.1\b#LOOPBACK#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#LOOPBACK#127.0.0.1#g; s#$TT#<throwaway-topic>#g; s#$TA#<throwaway-alert-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-monupgrade
REAL_BRIDGE_ENV="$HOME/.config/pft-alerts/ntfy.env"
HAD=0; MADE=0; MSTART=0; SIL=""; BRIDGE_TEST=0; CANARY=0
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
SIL_MIN="${SIL_MIN:-90}"; TTL_MIN="${TTL_MIN:-75}"; DRAIN_MAX_S="${DRAIN_MAX_S:-900}"
MU="sudo -n env STATE_DIR=$SD NTFY_TEST_URL=$TAU"

state_v() { curl -s -m 10 -d '{"method":"server_info"}' "$RPC" | jq -r '.result.info.server_state // "?"'; }
state_s() { R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r '.result.info.server_state // \"?\"'"; }
others() { # Prometheus alerts (pending included) other than the watchdog and digest-only ones that no active silence
  # but this run's own ($SIL) matches (matchers evaluated here, so pending alerts count too): what would reach the
  # operator once the run's silence is expired. Bodies via files; unreadable/empty fails closed. PROM_URL_O /
  # AM_URL_O: dead-endpoint controls.
  local d out
  d="$(mktemp -d)"
  if curl -s -m 15 "${PROM_URL_O:-$PROM}/api/v1/alerts" >"$d/p" && curl -s -m 15 "${AM_URL_O:-$AM}/api/v2/silences" >"$d/s" \
    && [ -s "$d/p" ] && [ -s "$d/s" ] && jq -e '.data.alerts | type == "array"' "$d/p" >/dev/null 2>&1 && jq -e 'type == "array"' "$d/s" >/dev/null 2>&1; then
    out="$(jq -rn --slurpfile p "$d/p" --slurpfile s "$d/s" --arg sil "$SIL" '
      [$s[0][] | select(.status.state == "active" and .id != $sil) | .matchers] as $ms
      | $p[0].data.alerts[] | select(.labels.alertname != "PFTAlertPipelineWatchdog" and (.labels.notify // "") != "digest")
      | .labels as $l
      | select(any($ms[]; all(.[]; . as $m | ($l[$m.name] // "") as $v
          | (if $m.isRegex then ($v | test("^(?:" + $m.value + ")$")) else $v == $m.value end) == ($m.isEqual != false))) | not)
      | "\(.labels.alertname) \(.labels.host // .labels.node // .labels.instance // "-") \(.state)"')" || out=query-error
  else out=query-error; fi
  rm -rf "$d"; [ -z "$out" ] || printf '%s\n' "$out"
}
test_drain() { # rc 0 when no PFTMonupgradeTest is active in Alertmanager and every [FIRING] of it on the throwaway alert
  # topic since the run start has its [RESOLVED] there too, i.e. nothing of the test alert is left for Alertmanager to
  # flush after the bridge moves back to the real topic (dry run 5: the last [RESOLVED] reached the operator a minute
  # after the move). Waits up to TEST_DRAIN_S. AM_URL_O / TAU_O: dead-endpoint controls. Unreadable fails closed.
  local t0 a n f r
  t0="$(date -u +%s)"
  while :; do
    a="$(curl -s -m 10 "${AM_URL_O:-$AM}/api/v2/alerts?filter=alertname%3D%22PFTMonupgradeTest%22")"
    n="$(curl -s -m 15 "${TAU_O:-$TAU}/json?poll=1&since=$since")" || n=""
    if [ -n "$a" ] && [ -n "$n" ] && jq -e 'type == "array"' >/dev/null 2>&1 <<<"$a"; then
      a="$(jq 'length' <<<"$a")"
      f="$(jq -r 'select(.event == "message") | .title // ""' 2>/dev/null <<<"$n" | grep -c '^\[FIRING\] PFTMonupgradeTest')"
      r="$(jq -r 'select(.event == "message") | .title // ""' 2>/dev/null <<<"$n" | grep -c '^\[RESOLVED\] PFTMonupgradeTest')"
      [ "$a" = 0 ] && [ "$r" -ge "$f" ] && { echo "test alerts drained: active 0, firing $f, resolved $r"; return 0; }
    else a=query-error; f='?'; r='?'; fi
    [ $(($(date -u +%s) - t0)) -ge "${TEST_DRAIN_S:-180}" ] && break
    sleep 5
  done
  echo "test alerts NOT drained after ${TEST_DRAIN_S:-180}s: active $a, firing $f, resolved $r"; return 1
}
bridge_to() { # ENV_FILE: re-create only the live bridge with that ntfy env (Prometheus + Alertmanager keep running)
  NTFY_ENV_FILE="$1" DOCKER="sudo -n docker" bash alerts/run-stack.sh bridge
}
restore() {
  echo; echo "== restore (trap)"
  if [ "$BRIDGE_TEST" = 1 ]; then echo "\$ test_drain"; test_drain 2>&1 | red | sed 's/^/  /'; echo "\$ bridge_to \$REAL_BRIDGE_ENV"; bridge_to "$REAL_BRIDGE_ENV" 2>&1 | red | sed 's/^/  /'; BRIDGE_TEST=0; fi
  if [ "$CANARY" = 1 ]; then echo "\$ canary down (sentry)"; R "STATE=~/$RD/canary bash $RD/repo/monupgrade/drill/canary.sh down" 2>&1 | red | sed 's/^/  /'; CANARY=0; fi
  if [ "$MSTART" = 1 ] && sudo -n pft-maint active >/dev/null 2>&1; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; fi
  MSTART=0
  if [ "$MADE" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE"; sudo -n mv -f "$BK" "$NE"; else echo "\$ sudo -n rm -f \$NE"; sudo -n rm -f "$NE"; fi
    MADE=0
    echo "\$ sudo -n systemctl start pft-keyescrow.service"; sudo -n systemctl start pft-keyescrow.service; echo "  (exit $?)"
  fi
  [ -z "$SIL" ] || echo "silence ${SIL:0:8} left active until its end (expired only after a clean drain)"
  rm -f "$OPS"
}
trap restore EXIT

# imagescan counts for the monitoring images: per container, findings of the running image and of the plan target
scan_counts() { # LABEL
  x "sudo -n pft-imagescan scan --no-fetch >/dev/null; echo scan exit \$?"
  sudo -n jq -c --arg l "$1" '.images as $im | [$im[] | select((.ref // "") | test("prom/(prometheus|alertmanager)"))
    | {label: $l, ref: (.ref | sub("@.*"; "")), in_use, fixable: ([.findings[] | select(.fixable)] | length),
       high_critical: ([.findings[] | select(.fixable and (.severity | test("(?i)high|critical")))] | length)}][]' \
    /var/cache/pft-imagescan/last-scan.json 2>&1 | red | sed 's/^/  /'
}
fixed_counts() { # fixable finding ids of the image each monitoring container ran BEFORE minus those of the one it runs now
  sudo -n jq -c --slurpfile b "$1" '.images as $now | ["prometheus", "alertmanager"][] as $n
    | ([$b[0].images[] | select(.in_use and ((.ref // "") | test("prom/" + $n + "[:@]"))) | .findings[] | select(.fixable) | .id] | unique) as $old
    | ([$now[] | select(.in_use and ((.ref // "") | test("prom/" + $n + "[:@]"))) | .findings[] | select(.fixable) | .id] | unique) as $new
    | {image: $n, fixable_before: ($old | length), fixable_after: ($new | length), fixed: ($old - $new | length), new: ($new - $old | length)}' \
    /var/cache/pft-imagescan/last-scan.json
}

echo "pft-monupgrade live run $RUN - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO)) - hosts '$HOSTS' dry=$DRY"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin; [ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "shellcheck monupgrade/pft-monupgrade.sh monupgrade/tests/*.sh monupgrade/drill/*.sh alerts/run-stack.sh && echo shellcheck clean"
check "shellcheck clean" "$XRC"
x "bash monupgrade/tests/run-tests.sh | tail -1; bash monupgrade/tests/run-apply-tests.sh | tail -1; bash monupgrade/tests/run-drill-tests.sh | tail -1"
check "offline tests pass (plan + apply + drill suites)" "$([ "$(grep -c ' 0 failed$' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "state_v; state_s"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-maint status | head -1; sudo -n pft-maint lock list; R 'sudo -n pft-maint status | head -1'"
check "no maintenance window on either host, no lock" "$([ "$(grep -c '^no maintenance window' <<<"$XOUT")" = 2 ] && grep -q '^no data-collection locks' <<<"$XOUT" && echo 0 || echo 1)"
x "others"
check "no alert but the watchdog, digest-only and already-silenced ones" "$([ -z "$XOUT" ] && echo 0 || echo 1)"
x "curl -s -m 10 $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"\(.id[0:8]) until \(.endsAt) \(.comment)\"'"
echo "  (pre-existing silences are kept; pft-monupgrade's gate checks that each one survives every switch)"
x "R 'sudo -n docker ps -a --filter name=pft- --format {{.Names}}; sudo -n docker volume ls -q --filter name=pft-prometheus-data' | wc -l"
check "sentry has no monitoring stack (canary host)" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env /etc/postfiat-monitor.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$REAL_BRIDGE_ENV" 2>/dev/null; sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
PREF="$(sudo -n docker inspect -f '{{.Config.Image}}' pft-prometheus)"; AREF="$(sudo -n docker inspect -f '{{.Config.Image}}' pft-alertmanager)"
pin() { local d; d="$(sudo -n docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$(sudo -n docker inspect -f '{{.Image}}' "$1")" | awk -v r="$2@" 'index($0, r) == 1 { print substr($0, length(r) + 1); exit }')"; [ -n "$d" ] && echo "${3%%@*}@$d"; }
CP="$(pin pft-prometheus prom/prometheus "$PREF")"; CA="$(pin pft-alertmanager prom/alertmanager "$AREF")"
echo "validator live images: prometheus $PREF ($CP), alertmanager $AREF ($CA)"
check "validator's current images pinned to their digests (canary uses the same)" "$([ -n "$CP" ] && [ -n "$CA" ] && echo 0 || echo 1)"
echo; echo "-- imagescan before (validator; monitoring images, counts only)"
scan_counts before
BEFORE="$HOME/$RD-scan-before.json"; mkdir -p "$HOME/.cache"; sudo -n install -m 600 -o "$ME" /var/cache/pft-imagescan/last-scan.json "$BEFORE"
gate

echo; echo "== 1. throwaway [MAINT] target, silence, maintenance window on both hosts"
sudo -n test -e "$NE" && HAD=1; echo "real \$NE present before: $HAD"
x "{ [ $HAD = 0 ] || sudo -n cp -p $NE $BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' '$TT' | sudo -n tee $NE >/dev/null && sudo -n chmod 600 $NE && sudo -n stat -c '%a %U' $NE"
[ "$XRC" = 0 ] && MADE=1; check "pft-maint target is the throwaway topic" "$([ "$MADE" = 1 ] && echo 0 || echo 1)"
gate
ends="$(date -u -d "+${SIL_MIN} min" +%FT%TZ)"
SBODY="$(jq -nc --arg e "$ends" --arg s "$(date -u +%FT%TZ)" --arg c "$TASK pft-monupgrade run $RUN (monitoring image switches)" '{startsAt:$s, endsAt:$e, createdBy:"pft-agent", comment:$c, matchers:[
  {name:"alertname",value:"PFTAlertPipelineWatchdog|PFTMonupgradeTest",isRegex:true,isEqual:false},
  {name:"notify",value:"digest",isRegex:false,isEqual:false}]}')"
SIL="$(curl -s -m 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
echo "silence (every alert but the watchdog, PFTMonupgradeTest and the digest-only ones) until $ends id ${SIL:0:8}"
check "Alertmanager silence created" "$([ -n "$SIL" ] && echo 0 || echo 1)"
gate
x "sudo -n pft-maint start --ttl ${TTL_MIN}m --reason '$TASK pft-monupgrade run $RUN'"
[ "$XRC" = 0 ] && MSTART=1; check "maintenance window started" "$([ "$MSTART" = 1 ] && echo 0 || echo 1)"
gate
sleep 70   # the sentry copy travels with the next watchdog heartbeat
x "R 'sudo -n pft-maint active && echo active'"
check "window valid on the sentry" "$([ "$XOUT" = active ] && echo 0 || echo 1)"
gate

cycle() { # HOST LABEL: plan -> apply -> rollback -> apply -> apply (no-op) [-> dry: rollback]
  local h="$1"
  if [ "$h" = sentry ]; then run() { x "R '$MU bash $RD/repo/monupgrade/pft-monupgrade.sh $*'"; }
  else run() { x "$MU bash monupgrade/pft-monupgrade.sh $*"; }; fi
  if [ "$h" = sentry ]; then x "R 'sudo -n mkdir -p -m 700 $SD'"; else x "sudo -n mkdir -p -m 700 $SD"; fi
  run plan --out "$SD/plan.json"
  check "$h plan READY (exit 0)" "$XRC"; gate
  run apply --plan "$SD/plan.json" --yes
  check "$h apply PASS" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS - apply' <<<"$XOUT" && echo 0 || echo 1)"; gate
  sleep 30
  run rollback --yes
  check "$h rollback PASS" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS - rollback' <<<"$XOUT" && echo 0 || echo 1)"; gate
  sleep 30
  run apply --plan "$SD/plan.json" --yes
  check "$h re-apply PASS" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS - apply' <<<"$XOUT" && echo 0 || echo 1)"; gate
  run apply --plan "$SD/plan.json" --yes
  check "$h second apply is a no-op" "$([ "$XRC" = 0 ] && grep -q 'RESULT: NOTHING TO DO' <<<"$XOUT" && echo 0 || echo 1)"; gate
  if [ "$DRY" = 1 ]; then
    sleep 30; run rollback --yes
    check "$h dry: final rollback PASS" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS - rollback' <<<"$XOUT" && echo 0 || echo 1)"; gate
  fi
}

echo; echo "== 2. switches"
for h in $HOSTS; do
  echo; echo "-- $h ($(date -u +%FT%TZ))"
  if [ "$h" = sentry ]; then
    x "R 'rm -rf ~/$RD && mkdir -p ~/$RD/repo ~/$RD/canary && chmod 700 ~/$RD' && git archive HEAD | ssh -o LogLevel=ERROR -o BatchMode=yes relay 'tar -x -C ~/$RD/repo' && R 'printf \"NTFY_URL=%s\n\" $TAU > ~/$RD/canary/ntfy.env && chmod 600 ~/$RD/canary/ntfy.env && sudo -n chown 65534:65534 ~/$RD/canary/ntfy.env && cd ~/$RD/repo && sha256sum monupgrade/pft-monupgrade.sh alerts/run-stack.sh alerts/prometheus.yml alerts/alertmanager.yml' && sha256sum monupgrade/pft-monupgrade.sh alerts/run-stack.sh alerts/prometheus.yml alerts/alertmanager.yml"
    check "sentry run copy = HEAD bytes" "$([ "$XRC" = 0 ] && [ "$(wc -l <<<"$XOUT")" = 8 ] && [ "$(awk '{print $1}' <<<"$XOUT" | sort | uniq -c | awk '$1 != 2' | wc -l)" = 0 ] && echo 0 || echo 1)"; gate
    x "R 'STATE=~/$RD/canary NTFY_ENV_FILE=~/$RD/canary/ntfy.env PROM_IMAGE=$CP AM_IMAGE=$CA bash $RD/repo/monupgrade/drill/canary.sh up' | tail -25"
    [ "$XRC" = 0 ] && CANARY=1; check "sentry canary up (validator's current images, bridge -> throwaway)" "$XRC"; gate
    x "for i in \$(seq 1 40); do R 'curl -s -m 5 http://127.0.0.1:9093/api/v2/alerts?filter=alertname%3D%22PFTAlertPipelineWatchdog%22' | jq -e 'length > 0' >/dev/null && { echo watchdog active after \$((i * 3))s; break; }; sleep 3; done"
    check "canary watchdog active" "$(grep -q 'watchdog active' <<<"$XOUT" && echo 0 || echo 1)"; gate
    cycle sentry
    x "R 'STATE=~/$RD/canary bash $RD/repo/monupgrade/drill/canary.sh down'"
    check "sentry canary removed (containers, volumes, pulled images)" "$XRC"; CANARY=0
    x "R 'sudo -n pft-integrity verify | tail -1'"
    check "sentry integrity PASS after the canary" "$(grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
    gate
  else
    TENV="$HOME/$RD-bridge.env"
    x "printf 'NTFY_URL=%s\n' '$TAU' > $TENV && chmod 600 $TENV && bridge_to $TENV"
    [ "$XRC" = 0 ] && BRIDGE_TEST=1; check "validator bridge -> throwaway alert topic" "$XRC"; gate
    cycle validator
    x test_drain; check "validator test alerts drained to the throwaway topic before the bridge moves back" "$XRC"; gate
    x "bridge_to $REAL_BRIDGE_ENV && rm -f $TENV"; check "validator bridge -> real target again" "$XRC"; BRIDGE_TEST=0
    x "sudo -n docker ps --filter name=pft- --format '{{.Names}} {{.Image}} {{.Status}}'"
    echo; echo "-- imagescan after (validator; monitoring images, counts only)"
    scan_counts after
    x "fixed_counts $BEFORE"; rm -f "$BEFORE"
    echo; echo "-- intended changes into pft-integrity (re-created monitoring containers)"
    x "sudo -n pft-integrity verify | grep -vE '^ *(OK|PASS)' | tail -20"
    x "sudo -n pft-integrity accept --reason '$TASK: pft-monupgrade run $RUN (monitoring containers re-created)' | tail -1"
    check "validator integrity accept" "$XRC"
    gate
  fi
done

echo; echo "== 3. end window, restore, checks, drain, read back"
x "sudo -n pft-maint end"; MSTART=0; check "window ended" "$XRC"
if [ "$HAD" = 1 ]; then x "sudo -n mv -f $BK $NE"; else x "sudo -n rm -f $NE"; fi; MADE=0
x "sudo -n systemctl start pft-keyescrow.service; sudo -n pft-keyescrow inventory | tail -1"
check "keyescrow drift 0 after the target restore" "$(grep -q 'escrow drift 0, new 0,' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "integrity PASS both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "state_v; state_s"
check "both nodes full at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s -m 5 -o /dev/null -w 'prometheus %{http_code}\n' http://127.0.0.1:9090/-/healthy; curl -s -m 5 -o /dev/null -w 'alertmanager %{http_code}\n' $AM/-/healthy; curl -s -m 5 http://127.0.0.1:9090/api/v1/status/buildinfo | jq -r '\"prometheus version \" + .data.version'; curl -s -m 5 $AM/api/v2/status | jq -r '\"alertmanager version \" + .versionInfo.version'"
check "validator Prometheus + Alertmanager healthy" "$([ "$(grep -cE ' 200$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
t=0; while :; do o="$(others)"; [ -z "$o" ] && break; [ "$t" -ge "$DRAIN_MAX_S" ] && break; sleep 30; t=$((t + 30)); done
echo "drain after ${t}s:"; printf '%s\n' "${o:-  (nothing but the watchdog / digest-only / pre-silenced alerts)}" | red | sed 's/^/  /'
if [ -z "$o" ]; then
  x "curl -s -m 10 -o /dev/null -w '%{http_code}' -X DELETE $AM/api/v2/silence/$SIL"
  check "silence expired after a clean drain" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"; SIL=""
else check "drained within ${DRAIN_MAX_S}s" 1; fi
sleep 30
x "curl -s -m 15 'https://ntfy.sh/$TT/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title'"
check "[MAINT] start/end reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" -ge 2 ] && echo 0 || echo 1)"
x "curl -s -m 15 '$TAU/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title' | sort | uniq -c"
check "test alerts reached the throwaway alert topic" "$(grep -q 'PFTMonupgradeTest' <<<"$XOUT" && echo 0 || echo 1)"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); m="$(curl -s -m 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -r 'select(.event == "message") | .title // ""')"
  n=0; [ -n "$m" ] && n="$(grep -vc '^\[pft-agent\] ' <<<"$m")"
  echo "  operator #$i topic: $n non-agent message(s)"; [ "$n" = 0 ] || { OPN=$((OPN + 1)); printf '%s\n' "$m" | red | sed 's/^/    /'; }
done < "$OPS"
check "operator topics got no alert/[MAINT] message during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s)"
x "R 'rm -rf ~/$RD'"
echo; echo "pft-monupgrade live run $RUN done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
