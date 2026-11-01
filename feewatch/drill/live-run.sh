#!/usr/bin/env bash
# live-run: the pft-feewatch alert drill. No network load: the alert inputs come from recorded + synthetic answers
# (drill/fixtures, built by make_drill_fixtures.py from the real validator answers) fed to the INSTALLED
# `pft-feewatch replay`, which writes drill-only textfiles (container="drill-*") into the validator's textfile dir.
# Built from ../../authwatch/drill/live-run.sh (redirect / bridge swap / silence / read-back framework).
#   bash feewatch/drill/live-run.sh 2>&1 | tee LOG    (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): relay, Alertmanager, Prometheus reachable; no pft-maint window; notifier env files
#    present, no leftovers; the bridge mounts the operator env; no active silence covers the feewatch alerts; no
#    feewatch alert active; no drill textfile; feewatch timers active and pft_feewatch_up 1 for both nodes; both nodes
#    full; pft-integrity PASS on both; redaction positive control. Operator topics, user name, host addresses and node
#    keys go into a 0600 literals file for redact.py; they are never printed.
# 1  redirect: LOCAL_ENVS / REMOTE_ENVS get a throwaway topic (sha256 recorded, restored on ANY exit and compared), the
#    bridge is recreated with a throwaway NTFY_ENV_FILE; Alertmanager silence for every alert EXCEPT the four feewatch
#    alerts and the pipeline watchdog; sudo pft-maint start on the validator, wait until the sentry has it.
# 2  fire: a refresher (every REFRESH s) replays five drill series:
#      drill-queue      queue_fee + healthy_info        -> PFTTxQueueNearFull (fill 0.9, for 10m)
#      drill-escalated  escalated_fee + escalated_info  -> PFTFeeEscalated (6x >= 4, for 15m)
#      drill-localload  healthy_fee + localload_info    -> PFTLocalLoadHigh (local 3 > net 1, for 10m)
#      drill-failing    healthy_fee + failing_info      -> PFTFeewatchStale (up 0, for 2m)
#      drill-stale      healthy answers, timestamp 600 s in the past -> PFTFeewatchStale (age > 300 s, for 2m)
#    Checks: exactly these five (alert, container) pairs fire, none for the real nodes, [FIRING] delivered for each.
# 3  recover: every drill series replays the healthy answers with a fresh timestamp; each pair must leave Prometheus
#    and deliver [RESOLVED]. Then the refresher stops and the drill textfiles are removed. ALERTS query_range: first/last
#    firing sample per series.
# 4  restore env files + bridge (mount source read back), pft-maint end, expire the silence, read back the throwaway
#    topic and count messages on every operator topic since the start (topics never printed); no drill textfile left;
#    pft-integrity PASS on both hosts, both nodes full, feewatch timers active, real pft_feewatch_up 1. Exit 0 = every
#    CHECK ok.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  PROM (http://127.0.0.1:9090)  REFRESH (20, s)
#      LOCAL_ENVS  REMOTE_ENVS  BRIDGE_ENV  AGENT_ENV  TTL (60m)  SIL_TTL (60, min)  FIRE_WAIT (1380, s)
#      RESOLVE_WAIT (600, s)  NTFY_WAIT (180, s)  REDACT (../../peerexpose/drill/redact.py)
# shellcheck disable=SC2016  # ok_if conditions are single-quoted on purpose: evaluated later
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REDACT="${REDACT:-$REPO/peerexpose/drill/redact.py}"
RUNSTACK="$REPO/alerts/run-stack.sh"
FX="$HERE/fixtures"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
REFRESH="${REFRESH:-20}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
TTL="${TTL:-60m}"; SIL_TTL="${SIL_TTL:-60}"
FIRE_WAIT="${FIRE_WAIT:-1380}"; RESOLVE_WAIT="${RESOLVE_WAIT:-600}"; NTFY_WAIT="${NTFY_WAIT:-180}"
FW_ALERTS='PFTTxQueueNearFull|PFTFeeEscalated|PFTLocalLoadHigh|PFTFeewatchStale'
WATCHDOG_ALERT=PFTAlertPipelineWatchdog
TF=/var/lib/pft-exporter/textfile
SUF=.pre-feewatch-drill
BIN=/usr/local/bin/pft-feewatch
# drill series: NAME FEE INFO AGE(s) EXPECTED-ALERT
PAIRS="drill-queue queue healthy 0 PFTTxQueueNearFull
drill-escalated escalated escalated 0 PFTFeeEscalated
drill-localload healthy localload 0 PFTLocalLoadHigh
drill-failing healthy failing 0 PFTFeewatchStale
drill-stale healthy healthy 600 PFTFeewatchStale"

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="fwdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
FAILS=0
check() { # NAME 0|1 DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { # print the exact command (redacted), run it, print its output (redacted) and exit code; output kept in XOUT
  echo "\$ $*" | red
  XOUT="$(eval "$*" 2>&1)"; XRC=$?
  printf '%s\n' "$XOUT" | red | sed 's/^/  /'
  echo "  (exit $XRC)"
}
pq() { # QUERY -> "labels value" lines
  curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric | del(.__name__) | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'
}
node_state() { # HOST CONTAINER
  on "$1" "sudo -n docker exec $2 curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
    | jq -r '.result.info.server_state // "down"' 2>/dev/null
}
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }

# replay one drill series with the installed tool; AGE > 0 back-dates the collect timestamp
replay_one() { # NAME FEE INFO AGE
  sudo -n "$BIN" replay --container "$1" --fee "$FX/$2_fee.json" --info "$FX/$3_info.json" \
    --now "$(( $(date +%s) - $4 ))" 2>/dev/null
}
# refresher: PHASE file says fire|recover; every REFRESH s every series is replayed (fire: its case, recover: healthy)
refresher() {
  local n f i a e
  while [ -e "$SEC/phase" ]; do
    while read -r n f i a e; do
      if [ "$(cat "$SEC/phase" 2>/dev/null)" = recover ]; then replay_one "$n" healthy healthy 0
      else replay_one "$n" "$f" "$i" "$a"; fi
    done <<<"$PAIRS"
    sleep "$REFRESH"
  done
}

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0; MAINT_STARTED=0; SIL=""; LOOP_PID=""
stop_refresher() { # let the loop see the missing phase file and finish its current replay, then delete the files
  local w=0
  rm -f "$SEC/phase"
  if [ -n "$LOOP_PID" ]; then
    while kill -0 "$LOOP_PID" 2>/dev/null && [ "$w" -lt $((REFRESH + 30)) ]; do sleep 1; w=$((w + 1)); done
    kill "$LOOP_PID" 2>/dev/null; wait "$LOOP_PID" 2>/dev/null; LOOP_PID=""
  fi
  sudo -n find "$TF" -maxdepth 1 -name 'pft_feewatch_drill-*.prom' -delete
}
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha src
  stop_refresher
  if [ -n "$(sudo -n find "$TF" -maxdepth 1 -name 'pft_feewatch_drill-*')" ]; then
    echo "  drill textfiles still present"; RESTORE_OK=false
  else echo "  drill textfiles removed: yes"; fi
  if [ "$MAINT_STARTED" = 1 ]; then
    echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'
  fi
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
    if [ "$src" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ -n "$SIL" ]; then
    curl -s --max-time 10 -o /dev/null -w "  drill silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-feewatch alert drill (fixture replay, no network load) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)"
  echo "sha256: live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        repo pft-feewatch.sh $(sha256sum < "$REPO/feewatch/pft-feewatch.sh" | cut -c1-64) feewatch_parse.py $(sha256sum < "$REPO/feewatch/feewatch_parse.py" | cut -c1-64)"
  echo "        installed validator $(sudo -n sha256sum "$BIN" | cut -c1-64) $(sudo -n sha256sum /usr/local/lib/pft-feewatch/feewatch_parse.py | cut -c1-64)"
  echo "        installed sentry    $(R "sudo -n sha256sum $BIN" | cut -c1-64) $(R 'sudo -n sha256sum /usr/local/lib/pft-feewatch/feewatch_parse.py' | cut -c1-64)"
  echo "        feewatch.rules.yml (repo, loaded by Prometheus) $(sha256sum < "$REPO/alerts/feewatch.rules.yml" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"
  echo "        fixtures: $(cd "$FX" && sha256sum ./*.json | sha256sum | cut -c1-64) (sha256 of 'sha256sum ./*.json')"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
echo "  pft-maint: no window open on either host"
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
nsil="$(curl -s --max-time 10 "$AM/api/v2/silences" | jq --arg r "$FW_ALERTS" '[.[] | select(.status.state == "active") | select(any(.matchers[]; .name == "alertname" and .isEqual != false and (.value as $v | if .isRegex then ("PFTFeeEscalated" | test("^(" + $v + ")$")) else ($v | test("^(" + $r + ")$")) end)))] | length')"
[ "$nsil" = 0 ] || { echo "  $nsil active silence(s) cover the feewatch alerts - stopping" >&2; exit 3; }
echo "  active silences covering the feewatch alerts: 0"
na="$(pq "ALERTS{alertname=~\"$FW_ALERTS\"}" | grep -c .)"
[ "$na" = 0 ] || { echo "  $na feewatch alert(s) already pending/firing - stopping" >&2; exit 3; }
echo "  feewatch alerts pending/firing: 0"
[ -z "$(sudo -n find "$TF" -maxdepth 1 -name 'pft_feewatch_drill-*')" ] || { echo "  leftover drill textfile - stopping" >&2; exit 3; }
echo "  drill textfiles present: 0"
if ! { systemctl is-active --quiet pft-feewatch@postfiatd.timer pft-feewatch-pull@postfiatd-sentry.timer && R "systemctl is-active --quiet pft-feewatch@postfiatd-sentry.timer"; }; then
  echo "  feewatch timers not active - stopping" >&2; exit 3
fi
echo "  pft-feewatch@ timers active on both hosts, pft-feewatch-pull@postfiatd-sentry.timer active on the validator"
up="$(pq 'pft_feewatch_up == 1' | grep -cE 'container=postfiatd(-sentry)?(,|$| )')"
[ "$up" = 2 ] || { echo "  pft_feewatch_up not 1 for both nodes - stopping" >&2; exit 3; }
echo "  pft_feewatch_up 1 for postfiatd and postfiatd-sentry"
for f in "$FX"/{healthy,queue,escalated}_fee.json "$FX"/{healthy,escalated,localload,failing}_info.json; do
  [ -r "$f" ] || { echo "  fixture $f missing - stopping" >&2; exit 3; }
done
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
# shellcheck disable=SC2016  # expands on the relay: the address it sees this host connect from
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
# shellcheck disable=SC2016  # expands on the relay
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"
[ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  k="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null)"
  [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  st="$(node_state "$h" "$c")"; echo "  $c: server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }

echo; echo "== 1. redirect notifiers + bridge, silence everything except the feewatch alerts, maintenance window"
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
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src" = "$SEC/bridge.env" ] || { echo "  bridge not pointed at the throwaway env - stopping"; exit 3; }
echo "  bridge -> $NTFY/<redacted> (throwaway env file in a 0700 temp dir)"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "feewatch drill $RUN: unrelated alerts" --arg x "$FW_ALERTS|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "feewatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"$FW_ALERTS|$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"
x "sudo -n pft-maint start --ttl $TTL --reason 'pft-feewatch drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. fire: replay the five drill series every ${REFRESH}s (installed $BIN replay, fixtures only)"
echo fire > "$SEC/phase"
refresher & LOOP_PID=$!
t_fire="$(date -u +%s)"
sleep 5
x "for n in drill-queue drill-escalated drill-localload drill-failing drill-stale; do sudo -n grep -E '^pft_feewatch_(up|collect_timestamp_seconds|queue_fill_ratio|escalation_multiple|escalation_alert_threshold|local_load_exceeds_net)\\{' $TF/pft_feewatch_\$n.prom; done"
check "2a drill textfiles written: up 1 x4, up 0 for drill-failing" "$(ok_if '[ "$(grep -c "^pft_feewatch_up{container=\"drill-[a-z]*\"} 1$" <<<"$XOUT")" = 4 ] && grep -qx "pft_feewatch_up{container=\"drill-failing\"} 0" <<<"$XOUT"')"
check "2b inputs: fill 0.9, multiple 6 (threshold 4), local over net 1" "$(ok_if 'grep -qx "pft_feewatch_queue_fill_ratio{container=\"drill-queue\"} 0.9" <<<"$XOUT" && grep -qx "pft_feewatch_escalation_multiple{container=\"drill-escalated\"} 6" <<<"$XOUT" && grep -qx "pft_feewatch_local_load_exceeds_net{container=\"drill-localload\"} 1" <<<"$XOUT"')"
echo "  waiting for the five (alert, container) pairs to fire (Escalated needs 15m; max ${FIRE_WAIT}s, poll 30s)"
got=0
while [ $(( $(date -u +%s) - t_fire )) -lt "$FIRE_WAIT" ]; do
  F="$(pq "ALERTS{alertstate=\"firing\",alertname=~\"$FW_ALERTS\"}")"
  got=0
  while read -r n _ _ _ e; do grep -qE "alertname=$e,.*container=$n(,| )" <<<"$F" && got=$((got + 1)); done <<<"$PAIRS"
  [ "$got" -ge 5 ] && break
  sleep 30
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_fire ))s after the first replay):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "2c all five (alert, container) pairs firing" "$([ "$got" -ge 5 ] && echo 0 || echo 1)" "$got/5"
check "2d exactly five feewatch alerts firing (no other container or rule)" "$(ok_if '[ "$(grep -c . <<<"$F")" = 5 ]')"
check "2e no feewatch alert for the real nodes" "$(ok_if '! grep -qE "container=postfiatd(-sentry)?(,| )" <<<"$F"')"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"; dl=0
  while read -r n _ _ _ e; do
    [ "$(jq -r --arg t "[FIRING] $e" 'select(.title == $t) | .message' <<<"$M" | grep -c -- "$n ")" -ge 1 ] && dl=$((dl + 1))
  done <<<"$PAIRS"
  [ "$dl" -ge 5 ] && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "2f [FIRING] delivered to the throwaway topic for all five pairs" "$([ "$dl" -ge 5 ] && echo 0 || echo 1)" "$dl/5"

echo; echo "== 3. recover: every drill series replays the healthy answers with a fresh timestamp"
echo recover > "$SEC/phase"
t_rec="$(date -u +%s)"
# the refresher sleeps REFRESH s between rounds: wait one full round before reading the files back (run 05 read them
# 5 s after the switch and still saw the fire-phase values: check 3a failed on the harness, not the tool)
sleep $((REFRESH + 10))
x "for n in drill-queue drill-escalated drill-localload drill-failing drill-stale; do sudo -n grep -E '^pft_feewatch_(up|queue_fill_ratio|escalation_multiple|local_load_exceeds_net)\\{' $TF/pft_feewatch_\$n.prom; done"
check "3a every drill series healthy: up 1 x5, fill 0, multiple 1, exceeds 0" "$(ok_if '[ "$(grep -c "^pft_feewatch_up{container=\"drill-[a-z]*\"} 1$" <<<"$XOUT")" = 5 ] && ! grep -qE "fill_ratio\{.*\} 0\.9|multiple\{.*\} 6|exceeds_net\{.*\} 1" <<<"$XOUT"')"
declare -A RES=()
while :; do
  F="$(pq "ALERTS{alertname=~\"$FW_ALERTS\"}")"
  M="$(topic_msgs "$ALERT")"
  done_n=0
  while read -r n _ _ _ e; do
    r="$(jq -r --arg t "[RESOLVED] $e" 'select(.title == $t) | .message' <<<"$M" | grep -c -- "$n ")"
    RES["$e/$n"]="$r"
    if ! grep -qE "alertname=$e,.*container=$n(,| )" <<<"$F" && [ "$r" -ge 1 ]; then done_n=$((done_n + 1)); fi
  done <<<"$PAIRS"
  [ "$done_n" -ge 5 ] && break
  [ $(( $(date -u +%s) - t_rec )) -lt "$RESOLVE_WAIT" ] || break
  sleep 20
done
echo "  $(ts): $done_n/5 pairs resolved in Prometheus with [RESOLVED] delivered ($(( $(date -u +%s) - t_rec ))s after the healthy replay)"
for k in "${!RES[@]}"; do echo "    [RESOLVED] $k: ${RES[$k]}"; done | sort
check "3b every (alert, container) pair left Prometheus and delivered [RESOLVED]" "$([ "$done_n" -ge 5 ] && echo 0 || echo 1)" "$done_n/5"
stop_refresher
x "sudo -n find $TF -maxdepth 1 -name 'pft_feewatch_*.prom' -printf '%f\n' | sort"
check "3c refresher stopped, drill textfiles removed, the two real feewatch files remain" "$(ok_if '[ -z "$LOOP_PID" ] && ! grep -q drill- <<<"$XOUT" && [ "$(grep -c . <<<"$XOUT")" = 2 ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"$FW_ALERTS\",alertstate=\"firing\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) container=\(.metric.container) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "3d query_range shows exactly the five drill series firing during the drill" "$(ok_if '[ "$(grep -c "samples=" <<<"$XOUT")" = 5 ] && [ "$(grep -c "container=drill-" <<<"$XOUT")" = 5 ]')"

echo; echo "== 4. restore, read back"
restore
check "env files byte-identical, bridge on the operator env, window ended, no drill textfile" \
  "$([ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && echo 0 || echo 1)"
sleep 20
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
check "operator topics received nothing during the drill" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  s="$(node_state "$h" "$c")"
  check "$c full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
up="$(pq 'pft_feewatch_up == 1' | grep -cE 'container=postfiatd(-sentry)?(,|$| )')"
check "real pft_feewatch_up 1 for both nodes, timers active" "$(ok_if '[ "$up" = 2 ] && systemctl is-active --quiet pft-feewatch@postfiatd.timer pft-feewatch-pull@postfiatd-sentry.timer && R "systemctl is-active --quiet pft-feewatch@postfiatd-sentry.timer"')"
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
