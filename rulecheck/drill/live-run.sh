#!/usr/bin/env bash
# live-run: the pft-rulecheck two-host drill (stale collector on the sentry + dead rule on the validator).
# Built from ../../statewatch/drill/live-run.sh (redirect / bridge swap / silence / read-back framework).
#   bash rulecheck/drill/live-run.sh 2>&1 | tee LOG     (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): relay, Alertmanager, Prometheus reachable; no pft-maint window; notifier env files
#    present, no leftovers; the bridge mounts the operator env; Prometheus mounts SLO_DIR at /etc/pft-slo; no active
#    silence covers the rulecheck alerts; both nodes full; pft-rulecheck exit 0 on both hosts; pft-integrity PASS on
#    both; redaction positive control. Operator topics, user name, host addresses and node keys go into a 0600
#    literals file for redact.py.
# 1  redirect: LOCAL_ENVS / REMOTE_ENVS get a throwaway topic (sha256 recorded, restored on ANY exit and compared),
#    the bridge is recreated with a throwaway NTFY_ENV_FILE; Alertmanager silence for every alert EXCEPT the three
#    rulecheck alerts and the pipeline watchdog (the collector stop also trips PFTStatewatchStale - silenced);
#    sudo pft-maint start on the validator, wait until the sentry has the window too.
# 2  faults: (a) stale collector: stop COLLECTOR_TIMER on the sentry. Its textfile goes stale by mtime there; on the
#    validator the 1-minute pull keeps re-copying it (fresh mtime) with an ageing collect timestamp.
#    (b) dead rule: DRILL_RULE (an alert on a metric nobody exports) is written to SLO_DIR and Prometheus reloaded.
# 3  detect: wait until the validator's pulled copy reads STALE by content, then one pft-rulecheck run on the sentry,
#    one pull + one run on the validator, through the real units. Checks: exactly the expected DEAD rule and STALE
#    files (validator: pulled copy STALE with source = timestamp metric; sentry: local file STALE by mtime); then
#    PFTRuleDead + PFTTextfileStale (host=validator and host=sentry) firing in Prometheus and delivered as [FIRING]
#    to the throwaway topic.
# 4  recover: remove DRILL_RULE + reload, start COLLECTOR_TIMER; wait for a fresh collection and pull; runs on both
#    hosts must exit 0; the alerts must leave Prometheus and [RESOLVED] reach the throwaway topic.
# 5  restore env files + bridge (mount source read back), pft-maint end, expire the silence, read back the throwaway
#    topic and count messages on every operator topic since the start (topics never printed); pft-integrity PASS on
#    both hosts, both nodes full, collector timer active. Exit 0 = every CHECK ok.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  PROM (http://127.0.0.1:9090)
#      COLLECTOR_TIMER (pft-statewatch@postfiatd-sentry.timer)  PULLED (pft_statewatch_postfiatd-sentry.prom)
#      SLO_DIR (../../slo)  LOCAL_ENVS  REMOTE_ENVS  BRIDGE_ENV  AGENT_ENV  TTL (45m)  SIL_TTL (50, min)
#      STALE_WAIT (600, s)  FIRE_WAIT (600, s)  NTFY_WAIT (180, s)  REDACT (../../peerexpose/drill/redact.py)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REDACT="${REDACT:-$REPO/peerexpose/drill/redact.py}"
RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
COLLECTOR_TIMER="${COLLECTOR_TIMER:-pft-statewatch@postfiatd-sentry.timer}"
PULLED="${PULLED:-pft_statewatch_postfiatd-sentry.prom}"
SLO_DIR="$(readlink -f "${SLO_DIR:-$REPO/slo}")"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
TTL="${TTL:-45m}"; SIL_TTL="${SIL_TTL:-50}"
STALE_WAIT="${STALE_WAIT:-600}"; FIRE_WAIT="${FIRE_WAIT:-600}"; NTFY_WAIT="${NTFY_WAIT:-180}"
RC_ALERTS='PFTRuleDead|PFTTextfileStale|PFTRulecheckNotRunning'
WATCHDOG_ALERT=PFTAlertPipelineWatchdog
DRILL_NAME=PFTRulecheckDrillDeadRule
DRILL_RULE="$SLO_DIR/zz-rulecheck-drill.rules.yml"
SUF=.pre-rulecheck-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="rcdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
FAILS=0
check() { # NAME 0|1 DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
XRC=0; XOUT=""
x() { # print the exact command, run it, print its output (redacted) and exit code; output kept in XOUT
  echo "\$ $*"
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
# json state of one textfile row from `pft-rulecheck check --json` on HOST
rc_json() { on "$1" "sudo -n pft-rulecheck check --json"; }

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0; MAINT_STARTED=0; TIMER_STOPPED=0; RULE_WRITTEN=0; SIL=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha src
  if [ "$RULE_WRITTEN" = 1 ] && [ -e "$DRILL_RULE" ]; then
    rm -f "$DRILL_RULE" && sudo -n docker kill -s HUP pft-prometheus >/dev/null && echo "  drill rule removed, Prometheus reloaded"
  fi
  if [ "$TIMER_STOPPED" = 1 ]; then
    R "sudo -n systemctl start $COLLECTOR_TIMER" && echo "  sentry $COLLECTOR_TIMER started"
    R "systemctl is-active --quiet $COLLECTOR_TIMER" || { echo "  sentry $COLLECTOR_TIMER NOT active"; RESTORE_OK=false; }
  fi
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

{ echo "pft-rulecheck two-host drill - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)"
  echo "sha256: live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        repo pft-rulecheck.sh $(sha256sum < "$REPO/rulecheck/pft-rulecheck.sh" | cut -c1-64) rulecheck_lib.py $(sha256sum < "$REPO/rulecheck/rulecheck_lib.py" | cut -c1-64)"
  echo "        installed validator $(sudo -n sha256sum /usr/local/bin/pft-rulecheck | cut -c1-64) $(sudo -n sha256sum /usr/local/lib/pft-rulecheck/rulecheck_lib.py | cut -c1-64)"
  echo "        installed sentry    $(R 'sudo -n sha256sum /usr/local/bin/pft-rulecheck' | cut -c1-64) $(R 'sudo -n sha256sum /usr/local/lib/pft-rulecheck/rulecheck_lib.py' | cut -c1-64)"
  echo "        rulecheck.rules.yml (repo, loaded by Prometheus) $(sha256sum < "$REPO/alerts/rulecheck.rules.yml" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

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
slo_src="$(sudo -n docker inspect pft-prometheus --format '{{range .Mounts}}{{if eq .Destination "/etc/pft-slo"}}{{.Source}}{{end}}{{end}}')"
[ "$(readlink -f "$slo_src")" = "$SLO_DIR" ] || { echo "  Prometheus does not mount SLO_DIR at /etc/pft-slo - stopping" >&2; exit 3; }
[ ! -e "$DRILL_RULE" ] || { echo "  leftover drill rule file - stopping" >&2; exit 3; }
echo "  Prometheus loads /etc/pft-slo/*.rules.yml from the repo's slo/ dir: yes; no leftover drill rule"
nsil="$(curl -s --max-time 10 "$AM/api/v2/silences" | jq --arg r "$RC_ALERTS" '[.[] | select(.status.state == "active") | select(any(.matchers[]; .name == "alertname" and .isEqual != false and (.value as $v | if .isRegex then ("PFTRuleDead" | test("^(" + $v + ")$")) else ($v | test("^(" + $r + ")$")) end)))] | length')"
[ "$nsil" = 0 ] || { echo "  $nsil active silence(s) cover the rulecheck alerts - stopping" >&2; exit 3; }
echo "  active silences covering the rulecheck alerts: 0"
R "systemctl is-active --quiet $COLLECTOR_TIMER" || { echo "  sentry $COLLECTOR_TIMER not active - stopping" >&2; exit 3; }
echo "  sentry $COLLECTOR_TIMER: active"
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
x "sudo -n pft-rulecheck check | tail -1"
check "baseline: validator pft-rulecheck exit 0" "$([ "$XRC" = 0 ] && echo 0 || echo 1)"
x "R 'sudo -n pft-rulecheck check' | tail -1"
check "baseline: sentry pft-rulecheck exit 0" "$([ "$XRC" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }

echo; echo "== 1. redirect notifiers + bridge, silence everything except the rulecheck alerts, maintenance window"
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
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "rulecheck drill $RUN: unrelated alerts" --arg x "$RC_ALERTS|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "rulecheck-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"$RC_ALERTS|$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"
x "sudo -n pft-maint start --ttl $TTL --reason 'pft-rulecheck drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. faults"
t_fault="$(date -u +%s)"
x "R 'sudo -n systemctl stop $COLLECTOR_TIMER && systemctl is-active $COLLECTOR_TIMER'"
TIMER_STOPPED=1
check "2a sentry collector timer stopped" "$([ "$(R "systemctl is-active $COLLECTOR_TIMER")" = inactive ] && echo 0 || echo 1)"
cat > "$DRILL_RULE" <<EOF
# pft-rulecheck drill $RUN: an alert on a metric nobody exports (a renamed metric). Removed at the end of the drill.
groups:
  - name: pft-rulecheck-drill
    rules:
      - alert: $DRILL_NAME
        expr: pft_rulecheck_drill_renamed_metric_total > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "drill rule (never fires: its metric does not exist)"
EOF
RULE_WRITTEN=1
x "sudo -n docker kill -s HUP pft-prometheus && sleep 20 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-rulecheck-drill\") | .rules[] | [.name, .health, .query] | @tsv'"
check "2b drill rule loaded by Prometheus" "$(grep -q "^$DRILL_NAME	ok	" <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 3. detect"
echo "  waiting for the validator's pulled $PULLED to read STALE by content (max ${STALE_WAIT}s, poll 30s)"
st=""
while [ $(( $(date -u +%s) - t_fault )) -lt "$STALE_WAIT" ]; do
  st="$(rc_json local | jq -r --arg f "$PULLED" '[.textfiles[] | select(.file == $f)][0] | "\(.state) age=\(.age) src=\(.source)"')"
  case "$st" in STALE*) break ;; esac
  sleep 30
done
echo "  $(ts) validator $PULLED: $st ($(( $(date -u +%s) - t_fault ))s after the stop)"
check "3a pulled copy STALE on the validator, judged by its content timestamp" \
  "$(case "$st" in "STALE "*"src=pft_statewatch_collect_timestamp_seconds") echo 0 ;; *) echo 1 ;; esac)" "$st"
x "sudo -n stat -c 'mtime %Y now $(date -u +%s)' /var/lib/pft-exporter/textfile/$PULLED"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^(STALE|MISSING|LEFTOVER|UNCONFIGURED|RESULT) '"
# on the sentry the stopped collector's file ages on both clocks (mtime and collect timestamp, ~1 s apart); the
# verdict names whichever is older, so only STALE + the single finding are asserted (run 1 wrongly required "mtime")
check "3b sentry run: its local $PULLED STALE, RESULT FINDINGS with STALE 1" "$(grep -qE "^STALE +$PULLED " <<<"$XOUT" && grep -q '^RESULT FINDINGS .*STALE 1 ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck-pull.service && sudo -n grep -E '^pft_rulecheck_textfile_stale.*} 1$' /var/lib/pft-exporter/textfile/pft_rulecheck_sentry.prom"
check "3c sentry result pulled to the validator (stale=1 for $PULLED)" "$(grep -q "file=\"$PULLED\",state=\"STALE\"} 1" <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^(DEAD|PARTIAL|ERROR|STALE|MISSING|LEFTOVER|UNCONFIGURED|RESULT) '"
check "3d validator run: exactly 1 DEAD (the drill rule) and 1 STALE (the pulled copy)" \
  "$(grep -qE "^DEAD +pft-rulecheck-drill/$DRILL_NAME +0/1 +pft_rulecheck_drill_renamed_metric_total" <<<"$XOUT" \
     && grep -qE "^STALE +$PULLED .*pft_statewatch_collect_timestamp_seconds" <<<"$XOUT" \
     && grep -qE '^RESULT FINDINGS - rules: LIVE [0-9]+ PARTIAL 0 DEAD 1 ERROR 0 IGNORED 0 \| textfiles: FRESH [0-9]+ STALE 1 MISSING 0 LEFTOVER 0 UNCONFIGURED 0' <<<"$XOUT" && echo 0 || echo 1)"
t_det="$(date -u +%s)"
echo "  waiting for PFTRuleDead + PFTTextfileStale (validator + sentry) to fire in Prometheus (for: 5m; max ${FIRE_WAIT}s, poll 20s)"
want=3; got=0
while [ $(( $(date -u +%s) - t_det )) -lt "$FIRE_WAIT" ]; do
  F="$(pq "ALERTS{alertstate=\"firing\",alertname=~\"PFTRuleDead|PFTTextfileStale\"}")"
  got=0
  grep -q "alertname=PFTRuleDead,.*rule=$DRILL_NAME" <<<"$F" && got=$((got + 1))
  grep -qE "alertname=PFTTextfileStale,.*file=$PULLED,host=validator" <<<"$F" && got=$((got + 1))
  grep -qE "alertname=PFTTextfileStale,.*file=$PULLED,host=sentry" <<<"$F" && got=$((got + 1))
  [ "$got" -ge "$want" ] && break
  sleep 20
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_det ))s after the runs):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "3e PFTRuleDead (drill rule) + PFTTextfileStale (host=validator, host=sentry) firing" "$([ "$got" -ge "$want" ] && echo 0 || echo 1)" "$got/$want"
echo "  waiting for [FIRING] delivery on the throwaway topic (max ${NTFY_WAIT}s)"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"
  nd="$(jq -r 'select(.title == "[FIRING] PFTRuleDead") | .message' <<<"$M" | grep -c "$DRILL_NAME")"
  ns="$(jq -r 'select(.title == "[FIRING] PFTTextfileStale") | .message' <<<"$M" | grep -c "$PULLED")"
  { [ "$nd" -ge 1 ] && [ "$ns" -ge 1 ]; } && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "3f [FIRING] PFTRuleDead naming $DRILL_NAME delivered to the throwaway topic" "$([ "$nd" -ge 1 ] && echo 0 || echo 1)" "$nd"
check "3g [FIRING] PFTTextfileStale naming $PULLED delivered to the throwaway topic" "$([ "$ns" -ge 1 ] && echo 0 || echo 1)" "$ns"

echo; echo "== 4. recover"
t_rec="$(date -u +%s)"
rm -f "$DRILL_RULE"
x "sudo -n docker kill -s HUP pft-prometheus && sleep 20 && curl -s $PROM/api/v1/rules | jq '[.data.groups[] | select(.name == \"pft-rulecheck-drill\")] | length'"
check "4a drill rule gone from Prometheus" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "R 'sudo -n systemctl start $COLLECTOR_TIMER && sudo -n systemctl start ${COLLECTOR_TIMER%.timer}.service && systemctl is-active $COLLECTOR_TIMER'"
TIMER_STOPPED=0
check "4b sentry collector timer active again" "$([ "$(tail -1 <<<"$XOUT")" = active ] && echo 0 || echo 1)"
echo "  waiting for the validator's pull to carry a fresh collection (statewatch pull runs every minute)"
st=""
for _ in $(seq 12); do
  st="$(rc_json local | jq -r --arg f "$PULLED" '[.textfiles[] | select(.file == $f)][0] | "\(.state) age=\(.age)"')"
  case "$st" in FRESH*) break ;; esac
  sleep 15
done
echo "  $(ts) validator $PULLED: $st"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "4c sentry run exit 0 (RESULT OK)" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck-pull.service && sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "4d validator run exit 0 (RESULT OK)" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
echo "  waiting for the alerts to leave Prometheus and [RESOLVED] to reach the throwaway topic (max ${NTFY_WAIT}s)"
w=0
while :; do
  F="$(pq "ALERTS{alertname=~\"PFTRuleDead|PFTTextfileStale\"}")"
  M="$(topic_msgs "$ALERT")"
  rd="$(jq -r 'select(.title == "[RESOLVED] PFTRuleDead") | .message' <<<"$M" | grep -c "$DRILL_NAME")"
  rs="$(jq -r 'select(.title == "[RESOLVED] PFTTextfileStale") | .message' <<<"$M" | grep -c "$PULLED")"
  { [ -z "$F" ] && [ "$rd" -ge 1 ] && [ "$rs" -ge 1 ]; } && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "4e no PFTRuleDead / PFTTextfileStale alert left in Prometheus" "$([ -z "$F" ] && echo 0 || echo 1)" "$(grep -c . <<<"${F:-}") alert(s)"
check "4f [RESOLVED] PFTRuleDead + PFTTextfileStale delivered to the throwaway topic" "$([ "$rd" -ge 1 ] && [ "$rs" -ge 1 ] && echo 0 || echo 1)" "PFTRuleDead $rd, PFTTextfileStale $rs"
echo "  recovery took $(( $(date -u +%s) - t_rec ))s"

echo; echo "== 5. restore, read back"
restore
check "drill rule removed, collector timer active, env files byte-identical, bridge on the operator env, window ended" \
  "$([ "$RESTORE_OK" = true ] && [ ! -e "$DRILL_RULE" ] && ! sudo -n pft-maint active >/dev/null 2>&1 && echo 0 || echo 1)"
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
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
