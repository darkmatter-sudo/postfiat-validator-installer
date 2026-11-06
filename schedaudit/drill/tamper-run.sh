#!/usr/bin/env bash
# tamper-run: recorded two-host tamper drill for schedaudit (task_63b12600036365c3f4249ba43596cd52, step 5), on a
# THROWAWAY topic only. Built from ../../jobwatch/drill/dedup-run.sh (PASS: bridge swap, alertpath pause, catch-all
# silence that never matches the pipeline watchdog, drain before restore, operator read-back) and ./install-run.sh
# (PASS: pft-maint window with [MAINT] to a throwaway topic, keyescrow re-run after the ntfy.env restore).
#   bash schedaudit/drill/tamper-run.sh 2>&1 | tee LOG     (agent user, repo root; sudo -n, `ssh relay`)
#   PREFLIGHT_ONLY=1 bash schedaudit/drill/tamper-run.sh    (step 0 only; changes nothing)
# The drill file is /etc/cron.d/pft-sadrill, root-owned, mode 0666, one line that can never fire (31 February) and
# would only touch a marker in /run. cron itself refuses a group/other-writable cron.d file; after `apply` (0644) cron
# loads it but the schedule never matches. Negative control: the marker never exists and cron logs no CMD for it.
# 0  preflight (nothing changed). 1  pft-maint window (both hosts; pft-integrity --notify is suppressed inside it),
#    bridge -> throwaway, silence all but PFTAlertPipelineWatchdog|PFTSchedEntryUnexpected.
# 2  TAMPER: drill file on both hosts -> audit: 1 new entry + chain_writable (crit) + untracked findings;
#    PFTSchedEntryUnexpected{kind=new} and {kind=finding} FIRING for both hosts on the throwaway topic.
# 3  FIX: `pft-schedaudit apply` on both hosts -> FIXED 666 -> 644 in apply.log, chain_writable gone, nothing else
#    touched (owner, content sha256 unchanged).
# 4  REMOVE: delete the drill file -> 0 unexpected; every drill alert RESOLVED on the throwaway topic.
# 5  negative control: marker absent on both hosts, no cron CMD line for the drill file.
# 6  restore: re-run privesc (+pull) so nothing graded the drill file stays exported, drain, bridge, alertpath, end
#    window, pft-maint target back, keyescrow drift 0, silence expired only when nothing else is active, read back
#    every operator topic (0), audit 0 unexpected, integrity PASS, nodes full.
# Env: RELAY (relay) NTFY AM PROM BRIDGE_ENV AGENT_ENV SIL_TTL (90 min) FIRE_WAIT (900 s) RESOLVE_WAIT (900 s)
#      DRAIN_WAIT (600 s) DRAIN_SETTLE (90 s) AP_WAIT (180 s) PREFLIGHT_ONLY=1
# shellcheck disable=SC2016,SC2015,SC2034  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
export TZ=UTC
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
REMOTE_ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
AP_WAIT="${AP_WAIT:-180}"; SIL_TTL="${SIL_TTL:-90}"; FIRE_WAIT="${FIRE_WAIT:-900}"; RESOLVE_WAIT="${RESOLVE_WAIT:-900}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; DRAIN_WAIT="${DRAIN_WAIT:-600}"
TASK=task_63b12600
SHA_HEAD="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile
DF=/etc/cron.d/pft-sadrill; MK=/run/pft-sadrill.ran
DLINE="0 0 31 2 * root /usr/bin/touch $MK"
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-sadrill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="sadrill-$(rnd)"; TT="pft-drill-schedaudit-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\ntopic\t%s\nuser\t%s\n' "$ALERT" "$TT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g; s#cron\.d/pft-agent#cron.d/<operator-agent>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes "$RELAY" "$@" </dev/null; }
L() { bash -c "$1" </dev/null; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
both() { R "$1"; local a=$?; L "$1"; local b=$?; [ "$a" = 0 ] && [ "$b" = 0 ]; } # sentry first, then validator
cn() { if [ "$1" = relay ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
lb() { if [ "$1" = relay ]; then echo sentry; else echo validator; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
info() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"; }
node_state() { info "$1" | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
pq() { curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
# bridge titles: "[STATUS] NAME" or "[STATUS] NAME xN" (folded); one message line per alert: "<summary annotation>"
n_lines() { # STATUS HOST KIND -> PFTSchedEntryUnexpected message lines for HOST + KIND on the throwaway topic
  topic_msgs "$ALERT" | jq -r --arg t "[$1] PFTSchedEntryUnexpected" 'select(.title == $t or (.title | startswith($t + " x"))) | .message' \
    | grep -c "^$2: unexpected scheduled-execution entry ($3:"; }
collect_now() { # both collectors, then the validator's pull of the sentry file (instead of waiting up to 5 + 5 min)
  R 'sudo -n systemctl start pft-schedaudit.service' && sudo -n systemctl start pft-schedaudit.service pft-schedaudit-pull.service </dev/null; }
ux() { # HOST KIND -> pft_schedaudit_unexpected value in the textfile the exporter serves (validator dir)
  sed -nE "s/^pft_schedaudit_unexpected\{host=\"$1\",kind=\"$2\"\} ([0-9]+)$/\1/p" "$TF/pft_schedaudit_$1.prom" 2>/dev/null; }
wait_kinds() { # STATE(firing|none) STATUS(FIRING|RESOLVED) KIND...: Prometheus state for every host+kind, then >= 1 line each
  local st="$1" s="$2" t0 F hl k ok need; shift 2; t0="$(date -u +%s)"; need=$(( 2 * $# ))
  while [ $(( $(date -u +%s) - t0 )) -lt "$FIRE_WAIT" ]; do
    F="$(pq 'ALERTS{alertname="PFTSchedEntryUnexpected",alertstate="firing"}')"; ok=0
    for hl in sentry validator; do for k in "$@"; do
      if [ "$st" = firing ]; then grep -q "host=$hl,.*kind=$k\|kind=$k,.*host=$hl" <<<"$F" || continue
      else grep -q "host=$hl,.*kind=$k\|kind=$k,.*host=$hl" <<<"$F" && continue; fi
      [ "$(n_lines "$s" "$hl" "$k")" -ge 1 ] && ok=$((ok + 1))
    done; done
    [ "$ok" = "$need" ] && break; sleep 15
  done
  echo "  $(ts) ($(( $(date -u +%s) - t0 ))s): PFTSchedEntryUnexpected firing in Prometheus:"; printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
  for hl in sentry validator; do for k in "$@"; do
    local c; c="$(n_lines "$s" "$hl" "$k")"
    if [ "$st" = firing ]; then check "$hl kind=$k firing in Prometheus" "$(ok_if 'grep -q "host=$hl,.*kind=$k\|kind=$k,.*host=$hl" <<<"$F"')"
    else check "$hl kind=$k no longer firing in Prometheus" "$(ok_if '! grep -q "host=$hl,.*kind=$k\|kind=$k,.*host=$hl" <<<"$F"')"; fi
    check "[$s] PFTSchedEntryUnexpected '$hl: ... ($k: ...)' on the throwaway topic" "$(ok_if '[ "$c" -ge 1 ]')" "$c line(s)"
  done; done
  echo "  [$s] times on the throwaway topic:"
  topic_msgs "$ALERT" | jq -r --arg t "[$s] PFTSchedEntryUnexpected" 'select(.title == $t or (.title | startswith($t + " x"))) | "\(.time | todate) \(.title) | \(.message | gsub("\n"; " / "))"' | red | sed 's/^/    /'
}

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0; DRILL_FILE=0; MAINT=0; SWAPPED=0; HAD=0; ORIG_SHA=absent
ap_pause() { R 'sudo -n systemctl stop pft-alertpath-check.timer' && AP_PAUSED=1
  echo "  sentry pft-alertpath-check.timer stopped: $([ "$AP_PAUSED" = 1 ] && echo yes || echo NO)"; }
ap_resume() { # wait (<= AP_WAIT s) for a read-only check to be OK again, then start the timer whatever the result
  local t0 rc=9; t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$AP_WAIT" ]; do
    R 'sudo -n pft-alertpath check >/dev/null 2>&1'; rc=$?; [ "$rc" = 0 ] && break; sleep 10
  done
  R 'sudo -n systemctl start pft-alertpath-check.timer' && AP_PAUSED=0
  echo "  sentry pft-alertpath check rc $rc after $(( $(date -u +%s) - t0 ))s; timer started again: $([ "$AP_PAUSED" = 0 ] && echo yes || echo NO)"
  [ "$rc" = 0 ] && [ "$AP_PAUSED" = 0 ]; }
bridge_src() { sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}'; }
UNDRILL="sudo -n rm -f $DF $MK; test ! -e $DF"
others_active() { # alerts other than the pipeline watchdog pending/firing in Prometheus + active in Alertmanager
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=count(ALERTS{alertname!="PFTAlertPipelineWatchdog"})' | jq -r '.data.result[0].value[1] // 0' 2>/dev/null)"
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts?active=true" | jq '[.[] | select(.labels.alertname != "PFTAlertPipelineWatchdog")] | length' 2>/dev/null)"
  echo "$(( ${p:-1} + ${a:-1} ))"; }
drain() { # every alert of the run resolved and its RESOLVED delivered to the THROWAWAY bridge before the bridge goes back
  local t0 n=1 settle="${DRAIN_SETTLE:-90}"
  t0="$(date -u +%s)"
  while [ $(( $(date -u +%s) - t0 )) -lt "$DRAIN_WAIT" ]; do
    n="$(others_active)"; [ "$n" = 0 ] && break; sleep 10
  done
  if [ "$n" = 0 ]; then
    echo "  drain: no alert but the watchdog pending/firing/active after $(( $(date -u +%s) - t0 ))s; waiting ${settle}s for RESOLVED delivery to the throwaway bridge"
    sleep "$settle"; n="$(others_active)"
  fi
  if [ "$n" = 0 ]; then echo "  drain: done, nothing left that could reach the operator topic: yes"; return 0; fi
  echo "  drain: NO - $n alert(s) still active after ${DRAIN_WAIT}s; the catch-all silence is kept (runs out $ends)"
  pq 'ALERTS{alertname!="PFTAlertPipelineWatchdog"}' | red | sed 's/^/    /'
  KEEP_SIL=1; return 1; }
KEEP_SIL=0
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$DRILL_FILE" = 1 ]; then
    both "$UNDRILL" && echo "  drill file + marker removed on both hosts: yes" || { echo "  drill file cleanup: NO"; RESTORE_OK=false; }
    collect_now
    R 'sudo -n systemctl start pft-privesc.service' ; sudo -n systemctl start pft-privesc.service </dev/null
    sudo -n systemctl start pft-privesc-pull.service </dev/null
    echo "  schedaudit + privesc collectors (+ pulls) re-run on both hosts"
  fi
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    drain || RESTORE_OK=false
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
  if [ -n "$SIL" ] && [ "$KEEP_SIL" = 0 ] && [ "$(others_active)" = 0 ]; then
    curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
  elif [ -n "$SIL" ]; then echo "  silence kept (an alert is still active); it runs out at $ends"; fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-schedaudit two-host tamper drill - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in schedaudit/drill/tamper-run.sh schedaudit/pft-schedaudit.sh schedaudit/schedaudit_lib.py alerts/schedaudit.rules.yml alerts/ntfy_bridge.py "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
x "sha256sum schedaudit/pft-schedaudit.sh schedaudit/schedaudit_lib.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-schedaudit /usr/local/lib/pft-schedaudit/schedaudit_lib.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-schedaudit /usr/local/lib/pft-schedaudit/schedaudit_lib.py | cut -c1-64'"
check "installed pft-schedaudit + helper = repo bytes on both hosts" "$(ok_if '[ "$(sort <<<"$XOUT" | uniq -c | awk "\$1 == 3" | wc -l)" = 2 ]')"
for h in relay local; do
  on "$h" "test ! -e $DF && test ! -e $MK" || { echo "  $(lb "$h"): $DF or $MK left over - stopping" >&2; exit 3; }
  x "on $h 'sudo -n pft-schedaudit audit | grep -E \"^SUMMARY\"'"
  check "$(lb "$h"): audit 0 unexpected findings, 0 new/removed, baseline yes" "$(ok_if 'grep -q "unexpected_findings=0 new=0 removed=0 baseline=yes" <<<"$XOUT"')"
done
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname!=\"PFTAlertPipelineWatchdog\"}' | jq -r '.data.result | length'"
check "no alert but the pipeline watchdog pending/firing in Prometheus" "$(ok_if '[ "$XOUT" = 0 ]')"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
check "no active silence (an earlier rollout silence would swallow the drill alert)" "$(ok_if '[ "$XOUT" = 0 ]')"
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-schedaudit\") | .rules[] | [.name, .health] | @tsv'"
check "schedaudit rules loaded and healthy" "$(ok_if '[ "$(grep -cE "^PFTSched(EntryUnexpected|auditStale)	ok$" <<<"$XOUT")" = 2 ]')"
[ -r "$BRIDGE_ENV" ] && [ "$(bridge_src)" = "$BRIDGE_ENV" ]; check "bridge mounts the operator env file" "$?"
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1'; check "sentry pft-alertpath-check.timer active, check OK" "$?"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ]; check "operator topics found" "$?"
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; [ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
for h in relay local; do
  s="$(node_state "$h")"; check "$(cn "$h") full or proposing" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "${s:-down}"
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"
  check "pft-integrity PASS on $(lb "$h")" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
  on "$h" "sudo -n pft-maint active" >/dev/null 2>&1; mrc=$?; check "no pft-maint window open on $(lb "$h")" "$(ok_if '[ "$mrc" != 0 ]')"
done
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; check "redaction positive control" "${PIPESTATUS[0]}"
[ "$FAILS" = 0 ] || { echo "  preflight failed - stopping before any change"; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed (ready: yes)"; exit 0; fi

echo; echo "== 1. pft-maint window ([MAINT] -> throwaway), bridge -> throwaway, silence all but the watchdog + PFTSchedEntryUnexpected"
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "  real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1; check "pft-maint throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 75m --reason '$TASK schedaudit tamper drill $RUN'"
[ "$XRC" = 0 ] && MAINT=1; check "pft-maint window open (75 min)" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-schedaudit tamper drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTSchedEntryUnexpected", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "schedaudit-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTSchedEntryUnexpected\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. TAMPER: $DF (root, 0666, never fires) on both hosts"
echo "  $DF:"; echo "    | $DLINE"
B64="$(printf '%s\n' "$DLINE" | base64 -w0)"
DRILL_FILE=1
x "both \"echo $B64 | base64 -d | sudo -n tee $DF >/dev/null && sudo -n chown root:root $DF && sudo -n chmod 0666 $DF && stat -c '%a %U:%G %s' $DF && sha256sum < $DF | cut -c1-64\""
check "drill file on both hosts, 666 root:root" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -c "^666 root:root " <<<"$XOUT")" = 2 ]')"
DSHA="$(sha256sum <<<"$DLINE" | cut -c1-64)"
check "drill file content = the line above on both hosts" "$(ok_if '[ "$(grep -cx "$DSHA" <<<"$XOUT")" = 2 ]')"
T_TAMPER="$(ts)"
x "collect_now; for h in validator sentry; do grep -E '^pft_schedaudit_(up|unexpected)\{' $TF/pft_schedaudit_\$h.prom; done"
for hl in sentry validator; do
  # finding = chain_writable only: the scope hook hands every entry file to pft-integrity, so a new cron.d file is
  # never `untracked` (run 02 expected >= 2 and failed on that); the integrity check below shows the other layer
  check "$hl textfile: unexpected new 1, finding 1 (chain_writable)" "$(ok_if '[ "$(ux "$hl" new)" = 1 ] && [ "$(ux "$hl" finding)" = 1 ]')" "new $(ux "$hl" new), finding $(ux "$hl" finding)"
done
for h in relay local; do
  x "on $h 'sudo -n pft-schedaudit audit' | grep -E 'pft-sadrill|^SUMMARY'"
  check "$(lb "$h"): no untracked finding for the drill file (scope hook)" "$(ok_if '! grep -q "untracked	cron\.d/pft-sadrill" <<<"$XOUT"')"
  check "$(lb "$h"): CRIT chain_writable on $DF (mode 666) + NEW entry cron.d/pft-sadrill" "$(ok_if 'grep -qE "^CRIT	chain_writable	cron\.d/pft-sadrill@[0-9a-f]+	$DF	" <<<"$XOUT" && grep -qE "new=1 " <<<"$XOUT"')"
done
for h in relay local; do
  x "on $h 'sudo -n pft-integrity verify' | grep -E 'pft-sadrill|sched:/etc/cron.d|^RESULT' | sed -E 's/ +sha256.*//'"
  check "$(lb "$h"): pft-integrity (read-only verify, no --notify) also sees the drill file: WARN, sched:/etc/cron.d changed" "$(ok_if 'grep -q "sched:/etc/cron.d" <<<"$XOUT" && grep -qE "^RESULT: (WARN|FAIL)" <<<"$XOUT"')"
done
x "both 'sudo -n pft-schedaudit apply --dry-run | grep -E \"^PLAN|pft-sadrill\"'"
check "apply --dry-run plans exactly the drill file on each host (PLAN lines: 2)" "$(ok_if '[ "$(grep -c "^PLAN" <<<"$XOUT")" = 2 ] && [ "$(grep "^PLAN" <<<"$XOUT" | grep -vc "$DF")" = 0 ]')"
wait_kinds firing FIRING new finding

echo; echo "== 3. FIX: pft-schedaudit apply (permissions only) on both hosts"
x "both 'sudo -n pft-schedaudit apply | grep -E \"^(FIXED|SUMMARY)\"; stat -c \"%a %U:%G %s\" $DF; sha256sum < $DF | cut -c1-64; sudo -n tail -n 1 /var/lib/pft-schedaudit/apply.log'"
T_FIX="$(ts)"
check "FIXED $DF 666 -> 644 on both hosts" "$(ok_if '[ "$(grep -cE "^FIXED	$DF	0666 -> 0644$" <<<"$XOUT")" = 2 ]')"
check "owner and content unchanged (root:root, same sha256) on both hosts" "$(ok_if '[ "$(grep -c "^644 root:root " <<<"$XOUT")" = 2 ] && [ "$(grep -cx "$DSHA" <<<"$XOUT")" = 2 ]')"
check "apply.log records the change on both hosts" "$(ok_if '[ "$(grep -v "^FIXED" <<<"$XOUT" | grep -c "FIXED	$DF	0666 -> 0644")" = 2 ]')"
x "collect_now; for h in validator sentry; do grep -E '^pft_schedaudit_unexpected\{' $TF/pft_schedaudit_\$h.prom; done"
for h in relay local; do
  x "on $h 'sudo -n pft-schedaudit audit' | grep -E 'pft-sadrill|^SUMMARY'"
  check "$(lb "$h"): chain_writable on the drill file gone, 0 unexpected findings; still NEW (not accepted)" "$(ok_if '! grep -q "chain_writable	cron\.d/pft-sadrill" <<<"$XOUT" && grep -q "unexpected_findings=0 new=1 " <<<"$XOUT"')"
done
for hl in sentry validator; do
  check "$hl textfile after apply: finding 0, new 1" "$(ok_if '[ "$(ux "$hl" finding)" = 0 ] && [ "$(ux "$hl" new)" = 1 ]')" "new $(ux "$hl" new), finding $(ux "$hl" finding)"
done
wait_kinds none RESOLVED finding
F2="$(pq 'ALERTS{alertname="PFTSchedEntryUnexpected",alertstate="firing",kind="new"}')"
check "kind=new still firing for both hosts after apply (the entry is still not accepted)" "$(ok_if '[ "$(grep -cE "host=(sentry|validator)" <<<"$F2")" = 2 ]')"

echo; echo "== 4. REMOVE the drill file on both hosts -> RESOLVED"
x "both 'sudo -n rm -f $DF && test ! -e $DF && echo removed'"
check "drill file removed on both hosts" "$(ok_if '[ "$(grep -cx removed <<<"$XOUT")" = 2 ]')"
T_RM="$(ts)"
x "collect_now; for h in validator sentry; do grep -E '^pft_schedaudit_unexpected\{' $TF/pft_schedaudit_\$h.prom; done"
for hl in sentry validator; do
  check "$hl textfile: unexpected new 0, finding 0, removed 0" "$(ok_if '[ "$(ux "$hl" new)" = 0 ] && [ "$(ux "$hl" finding)" = 0 ] && [ "$(ux "$hl" removed)" = 0 ]')"
done
wait_kinds none RESOLVED new

echo; echo "== 5. negative control: the drill job never ran"
x "both 'test ! -e $MK && echo marker-absent'"
check "marker $MK absent on both hosts" "$(ok_if '[ "$(grep -cx marker-absent <<<"$XOUT")" = 2 ]')"
x "both 'sudo -n journalctl --utc _COMM=cron --since @$since --no-pager -o cat | grep -E \"pft-sadrill|$MK\" || echo \"(no cron line names the drill file)\"'"
check "no cron CMD line for the drill job on either host" "$(ok_if '! grep -q "CMD" <<<"$XOUT"')"

echo; echo "== 6. restore (privesc re-run, drain, bridge, window, target), read back"
restore
check "drill file gone, collectors re-run, drained, bridge on the operator env, window ended, target back" "$(ok_if '[ "$RESTORE_OK" = true ]')"
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$(ok_if '[ "$ORIG_SHA" = "$NOW_SHA" ]')"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(ok_if 'grep -q "} 0$" <<<"$XOUT"')"
x "topic_msgs \"\$TT\" | jq -r '.title'"
check "[MAINT] start and end reached the pft-maint throwaway topic" "$(ok_if '[ "$(grep -c "^\[MAINT\]" <<<"$XOUT")" -ge 2 ]')"
for h in relay local; do
  x "on $h 'sudo -n pft-schedaudit audit | grep -E \"^SUMMARY\"; sudo -n pft-privesc audit | tail -1'"
  check "$(lb "$h"): schedaudit 0 unexpected, privesc PASS at the end" "$(ok_if 'grep -q "unexpected_findings=0 new=0 removed=0 baseline=yes" <<<"$XOUT" && grep -q "^RESULT: PASS" <<<"$XOUT"')"
done
x "pq 'ALERTS{alertname!=\"PFTAlertPipelineWatchdog\"}'"
check "no alert but the watchdog pending/firing at the end" "$(ok_if '[ -z "$XOUT" ]')"
echo "  operator read-back waits 90 s (>= group_interval + 30 s after the silence expiry)"; sleep 90
readback() { # TOPIC LABEL [quiet]
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$ALERT" "throwaway (bridge)"
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  check "pft-integrity PASS on $(lb "$h") at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  s="$(node_state "$h")"; check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo "  timestamps: tamper $T_TAMPER, apply $T_FIX, removed $T_RM"
echo; echo "tamper-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
