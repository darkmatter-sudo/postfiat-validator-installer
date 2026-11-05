#!/usr/bin/env bash
# kmsg-run: recorded two-host alert drill for pft-kernwatch (task_1036cee24a86b033eff49eceacf32135, step 4). Writes one
# marked test record per alerting severity into each host's kernel log through /dev/kmsg and proves PFTKernelCritical
# and PFTKernelWarning go FIRING and then RESOLVED for both hosts on a throwaway ntfy topic, with zero messages on the
# operator topics. Built from ../../seccomp/drill/live-run.sh (bridge swap, silence, read-back, PREFLIGHT_ONLY).
#   bash kernwatch/drill/kmsg-run.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
# The test records (DRILL = random id, printed redacted only as its first 8 hex chars):
#   crit  oom_global  "Out of memory: Killed process 4194303 (pftkw-DRILL) total-vm:0kB, anon-rss:0kB, file-rss:0kB,
#                      shmem-rss:0kB, UID:0 pgtables:0kB oom_score_adj:0 [PFT-KERNWATCH-DRILL DRILL]"
#   warn  segfault    "segfault at 0 ip 0000000000000000 sp 0000000000000000 error 4 [PFT-KERNWATCH-DRILL DRILL]"
# Both start with a word followed by a space, so journald keeps the whole line as MESSAGE (a leading "name[pid]:" would
# become SYSLOG_IDENTIFIER and strip the marker). Userspace /dev/kmsg writes get facility LOG_USER, not kern; journald
# still files them under _TRANSPORT=kernel, which is what `journalctl -k` (and pft-kernwatch) read: step 2 checks that
# on each host before anything waits for an alert. No process is killed and nothing restarts.
# Only the Alertmanager bridge is redirected: PFTKernel* alerts have no other delivery path (the watchdog, monitor and
# integrity notifiers never read the kernel log), and leaving their env files alone keeps pft-keyescrow's fingerprints
# of those files clean (lesson from the keyescrow drill). Every other alert is silenced for the run; the operator
# topics are read back at the end (must be 0 messages).
# Run 06 paged the operator twice: the sentry's pft-alertpath check (60 s timer, its own ntfy.env) saw the bridge
# "not listening" while step 1 re-created it ([alertpath] DEGRADED 07:18:33Z, RECOVERED 07:19:33Z). An Alertmanager
# silence never reaches that notifier. Every bridge re-create (step 1 and restore) is now wrapped in ap_pause/ap_resume:
# stop pft-alertpath-check.timer on the sentry, re-create, wait until a plain `pft-alertpath check` (no --notify,
# read-only) is OK from a fresh snapshot, then start the timer again (also on every exit path).
# 0  preflight (nothing changed): clean pushed HEAD; relay, Alertmanager, Prometheus reachable; the 24 h baseline window
#    is over (BASELINE_END); pft_kernwatch_up 1 for both hosts in Prometheus; no PFTKernel* alert active; bridge on the
#    operator env; both nodes full; pft-integrity PASS on both; redaction control.
# 1  bridge -> throwaway topic; silence alertname=~".+" except PFTAlertPipelineWatchdog|PFTKernelCritical|PFTKernelWarning.
# 2  inject the two records on the sentry, then the validator; journalctl -k finds both on each host.
# 3  collect on both hosts + pull; textfiles show oom_global and segfault counters +1 for both hosts; report shows them.
# 4  FIRING: 4 series in Prometheus (2 rules x 2 hosts) and [FIRING] messages naming each host on the throwaway topic.
# 5  RESOLVED: PFTKernelCritical leaves ~15 min, PFTKernelWarning ~30 min after the records; [RESOLVED] per host.
# 6  restore (bridge, silence), read back every operator topic, integrity PASS, nodes full, kernwatch up.
# Env: RELAY (relay) NTFY (https://ntfy.sh) AM PROM BRIDGE_ENV AGENT_ENV BASELINE_END (2026-11-05T07:17:00Z)
#      SIL_TTL (60 min) FIRE_WAIT (600 s) RESOLVE_WAIT (2700 s) PREFLIGHT_ONLY=1: step 0 only (exit 0 ready, 4 not).
# shellcheck disable=SC2016,SC2015,SC2034  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"; RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
REMOTE_ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
BASELINE_END="${BASELINE_END:-2026-11-05T07:17:00Z}"
AP_WAIT="${AP_WAIT:-180}"; SIL_TTL="${SIL_TTL:-60}"; FIRE_WAIT="${FIRE_WAIT:-600}"; RESOLVE_WAIT="${RESOLVE_WAIT:-2700}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; NOT_READY=0
TASK=task_1036cee2
SHA_HEAD="$(git rev-parse HEAD)"
TF=/var/lib/pft-exporter/textfile

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="kwdrill-$(rnd)"; DRILL="$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#$DRILL#${DRILL:0:8}…#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
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
n_msgs() { # STATUS ALERTNAME HOST CLASS -> count of matching throwaway-topic messages
  topic_msgs "$ALERT" | jq -r --arg t "[$1] $2" 'select(.title == $t) | .message' | grep -c "^$3: kernel $4 "
}

RESTORED=0; RESTORE_OK=true; SIL=""; BRIDGE_SWAPPED=0; AP_PAUSED=0
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
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    [ "$AP_PAUSED" = 1 ] || ap_pause
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    if [ "$(bridge_src)" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "$AP_PAUSED" = 1 ]; then ap_resume || RESTORE_OK=false; fi
  [ -n "$SIL" ] && curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-kernwatch two-host /dev/kmsg alert drill - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in kernwatch/drill/kmsg-run.sh kernwatch/pft-kernwatch.sh kernwatch/kernwatch_parse.py kernwatch/catalogue.tsv \
           alerts/kernwatch.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
if [ "$(date -u +%s)" -lt "$(date -u -d "$BASELINE_END" +%s)" ]; then
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  the 24 h baseline window runs until $BASELINE_END - a real run would stop here"; NOT_READY=1
  else echo "  the 24 h baseline window runs until $BASELINE_END - stopping (the drill records would sit in the baseline)" >&2; exit 4; fi
else echo "  baseline window over ($BASELINE_END)"; fi
for h in local relay; do
  on "$h" "command -v pft-kernwatch >/dev/null && systemctl is-active --quiet pft-kernwatch.timer" \
    || { echo "  $(lb "$h"): pft-kernwatch or its timer missing - stopping" >&2; exit 3; }
done
systemctl is-active --quiet pft-kernwatch-pull.timer || { echo "  pft-kernwatch-pull.timer not active - stopping" >&2; exit 3; }
for h in local relay; do # run 06: the installed report rejected `--since -15min` (argparse), fixed at ca7d08c
  on "$h" "sudo -n pft-kernwatch report --since -1min --format tsv >/dev/null 2>&1" \
    || { echo "  $(lb "$h"): installed pft-kernwatch report rejects --since -1min (pre-ca7d08c build) - stopping" >&2; exit 3; }
done
echo "  installed pft-kernwatch report accepts --since -1min on both hosts"
R 'systemctl is-active --quiet pft-alertpath-check.timer && sudo -n pft-alertpath check >/dev/null 2>&1' \
  || { echo "  sentry pft-alertpath-check.timer not active or check not OK - stopping" >&2; exit 3; }
echo "  sentry pft-alertpath-check.timer active, check OK"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_kernwatch_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
[ "$(grep -cE '^(sentry|validator) 1$' <<<"$XOUT")" = 2 ] || { echo "  pft_kernwatch_up is not 1 for both hosts - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTKernel.*\"}' | jq -r '.data.result | length'"
[ "$XOUT" = 0 ] || { echo "  a PFTKernel* alert is already active (investigate it first) - stopping" >&2; exit 4; }
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-kernwatch\") | .rules[] | [.name, .health] | @tsv'"
[ "$(grep -cE '^PFTKernel(Critical|Warning)	ok$' <<<"$XOUT")" = 2 ] || { echo "  kernwatch rules not loaded/healthy - stopping" >&2; exit 4; }
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
[ "$(bridge_src)" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f 2>/dev/null"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; [ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
for h in relay local; do
  s="$(node_state "$h")"; echo "  $(cn "$h"): server_state=${s:-down}"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then
  echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed (ready: $([ "$NOT_READY" = 0 ] && echo yes || echo "no, see the would-stop lines above"))"
  exit $(( NOT_READY ? 4 : 0 ))
fi

echo; echo "== 1. bridge -> throwaway topic; silence everything except the two rules under test and the watchdog"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
ap_pause; check "sentry pft-alertpath-check.timer paused for the bridge re-create" "$(ok_if '[ "$AP_PAUSED" = 1 ]')"
[ "$FAILS" = 0 ] || exit 3
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
check "Alertmanager bridge -> throwaway env file (0700 temp dir)" "$(ok_if '[ "$(bridge_src)" = "$SEC/bridge.env" ]')"
ap_resume; check "sentry pft-alertpath OK again, check timer running" "$?"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-kernwatch kmsg drill $RUN" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog|PFTKernelCritical|PFTKernelWarning", isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "kernwatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "silence alertname=~\".+\", alertname!~\"PFTAlertPipelineWatchdog|PFTKernelCritical|PFTKernelWarning\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. inject one marked record per alerting severity into each host's kernel log (/dev/kmsg)"
CRIT="Out of memory: Killed process 4194303 (pftkw-${DRILL:0:8}) total-vm:0kB, anon-rss:0kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:0kB oom_score_adj:0 [PFT-KERNWATCH-DRILL $DRILL]"
WARN="segfault at 0 ip 0000000000000000 sp 0000000000000000 error 4 [PFT-KERNWATCH-DRILL $DRILL]"
t_inj="$(date -u +%s)"
for h in relay local; do
  ic="printf '<3>%s\\n' '$CRIT' | sudo -n tee /dev/kmsg >/dev/null && printf '<6>%s\\n' '$WARN' | sudo -n tee /dev/kmsg >/dev/null"
  echo "\$ [$(lb "$h")] $ic" | red
  on "$h" "$ic"; rc=$?; echo "  (exit $rc)"
  check "$(lb "$h"): both records written to /dev/kmsg" "$rc"
  sleep 2
  echo "\$ [$(lb "$h")] sudo -n journalctl -k -b --since -5min -o json --no-pager | grep -F 'PFT-KERNWATCH-DRILL $DRILL' | jq -r '[._TRANSPORT, .SYSLOG_FACILITY, .PRIORITY, first 3 words of MESSAGE] | @tsv'" | red
  XOUT="$(on "$h" "sudo -n journalctl -k -b --since -5min -o json --no-pager" | grep -F "PFT-KERNWATCH-DRILL $DRILL" \
    | jq -r '[._TRANSPORT, .SYSLOG_FACILITY, .PRIORITY, (.MESSAGE | split(" ")[0:3] | join(" "))] | @tsv')"
  printf '%s\n' "$XOUT" | red | sed 's/^/  /'
  check "$(lb "$h"): journalctl -k finds both marked records (_TRANSPORT=kernel)" "$(ok_if '[ "$(grep -c "^kernel	" <<<"$XOUT")" = 2 ]')"
done
[ "$FAILS" = 0 ] || { echo "  injection not visible to journalctl -k - stopping"; exit 4; }

echo; echo "== 3. collect on both hosts + pull; counters and report"
x "R 'sudo -n systemctl start pft-kernwatch.service; systemctl show -p Result --value pft-kernwatch.service' && sudo -n systemctl start pft-kernwatch.service pft-kernwatch-pull.service; systemctl show -p Result --value pft-kernwatch.service pft-kernwatch-pull.service; grep -hE '^pft_kernwatch_matches_total\{.*pattern=\"(oom_global|segfault)\"' $TF/pft_kernwatch_validator.prom $TF/pft_kernwatch_sentry.prom"
for hl in validator sentry; do
  check "$hl textfile: oom_global >= 1 and segfault >= 1" \
    "$(ok_if 'grep -qE "host=\"$hl\",pattern=\"oom_global\".* [1-9][0-9]*$" <<<"$XOUT" && grep -qE "host=\"$hl\",pattern=\"segfault\".* [1-9][0-9]*$" <<<"$XOUT"')"
done
for h in relay local; do
  x "on $h 'sudo -n pft-kernwatch report --since -15min --format tsv'"
  check "$(lb "$h"): report lists oom_global and segfault" "$(ok_if 'grep -q "oom_global" <<<"$XOUT" && grep -q "segfault" <<<"$XOUT"')"
done

echo; echo "== 4. FIRING: PFTKernelCritical (oom) + PFTKernelWarning (segv) for both hosts"
F=""
while [ $(( $(date -u +%s) - t_inj )) -lt "$FIRE_WAIT" ]; do
  F="$(pq 'ALERTS{alertname=~"PFTKernelCritical|PFTKernelWarning",alertstate="firing"}')"
  [ "$(grep -cE 'host=(sentry|validator)' <<<"$F")" -ge 4 ] && break; sleep 15
done
echo "  $(ts) ($(( $(date -u +%s) - t_inj ))s after the records):"; printf '%s\n' "${F:-none}" | red | sed 's/^/    /'
for hl in sentry validator; do
  check "PFTKernelCritical{host=$hl,pattern=oom_global} firing" "$(ok_if 'grep -E "alertname=PFTKernelCritical" <<<"$F" | grep "host=$hl" | grep -q "pattern=oom_global"')"
  check "PFTKernelWarning{host=$hl,pattern=segfault} firing" "$(ok_if 'grep -E "alertname=PFTKernelWarning" <<<"$F" | grep "host=$hl" | grep -q "pattern=segfault"')"
done
w=0
while :; do
  ok=0
  for hl in sentry validator; do
    [ "$(n_msgs FIRING PFTKernelCritical "$hl" oom)" -ge 1 ] && ok=$((ok + 1))
    [ "$(n_msgs FIRING PFTKernelWarning "$hl" segv)" -ge 1 ] && ok=$((ok + 1))
  done
  [ "$ok" = 4 ] && break
  w=$((w + 15)); [ "$w" -le 300 ] || break; sleep 15
done
for hl in sentry validator; do
  check "[FIRING] PFTKernelCritical '$hl: kernel oom ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs FIRING PFTKernelCritical "$hl" oom)" -ge 1 ]')"
  check "[FIRING] PFTKernelWarning '$hl: kernel segv ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs FIRING PFTKernelWarning "$hl" segv)" -ge 1 ]')"
done

echo; echo "== 5. RESOLVED: no new record; Critical leaves after its 15 min window, Warning after 30 min"
t_res=""; while [ $(( $(date -u +%s) - t_inj )) -lt "$RESOLVE_WAIT" ]; do
  F="$(pq 'ALERTS{alertname=~"PFTKernelCritical|PFTKernelWarning"}')"
  ok=0
  for hl in sentry validator; do
    [ "$(n_msgs RESOLVED PFTKernelCritical "$hl" oom)" -ge 1 ] && ok=$((ok + 1))
    [ "$(n_msgs RESOLVED PFTKernelWarning "$hl" segv)" -ge 1 ] && ok=$((ok + 1))
  done
  [ -z "$F" ] && [ "$ok" = 4 ] && { t_res="$(date -u +%s)"; break; }
  sleep 60
done
echo "  $(ts): alerts left in Prometheus: $(grep -c . <<<"$F")"
check "no PFTKernel* alert left in Prometheus" "$(ok_if '[ -z "$F" ]')" "${t_res:+$(( t_res - t_inj ))s after the records}"
for hl in sentry validator; do
  check "[RESOLVED] PFTKernelCritical '$hl: kernel oom ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs RESOLVED PFTKernelCritical "$hl" oom)" -ge 1 ]')"
  check "[RESOLVED] PFTKernelWarning '$hl: kernel segv ...' on the throwaway topic" "$(ok_if '[ "$(n_msgs RESOLVED PFTKernelWarning "$hl" segv)" -ge 1 ]')"
done

echo; echo "== 6. restore, read back"
restore
check "bridge back on the operator env, silence expired" "$(ok_if '[ "$RESTORE_OK" = true ]')"
sleep 60
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
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=pft_kernwatch_up' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "pft_kernwatch_up 1 for both hosts at the end" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 1$" <<<"$XOUT")" = 2 ]')"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $(lb "$h"): $r"
  check "pft-integrity PASS on $(lb "$h") at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  s="$(node_state "$h")"
  check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "kmsg-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
