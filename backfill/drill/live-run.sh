#!/usr/bin/env bash
# live-run: recorded two-host install of pft-backfill, a sentry-only live ledger gap + capped verified repair, and the
# FIRING -> RESOLVED alert drill on a throwaway topic.
# Built from ../../cluster/drill/live-run.sh (install / redirect / silence / window / read-back, PASS run 09) and
# ../../upgradewatch/drill/live-run.sh (bridge swap + drill-textfile refresher, PASS run 12).
#   bash backfill/drill/live-run.sh 2>&1 | tee LOG    (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): clean pushed HEAD with the run-commit lines; relay, Alertmanager, Prometheus
#    reachable; no pft-maint window; no data collector reading the validator's node; notifier env files present, no
#    leftovers; the bridge mounts the operator env; no backfill alert active, no silence covering them, no drill file;
#    pft-maint status --json and the public RPC answer on both hosts; both nodes full; pft-integrity PASS on both;
#    redaction positive control. Topics, user, addresses and node keys go into a 0600 literals file; never printed.
# 1  redirect notifiers + bridge to a throwaway topic, silence every alert EXCEPT the two backfill alerts and the
#    pipeline watchdog, pft-maint window (the sentry gets it too).
# 2  install on both hosts (+ the validator's pull of the sentry files); Prometheus loads both backfill rules.
# 3  before: status (text + --json) on both hosts; a repair --apply inside the window must be REFUSED (exit 4).
#    The alert drill starts: a refresher writes pft_backfill_drill.prom (node="drill-gap": 37 interior ledgers missing
#    on a full node -> PFTBackfillGap after 20m; node="drill-down": up 0 -> PFTBackfillCheckFailed after 10m).
# 4  live gap on the SENTRY only: stop postfiatd-sentry for GAP_STOP s (longer than ledger_history 256 ledgers, so the
#    node's own restart backfill cannot reach the hole), start it, wait for full. The validator keeps its ~10 other
#    peers (the sentry is only its [ips_fixed] peer), so it keeps syncing and gets no gap. The real sentry status reads
#    up 0 while stopped, so PFTBackfillCheckFailed{node="sentry"} is expected to fire live too.
# 5  drill alerts: both drill pairs firing + [FIRING] delivered to the throwaway topic.
# 6  pft-maint end (repair refuses inside a window), then on the sentry: status, repair dry run, repair --apply
#    (capped), status after. If normal sync already closed every gap, that is recorded (fixture fallback = the
#    offline repair suite) instead of a repair.
# 7  recover: drill series healthy -> both pairs leave Prometheus with [RESOLVED] delivered; every real backfill alert
#    clears; the drill file is removed. ALERTS query_range for the run.
# 8  metrics (units on both hosts, pull, Prometheus), 9 baselines (integrity accept, fleet sync + skew, rulecheck),
#    10 restore + read-back of the throwaway topic and every operator topic (counts only). The fleet sync in 9 runs in a
#    second short window (pft-fleet refuses without one); restore ends it.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM  PROM  LOCAL_ENVS  REMOTE_ENVS  BRIDGE_ENV  AGENT_ENV  TTL (150m)
#      SIL_TTL (240, min)  GAP_STOP (1080, s)  FIRE_WAIT (2400, s)  RESOLVE_WAIT (1200, s)  NTFY_WAIT (180, s)
#      CLEAR_WAIT (900, s)  READBACK_WAIT (150, s)  REFRESH (20, s)  REPAIR_ARGS
#      PREFLIGHT_ONLY=1: step 0 only, nothing changed; exit 0 = ready, 4 = not ready.
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"
RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_ENV=/etc/pft-maint/ntfy.env
TTL="${TTL:-150m}"; SIL_TTL="${SIL_TTL:-240}"; GAP_STOP="${GAP_STOP:-1080}"; REFRESH="${REFRESH:-20}"
FIRE_WAIT="${FIRE_WAIT:-2400}"; RESOLVE_WAIT="${RESOLVE_WAIT:-1200}"; NTFY_WAIT="${NTFY_WAIT:-180}"
CLEAR_WAIT="${CLEAR_WAIT:-900}"; READBACK_WAIT="${READBACK_WAIT:-150}"
REPAIR_ARGS="${REPAIR_ARGS:---max-ledgers 32 --interval 1 --wait 120 --max-runtime 900}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; NOT_READY=0
COLLECTORS="${COLLECTORS:-pft-payflow-tx.service pft-senders-tx.service}"
BF_ALERTS='PFTBackfillGap|PFTBackfillCheckFailed'; WATCHDOG_ALERT=PFTAlertPipelineWatchdog
PUBLIC_RPC=https://rpc.testnet.postfiat.org/
TF=/var/lib/pft-exporter/textfile; DRILLF="$TF/pft_backfill_drill.prom"
PAIRS="drill-gap PFTBackfillGap
drill-down PFTBackfillCheckFailed"
TASK=task_b2987318
SUF=.pre-backfill-live
SHA_HEAD="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
RDIR="/var/tmp/pft-backfill-live-$SHORT"   # sentry copy of the tree (read with bash, never executed from a noexec mount)

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="bflive-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"; LAST_START="$since"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
cn() { if [ "$1" = relay ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
info() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"; }
node_state() { info "$1" | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
node_key() { info "$1" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null; }
started() { LAST_START="$(date -u +%s)"; } # every node (re)start pushes the post-run silence end out
pq() { # QUERY -> "labels value" lines
  curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric | del(.__name__) | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'
}
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
status_json() { on "$1" "sudo -n pft-backfill status --json" 2>/dev/null | sed -n '/^{/,$p'; }

# drill textfile: PHASE fire|recover; written atomically (temp name does not end in .prom, so node_exporter skips it)
drill_prom() { # PHASE
  local now gap=37 up=0
  now="$(date +%s)"
  [ "$1" = recover ] && { gap=0; up=1; }
  printf '# drill textfile written by backfill/drill/live-run.sh (%s); removed at the end of the run\n' "$RUN"
  printf 'pft_backfill_up{node="drill-gap"} 1\npft_backfill_node_full{node="drill-gap"} 1\n'
  printf 'pft_backfill_missing_ledgers{node="drill-gap",kind="interior"} %s\n' "$gap"
  printf 'pft_backfill_missing_ledgers{node="drill-gap",kind="edge"} 0\n'
  printf 'pft_backfill_status_timestamp_seconds{node="drill-gap"} %s\n' "$now"
  printf 'pft_backfill_up{node="drill-down"} %s\n' "$up"
  printf 'pft_backfill_status_timestamp_seconds{node="drill-down"} %s\n' "$now"
}
refresher() {
  while [ -e "$SEC/phase" ]; do
    drill_prom "$(cat "$SEC/phase" 2>/dev/null)" | sudo -n sh -c "cat > $TF/.pft_backfill_drill.tmp && chmod 0644 $TF/.pft_backfill_drill.tmp && mv -f $TF/.pft_backfill_drill.tmp $DRILLF"
    sleep "$REFRESH"
  done
}

declare -A SHA=()
declare -a MOVED=()
CHANGED=0; RESTORED=0; RESTORE_OK=true; MAINT_STARTED=0; MAINT_ENV_MADE=0; SIL=""; BRIDGE_SWAPPED=0; LOOP_PID=""; SENTRY_STOPPED=0
stop_refresher() {
  local w=0
  rm -f "$SEC/phase"
  if [ -n "$LOOP_PID" ]; then
    while kill -0 "$LOOP_PID" 2>/dev/null && [ "$w" -lt $((REFRESH + 30)) ]; do sleep 1; w=$((w + 1)); done
    kill "$LOOP_PID" 2>/dev/null; wait "$LOOP_PID" 2>/dev/null; LOOP_PID=""
  fi
  sudo -n rm -f "$DRILLF" "$TF/.pft_backfill_drill.tmp"
}
bf_active() { # backfill alerts in Prometheus (pending/firing) + active in Alertmanager
  echo $(( $(pq "ALERTS{alertname=~\"$BF_ALERTS\"}" | grep -c .) + $(curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false" | jq --arg r "$BF_ALERTS" '[.[] | select(.labels.alertname | test("^(" + $r + ")$"))] | length') ))
}
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  [ "$CHANGED" = 1 ] || return 0   # stopped before step 1: nothing to restore
  local k h f now_sha left n w src nb SIL2 SIL3
  if [ "$SENTRY_STOPPED" = 1 ]; then
    echo "  sentry still stopped: starting it"; R "sudo -n docker start postfiatd-sentry" >/dev/null || { echo "  docker start FAILED"; RESTORE_OK=false; }
    SENTRY_STOPPED=0; started
  fi
  stop_refresher
  if sudo -n test -e "$DRILLF"; then echo "  drill textfile still present"; RESTORE_OK=false; else echo "  drill textfile removed: yes"; fi
  if [ "$MAINT_STARTED" = 1 ] && sudo -n pft-maint active >/dev/null 2>&1; then
    echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'
  fi
  # backfill alerts are NOT under the drill silence: clear them (rulecheck re-run for the removed drill file) before
  # the bridge points at the operator again; whatever is still active then gets its own silence, never a message
  sudo -n systemctl start pft-rulecheck.service >/dev/null 2>&1 || true
  w=0; n="$(bf_active)"
  while [ "$n" != 0 ] && [ "$w" -lt "$CLEAR_WAIT" ]; do sleep 15; w=$((w + 15)); n="$(bf_active)"; done
  echo "  backfill alerts still pending/firing/active before the bridge restore: $n (${w}s)"
  if [ "$n" != 0 ]; then
    nb="$(jq -nc --arg s "$(ts)" --arg e "$(date -u -d '+90 min' +%FT%TZ)" --arg r "$BF_ALERTS" --arg c "$TASK post-run: backfill alerts not yet cleared" \
      '{matchers: [{name: "alertname", value: $r, isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "backfill-live", comment: $c}')"
    SIL3="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$nb" | jq -r '.silenceID // empty')"
    echo "  narrow silence for the backfill alerts (90 min, expires by itself): $([ -n "$SIL3" ] && echo created || echo FAILED)"
    RESTORE_OK=false
  fi
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
    src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
    if [ "$src" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ -n "$SIL" ]; then
    # expiring the catch-all releases whatever it still holds: wait for those alerts to resolve first (lesson: expiring
    # a silence releases what it held); PFTContainerRestarted is handed to its own narrow silence below
    held() { curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=true&inhibited=false" \
      | jq -r --arg id "$SIL" '[.[] | select(.status.silencedBy | index($id)) | select(.labels.alertname != "PFTContainerRestarted") | .labels.alertname] | unique | join(",")'; }
    w=0; n="$(held)"
    while [ -n "$n" ] && [ "$w" -lt "$CLEAR_WAIT" ]; do sleep 15; w=$((w + 15)); n="$(held)"; done
    if [ -n "$n" ]; then
      echo "  catch-all still holds active alerts after ${w}s: $n - kept until its end time $ends (not expired)"
      RESTORE_OK=false; R "rm -rf $RDIR" || true; return 0
    fi
    echo "  catch-all holds no other active alert (${w}s)"
    left=$(( LAST_START + 25 * 60 - $(date -u +%s) ))
    if [ "$left" -gt 0 ]; then
      # keep only what the sentry restart still needs (PFTContainerRestarted looks back 15 min), never the catch-all,
      # which would also hold other alerts past the run (lesson: alertpath STALE after apparmor run 26)
      nb="$(jq -nc --arg s "$(ts)" --arg e "$(date -u -d "@$(( LAST_START + 25 * 60 ))" +%FT%TZ)" --arg c "$TASK post-run: PFTContainerRestarted only" \
        '{matchers: [{name: "alertname", value: "PFTContainerRestarted", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "backfill-live", comment: $c}')"
      SIL2="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$nb" | jq -r '.silenceID // empty')"
      if [ -n "$SIL2" ]; then
        echo "  narrow silence alertname=PFTContainerRestarted until last node start $(date -u -d "@$LAST_START" +%TZ) + 25 min (${left}s); expires by itself"
        curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
      else echo "  narrow silence FAILED: catch-all kept until its end time"; RESTORE_OK=false; fi
    else curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"; fi
  fi
  R "rm -rf $RDIR" || true
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-backfill two-host live run (sentry gap + repair + alert drill) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in backfill/drill/live-run.sh backfill/pft-backfill.sh backfill/backfill_parse.py backfill/install.sh alerts/backfill.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
for u in $COLLECTORS; do
  systemctl is-active -q "$u" || continue
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  $u is collecting from the validator's node - a real run would stop here"; NOT_READY=1
  else echo "  $u is collecting from the validator's node - stopping (planned node work while it collects)" >&2; exit 4; fi
done
# The rule line and the manifest lines ship in the run commit, not earlier: the live Prometheus reads this tree, so a
# loaded rule with no pft_backfill_* series yet would page PFTRuleDead, and manifest lines would make pft-fleet skew MISSING.
for need in "alerts/prometheus.yml:/etc/pft-alerts/backfill.rules.yml" "fleet/manifest.tsv:backfill/pft-backfill.sh"; do
  grep -qF "${need#*:}" "${need%%:*}" && continue
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  ${need%%:*} has no ${need#*:} line - a real run would stop here (add it in the run commit)"; NOT_READY=1
  else echo "  ${need%%:*} has no ${need#*:} line - stopping (add it in the run commit)" >&2; exit 3; fi
done
echo "  pft-maint: no window on either host; collectors inactive + run-commit lines present: $([ "$NOT_READY" = 0 ] && echo yes || echo "NO, see above")"
for h in local relay; do
  w="$(on "$h" "sudo -n pft-maint status --json" 2>/dev/null | jq -r '.window // empty' 2>/dev/null)"
  echo "  $h pft-maint status --json window: ${w:-unreadable}"
  [ "$w" = none ] || { echo "  pft-maint status --json does not say none on $h - stopping" >&2; exit 4; }
  p="$(on "$h" "curl -s -m 20 -d '{\"method\":\"server_info\"}' $PUBLIC_RPC" | jq -r '.result.info.complete_ledgers // empty' 2>/dev/null)"
  echo "  $h -> public RPC complete_ledgers: ${p:-no answer}"
  [ -n "$p" ] || { echo "  public RPC not reachable from $h (the repair cross-check needs it) - stopping" >&2; exit 4; }
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
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
nsil="$(curl -s --max-time 10 "$AM/api/v2/silences" | jq '[.[] | select(.status.state == "active") | select(any(.matchers[]; .name == "alertname" and .isEqual != false and (.value as $v | if .isRegex then ("PFTBackfillGap" | test("^(" + $v + ")$")) else ($v | test("^PFTBackfill")) end)))] | length')"
[ "$nsil" = 0 ] || { echo "  $nsil active silence(s) cover the backfill alerts - stopping" >&2; exit 3; }
na="$(pq "ALERTS{alertname=~\"$BF_ALERTS\"}" | grep -c .)"
[ "$na" = 0 ] || { echo "  $na backfill alert(s) already pending/firing - stopping" >&2; exit 3; }
sudo -n test -e "$DRILLF" && { echo "  leftover drill textfile - stopping" >&2; exit 3; }
echo "  silences covering the backfill alerts: 0; backfill alerts pending/firing: 0; drill textfile: none"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
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
  k="$(node_key "$h")"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  s="$(node_state "$h")"; echo "  $(cn "$h"): server_state=${s:-down}"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then
  echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed (ready: $([ "$NOT_READY" = 0 ] && echo yes || echo "no, see the would-stop lines above"))"
  exit $(( NOT_READY ? 4 : 0 ))
fi

echo; echo "== 1. redirect notifiers + bridge, silence every alert except the backfill alerts and the watchdog, window"
CHANGED=1
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
sudo -n sh -c "umask 077; printf 'NTFY_SERVER=%s\nNTFY_TOPIC=%s\n' $NTFY $ALERT > $MAINT_ENV" && MAINT_ENV_MADE=1
check "$MAINT_ENV created with the throwaway topic (0600)" "$(ok_if '[ "$MAINT_ENV_MADE" = 1 ] && [ "$(sudo -n stat -c %a "$MAINT_ENV")" = 600 ]')"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src" = "$SEC/bridge.env" ] || { echo "  bridge not pointed at the throwaway env - stopping"; exit 3; }
echo "  bridge -> $NTFY/<redacted> (throwaway env file in a 0700 temp dir)"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-backfill live run $RUN (planned sentry stop; backfill alerts under test)" --arg x "$BF_ALERTS|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: $x, isRegex: true, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "backfill-live", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence alertname=~\".+\", alertname!~\"$BF_ALERTS|$WATCHDOG_ALERT\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
x "sudo -n pft-maint start --ttl $TTL --reason '$TASK pft-backfill live run $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. install (sentry first, then validator, then the validator's pull of the sentry files)"
x "git archive $SHA_HEAD backfill | R 'rm -rf $RDIR && mkdir -m 700 $RDIR && tar -x -C $RDIR'"
x "R 'sudo -n bash $RDIR/backfill/install.sh --host sentry'"
check "sentry install exit 0, first status textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_backfill_up{node=\"sentry\"} 1" <<<"$XOUT"')"
x "sudo -n bash backfill/install.sh"
check "validator install exit 0, first status textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_backfill_up{node=\"validator\"} 1" <<<"$XOUT"')"
x "sudo -n grep -q '^PULL_SSH=' /etc/pft-backfill.env || sudo -n sh -c 'grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-backfill.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-backfill.env; sudo -n stat -c '%a %U' /etc/pft-backfill.env"
x "sudo -n bash backfill/install.sh --pull"
check "pull install exit 0, sentry status file present on the validator" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_backfill_up{node=\"sentry\"}" <<<"$XOUT"')"
x "systemctl is-enabled pft-backfill.timer pft-backfill-pull.timer pft-backfill-repair.timer; R 'systemctl is-enabled pft-backfill.timer pft-backfill-repair.timer'"
check "status timers enabled on both hosts, pull enabled, repair timers installed but NOT enabled (opt-in)" "$(ok_if '[ "$(grep -c "^enabled$" <<<"$XOUT")" = 3 ] && [ "$(grep -c "^disabled$" <<<"$XOUT")" = 2 ]')"
x "grep -n backfill.rules.yml alerts/prometheus.yml; sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-backfill\") | .rules[] | [.name, .health] | @tsv'"
check "PFTBackfillGap + PFTBackfillCheckFailed loaded, health ok" "$(ok_if '[ "$(grep -cE "^PFTBackfill(Gap|CheckFailed)	ok" <<<"$XOUT")" = 2 ]')"

echo; echo "== 3. before: status on both hosts; repair refused inside the window; alert drill starts"
for h in relay local; do
  x "on $h 'sudo -n pft-backfill status; echo status-exit=\$?'"
  J="$(status_json "$h")"; echo "  --json: $(jq -c '{host, server_state, ranges, window, missing_interior, missing_edge}' <<<"$J")"
done
x "R 'sudo -n pft-backfill repair --apply --max-ledgers 1; echo repair-exit=\$?'"
check "sentry repair --apply inside the window: REFUSED (exit 4, window named), nothing requested" "$(ok_if 'grep -qx "repair-exit=4" <<<"$XOUT" && grep -q "pft-maint window is open" <<<"$XOUT"')"
echo fire > "$SEC/phase"
refresher & LOOP_PID=$!
t_fire="$(date -u +%s)"; sleep 5
x "sudo -n cat $DRILLF"
check "drill textfile written: drill-gap 37 interior on a full node, drill-down up 0" "$(ok_if 'grep -qx "pft_backfill_missing_ledgers{node=\"drill-gap\",kind=\"interior\"} 37" <<<"$XOUT" && grep -qx "pft_backfill_up{node=\"drill-down\"} 0" <<<"$XOUT"')"

echo; echo "== 4. live gap on the sentry: stop postfiatd-sentry for ${GAP_STOP}s, start, wait for full"
x "R 'sudo -n docker exec postfiatd-sentry curl -s -m 10 -d \"{\\\"method\\\":\\\"server_info\\\"}\" http://127.0.0.1:5005' | jq -c '.result.info | {server_state, complete_ledgers, validated: .validated_ledger.seq}'"
t_stop="$(date -u +%s)"
SENTRY_STOPPED=1; started; x "R 'sudo -n docker stop -t 60 postfiatd-sentry'"
check "sentry stopped" "$XRC"
sleep "$GAP_STOP"
x "R 'sudo -n docker start postfiatd-sentry'"; SENTRY_STOPPED=0; started
check "sentry started after $(( $(date -u +%s) - t_stop ))s" "$XRC"
w=0; until [ "$(node_state relay)" = full ]; do w=$((w + 10)); [ "$w" -le 1200 ] || break; sleep 10; done
check "sentry full ${w}s after the start" "$(ok_if '[ "$(node_state relay)" = full ]')"
w=0; until [ "$(node_state local)" = full ]; do w=$((w + 10)); [ "$w" -le 900 ] || break; sleep 10; done
check "validator full again ${w}s later" "$(ok_if '[ "$(node_state local)" = full ]')"
for i in 1 2 3; do
  J="$(status_json relay)"; echo "  $(ts) sentry status: $(jq -c '{server_state, ranges, window, missing_interior, missing_edge, gaps}' <<<"$J")"
  sleep 20
done

echo; echo "== 5. drill alerts: both pairs firing and delivered"
got=0
while [ $(( $(date -u +%s) - t_fire )) -lt "$FIRE_WAIT" ]; do
  F="$(pq "ALERTS{alertstate=\"firing\",alertname=~\"$BF_ALERTS\"}")"
  got=0
  while read -r n e; do grep -qE "alertname=$e,.*node=$n(,| )" <<<"$F" && got=$((got + 1)); done <<<"$PAIRS"
  [ "$got" -ge 2 ] && break
  sleep 30
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_fire ))s after the first drill write):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "both drill pairs firing (PFTBackfillGap drill-gap, PFTBackfillCheckFailed drill-down)" "$([ "$got" -ge 2 ] && echo 0 || echo 1)" "$got/2"
check "no backfill alert for the validator" "$(ok_if '! grep -qE "node=validator(,| )" <<<"$F"')"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"; dl=0
  while read -r n e; do
    [ "$(jq -r --arg t "[FIRING] $e" 'select(.title == $t) | .message' <<<"$M" | grep -c "$n")" -ge 1 ] && dl=$((dl + 1))
  done <<<"$PAIRS"
  [ "$dl" -ge 2 ] && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "[FIRING] delivered to the throwaway topic for both drill pairs" "$([ "$dl" -ge 2 ] && echo 0 || echo 1)" "$dl/2"

echo; echo "== 6. end the window, then the live repair on the sentry"
x "sudo -n pft-maint end"
# repair fails closed on anything but window "none" (an expired-but-not-ticked flag reads "expired")
w=0; until [ "$(R 'sudo -n pft-maint status --json' 2>/dev/null | jq -r '.window // empty' 2>/dev/null)" = none ]; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
x "R 'sudo -n pft-maint status --json' | jq -c '{window}'"
check "window ended on both hosts (sentry after ${w}s)" "$(ok_if '! sudo -n pft-maint active >/dev/null 2>&1 && grep -q "\"window\":\"none\"" <<<"$XOUT"')"
x "R 'sudo -n pft-backfill status; echo status-exit=\$?'"
GAPPED=0; grep -q "status-exit=1" <<<"$XOUT" && grep -qE "^  gap " <<<"$XOUT" && GAPPED=1
x "R 'sudo -n pft-backfill repair $REPAIR_ARGS; echo repair-exit=\$?'"
check "sentry repair dry run: exit 0, nothing requested" "$(ok_if 'grep -qx "repair-exit=0" <<<"$XOUT" && grep -q "RESULT: DRY RUN" <<<"$XOUT"')"
if [ "$GAPPED" = 1 ]; then
  x "R 'sudo -n pft-backfill repair --apply --textfile $REPAIR_ARGS; echo repair-exit=\$?'"
  C="$(grep -oE 'counts: planned [0-9]+ fetched [0-9]+ verified [0-9]+ failed [0-9]+ timeout [0-9]+ skipped [0-9]+' <<<"$XOUT")"
  read -r _ _ PL _ FE _ VE _ FA _ TO _ SK <<<"$C"
  check "live repair: no MISMATCH/failure, at least one ledger fetched, every fetched ledger verified" "$(ok_if '[ -n "$C" ] && [ "$FA" = 0 ] && [ "$FE" -ge 1 ] && [ "$VE" = "$FE" ]')" "$C"
  check "live repair: before/after complete_ledgers printed" "$(ok_if 'grep -q "before: complete_ledgers" <<<"$XOUT" && grep -q "after:  complete_ledgers" <<<"$XOUT"')"
  x "R 'sudo -n pft-backfill status; echo status-exit=\$?'"
else
  echo "  NOTE: normal sync closed every gap in the window before the repair could run; the repair path is proven by the"
  echo "  offline suite (fixture fallback, backfill/tests/run-repair-tests.sh) and the dry run above."
fi
x "sudo -n pft-backfill repair; echo repair-exit=\$?"
check "validator repair dry run exit 0" "$(ok_if 'grep -qx "repair-exit=0" <<<"$XOUT"')"

echo; echo "== 7. recover: drill series healthy, every backfill alert clears"
echo recover > "$SEC/phase"; t_rec="$(date -u +%s)"
sleep $((REFRESH + 10))
x "sudo -n cat $DRILLF"
declare -A RES=()
while :; do
  F="$(pq "ALERTS{alertname=~\"$BF_ALERTS\"}")"; M="$(topic_msgs "$ALERT")"; done_n=0
  while read -r n e; do
    r="$(jq -r --arg t "[RESOLVED] $e" 'select(.title == $t) | .message' <<<"$M" | grep -c "$n")"
    RES["$e/$n"]="$r"
    if ! grep -qE "alertname=$e,.*node=$n(,| )" <<<"$F" && [ "$r" -ge 1 ]; then done_n=$((done_n + 1)); fi
  done <<<"$PAIRS"
  [ "$done_n" -ge 2 ] && [ -z "$F" ] && break
  [ $(( $(date -u +%s) - t_rec )) -lt "$RESOLVE_WAIT" ] || break
  sleep 20
done
for k in "${!RES[@]}"; do echo "    [RESOLVED] $k: ${RES[$k]}"; done | sort
check "both drill pairs left Prometheus with [RESOLVED] delivered" "$([ "$done_n" -ge 2 ] && echo 0 || echo 1)" "$done_n/2"
check "no backfill alert pending/firing for any node" "$(ok_if '[ -z "$F" ]')" "$(grep -c . <<<"$F") left"
stop_refresher
check "refresher stopped, drill textfile removed" "$(ok_if '[ -z "$LOOP_PID" ] && ! sudo -n test -e "$DRILLF"')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"$BF_ALERTS\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) node=\(.metric.node) \(.metric.alertstate) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "query_range: both drill pairs firing during the run" "$(ok_if '[ "$(grep -cE "^PFTBackfill(Gap node=drill-gap|CheckFailed node=drill-down) firing" <<<"$XOUT")" = 2 ]')"
echo "  live: PFTBackfillCheckFailed node=sentry while the sentry was stopped: $(grep -c "^PFTBackfillCheckFailed node=sentry firing" <<<"$XOUT") firing series (expected 1 for a ${GAP_STOP}s stop)"
x "topic_msgs $ALERT | jq -r 'select(.title | test(\"PFTBackfill\")) | \"\(.time | todate) \(.title) \(.message)\"'"

echo; echo "== 8. metrics: units on both hosts, pull, Prometheus"
x "R 'sudo -n systemctl start pft-backfill.service; systemctl show -p Result --value pft-backfill.service'"
x "sudo -n systemctl start pft-backfill.service pft-backfill-pull.service; systemctl show -p Result --value pft-backfill.service pft-backfill-pull.service; grep -hE '^pft_backfill_(up|missing_ledgers|repair_ledgers)' $TF/pft_backfill*.prom"
check "units Result success, textfiles up 1 for validator and sentry" "$(ok_if '[ "$(grep -c "^success$" <<<"$XOUT")" = 2 ] && [ "$(grep -cE "^pft_backfill_up\{node=\"(validator|sentry)\"\} 1$" <<<"$XOUT")" = 2 ]')"
x "sleep 45; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_backfill_up' | jq -r '.data.result[] | \"\(.metric.node) \(.value[1])\"' | sort"
check "Prometheus: pft_backfill_up 1 for sentry and validator, no drill series left" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 1$" <<<"$XOUT")" = 2 ] && ! grep -q drill <<<"$XOUT"')"

echo; echo "== 9. baselines: integrity accept on both hosts, fleet manifest sync, skew, rulecheck"
x "sudo -n pft-integrity verify | grep -E '^  \[(WARN|FAIL)\]|^RESULT' | sed -E 's/ +sha256.*//' | head -30"
x "sudo -n pft-integrity accept --reason '$TASK: pft-backfill $SHORT installed (script, parser, units, env, rulecheck.conf)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^  \[(WARN|FAIL)\]|^RESULT' | sed -E 's/ +sha256.*//' | head -30"
x "R \"sudo -n pft-integrity accept --reason '$TASK: pft-backfill $SHORT installed (script, parser, units, env); planned sentry stop/start'\" | tail -2"
# pft-fleet sync refuses without a window, and step 6 ended the first one (repair refuses inside a window)
x "sudo -n pft-maint start --ttl 20m --reason '$TASK pft-backfill live run $RUN: fleet manifest sync'"
check "second window for the fleet sync" "$XRC"
x "sudo -n pft-fleet sync --addon fleet --to $SHA_HEAD --apply --reason '$TASK backfill manifest lines'"
check "fleet sync of the manifest exit 0" "$XRC"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, backfill CURRENT on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -cE "^ *(validator|sentry) +backfill +CURRENT" <<<"$XOUT")" = 2 ]')"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after accept + sync" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"

echo; echo "== 10. restore, read back"
restore
check "env files byte-identical, bridge on the operator env, pft-maint env removed, window ended, drill file gone" "$(ok_if '[ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && ! sudo -n test -e "$MAINT_ENV"')"
sleep "$READBACK_WAIT"
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
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
  s="$(node_state "$h")"; check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
