#!/usr/bin/env bash
# live-run: recorded two-host install + enforced proof of pft-apparmor, sentry first. Built from
# ../../cluster/drill/live-run.sh (redirect / silence / window / read-back / PREFLIGHT_ONLY framework). This run DOES
# re-create and restart both nodes (sentry several times), so every alert is silenced on the validator's
# Alertmanager for the run and until the last node start + 25 min (PFTContainerRestarted looks back 15 min), and
# every notifier on both hosts points at a throwaway topic.
#   bash apparmor/drill/live-run.sh LEARN_EVENTS 2>&1 | tee LOG   (agent user, repo root; sudo -n, `ssh relay`)
#   LEARN_EVENTS: path ON THE SENTRY of the events file written by the recorded `pft-apparmor learn` run.
#   PROFILE_FILE=/path bash apparmor/drill/live-run.sh 2>&1 | tee LOG   re-apply mode: a finished profile (path ON THE
#   VALIDATOR, e.g. merged from the sentry's and the validator's learn events) is copied to both hosts (sha256
#   compared); step 1b rolls back what is applied; step 3 runs host-run.sh sentry --profile (no drill: run 26 has it),
#   step 4 host-run.sh validator --profile, both including step 5b (add-on units + one real retention tick).
# 0  preflight (nothing changed yet): clean pushed HEAD; relay, Alertmanager, Prometheus reachable; no pft-maint
#    window; no data collector reading the validator's node; learn events present; run-commit lines present;
#    notifier env files present, no leftovers; both nodes full; pft-integrity PASS on both; redaction control.
# 1  redirect notifiers to a throwaway topic, silence alertname=~".+" except PFTAlertPipelineWatchdog, pft-maint window (sentry gets it too).
# 1b reset: an apply left in place by an earlier run is rolled back first.
# 2  install on both hosts (+ the validator's pull of the sentry file); Prometheus loads PFTAppArmorDrift.
# 3  sentry: drill/host-run.sh sentry --drill (before, P0 from learn, injected gate miss -> automatic rollback,
#    bounded complain window + explicit rollback, P1 from learn + complain events, enforce, positive/negative
#    controls, ack, enforced restart, explicit rollback, re-apply).
# 4  validator: P1 copied from the sentry (sha256 compared); drill/host-run.sh validator (before, enforce,
#    controls, ack, enforced restart).
# 5  metrics (units, pull, Prometheus), 6 baselines (integrity, fleet, rulecheck), 7 restore + read-back.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM  PROM  LOCAL_ENVS  REMOTE_ENVS  TTL (3h)  SIL_TTL (240, min: window + last start + 25 min)
#      CMIN (20, sentry complain window in minutes)
#      PREFLIGHT_ONLY=1: run step 0 only and exit before any change (an active data collector or a missing
#      run-commit line is reported as "would stop" instead of stopping); exit 0 = ready, 4 = not ready.
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"
LEARN_EVENTS="${1:-}"; PROFILE_FILE="${PROFILE_FILE:-}"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_ENV=/etc/pft-maint/ntfy.env
TTL="${TTL:-3h}"; SIL_TTL="${SIL_TTL:-240}"; CMIN="${CMIN:-20}"; PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"; NOT_READY=0
COLLECTORS="${COLLECTORS:-pft-payflow-tx.service pft-senders-tx.service}"
TASK=task_faf99695
SUF=.pre-apparmor-live
SHA_HEAD="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
RDIR="/var/tmp/pft-apparmor-live-$SHORT"   # sentry copy of the tree (read with bash, never executed from a noexec mount)
P1=/var/lib/pft-apparmor/pft-postfiatd.live   # the profile host-run writes on the sentry and the validator applies
[ -z "$PROFILE_FILE" ] || P1=/var/lib/pft-apparmor/pft-postfiatd.reapply   # re-apply mode: PROFILE_FILE copied here on both hosts

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="aalive-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"; LAST_START="$since"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
cn() { if [ "$1" = relay ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
node_state() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
node_key() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null; }
started() { LAST_START="$(date -u +%s)"; } # every node (re)start pushes the silence end out


declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; MAINT_STARTED=0; MAINT_ENV_MADE=0; SIL=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha left
  if [ "$MAINT_STARTED" = 1 ]; then echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'; fi
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
  if [ -n "$SIL" ]; then
    left=$(( LAST_START + 25 * 60 - $(date -u +%s) ))
    if [ "$left" -gt 0 ]; then
      # Keep only what the restarts still need: a silence for PFTContainerRestarted alone (15-min resets() window),
      # never the catch-all, which would also hold PFTAlertPipelineWatchdog past the window (lesson: alertpath STALE).
      nb="$(jq -nc --arg s "$(ts)" --arg e "$(date -u -d "@$(( LAST_START + 25 * 60 ))" +%FT%TZ)" --arg c "$TASK post-run: PFTContainerRestarted only" \
        '{matchers: [{name: "alertname", value: "PFTContainerRestarted", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "apparmor-live", comment: $c}')"
      SIL2="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$nb" | jq -r '.silenceID // empty')"
      if [ -n "$SIL2" ]; then
        echo "  narrow silence alertname=PFTContainerRestarted until last node start $(date -u -d "@$LAST_START" +%TZ) + 25 min (${left}s); expires by itself"
        curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
      else echo "  narrow silence FAILED: catch-all kept (it excludes PFTAlertPipelineWatchdog) until its end time"; RESTORE_OK=false; fi
    else curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"; fi
  fi
  R "rm -rf $RDIR" || true
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-apparmor two-host live run (sentry first) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in apparmor/drill/live-run.sh apparmor/drill/host-run.sh apparmor/pft-apparmor.sh apparmor/install.sh alerts/apparmor.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
[ -n "$LEARN_EVENTS$PROFILE_FILE" ] || { echo "  usage: live-run.sh LEARN_EVENTS (path on the sentry) | PROFILE_FILE=path live-run.sh" >&2; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
for u in $COLLECTORS; do
  systemctl is-active -q "$u" || continue
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  $u is collecting from the validator's node - a real run would stop here"; NOT_READY=1
  else echo "  $u is collecting from the validator's node - stopping (re-creates would cut its window)" >&2; exit 4; fi
done
nl="$(sudo -n pft-maint status --json 2>/dev/null | jq -r '.locks | length' 2>/dev/null)"
if [ "${nl:-1}" != 0 ]; then
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  validator: ${nl:-?} pft-maint data-collection lock(s) held - apply would refuse; a real run would stop here"; NOT_READY=1
  else echo "  validator: ${nl:-?} pft-maint data-collection lock(s) held - stopping" >&2; exit 4; fi
fi
# The rule line and the manifest lines ship in the run commit, not earlier: the live Prometheus reads this tree, so a
# loaded rule with no pft_apparmor_* series yet would page PFTRuleDead, and manifest lines would make pft-fleet skew MISSING.
for need in "alerts/prometheus.yml:/etc/pft-alerts/apparmor.rules.yml" "fleet/manifest.tsv:apparmor/pft-apparmor.sh"; do
  grep -qF "${need#*:}" "${need%%:*}" && continue
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  ${need%%:*} has no ${need#*:} line - a real run would stop here (add it in the run commit)"; NOT_READY=1
  else echo "  ${need%%:*} has no ${need#*:} line - stopping (add it in the run commit)" >&2; exit 3; fi
done
# pft-integrity (and anything else that auto-detects "the" node) takes the first running container with a postfiatd
# image, i.e. the newest: a leftover throwaway would make it grade the wrong container (seen during the learn run).
for h in local relay; do
  n="$(on "$h" "sudo -n docker ps --format '{{.Names}} {{.Image}}'" | awk -v c="$(cn "$h")" '$2 ~ /postfiatd/ && $1 != c' | wc -l)"
  [ "$n" = 0 ] || { echo "  $h: $n running postfiatd-image container(s) besides $(cn "$h") (learn throwaway?) - stopping" >&2; exit 3; }
done
echo "  no extra postfiatd-image container running on either host"
if [ -n "$PROFILE_FILE" ]; then
  x "sudo -n pft-apparmor check '$PROFILE_FILE' && sudo -n cat '$PROFILE_FILE' | sha256sum | cut -c1-64 && sudo -n grep -c . '$PROFILE_FILE'"
  if [ "$XRC" != 0 ]; then
    if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  PROFILE_FILE missing or does not compile - a real run would stop here"; NOT_READY=1
    else echo "  PROFILE_FILE missing or does not compile - stopping" >&2; exit 3; fi
  fi
else
x "R 'sudo -n cat $LEARN_EVENTS | wc -l; sudo -n cat $LEARN_EVENTS | sha256sum | cut -c1-64; sudo -n cut -f1 $LEARN_EVENTS | sort | uniq -c'"
if ! { [ "$XRC" = 0 ] && [ "$(head -1 <<<"$XOUT")" -gt 0 ] 2>/dev/null; }; then
  if [ "$PREFLIGHT_ONLY" = 1 ]; then echo "  learn events missing or empty on the sentry - a real run would stop here"; NOT_READY=1
  else echo "  learn events missing or empty on the sentry - stopping" >&2; exit 3; fi
fi
fi
x "on local 'sudo -n test -f /var/lib/pft-apparmor/apply-postfiatd.json && sudo -n jq -c \"{id, mode, rolled_back}\" /var/lib/pft-apparmor/apply-postfiatd.json'; R 'sudo -n test -f /var/lib/pft-apparmor/apply-postfiatd-sentry.json && sudo -n jq -c \"{id, mode, rolled_back}\" /var/lib/pft-apparmor/apply-postfiatd-sentry.json'"
echo "  (informational: apply state from an earlier run, if any; step 1b rolls back an apply still in place)"
echo "  pft-maint: no window on either host; collectors inactive, no locks, run-commit lines present: $([ "$NOT_READY" = 0 ] && echo yes || echo "NO, see above")"
sudo -n test -e "$MAINT_ENV" && { echo "  $MAINT_ENV exists (this runner expects it absent) - stopping" >&2; exit 3; }
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
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
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
if [ "$PREFLIGHT_ONLY" = 1 ]; then
  echo; echo "PREFLIGHT_ONLY: stopping before step 1, nothing changed (ready: $([ "$NOT_READY" = 0 ] && echo yes || echo "no, see the would-stop lines above"))"
  exit $(( NOT_READY ? 4 : 0 ))
fi
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }

echo; echo "== 1. redirect notifiers, silence every alert, maintenance window"
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
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-apparmor live run $RUN (planned re-creates/restarts of both nodes)" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog", isRegex: false, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "apparmor-live", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence alertname=~\".+\", alertname!=PFTAlertPipelineWatchdog (the dead-man switch keeps flowing), until $ends" "$(ok_if '[ -n "$SIL" ]')"
x "sudo -n pft-maint start --ttl $TTL --reason '$TASK pft-apparmor live run $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 1b. reset: an apply an earlier run left in place is rolled back first"
for h in relay local; do
  sf="/var/lib/pft-apparmor/apply-$(cn "$h").json"
  if on "$h" "sudo -n test -f $sf" && [ "$(on "$h" "sudo -n jq -r '.rolled_back // false' $sf")" = false ]; then
    x "on $h 'sudo -n pft-apparmor rollback --yes'"; started
    check "$h: rollback of the earlier apply -> PASS" "$(ok_if '[ "$XRC" = 0 ]')"
  else echo "  $h: no apply in place (nothing to reset)"; fi
done
[ "$FAILS" = 0 ] || { echo "  reset failed - stopping"; exit 4; }

echo; echo "== 2. install (sentry first, then validator, then the validator's pull of the sentry file)"
x "git archive $SHA_HEAD apparmor | R 'rm -rf $RDIR && mkdir -m 700 $RDIR && tar -x -C $RDIR'"
x "R 'sudo -n bash $RDIR/apparmor/install.sh --host sentry'"
check "sentry install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_apparmor_findings{host=\"sentry\"}" <<<"$XOUT"')"
x "sudo -n bash apparmor/install.sh"
check "validator install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_apparmor_findings{host=\"validator\"}" <<<"$XOUT"')"
x "sudo -n grep -q '^PULL_SSH=' /etc/pft-apparmor.env || sudo -n sh -c 'grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-apparmor.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-apparmor.env; sudo -n stat -c '%a %U' /etc/pft-apparmor.env"
x "sudo -n bash apparmor/install.sh --pull"
check "pull install exit 0, sentry file present on the validator" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_apparmor_findings{host=\"sentry\"}" <<<"$XOUT"')"
x "sudo -n grep -n pft_apparmor /etc/pft-rulecheck.conf; R 'sudo -n grep -n pft_apparmor /etc/pft-rulecheck.conf'"
x "grep -n apparmor.rules.yml alerts/prometheus.yml; sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-apparmor\") | .rules[] | [.name, .health] | @tsv'"
check "PFTAppArmorDrift loaded, health ok" "$(ok_if 'grep -qE "^PFTAppArmorDrift	ok" <<<"$XOUT"')"
[ "$FAILS" = 0 ] || { echo "  install failed - stopping before any node change"; exit 4; }

echo; echo "== 3. sentry: before, P0, injected gate miss, complain window, P1, enforce, controls, restart, rollback, re-apply"
started
if [ -n "$PROFILE_FILE" ]; then
  echo "  re-apply mode: PROFILE_FILE -> $P1 on both hosts, then host-run.sh sentry --profile (no drill)"
  x "sudo -n install -m 0644 '$PROFILE_FILE' $P1 && sudo -n cat $P1 | R 'sudo -n sh -c \"umask 022; cat > $P1\"' && sudo -n cat $P1 | sha256sum | cut -c1-64; R 'sudo -n cat $P1 | sha256sum | cut -c1-64'"
  check "profile copied, sha256 identical on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(sed -n 1p <<<"$XOUT")" = "$(sed -n 2p <<<"$XOUT")" ] && [ -n "$(sed -n 1p <<<"$XOUT")" ]')"
  [ "$FAILS" = 0 ] || { echo "  profile copy failed - stopping before any node change"; exit 4; }
  x "R 'sudo -n bash $RDIR/apparmor/drill/host-run.sh sentry --profile $P1'"
else
  x "R 'sudo -n CMIN=$CMIN bash $RDIR/apparmor/drill/host-run.sh sentry --drill --learn $LEARN_EVENTS --out-profile $P1 --complain-min $CMIN'"
fi
started
check "sentry host-run RESULT: PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^RESULT: PASS" <<<"$XOUT"')" "$(grep -c '^PASS ' <<<"$XOUT") PASS, $(grep -c '^FAIL ' <<<"$XOUT") FAIL"
[ "$XRC" = 0 ] || { echo "  sentry did not pass - validator NOT changed; stopping"; exit 1; }

echo; echo "== 4. validator: P1 from the sentry, before, enforce, controls, restart"
[ -n "$PROFILE_FILE" ] || x "sudo -n install -d -m 700 /var/lib/pft-apparmor && R 'sudo -n cat $P1' | sudo -n sh -c 'umask 022; cat > $P1' && sudo -n cat $P1 | sha256sum | cut -c1-64; R 'sudo -n cat $P1 | sha256sum | cut -c1-64'"
[ -n "$PROFILE_FILE" ] || check "P1 copied, sha256 identical on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(sed -n 1p <<<"$XOUT")" = "$(sed -n 2p <<<"$XOUT")" ] && [ -n "$(sed -n 1p <<<"$XOUT")" ]')"
started
x "sudo -n bash apparmor/drill/host-run.sh validator --profile $P1"
started
check "validator host-run RESULT: PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^RESULT: PASS" <<<"$XOUT"')" "$(grep -c '^PASS ' <<<"$XOUT") PASS, $(grep -c '^FAIL ' <<<"$XOUT") FAIL"
x "R 'sudo -n cat /etc/apparmor.d/pft-postfiatd' | sudo -n diff /etc/apparmor.d/pft-postfiatd - && echo identical"
check "boot copy /etc/apparmor.d/pft-postfiatd identical on both hosts" "$XRC"

echo; echo "== 5. metrics: hourly unit on both hosts, pull, Prometheus"
x "R 'sudo -n systemctl start pft-apparmor.service; systemctl show -p Result --value pft-apparmor.service; sudo -n grep -E \"^pft_apparmor_(findings|last_run)\" /var/lib/pft-exporter/textfile/pft_apparmor_sentry.prom'"
x "sudo -n systemctl start pft-apparmor.service pft-apparmor-pull.service; systemctl show -p Result --value pft-apparmor.service pft-apparmor-pull.service; grep -hE '^pft_apparmor_findings' /var/lib/pft-exporter/textfile/pft_apparmor_*.prom"
check "textfiles: findings 0 for validator and sentry" "$(ok_if '[ "$(grep -cE "^pft_apparmor_findings\{host=\"(validator|sentry)\"\} 0$" <<<"$XOUT")" = 2 ]')"
x "sleep 45; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_apparmor_findings' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "Prometheus: pft_apparmor_findings 0 for sentry and validator" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 0$" <<<"$XOUT")" = 2 ]')"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=\"PFTAppArmorDrift\"}' | jq -r '.data.result | length'"
check "PFTAppArmorDrift neither pending nor firing" "$(ok_if '[ "$XOUT" = 0 ]')"

echo; echo "== 6. baselines: integrity accept on both hosts, fleet manifest sync, skew, rulecheck"
x "sudo -n pft-integrity verify | grep -E '^(  \[(WARN|FAIL)\]|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "sudo -n pft-integrity accept --reason '$TASK: pft-apparmor $SHORT installed + applied (script, units, env, rulecheck.conf, profile, compose override)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(  \[(WARN|FAIL)\]|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "R \"sudo -n pft-integrity accept --reason '$TASK: pft-apparmor $SHORT installed + applied (script, units, env, rulecheck.conf, profile, container)'\" | tail -2"
x "sudo -n pft-fleet sync --addon fleet --to $SHA_HEAD --apply --reason '$TASK apparmor manifest lines'"
check "fleet sync of the manifest exit 0" "$XRC"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, apparmor CURRENT on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -cE "^ *(validator|sentry) +apparmor +CURRENT" <<<"$XOUT")" = 2 ]')"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "sentry pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after accept + sync" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"
x "systemctl is-active pft-apparmor.timer pft-apparmor-pull.timer; R 'systemctl is-active pft-apparmor.timer'"
check "timers active (validator audit + pull, sentry audit)" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -cx active <<<"$XOUT")" = 3 ]')"

echo; echo "== 7. restore, read back"
restore
check "env files byte-identical, pft-maint env removed, window ended" "$(ok_if '[ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && ! sudo -n test -e "$MAINT_ENV"')"
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
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  s="$(node_state "$h")"
  check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
