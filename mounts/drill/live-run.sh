#!/usr/bin/env bash
# live-run: recorded two-host install + apply of pft-mounts, sentry first. Built from ../../feewatch/drill/live-run.sh
# (redirect / silence / window / read-back framework) and ../../privesc/drill/install-run.sh (install, integrity,
# fleet). No reboot, no postfiatd restart.
#   bash mounts/drill/live-run.sh 2>&1 | tee LOG    (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): clean pushed HEAD; relay, Alertmanager, Prometheus reachable; no pft-maint window;
#    notifier env files present, no leftovers; pft-mounts not installed; both nodes full; pft-integrity PASS on both;
#    redaction positive control. Operator topics, user name, host addresses and node keys go into a 0600 literals
#    file for redact.py; they are never printed.
# 1  redirect: LOCAL_ENVS / REMOTE_ENVS get a throwaway topic (sha256 recorded, restored on ANY exit and compared);
#    /etc/pft-maint/ntfy.env (absent by default: pft-maint then falls back to the monitor topic) is created with the
#    throwaway topic and removed afterwards; Alertmanager silence for the alerts a new add-on can trip
#    (PFTMount*, PFTRuleDead, PFTTextfileStale, PFTRulecheck*, PFTFleet*); pft-maint start, wait for the sentry.
# 2  install: sentry (--host sentry), validator, validator --pull; Prometheus reload, rule loaded.
# 3  sentry: drill/host-run.sh sentry --drill (before, injected gate miss -> automatic rollback, apply, after,
#    persistence, negative controls, explicit rollback, re-apply).
# 4  validator: drill/host-run.sh validator (before, apply, after, persistence, negative controls).
# 5  metrics: the hourly unit on both hosts + pull; Prometheus pft_mounts_findings 0 for both hosts.
# 6  baselines: pft-integrity verify/accept on both hosts (new binary, units, env); pft-fleet sync of the fleet
#    manifest; pft-fleet skew exit 0; pft-rulecheck RESULT OK on both hosts.
# 7  restore: window end, env files byte-identical, silence expired; read back the throwaway topic and count messages
#    on every operator topic since the start (topics never printed); integrity PASS + nodes full on both hosts.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM  PROM  LOCAL_ENVS  REMOTE_ENVS  TTL (75m)  SIL_TTL (100, min)
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later (they read RESTORE_OK); A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_ENV=/etc/pft-maint/ntfy.env
TTL="${TTL:-75m}"; SIL_TTL="${SIL_TTL:-100}"
SIL_ALERTS='PFTMount.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*'
SUF=.pre-mounts-live
SHA_HEAD="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
RDIR="/var/tmp/pft-mounts-live-$SHORT"   # sentry copy of the tree (read with bash, never executed from a noexec mount)

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="mntlive-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"   # host names -> <host> (redact.py has no host kind); RHN is set in the preflight
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
pq() { curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric | del(.__name__) | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'; }
node_state() { on "$1" "sudo -n docker exec $2 curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
    | jq -r '.result.info.server_state // "down"' 2>/dev/null; }

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; MAINT_STARTED=0; MAINT_ENV_MADE=0; SIL=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha
  if [ "$MAINT_STARTED" = 1 ]; then echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'; fi
  if [ "$MAINT_ENV_MADE" = 1 ]; then
    sudo -n rm -f "$MAINT_ENV" && echo "  removed $MAINT_ENV (absent before the run: pft-maint falls back to the monitor target again)" \
      || { echo "  remove $MAINT_ENV FAILED"; RESTORE_OK=false; }
  fi
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-run copy: yes"
    else echo "  restored $k: sha256 matches pre-run copy: NO"; RESTORE_OK=false; fi
  done
  if [ -n "$SIL" ]; then curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"; fi
  R "rm -rf $RDIR" || true
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-mounts two-host live run (sentry first) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  echo "sha256: live-run.sh $(sha256sum < "$0" | cut -c1-64) host-run.sh $(sha256sum < "$HERE/host-run.sh" | cut -c1-64)"
  echo "        pft-mounts.sh $(sha256sum < mounts/pft-mounts.sh | cut -c1-64) install.sh $(sha256sum < mounts/install.sh | cut -c1-64)"
  echo "        mounts.rules.yml $(sha256sum < alerts/mounts.rules.yml | cut -c1-64) redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
echo "  pft-maint: no window open on either host"
sudo -n test -e "$MAINT_ENV" && { echo "  $MAINT_ENV exists (this runner expects it absent) - stopping" >&2; exit 3; }
echo "  $MAINT_ENV absent (pft-maint falls back to the monitor target): will be created with the throwaway topic"
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
x "ls /usr/local/bin/pft-mounts /etc/pft-mounts.env 2>&1; R 'ls /usr/local/bin/pft-mounts /etc/pft-mounts.env 2>&1'"
check "pft-mounts not installed yet on either host" "$(ok_if '[ "$(grep -c "No such file" <<<"$XOUT")" = 4 ]')"
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
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  k="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null)"
  [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  s="$(node_state "$h" "$c")"; echo "  $c: server_state=${s:-down}"
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
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }

echo; echo "== 1. redirect notifiers, silence the add-on alerts, maintenance window"
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
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "task_17c7c414 pft-mounts live run $RUN" --arg x "$SIL_ALERTS" \
  '{matchers: [{name: "alertname", value: $x, isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "mounts-live", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence alertname=~\"$SIL_ALERTS\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
x "sudo -n pft-maint start --ttl $TTL --reason 'task_17c7c414 pft-mounts live run $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. install (sentry first, then validator, then the validator's pull of the sentry file)"
x "git archive $SHA_HEAD mounts | R 'rm -rf $RDIR && mkdir -m 700 $RDIR && tar -x -C $RDIR'"
x "R 'sudo -n bash $RDIR/mounts/install.sh --host sentry'"
check "sentry install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_mounts_findings{host=\"sentry\"}" <<<"$XOUT"')"
x "sudo -n bash mounts/install.sh"
check "validator install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_mounts_findings{host=\"validator\"}" <<<"$XOUT"')"
x "sudo -n grep -q '^PULL_SSH=' /etc/pft-mounts.env || sudo -n sh -c 'grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-mounts.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-mounts.env; sudo -n stat -c '%a %U' /etc/pft-mounts.env"
x "sudo -n bash mounts/install.sh --pull"
check "pull install exit 0, sentry file present on the validator" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_mounts_findings{host=\"sentry\"}" <<<"$XOUT"')"
x "sudo -n grep -n pft_mounts /etc/pft-rulecheck.conf; R 'sudo -n grep -n pft_mounts /etc/pft-rulecheck.conf'"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-mounts\") | .rules[] | [.name, .health, .state] | @tsv'"
check "PFTMountHardeningDrift loaded, health ok" "$(ok_if 'grep -qE "^PFTMountHardeningDrift	ok	" <<<"$XOUT"')"

echo; echo "== 3. sentry: before, injected gate miss, apply, after, persistence, negative controls, rollback drill, re-apply"
x "R 'sudo -n bash $RDIR/mounts/drill/host-run.sh sentry --drill'"
check "sentry host-run RESULT: PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^RESULT: PASS" <<<"$XOUT"')" "$(grep -c '^PASS ' <<<"$XOUT") PASS, $(grep -c '^FAIL ' <<<"$XOUT") FAIL"
[ "$XRC" = 0 ] || { echo "  sentry did not pass - validator NOT changed; stopping"; exit 1; }

echo; echo "== 4. validator: before, apply, after, persistence, negative controls"
x "sudo -n bash mounts/drill/host-run.sh validator"
check "validator host-run RESULT: PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^RESULT: PASS" <<<"$XOUT"')" "$(grep -c '^PASS ' <<<"$XOUT") PASS, $(grep -c '^FAIL ' <<<"$XOUT") FAIL"

echo; echo "== 5. metrics: hourly unit on both hosts, pull, Prometheus"
x "R 'sudo -n systemctl start pft-mounts.service; systemctl show -p Result --value pft-mounts.service; sudo -n grep -E \"^pft_mounts_(findings|last_run)\" /var/lib/pft-exporter/textfile/pft_mounts_sentry.prom'"
x "sudo -n systemctl start pft-mounts.service pft-mounts-pull.service; systemctl show -p Result --value pft-mounts.service pft-mounts-pull.service; grep -hE '^pft_mounts_findings' /var/lib/pft-exporter/textfile/pft_mounts_*.prom"
check "textfiles: findings 0 for validator and sentry" "$(ok_if '[ "$(grep -cE "^pft_mounts_findings\{host=\"(validator|sentry)\"\} 0$" <<<"$XOUT")" = 2 ]')"
x "sleep 45; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_mounts_findings' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "Prometheus: pft_mounts_findings 0 for sentry and validator" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 0$" <<<"$XOUT")" = 2 ]')"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=\"PFTMountHardeningDrift\"}' | jq -r '.data.result | length'"
check "PFTMountHardeningDrift neither pending nor firing" "$(ok_if '[ "$XOUT" = 0 ]')"

echo; echo "== 6. baselines: integrity accept on both hosts, fleet manifest sync, skew, rulecheck"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "sudo -n pft-integrity accept --reason 'task_17c7c414: pft-mounts $SHORT installed (script, units, env, rulecheck.conf)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "R \"sudo -n pft-integrity accept --reason 'task_17c7c414: pft-mounts $SHORT installed (script, units, env, rulecheck.conf)'\" | tail -2"
x "sudo -n pft-fleet sync --addon fleet --to $SHA_HEAD --apply --reason 'task_17c7c414 mounts manifest lines'"
check "fleet sync of the manifest exit 0" "$XRC"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, mounts CURRENT on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -cE "^ *(validator|sentry) +mounts +CURRENT" <<<"$XOUT")" = 2 ]')"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "sentry pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after accept + sync" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"
x "TZ=UTC systemctl is-active pft-mounts.timer pft-mounts-pull.timer; R 'systemctl is-active pft-mounts.timer'"
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
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  s="$(node_state "$h" "$c")"
  check "$c full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
