#!/usr/bin/env bash
# live-run: the live two-host pft-patch drill. Every ntfy notifier on both hosts points at throwaway topics for the
# whole run, an outer Alertmanager silence covers alerts that outlive pft-patch's own per-host silence (an injected
# failure expires that one at once, on purpose), and all output is redacted on the way out.
#   [INJECT=sentry-postgate] [WANT=1] bash drill/live-run.sh [pft-patch run args...] 2>&1 | tee LOG
#   (as the agent user, from patch/; uses sudo -n and `ssh relay`; `--yes` is always passed)
# 0  preflight (nothing changed yet): relay reachable, Alertmanager ready, no pft-maint lock or window, env files
#    present, no leftovers, both nodes full, the INSTALLED pft-patch on both hosts has this checkout's sha256.
#    Topics, user name, host addresses and node keys go into a 0600 literals file for redact.py; the redaction
#    positive control runs before any change.
# 1  redirect: LOCAL_ENVS here and REMOTE_ENVS on the relay get a throwaway ALERT topic; a drill-only pft-maint
#    ntfy.env on both hosts gets a second throwaway MAINT topic. sha256 of every original is recorded; all of it is
#    restored on ANY exit (trap) and compared. Outer Alertmanager silence: alertname=~".+" except the pipeline
#    watchdog (alertpath must keep seeing it), OUTER_TTL.
# 2  per host: boot id, dpkg.log sha256, container StartedAt, server_state (before); then
#    sudo [PFT_PATCH_INJECT=$INJECT] pft-patch run --yes ARGS, exit must equal WANT; the same record after; for a
#    host that rebooted: auditd enabled 2 and loaded rules == compiled /etc/audit/audit.rules (one ENOENT aborts a
#    boot load); sentry DOCKER-USER -> PFT-EGRESS jump present once; both nodes full.
# 3  restore notifiers; outer silence expired if no node container restarted, else kept until the newest start +
#    RESTART_TAIL (PFTContainerRestarted stays true 15 min after a start); read back both throwaway topics; count
#    messages on every operator topic since the start (topics never printed); pft-integrity verify on both hosts.
#    Exit 0 = every CHECK ok.
# Env: INJECT ("")  WANT (0)  RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)
#      SENTRY_C (postfiatd-sentry)  VALIDATOR_C (postfiatd)  LOCAL_ENVS  REMOTE_ENVS  BRIDGE_ENV  AGENT_ENV
#      MAINT_DIR_L / MAINT_DIR_R (/etc/pft-maint)  OUTER_TTL (90, min)  RESTART_TAIL (25, min)  NTFY_WAIT (20)
#      WATCHDOG_ALERT (PFTAlertPipelineWatchdog)  REDACT (../peerexpose/drill/redact.py)  PFT_PATCH (../pft-patch.sh)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PP="${PFT_PATCH:-$HERE/../pft-patch.sh}"
REDACT="${REDACT:-$HERE/../../peerexpose/drill/redact.py}"
INJECT="${INJECT:-}"; WANT="${WANT:-0}"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"; AM="${AM:-http://127.0.0.1:9093}"
SENTRY_C="${SENTRY_C:-postfiatd-sentry}"; VALIDATOR_C="${VALIDATOR_C:-postfiatd}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_DIR_L="${MAINT_DIR_L:-/etc/pft-maint}"; MAINT_DIR_R="${MAINT_DIR_R:-/etc/pft-maint}"
OUTER_TTL="${OUTER_TTL:-90}"; RESTART_TAIL="${RESTART_TAIL:-25}"; NTFY_WAIT="${NTFY_WAIT:-20}"
WATCHDOG_ALERT="${WATCHDOG_ALERT:-PFTAlertPipelineWatchdog}"
SUF=.pre-patch-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="ppdrill-$(rnd)"; MAINT="ppmaint-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\ntopic\t%s\nuser\t%s\n' "$ALERT" "$MAINT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
hostof() { if [ "$1" = sentry ]; then echo relay; else echo local; fi; }
cof() { if [ "$1" = sentry ]; then echo "$SENTRY_C"; else echo "$VALIDATOR_C"; fi; }
state() { # HOST CONTAINER -> server_state (down if no answer)
  local s; s="$(on "$1" "sudo -n docker exec $2 curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
    | jq -r '.result.info.server_state // empty' 2>/dev/null)"; echo "${s:-down}"
}
started() { on "$1" "sudo -n docker inspect -f '{{.State.StartedAt}}' $2" 2>/dev/null; }
record() { # HOSTNAME -> "boot=<8> dpkg=<12> started=<StartedAt> state=<state>"
  local h c b d
  h="$(hostof "$1")"; c="$(cof "$1")"
  b="$(on "$h" "cat /proc/sys/kernel/random/boot_id" | cut -c1-8)"
  d="$(on "$h" "sudo -n sha256sum /var/log/dpkg.log" | cut -c1-12)"
  echo "boot=$b dpkg=$d started=$(started "$h" "$c") state=$(state "$h" "$c")"
}
FAILS=0
check() { # NAME CONDITION-RESULT(0/1) DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}

declare -A SHA=()
declare -a MOVED=() CREATED=()
RESTORED=0; RESTORE_OK=true; SIL=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"   # sudo reads the file (a '<' redirect would not)
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
  for k in "${CREATED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n rm -f $f"
    if on "$h" "sudo -n test -e $f"; then echo "  removed drill-only $k: NO"; RESTORE_OK=false
    else echo "  removed drill-only $k: yes"; fi
  done
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-patch live-run - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN"
  echo "sha256: pft-patch.sh $(sha256sum < "$PP" | cut -c1-64) | live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"
  echo "args: ${INJECT:+PFT_PATCH_INJECT=$INJECT }pft-patch run --yes $* | expected exit $WANT"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
locks="$(sudo -n pft-maint lock list 2>&1)"
[ "$locks" = "no data-collection locks" ] || { echo "  pft-maint data-collection lock held: $locks - stopping" >&2; exit 4; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is already open - stopping" >&2; exit 4; }
echo "  pft-maint: $locks, no window open"
want_sha="$(sha256sum < "$PP" | cut -c1-64)"
for hn in sentry validator; do
  h="$(hostof "$hn")"
  got="$(on "$h" "sudo -n sha256sum /usr/local/sbin/pft-patch" | cut -c1-64)"
  echo "  $hn: installed /usr/local/sbin/pft-patch sha256 ${got:-missing}"
  [ "$got" = "$want_sha" ] || { echo "  $hn: installed pft-patch differs from this checkout - stopping" >&2; exit 3; }
done
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
! L "sudo -n test -e $MAINT_DIR_L/ntfy.env" || { echo "  local $MAINT_DIR_L/ntfy.env exists - refusing to overwrite" >&2; exit 3; }
! R "sudo -n test -e $MAINT_DIR_R/ntfy.env" || { echo "  relay $MAINT_DIR_R/ntfy.env exists - refusing to overwrite" >&2; exit 3; }
# operator topics (read back at the end, never printed): every notifier env here and on the relay, the alert bridge,
# and the agent's own topic
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
# shellcheck disable=SC2016  # expands on the relay: the address it sees this host connect from
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"
[ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
# shellcheck disable=SC2016  # expands on the relay
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"
[ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
for hn in sentry validator; do
  h="$(hostof "$hn")"; c="$(cof "$hn")"
  si="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005")"
  k="$(jq -r '.result.info.pubkey_node // empty' <<<"$si" 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  st="$(jq -r '.result.info.server_state // "down"' <<<"$si" 2>/dev/null)"
  echo "  $hn ($c): server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }

echo; echo "== 1. redirect notifiers, outer Alertmanager silence"
redirect() { # HOST PATH
  local h="$1" f="$2"
  SHA["$h:$f"]="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
  [[ "${SHA[$h:$f]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $h:$f unreadable - stopping before any change"; exit 3; }
  echo "  $h:$f sha256 ${SHA[$h:$f]:0:12} (before)"
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $h:$f -> $NTFY/<redacted> (ALERT), original kept as $f$SUF"
}
for f in $LOCAL_ENVS; do redirect local "$f"; done
for f in $REMOTE_ENVS; do redirect relay "$f"; done
for k in "local:$MAINT_DIR_L" "relay:$MAINT_DIR_R"; do
  h="${k%%:*}"; d="${k#*:}"
  CREATED+=("$h:$d/ntfy.env")
  on "$h" "sudo -n sh -c 'umask 077; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $MAINT > $d/ntfy.env'" \
    || { echo "  $h:$d/ntfy.env not created - stopping"; exit 3; }
  echo "  $h:$d/ntfy.env created for the drill only -> $NTFY/<redacted> (MAINT)"
done
ends="$(date -u -d "+$OUTER_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "pft-patch drill $RUN (outer)" --arg w "$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $w, isRegex: false, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "pft-patch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  outer Alertmanager silence alertname=~\".+\", alertname!=\"$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"

echo; echo "== 2. pft-patch run"
declare -A BEFORE=() AFTER=()
for hn in sentry validator; do BEFORE[$hn]="$(record "$hn")"; echo "  before $hn: ${BEFORE[$hn]}"; done
echo; echo "\$ sudo ${INJECT:+PFT_PATCH_INJECT=$INJECT }pft-patch run --yes $* ($(ts))"
# shellcheck disable=SC2024  # the output file is ours; only pft-patch runs as root
sudo -n env ${INJECT:+PFT_PATCH_INJECT="$INJECT"} pft-patch run --yes "$@" > "$SEC/run.out" 2>&1; rc=$?
red < "$SEC/run.out"
echo "exit $rc ($(ts))"
check "pft-patch run exit $WANT" "$([ "$rc" = "$WANT" ] && echo 0 || echo 1)" "got $rc"
echo
restarted=0
for hn in sentry validator; do
  h="$(hostof "$hn")"; c="$(cof "$hn")"
  AFTER[$hn]="$(record "$hn")"; echo "  after  $hn: ${AFTER[$hn]}"
  for _i in $(seq 1 60); do case "$(state "$h" "$c")" in full|proposing) break ;; esac; sleep 10; done
  ss="$(state "$h" "$c")"
  check "$hn server_state full after the run" "$(case "$ss" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$ss"
  [ "${BEFORE[$hn]#* started=}" = "${AFTER[$hn]#* started=}" ] || restarted=1
  b0="${BEFORE[$hn]%% *}"; b1="${AFTER[$hn]%% *}"
  if [ "$b0" != "$b1" ]; then
    en="$(on "$h" "sudo -n auditctl -s" | awk '$1=="enabled"{print $2}')"
    nl="$(on "$h" "sudo -n auditctl -l" | grep -c .)"; nc="$(on "$h" "sudo -n grep -cE '^-(a|w) ' /etc/audit/audit.rules")"
    echo "  $hn rebooted ($b0 -> $b1): auditd enabled $en, $nl rules loaded, $nc compiled"
    check "$hn auditd immutable (-e 2) after the reboot" "$([ "$en" = 2 ] && echo 0 || echo 1)" "enabled $en"
    check "$hn every compiled audit rule loaded at boot" "$([ "$nl" = "$nc" ] && [ "${nc:-0}" -gt 0 ] && echo 0 || echo 1)" "$nl/$nc"
  fi
done
n="$(R "sudo -n iptables -S DOCKER-USER" | grep -c -- '-j PFT-EGRESS')"
check "sentry DOCKER-USER -> PFT-EGRESS jump present once" "$([ "$n" = 1 ] && echo 0 || echo 1)" "$n"

echo; echo "== 3. restore, outer silence, read back"
restore
check "notifier env files restored byte-identical, drill-only files removed" "$([ "$RESTORE_OK" = true ] && echo 0 || echo 1)"
if [ "$restarted" = 1 ]; then
  newest="$(for hn in sentry validator; do s="${AFTER[$hn]#* started=}"; s="${s%% *}"; date -u -d "$s" +%s; done | sort -n | tail -1)"
  e="$(date -u -d "@$(( newest + RESTART_TAIL * 60 ))" +%FT%TZ)"
  curl -s --max-time 10 -o /dev/null -w "  outer silence kept until $e (newest container start + ${RESTART_TAIL} min): HTTP %{http_code}\n" \
    -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$(jq -c --arg id "$SIL" --arg e "$e" '. + {id: $id, endsAt: $e}' <<<"$SBODY")"
else
  curl -s --max-time 10 -o /dev/null -w '  no node container restarted: outer silence expired: HTTP %{http_code}\n' -X DELETE "$AM/api/v2/silence/$SIL"
fi
sleep "$NTFY_WAIT"
readback() { # TOPIC LABEL [quiet] -> sets N_MSG; prints messages unless quiet
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$MAINT" MAINT
readback "$ALERT" ALERT
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the drill" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo "  \$ pft-integrity verify (validator host)"; sudo -n pft-integrity verify 2>&1 | red | tail -12 | sed 's/^/    /'
echo "  \$ pft-integrity verify (sentry host)"; R "sudo -n pft-integrity verify" 2>&1 | red | tail -12 | sed 's/^/    /'
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
