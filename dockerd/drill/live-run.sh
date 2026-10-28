#!/usr/bin/env bash
# live-run: the two-host pft-dockerd drill, sentry first, inside a pft-maint window and an Alertmanager silence,
# with every ntfy notifier on both hosts pointed at throwaway topics and all output redacted on the way out.
#   bash drill/live-run.sh 2>&1 | tee LOG        (as the agent user, from dockerd/; uses sudo -n and `ssh relay`)
# 0  preflight (nothing changed yet): relay reachable, Alertmanager ready, no pft-maint lock, env files present,
#    no leftovers from an earlier drill, both nodes full. Topics, user name, host addresses and node keys go
#    into a 0600 literals file for redact.py; the redaction positive control runs before any change.
# 1  redirect: LOCAL_ENVS here and REMOTE_ENVS on the relay get a throwaway ALERT topic; a drill-only pft-maint
#    ntfy.env on both hosts gets a second throwaway MAINT topic. sha256 of every original is recorded; all of it
#    is restored on ANY exit (trap) and compared. Then `pft-maint start` (both hosts) and an Alertmanager silence
#    on job=~".+" (every node/exporter alert; the label-less PFTAlertPipelineWatchdog keeps flowing).
# 2  per host, sentry first (step: command, redacted output, exit code, expected exit):
#    audit, audit --json (initial; findings expected) | apply --dry-run | bad-key drill (exit 4, daemon.json sha256
#    unchanged) | apply --yes (exit 0) | health drill (exit 1, rollback, daemon.json byte-identical to the applied
#    file) | audit, audit --json (final) | node container StartedAt unchanged and server_state full.
#    REBOOT_SENTRY=1: reboot the sentry inside the window so auditd (-e 2, immutable) loads the staged watches,
#    wait for the node to be full again, audit the sentry once more. The reboot restarts the sentry container by
#    design; StartedAt is compared only across the dockerd steps, before the reboot.
# 3  end window, expire silence, restore notifiers, read both throwaway topics back, pft-integrity verify on both
#    hosts (rebaseline is a separate, reviewed step), verdict. Exit 0 = every CHECK ok.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  SENTRY_C (postfiatd-sentry)
#      VALIDATOR_C (postfiatd)  LOCAL_ENVS  REMOTE_ENVS  MAINT_DIR_L / MAINT_DIR_R (/etc/pft-maint)  TTL (1h)
#      DRILL_BUDGET (60: HEALTH_BUDGET of the health drill)  REBOOT_SENTRY (0)  NTFY_WAIT (15)
#      HOSTS ("sentry validator")  REDACT (../peerexpose/drill/redact.py)  DRY (1 = preflight, redirect,
#      window, silence and restore only; no pft-dockerd step changes anything)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PD="${PFT_DOCKERD:-$HERE/../pft-dockerd.sh}"
REDACT="${REDACT:-$HERE/../../peerexpose/drill/redact.py}"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"; AM="${AM:-http://127.0.0.1:9093}"
SENTRY_C="${SENTRY_C:-postfiatd-sentry}"; VALIDATOR_C="${VALIDATOR_C:-postfiatd}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
MAINT_DIR_L="${MAINT_DIR_L:-/etc/pft-maint}"; MAINT_DIR_R="${MAINT_DIR_R:-/etc/pft-maint}"
TTL="${TTL:-1h}"; DRILL_BUDGET="${DRILL_BUDGET:-60}"; REBOOT_SENTRY="${REBOOT_SENTRY:-0}"
NTFY_WAIT="${NTFY_WAIT:-15}"; HOSTS="${HOSTS:-sentry validator}"; DRY="${DRY:-0}"
SUF=.pre-dockerd-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="dkdrill-$(rnd)"; MAINT="dkmaint-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
printf 'topic\t%s\ntopic\t%s\nuser\t%s\n' "$ALERT" "$MAINT" "$(id -un)" >> "$LIT"
# the user name is a literal (above); a generic "by <word>" rewrite also hit text like "enabled by reload"
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
djsha() { on "$1" "sudo -n sh -c 'if [ -f /etc/docker/daemon.json ]; then sha256sum /etc/docker/daemon.json | cut -c1-64; else echo absent; fi'"; }

egress_jump() { # HOSTNAME: egress/ owns a DOCKER-USER -> PFT-EGRESS jump; after the dockerd restarts it must be there once
  local h n; h="$(hostof "$1")"
  on "$h" "test -x /usr/local/sbin/pft-egress" || { echo "-- $1: egress/ not installed, no PFT-EGRESS jump to check"; return 0; }
  n="$(on "$h" "sudo -n iptables -S DOCKER-USER" | grep -c -- '-j PFT-EGRESS')"
  check "$1 DOCKER-USER -> PFT-EGRESS jump present once after the dockerd restarts" "$([ "$n" = 1 ] && echo 0 || echo 1)" "$n"
}
FAILS=0
check() { # NAME CONDITION-RESULT(0/1) DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}

declare -A SHA=()
declare -a MOVED=() CREATED=()
RESTORED=0; RESTORE_OK=true; RDIR=""; SIL=""; WINDOW=0
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha
  if [ "$WINDOW" = 1 ]; then
    sudo -n pft-maint end --reason "pft-dockerd drill done" 2>&1 | red | sed 's/^/  /'
  fi
  if [ -n "$SIL" ]; then
    curl -s --max-time 10 -o /dev/null -w '  silence expired: HTTP %{http_code}\n' -X DELETE "$AM/api/v2/silence/$SIL"
  fi
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
  [ -z "$RDIR" ] || R "rm -rf $RDIR"
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

# step HOSTNAME NAME WANT_EXIT [ENV=VAL ...] -- ARGS... : runs pft-dockerd as root on that host, redacted
step() {
  local hn="$1" name="$2" want="$3" h envs=() rc; shift 3
  while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
  h="$(hostof "$hn")"
  echo; echo "-- $hn: $name ($(ts))"
  echo "\$ sudo ${envs[*]:+${envs[*]} }pft-dockerd $*" | red
  if [ "$h" = relay ]; then
    R "sudo -n env ${envs[*]} bash $RDIR/pft-dockerd.sh $(printf '%q ' "$@")" > "$SEC/step.out" 2>&1; rc=$?
  else
    # shellcheck disable=SC2024  # the output file is ours; only pft-dockerd runs as root
    sudo -n env "${envs[@]}" bash "$PD" "$@" > "$SEC/step.out" 2>&1; rc=$?
  fi
  red < "$SEC/step.out"
  echo "exit $rc"
  if [ "$want" = any ]; then return 0; fi
  check "$hn $name exit $want" "$([ "$rc" = "$want" ] && echo 0 || echo 1)" "got $rc"
}

{ echo "pft-dockerd live-run - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN$([ "$DRY" = 1 ] && echo ' - DRY')"
  echo "sha256: pft-dockerd.sh $(sha256sum < "$PD" | cut -c1-64) | live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
locks="$(sudo -n pft-maint lock list 2>&1)"
[ "$locks" = "no data-collection locks" ] || { echo "  pft-maint data-collection lock held: $locks - stopping" >&2; exit 4; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is already open - stopping" >&2; exit 4; }
echo "  pft-maint: $locks, no window open"
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
# shellcheck disable=SC2016  # expands on the relay: the address it sees this host connect from
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"
[ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
for hn in sentry validator; do
  h="$(hostof "$hn")"; c="$(cof "$hn")"
  si="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005")"
  k="$(jq -r '.result.info.pubkey_node // empty' <<<"$si" 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  st="$(jq -r '.result.info.server_state // "down"' <<<"$si" 2>/dev/null)"
  echo "  $hn ($c): server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
# shellcheck disable=SC2016  # expands on the relay
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"
[ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
RDIR="$(R 'mktemp -d')"
if [ -z "$RDIR" ] || ! R "cat > $RDIR/pft-dockerd.sh" < "$PD" \
   || [ "$(R "sha256sum < $RDIR/pft-dockerd.sh")" != "$(sha256sum < "$PD")" ]; then
  echo "  copy of pft-dockerd.sh to the relay failed - stopping" >&2; exit 3
fi
echo "  pft-dockerd.sh copied to the sentry host (temp dir, same sha256), removed on exit"

echo; echo "== 1. redirect notifiers, open the maintenance window, silence Alertmanager"
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
sudo -n pft-maint start --ttl "$TTL" --reason "pft-dockerd drill $RUN" 2>&1 | red | sed 's/^/  /'
sudo -n pft-maint active >/dev/null 2>&1 || { echo "  pft-maint window did not open - stopping"; exit 3; }
WINDOW=1
ends="$(date -u -d "+${TTL/h/ hour}" +%FT%TZ 2>/dev/null || date -u -d '+1 hour' +%FT%TZ)"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$(jq -nc \
  --arg s "$(ts)" --arg e "$ends" --arg c "pft-dockerd drill $RUN" \
  '{matchers: [{name: "job", value: ".+", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "pft-dockerd-drill", comment: $c}')" \
  | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  Alertmanager silence job=~\".+\" until $ends (id ${SIL:0:8})"

if [ "$DRY" = 1 ]; then
  echo; echo "== 2. DRY=1: read-only audit per host, no change"
  for hn in $HOSTS; do step "$hn" audit-initial any -- audit; done
else
  echo; echo "== 2. sequence per host: $HOSTS"
  for hn in $HOSTS; do
    h="$(hostof "$hn")"; c="$(cof "$hn")"
    st0="$(started "$h" "$c")"; echo; echo "-- $hn: $c StartedAt before: $st0, daemon.json sha256 $(djsha "$h")"
    step "$hn" audit-initial any -- audit
    step "$hn" audit-initial-json any -- audit --json
    step "$hn" plan-dry-run 0 -- apply --dry-run
    s1="$(djsha "$h")"
    step "$hn" bad-key-drill 4 PFT_DOCKERD_INJECT=bad-key -- apply --yes
    s2="$(djsha "$h")"
    check "$hn bad-key drill: daemon.json unchanged" "$([ "$s1" = "$s2" ] && echo 0 || echo 1)" "sha256 $s1 -> $s2"
    step "$hn" apply 0 -- apply --yes
    s3="$(djsha "$h")"
    step "$hn" health-drill 1 PFT_DOCKERD_INJECT=health "HEALTH_BUDGET=$DRILL_BUDGET" -- apply --yes
    s4="$(djsha "$h")"
    check "$hn health drill: daemon.json byte-identical to the applied file" "$([ "$s3" = "$s4" ] && [ "$s3" != absent ] && echo 0 || echo 1)" "sha256 $s3 -> $s4"
    step "$hn" audit-final any -- audit
    step "$hn" audit-final-json any -- audit --json
    st1="$(started "$h" "$c")"; ss="$(state "$h" "$c")"
    echo "-- $hn: $c StartedAt after: $st1, server_state $ss"
    check "$hn container StartedAt unchanged through apply + both drills" "$([ -n "$st0" ] && [ "$st0" = "$st1" ] && echo 0 || echo 1)"
    check "$hn server_state full" "$(case "$ss" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$ss"
    egress_jump "$hn"
  done
  if [ "$REBOOT_SENTRY" = 1 ]; then
    echo; echo "-- sentry: reboot to load the staged auditd watches (auditd -e 2) ($(ts))"
    R "sudo -n systemctl reboot" || true
    sleep 30
    for _i in $(seq 1 60); do R true 2>/dev/null && break; sleep 10; done
    for _i in $(seq 1 90); do case "$(state relay "$SENTRY_C")" in full|proposing) break ;; esac; sleep 10; done
    echo "  sentry back: uptime $(R 'cut -d. -f1 /proc/uptime') s, server_state $(state relay "$SENTRY_C") ($(ts))"
    RDIR="$(R 'mktemp -d')"; R "cat > $RDIR/pft-dockerd.sh" < "$PD"
    step sentry audit-after-reboot 0 -- audit
    en="$(R "sudo -n auditctl -s" | awk '$1=="enabled"{print $2}')"; nr="$(R "sudo -n auditctl -l" | grep -c .)"
    echo "  sentry auditd after reboot: enabled $en, $nr rules loaded"
    check "sentry auditd immutable (-e 2) after reboot" "$([ "$en" = 2 ] && echo 0 || echo 1)" "enabled $en"
    # one ENOENT aborts the boot load, so also require every staged pft-dockerd watch to be loaded
    miss="$(R "sudo -n sed -n 's/^-w \\([^ ]*\\) .*/\\1/p' /etc/audit/rules.d/pft-dockerd.rules | while read -r w; do sudo -n auditctl -l | grep -qE -- \"^-w \$w( |\$)\" || echo \"\$w\"; done")"
    nw="$(R "sudo -n grep -c '^-w ' /etc/audit/rules.d/pft-dockerd.rules")"
    echo "  sentry pft-dockerd.rules: $nw watch(es) staged, not loaded: ${miss:-none}"
    check "sentry: every staged pft-dockerd watch loaded at boot" "$([ -z "$miss" ] && [ "${nw:-0}" -gt 0 ] && echo 0 || echo 1)" "${miss:-all $nw loaded}"
    egress_jump sentry
    check "sentry server_state full after reboot" "$(case "$(state relay "$SENTRY_C")" in full|proposing) echo 0 ;; *) echo 1 ;; esac)"
  fi
fi

echo; echo "== 3. close window, expire silence, restore, read back"
restore
check "notifier env files restored byte-identical, drill-only files removed" "$([ "$RESTORE_OK" = true ] && echo 0 || echo 1)"
sleep "$NTFY_WAIT"
readback() { # TOPIC LABEL -> prints messages, sets N_MSG
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$MAINT" MAINT
readback "$ALERT" ALERT
check "ALERT throwaway topic received nothing" "$([ "$N_MSG" = 0 ] && echo 0 || echo 1)" "$N_MSG"
echo "  \$ pft-integrity verify (validator host)"; sudo -n pft-integrity verify 2>&1 | red | tail -12 | sed 's/^/    /'
echo "  \$ pft-integrity verify (sentry host)"; R "sudo -n pft-integrity verify" 2>&1 | red | tail -12 | sed 's/^/    /'
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
