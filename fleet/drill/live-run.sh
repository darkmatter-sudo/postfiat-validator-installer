#!/usr/bin/env bash
# live-run: the pft-fleet two-host drill. Inside one pft-maint window, with every ntfy notifier on both hosts pointed at
# a throwaway topic, it walks the sentry's copy of one add-on (DRILL_ADDON, default sysctl: a single script that only
# runs when an operator calls it, so no timer or service depends on it) through every state and every sync path:
#   0  preflight (nothing changed yet): relay reachable, no pft-maint window, notifier env files present and no
#      leftovers, both nodes full, pft-integrity PASS on both hosts, redaction positive control.
#   1  redirect: LOCAL_ENVS / REMOTE_ENVS get the throwaway topic (sha256 recorded, restored on ANY exit and compared).
#   2  sudo pft-maint start on the validator; wait until the sentry has the window too (watchdog channel).
#   3  A baseline skew (sentry DRILL_ADDON CURRENT)
#      B dry run, then sync --to OLD --hosts sentry --apply            -> sentry BEHIND + DIVERGED (skew exit 1)
#      C sync --to REF with an injected gate failure on the sentry    -> exit 5, original (BEHIND) sha256 restored,
#                                                                        pft-integrity PASS without an accept
#      D sync --to REF --apply                                         -> sentry CURRENT (skew: addon back to CURRENT)
#      E uncommitted hand edit on the sentry (one comment line)        -> MODIFIED (skew exit 2)
#      F sync --to REF --apply                                         -> CURRENT, bytes = repo
#      G FIX_ADDONS (real drift found by the first live skew) synced to REF, then the final skew
#   4  sudo pft-maint end; restore env files (sha256 compared); read back the throwaway topic and count messages on
#      every operator topic since the start (topics never printed); pft-integrity verify on both hosts.
#   Exit 0 = every CHECK ok. Every command is printed by x() exactly as it runs; output is redacted on the way out.
#   bash drill/live-run.sh 2>&1 | tee LOG     (as the agent user, from fleet/; uses sudo -n and `ssh relay`)
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  DRILL_ADDON (sysctl)  OLD (oldest commit of the add-on's first file)
#      REF (main)  FIX_ADDONS ("alertpath backup")  LOCAL_ENVS  REMOTE_ENVS  AGENT_ENV  TTL (45m)  NTFY_WAIT (20, s)
#      REDACT (../../peerexpose/drill/redact.py)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FL="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$FL/.." && pwd)"
REDACT="${REDACT:-$HERE/../../peerexpose/drill/redact.py}"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
DRILL_ADDON="${DRILL_ADDON:-sysctl}"; REF="${REF:-main}"; FIX_ADDONS="${FIX_ADDONS-alertpath backup}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"; TTL="${TTL:-45m}"; NTFY_WAIT="${NTFY_WAIT:-20}"
SUF=.pre-fleet-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="fleetdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; }
FAILS=0
check() { # NAME 0|1 DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
XRC=0; XOUT=""
x() { # print the exact command, run it, print its exit code; output kept in XOUT
  echo "\$ $*"
  XOUT="$(eval "$*" 2>&1)"; XRC=$?
  printf '%s\n' "$XOUT" | red
  echo "(exit $XRC)"
}
q() { XOUT="$(eval "$*" 2>&1)"; XRC=$?; } # same, silent (for checks whose command was already shown)
is() { [ "$1" = "$2" ] && echo 0 || echo 1; }
# grep the last skew output
skew_has() { grep -qE -- "$1" <<<"$XOUT" && echo 0 || echo 1; }

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; MAINT_STARTED=0
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$MAINT_STARTED" = 1 ]; then
    echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'
  fi
  local k h f now_sha
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

FIRST="$(python3 -I "$FL/fleet_lib.py" files --manifest "$FL/manifest.tsv" --addon "$DRILL_ADDON" --role sentry | head -1)"
DPATH="$(cut -f3 <<<"$FIRST")"; DREPO="$(cut -f2 <<<"$FIRST")"
[ -n "$DPATH" ] || { echo "add-on $DRILL_ADDON has no sentry file in the manifest" >&2; exit 3; }
OLD="${OLD:-$(git -C "$REPO" log --format=%H "$REF" -- "$DREPO" | tail -1)}"
REFC="$(git -C "$REPO" rev-parse "$REF")"
want_old="$(git -C "$REPO" show "$OLD:$DREPO" | sha256sum | cut -c1-64)"
want_ref="$(git -C "$REPO" show "$REF:$DREPO" | sha256sum | cut -c1-64)"
ssha() { R "sudo -n sha256sum $DPATH" | cut -c1-64; }

{ echo "pft-fleet two-host drill - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD) | $REF $REFC"
  echo "sha256: live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  for f in pft-fleet.sh fleet_lib.py manifest.tsv; do
    echo "        repo $f $(sha256sum < "$FL/$f" | cut -c1-64)"
  done
  echo "        installed /usr/local/sbin/pft-fleet $(sudo -n sha256sum /usr/local/sbin/pft-fleet | cut -c1-64)"
  echo "        installed fleet_lib.py $(sudo -n sha256sum /usr/local/lib/pft-fleet/fleet_lib.py | cut -c1-64) manifest.tsv $(sudo -n sha256sum /usr/local/lib/pft-fleet/manifest.tsv | cut -c1-64)"
  echo "drill add-on $DRILL_ADDON: sentry $DPATH <- $DREPO; OLD $OLD (sha256 ${want_old:0:12}), $REF (sha256 ${want_ref:0:12})"
  echo "redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
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
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
# shellcheck disable=SC2016  # expands on the relay
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
# shellcheck disable=SC2016  # expands on the relay
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  st="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.server_state // "down"' 2>/dev/null)"
  echo "  $c: server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"
  echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping (an accept would hide it)" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }

echo; echo "== 1. redirect every ntfy notifier on both hosts to a throwaway topic"
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

echo; echo "== 2. maintenance window"
x "sudo -n pft-maint start --ttl $TTL --reason 'pft-fleet drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do
  w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10
done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 3A. baseline"
x "sudo -n pft-fleet skew --hosts sentry"
check "A skew: sentry $DRILL_ADDON CURRENT" "$(skew_has "^sentry +$DRILL_ADDON +CURRENT")"
s0="$(ssha)"; echo "  sentry $DPATH sha256 $s0"
check "A sentry bytes = $REF" "$(is "$s0" "$want_ref")"

echo; echo "== 3B. make the sentry BEHIND: pinned sync to $OLD"
x "sudo -n pft-fleet sync --addon $DRILL_ADDON --to ${OLD:0:12} --hosts sentry"
check "B dry run exit 0" "$(is "$XRC" 0)"
check "B dry run changed nothing" "$(is "$(ssha)" "$s0")"
x "sudo -n pft-fleet sync --addon $DRILL_ADDON --to ${OLD:0:12} --hosts sentry --apply --reason 'fleet drill $RUN: step B'"
check "B apply exit 0" "$(is "$XRC" 0)"
s1="$(ssha)"; echo "  sentry $DPATH sha256 $s1"
check "B sentry bytes = $OLD" "$(is "$s1" "$want_old")"
x "sudo -n pft-fleet skew"
check "B skew exit 1 (drift)" "$(is "$XRC" 1)"
check "B skew: sentry $DRILL_ADDON BEHIND" "$(skew_has "^sentry +$DRILL_ADDON +BEHIND")"
check "B skew: $DRILL_ADDON DIVERGED" "$(skew_has "^\* +$DRILL_ADDON +DIVERGED")"

echo; echo "== 3C. injected gate failure: sync to $REF, gate fails on the sentry, rollback"
x "sudo -n env PFT_FLEET_INJECT_GATE_FAIL=sentry pft-fleet sync --addon $DRILL_ADDON --to $REF --hosts sentry --apply"
check "C exit 5 (rolled back)" "$(is "$XRC" 5)"
s2="$(ssha)"; echo "  sentry $DPATH sha256 before C $s1 / after C $s2"
check "C original sha256 restored" "$(is "$s2" "$s1")"
x "R 'sudo -n pft-integrity verify' | tail -2"
check "C sentry pft-integrity PASS without an accept (cp -p restore)" "$(grep -q '^RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-fleet skew --hosts sentry"
check "C skew: sentry $DRILL_ADDON still BEHIND" "$(skew_has "^sentry +$DRILL_ADDON +BEHIND")"

echo; echo "== 3D. health-gated sync back to $REF"
x "sudo -n pft-fleet sync --addon $DRILL_ADDON --to $REF --hosts sentry --apply --reason 'fleet drill $RUN: step D'"
check "D exit 0" "$(is "$XRC" 0)"
check "D sentry bytes = $REF" "$(is "$(ssha)" "$want_ref")"
x "sudo -n pft-fleet skew --hosts sentry"
check "D skew: sentry $DRILL_ADDON CURRENT" "$(skew_has "^sentry +$DRILL_ADDON +CURRENT")"

echo; echo "== 3E. uncommitted hand edit on the sentry"
x "R \"echo '# pft-fleet drill $RUN: uncommitted hand edit' | sudo -n tee -a $DPATH >/dev/null\""
x "sudo -n pft-fleet skew"
check "E skew exit 2" "$(is "$XRC" 2)"
check "E skew: sentry $DRILL_ADDON MODIFIED" "$(skew_has "^sentry +$DRILL_ADDON +MODIFIED")"

echo; echo "== 3F. sync the hand-edited copy back to $REF"
x "sudo -n pft-fleet sync --addon $DRILL_ADDON --to $REF --hosts sentry --apply --reason 'fleet drill $RUN: step F'"
check "F exit 0" "$(is "$XRC" 0)"
check "F sentry bytes = $REF" "$(is "$(ssha)" "$want_ref")"

echo; echo "== 3G. real drift from the first live skew: ${FIX_ADDONS:-none}"
for a in $FIX_ADDONS; do
  x "sudo -n pft-fleet sync --addon $a --to $REF --apply --reason 'fleet drill $RUN: real drift fixed'"
  check "G $a sync exit 0" "$(is "$XRC" 0)"
done
x "sudo -n pft-fleet skew"
check "G final skew exit 0 (every add-on CURRENT on both hosts, nothing DIVERGED)" "$(is "$XRC" 0)"

echo; echo "== 4. end window, restore, read back"
restore
MAINT_STARTED=0
check "notifier env files restored byte-identical" "$([ "$RESTORE_OK" = true ] && echo 0 || echo 1)"
sleep "$NTFY_WAIT"
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
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"
  echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  st="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.server_state // "down"' 2>/dev/null)"
  check "$c full at the end" "$(case "$st" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$st"
done
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
