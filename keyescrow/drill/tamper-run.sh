#!/usr/bin/env bash
# tamper-run: the pft-keyescrow one-byte tamper drill, live on both hosts. No change to either node and no secret is
# read in plaintext: the drill flips ONE byte of the newest encrypted generation each host holds for its peer, lets
# the INSTALLED units (pft-keyescrow.service: verify --textfile; pft-keyescrow-pull.service on the validator) export
# the result, waits for PFTKeyEscrowVerifyFailed to fire and reach a THROWAWAY ntfy topic, then puts the original
# bytes back (cp -p from a 0700 root backup), and waits for the alert to resolve.
#   T1  validator holds the sentry's newest generation: one byte flipped           -> "ciphertext sha256 MISMATCH"
#   T2  sentry holds the validator's newest generation: one byte flipped AND the meta's cipher_sha256 rewritten to the
#       tampered file's hash, so the sha check passes and the in-memory age decrypt (AEAD) must catch it
#   Both: restore --dry-run from the tampered copy must be refused ("reseal refused"), nothing written.
# Built from ../../upgradewatch/drill/live-run.sh (redirect / bridge swap / silence / read-back framework, PASS run 12),
# with the silence never matching PFTAlertPipelineWatchdog (lesson from the apparmor run 26).
#   bash keyescrow/drill/tamper-run.sh > LOG 2>&1   (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): relay, Alertmanager, Prometheus; no pft-maint window; notifier env files present,
#    no leftovers; bridge mounts the operator env; no active silence covers PFTKeyEscrowVerifyFailed; no keyescrow
#    alert active; held_verify_ok 1 for both (node, peer) pairs; `verify --all` exit 0 on both hosts; both nodes full;
#    pft-integrity PASS on both; redaction positive control.
# 1  redirect notifiers + bridge to a throwaway topic, silence every alert except PFTKeyEscrowVerifyFailed and the
#    pipeline watchdog, pft-maint window (sentry copy).
# 2  tamper T1 + T2, run the units, check the verify output, the exported metric, refused dry-run restores, FIRING
#    in Prometheus for exactly the two pairs, [FIRING] on the throwaway topic for both.
# 3  restore the original bytes (sha256 == pre-drill), run the units, verify_ok 1, both pairs leave Prometheus and
#    deliver [RESOLVED]; ALERTS query_range.
# 4  restore notifiers + bridge, end window, expire silence, read back throwaway + operator topics (never printed),
#    integrity PASS both, nodes full, `verify --all` exit 0 both, no drill backup left. Exit 0 = every CHECK ok.
# Env: RELAY (relay) NTFY (https://ntfy.sh) AM PROM  TTL (60m) SIL_TTL (60, min) FIRE_WAIT (900, s)
#      RESOLVE_WAIT (600, s) NTFY_WAIT (180, s) READBACK_WAIT (150, s) PREFLIGHT_ONLY (0)
# shellcheck disable=SC2016  # ok_if conditions are single-quoted on purpose: evaluated later
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REDACT="${REDACT:-$REPO/peerexpose/drill/redact.py}"
RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
TTL="${TTL:-60m}"; SIL_TTL="${SIL_TTL:-60}"
FIRE_WAIT="${FIRE_WAIT:-900}"; RESOLVE_WAIT="${RESOLVE_WAIT:-600}"; NTFY_WAIT="${NTFY_WAIT:-180}"
READBACK_WAIT="${READBACK_WAIT:-150}"
KE_ALERT=PFTKeyEscrowVerifyFailed
WATCHDOG_ALERT=PFTAlertPipelineWatchdog
SUF=.pre-keyescrow-drill
BIN=/usr/local/bin/pft-keyescrow
ST=/var/lib/pft-keyescrow
# expected pairs: NODE(holder) PEER(owner of the secrets) HOST-to-run-on
PAIRS="validator sentry local
sentry validator relay"

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="kedrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
BKD="$ST/drill-backup-$RUN"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d "${TEST_TMPDIR:-$HOME/.cache}/kedrill.XXXXXX")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
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
newest() { on "$1" "sudo -n ls $ST/store/$2/" | sed -n 's/^gen-\([0-9TZ]*\)\.meta$/\1/p' | sort | tail -1; } # HOST FROM
# run the installed units the timers run, then show what they logged (UTC, this run only)
run_units() {
  local t; t="$(date -u +%s)"
  x "sudo -n systemctl start pft-keyescrow.service; R 'sudo -n systemctl start pft-keyescrow.service'; sudo -n systemctl start pft-keyescrow-pull.service; echo started"
  x "sudo -n journalctl --utc -o cat -u pft-keyescrow.service --since @$t | grep -E 'MISMATCH|VERIFY|RESULT: [0-9]'; R 'sudo -n journalctl --utc -o cat -u pft-keyescrow.service --since @$t' | grep -E 'MISMATCH|VERIFY|RESULT: [0-9]'; sudo -n journalctl --utc -o cat -u pft-keyescrow-pull.service --since @$t | grep -E 'pulled|rejected|failed'"
  # shellcheck disable=SC2034  # read inside ok_if strings
  UNITLOG="$XOUT"
}
wait_metric() { # VALUE -> waits until both pairs show pft_keyescrow_held_verify_ok VALUE in Prometheus (max 180 s)
  local w=0 n
  while :; do
    n="$(pq "pft_keyescrow_held_verify_ok == $1" | grep -cE 'node=(validator,peer=sentry|sentry,peer=validator)')"
    [ "$n" = 2 ] && break
    w=$((w + 10)); [ "$w" -le 180 ] || break; sleep 10
  done
  echo "  Prometheus: $n/2 pairs with pft_keyescrow_held_verify_ok $1 after ${w}s"
  x "curl -s --max-time 20 $PROM/api/v1/query --data-urlencode 'query=pft_keyescrow_held_verify_ok' | jq -r '.data.result[] | \"\(.metric.node) peer=\(.metric.peer) \(.value[1])\"' | sort"
  [ "$n" = 2 ]
}

declare -A SHA=()
declare -a MOVED=()
declare -A G=() ORIG_AGE=() ORIG_META=()
RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0; MAINT_STARTED=0; SIL=""; TAMPERED=""
put_back() { # put the original generation files back (cp -p from the backup), compare sha256, drop the backup
  local node peer h g a m
  while read -r node peer h; do
    [[ " $TAMPERED " == *" $node "* ]] || continue
    g="${G[$node]}"
    on "$h" "sudo -n cp -p $BKD/gen-$g.age $BKD/gen-$g.meta $ST/store/$peer/" || { echo "  put back $node: cp FAILED"; RESTORE_OK=false; continue; }
    a="$(on "$h" "sudo -n sha256sum $ST/store/$peer/gen-$g.age" | cut -c1-64)"
    m="$(on "$h" "sudo -n sha256sum $ST/store/$peer/gen-$g.meta" | cut -c1-64)"
    if [[ "$a" =~ ^[0-9a-f]{64}$ ]] && [ "$a" = "${ORIG_AGE[$node]}" ] && [ "$m" = "${ORIG_META[$node]}" ]; then
      echo "  $node: gen $g .age + .meta sha256 match the pre-drill copies: yes"
      on "$h" "sudo -n rm -rf $BKD" && echo "  $node: drill backup dir removed"
    else echo "  $node: gen $g sha256 match the pre-drill copies: NO (backup kept)"; RESTORE_OK=false; fi
    TAMPERED="${TAMPERED/ $node/}"
  done <<<"$PAIRS"
}
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha src
  [ -z "${TAMPERED// /}" ] || put_back
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
  if [ "${#MOVED[@]}" -gt 0 ]; then
    # the redirected ntfy env files are declared secrets: an inventory run during the drill exported them as drift
    # (run 18). Re-run the units on the restored files and require drift 0 for both nodes before going on.
    local dw=0 dn=0
    sudo -n systemctl start pft-keyescrow.service; R 'sudo -n systemctl start pft-keyescrow.service'
    sudo -n systemctl start pft-keyescrow-pull.service
    while :; do
      dn="$(pq 'pft_keyescrow_drift_items == 0' | grep -cE 'node=(validator|sentry)(,|$| )')"
      [ "$dn" = 2 ] && break
      dw=$((dw + 10)); [ "$dw" -le 180 ] || break; sleep 10
    done
    echo "  units re-run on the restored env files: pft_keyescrow_drift_items 0 for $dn/2 nodes (${dw}s)"
    [ "$dn" = 2 ] || RESTORE_OK=false
  fi
  if [ -n "$SIL" ]; then
    # the silence only holds unrelated alerts; keep it until no keyescrow alert is left anywhere, then expire it
    local w=0 n=1
    while [ "$w" -le 300 ]; do
      n="$(( $(pq "ALERTS{alertname=\"$KE_ALERT\"}" | grep -c .) + $(curl -s --max-time 10 "$AM/api/v2/alerts" | jq --arg a "$KE_ALERT" '[.[] | select(.labels.alertname == $a)] | length') ))"
      [ "$n" = 0 ] && break
      sleep 10; w=$((w + 10))
    done
    echo "  $KE_ALERT alerts left in Prometheus + Alertmanager: $n (${w}s)"
    [ "$n" = 0 ] || RESTORE_OK=false
    curl -s --max-time 10 -o /dev/null -w "  drill silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-keyescrow tamper drill (one byte, both holders) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)"
  echo "sha256: tamper-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        repo pft-keyescrow.sh $(sha256sum < "$REPO/keyescrow/pft-keyescrow.sh" | cut -c1-64) keyescrow_tar.py $(sha256sum < "$REPO/keyescrow/keyescrow_tar.py" | cut -c1-64)"
  echo "        installed validator $(sudo -n sha256sum "$BIN" | cut -c1-64) $(sudo -n sha256sum /usr/local/lib/pft-keyescrow/keyescrow_tar.py | cut -c1-64)"
  echo "        installed sentry    $(R "sudo -n sha256sum $BIN" | cut -c1-64) $(R 'sudo -n sha256sum /usr/local/lib/pft-keyescrow/keyescrow_tar.py' | cut -c1-64)"
  echo "        keyescrow.rules.yml (repo, loaded by Prometheus) $(sha256sum < "$REPO/alerts/keyescrow.rules.yml" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64) flipbyte.py $(sha256sum < "$HERE/flipbyte.py" | cut -c1-64)"; }

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
for h in local relay; do
  [ -z "$(on "$h" "sudo -n find $ST -maxdepth 1 -name 'drill-backup-*'")" ] || { echo "  leftover drill backup on $h - stopping" >&2; exit 3; }
done
echo "  notifier env files present, no leftovers, no drill backup on either host"
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
nsil="$(curl -s --max-time 10 "$AM/api/v2/silences" | jq --arg a "$KE_ALERT" '[.[] | select(.status.state == "active") | select(any(.matchers[]; .name == "alertname" and .isEqual != false and (if .isRegex then ($a | test("^(" + .value + ")$")) else .value == $a end)))] | length')"
[ "$nsil" = 0 ] || { echo "  $nsil active silence(s) cover $KE_ALERT - stopping" >&2; exit 3; }
echo "  active silences covering $KE_ALERT: 0"
na="$(pq 'ALERTS{alertname=~"PFTKeyEscrow.*"}' | grep -c .)"
[ "$na" = 0 ] || { echo "  $na keyescrow alert(s) already pending/firing - stopping" >&2; exit 3; }
echo "  keyescrow alerts pending/firing: 0"
n1="$(pq 'pft_keyescrow_held_verify_ok == 1' | grep -cE 'node=(validator,peer=sentry|sentry,peer=validator)')"
[ "$n1" = 2 ] || { echo "  pft_keyescrow_held_verify_ok not 1 for both pairs - stopping" >&2; exit 3; }
echo "  pft_keyescrow_held_verify_ok 1 for (validator, sentry) and (sentry, validator)"
nd="$(pq 'pft_keyescrow_drift_items == 0' | grep -cE 'node=(validator|sentry)(,|$| )')"
[ "$nd" = 2 ] || { echo "  pft_keyescrow_drift_items not 0 for both nodes - stopping" >&2; exit 3; }
echo "  pft_keyescrow_drift_items 0 for both nodes"
x "sudo -n $BIN verify --all | tail -1; R 'sudo -n $BIN verify --all' | tail -1"
check "0 verify --all exit 0 on both hosts before the drill" "$(ok_if '[ "$(grep -c "failed -> exit 0$" <<<"$XOUT")" = 2 ]')"
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
# the age recipients are public, but they would link the two hosts: redact them too
for h in local relay; do k="$(on "$h" "sudo -n $BIN pubkey" 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"; done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
while read -r node peer h; do
  G[$node]="$(newest "$h" "$peer")"
  [[ "${G[$node]}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "  no newest generation held on $node for $peer - stopping" >&2; exit 3; }
  ORIG_AGE[$node]="$(on "$h" "sudo -n sha256sum $ST/store/$peer/gen-${G[$node]}.age" | cut -c1-64)"
  ORIG_META[$node]="$(on "$h" "sudo -n sha256sum $ST/store/$peer/gen-${G[$node]}.meta" | cut -c1-64)"
  [[ "${ORIG_AGE[$node]}" =~ ^[0-9a-f]{64}$ && "${ORIG_META[$node]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $node's held gen unreadable - stopping" >&2; exit 3; }
  echo "  $node holds $peer's newest gen ${G[$node]}: .age sha256 ${ORIG_AGE[$node]}, .meta sha256 ${ORIG_META[$node]}"
done <<<"$PAIRS"
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }
if [ "${PREFLIGHT_ONLY:-0}" = 1 ]; then echo; echo "PREFLIGHT_ONLY=1: stopping after step 0, nothing changed ($FAILS check(s) failed)"; exit 0; fi

echo; echo "== 1. redirect notifiers + bridge, silence everything except $KE_ALERT and the watchdog, maintenance window"
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
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "keyescrow tamper drill $RUN: unrelated alerts" --arg x "$KE_ALERT|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "keyescrow-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"$KE_ALERT|$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"
x "sudo -n pft-maint start --ttl $TTL --reason 'pft-keyescrow tamper drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. tamper: flip one byte (XOR 0x01, middle of the file) of the newest held generation on each holder"
FLIP="$HERE/flipbyte.py" # piped to python3 on the holder; prints offset and size only (never byte values)
while read -r node peer h; do
  g="${G[$node]}"; d="$ST/store/$peer"
  echo "-- T$([ "$node" = validator ] && echo 1 || echo 2): $node holds $peer's gen $g"
  on "$h" "sudo -n sh -c 'umask 077; mkdir $BKD && cp -p $d/gen-$g.age $d/gen-$g.meta $BKD/'" || { echo "  backup failed - stopping"; exit 3; }
  TAMPERED+=" $node"
  if [ "$node" = sentry ]; then # T2: also make the meta agree with the tampered ciphertext (only the decrypt can catch it)
    x "on $h 'sudo -n python3 -I - $d/gen-$g.age $d/gen-$g.meta' < $FLIP"
    check "sentry: meta cipher_sha256 now equals the tampered file's sha256" "$(ok_if 'grep -qx "meta cipher_sha256 lines with the tampered file.s sha256: 1" <<<"$XOUT"')"
  else
    x "on $h 'sudo -n python3 -I - $d/gen-$g.age' < $FLIP"
  fi
  x "on $h \"sudo -n cmp -l $BKD/gen-$g.age $d/gen-$g.age | wc -l; sudo -n sha256sum $d/gen-$g.age | cut -c1-64\""
  check "$node: exactly one byte differs from the backup, sha256 changed" "$(ok_if '[ "$(head -1 <<<"$XOUT")" = 1 ] && [ "$(sed -n 2p <<<"$XOUT")" != "${ORIG_AGE[$node]}" ]')"
done <<<"$PAIRS"
run_units
check "2a T1 validator unit: sentry's gen ${G[validator]} ciphertext sha256 MISMATCH, VERIFY FAILED" "$(ok_if 'grep -q "gen ${G[validator]}: ciphertext sha256 MISMATCH" <<<"$UNITLOG" && grep -qx "VERIFY FAILED from=sentry gen=${G[validator]}" <<<"$UNITLOG"')"
check "2b T2 sentry unit: validator's gen ${G[sentry]} VERIFY FAILED with the sha256 check passing (decrypt caught it)" "$(ok_if 'grep -qx "VERIFY FAILED from=validator gen=${G[sentry]}" <<<"$UNITLOG" && ! grep -q "gen ${G[sentry]}: ciphertext sha256 MISMATCH" <<<"$UNITLOG"')"
check "2c pull: both sentry textfiles pulled to the validator" "$(ok_if '[ "$(grep -c "pulled from sentry" <<<"$UNITLOG")" = 2 ]')"
x "sudo -n $BIN verify; echo rc=\$?; R 'sudo -n $BIN verify; echo rc=\$?'"
check "2d manual verify: exit 2 on both hosts, sha256 MISMATCH only for T1" "$(ok_if '[ "$(grep -cx "rc=2" <<<"$XOUT")" = 2 ] && [ "$(grep -c "ciphertext sha256 MISMATCH" <<<"$XOUT")" = 1 ] && grep -qx "VERIFY FAILED from=validator gen=${G[sentry]}" <<<"$XOUT"')"
# restore runs on the host with PEER_SSH (validator) in both directions: --host sentry reseals the validator's held
# copy (T1), --host validator asks the sentry to reseal its held copy (T2)
x "sudo -n $BIN restore --host sentry --dry-run; echo rc=\$?; sudo -n $BIN restore --host validator --dry-run; echo rc=\$?"
check "2e restore --dry-run from each tampered copy refused (reseal refused x2, RESULT: FAIL x2, rc 2 x2)" "$(ok_if '[ "$(grep -c "reseal refused: held generation" <<<"$XOUT")" = 2 ] && [ "$(grep -c "RESULT: FAIL - restore on" <<<"$XOUT")" = 2 ] && [ "$(grep -cx "rc=2" <<<"$XOUT")" = 2 ]')"
wait_metric 0; check "2f Prometheus: pft_keyescrow_held_verify_ok 0 for both pairs" "$?"
t_fire="$(date -u +%s)"
echo "  waiting for $KE_ALERT to fire for both pairs (for: 5m; max ${FIRE_WAIT}s, poll 30s)"
got=0
while [ $(( $(date -u +%s) - t_fire )) -lt "$FIRE_WAIT" ]; do
  F="$(pq "ALERTS{alertstate=\"firing\",alertname=\"$KE_ALERT\"}")"
  got=0
  while read -r node peer h; do grep -qE "node=$node,peer=$peer(,| )" <<<"$F" && got=$((got + 1)); done <<<"$PAIRS"
  [ "$got" -ge 2 ] && break
  sleep 30
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_fire ))s after the metric showed 0):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "2g $KE_ALERT firing for both (node, peer) pairs" "$([ "$got" -ge 2 ] && echo 0 || echo 1)" "$got/2"
check "2h exactly 2 $KE_ALERT firing" "$(ok_if '[ "$(grep -c . <<<"$F")" = 2 ]')"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"; dl=0
  while read -r node peer h; do
    [ "$(jq -r --arg t "[FIRING] $KE_ALERT" 'select(.title == $t) | .message' <<<"$M" | grep -c "of $peer's secrets held on $node")" -ge 1 ] && dl=$((dl + 1))
  done <<<"$PAIRS"
  [ "$dl" -ge 2 ] && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
jq -c '{time: (.time | todate), title, message}' <<<"$M" | red | sed 's/^/    /'
check "2i [FIRING] delivered to the throwaway topic for both pairs" "$([ "$dl" -ge 2 ] && echo 0 || echo 1)" "$dl/2"

echo; echo "== 3. put the original bytes back, re-run the units"
put_back
check "3a both held generations byte-identical to the pre-drill copies, backups removed" "$(ok_if '[ "$RESTORE_OK" = true ] && [ -z "${TAMPERED// /}" ]')"
t_rec="$(date -u +%s)"
run_units
check "3b units: both held generations VERIFIED again" "$(ok_if 'grep -qx "VERIFIED from=sentry gen=${G[validator]} items=[0-9]*" <<<"$UNITLOG" && grep -qx "VERIFIED from=validator gen=${G[sentry]} items=[0-9]*" <<<"$UNITLOG" && ! grep -q "VERIFY FAILED" <<<"$UNITLOG"')"
wait_metric 1; check "3c Prometheus: pft_keyescrow_held_verify_ok 1 for both pairs" "$?"
declare -A RES=()
while :; do
  F="$(pq "ALERTS{alertname=\"$KE_ALERT\"}")"
  M="$(topic_msgs "$ALERT")"
  done_n=0
  while read -r node peer h; do
    r="$(jq -r --arg t "[RESOLVED] $KE_ALERT" 'select(.title == $t) | .message' <<<"$M" | grep -c "of $peer's secrets held on $node")"
    RES["$node/$peer"]="$r"
    if ! grep -qE "node=$node,peer=$peer(,| )" <<<"$F" && [ "$r" -ge 1 ]; then done_n=$((done_n + 1)); fi
  done <<<"$PAIRS"
  [ "$done_n" -ge 2 ] && break
  [ $(( $(date -u +%s) - t_rec )) -lt "$RESOLVE_WAIT" ] || break
  sleep 20
done
echo "  $(ts): $done_n/2 pairs left Prometheus with [RESOLVED] delivered ($(( $(date -u +%s) - t_rec ))s after the bytes were put back)"
for k in "${!RES[@]}"; do echo "    [RESOLVED] $k: ${RES[$k]}"; done | sort
check "3d both pairs left Prometheus and delivered [RESOLVED]" "$([ "$done_n" -ge 2 ] && echo 0 || echo 1)" "$done_n/2"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=\"$KE_ALERT\",alertstate=\"firing\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) node=\(.metric.node) peer=\(.metric.peer) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "3e query_range shows exactly the 2 drill series firing during the drill" "$(ok_if '[ "$(grep -c "samples=" <<<"$XOUT")" = 2 ]')"

echo; echo "== 4. restore, read back"
restore
check "env files byte-identical, bridge on the operator env, window ended, generations restored" \
  "$([ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && echo 0 || echo 1)"
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
check "operator topics received nothing during the drill" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
  check "no drill backup left on $h" "$(ok_if '[ -z "$(on "$h" "sudo -n find $ST -maxdepth 1 -name drill-backup-\*")" ]')"
done
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  s="$(node_state "$h" "$c")"
  check "$c full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
x "sudo -n $BIN verify --all | tail -1; R 'sudo -n $BIN verify --all' | tail -1"
check "verify --all exit 0 on both hosts at the end" "$(ok_if '[ "$(grep -c "failed -> exit 0$" <<<"$XOUT")" = 2 ]')"
echo; echo "tamper-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
