#!/usr/bin/env bash
# nightly-run: read-only proof of one unattended nightly escrow (pft-keyescrow-escrow.timer, 02:40 UTC + up to 10 min
# random delay, validator). Started BEFORE the timer fires, it records what both hosts hold, waits for the timer to
# trigger the service and for the service to finish, then checks the run from the service's own journal and from both
# hosts' state. It changes nothing: no window, no silence, no notifier redirect, no restart.
#   0  before: timer schedule, last escrow time, newest held generation on each side, verify --all on both
#   1  wait: timer LastTriggerUSec moves past the start of this script and the service is no longer active (timeout)
#   2  the run: unit Result/ExecMainStatus, its journal since the trigger (sudo: lesson 196), both directions VERIFIED
#   3  after: newer generation held on each side and verified, last escrow time moved, inventory exit 0 on both,
#      metrics pulled, Prometheus series + no PFTKeyEscrow* alert firing
#   4  zero-leak check on both hosts (state dir, textfile dir, and this run's raw log on the validator)
#   bash keyescrow/drill/nightly-run.sh > LOG 2>&1   (agent user, from the repo root; uses sudo -n, `ssh relay`)
# Env: RELAY (relay) PROM WAIT_MAX (3600, s) LOG (path of this run's raw log, scanned by the leak check)
# Exit 0 = every CHECK ok.
# shellcheck disable=SC2016,SC2034,SC1091  # ok_if conditions are single-quoted on purpose (evaluated later, so
# the rc variables are used there); /etc/os-release is read at run time
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REDACT="${REDACT:-$REPO/peerexpose/drill/redact.py}"
RELAY="${RELAY:-relay}"; PROM="${PROM:-http://127.0.0.1:9090}"; WAIT_MAX="${WAIT_MAX:-3600}"; LOG="${LOG:-}"
BIN=/usr/local/bin/pft-keyescrow
ST=/var/lib/pft-keyescrow
TF=/var/lib/pft-exporter/textfile
SVC=pft-keyescrow-escrow.service
TMR=pft-keyescrow-escrow.timer
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d "${TEST_TMPDIR:-$HOME/.cache}/kenightly.XXXXXX")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"
printf 'user\t%s\n' "$(id -un)" > "$LIT"; chmod 600 "$LIT"
trap 'rm -rf "$SEC"' EXIT
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
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
# journal without the hostname field: short-iso-precise is "TIME HOST UNIT[PID]: MSG"
jn() { cut -d' ' -f1,3-; }
newest_gen() { sed -n 's/^ *VERIFIED from=[a-z]* gen=\([0-9TZ]*\) .*/\1/p' | sort | tail -1; }
gen_epoch() { date -u -d "$(sed -E 's/^(....)(..)(..)T(..)(..)(..)Z$/\1-\2-\3 \4:\5:\6/' <<<"$1")" +%s 2>/dev/null || echo 0; }

since="$(date -u +%s)"
echo "pft-keyescrow nightly-run - $(ts)"
echo "OS: $(. /etc/os-release && echo "$PRETTY_NAME") | sentry OS: $(R '. /etc/os-release && echo "$PRETTY_NAME"')"
echo "repo HEAD: $(git -C "$REPO" rev-parse HEAD)"
echo "script sha256: $(sha256sum "$0" | cut -c1-64)  keyescrow/drill/nightly-run.sh"
echo "installed tool sha256: validator $(sha256sum "$BIN" | cut -c1-64), sentry $(R "sha256sum $BIN" | cut -c1-64)"

echo "== 0. before ($(ts))"
x "cat '$REPO/keyescrow/systemd/$TMR'"
x "TZ=UTC systemctl list-timers --all $TMR --no-pager | head -2"
x "TZ=UTC systemctl show $TMR -p LastTriggerUSec -p NextElapseUSecRealtime"
x "TZ=UTC systemctl show $SVC -p Result -p ExecMainStatus -p ActiveState"
x "grep -h '^pft_keyescrow_last_escrow_timestamp_seconds' $TF/pft_keyescrow.prom"
LAST0="$(awk '{print $2}' <<<"$XOUT")"
x "sudo -n $BIN verify --all | grep -E '^ *(VERIFIED|RESULT)'"
VG0="$(newest_gen <<<"$XOUT")"; VRC0=$XRC
x "R 'sudo -n $BIN verify --all' | grep -E '^ *(VERIFIED|RESULT)'"
SG0="$(newest_gen <<<"$XOUT")"; SRC0=$XRC
check "before: both holders verify --all exit 0" "$(ok_if '[ "$VRC0" = 0 ] && [ "$SRC0" = 0 ]')" "validator holds sentry newest $VG0, sentry holds validator newest $SG0"

echo "== 1. wait for the timer ($(ts), up to ${WAIT_MAX} s)"
waited=0; trig=0; state=""
while [ "$waited" -lt "$WAIT_MAX" ]; do
  lt="$(systemctl show $TMR -p LastTriggerUSec --value)"
  trig="$(date -u -d "$lt" +%s 2>/dev/null || echo 0)"
  state="$(systemctl show $SVC -p ActiveState --value)"
  if [ "$trig" -ge "$since" ] && [ "$state" != activating ] && [ "$state" != active ] && [ "$state" != deactivating ]; then break; fi
  sleep 15; waited=$((waited + 15))
done
if [ "$trig" -ge "$since" ]; then how="timer triggered at $(date -u -d "@$trig" +%FT%TZ)"; else how="TIMEOUT"; fi
echo "wait loop exited after ${waited} s: $how, service state $state ($(ts))"
check "timer triggered the service after this script started and the service finished" "$(ok_if '[ "$trig" -ge "$since" ] && [ "$state" = inactive ]')" "$how, $state"

echo "== 2. the run ($(ts))"
x "TZ=UTC systemctl show $SVC -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp"
check "service Result=success ExecMainStatus=0" "$(ok_if 'grep -qx "Result=success" <<<"$XOUT" && grep -qx "ExecMainStatus=0" <<<"$XOUT"')"
x "sudo -n journalctl -u $SVC --since @$((trig - 1)) --utc -o short-iso-precise --no-pager | jn"
J="$XOUT"
check "journal: triggered by the timer (systemd Starting line) and Finished" "$(ok_if 'grep -q "Starting pft-keyescrow nightly escrow" <<<"$J" && grep -q "Finished pft-keyescrow nightly escrow" <<<"$J"')"
check "journal: validator generation VERIFIED by the sentry" "$(ok_if 'grep -q "VERIFIED from=validator gen=" <<<"$J"')"
check "journal: sentry generation VERIFIED here" "$(ok_if 'grep -q "VERIFIED from=sentry gen=" <<<"$J"')"
check "journal: RESULT PASS both directions" "$(ok_if 'grep -q "RESULT: PASS - both directions sealed, held and verified" <<<"$J"')"
check "journal: no age identity printed" "$(ok_if '! grep -q "AGE-SECRET-KEY" <<<"$J"')" "$(grep -c AGE-SECRET-KEY <<<"$J") matches; control: $(sudo -n grep -c AGE-SECRET-KEY $ST/age.key) in the identity file"

echo "== 3. after ($(ts))"
x "sudo -n $BIN verify --all | grep -E '^ *(VERIFIED|RESULT)'"
VG1="$(newest_gen <<<"$XOUT")"; VRC1=$XRC
x "R 'sudo -n $BIN verify --all' | grep -E '^ *(VERIFIED|RESULT)'"
SG1="$(newest_gen <<<"$XOUT")"; SRC1=$XRC
check "validator holds a newer sentry generation from tonight, all verified" "$(ok_if '[ "$VRC1" = 0 ] && [[ "$VG1" > "$VG0" ]] && [ "$(gen_epoch "$VG1")" -ge "$((trig - 5))" ]')" "$VG0 -> $VG1"
check "sentry holds a newer validator generation from tonight, all verified" "$(ok_if '[ "$SRC1" = 0 ] && [[ "$SG1" > "$SG0" ]] && [ "$(gen_epoch "$SG1")" -ge "$((trig - 5))" ]')" "$SG0 -> $SG1"
x "grep -h '^pft_keyescrow_last_escrow_timestamp_seconds' $TF/pft_keyescrow.prom"
LAST1="$(awk '{print $2}' <<<"$XOUT")"
check "last escrow time moved to tonight's run" "$(ok_if '[ "${LAST1:-0}" -gt "${LAST0:-0}" ] && [ "${LAST1:-0}" -ge "$trig" ]')" "$LAST0 -> $LAST1"
x "sudo -n $BIN inventory | tail -1; R 'sudo -n $BIN inventory' | tail -1"
check "inventory on both: exit 0 (no drift, nothing new)" "$(ok_if '[ "$(grep -c -- "-> exit 0" <<<"$XOUT")" = 2 ]')"
x "grep -h '^pft_keyescrow_held_[a-z_]*{' $TF/pft_keyescrow_held.prom $TF/pft_keyescrow_held_sentry.prom"
check "held metrics: verify_ok 1 on both sides" "$(ok_if '[ "$(grep -c "^pft_keyescrow_held_verify_ok{.*} 1$" <<<"$XOUT")" = 2 ]')"
x "curl -fsS --max-time 20 '$PROM/api/v1/query' --data-urlencode 'query=pft_keyescrow_last_escrow_timestamp_seconds' | jq -r '.data.result[] | .metric.node + \" \" + .value[1]'"
x "curl -fsS --max-time 20 '$PROM/api/v1/alerts' | jq -r '[.data.alerts[] | select(.labels.alertname | startswith(\"PFTKeyEscrow\"))] | length'"
check "no PFTKeyEscrow* alert pending or firing" "$(ok_if '[ "$XOUT" = 0 ]')"

echo "== 4. zero-leak check ($(ts))"
TREE="/var/tmp/pft-keyescrow-nightly-$(git -C "$REPO" rev-parse --short HEAD)"
x "R 'mkdir -p $TREE' && scp -q -o LogLevel=ERROR '$HERE/leakcheck.py' '$RELAY:$TREE/leakcheck.py' && echo copied"
SCANLOG=""; [ -n "$LOG" ] && [ -f "$LOG" ] && SCANLOG="--scan $LOG"
x "sudo -n python3 -I '$HERE/leakcheck.py' --tool $BIN --conf /etc/pft-keyescrow.env --host validator --scan $ST --scan $TF $SCANLOG"
check "validator: every secret probed, 0 leaks${SCANLOG:+ (incl. the raw log of this run)}" "$(ok_if '[ "$XRC" = 0 ]')"
x "R 'sudo -n python3 -I $TREE/leakcheck.py --tool $BIN --conf /etc/pft-keyescrow.env --host sentry --scan $ST --scan $TF'"
check "sentry: every secret probed, 0 leaks" "$(ok_if '[ "$XRC" = 0 ]')"
x "R 'rm -rf $TREE' && echo removed"

echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed check(s) - $(ts)"
[ "$FAILS" = 0 ]
