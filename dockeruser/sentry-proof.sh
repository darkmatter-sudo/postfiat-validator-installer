#!/usr/bin/env bash
# sentry-proof: live proof of the guide's DOCKER-USER persistence change on the SENTRY only (never the validator).
#   bash sentry-proof.sh pre  EXTRACT_DIR 2>&1 | tee LOG    install from the guide, lose rules, detect, restore, idempotency
#   bash sentry-proof.sh post EXTRACT_DIR BOOT_ID_BEFORE 2>&1 | tee LOG    after the reboot: rules back, check exit 0, node full
# Runs on the validator as the agent user and reaches the sentry with `ssh relay` (EXTRACT_DIR = extract_dockeruser.py
# output of the pinned guide commit). The guide's own blocks are sent unchanged: install.sh and check.sh via `bash -s`.
# pre: an Alertmanager silence scoped to host="sentry" (SIL_MIN minutes) covers the whole sequence and is expired at
#      the end once nothing for the sentry is pending; pft-integrity on the sentry accepts the two changed files right
#      after the install (refused when the hourly integrity run is less than 10 minutes away).
# Every step prints the command, its output and rc; CHECK lines carry the verdict. Exit 0 = every CHECK ok.
# Env: RELAY (relay)  SENTRY_C (postfiatd-sentry)  AM (http://127.0.0.1:9093)  SIL_MIN (20)
set -uo pipefail
RELAY="${RELAY:-relay}"; SENTRY_C="${SENTRY_C:-postfiatd-sentry}"; AM="${AM:-http://127.0.0.1:9093}"
SIL_MIN="${SIL_MIN:-20}"
MODE="${1:-}"; X="${2:-}"
[ "$MODE" = pre ] || [ "$MODE" = post ] || { echo "usage: bash $0 pre|post EXTRACT_DIR [BOOT_ID_BEFORE]" >&2; exit 2; }
for f in install.sh check.sh postfiat-docker-user.sh postfiat-docker-user.service; do
  [ -f "$X/$f" ] || { echo "missing $X/$f" >&2; exit 2; }
done
ts() { date -u +%FT%TZ; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@" </dev/null; }
RS() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; } # with stdin (scripts)
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
step() { echo; echo "== $(ts) $*"; }
x() { echo "\$ $1"; R "set -o pipefail; $1"; local rc=$?; echo "rc=$rc"; return $rc; } # remote command string (pipefail: rc of the tool, not of tail)
state() { R "docker exec $SENTRY_C curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
  | jq -r '.result.info | "\(.server_state) peers=\(.peers) complete_ledgers=\(.complete_ledgers)"' 2>/dev/null; }
rules() { R "iptables -w -S DOCKER-USER"; }
run_check() { # the guide's check block, unchanged -> sets CK_RC, CK_OUT
  echo "\$ ssh relay bash -s < check.sh   (guide check block, sha256 $(sha256sum "$X/check.sh" | cut -c1-16))"
  CK_OUT="$(RS bash -s < "$X/check.sh" 2>&1)"; CK_RC=$?; echo "$CK_OUT"; echo "rc=$CK_RC"
}
count2559() { rules | grep -c -e '--dport 2559 '; }

echo "dockeruser sentry-proof $MODE - $(ts)"
echo "sha256: sentry-proof.sh $(sha256sum "$0" | cut -c1-64)"
for f in install.sh check.sh postfiat-docker-user.sh postfiat-docker-user.service; do
  echo "        $f $(sha256sum "$X/$f" | cut -c1-64)"
done
echo "host: sentry ($(R 'lsb_release -ds 2>/dev/null; uname -r' | paste -sd' ' -)) | $(R 'iptables --version')"

if [ "$MODE" = pre ]; then
  step "P0 preflight"
  boot="$(R 'cat /proc/sys/kernel/random/boot_id')"; echo "boot_id ${boot:0:8}"
  s="$(state)"; echo "server_state $s"; [[ "$s" == full* ]]; check "P0 sentry node full" $?
  x "pft-integrity verify | tail -1"; check "P0 sentry integrity PASS before any change" $?
  nxt="$(R "systemctl show pft-integrity.timer -p NextElapseUSecRealtime --value")"; echo "integrity timer next: $nxt"
  left=$(( $(date -u -d "$nxt" +%s 2>/dev/null || echo 0) - $(date -u +%s) )); echo "seconds until the next integrity run: $left"
  [ "$left" -gt 600 ]; check "P0 next pft-integrity run > 10 min away" $?
  pend="$(curl -s "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq -r '[.[] | select(.labels.host == "sentry") | .labels.alertname] | join(",")')"
  echo "unsilenced active AM alerts for host=sentry: ${pend:-none}"; [ -z "$pend" ]; check "P0 no sentry alert active" $?
  if [ "$FAILS" != 0 ]; then echo "RESULT: preflight failed ($FAILS), nothing changed"; exit 1; fi

  step "P1 maintenance silence (Alertmanager, host=\"sentry\", ${SIL_MIN}m)"
  now="$(date -u +%FT%TZ)"; end="$(date -u -d "+$SIL_MIN min" +%FT%TZ)"
  body="$(jq -nc --arg s "$now" --arg e "$end" '{matchers: [{name: "host", value: "sentry", isRegex: false, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "pft-agent", comment: "task_27cde dockeruser sentry proof (planned)"}')"
  SIL="$(curl -s -XPOST -H 'Content-Type: application/json' -d "$body" "$AM/api/v2/silences" | jq -r '.silenceID // empty')"
  echo "silence ${SIL:0:8} until $end"; [ -n "$SIL" ]; check "P1 silence created" $?
  [ -n "$SIL" ] || { echo "RESULT: no silence, stopping before any change"; exit 1; }

  step "P2 before: installed files and DOCKER-USER"
  x "sha256sum /usr/local/sbin/postfiat-docker-user.sh /etc/systemd/system/postfiat-docker-user.service"
  x "systemctl is-enabled postfiat-docker-user.service; systemctl is-active postfiat-docker-user.service"
  x "iptables -w -S DOCKER-USER"

  step "P3 install exactly as the guide says (install block, unchanged)"
  echo "\$ ssh relay bash -s < install.sh"
  RS bash -s < "$X/install.sh"; rc=$?; echo "rc=$rc"; check "P3 guide install block exit 0" "$rc"
  x "pft-integrity accept --reason 'task_27cde: postfiat-docker-user.sh + unit from the guide PR' | tail -2"
  check "P3 integrity baseline accepted for the two intended changes" $?
  inst="$(R 'sha256sum /usr/local/sbin/postfiat-docker-user.sh /etc/systemd/system/postfiat-docker-user.service' | cut -c1-64 | paste -sd' ' -)"
  want="$(sha256sum "$X/postfiat-docker-user.sh" "$X/postfiat-docker-user.service" | cut -c1-64 | paste -sd' ' -)"
  echo "installed sha256: $inst"; echo "guide     sha256: $want"; [ "$inst" = "$want" ]; check "P3 installed files byte-identical to the guide" $?
  x "systemctl is-enabled postfiat-docker-user.service"; check "P3 unit enabled" $?

  step "P4 rules present: guide check must exit 0"
  x "iptables -w -S DOCKER-USER"
  run_check; [ "$CK_RC" = 0 ] && [[ "$CK_OUT" == OK:* ]]; check "P4 check exit 0 with rules present" $?

  step "P5 lose the rules: stop the unit, flush the TCP 2559 rules and RETURN (other DOCKER-USER rules on this host stay)"
  x "systemctl stop postfiat-docker-user.service"
  x "for n in \$(iptables -w -S DOCKER-USER | awk 'NR > 1 && (/--dport 2559 / || \$0 == \"-A DOCKER-USER -j RETURN\") { print NR - 1 }' | sort -rn); do iptables -w -D DOCKER-USER \$n || exit 1; done"
  check "P5 flush" $?
  x "iptables -w -S DOCKER-USER"; n="$(count2559)"; echo "TCP 2559 rules now: $n"; [ "$n" = 0 ]; check "P5 no TCP 2559 rule left" $?
  run_check; [ "$CK_RC" = 1 ] && [[ "$CK_OUT" == "FAIL: TCP 2559 rules missing"* ]]; check "P5 check detects the loss: exit 1" $?

  step "P6 unit start restores the rules"
  x "systemctl start postfiat-docker-user.service"; check "P6 unit start" $?
  x "systemctl show postfiat-docker-user.service -p ActiveState -p SubState -p Result -p ExecMainStatus"
  x "iptables -w -S DOCKER-USER"
  run_check; [ "$CK_RC" = 0 ]; check "P6 check exit 0 after unit start" $?

  step "P7 idempotency: two more runs, rule count and chain unchanged"
  c0="$(rules | wc -l)"; h0="$(rules | sha256sum | cut -c1-16)"; echo "run 0: lines=$c0 sha=$h0"
  for i in 1 2; do
    x "systemctl restart postfiat-docker-user.service"; check "P7 restart $i" $?
    c="$(rules | wc -l)"; h="$(rules | sha256sum | cut -c1-16)"; echo "run $i: lines=$c sha=$h"
    [ "$c" = "$c0" ] && [ "$h" = "$h0" ]; check "P7 run $i: rule count and chain unchanged" $?
  done
  run_check; [ "$CK_RC" = 0 ]; check "P7 check exit 0 after the idempotent runs" $?

  step "P8 node and egress policy after the sequence"
  s="$(state)"; echo "server_state $s"; [[ "$s" == full* ]]; check "P8 sentry node full" $?
  x "pft-egress check --container $SENTRY_C | tail -1"; check "P8 pft-egress check (jump kept at DOCKER-USER 1)" $?
  x "pft-integrity verify | tail -1"; check "P8 integrity PASS" $?

  step "P9 end of the maintenance silence"
  for i in $(seq 1 12); do
    p="$(curl -s "$AM/api/v2/alerts?active=true" | jq -r '[.[] | select(.labels.host == "sentry") | .labels.alertname] | join(",")')"
    [ -z "$p" ] && break; echo "sentry alerts still active: $p (wait 10 s)"; sleep 10
  done
  [ -z "$p" ]; check "P9 nothing active for the sentry before expiry" $?
  if [ -z "$p" ]; then curl -s -XDELETE "$AM/api/v2/silence/$SIL" -o /dev/null -w 'expire silence http %{http_code}\n'
  else echo "silence kept until its end (something active)"; fi
  echo "boot_id_before ${boot}"
else
  BOOT0="${3:-}"; [ -n "$BOOT0" ] || { echo "post needs BOOT_ID_BEFORE" >&2; exit 2; }
  step "Q1 the sentry rebooted"
  boot="$(R 'cat /proc/sys/kernel/random/boot_id')"; echo "boot_id before ${BOOT0:0:8} now ${boot:0:8}"
  [ -n "$boot" ] && [ "$boot" != "$BOOT0" ]; check "Q1 new boot id" $?
  x "uptime -s; systemctl show postfiat-docker-user.service -p ActiveState -p SubState -p Result -p ExecMainStatus -p ActiveEnterTimestamp"
  x "journalctl --utc -b -u postfiat-docker-user.service -o short-iso --no-pager | tail -5"
  act="$(R 'systemctl show postfiat-docker-user.service -p ActiveState -p Result --value' | paste -sd' ' -)"
  [ "$act" = "active success" ]; check "Q1 unit ran at boot: active, Result success" $?
  x "systemctl show -p After postfiat-docker-user.service --value | tr ' ' '\\n' | grep -x docker.service"
  check "Q1 unit ordered After=docker.service" $?

  step "Q2 rules persisted across the reboot"
  x "iptables -w -S DOCKER-USER"; n="$(count2559)"; echo "TCP 2559 rules: $n"; [ "$n" = 4 ]; check "Q2 four TCP 2559 rules present" $?
  last="$(rules | tail -1)"; [ "$last" = "-A DOCKER-USER -j RETURN" ]; check "Q2 RETURN last" $?
  run_check; [ "$CK_RC" = 0 ] && [[ "$CK_OUT" == OK:* ]]; check "Q2 guide check exit 0 after the reboot" $?

  step "Q3 node state"
  for i in $(seq 1 30); do s="$(state)"; [[ "$s" == full* ]] && break; sleep 10; done
  echo "server_state $s"; [[ "$s" == full* ]]; check "Q3 sentry server_state full" $?
  x "pft-egress check --container $SENTRY_C | tail -1"; check "Q3 pft-egress check" $?
  x "pft-integrity verify | tail -1"; check "Q3 integrity PASS" $?
fi
echo
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed check(s) - $(ts)"
[ "$FAILS" = 0 ]
