#!/usr/bin/env bash
# sentry-proof: live proof of the guide's continuous health check on the SENTRY only (never the validator).
#   bash sentry-proof.sh EXTRACT_DIR 2>&1 | tee LOG
# Runs on the validator as the agent user and reaches the sentry with `ssh relay` (EXTRACT_DIR = extract_healthcheck.py
# output of the pinned guide commit). The guide's blocks are sent unchanged (install.sh, visibility.sh via `bash -s`);
# the only host-specific input is /etc/default/postfiat-healthcheck with CONTAINER=postfiatd-sentry, the override the
# guide documents for a differently named container.
#  S0 preflight          sentry full, integrity PASS, next integrity run > 10 min away, no sentry alert, not installed
#  S1 silence            Alertmanager silence host="sentry" (SIL_MIN) for the induced FAIL and the new timer
#  S2 install            guide install block; installed files byte-identical to the guide; integrity + schedaudit
#                        accept the intended new files/timer at once; systemd-analyze verify of the installed units
#  S3 run now            guide visibility block (systemctl start + journal); exit 0, RESULT OK
#  S4 timer              wait for RUNS (3) timer-started runs after the install, each RESULT OK and Result=success;
#                        systemctl --failed empty
#  S5 induced FAIL       MIN_PEERS=1000 in the defaults file -> service run fails with only `peers` FAIL, unit listed
#                        by systemctl --failed; the node is never stopped (container start time and state unchanged)
#  S6 recovery           MIN_PEERS removed -> next run OK, systemctl --failed empty again
#  S7 scratch uninstall  the install block with postfiat-healthcheck renamed scratch-healthcheck (+ the guide's alert
#                        drop-in and a defaults file), then the guide's uninstall block with the same rename: every
#                        scratch file and unit gone, the real health check untouched; integrity + schedaudit accept
#  S8 end                node full, integrity PASS, schedaudit 0 unexpected, jobwatch inventory lists the timer
#  S9 silence            expired once nothing for the sentry is active
# Every step prints the command, its output and rc; CHECK lines carry the verdict. Exit 0 = every CHECK ok.
# Env: RELAY (relay)  SENTRY_C (postfiatd-sentry)  AM (http://127.0.0.1:9093)  SIL_MIN (40)  RUNS (3)
#      CLEANUP (0; 1 = run the guide's uninstall at the end, for dry runs)
set -uo pipefail
RELAY="${RELAY:-relay}"; SENTRY_C="${SENTRY_C:-postfiatd-sentry}"; AM="${AM:-http://127.0.0.1:9093}"
SIL_MIN="${SIL_MIN:-40}"; RUNS="${RUNS:-3}"; CLEANUP="${CLEANUP:-0}"
X="${1:-}"
PARTS=(install.sh visibility.sh uninstall.sh alert.conf postfiat-healthcheck postfiat-healthcheck.service
  postfiat-healthcheck.timer)
for f in "${PARTS[@]}"; do [ -f "$X/$f" ] || { echo "usage: bash $0 EXTRACT_DIR (missing $X/$f)" >&2; exit 2; }; done
ts() { date -u +%FT%TZ; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "export TZ=UTC; $*" </dev/null; }
RS() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "export TZ=UTC; $*"; } # with stdin
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
step() { echo; echo "== $(ts) $*"; }
x() { echo "\$ $1"; R "set -o pipefail; $1"; local rc=$?; echo "rc=$rc"; return $rc; }
state() { R "docker exec $SENTRY_C curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
  | jq -r '.result.info | "\(.server_state) peers=\(.peers)"' 2>/dev/null; }
started() { R "docker inspect -f '{{.State.StartedAt}}' $SENTRY_C"; }
prop() { R "systemctl show postfiat-healthcheck.service -p $1 --value"; } # one property per call
failed_list() { R "systemctl --failed --no-legend --plain --no-pager | awk '{print \$1}'"; }
accept() { # integrity first (its scope hook tracks the new files), then schedaudit, then collect
  x "pft-integrity accept --reason '$1' | tail -1" && x "pft-schedaudit accept --reason '$1' | tail -1" \
    && x "pft-schedaudit collect && pft-schedaudit audit | tail -1"
}
runs_ok() { # RESULT OK lines from service runs since $1 (unix time)
  R "journalctl -u postfiat-healthcheck.service --since @$1 -o cat --no-pager | grep -c '^RESULT OK\$'"
}

echo "healthcheck sentry-proof - $(ts)"
echo "sha256: sentry-proof.sh $(sha256sum "$0" | cut -c1-64)"
for f in "${PARTS[@]}"; do echo "        $f $(sha256sum "$X/$f" | cut -c1-64)"; done
echo "host: sentry ($(R 'lsb_release -ds 2>/dev/null; systemctl --version | head -1' | paste -sd' ' -))"

step "S0 preflight"
s="$(state)"; echo "server_state $s"; [[ "$s" == full* ]]; check "S0 sentry node full" $?
START0="$(started)"; echo "container StartedAt $START0"
x "pft-integrity verify | tail -1"; check "S0 sentry integrity PASS before any change" $?
nxt="$(R "systemctl show pft-integrity.timer -p NextElapseUSecRealtime --value")"; echo "integrity timer next: $nxt"
left=$(( $(date -u -d "$nxt" +%s 2>/dev/null || echo 0) - $(date -u +%s) )); echo "seconds until the next integrity run: $left"
[ "$left" -gt 600 ]; check "S0 next pft-integrity run > 10 min away" $?
pend="$(curl -s "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq -r '[.[] | select(.labels.host == "sentry") | .labels.alertname] | join(",")')"
echo "unsilenced active AM alerts for host=sentry: ${pend:-none}"; [ -z "$pend" ]; check "S0 no sentry alert active" $?
ALL='/usr/local/bin/postfiat-healthcheck /etc/systemd/system/postfiat-healthcheck.* /etc/default/postfiat-healthcheck /var/lib/systemd/timers/stamp-postfiat-healthcheck.timer /usr/local/bin/scratch-healthcheck /etc/systemd/system/scratch-healthcheck.* /etc/default/scratch-healthcheck /var/lib/systemd/timers/stamp-scratch-healthcheck.timer'
x "ls -ld $ALL 2>&1 | sed 's/^/  /'"
n="$(R "ls -d $ALL 2>/dev/null | wc -l")"
[ "$n" = 0 ]; check "S0 nothing installed yet (real or scratch, incl. timer stamp files)" $?
if [ "$FAILS" != 0 ]; then echo "RESULT: preflight failed ($FAILS), nothing changed"; exit 1; fi

step "S1 maintenance silence (Alertmanager, host=\"sentry\", ${SIL_MIN}m)"
now="$(date -u +%FT%TZ)"; end="$(date -u -d "+$SIL_MIN min" +%FT%TZ)"
body="$(jq -nc --arg s "$now" --arg e "$end" '{matchers: [{name: "host", value: "sentry", isRegex: false, isEqual: true}],
  startsAt: $s, endsAt: $e, createdBy: "pft-agent", comment: "task_05f47 healthcheck sentry proof (planned, induced FAIL)"}')"
SIL="$(curl -s -XPOST -H 'Content-Type: application/json' -d "$body" "$AM/api/v2/silences" | jq -r '.silenceID // empty')"
echo "silence ${SIL:0:8} until $end"; [ -n "$SIL" ]; check "S1 silence created" $?
[ -n "$SIL" ] || { echo "RESULT: no silence, stopping before any change"; exit 1; }

step "S2 install exactly as the guide says"
x "printf 'CONTAINER=%s\n' $SENTRY_C | tee /etc/default/postfiat-healthcheck"
check "S2 defaults file: CONTAINER override (documented in the guide)" $?
T0="$(R 'date +%s')"; echo "install time $T0 ($(date -u -d "@$T0" +%TZ))"
echo "\$ ssh relay bash -s < install.sh   (guide install block, sha256 $(sha256sum "$X/install.sh" | cut -c1-16))"
RS bash -s < "$X/install.sh"; rc=$?; echo "rc=$rc"; check "S2 guide install block exit 0" "$rc"
accept "task_05f47: postfiat-healthcheck script + service + timer + defaults file from the guide PR"
check "S2 integrity + schedaudit accepted the intended new files and timer" $?
inst="$(R 'sha256sum /usr/local/bin/postfiat-healthcheck /etc/systemd/system/postfiat-healthcheck.service /etc/systemd/system/postfiat-healthcheck.timer' | cut -c1-64 | paste -sd' ' -)"
want="$(sha256sum "$X/postfiat-healthcheck" "$X/postfiat-healthcheck.service" "$X/postfiat-healthcheck.timer" | cut -c1-64 | paste -sd' ' -)"
echo "installed sha256: $inst"; echo "guide     sha256: $want"; [ "$inst" = "$want" ]; check "S2 installed files byte-identical to the guide" $?
x "stat -c '%a %U %n' /usr/local/bin/postfiat-healthcheck"
x "systemctl is-enabled postfiat-healthcheck.timer && systemctl is-active postfiat-healthcheck.timer"
check "S2 timer enabled and active" $?
x "systemd-analyze verify /etc/systemd/system/postfiat-healthcheck.timer /etc/systemd/system/postfiat-healthcheck.service 2>&1 | grep postfiat-healthcheck; test \${PIPESTATUS[0]} = 0"
check "S2 systemd-analyze verify of the installed units: rc 0, no finding" $?
x "systemctl show postfiat-healthcheck.timer -p TimersCalendar -p Persistent -p NextElapseUSecRealtime"

step "S3 run now (guide visibility block, unchanged)"
echo "\$ ssh relay bash -s < visibility.sh"
out="$(RS bash -s < "$X/visibility.sh" 2>&1)"; echo "$out"
grep -qx 'RESULT OK' <<<"$out" && grep -qx 'exit 0' <<<"$out"; check "S3 run now: exit 0, RESULT OK" $?
T3="$(R 'date +%s')"; sleep 1 # S4 counts only runs started by the timer after this point

step "S4 wait for $RUNS timer runs (timer fires every 5 min)"
for _ in $(seq 1 $(( RUNS * 6 + 6 ))); do
  n="$(runs_ok "$T3")"; [ "$n" -ge "$RUNS" ] && break; echo "$(ts) timer runs with RESULT OK so far: $n"; sleep 60
done
x "journalctl -u postfiat-healthcheck.service --since @$T0 -o short-iso --no-pager"
n="$(runs_ok "$T3")"; [ "$n" -ge "$RUNS" ]; check "S4 $RUNS timer runs, each RESULT OK" $? "$n"
x "systemctl show postfiat-healthcheck.timer -p LastTriggerUSec -p NextElapseUSecRealtime"
nfail="$(R "journalctl -u postfiat-healthcheck.service --since @$T0 -o cat --no-pager | grep -c -E '^(RESULT (FAIL|UNKNOWN)|.*Failed with result)'")"
[ "$nfail" = 0 ]; check "S4 no failed run since the install" $? "$nfail"
echo "Result=$(prop Result) ExecMainStatus=$(prop ExecMainStatus) NRestarts=$(prop NRestarts)"
[ "$(prop Result)" = success ]; check "S4 last run Result=success" $?
x "systemctl list-timers postfiat-healthcheck.timer --no-pager"
x "systemctl --failed --no-pager"; fl="$(failed_list)"; [ -z "$fl" ]; check "S4 systemctl --failed empty" $? "${fl:-none}"

step "S5 induced peers-only FAIL with MIN_PEERS (node keeps running)"
s="$(state)"; echo "server_state $s"
x "echo MIN_PEERS=1000 | tee -a /etc/default/postfiat-healthcheck; cat /etc/default/postfiat-healthcheck"
T1="$(R 'date +%s')"
x "systemctl start postfiat-healthcheck.service"; rc=$?; [ "$rc" != 0 ]; check "S5 service run fails (systemctl start rc != 0)" $? "rc=$rc"
x "journalctl -u postfiat-healthcheck.service --since @$T1 -o cat --no-pager"
j="$(R "journalctl -u postfiat-healthcheck.service --since @$T1 -o cat --no-pager")"
grep -q '^CHECK peers FAIL .*(min 1000)$' <<<"$j" && [ "$(grep -c '^CHECK [a-z_]* OK ' <<<"$j")" = 3 ] && grep -qx 'RESULT FAIL 1' <<<"$j"
check "S5 only peers FAIL (3 other checks OK, RESULT FAIL 1)" $?
echo "Result=$(prop Result) ExecMainStatus=$(prop ExecMainStatus)"
[ "$(prop Result)" = exit-code ] && [ "$(prop ExecMainStatus)" = 1 ]; check "S5 Result=exit-code, exit status 1" $?
x "systemctl --failed --no-pager"; fl="$(failed_list)"; grep -qx postfiat-healthcheck.service <<<"$fl"
check "S5 systemctl --failed lists postfiat-healthcheck.service" $?
s="$(state)"; echo "server_state $s"; [[ "$s" == full* ]] && [ "$(started)" = "$START0" ]
check "S5 node not stopped: still full, container StartedAt unchanged" $?

step "S6 clear the override: next run OK"
x "sed -i '/^MIN_PEERS=/d' /etc/default/postfiat-healthcheck; cat /etc/default/postfiat-healthcheck"
T2="$(R 'date +%s')"
x "systemctl start postfiat-healthcheck.service"; check "S6 service run succeeds" $?
x "journalctl -u postfiat-healthcheck.service --since @$T2 -o cat --no-pager"
[ "$(runs_ok "$T2")" = 1 ]; check "S6 RESULT OK after the override is removed" $?
[ "$(prop Result)" = success ]; check "S6 Result=success" $?
x "systemctl --failed --no-pager"; fl="$(failed_list)"; [ -z "$fl" ]; check "S6 systemctl --failed empty again" $? "${fl:-none}"
x "pft-integrity verify | tail -1"; check "S6 integrity PASS (defaults file back to its accepted content)" $?

step "S7 uninstall, exercised on a scratch copy (postfiat-healthcheck -> scratch-healthcheck)"
ren() { sed 's/postfiat-healthcheck/scratch-healthcheck/g' "$1"; }
x "printf 'CONTAINER=%s\n' $SENTRY_C | tee /etc/default/scratch-healthcheck"
echo "\$ ssh relay bash -s < (install.sh renamed)"; ren "$X/install.sh" | RS bash -s; rc=$?; echo "rc=$rc"
check "S7 scratch install exit 0" "$rc"
x "mkdir -p /etc/systemd/system/scratch-healthcheck.service.d && cat > /etc/systemd/system/scratch-healthcheck.service.d/alert.conf <<'EOF'
$(cat "$X/alert.conf")
EOF
systemctl daemon-reload; systemctl show scratch-healthcheck.service -p OnFailure --value"
accept "task_05f47: scratch-healthcheck copy for the uninstall test (removed in the same step)"
x "systemctl start scratch-healthcheck.service && journalctl -u scratch-healthcheck.service -o cat --no-pager | tail -1"
check "S7 scratch copy runs" $?
x "ls -ld /usr/local/bin/scratch-healthcheck /etc/systemd/system/scratch-healthcheck.* /etc/default/scratch-healthcheck /var/lib/systemd/timers/stamp-scratch-healthcheck.timer"
x "systemctl is-active scratch-healthcheck.timer"; check "S7 scratch timer active before uninstall" $?
echo "\$ ssh relay bash -s < (uninstall.sh renamed)"; ren "$X/uninstall.sh" | sed 's/^/  /'
ren "$X/uninstall.sh" | RS bash -s; rc=$?; echo "rc=$rc"; check "S7 guide uninstall block (renamed) exit 0" "$rc"
SCR='/usr/local/bin/scratch-healthcheck /etc/systemd/system/scratch-healthcheck.* /etc/default/scratch-healthcheck /var/lib/systemd/timers/stamp-scratch-healthcheck.timer'
x "ls -ld $SCR 2>&1 | sed 's/^/  /'"
left="$(R "ls -d $SCR 2>/dev/null | wc -l")"
[ "$left" = 0 ]; check "S7 every scratch file removed (incl. the timer stamp)" $? "$left left"
lt="$(R 'systemctl list-units --all --no-legend --plain "scratch-healthcheck*" | wc -l; systemctl list-unit-files --no-legend "scratch-healthcheck*" | wc -l' | paste -sd+ - | bc)"
x "systemctl list-units --all --no-pager 'scratch-healthcheck*'; systemctl list-timers --all --no-pager 'scratch-healthcheck*'"
[ "$lt" = 0 ]; check "S7 no scratch unit or unit file left loaded" $? "$lt"
inst2="$(R 'sha256sum /usr/local/bin/postfiat-healthcheck /etc/systemd/system/postfiat-healthcheck.service /etc/systemd/system/postfiat-healthcheck.timer' | cut -c1-64 | paste -sd' ' -)"
[ "$inst2" = "$want" ] && [ "$(R 'systemctl is-active postfiat-healthcheck.timer')" = active ]
check "S7 real health check untouched (files identical, timer active)" $?
accept "task_05f47: scratch-healthcheck removed by the guide uninstall block"
check "S7 integrity + schedaudit accepted the removal" $?

step "S8 end state"
s="$(state)"; echo "server_state $s"; [[ "$s" == full* ]] && [ "$(started)" = "$START0" ]
check "S8 sentry node full, never restarted" $?
x "pft-integrity verify | tail -1"; check "S8 integrity PASS" $?
x "pft-schedaudit audit | tail -1 | grep -E 'unexpected_findings=0 new=0 removed=0'"; check "S8 schedaudit: 0 unexpected, 0 new, 0 removed" $?
x "pft-jobwatch collect && pft-jobwatch inventory | grep -E '^(job|postfiat-healthcheck.timer)'"
check "S8 jobwatch inventory lists postfiat-healthcheck.timer" $?
x "env TEXT_BUDGET=999999 pft-jobwatch collect --stdout | wc -c"
x "systemctl list-timers postfiat-healthcheck.timer --no-pager"
x "systemctl --failed --no-pager"; fl="$(failed_list)"; [ -z "$fl" ]; check "S8 systemctl --failed empty" $? "${fl:-none}"
if [ "$CLEANUP" = 1 ]; then
  step "S8b dry run cleanup: guide uninstall block on the real install"
  RS bash -s < "$X/uninstall.sh"; echo "rc=$?"
  accept "task_05f47: dry-run cleanup, postfiat-healthcheck removed"
fi

step "S9 end of the maintenance silence"
for _ in $(seq 1 18); do
  p="$(curl -s "$AM/api/v2/alerts?active=true" | jq -r '[.[] | select(.labels.host == "sentry") | .labels.alertname] | join(",")')"
  [ -z "$p" ] && break; echo "sentry alerts still active: $p (wait 20 s)"; sleep 20
done
[ -z "$p" ]; check "S9 nothing active for the sentry before expiry" $?
if [ -z "$p" ]; then curl -s -XDELETE "$AM/api/v2/silence/$SIL" -o /dev/null -w 'expire silence http %{http_code}\n'
else echo "silence kept until its end (something active)"; fi
echo
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed check(s) - $(ts)"
[ "$FAILS" = 0 ]
