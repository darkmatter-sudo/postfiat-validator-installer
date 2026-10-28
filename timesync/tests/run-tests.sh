#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2001
# Offline tests for pft-timesync.sh: every audit state (PASS/WARN/CRIT per check, exit 0/1/2, --json), boot-gate,
# metrics, plan, apply (policy-rc.d blocks the package start, chronyd -p validation, sync gate), the automatic
# byte-identical rollback for every gate miss, refusals and manual rollback. No root, no network, no chrony.
# Usage: tests/run-tests.sh [path/to/pft-timesync.sh]
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-timesync.sh}"
# shellcheck source=tests/stubs.sh
. "$HERE/stubs.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | tail -15; }
fresh() { N=$((N + 1)); E="$T/e$N"; mk_env "$E"; use_env "$E"; }
run() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
expect() { # NAME RC REGEX
  if [ "$RC" = "$2" ] && grep -qE -- "$3" <<<"$OUT"; then ok "$1"; else ko "$1 (rc=$RC want $2, /$3/)" "$OUT"; fi
}
check() { # NAME CONDITION (evaluated in a subshell)
  if (eval "$2") >/dev/null 2>&1; then ok "$1"; else ko "$1" "$OUT"; fi
}
csvset() { # FILE ROW FIELD VALUE  (edit one field of one row of a stub CSV)
  awk -F, -v OFS=, -v r="$2" -v f="$3" -v v="$4" 'NR==r{$f=v}1' "$STUB_S/$1" > "$STUB_S/x" && mv "$STUB_S/x" "$STUB_S/$1"
}

# --- audit: chrony host with the tool's own config (good)
fresh; chrony_host; run audit; expect "audit good chrony host -> OK exit 0" 0 '^RESULT: OK \(daemon chrony\) -> exit 0$'
check "good host has no WARN/CRIT lines" '! grep -qE "^\[(WARN|CRIT)" <<<"$OUT"'
check "good host counts 5 NTS sources" 'grep -qE "^\[PASS\] nts +5 NTS-authenticated" <<<"$OUT"'
check "good host: offset sign (chrony 'slow' = clock behind -> negative)" 'grep -qE "^\[PASS\] offset +system clock -0.000680615 s" <<<"$OUT"'
check "good host: makestep boot-only" 'grep -qE "^\[PASS\] makestep +steps only within 300 s of boot" <<<"$OUT"'
run audit --json
check "--json good host" '[ "$RC" = 0 ] && jq -e ".result==\"OK\" and .exit==0 and .daemon==\"chrony\" and (.checks|length)==12 and ([.checks[]|select(.state==\"WARN\" or .state==\"CRIT\")]|length)==0" <<<"$OUT"'

# --- audit: one bad fixture per check (NAME | RC | setup | expected line regex)
while IFS='|' read -r name want setup re; do
  [ -z "$name" ] && continue
  fresh; chrony_host; eval "$setup"; run audit
  expect "audit $name -> rc $want" "$want" "$re"
  run audit --json
  check "audit --json $name -> exit $want" '[ "$RC" = '"$want"' ] && jq -e ".exit=='"$want"'" <<<"$OUT"'
done <<'CASES'
no daemon|2|: > "$STUB_S/active"|^\[CRIT\] daemon +no time daemon active
conflicting daemons|2|echo systemd-timesyncd >> "$STUB_S/active"|^\[CRIT\] conflicting-daemons +chrony systemd-timesyncd active together
chronyd not answering|2|touch "$STUB_S/chronyd_down"|^\[CRIT\] chronyd +chronyc gets no answer
only 3 NTS (2 sources without NTS)|1|csvset authdata 1 2 -; csvset authdata 2 2 -|^\[WARN\] nts +3 NTS-authenticated reachable sources \(< 4\)
NTS-KE not done (KLen 0)|1|csvset authdata 1 5 0; csvset authdata 3 5 0|^\[WARN\] nts +3 NTS
NTS source unreachable (reach 0)|1|csvset sources 1 6 0; csvset sources 2 6 0|^\[WARN\] nts +3 NTS
fewer sources than minsources|1|head -2 "$STUB_S/sources" > x; mv x "$STUB_S/sources"; csvset sources 2 2 '*'|^\[WARN\] sources +2 configured \(< 3\)
no selected source|2|sed -i 's/^\^,\*,/^,+,/' "$STUB_S/sources"|^\[CRIT\] selected +no source selected
offset 0.1 s|1|csvset tracking 1 5 0.100000000|^\[WARN\] offset +system clock -0.100000000 s from NTP time \(> 0.05\)
offset -0.3 s (fast)|2|csvset tracking 1 5 -0.300000000|^\[CRIT\] offset +system clock 0.300000000 s .*\(> 0.25\)
root dispersion 0.2 s|1|csvset tracking 1 12 0.2|^\[WARN\] root-dispersion +0.2 s \(> 0.1\)
root dispersion 2 s|2|csvset tracking 1 12 2.0|^\[CRIT\] root-dispersion +2.0 s \(> 1.0\)
stratum 8|1|csvset tracking 1 3 8|^\[WARN\] stratum +8 \(> 6\)
stratum 16|2|csvset tracking 1 3 16|^\[CRIT\] stratum +16 \(unsynchronised\)
leap insert pending|1|csvset tracking 1 14 'Insert second'|^\[WARN\] leap +Insert second pending
leap not synchronised|2|csvset tracking 1 14 'Not synchronised'|^\[CRIT\] leap +Not synchronised
makestep in chrony.conf|1|echo 'makestep 1 3' >> "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf"|^\[WARN\] makestep +chrony.conf allows clock steps after start
makestep commented out is not a step|0|echo '# makestep 1 3' >> "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf"|^\[PASS\] makestep
no boot-gate drop-in, no makestep|0|rm "$PFT_TIMESYNC_ROOT/etc/systemd/system/chrony.service.d/50-pft-timesync.conf"|^\[PASS\] makestep +never steps
maxslewrate unset|1|sed -i '/^maxslewrate/d' "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf"|^\[WARN\] slew-bound +maxslewrate unset
maxslewrate 5000|1|sed -i 's/^maxslewrate .*/maxslewrate 5000/' "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf"|^\[WARN\] slew-bound +maxslewrate 5000 ppm
RTC in local time|1|echo yes > "$STUB_S/localrtc"|^\[WARN\] rtc +RTC in local time
timesyncd host (before migration)|1|echo systemd-timesyncd > "$STUB_S/active"|^RESULT: WARN \(daemon systemd-timesyncd\) -> exit 1
timesyncd unsynchronised|2|echo systemd-timesyncd > "$STUB_S/active"; echo no > "$STUB_S/synced"|^\[CRIT\] selected +NTPSynchronized=no
timesyncd dispersion 150ms|1|echo systemd-timesyncd > "$STUB_S/active"; sed -i 's/RootDispersion=686us/RootDispersion=150ms/' "$STUB_S/tsd_msg"|^\[WARN\] root-dispersion +0.150000000 s
timesyncd leap 3|2|echo systemd-timesyncd > "$STUB_S/active"; sed -i 's/Leap=0/Leap=3/' "$STUB_S/tsd_msg"|^\[CRIT\] leap +Not synchronised
CASES
fresh; run audit
check "timesyncd host: nts WARN + offset INFO + 1 source WARN" 'grep -qE "^\[WARN\] nts +0 NTS" <<<"$OUT" && grep -qE "^\[INFO\] offset" <<<"$OUT" && grep -qE "^\[WARN\] sources +1 in use" <<<"$OUT"'

# --- boot-gate
fresh; echo '120.5 100.0' > "$PFT_TIMESYNC_ROOT/proc/uptime"; run boot-gate
check "boot-gate within window writes makestep 1.0 3" 'grep -qx "makestep 1.0 3" "$PFT_TIMESYNC_ROOT/etc/chrony/conf.d/pft-boot-makestep.conf"'
echo '301.0 100.0' > "$PFT_TIMESYNC_ROOT/proc/uptime"; run boot-gate
check "boot-gate after window removes it" '[ ! -e "$PFT_TIMESYNC_ROOT/etc/chrony/conf.d/pft-boot-makestep.conf" ] && grep -q "no makestep" <<<"$OUT"'

# --- metrics
fresh; chrony_host; mkdir -p "$PFT_TIMESYNC_ROOT/var/lib/pft-exporter/textfile"; run metrics
P="$PFT_TIMESYNC_ROOT/var/lib/pft-exporter/textfile/pft_timesync.prom"
check "metrics: state 0, offset, nts 5, synced 1, timestamp" 'grep -qx "pft_timesync_state 0" "$P" && grep -qx "pft_timesync_offset_seconds -0.000680615" "$P" && grep -qx "pft_timesync_nts_sources 5" "$P" && grep -qx "pft_timesync_synced 1" "$P" && grep -qE "^pft_timesync_collect_timestamp_seconds [0-9]{10}$" "$P"'
check "metrics: per-check gauges + no temp file left" 'grep -qx "pft_timesync_check{check=\"nts\"} 0" "$P" && [ -z "$(find "$(dirname "$P")" -name ".pft_timesync.*")" ]'
sed -i 's/^\^,\*,/^,+,/' "$STUB_S/sources"; csvset tracking 1 14 'Not synchronised'; run metrics
check "metrics: unsynced -> state 2, synced 0, check selected 2" 'grep -qx "pft_timesync_state 2" "$P" && grep -qx "pft_timesync_synced 0" "$P" && grep -qx "pft_timesync_check{check=\"selected\"} 2" "$P"'
fresh; mkdir -p "$PFT_TIMESYNC_ROOT/var/lib/pft-exporter/textfile"; run metrics
P="$PFT_TIMESYNC_ROOT/var/lib/pft-exporter/textfile/pft_timesync.prom"
check "metrics on timesyncd: daemon label, no offset series, synced 1" 'grep -qx "pft_timesync_daemon{daemon=\"systemd-timesyncd\"} 1" "$P" && ! grep -q "^pft_timesync_offset_seconds" "$P" && grep -qx "pft_timesync_synced 1" "$P"'

# --- plan
fresh; run plan
check "plan: >= 4 NTS servers, minsources, maxslewrate, no active makestep" '[ "$(grep -cE "^server [^ ]+ iburst nts$" <<<"$OUT")" -ge 4 ] && grep -qx "minsources 3" <<<"$OUT" && grep -qx "maxslewrate 500" <<<"$OUT" && ! grep -qE "^makestep" <<<"$OUT" && grep -qx "cmdport 0" <<<"$OUT"'
check "plan: drop-in runs boot-gate outside the sandbox" 'grep -qx "ExecStartPre=+/usr/local/sbin/pft-timesync boot-gate" <<<"$OUT"'
PFT_TIMESYNC_INJECT=unreachable run plan
check "plan with injection: TEST-NET-1 only" '[ "$(grep -c "^server 192\.0\.2\." <<<"$OUT")" = 5 ] && ! grep -q cloudflare <<<"$OUT"'

# --- apply: refusals (nothing changed)
fresh; H0="$(sha256sum "$PFT_TIMESYNC_ROOT/etc/systemd/timesyncd.conf")"
run apply; expect "apply without --yes -> refused 4" 4 're-run with --yes'
touch "$PFT_TIMESYNC_ROOT/usr/sbin/policy-rc.d"; run apply --yes; expect "apply with an existing policy-rc.d -> refused 4" 4 'policy-rc.d exists'
rm "$PFT_TIMESYNC_ROOT/usr/sbin/policy-rc.d"
MIN_NTS=6 run apply --yes; expect "apply with fewer servers than MIN_NTS -> refused 4" 4 'only 5 NTS_SERVERS'
touch "$STUB_S/download_fail"; run apply --yes; expect "apply: timesyncd .deb not cacheable -> refused 4" 4 'cannot cache systemd-timesyncd'
check "refusals changed nothing (no stop/install, timesyncd active, file identical)" '! grep -qE "systemctl stop|install -y -q -o" "$STUB_S/calls" && grep -qx systemd-timesyncd "$STUB_S/active" && [ "$(sha256sum "$PFT_TIMESYNC_ROOT/etc/systemd/timesyncd.conf")" = "$H0" ]'
CONTAINER=nope run apply --yes; expect "apply: unknown container -> refused 4" 4 'cannot read nope StartedAt'

# --- apply: happy path from timesyncd
fresh; run apply --yes; expect "apply from timesyncd -> PASS exit 0" 0 'apply: PASS$'
check "apply: sync gate PASS line names 5 NTS sources + StartedAt unchanged" 'grep -qE "sync gate: PASS after [0-9]+ s \(selected ntppool1.time.nl, 5 NTS sources, offset -0.000680615 s, leap Normal; postfiatd StartedAt unchanged, server_state full\)" <<<"$OUT"'
check "apply: chrony package start was blocked by policy-rc.d, which is gone afterwards" 'grep -qx blocked "$STUB_S/policy_at_install" && [ ! -e "$PFT_TIMESYNC_ROOT/usr/sbin/policy-rc.d" ]'
check "apply: timesyncd stopped BEFORE the install" '[ "$(grep -n "systemctl stop systemd-timesyncd" "$STUB_S/calls" | cut -d: -f1)" -lt "$(grep -n "install -y -q -o" "$STUB_S/calls" | cut -d: -f1)" ]'
check "apply: chrony.conf = plan, drop-in written, chronyd -p ran first" 'diff <(bash "$TOOL" plan | sed -n "/^# \/etc\/chrony\/chrony.conf$/,/^# \/etc\/systemd\/system/p" | sed "1d;\$d") "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf" && grep -q boot-gate "$PFT_TIMESYNC_ROOT/etc/systemd/system/chrony.service.d/50-pft-timesync.conf" && grep -q "chronyd -p -f .*chrony.conf.pft-new" "$STUB_S/calls"'
check "apply: only chrony active, timesyncd .deb cached in the backup" '[ "$(cat "$STUB_S/active")" = chrony ] && ls "$PFT_TIMESYNC_ROOT"/var/lib/pft-timesync/*/systemd-timesyncd_249.11-0ubuntu3.23_amd64.deb'
check "apply: after-audit OK" 'grep -qE "^  RESULT: OK \(daemon chrony\)" <<<"$OUT"'
run apply --yes; expect "apply again -> idempotent, nothing changed" 0 'already applied'
check "idempotent apply did not reinstall or restart" '[ "$(grep -c "restart chrony" "$STUB_S/calls")" = 1 ]'
# manual rollback after a good apply
run rollback; expect "rollback without --yes -> refused 4" 4 're-run with --yes'
run rollback --yes; expect "manual rollback -> PASS" 0 'rollback: PASS'
check "manual rollback: timesyncd.conf byte-identical, chrony files absent, timesyncd back" 'grep -qE "restore .*timesyncd.conf: sha256 [0-9a-f]{64} byte-identical" <<<"$OUT" && [ ! -e "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf" ] && [ ! -e "$PFT_TIMESYNC_ROOT/etc/systemd/system/chrony.service.d/50-pft-timesync.conf" ] && [ "$(cat "$STUB_S/active")" = systemd-timesyncd ] && grep -qx "systemd-timesyncd 249.11-0ubuntu3.23" "$STUB_S/pkgs" && ! grep -q "^chrony " "$STUB_S/pkgs"'

# --- apply: automatic rollback on every gate miss
while IFS='|' read -r name setup re; do
  [ -z "$name" ] && continue
  fresh; H0="$(sha256sum < "$PFT_TIMESYNC_ROOT/etc/systemd/timesyncd.conf")"; eval "$setup"
  run apply --yes; expect "apply $name -> automatic rollback exit 1" 1 "$re"
  check "$name: rollback PASS, file byte-identical, timesyncd back, chrony purged" 'grep -q "rollback: PASS" <<<"$OUT" && [ "$(sha256sum < "$PFT_TIMESYNC_ROOT/etc/systemd/timesyncd.conf")" = "$H0" ] && [ "$(cat "$STUB_S/active")" = systemd-timesyncd ] && ! grep -q "^chrony " "$STUB_S/pkgs" && [ ! -e "$PFT_TIMESYNC_ROOT/etc/chrony/chrony.conf" ] && [ ! -e "$PFT_TIMESYNC_ROOT/usr/sbin/policy-rc.d" ]'
done <<'MISS'
unreachable sources (injected)|export PFT_TIMESYNC_INJECT=unreachable|sync gate: FAIL after [0-9]+ s \(selected= nts=0 .*leap=Not synchronised.*injected=unreachable\)
chronyd -p rejects the config|touch "$STUB_S/chronyd_reject"|chronyd -p rejects the candidate
apt install fails|touch "$STUB_S/install_fail"|apt-get install chrony failed
postfiatd restarted during the gate|echo 'echo 2026-10-28T21:00:00Z > "$S/started"' > "$STUB_S/restart_hook"|StartedAt CHANGED
server_state not full|echo syncing > "$STUB_S/state"|server_state=syncing
only 3 NTS sources authenticate|echo 'sed "1,2s/,NTS,/,-,/" <<<"$GOOD_AUTH" > "$S/authdata"' > "$STUB_S/restart_hook"|sync gate: FAIL .*nts=3
offset above OFFSET_WARN|echo 'sed -i "s/,0.000680615,/,0.080000000,/" "$S/tracking"' > "$STUB_S/restart_hook"|sync gate: FAIL .*offset=-0.080000000
MISS
unset PFT_TIMESYNC_INJECT
fresh; PFT_TIMESYNC_INJECT=unreachable run apply --yes
check "injected rollback prints the restore lines (absent + byte-identical)" 'grep -qE "restore .*/etc/chrony/chrony.conf: absent as before" <<<"$OUT" && grep -qE "restore .*/etc/systemd/timesyncd.conf: sha256 [0-9a-f]{64} byte-identical" <<<"$OUT" && grep -q "packages: chrony=none (before none), systemd-timesyncd=249.11-0ubuntu3.23 (before 249.11-0ubuntu3.23)" <<<"$OUT"'
check "injected rollback: postfiatd StartedAt unchanged, full" 'grep -q "postfiatd StartedAt 2026-10-28T11:33:11.2Z (unchanged), server_state full" <<<"$OUT"'
fresh; touch "$STUB_S/dpkg_fail"; PFT_TIMESYNC_INJECT=unreachable run apply --yes; expect "rollback that cannot reinstall timesyncd -> exit 5" 5 'rollback: FAIL'
check "failed rollback names the mismatch" 'grep -q "systemd-timesyncd=none (before 249.11-0ubuntu3.23)" <<<"$OUT"'
fresh; run apply --yes >/dev/null; printf 'tampered\n' >> "$PFT_TIMESYNC_ROOT/var/lib/pft-timesync/"*/f1; run rollback --yes
expect "rollback whose backup copy differs from the recorded sha -> exit 5" 5 'timesyncd.conf: sha256 [0-9a-f]{64} != [0-9a-f]{64} -> MISMATCH'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
