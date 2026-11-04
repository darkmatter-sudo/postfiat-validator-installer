#!/usr/bin/env bash
# Offline tests for pft-apparmor.sh: audit grading against fake hosts (stub docker / apparmor_parser / systemctl,
# fake /sys and audit logs under PFT_AA_ROOT), --json and --prom, the audit-log event normalizer, and the profile
# generator (path normalization, masks, capabilities, deny-overlap refusals). With a real apparmor_parser on the
# box, every generated profile is also compiled (-Q -K, nothing loaded). No root, no containers.
# Usage: tests/run-tests.sh [path/to/pft-apparmor.sh]
# Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts (mounts/).
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-apparmor.sh}"
FIX="$HERE/fixtures"
base="${TEST_TMPDIR:-$HOME/.cache}"; mkdir -p "$base"
T="$(mktemp -d "$base/pft-aa-tests.XXXXXX")"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0; NOW=1793600000
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -20; }

# ---- fake host -------------------------------------------------------------------------------------------
# $E/root: fake filesystem; $E/s: stub commands reading $E/state/* (inspect JSON, parser rc, unit state)
mk_env() {
  local e="$1"
  mkdir -p "$e/root/sys/module/apparmor/parameters" "$e/root/sys/kernel/security/apparmor" "$e/root/etc/apparmor.d" \
    "$e/root/var/log/audit" "$e/root/opt/postfiatd" "$e/root/textfile" "$e/s" "$e/state"
  echo Y > "$e/root/sys/module/apparmor/parameters/enabled"
  printf 'docker-default (enforce)\npft-postfiatd (enforce)\n/usr/sbin/chronyd (enforce)\n' > "$e/root/sys/kernel/security/apparmor/profiles"
  printf '#include <tunables/global>\nprofile pft-postfiatd flags=(attach_disconnected) {\n}\n' > "$e/root/etc/apparmor.d/pft-postfiatd"
  printf 'services:\n  postfiatd:\n    security_opt:\n      - "apparmor=pft-postfiatd"\n' > "$e/root/opt/postfiatd/docker-compose.apparmor.yml"
  : > "$e/root/var/log/audit/audit.log"
  cp "$FIX/inspect-ok.json" "$e/state/inspect.json"
  echo 0 > "$e/state/parser_rc"; echo enabled > "$e/state/apparmor_unit"
  cat > "$e/s/docker" <<STUB
#!/usr/bin/env bash
echo "docker \$*" >> "$e/state/calls"
case "\$1" in
  inspect) [ -s "$e/state/inspect.json" ] || { echo "[]"; exit 1; }; cat "$e/state/inspect.json" ;;
  *) exit 0 ;;
esac
STUB
  cat > "$e/s/apparmor_parser" <<STUB
#!/usr/bin/env bash
echo "apparmor_parser \$*" >> "$e/state/calls"
exit "\$(cat "$e/state/parser_rc")"
STUB
  cat > "$e/s/systemctl" <<STUB
#!/usr/bin/env bash
[ "\$1" = is-enabled ] && [ "\$(cat "$e/state/apparmor_unit")" = enabled ] && { echo enabled; exit 0; }
echo disabled; exit 1
STUB
  chmod +x "$e/s/"*
}
fresh() {
  N=$((N + 1)); E="$T/e$N"; mk_env "$E"
  export PFT_AA_ROOT="$E/root" PFT_AA_DOCKER="$E/s/docker" PFT_AA_PARSER="$E/s/apparmor_parser" \
    PFT_AA_SYSTEMCTL="$E/s/systemctl" PFT_AA_NOW="$NOW" TEXTFILE_DIR="$E/root/textfile" CONTAINER=postfiatd
}
run() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
line() { grep -E "^  \[[A-Z]+ *\] $1 " <<<"$OUT"; }
st() { line "$1" | sed -E 's/^ *\[([A-Z]+) *\].*/\1/'; }
expect() { # NAME CHECK STATUS [DETAIL-REGEX]
  local s; s="$(st "$2")"
  if [ "$s" = "$3" ] && { [ -z "${4:-}" ] || line "$2" | grep -qE -- "$4"; }; then ok "$1"; else ko "$1 (want $3${4:+ /$4/}, got '${s}')" "$OUT"; fi
}
inspect_set() { jq "$1" "$E/state/inspect.json" > "$E/state/i.tmp" && mv "$E/state/i.tmp" "$E/state/inspect.json"; }
avc() { # EPOCH STATUS PROFILE OP NAME
  printf 'type=AVC msg=audit(%s.100:1): apparmor="%s" operation="%s" profile="%s" name="%s" pid=7 comm="x" requested_mask="r" denied_mask="r" fsuid=0 ouid=0\n' \
    "$1" "$2" "$4" "$3" "$5" >> "$E/root/var/log/audit/audit.log"
}

# ---- audit -----------------------------------------------------------------------------------------------
fresh; run audit
[ "$RC" = 0 ] && ok "healthy: exit 0" || ko "healthy: exit $RC" "$OUT"
for c in kernel parser loaded container mode boot recreate confine:cap_drop confine:read_only confine:nnp denials; do
  expect "healthy: $c PASS" "$c" PASS
done
grep -q '^RESULT: PASS$' <<<"$OUT" && ok "healthy: RESULT PASS" || ko "healthy: RESULT line" "$OUT"

fresh; echo N > "$E/root/sys/module/apparmor/parameters/enabled"; run audit
[ "$RC" = 1 ] && expect "kernel disabled: FAIL" kernel FAIL "enabled='N'" || ko "kernel disabled: exit $RC" "$OUT"
fresh; rm "$E/root/sys/module/apparmor/parameters/enabled"; run audit
expect "kernel param missing: FAIL" kernel FAIL "missing"

fresh; PFT_AA_PARSER="$E/s/nope" run audit
expect "parser missing: FAIL" parser FAIL "not found"

fresh; inspect_set '.[0].AppArmorProfile = "docker-default"'; run audit
expect "docker-default: container FAIL" container FAIL "docker-default"
expect "docker-default: mode not graded" mode INFO "not graded"
[ "$RC" = 1 ] && ok "docker-default: exit 1" || ko "docker-default: exit $RC" "$OUT"
fresh; inspect_set '.[0].AppArmorProfile = "unconfined"'; run audit
expect "unconfined: container FAIL" container FAIL "unconfined"
fresh; inspect_set '.[0].AppArmorProfile = ""'; run audit
expect "empty profile: container FAIL" container FAIL "unconfined"
fresh; inspect_set '.[0].AppArmorProfile = "pft-other"'; run audit
expect "other profile: container FAIL" container FAIL "pft-other"

fresh; sed -i 's/^pft-postfiatd (enforce)/pft-postfiatd (complain)/' "$E/root/sys/kernel/security/apparmor/profiles"; run audit
expect "complain: loaded PASS (mode shown)" loaded PASS "complain"
expect "complain: mode WARN" mode WARN "blocks nothing"
[ "$RC" = 1 ] && ok "complain: exit 1" || ko "complain: exit $RC" "$OUT"
fresh; sed -i '/^pft-postfiatd /d' "$E/root/sys/kernel/security/apparmor/profiles"; run audit
expect "not loaded: loaded FAIL" loaded FAIL "not loaded"
expect "not loaded: mode FAIL" mode FAIL "unknown"
fresh; chmod 000 "$E/root/sys/kernel/security/apparmor/profiles"; run audit
if [ "$(id -u)" = 0 ]; then ok "profiles unreadable: skipped (root reads anything)"; else expect "profiles unreadable: loaded FAIL" loaded FAIL "unreadable"; fi

fresh; rm "$E/root/etc/apparmor.d/pft-postfiatd"; run audit
expect "no profile file: boot FAIL" boot FAIL "missing"
fresh; printf 'profile pft-postfiatdX {\n}\n' > "$E/root/etc/apparmor.d/pft-postfiatd"; run audit
expect "file defines another name: boot FAIL" boot FAIL "does not define"
fresh; echo 1 > "$E/state/parser_rc"; run audit
expect "file does not parse: boot FAIL" boot FAIL "does not parse"
fresh; echo disabled > "$E/state/apparmor_unit"; run audit
expect "apparmor.service disabled: boot FAIL" boot FAIL "not enabled"

fresh; inspect_set '.[0].Config.Labels["com.docker.compose.project.config_files"] = "/opt/postfiatd/docker-compose.yml"'; run audit
expect "compose without override: recreate FAIL" recreate FAIL "drops it"
fresh; printf 'services:\n  postfiatd:\n    security_opt:\n      - apparmor:pft-postfiatd\n' > "$E/root/opt/postfiatd/docker-compose.apparmor.yml"; run audit
expect "compose override, colon form: recreate PASS" recreate PASS
fresh; inspect_set 'del(.[0].Config.Labels["com.docker.compose.project.config_files"])'; run audit
expect "docker run container under profile: recreate PASS" recreate PASS "HostConfig"
fresh; inspect_set 'del(.[0].Config.Labels["com.docker.compose.project.config_files"]) | .[0].AppArmorProfile = "docker-default"'; run audit
expect "docker run container not under profile: recreate FAIL" recreate FAIL

fresh; inspect_set '.[0].HostConfig.CapDrop = []'; run audit
expect "cap_drop lost: FAIL" confine:cap_drop FAIL
fresh; inspect_set '.[0].HostConfig.CapDrop = ["all"]'; run audit
expect "cap_drop lowercase all: PASS" confine:cap_drop PASS
fresh; inspect_set '.[0].HostConfig.ReadonlyRootfs = false'; run audit
expect "read-only lost: FAIL" confine:read_only FAIL
fresh; inspect_set '.[0].HostConfig.SecurityOpt = ["apparmor=pft-postfiatd"]'; run audit
expect "nnp lost: FAIL" confine:nnp FAIL
fresh; inspect_set '.[0].HostConfig.SecurityOpt = ["no-new-privileges"]'; run audit
expect "nnp short form: PASS" confine:nnp PASS
fresh; inspect_set '.[0].HostConfig.SecurityOpt = ["no-new-privileges:false"]'; run audit
expect "nnp :false: FAIL" confine:nnp FAIL

fresh; : > "$E/state/inspect.json"; run audit
expect "container missing: FAIL" container FAIL "not found"

# denials: window, profile match, child profiles, other profiles, ALLOWED lines
fresh
avc $((NOW - 100)) DENIED pft-postfiatd open /usr/bin/x
avc $((NOW - 50)) DENIED pft-postfiatd open /usr/bin/x
avc $((NOW - 40)) DENIED pft-postfiatd exec /tmp/t
avc $((NOW - 90000)) DENIED pft-postfiatd open /old
avc $((NOW - 10)) DENIED pft-postfiatdX open /other-profile
avc $((NOW - 10)) DENIED docker-default open /docker-default
avc $((NOW - 10)) ALLOWED pft-postfiatd open /allowed
run audit
expect "denials: WARN with count 3" denials WARN "^  \[WARN\] denials +3 DENIED"
line denials | grep -q 'open /usr/bin/x x2; exec /tmp/t x1' && ok "denials: top pairs, most frequent first" || ko "denials: top pairs" "$(line denials)"
[ "$RC" = 1 ] && ok "denials: exit 1" || ko "denials: exit $RC" "$OUT"
run audit --since 45
expect "denials --since 45: only the last one" denials WARN "1 DENIED"
fresh; avc $((NOW - 10)) DENIED pft-postfiatd//null-/bin/x open /child; run audit
expect "denials: child profile counted" denials WARN "1 DENIED"
fresh; cp "$E/root/var/log/audit/audit.log" "$E/root/var/log/audit/audit.log.1"
avc $((NOW - 10)) DENIED pft-postfiatd open /rotated; cp "$E/root/var/log/audit/audit.log" "$E/root/var/log/audit/audit.log.1"; : > "$E/root/var/log/audit/audit.log"
run audit
expect "denials: rotated audit.log.1 read" denials WARN "1 DENIED"
fresh; rm "$E/root/var/log/audit/audit.log"; run audit
expect "no audit log: denials FAIL" denials FAIL "no readable audit log"

# --json / --prom
fresh; inspect_set '.[0].AppArmorProfile = "docker-default"'; avc $((NOW - 5)) DENIED pft-postfiatd open /x
run audit --json --prom "$E/root/textfile/a.prom"
j="$OUT"
jq -e '.findings == 2 and .denied_events == 1 and .profile == "pft-postfiatd" and .host == "validator"' <<<"$j" >/dev/null \
  && ok "--json: findings/denied/profile/host" || ko "--json: top fields" "$j"
jq -e '[.checks[] | select(.check == "container")][0] | .status == "FAIL" and (.detail | test("docker-default"))' <<<"$j" >/dev/null \
  && ok "--json: container check object" || ko "--json: container check" "$j"
jq -e '[.checks[] | select(.check == "mode")][0].status == "INFO"' <<<"$j" >/dev/null && ok "--json: INFO kept" || ko "--json: INFO" "$j"
P="$E/root/textfile/a.prom"
grep -qx 'pft_apparmor_findings{host="validator"} 2' "$P" && ok "--prom: findings" || ko "--prom: findings" "$(cat "$P")"
grep -qx 'pft_apparmor_denied_events{host="validator"} 1' "$P" && ok "--prom: denied_events" || ko "--prom: denied" "$(cat "$P")"
grep -qx 'pft_apparmor_check{host="validator",check="container",status="FAIL"} 0' "$P" && ok "--prom: failing check = 0" || ko "--prom: container" "$(cat "$P")"
grep -qx 'pft_apparmor_check{host="validator",check="kernel",status="PASS"} 1' "$P" && ok "--prom: passing check = 1" || ko "--prom: kernel" "$(cat "$P")"
grep -q 'check="mode"' "$P" && ko "--prom: INFO line exported" "$(cat "$P")" || ok "--prom: INFO not exported"
grep -qx "pft_apparmor_last_run_timestamp_seconds{host=\"validator\"} $NOW" "$P" && ok "--prom: last_run" || ko "--prom: last_run" "$(cat "$P")"
[ "$(stat -c %a "$P")" = 644 ] && ok "--prom: mode 0644" || ko "--prom: mode $(stat -c %a "$P")"
compgen -G "$E/root/textfile/a.prom.*" >/dev/null && ko "--prom: temp file left" || ok "--prom: no temp file left"
fresh; printf 'HOST_LABEL=sentry\n' > "$E/root/etc/pft-apparmor.env"; run audit --textfile
[ -f "$E/root/textfile/pft_apparmor_sentry.prom" ] && ok "--textfile: HOST_LABEL from env file" || ko "--textfile: file" "$(ls "$E/root/textfile")"
fresh; printf 'PROFILE=Bad Name\n' > "$E/root/etc/pft-apparmor.env"; run audit
[ "$RC" = 2 ] && ok "bad PROFILE in env file: exit 2" || ko "bad PROFILE: exit $RC" "$OUT"
fresh; run audit --bogus
[ "$RC" = 3 ] && ok "unknown option: exit 3" || ko "unknown option: exit $RC" "$OUT"
fresh; run audit --since abc
[ "$RC" = 3 ] && ok "--since non-numeric: exit 3" || ko "--since abc: exit $RC" "$OUT"

# ---- events (normalizer) ---------------------------------------------------------------------------------
fresh; cp "$FIX/audit-learn.log" "$E/root/var/log/audit/audit.log"
run events --since-epoch 1793603390 --profile pft-aa-learn
EV="$OUT"
grep -qx $'file\t/etc/passwd\tr' <<<"$EV" && ok "events: file line" || ko "events: file line" "$EV"
grep -qx $'exec\t/usr/sbin/cron\tx' <<<"$EV" && ok "events: exec line" || ko "events: exec line" "$EV"
grep -qx $'cap\tsetgid\t-' <<<"$EV" && ok "events: capability line" || ko "events: cap line" "$EV"
grep -qx $'net\tinet stream\t-' <<<"$EV" && ok "events: socket family line" || ko "events: net line" "$EV"
grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<<"$EV" && ko "events: an IP address leaked" "$EV" || ok "events: no IP address in output"
grep -q '/before-t0' <<<"$EV" && ko "events: line before T0 kept" "$EV" || ok "events: lines before T0 dropped"
grep -q '/other-profile' <<<"$EV" && ko "events: other profile kept" "$EV" || ok "events: other profiles dropped"
grep -q $'file\t/denied-in-learn' <<<"$EV" && ok "events: DENIED lines of the profile kept" || ko "events: DENIED kept" "$EV"
[ "$(sort -u <<<"$EV" | wc -l)" = "$(wc -l <<<"$EV")" ] && ok "events: unique lines" || ko "events: duplicates" "$EV"
grep -q 'type=SYSCALL\|EXECVE' <<<"$EV" && ko "events: non-AVC record kept" "$EV" || ok "events: non-AVC records dropped"
fresh; rm "$E/root/var/log/audit/audit.log"; run events
[ "$RC" = 2 ] && ok "events: no audit log -> exit 2" || ko "events: exit $RC" "$OUT"

# ---- generate --------------------------------------------------------------------------------------------
fresh
gen() { OUT="$(bash "$TOOL" generate "$@" 2>&1)"; RC=$?; }
has() { grep -qxF -- "  $1" <<<"$OUT" && ok "generate: '$1'" || ko "generate: missing '$1'" "$OUT"; }
hasnt() { grep -qF -- "$1" <<<"$OUT" && ko "generate: unexpected '$1'" "$(grep -F -- "$1" <<<"$OUT")" || ok "generate: no '$1'"; }
gen --events "$FIX/events.tsv" --caps "CAP_SETGID CAP_SETUID"
[ "$RC" = 0 ] && ok "generate: exit 0" || ko "generate: exit $RC" "$OUT"
grep -q '^profile pft-postfiatd flags=(attach_disconnected,mediate_deleted) {$' <<<"$OUT" && ok "generate: profile header" || ko "generate: header" "$OUT"
has "/var/lib/postfiatd/db/{,**} rwk,"
has "/var/log/postfiatd/{,**} rwk,"
has "/etc/postfiatd/{,**} r,"
has "@{PROC}/@{pid}/stat r,"
has "@{PROC}/@{pid}/task/@{tid}/comm r,"
has "@{PROC}/sys/kernel/pid_max r,"
has "/usr/sbin/cron ix,"
has "/usr/bin/savelog rix,"
has "capability setgid,"
has "capability setuid,"
has "capability chown,"
has "/etc/shadow r,"
has "audit deny /etc/gshadow rwklx,"
has "audit deny /tmp/** x,"
has "audit deny ptrace (trace,tracedby),"
has "ptrace (read,readby) peer=pft-postfiatd,  # ps reads the other processes' /proc entries"
has "audit deny network inet raw,"
has "network netlink raw,"
has "/usr/bin/logger ix,"
hasnt "audit deny network raw,"
has "deny @{PROC}/sysrq-trigger rwklx,"
hasnt "/var/lib/postfiatd/db/nudb"
hasnt "/usr/bin/savelog r,"
hasnt "/proc/1"
has "deny /etc/cron.daily/apt-compat x,"
has "deny /usr/lib/apt/apt.systemd.daily x,"
hasnt "audit deny /etc/cron.daily/apt-compat"
has "/ r,"
[ "$(grep -n '^  deny /etc/cron.daily/apt-compat x,$' <<<"$OUT" | cut -d: -f1)" -lt "$(grep -n 'pft-apparmor explicit denials' <<<"$OUT" | cut -d: -f1)" ] \
  && ok "generate: quiet denials come before the logged block" || ko "generate: quiet deny placement" "$OUT"
[ "$(grep -c '^  capability setgid,$' <<<"$OUT")" = 1 ] && ok "generate: learned + --caps capability not duplicated" || ko "generate: dup capability" "$OUT"
gen --events "$FIX/events.tsv" --name pft-test
grep -q '^profile pft-test ' <<<"$OUT" && grep -qxF '  signal (send,receive) peer=pft-test,' <<<"$OUT" && ok "generate --name: header + signal peer" || ko "generate --name" "$OUT"
grep -qxF '  capability setuid,' <<<"$OUT" && ko "generate: setuid without --caps (not learned)" "$OUT" || ok "generate: no unlearned capability without --caps"
cp "$FIX/events.tsv" "$T/ev-bad1.tsv"; printf 'file\t/etc/gshadow\tr\n' >> "$T/ev-bad1.tsv"
gen --events "$T/ev-bad1.tsv"
[ "$RC" = 4 ] && grep -q "overlaps audit deny '/etc/gshadow rwklx'" <<<"$OUT" && ok "generate: refuses learned read of gshadow (exit 4)" || ko "generate: gshadow overlap rc=$RC" "$OUT"
cp "$FIX/events.tsv" "$T/ev-bad2.tsv"; printf 'exec\t/tmp/dropper\tx\n' >> "$T/ev-bad2.tsv"
gen --events "$T/ev-bad2.tsv"
[ "$RC" = 4 ] && grep -q "learned exec '/tmp/{,\*\*}' overlaps audit deny '/tmp/\*\* x'" <<<"$OUT" && ok "generate: refuses learned exec from /tmp (exit 4)" || ko "generate: /tmp exec overlap rc=$RC" "$OUT"
cp "$FIX/events.tsv" "$T/ev-bad3.tsv"; printf 'file\t/usr/lib/x/y.so\trw\n' >> "$T/ev-bad3.tsv"
gen --events "$T/ev-bad3.tsv"
[ "$RC" = 4 ] && grep -q "overlaps audit deny '/usr/\*\* wl'" <<<"$OUT" && ok "generate: refuses learned write under /usr (exit 4)" || ko "generate: /usr write overlap rc=$RC" "$OUT"
cp "$FIX/events.tsv" "$T/ev-ok4.tsv"; printf 'file\t/usr/lib/x/y.so\trm\n' >> "$T/ev-ok4.tsv"
gen --events "$T/ev-ok4.tsv"
[ "$RC" = 0 ] && grep -qxF '  /usr/lib/x/y.so rm,' <<<"$OUT" && ok "generate: read+mmap under /usr allowed" || ko "generate: /usr rm rc=$RC" "$OUT"
cp "$FIX/events.tsv" "$T/ev-bad5.tsv"; printf 'bogus\t/x\tr\n' >> "$T/ev-bad5.tsv"
gen --events "$T/ev-bad5.tsv"
[ "$RC" = 2 ] && ok "generate: unknown event kind -> exit 2" || ko "generate: bogus kind rc=$RC" "$OUT"
gen --events "$T/missing.tsv"
[ "$RC" = 2 ] && ok "generate: missing events file -> exit 2" || ko "generate: missing file rc=$RC" "$OUT"
gen
[ "$RC" = 3 ] && ok "generate: no --events -> exit 3" || ko "generate: usage rc=$RC" "$OUT"
printf 'file\t/var/log/postfiatd/debug.log\twac\nfile\t/var/log/postfiatd/x\tdk\n' > "$T/ev-mask.tsv"
EXTRA_EXEC="" gen --events "$T/ev-mask.tsv"
grep -q logger <<<"$OUT" && ko "generate: EXTRA_EXEC='' still adds logger" "$OUT" || ok "generate: EXTRA_EXEC empty adds nothing"
QUIET_DENY_EXEC="" EXTRA_FILE="" gen --events "$T/ev-mask.tsv"
grep -qF 'quiet denials' <<<"$OUT" && ko "generate: QUIET_DENY_EXEC='' still writes the quiet block" "$OUT" || ok "generate: QUIET_DENY_EXEC empty adds no quiet block"
grep -qxF '  / r,' <<<"$OUT" && ko "generate: EXTRA_FILE='' still adds / r" "$OUT" || ok "generate: EXTRA_FILE empty adds nothing"
EXTRA_FILE="/etc/foo" gen --events "$T/ev-mask.tsv"
[ "$RC" = 2 ] && ok "generate: EXTRA_FILE without :MASK -> exit 2" || ko "generate: bad EXTRA_FILE rc=$RC" "$OUT"
EXTRA_FILE="/etc/gshadow:r" gen --events "$T/ev-mask.tsv"
[ "$RC" = 4 ] && ok "generate: EXTRA_FILE overlapping an audit deny -> exit 4" || ko "generate: EXTRA_FILE overlap rc=$RC" "$OUT"
QUIET_DENY_EXEC="relative/x" gen --events "$T/ev-mask.tsv"
[ "$RC" = 2 ] && ok "generate: relative QUIET_DENY_EXEC -> exit 2" || ko "generate: bad QUIET_DENY_EXEC rc=$RC" "$OUT"
printf 'extra\t/usr/bin/flock\tx\n' >> "$T/ev-mask.tsv"
gen --events "$T/ev-mask.tsv"
has "/var/log/postfiatd/{,**} wk,"
has "/usr/bin/flock ix,"
printf 'file\t/var/cache/pft-c\tc\nfile\t/var/cache/pft-d\td\nfile\t/var/cache/pft-a\ta\n' > "$T/ev-acd.tsv"
gen --events "$T/ev-acd.tsv"
has "/var/cache/pft-c w,"
has "/var/cache/pft-d w,"
has "/var/cache/pft-a w,"

# ---- real parser: the generated profiles compile ---------------------------------------------------------
if command -v apparmor_parser >/dev/null 2>&1 && [ -r "$FIX/events-explore.tsv" ]; then
  for f in "$FIX/events.tsv" "$FIX/events-explore.tsv"; do
    bash "$TOOL" generate --events "$f" --caps "CAP_SETGID CAP_SETUID" > "$T/p.profile" 2>&1
    o="$(apparmor_parser -Q -K "$T/p.profile" 2>&1)" && ok "apparmor_parser -Q -K: profile from $(basename "$f") compiles" \
      || ko "apparmor_parser: $(basename "$f")" "$o"
  done
  printf 'profile x {\n  /etc/passwd rr ,\n' > "$T/bad.profile"
  apparmor_parser -Q -K "$T/bad.profile" >/dev/null 2>&1 && ko "apparmor_parser: broken profile accepted" || ok "apparmor_parser: broken profile rejected (control)"
  PFT_AA_PARSER=apparmor_parser run check "$T/bad.profile"
  [ "$RC" != 0 ] && ok "check: non-zero on a broken profile" || ko "check: rc 0 on broken" "$OUT"
  PFT_AA_PARSER=apparmor_parser run check "$T/p.profile"
  [ "$RC" = 0 ] && ok "check: zero on a generated profile" || ko "check: rc $RC" "$OUT"
else
  echo "skip apparmor_parser compile tests (no apparmor_parser or fixture)"
fi

# ---- apply / rollback ------------------------------------------------------------------------------------
# shellcheck source=SCRIPTDIR/apply-tests.inc.sh
. "$HERE/apply-tests.inc.sh"

# ---- validate / pull / install.sh -----------------------------------------------------------------------
# shellcheck source=SCRIPTDIR/pull-install-tests.inc.sh
. "$HERE/pull-install-tests.inc.sh"

# ---- ack-denials -----------------------------------------------------------------------------------------
# shellcheck source=SCRIPTDIR/ack-tests.inc.sh
. "$HERE/ack-tests.inc.sh"

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
