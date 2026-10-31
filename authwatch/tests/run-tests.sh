#!/usr/bin/env bash
# Offline tests for pft-authwatch.sh + authwatch_parse.py: stub journalctl/ssh/ssh-keygen, fixture journal entries
# captured on the validator and the sentry (redacted by tests/make_fixtures.py), no root, nothing on the host is
# read or changed.
#   bash authwatch/tests/run-tests.sh [SCRIPT [PARSER]]   (defaults ../pft-authwatch.sh ../authwatch_parse.py)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; inv0/PULLENV/e_lu/t0 are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-authwatch.sh}"
P="${2:-$HERE/../authwatch_parse.py}"
FXV="$HERE/fixtures/journal-validator.jsonl"
FXS="$HERE/fixtures/journal-sentry.jsonl"
T="$(mktemp -d)" || exit 1
[ -d "$T" ] || exit 1
trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }   # NAME CONDITION (subshell: an exit in it is a FAIL)
has()   { grep -qxF -- "$2" "$1"; }                              # FILE LINE (exact)
val()   { awk -v k="$2" 'index($0, k " ") == 1 { print $NF; f = 1 } END { if (!f) print "MISSING" }' "$1"; }

# stub journalctl: serves $T/journal.jsonl. --after-cursor C prints the lines after the one whose __CURSOR is C;
# -n N prints the last N; exit 1 + stderr if $T/jfail exists; records its args in $T/jargs
mkdir -p "$T/bin" "$T/tf" "$T/st" "$T/etc"
cat > "$T/bin/journalctl" <<STUB
#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
open("$T/jargs", "w").write(" ".join(a) + "\n")
if os.path.exists("$T/jhang"):
    import time; time.sleep(30)
if os.path.exists("$T/jfail"):
    print("Failed to open journal: Permission denied", file=sys.stderr); sys.exit(1)
lines = open("$T/journal.jsonl").read().splitlines() if os.path.exists("$T/journal.jsonl") else []
if "--after-cursor" in a:
    c = a[a.index("--after-cursor") + 1]
    i = next((k for k, l in enumerate(lines) if json.loads(l).get("__CURSOR") == c), None)
    lines = lines[i + 1:] if i is not None else lines
if "-n" in a:
    n = int(a[a.index("-n") + 1]); lines = lines[-n:] if n else []
for l in lines:
    print(l)
STUB
# stub ssh-keygen -lf FILE: one "256 FP comment (ED25519)" line per non-comment line of FILE whose 2nd field is the
# fingerprint to report (test files hold "ssh-ed25519 SHA256:..." lines)
cat > "$T/bin/ssh-keygen" <<'STUB'
#!/bin/sh
f=""; while [ $# -gt 0 ]; do [ "$1" = -lf ] && f="$2"; shift; done
awk '!/^#/ && NF >= 2 { print "256 " $2 " key (ED25519)" }' "$f"
STUB
# stub ssh for pull: prints $T/remote.prom (or fails if $T/sfail exists)
cat > "$T/bin/ssh" <<STUB
#!/bin/sh
[ -e "$T/shang" ] && sleep 30
[ -e "$T/sfail" ] && exit 255
cat "$T/remote.prom"
STUB
chmod +x "$T/bin/journalctl" "$T/bin/ssh-keygen" "$T/bin/ssh"
ALLOW="$T/etc/allowlist"
export PFT_AW_CONF=/nonexistent PFT_AW_JOURNALCTL="$T/bin/journalctl" PFT_AW_SSHKEYGEN="$T/bin/ssh-keygen" \
  PFT_AW_PARSER="$P" PFT_AW_NOW=1700000000
run() { # HOST [collect args] -> $T/out, $T/rc, $T/err
  local host="$1"; shift
  ALLOWLIST="$ALLOW" bash "$S" collect --host "$host" --textfile-dir "$T/tf" --state-dir "$T/st" "$@" > "$T/out" 2> "$T/err"
  echo $? > "$T/rc"
}
aw() { ALLOWLIST="$ALLOW" bash "$S" "$@"; }
OUT="$T/tf/pft_authwatch_validator.prom"
H='host="validator"'
# independent counts straight from the fixture messages (grep, not the parser)
cnt() { jq -r '.MESSAGE' "$1" | grep -cE "$2"; }

echo "== 1. message classes (real fixture shapes)"
jq -r '[.SYSLOG_IDENTIFIER, .MESSAGE] | @tsv' "$FXV" "$FXS" | python3 -I "$P" classify > "$T/cls"
paste <(jq -r '.MESSAGE' "$FXV" "$FXS") "$T/cls" > "$T/cls2"
check "every Accepted publickey line -> accepted/publickey" '! grep -E "^Accepted publickey" "$T/cls2" | grep -vqE "	accepted	publickey/unknown$"'
check "every 'Invalid user' line -> failed/invalid_user" '! grep -E "^Invalid user " "$T/cls2" | grep -vqE "	failed	invalid_user$"'
check "every '... authenticating user ... [preauth]' line -> failed/preauth_abort" '! grep -E "^(Connection closed by|Connection reset by|Disconnected from) authenticating user" "$T/cls2" | grep -vqE "	failed	preauth_abort$"'
check "max auth attempts -> failed/max_auth" '! grep -E "^error: maximum authentication attempts" "$T/cls2" | grep -vqE "	failed	max_auth$"'
check "Unable to negotiate -> negotiate (not a failed auth)" '! grep -E "^Unable to negotiate" "$T/cls2" | grep -vqE "	negotiate	(cipher|mac|kex|hostkey)$"'
check "companion lines of an invalid user are not counted twice" '! grep -E "^(Disconnected from|Connection closed by|Connection reset by) invalid user|^Disconnecting invalid user|^Received disconnect" "$T/cls2" | grep -vqE "	-	-$"'
check "sudo COMMAND lines -> sudo/ok" '! grep -E "^ *[a-z0-9_.-]+ : (TTY=[^ ]+ ; )?PWD=" "$T/cls2" | grep -vqE "	sudo	ok$"'
check "session open/close lines are not counted" '! grep -E "^pam_unix\(" "$T/cls2" | grep -vqE "	-	-$"'
check "the fixtures cover >= 6 counted classes" '[ "$(awk -F"\t" "\$2 != \"-\" { print \$2 \"/\" \$3 }" "$T/cls2" | sort -u | wc -l)" -ge 6 ]'
printf '%s\t%s\n' sshd "Failed password for invalid user admin from 198.51.100.9 port 4242 ssh2" \
  sshd "Failed publickey for root from 198.51.100.9 port 4242 ssh2: ED25519 SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  sshd "Accepted password for user01 from 198.51.100.9 port 4242 ssh2" \
  sudo "  user01 : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/true" \
  sudo "  user02 : user NOT in sudoers ; TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/true" \
  sudo "  user01 : a password is required ; TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/true" \
  sshd "Server listening on 0.0.0.0 port 22." | python3 -I "$P" classify | tr '\t\n' ': ' > "$T/cls3"
check "synthetic: Failed password / Failed publickey / password login / 3 sudo failures / noise" \
  '[ "$(cat "$T/cls3")" = "failed:failed_password failed:failed_publickey accepted:password/none sudo:auth_failure sudo:denied sudo:auth_failure -:- " ]'

echo "== 2. first run takes the journal tail as cursor and counts nothing"
cp "$FXV" "$T/journal.jsonl"
run validator
check "rc 0" '[ "$(cat "$T/rc")" = 0 ]'
check "journalctl asked for -n 1 (no cursor yet)" 'grep -q -- "-n 1" "$T/jargs" && ! grep -q -- "--after-cursor" "$T/jargs"'
check "journalctl filtered to sshd + sudo" 'grep -q "SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sudo" "$T/jargs"'
check "cursor = last fixture entry" '[ "$(jq -r .cursor "$T/st/state-validator.json")" = "$(tail -1 "$FXV" | jq -r .__CURSOR)" ]'
check "up 1, timestamp from PFT_AW_NOW" 'has "$OUT" "pft_authwatch_up{$H} 1" && has "$OUT" "pft_authwatch_collect_timestamp_seconds{$H} 1700000000"'
check "all counters 0 after baseline" '[ "$(grep -E "_total\{" "$OUT" | awk "\$2 != 0" | wc -l)" = 0 ]'

echo "== 3. new entries are counted exactly once (resume from cursor)"
head -1 "$FXV" > "$T/journal.jsonl"
rm -f "$T/st/state-validator.json"; run validator            # baseline at fixture line 1
cp "$FXV" "$T/journal.jsonl"; run validator                 # lines 2..N are new
tail -n +2 "$FXV" > "$T/new.jsonl"
e_inv=$(cnt "$T/new.jsonl" '^Invalid user '); e_acc=$(cnt "$T/new.jsonl" '^Accepted publickey ')
e_pre=$(cnt "$T/new.jsonl" '^(Connection closed by|Connection reset by|Disconnected from) authenticating user \S+ \S+ port [0-9]+ \[preauth\]$')
e_sudo=$(cnt "$T/new.jsonl" '^ *[a-z0-9_.-]+ : (TTY=\S+ ; )?PWD=')
e_n=$(wc -l < "$T/new.jsonl")
check "rc 0" '[ "$(cat "$T/rc")" = 0 ]'
check "journalctl resumed with --after-cursor <line 1 cursor>" 'grep -qF -- "--after-cursor $(head -1 "$FXV" | jq -r .__CURSOR)" "$T/jargs"'
check "invalid_user = grep count ($e_inv)" '[ "$(val "$OUT" "pft_authwatch_ssh_failed_total{$H,reason=\"invalid_user\"}")" = "$e_inv" ]'
check "preauth_abort = grep count ($e_pre)" '[ "$(val "$OUT" "pft_authwatch_ssh_failed_total{$H,reason=\"preauth_abort\"}")" = "$e_pre" ]'
check "accepted publickey (unknown, empty allowlist) = grep count ($e_acc)" '[ "$(val "$OUT" "pft_authwatch_ssh_accepted_total{$H,method=\"publickey\",key_class=\"unknown\"}")" = "$e_acc" ]'
check "sudo ok = grep count ($e_sudo)" '[ "$(val "$OUT" "pft_authwatch_sudo_total{$H,result=\"ok\"}")" = "$e_sudo" ]'
check "entries_total = new lines ($e_n)" '[ "$(val "$OUT" "pft_authwatch_journal_entries_total{$H}")" = "$e_n" ]'
cp "$OUT" "$T/after1.prom"
run validator
check "a run with no new entries changes no counter" 'diff <(grep -v collect_timestamp "$T/after1.prom") <(grep -v collect_timestamp "$OUT") >/dev/null'
check "last_unknown_login = newest Accepted entry time" '[ "$(val "$OUT" "pft_authwatch_last_unknown_login_timestamp_seconds{$H}")" = "$(jq -r "select(.MESSAGE|startswith(\"Accepted\")) | .__REALTIME_TIMESTAMP" "$T/new.jsonl" | sort -n | tail -1 | cut -c1-10)" ]'

echo "== 4. a run that dies after the state write does not double count"
printf '%s\n' '{"__CURSOR":"s=fixture;i=new1","__REALTIME_TIMESTAMP":"1700000100000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Invalid user probe from 198.51.100.200 port 1"}' >> "$T/journal.jsonl"
rm -f "$OUT"; mkdir "$OUT"                                  # the textfile path is a directory: the rename fails
run validator
check "crash run exits non-zero" '[ "$(cat "$T/rc")" != 0 ]'
rmdir "$OUT"; run validator
check "next run: invalid_user +1 exactly" '[ "$(val "$OUT" "pft_authwatch_ssh_failed_total{$H,reason=\"invalid_user\"}")" = "$((e_inv + 1))" ]'
check "no temp files left in the textfile dir" '[ -z "$(find "$T/tf" -name ".authwatch-*")" ]'

echo "== 5. allowlist: import, dedupe, classify, remove"
# the key of the NEWEST login: then last_unknown_login must skip the newest Accepted entry (mutant P06)
fp1="$(jq -r '.MESSAGE' "$FXV" | grep -oE 'SHA256:[A-Za-z0-9+/]{43}' | tail -1)"
printf '# keys\nssh-ed25519 %s op\nssh-ed25519 %s again\n' "$fp1" "$fp1" > "$T/ak"
check "import adds 1 (duplicate skipped)" '[ "$(aw allow import "$T/ak")" = "allowlist: 1 added, 1 total" ]'
check "import again adds 0" '[ "$(aw allow import "$T/ak")" = "allowlist: 0 added, 1 total" ]'
check "allowlist file mode 600" '[ "$(stat -c %a "$ALLOW")" = 600 ]'
check "add rejects a malformed fingerprint (exit 3)" 'aw allow add SHA256:short 2>/dev/null; [ $? = 3 ]'
e_fp1=$(jq -r '.MESSAGE' "$T/new.jsonl" | grep -c "^Accepted publickey .*$fp1$")
e_other=$(( $(cnt "$T/new.jsonl" '^Accepted publickey ') - e_fp1 ))
rm -f "$T/st/state-validator.json"; head -1 "$FXV" > "$T/journal.jsonl"; run validator
cp "$FXV" "$T/journal.jsonl"; run validator
check "logins with the allowlisted key -> allowlisted ($e_fp1)" '[ "$e_fp1" -gt 0 ] && [ "$(val "$OUT" "pft_authwatch_ssh_accepted_total{$H,method=\"publickey\",key_class=\"allowlisted\"}")" = "$e_fp1" ]'
check "other keys stay unknown ($e_other)" '[ "$(val "$OUT" "pft_authwatch_ssh_accepted_total{$H,method=\"publickey\",key_class=\"unknown\"}")" = "$e_other" ]'
check "allowlist_entries 1" 'has "$OUT" "pft_authwatch_allowlist_entries{$H} 1"'
e_lu="$(jq -r --arg fp "$fp1" 'select((.MESSAGE|startswith("Accepted")) and (.MESSAGE|endswith($fp)|not)) | .__REALTIME_TIMESTAMP' "$T/new.jsonl" | sort -n | tail -1 | cut -c1-10)"
check "last_unknown_login ignores allowlisted logins" '[ -n "$e_lu" ] && [ "$(val "$OUT" "pft_authwatch_last_unknown_login_timestamp_seconds{$H}")" = "$e_lu" ]'
check "remove -> 0 total" '[ "$(aw allow remove "$fp1")" = "allowlist: 0 total" ]'

echo "== 6. privacy: no identity reaches the textfile or the state file"
rm -f "$T/st/state-sentry.json"
head -1 "$FXS" > "$T/journal.jsonl"; run sentry; cp "$FXS" "$T/journal.jsonl"; run sentry
for f in "$OUT" "$T/tf/pft_authwatch_sentry.prom" "$T/st/state-validator.json" "$T/st/state-sentry.json"; do
  check "$(basename "$f"): no address, user name or fingerprint" '! grep -qE "198\.51\.100|203\.0\.113|2001:db8|user[0-9]|SHA256:|root|probe" "$f"'
done
check "only label keys host/method/key_class/reason/kind/result/version" '[ -z "$(grep -hv "^#" "$OUT" "$T/tf/pft_authwatch_sentry.prom" | grep -oE "[a-z_]+=" | sort -u | grep -vxE "(host|method|key_class|reason|kind|result|version)=")" ]'
check "sentry file carries host=\"sentry\" and passes validate" 'bash "$S" validate "$T/tf/pft_authwatch_sentry.prom" sentry'
check "the sentry fixtures count accepted logins" '[ "$(val "$T/tf/pft_authwatch_sentry.prom" "pft_authwatch_ssh_accepted_total{host=\"sentry\",method=\"publickey\",key_class=\"unknown\"}")" = "$(tail -n +2 "$FXS" | jq -r .MESSAGE | grep -c "^Accepted publickey ")" ]'

echo "== 7. journal errors, --stdout dry run, odd messages"
cp "$T/st/state-validator.json" "$T/st.keep"; touch "$T/jfail"; run validator
check "journalctl failure -> exit 1 with its message" '[ "$(cat "$T/rc")" = 1 ] && grep -q "Permission denied" "$T/err"'
check "journalctl failure leaves the state untouched" 'cmp -s "$T/st.keep" "$T/st/state-validator.json"'
rm -f "$T/jfail"; touch "$T/jhang"; t0=$(date +%s)
JOURNAL_TIMEOUT=2 run validator
check "hung journalctl -> killed by JOURNAL_TIMEOUT, exit 1 within 10 s, state untouched" '[ "$(cat "$T/rc")" = 1 ] && [ $(( $(date +%s) - t0 )) -lt 10 ] && cmp -s "$T/st.keep" "$T/st/state-validator.json"'
rm -f "$T/jhang"
cp "$FXV" "$T/journal.jsonl"
printf '%s\n' '{"__CURSOR":"s=fixture;i=bytes","__REALTIME_TIMESTAMP":"1700000200000000","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[73,110,118,97,108,105,100,32,117,115,101,114,32,255,32,102,114,111,109,32,49,57,56,46,53,49,46,49,48,48,46,49,32,112,111,114,116,32,49]}' 'not json' >> "$T/journal.jsonl"
cp "$OUT" "$T/pre-stdout.prom"
inv0="$(val "$T/pre-stdout.prom" "pft_authwatch_ssh_failed_total{$H,reason=\"invalid_user\"}")"
run validator --stdout
check "--stdout prints the textfile with the new entry counted" 'grep -qxF "pft_authwatch_ssh_failed_total{$H,reason=\"invalid_user\"} $((inv0 + 1))" "$T/out"'
check "--stdout changed neither state nor textfile" 'cmp -s "$T/st.keep" "$T/st/state-validator.json" && cmp -s "$T/pre-stdout.prom" "$OUT"'
run validator
check "byte-array MESSAGE (non-UTF-8) is decoded and counted; a non-JSON line is skipped" '[ "$(cat "$T/rc")" = 0 ] && [ "$(val "$OUT" "pft_authwatch_ssh_failed_total{$H,reason=\"invalid_user\"}")" = "$((inv0 + 1))" ]'
check "bad --host is a usage error (3)" 'run "Bad;host"; [ "$(cat "$T/rc")" = 3 ]'

echo "== 8. pull: validate and rename, reject a bad or failed copy"
PULLENV=(env PULL_SSH="$T/bin/ssh peer" REMOTE_DIR=/r)
cp "$T/tf/pft_authwatch_sentry.prom" "$T/remote.prom"; rm -f "$T/tf/pft_authwatch_sentry.prom"
check "pull copies a valid sentry file" '"${PULLENV[@]}" bash "$S" pull --host sentry --textfile-dir "$T/tf" && cmp -s "$T/remote.prom" "$T/tf/pft_authwatch_sentry.prom"'
check "pulled file mode 644" '[ "$(stat -c %a "$T/tf/pft_authwatch_sentry.prom")" = 644 ]'
sed 's/host="sentry"/host="validator"/' "$T/tf/pft_authwatch_sentry.prom" > "$T/remote.prom"
check "wrong host label -> exit 2, old file kept" '"${PULLENV[@]}" bash "$S" pull --host sentry --textfile-dir "$T/tf" 2>/dev/null; [ $? = 2 ] && grep -q "host=\"sentry\"" "$T/tf/pft_authwatch_sentry.prom"'
grep -v '^pft_authwatch_up{' "$T/tf/pft_authwatch_sentry.prom" > "$T/remote.prom"
check "no up sample -> exit 2" '"${PULLENV[@]}" bash "$S" pull --host sentry --textfile-dir "$T/tf" 2>/dev/null; [ $? = 2 ]'
printf 'garbage\n' > "$T/remote.prom"
check "garbage -> exit 2" '"${PULLENV[@]}" bash "$S" pull --host sentry --textfile-dir "$T/tf" 2>/dev/null; [ $? = 2 ]'
touch "$T/shang"; t0=$(date +%s)
check "hung ssh -> killed by PULL_TIMEOUT, exit 1 within 10 s" '"${PULLENV[@]}" PULL_TIMEOUT=2 bash "$S" pull --host sentry --textfile-dir "$T/tf" 2>/dev/null; [ $? = 1 ] && [ $(( $(date +%s) - t0 )) -lt 10 ]'
rm -f "$T/shang"; touch "$T/sfail"
check "ssh failure -> exit 1" '"${PULLENV[@]}" bash "$S" pull --host sentry --textfile-dir "$T/tf" 2>/dev/null; [ $? = 1 ]'
check "no temp files left after failed pulls" '[ -z "$(find "$T/tf" -name ".pull-*")" ]'
check "pull without PULL_SSH -> exit 3" 'bash "$S" pull --host sentry --textfile-dir "$T/tf" 2>/dev/null; [ $? = 3 ]'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
