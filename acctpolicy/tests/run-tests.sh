#!/usr/bin/env bash
# Offline tests for pft-acctpolicy.sh: a fixture root (synthetic passwd/shadow/group with fake hashes, stock Ubuntu
# 22.04 pam.d/common-auth, common-password, su, login.defs and default/useradd from fixtures/), stub sshd (-T / -t),
# stub docker (inspect + server_info), stub sudo (root su) and a stub self-test. No root; nothing on the host changes.
# Every check ID has a PASS fixture and a non-PASS fixture; every apply/rollback guard has a test whose input passes
# every OTHER guard and asserts that no file was written.
#   bash acctpolicy/tests/run-tests.sh [SCRIPT]   (default ../pft-acctpolicy.sh)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; OUT/RC/before are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-acctpolicy.sh}"
FX="$HERE/fixtures"
T="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}")"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; [ -z "${AP_FAILFAST:-}" ] || exit 1; }   # FAILFAST: mutants.py
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }

export PFT_AP_ROOT="$T/root" PFT_AP_NOW=4070908800 STATE_DIR="$T/state" CONTAINER=""
export PFT_AP_SSHD="$T/bin/sshd" PFT_AP_DOCKER="$T/bin/docker" PFT_AP_SUDO="$T/bin/sudo" PFT_AP_SELFTEST="$T/bin/selftest"
PFT_AP_OWNER="$(id -un)"; PFT_AP_GROUP="$(id -gn)"; export PFT_AP_OWNER PFT_AP_GROUP
E="$T/root/etc"
HASH_Y='$y$j9T$FIXTUREsaltAAAA$FIXTUREhashYESCRYPTxxxxxxxxxxxxxxxxxxxxxxx'
HASH_MD5='$1$FIXsalt$FIXTUREhashMD5xxxxxxxxx'
mkdir -p "$T/bin"
# stub sshd: -T -> $T/sshd_T; -t -> exit $(cat $T/sshd_t_rc)
cat > "$T/bin/sshd" <<EOF
#!/bin/sh
case "\$1" in -T) cat "$T/sshd_T" ;; -t) exit "\$(cat "$T/sshd_t_rc")" ;; *) exit 9 ;; esac
EOF
# stub docker: inspect -f FORMAT C -> per-format files in $T/ctr/; exec C postfiatd --conf CFG server_info -> $T/node
cat > "$T/bin/docker" <<EOF
#!/bin/bash
echo "\$*" >> "$T/docker.calls"
case "\$1" in
  inspect) c="\$4"; [ -d "$T/ctr/\$c" ] || exit 1
    case "\$3" in
      '{{.State.Running}}') cat "$T/ctr/\$c/running" ;; '{{.State.Pid}}') echo 4242 ;;
      '{{.HostConfig.Privileged}}') cat "$T/ctr/\$c/priv" ;; '{{json .HostConfig.SecurityOpt}}') cat "$T/ctr/\$c/sec" ;;
      '{{json .HostConfig.CapDrop}}') cat "$T/ctr/\$c/capdrop" ;; *) exit 9 ;;
    esac ;;
  exec) [ "\$3 \$4 \$5 \$6" = "postfiatd --conf /etc/postfiatd/postfiatd.cfg server_info" ] || exit 9
    read -r st p < "$T/node"; printf '{"result":{"info":{"server_state":"%s","peers":%s}}}\n' "\$st" "\$p" ;;
  *) exit 9 ;;
esac
EOF
# stub sudo: only the root-su self-test shape; $T/su_fail makes it fail
cat > "$T/bin/sudo" <<EOF
#!/bin/sh
[ "\$*" = "-n su -s /bin/sh -c echo su-ok nobody" ] || { echo "unexpected sudo \$*" >&2; exit 9; }
[ -e "$T/su_fail" ] && { echo "su: Authentication failure"; exit 1; }
echo su-ok
EOF
# stub self-test (stands for the throwaway-sshd login + sudo -n): logs each call; fails if $T/selftest_fail exists,
# or (after-change failure) if $T/selftest_fail_if_no_nullok exists and common-auth no longer has nullok
cat > "$T/bin/selftest" <<EOF
#!/bin/sh
echo call >> "$T/selftest.calls"
[ -e "$T/selftest_fail" ] && { echo "stub ssh: Permission denied (publickey)"; exit 1; }
if [ -e "$T/selftest_fail_if_no_nullok" ] && ! grep -q nullok "$E/pam.d/common-auth"; then echo "stub ssh: PAM account failure"; exit 1; fi
echo "stub ssh key login + sudo -n ok"
EOF
chmod +x "$T/bin/"*

reset() { # the fixture: a stock Ubuntu 22.04 node host like the live validator, before apply
  rm -rf "$T/root" "$T/state" "$T/ctr" "$T"/*.calls "$T/su_fail" "$T/selftest_fail" "$T/selftest_fail_if_no_nullok"
  mkdir -p "$E/pam.d" "$E/default" "$T/root/home/alice" "$T/root/home/bob" "$T/root/proc/4242/root/etc" \
    "$T/root/var/lib/svc/.ssh"
  cat > "$E/passwd" <<'P'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
svc:x:998:998::/var/lib/svc:/bin/sh
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
P
  printf 'root:%s:20383:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nsync:*:19000:0:99999:7:::\nnobody:*:19000:0:99999:7:::\nsvc:!:20380::::::\nalice:!:20380:0:99999:7:::\nbob:*:20380:0:99999:7:::\n' "$HASH_Y" > "$E/shadow"
  printf 'root:x:0:\ndaemon:x:1:\nsudo:x:27:alice,bob\nsvc:x:998:\nalice:x:1000:\nbob:x:1001:\nnogroup:x:65534:\n' > "$E/group"
  printf 'root:*::\nsudo:*::\n' > "$E/gshadow"
  cp "$E/passwd" "$E/passwd-"; cp "$E/shadow" "$E/shadow-"
  chmod 644 "$E/passwd" "$E/group" "$E/passwd-"; chmod 640 "$E/shadow" "$E/gshadow" "$E/shadow-"
  chmod 750 "$T/root/home/alice" "$T/root/home/bob"
  printf 'restrict,command="/usr/local/bin/svc receive" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTUREFIXTUREFIXTUREFIXTUREFIXTUREFIXTUREFIX svc\n' > "$T/root/var/lib/svc/.ssh/authorized_keys"
  cp "$FX/pam.d-common-auth" "$E/pam.d/common-auth"; cp "$FX/pam.d-common-password" "$E/pam.d/common-password"
  cp "$FX/pam.d-su" "$E/pam.d/su"; cp "$FX/login.defs" "$E/login.defs"; cp "$FX/useradd" "$E/default/useradd"
  chmod 640 "$E/default/useradd"
  printf 'root:x:0:0:root:/root:/bin/bash\npostfiat:x:1000:1000::/var/lib/postfiatd:/usr/sbin/nologin\n' > "$T/root/proc/4242/root/etc/passwd"
  printf 'root:*:19000:0:99999:7:::\npostfiat:!:19000::::::\n' > "$T/root/proc/4242/root/etc/shadow"
  mkdir -p "$T/ctr/postfiatd"; echo true > "$T/ctr/postfiatd/running"; echo false > "$T/ctr/postfiatd/priv"
  echo '["no-new-privileges:true","apparmor=pft-postfiatd"]' > "$T/ctr/postfiatd/sec"; echo '["ALL"]' > "$T/ctr/postfiatd/capdrop"
  printf 'usepam yes\npermitrootlogin without-password\npasswordauthentication no\nkbdinteractiveauthentication no\n' > "$T/sshd_T"
  echo 0 > "$T/sshd_t_rc"; echo "full 10" > "$T/node"
}
FILES() { for f in "$E/pam.d/common-auth" "$E/pam.d/su" "$E/login.defs" "$E/default/useradd"; do printf '%s %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$(stat -c %a "$f")"; done; }
st() { awk -v i="$1" '$1 == i { print $2 }' <<<"$OUT"; }   # status of check ID in the last audit OUT
audit() { OUT="$(bash "$S" audit 2>&1)"; RC=$?; }

# ---------- audit: the stock fixture ----------
reset; audit
check "stock: exit 1 (findings)" '[ "$RC" = 1 ]'
check "stock: 5 WARN = the fixable set" '[ "$(st pam.nullok)$(st pam.su-wheel)$(st login.encrypt)$(st login.pass-max)$(st useradd.inactive)" = WARNWARNWARNWARNWARN ]'
check "stock: every other check PASS" '[ "$(grep -cE "^[a-z.0-9-]+ +PASS " <<<"$OUT")" = 16 ]'
check "stock: 21 check lines (= checks table)" '[ "$(grep -cE "^(acct|pam|login|useradd|ctr)\." <<<"$OUT")" = "$(bash "$S" checks | wc -l)" ]'
check "stock: root usable password PASS only with sshd password/kbd no" '[ "$(st acct.root-password)" = PASS ] && grep -q "console recovery" <<<"$OUT"'
check "stock: locked system account with forced-command key PASS" '[ "$(st acct.system-shell)" = PASS ] && grep -q "1 system account" <<<"$OUT"'
check "stock: faillock N/A (no password path) is PASS with its reason" '[ "$(st pam.faillock)" = PASS ] && grep -q "no password path" <<<"$OUT"'
check "stock: no hash value or salt in output" '! grep -q FIXTURE <<<"$OUT"'
OUT="$(bash "$S" audit --json)"; RC=$?
check "json: valid, 21 checks, warn 5 fail 0, exit 1" '[ "$RC" = 1 ] && [ "$(jq -r "[(.checks|length), .warn, .fail]|join(\" \")" <<<"$OUT")" = "21 5 0" ]'
check "json: no hash value" '! grep -q FIXTURE <<<"$OUT"'

# ---------- audit: one negative fixture per check ID ----------
reset; echo 'toor:x:0:0::/root:/bin/sh' >> "$E/passwd"; echo 'toor:*:1::::::' >> "$E/shadow"; audit
check "acct.uid0 FAIL: second UID 0" '[ "$(st acct.uid0)" = FAIL ] && [ "$RC" = 1 ]'
reset; echo 'carol:x:1001:1001::/home/bob:/bin/bash' >> "$E/passwd"; echo 'carol:*:1::::::' >> "$E/shadow"; audit
check "acct.dup-uid FAIL: shared UID" '[ "$(st acct.dup-uid)" = FAIL ]'
reset; echo 'sudo:x:28:' >> "$E/group"; audit
check "acct.dup-name FAIL: duplicate group name" '[ "$(st acct.dup-name)" = FAIL ] && [ "$(st acct.dup-uid)" = PASS ]'
reset; sed -i 's/^bob:x:/bob:'"${HASH_MD5//\$/\\\$}"':/' "$E/passwd"; audit
check "acct.shadowed FAIL: hash in passwd" '[ "$(st acct.shadowed)" = FAIL ] && ! grep -q FIXTURE <<<"$OUT"'
reset; echo 'dave:x:1003:1003::/home/dave:/bin/bash' >> "$E/passwd"; audit
check "acct.shadowed FAIL: no shadow entry" '[ "$(st acct.shadowed)" = FAIL ]'
reset; sed -i 's/^bob:\*:/bob::/' "$E/shadow"; audit
check "acct.empty-password FAIL: empty field" '[ "$(st acct.empty-password)" = FAIL ]'
reset; sed -i 's/^bob:\*:/bob:'"${HASH_MD5//\$/\\\$}"':/' "$E/shadow"; audit
check "acct.hash-scheme WARN: md5, scheme named, hash not printed" '[ "$(st acct.hash-scheme)" = WARN ] && grep -q "md5 x1" <<<"$OUT" && ! grep -q FIXTURE <<<"$OUT"'
check "pam.faillock WARN: a non-root account has a usable password" '[ "$(st pam.faillock)" = WARN ]'
reset; sed -i 's/^passwordauthentication no/passwordauthentication yes/' "$T/sshd_T"; audit
check "acct.root-password FAIL: usable root password + sshd password yes" '[ "$(st acct.root-password)" = FAIL ]'
check "pam.faillock WARN: sshd password yes" '[ "$(st pam.faillock)" = WARN ]'
reset; sed -i 's/^kbdinteractiveauthentication no/kbdinteractiveauthentication yes/' "$T/sshd_T"; audit
check "acct.root-password FAIL: kbd-interactive yes" '[ "$(st acct.root-password)" = FAIL ]'
reset; sed -i 's/^permitrootlogin .*/permitrootlogin yes/' "$T/sshd_T"; audit
check "acct.root-password FAIL: permitrootlogin yes" '[ "$(st acct.root-password)" = FAIL ]'
reset; sed -i 's/^root:[^:]*:/root:!:/' "$E/shadow"; sed -i 's/^passwordauthentication no/passwordauthentication yes/' "$T/sshd_T"; audit
check "acct.root-password PASS: locked root, whatever sshd says" '[ "$(st acct.root-password)" = PASS ]'
reset; sed -i 's/^svc:!:/svc:*:/' "$E/shadow"; printf 'ssh-ed25519 AAAAC3Nza unrestricted\n' >> "$T/root/var/lib/svc/.ssh/authorized_keys"; audit
check "acct.system-shell WARN: key without restrict,command=" '[ "$(st acct.system-shell)" = WARN ] && grep -q uid998 <<<"$OUT"'
reset; sed -i 's/^svc:!:/svc:'"${HASH_MD5//\$/\\\$}"':/' "$E/shadow"; audit
check "acct.system-shell WARN: system account with a usable password" '[ "$(st acct.system-shell)" = WARN ]'
reset; printf 'command="/x" ssh-ed25519 AAAAC3Nza no-restrict\n' > "$T/root/var/lib/svc/.ssh/authorized_keys"; audit
check "acct.system-shell WARN: command= without restrict" '[ "$(st acct.system-shell)" = WARN ]'
reset; chmod 644 "$E/shadow"; audit
check "acct.file-modes FAIL: shadow 0644" '[ "$(st acct.file-modes)" = FAIL ] && grep -q "/etc/shadow" <<<"$OUT"'
reset; chmod 666 "$E/passwd-"; audit
check "acct.file-modes FAIL: passwd- backup world-writable" '[ "$(st acct.file-modes)" = FAIL ]'
reset; chmod 600 "$E/shadow"; chmod 600 "$E/passwd"; audit
check "acct.file-modes PASS: stricter modes" '[ "$(st acct.file-modes)" = PASS ]'
reset; PFT_AP_OWNER=root audit
check "acct.file-modes FAIL: owner is not the expected owner" '[ "$(st acct.file-modes)" = FAIL ]'
reset; chmod 755 "$T/root/home/bob"; audit
check "acct.home-modes WARN: world-readable home" '[ "$(st acct.home-modes)" = WARN ] && grep -q "1 of 2" <<<"$OUT"'
reset; chmod 770 "$T/root/home/alice"; audit
check "acct.home-modes WARN: group-writable home" '[ "$(st acct.home-modes)" = WARN ]'
reset; sed -i 's/pam_unix.so nullok/pam_unix.so/' "$E/pam.d/common-auth"; audit
check "pam.nullok PASS without nullok" '[ "$(st pam.nullok)" = PASS ]'
reset; sed -i 's/pam_unix.so nullok/pam_unix.so nullok_secure/' "$E/pam.d/common-auth"; audit
check "pam.nullok WARN: nullok_secure" '[ "$(st pam.nullok)" = WARN ]'
reset; printf '#auth sufficient pam_unix.so nullok\n' > "$E/pam.d/common-auth"; audit
check "pam.nullok PASS: commented-out line ignored" '[ "$(st pam.nullok)" = PASS ]'
reset; printf 'auth sufficient pam_permit.so\n' > "$E/pam.d/other"; audit
check "pam.permit FAIL: auth sufficient pam_permit" '[ "$(st pam.permit)" = FAIL ] && grep -q "other" <<<"$OUT"'
reset; printf 'auth [success=done default=ignore] pam_permit.so\n' > "$E/pam.d/cron"; audit
check "pam.permit FAIL: pam_permit jump" '[ "$(st pam.permit)" = FAIL ]'
reset; printf 'account sufficient pam_permit.so\n' > "$E/pam.d/other"; audit
check "pam.permit PASS: account stack, not auth" '[ "$(st pam.permit)" = PASS ]'
reset; sed -i 's/^passwordauthentication no/passwordauthentication yes/' "$T/sshd_T"; sed -i '0,/pam_unix.so/s//pam_unix.so\nauth required pam_faillock.so authfail/' "$E/pam.d/common-auth"; audit
check "pam.faillock PASS: configured" '[ "$(st pam.faillock)" = PASS ] && grep -q "configured in common-auth" <<<"$OUT"'
reset; printf 'auth required pam_wheel.so use_uid group=sudo\n' >> "$E/pam.d/su"; audit
check "pam.su-wheel PASS: pam_wheel use_uid" '[ "$(st pam.su-wheel)" = PASS ]'
reset; printf 'auth required pam_wheel.so deny group=nosu use_uid\n' >> "$E/pam.d/su"; audit
check "pam.su-wheel WARN: deny form only" '[ "$(st pam.su-wheel)" = WARN ]'
reset; sed -i 's/^ENCRYPT_METHOD SHA512/ENCRYPT_METHOD YESCRYPT/' "$E/login.defs"; audit
check "login.encrypt PASS: matches pam_unix yescrypt" '[ "$(st login.encrypt)" = PASS ]'
reset; sed -i 's/^ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$E/login.defs"; sed -i 's/ yescrypt/ md5/' "$E/pam.d/common-password"; audit
check "login.encrypt WARN: equal but md5" '[ "$(st login.encrypt)" = WARN ]'
reset; sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' "$E/login.defs"; audit
check "login.pass-max PASS: 365/1" '[ "$(st login.pass-max)" = PASS ]'
reset; sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' "$E/login.defs"; audit
check "login.pass-max WARN: max ok, min 0" '[ "$(st login.pass-max)" = WARN ]'
reset; sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 366/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' "$E/login.defs"; audit
check "login.pass-max WARN: 366 > 365" '[ "$(st login.pass-max)" = WARN ]'
reset; sed -i 's/^UMASK.*/UMASK 002/' "$E/login.defs"; audit
check "login.umask WARN: 002" '[ "$(st login.umask)" = WARN ]'
reset; sed -i 's/^UMASK.*/UMASK 020/' "$E/login.defs"; audit
check "login.umask WARN: 020 (other-write open)" '[ "$(st login.umask)" = WARN ]'
reset; sed -i 's/^UMASK.*/UMASK 027/' "$E/login.defs"; audit
check "login.umask PASS: 027" '[ "$(st login.umask)" = PASS ]'
reset; echo 'INACTIVE=30' >> "$E/default/useradd"; audit
check "useradd.inactive PASS: 30" '[ "$(st useradd.inactive)" = PASS ]'
reset; echo 'INACTIVE=31' >> "$E/default/useradd"; audit
check "useradd.inactive WARN: 31 > 30" '[ "$(st useradd.inactive)" = WARN ]'
reset; echo 'INACTIVE=0' >> "$E/default/useradd"; audit
check "useradd.inactive WARN: 0" '[ "$(st useradd.inactive)" = WARN ]'
reset; echo 'evil:x:0:0::/:/bin/sh' >> "$T/root/proc/4242/root/etc/passwd"; audit
check "ctr.uid0 FAIL: second UID 0 in the container" '[ "$(st ctr.uid0)" = FAIL ] && [ "$(st acct.uid0)" = PASS ]'
reset; sed -i 's/^postfiat:!:/postfiat::/' "$T/root/proc/4242/root/etc/shadow"; audit
check "ctr.empty-password FAIL: empty field in the container" '[ "$(st ctr.empty-password)" = FAIL ]'
reset; sed -i 's/^postfiat:x:/postfiat::/' "$T/root/proc/4242/root/etc/passwd"; audit
check "ctr.empty-password FAIL: empty passwd field in the container" '[ "$(st ctr.empty-password)" = FAIL ]'
reset; echo true > "$T/ctr/postfiatd/priv"; audit
check "ctr.runtime FAIL: privileged" '[ "$(st ctr.runtime)" = FAIL ]'
reset; echo '["apparmor=pft-postfiatd"]' > "$T/ctr/postfiatd/sec"; audit
check "ctr.runtime FAIL: no no-new-privileges" '[ "$(st ctr.runtime)" = FAIL ]'
reset; echo '["NET_RAW"]' > "$T/ctr/postfiatd/capdrop"; audit
check "ctr.runtime FAIL: capdrop not ALL" '[ "$(st ctr.runtime)" = FAIL ]'
reset; rm -rf "$T/ctr/postfiatd"
mkdir -p "$T/ctr/postfiatd-sentry"; echo true > "$T/ctr/postfiatd-sentry/running"; echo false > "$T/ctr/postfiatd-sentry/priv"
echo '["no-new-privileges"]' > "$T/ctr/postfiatd-sentry/sec"; echo '["ALL"]' > "$T/ctr/postfiatd-sentry/capdrop"; audit
check "ctr: sentry container auto-detected" '[ "$(st ctr.runtime)" = PASS ] && grep -q "postfiatd-sentry: not privileged" <<<"$OUT"'
reset; rm -rf "$T/ctr/postfiatd"; audit
check "ctr: no running container -> 3 FAIL" '[ "$(st ctr.uid0)$(st ctr.empty-password)$(st ctr.runtime)" = FAILFAILFAIL ]'
reset; audit
check "audit never execs into the container" '! grep -q "^exec" "$T/docker.calls"'

# ---------- plan ----------
reset; before="$(FILES)"; OUT="$(bash "$S" plan 2>&1)"; RC=$?
check "plan: exit 0, names the 5 fixes" '[ "$RC" = 0 ] && grep -q "^plan: nullok su-wheel encrypt passage inactive" <<<"$OUT"'
check "plan: read-only (files unchanged, no state dir)" '[ "$(FILES)" = "$before" ] && [ ! -e "$T/state" ]'
check "plan: diff removes nullok, adds pam_wheel on its own line" 'grep -q "^-auth.*pam_unix.so nullok" <<<"$OUT" && grep -q "^+auth       required   pam_wheel.so use_uid group=sudo$" <<<"$OUT"'
reset; sed -i 's/^bob:\*:/bob::/' "$E/shadow"; OUT="$(bash "$S" plan 2>&1)"
check "plan: nullok fix withheld while an empty password exists" '! grep -q "plan:.*nullok" <<<"$OUT" && grep -q "plan: su-wheel" <<<"$OUT"'
reset; sed -i 's/^sudo:x:27:/sudoers:x:27:/' "$E/group"; OUT="$(bash "$S" plan 2>&1)"
check "plan: su-wheel withheld when SU_GROUP does not exist" '! grep -q "su-wheel" <<<"$OUT"'
reset; sed -i '/pam_rootok/d' "$E/pam.d/su"; OUT="$(bash "$S" plan 2>&1)"; RC=$?
check "plan: su-wheel withheld without a pam_rootok line, other fixes still planned" '[ "$RC" = 0 ] && ! grep -q "su-wheel" <<<"$OUT" && grep -q "^plan: nullok encrypt passage inactive" <<<"$OUT"'

# ---------- apply guards: each must leave every file untouched and write no state ----------
nochange() { [ "$(FILES)" = "$before" ] && [ ! -e "$T/state/apply.json" ] && [ -z "$(ls -A "$T/state/backup" 2>/dev/null)" ]; }
reset; before="$(FILES)"; OUT="$(bash "$S" apply 2>&1)"; RC=$?
check "apply without --yes: exit 4, nothing written, no self-test" '[ "$RC" = 4 ] && nochange && [ ! -e "$T/selftest.calls" ]'
reset; before="$(FILES)"; mkdir -p "$T/state"; echo '{}' > "$T/state/apply.json"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply with a previous apply in place: exit 4, files untouched" '[ "$RC" = 4 ] && [ "$(FILES)" = "$before" ] && [ ! -e "$T/selftest.calls" ]'
reset; before="$(FILES)"; echo "syncing 10" > "$T/node"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply with node not full: exit 4, nothing written" '[ "$RC" = 4 ] && nochange && grep -q "not healthy" <<<"$OUT"'
reset; before="$(FILES)"; echo "full 0" > "$T/node"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply with 0 peers (< MIN_PEERS): exit 4, nothing written" '[ "$RC" = 4 ] && nochange'
reset; before="$(FILES)"; touch "$T/selftest_fail"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply when the self-test fails BEFORE any change: exit 4, nothing written" '[ "$RC" = 4 ] && nochange && grep -q "BEFORE any change" <<<"$OUT"'
reset; before="$(FILES)"; echo 1 > "$T/sshd_t_rc"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply when sshd -t fails before: exit 4, nothing written" '[ "$RC" = 4 ] && nochange'
reset; before="$(FILES)"; touch "$T/su_fail"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply when root su fails before: exit 4, nothing written" '[ "$RC" = 4 ] && nochange'

# ---------- apply: success, automatic restore, rollback ----------
reset; before="$(FILES)"; m_su="$(stat -c %a "$E/pam.d/su")"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply: exit 0, self-test PASS" '[ "$RC" = 0 ] && grep -q "self-test PASS" <<<"$OUT"'
check "apply: self-test ran before AND after the change" '[ "$(wc -l < "$T/selftest.calls")" = 2 ]'
check "apply: modes preserved" '[ "$(stat -c %a "$E/default/useradd")" = 640 ] && [ "$(stat -c %a "$E/pam.d/su")" = "$m_su" ]'
check "apply: apply.json records 4 files with their before sha256" '[ "$(jq ".files|length" "$T/state/apply.json")" = 4 ]'
check "apply: backup dir 0700" '[ "$(stat -c %a "$T/state/backup")" = 700 ]'
check "apply: only the planned lines changed in common-auth" '[ "$(diff "$FX/pam.d-common-auth" "$E/pam.d/common-auth" | grep -c "^[<>]")" = 2 ]'
audit
check "apply: audit afterwards PASS, exit 0" '[ "$RC" = 0 ] && grep -q "RESULT: PASS - 21 checks" <<<"$OUT"'
OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply: second apply refused while the first is in place" '[ "$RC" = 4 ]'
OUT="$(bash "$S" rollback 2>&1)"; RC=$?
check "rollback without --yes: exit 4" '[ "$RC" = 4 ] && [ -e "$T/state/apply.json" ]'
OUT="$(bash "$S" rollback --yes 2>&1)"; RC=$?
check "rollback: exit 0, files byte-identical (sha + mode) to before apply" '[ "$RC" = 0 ] && [ "$(FILES)" = "$before" ] && [ ! -e "$T/state/apply.json" ]'
check "rollback: prints a restored sha line per file" '[ "$(grep -c "^restored " <<<"$OUT")" = 4 ]'
OUT="$(bash "$S" rollback --yes 2>&1)"; RC=$?
check "rollback with nothing applied: exit 4" '[ "$RC" = 4 ]'
OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply again after rollback: exit 0" '[ "$RC" = 0 ]'
OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
b="$(jq -r .backup "$T/state/apply.json")"; for f1 in "$b"/*; do [ "${f1##*/}" = manifest ] || break; done; echo tamper >> "$f1"
OUT="$(bash "$S" rollback --yes 2>&1)"; RC=$?
check "rollback with a tampered backup: exit 5, apply.json kept" '[ "$RC" = 5 ] && grep -q "RESTORE MISMATCH" <<<"$OUT" && [ -e "$T/state/apply.json" ]'
reset; before="$(FILES)"; OUT="$(VERIFY_INJECT=selftest bash "$S" apply --yes 2>&1)"; RC=$?
check "apply VERIFY_INJECT=selftest: exit 1, restored byte-identical, no apply.json" '[ "$RC" = 1 ] && [ "$(FILES)" = "$before" ] && [ ! -e "$T/state/apply.json" ] && grep -q "restored byte-identical" <<<"$OUT"'
reset; before="$(FILES)"; touch "$T/selftest_fail_if_no_nullok"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply whose change breaks the SSH self-test: exit 1, restored byte-identical" '[ "$RC" = 1 ] && [ "$(FILES)" = "$before" ] && [ ! -e "$T/state/apply.json" ]'
reset; sed -i 's/pam_unix.so nullok/pam_unix.so/' "$E/pam.d/common-auth"; printf 'auth required pam_wheel.so use_uid group=sudo\n' >> "$E/pam.d/su"
sed -i 's/^ENCRYPT_METHOD SHA512/ENCRYPT_METHOD YESCRYPT/; s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' "$E/login.defs"
echo 'INACTIVE=30' >> "$E/default/useradd"; before="$(FILES)"; OUT="$(bash "$S" apply --yes 2>&1)"; RC=$?
check "apply on a hardened host: nothing to fix, exit 0, nothing written" '[ "$RC" = 0 ] && grep -q "nothing to fix" <<<"$OUT" && nochange'
reset; OUT="$( { bash "$S" plan; bash "$S" apply --yes; bash "$S" rollback --yes; } 2>&1)"
check "plan/apply/rollback output never contains a hash" '! grep -q FIXTURE <<<"$OUT"'
reset; OUT="$(bash "$S" bogus 2>&1)"; RC=$?
check "unknown command: exit 3" '[ "$RC" = 3 ]'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
