#!/usr/bin/env bash
# Live proof on one host (run as root on the validator, or on the sentry via `ssh <sentry> sudo bash -s < host-run.sh`):
#   1. audit                     the host as it is (found)
#   2. apply                     fix the real findings apply may fix (fixed); re-audit (verified)
#   3. plant three fixtures      unpackaged SUID copy of /usr/bin/true, world-writable cron.d file (comment only, cron
#                                refuses insecure files anyway), world-writable script in /usr/local/bin
#   4. audit                     fixtures FAIL
#   5. apply                     fixtures fixed (the SUID copy is in REMOVE_SUID for this run only); re-audit PASS
#   6. undo                      every recorded change of steps 2 and 5 restored, stat + sha256 verified
#   7. audit                     the original findings AND the fixtures are back (undo really restores)
#   8. remove fixtures, apply    final state: real findings fixed, fixtures gone; final audit
# Every pft-privesc call runs the installed /usr/local/bin/pft-privesc with the installed config, plus a temporary
# conf copy for steps 5-6 that adds REMOVE_SUID. Audits in this script write their textfile to a temp dir, never to
# the exporter's (the hourly unit owns that file); apply's own re-audit does write it, which is the live state.
# Output: one "== step" header per step, every command echoed before it runs, CHECK lines, RESULT line.
# shellcheck disable=SC2016,SC2034,SC1091  # ck conditions are single-quoted and eval'd (they read rc1, TF, ...)
set -uo pipefail
PE=/usr/local/bin/pft-privesc
FIX_SUID=/usr/local/sbin/pft-privesc-drill-suid
FIX_CRON=/etc/cron.d/pft-privesc-drill
FIX_PATH=/usr/local/bin/pft-privesc-drill-path
TF="$(mktemp -d)"
CONF2="$(mktemp)"
trap 'rm -rf "$TF" "$CONF2"' EXIT
NOK=0; NBAD=0
x() { echo "\$ $*"; eval "$*"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
ck() { if (eval "$2") > /dev/null 2>&1; then NOK=$((NOK + 1)); echo "CHECK PASS $1"; else NBAD=$((NBAD + 1)); echo "CHECK FAIL $1"; fi; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
[ -x "$PE" ] || { echo "pft-privesc not installed" >&2; exit 2; }
for f in "$FIX_SUID" "$FIX_CRON" "$FIX_PATH"; do [ -e "$f" ] && { echo "fixture $f already exists: refusing" >&2; exit 2; }; done
[ -s /var/lib/pft-privesc/backup/manifest.tsv ] && { echo "apply changes already recorded: refusing" >&2; exit 2; }
echo "pft-privesc drill/host-run.sh - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - $($PE version)"
echo "sha256 $(sha256sum < "$PE" | cut -c1-64) /usr/local/bin/pft-privesc"
echo "sha256 $(sha256sum < /usr/local/lib/pft-privesc/privesc_classify.py | cut -c1-64) privesc_classify.py"
snap() { # snap FILE : mode uid gid + caps of every path a fix touches, and the statoverride list
  { for p in /usr/bin/pkexec /usr/libexec/polkit-agent-helper-1 /usr/bin/chfn /usr/bin/chsh /usr/bin/fusermount3 \
      /usr/lib/openssh/ssh-keysign /usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper \
      "$FIX_SUID" "$FIX_CRON" "$FIX_PATH"; do
      [ -e "$p" ] && printf '%s %s %s\n' "$p" "$(stat -c '%a %u %g' "$p")" "$(getcap "$p" | awk '{print $2}')"
    done; dpkg-statoverride --list | sort; } > "$1"
}

echo "== 1 audit (found)"
x "$PE audit --textfile-dir $TF > $TF/a1.txt"; rc1=$?
grep -vE '^PASS ' "$TF/a1.txt"
snap "$TF/s0"

echo "== 2 apply real findings (fixed), re-audit (verified)"
x "$PE apply"
x "$PE audit --textfile-dir $TF > $TF/a2.txt"; rc2=$?
tail -1 "$TF/a2.txt"
grep -E '^(FAIL|WARN) ' "$TF/a2.txt"
ck "1 the original audit had findings (exit 1)" '[ "$rc1" = 1 ]'
ck "2 after apply: RESULT PASS, exit 0" '[ "$rc2" = 0 ] && grep -q "^RESULT: PASS - 0 fail, 0 warn" "$TF/a2.txt"'
snap "$TF/s1"

echo "== 3 plant fixtures"
x "install -m 4755 /usr/bin/true $FIX_SUID"
x "printf '# pft-privesc drill fixture: comment only, never runs\n' > $FIX_CRON && chmod 0666 $FIX_CRON"
x "printf '#!/bin/sh\necho drill\n' > $FIX_PATH && chmod 0777 $FIX_PATH"

echo "== 4 audit: fixtures FAIL"
x "$PE audit --textfile-dir $TF > $TF/a4.txt"
grep -E '^(FAIL|WARN) |^RESULT' "$TF/a4.txt"
ck "3 planted SUID: FAIL PE-SUID-UNPKG" 'grep -qE "^FAIL PE-SUID-UNPKG +$FIX_SUID: SUID mode 4755, not owned by any package" "$TF/a4.txt"'
ck "4 planted cron file: FAIL PE-EXEC-CRON" 'grep -qE "^FAIL PE-EXEC-CRON +$FIX_CRON: $FIX_CRON world-writable \(mode 0666\)" "$TF/a4.txt"'
ck "5 planted PATH script: FAIL PE-PATH-FILE" 'grep -qE "^FAIL PE-PATH-FILE +$FIX_PATH: $FIX_PATH world-writable \(mode 0777\)" "$TF/a4.txt"'

echo "== 5 apply fixtures (REMOVE_SUID=$FIX_SUID for this run), re-audit"
cp /etc/pft-privesc.env "$CONF2"; echo "REMOVE_SUID=$FIX_SUID" >> "$CONF2"
x "PFT_PE_CONF=$CONF2 $PE apply"
x "PFT_PE_CONF=$CONF2 $PE audit --textfile-dir $TF > $TF/a5.txt"; rc5=$?
tail -1 "$TF/a5.txt"
ck "6 after apply: RESULT PASS, exit 0" '[ "$rc5" = 0 ]'
ck "7 fixture modes: suid 755, cron 644, script 755" '[ "$(stat -c %a $FIX_SUID)" = 755 ] && [ "$(stat -c %a $FIX_CRON)" = 644 ] && [ "$(stat -c %a $FIX_PATH)" = 755 ]'
x "$PE status"

echo "== 6 undo"
x "PFT_PE_CONF=$CONF2 $PE undo"; rc6=$?
ck "8 undo exit 0" '[ "$rc6" = 0 ]'
snap "$TF/s3"

echo "== 7 audit after undo: original findings and fixtures back"
x "$PE audit --textfile-dir $TF > $TF/a7.txt"
grep -E '^(FAIL|WARN) |^RESULT' "$TF/a7.txt"
ck "9 stat + caps of every touched path and the statoverride list equal step 1 (fixtures excepted)" 'diff <(grep -v pft-privesc-drill "$TF/s0") <(grep -v pft-privesc-drill "$TF/s3")'
ck "10 fixtures back to 4755 / 0666 / 0777" '[ "$(stat -c %a $FIX_SUID)" = 4755 ] && [ "$(stat -c %a $FIX_CRON)" = 666 ] && [ "$(stat -c %a $FIX_PATH)" = 777 ]'
ck "11 the step-1 WARN/FAIL lines are all present again" 'diff <(grep -E "^(FAIL|WARN) " "$TF/a1.txt") <(grep -E "^(FAIL|WARN) " "$TF/a7.txt" | grep -v pft-privesc-drill)'

echo "== 8 remove fixtures, apply the real fixes again, final audit"
x "rm -f $FIX_SUID $FIX_CRON $FIX_PATH"
x "$PE apply"
x "$PE audit --textfile-dir $TF > $TF/a8.txt"; rc8=$?
tail -1 "$TF/a8.txt"
ck "12 final: RESULT PASS, exit 0, no fixture left" '[ "$rc8" = 0 ] && [ ! -e $FIX_SUID ] && [ ! -e $FIX_CRON ] && [ ! -e $FIX_PATH ]'
snap "$TF/s4"
ck "13 final permissions equal the step-2 fixed state" 'diff "$TF/s1" "$TF/s4"'
x "$PE status"
echo "RESULT: $NOK checks passed, $NBAD failed"
[ "$NBAD" -eq 0 ]
