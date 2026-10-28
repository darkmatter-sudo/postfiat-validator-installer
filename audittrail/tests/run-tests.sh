#!/usr/bin/env bash
# "cond && ok || bad" is intended: ok() always returns 0, so bad runs only when cond fails. drift() takes its
# setup/undo steps as single-quoted strings on purpose (eval at call time); /etc/os-release is the host's.
# shellcheck disable=SC2015,SC2016,SC1091
# Offline test suite for pft-audittrail.sh - no root, no auditd, no journald changes. auditctl, augenrules,
# journalctl, ausearch, systemctl, dpkg, apt-get and docker are small stateful stubs; every host path lives
# under a temp PFT_AT_ROOT. Fixtures in fixtures/ are real output captured on the sentry and the validator
# (auditctl -s, ausearch --format csv, journalctl --verify of an unsealed journal and of a byte-flipped copy).
# Usage: bash audittrail/tests/run-tests.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AT="${PFT_AT_SCRIPT:-$HERE/../pft-audittrail.sh}"   # PFT_AT_SCRIPT: run the suite against another build
FX="$HERE/fixtures"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }
ind() { sed 's/^/    /'; }

MID=0123456789abcdef0123456789abcdef
CFGVOL=/var/lib/docker/volumes/postfiatd_postfiatd-config/_data
export STUB="$WORK/stub" FX MID
mkdir -p "$STUB" "$WORK/bin"

# --- stubs ---
cat > "$WORK/bin/auditctl" <<'EOF'
#!/usr/bin/env bash
echo "auditctl $*" >> "$STUB/calls.log"
en="$(cat "$STUB/enabled")"
case "$1" in
  -s) sed "s/^enabled .*/enabled $en/" "$FX/auditctl-s.txt" ;;
  -l) if [ -s "$STUB/rules" ]; then cat "$STUB/rules"; else echo "No rules"; fi ;;
  -D) [ "$en" = 2 ] && { echo "Error deleting rule (Operation not permitted)" >&2; exit 1; }; : > "$STUB/rules" ;;
  -W) [ "$en" = 2 ] && { echo "Error deleting rule (Operation not permitted)" >&2; exit 1; }
      grep -v -F -- "-w $2 " "$STUB/rules" > "$STUB/rules.n"; mv "$STUB/rules.n" "$STUB/rules" ;;
  -e) [ "$en" = 2 ] && exit 1; echo "$2" > "$STUB/enabled" ;;
  -w|-a) [ "$en" = 2 ] && { echo "Error sending add rule data request (Operation not permitted)" >&2; exit 1; }; echo "$*" >> "$STUB/rules" ;;
esac
EOF
cat > "$WORK/bin/augenrules" <<'EOF'
#!/usr/bin/env bash
echo "augenrules $*" >> "$STUB/calls.log"
[ "$(cat "$STUB/enabled")" = 2 ] && { echo "The audit system is in immutable mode, no rule changes allowed" >&2; exit 1; }
all="$(cat "${RULES_DIR_ABS:-$PFT_AT_ROOT/etc/audit/rules.d}"/*.rules 2>/dev/null)"
# STUB_BOOT=1: the load runs as auditd.service ExecStartPost. With ProtectHome=yes (Ubuntu's unit) /root and /home
# are hidden: auditctl stops at the first watch below them (ENOENT) and the rest, -e 2 included, never loads.
if [ "${STUB_BOOT:-0}" = 1 ] && [ "$(cat "$STUB/protecthome" 2>/dev/null || echo yes)" = yes ] && grep -qE '^-w /(root|home)/' <<<"$all"; then
  awk '/^-w \/(root|home)\//{exit} /^-[wa] /' <<<"$all" | sed -E '/^-a /s/ -k ([^ ]+)$/ -F key=\1/' > "$STUB/rules"
  echo "Error sending add rule data request (No such file or directory)" >&2; exit 1
fi
grep -E '^-[wa] ' <<<"$all" | sed -E '/^-a /s/ -k ([^ ]+)$/ -F key=\1/' > "$STUB/rules"
grep -qx -- '-e 2' <<<"$all" && echo 2 > "$STUB/enabled"
exit 0
EOF
cat > "$WORK/bin/journalctl" <<'EOF'
#!/usr/bin/env bash
# journald model (enough for the key-change bugs found live): the active file system.journal holds "sealed:<key>"
# or "unsealed"; journald loads the fss key at restart ($STUB/jd_key). Reopening a file sealed under another key
# appends mixed tags (-> $STUB/mixed), reopening it with no key fails and journald stays on /run ($STUB/mode).
echo "journalctl $*" >> "$STUB/calls.log"
j="${JOURNAL_DIR_ABS:-$PFT_AT_ROOT/var/log/journal}/$MID"; a="$j/system.journal"
jd="$(cat "$STUB/jd_key" 2>/dev/null || echo none)"
case "$1" in
  --setup-keys) [ -e "$j/fss" ] && { echo "Sealing key file $j/fss exists already." >&2; exit 1; }
                mkdir -p "$j"; echo "fake-sealing-key-$RANDOM$RANDOM" > "$j/fss"
                echo "New keys have been generated (human text goes to stderr when stdout is not a tty)" >&2
                echo "8f2b7c-1d3e5a-9c4b0f-2e6d8a/1b2c3d-35a4e900" ;;
  --relinquish-var) echo runtime > "$STUB/mode"; touch "$STUB/relinquished" ;;
  --flush) rm -f "$STUB/relinquished"; bash "$STUB/../bin/jd-open" || exit 1 ;;
  --rotate) if [ "$(cat "$STUB/mode" 2>/dev/null)" = var ] && [ -e "$a" ]; then
              n=$(( $(cat "$STUB/seq" 2>/dev/null || echo 0) + 1 )); echo $n > "$STUB/seq"
              mv "$a" "$j/system@${MID}-$(printf %016x $n)-00065eb5efbbaefd.journal"
              if [ "$jd" = none ]; then echo unsealed > "$a"; else echo "sealed:$jd" > "$a"; fi; echo "seq:$RANDOM" >> "$a"
            fi ;;
  --header) f="${2#--file=}"; [ -e "$f" ] || exit 1
            echo "Sequential number ID: $MID"; echo "State: ONLINE"
            grep -q '^sealed:' "$f" && echo "Compatible flags: SEALED" || echo "Compatible flags:"
            q="$(sed -n 's/^seq://p' "$f")"; q="${q:-10}"; echo "Head sequential number: $q ($(printf %x "$q"))"; echo "Head realtime timestamp: Mon 2026-10-26 03:29:24 UTC (65eb5efbbaefd)" ;;
  --verify) out="$(sed "s#<machine-id>#$MID#" "$FX/journalctl-verify-unsealed.txt")"; key=no
            case " $* " in *" --verify-key="*) key=yes ;; esac
            if [ -e "$STUB/verify_flipped" ]; then printf '%s\n' "$out"; sed "s#copy.journal#$j/system@flipped.journal#" "$FX/journalctl-verify-flipped.txt"; exit 1; fi
            printf '%s\n' "$out"
            # once FSS keys exist the active file is sealed: real journalctl refuses it without the key
            if [ -e "$j/fss" ] && [ $key = no ]; then sed "s#<machine-id>#$MID#" "$FX/journalctl-verify-sealed-nokey.txt"; exit 1; fi
            [ -e "$j/fss" ] && echo "PASS: $j/system.journal" ;;
esac
EOF
cat > "$WORK/bin/jd-open" <<'EOF'
#!/usr/bin/env bash
# journald (re)opening /var: called at restart (unless relinquished) and by --flush
j="${JOURNAL_DIR_ABS:-$PFT_AT_ROOT/var/log/journal}/$MID"; a="$j/system.journal"
jd="$(cat "$STUB/jd_key" 2>/dev/null || echo none)"
[ -e "$STUB/relinquished" ] && exit 0
mkdir -p "$j"
if [ ! -e "$a" ]; then
  if [ "$jd" = none ]; then echo unsealed > "$a"; else echo "sealed:$jd" > "$a"; fi; echo "seq:$RANDOM" >> "$a"
elif grep -q '^sealed:' "$a"; then
  k="$(sed 's/^sealed://' "$a")"
  if [ "$jd" = none ]; then echo runtime > "$STUB/mode"; echo "open $a: Required key not available" >&2; exit 1; fi
  [ "$k" = "$jd" ] || echo "mixed: file sealed:$k reopened with key $jd" >> "$STUB/mixed"
fi
echo var > "$STUB/mode"
EOF
cat > "$WORK/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB/calls.log"
case "$1 ${2:-}" in
  "restart systemd-journald") # journald Audit= (default no) sets kernel auditing at start; immutable (2) cannot change
    f="${JOURNAL_DIR_ABS:-$PFT_AT_ROOT/var/log/journal}/$MID/fss"
    if [ -e "$f" ]; then cat "$f" > "$STUB/jd_key"; else echo none > "$STUB/jd_key"; fi
    bash "$STUB/../bin/jd-open" 2>/dev/null
    en="$(cat "$STUB/enabled")"
    if [ "$en" != 2 ]; then
      if grep -qx 'Audit=yes' "${JOURNALD_DIR_ABS:-$PFT_AT_ROOT/etc/systemd/journald.conf.d}"/*.conf 2>/dev/null; then echo 1 > "$STUB/enabled"; else echo 0 > "$STUB/enabled"; fi
    fi ;;
  "is-active auditd") cat "$STUB/auditd_active"; [ "$(cat "$STUB/auditd_active")" = active ] ;;
  "stop auditd") echo inactive > "$STUB/auditd_active" ;;
  "daemon-reload ") d="${AUDITD_UNIT_DIR_ABS:-$PFT_AT_ROOT/etc/systemd/system/auditd.service.d}"
    if grep -qx 'ProtectHome=read-only' "$d"/*.conf 2>/dev/null; then echo read-only > "$STUB/protecthome"; else echo yes > "$STUB/protecthome"; fi ;;
  "show -p") cat "$STUB/protecthome" 2>/dev/null || echo yes ;;
esac
exit 0
EOF
cat > "$WORK/bin/dpkg" <<'EOF'
#!/usr/bin/env bash
[ -e "$STUB/installed" ] && { echo "Package: auditd"; echo "Status: install ok installed"; exit 0; }
echo "dpkg-query: package 'auditd' is not installed and no information is available" >&2; exit 1
EOF
cat > "$WORK/bin/apt-get" <<'EOF'
#!/usr/bin/env bash
echo "apt-get $*" >> "$STUB/calls.log"
case "$1" in
  install) touch "$STUB/installed"; echo active > "$STUB/auditd_active" ;;
  remove) rm -f "$STUB/installed"; echo inactive > "$STUB/auditd_active" ;;
esac
EOF
cat > "$WORK/bin/docker" <<EOF
#!/usr/bin/env bash
[ "\$1 \$2" = "inspect postfiatd" ] || exit 1
case "\$*" in *Mounts*) echo "$CFGVOL" ;; *) echo '[{}]' ;; esac
EOF
cat > "$WORK/bin/ausearch" <<'EOF'
#!/usr/bin/env bash
echo "ausearch $*" >> "$STUB/calls.log"
case " $* " in *" --input-logs "*) ;; *) echo "stub: called without --input-logs (would read stdin)" >&2; exit 9 ;; esac
k=""; while [ $# -gt 0 ]; do [ "$1" = -k ] && k="$2"; shift; done
[ -e "$STUB/ausearch-$k.csv" ] && { cat "$STUB/ausearch-$k.csv"; exit 0; }
echo "<no matches>" >&2; exit 1
EOF
chmod +x "$WORK/bin/"*

reset_host() { # fresh fake root: installer defaults, no auditd, unsealed persistent journal
  rm -rf "$WORK/root" "$STUB"; mkdir -p "$STUB"
  local r="$WORK/root"
  export PFT_AT_ROOT="$r"
  mkdir -p "$r$CFGVOL" "$r/opt/postfiatd" "$r/etc/ssh/sshd_config.d" "$r/etc/sudoers.d" "$r/etc/systemd/system" \
           "$r/usr/bin" "$r/etc/pft-watchdog" "$r/srv/agent" "$r/var/log/journal/$MID" "$r/etc/audit/rules.d" \
           "$r/usr/local/bin"
  touch "$r$CFGVOL/postfiatd.cfg" "$r$CFGVOL/validator-keys.json" "$r/opt/postfiatd/docker-compose.yml" \
        "$r/etc/ssh/sshd_config" "$r/etc/sudoers" "$r/usr/bin/docker" "$r/usr/bin/dockerd" "$r/usr/bin/kmod" \
        "$r/etc/localtime" "$r/usr/local/bin/pft-integrity" "$r/etc/pft-integrity.env"
  echo 1 > "$STUB/enabled"; echo inactive > "$STUB/auditd_active"; : > "$STUB/rules"
  echo unsealed > "$r/var/log/journal/$MID/system.journal"; echo none > "$STUB/jd_key"; echo var > "$STUB/mode"
}
run() { env PATH="$WORK/bin:$PATH" AGENT_DIRS=/srv/agent PFT_AT_TEST=1 PFT_AT_MACHINE_ID="$MID" STATE_DIR=/var/lib/pft-audittrail bash "$AT" "$@"; }
R() { echo "$WORK/root$1"; }

echo "# pft-audittrail unit tests - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - bash $BASH_VERSION"

# --- 1. plan ---
reset_host
out="$(run plan 2>&1)"; rc=$?
[ $rc -eq 0 ] && ok "plan exits 0" || bad "plan rc=$rc"
grep -q -- "-w /etc/ssh/sshd_config -p wa -k pft-ssh" <<<"$out" && grep -q -- "-w $CFGVOL -p wa -k pft-cfg" <<<"$out" \
  && ok "plan: sshd + node config volume (discovered via docker inspect) watched" || { bad "plan watches"; ind <<<"$out"; }
! grep -q -e validator-keys -e /srv/agent -e /etc/pft-watchdog <<<"$out" && grep -q -- "-w <redacted> -p wa -k pft-keys" <<<"$out" \
  && grep -q -- "-w <redacted> -p wa -k pft-agent" <<<"$out" \
  && ok "plan: pft-keys / pft-agent paths redacted" || { bad "plan prints secret paths"; ind <<<"$out"; }
grep -q "skip pft-ssh /root/.ssh/authorized_keys (absent)" <<<"$out" && ! grep -q -- "-w /root/.ssh" <<<"$out" \
  && ok "plan: absent path skipped, not watched" || bad "absent path handling"
grep -q -- "-S execve -F exe=/usr/bin/docker -F auid>=1000 -F auid!=unset -k pft-exec" <<<"$out" && grep -q -- "-S execve -F exe=/usr/bin/docker -F auid=0 -k pft-exec" <<<"$out" \
  && grep -q -- "-S init_module,finit_module,delete_module -k pft-modules" <<<"$out" && grep -q -- "-S adjtimex,settimeofday,clock_settime -k pft-time" <<<"$out" \
  && ok "plan: execve (auid>=1000 + root logins), module-load and time-change rules" || bad "syscall rules"
out2="$(run plan --immutable)"; grep -q "immutable: off" <<<"$out" && grep -qx -- "-e 2" <<<"$out2" && ok "plan: -e 2 only with --immutable" || bad "immutable plan"
[ ! -e "$(R /var/lib/pft-audittrail)" ] && [ ! -s "$STUB/calls.log" ] && ok "plan changed nothing" || bad "plan wrote something"

# --- 2. refusals + dry-run ---
run apply --container postfiatd >/dev/null 2>&1; rc=$?
[ $rc -eq 4 ] && ok "apply without --yes refused (exit 4)" || bad "apply no --yes rc=$rc"
out="$(run apply --yes 2>&1)"; rc=$?
[ $rc -eq 4 ] && grep -q "pass --key-out FILE" <<<"$out" && ok "apply without --key-out refused while no FSS key exists (exit 4)" || bad "key-out guard rc=$rc: $out"
out="$(run apply --yes --dry-run 2>&1)"; rc=$?
[ $rc -eq 0 ] && grep -q "dry-run: nothing changed" <<<"$out" && grep -q "^+-w /etc/sudoers -p wa -k pft-sudo" <<<"$out" \
  && [ ! -e "$(R /etc/audit/rules.d/pft-audittrail.rules)" ] && [ ! -e "$STUB/installed" ] \
  && ok "apply --dry-run: diff printed, nothing changed" || { bad "dry-run rc=$rc"; ind <<<"$out"; }

# --- 3. apply ---
out="$(run apply --yes --key-out "$WORK/vkey" 2>&1)"; rc=$?
n="$(grep -c '^-[wa] ' "$(R /etc/audit/rules.d/pft-audittrail.rules)")"
[ $rc -eq 0 ] && [ -e "$STUB/installed" ] && [ "$(grep -c . "$STUB/rules")" -eq "$n" ] && [ "$n" -gt 15 ] \
  && ok "apply: auditd installed, $n rules written and loaded" || { bad "apply rc=$rc"; ind <<<"$out"; }
[ "$(stat -c %a "$WORK/vkey")" = 600 ] && grep -q '/1b2c3d-35a4e900$' "$WORK/vkey" && ! grep -q 8f2b7c <<<"$out" \
  && grep -q "sha256 prefix $(sha256sum "$WORK/vkey" | cut -c1-12)" <<<"$out" \
  && ok "apply: verification key only in --key-out (0600), stdout shows a sha256 prefix" || { bad "key handling"; ind <<<"$out"; }
grep -qx "Seal=yes" "$(R /etc/systemd/journald.conf.d/pft-audittrail.conf)" && grep -qx "Storage=persistent" "$(R /etc/systemd/journald.conf.d/pft-audittrail.conf)" \
  && grep -q "systemctl restart systemd-journald" "$STUB/calls.log" && grep -q "journalctl --rotate" "$STUB/calls.log" \
  && ok "apply: journald drop-in, restart + rotate" || bad "journald setup"
[ "$(stat -c %a "$(R /var/lib/pft-audittrail/salt)")" = 600 ] && [ -e "$(R /var/lib/pft-audittrail/canary)" ] \
  && ok "apply: root-only salt + canary file" || bad "salt/canary"
out="$(run apply --yes --key-out "$WORK/vkey" 2>&1)"; rc=$?
[ $rc -eq 4 ] && grep -q "refusing to overwrite" <<<"$out" && ok "apply refuses to overwrite an existing key file" || bad "overwrite guard rc=$rc"
cp "$STUB/rules" "$WORK/rules.1"; : > "$STUB/calls.log"
out="$(run apply --yes 2>&1)"; rc=$?
[ $rc -eq 0 ] && cmp -s "$STUB/rules" "$WORK/rules.1" && ! grep -q -e setup-keys -e "apt-get install" "$STUB/calls.log" \
  && ok "re-apply: idempotent, no new keys, no reinstall" || { bad "re-apply rc=$rc"; ind <<<"$out"; }

# --- 4. check ---
out="$(run check 2>&1)"; rc=$?
[ $rc -eq 0 ] && grep -q "RESULT: PASS" <<<"$out" && ok "check PASS after apply" || { bad "check rc=$rc"; ind <<<"$out"; }
grep -q "1 sealed file(s) need the off-host key" <<<"$out" && ok "check: sealed file without key = expected (counted, not failed)" || { bad "sealed nokey"; ind <<<"$out"; }
out="$(run check --verify-key-file "$WORK/vkey" 2>&1)"; grep -q "verify-key: 4 files PASS$" <<<"$out" && ok "check --verify-key-file: sealed file verified too (4 PASS)" || { bad "verify with key"; ind <<<"$out"; }
grep -qx "Audit=yes" "$(R /etc/systemd/journald.conf.d/pft-audittrail.conf)" && [ "$(cat "$STUB/enabled")" = 1 ] \
  && ok "apply: drop-in has Audit=yes, auditing still enabled after the journald restart" || bad "Audit=yes regression"
run check --verify-key-file "$WORK/vkey" >/dev/null 2>&1 && grep -q -- "--verify --verify-key=8f2b7c" "$STUB/calls.log" \
  && ok "check --verify-key-file passes the key to journalctl --verify" || bad "verify key not passed"
out="$(run check 2>&1)"; ! grep -q "$MID" <<<"$out" && ok "check output carries no machine-id paths" || bad "machine-id leaked"

drift() { # NAME SETUP UNDO EXPECT
  eval "$2"; out="$(run check 2>&1)"; rc=$?
  [ $rc -eq 1 ] && grep -q -- "$4" <<<"$out" && ok "drift: $1 -> exit 1 ($4)" || { bad "drift $1 rc=$rc"; ind <<<"$out"; }
  eval "$3"
}
drift "watch deleted (auditctl -W)" 'cp "$STUB/rules" "$WORK/r.bak"; PATH="$WORK/bin:$PATH" auditctl -W /etc/ssh/sshd_config -p wa -k pft-ssh' \
  'cp "$WORK/r.bak" "$STUB/rules"' "differ from apply snapshot"
drift "all rules flushed (auditctl -D)" 'cp "$STUB/rules" "$WORK/r.bak"; : > "$STUB/rules"' 'cp "$WORK/r.bak" "$STUB/rules"' "loaded pft-\* rules 0 != rules file"
drift "rule swapped, same count" 'cp "$STUB/rules" "$WORK/r.bak"; sed -i "s/-k pft-sudo/-k pft-sudx/" "$STUB/rules"' 'cp "$WORK/r.bak" "$STUB/rules"' "differ from apply snapshot"
drift "auditd stopped" 'echo inactive > "$STUB/auditd_active"' 'echo active > "$STUB/auditd_active"' "auditd not active"
drift "audit disabled (enabled 0)" 'echo 0 > "$STUB/enabled"' 'echo 1 > "$STUB/enabled"' "enabled=0 (expected 1)"
drift "journal byte-flipped" 'touch "$STUB/verify_flipped"' 'rm -f "$STUB/verify_flipped"' "FAIL: system@flipped.journal (Bad message)"
drift "FSS key removed" 'mv "$(R /var/log/journal/$MID/fss)" "$WORK/fss.bak"' 'mv "$WORK/fss.bak" "$(R /var/log/journal/$MID/fss)"' "FSS sealing key missing"
drift "journald drop-in edited (Seal=no)" 'sed -i s/Seal=yes/Seal=no/ "$(R /etc/systemd/journald.conf.d/pft-audittrail.conf)"' \
  'sed -i s/Seal=no/Seal=yes/ "$(R /etc/systemd/journald.conf.d/pft-audittrail.conf)"' "journald drop-in missing or changed"
drift "rules file deleted" 'mv "$(R /etc/audit/rules.d/pft-audittrail.rules)" "$WORK/rf.bak"' 'mv "$WORK/rf.bak" "$(R /etc/audit/rules.d/pft-audittrail.rules)"' "rules file .* missing"
out="$(run check 2>&1)"; rc=$?
[ $rc -eq 0 ] && ok "check PASS again after every drift was undone" || { bad "post-drift check rc=$rc"; ind <<<"$out"; }
cp "$STUB/rules" "$WORK/r.bak"; sed -i 's#^-w /srv/agent#-w /srv/agentX#' "$STUB/rules"
out="$(run check 2>&1)"; ! grep -q "/srv/agent" <<<"$out" && grep -q "<redacted> -p wa -k pft-agent" <<<"$out" \
  && ok "check drift diff redacts pft-agent/pft-keys paths" || { bad "drift diff leaks path"; ind <<<"$out"; }
cp "$WORK/r.bak" "$STUB/rules"

# --- 5. report ---
cp "$FX/ausearch-pft-fixture.csv" "$STUB/ausearch-pft-canary.csv"
{ cat "$FX/ausearch-pft-fixture.csv"; echo ",SYSCALL,10/26/26,04:20:00,200,audit-rule,9500,alice,root,privileged-acct,opened-file,success,/opt/postfiatd/secret-name.json,1,file,bash"; } \
  > "$STUB/ausearch-pft-keys.csv"   # last line synthetic: a non-root auid on a pft-keys object
out="$(run report --since recent 2>&1)"; rc=$?
salt="$(cat "$(R /var/lib/pft-audittrail/salt)")"; hu="u-$(printf '%s%s' "$salt" alice | sha256sum | cut -c1-8)"
[ $rc -eq 0 ] && grep -q "^| pft-canary | 4 | root (4) | auditctl (3), bash (1) | (rule change) (3), /tmp/pft-at-fixture.Zyju/watched (1) |$" <<<"$out" \
  && ok "report: real ausearch csv -> counts by auid/command/object" || { bad "report rc=$rc"; ind <<<"$out"; }
grep -q "| pft-keys | 5 | root (4), $hu (1) |" <<<"$out" && ! grep -q -e alice -e secret-name <<<"$out" && grep -q "| (rule change) (3), <redacted> (2) |$" <<<"$out" \
  && ok "report: username hashed ($hu), pft-keys object redacted" || { bad "report hashing/redaction"; ind <<<"$out"; }
grep -q "^| pft-ssh | 0 | | | |$" <<<"$out" && ! grep -q "without --input-logs" <<<"$out" \
  && ok "report: keys with no events listed as 0; ausearch always run with --input-logs" || bad "report zero rows"
cp "$FX/ausearch-units-nopath.csv" "$STUB/ausearch-pft-units.csv"   # real sentry rows: install's fchmod, no OBJ_PRIME
out="$(run report --since recent 2>&1)"
grep -q '^| pft-units | 2 | root (2) | install (2) | (no path: changed-file-attributes-of) (2) |$' <<<"$out" \
  && ok "report: path-less (fd) events named by action, never an empty object" || { bad "report path-less rows"; ind <<<"$out"; }

# --- 6. immutable + rollback ---
out="$(run apply --yes --immutable 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ "$(cat "$STUB/enabled")" = 2 ] && grep -qx -- "-e 2" "$(R /etc/audit/rules.d/zz-pft-audittrail-immutable.rules)" \
  && ok "apply --immutable: -e 2 file sorts last, kernel enabled=2" || { bad "immutable apply rc=$rc"; ind <<<"$out"; }
run check >/dev/null 2>&1 && ok "check PASS with immutable (expects enabled 2)" || bad "immutable check"
PATH="$WORK/bin:$PATH" auditctl -D 2>"$WORK/d.err"; rc=$?
[ $rc -eq 1 ] && grep -q "Operation not permitted" "$WORK/d.err" && [ -s "$STUB/rules" ] && ok "immutable: auditctl -D refused, rules kept" || bad "immutable -D"
out="$(run rollback --yes 2>&1)"; rc=$?
[ $rc -eq 2 ] && grep -q "IMMUTABLE" <<<"$out" && [ ! -e "$(R /etc/audit/rules.d/pft-audittrail.rules)" ] && [ ! -e "$(R /var/log/journal/$MID/fss)" ] \
  && [ -e "$STUB/installed" ] && ok "rollback while immutable: files removed, exit 2 (reboot pending), auditd kept" || { bad "immutable rollback rc=$rc"; ind <<<"$out"; }
echo 1 > "$STUB/enabled"; : > "$STUB/rules"   # = reboot: kernel rules gone, auditd loads rules.d at boot
out="$(run rollback --yes 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ ! -e "$STUB/installed" ] && [ ! -e "$(R /var/lib/pft-audittrail)" ] && ! grep -q pft- "$STUB/rules" \
  && ok "rollback after reboot: auditd removed (installed by apply), state gone" || { bad "rollback after reboot rc=$rc"; ind <<<"$out"; }

reset_host; touch "$STUB/installed"; echo active > "$STUB/auditd_active"
run apply --yes --key-out "$WORK/vkey2" >/dev/null 2>&1
out="$(run rollback --yes --dry-run)"; grep -q "kept (was installed before apply)" <<<"$out" && [ -e "$(R /etc/audit/rules.d/pft-audittrail.rules)" ] \
  && ok "rollback --dry-run changes nothing, keeps a pre-existing auditd" || bad "rollback dry-run"
out="$(run rollback --yes 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ -e "$STUB/installed" ] && ! grep -q pft- "$STUB/rules" && [ ! -e "$(R /etc/systemd/journald.conf.d/pft-audittrail.conf)" ] \
  && ok "rollback: rules + drop-in gone, pre-existing auditd kept" || { bad "rollback rc=$rc"; ind <<<"$out"; }
[ "$(cat "$STUB/enabled")" = 1 ] && grep -q "journald restart disabled kernel auditing; re-enabled: enabled=1" <<<"$out" \
  && ok "rollback: kernel auditing re-enabled after journald (Audit=no default) restart" || { bad "rollback left auditing off (enabled=$(cat "$STUB/enabled"))"; ind <<<"$out"; }
out="$(run check 2>&1)"; rc=$?
[ $rc -eq 1 ] && grep -q "not applied" <<<"$out" && ok "check after rollback: FAIL (not applied)" || bad "check after rollback rc=$rc"

# --- 7. production-shaped run: empty PFT_AT_ROOT, absolute dirs (the live rollback drill hit ${R:?} here) ---
reset_host; touch "$STUB/installed"; echo active > "$STUB/auditd_active"
P="$WORK/prod"; rm -rf "$P"; mkdir -p "$P/rules.d" "$P/journald.conf.d" "$P/journal/$MID"
prun() { env PATH="$WORK/bin:$PATH" AGENT_DIRS=/srv/agent PFT_AT_TEST=1 PFT_AT_ROOT= PFT_AT_MACHINE_ID="$MID" RULES_DIR="$P/rules.d" JOURNALD_DIR="$P/journald.conf.d" \
  AUDITD_UNIT_DIR="$P/auditd.service.d" AUDITD_UNIT_DIR_ABS="$P/auditd.service.d" \
  JOURNAL_DIR="$P/journal" JOURNAL_DIR_ABS="$P/journal" STATE_DIR="$P/state" RULES_DIR_ABS="$P/rules.d" JOURNALD_DIR_ABS="$P/journald.conf.d" CONTAINER=none bash "$AT" "$@"; }
out="$(prun apply --yes --key-out "$WORK/vkey3" 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ -e "$P/state/state.json" ] && ok "empty PFT_AT_ROOT: apply ok" || { bad "prod apply rc=$rc"; ind <<<"$out"; }
out="$(prun rollback --yes 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ ! -e "$P/state" ] && ! grep -q "parameter null" <<<"$out" && ok "empty PFT_AT_ROOT: rollback removes the state dir, exit 0" || { bad "prod rollback rc=$rc"; ind <<<"$out"; }

# --- 8. FSS key change: rollback + re-apply must not mix keys in one file or leave journald on /run ---
# (found live on the sentry: a re-apply sealed one file under two keys -> "Epoch sequence out of synchronization",
#  and after rollback journald could not reopen the sealed active file and logged to the volatile /run journal)
reset_host; touch "$STUB/installed"; echo active > "$STUB/auditd_active"
J="$(R /var/log/journal/$MID)"
run apply --yes --key-out "$WORK/k1" >/dev/null 2>&1; k1="$(sed 's/^sealed://' "$J/system.journal")"
out="$(run rollback --yes 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ "$(cat "$STUB/mode")" = var ] && grep -qx unsealed "$J/system.journal" \
  && ok "rollback: journald back on /var with a fresh unsealed system.journal" || { bad "rollback left journald on $(cat "$STUB/mode") rc=$rc"; ind <<<"$out"; }
arch=""; for f in "$J"/system@"$MID"-*-00065eb5efbbaefd.journal; do grep -qx "sealed:$k1" "$f" 2>/dev/null && arch="$f"; done
[ -n "$arch" ] && [[ "$(basename "$arch")" =~ ^system@${MID}-[0-9a-f]{16}-00065eb5efbbaefd\.journal$ ]] \
  && ok "rollback: the sealed active file was archived under journald's name (system@<seqnum id>-<head seq>-<head rt>)" || { bad "no archive"; find "$J" -type f | ind; }
out="$(run apply --yes --key-out "$WORK/k2" 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ ! -s "$STUB/mixed" ] && ! grep -qx "sealed:$k1" "$J/system.journal" \
  && ok "re-apply with new keys: no file sealed under two keys" || { bad "re-apply rc=$rc mixed: $(cat "$STUB/mixed" 2>/dev/null)"; ind <<<"$out"; }
# key change with the old key still loaded (fss deleted by hand, journald not restarted)
rm -f "$J/fss"; : > "$STUB/mixed"
out="$(run apply --yes --key-out "$WORK/k3" 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ ! -s "$STUB/mixed" ] && [ "$(cat "$STUB/mode")" = var ] && grep -q '^sealed:' "$J/system.journal" \
  && ok "re-key while the old key is loaded: old file archived, new file sealed, no mixing" || { bad "re-key rc=$rc mixed: $(cat "$STUB/mixed" 2>/dev/null)"; ind <<<"$out"; }

# --- 9. boot-time rule load (found live: sentry reboot loaded 11 of 42 rules and no -e 2) ---
# auditd.service loads rules.d at boot as ExecStartPost with ProtectHome=true, so /root/.ssh/authorized_keys is
# ENOENT there and auditctl aborts. apply installs a ProtectHome=read-only drop-in; check verifies it.
boot() { : > "$STUB/rules"; echo 1 > "$STUB/enabled"; env PATH="$WORK/bin:$PATH" STUB_BOOT=1 augenrules --load 2>/dev/null; }
reset_host; touch "$STUB/installed"; echo active > "$STUB/auditd_active"; mkdir -p "$(R /root/.ssh)"; touch "$(R /root/.ssh/authorized_keys)"
out="$(run apply --yes --immutable --key-out "$WORK/k9" 2>&1)"; rc=$?
DI="$(R /etc/systemd/system/auditd.service.d/pft-audittrail.conf)"
[ $rc -eq 0 ] && grep -qx 'ProtectHome=read-only' "$DI" && grep -q "systemctl daemon-reload" "$STUB/calls.log" \
  && grep -q -- "-w /root/.ssh/authorized_keys -p wa -k pft-ssh" "$(R /etc/audit/rules.d/pft-audittrail.rules)" \
  && ok "apply: auditd.service drop-in ProtectHome=read-only + daemon-reload (a /root watch is in the rules)" || { bad "auditd drop-in rc=$rc"; ind <<<"$out"; }
n="$(grep -c '^-[wa] ' "$(R /etc/audit/rules.d/pft-audittrail.rules)")"; boot
[ "$(grep -c . "$STUB/rules")" -eq "$n" ] && [ "$(cat "$STUB/enabled")" = 2 ] \
  && ok "simulated boot with the drop-in: all $n rules + -e 2 load inside auditd.service" || bad "boot with drop-in: $(grep -c . "$STUB/rules")/$n rules, enabled $(cat "$STUB/enabled")"
run check >/dev/null 2>&1 && ok "check PASS after the simulated boot (immutable)" || { bad "check after boot"; run check 2>&1 | ind; }
out="$(run check 2>&1)"; grep -q "PASS\] auditd.service ProtectHome=read-only" <<<"$out" && ok "check reports ProtectHome=read-only" || { bad "check ProtectHome line"; ind <<<"$out"; }
# negative control: Ubuntu's stock unit (drop-in absent) -> the boot load aborts; check must see it BEFORE a reboot
mv "$DI" "$WORK/di.bak"; env PATH="$WORK/bin:$PATH" systemctl daemon-reload; boot
[ "$(grep -c . "$STUB/rules")" -lt "$n" ] && [ "$(cat "$STUB/enabled")" = 1 ] \
  && ok "control: without the drop-in the simulated boot aborts ($(grep -c . "$STUB/rules")/$n rules, enabled 1)" || bad "control boot did not abort"
out="$(run check 2>&1)"; rc=$?
[ $rc -eq 1 ] && grep -q "auditd.service drop-in .* missing or changed" <<<"$out" && ok "check: missing auditd.service drop-in -> FAIL" || { bad "check missing drop-in rc=$rc"; ind <<<"$out"; }
cp "$WORK/di.bak" "$DI"; echo yes > "$STUB/protecthome"   # file back, but no daemon-reload yet
out="$(run check 2>&1)"; rc=$?
[ $rc -eq 1 ] && grep -q "ProtectHome=yes: the boot-time rule load cannot see the /root watches" <<<"$out" \
  && ok "check: drop-in present but not loaded (ProtectHome=yes) -> FAIL" || { bad "check daemon-reload pending rc=$rc"; ind <<<"$out"; }
env PATH="$WORK/bin:$PATH" systemctl daemon-reload; echo 1 > "$STUB/enabled"
out="$(run rollback --yes 2>&1)"; rc=$?
[ $rc -eq 0 ] && [ ! -e "$DI" ] && [ "$(cat "$STUB/protecthome")" = yes ] && ok "rollback removes the auditd.service drop-in + daemon-reload" || { bad "rollback drop-in rc=$rc"; ind <<<"$out"; }

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
