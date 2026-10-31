#!/usr/bin/env bash
# Stubbed tests for pft-privesc.sh + privesc_classify.py. No root, no real dpkg/systemd/docker/sudo; no host file is
# touched. Each case builds a fresh fake root (PFT_PE_ROOT) in a temp dir; files there belong to the test user, who
# is treated as root (PFT_PE_ROOT_UID). stubs.py stands in for dpkg, dpkg-statoverride, getcap, setcap, systemctl,
# getent, docker, visudo, runuser and chown (see its docstring). Owner-based checks (a file owned by another uid)
# cannot be built without root; tests/test_owner.py covers those by patching os.lstat.
# One PASS/FAIL line per check; exit 1 if any failed.
#   Usage: tests/run-tests.sh [PFT_PRIVESC_SH] [PRIVESC_CLASSIFY_PY]
# shellcheck disable=SC2016,SC2034,SC2119,SC2120  # check conditions are single-quoted and eval'd by check()
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$(readlink -f "${1:-$HERE/../pft-privesc.sh}")"
CLASSPY="$(readlink -f "${2:-$HERE/../privesc_classify.py}")"
T="$(mktemp -d)"
trap 'chmod -R u+rwX "${T:?}" 2>/dev/null; rm -rf "${T:?}"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $*"; [ -z "${PFT_TEST_DEBUG:-}" ] || sed 's/^/    | /' "$T/out" | head -"$PFT_TEST_DEBUG"; }
# check NAME 'CONDITION' : condition runs in a subshell, so an exit inside it cannot end the suite
check() { if (eval "$2") >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

mkdir -p "$T/bin" "$T/lib"
for s in dpkg dpkg-statoverride getcap setcap systemctl getent docker visudo runuser chown; do
  printf '#!/bin/sh\nexec python3 %q %s "$@"\n' "$HERE/stubs.py" "$s" > "$T/bin/$s"; chmod +x "$T/bin/$s"
done
cp "$CLASSPY" "$T/lib/privesc_classify.py"
MYUID="$(id -u)"
export PATH="$T/bin:$PATH" PFT_PE_LIB="$T/lib" PFT_PE_NOW=1800000000 PFT_PE_CONF="$T/env" \
  PFT_PE_ROOT_UID="$MYUID" PFT_PE_DPKG="$T/bin/dpkg" PFT_PE_STATOVERRIDE="$T/bin/dpkg-statoverride" \
  PFT_PE_GETCAP="$T/bin/getcap" PFT_PE_SETCAP="$T/bin/setcap" PFT_PE_SYSTEMCTL="$T/bin/systemctl" \
  PFT_PE_GETENT="$T/bin/getent" PFT_PE_DOCKER="$T/bin/docker" PFT_PE_VISUDO="$T/bin/visudo" \
  PFT_PE_RUNUSER="$T/bin/runuser"
ME="$(id -un)"

mk() { # mk MODE PATH [CONTENT] : file under the fake root
  mkdir -p "$(dirname "$R$2")"; [ -e "$R$2" ] && chmod u+w "$R$2"; printf '%s\n' "${3:-x}" > "$R$2"; chmod "$1" "$R$2"
}
# fresh : new fake root R + stub dir STUB with a clean Ubuntu-like baseline (3 unneeded SUID, 1 unneeded cap)
fresh() {
  N=$((N + 1)); R="$T/root.$N"; STUB="$T/stub.$N"; TF="$R/textfile"
  mkdir -p "$R" "$STUB" "$TF" "$R/var/lib/pft-privesc"
  export PFT_PE_ROOT="$R" STUB
  for p in /usr/bin/sudo /usr/bin/passwd /usr/bin/pkexec /usr/bin/chfn /usr/lib/openssh/ssh-keysign; do mk 4755 "$p"; done
  mk 2755 /usr/bin/crontab
  mk 755 /usr/bin/true; mk 755 /usr/bin/vim; mk 755 /usr/local/bin/pft-tool; mk 755 /usr/sbin/cron
  mk 755 /usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper; mk 755 /usr/bin/ping
  ln -s usr/bin "$R/bin"   # usrmerge: dpkg knows some files as /bin/x
  mk 440 /etc/sudoers 'Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults use_pty
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d'
  mk 440 /etc/sudoers.d/90-agent "$ME ALL=(ALL) NOPASSWD:ALL"
  mk 440 /etc/sudoers.d/README '# ignored by nothing, parsed like any file'
  mk 644 /etc/crontab '17 * * * * root cd / && run-parts --report /etc/cron.hourly'
  mk 755 /etc/cron.hourly/pft-hourly '#!/bin/sh'
  mk 644 /etc/cron.d/pft-job '*/5 * * * * root /usr/local/bin/pft-tool --quiet'
  mk 644 /lib/systemd/system/pft-tool.service '[Service]'
  mk 644 /lib/systemd/system/cron.service '[Service]'
  mkdir -p "$R/run/containerd"; mk 660 /run/containerd/containerd.sock
  printf '%s\n' "/usr/bin/sudo	sudo" "/usr/bin/passwd	passwd" "/usr/bin/pkexec	pkexec" "/usr/bin/chfn	passwd" \
    "/usr/lib/openssh/ssh-keysign	openssh-client" "/usr/bin/crontab	cron" "/bin/fusermount3	fuse3" \
    "/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper	libgstreamer1.0-0:amd64" \
    "/usr/bin/ping	iputils-ping" > "$STUB/dpkg-owners.tsv"
  printf '%s\t%s\n' "$R/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper" "cap_net_bind_service,cap_net_admin=ep" \
    "$R/usr/bin/ping" "cap_net_raw=ep" > "$STUB/caps.tsv"
  echo "root root 2755 /usr/bin/crontab" > "$STUB/statoverride"
  cat > "$STUB/units.show" <<UNITS
Id=pft-tool.service
User=
FragmentPath=/lib/systemd/system/pft-tool.service
DropInPaths=
ExecStart={ path=/usr/local/bin/pft-tool ; argv[]=/usr/local/bin/pft-tool --run ; ignore_errors=no }

Id=cron.service
User=
FragmentPath=/lib/systemd/system/cron.service
DropInPaths=
ExecStart={ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f ; ignore_errors=no }
UNITS
  printf 'root:x:0:0::/root:/bin/bash\n%s:x:1001:1001::/home/%s:/bin/bash\nlxd:x:998:119::/var/snap/lxd:/bin/false\n' \
    "$ME" "$ME" > "$STUB/passwd"
  printf 'root:x:0:\nsudo:x:27:\ndocker:x:120:%s\nlxd:x:119:\ndisk:x:6:\n' "$ME" > "$STUB/group"
  : > "$STUB/docker-ps"
  printf 'TEXTFILE_DIR=%s\nAGENT_USER=%s\n' "$TF" "$ME" > "$T/env"   # never the real textfile dir
}
N=0
pe() { bash "$TOOL" "$@"; }
audit_to() { pe audit --textfile-dir "$TF" "$@" > "$T/out" 2>&1; echo $? > "$T/rc"; }
rc() { cat "$T/rc"; }
prom() { cat "$TF/pft_privesc_validator.prom"; }
has() { grep -qE "$1" "$T/out"; }
mode() { stat -c %a "$R$1"; }

echo "== audit: baseline (Ubuntu-like, stock SUID set)"
fresh; audit_to
check "B1 baseline: exit 1, RESULT WARN, 0 fail, 4 warn, 4 fixable" '[ "$(rc)" = 1 ] && has "^RESULT: WARN - 0 fail, 4 warn, 4 fixable by apply, 0 errors -> exit 1$"'
check "B2 sudo, passwd, crontab (SGID) PASS PE-SUID-OK" 'has "^PASS PE-SUID-OK +/usr/bin/sudo: SUID mode 4755 \(sudo\)" && has "^PASS PE-SUID-OK +/usr/bin/passwd" && has "^PASS PE-SUID-OK +/usr/bin/crontab: SGID mode 2755"'
check "B3 pkexec, chfn, ssh-keysign WARN PE-SUID-UNNEEDED" 'has "^WARN PE-SUID-UNNEEDED +/usr/bin/pkexec" && has "^WARN PE-SUID-UNNEEDED +/usr/bin/chfn" && has "^WARN PE-SUID-UNNEEDED +/usr/lib/openssh/ssh-keysign"'
check "B4 gst-ptp-helper WARN PE-CAP-UNNEEDED, ping PASS PE-CAP-OK" 'has "^WARN PE-CAP-UNNEEDED +/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper" && has "^PASS PE-CAP-OK +/usr/bin/ping: cap_net_raw=ep"'
check "B5 sudoers, exec, path, rooteq PASS" 'has "^PASS PE-SUDO-OK +sudoers: visudo OK, 3 file" && has "^PASS PE-EXEC-OK" && has "^PASS PE-PATH-OK" && has "^PASS PE-ROOTEQ-OK"'
check "B6 agent in docker with full sudo = INFO, names hashed" 'has "^INFO PE-ROOTEQ-ADMIN +docker: account acct-[0-9a-f]{8} is in docker and already has full sudo" && ! grep -qF "$ME" "$T/out"'
check "B7 metrics: up 1, last_run, suid warn 4, fixable 4, backup 0" 'prom | grep -qx "pft_privesc_up{host=\"validator\"} 1" && prom | grep -qx "pft_privesc_last_run_timestamp_seconds{host=\"validator\"} 1800000000" && prom | grep -qx "pft_privesc_findings{host=\"validator\",area=\"suid\",grade=\"warn\"} 4" && prom | grep -qx "pft_privesc_fixable{host=\"validator\"} 4" && prom | grep -qx "pft_privesc_backup_entries{host=\"validator\"} 0"'
check "B8 textfile passes validate" 'pe validate "$TF/pft_privesc_validator.prom" validator'
pe audit --show-names --textfile-dir "$TF" > "$T/names" 2>&1
check "B9 --show-names prints the account" 'grep -qF "account $ME is in docker" "$T/names"'
pe audit --json --textfile-dir "$TF" > "$T/json"
check "B10 --json: result WARN, exit 1, 4 fixable, findings list" 'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d[\"result\"]==\"WARN\" and d[\"exit\"]==1 and d[\"fixable\"]==4 and len(d[\"findings\"])>8" "$T/json"'

mk 444 /etc/machine-id 0123456789abcdef0123456789abcdef; audit_to
H_SALT="acct-$(printf '%s' "0123456789abcdef0123456789abcdef:$ME" | sha256sum | cut -c1-8)"
H_BARE="acct-$(printf '%s' "$ME" | sha256sum | cut -c1-8)"
check "B11 account hash keyed by /etc/machine-id (bare sha256 of the name never printed)" 'grep -qF "account $H_SALT is in docker" "$T/out" && ! grep -qF "$H_BARE" "$T/out"'

echo "== audit: suid area"
fresh; mk 4755 /usr/local/sbin/odd-suid; audit_to
check "S1 unpackaged SUID: FAIL PE-SUID-UNPKG, not fixable" 'has "^FAIL PE-SUID-UNPKG +/usr/local/sbin/odd-suid: SUID mode 4755, not owned by any package" && has "1 fail, 4 warn, 4 fixable"'
echo "REMOVE_SUID=/usr/local/sbin/odd-suid" >> "$T/env"; audit_to
check "S2 ... listed in REMOVE_SUID: fixable" 'has "1 fail, 4 warn, 5 fixable"'
fresh; printf 'passwd\t/usr/bin/chfn\n' > "$STUB/md5-changed.tsv"; audit_to
check "S3 dpkg --verify md5 change: FAIL PE-SUID-MODIFIED" 'has "^FAIL PE-SUID-MODIFIED +/usr/bin/chfn: SUID mode 4755, dpkg --verify: md5sum differs from package passwd"'
fresh; chmod 4777 "$R/usr/bin/pkexec"; audit_to
check "S4 world-writable SUID: FAIL PE-SUID-WRITABLE with chmod 4755" 'has "^FAIL PE-SUID-WRITABLE +/usr/bin/pkexec: SUID mode 4777; /usr/bin/pkexec world-writable \(mode 4777\)"'
fresh; chmod 0777 "$R/usr/lib/openssh"; audit_to
check "S5 writable parent dir of a SUID file: FAIL names the dir" 'has "^FAIL PE-SUID-WRITABLE +/usr/lib/openssh/ssh-keysign: .*; /usr/lib/openssh world-writable"'
fresh; chmod 1777 "$R/usr/lib/openssh"; audit_to
check "S6 sticky world-writable parent: not a finding" '! has "PE-SUID-WRITABLE"'
fresh; mk 4755 /usr/bin/fusermount3; audit_to
check "S7 usrmerge: /usr/bin/fusermount3 owned via /bin/fusermount3 (fuse3) -> UNNEEDED" 'has "^WARN PE-SUID-UNNEEDED +/usr/bin/fusermount3: SUID mode 4755 \(fuse3\)"'
fresh; mk 4755 /usr/bin/newtool; printf '/usr/bin/newtool\tnewpkg\n' >> "$STUB/dpkg-owners.tsv"; audit_to
check "S8 dpkg-owned SUID on neither list: WARN PE-SUID-REVIEW, not fixable" 'has "^WARN PE-SUID-REVIEW +/usr/bin/newtool" && has "4 fixable"'
fresh; printf '%s\t%s\n' "$R/usr/local/bin/pft-tool" "cap_sys_admin=ep" >> "$STUB/caps.tsv"; audit_to
check "S9 capabilities on an unpackaged file: FAIL PE-CAP-UNPKG" 'has "^FAIL PE-CAP-UNPKG +/usr/local/bin/pft-tool: capabilities cap_sys_admin=ep"'

echo "== audit: sudoers area"
fresh; chmod 0666 "$R/etc/sudoers.d/90-agent"; audit_to
check "U1 world-writable sudoers.d file: FAIL PE-SUDO-PERM, fixable" 'has "^FAIL PE-SUDO-PERM +/etc/sudoers.d/90-agent: owner [0-9]+:[0-9]+ mode 0666" && has "5 fixable"'
fresh; echo 1 > "$STUB/visudo.rc"; audit_to
check "U2 visudo -c fails: FAIL PE-SUDO-SYNTAX" 'has "^FAIL PE-SUDO-SYNTAX"'
fresh; mk 440 /etc/sudoers.d/50-ops 'Defaults env_keep += "LD_PRELOAD"
Cmnd_Alias EDIT = /usr/bin/vim
ops ALL=(root) NOPASSWD: EDIT, /usr/local/bin/pft-tool *, rel-cmd'
chmod 0777 "$R/usr/local/bin"; audit_to
check "U3 env_keep LD_PRELOAD: FAIL PE-SUDO-ENV" 'has "^FAIL PE-SUDO-ENV +Defaults: env_keep keeps LD_PRELOAD"'
check "U4 NOPASSWD vim via Cmnd_Alias: WARN PE-SUDO-SHELLESC" 'has "^WARN PE-SUDO-SHELLESC +/etc/sudoers.d/50-ops: acct-[0-9a-f]{8}: NOPASSWD vim can spawn a shell"'
check "U5 command in a world-writable dir: FAIL PE-SUDO-CMD-WRITABLE" 'has "^FAIL PE-SUDO-CMD-WRITABLE +/etc/sudoers.d/50-ops: .*/usr/local/bin/pft-tool: /usr/local/bin world-writable"'
check "U6 wildcard args: WARN PE-SUDO-WILDCARD; relative command: FAIL" 'has "^WARN PE-SUDO-WILDCARD" && has "^FAIL PE-SUDO-CMD-RELATIVE .*relative command rel-cmd"'
fresh; mk 440 /etc/sudoers 'Defaults !env_reset
root ALL=(ALL:ALL) ALL
#includedir /etc/sudoers.d'; audit_to
check "U7 !env_reset FAIL; secure_path + use_pty missing WARN; #includedir still read" 'has "^FAIL PE-SUDO-ENV +Defaults: !env_reset" && has "^WARN PE-SUDO-DEFAULTS +Defaults: secure_path not set" && has "^WARN PE-SUDO-DEFAULTS +Defaults: use_pty not set" && has "INFO PE-ROOTEQ-ADMIN"'
fresh; mk 440 /etc/sudoers.d/90-agent.bak "nobody ALL=(ALL) NOPASSWD: /usr/bin/vim"; mk 440 /etc/sudoers.d/old~ "nobody ALL=(ALL) NOPASSWD: /usr/bin/vim"; audit_to
check "U8 includedir skips names with a dot or ending in ~ (like sudo)" '! has "SHELLESC" && has "PE-SUDO-OK +sudoers: visudo OK, 3 file"'
fresh; mk 440 /etc/sudoers.d/90-agent "$ME ALL=(ALL) NOPASSWD: \\
  ALL"; audit_to
check "U9 continuation line + NOPASSWD:ALL tag still a full-root rule" 'has "^INFO PE-SUDO-ADMIN +sudoers: full-root rule for account acct-" && has "PE-ROOTEQ-ADMIN"'

echo "== audit: exec area (units + cron)"
fresh; chmod 0777 "$R/usr/local/bin/pft-tool"; audit_to
check "E1 root unit ExecStart world-writable: FAIL PE-EXEC-UNIT, chmod 0755 action" 'has "^FAIL PE-EXEC-UNIT +pft-tool.service: runs /usr/local/bin/pft-tool: /usr/local/bin/pft-tool world-writable \(mode 0777\)"'
check "E2 ... and the cron.d line that runs it: FAIL PE-EXEC-CRON" 'has "^FAIL PE-EXEC-CRON +/etc/cron.d/pft-job: runs /usr/local/bin/pft-tool"'
fresh; sed -i "s/^User=$/User=nobody/" "$STUB/units.show"; chmod 0777 "$R/usr/sbin/cron"; audit_to
check "E3 non-root units are skipped (User=nobody)" '! has "PE-EXEC-UNIT"'
fresh; chmod 0666 "$R/lib/systemd/system/pft-tool.service"; audit_to
check "E4 world-writable unit file: FAIL PE-EXEC-UNITFILE" 'has "^FAIL PE-EXEC-UNITFILE +pft-tool.service: /lib/systemd/system/pft-tool.service: /lib/systemd/system/pft-tool.service world-writable"'
fresh; mk 0757 /opt/run.sh '#!/bin/sh'; sed -i 's#argv\[\]=/usr/sbin/cron -f#argv[]=/bin/sh /opt/run.sh /var/log/data.txt#' "$STUB/units.show"
mk 0666 /var/log/data.txt; audit_to
check "E5 script argument checked, data-file argument not" 'has "^FAIL PE-EXEC-UNIT +cron.service: argument /opt/run.sh: /opt/run.sh world-writable" && ! has "data.txt"'
fresh; sed -i 's#path=/usr/sbin/cron#path=cron-bare#' "$STUB/units.show"; mk 0777 /usr/sbin/cron-bare; audit_to
check "E6 bare ExecStart name resolved in the systemd search path" 'has "^FAIL PE-EXEC-UNIT +cron.service: runs /usr/sbin/cron-bare"'
fresh; chmod 0666 "$R/etc/cron.d/pft-job"; chmod 0777 "$R/etc/cron.hourly/pft-hourly"; audit_to
check "E7 writable cron.d file and run-parts script: FAIL PE-EXEC-CRON x2" '[ "$(grep -c "^FAIL PE-EXEC-CRON" "$T/out")" = 2 ]'
fresh; ln -sf /opt/target "$R/usr/local/bin/pft-tool"; mk 0777 /opt/target; audit_to
check "E8 symlinked ExecStart: the resolved target is checked" 'has "^FAIL PE-EXEC-UNIT +pft-tool.service: runs /usr/local/bin/pft-tool: /opt/target world-writable"'

echo "== audit: path area"
fresh; chmod 0777 "$R/usr/local/bin"; audit_to
check "P1 world-writable PATH dir: FAIL PE-PATH-DIR" 'has "^FAIL PE-PATH-DIR +/usr/local/bin: /usr/local/bin world-writable \(mode 0777\)"'
fresh; chmod 0646 "$R/usr/bin/true"; audit_to
check "P2 world-writable file in a PATH dir: FAIL PE-PATH-FILE" 'has "^FAIL PE-PATH-FILE +/usr/bin/true: /usr/bin/true world-writable \(mode 0646\)"'
fresh; mk 644 /etc/environment 'PATH="/usr/local/bin:.:/usr/bin"'; audit_to
check "P3 relative entry in /etc/environment PATH: FAIL PE-PATH-REL" 'has "^FAIL PE-PATH-REL +/etc/environment: PATH entry .\..+ is empty or relative"'
fresh; mk 0666 /opt/tgt; ln -s /opt/tgt "$R/usr/local/bin/linked"; audit_to
check "P4 symlink in a PATH dir to a writable target: FAIL PE-PATH-FILE" 'has "^FAIL PE-PATH-FILE +/usr/local/bin/linked: /opt/tgt world-writable"'
fresh; mkdir -p "$R/snapx"; chmod 0777 "$R/snapx"; mk 644 /etc/environment 'PATH="/usr/bin:/snapx/bin"'; audit_to
check "P5 missing PATH dir whose parent is writable: FAIL PE-PATH-DIR" 'has "^FAIL PE-PATH-DIR +/snapx/bin: /snapx world-writable"'

fresh; chmod 1777 "$R/usr/bin/true"; audit_to
check "P6 sticky bit on the FILE itself does not exempt it (only parent dirs)" 'has "^FAIL PE-PATH-FILE +/usr/bin/true: /usr/bin/true world-writable \(mode 1777\)"'

fresh; chmod 1777 "$R/usr/local/bin"; audit_to
check "P7 sticky world-writable PATH dir is still a FAIL (anyone can add a file root runs)" 'has "^FAIL PE-PATH-DIR +/usr/local/bin: /usr/local/bin world-writable \(mode 1777\)"'

echo "== audit: rooteq area"
fresh; printf 'root:x:0:\nsudo:x:27:\ndocker:x:120:%s,eve\nlxd:x:119:\ndisk:x:6:\n' "$ME" > "$STUB/group"
printf 'eve:x:1002:1002::/home/eve:/bin/bash\n' >> "$STUB/passwd"; audit_to
check "R1 docker member without sudo: FAIL PE-ROOTEQ-GROUP (hashed name)" 'has "^FAIL PE-ROOTEQ-GROUP +docker: account acct-[0-9a-f]{8} is in docker \(root-equivalent\) without a full sudo rule" && ! has "eve"'
fresh; printf 'root:x:0:\nsudo:x:27:bob\ndocker:x:120:bob\nlxd:x:119:\ndisk:x:6:\n' > "$STUB/group"
printf 'bob:x:1003:1003::/home/bob:/bin/bash\n' >> "$STUB/passwd"; audit_to
check "R2 member of %sudo (group rule) counts as full sudo: INFO" 'has "^INFO PE-ROOTEQ-ADMIN +docker: account acct-" && ! has "PE-ROOTEQ-GROUP"'
fresh; printf 'carol:x:1004:6::/home/carol:/bin/bash\n' >> "$STUB/passwd"; audit_to
check "R3 primary group disk counts as membership: FAIL" 'has "^FAIL PE-ROOTEQ-GROUP +disk: account acct-"'
check "R4 lxd daemon account (/bin/false, primary lxd) = INFO service" 'has "^INFO PE-ROOTEQ-SERVICE +lxd: service account acct-"'
fresh; chmod 0666 "$R/run/containerd/containerd.sock"; audit_to
check "R5 containerd.sock 0666: FAIL PE-ROOTEQ-SOCK, fixable" 'has "^FAIL PE-ROOTEQ-SOCK +/run/containerd/containerd.sock: mode 0666" && has "5 fixable"'
fresh; echo c1 > "$STUB/docker-ps"; echo "/postfiatd /var/lib/postfiatd /var/run/docker.sock" > "$STUB/docker-inspect-c1"; audit_to
check "R6 container bind-mounting docker.sock: FAIL PE-ROOTEQ-MOUNT (data mount ignored)" 'has "^FAIL PE-ROOTEQ-MOUNT +postfiatd: bind-mounts /var/run/docker.sock" && ! has "bind-mounts /var/lib/postfiatd"'

echo "== audit: errors"
fresh; rm "$STUB/group"; audit_to
check "X1 getent group fails: exit 2, RESULT ERROR, up 0" '[ "$(rc)" = 2 ] && has "^RESULT: ERROR" && prom | grep -qx "pft_privesc_up{host=\"validator\"} 0"'
fresh; printf 'bad line\n' > "$STUB/statoverride"; audit_to
check "X2 statoverride list unparsable lines are skipped, not fatal" '[ "$(rc)" = 1 ]'

echo "== apply"
fresh; chmod 0777 "$R/usr/local/bin/pft-tool"; chmod 0666 "$R/etc/sudoers.d/90-agent"
mk 4755 /usr/bin/fusermount3; echo "root root 4755 /usr/lib/openssh/ssh-keysign" >> "$STUB/statoverride"
pe apply --dry-run > "$T/out" 2>&1; echo $? > "$T/rc"
check "A1 --dry-run: exit 0, plan lists 7 changes (pft-tool once), nothing changed" '[ "$(rc)" = 0 ] && has "plan: 7 change" && has "dry run: nothing changed" && [ "$(mode /usr/local/bin/pft-tool)" = 777 ] && [ ! -e "$R/var/lib/pft-privesc/backup/manifest.tsv" ]'
cp "$STUB/statoverride" "$T/so.before"; cp "$STUB/caps.tsv" "$T/caps.before"
for p in /usr/local/bin/pft-tool /etc/sudoers.d/90-agent /usr/bin/pkexec /usr/bin/fusermount3 /usr/lib/openssh/ssh-keysign; do
  printf '%s %s\n' "$p" "$(stat -c '%a %u %g' "$R$p")"; done > "$T/stat.before"
pe apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "A2 apply: exit 0, APPLIED, 7 entries in the manifest" '[ "$(rc)" = 0 ] && has "APPLIED: 7 change" && [ "$(wc -l < "$R/var/lib/pft-privesc/backup/manifest.tsv")" = 7 ]'
check "A3 modes after: pft-tool 755, sudoers file 440, pkexec 755, chfn 755" '[ "$(mode /usr/local/bin/pft-tool)" = 755 ] && [ "$(mode /etc/sudoers.d/90-agent)" = 440 ] && [ "$(mode /usr/bin/pkexec)" = 755 ] && [ "$(mode /usr/bin/chfn)" = 755 ]'
check "A4 statoverrides: pkexec added, fusermount3 under dpkg path /bin/fusermount3, ssh-keysign replaced" 'grep -qx "[^ ]* [^ ]* 0755 /usr/bin/pkexec" "$STUB/statoverride" && grep -qx "[^ ]* [^ ]* 0755 /bin/fusermount3" "$STUB/statoverride" && grep -qx "[^ ]* [^ ]* 0755 /usr/lib/openssh/ssh-keysign" "$STUB/statoverride" && ! grep -q "4755 /usr/lib/openssh/ssh-keysign" "$STUB/statoverride"'
check "A5 gst-ptp-helper capabilities removed (setcap -r)" '! grep -q gst-ptp-helper "$STUB/caps.tsv" && grep -q "^setcap -r .*gst-ptp-helper" "$STUB/calls.log"'
check "A6 re-audit after apply: RESULT PASS, PE-SUID-REMOVED for 4" 'grep -q "after: RESULT: PASS - 0 fail, 0 warn" "$T/out" && [ "$(grep -c "^PASS PE-SUID-REMOVED" "$R/var/lib/pft-privesc/apply-audit.txt")" = 4 ]'
check "A7 sudoers change ran visudo -c + agent sudo check after it" 'grep -n "" "$STUB/calls.log" | grep -A3 "chown 0:0 .*90-agent" | grep -q "visudo -c" && grep -q "^runuser -u $ME -- sudo -n true" "$STUB/calls.log"'
check "A8 crontab (needed SGID) and sudo untouched" '[ "$(mode /usr/bin/crontab)" = 2755 ] && [ "$(mode /usr/bin/sudo)" = 4755 ]'
pe audit --textfile-dir "$TF" > /dev/null
check "A9 metric backup_entries 7 after apply" 'prom | grep -qx "pft_privesc_backup_entries{host=\"validator\"} 7"'
pe apply > "$T/out2" 2>&1
check "A10 second apply: nothing to apply" 'grep -q "nothing to apply" "$T/out2" && [ "$(wc -l < "$R/var/lib/pft-privesc/backup/manifest.tsv")" = 7 ]'

echo "== undo"
pe undo > "$T/out" 2>&1; echo $? > "$T/rc"
for p in /usr/local/bin/pft-tool /etc/sudoers.d/90-agent /usr/bin/pkexec /usr/bin/fusermount3 /usr/lib/openssh/ssh-keysign; do
  printf '%s %s\n' "$p" "$(stat -c '%a %u %g' "$R$p")"; done > "$T/stat.after"
check "D1 undo: exit 0, UNDO OK, 7 restored" '[ "$(rc)" = 0 ] && has "UNDO OK" && [ "$(grep -c " restored " "$T/out")" = 7 ]'
check "D2 mode/uid/gid of every touched file identical to before apply" 'cmp -s "$T/stat.before" "$T/stat.after"'
check "D3 statoverride list identical to before (old ssh-keysign override re-added)" '[ "$(sort "$STUB/statoverride")" = "$(sort "$T/so.before")" ]'
check "D4 capabilities restored" '[ "$(sort "$STUB/caps.tsv")" = "$(sort "$T/caps.before")" ]'
check "D5 manifest moved to last-undo; second undo: nothing to undo (exit 2)" '[ ! -e "$R/var/lib/pft-privesc/backup/manifest.tsv" ] && [ -s "$R/var/lib/pft-privesc/last-undo/manifest.tsv" ] && ! pe undo'
fresh; pe apply > /dev/null 2>&1; echo changed >> "$R/usr/bin/pkexec"; pe undo > "$T/out" 2>&1; echo $? > "$T/rc"
check "D6 content changed after apply: UNDO FAILED, exit 2, manifest kept" '[ "$(rc)" = 2 ] && has "pkexec content changed since apply" && has "UNDO FAILED" && [ -s "$R/var/lib/pft-privesc/backup/manifest.tsv" ]'

echo "== apply guards"
fresh; echo 1 > "$STUB/visudo.rc"; pe apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "G1 visudo -c fails before: refused, exit 2, nothing changed" '[ "$(rc)" = 2 ] && has "visudo -c fails before apply" && [ "$(mode /usr/bin/pkexec)" = 4755 ]'
fresh; echo 1 > "$STUB/agent.rc"; pe apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "G2 agent cannot sudo before: refused, exit 2" '[ "$(rc)" = 2 ] && has "cannot sudo -n true before apply" && [ "$(mode /usr/bin/pkexec)" = 4755 ]'
fresh; sed -i "/^AGENT_USER=/d" "$T/env"; pe apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "G3 no AGENT_USER: refused" '[ "$(rc)" = 2 ] && has "AGENT_USER"'
fresh; chmod 0666 "$R/etc/sudoers.d/90-agent"; echo 1 > "$STUB/agent.flip-after"; echo 1 > "$STUB/agent.rc2"
pe apply > "$T/out" 2>&1; echo $? > "$T/rc"
check "G4 agent sudo lost after a sudoers change: exit 3, run rolled back" '[ "$(rc)" = 3 ] && has "agent sudo check failed after a sudoers change" && has "rolling back" && [ "$(mode /etc/sudoers.d/90-agent)" = 666 ] && [ "$(mode /usr/bin/pkexec)" = 4755 ]'
check "G5 ... and the manifest holds no entry of the failed run" '[ ! -s "$R/var/lib/pft-privesc/backup/manifest.tsv" ]'
fresh; chmod 4777 "$R/usr/bin/sudo"; pe apply > "$T/out" 2>&1
check "G6 PROTECTED: a world-writable /usr/bin/sudo is reported, never changed by apply" 'grep -qE "FAIL PE-SUID-WRITABLE +/usr/bin/sudo" "$T/out" && [ "$(mode /usr/bin/sudo)" = 4777 ]'
fresh; pe apply --only PE-CAP-UNNEEDED > "$T/out" 2>&1
check "G7 --only PE-CAP-UNNEEDED: only the capability removed" 'has "plan: 1 change" && [ "$(mode /usr/bin/pkexec)" = 4755 ] && ! grep -q gst-ptp-helper "$STUB/caps.tsv"'

fresh; chmod 4777 "$R/usr/bin/sudo"; sed -i 's#path=/usr/sbin/cron#path=/bin/sudo#' "$STUB/units.show"; pe apply > "$T/out" 2>&1
check "G8 PROTECTED by resolved path: unit runs /bin/sudo (usrmerge alias), apply skips it" 'has "skip \(protected\) PE-EXEC-UNIT /bin/sudo" && [ "$(mode /usr/bin/sudo)" = 4777 ]'

echo "== undo: order and stat verification"
fresh; chmod 4777 "$R/usr/bin/pkexec"
pe apply --only PE-SUID-WRITABLE > /dev/null 2>&1; pe apply --only PE-SUID-UNNEEDED > "$T/out" 2>&1
check "D7 two applies on one file: chmod 4777->4755, then statoverride 4755->0755" '[ "$(mode /usr/bin/pkexec)" = 755 ] && [ "$(wc -l < "$R/var/lib/pft-privesc/backup/manifest.tsv")" -ge 2 ]'
pe undo > "$T/out" 2>&1
check "D8 undo newest-first returns pkexec to the original 4777" '[ "$(mode /usr/bin/pkexec)" = 4777 ] && has "UNDO OK"'
fresh; pe apply --only PE-CAP-UNNEEDED > /dev/null 2>&1
awk -F'\t' 'BEGIN{OFS="\t"} {$7=4242; print}' "$R/var/lib/pft-privesc/backup/manifest.tsv" > "$T/m" && cp "$T/m" "$R/var/lib/pft-privesc/backup/manifest.tsv"
pe undo > "$T/out" 2>&1; echo $? > "$T/rc"
check "D9 restored owner differs from the record (chown had no effect): UNDO FAILED" '[ "$(rc)" = 2 ] && has "gst-ptp-helper is .755 [0-9]+ [0-9]+., recorded .755 4242 [0-9]+." && has "UNDO FAILED"'

echo "== validate"
fresh; audit_to
check "V1 extra line rejected" 'cp "$TF/pft_privesc_validator.prom" "$T/v"; echo "evil 1" >> "$T/v"; ! pe validate "$T/v" validator'
check "V2 wrong host label rejected" '! pe validate "$TF/pft_privesc_validator.prom" sentry'
check "V4 foreign metric name rejected" 'cp "$TF/pft_privesc_validator.prom" "$T/v"; echo "evil_metric{host=\"validator\"} 1" >> "$T/v"; ! pe validate "$T/v" validator'
check "V3 no up sample rejected" 'grep -v "^pft_privesc_up" "$TF/pft_privesc_validator.prom" > "$T/v"; ! pe validate "$T/v" validator'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
