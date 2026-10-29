#!/usr/bin/env bash
# Stub commands for run-tests.sh. Sourced; mk_env DIR builds a fake host in DIR:
#   DIR/root   PFT_PATCH_ROOT (etc/apt/apt.conf.d, var/run, var/lib/pft-patch)
#   DIR/s      stub state: sim (apt-get -s output), holds, installed (one package per line), nr (needrestart -b output),
#              calls (every stub call with its arguments)
#   DIR/bin    one executable per stubbed command
# The fake apt-config parses root/etc/apt/apt.conf.d/* in name order like apt does for the two forms the tool and
# Ubuntu use: `Key { "a"; "b"; };` (lists append) and `Key "v";` (scalars: the last file wins), and prints a dump.
# SIM_* are used by run-tests.sh.
# shellcheck disable=SC2016,SC2034

mk_env() {
  local d="$1"
  mkdir -p "$d/root/etc/apt/apt.conf.d" "$d/root/var/run" "$d/root/var/lib" "$d/root/var/log" "$d/root/proc/sys/kernel/random" "$d/s" "$d/bin"
  echo "boot-$RANDOM$RANDOM" > "$d/root/proc/sys/kernel/random/boot_id"; echo "2026-10-01 startup" > "$d/root/var/log/dpkg.log"
  cat > "$d/root/etc/apt/apt.conf.d/20auto-upgrades" <<'C'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
C
  cat > "$d/root/etc/apt/apt.conf.d/50unattended-upgrades" <<'C'
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}";
	"${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "auto";
C
  : > "$d/s/sim"; : > "$d/s/holds"; : > "$d/s/calls"
  printf 'docker.io\ncontainerd\nruncx\nrunc\n' > "$d/s/installed"
  printf 'NEEDRESTART-VER: 3.5\nNEEDRESTART-KCUR: 5.15.0-198-generic\nNEEDRESTART-KEXP: 5.15.0-198-generic\nNEEDRESTART-KSTA: 1\n' > "$d/s/nr"

  cat > "$d/bin/apt-get" <<'B'
#!/usr/bin/env bash
echo "apt-get $*" >> "$STUB_S/calls"
case " $* " in
  *" update "*) [ -e "$STUB_S/update_fail" ] && { echo "E: update failed"; exit 100; }; exit 0 ;;
  *" install "*)
    [ -e "$STUB_S/install_fail" ] && { echo "E: Sub-process /usr/bin/dpkg returned an error code (1)"; exit 100; }
    echo "Setting up ${*: -1} ..."
    echo "$(date -u +%F) upgrade $*" >> "$PFT_PATCH_ROOT/var/log/dpkg.log"
    [ -e "$STUB_S/install_reboot" ] && { touch "$PFT_PATCH_ROOT/var/run/reboot-required"; echo linux-base > "$PFT_PATCH_ROOT/var/run/reboot-required.pkgs"; }
    [ -e "$STUB_S/install_ksta3" ] && sed -i 's/KSTA: 1/KSTA: 3/' "$STUB_S/nr"
    [ -e "$STUB_S/install_svc" ] && cat "$STUB_S/install_svc" >> "$STUB_S/nr"
    [ -e "$STUB_S/install_integrity" ] && touch "$STUB_S/integrity_warn"
    : > "$STUB_S/sim"; exit 0 ;;
esac
[ -e "$STUB_S/sim_fail" ] && { echo "E: Could not open lock file"; exit 100; }
cat "$STUB_S/sim"
B
  cat > "$d/bin/apt-mark" <<'B'
#!/usr/bin/env bash
echo "apt-mark $*" >> "$STUB_S/calls"
cat "$STUB_S/holds"
B
  cat > "$d/bin/dpkg-query" <<'B'
#!/usr/bin/env bash
echo "dpkg-query $*" >> "$STUB_S/calls"
p="${*: -1}"
grep -qxF -- "$p" "$STUB_S/installed" && { printf 'ii '; exit 0; }
echo "dpkg-query: no packages found matching $p" >&2; exit 1
B
  cat > "$d/bin/needrestart" <<'B'
#!/usr/bin/env bash
echo "needrestart $*" >> "$STUB_S/calls"
[ -e "$STUB_S/nr_missing" ] && exit 127
cat "$STUB_S/nr"
B
  cat > "$d/bin/apt-config" <<'B'
#!/usr/bin/env bash
echo "apt-config $*" >> "$STUB_S/calls"
[ "${1:-}" = dump ] || exit 100
python3 - "$PFT_PATCH_ROOT/etc/apt/apt.conf.d" <<'PY'
import os, re, sys
d = sys.argv[1]; order = []; scal = {}; lists = {}
for f in sorted(os.listdir(d)):
    txt = re.sub(r'//[^\n]*', '', open(os.path.join(d, f)).read())
    for m in re.finditer(r'([A-Za-z:\-]+)\s*\{((?:\s*"[^"]*";)*\s*)\};|([A-Za-z:\-]+)\s+"([^"]*)";', txt):
        if m.group(1):
            k = m.group(1); lists.setdefault(k, [])
            if k not in order: order.append(k)
            lists[k] += re.findall(r'"([^"]*)"', m.group(2))
        else:
            k = m.group(3); scal[k] = m.group(4)
            if k not in order: order.append(k)
for k in order:
    if k in lists:
        for v in lists[k]: print(f'{k}:: "{v}";')
    if k in scal: print(f'{k} "{scal[k]}";')
PY
B
  # an apt-config whose dump never shows the blacklist (e.g. a newer apt that ignores the key)
  printf '#!/usr/bin/env bash\n"%s/bin/apt-config" "$@" | grep -v "^Unattended-Upgrade::Package-Blacklist"\n' "$d" > "$d/bin/apt-config-noblacklist"
  chmod +x "$d/bin/"*
}

use_env() {
  export STUB_S="$1/s" PFT_PATCH_ROOT="$1/root" PFT_PATCH_NOROOT=1
  export PFT_PATCH_APT_GET="$1/bin/apt-get" PFT_PATCH_APT_CONFIG="$1/bin/apt-config" PFT_PATCH_APT_MARK="$1/bin/apt-mark"
  export PFT_PATCH_DPKG_QUERY="$1/bin/dpkg-query" PFT_PATCH_NEEDRESTART="$1/bin/needrestart"
  unset POLICY_FILE BACKUP_DIR RUNTIME_PKGS
}

# apt-get -s lines in the real format (Ubuntu 22.04, captured in logs)
SIM_SEC='Inst libssl3 [3.0.2-0ubuntu1.18] (3.0.2-0ubuntu1.19 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])'
SIM_OTH='Inst nano [6.2-1ubuntu0.2] (6.2-1ubuntu0.3 Ubuntu:22.04/jammy-updates [amd64])'
SIM_KER='Inst linux-image-virtual [5.15.0.198.171] (5.15.0.202.174 Ubuntu:22.04/jammy-updates [amd64])'
SIM_3RD='Inst gh [2.102.1] (2.103.3 gh:cli.github.com [amd64])'
