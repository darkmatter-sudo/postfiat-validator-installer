#!/usr/bin/env bash
# Stub commands for run-tests.sh. Sourced; mk_env DIR builds a fake host in DIR:
#   DIR/root   PFT_MOUNTS_ROOT: etc/fstab, proc/1/mountinfo (host), proc/4242/mountinfo (postfiatd)
#   DIR/s      stub state: group, started (StartedAt), state (server_state), units, results, calls
#   DIR/bin    one executable per stubbed command
# mount/umount (also inside nsenter) edit the fake mountinfo files through fake_mount.py.
# Stub bodies are literal scripts, single-quoted on purpose.
# shellcheck disable=SC2016

STUBS_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Bare Ubuntu 22.04 cloud image defaults (no separate /tmp, /var/tmp; /dev/shm without noexec; /proc without hidepid).
HOST_MI='22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,discard,errors=remount-ro
23 22 0:5 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=4010000k,inode64
24 23 0:21 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw,inode64
25 22 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
26 22 8:15 / /boot/efi rw,relatime shared:4 - vfat /dev/sda15 rw,fmask=0077,dmask=0077'
CONT_MI='900 899 0:80 / / rw,relatime - overlay overlay rw,lowerdir=x
901 900 8:1 /var/lib/docker/volumes/postfiatd_postfiatd-data/_data /var/lib/postfiatd/db rw,relatime - ext4 /dev/sda1 rw,discard,errors=remount-ro
902 900 0:81 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=65536k,inode64'
FSTAB_BARE='LABEL=cloudimg-rootfs	/	 ext4	discard,errors=remount-ro	0 1
LABEL=UEFI	/boot/efi	vfat	umask=0077	0 1'

mk_env() {
  local d="$1"
  mkdir -p "$d/root/etc/systemd/system" "$d/root/etc/apt/apt.conf.d" "$d/root/proc/1" "$d/root/proc/4242" "$d/s" "$d/bin"
  printf '%s\n' "$HOST_MI" > "$d/root/proc/1/mountinfo"
  printf '%s\n' "$CONT_MI" > "$d/root/proc/4242/mountinfo"
  printf '%s\n' "$FSTAB_BARE" > "$d/root/etc/fstab"
  echo 'docker:x:999:' > "$d/s/group"
  echo 4242 > "$d/s/pid"
  echo 2026-10-28T11:33:11.2Z > "$d/s/started"
  echo full > "$d/s/state"
  printf 'pft-heartbeat.service\npft-statewatch@postfiatd.service\n' > "$d/s/oneshots"
  printf 'pft-exporter.service\n' > "$d/s/daemons"
  : > "$d/s/failunits"; : > "$d/s/resultfail"; : > "$d/s/calls"
  # hardened: 0 while the fake host's /tmp is a noexec mount. Gate faults below fire only then, like a fault that
  # apply caused (and rollback cures).
  cat > "$d/bin/hardened" <<'B'
#!/usr/bin/env bash
grep -qE ' /tmp [^ ]*noexec' "$STUB_R/proc/1/mountinfo"
B

  cat > "$d/bin/docker" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; echo "docker $*" >> "$S/calls"
[ "$1" = inspect ] || exit 0
[ "$2" = -f ] || { [ "$3" = postfiatd ] || [ "$2" = postfiatd ]; exit $?; }
[ "$4" = postfiatd ] || exit 1
case "$3" in
  *State.Pid*) cat "$S/pid" ;;
  *State.StartedAt*) if [ -f "$S/restart-after" ] && [ "$(grep -c '^docker inspect -f {{.State.StartedAt}}' "$S/calls")" -gt "$(cat "$S/restart-after")" ]; then echo 2026-11-01T00:00:00Z; else cat "$S/started"; fi ;;
  *Mounts*) [ -f "$S/nodata" ] || echo "${STUB_DATA_SRC:-/var/lib/docker/volumes/postfiatd_postfiatd-data/_data}" ;;
esac
B
  cat > "$d/bin/mount" <<'B'
#!/usr/bin/env bash
exec python3 "$STUB_HERE/fake_mount.py" "$STUB_R/proc/1/mountinfo" mount "$@"
B
  cat > "$d/bin/umount" <<'B'
#!/usr/bin/env bash
exec python3 "$STUB_HERE/fake_mount.py" "$STUB_R/proc/1/mountinfo" umount "$@"
B
  cat > "$d/bin/nsenter" <<'B'
#!/usr/bin/env bash
# nsenter -t PID -m -- mount ARGS...
echo "nsenter $*" >> "$STUB_S/calls"
[ "$1" = -t ] && [ "$3" = -m ] && [ "$4" = -- ] && [ "$5" = mount ] || exit 2
pid="$2"; shift 5
FAKE_FAIL="${FAKE_NS_FAIL:-}" exec python3 "$STUB_HERE/fake_mount.py" "$STUB_R/proc/$pid/mountinfo" mount "$@"
B
  cat > "$d/bin/findmnt" <<'B'
#!/usr/bin/env bash
echo "findmnt $*" >> "$STUB_S/calls"
[ "$1" = --verify ] && [ "$2" = --tab-file ] || exit 2
[ -f "$STUB_S/verify-fail" ] && { echo "/tmp"; echo "   [E] unreachable on boot required target: No such file or directory"; echo "0 parse errors, 1 error, 0 warnings"; exit 1; }
echo "0 parse errors, 0 errors, 0 warnings"
B
  cat > "$d/bin/systemctl" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; echo "systemctl $*" >> "$S/calls"
case "$1" in
  daemon-reload) exit 0 ;;
  list-timers) sed 's/^/Sat 2026-11-01 00:00:00 UTC 1min left n\/a n\/a x.timer /' "$S/oneshots" ;;
  list-units) sed 's/$/ loaded active running x/' "$S/daemons" ;;
  start) grep -qx "$2" "$S/failunits" && "$STUB_BIN/hardened" && exit 1; exit 0 ;;
  show) u="${!#}"; { grep -qx "$u" "$S/failunits" || grep -qx "$u" "$S/resultfail"; } && "$STUB_BIN/hardened" && echo exit-code || echo success ;;
  is-active) [ -f "$S/daemon-down" ] && "$STUB_BIN/hardened" && echo failed || echo active ;;
esac
B
  cat > "$d/bin/ss" <<'B'
#!/usr/bin/env bash
echo 'LISTEN 0 4096 0.0.0.0:2559 0.0.0.0:*'
echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'
B
  printf '#!/usr/bin/env bash\nexit 0\n' > "$d/bin/sshd"
  cat > "$d/bin/ssh-keyscan" <<'B'
#!/usr/bin/env bash
[ -f "$STUB_S/ssh-down" ] && "$STUB_BIN/hardened" && exit 1
echo '127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE'
B
  cat > "$d/bin/getent" <<'B'
#!/usr/bin/env bash
grep "^$2:" "$STUB_S/group"
B
  cat > "$d/bin/groupadd" <<'B'
#!/usr/bin/env bash
echo "groupadd $*" >> "$STUB_S/calls"
echo "${!#}:x:998:" >> "$STUB_S/group"
B
  cat > "$d/bin/rpc" <<'B'
#!/usr/bin/env bash
if "$STUB_BIN/hardened"; then cat "$STUB_S/state"; else echo full; fi
B
  chmod +x "$d/bin/"*
}

use_env() { # DIR: point the tool at the fake host
  local d="$1"
  export STUB_S="$d/s" STUB_R="$d/root" STUB_HERE="$STUBS_HERE" STUB_BIN="$d/bin"
  export PFT_MOUNTS_ROOT="$d/root" PFT_MOUNTS_DOCKER="$d/bin/docker" PFT_MOUNTS_MOUNT="$d/bin/mount"
  export PFT_MOUNTS_UMOUNT="$d/bin/umount" PFT_MOUNTS_NSENTER="$d/bin/nsenter" PFT_MOUNTS_FINDMNT="$d/bin/findmnt"
  export PFT_MOUNTS_SYSTEMCTL="$d/bin/systemctl" PFT_MOUNTS_SS="$d/bin/ss" PFT_MOUNTS_SSHD="$d/bin/sshd"
  export PFT_MOUNTS_KEYSCAN="$d/bin/ssh-keyscan" PFT_MOUNTS_GETENT="$d/bin/getent" PFT_MOUNTS_GROUPADD="$d/bin/groupadd"
  export PFT_MOUNTS_RPC="$d/bin/rpc" CONTAINER=postfiatd HEALTH_BUDGET=2 POLL_SEC=1 FAKE_CALLS="$d/s/calls"
  unset PFT_MOUNTS_INJECT GATE_UNITS FAKE_FAIL FAKE_NS_FAIL
}
