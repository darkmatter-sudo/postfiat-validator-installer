#!/usr/bin/env bash
# host-run: the live pft-mounts proof on ONE host, run as root by drill/live-run.sh inside its pft-maint window:
#   sudo bash host-run.sh ROLE [--drill]        ROLE = validator | sentry (label only); uses the INSTALLED tool
# 0  before: StartedAt, server_state, fstab sha256, live options of /tmp /var/tmp /dev/shm and of the data dir inside
#    the container; audit (text + --json), plan, apply --dry-run.
# 1  (--drill) injected gate miss: PFT_MOUNTS_INJECT=health apply must roll back on its own: exit 1, fstab and every
#    live option as before.
# 2  apply --yes: exit 0, gate PASS.
# 3  after: audit exit 0 (text + --json); persistence without a reboot: `findmnt --verify` on /etc/fstab, the fstab
#    entries findmnt reads (`findmnt -s`), the mount units systemd's fstab-generator built from them (Options,
#    SourcePath=/etc/fstab) and the apt TempDir.
# 4  negative controls, each next to a positive control on a root-fs directory without the option (CTL, 0755):
#      noexec  a copy of /bin/true in /tmp, /var/tmp, /dev/shm exits 126; in CTL exits 0
#      nodev   a char device (1,5 = zero) made with mknod in /tmp, /var/tmp, /dev/shm and the data dir cannot be
#              opened; in CTL it reads one byte
#      nosuid  a SUID-root copy of /usr/bin/id run as uid 65534 from the data dir (exec allowed, nosuid) prints euid
#              65534; from CTL it prints 0. Run through /proc/self/fd/N (opened by root first), so the unprivileged
#              user needs no search permission on the docker volume path.
#      container  the data dir mount flags inside postfiatd's own mount table carry nodev,nosuid
# 5  (--drill) explicit rollback: exit 0, fstab sha256 and every live option back to step 0, audit shows the step-0
#    findings again; then apply again: exit 0, audit PASS.
# Throughout: postfiatd StartedAt unchanged, server_state full at the end, sshd -t ok and :22 listening.
# shellcheck disable=SC2016,SC2034  # v() conditions are single-quoted on purpose: evaluated later (they read L4 etc.)
set -uo pipefail
ROLE="${1:?role}"; DRILL=0; [ "${2:-}" = --drill ] && DRILL=1
T=/usr/local/bin/pft-mounts
DATA_DEST=/var/lib/postfiatd/db
c=postfiatd; docker inspect postfiatd >/dev/null 2>&1 || c=postfiatd-sentry
CTL="$(mktemp -d /usr/local/lib/pft-mounts-negctl.XXXXXX)"; chmod 0755 "$CTL"
NEG="negctl-$$"
SRC="$(docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$DATA_DEST\"}}{{.Source}}{{end}}{{end}}" "$c")"
lbl() { sed -E 's#/var/lib/docker/volumes/([^/ ]+)/_data#<docker-volume:\1>#g'; }
cleanup() {
  rm -rf "$CTL"
  rm -f "/tmp/$NEG".* "/var/tmp/$NEG".* "/dev/shm/$NEG".* "$SRC/.$NEG".*
}
trap cleanup EXIT
st() { docker inspect -f '{{.State.StartedAt}}' "$c"; }
ss_() { docker exec "$c" sh -c 'curl -s -m 5 -d "{\"method\":\"server_info\"}" http://127.0.0.1:5005/' | jq -r '.result.info.server_state'; }
fsha() { sha256sum /etc/fstab | cut -c1-64; }
pid() { docker inspect -f '{{.State.Pid}}' "$c"; }
live() { # live mount options: host /tmp /var/tmp /dev/shm (top mount), data dir host side, data dir inside the container
  local t
  for t in /tmp /var/tmp /dev/shm; do
    echo "host $t $(awk -v t="$t" '$5 == t { o = $6 } END { print (o == "" ? "(not a mount)" : o) }' /proc/1/mountinfo)"
  done
  echo "host <data-volume> $(awk -v t="$SRC" '$5 == t { o = $6 } END { print (o == "" ? "(not a mount)" : o) }' /proc/1/mountinfo)"
  echo "$c $DATA_DEST $(awk -v t="$DATA_DEST" '$5 == t { o = $6 } END { print (o == "" ? "(not a mount)" : o) }' "/proc/$(pid)/mountinfo")"
}
F=0
v() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; F=$((F + 1)); fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | lbl; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | lbl | sed 's/^/  /'; echo "  (exit $XRC)"; }
nfind() { grep -oE 'FAIL - [0-9]+ finding' <<<"$1" | grep -oE '[0-9]+' || echo 0; }

echo "# pft-mounts host run ($ROLE$([ "$DRILL" = 1 ] && echo ', with injected gate miss + rollback drill')) $(date -u +%FT%TZ)"
head -1 /etc/os-release
echo "tool $T sha256 $(sha256sum "$T" | cut -c1-64); host-run.sh sha256 $(sha256sum < "$0" | cut -c1-64)"
echo "container $c, data dir $DATA_DEST <- $(lbl <<<"$SRC")"
x "pft-maint active"
v "pft-maint window active on this host" '[ "$XRC" = 0 ]'
[ "$F" = 0 ] || { echo "RESULT: FAIL (no window) $(date -u +%FT%TZ)"; exit 1; }

echo; echo "== 0. before"
S0="$(st)"; H0="$(fsha)"; L0="$(live)"
echo "  $c StartedAt $S0, server_state $(ss_), fstab sha256 $H0"
printf '%s\n' "$L0" | sed 's/^/  live: /'
x "$T audit"; A0="$XOUT"; N0="$(nfind "$A0")"
v "before: audit exit 1 with findings ($N0)" '[ "$XRC" = 1 ] && [ "$N0" -gt 0 ]'
x "$T audit --json | jq -c '{findings, result, failing: [.checks[] | select(.status == \"FAIL\" or .status == \"WARN\") | .id]}'"
v "before: --json findings equals the text count" '[ "$(jq -r .findings <<<"$XOUT")" = "$N0" ]'
x "$T plan"
v "plan exit 0 (no unmanaged fstab line for a managed target)" '[ "$XRC" = 0 ]'
x "$T apply --dry-run"
v "dry run exit 0, fstab unchanged" '[ "$XRC" = 0 ] && [ "$(fsha)" = "$H0" ]'

if [ "$DRILL" = 1 ]; then
  echo; echo "== 1. injected gate miss: PFT_MOUNTS_INJECT=health HEALTH_BUDGET=20 apply --yes (must roll back on its own)"
  x "PFT_MOUNTS_INJECT=health HEALTH_BUDGET=20 $T apply --yes"
  v "injected apply exit 1 (automatic rollback)" '[ "$XRC" = 1 ] && grep -q "automatic rollback" <<<"$XOUT" && grep -q "rollback: health: PASS" <<<"$XOUT"'
  v "fstab byte-identical after the automatic rollback ($(fsha | cut -c1-12))" '[ "$(fsha)" = "$H0" ]'
  L1="$(live)"; printf '%s\n' "$L1" | sed 's/^/  live: /'
  v "every live option back to step 0" '[ "$L1" = "$L0" ]'
  x "$T audit"; v "audit shows the same $N0 findings again" '[ "$XRC" = 1 ] && [ "$(nfind "$XOUT")" = "$N0" ]'
  v "apt TempDir file removed by the rollback" '[ ! -e /etc/apt/apt.conf.d/50pft-mounts ]'
fi

echo; echo "== 2. apply --yes"
x "$T apply --yes"
v "apply exit 0, health gate PASS" '[ "$XRC" = 0 ] && grep -q "health: PASS" <<<"$XOUT"'

echo; echo "== 3. after: audit, persistence without a reboot"
L2="$(live)"; printf '%s\n' "$L2" | sed 's/^/  live: /'
x "$T audit"
v "after: audit exit 0, RESULT: PASS" '[ "$XRC" = 0 ] && grep -q "RESULT: PASS" <<<"$XOUT"'
x "$T audit --json | jq -c '{findings, result}'"
v "after: --json findings 0" '[ "$(jq -r .findings <<<"$XOUT")" = 0 ]'
x "findmnt --verify"
v "findmnt --verify accepts /etc/fstab" '[ "$XRC" = 0 ]'
x "findmnt -s -n -o TARGET,SOURCE,FSTYPE,OPTIONS /tmp; findmnt -s -n -o TARGET,SOURCE,FSTYPE,OPTIONS /var/tmp; findmnt -s -n -o TARGET,SOURCE,FSTYPE,OPTIONS /dev/shm; findmnt -s -n -o TARGET,OPTIONS '$SRC'"
v "fstab entries (findmnt -s) for /tmp /var/tmp /dev/shm carry nodev,nosuid,noexec; data dir nodev,nosuid" \
  '[ "$(grep -cE "nodev,nosuid,noexec" <<<"$XOUT")" = 3 ] && grep -qE "^<?.*bind,nodev,nosuid$" <<<"$(tail -1 <<<"$XOUT")"'
# boot path 1: systemd-fstab-generator turns fstab lines into mount units (/run/systemd/generator). It skips API
# mounts such as /dev/shm, so there is no dev-shm.mount (run 05's check expected one, and read `systemctl show
# -p Options`, which is the LIVE kernel option string in kernel order: harness bug, kept in log 05).
x "for f in /run/systemd/generator/tmp.mount /run/systemd/generator/var-tmp.mount \$(grep -l '^Where=$SRC\$' /run/systemd/generator/*.mount); do echo \"== \${f##*/}\"; grep -E '^(SourcePath|Where|Options)=' \$f; done; ls /run/systemd/generator/dev-shm.mount 2>&1"
v "fstab-generator units (what the next boot mounts): /tmp, /var/tmp bind,nodev,nosuid,noexec; data dir bind,nodev,nosuid; all from /etc/fstab" \
  '[ "$(grep -c "^Options=bind,nodev,nosuid,noexec$" <<<"$XOUT")" = 2 ] && [ "$(grep -c "^Options=bind,nodev,nosuid$" <<<"$XOUT")" = 1 ] && [ "$(grep -c "^SourcePath=/etc/fstab$" <<<"$XOUT")" = 3 ]'
# boot path 2: /dev/shm gets its fstab options from systemd-remount-fs (mount -o remount <api mount> reads fstab).
# Proof without a reboot: drop noexec live, then a remount that names only the mount point must bring it back.
x "systemctl show -p ExecStart --value systemd-remount-fs.service | grep -o 'path=[^ ]*'; findmnt -n -o OPTIONS /dev/shm; mount -o remount,exec /dev/shm && findmnt -n -o OPTIONS /dev/shm; mount -o remount /dev/shm && findmnt -n -o OPTIONS /dev/shm"
findmnt -n -o OPTIONS /dev/shm | grep -qE '(^|,)noexec(,|$)' || mount -o remount,noexec /dev/shm  # never leave it exec
v "/dev/shm: noexec dropped live, then an fstab-only remount (the systemd-remount-fs path) restores nodev,nosuid,noexec" \
  '[ "$XRC" = 0 ] && ! grep -qE "(^|,)noexec(,|$)" <<<"$(sed -n 3p <<<"$XOUT")" && ( for o in nodev nosuid noexec; do grep -qE "(^|,)$o(,|$)" <<<"$(sed -n 4p <<<"$XOUT")" || exit 1; done )'
x "cat /etc/apt/apt.conf.d/50pft-mounts; stat -c '%a %U %n' /var/lib/pft-mounts/apt-tmp; apt-config dump | grep -i ExtractTemplates::TempDir"
v "apt TempDir points at the 0700 exec directory" '[ "$XRC" = 0 ] && grep -q "^700 root" <<<"$XOUT"'

echo; echo "== 4. negative controls (positive control: a root-fs directory without the option, removed afterwards)"
for d in /tmp /var/tmp /dev/shm; do
  cp /bin/true "$d/$NEG.true" && chmod 0755 "$d/$NEG.true"
  x "$d/$NEG.true"
  v "noexec $d: exec refused (126)" '[ "$XRC" = 126 ] && grep -q "Permission denied" <<<"$XOUT"'
done
cp /bin/true "$CTL/true" && chmod 0755 "$CTL/true"
x "$CTL/true"; v "positive control: the same binary in a root-fs dir runs (0)" '[ "$XRC" = 0 ]'
for d in /tmp /var/tmp /dev/shm; do
  mknod "$d/$NEG.zero" c 1 5
  x "head -c 1 $d/$NEG.zero | wc -c"
  v "nodev $d: device node made by mknod cannot be opened" 'grep -q "Permission denied" <<<"$XOUT"'
done
mknod "$SRC/.$NEG.zero" c 1 5
x "head -c 1 '$SRC/.$NEG.zero' | wc -c"
v "nodev data dir (host side): device node cannot be opened" 'grep -q "Permission denied" <<<"$XOUT"'
mknod "$CTL/zero" c 1 5
x "head -c 1 $CTL/zero | wc -c"; v "positive control: the same device in a root-fs dir reads 1 byte" '[ "$(tail -1 <<<"$XOUT")" = 1 ]'
cp /usr/bin/id "$SRC/.$NEG.id" && chown root:root "$SRC/.$NEG.id" && chmod 4755 "$SRC/.$NEG.id"
cp /usr/bin/id "$CTL/id" && chown root:root "$CTL/id" && chmod 4755 "$CTL/id"
x "stat -c '%A %U %n' '$SRC/.$NEG.id' $CTL/id"
x "exec 3< '$SRC/.$NEG.id'; setpriv --reuid=65534 --regid=65534 --clear-groups /proc/self/fd/3 -u"
v "nosuid data dir: a SUID-root binary run as uid 65534 keeps euid 65534" '[ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = 65534 ]'
x "exec 3< $CTL/id; setpriv --reuid=65534 --regid=65534 --clear-groups /proc/self/fd/3 -u"
v "positive control: the same SUID binary in a root-fs dir gives euid 0" '[ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = 0 ]'
x "awk -v t=$DATA_DEST '\$5 == t { print \$5, \$6 }' /proc/\$(docker inspect -f '{{.State.Pid}}' $c)/mountinfo"
v "inside $c: $DATA_DEST mounted nodev,nosuid (the running node has it, no restart)" 'grep -q "nosuid" <<<"$XOUT" && grep -q "nodev" <<<"$XOUT"'
cleanup; CTL="$(mktemp -d /usr/local/lib/pft-mounts-negctl.XXXXXX)"
x "ls -A /tmp /var/tmp /dev/shm '$SRC' 2>/dev/null | grep -c '$NEG' || true"
v "every control file removed" '[ "$(tail -1 <<<"$XOUT")" = 0 ]'

if [ "$DRILL" = 1 ]; then
  echo; echo "== 5. explicit rollback, then apply again"
  x "$T rollback --yes"
  v "rollback exit 0" '[ "$XRC" = 0 ] && grep -q "rollback: done" <<<"$XOUT"'
  v "fstab byte-identical to step 0 ($(fsha | cut -c1-12))" '[ "$(fsha)" = "$H0" ]'
  L3="$(live)"; printf '%s\n' "$L3" | sed 's/^/  live: /'
  v "every live option back to step 0" '[ "$L3" = "$L0" ]'
  x "$T audit"; v "audit shows the step-0 findings again ($N0)" '[ "$XRC" = 1 ] && [ "$(nfind "$XOUT")" = "$N0" ]'
  x "$T apply --yes"
  v "re-apply exit 0, gate PASS" '[ "$XRC" = 0 ] && grep -q "health: PASS" <<<"$XOUT"'
  x "$T audit"; v "after re-apply: audit PASS" '[ "$XRC" = 0 ]'
  L4="$(live)"
  v "live options after re-apply equal those after the first apply" '[ "$L4" = "$L2" ]'
fi

echo; echo "== end"
x "sshd -t && echo sshd config ok; ss -Hltn | awk '{print \$4}' | grep -cE ':22\$'"
v "sshd -t ok, :22 listening" '[ "$XRC" = 0 ] && grep -q "sshd config ok" <<<"$XOUT"'
v "$c StartedAt unchanged ($S0)" '[ "$(st)" = "$S0" ]'
v "server_state full" '[ "$(ss_)" = full ]'
echo "RESULT: $([ "$F" = 0 ] && echo PASS || echo "FAIL ($F)") $(date -u +%FT%TZ)"
[ "$F" = 0 ]
