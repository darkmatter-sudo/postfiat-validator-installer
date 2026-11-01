#!/usr/bin/env bash
# Offline tests for pft-mounts.sh against fake hosts (tests/stubs.sh + fake_mount.py): audit grading for absent
# mounts, self-binds, tmp.mount, duplicate/commented/UUID/escaped fstab lines, hidepid, a root-fs and a dedicated-fs
# data directory, --json and --prom; plan; apply/rollback (byte-identical fstab and mount tables) and every gate.
# No root, no real mounts.
# Usage: tests/run-tests.sh [path/to/pft-mounts.sh]
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-mounts.sh}"
# shellcheck source=tests/stubs.sh
. "$HERE/stubs.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -20; }
fresh() { N=$((N + 1)); E="$T/e$N"; mk_env "$E"; use_env "$E"; }
run() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
line() { grep -E "\] [^ ]+ +$1 " <<<"$OUT"; } # audit line for check id
st() { line "$1" | sed -E 's/^ *\[([A-Z]+) *\].*/\1/'; }
expect() { # NAME CHECK STATUS [DETAIL-REGEX]
  local s; s="$(st "$2")"
  if [ "$s" = "$3" ] && { [ -z "${4:-}" ] || line "$2" | grep -qE "$4"; }; then ok "$1"; else ko "$1 (want $3${4:+ /$4/}, got '${s}')" "$(line "$2")"; fi
}
mi_add() { echo "$1" >> "$E/root/proc/self/mountinfo"; }
fs_add() { printf '%s\n' "$1" >> "$E/root/etc/fstab"; }
calls() { grep -c "$1" "$E/s/calls"; }

# --- audit: bare host --------------------------------------------------------------------------------------
fresh; run audit
[ "$RC" = 1 ] && ok "bare: exit 1" || ko "bare: exit $RC" "$OUT"
expect "bare: /tmp not separate" /tmp:separate FAIL 'not a separate mount \(on /\)'
expect "bare: /tmp noexec" /tmp:noexec FAIL 'no separate mount'
expect "bare: /var/tmp nosuid" /var/tmp:nosuid FAIL
expect "bare: /dev/shm separate (systemd)" /dev/shm:separate PASS 'systemd'
expect "bare: /dev/shm nodev (systemd default)" /dev/shm:nodev PASS 'systemd default'
expect "bare: /dev/shm noexec" /dev/shm:noexec FAIL 'not set live'
expect "bare: hidepid off" proc:hidepid FAIL 'off'
expect "bare: data on root fs" data:mount INFO 'docker-volume:postfiatd_postfiatd-data.*root fs'
expect "bare: data nodev" data:nodev FAIL 'inside postfiatd'
expect "bare: data nosuid" data:nosuid FAIL
grep -q 'RESULT: FAIL - 12 finding' <<<"$OUT" && ok "bare: 12 findings" || ko "bare: count" "$(tail -1 <<<"$OUT")"
grep -q '/var/lib/docker' <<<"$OUT" && ko "bare: host path printed" "$(grep /var/lib/docker <<<"$OUT")" || ok "bare: no host volume path in output"
CODES="$(grep -oE '\] [0-9.]+ ' <<<"$OUT" | awk '{print $2}' | sort -u | paste -sd' ' -)"
[ "$CODES" = "1.1.2.1.1 1.1.2.1.2 1.1.2.1.3 1.1.2.1.4 1.1.2.2.1 1.1.2.2.2 1.1.2.2.3 1.1.2.2.4 1.1.2.5.1 1.1.2.5.2 1.1.2.5.3 1.1.2.5.4" ] \
  && ok "bare: CIS ids 1.1.2.1.x/2.x/5.x" || ko "bare: CIS ids" "$CODES"

# --json and --prom on the failing host
run audit --json --prom "$E/s/m.prom"
J="$(sed -n '/^{/,$p' <<<"$OUT")"
[ "$RC" = 1 ] && [ "$(jq -r '.findings' <<<"$J")" = 12 ] && [ "$(jq -r '.result' <<<"$J")" = FAIL ] \
  && [ "$(jq -r '[.checks[] | select(.id=="/tmp:noexec")][0].status' <<<"$J")" = FAIL ] && ok "json: findings 12, /tmp:noexec FAIL" || ko "json" "$OUT"
grep -qx 'pft_mounts_findings 12' "$E/s/m.prom" && grep -q 'pft_mounts_check{check="/tmp:noexec",cis="1.1.2.1.4",status="FAIL"} 0' "$E/s/m.prom" \
  && ! grep -q 'data:mount' "$E/s/m.prom" && ok "prom: findings 12, per-check 0, INFO not exported" || ko "prom" "$(cat "$E/s/m.prom")"
[ "$(stat -c %a "$E/s/m.prom")" = 644 ] && [ -z "$(find "$E/s" -name 'm.prom.*')" ] && ok "prom: 0644, no temp left" || ko "prom: mode/temp" "$(ls -l "$E/s")"

# --- audit: grading edge cases -----------------------------------------------------------------------------
# live-only: self-binds + options live, fstab untouched -> WARN (not persistent), never PASS
fresh
mi_add '40 22 8:1 /tmp /tmp rw,nosuid,nodev,noexec,relatime shared:20 - ext4 /dev/sda1 rw,discard'
run audit
expect "live-only: /tmp separate WARN" /tmp:separate WARN 'gone after the next boot'
expect "live-only: /tmp noexec WARN" /tmp:noexec WARN 'not persistent'

# persistent but not live (fstab block written, remount pending)
fresh
fs_add '/tmp /tmp none bind,nodev,nosuid,noexec 0 0'
mi_add '40 22 8:1 /tmp /tmp rw,relatime shared:20 - ext4 /dev/sda1 rw,discard'
run audit
expect "pending: /tmp noexec FAIL, entry has it" /tmp:noexec FAIL 'has it: remount pending'
expect "pending: /tmp separate PASS (fstab)" /tmp:separate PASS 'fstab:3'

# duplicate fstab targets: the LAST one wins (mount -a stacks), plus a WARN
fresh
mi_add '40 22 8:1 /tmp /tmp rw,nosuid,nodev,noexec,relatime shared:20 - ext4 /dev/sda1 rw,discard'
fs_add '/tmp /tmp none bind,nodev,nosuid,noexec 0 0'
fs_add '/tmp /tmp none bind,nodev 0 0'
run audit
expect "dup: WARN for /tmp" fstab-dup:/tmp WARN '2 fstab entries'
expect "dup: last line wins (noexec not persistent)" /tmp:noexec WARN 'not persistent'
expect "dup: nodev in last line" /tmp:nodev PASS 'fstab:4'

# comments, UUID sources and blank lines: a commented-out hardening line counts for nothing
fresh
fs_add '# /tmp /tmp none bind,nodev,nosuid,noexec 0 0'
fs_add ''
fs_add 'UUID=0a1b2c3d-1111-2222-3333-444455556666 /var/tmp ext4 defaults,nodev,nosuid,noexec 0 2'
mi_add '40 22 8:1 /tmp /tmp rw,nosuid,nodev,noexec,relatime shared:20 - ext4 /dev/sda1 rw,discard'
mi_add '41 22 8:2 / /var/tmp rw,nosuid,nodev,noexec,relatime shared:21 - ext4 /dev/sdb1 rw'
run audit
expect "comment: commented /tmp line ignored" /tmp:noexec WARN 'not persistent'
expect "uuid: /var/tmp from UUID= line" /var/tmp:noexec PASS 'fstab:5'
expect "uuid: /var/tmp separate" /var/tmp:separate PASS 'ext4 mount'

# tmp.mount (tmpfs) enabled in /etc/systemd/system: it is the persistent source for /tmp
fresh
printf '[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\nOptions=mode=1777,strictatime,nosuid,nodev,size=50%%\n' > "$E/root/etc/systemd/system/tmp.mount"
mkdir -p "$E/root/etc/systemd/system/local-fs.target.wants"; ln -s ../tmp.mount "$E/root/etc/systemd/system/local-fs.target.wants/tmp.mount"
fs_add '/tmp /tmp none bind,nodev,nosuid,noexec 0 0'
mi_add '40 22 0:30 / /tmp rw,nosuid,nodev,noexec shared:20 - tmpfs tmpfs rw,inode64'
run audit
expect "tmp.mount: separate via tmp.mount" /tmp:separate PASS 'tmp.mount'
expect "tmp.mount: overrides fstab (no noexec in unit)" /tmp:noexec WARN 'not persistent'
expect "tmp.mount: nosuid" /tmp:nosuid PASS 'tmp.mount'
# the same unit file, NOT enabled -> fstab is the source
rm "$E/root/etc/systemd/system/local-fs.target.wants/tmp.mount"; run audit
expect "tmp.mount disabled: fstab is the source" /tmp:noexec PASS 'fstab:3'

# absent tmpfs: /dev/shm not mounted at all
fresh; sed -i '/ \/dev\/shm /d' "$E/root/proc/self/mountinfo"; run audit
expect "no /dev/shm: separate FAIL" /dev/shm:separate FAIL 'not a separate mount \(on /dev\)'
# /dev/shm noexec live but no fstab entry: systemd's default lacks noexec -> WARN
fresh; sed -i 's#^24 23 0:21 / /dev/shm rw,nosuid,nodev #24 23 0:21 / /dev/shm rw,nosuid,nodev,noexec #' "$E/root/proc/self/mountinfo"; run audit
expect "shm: noexec live only WARN" /dev/shm:noexec WARN 'not persistent'

# escaped mount points (\040 = space) are decoded on both sides
fresh
mi_add '42 22 8:1 /srv/a\040b /var/tmp rw,nosuid,nodev,noexec,relatime shared:22 - ext4 /dev/sda1 rw'
fs_add '/srv/a\040b /var/tmp none bind,nodev,nosuid,noexec 0 0'
run audit
expect "escaped: /var/tmp from a spaced source" /var/tmp:noexec PASS 'fstab:3'

# hidepid: ptraceable does not hide; invisible live without fstab -> WARN; both -> PASS
fresh; sed -i 's#- proc proc rw$#- proc proc rw,hidepid=ptraceable#' "$E/root/proc/self/mountinfo"; run audit
expect "hidepid=ptraceable FAIL" proc:hidepid FAIL
fresh; sed -i 's#- proc proc rw$#- proc proc rw,hidepid=invisible,gid=998#' "$E/root/proc/self/mountinfo"; run audit
expect "hidepid live only WARN" proc:hidepid WARN 'not in fstab'
fs_add 'proc /proc proc defaults,hidepid=2,gid=998 0 0'; run audit
expect "hidepid live + fstab PASS" proc:hidepid PASS 'hidepid=invisible \(exempt gid set\)'

# data dir on a dedicated filesystem whose own fstab line has nodev,nosuid
fresh
export STUB_DATA_SRC=/data/postfiatd
mi_add '43 22 8:3 / /data rw,nosuid,nodev,relatime shared:23 - xfs /dev/sdc1 rw'
fs_add 'UUID=9f9f9f9f-0000-1111-2222-333344445555 /data xfs defaults,nodev,nosuid 0 2'
sed -i 's#^901 900 8:1 [^ ]* /var/lib/postfiatd/db rw,relatime #901 900 8:3 /postfiatd /var/lib/postfiatd/db rw,nosuid,nodev,relatime #' "$E/root/proc/4242/mountinfo"
run audit
expect "dedicated fs: data mount INFO" data:mount INFO 'on host mount /data$'
expect "dedicated fs: nodev via the fs's fstab line" data:nodev PASS 'fstab:3'
unset STUB_DATA_SRC
# data flags set inside the container only (no host entry) -> WARN: the next container start loses them
fresh; sed -i 's#/var/lib/postfiatd/db rw,relatime #/var/lib/postfiatd/db rw,nosuid,nodev,relatime #' "$E/root/proc/4242/mountinfo"; run audit
expect "data: container-only WARN" data:nosuid WARN 'next container start'
# container not running / no data mount -> INFO, no data findings
fresh; echo 0 > "$E/s/pid"; run audit
expect "data: container down INFO" data:mount INFO 'skipped'
[ -z "$(line data:nodev)" ] && ok "data: no data checks when skipped" || ko "data: checks when skipped" "$OUT"

# --- plan -------------------------------------------------------------------------------------------------
fresh; run plan
[ "$RC" = 0 ] && grep -q '/tmp /tmp none bind,nodev,nosuid,noexec 0 0' <<<"$OUT" && grep -q '<docker-volume:postfiatd_postfiatd-data> <docker-volume:postfiatd_postfiatd-data> none bind,nodev,nosuid' <<<"$OUT" \
  && ! grep -q /var/lib/docker <<<"$OUT" && ok "plan: block shown, volume path redacted" || ko "plan" "$OUT"
fs_add '/tmp /tmp none bind,nodev 0 0'; run plan
[ "$RC" = 4 ] && grep -q 'REFUSE: unmanaged.*' <<<"$OUT" && grep -q 'line 3: /tmp /tmp none bind,nodev 0 0' <<<"$OUT" && ok "plan: refuses an unmanaged /tmp line" || ko "plan: unmanaged" "$OUT"

# --- apply / rollback -------------------------------------------------------------------------------------
snap() { cat "$E/root/etc/fstab" "$E/root/proc/self/mountinfo" "$E/root/proc/4242/mountinfo" | sha256sum | cut -c1-16; }
fresh; run apply
[ "$RC" = 4 ] && grep -q 'pass --yes' <<<"$OUT" && ok "apply: refuses without --yes" || ko "apply: no --yes" "$OUT"
S0="$(snap)"; run apply --dry-run
[ "$RC" = 0 ] && [ "$(snap)" = "$S0" ] && [ "$(calls '^mount\|^nsenter\|groupadd')" = 0 ] && grep -q '^+/tmp /tmp none bind' <<<"$OUT" \
  && ok "apply --dry-run: diff shown, nothing changed" || ko "apply --dry-run" "$OUT"

fresh; cp "$E/root/etc/fstab" "$E/s/fstab.orig"; cp "$E/root/proc/self/mountinfo" "$E/s/mi.orig"; cp "$E/root/proc/4242/mountinfo" "$E/s/cmi.orig"
run apply --yes
[ "$RC" = 0 ] && grep -q 'health: PASS' <<<"$OUT" && ok "apply: exit 0, gate PASS" || ko "apply: exit $RC" "$OUT"
[ "$(head -2 "$E/root/etc/fstab")" = "$(cat "$E/s/fstab.orig")" ] && [ "$(grep -c '^# BEGIN pft-mounts' "$E/root/etc/fstab")" = 1 ] \
  && ok "apply: other fstab lines byte-identical, one block" || ko "apply: fstab" "$(cat "$E/root/etc/fstab")"
grep -q 'proc /proc proc defaults,hidepid=invisible,gid=998 0 0' "$E/root/etc/fstab" && grep -q '^pft-procview:x:998:$' "$E/s/group" \
  && ok "apply: group created, gid in fstab" || ko "apply: group" "$(cat "$E/s/group")"
grep -q 'nsenter -t 4242 -m -- mount --options-mode ignore -o remount,bind,rw,relatime,nodev,nosuid /var/lib/postfiatd/db' "$E/s/calls" \
  && ok "apply: container remount inside postfiatd's namespace" || ko "apply: nsenter" "$(grep nsenter "$E/s/calls")"
grep -q 'systemctl start pft-heartbeat.service' "$E/s/calls" && grep -q 'systemctl start pft-statewatch@postfiatd.service' "$E/s/calls" \
  && ok "apply: gate re-ran the timer oneshots" || ko "apply: gate units" "$(grep 'systemctl start' "$E/s/calls")"
run audit
[ "$RC" = 0 ] && grep -q 'RESULT: PASS' <<<"$OUT" && ok "after apply: audit PASS (exit 0)" || ko "after apply: audit" "$OUT"
C0="$(calls '^mount')"; run apply --yes
[ "$RC" = 0 ] && grep -q 'already applied' <<<"$OUT" && [ "$(calls '^mount')" = "$C0" ] && ok "apply again: idempotent, no mount calls" || ko "apply again" "$OUT"
run rollback --yes
[ "$RC" = 0 ] && cmp -s "$E/root/etc/fstab" "$E/s/fstab.orig" && cmp -s "$E/root/proc/self/mountinfo" "$E/s/mi.orig" && cmp -s "$E/root/proc/4242/mountinfo" "$E/s/cmi.orig" \
  && ok "rollback: fstab + both mount tables byte-identical to before apply" || ko "rollback: rc=$RC" "$OUT"$'\n'"$(diff "$E/s/mi.orig" "$E/root/proc/self/mountinfo"; diff "$E/s/cmi.orig" "$E/root/proc/4242/mountinfo")"
run rollback
[ "$RC" = 4 ] && ok "rollback: refuses without --yes" || ko "rollback: no --yes rc=$RC" "$OUT"

# re-apply over an existing (older) managed block: still exactly one block, nothing else touched
fresh; printf '%s\n' "# BEGIN pft-mounts (managed; edit with pft-mounts, see mounts/README.md)" '/tmp /tmp none bind,nodev 0 0' '# END pft-mounts' >> "$E/root/etc/fstab"
run apply --yes
[ "$RC" = 0 ] && [ "$(grep -c '^# BEGIN pft-mounts' "$E/root/etc/fstab")" = 1 ] && ! grep -q 'bind,nodev 0 0' "$E/root/etc/fstab" && ok "apply: replaces an old block" || ko "apply: old block" "$(cat "$E/root/etc/fstab")"

# gates: each miss -> automatic rollback, exit 1, fstab and mount tables back byte-identical
gate_case() { # NAME SETUP
  fresh; cp "$E/root/etc/fstab" "$E/s/fstab.orig"; cp "$E/root/proc/self/mountinfo" "$E/s/mi.orig"; cp "$E/root/proc/4242/mountinfo" "$E/s/cmi.orig"
  eval "$2"
  run apply --yes
  if [ "$RC" = 1 ] && grep -q 'automatic rollback' <<<"$OUT" && cmp -s "$E/root/etc/fstab" "$E/s/fstab.orig" \
     && cmp -s "$E/root/proc/self/mountinfo" "$E/s/mi.orig" && cmp -s "$E/root/proc/4242/mountinfo" "$E/s/cmi.orig"; then ok "gate: $1 -> rolled back"
  else ko "gate: $1 (rc=$RC)" "$OUT"; fi
  unset PFT_MOUNTS_INJECT FAKE_FAIL FAKE_NS_FAIL
}
gate_case "injected health miss" 'export PFT_MOUNTS_INJECT=health'
gate_case "server_state not full" 'echo syncing > "$E/s/state"'
gate_case "oneshot unit fails" 'echo pft-statewatch@postfiatd.service > "$E/s/failunits"'
gate_case "daemon goes inactive" 'touch "$E/s/daemon-down"'
gate_case "ssh handshake fails" 'touch "$E/s/ssh-down"'
gate_case "postfiatd restarted (StartedAt changed)" 'echo 1 > "$E/s/restart-after"'
gate_case "live remount fails (/var/tmp)" 'export FAKE_FAIL="noexec /var/tmp"'
gate_case "container remount fails" 'export FAKE_NS_FAIL=remount'
fresh; OUT="$(PFT_MOUNTS_INJECT=health bash "$TOOL" apply --yes 2>&1)"
grep -q 'injected=health' <<<"$OUT" && ok "gate: FAIL line names the injection" || ko "gate: injection label"

# candidate rejected by findmnt --verify -> exit 4, nothing touched
fresh; S0="$(snap)"; touch "$E/s/verify-fail"; run apply --yes
[ "$RC" = 4 ] && [ "$(snap)" = "$S0" ] && [ "$(calls '^mount')" = 0 ] && grep -q 'REFUSED' <<<"$OUT" && ok "verify fail: refused, untouched" || ko "verify fail rc=$RC" "$OUT"

# rollback itself fails -> exit 5
fresh; export PFT_MOUNTS_INJECT=health FAKE_FAIL="umount /var/tmp"; run apply --yes
[ "$RC" = 5 ] && ok "rollback failure: exit 5" || ko "rollback failure: rc=$RC" "$OUT"
unset PFT_MOUNTS_INJECT FAKE_FAIL

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
