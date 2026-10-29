#!/usr/bin/env bash
# Offline tests for pft-patch.sh status and policy: every status class on its own fixture, --json, read-only status
# (fake root unchanged, apt-get only simulated), the unattended-upgrades blacklist semantics (re.match), policy
# apply/idempotence/refusal when overridden, and byte-identical rollback. No root, no apt, no network.
# Usage: tests/run-tests.sh [path/to/pft-patch.sh]
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-patch.sh}"
# shellcheck source=SCRIPTDIR/stubs.sh
. "$HERE/stubs.sh"
ORIG_PATH="$PATH"
T="$(mktemp -d)"; trap 'rm -rf "${T:?}"' EXIT
PASS=0; FAIL=0; N=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -15; }
fresh() { N=$((N + 1)); E="$T/e$N"; mk_env "$E"; use_env "$E"; }
run() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
expect() { # NAME RC REGEX
  if [ "$RC" = "$2" ] && grep -qE -- "$3" <<<"$OUT"; then ok "$1"; else ko "$1 (rc=$RC want $2, /$3/)" "$OUT"; fi
}
expect_not() { # NAME REGEX
  if grep -qE -- "$2" <<<"$OUT"; then ko "$1 (unexpected /$2/)" "$OUT"; else ok "$1"; fi
}
treesum() { (cd "$PFT_PATCH_ROOT" && find . -type f -print0 | sort -z | xargs -0 sha256sum 2>/dev/null; find . | sort) | sha256sum; }
safe() { bash "$TOOL" policy apply --yes >/dev/null 2>&1; } # a host with the policy applied
D="etc/apt/apt.conf.d"
CD() { echo "${PFT_PATCH_ROOT:?}/$D"; }        # the fake host's apt.conf.d
nodrop() { rm -f "$(CD)/52pft-patch"; }         # a host without the policy

# --- status: clean host
fresh; safe; run status
expect "clean host -> OK exit 0" 0 '^RESULT: OK$'
expect_not "clean host has no WARN/CRIT" '^\[(WARN|CRIT)'
expect "exposure OK after policy" 0 '\[OK  \] exposure'

# --- status: one fixture per class (NAME | setup | rc | regex)
while IFS='|' read -r name setup want re; do
  [ -z "$name" ] && continue
  fresh; safe; eval "$setup"; run status
  expect "status $name" "$want" "$re"
done <<'CASES'
security update -> CRIT|echo "$SIM_SEC" > "$STUB_S/sim"|2|\[CRIT\] updates +1 security update\(s\) pending: libssl3$
other update only -> WARN|echo "$SIM_OTH" > "$STUB_S/sim"|1|\[WARN\] updates +1 other update\(s\) pending \(0 kernel
kernel counted as other|printf '%s\n%s\n' "$SIM_KER" "$SIM_OTH" > "$STUB_S/sim"|1|2 other update\(s\) pending \(1 kernel package
third-party repo is other, not security|echo "$SIM_3RD" > "$STUB_S/sim"|1|\[OK  \] updates +0 security
mixed: CRIT wins|printf '%s\n%s\n' "$SIM_OTH" "$SIM_SEC" > "$STUB_S/sim"|2|^RESULT: CRIT$
simulation fails -> CRIT|touch "$STUB_S/sim_fail"|2|\[CRIT\] updates +cannot simulate: apt-get -s failed: E: Could not open lock
hold without update -> WARN|echo tmux > "$STUB_S/holds"|1|\[WARN\] holds +1 held package\(s\), none with a pending update: tmux
held package with update -> CRIT|echo nano > "$STUB_S/holds"; echo "$SIM_OTH" > "$STUB_S/sim"|2|\[CRIT\] holds +held with an update pending: nano
reboot-required -> CRIT|touch "$PFT_PATCH_ROOT/var/run/reboot-required"; printf 'linux-image-5.15.0-202-generic\nlibc6\n' > "$PFT_PATCH_ROOT/var/run/reboot-required.pkgs"|2|\[CRIT\] reboot +reboot required by: linux-image-5.15.0-202-generic libc6
reboot-required without pkgs file|touch "$PFT_PATCH_ROOT/var/run/reboot-required"|2|\[CRIT\] reboot +reboot required$
newer kernel installed KSTA 3|sed -i 's/KSTA: 1/KSTA: 3/' "$STUB_S/nr"|1|\[WARN\] kernel +a newer kernel is installed \(needrestart KSTA 3\)
ABI kernel KSTA 2|sed -i 's/KSTA: 1/KSTA: 2/' "$STUB_S/nr"|1|\[WARN\] kernel .*KSTA 2
services on old libs -> WARN|printf 'NEEDRESTART-SVC: packagekit.service\nNEEDRESTART-SVC: ssh.service\n' >> "$STUB_S/nr"|1|\[WARN\] services +restart needed \(old libraries\): packagekit.service ssh.service
needrestart missing -> INFO only|touch "$STUB_S/nr_missing"|0|\[INFO\] services +needrestart not available or incomplete
needrestart without KSTA (non-root) -> INFO|printf 'NEEDRESTART-VER: 3.5\n' > "$STUB_S/nr"|0|\[INFO\] services +needrestart not available or incomplete
no policy -> exposure WARN, installed only|nodrop|1|\[WARN\] exposure .*: docker.io containerd runc not blacklisted
unattended off -> INFO, no exposure|nodrop; sed -i 's/Unattended-Upgrade "1"/Unattended-Upgrade "0"/' "$(CD)/20auto-upgrades"|0|\[INFO\] exposure +unattended upgrades are off
Automatic-Reboot true in a later file -> WARN|echo 'Unattended-Upgrade::Automatic-Reboot "true";' > "$(CD)/99local"|1|\[WARN\] autoreboot +Unattended-Upgrade::Automatic-Reboot=true
prefix blacklist entry covers docker.io (re.match)|nodrop; printf 'Unattended-Upgrade::Package-Blacklist { "docker"; "containerd"; "runc$"; };\n' > "$(CD)/60x"|0|\[OK  \] exposure
mid-string entry does not cover (re.match is anchored)|nodrop; printf 'Unattended-Upgrade::Package-Blacklist { "io"; "containerd"; "runc"; };\n' > "$(CD)/60x"|1|\[WARN\] exposure .*: docker.io not blacklisted
not-installed runtime packages ignored|nodrop; : > "$STUB_S/installed"|0|\[OK  \] exposure
CASES

# --- status --json
fresh; safe; printf '%s\n%s\n%s\n' "$SIM_SEC" "$SIM_OTH" "$SIM_KER" > "$STUB_S/sim"; touch "$PFT_PATCH_ROOT/var/run/reboot-required"
echo 'NEEDRESTART-SVC: ssh.service' >> "$STUB_S/nr"; nodrop; run status --json
if [ "$RC" = 2 ] && jq -e '.result=="CRIT" and .exit==2 and .updates.security==1 and .updates.other==2 and .updates.kernel==1
  and .reboot_required==true and .needrestart.ksta=="1" and .needrestart.services==["ssh.service"]
  and .unattended.runtime_exposed==["docker.io","containerd","runc"] and .unattended.enabled==true
  and (.items|length)==8' <<<"$OUT" >/dev/null; then ok "--json fields and exit 2"; else ko "--json fields and exit 2" "$OUT"; fi
fresh; safe; run status --json
jq -e '.result=="OK" and .exit==0 and .unattended.runtime_exposed==[] and .holds==[]' <<<"$OUT" >/dev/null && [ "$RC" = 0 ] && ok "--json clean host" || ko "--json clean host" "$OUT"

# --- status is read-only
fresh; printf '%s\n%s\n' "$SIM_SEC" "$SIM_OTH" > "$STUB_S/sim"; before="$(treesum)"; run status; run status --json
[ "$before" = "$(treesum)" ] && ok "status leaves the fake root unchanged" || ko "status leaves the fake root unchanged"
if grep '^apt-get' "$STUB_S/calls" | grep -qv -- ' -s '; then ko "apt-get only called with -s" "$(cat "$STUB_S/calls")"
else grep -q '^apt-get -s ' "$STUB_S/calls" && ok "apt-get only called with -s (simulation)" || ko "apt-get called at all"; fi
grep -qE '^apt-mark (hold|unhold)|^needrestart .*-r a' "$STUB_S/calls" && ko "no state-changing apt-mark/needrestart" || ok "no state-changing apt-mark/needrestart"

# --- policy
fresh; run policy apply
expect "apply without --yes refused" 4 'add --yes'
[ -e "$(CD)/52pft-patch" ] && ko "no drop-in after refusal" || ok "no drop-in after refusal"
run policy apply --yes
expect "apply" 0 '^applied: .*/52pft-patch sha256 [0-9a-f]{64}$'
expect "apply backup records absent drop-in" 0 '^backup: .*\(drop-in absent, apt-config dump sha256 [0-9a-f]{64}\)'
expect "apply reports effective blacklist" 0 'effective: blacklist docker.io docker-ce docker-ce-cli containerd containerd.io runc; Automatic-Reboot false; Unattended-Upgrade 1$'
[ "$(bash "$TOOL" policy show)" = "$(cat "$(CD)/52pft-patch")" ] && ok "policy show == installed drop-in" || ko "policy show == installed drop-in"
grep -q 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security"' <<<"$("$PFT_PATCH_APT_CONFIG" dump)" && ok "security origin still allowed after apply" || ko "security origin still allowed after apply"
[ "$(stat -c %a "$(CD)/52pft-patch")" = 644 ] && ok "drop-in mode 0644" || ko "drop-in mode 0644"
nb="$(find "$PFT_PATCH_ROOT/var/lib/pft-patch/backup" -mindepth 1 -maxdepth 1 | wc -l)"
run policy apply --yes
expect "second apply is a no-op" 0 '^policy already applied'
[ "$(find "$PFT_PATCH_ROOT/var/lib/pft-patch/backup" -mindepth 1 -maxdepth 1 | wc -l)" = "$nb" ] && ok "no-op apply makes no backup" || ko "no-op apply makes no backup"

# rollback from "absent"
fresh; base="$("$PFT_PATCH_APT_CONFIG" dump | sha256sum)"; bash "$TOOL" policy apply --yes >/dev/null
run policy rollback
expect "rollback without --yes refused" 4 'add --yes'
run policy rollback --yes
expect "rollback from absent: drop-in removed" 0 'drop-in removed \(was absent before apply\)'
expect "rollback from absent: byte-identical" 0 '^rollback: byte-identical$'
[ ! -e "$(CD)/52pft-patch" ] && [ "$base" = "$("$PFT_PATCH_APT_CONFIG" dump | sha256sum)" ] && ok "effective config == before apply" || ko "effective config == before apply"
run policy rollback --yes
expect "second rollback: no backup left" 2 'no backup in'

# rollback restores an older, different drop-in byte for byte (mode and content)
fresh; printf '// operator edit\nUnattended-Upgrade::Package-Blacklist { "vim"; };\n' > "$(CD)/52pft-patch"; chmod 600 "$(CD)/52pft-patch"
cp -p "$(CD)/52pft-patch" "$T/orig"; run policy apply --yes
expect "apply over an existing drop-in backs it up" 0 '^backup: .*\(drop-in sha256 [0-9a-f]{64}'
run policy rollback --yes
expect "rollback restores previous drop-in" 0 '^rollback: byte-identical$'
cmp -s "$T/orig" "$(CD)/52pft-patch" && [ "$(stat -c %a "$(CD)/52pft-patch")" = 600 ] && ok "restored drop-in byte-identical, mode kept" || ko "restored drop-in byte-identical, mode kept"

# rollback detects a mismatch (effective config changed since apply)
fresh; bash "$TOOL" policy apply --yes >/dev/null; echo 'APT::Periodic::Verbose "2";' > "$(CD)/99other"; run policy rollback --yes
expect "rollback mismatch -> exit 5, backup kept" 5 'rollback: MISMATCH \(backup kept in'

# apply refused when a later file overrides it; previous state restored, no backup left
fresh; echo 'Unattended-Upgrade::Automatic-Reboot "true";' > "$(CD)/99local"; run policy apply --yes
expect "overridden Automatic-Reboot -> refused exit 4" 4 "REFUSED: the drop-in is not effective"
expect "refusal names the override" 4 "Automatic-Reboot is 'true'"
[ ! -e "$(CD)/52pft-patch" ] && ok "refused apply leaves no drop-in" || ko "refused apply leaves no drop-in"
[ -z "$(ls -A "$PFT_PATCH_ROOT/var/lib/pft-patch/backup" 2>/dev/null)" ] && ok "refused apply leaves no backup" || ko "refused apply leaves no backup"
fresh
RUNTIME_PKGS="docker.io" PFT_PATCH_APT_CONFIG="$E/bin/apt-config-noblacklist" run policy apply --yes
expect "blacklist not visible in effective config -> refused" 4 'not blacklisted: docker.io'
[ ! -e "$(CD)/52pft-patch" ] && ok "refused (blacklist) leaves no drop-in" || ko "refused (blacklist) leaves no drop-in"

# --- usage
fresh; run; expect "no command -> usage 3" 3 'Usage'
run status --yaml; expect "bad status flag -> 3" 3 'Usage'
run policy apply --force; expect "bad policy flag -> 3" 3 'Usage'
run policy frob; expect "bad policy sub -> 3" 3 'Usage'

# --- run mode (two-host fake)
# shellcheck source=SCRIPTDIR/run-stubs.sh
. "$HERE/run-stubs.sh"
# shellcheck source=SCRIPTDIR/run-cases.sh
. "$HERE/run-cases.sh"

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
