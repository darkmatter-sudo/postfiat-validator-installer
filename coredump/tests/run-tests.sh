#!/usr/bin/env bash
# check() takes its condition as a single-quoted string evaluated later, on purpose.
# shellcheck disable=SC2016,SC2034
# Tests for pft-coredump.sh against fixture trees (fake /proc, /etc, /sys) and stub docker / prlimit / sysctl /
# dpkg-query / systemctl / pft-maint (tests/stubs). No root, no real container, nothing outside TEST_TMPDIR.
# Usage: bash tests/run-tests.sh [TOOL]   (TOOL defaults to ../pft-coredump.sh; mutate.py passes mutated copies)
# Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
TOOL="${1:-$HERE/../pft-coredump.sh}"
BASE="$(mktemp -d "${TEST_TMPDIR:-$HOME/.cache}/pft-cd-tests.XXXXXX")"
trap 'rm -rf "$BASE"' EXIT
PASS=0; FAILN=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAILN=$((FAILN + 1)); echo "FAIL $1${2:+: $2}"; }
check() { if eval "$2"; then ok "$1"; else bad "$1" "${3:-}"; fi; }   # NAME CONDITION [DETAIL]

limits() { printf 'Limit                     Soft Limit           Hard Limit           Units     \nMax core file size        %s            %s            bytes     \n' "$1" "$2"; }
# fresh fixture: compose (validator shape) or run (sentry shape) container with PID 1 + one child, unlimited cores
fixture() { # KIND
  T="$BASE/t$RANDOM$RANDOM"; ROOT="$T/root"; STUB="$T/stub"
  mkdir -p "$ROOT"/proc/sys/kernel "$ROOT"/proc/sys/fs "$ROOT"/etc/sysctl.d "$ROOT"/etc/default "$ROOT"/etc/docker "$ROOT"/sys/power \
    "$ROOT"/opt/postfiatd "$ROOT"/var/crash "$ROOT/var/lib/docker/volumes/data" "$STUB/c" "$STUB/pkg"
  echo core > "$ROOT/proc/sys/kernel/core_pattern"; echo 0 > "$ROOT/proc/sys/fs/suid_dumpable"
  printf 'Filename\tType\tSize\tUsed\tPriority\n' > "$ROOT/proc/swaps"
  echo '[disabled] platform shutdown' > "$ROOT/sys/power/disk"
  echo '{"live-restore": true}' > "$ROOT/etc/docker/daemon.json"
  touch "$STUB/pkg/apport"; echo 'enabled=0' > "$ROOT/etc/default/apport"
  local p
  for p in 100 101; do
    mkdir -p "$ROOT/proc/$p"; echo "0::/system.slice/docker-node.scope" > "$ROOT/proc/$p/cgroup"
    limits unlimited unlimited > "$ROOT/proc/$p/limits"; echo 00000033 > "$ROOT/proc/$p/coredump_filter"
  done
  mkdir -p "$ROOT/proc/200"; echo "0::/system.slice/other.service" > "$ROOT/proc/200/cgroup"; limits unlimited unlimited > "$ROOT/proc/200/limits"
  if [ "$1" = compose ]; then
    NAME=postfiatd
    printf 'NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.shutdown.yml\n' > "$ROOT/opt/postfiatd/.env"; chmod 600 "$ROOT/opt/postfiatd/.env"
    jq -n '{Name: "/postfiatd", State: {Pid: 100, Running: true, StartedAt: "t0"},
      Config: {Image: "agtipft/postfiatd:testnet-light-latest", Cmd: null, Env: ["NETWORK=testnet"], User: "0:0", StopTimeout: 31,
               Labels: {"com.docker.compose.project": "postfiatd", "com.docker.compose.project.working_dir": "/opt/postfiatd",
                        "com.docker.compose.service": "postfiatd"}},
      HostConfig: {RestartPolicy: {Name: "unless-stopped"}, LogConfig: {Type: "json-file", Config: {}}, NetworkMode: "postfiatd_default",
                   Ulimits: null, ReadonlyRootfs: true, SecurityOpt: ["no-new-privileges:true"]},
      Mounts: [{Type: "bind", Source: "/opt/postfiatd/logs", Destination: "/var/log/postfiatd", RW: true}]}' > "$STUB/c/postfiatd.json"
  else
    NAME=postfiatd-sentry
    jq -n '{Name: "/postfiatd-sentry", State: {Pid: 100, Running: true, StartedAt: "t0"},
      Config: {Image: "agtipft/postfiatd:testnet-light-latest", Cmd: null, Env: ["NETWORK=testnet"], User: "", StopTimeout: 31, Labels: {}},
      HostConfig: {RestartPolicy: {Name: "unless-stopped"}, LogConfig: {Type: "json-file", Config: {"max-size": "100m"}}, NetworkMode: "default",
                   Ulimits: null, ReadonlyRootfs: true, CapDrop: ["ALL"], SecurityOpt: ["no-new-privileges:true", "seccomp={stored}"]},
      Mounts: [{Type: "volume", Name: "sentry-db", Source: "/var/lib/docker/volumes/data", Destination: "/var/lib/postfiatd/db", RW: true}]}' > "$STUB/c/postfiatd-sentry.json"
    mkdir -p "$ROOT/usr/local/bin"
    printf '#!/bin/sh\n# copies (.HostConfig.Ulimits // [])\n' > "$ROOT/usr/local/bin/pft-seccomp"
    printf '#!/bin/sh\n# copies (.HostConfig.Ulimits // [])\n' > "$ROOT/usr/local/bin/pft-apparmor"
  fi
  echo '{"result":{"info":{"server_state":"full"}}}' > "$STUB/rpc.json"
  : > "$STUB/calls"
}
# run the tool in the current fixture; output in OUT, exit code in RC
cd_run() {
  OUT="$(PFT_COREDUMP_ROOT="$ROOT" PFT_STUB="$STUB" PFT_COREDUMP_DOCKER="$HERE/stubs/docker" PFT_COREDUMP_PRLIMIT="$HERE/stubs/prlimit" \
    PFT_COREDUMP_SYSCTL="$HERE/stubs/sysctl" PFT_COREDUMP_DPKG="$HERE/stubs/dpkg-query" PFT_COREDUMP_SYSTEMCTL="$HERE/stubs/systemctl" \
    PFT_COREDUMP_MAINT="$HERE/stubs/pft-maint" PFT_COREDUMP_RPC="cat $STUB/rpc.json" PFT_COREDUMP_UID="${UIDV:-0}" CONTAINER="$NAME" \
    POLL_SEC=0 RECOVER_TIMEOUT=2 SCAN_DIRS="${SCAN:-/var/crash
/opt/postfiatd
/var/lib/docker/volumes/data}" bash "$TOOL" "$@" </dev/null 2>&1)"; RC=$?
}
st() { grep -o "\[[A-Z]*\] $1 " <<<"$OUT" | tr -d '[]' | cut -d' ' -f1; }   # status of check ID in OUT
lim() { awk '/^Max core/ { print $5 ":" $6 }' "$ROOT/proc/$1/limits"; }
pat() { cat "$ROOT/proc/sys/kernel/core_pattern"; }
safe_dropin() { printf 'kernel.core_pattern = |/bin/false\n' > "$ROOT/etc/sysctl.d/60-pft-coredump.conf"; }
all00() { local p; for p in 100 101; do limits 0 0 > "$ROOT/proc/$p/limits"; done; }

echo "pft-coredump tests - tool sha256 $(sha256sum "$TOOL" | cut -c1-64)"

# ---- audit: baseline (the found state on both hosts) ----
fixture compose; cd_run audit
check "baseline: exit 2 (FAIL)" '[ "$RC" = 2 ]' "rc=$RC"
check "baseline: CD01 FAIL (pattern core)" '[ "$(st CD01)" = FAIL ]'
check "baseline: CD02 FAIL (kernel default)" '[ "$(st CD02)" = FAIL ] && grep -q "kernel default" <<<"$OUT"'
check "baseline: CD06 FAIL 2/2 (other cgroup ignored)" '[ "$(st CD06)" = FAIL ] && grep -q "2/2 container processes" <<<"$OUT"'
check "baseline: CD07 WARN (anon memory, dump possible)" '[ "$(st CD07)" = WARN ]'
check "baseline: CD08 FAIL / CD09 FAIL" '[ "$(st CD08)" = FAIL ] && [ "$(st CD09)" = FAIL ]'
check "baseline: CD03 CD04 CD05 CD11 CD12 CD13 PASS, CD10 INFO" '[ "$(st CD03)$(st CD04)$(st CD05)$(st CD11)$(st CD12)$(st CD13)$(st CD10)" = PASSPASSPASSPASSPASSPASSINFO ]'
check "baseline: 13 checks in ID order" '[ "$(grep -o "\] CD[0-9]*" <<<"$OUT" | tr -d "] " | paste -sd,)" = CD01,CD02,CD03,CD04,CD05,CD06,CD07,CD08,CD09,CD10,CD11,CD12,CD13 ]'
cd_run audit --json
check "json: valid, exit 2, 13 checks, CD01 FAIL" 'jq -e ".exit == 2 and (.checks | length) == 13 and (.checks[] | select(.id == \"CD01\") | .status) == \"FAIL\"" <<<"$OUT" >/dev/null' "$OUT"

# ---- CD01 / CD02 / CD05 ----
fixture compose; echo '|/bin/false' > "$ROOT/proc/sys/kernel/core_pattern"; cd_run audit
check "CD01 PASS for |/bin/false" '[ "$(st CD01)" = PASS ]'
echo '|/usr/share/apport/apport -p%p -s%s' > "$ROOT/proc/sys/kernel/core_pattern"; cd_run audit
check "CD01 FAIL for an apport pipe" '[ "$(st CD01)" = FAIL ] && grep -q "pipes to /usr/share/apport/apport" <<<"$OUT"'
echo '/var/crash/core.%e.%p' > "$ROOT/proc/sys/kernel/core_pattern"; cd_run audit
check "CD01 FAIL for an absolute file pattern" '[ "$(st CD01)" = FAIL ]'
echo '|/lib/systemd/systemd-coredump %P %u' > "$ROOT/proc/sys/kernel/core_pattern"; touch "$STUB/pkg/systemd-coredump"; cd_run audit
check "CD01+CD05 FAIL: systemd-coredump with default storage" '[ "$(st CD01)" = FAIL ] && [ "$(st CD05)" = FAIL ]'
mkdir -p "$ROOT/etc/systemd/coredump.conf.d"; printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > "$ROOT/etc/systemd/coredump.conf.d/x.conf"; cd_run audit
check "CD01+CD05 PASS: systemd-coredump Storage=none ProcessSizeMax=0" '[ "$(st CD01)" = PASS ] && [ "$(st CD05)" = PASS ]'
printf '[Coredump]\nStorage=none\n' > "$ROOT/etc/systemd/coredump.conf.d/x.conf"; cd_run audit
check "CD05 FAIL: Storage=none without ProcessSizeMax=0" '[ "$(st CD05)" = FAIL ]'
rm "$ROOT/etc/systemd/coredump.conf.d/x.conf"; printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > "$ROOT/etc/systemd/coredump.conf.d/a.conf"; printf '[Coredump]\nStorage=external\n' > "$ROOT/etc/systemd/coredump.conf.d/b.conf"; cd_run audit
check "CD05 FAIL: a later drop-in turns storage back on (last wins)" '[ "$(st CD05)" = FAIL ]'

fixture compose; safe_dropin; cd_run audit
check "CD02 PASS: /etc/sysctl.d drop-in" '[ "$(st CD02)" = PASS ] && grep -q "from /etc/sysctl.d/60-pft-coredump.conf" <<<"$OUT"'
echo 'kernel.core_pattern=core' > "$ROOT/etc/sysctl.d/99-later.conf"; cd_run audit
check "CD02 FAIL: a later-sorting file wins" '[ "$(st CD02)" = FAIL ] && grep -q "99-later.conf" <<<"$OUT"'
rm "$ROOT/etc/sysctl.d/99-later.conf"; mkdir -p "$ROOT/usr/lib/sysctl.d"; echo 'kernel.core_pattern=core' > "$ROOT/usr/lib/sysctl.d/60-pft-coredump.conf"; cd_run audit
check "CD02 PASS: /etc shadows the same name in /usr/lib" '[ "$(st CD02)" = PASS ]'
echo 'kernel/core_pattern = core' > "$ROOT/usr/lib/sysctl.d/70-slash.conf"; cd_run audit
check "CD02 FAIL: slash key form is parsed" '[ "$(st CD02)" = FAIL ] && grep -q "70-slash.conf" <<<"$OUT"'
rm "$ROOT/usr/lib/sysctl.d/70-slash.conf"; echo '# kernel.core_pattern = core' > "$ROOT/etc/sysctl.d/80-comment.conf"; cd_run audit
check "CD02 PASS: commented line ignored" '[ "$(st CD02)" = PASS ]'
echo 'enabled=1' > "$ROOT/etc/default/apport"; cd_run audit
check "CD02+CD04 FAIL: apport enabled overrides the drop-in" '[ "$(st CD02)" = FAIL ] && [ "$(st CD04)" = FAIL ]'
: > "$ROOT/etc/default/apport"; cd_run audit
check "CD04 FAIL: installed without enabled= (default on)" '[ "$(st CD04)" = FAIL ]'
rm "$STUB/pkg/apport"; cd_run audit
check "CD04 PASS: not installed" '[ "$(st CD04)" = PASS ] && grep -q "CD04 apport: not installed" <<<"$OUT"'

# ---- CD03 ----
fixture compose; echo 2 > "$ROOT/proc/sys/fs/suid_dumpable"; cd_run audit
check "CD03 WARN for suid_dumpable 2" '[ "$(st CD03)" = WARN ]'

# ---- CD06 / CD07 ----
fixture compose; all00; cd_run audit
check "CD06 PASS all 0:0, CD07 INFO" '[ "$(st CD06)" = PASS ] && [ "$(st CD07)" = INFO ]'
limits unlimited unlimited > "$ROOT/proc/101/limits"; cd_run audit
check "CD06 FAIL: one child still unlimited" '[ "$(st CD06)" = FAIL ] && grep -q "1/2 container processes" <<<"$OUT"'
limits 0 unlimited > "$ROOT/proc/101/limits"; cd_run audit
check "CD06 WARN: soft 0 hard unlimited" '[ "$(st CD06)" = WARN ]'
limits unlimited unlimited > "$ROOT/proc/101/limits"; echo 00000030 > "$ROOT/proc/100/coredump_filter"; cd_run audit
check "CD07 INFO: anonymous memory excluded" '[ "$(st CD07)" = INFO ]'
echo 00000001 > "$ROOT/proc/100/coredump_filter"; cd_run audit
check "CD07 WARN: bit 0 alone" '[ "$(st CD07)" = WARN ]'

# ---- CD08 / CD09 ----
fixture compose
printf 'services:\n  postfiatd:\n    ulimits:\n      core:\n        soft: 0\n        hard: 0\n' > "$ROOT/opt/postfiatd/docker-compose.coredump.yml"; cd_run audit
check "CD09 FAIL: overlay present but not in COMPOSE_FILE" '[ "$(st CD09)" = FAIL ]'
sed -i 's/^COMPOSE_FILE=.*/&:docker-compose.coredump.yml/' "$ROOT/opt/postfiatd/.env"; cd_run audit
check "CD08 WARN pending re-create, CD09 PASS" '[ "$(st CD08)" = WARN ] && grep -q "pending re-create" <<<"$OUT" && [ "$(st CD09)" = PASS ]'
jq '.HostConfig.Ulimits = [{Name: "core", Hard: 0, Soft: 0}]' "$STUB/c/postfiatd.json" > "$T/x" && mv "$T/x" "$STUB/c/postfiatd.json"; cd_run audit
check "CD08 PASS when the container has core 0:0" '[ "$(st CD08)" = PASS ]'
jq '.HostConfig.Ulimits = [{Name: "core", Hard: 0, Soft: 0}]' "$STUB/c/postfiatd.json" > "$T/x" && mv "$T/x" "$STUB/c/postfiatd.json"
echo '{"services":{"postfiatd":{"ulimits":{"core":{"hard":5}}}}}' > "$STUB/compose_json"; cd_run audit
check "CD09 FAIL for compose core soft 0 (omitted) hard 5" '[ "$(st CD09)" = FAIL ] && grep -q "ulimits core 0:5" <<<"$OUT"'
echo '{"services":{"postfiatd":{"ulimits":{"core":{}}}}}' > "$STUB/compose_json"; cd_run audit
check "CD09 PASS for compose core {} (zeros omitted by compose JSON)" '[ "$(st CD09)" = PASS ]'
rm "$STUB/compose_json"; touch "$STUB/compose_bad"; cd_run audit
check "CD09 FAIL when compose config fails" '[ "$(st CD09)" = FAIL ] && grep -q "ulimits core error" <<<"$OUT"'
fixture run; cd_run audit
check "run: CD08 FAIL, CD09 FAIL (HostConfig unset)" '[ "$(st CD08)" = FAIL ] && [ "$(st CD09)" = FAIL ]'
jq '.HostConfig.Ulimits = [{Name: "core", Hard: 0, Soft: 0}]' "$STUB/c/postfiatd-sentry.json" > "$T/x" && mv "$T/x" "$STUB/c/postfiatd-sentry.json"; cd_run audit
check "run: CD08 PASS, CD09 PASS (tools copy Ulimits)" '[ "$(st CD08)" = PASS ] && [ "$(st CD09)" = PASS ]'
printf '#!/bin/sh\n# no ulimit handling\n' > "$ROOT/usr/local/bin/pft-apparmor"; cd_run audit
check "run: CD09 FAIL names the tool that drops Ulimits" '[ "$(st CD09)" = FAIL ] && grep -q "drop Ulimits: pft-apparmor" <<<"$OUT"'

# ---- CD11 / CD12 / CD13 ----
fixture compose; printf '/swap.img\tfile\t1024\t0\t-2\n' >> "$ROOT/proc/swaps"; cd_run audit
check "CD11 WARN plain swap, CD12 PASS ([disabled])" '[ "$(st CD11)" = WARN ] && [ "$(st CD12)" = PASS ]'
echo '[platform] shutdown' > "$ROOT/sys/power/disk"; cd_run audit
check "CD12 WARN: swap and hibernation possible" '[ "$(st CD12)" = WARN ]'
mkdir -p "$ROOT/etc/systemd"; printf '[Sleep]\nAllowHibernation=no\n' > "$ROOT/etc/systemd/sleep.conf"; cd_run audit
check "CD12 PASS: AllowHibernation=no" '[ "$(st CD12)" = PASS ]'
fixture compose; printf '/dev/dm-1\tpartition\t1024\t0\t-2\n' >> "$ROOT/proc/swaps"; cd_run audit
check "CD11 PASS: dm-crypt swap only" '[ "$(st CD11)" = PASS ]'
fixture compose; head -c 4096 /dev/zero > "$ROOT/var/crash/_usr_bin_secretname.0.crash"; mkdir -p "$ROOT/opt/postfiatd/logs"
head -c 100 /dev/zero > "$ROOT/opt/postfiatd/logs/core"; echo text > "$ROOT/opt/postfiatd/logs/core.txt"; cd_run audit
check "CD13 FAIL: 2 files 4196 bytes, core.txt not counted" '[ "$(st CD13)" = FAIL ] && grep -q "2 core/crash file(s), 4196 bytes" <<<"$OUT"' "$(grep CD13 <<<"$OUT")"
check "CD13: file names withheld" '! grep -q secretname <<<"$OUT"'
mkdir -p "$ROOT/var/lib/docker/volumes/data/a/b/c"; head -c 10 /dev/zero > "$ROOT/var/lib/docker/volumes/data/a/b/c/core.123"
rm "$ROOT/var/crash/"*.crash "$ROOT/opt/postfiatd/logs/core"; cd_run audit
check "CD13 PASS: deeper than SCAN_DEPTH not scanned" '[ "$(st CD13)" = PASS ]'
mv "$ROOT/var/lib/docker/volumes/data/a/b/c/core.123" "$ROOT/var/lib/docker/volumes/data/a/core.123"; cd_run audit
check "CD13 FAIL: core.N inside a mount source" '[ "$(st CD13)" = FAIL ]'

# ---- exit codes ----
fixture compose; safe_dropin; echo '|/bin/false' > "$ROOT/proc/sys/kernel/core_pattern"; all00
jq '.HostConfig.Ulimits = [{Name: "core", Hard: 0, Soft: 0}]' "$STUB/c/postfiatd.json" > "$T/x" && mv "$T/x" "$STUB/c/postfiatd.json"
printf 'services:\n  postfiatd:\n    ulimits:\n      core:\n        soft: 0\n        hard: 0\n' > "$ROOT/opt/postfiatd/docker-compose.coredump.yml"
sed -i 's/^COMPOSE_FILE=.*/&:docker-compose.coredump.yml/' "$ROOT/opt/postfiatd/.env"; cd_run audit
check "exit 0 when every check passes" '[ "$RC" = 0 ] && grep -q "RESULT: PASS - 0 fail, 0 warn -> exit 0" <<<"$OUT"' "rc=$RC $(grep -E 'WARN|FAIL' <<<"$OUT")"
echo 1 > "$ROOT/proc/sys/fs/suid_dumpable"; cd_run audit
check "exit 1 with only a WARN" '[ "$RC" = 1 ]' "rc=$RC"
rm "$STUB/c/postfiatd.json"; cd_run audit
check "exit 3 when the container is missing" '[ "$RC" = 3 ]' "rc=$RC"
fixture compose; jq '.State.Pid = 999' "$STUB/c/postfiatd.json" > "$T/x" && mv "$T/x" "$STUB/c/postfiatd.json"; cd_run audit
check "exit 3 when /proc/PID is unreadable" '[ "$RC" = 3 ]' "rc=$RC"
fixture compose; cd_run bogus
check "exit 65 on usage error" '[ "$RC" = 65 ]' "rc=$RC"

# ---- apply / rollback / re-apply: compose (validator shape: files only, never re-created) ----
fixture compose
cp -p "$ROOT/opt/postfiatd/.env" "$T/env.orig"; echo '# pre-existing' > "$ROOT/etc/sysctl.d/60-pft-coredump.conf"; cp "$ROOT/etc/sysctl.d/60-pft-coredump.conf" "$T/dropin.orig"
cd_run apply
check "apply without --yes refused (4), nothing changed" '[ "$RC" = 4 ] && [ "$(pat)" = core ] && [ "$(lim 100)" = unlimited:unlimited ]' "rc=$RC"
UIDV=1000 cd_run apply --yes
check "apply as non-root refused (4)" '[ "$RC" = 4 ] && grep -q "root required" <<<"$OUT" && [ "$(pat)" = core ]' "rc=$RC"
touch "$STUB/maint"; cd_run apply --yes --recreate; rm "$STUB/maint"
check "compose apply --recreate refused (4) even inside pft-maint" '[ "$RC" = 4 ] && grep -q "only for a docker run container" <<<"$OUT" && [ "$(pat)" = core ]' "rc=$RC"
cd_run apply --yes
check "compose apply: exit 0" '[ "$RC" = 0 ]' "rc=$RC $OUT"
check "compose apply: core_pattern |/bin/false live + drop-in" '[ "$(pat)" = "|/bin/false" ] && grep -qx "kernel.core_pattern = |/bin/false" "$ROOT/etc/sysctl.d/60-pft-coredump.conf"'
check "compose apply: both container processes 0:0, other cgroup untouched" '[ "$(lim 100)$(lim 101)" = 0:00:0 ] && [ "$(lim 200)" = unlimited:unlimited ]'
check "compose apply: overlay + COMPOSE_FILE appended, other .env lines kept, mode kept" 'grep -qx "COMPOSE_FILE=docker-compose.yml:docker-compose.shutdown.yml:docker-compose.coredump.yml" "$ROOT/opt/postfiatd/.env" && grep -qx NETWORK=testnet "$ROOT/opt/postfiatd/.env" && [ "$(stat -c %a "$ROOT/opt/postfiatd/.env")" = 600 ]'
check "compose apply: container never stopped/re-created" '! grep -qE "^docker (stop|run|rm|rename|start|compose up)" "$STUB/calls"' "$(grep -E '^docker (stop|run|rm|start)' "$STUB/calls")"
check "compose apply: no systemd-coredump drop-in when not installed" '[ ! -e "$ROOT/etc/systemd/coredump.conf.d/60-pft-coredump.conf" ]'
cd_run audit
check "after compose apply: CD01 CD02 CD06 PASS, CD08 WARN pending, CD09 PASS, exit 1" '[ "$(st CD01)$(st CD02)$(st CD06)$(st CD08)$(st CD09)" = PASSPASSPASSWARNPASS ] && [ "$RC" = 1 ]' "rc=$RC"
cd_run apply --yes
check "second apply refused while applied (4)" '[ "$RC" = 4 ] && grep -q "not rolled back" <<<"$OUT"' "rc=$RC"
cd_run rollback --yes
check "compose rollback: exit 0" '[ "$RC" = 0 ]' "rc=$RC $OUT"
check "compose rollback: .env byte-identical, mode kept" 'cmp -s "$T/env.orig" "$ROOT/opt/postfiatd/.env" && [ "$(stat -c %a "$ROOT/opt/postfiatd/.env")" = 600 ]'
check "compose rollback: overlay removed (did not exist)" '[ ! -e "$ROOT/opt/postfiatd/docker-compose.coredump.yml" ]'
check "compose rollback: pre-existing drop-in content restored" 'cmp -s "$T/dropin.orig" "$ROOT/etc/sysctl.d/60-pft-coredump.conf"'
check "compose rollback: pattern core, limits unlimited again" '[ "$(pat)" = core ] && [ "$(lim 100)$(lim 101)" = unlimited:unlimitedunlimited:unlimited ]'
cd_run rollback --yes
check "second rollback: nothing to do (0)" '[ "$RC" = 0 ] && grep -q "already rolled back" <<<"$OUT"' "rc=$RC"
cd_run audit
check "after rollback: audit back to the found state (CD01 CD06 CD09 FAIL)" '[ "$(st CD01)$(st CD06)$(st CD09)" = FAILFAILFAIL ] && [ "$RC" = 2 ]'
sleep 1; cd_run apply --yes
check "re-apply: exit 0, a second snapshot" '[ "$RC" = 0 ] && [ "$(find "$ROOT/var/lib/pft-coredump" -maxdepth 1 -name "snap-*" | wc -l)" = 2 ]' "rc=$RC"
check "re-apply: pattern + limits applied again" '[ "$(pat)" = "|/bin/false" ] && [ "$(lim 100)$(lim 101)" = 0:00:0 ]'
check "snapshot dir mode 700" '[ "$(stat -c %a "$ROOT/var/lib/pft-coredump")" = 700 ]'

fixture compose; touch "$STUB/pkg/systemd-coredump"; cd_run apply --yes
check "apply writes the systemd-coredump drop-in when installed" 'grep -qx Storage=none "$ROOT/etc/systemd/coredump.conf.d/60-pft-coredump.conf" && grep -qx ProcessSizeMax=0 "$ROOT/etc/systemd/coredump.conf.d/60-pft-coredump.conf"'
cd_run rollback --yes
check "rollback removes the systemd-coredump drop-in" '[ "$RC" = 0 ] && [ ! -e "$ROOT/etc/systemd/coredump.conf.d/60-pft-coredump.conf" ]'

fixture compose; touch "$STUB/prlimit_fail"; cd_run apply --yes
check "prlimit failure: exit 1, automatic rollback restores pattern + drop-in absence" '[ "$RC" = 1 ] && [ "$(pat)" = core ] && [ ! -e "$ROOT/etc/sysctl.d/60-pft-coredump.conf" ] && grep -q "rollback RESULT: FAILED\|rollback RESULT: PASS" <<<"$OUT"' "rc=$RC"
fixture compose; touch "$STUB/compose_bad"; cd_run apply --yes
check "invalid compose config: exit 1, .env + overlay restored, limits back" '[ "$RC" = 1 ] && cmp -s <(printf "NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.shutdown.yml\n") "$ROOT/opt/postfiatd/.env" && [ ! -e "$ROOT/opt/postfiatd/docker-compose.coredump.yml" ] && [ "$(lim 100)" = unlimited:unlimited ] && [ "$(pat)" = core ]' "rc=$RC $OUT"
fixture compose; cd_run apply --yes; rm -rf "$ROOT/proc/101"; cd_run rollback --yes
check "rollback: a vanished process is reported, the rest restored" '[ "$RC" = 0 ] && grep -q "pid 101 gone" <<<"$OUT" && [ "$(lim 100)" = unlimited:unlimited ]' "rc=$RC"

# ---- apply / rollback: docker run (sentry shape: re-created with --ulimit core=0:0) ----
fixture run; cd_run apply --yes --recreate
check "run apply --recreate without pft-maint refused (4)" '[ "$RC" = 4 ] && grep -q pft-maint <<<"$OUT" && [ "$(pat)" = core ]' "rc=$RC"
touch "$STUB/maint"; echo '{"result":{"info":{"server_state":"syncing"}}}' > "$STUB/rpc.json"; cd_run apply --yes --recreate
check "run apply --recreate with node not full refused (4)" '[ "$RC" = 4 ]' "rc=$RC"
echo '{"result":{"info":{"server_state":"full"}}}' > "$STUB/rpc.json"; SIG0="$(jq -cS '{i: .Config.Image, r: .HostConfig.RestartPolicy, ro: .HostConfig.ReadonlyRootfs, so: .HostConfig.SecurityOpt, st: .Config.StopTimeout}' "$STUB/c/postfiatd-sentry.json")"
cd_run apply --yes --recreate
check "run apply: exit 0, gate PASS" '[ "$RC" = 0 ] && grep -q "apply gate PASS" <<<"$OUT"' "rc=$RC $OUT"
check "run apply: container Ulimits core 0:0" '[ "$(jq -c .HostConfig.Ulimits "$STUB/c/postfiatd-sentry.json")" = "[{\"Name\":\"core\",\"Hard\":0,\"Soft\":0}]" ]'
check "run apply: restart policy, read-only, seccomp, stop timeout kept" '[ "$(jq -cS "{i: .Config.Image, r: .HostConfig.RestartPolicy, ro: .HostConfig.ReadonlyRootfs, so: .HostConfig.SecurityOpt, st: .Config.StopTimeout}" "$STUB/c/postfiatd-sentry.json")" = "$SIG0" ]'
check "run apply: kept previous container had restart=no while the new one started" '[ "$(cat "$STUB/old_restart_at_run")" = no ]'
check "run apply: previous container removed" '[ "$(find "$STUB/c" -name "*precd*" | wc -l)" = 0 ]'
check "run apply: env values masked in the printed docker run" 'grep -q "env=NETWORK=<value>" <<<"$OUT" && ! grep -q "NETWORK=testnet" <<<"$OUT"'
NEWPID="$(jq -r .State.Pid "$STUB/c/postfiatd-sentry.json")"
check "run apply: new process starts with 0:0" '[ "$(lim "$NEWPID")" = 0:0 ]'
cd_run audit
check "after run apply: exit 0 (all PASS)" '[ "$RC" = 0 ]' "rc=$RC $(grep -E 'WARN|FAIL' <<<"$OUT")"
cd_run rollback --yes
check "run rollback: exit 0, re-created without Ulimits" '[ "$RC" = 0 ] && [ "$(jq -c ".HostConfig.Ulimits // []" "$STUB/c/postfiatd-sentry.json")" = "[]" ]' "rc=$RC $OUT"
check "run rollback: config kept, pattern core" '[ "$(jq -cS "{i: .Config.Image, r: .HostConfig.RestartPolicy, ro: .HostConfig.ReadonlyRootfs, so: .HostConfig.SecurityOpt, st: .Config.StopTimeout}" "$STUB/c/postfiatd-sentry.json")" = "$SIG0" ] && [ "$(pat)" = core ]'
NEWPID="$(jq -r .State.Pid "$STUB/c/postfiatd-sentry.json")"
check "run rollback: new process unlimited again" '[ "$(lim "$NEWPID")" = unlimited:unlimited ]'
sleep 1; cd_run apply --yes --recreate
check "run re-apply: exit 0, core 0:0" '[ "$RC" = 0 ] && [ "$(jq -c .HostConfig.Ulimits "$STUB/c/postfiatd-sentry.json")" = "[{\"Name\":\"core\",\"Hard\":0,\"Soft\":0}]" ]' "rc=$RC"
fixture run; cd_run apply --yes
check "run apply without --recreate: container untouched, CD08 reported" '[ "$RC" = 0 ] && ! grep -qE "^docker (stop|run)" "$STUB/calls" && grep -q "left as is" <<<"$OUT"' "rc=$RC"

fixture run; touch "$STUB/maint"
PFT_COREDUMP_INJECT=gate cd_run apply --yes --recreate
check "gate failure: exit 1, old container restored (StartedAt changes, Ulimits unset)" '[ "$RC" = 1 ] && grep -q "previous container restored" <<<"$OUT" && [ "$(jq -c ".HostConfig.Ulimits // []" "$STUB/c/postfiatd-sentry.json")" = "[]" ]' "rc=$RC $OUT"
check "gate failure: pattern + drop-in rolled back, no stray containers" '[ "$(pat)" = core ] && [ ! -e "$ROOT/etc/sysctl.d/60-pft-coredump.conf" ] && [ "$(find "$STUB/c" -name "*.json" | wc -l)" = 1 ] && [ "$(jq -r .HostConfig.RestartPolicy.Name "$STUB/c/postfiatd-sentry.json")" = unless-stopped ]'
fixture run; touch "$STUB/maint" "$STUB/run_drop_ro"; cd_run apply --yes --recreate
check "gate: a setting lost in the re-create (read-only) fails + rolls back" '[ "$RC" = 1 ] && grep -q "configuration changed" <<<"$OUT" && [ "$(jq -r .HostConfig.ReadonlyRootfs "$STUB/c/postfiatd-sentry.json")" = true ] && [ "$(pat)" = core ]' "rc=$RC"
fixture run; touch "$STUB/maint" "$STUB/run_drop_ulimit"; cd_run apply --yes --recreate
check "gate: re-created without the ulimit fails + rolls back" '[ "$RC" = 1 ] && grep -q "Ulimits \[\] want" <<<"$OUT" && [ "$(pat)" = core ]' "rc=$RC $(grep gate <<<"$OUT")"
fixture run; touch "$STUB/maint" "$STUB/run_fail"; cd_run apply --yes --recreate
check "docker run failure: exit 1, old container back under its name" '[ "$RC" = 1 ] && [ -f "$STUB/c/postfiatd-sentry.json" ] && [ "$(jq -r .HostConfig.RestartPolicy.Name "$STUB/c/postfiatd-sentry.json")" = unless-stopped ]' "rc=$RC $OUT"

# ---- recreate tools carry Ulimits (the run_args of every tool that can re-create the sentry) ----
INS='{"Name":"/postfiatd-sentry","Config":{"Image":"img","Env":[],"Cmd":null},"HostConfig":{"RestartPolicy":{"Name":"always"},"LogConfig":{"Type":"json-file"},"Ulimits":[{"Name":"core","Hard":0,"Soft":0}]},"Mounts":[]}'
for t in seccomp/pft-seccomp.sh apparmor/pft-apparmor.sh shutdown/pft-shutdown.sh "$TOOL"; do
  f="$t"; [ -f "$f" ] || f="$REPO/$t"
  out="$(SECCOMP_FILE=/x bash -c 'eval "$(sed -n "/^run_args() {/,/^}/p" "$1")"; if grep -q "^run_args() { # INSPECT0 IMAGE_ENV_JSON ULIMITS_JSON" "$1"; then run_args "$2" "[]" "$(jq -c ".HostConfig.Ulimits" <<<"$2")"; else run_args "$2" "[]" X; fi' _ "$f" "$INS" 2>&1)"
  check "run_args of $(basename "$t") emits --ulimit=core=0:0" 'grep -qx -- "--ulimit=core=0:0" <<<"$out"' "$out"
done

echo "RESULT: $PASS passed, $FAILN failed"
[ "$FAILN" = 0 ]
