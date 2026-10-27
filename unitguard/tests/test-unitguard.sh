#!/usr/bin/env bash
# Offline tests for pft-unitguard.sh: stub systemctl + systemd-analyze, temp DROPIN_ROOT/STATE_DIR, fake profiles.
# No root, no real systemd change. Usage: bash tests/test-unitguard.sh [path/to/pft-unitguard.sh]
# eval-checks are single-quoted on purpose (evaluated later by check()).
# shellcheck disable=SC2016
set -uo pipefail
T="$(cd "$(dirname "$0")" && pwd)"
UG="${1:-$T/../pft-unitguard.sh}"
pass=0; fail=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
no() { fail=$((fail+1)); echo "FAIL $1"; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }

setup() {
  umask 022; W="$(mktemp -d)"; export STUB_DIR="$W/stub" DROPIN_ROOT="$W/etc" STATE_DIR="$W/state" PROFILE_DIR="$W/profiles"
  mkdir -p "$STUB_DIR/bin" "$DROPIN_ROOT" "$PROFILE_DIR"; chmod 0755 "$STUB_DIR/bin"
  printf '#!/bin/sh\n' > "$STUB_DIR/bin/tool"; chmod 0755 "$STUB_DIR/bin/tool"
  printf 'a.service oneshot\nd.service simple\nk.service oneshot\nt@one.service oneshot\nr.service oneshot remain\n' > "$STUB_DIR/units"
  printf '#@ class: standard\n#@ check: true\n[Service]\nNoNewPrivileges=yes\n' > "$PROFILE_DIR/a.service.conf"
  printf '#@ class: standard\n#@ check: true\n[Service]\nProtectSystem=strict\n' > "$PROFILE_DIR/d.service.conf"
  printf '#@ class: docker\n#@ exception: docker.sock\n#@ check: true\n[Service]\nPrivateTmp=yes\n' > "$PROFILE_DIR/k.service.conf"
  printf '#@ class: iptables\n[Service]\nPrivateTmp=yes\n' > "$PROFILE_DIR/t@.service.conf"
  printf '#@ class: iptables\n#@ check: true\n[Service]\nPrivateTmp=yes\n' > "$PROFILE_DIR/r.service.conf"
  export PFT_UNITGUARD_TEST=1 PFT_UNITGUARD_SYSTEMCTL="$T/stubs/systemctl" PFT_UNITGUARD_ANALYZE="$T/stubs/systemd-analyze"
  PFT_UNITGUARD_OWNER_UID="$(id -u)"
  export PFT_UNITGUARD_SLEEP=true PFT_UNITGUARD_OWNER_UID HOLD_UNITS=""
}
ug() { bash "$UG" "$@" > "$W/out" 2>&1; echo $? > "$W/rc"; }
rc() { cat "$W/rc"; }
has() { grep -qF -- "$1" "$W/out"; }
dp() { echo "$DROPIN_ROOT/$1.d/50-unitguard.conf"; }

# 1 audit before any apply
setup; ug audit
check "audit-before: rc 0, a not-applied at 9.6" '[ "$(rc)" = 0 ] && grep -qE "^a.service +9.6 .* no +not-applied" "$W/out"'
check "audit-before: template instance listed" 'grep -q "^t@one.service" "$W/out"'
ug audit --units a --detail
check "audit --detail lists missing checks" 'has "missing: Check1= Check2="'

# 2 apply standard unit: pass
setup; ug apply a
check "apply-a: rc 0 + PASS line" '[ "$(rc)" = 0 ] && has "PASS a.service exposure now: 3.1"'
check "apply-a: drop-in content from profile, metadata stripped" 'grep -qx "NoNewPrivileges=yes" "$(dp a.service)" && ! grep -q "^#@" "$(dp a.service)"'
check "apply-a: drop-in mode 0644, dir 0755" '[ "$(stat -c %a "$(dp a.service)")" = 644 ] && [ "$(stat -c %a "$DROPIN_ROOT/a.service.d")" = 755 ]'
check "apply-a: daemon-reload before start" 'grep -n "" "$STUB_DIR/calls.log" | grep -E "daemon-reload|start a.service" | head -1 | grep -q daemon-reload'
check "apply-a: before score recorded 9.6" '[ "$(cat "$STATE_DIR"/*a.service*.before)" = 9.6 ]'
ug audit --units a
check "audit-after: OK verdict" 'grep -qE "^a.service +3.1 .* yes +OK" "$W/out" && [ "$(rc)" = 0 ]'

# 3 unit fails under profile -> rollback
setup; echo a.service > "$STUB_DIR/fail-with-dropin"; ug apply a
check "fail-unit: rc 1, rolled back, drop-in gone" '[ "$(rc)" = 1 ] && has "FAIL a.service under the profile" && has "ROLLED-BACK a.service (runs again on the unit without a drop-in)" && [ ! -f "$(dp a.service)" ]'
check "fail-unit: unit re-run after rollback" '[ "$(grep -c "start a.service" "$STUB_DIR/calls.log")" = 2 ]'

# 3b broken profile change over a working unitguard drop-in -> the working drop-in is restored, not removed
setup; ug apply a; cp "$(dp a.service)" "$W/good"
printf '#@ class: standard\n#@ check: echo broken; exit 9\n[Service]\nReadOnlyPaths=/x\n' > "$PROFILE_DIR/a.service.conf"; ug apply a
check "re-apply broken: rc 1, previous unitguard drop-in restored byte-identical" '[ "$(rc)" = 1 ] && has "restored previous" && cmp -s "$W/good" "$(dp a.service)"'
check "re-apply broken: no leftover .prev, re-run after restore" '[ -z "$(ls "$STATE_DIR"/*.prev 2>/dev/null)" ] && has "ROLLED-BACK a.service (runs again on the previous drop-in)"'

# 4 functional check fails -> rollback
setup; printf '#@ class: standard\n#@ check: echo boom; exit 7\n[Service]\nNoNewPrivileges=yes\n' > "$PROFILE_DIR/a.service.conf"; ug apply a
check "fail-check: rc 1, check exit 7 logged, rolled back" '[ "$(rc)" = 1 ] && has "check exit 7" && has "    | boom" && [ ! -f "$(dp a.service)" ]'

# 5 standard unit runs but misses 5.0 target
setup; echo 6.2 > "$STUB_DIR/a.service.score"; ug apply a
check "fail-target: rc 1, misses target 5.0, rolled back" '[ "$(rc)" = 1 ] && has "exposure 6.2 UNSAFE 20 misses target 5.0" && [ ! -f "$(dp a.service)" ]'

# 6 docker class: must drop below before; equal fails
setup; echo 8.4 > "$STUB_DIR/k.service.score"; ug apply k
check "docker-lower: rc 0" '[ "$(rc)" = 0 ] && has "PASS k.service exposure now: 8.4"'
setup; echo 9.6 > "$STUB_DIR/k.service.score"; ug apply k
check "docker-equal: rc 1 (not reduced)" '[ "$(rc)" = 1 ] && has "misses target <before"'

# 7 long-running unit restarting under profile
setup; echo d.service > "$STUB_DIR/restarts-with-dropin"; ug apply d
check "daemon-restarts: rc 1, NRestarts change logged, rolled back" '[ "$(rc)" = 1 ] && has "NRestarts 1 -> 2" && [ ! -f "$(dp d.service)" ]'
setup; ug apply d
check "daemon-ok: restart used, rc 0" '[ "$(rc)" = 0 ] && grep -q "restart d.service" "$STUB_DIR/calls.log"'

# 7b RemainAfterExit=yes oneshot (already active): apply must restart it, or the profile never runs (false PASS)
setup; ug apply r
check "remain: restart used, rc 0" '[ "$(rc)" = 0 ] && grep -q "restart r.service" "$STUB_DIR/calls.log" && has "(oneshot, restart)"'
setup; echo r.service > "$STUB_DIR/fail-with-dropin"; ug apply r
check "remain-fail: unit failing under the profile is caught and rolled back" '[ "$(rc)" = 1 ] && has "ROLLED-BACK r.service" && [ ! -f "$(dp r.service)" ]'

# 8 rollback: removes ours, restores an earlier foreign drop-in of the same name
setup; ug apply a; ug rollback a
check "rollback: drop-in removed, rc 0" '[ "$(rc)" = 0 ] && [ ! -f "$(dp a.service)" ] && has "removed"'
setup; mkdir -p "$DROPIN_ROOT/a.service.d"; echo "[Service]" > "$(dp a.service)"; echo "Nice=5" >> "$(dp a.service)"
ug apply a; ug rollback a
check "rollback: earlier drop-in restored byte-identical" '[ "$(cat "$(dp a.service)")" = "$(printf "[Service]\nNice=5")" ] && has "restored earlier"'

# 9 HOLD_UNITS / --skip
setup; ug apply --all --skip "d.service"
check "skip: d left alone, others applied" 'has "HOLD d.service" && [ ! -f "$(dp d.service)" ] && [ -f "$(dp a.service)" ] && [ -f "$(dp k.service)" ]'

# 10 template instance -> drop-in on the template
setup; ug apply t@one.service
check "template: drop-in on t@.service.d" '[ "$(rc)" = 0 ] && [ -f "$(dp t@.service)" ]'

# 11 permissions: group-writable drop-in dir -> audit flags it, rc 1
setup; ug apply a; chmod 0775 "$DROPIN_ROOT/a.service.d"; ug audit --units a
check "perms: group-writable dir flagged" '[ "$(rc)" = 1 ] && has "PERMS BAD:$DROPIN_ROOT/a.service.d"'
setup; chmod 0757 "$STUB_DIR/bin"; ug audit --units a
check "perms: world-writable parent dir of ExecStart binary flagged" '[ "$(rc)" = 1 ] && has "PERMS BAD:$STUB_DIR/bin/tool"'

# 12 usage / refusals
setup; ug apply; check "usage: apply without unit -> 3" '[ "$(rc)" = 3 ]'
ug plan nosuch; check "plan: unknown unit -> 3" '[ "$(rc)" = 3 ] && has "no profile"'
ug plan k; check "plan: shows exception + drop-in" 'has "exception: docker.sock" && has "PrivateTmp=yes" && has "target: <= <before"'
PFT_UNITGUARD_TEST="" bash "$UG" apply a > "$W/out" 2>&1; echo $? > "$W/rc"
if [ "$(id -u)" != 0 ]; then check "root: apply as non-root refused (4)" '[ "$(rc)" = 4 ]'; fi

echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
