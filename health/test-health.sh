#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034  # check() evals single-quoted assertions that read RC/CALLS
# Offline test of postfiat-health (the copy embedded in install.sh) against stubbed ss / docker / ufw /
# iptables / curl / sleep. Touches nothing on the host: no root, no docker, no network.
# Usage: bash health/test-health.sh [INSTALL_SH]     (default: install.sh next to this folder)
# Exit 0 = all checks passed.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$HERE/../install.sh}"
T="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}" health-test.XXXXXX)"
trap 'rm -rf "$T"' EXIT
PASSES=0; FAILS=0
check() { if eval "$2"; then PASSES=$((PASSES + 1)); echo "PASS  $1"; else FAILS=$((FAILS + 1)); echo "FAIL  $1"; sed 's/^/      | /' "$T/out"; fi; }

# Extract the script exactly as install.sh writes it.
awk '/^cat > \/usr\/local\/bin\/postfiat-health <<.EOF.$/ {on=1; next} on && /^EOF$/ {exit} on {print}' "$SRC" > "$T/postfiat-health"
[ -s "$T/postfiat-health" ] || { echo "FAIL  could not extract postfiat-health from $SRC"; exit 1; }
chmod 755 "$T/postfiat-health"
echo "postfiat-health sha256 $(sha256sum < "$T/postfiat-health" | cut -d' ' -f1) ($(wc -l < "$T/postfiat-health") lines)"

mkdir -p "$T/bin"
# ss: plays $T/ss.plan one line per call ("ok", "empty", "fail", "nopeer", "exposed"); the last line repeats.
cat > "$T/bin/ss" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_DIR/ss.calls" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STUB_DIR/ss.calls"
mode="$(sed -n "${n}p" "$STUB_DIR/ss.plan")"; [ -n "$mode" ] || mode="$(tail -n1 "$STUB_DIR/ss.plan")"
row() { printf 'LISTEN 0      4096       %s         0.0.0.0:*\n' "$1"; }
case "$mode" in
  ok)      row 127.0.0.1:5005; row 127.0.0.1:6005; row 127.0.0.1:6006; row 127.0.0.1:50051; row 0.0.0.0:2559; row 0.0.0.0:22 ;;
  nopeer)  row 127.0.0.1:5005; row 127.0.0.1:6005; row 0.0.0.0:22 ;;
  exposed) row 0.0.0.0:5005; row 0.0.0.0:2559 ;;
  empty)   ;;
  fail)    echo "Cannot open netlink socket" >&2; exit 1 ;;
esac
STUB
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  inspect) echo running ;;
  exec) echo '{"result":{"info":{"server_state":"full","build_version":"1.0.9","peers":12,"complete_ledgers":"1-2"}}}' ;;
esac
STUB
cat > "$T/bin/curl" <<'STUB'
#!/usr/bin/env bash
echo '{"result":{"info":{"build_version":"1.0.9"}}}'
STUB
cat > "$T/bin/ufw" <<'STUB'
#!/usr/bin/env bash
printf 'Status: active\n\nTo                         Action      From\n2559/tcp                   LIMIT       Anywhere\n'
STUB
# iptables: far more output than a pipe buffer, with the limit rule FIRST, so an early-exiting
# `iptables | grep -q` under pipefail gets SIGPIPE (141) and would read as "missing".
cat > "$T/bin/iptables" <<'STUB'
#!/usr/bin/env bash
echo "-A DOCKER-USER -p tcp -m tcp --dport 2559 -m state --state NEW -m limit --limit 30/min -j RETURN"
[ "${IPT_BIG:-0}" = 1 ] && for i in $(seq 1 20000); do echo "-A DOCKER-USER -s 10.$((i % 250)).0.0/16 -m comment --comment filler-$i -j RETURN"; done
exit 0
STUB
cat > "$T/bin/sleep" <<'STUB'
#!/usr/bin/env bash
echo "$1" >> "$STUB_DIR/sleep.calls"
STUB
chmod 755 "$T/bin/"*
export STUB_DIR="$T"

run() {  # run PLAN... ; sets RC, output in $T/out, ss call count in CALLS
  rm -f "$T/ss.calls" "$T/sleep.calls"; printf '%s\n' "$@" > "$T/ss.plan"
  PATH="$T/bin:$PATH" "$T/postfiat-health" > "$T/out" 2>&1; RC=$?
  CALLS="$(cat "$T/ss.calls" 2>/dev/null || echo 0)"
}
has() { grep -Eq -- "$1" "$T/out"; }

run ok
check "healthy ss: exit 0, one ss read, no retry line" '[ "$RC" = 0 ] && [ "$CALLS" = 1 ] && has "^  \[PASS\] peer port 2559 listening$" && ! has "ss read"'
run empty ok
check "one empty ss read then ok: retried, HEALTHY (the 2026-11-12 false alarm)" '[ "$RC" = 0 ] && [ "$CALLS" = 2 ] && has "\[INFO\] ss read 2 times \(last rc=0, 6 lines\)" && has "RESULT: HEALTHY"'
run fail ok
check "one failing ss (rc 1) then ok: retried, HEALTHY" '[ "$RC" = 0 ] && [ "$CALLS" = 2 ] && has "RESULT: HEALTHY"'
run empty empty ok
check "two empty reads then ok: HEALTHY on the 3rd read, 2 sleeps of 2 s" '[ "$RC" = 0 ] && [ "$CALLS" = 3 ] && [ "$(cat "$T/sleep.calls" | tr "\n" " ")" = "2 2 " ]'
run nopeer
check "control: peer port really down -> FAIL after 3 reads with rc and line count" '[ "$RC" = 1 ] && [ "$CALLS" = 3 ] && has "^  \[FAIL\] peer port 2559 not listening \(ss rc=0, 3 lines, 3 reads\)$" && has "RESULT: UNHEALTHY"'
run empty
check "control: ss always empty -> FAIL (0 lines, 3 reads)" '[ "$RC" = 1 ] && has "\[FAIL\] peer port 2559 not listening \(ss rc=0, 0 lines, 3 reads\)"'
run fail
check "control: ss always failing -> FAIL reports rc=1" '[ "$RC" = 1 ] && has "\[FAIL\] peer port 2559 not listening \(ss rc=1, 0 lines, 3 reads\)"'
run exposed
check "control: admin port on 0.0.0.0 still FAILs (here-string grep keeps the check)" '[ "$RC" = 1 ] && has "\[FAIL\] admin port 5005 exposed on all interfaces" && [ "$CALLS" = 1 ]'
rm -f "$T/ss.calls"; printf 'empty\nok\n' > "$T/ss.plan"; SS_TRIES=1 PATH="$T/bin:$PATH" "$T/postfiat-health" > "$T/out" 2>&1; RC=$?
check "SS_TRIES=1 disables the retry (1 read, FAIL)" '[ "$RC" = 1 ] && [ "$(cat "$T/ss.calls")" = 1 ]'
IPT_BIG=1 run ok
check "large DOCKER-USER output with the rule first: PASS (no SIGPIPE false negative)" '[ "$RC" = 0 ] && has "\[PASS\] DOCKER-USER rate limit on 2559"'

echo "RESULT: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
