#!/usr/bin/env bash
# task_6a35 verification: re-apply the two rotation-tracking mutants from
# mutants.py ("inode ignored", "rotated read from 0") to a fresh clone of the
# PR head, show each one as a unified diff, run scripts/test-rpc-events-report
# against the mutated tool and print its FAIL lines and exit status.
set -uo pipefail
PIN=4b9a8b6f9c7f87315f0a7d78a894be097a1caa2a
red() { sed -u -e "s#$HOME#~#g" -e "s#$(id -un)#<user>#g"; }
x() { echo "\$ $*" | red; eval "$*" 2>&1 | red; local rc=${PIPESTATUS[0]}; echo "[exit $rc]"; return "$rc"; }
FAILS=0
echo "== task_6a35 recorded run: mutant diffs  $(date -u +%FT%TZ)"
export TMPDIR=$HOME/.cache/rpcev-tmp
mkdir -p "$TMPDIR"
W=$(mktemp -d -p "$HOME/.cache")
chmod 755 "$W"
x "git clone -q https://github.com/darkmatter-sudo/postfiatl1v2.git $W/repo" || exit 1
cd "$W/repo" || exit 1
x "git checkout -q $PIN" || exit 1
x "git log -1 --format='repo HEAD %H %s'"
x "sha256sum scripts/rpc-events-report scripts/test-rpc-events-report"
echo "-- unmutated baseline (must pass)"
x "scripts/test-rpc-events-report | tail -1" || FAILS=$((FAILS + 1))

# mutate NAME OLD NEW: OLD must occur exactly once (same rule as mutants.py)
mutate() {
  local name=$1 old=$2 new=$3 m="$W/mut-${1// /-}"
  echo "== mutant: $name"
  mkdir -p "$m/scripts"
  cp -r ops "$m/ops"
  cp scripts/test-rpc-events-report "$m/scripts/"
  if ! python3 -I - scripts/rpc-events-report "$m/scripts/rpc-events-report" "$old" "$new" <<'PY'
import sys
src, dst, old, new = sys.argv[1:]
text = open(src).read()
n = text.count(old)
print(f"occurrences of the mutated text: {n}")
if n != 1:
    sys.exit(3)
open(dst, "w").write(text.replace(old, new))
PY
  then
    echo "NOT APPLIED"
    FAILS=$((FAILS + 1))
    return
  fi
  echo "(diff exits 1 because the files differ)"
  x "diff -u --label a/scripts/rpc-events-report --label b/scripts/rpc-events-report scripts/rpc-events-report $m/scripts/rpc-events-report"
  echo "-- test suite against the mutated tool"
  local rc=0
  bash "$m/scripts/test-rpc-events-report" >"$m/test.out" 2>&1 || rc=$?
  command grep -E '^(FAIL|RESULT)' "$m/test.out" | red
  echo "test-rpc-events-report exit status: $rc"
  if [ "$rc" -ne 0 ] && command grep -q '^FAIL' "$m/test.out"; then
    echo "CAUGHT $name"
  else
    echo "SURVIVED $name"
    FAILS=$((FAILS + 1))
  fi
}
mutate "inode ignored" 'live_stat.st_ino == state["inode"]' 'True'
mutate "rotated read from 0" 'segments = [(candidate, offset, True)]' 'segments = [(candidate, 0, True)]'

echo "-- the assertions that report these failures (test file at the PR head)"
x "grep -n -e '^check_eq()' -e '^rotation_case()' -e 'events counted exactly once' -e '\"\$1: rotated\"' -e 'read the rotated file from the old offset' -e 'rotation_case \"same-head rename\"' -e 'rotation_case \"copytruncate+gz\"' -e '^  exit 1' scripts/test-rpc-events-report"
x "sed -n '43,45p;305,310p;323,324p;353,365p;507,512p' scripts/test-rpc-events-report"
cd / && rm -rf "$W"
echo "RUN RESULT: $([ $FAILS -eq 0 ] && echo PASS || echo "FAIL ($FAILS)")"
