#!/usr/bin/env bash
# Recorded controls for the mutate.py orphan check (task_2fac2360 log 44). Run from the repo root.
set -u
export TZ=UTC
red() { sed -u -E "s#$HOME#~#g; s#$(id -un)#<user>#g"; }
x() { echo "\$ $*" | red; eval "$*" 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
echo "orphan-check controls at $(git rev-parse HEAD) - $(date -u +%FT%TZ) - $(lsb_release -ds)"
echo "== 0. state after recorded run 43: no process names a mutant scratch dir, no scratch dir left"
x "pgrep -af 'atmut[.]' | grep -v orphan-controls || echo none"
x "ls -d ~/.cache/atmut.* 2>/dev/null | wc -l"
echo "== 1. decoy: an unrelated shell whose command line only NAMES an old scratch dir"
setsid bash -c 'sleep 600; true' atmut.decoy-old-scratch </dev/null >/dev/null 2>&1 &
DECOY=$!
sleep 1
echo "decoy pid $DECOY"
x "pgrep -fc '[a]tmut\\.'   # the OLD check's exact pattern: counts the decoy"
echo "== 2. fixed harness with the decoy alive: orphan check 0, exit 0"
x "TEST_TMPDIR=\$HOME/.cache python3 -u aptrust/tests/mutate.py --jobs 2 --only A01,O01"
echo "== 3. positive control: ATMUT_ORPHAN_SELFTEST=1 leaves one child behind -> orphan check 1, exit 1"
x "ATMUT_ORPHAN_SELFTEST=1 TEST_TMPDIR=\$HOME/.cache python3 -u aptrust/tests/mutate.py --jobs 2 --only A01"
echo "== 4. cleanup by PID"
for p in $(pgrep -f 'orphan-selftest$'); do echo "kill selftest child $p"; kill "$p"; done
kill "$DECOY"; echo "kill decoy $DECOY"
sleep 1
x "pgrep -af 'atmut[.]' | grep -v orphan-controls || echo none"
x "ls -d ~/.cache/atmut.* 2>/dev/null | wc -l"
echo "END $(date -u +%FT%TZ)"
