#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline check of acctpolicy/
# (task_6a2e044a1006072ef343c005ba3765ff): sha256 of pft-acctpolicy.sh against the sha256 logs/03 recorded for the
# repo file AND the installed /usr/local/bin/pft-acctpolicy on both hosts, shellcheck, ruff (from the repo root and
# from acctpolicy/), the offline suite under umask 022 and 002, and the mutation harness (baseline + every mutant).
# Nothing on the host is read or changed.
#   bash acctpolicy/drill/fresh-clone.sh SHA 2>&1 | tee LOG
# The work dir is a new mktemp dir under ~/.cache (/tmp is noexec on this host), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | acctpolicy fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
L=acctpolicy/logs/03-live-run-02.log
echo "== pft-acctpolicy.sh vs logs/03 (repo file at the installed commit, and the binary installed on both hosts)"
must "sha256sum acctpolicy/pft-acctpolicy.sh | cut -c1-64 > $W/now.txt && cat $W/now.txt"
must "sed -n '/^== 3/,/^== 4/p' $L | grep -oE '^  [0-9a-f]{64}' | tr -d ' ' > $W/live.txt && cat $W/live.txt && [ \$(wc -l < $W/live.txt) = 3 ] && [ \$(sort -u $W/live.txt | wc -l) = 1 ] && diff <(head -1 $W/live.txt) $W/now.txt && echo 'identical: repo file = installed on validator and sentry (3/3 sha256 equal)'"
echo "== static checks"
must "shellcheck acctpolicy/*.sh acctpolicy/tests/*.sh acctpolicy/drill/*.sh"
must "ruff check acctpolicy && ruff format --check acctpolicy"
must "cd acctpolicy && ruff check . && ruff format --check ."
echo "== offline suite (umask 022, then 002)"
must "umask 022; TMPDIR=$W bash acctpolicy/tests/run-tests.sh > $W/s1.txt 2>&1; rc=\$?; grep -E '^(FAIL|RESULT)' $W/s1.txt; exit \$rc"
must "umask 002; TMPDIR=$W bash acctpolicy/tests/run-tests.sh > $W/s2.txt 2>&1; rc=\$?; grep -E '^(FAIL|RESULT)' $W/s2.txt; exit \$rc"
must "grep -c '^PASS ' $W/s1.txt"
echo "== mutation harness (baseline must pass, then every mutant must be caught)"
must "TMPDIR=$W TEST_TMPDIR=$W python3 -I acctpolicy/tests/mutants.py -j 4"
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
