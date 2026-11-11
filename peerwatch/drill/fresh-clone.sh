#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline peerwatch check (shellcheck, ruff,
# the fixture suite, the summary over the published history, promtool, the mutation harness) on that clone. Nothing on
# the host is read or changed.
#   bash peerwatch/drill/fresh-clone.sh SHA [--no-mutants] 2>&1 | tee LOG
# The work dir is a new mktemp dir under ~/.cache, mode 755 (/tmp is noexec here, and the promtool container runs as
# nobody), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA [--no-mutants]}"
MUT=1; [ "${2:-}" = --no-mutants ] && MUT=0
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | peerwatch fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
x "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
x "git checkout -q $SHA && git rev-parse HEAD"
x "git status --short | wc -l"
x "sha256sum peerwatch/*.sh peerwatch/*.py peerwatch/systemd/* peerwatch/tests/*.py peerwatch/tests/fixtures/* alerts/peerwatch.rules.yml alerts/peerwatch.tests.yml"
echo "== static checks"
x "shellcheck peerwatch/*.sh peerwatch/drill/*.sh"
x "cd peerwatch && ruff check . && ruff format --check ."
echo "== fixture suite"
x "TEST_TMPDIR=$W python3 -I peerwatch/tests/test_peerwatch.py 2>&1 | tail -n 4"
echo "== promtool (generated file up to date, then the tests)"
x "python3 peerwatch/tests/gen_rule_tests.py | cmp - alerts/peerwatch.tests.yml && echo generated file up to date"
x "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules peerwatch.rules.yml"
x "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules peerwatch.tests.yml"
if [ -d peerwatch/logs/data ]; then
  echo "== summary re-computed from the published history files (must equal the committed summary)"
  x "for f in peerwatch/logs/data/summary-*.md; do echo \$f; done"
fi
if [ "$MUT" = 1 ]; then
  echo "== mutation harness (baseline, timeout and orphan controls first)"
  x "TEST_TMPDIR=$W nice -n 15 python3 -u peerwatch/tests/mutate.py --jobs 2 | tail -n 8"
fi
echo "fresh-clone done $(date -u +%FT%TZ)"
