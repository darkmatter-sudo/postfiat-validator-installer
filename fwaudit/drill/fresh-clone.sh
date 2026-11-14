#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline fwaudit check (shellcheck, ruff,
# the fixture/stub suite, promtool check + test, the integrity v6 collector tests, sha256 of the published logs) on
# that clone. Nothing on the host is read or changed (the stub suite never calls the real ufw/docker/systemctl).
#   bash fwaudit/drill/fresh-clone.sh SHA [--mutants] 2>&1 | tee LOG
# --mutants also runs tests/mutate.py (about 50 min with 3 jobs). The work dir is a new mktemp dir under ~/.cache,
# mode 755 (/tmp is noexec here, and the promtool container runs as nobody), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA [--mutants]}"
MUT=0; [ "${2:-}" = --mutants ] && MUT=1
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | fwaudit fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2) | pytest $(python3 -m pytest --version 2>&1 | awk '{print $2}')"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
must "sha256sum fwaudit/*.sh fwaudit/*.py fwaudit/policy/* fwaudit/systemd/* fwaudit/drill/*.sh alerts/fwaudit.rules.yml alerts/fwaudit.tests.yml integrity/pft-integrity.sh"
must "sha256sum fwaudit/logs/*.log"
echo "== static checks"
must "shellcheck fwaudit/*.sh fwaudit/drill/*.sh fwaudit/tests/stubs/collect fwaudit/tests/stubs/docker fwaudit/tests/stubs/logcall fwaudit/tests/stubs/maint fwaudit/tests/stubs/rpc"
must "cd fwaudit && ruff check . && ruff format --check ."
echo "== fixture + stub suite"
must "cd fwaudit && TMPDIR=$W TEST_TMPDIR=$W python3 -m pytest -q -p no:cacheprovider tests 2>&1 | tail -n 3"
echo "== promtool"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules fwaudit.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules fwaudit.tests.yml"
echo "== integrity fw:ufw v6 collector tests"
must "TEST_TMPDIR=$W bash integrity/tests/test-fw.sh 2>&1 | tail -n 3"
if [ "$MUT" = 1 ]; then
  echo "== mutation harness (baseline, timeout and orphan controls first)"
  must "TEST_TMPDIR=$W nice -n 15 python3 -u fwaudit/tests/mutate.py --jobs 3 </dev/null | tail -n 8"
fi
echo "fresh-clone done $(date -u +%FT%TZ): $FAILS step(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
