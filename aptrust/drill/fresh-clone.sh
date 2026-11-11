#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline aptrust check (shellcheck, the
# fixture suite, promtool; the mutation harness is recorded separately, logs/43) on that clone. Nothing on the host is read or changed.
#   bash aptrust/drill/fresh-clone.sh SHA 2>&1 | tee LOG
# The work dir is a new mktemp dir under ~/.cache, mode 755 (/tmp is noexec here, and the promtool container runs as
# nobody), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
x() { echo "\$ $*" | sed -E "s#$HOME#~#g"; ( eval "$*" ) 2>&1 | sed -E "s#$HOME#~#g"; echo "(exit ${PIPESTATUS[0]})"; }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | aptrust fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | $(jq --version) | $(gpg --version | head -n 1)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
x "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
x "git checkout -q $SHA && git rev-parse HEAD"
x "git status --short | wc -l"
x "sha256sum aptrust/pft-aptrust.sh aptrust/install.sh aptrust/systemd/* aptrust/drill/*.sh aptrust/tests/* alerts/aptrust.rules.yml alerts/aptrust.tests.yml"
echo "== static checks"
x "shellcheck aptrust/pft-aptrust.sh aptrust/install.sh aptrust/tests/run-tests.sh aptrust/tests/orphan-controls.sh aptrust/drill/*.sh"
x "bash -n aptrust/pft-aptrust.sh && python3 -m py_compile aptrust/tests/mutate.py && echo syntax ok"
echo "== fixture suite"
x "TEST_TMPDIR=$W bash aptrust/tests/run-tests.sh | tail -n 3"
echo "== promtool"
x "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules aptrust.tests.yml"
x "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules aptrust.rules.yml"
echo "== mutation harness: not re-run here (91 mutants x the full suite is ~70 min); the recorded run is logs/43, made"
echo "   at de6189ef01382f10bab8b8b5204dacdc0f89bf6b; the mutated files and the suite must be unchanged since then (0 below)."
echo "   (tests/mutate.py itself changed after it: orphan-check fix, logs/44)"
x "git diff de6189ef01382f10bab8b8b5204dacdc0f89bf6b HEAD -- aptrust/pft-aptrust.sh aptrust/tests/run-tests.sh alerts/aptrust.rules.yml alerts/aptrust.tests.yml | wc -l"
x "git diff --stat de6189ef01382f10bab8b8b5204dacdc0f89bf6b HEAD -- aptrust/tests"
echo "fresh-clone done $(date -u +%FT%TZ)"
