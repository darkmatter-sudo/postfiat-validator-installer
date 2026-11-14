#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline histarchive gap-repair check:
# sha256 of the key files against the values the live run (logs/22) recorded and installed, the committed capture
# against its SHA256SUMS, shellcheck, ruff, all four unittest suites, promtool check + test, and the offline
# re-derivation of the real 8042619-8042680 fill from the committed capture (drill/repro-real-gap.py: verify gaps
# 1 -> 0, fill segment byte-identical to the live one, duplicate refused, independent seqcheck PASS).
# Nothing on the host is read or changed (no node, no RPC; promtool runs with --network none).
#   bash histarchive/drill/fresh-clone.sh SHA 2>&1 | tee LOG
# The work dir is a new mktemp dir under ~/.cache, mode 755 (/tmp is noexec here, and the promtool container runs as
# nobody), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | histarchive gap-repair fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2) | age $(age --version)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
echo "== key files vs the live gap-repair run (logs/22 preflight lines 5-11: the code that was installed on both hosts and filled the gap)"
must "sha256sum histarchive/pft-histarchive.sh histarchive/histarchive.py histarchive/lib_hashverify.py histarchive/tests/seqcheck.py histarchive/drill/fill-run.sh alerts/histarchive.rules.yml histarchive/logs/data/gap-8042619-8042680/capture-8042618-8042681.jsonl > $W/now.txt && cat $W/now.txt"
must "sed -n '5,11p' histarchive/logs/22-fill-live-resumed.log | sed 's/^ *//' > $W/live.txt && diff $W/live.txt $W/now.txt && echo 'identical: 7/7 sha256 equal the live run'"
must "cd histarchive/logs/data/gap-8042619-8042680 && sha256sum -c SHA256SUMS"
must "sha256sum histarchive/tests/*.py histarchive/drill/*.sh histarchive/drill/*.py histarchive/install.sh alerts/histarchive.tests.yml"
echo "== static checks"
must "shellcheck histarchive/pft-histarchive.sh histarchive/install.sh histarchive/drill/*.sh"
must "cd histarchive && ruff check . && ruff format --check ."
echo "== all test suites (fake JSON-RPC node, real age; tests/test_fillgap.py holds every adversarial fill case)"
must "cd histarchive && TMPDIR=$W TEST_TMPDIR=$W timeout 1500 python3 -m unittest tests/test_histarchive.py tests/test_wrapper.py tests/test_diskcost.py tests/test_fillgap.py </dev/null > $W/unit.txt 2>&1; rc=\$?; tail -n 4 $W/unit.txt; exit \$rc"
must "grep -c '^FAIL:\\|^ERROR:' $W/unit.txt || true"
echo "== promtool (pinned image already on the host)"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules histarchive.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules histarchive.tests.yml"
echo "== offline re-derivation of the real gap repair from the committed capture"
must "TMPDIR=$W python3 -u histarchive/drill/repro-real-gap.py"
echo "fresh-clone done $(date -u +%FT%TZ): $FAILS step(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
