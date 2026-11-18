#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline check of budget/ and the
# histarchive bounded verify (task_9fb56f105f2b404c135135b0e6ff456e): sha256 of the key files against what logs/12
# recorded as installed on both hosts, the committed sampler JSONL against its logs/12 sha256, shellcheck, ruff,
# the budget and histarchive test suites, promtool check + test, and the offline rebuild of the report from the
# committed JSONL (text and --json) compared with cmp against the committed report.
# Nothing on the host is read or changed (no node, no sampler data; promtool runs with --network none).
#   bash budget/drill/fresh-clone.sh SHA 2>&1 | tee LOG
# The work dir is a new mktemp dir under ~/.cache, mode 755 (/tmp is noexec here, and the promtool container runs as
# nobody), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | budget fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
S=budget/logs/12-snapshot.log
echo "== key files vs the files installed on both hosts (logs/12: the code running when the JSONL was taken)"
must "sha256sum budget/pft-budget.sh budget/budget.py budget/systemd/pft-budget-sampler.service budget/systemd/pft-budget-collect.service histarchive/histarchive.py histarchive/pft-histarchive.sh | cut -c1-64 > $W/now.txt && cat $W/now.txt"
for h in validator sentry; do
  must "sed -n '/^== installed key files, $h/,/^==/p' $S | grep -E '^[0-9a-f]{64} ' | cut -c1-64 > $W/$h.txt && diff $W/$h.txt $W/now.txt && echo 'identical: 6/6 sha256 equal the $h install'"
done
echo "== committed sampler JSONL vs the sha256 taken at the snapshot (logs/12)"
must "grep -E '^[0-9a-f]{64}  logs/data/' $S | (cd budget && sha256sum -c)"
echo "== static checks"
must "shellcheck budget/*.sh budget/drill/*.sh histarchive/pft-histarchive.sh"
must "cd budget && ruff check . && ruff format --check ."
must "cd histarchive && ruff check . && ruff format --check ."
echo "== test suites"
must "cd budget && TMPDIR=$W timeout 900 python3 -m pytest -q -p no:cacheprovider tests </dev/null 2>&1 | tail -n 3"
must "cd histarchive && TMPDIR=$W TEST_TMPDIR=$W timeout 1500 python3 -m unittest tests/test_histarchive.py tests/test_wrapper.py tests/test_diskcost.py tests/test_fillgap.py </dev/null > $W/unit.txt 2>&1; rc=\$?; tail -n 4 $W/unit.txt; exit \$rc"
echo "== promtool (pinned image already on the host)"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules budget.rules.yml histarchive.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules budget.tests.yml histarchive.tests.yml"
echo "== offline report rebuild from the committed JSONL (example conf = live conf values, --now from logs/data/NOW)"
D=budget/logs/data
# report exits 2 when any unit is WARN (here: the two deliberate old-code 'before' runs at 1G); cmp decides
for fmt in txt json; do
  j=""; [ "$fmt" = json ] && j=--json
  must "python3 -I budget/budget.py --conf budget/pft-budget.env.example report $j --now \$(cat $D/NOW) --data $D/validator-samples.jsonl $D/sentry-samples.jsonl > $W/report.$fmt; echo \"report rc \$?\"; cmp $W/report.$fmt $D/report-offline.$fmt && echo 'cmp exit 0: $fmt report byte-identical'"
done
must "grep -E 'histarchive-(periodic|verify)|^RESULT' $D/report-offline.txt"
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
