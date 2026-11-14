#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline alertstats check (sha256 of the
# key files and published logs, shellcheck, ruff, pytest, promtool check + test) and the byte-identical --offline
# rebuild of the published 7-day report (md, json, csv) from its committed bundle. Nothing on the host is read or
# changed (no Prometheus/Alertmanager/docker logs access; promtool runs with --network none).
#   bash alertstats/drill/fresh-clone.sh SHA [--mutants] 2>&1 | tee LOG
# --mutants also runs tests/mutate.py. The work dir is a new mktemp dir under ~/.cache, mode 755 (/tmp is noexec
# here, and the promtool container runs as nobody), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA [--mutants]}"
MUT=0; [ "${2:-}" = --mutants ] && MUT=1
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | alertstats fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2) | pytest $(python3 -m pytest --version 2>&1 | awk '{print $2}')"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
must "sha256sum alertstats/*.sh alertstats/*.py alertstats/systemd/* alertstats/drill/*.sh alertstats/tests/*.py alerts/alertstats.rules.yml alerts/alertstats.tests.yml"
must "sha256sum alertstats/logs/*.log alertstats/logs/report-7d*/*"
echo "== static checks"
must "shellcheck alertstats/*.sh alertstats/drill/*.sh alertstats/tests/stubs/docker"
must "cd alertstats && ruff check . && ruff format --check ."
echo "== pytest (synthetic + real captures, stub API, redaction gate)"
must "cd alertstats && TMPDIR=$W TEST_TMPDIR=$W python3 -m pytest -q -p no:cacheprovider tests 2>&1 | tail -n 3"
echo "== promtool"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules alertstats.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules alertstats.tests.yml"
echo "== byte-identical --offline rebuild of the published 7-day report"
# every published report dir (the first install's and the upgrade's): md/json/csv rebuilt from its bundle
NB=0
for D in alertstats/logs/report-7d*/; do
  for B in "$D"*.json.gz; do
    [ -f "$B" ] || continue
    NB=$((NB + 1))
    for f in md json csv; do
      must "python3 -I alertstats/alertstats_build.py report --offline $B --format $f | cmp - ${B%.json.gz}.$f && echo identical $f"
    done
  done
  must "python3 -I alertstats/tests/redaction_gate.py $D"
done
echo "published bundles rebuilt: $NB"
[ "$NB" -ge 1 ] || { echo "no published bundle"; FAILS=$((FAILS + 1)); }
if [ "$MUT" = 1 ]; then
  echo "== mutation harness"
  must "TEST_TMPDIR=$W nice -n 15 python3 -u alertstats/tests/mutate.py </dev/null | tail -n 8"
fi
echo "fresh-clone done $(date -u +%FT%TZ): $FAILS step(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
