#!/usr/bin/env bash
# record-tests.sh: the full test set for ../dnsaudit as one recorded log (used for logs/ and the fresh-clone
# transcript): repo HEAD + sha256 of every file under test, shellcheck, ruff (check + format), the offline suite,
# promtool check/test of the rule, the alert-rule mutants and the script mutants. Output is redacted (home paths,
# user name). Exit 0 only if every step passed.
#   TEST_TMPDIR=$HOME/.cache bash dnsaudit/tests/record-tests.sh 2>&1 | tee LOG
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D="$(cd "$HERE/.." && pwd)"; A="$(cd "$D/../alerts" && pwd)"
export TEST_TMPDIR="${TEST_TMPDIR:-$HOME/.cache}"
case "$TEST_TMPDIR" in /*) ;; *) echo "TEST_TMPDIR must be absolute"; exit 3 ;; esac
U="$(id -un)"
red() { sed -E "s#$HOME#~#g; s#/home/[a-z0-9_-]+#~#g; s#\b$U\b#<user>#g"; }
FAILS=0
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; local rc="${PIPESTATUS[0]}"; echo "  (exit $rc)"; [ "$rc" = 0 ] || FAILS=$((FAILS + 1)); return 0; }
echo "dnsaudit record-tests - $(date -u +%FT%TZ)"
x "git -C '$D' rev-parse HEAD; git -C '$D' status --short -- . ../alerts | wc -l"
x "cd '$D' && sha256sum pft-dnsaudit.sh systemd/pft-dnsaudit.service systemd/pft-dnsaudit.timer tests/run-tests.sh tests/stub_dig.py tests/mutate.py tests/rules-mutants.sh '$A/dnsaudit.rules.yml' '$A/dnsaudit.tests.yml' | sed 's#  .*/alerts/#  alerts/#'"
x "cd '$D' && shellcheck --version | sed -n 2p && shellcheck pft-dnsaudit.sh tests/*.sh drill/*.sh && echo shellcheck-clean"
x "cd '$D' && ruff --version && ruff check . && ruff format --check ."
x "cd '$D/tests' && ruff check . && ruff format --check ."
x "bash '$D/tests/run-tests.sh' | tail -3"
P="$(mktemp -d -p "$TEST_TMPDIR")"; chmod 755 "$P"; cp "$A/dnsaudit.rules.yml" "$A/dnsaudit.tests.yml" "$P/"; chmod 644 "$P"/*.yml
x "sudo -n docker run --rm -v '$P:/w' -w /w --entrypoint promtool prom/prometheus:v3.5.0 check rules dnsaudit.rules.yml"
x "sudo -n docker run --rm -v '$P:/w' -w /w --entrypoint promtool prom/prometheus:v3.5.0 test rules dnsaudit.tests.yml"
rm -rf "$P"
x "bash '$D/tests/rules-mutants.sh'"
x "nice -n 15 python3 -I '$D/tests/mutate.py' -j 4"
echo "RESULT: $FAILS step(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
