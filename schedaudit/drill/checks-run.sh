#!/usr/bin/env bash
# shellcheck disable=SC1091
# Recorded checks for schedaudit at the current (pushed, clean) HEAD: shellcheck (schedaudit + the pft-integrity hook),
# ruff check + format --check, promtool check + test rules, the offline suite and the mutant harness. Changes nothing
# on the host (promtool runs in the pinned prom/prometheus:v3.5.0 image already on the host, --network none).
#   bash schedaudit/drill/checks-run.sh 2>&1 | tee LOG    (from the repo root)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 3
export TZ=UTC TEST_TMPDIR="$HOME/.cache"
x() { echo "\$ $*"; eval "$*"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; FAILS=$((FAILS + 1)); fi; }
# shellcheck disable=SC2016 # expanded by eval in x(), so the log shows $PWD, not the local path
P='docker run --rm --network none --entrypoint promtool -v "$PWD/alerts":/w:ro -w /w prom/prometheus:v3.5.0'
echo "schedaudit checks - $(date -u +%FT%TZ) - OS: $(. /etc/os-release; echo "$PRETTY_NAME") - HEAD $(git rev-parse HEAD) (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
echo "== this script"; sed 's/^/  | /' schedaudit/drill/checks-run.sh
x "sha256sum schedaudit/pft-schedaudit.sh schedaudit/schedaudit_lib.py schedaudit/install.sh schedaudit/systemd/* alerts/schedaudit.rules.yml alerts/schedaudit.tests.yml schedaudit/tests/*.py integrity/pft-integrity.sh"
x "shellcheck --version | sed -n 2p; shellcheck schedaudit/pft-schedaudit.sh schedaudit/install.sh schedaudit/drill/*.sh integrity/pft-integrity.sh"; check "shellcheck clean" $?
x "ruff --version; ruff check schedaudit/ && ruff format --check schedaudit/"; check "ruff check + format clean" $?
x "$P check rules schedaudit.rules.yml"; check "promtool check rules" $?
x "$P test rules schedaudit.tests.yml"; check "promtool test rules" $?
x "nice -n 15 python3 -u schedaudit/tests/test_schedaudit.py"; check "offline suite" $?
x "nice -n 15 python3 -u schedaudit/tests/mutate.py --jobs 2 --timeout 180"; check "mutants: all CAUGHT, 0 orphans" $?
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) ($FAILS failed checks) - end $(date -u +%FT%TZ)"
[ "$FAILS" = 0 ]
