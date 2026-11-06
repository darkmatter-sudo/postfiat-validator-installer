#!/usr/bin/env bash
# Recorded checks for jobwatch at the current (pushed, clean) HEAD: shellcheck, ruff check + format --check,
# promtool check + test rules, the offline suite and the mutant harness, plus the alerts/ ntfy bridge (unit tests +
# mutants; one message per state change, 2026-11-06). Changes nothing on the host.
#   bash jobwatch/drill/checks-run.sh 2>&1 | tee LOG    (from the repo root)
# shellcheck disable=SC1091
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 3
export TZ=UTC TEST_TMPDIR="$HOME/.cache"
x() { echo "\$ $*"; eval "$*"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; FAILS=$((FAILS + 1)); fi; }
# shellcheck disable=SC2016 # expanded by eval in x(), so the log shows $PWD, not the local path
P='docker run --rm --network none --entrypoint promtool -v "$PWD/alerts":/w:ro -w /w prom/prometheus:v3.5.0'
echo "jobwatch checks - $(date -u +%FT%TZ) - OS: $(. /etc/os-release; echo "$PRETTY_NAME") - HEAD $(git rev-parse HEAD) (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
echo "== this script"; sed 's/^/  | /' jobwatch/drill/checks-run.sh
x "sha256sum jobwatch/pft-jobwatch.sh jobwatch/jobwatch_lib.py jobwatch/install.sh jobwatch/systemd/* alerts/jobwatch.rules.yml alerts/jobwatch.tests.yml jobwatch/tests/*.py alerts/ntfy_bridge.py alerts/test_ntfy_bridge.py alerts/mutate_bridge.py"
x "shellcheck --version | sed -n 2p; shellcheck jobwatch/pft-jobwatch.sh jobwatch/install.sh jobwatch/drill/*.sh"; check "shellcheck clean" $?
x "ruff --version; ruff check jobwatch/ alerts/ntfy_bridge.py alerts/test_ntfy_bridge.py alerts/mutate_bridge.py && ruff format --check jobwatch/ alerts/ntfy_bridge.py alerts/test_ntfy_bridge.py alerts/mutate_bridge.py"; check "ruff check + format clean" $?
x "$P check rules jobwatch.rules.yml"; check "promtool check rules" $?
x "$P test rules jobwatch.tests.yml"; check "promtool test rules" $?
x "python3 -u jobwatch/tests/test_jobwatch.py"; check "offline suite" $?
x "python3 -u jobwatch/tests/mutate.py --jobs 4"; check "mutants: all CAUGHT, 0 orphans" $?
x "(cd alerts && python3 -m unittest -v test_ntfy_bridge 2>&1)"; check "ntfy bridge unit tests" $?
x "python3 -u alerts/mutate_bridge.py"; check "ntfy bridge mutants: all CAUGHT" $?
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) ($FAILS failed checks) - end $(date -u +%FT%TZ)"
[ "$FAILS" = 0 ]
