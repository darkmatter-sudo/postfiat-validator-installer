#!/usr/bin/env bash
# checks: static checks + full suite on the committed HEAD, plus a fail-before control for a fix: the new tests run
# against the helper from OLD_SHA (in a scratch copy of alertstats/) and must FAIL there, by assertion.
#   bash alertstats/drill/checks.sh OLD_SHA 'pytest -k expression' 2>&1 | tee LOG   (from the repo root)
# Read-only: promtool runs in a throwaway container with --network none; nothing on the host changes.
set -uo pipefail
OLD="${1:?usage: checks.sh OLD_SHA K_EXPR}"; K="${2:?usage: checks.sh OLD_SHA K_EXPR}"
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "alertstats checks - $(date -u +%FT%TZ) - repo HEAD $(git rev-parse HEAD) (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO)) - fail-before vs $(git rev-parse "$OLD")"
must "sha256sum alertstats/*.sh alertstats/*.py alertstats/systemd/* alertstats/drill/*.sh alertstats/tests/*.py alerts/alertstats.rules.yml alerts/alertstats.tests.yml"
must "shellcheck alertstats/*.sh alertstats/drill/*.sh alertstats/tests/stubs/docker"
must "(cd alertstats && ruff check . && ruff format --check .)"
must "(cd alertstats && TMPDIR=\$HOME/.cache python3 -m pytest -q -p no:cacheprovider tests)"
must "sudo -n docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules alertstats.rules.yml"
must "sudo -n docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules alertstats.tests.yml"
echo "== fail-before control: HEAD tests, helper from $OLD"
W="$(mktemp -d -p "$HOME/.cache")"; trap 'rm -rf "$W"' EXIT
cp -r alertstats "$W/alertstats"; rm -rf "$W/alertstats/tests/__pycache__" "$W/alertstats/__pycache__"
git show "$OLD:alertstats/alertstats_build.py" > "$W/alertstats/alertstats_build.py"
x "sha256sum alertstats/alertstats_build.py; (cd \$W/alertstats && sha256sum alertstats_build.py)"
x "(cd \$W/alertstats && TMPDIR=\$HOME/.cache python3 -m pytest -q -p no:cacheprovider tests -k '$K' 2>&1 | grep -E '^(FAILED|E +assert|[0-9]+ (passed|failed))' | sed 's/ in [0-9.]*s//')"
rc=$?
if [ "$rc" = 1 ]; then echo "CONTROL ok: the new tests fail on the old helper"; else echo "CONTROL FAIL: expected pytest exit 1, got $rc"; FAILS=$((FAILS + 1)); fi
x "(cd \$W/alertstats && cp $REPO/alertstats/alertstats_build.py . && TMPDIR=\$HOME/.cache python3 -m pytest -q -p no:cacheprovider tests -k '$K' 2>&1 | tail -n 1 | sed 's/ in [0-9.]*s//')" || FAILS=$((FAILS + 1))
echo "checks done $(date -u +%FT%TZ): $FAILS failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
