#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline peertls check: sha256 of the key
# files against the values the recorded install (INSTALL_LOG, preflight sha256 lines) printed, shellcheck, ruff (from
# the repo root and from peertls/), the full test suite (real weak s_server fixtures + the fix's stub node), promtool
# check + test, and the offline rebuild of every committed cross-host report: `render JSON | cmp - TXT` exit 0, the
# two crosschecks re-run from the committed JSON (PASS, output = committed file) and the flip control (must FAIL).
# Nothing on the host is read or changed (s_server binds 127.0.0.1 only; promtool runs with --network none).
#   bash peertls/drill/fresh-clone.sh SHA peertls/logs/NN-install-run.log 2>&1 | tee LOG
# The work dir is a new mktemp dir under ~/.cache, mode 755 (/tmp is noexec here, and the promtool container runs as
# nobody), removed at the end.
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA INSTALL_LOG}"; ILOG="${2:?usage: fresh-clone.sh SHA INSTALL_LOG}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | peertls fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2) | pytest $(python3 -m pytest --version 2>&1 | awk '{print $2}') | $(openssl version | cut -d' ' -f1-2)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
KEY="peertls/pft-peertls.sh peertls/pft-peertls-fix.sh peertls/peertls_eval.py peertls/install.sh peertls/policy/sentry.policy peertls/policy/validator.policy alerts/peertls.rules.yml"
echo "== key files vs the recorded install ($ILOG: the bytes pft-fleet installed on both hosts)"
must "sha256sum $KEY > $W/now.txt && cat $W/now.txt"
must "for f in $KEY; do grep -E \"^  [0-9a-f]{64}  \$f\\\$\" $ILOG | head -1 | sed 's/^  //'; done > $W/inst.txt && diff $W/inst.txt $W/now.txt && echo \"identical: \$(wc -l < $W/now.txt)/7 sha256 equal the install log\""
must "sha256sum peertls/tests/*.py peertls/tests/fixnode/docker peertls/drill/*.sh peertls/systemd/* alerts/peertls.tests.yml peertls/logs/*.log peertls/logs/cross/*"
echo "== static checks"
must "shellcheck peertls/*.sh peertls/drill/*.sh peertls/tests/fixnode/docker"
must "ruff check peertls && cd peertls && ruff check . && ruff format --check ."
echo "== full test suite (weak s_server fixtures on 127.0.0.1, fix script against the stub node)"
must "cd peertls && TMPDIR=$W TEST_TMPDIR=$W timeout 1500 python3 -m pytest -q -p no:cacheprovider tests </dev/null 2>&1 | tail -n 3"
echo "== promtool (pinned image already on the host)"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules peertls.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules peertls.tests.yml"
echo "== offline rebuild of the committed cross-host reports"
for n in validator-local sentry-local validator-remote sentry-remote; do
  must "python3 peertls/peertls_eval.py render peertls/logs/cross/$n.json | cmp - peertls/logs/cross/$n.txt && echo '$n: render(JSON) == committed report (cmp exit 0)'"
done
must "python3 peertls/peertls_eval.py crosscheck peertls/logs/cross/validator-remote.json peertls/logs/cross/sentry-local.json | cmp - peertls/logs/cross/crosscheck-validator-to-sentry.txt && echo 'validator -> sentry crosscheck PASS, output == committed'"
must "python3 peertls/peertls_eval.py crosscheck peertls/logs/cross/sentry-remote.json peertls/logs/cross/validator-local.json | cmp - peertls/logs/cross/crosscheck-sentry-to-validator.txt && echo 'sentry -> validator crosscheck PASS, output == committed'"
must "out=\$(python3 peertls/peertls_eval.py crosscheck peertls/logs/cross/validator-remote.json peertls/logs/cross/validator-local.json); rc=\$?; grep 'cert sha256' <<<\"\$out\"; echo \"flip control rc=\$rc (want 2)\"; [ \$rc = 2 ] && grep -q '^FAIL .* cert sha256: ' <<<\"\$out\" && cmp <(printf '%s\\n' \"\$out\") peertls/logs/cross/crosscheck-flip-control.txt"
echo "fresh-clone done $(date -u +%FT%TZ): $FAILS step(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
