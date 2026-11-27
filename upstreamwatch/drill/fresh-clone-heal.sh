#!/usr/bin/env bash
# fresh-clone-heal: anonymous public clone of this repo at a commit, then every offline check of the local_lagging +
# bounded vulnscan heal (task_dfa49345fcc602ce6d66553813e99516): sha256 of the key files in the clone against the
# files installed on both hosts (read-only sha256sum, validator local + sentry via ssh relay), shellcheck, ruff, the
# full pytest suite, the vulnscan test suite, the generated promtool tests and promtool check + test of the rules.
# No host config is changed; no network after the clone except the read-only ssh hash read.
#   bash upstreamwatch/drill/fresh-clone-heal.sh SHA 2>&1 | tee LOG
set -uo pipefail
SHA="${1:?usage: fresh-clone-heal.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | heal fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
echo "== key files: clone vs installed on both hosts (pft-fleet manifest destinations)"
# repo path -> installed path (fleet/manifest.tsv rows, both hosts)
MAP="upstreamwatch/pft-upstreamwatch.sh=/usr/local/bin/pft-upstreamwatch
upstreamwatch/upstreamwatch_lib.py=/usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py
upstreamwatch/systemd/pft-upstreamwatch.service=/etc/systemd/system/pft-upstreamwatch.service
vulnscan/pft-vulnscan.sh=/usr/local/bin/pft-vulnscan
vulnscan/systemd/pft-vulnscan-heal.service=/etc/systemd/system/pft-vulnscan-heal.service"
REPO_FILES="$(echo "$MAP" | cut -d= -f1 | tr '\n' ' ')"
DEST_FILES="$(echo "$MAP" | cut -d= -f2 | tr '\n' ' ')"
must "sha256sum $REPO_FILES > $W/clone.full && cat $W/clone.full && cut -c1-64 $W/clone.full > $W/clone.txt"
must "sudo -n sha256sum $DEST_FILES > $W/validator.full && cat $W/validator.full && cut -c1-64 $W/validator.full > $W/validator.txt"
must "ssh -o BatchMode=yes relay 'sudo -n sha256sum $DEST_FILES' </dev/null > $W/sentry.full && cat $W/sentry.full && cut -c1-64 $W/sentry.full > $W/sentry.txt"
for h in validator sentry; do
  must "[ \$(wc -l < $W/$h.txt) = 5 ] && diff $W/clone.txt $W/$h.txt && echo 'identical: 5/5 sha256 clone = installed on $h'"
done
must "sha256sum alerts/upstreamwatch.rules.yml alerts/upstreamwatch.tests.yml upstreamwatch/tests/test_upstreamwatch.py upstreamwatch/tests/mutate.py vulnscan/tests/run-tests.sh upstreamwatch/drill/heal-proof.sh upstreamwatch/README.md"
echo "== static checks"
must "shellcheck upstreamwatch/pft-upstreamwatch.sh upstreamwatch/install.sh upstreamwatch/drill/*.sh vulnscan/pft-vulnscan.sh vulnscan/install.sh vulnscan/tests/run-tests.sh && echo 'shellcheck: 0 findings'"
must "cd upstreamwatch && ruff check ."
echo "== tests"
must "cd upstreamwatch && TMPDIR=$W timeout 900 python3 -m pytest -q -p no:cacheprovider tests </dev/null 2>&1 | tail -n 2"
must "TEST_TMPDIR=$W timeout 1200 bash vulnscan/tests/run-tests.sh </dev/null | grep -E '^(FAIL|RESULT)'"
must "python3 upstreamwatch/tests/gen_rule_tests.py | cmp - alerts/upstreamwatch.tests.yml && echo 'generated promtool tests unchanged'"
echo "== promtool (pinned image already on the host)"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.16.0 check rules upstreamwatch.rules.yml vulnscan.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.16.0 test rules upstreamwatch.tests.yml vulnscan.tests.yml"
echo "== README section with the state table and the new settings"
must "grep -n -E '^## (States|Bounded heal)|local_lagging|LAG_HEAL_HOURS|HEAL_INTERVAL_HOURS' upstreamwatch/README.md | head -n 20"
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
