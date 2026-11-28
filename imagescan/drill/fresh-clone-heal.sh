#!/usr/bin/env bash
# fresh-clone-heal: anonymous public clone of this repo at a commit, then every offline check of the imagescan fetch
# retry + bounded imagescan heal (task_cb7b8dacdef0ebcd45ce6bdf6631708e): sha256 of the key files in the clone against
# the files installed on both hosts (read-only sha256sum, validator local + sentry via ssh relay; pft-fleet manifest
# destinations), the fleet manifest rows, shellcheck, ruff, both pytest suites, the generated upstreamwatch promtool
# tests unchanged and promtool check + test of both modules' rules (no rule added by this task).
# No host config is changed; no network after the clone except the read-only ssh hash read.
#   bash imagescan/drill/fresh-clone-heal.sh SHA 2>&1 | tee LOG
set -uo pipefail
SHA="${1:?usage: fresh-clone-heal.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | imagescan heal fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
echo "== key files: clone vs installed on both hosts (pft-fleet manifest destinations)"
# repo path=installed path=hosts (pft-fleet itself runs on the validator only, so only it has the fleet copy)
MAP="imagescan/pft-imagescan.sh=/usr/local/bin/pft-imagescan=both
imagescan/imagescan_lib.py=/usr/local/lib/pft-imagescan/imagescan_lib.py=both
imagescan/systemd/pft-imagescan.service=/etc/systemd/system/pft-imagescan.service=both
imagescan/systemd/pft-imagescan-heal.service=/etc/systemd/system/pft-imagescan-heal.service=both
upstreamwatch/pft-upstreamwatch.sh=/usr/local/bin/pft-upstreamwatch=both
upstreamwatch/upstreamwatch_lib.py=/usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py=both
fleet/manifest.tsv=/usr/local/lib/pft-aptrust/manifest.tsv=both
fleet/manifest.tsv=/usr/local/lib/pft-fleet/manifest.tsv=validator"
for h in validator sentry; do
  rows="$(echo "$MAP" | grep -E "=(both|$h)\$")"
  n="$(echo "$rows" | wc -l)"
  must "sha256sum $(echo "$rows" | cut -d= -f1 | tr '\n' ' ')> $W/clone-$h.full && cat $W/clone-$h.full && cut -c1-64 $W/clone-$h.full > $W/clone-$h.txt"
  dest="$(echo "$rows" | cut -d= -f2 | tr '\n' ' ')"
  if [ "$h" = validator ]; then
    must "sudo -n sha256sum $dest> $W/$h.full && cat $W/$h.full && cut -c1-64 $W/$h.full > $W/$h.txt"
  else
    must "ssh -o BatchMode=yes relay 'sudo -n sha256sum $dest' </dev/null > $W/$h.full && cat $W/$h.full && cut -c1-64 $W/$h.full > $W/$h.txt"
  fi
  must "[ \$(wc -l < $W/$h.txt) = $n ] && diff $W/clone-$h.txt $W/$h.txt && echo 'identical: $n/$n sha256 clone = installed on $h'"
done
must "grep -n 'pft-imagescan-heal.service' fleet/manifest.tsv"
must "sha256sum imagescan/tests/test_fetch.py imagescan/tests/mutate.py upstreamwatch/tests/test_upstreamwatch.py upstreamwatch/tests/mutate.py imagescan/drill/heal-proof.sh imagescan/README.md upstreamwatch/README.md"
echo "== static checks"
must "shellcheck imagescan/pft-imagescan.sh imagescan/install.sh imagescan/drill/*.sh upstreamwatch/pft-upstreamwatch.sh upstreamwatch/install.sh upstreamwatch/drill/*.sh && echo 'shellcheck: 0 findings'"
must "cd imagescan && ruff check ."
must "cd upstreamwatch && ruff check ."
echo "== tests"
must "cd imagescan && TMPDIR=$W TEST_TMPDIR=$W timeout 900 python3 -m pytest -q -p no:cacheprovider tests </dev/null 2>&1 | tail -n 2"
must "cd upstreamwatch && TMPDIR=$W TEST_TMPDIR=$W timeout 900 python3 -m pytest -q -p no:cacheprovider tests </dev/null 2>&1 | tail -n 2"
must "python3 upstreamwatch/tests/gen_rule_tests.py | cmp - alerts/upstreamwatch.tests.yml && echo 'generated promtool tests unchanged'"
echo "== promtool (pinned image already on the host)"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.16.0 check rules imagescan.rules.yml upstreamwatch.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.16.0 test rules imagescan.tests.yml upstreamwatch.tests.yml"
must "git diff --name-only ddc18b9 HEAD -- alerts/ | wc -l"
echo "== README sections"
must "grep -n -E 'retried_fresh|still_behind|pft-imagescan-heal.service' imagescan/README.md | head -n 12"
must "grep -n -E 'imagescan' upstreamwatch/README.md | grep -n -E 'HEALABLE|heal|LAG_HEAL_HOURS|HEAL_INTERVAL_HOURS' | head -n 12"
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
