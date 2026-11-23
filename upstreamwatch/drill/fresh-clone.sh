#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline check of upstreamwatch/
# (task_62b5fc29b42bbe4e484a03a450c97616): sha256 of the key files against what logs/01 recorded as installed on both
# hosts, shellcheck, ruff (repo root and upstreamwatch/), the full test suite, promtool check + test of the rules,
# and per host the text/JSON/Prometheus reports re-rendered offline from the committed reports/<host>/obs.json and
# compared with cmp against the committed reports. No docker call except promtool (--network none, pinned image
# already on the host), no host config (PFT_UW_CONF=/dev/null), no root, no network after the clone.
#   bash upstreamwatch/drill/fresh-clone.sh SHA 2>&1 | tee LOG
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | upstreamwatch fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
U=upstreamwatch/logs/01-install.log
K="upstreamwatch/pft-upstreamwatch.sh upstreamwatch/upstreamwatch_lib.py upstreamwatch/systemd/pft-upstreamwatch.service upstreamwatch/systemd/pft-upstreamwatch.timer"
echo "== key files vs the files installed on both hosts (logs/01 step 4: repo, validator, sentry)"
must "sha256sum $K | cut -c1-64 > $W/now.txt && sha256sum $K"
must "sed -n '/^\\\$ sha256sum upstreamwatch\\/pft-upstreamwatch.sh upstreamwatch\\/upstreamwatch_lib.py upstreamwatch\\/systemd\\/pft-upstreamwatch.service upstreamwatch\\/systemd\\/pft-upstreamwatch.timer | cut/,/^  (exit/p' $U | grep -oE '^  [0-9a-f]{64}$' | tr -d ' ' > $W/log.txt && wc -l < $W/log.txt"
n=0
for h in repo-at-install validator sentry; do
  n=$((n + 1))
  must "sed -n '$(((n - 1) * 4 + 1)),$((n * 4))p' $W/log.txt > $W/$h.txt && [ -s $W/$h.txt ] && diff $W/$h.txt $W/now.txt && echo 'identical: 4/4 sha256 equal $h (logs/01)'"
done
echo "== static checks"
must "shellcheck upstreamwatch/pft-upstreamwatch.sh upstreamwatch/install.sh upstreamwatch/drill/*.sh"
must "ruff check upstreamwatch"
must "cd upstreamwatch && ruff check ."
echo "== tests"
must "cd upstreamwatch && TMPDIR=$W timeout 900 python3 -m pytest -q -p no:cacheprovider tests </dev/null 2>&1 | tail -n 2"
echo "== promtool (pinned image already on the host)"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules upstreamwatch.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules upstreamwatch.tests.yml"
echo "== offline report re-render per host from the committed observation"
for h in validator sentry; do
  d=upstreamwatch/reports/$h
  must "sha256sum $d/obs.json"
  for f in text json prom; do
    ext=$f; [ "$f" = text ] && ext=txt
    must "PFT_UW_CONF=/dev/null PFT_UW_LIB=\$PWD/upstreamwatch/upstreamwatch_lib.py bash upstreamwatch/pft-upstreamwatch.sh report --obs $d/obs.json --format $f > $W/$h.$ext && cmp $W/$h.$ext $d/report.$ext && echo 'cmp exit 0: $h report.$ext byte-identical'"
  done
  must "grep -E '^(usn-host|RESULT)' $d/report.txt | cut -c1-160"
done
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
