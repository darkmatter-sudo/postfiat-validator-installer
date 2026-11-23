#!/usr/bin/env bash
# fresh-clone: anonymous public clone of this repo at a commit, then every offline check of imagescan/
# (task_76248c8a4b04f05417f1bd7088735a54): sha256 of the key files against what logs/17 recorded as installed on both
# hosts, shellcheck, ruff (from the repo root and from imagescan/), the test suite, promtool check + test, and per
# host the offline public report rebuilt from the committed bundle (reports/<host>/: inventories minus the withheld
# upstream image, containers, scan time, feeds.json + xz feed copies, withheld.json, before.json) compared with cmp
# against the committed report. The feed copies are unpacked and checked against the sha256 pinned in feeds.json
# first (the report refuses a feed whose hash differs, too). No docker call except promtool (--network none, pinned
# image already on the host), no host config (PFT_IS_CONF=/dev/null), no root, no network after the clone.
#   bash imagescan/drill/fresh-clone.sh SHA 2>&1 | tee LOG
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA}"
export TZ=UTC
W="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$W"; trap 'rm -rf "$W"' EXIT
red() { sed -u -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g"; }
x() { echo "\$ $*" | red; ( eval "$*" ) 2>&1 | red; rc=${PIPESTATUS[0]}; echo "(exit $rc)"; return "$rc"; }
FAILS=0; must() { x "$@" || FAILS=$((FAILS + 1)); }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | imagescan fresh-clone verification at $SHA | $(shellcheck --version | sed -n 's/^version: /shellcheck /p') | $(python3 --version) | ruff $(ruff --version | cut -d' ' -f2) | $(xz --version | head -1)"
echo "(work dir: a new mktemp dir under ~/.cache, mode 755; /tmp is noexec on this host)"
cd "$W" || exit 3
must "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git repo"
cd repo || exit 3
must "git checkout -q $SHA && git rev-parse HEAD"
must "git status --short | wc -l"
U=imagescan/logs/17-upgrade.log
K="imagescan/pft-imagescan.sh imagescan/imagescan_lib.py imagescan/systemd/pft-imagescan.service imagescan/systemd/pft-imagescan.timer"
echo "== key files vs the files installed on both hosts (logs/17: the upgrade to the submitted code)"
must "sha256sum $K | cut -c1-64 > $W/now.txt && cat $W/now.txt"
# logs/17 step 3 prints 12 hashes: repo (4), validator installed (4), sentry installed (4)
must "sed -n '/^\\\$ sha256sum imagescan\\/pft-imagescan.sh imagescan\\/imagescan_lib.py imagescan\\/systemd\\/pft-imagescan.service/,/^  (exit/p' $U | grep -oE '^  [0-9a-f]{64}$' | tr -d ' ' > $W/log.txt && wc -l < $W/log.txt"
n=0
for h in repo-at-install validator sentry; do
  n=$((n + 1))
  must "sed -n '$(((n - 1) * 4 + 1)),$((n * 4))p' $W/log.txt > $W/$h.txt && [ -s $W/$h.txt ] && diff $W/$h.txt $W/now.txt && echo 'identical: 4/4 sha256 equal $h (logs/17)'"
done
echo "== static checks"
must "shellcheck imagescan/pft-imagescan.sh imagescan/install.sh imagescan/drill/*.sh"
must "ruff check imagescan"
must "cd imagescan && ruff check ."
echo "== tests"
must "cd imagescan && TMPDIR=$W TEST_TMPDIR=$W timeout 900 python3 -m pytest -q -p no:cacheprovider tests </dev/null 2>&1 | tail -n 2"
echo "== promtool (pinned image already on the host)"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 check rules imagescan.rules.yml"
must "docker run --rm --network none --entrypoint promtool -v \"\$PWD/alerts\":/w:ro -w /w prom/prometheus:v3.5.0 test rules imagescan.tests.yml"
echo "== offline public report rebuild per host from the committed bundle"
for h in validator sentry; do
  R=imagescan/reports/$h; B="$W/bundle-$h"
  must "cp -r $R $B && rm -f $B/report-public.txt && for f in $B/feeds/*.xz; do xz -d \"\$f\" || exit 1; done && ls $B/feeds"
  must "python3 -I -c 'import hashlib, json, sys, os
d = sys.argv[1]; m = json.load(open(os.path.join(d, \"feeds.json\")))[\"feeds\"]; bad = 0
for k, v in sorted(m.items()):
    got = hashlib.sha256(open(os.path.join(d, v[\"file\"]), \"rb\").read()).hexdigest(); ok = got == v[\"sha256\"]; bad += not ok
    print(k, v[\"file\"], got, \"ok\" if ok else \"MISMATCH\")
sys.exit(1 if bad else 0)' $B/feeds"
  bf=""; [ -f "$R/before.json" ] && bf="--before $B/before.json"
  # the report exits 1 when a fixable high/critical alert or drift is open, 0 otherwise; cmp decides
  must "PFT_IS_CONF=/dev/null PFT_IS_LIB=\$PWD/imagescan/imagescan_lib.py bash imagescan/pft-imagescan.sh report --bundle $B --public --withheld $B/withheld.json $bf > $W/report-$h.txt; echo \"report rc \$?\"; cmp $W/report-$h.txt $R/report-public.txt && echo 'cmp exit 0: $h public report byte-identical'"
  must "grep -E '^(RESULT|IMAGE .*WITHHELD|  fixed since|DRIFT)' $R/report-public.txt | cut -c1-160"
done
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
