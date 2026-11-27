#!/usr/bin/env bash
# record: fresh public clone at the submission pin, lock-held heal branch probe (task_dfa49 verification)
set -u
PIN=3340eb6496af404b03f2fd717a329e1391628eb9; IMPL=94d06587ff024bc240f19254400ce099949646a5
PROBE_SRC="$1"
red() { sed -e "s#$HOME#~#g" -e "s#/home/[^/ ]*#~#g"; }
x() { echo "\$ $*" | red; eval "$*" 2>&1 | red; rc=${PIPESTATUS[0]}; echo "exit=$rc"; return "$rc"; }
D=$(mktemp -d -p "$HOME/.cache"); chmod 755 "$D"; cd "$D" || exit 1
echo "# $(date -u +%FT%TZ) verification probe: heal lock-held branch (task_dfa49)"
x git clone -q https://github.com/darkmatter-sudo/postfiat-validator-installer.git r
cd r || exit 1
x git checkout -q $PIN
x git rev-parse HEAD
x git diff --stat $IMPL $PIN -- upstreamwatch/upstreamwatch_lib.py upstreamwatch/pft-upstreamwatch.sh upstreamwatch/tests/test_upstreamwatch.py
echo "(empty diff = both files identical at $IMPL and $PIN)"
x sha256sum upstreamwatch/upstreamwatch_lib.py upstreamwatch/pft-upstreamwatch.sh upstreamwatch/tests/test_upstreamwatch.py
x "awk 'NR>=594 && NR<=622 {printf \"%6d\\t%s\\n\", NR, \$0}' upstreamwatch/upstreamwatch_lib.py"
x "grep -n -E 'heal-plan|flock -n 8|heal_log \"\\\$feed\" skip|--result started' upstreamwatch/pft-upstreamwatch.sh"
x "grep -n -E 'HEAL_LOCK=|DATA_DIR=/' upstreamwatch/pft-upstreamwatch.sh"
x "grep -n -A4 'if result == \"started\"' upstreamwatch/upstreamwatch_lib.py"
x cp "$PROBE_SRC" upstreamwatch/tests/test_zz_lockprobe.py
x sha256sum upstreamwatch/tests/test_zz_lockprobe.py
cd upstreamwatch || exit 1
mkdir -p "$HOME/.cache/pyt"
echo "(test_zz_lockprobe.py star-imports test_upstreamwatch.py for its fixtures, so pytest collects the 84 suite tests there too: expect 84 + 2 probes = 86)"
x python3 -u -m pytest -q -s -p no:cacheprovider --basetemp "$HOME/.cache/pyt/vdfa49rec" tests/test_zz_lockprobe.py
echo "# end $(date -u +%FT%TZ)"
