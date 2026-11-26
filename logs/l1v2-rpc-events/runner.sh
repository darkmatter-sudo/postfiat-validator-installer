#!/usr/bin/env bash
# recorded runs for task_6a35: $1 = branch|clone|mutants
set -uo pipefail
MODE=$1
REPO=$HOME/work/postfiatl1v2
REL=$HOME/.cache/rpcev-rel
SHA=e036033d437d85c4f60fc8e6689a771fdda01dd2ce88456571e6c9092faf4caf
red() { sed -u -e "s#$HOME#~#g" -e "s#$(id -un)#<user>#g"; }
x() { echo "\$ $*" | red; eval "$*" 2>&1 | red; local rc=${PIPESTATUS[0]}; echo "[exit $rc]"; return $rc; }
FAILS=0
step() { x "$@" || FAILS=$((FAILS + 1)); }
echo "== task_6a35 recorded run: $MODE  $(date -u +%FT%TZ)"
echo "host: Ubuntu $(. /etc/os-release; echo "$VERSION_ID"), $(ldd --version | head -1 | awk '{print "glibc " $NF}'), $(python3 --version), $(shellcheck --version | sed -n 2p | tr -d ' '), ruff $(ruff --version | cut -d' ' -f2), $(jq --version), logrotate $(logrotate --version 2>&1 | head -1 | awk '{print $2}')"
export TMPDIR=$HOME/.cache/rpcev-tmp; mkdir -p "$TMPDIR"
case $MODE in
branch|clone)
  if [ "$MODE" = clone ]; then
    PIN=$(git -C "$REPO" rev-parse rpc-events-report)
    W=$(mktemp -d -p "$HOME/.cache"); chmod 755 "$W"
    step "git clone -q https://github.com/darkmatter-sudo/postfiatl1v2.git $W/postfiatl1v2"
    cd "$W/postfiatl1v2" || exit 1
    step "git checkout -q $PIN"
  else
    cd "$REPO" || exit 1
  fi
  step "git log -1 --format='repo HEAD %H %s'"
  step "git rev-parse HEAD~1 && git diff --stat HEAD~1 HEAD"
  step "sha256sum scripts/rpc-events-report scripts/test-rpc-events-report docs/runbooks/public-rpc-operator-policy.md"
  echo "-- release binary: postfiatorg/postfiatl1v2 release cobalt-operator-v2-20260824"
  step "gh release view cobalt-operator-v2-20260824 -R postfiatorg/postfiatl1v2 --json tagName,publishedAt,assets -q '.tagName, .publishedAt, (.assets[] | select(.name==\"postfiat-node\") | .name + \" \" + (.size|tostring) + \" \" + .digest)'"
  step "curl -fsSL https://github.com/postfiatorg/postfiatl1v2/releases/download/cobalt-operator-v2-20260824/cobalt-operator-assets-SHA256SUMS.txt | grep ' postfiat-node\$'"
  step "sha256sum $REL/postfiat-node"
  echo "-- glibc 2.39 loader+libc+libm copied from the local Ubuntu 24.04 image (the release binary needs GLIBC_2.39; host has 2.35)"
  step "sha256sum $REL/glibc239/*"
  step "$REL/glibc239/ld-linux-x86-64.so.2 --library-path $REL/glibc239 $REL/glibc239/libc.so.6 | head -1"
  step "shellcheck scripts/test-rpc-events-report"
  step "ruff check scripts/rpc-events-report"
  step "ruff format --check scripts/rpc-events-report"
  step "bash -n scripts/test-rpc-events-report && python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' scripts/rpc-events-report && echo syntax ok"
  echo "-- test without the release binary (as CI would run it)"
  step "scripts/test-rpc-events-report"
  echo "-- test with the sha256-checked release binary (real loopback capture)"
  step "RPC_EVENTS_NODE_BIN=$REL/postfiat-node RPC_EVENTS_NODE_SHA256=$SHA RPC_EVENTS_NODE_LAUNCHER='$REL/glibc239/ld-linux-x86-64.so.2 --library-path $REL/glibc239' scripts/test-rpc-events-report"
  echo "-- control: a wrong expected hash must refuse to run the binary (expect exit 1)"
  x "RPC_EVENTS_NODE_BIN=$REL/postfiat-node RPC_EVENTS_NODE_SHA256=0000000000000000000000000000000000000000000000000000000000000000 scripts/test-rpc-events-report"
  [ $? -eq 1 ] && echo "control OK: refused" || { echo "control FAIL"; FAILS=$((FAILS + 1)); }
  if [ "$MODE" = branch ]; then
    echo "-- existing repository checks"
    step "scripts/docs-site-redaction-check"
    step "sudo docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v $REPO:/repo:ro -w /repo python:3.12-slim sh -c 'pip install -q --disable-pip-version-check --require-hashes --target /tmp/lib -r requirements-docs.txt >/tmp/pip.log 2>&1 || exit 9; export PYTHONPATH=/tmp/lib PATH=/tmp/lib/bin:\$PATH; scripts/public-doc-links && scripts/test-public-doc-links && mkdocs build --strict -q -d /tmp/site && echo mkdocs strict ok'"
    step "for s in \$(sed -n 's#^  \\(scripts/[^ ;\\\\]*\\).*#\\1#p' scripts/check); do bash -n \$s || exit 1; done; echo 'scripts/check shell list: bash -n ok'"
    echo "-- scripts/test-postfiat-logrotate on this branch and on main (needs the postfiat user; same result on both)"
    echo "(informational, not counted: exits 1 here and on main alike)"
    x "scripts/test-postfiat-logrotate 2>&1 | tail -2"
    x "git diff --quiet origin/main -- scripts/test-postfiat-logrotate ops/validator-host/logrotate systemd/postfiat-logrotate.example && echo 'test-postfiat-logrotate and its inputs are unchanged from main'"
  else
    cd / && rm -rf "$W"
  fi
  ;;
mutants)
  cd "$REPO" || exit 1
  step "git log -1 --format='repo HEAD %H %s'"
  step "sha256sum scripts/rpc-events-report scripts/test-rpc-events-report $HOME/.cache/rpcev-mut/mut.py"
  step "cat $HOME/.cache/rpcev-mut/mut.py"
  step "python3 -I $HOME/.cache/rpcev-mut/mut.py $REPO"
  ;;
esac
echo "RUN RESULT: $([ $FAILS -eq 0 ] && echo PASS || echo "FAIL ($FAILS steps)")"
