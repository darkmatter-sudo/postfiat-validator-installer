#!/usr/bin/env bash
# Fresh public-clone reproduction of valwatch (task_34064fdaf85b26153cf88a4ea94515db). Clones the public repo
# anonymously into a new scratch dir, checks out SHA and runs every reproducibility clause of the card on it:
#   1. sha256 of the key files = the files installed on both hosts.  2. shellcheck, ruff check + format (both cwds).
#   3. full test suite.  4. promtool test rules.  5. offline rebuild of the committed two-host collection (cmp).
#   6. compare re-run on the committed detail files = committed compare.{txt,json}.
#   7. mutation-run code identity: files mutated in logs/07-mutants.log unchanged since its HEAD (c40a8db).
#   8. every SHA-pinned evidence URL returns HTTP 200 to an unauthenticated curl.
# Read-only on both hosts (sha256sum of installed files only).
#   bash valwatch/drill/fresh-clone.sh SHA 2>&1 | tee LOG
set -uo pipefail
SHA="${1:?usage: fresh-clone.sh SHA}"
export TZ=UTC
URL=https://github.com/darkmatter-sudo/postfiat-validator-installer
RAW=https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer
MUT_HEAD=c40a8db023bcb1fc9e60823cc7c05a16086272e2
ME="$(id -un)"; HN="$(hostname)"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@" </dev/null; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
W="$(mktemp -d -p "$HOME/.cache")" || exit 3; chmod 755 "$W"
trap 'rm -rf "$W"' EXIT
export TMPDIR="$HOME/.cache"
echo "valwatch fresh public clone - $(date -u +%FT%TZ) - SHA $SHA"

echo; echo "== 0. anonymous clone"
x "env -u GH_TOKEN -u GITHUB_TOKEN GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone -q $URL $W/repo && cd $W/repo && git checkout -q $SHA && git rev-parse HEAD && git log -1 --format='%H %ad %an'"
check "clone + checkout $SHA" "$([ "$XRC" = 0 ] && grep -qx "$SHA" <<<"$XOUT" && echo 0 || echo 1)"
cd "$W/repo" || exit 3
chmod -R a+rX "$W/repo"

echo; echo "== 1. key files vs installed (both hosts)"
x "sha256sum valwatch/pft-valwatch.sh valwatch/valwatch.py valwatch/install.sh valwatch/systemd/* alerts/valwatch.rules.yml alerts/valwatch.tests.yml valwatch/drill/*.sh valwatch/tests/mutate.py valwatch/tests/test_valwatch.py"
a="$(sha256sum < valwatch/pft-valwatch.sh | cut -c1-64)"; b="$(sha256sum < valwatch/valwatch.py | cut -c1-64)"
inst='sha256sum /usr/local/bin/pft-valwatch /usr/local/lib/pft-valwatch/valwatch.py /etc/systemd/system/pft-valwatch@.service /etc/systemd/system/pft-valwatch-textfile@.service /etc/systemd/system/pft-valwatch-textfile@.timer'
x "$inst; R '$inst'"
n=0
for f in pft-valwatch@.service pft-valwatch-textfile@.service pft-valwatch-textfile@.timer; do
  n=$((n + $(grep -c "^$(sha256sum < "valwatch/systemd/$f" | cut -c1-64)  /etc/systemd/system/$f$" <<<"$XOUT")))
done
n=$((n + $(grep -c -e "^$a  /usr/local/bin/pft-valwatch$" -e "^$b  /usr/local/lib/pft-valwatch/valwatch.py$" <<<"$XOUT")))
check "clone sha256 = installed on validator and sentry (script, helper, 3 units)" "$([ "$n" = 10 ] && echo 0 || echo 1)" "$n/10"

echo; echo "== 2. lint"
x "shellcheck valwatch/pft-valwatch.sh valwatch/install.sh valwatch/drill/*.sh"
check "shellcheck clean" "$XRC"
x "ruff check valwatch && ruff format --check valwatch"
check "ruff from repo root" "$XRC"
x "cd valwatch && ruff check . && ruff format --check ."
check "ruff from valwatch/" "$XRC"

echo; echo "== 3. full test suite"
x "cd valwatch && python3 -m pytest -q -p no:cacheprovider tests </dev/null | tail -3"
check "pytest 0 failed" "$([ "$XRC" = 0 ] && grep -qE '^[0-9]+ passed' <<<"$XOUT" && ! grep -q failed <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 4. promtool"
x "sudo -n docker run --rm --network none --entrypoint promtool -v $W/repo/alerts:/w:ro -w /w prom/prometheus:v3.5.0 test rules valwatch.tests.yml"
check "promtool SUCCESS" "$XRC"

echo; echo "== 5. offline rebuild of the committed collection"
x "sha256sum valwatch/data/window.env valwatch/data/*/*.gz valwatch/reports/*"
x "bash valwatch/drill/offline-rebuild.sh"
check "offline rebuild byte-identical (6 outputs)" "$XRC"

echo; echo "== 6. compare re-run"
python3 -I valwatch/valwatch.py compare valwatch/reports/validator.detail.json valwatch/reports/sentry.detail.json > "$W/c.txt"; c1=$?
python3 -I valwatch/valwatch.py compare valwatch/reports/validator.detail.json valwatch/reports/sentry.detail.json --json > "$W/c.json"; c2=$?
x "cmp $W/c.txt valwatch/reports/compare.txt && cmp $W/c.json valwatch/reports/compare.json && head -2 $W/c.txt && tail -1 $W/c.txt"
check "compare exit 0/0 and byte-identical to committed" "$([ "$c1$c2$XRC" = 000 ] && echo 0 || echo 1)" "exit $c1/$c2"

echo; echo "== 7. mutation-run code identity (logs/07-mutants.log, HEAD $MUT_HEAD)"
x "git cat-file -t $MUT_HEAD && git merge-base --is-ancestor $MUT_HEAD $SHA && echo ancestor"
x "git diff --stat $MUT_HEAD $SHA -- valwatch/valwatch.py valwatch/pft-valwatch.sh valwatch/tests alerts/valwatch.rules.yml alerts/valwatch.tests.yml | wc -l"
check "no mutated/tested file changed since the mutation run" "$([ "$(tail -1 <<<"$XOUT" | tr -d ' ')" = 0 ] && echo 0 || echo 1)"
x "sed -n 1,2p valwatch/logs/07-mutants.log; grep -E '^(control|RESULT|exit=)' valwatch/logs/07-mutants.log"
check "mutation run 64/64 caught" "$(grep -q '^RESULT: 64 caught, 0 survived, 0 not applied, 0 broken of 64$' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 8. evidence URLs (unauthenticated, pinned to $SHA)"
for p in valwatch/README.md valwatch/logs/09-install.log valwatch/logs/11-collect.log valwatch/logs/07-mutants.log \
  valwatch/reports/validator.txt valwatch/reports/sentry.txt valwatch/reports/compare.txt valwatch/reports/compare.json \
  alerts/valwatch.rules.yml alerts/valwatch.tests.yml valwatch/drill/collect-run.sh valwatch/drill/fresh-clone.sh; do
  code="$(curl -s -o "$W/u" -w '%{http_code}' "$RAW/$SHA/$p")"
  same="$(cmp -s "$W/u" "$p" && echo same || echo DIFFERENT)"
  echo "  $code $same $RAW/$SHA/$p"
  check "URL $p" "$([ "$code" = 200 ] && [ "$same" = same ] && echo 0 || echo 1)"
done
code="$(curl -s -o /dev/null -w '%{http_code}' "$URL/commit/$SHA")"; echo "  $code $URL/commit/$SHA"
check "commit URL" "$([ "$code" = 200 ] && echo 0 || echo 1)"

echo; echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS check(s) failed"
[ "$FAILS" = 0 ]
