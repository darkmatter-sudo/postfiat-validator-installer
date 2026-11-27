#!/usr/bin/env bash
# shellcheck disable=SC2016  # ok() evals its single-quoted test at call time
# fresh-clone: verify the upstream-rollback evidence from fresh PUBLIC clones (task_8ab4d4e6ec984527f1895c675fc84c59).
#   bash upstream-rollback/fresh-clone.sh PIN PRSHA 2>&1 | tee LOG   (validator, agent user, `ssh relay` = sentry)
# PIN = commit of darkmatter-sudo/postfiat-validator-installer to test; PRSHA = head of the PR branch in
# darkmatter-sudo/postfiatorg.github.io. Clones both anonymously, then:
#  F1 checkouts: PIN and PRSHA; PRSHA descends from upstream main 99a3412 and changes only the three guide copies
#  F2 sha256 of the three PR-branch guide copies and of the kit scripts
#  F3 three-copy diff: section 10 identical in all copies, and the PR diff hunks identical (line numbers stripped)
#  F4 extraction: PR branch -> 7 blocks; controls: upstream main (old section) and a mismatched copy must fail
#  F5 shellcheck: the extracted blocks (-e SC2164, see README) and the kit's own shell scripts
#  F6 the full live test from the clone: sentry-proof.sh on the extracted PR-branch blocks
# Exit 0 = every CHECK ok and the live test PASS.
set -uo pipefail
PIN="${1:?PIN}"; PRSHA="${2:?PRSHA}"
BASE=99a341201863ce31aaf259943ef810011605d415
KIT=https://github.com/darkmatter-sudo/postfiat-validator-installer.git
FORK=https://github.com/darkmatter-sudo/postfiatorg.github.io.git
UP=https://github.com/postfiatorg/postfiatorg.github.io.git
COPIES=(content/validator-setup.md static/agents/validator-setup.md static/agents/validator-setup.txt)
ME="$(id -un)"; HN="$(hostname)"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok() { if eval "$1"; then echo 0; else echo 1; fi; }
sec() { sed -n '/^## 10\. Upgrade Procedure After Fresh Install$/,/^## Endpoint Visibility/p' "$1"; }
T="$(mktemp -d "$HOME/.cache/rbclone.XXXXXX")"; trap 'rm -rf "$T"' EXIT
cd "$T" || exit 3
echo "upstream-rollback fresh-clone - $(date -u +%FT%TZ) - PIN $PIN PRSHA $PRSHA"
echo "tools: $(git --version), $(python3 --version), shellcheck $(shellcheck --version | sed -n 's/^version: //p')"

echo; echo "== F1 fresh public clones"
x "git clone -q $KIT kit && git -C kit checkout -q $PIN && git -C kit rev-parse HEAD"
check "F1 kit at PIN" "$(ok '[ "$(tail -1 <<<"$XOUT")" = "$PIN" ]')"
x "git -C kit log -1 --format='%H %ad %an %s' --date=iso-strict"
x "git clone -q $FORK guide && git -C guide checkout -q $PRSHA && git -C guide rev-parse HEAD"
check "F1 guide at PRSHA" "$(ok '[ "$(tail -1 <<<"$XOUT")" = "$PRSHA" ]')"
x "git -C guide fetch -q $UP main && git -C guide rev-parse FETCH_HEAD && git -C guide merge-base --is-ancestor $BASE $PRSHA && echo 'PRSHA descends from $BASE'"
check "F1 PRSHA descends from upstream main 99a3412" "$XRC"
x "git -C guide log --format='%h %ad %s' --date=iso-strict $BASE..$PRSHA"
x "git -C guide diff --stat $BASE $PRSHA"
x "git -C guide diff --name-only $BASE $PRSHA"
check "F1 the PR changes exactly the three guide copies" "$(ok '[ "$XOUT" = "$(printf "%s\n" "${COPIES[@]}" | sort)" ]')"

echo; echo "== F2 hashes"
x "cd guide && sha256sum ${COPIES[*]} > ../guide.sha256; cd .. && cat guide.sha256"
x "cd kit/upstream-rollback && sha256sum extract_rollback.py sentry-proof.sh fresh-clone.sh README.md > ../../kit.sha256; cd ../.. && cat kit.sha256"

echo; echo "== F3 three-copy diff"
for c in "${COPIES[@]:1}"; do
  x "diff <(sec guide/${COPIES[0]}) <(sec guide/$c) && echo 'section 10 identical: ${COPIES[0]} = $c'"
  check "F3 section 10 of $c = ${COPIES[0]}" "$XRC"
done
x "sec guide/${COPIES[0]} | sha256sum; sec guide/${COPIES[1]} | sha256sum; sec guide/${COPIES[2]} | sha256sum"
check "F3 one section hash for all three copies" "$(ok '[ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ]')"
hunks() { git -C guide diff -U3 "$BASE" "$PRSHA" -- "$1" | sed -n '/^@@/,$p' | sed -E 's/^@@ -[0-9,]+ \+[0-9,]+ @@/@@/'; }
for c in "${COPIES[@]:1}"; do
  x "diff <(hunks ${COPIES[0]}) <(hunks $c) && echo 'PR hunks identical: ${COPIES[0]} = $c'"
  check "F3 PR diff hunks of $c = ${COPIES[0]}" "$XRC"
done
x "git -C guide diff $BASE $PRSHA -- ${COPIES[0]}"

echo; echo "== F4 extraction from the PR branch, with controls"
x "python3 -I kit/upstream-rollback/extract_rollback.py out ${COPIES[*]/#/guide/}"
check "F4 seven blocks extracted, three identical copies" "$(ok '[ "$XRC" = 0 ] && grep -qx "copies with identical section 10: 3" <<<"$XOUT" && [ "$(grep -c "^0[1-7]-.*\.sh " <<<"$XOUT")" = 7 ]')"
x "git -C guide show $BASE:${COPIES[0]} > main.md && python3 -I kit/upstream-rollback/extract_rollback.py ctl-main main.md"
check "F4 control: upstream main's section 10 is rejected (no rollback blocks)" "$(ok '[ "$XRC" = 1 ] && grep -q "expected 7 bash blocks" <<<"$XOUT"')"
x "python3 -I kit/upstream-rollback/extract_rollback.py ctl-mix guide/${COPIES[0]} main.md"
check "F4 control: a copy with a different section 10 is rejected" "$(ok '[ "$XRC" = 1 ] && grep -q "section 10 differs" <<<"$XOUT"')"

echo; echo "== F5 shellcheck"
x "cd out && shellcheck -s bash -e SC2164 0*.sh && echo 'blocks clean'; cd .."
check "F5 shellcheck -e SC2164 clean on the seven blocks" "$(ok 'grep -qx "blocks clean" <<<"$XOUT"')"
x "cd out && shellcheck -s bash -f gcc 0*.sh; cd .."
check "F5 without the exclusion only SC2164 on the three cd lines" "$(ok '[ "$(grep -c . <<<"$XOUT")" = 3 ] && [ "$(grep -c "^0[167]-[a-z]*\.sh:1:1: warning: .*\[SC2164\]$" <<<"$XOUT")" = 3 ]')"
x "shellcheck kit/upstream-rollback/sentry-proof.sh kit/upstream-rollback/fresh-clone.sh && echo 'kit scripts clean'"
check "F5 shellcheck clean on the kit scripts" "$XRC"

echo; echo "== F6 live test from the clone (sentry throwaway project)"
echo "\$ bash kit/upstream-rollback/sentry-proof.sh out"
bash kit/upstream-rollback/sentry-proof.sh out 2>&1 | sed 's/^/  | /'
rc="${PIPESTATUS[0]}"; echo "  (exit $rc)"
check "F6 sentry-proof PASS from the fresh clone" "$rc"
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
