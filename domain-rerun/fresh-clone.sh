#!/usr/bin/env bash
# shellcheck disable=SC2016  # ok() evals its single-quoted test at call time
# fresh-clone: verify the domain-rerun evidence from fresh PUBLIC clones (task_58670ccd9d10dc7c2f07a8d3daec6a8a).
#   bash domain-rerun/fresh-clone.sh PIN PRSHA 2>&1 | tee LOG   (validator, agent user, `ssh relay` = sentry)
# PIN = commit of darkmatter-sudo/postfiat-validator-installer to test; PRSHA = head of the PR branch in
# darkmatter-sudo/postfiatorg.github.io. Clones both anonymously, then:
#  F1 checkouts: PIN and PRSHA; PRSHA descends from upstream main ac8b944 and changes only the three guide copies
#  F2 sha256 of the three PR-branch guide copies, of upstream main's copy and of the kit files
#  F3 three-copy diff: the Troubleshooting section identical in all three copies (PR head and main), the PR diff
#     hunks identical (line numbers stripped) and inside Troubleshooting only
#  F4 extraction: PR head -> 7 section blocks + T1/T2 from 3 identical copies; main -> 7 blocks, no re-run block;
#     control: a copy with a different Troubleshooting section is rejected
#  F5 shellcheck: the two new PR blocks (-e SC2164: the guide's bare cd "$POSTFIATD_DIR" lines) and the kit scripts
#  F6 live test from the clone on upstream main: domain-test.sh with EXPECT=fail
#  F7 live test from the clone on the PR head: domain-test.sh with EXPECT=pass
# Exit 0 = every CHECK ok and both live tests exit 0.
set -uo pipefail
PIN="${1:?PIN}"; PRSHA="${2:?PRSHA}"
BASE=ac8b9443c3e785158934162d80bf68ebde294b88
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
ts_sec() { sed -n '/^## Troubleshooting$/,/^## Agent Safety Checklist$/p' "$1"; }
T="$(mktemp -d "$HOME/.cache/domclone.XXXXXX")"; chmod 755 "$T"; trap 'rm -rf "$T"' EXIT
cd "$T" || exit 3
echo "domain-rerun fresh-clone - $(date -u +%FT%TZ) - PIN $PIN PRSHA $PRSHA"
echo "tools: $(git --version), $(python3 --version), shellcheck $(shellcheck --version | sed -n 's/^version: //p')"

echo; echo "== F1 fresh public clones"
x "git clone -q $KIT kit && git -C kit checkout -q $PIN && git -C kit rev-parse HEAD"
check "F1 kit at PIN" "$(ok '[ "$(tail -1 <<<"$XOUT")" = "$PIN" ]')"
x "git -C kit log -1 --format='%H %ad %an %s' --date=iso-strict"
x "git clone -q $FORK guide && git -C guide checkout -q $PRSHA && git -C guide rev-parse HEAD"
check "F1 guide at PRSHA" "$(ok '[ "$(tail -1 <<<"$XOUT")" = "$PRSHA" ]')"
x "git -C guide fetch -q $UP main && git -C guide rev-parse FETCH_HEAD && git -C guide merge-base --is-ancestor $BASE $PRSHA && echo 'PRSHA descends from $BASE'"
check "F1 PRSHA descends from upstream main ac8b944" "$XRC"
x "git -C guide log --format='%h %ad %s' --date=iso-strict $BASE..$PRSHA"
x "git -C guide diff --stat $BASE $PRSHA"
x "git -C guide diff --name-only $BASE $PRSHA"
check "F1 the PR changes exactly the three guide copies" "$(ok '[ "$XOUT" = "$(printf "%s\n" "${COPIES[@]}" | sort)" ]')"

echo; echo "== F2 hashes"
x "for c in ${COPIES[*]}; do mkdir -p main/\$(dirname \$c); git -C guide show $BASE:\$c > main/\$c; done; cp main/${COPIES[0]} main.md && sha256sum main.md"
x "cd guide && sha256sum ${COPIES[*]} > ../guide.sha256; cd .. && cat guide.sha256"
x "cd kit/domain-rerun && sha256sum extract_domain.py domain-test.sh fresh-clone.sh README.md > ../../kit.sha256; cd ../.. && cat kit.sha256"

echo; echo "== F3 three-copy diff"
for side in guide main; do
  for c in "${COPIES[@]:1}"; do
    x "diff <(ts_sec $side/${COPIES[0]}) <(ts_sec $side/$c) && echo 'Troubleshooting identical ($side): ${COPIES[0]} = $c'"
    check "F3 $side: Troubleshooting of $c = ${COPIES[0]}" "$XRC"
  done
  x "for c in ${COPIES[*]}; do ts_sec $side/\$c | sha256sum; done"
  check "F3 $side: one Troubleshooting hash for all three copies" "$(ok '[ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ]')"
done
hunks() { git -C guide diff -U3 "$BASE" "$PRSHA" -- "$1" | sed -n '/^@@/,$p' | sed -E 's/^@@ -[0-9,]+ \+[0-9,]+ @@/@@/'; }
for c in "${COPIES[@]:1}"; do
  x "diff <(hunks ${COPIES[0]}) <(hunks $c) && echo 'PR hunks identical: ${COPIES[0]} = $c'"
  check "F3 PR diff hunks of $c = ${COPIES[0]}" "$XRC"
done
# every changed line of the PR head lies between "## Troubleshooting" and "## Agent Safety Checklist"
inside() {
  local f="$1" a b
  a="$(grep -n '^## Troubleshooting$' "guide/$f" | cut -d: -f1)"; b="$(grep -n '^## Agent Safety Checklist$' "guide/$f" | cut -d: -f1)"
  git -C guide diff -U0 "$BASE" "$PRSHA" -- "$f" | sed -n 's/^@@ -[0-9,]* +\([0-9]*\),*\([0-9]*\) @@.*/\1 \2/p' |
    awk -v a="$a" -v b="$b" '{n = ($2 == "") ? 1 : $2; if (n > 0 && ($1 <= a || $1 + n - 1 >= b)) bad++} END {print "hunks outside Troubleshooting (" a "-" b "): " bad + 0}'
}
for c in "${COPIES[@]}"; do
  x "inside $c"
  check "F3 $c: PR changes only inside Troubleshooting" "$(ok 'grep -q "): 0$" <<<"$XOUT"')"
done
x "git -C guide diff $BASE $PRSHA -- ${COPIES[0]}"

echo; echo "== F4 extraction, with a control"
x "python3 -I kit/domain-rerun/extract_domain.py out ${COPIES[*]/#/guide/}"
check "F4 PR head: 7 section blocks + T1 and T2, three identical copies" "$(ok '[ "$XRC" = 0 ] && grep -qx "copies with identical sections 5-7 and Troubleshooting: 3" <<<"$XOUT" && [ "$(grep -c "^0[5-7][a-d]*-.*\.sh " <<<"$XOUT")" = 7 ] && grep -q "^T1-rerun.sh " <<<"$XOUT" && grep -q "^T2-seqcheck.sh " <<<"$XOUT"')"
x "python3 -I kit/domain-rerun/extract_domain.py out-main ${COPIES[*]/#/main/}"
check "F4 upstream main: 7 blocks, no re-run block, three identical copies" "$(ok '[ "$XRC" = 0 ] && grep -qx "copies with identical sections 5-7 and Troubleshooting: 3" <<<"$XOUT" && [ "$(grep -c "^0[5-7][a-d]*-.*\.sh " <<<"$XOUT")" = 7 ] && ! grep -q "^T[12]-" <<<"$XOUT"')"
x "python3 -I kit/domain-rerun/extract_domain.py ctl-mix guide/${COPIES[0]} main.md"
check "F4 control: a copy with a different Troubleshooting section is rejected" "$(ok '[ "$XRC" = 1 ] && grep -q "Troubleshooting differs" <<<"$XOUT"')"

echo; echo "== F5 shellcheck"
x "cd out && shellcheck -s bash -e SC2164 T1-rerun.sh T2-seqcheck.sh && echo 'PR blocks clean'; cd .."
check "F5 shellcheck -e SC2164 clean on the two new PR blocks" "$(ok 'grep -qx "PR blocks clean" <<<"$XOUT"')"
x "cd out && shellcheck -s bash -f gcc T1-rerun.sh T2-seqcheck.sh; cd .."
check "F5 without the exclusion only SC2164 on the two cd lines" "$(ok '[ "$(grep -c . <<<"$XOUT")" = 2 ] && [ "$(grep -c "^T[12]-[a-z]*\.sh:1:1: warning: .*\[SC2164\]$" <<<"$XOUT")" = 2 ]')"
x "shellcheck kit/domain-rerun/domain-test.sh kit/domain-rerun/fresh-clone.sh && echo 'kit scripts clean'"
check "F5 shellcheck clean on the kit scripts" "$XRC"

echo; echo "== F6 live test from the clone: upstream main (sentry throwaway project)"
echo "\$ EXPECT=fail bash kit/domain-rerun/domain-test.sh main.md"
EXPECT=fail bash kit/domain-rerun/domain-test.sh main.md 2>&1 | sed 's/^/  | /'
rc="${PIPESTATUS[0]}"; echo "  (exit $rc)"
check "F6 domain-test on upstream main: RERUN FAIL as expected, harness clean (exit 0)" "$rc"

echo; echo "== F7 live test from the clone: PR head (sentry throwaway project)"
echo "\$ EXPECT=pass bash kit/domain-rerun/domain-test.sh guide/${COPIES[0]}"
EXPECT=pass bash kit/domain-rerun/domain-test.sh "guide/${COPIES[0]}" 2>&1 | sed 's/^/  | /'
rc="${PIPESTATUS[0]}"; echo "  (exit $rc)"
check "F7 domain-test on the PR head: RERUN PASS, harness clean (exit 0)" "$rc"
echo; echo "fresh-clone done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
