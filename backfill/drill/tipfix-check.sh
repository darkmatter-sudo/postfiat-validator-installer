#!/usr/bin/env bash
# Offline proof for the tip-race fix (backfill_parse.py TIP_GRACE): no root, docker or network.
#   1. fail-before: the CURRENT tests against the parser of FROM (default: the commit before the fix) must FAIL on
#      the tip tests (and only there), by assertion.
#   2. after: every suite passes on the working tree.
#   3. parser mutants (one exact replacement each, must apply exactly once): each must be killed by a named test.
#   4. lint: shellcheck, ruff check + format --check on the changed files.
#   bash backfill/drill/tipfix-check.sh 2>&1 | tee LOG      (repo root)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
FROM="${FROM:-732606b}"
BASE="${TEST_TMPDIR:-$HOME/.cache}"; mkdir -p "$BASE"
T="$(mktemp -d "$BASE/bf-tipfix.XXXXXX")"; trap 'rm -rf "$T"' EXIT
export TEST_TMPDIR="$T" TMPDIR="$T"
red() { sed -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g; s#$(hostname)#<host>#g"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
copy() { # DIR [PARSER_SOURCE_FILE] -> a scratch copy of backfill/ with that parser
  rm -rf "$1"; cp -r backfill "$1"; rm -rf "$1/logs" "$1/__pycache__" "$1/tests/__pycache__"
  [ -n "${2:-}" ] && cp "$2" "$1/backfill_parse.py"
  return 0
}
unit() { python3 -u "$1/tests/test_backfill_parse.py" 2>&1; }
shellsuite() { bash "$1/tests/run-tests.sh" 2>&1; }

echo "== tipfix-check $(date -u +%FT%TZ) | HEAD $(git rev-parse HEAD) | tree $(git status --short backfill | grep -c .) changed file(s) | FROM $(git rev-parse "$FROM")"
sha256sum backfill/backfill_parse.py backfill/pft-backfill.sh backfill/tests/test_backfill_parse.py backfill/tests/run-tests.sh

echo; echo "== 1. fail-before: current tests vs the parser of $FROM"
git show "$FROM:backfill/backfill_parse.py" > "$T/old_parse.py"
copy "$T/old" "$T/old_parse.py"
OUT="$(unit "$T/old")"; RC=$?
printf '%s\n' "$OUT" | grep -E '^(FAIL|ERROR):|^(OK|FAILED)|^Ran ' | red | sed 's/^/  /'
NAMES="$(grep -oE '^(FAIL|ERROR): test_[a-z_]+' <<<"$OUT" | sed -E 's/^(FAIL|ERROR): //' | sort -u | tr '\n' ' ')"
echo "  failing tests: $NAMES"
check "old parser: unit suite exits 1" "$([ "$RC" = 1 ] && echo 0 || echo 1)"
check "old parser: exactly the 4 tip tests fail (tip_grace_boundary, tip_race_live_captures, tip_with_interior_hole, status_with_gaps)" \
  "$([ "$NAMES" = "test_status_with_gaps test_tip_grace_boundary test_tip_race_live_captures test_tip_with_interior_hole " ] && echo 0 || echo 1)"
check "old parser: failures are assertions/KeyError on the new field, not import errors" "$(grep -q 'ImportError\|SyntaxError' <<<"$OUT" && echo 1 || echo 0)"
OUT="$(shellsuite "$T/old")"; RC=$?
printf '%s\n' "$OUT" | grep -E '^FAIL|^RESULT' | cut -c1-160 | red | sed 's/^/  /'
check "old parser: shell suite fails only on the tip-race checks" \
  "$([ "$RC" != 0 ] && ! grep '^FAIL' <<<"$OUT" | grep -vq 'tip' && grep -q '^FAIL tip race: exit 0 PASS' <<<"$OUT" && echo 0 || echo 1)"

echo; echo "== 2. after: every suite on the working tree"
copy "$T/new"
OUT="$(unit "$T/new")"; RC=$?; printf '%s\n' "$OUT" | tail -3 | red | sed 's/^/  /'
check "unit suite passes" "$RC"
OUT="$(shellsuite "$T/new")"; RC=$?; printf '%s\n' "$OUT" | grep -E '^FAIL|^RESULT|tip|tail 3' | red | sed 's/^/  /'
check "status/plan shell suite passes" "$RC"
OUT="$(bash "$T/new/tests/run-repair-tests.sh" 2>&1)"; RC=$?; printf '%s\n' "$OUT" | grep -E '^FAIL|^RESULT' | red | sed 's/^/  /'
check "repair shell suite passes" "$RC"

echo; echo "== 3. parser mutants"
mutant() { # ID WHAT OLD NEW
  local d="$T/m-$1" n
  copy "$d"
  n="$(OLD="$3" python3 -c 'import os,sys; print(open(sys.argv[1]).read().count(os.environ["OLD"]))' "$d/backfill_parse.py")"
  if [ "$n" != 1 ]; then check "$1 $2: applies exactly once" 1 "matches $n"; return; fi
  OLD="$3" NEW="$4" python3 -c 'import os,sys; p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace(os.environ["OLD"], os.environ["NEW"]))' "$d/backfill_parse.py"
  local u s; u="$(unit "$d")"; s="$(shellsuite "$d")"
  local k; k="$( { grep -oE '^(FAIL|ERROR): test_[a-z_]+' <<<"$u" | sed -E 's/^(FAIL|ERROR): //'; grep -E '^FAIL ' <<<"$s" | cut -c6-60; } | sort -u | tr '\n' ';')"
  echo "  $1 ($2): killed by: ${k:-nothing}"
  check "$1 $2: KILLED" "$([ -n "$k" ] && echo 0 || echo 1)"
}
mutant M1 "grace boundary < instead of <=" 'if tail <= TIP_GRACE else' 'if tail < TIP_GRACE else'
mutant M2 "grace 3" 'TIP_GRACE = 2 ' 'TIP_GRACE = 3 '
mutant M3 "tip counted as interior" '"kind": "tip" if' '"kind": "interior" if'
mutant M4 "tip planned" 'for kind in ("interior", "edge"):
        for g in sorted(' 'for kind in ("interior", "edge", "tip"):
        for g in sorted('
mutant M5 "tip metric not exported" "f'pft_backfill_missing_ledgers{{{lab},kind=\"tip\"}} {acc[\"missing_tip\"]}'," ''
mutant M6 "missing_tip not counted" 'res["missing_tip"] = sum(g["size"] for g in gaps if g["kind"] == "tip")' 'res["missing_tip"] = 0'

echo; echo "== 4. lint"
OUT="$(shellcheck backfill/pft-backfill.sh backfill/tests/run-tests.sh backfill/drill/tipfix-check.sh 2>&1)"; RC=$?; printf '%s\n' "${OUT:-shellcheck clean}" | sed 's/^/  /'
check "shellcheck clean" "$RC"
OUT="$(cd backfill && ruff check backfill_parse.py tests/test_backfill_parse.py && ruff format --check backfill_parse.py tests/test_backfill_parse.py 2>&1)"; RC=$?; printf '%s\n' "$OUT" | sed 's/^/  /'
check "ruff check + format clean" "$RC"

echo; echo "tipfix-check done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
