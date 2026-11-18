#!/usr/bin/env bash
# Usage: tests/memcmp.sh [OLD_REV]  old (default ed2e353) vs working-tree valwatch.py: byte-identical report/textfile
# outputs and rc + peak RSS, on both fixtures and a synthetic 24 h directory (tests/gen_synthetic.py). Exit 0 = all identical.
set -uo pipefail
R=$(cd "$(dirname "$0")/../.." && pwd)
OLD=${1:-ed2e353}
W=$(mktemp -d -p ~/.cache)
trap 'rm -rf "$W"' EXIT
cd "$R/valwatch" || exit 3
git -C "$R" show "$OLD:valwatch/valwatch.py" > "$W/old.py"
cp valwatch.py "$W/new.py"
echo "# $(date -u +%FT%TZ) old=$OLD:valwatch/valwatch.py sha256 $(sha256sum < "$W/old.py" | cut -c1-64)"
echo "# new=working tree valwatch.py sha256 $(sha256sum < "$W/new.py" | cut -c1-64) (HEAD $(git rev-parse HEAD))"
echo "# gen_synthetic.py sha256 $(sha256sum < tests/gen_synthetic.py | cut -c1-64)"
python3 -I tests/gen_synthetic.py tests/fixtures/validator/valwatch-20261118T18.jsonl.gz "$W/D" 24
echo "synthetic: $(find "$W/D" -name "valwatch-*" | wc -l) files $(du -sb "$W/D" | cut -f1) bytes"
for fx in validator sentry; do mkdir -p "$W/$fx"; zcat "tests/fixtures/$fx/valwatch-20261118T18.jsonl.gz" > "$W/$fx/valwatch-20261118T18.jsonl"; done
LAST=$(tail -1 "$W/D/$(find "$W/D" -name "valwatch-*" -printf "%f\n" | sort | tail -1)" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["r"]//1000)')
MID=$((LAST - 43200))
fails=0
run() {  # run LABEL ARGS... : old and new, compare stdout bytes and rc, print RSS of each
  local label=$1; shift
  local ro rn
  /usr/bin/time -f '%M %e' -o "$W/t.old" python3 -I "$W/old.py" "$@" > "$W/o.old"; ro=$?
  /usr/bin/time -f '%M %e' -o "$W/t.new" python3 -I "$W/new.py" "$@" > "$W/o.new"; rn=$?
  if [ "$ro" = "$rn" ] && cmp -s "$W/o.old" "$W/o.new"; then v=IDENTICAL; else v=DIFFERENT; fails=$((fails+1)); fi
  echo "$label: $v rc old=$ro new=$rn bytes=$(wc -c < "$W/o.new") sha256=$(sha256sum < "$W/o.new" | cut -c1-16)"
  echo "    old maxrss_kib/elapsed_s $(tail -1 "$W/t.old")   new $(tail -1 "$W/t.new")"
}
for fx in validator sentry; do
  run "fixture $fx report" report --dir "$W/$fx"
  run "fixture $fx --json" report --dir "$W/$fx" --json
  run "fixture $fx --detail" report --dir "$W/$fx" --detail
done
run "24h report" report --dir "$W/D"
run "24h --json" report --dir "$W/D" --json
run "24h --detail" report --dir "$W/D" --detail
run "24h --from MID (carry-in)" report --dir "$W/D" --from "$MID" --json
run "24h --from MID --to MID+7200" report --dir "$W/D" --from "$MID" --to $((MID + 7200)) --detail
grep -c '"t":"U"' "$W"/D/valwatch-* | sed 's|.*/||' | tr '\n' ' '; echo "(U records per hour file)"
run "24h textfile" textfile --dir "$W/D" --name postfiatd --now "$LAST"
echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo FAIL) - $fails difference(s)"
[ "$fails" = 0 ]
