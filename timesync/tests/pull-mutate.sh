#!/usr/bin/env bash
# Mutation controls for pft-timesync-pull.sh (same method as mutate.sh): each mutant is one exact text replacement
# that must match exactly once (else NOT APPLIED, a harness failure). The unmutated copy runs first as a control.
# Usage: tests/pull-mutate.sh
# Mutant texts are literal code, single-quoted on purpose. Each NEW text must still be valid code (an awk syntax
# error would fail every test and "catch" the mutant for the wrong reason), so disabled checks become if (0).
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_TOOL="$HERE/../pft-timesync-pull.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
CAUGHT=0; SURVIVED=0; NOTAPPLIED=0; TOTAL=0

echo "sha256 $(sha256sum "$SRC_TOOL" | cut -c1-64) pft-timesync-pull.sh"
cp "$SRC_TOOL" "$W/pull.sh"
if bash "$HERE/pull-tests.sh" "$W/pull.sh" > "$W/control.out" 2>&1; then
  echo "control: unmutated copy $(tail -1 "$W/control.out")"
else
  echo "control: FAILED - harness invalid"; tail -5 "$W/control.out"; exit 2
fi

mutant() { # ID DESCRIPTION OLD NEW
  local id="$1" desc="$2" n
  TOTAL=$((TOTAL + 1))
  cp "$SRC_TOOL" "$W/pull.sh"
  n="$(OLD="$3" NEW="$4" F="$W/pull.sh" python3 -c '
import os; p=os.environ["F"]; s=open(p).read(); o=os.environ["OLD"]; c=s.count(o)
if c==1: open(p,"w").write(s.replace(o, os.environ["NEW"]))
print(c)')"
  if [ "$n" != 1 ]; then NOTAPPLIED=$((NOTAPPLIED + 1)); echo "$id NOT APPLIED (matches=$n) - $desc"; return; fi
  if bash "$HERE/pull-tests.sh" "$W/pull.sh" > "$W/$id.out" 2>&1; then
    SURVIVED=$((SURVIVED + 1)); echo "$id SURVIVED - $desc"
  else
    CAUGHT=$((CAUGHT + 1))
    echo "$id CAUGHT - $desc :: $(grep -c '^FAIL' "$W/$id.out") failing: $(grep '^FAIL' "$W/$id.out" | head -3 | cut -c6-70 | paste -sd ';')"
  fi
}

mutant P01 "peer may set its own host label" \
  'if (("," labels) ~ /,host=/) bad("sample already has a host label")' 'if (0) bad("sample already has a host label")'
mutant P02 "host label appended last instead of first" \
  'out[++n] = name "{" h (labels == "" ? "" : "," labels) "}" rest' 'out[++n] = name "{" (labels == "" ? "" : labels ",") h "}" rest'
mutant P03 "any metric name accepted" \
  'if (match($0, /^pft_timesync_[a-z0-9_]+/) == 0) bad("not a pft_timesync_ sample")' 'if (match($0, /^[a-z_][a-z0-9_]*/) == 0) bad("not a pft_timesync_ sample")'
mutant P04 "foreign HELP/TYPE lines treated as plain comments" \
  '/^# (HELP|TYPE) / { bad("HELP/TYPE for a foreign metric") }' '/^# (HELP|TYPE) / { next }'
mutant P05 "value not anchored at the end (trailing garbage)" \
  'if (rest !~ /^ -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) bad("malformed value")' 'if (rest !~ /^ -?[0-9]+/) bad("malformed value")'
mutant P06 "label values may contain quotes/backslashes" \
  'lbl = "[a-z_][a-z0-9_]*=\"[^\"\\\\\n]*\""' 'lbl = "[a-z_][a-z0-9_]*=\".*\""'
mutant P07 "pft_timesync_state not required" \
  'if (!st) { print "no pft_timesync_state sample" > "/dev/stderr"; exit 1 }' 'if (0) { print "no pft_timesync_state sample" > "/dev/stderr"; exit 1 }'
mutant P08 "collect timestamp not required (stale alert could never fire)" \
  'if (!ts) { print "no pft_timesync_collect_timestamp_seconds sample" > "/dev/stderr"; exit 1 }' 'if (0) { print "no pft_timesync_collect_timestamp_seconds sample" > "/dev/stderr"; exit 1 }'
mutant P09 "size limit not enforced" \
  '[ "$size" -le "$MAX_BYTES" ] ||' 'true ||'
mutant P10 "fetch failure not detected (empty copy replaces the previous one)" \
  'if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_FILE" > "$raw" 2>/dev/null </dev/null; then' 'if ! { timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_FILE" > "$raw" 2>/dev/null </dev/null; true; }; then'
mutant P11 "relabel failure ignored (invalid file renamed into place)" \
  'if ! why="$(relabel "$raw" "$label" 2>&1 >"$tmp")"; then' 'if ! why="$(relabel "$raw" "$label" 2>&1 >"$tmp"; true)"; then'
mutant P12 "temp file not removed on rejection" \
  'rm -f "$raw" "$tmp"; die "rejected the peer file' 'rm -f "$raw"; die "rejected the peer file'
mutant P13 "non-atomic write straight to the destination" \
  'dst="$TEXTFILE_DIR/pft_timesync_peer_$label.prom"
  raw=' 'dst="$TEXTFILE_DIR/pft_timesync_peer_$label.prom"; : > "$dst"
  raw='
mutant P14 "conf sourced even when not root-owned" \
  '[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"' '[ -f "$CONF" ] && . "$CONF"'
mutant P15 "output file left with mktemp mode 600" \
  'if ! { chmod 644 "$tmp" && mv -f "$tmp" "$dst"; }' 'if ! { mv -f "$tmp" "$dst"; }'
mutant P16 "host label not validated" \
  'valid_label() { [[ "$1" =~ ^[a-z0-9][a-z0-9_.-]{0,31}$ ]]; }' 'valid_label() { true; }'

echo "RESULT: $CAUGHT/$TOTAL caught, $SURVIVED survived, $NOTAPPLIED not applied"
[ "$SURVIVED" = 0 ] && [ "$NOTAPPLIED" = 0 ]
