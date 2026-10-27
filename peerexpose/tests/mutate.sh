#!/usr/bin/env bash
# Mutation check for pft-peerexpose (classifier, config, apply/rollback): each mutant is an exact one-line replacement in a copy of the
# script; the offline suite must FAIL on it. A mutant counts as caught only if it was applied (copy differs) and
# the suite printed at least one FAIL line and a RESULT line. Usage: bash tests/mutate.sh
# Mutant texts are literal script lines, so they are single-quoted on purpose (a mutant may span two lines).
# shellcheck disable=SC2016,SC1003
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../pft-peerexpose.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# id@@description@@exact old text (must occur exactly once)@@new text
MUTANTS=(
  'M1@@sentry overlay allowed@@    sentry:crawl.overlay.*|sentry:crawl.counts) echo restrict ;;@@    sentry:crawl.counts) echo restrict ;;'
  'M2@@validator health restricted@@    validator:health.*) echo allow ;;@@    validator:health.*) echo restrict ;;'
  'M3@@disclosed needs 2+ matches@@    if [ "$n" -gt 0 ]; then record@@    if [ "$n" -gt 1 ]; then record'
  'M4@@vl 200 counts without blob@@    if [ "$code" = 200 ] && jq -e '"'"'has("blob")'"'"' "$TMP/vl.body" >/dev/null 2>&1; then@@    if [ "$code" = 200 ]; then'
  'M5@@violation ignores role policy@@  if [ "$2" = disclosed ] && [ "$(policy "$ROLE" "$1")" = restrict ]; then verdict=VIOLATION@@  if [ "$2" = disclosed ]; then verdict=VIOLATION'
  'M6@@errors do not set exit 2@@  if [ "$ERRORS" -gt 0 ]; then return 2; fi@@  :'
  'M7@@non-200 crawl treated as disclosed@@    record crawl.endpoint restricted 0 "http $code"@@    record crawl.endpoint disclosed 1 "http $code"'
  'M8@@peer IPs not inspected@@crawl.overlay.peer_ip|.overlay.active[]?.ip // empty@@crawl.overlay.peer_ip|.overlay.nothing[]?.ip // empty'
  'M9@@sentry block keeps overlay public@@    sentry) printf '"'"'[crawl]\noverlay=0@@    sentry) printf '"'"'[crawl]\noverlay=1'
  'M10@@render leaves old [vl] sections in place@@    /^[[:space:]]*\[/ { skip = (tolower($0) ~ /^[[:space:]]*\[(crawl|vl)\][[:space:]]*$/) }@@    /^[[:space:]]*\[/ { skip = (tolower($0) ~ /^[[:space:]]*\[(crawl)\][[:space:]]*$/) }'
  'M11@@effective default counts=1@@v["counts"] = 0;@@v["counts"] = 1;'
  'M12@@validate ignores changes outside the block@@  cmp -s <(strip_managed < "$2") <(strip_managed < "$3") \@@  true \'
  'M13@@bare [crawl] 0 not parsed@@if (sec == "crawl") v["crawl"] = (line == "1" || tolower(line) == "true") ? 1 : 0; next@@next'
  'M14@@[vl] count not checked@@  [ "$n" -eq 1 ] || { echo "validate: expected exactly one [vl] section, found $n"; return 1; }@@  :'
  'M15@@lock list ignored@@    [ "$locks" = "no data-collection locks" ] || { echo@@    true || { echo'
  'M16@@required peers not checked@@[ "$req" -eq "${#REQ_PEERS[@]}" ] \@@true \'
  'M17@@audit not part of the gate@@       && { [ "$1" != audit ] || [ "$viol" = 0 ]; }; then@@       ; then'
  'M18@@no automatic rollback after a failed gate@@  log "  apply gate FAILED: automatic rollback to $bak"@@  window_close; log "RESULT: APPLIED"; return 0'
  'M19@@pre-rollback copy moves LATEST@@    [ "$1" != pre-apply ] || echo "$dst" > "$d/LATEST"@@    echo "$dst" > "$d/LATEST"'
  'M20@@dry run writes@@  if $DRY_RUN; then log "RESULT: DRY RUN (nothing written, no restart)"; return 0; fi
  bak=@@  bak='
  'M21@@no silence before the restart@@  if [ "$AM" != none ]; then
    n=@@  if false; then
    n='
  'M22@@rollback skips the outside-block drift check@@  cmp -s <(strip_managed < "$cur") <(strip_managed < "$FROM") \@@  true \'
)

caught=0; total=0
for m in "${MUTANTS[@]}"; do
  id="${m%%@@*}"; rest="${m#*@@}"; desc="${rest%%@@*}"
  total=$((total + 1))
  cp "$SRC" "$WORK/m.sh"
  applied=true
  python3 - "$WORK/m.sh" "$m" <<'EOF' || applied=false
import sys
path, spec = sys.argv[1], sys.argv[2]
_, _, old, new = spec.split("@@")
src = open(path).read()
if src.count(old) != 1:
    sys.exit(1)
open(path, "w").write(src.replace(old, new, 1))
EOF
  if ! $applied || cmp -s "$SRC" "$WORK/m.sh"; then
    echo "$id NOT APPLIED ($desc)"; continue
  fi
  bash "$HERE/run-tests.sh" "$WORK/m.sh" > "$WORK/out" 2>&1
  fails="$(grep -c '^FAIL ' "$WORK/out")"
  if grep -q '^RESULT: ' "$WORK/out" && [ "$fails" -gt 0 ]; then
    caught=$((caught + 1))
    echo "$id CAUGHT ($desc) by $fails test(s): $(grep '^FAIL ' "$WORK/out" | sed 's/^FAIL //' | paste -sd ';' -)"
  else
    echo "$id SURVIVED ($desc)"
  fi
done
echo "MUTANTS: $caught/$total caught"
[ "$caught" -eq "$total" ]
