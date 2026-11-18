#!/usr/bin/env bash
# Offline rebuild of a committed valwatch collection (task_34064fdaf85b26153cf88a4ea94515db): unpack
# data/ROLE/*.jsonl.gz into a scratch directory, run `valwatch.py report` over it with the window and thresholds
# from data/window.env, and `cmp` each output with the committed reports/ROLE.{txt,json,detail.json}.
# Needs only python3 and gzip: no node, no root, no network.
#   bash valwatch/drill/offline-rebuild.sh [ROLE...]     (default: validator sentry; from any cwd)
# Exit 0 when every output is byte-identical, 1 when any differs or a report fails.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$HERE/data/window.env" || exit 3
if [ -z "${FROM:-}" ] || [ -z "${TO:-}" ]; then echo "window.env lacks FROM/TO"; exit 3; fi
ROLES=("$@"); [ ${#ROLES[@]} -gt 0 ] || ROLES=(validator sentry)
SCR="$(mktemp -d -p "${TMPDIR:-$HOME/.cache}")" || exit 3
trap 'rm -rf "$SCR"' EXIT
TH=(--warn-delay-ms "$WARN_DELAY_MS" --min-participation "$MIN_PARTICIPATION" --min-margin "$MIN_MARGIN")
fails=0
for role in "${ROLES[@]}"; do
  mkdir -p "$SCR/$role/data"
  for gz in "$HERE/data/$role"/*.jsonl.gz; do
    gzip -dc "$gz" > "$SCR/$role/data/$(basename "$gz" .gz)" || { echo "FAIL $role: cannot unpack $gz"; fails=$((fails + 1)); }
  done
  for kind in txt json detail.json; do
    case "$kind" in txt) opt=() ;; json) opt=(--json) ;; detail.json) opt=(--detail) ;; esac
    out="$SCR/$role/$role.$kind"
    python3 -I "$HERE/valwatch.py" report --dir "$SCR/$role/data" --from "$FROM" --to "$TO" "${TH[@]}" "${opt[@]}" > "$out"
    rc=$?
    if [ "$rc" != 0 ]; then echo "FAIL $role.$kind: report exit $rc"; fails=$((fails + 1)); continue; fi
    if cmp "$out" "$HERE/reports/$role.$kind"; then
      echo "ok   $role.$kind byte-identical ($(wc -c < "$out") bytes, sha256 $(sha256sum < "$out" | cut -c1-64))"
    else
      echo "FAIL $role.$kind differs from reports/$role.$kind"; fails=$((fails + 1))
    fi
  done
done
echo "RESULT: $fails difference(s)"
[ "$fails" = 0 ]
