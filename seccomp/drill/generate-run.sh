#!/usr/bin/env bash
# generate-run: the recorded offline profile build from the committed learn data of both hosts (no root, no Docker
# change, no RPC). Builds the validator-only, sentry-only and merged profiles, checks the merged one, prints its file
# and canonical (Docker-stored) sha256 and the full per-syscall diff vs Docker's default; writes them to OUTDIR.
#   COMMIT=<sha> bash seccomp/drill/generate-run.sh OUTDIR   (from a clean checkout at COMMIT; log on stdout)
set -uo pipefail
OUT="${1:-}"; [ -n "$OUT" ] || { echo "usage: generate-run.sh OUTDIR" >&2; exit 3; }
D="$(cd "$(dirname "$0")/.." && pwd)"; T="$D/pft-seccomp.sh"; mkdir -p "$OUT" || exit 2
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | validator-host | recorded offline generate: one profile from both hosts' learn"
echo "# tree: commit ${COMMIT:-unknown}"
for f in pft-seccomp.sh pft_seccomp.py ref/docker-default-29.1.3.json margin.tsv drill/generate-run.sh learn/validator/census.json \
  learn/validator/events.tsv learn/sentry/census.json learn/sentry/events.tsv; do
  echo "# sha256 $(sha256sum < "$D/$f" | cut -c1-64) seccomp/$f"
done
echo "# libseccomp $(dpkg-query -W -f '${Version}' libseccomp2 2>/dev/null)"
rc=0
for h in validator sentry; do
  echo "\$ bash pft-seccomp.sh generate --learn learn/$h > OUT/$h.json"
  bash "$T" generate --learn "$D/learn/$h" > "$OUT/$h.json"; r=$?; [ "$r" = 0 ] || rc=1
  echo "(exit $r)  sha256 $(sha256sum < "$OUT/$h.json" | cut -c1-64)"
done
echo "\$ bash pft-seccomp.sh generate --learn learn/validator --learn learn/sentry > OUT/pft-postfiatd.json"
bash "$T" generate --learn "$D/learn/validator" --learn "$D/learn/sentry" > "$OUT/pft-postfiatd.json"; r=$?; [ "$r" = 0 ] || rc=1; echo "(exit $r)"
echo "  file sha256 $(sha256sum < "$OUT/pft-postfiatd.json" | cut -c1-64); canonical (docker-stored json.Compact) sha256 $(python3 -I "$D/pft_seccomp.py" canon "$OUT/pft-postfiatd.json" 2>&1 | tail -1)"
if cmp -s "$OUT/validator.json" "$OUT/sentry.json" && cmp -s "$OUT/validator.json" "$OUT/pft-postfiatd.json"; then
  echo "  validator-only, sentry-only and merged profiles are byte-identical"
else
  echo "  validator-only / sentry-only / merged profiles differ (the merged one is the union; see the diff)"
fi
echo "\$ bash pft-seccomp.sh check OUT/pft-postfiatd.json"; bash "$T" check "$OUT/pft-postfiatd.json"; r=$?; [ "$r" = 0 ] || rc=1; echo "(exit $r)"
jq -c '[.defaultAction, .defaultErrnoRet, .architectures, .flags, [.syscalls[] | {action, errnoRet, args: (.args != null), n: (.names | length)}]]' "$OUT/pft-postfiatd.json"
echo "\$ bash pft-seccomp.sh diff --learn learn/validator --learn learn/sentry > OUT/diff.tsv"
bash "$T" diff --learn "$D/learn/validator" --learn "$D/learn/sentry" > "$OUT/diff.tsv"; r=$?; [ "$r" = 0 ] || rc=1; echo "(exit $r)"
echo "== per-syscall diff vs Docker's default ($(grep -vc '^#' "$OUT/diff.tsv") rows)"; cat "$OUT/diff.tsv"
echo "== kept by margin or by a LOG record only:"; awk -F'\t' '$4 ~ /^(margin|SCMP_ACT_LOG)/' "$OUT/diff.tsv"
[ "$rc" = 0 ] && echo "RESULT: PASS - one profile for both hosts" || echo "RESULT: FAIL - a step failed"
exit "$rc"
