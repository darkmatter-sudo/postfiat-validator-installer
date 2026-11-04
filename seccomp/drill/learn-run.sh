#!/usr/bin/env bash
# learn-run: the recorded learn on one host (throwaway containers only; the live node is never touched), then the
# offline generate/diff/check of its result. Run as root from a checkout of the repo at COMMIT:
#   sudo COMMIT=<sha> bash seccomp/drill/learn-run.sh validator|sentry OUTDIR [MINUTES]   (log on stdout)
set -uo pipefail
HOST="${1:-}"; OUT="${2:-}"; MIN="${3:-65}"
case "$HOST" in validator|sentry) ;; *) echo "usage: learn-run.sh validator|sentry OUTDIR [MINUTES]" >&2; exit 3 ;; esac
if [ -z "$OUT" ] || ! [[ "$MIN" =~ ^[0-9]+$ ]]; then echo "usage: learn-run.sh validator|sentry OUTDIR [MINUTES]" >&2; exit 3; fi
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 3; }
D="$(cd "$(dirname "$0")/.." && pwd)"; T="$D/pft-seccomp.sh"
x() { echo "\$ $*"; "$@"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
echo "OS: $(lsb_release -ds) | $(date -u +%FT%TZ) | $HOST-host | recorded learn run, --minutes $MIN per phase"
echo "# tree: commit ${COMMIT:-unknown}"
for f in pft-seccomp.sh pft_seccomp.py ref/docker-default-29.1.3.json margin.tsv drill/learn-run.sh; do
  echo "# sha256 $(sha256sum < "$D/$f" | cut -c1-64) seccomp/$f"
done
echo "# kernel $(uname -r), docker $(docker version --format '{{.Server.Version}}'), libseccomp $(dpkg-query -W -f '${Version}' libseccomp2), bpftrace $(bpftrace --version 2>/dev/null)"
echo "# audit before: $(auditctl -s | grep -E '^(enabled|lost|backlog_limit) ' | paste -sd' ')"
x bash "$T" learn --out "$OUT" --minutes "$MIN" --phase both; rc=$?
echo "# audit after: $(auditctl -s | grep -E '^(enabled|lost|backlog_limit) ' | paste -sd' ')"
echo "# leftover throwaways: $(docker ps -a --format '{{.Names}}' | grep -c '^pftsc-learn-')"
[ "$rc" = 0 ] || { echo "RESULT: FAIL - learn exit $rc"; exit 1; }
echo; echo "== offline: generate, check, diff (from $OUT)"
x bash "$T" generate --learn "$OUT" > "$OUT/profile.json" && echo "  profile sha256 $(sha256sum < "$OUT/profile.json" | cut -c1-64), canonical (docker-stored) sha256 $(python3 -I "$D/pft_seccomp.py" canon "$OUT/profile.json")"
x bash "$T" check "$OUT/profile.json"
x bash "$T" diff --learn "$OUT" > "$OUT/diff.tsv"; grep -v 'never observed' "$OUT/diff.tsv"; tail -1 "$OUT/diff.tsv"
echo "RESULT: PASS - learn done, profile generated"
