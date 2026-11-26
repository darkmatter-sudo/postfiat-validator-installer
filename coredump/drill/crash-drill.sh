#!/usr/bin/env bash
# crash-drill: does a SIGSEGV in a container of the node's own image write a core file on this host right now?
# Runs throwaway containers only (never the node): the image of the running postfiatd / postfiatd-sentry container
# by image ID (no pull), --network none, --memory 64m, --rm, entrypoint overridden to sh. In each probe a child
# `sleep` gets SIGSEGV with its cwd on a bind-mounted scratch dir, so a file core pattern ("core") lands there.
# Core files are only counted and sized, never opened, and are deleted (count printed) after each probe.
#   probe A  --ulimit core=-1 (unlimited): tests the host's kernel.core_pattern layer alone
#   probe B  --ulimit core=0:0 (what pft-coredump apply gives the node): tests the container ulimit layer
# Usage: sudo crash-drill.sh STAGE [EXPECT_A EXPECT_B]   EXPECT = core | none (exit 1 when a probe differs)
# Exit: 0 every probe as expected (or no expectation given), 1 a probe differs, 64 error.
# shellcheck disable=SC2016  # the sh -c probe is expanded inside the container
set -uo pipefail
STAGE="${1:?usage: crash-drill.sh STAGE [EXPECT_A EXPECT_B]}"; EXA="${2:-}"; EXB="${3:-}"
DOCKER="${DOCKER:-docker}"
BASE="${DRILL_DIR:-/var/lib/pft-coredump/drill}"
C=""
for n in postfiatd postfiatd-sentry; do "$DOCKER" inspect "$n" >/dev/null 2>&1 && { C="$n"; break; }; done
[ -n "$C" ] || { echo "crash-drill: no node container"; exit 64; }
IMG="$("$DOCKER" inspect -f '{{.Image}}' "$C")" || exit 64
echo "crash-drill $STAGE - $(date -u +%FT%TZ) - image of $C ${IMG:0:19} (local, no pull)"
echo "  host kernel.core_pattern '$(cat /proc/sys/kernel/core_pattern)' core_uses_pid $(cat /proc/sys/kernel/core_uses_pid)"
rc=0
probe() { # ID ULIMIT EXPECT
  local d n b out res
  d="$BASE/$STAGE-$1"; rm -rf "$d"; mkdir -p "$d" && chmod 700 "$d" || exit 64
  out="$("$DOCKER" run --rm --name "pft-cd-drill-$STAGE-$1" --network none --memory 64m --ulimit "core=$2" \
    -v "$d:/dump" -w /dump --entrypoint sh "$IMG" -c 'sleep 30 & p=$!; kill -SEGV $p; wait $p; echo "child exit $? (139 = SIGSEGV)"; echo "ulimit=$(ulimit -c)"' 2>&1)"
  n="$(find "$d" -type f | wc -l)"; b="$(find "$d" -type f -printf '%s\n' | awk '{ s += $1 } END { print s + 0 }')"
  res=none; [ "$n" -gt 0 ] && res=core
  printf '  probe %s ulimit core=%s: %s; shell: "%s"; in-container ulimit -c %s -> %s file(s), %s bytes => %s' "$1" "$2" \
    "$(grep -m1 'child exit' <<<"$out")" "$(grep -m1 -i 'segmentation' <<<"$out" | sed 's/^.*: //')" "$(sed -n 's/^ulimit=//p' <<<"$out")" "$n" "$b" "$res"
  if [ -n "$3" ]; then
    if [ "$res" = "$3" ]; then printf ' (expected %s: ok)\n' "$3"; else printf ' (expected %s: DIFFERS)\n' "$3"; rc=1; fi
  else echo; fi
  echo "    cleanup: $(find "$d" -type f -delete -print | wc -l) file(s) deleted unread"; rmdir "$d"
}
probe A -1 "$EXA"
probe B 0:0 "$EXB"
[ -n "$("$DOCKER" ps -aq --filter name=pft-cd-drill-)" ] && { echo "  leftover drill containers!"; rc=1; }
echo "crash-drill $STAGE RESULT: $([ "$rc" = 0 ] && echo PASS || echo FAIL)"
exit "$rc"
