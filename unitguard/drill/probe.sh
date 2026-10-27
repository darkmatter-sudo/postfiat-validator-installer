#!/usr/bin/env bash
# Run one command in a transient systemd service that carries a unitguard profile's directives (systemd-run -p ...),
# so a profile can be tried against a tool's real command before apply, and a sandbox can be shown to block
# something (negative proof). Nothing is installed; the transient unit is collected when it exits.
# Usage: sudo bash probe.sh PROFILE_FILE [--expect-fail] -- CMD [ARGS...]
#   prints the properties used, the command, its output and exit code.
#   --expect-fail: PASS when CMD exits non-zero (blocked), FAIL when it succeeds. Default: PASS on exit 0.
set -uo pipefail
p="${1:?profile}"; shift
expect=ok
[ "${1:-}" = --expect-fail ] && { expect=fail; shift; }
[ "${1:-}" = -- ] && shift
[ $# -gt 0 ] || { echo "usage: probe.sh PROFILE [--expect-fail] -- CMD..." >&2; exit 3; }
props=()
while IFS= read -r l; do
  case "$l" in ''|'#'*|'['*) continue ;; esac
  props+=(-p "$l")
done < "$p"
echo "probe profile: $(basename "$p") ($(( ${#props[@]} / 2 )) properties) sha256 $(sha256sum "$p" | cut -c1-16)"
echo "probe command: $*"
systemd-run --quiet --wait --pipe --collect --service-type=exec "${props[@]}" -- "$@"
rc=$?
echo "probe exit $rc"
if [ "$expect" = fail ]; then [ "$rc" -ne 0 ] && { echo "PROBE PASS (blocked as expected)"; exit 0; }; echo "PROBE FAIL (expected to be blocked)"; exit 1
else [ "$rc" -eq 0 ] && { echo "PROBE PASS"; exit 0; }; echo "PROBE FAIL"; exit 1; fi
