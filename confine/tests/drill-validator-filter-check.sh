#!/usr/bin/env bash
# Checks drill-validator.sh's integrity-accept filter against synthetic pft-integrity verify output.
set -u
# shellcheck disable=SC2034  # CONTAINER and IV are read by the eval'd filter line
CONTAINER=postfiatd
LINE="$(grep -n '^other=' drill-validator.sh | cut -d: -f1)"
FILTER="$(sed -n "${LINE}p" drill-validator.sh)"
echo "filter under test (drill-validator.sh line $LINE, eval'd as-is):"; echo "$FILTER"
check() { # name expect(empty|nonempty) input
  # shellcheck disable=SC2034  # read by the eval'd filter line
  local IV="$3" other
  eval "$FILTER"   # the exact line from drill-validator.sh, sets $other
  local got=empty; [ -n "$other" ] && got=nonempty
  [ "$got" = "$2" ] && r=PASS || r=FAIL
  echo "[$r] $1: expect $2, got $got${other:+ -> $other}"
}
check "only compose + own container (accept)" empty "  [FAIL] compose:.env                                 changed  mtime, sha256
  [WARN] compose:docker-compose.confine.yml           added    new file
  [FAIL] container:postfiatd                          changed  cap_add, cap_drop, labels, readonly_rootfs
RESULT: FAIL - 46 unchanged, 1 warn, 2 fail -> exit 2"
check "unrelated binary changed (refuse)" nonempty "  [FAIL] container:postfiatd   changed cap_add
  [WARN] bin:pft-agent   changed sha256"
check "other container with same prefix (refuse)" nonempty "  [FAIL] container:postfiatd-sentry   changed cap_add"
check "sshd change (refuse)" nonempty "  [WARN] sshd:sshd_config   changed mtime"
check "PASS output, nothing changed" empty "RESULT: PASS - 49 unchanged, 0 warn, 0 fail -> exit 0"
