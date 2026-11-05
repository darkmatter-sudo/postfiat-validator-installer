# stop-lib.sh: what live-run.sh's stop path may accept into the pft-integrity baseline by itself. Sourced by
# live-run.sh and tests/run-tests.sh (tested on the real verify lines of logs 13 and 17).
# shellcheck shell=bash

# pft-integrity verify output -> the WARN/FAIL item names, one per line
own_items() { grep -E '^  \[(WARN|FAIL)\]' | awk '{print $2}' | sort -u; }

# VERIFY_OUTPUT CONTAINER ENFORCED(0|1) -> rc 0 if every changed item is pft-seccomp's own install (binary, units),
# or the node container itself with ONLY security_opt changed while ENFORCED=1 (the host's audit grades it as running
# under the installed profile: an apply that passed and stayed in place before the run stopped, live run 16).
# Anything else (or the container changed in any other field) -> rc 1: left for a human.
install_only() {
  local items i
  items="$(own_items <<<"$1")"
  while read -r i; do
    [ -n "$i" ] || continue
    case "$i" in
      bin:pft-seccomp | unit:pft-seccomp.service | unit:pft-seccomp.timer | unit:pft-seccomp-pull.service | unit:pft-seccomp-pull.timer) ;;
      "container:$2") [ "$3" = 1 ] && grep -qE "^  \[(WARN|FAIL)\] container:$2 +changed +security_opt *$" <<<"$1" || return 1 ;;
      *) return 1 ;;
    esac
  done <<<"$items"
}
