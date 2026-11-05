# denied-lib.sh: the drill's own (independent of pft-seccomp audit) count of errno type=SECCOMP records.
# Sourced by host-run.sh and tests/run-tests.sh. The kernel logs EVERY errno answer as code=0x50000 (the errno value
# is not in the record), so a syscall the profile answers by design with its own errno (Docker's clone3 -> ENOSYS:
# glibc falls back to clone, on every thread start) is logged like a denial. Live run 16 stopped at the sentry
# canary because this counter (unlike pft-seccomp's audit/gate since da341ce) counted those clone3 records.
# shellcheck shell=bash

# PROFILE_FILE -> space-separated syscalls with an argument-free, unconditional ERRNO rule whose errno is not EPERM
# (the same selection as pft-seccomp.sh expected_errno; argument-filtered or caps-conditional rules do not qualify)
expected_list() {
  [ -r "${1:-}" ] || return 0
  jq -r '[.syscalls[]? | select(.action == "SCMP_ACT_ERRNO" and (.errnoRet // 1) != 1 and ((.args // []) | length) == 0
          and (has("includes") | not) and (has("excludes") | not)) | .names[]] | unique | join(" ")' "$1" 2>/dev/null
}

# SINCE_EPOCH LABEL SYSCALL SKIP FILE... -> number of errno type=SECCOMP records for subj=LABEL at/after SINCE.
# SYSCALL non-empty: only that syscall (negative controls; SKIP is ignored). SYSCALL empty: every syscall except
# those in SKIP (space-separated, from expected_list).
count_records() {
  local t="$1" l="$2" n="$3" skip="$4"; shift 4
  cat "$@" 2>/dev/null | awk -v t="$t" -v n="$n" -v l="$l" -v skip="$skip" '
    BEGIN { ns = split(skip, a, " "); for (i = 1; i <= ns; i++) sk[a[i]] = 1 }
    index($0, "type=SECCOMP ") && index($0, " subj=" l " ") && index($0, " code=0x50000") {
      s = ""; if (match($0, /SYSCALL=[A-Za-z0-9_]+$/)) s = substr($0, RSTART + 8)
      if (n != "") { if (s != n) next } else if (s in sk) next
      if (match($0, /audit\([0-9]+/) && substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0) c++ }
    END { print c + 0 }'
}
