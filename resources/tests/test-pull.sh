#!/usr/bin/env bash
# Offline tests for pft-resources-pull.sh: PULL_SSH is a stub that prints a fixture file (or fails / hangs); no
# network, no root, nothing on the host.   bash resources/tests/test-pull.sh [SCRIPT]   (check-pull.sh passes mutants)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; rc/err are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-resources-pull.sh}"
T="$(mktemp -d)"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }      # NAME CONDITION (subshell: an exit in it is a FAIL)

N=postfiatd-sentry
TF="$T/tf"; mkdir -p "$TF"; DST="$TF/pft_resources_$N.prom"
# the stub "ssh": `stub cat -- PATH` prints $T/remote (mode from $T/mode: ok | fail | hang), and records PATH
cat > "$T/stub" <<EOF
#!/bin/sh
echo "\$*" > "$T/args"
case "\$(cat "$T/mode")" in fail) exit 255 ;; hang) sleep 30 ;; esac
cat "$T/remote"
EOF
chmod +x "$T/stub"
good() { # a file shaped like the real collector output (header comment, HELP/TYPE, multi-label samples)
  cat <<EOF
# pft-resources v1 (cgroup v2 collector, ../resources)
# HELP pft_resources_up 1 if every required cgroup/proc file was read and parsed
# TYPE pft_resources_up gauge
pft_resources_up{container="$N"} 1
# HELP pft_resources_collect_timestamp_seconds Unix time of this collection
# TYPE pft_resources_collect_timestamp_seconds gauge
pft_resources_collect_timestamp_seconds{container="$N"} 1793084400
pft_resources_container_info{container="$N",id="885926643ead"} 1
pft_resources_memory_current_bytes{container="$N"} 851116032
pft_resources_pressure_avg60_ratio{container="$N",resource="io",kind="some"} 0.0008
pft_resources_cpu_usage_seconds_total{container="$N"} 22624.289328
EOF
}
run() { # [args...] -> $T/rc, $T/err ; uses $T/remote and $T/mode
  local conf="$T/conf"
  PFT_RES_PULL_CONF="$conf" PULL_SSH="${SSH_OVERRIDE-$T/stub}" TEXTFILE_DIR="$TF" PULL_TIMEOUT="${TMO:-5}" \
    MAX_BYTES="${MAXB:-65536}" bash "$S" "$@" > "$T/out" 2> "$T/err"; echo $? > "$T/rc"
}
rc() { cat "$T/rc"; }
reset_dst() { printf 'PREVIOUS\n' > "$DST"; }      # marker: proves a failed pull keeps the previous copy
kept() { [ "$(cat "$DST")" = PREVIOUS ]; }
no_tmp() { [ -z "$(find "$TF" -name '.pull-*' -print -quit)" ]; }
reject() { # NAME FILE-CONTENT-COMMAND EXPECTED-REASON-SUBSTRING
  local want="$3"   # check() eval()s in its own frame, where $3 is unset
  eval "$2" > "$T/remote"; echo ok > "$T/mode"; reset_dst; run pull --container "$N"
  check "$1: exit 2" '[ "$(rc)" = 2 ]'
  check "$1: reason '$want'" 'grep -qF -- "$want" "$T/err"'
  check "$1: previous copy kept, no temp file left" 'kept && no_tmp'
}

echo "== 1 good file is installed atomically and byte-identical"
good > "$T/remote"; echo ok > "$T/mode"; reset_dst; run pull --container "$N"
check "1a exit 0" '[ "$(rc)" = 0 ]'
check "1b destination == remote file" 'cmp -s "$T/remote" "$DST"'
check "1c mode 0644" '[ "$(stat -c %a "$DST")" = 644 ]'
check "1d remote path asked for" 'grep -qx -- "cat -- /var/lib/pft-exporter/textfile/pft_resources_$N.prom" "$T/args"'
check "1e no temp file left" 'no_tmp'
check "1f validate subcommand agrees" 'bash "$S" validate "$T/remote" "$N" | grep -qx valid'

echo "== 2 fetch failures keep the previous copy (exit 1)"
echo fail > "$T/mode"; reset_dst; run pull --container "$N"
check "2a ssh failure: exit 1" '[ "$(rc)" = 1 ]'
check "2b ssh failure: previous kept, no temp" 'kept && no_tmp'
echo hang > "$T/mode"; reset_dst; s=$(date +%s); TMO=2 run pull --container "$N"; e=$(( $(date +%s) - s ))
check "2c hang: exit 1 after the timeout (${e}s)" '[ "$(rc)" = 1 ] && [ "$e" -lt 10 ]'
check "2d hang: previous kept, no temp" 'kept && no_tmp'

echo "== 3 validation rejects (exit 2, previous copy kept)"
reject "3a foreign metric name" 'good; echo "node_exporter_build_info{container=\"$N\"} 1"' "not a pft_resources_ line"
reject "3b other container's series" 'good; echo "pft_resources_up{container=\"postfiatd\"} 0"' "first label is not"
reject "3c container label not first" 'good | sed "s/{container=\"$N\",id=/{id=\"x\",container=\"$N\",x=/"' "first label is not"
reject "3d HELP for a foreign metric" 'good; echo "# TYPE up counter"' "foreign metric"
reject "3e non-numeric value" 'good; echo "pft_resources_fd_open{container=\"$N\"} lots"' "malformed labels or value"
reject "3f extra text after value" 'good; echo "pft_resources_fd_open{container=\"$N\"} 1 2 3"' "malformed labels or value"
reject "3g escaped quote in a label" 'good; echo "pft_resources_x{container=\"$N\",a=\"b\\\",c=\\\"d\"} 1"' "malformed labels or value"
reject "3h sample without labels" 'good; echo "pft_resources_up 1"' "sample without labels"
reject "3i no up sample" 'good | grep -v "^pft_resources_up{"' "no pft_resources_up"
reject "3j no timestamp sample" 'good | grep -v "^pft_resources_collect_timestamp"' "no pft_resources_collect_timestamp_seconds"
reject "3k empty file" ': ' "empty file"
reject "3l container prefix trick (postfiatd-sentry2)" 'good | sed "s/container=\"$N\"/container=\"${N}2\"/"' "first label is not"
good > "$T/remote"; echo ok > "$T/mode"; reset_dst; MAXB=200 run pull --container "$N"
check "3m over MAX_BYTES: exit 2 + reason" '[ "$(rc)" = 2 ] && grep -q "> MAX_BYTES 200" "$T/err"'
check "3n over MAX_BYTES: previous kept" 'kept && no_tmp'

echo "== 4 usage / config errors (exit 3, nothing written)"
reset_dst; run pull --container 'x;rm -rf /'
check "4a bad container name: exit 3, previous kept" '[ "$(rc)" = 3 ] && kept'
reset_dst; SSH_OVERRIDE="" run pull --container "$N"
check "4b PULL_SSH unset: exit 3, previous kept" '[ "$(rc)" = 3 ] && kept'
reset_dst; run pull --bogus
check "4c unknown argument: exit 3" '[ "$(rc)" = 3 ]'
reset_dst; TMO=abc run pull --container "$N"
check "4d non-integer timeout: exit 3, previous kept" '[ "$(rc)" = 3 ] && kept'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
