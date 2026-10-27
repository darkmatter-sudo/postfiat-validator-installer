#!/usr/bin/env bash
# Offline tests for pft-resources.sh: fixture cgroup v2 + /proc trees, stub docker, no root, nothing on the host.
#   bash resources/tests/run-tests.sh [SCRIPT]     (SCRIPT defaults to ../pft-resources.sh; check.sh passes mutants)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; OUT/rc/good_lines are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-resources.sh}"
T="$(mktemp -d)"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }      # NAME CONDITION (subshell: an exit in it is a FAIL)
has()   { grep -qxF -- "$2" "$1"; }                                 # FILE LINE (exact)

# fixture ROOT SCOPE PID: cgroup dir + proc entries for one container run (sets CG)
mkfix() {
  local root="$1" scope="$2" pid="$3" cg i
  cg="$root/cg/system.slice/docker-$scope.scope"; mkdir -p "$cg" "$root/proc/$pid/fd" "$root/proc/sys/kernel" "$root/proc/7/fd"
  echo 851116032 > "$cg/memory.current"; echo 2415919104 > "$cg/memory.max"
  printf 'anon 802664448\nfile 43819008\nkernel_stack 507904\npagetables 2179072\nsock 172032\nshmem 4096\n' > "$cg/memory.stat"
  printf 'low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\n' > "$cg/memory.events"
  printf 'usage_usec 22624289328\nuser_usec 8000398953\nsystem_usec 14601485029\nnr_periods 10\nnr_throttled 4\nthrottled_usec 2500000\n' > "$cg/cpu.stat"
  echo 'max 100000' > "$cg/cpu.max"; echo 31 > "$cg/pids.current"; echo 256 > "$cg/pids.max"
  printf 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n' > "$cg/memory.pressure"
  printf 'some avg10=2.41 avg60=3.27 avg300=3.34 total=3380818249\nfull avg10=0.93 avg60=1.20 avg300=1.44 total=1712346293\n' > "$cg/cpu.pressure"
  printf 'some avg10=0.00 avg60=0.08 avg300=0.05 total=250398196\nfull avg10=0.00 avg60=0.01 avg300=0.03 total=201096113\n' > "$cg/io.pressure"
  printf '7\n%s\n' "$pid" > "$cg/cgroup.procs"
  echo postfiatd > "$root/proc/$pid/comm"; echo cron > "$root/proc/7/comm"
  for i in $(seq 1 43); do : > "$root/proc/$pid/fd/$i"; done
  printf 'Limit                     Soft Limit           Hard Limit           Units     \nMax open files            1024                 524288               files     \n' > "$root/proc/$pid/limits"
  echo "0::/system.slice/docker-$scope.scope" > "$root/proc/$pid/cgroup"
  echo 'MemTotal:        8127628 kB' > "$root/proc/meminfo"; echo 4194304 > "$root/proc/sys/kernel/pid_max"
  CG="$cg"
}
# stub docker: `docker inspect ...` prints the line in DIR/inspect (PID ID OOMKilled RestartCount), fails if absent
mkstub() { mkdir -p "$1/bin"; printf '#!/bin/sh\n[ "$1" = inspect ] || exit 1\ncat "%s/inspect" 2>/dev/null || exit 1\n' "$1" > "$1/bin/docker"; chmod +x "$1/bin/docker"; }
run() { # ROOT [args] -> textfile $OUT, ROOT/rc, ROOT/err, ROOT/hist.jsonl
  local root="$1"; shift
  mkdir -p "$root/tf"
  PFT_RES_CONF=/nonexistent PFT_RES_CGROOT="$root/cg" PFT_RES_PROC="$root/proc" PFT_RES_DOCKER="$root/bin/docker" \
    PFT_RES_NOW=1793081423 bash "$S" collect --textfile-dir "$root/tf" --history "$root/hist.jsonl" "$@" 2> "$root/err"
  echo $? > "$root/rc"; OUT="$root/tf/pft_resources_postfiatd.prom"
}
new() { # NAME PID -> fixture dir with a stub docker reporting PID (running, not OOM-killed, 0 restarts)
  local d="$T/$1"; mkdir -p "$d"; mkstub "$d"; echo "$2 407cf9b6ffa63813a1eb3baa false 0" > "$d/inspect"; printf '%s' "$d"
}

echo "== 1 normal fixture"
D="$(new normal 1065763)"; mkfix "$D" aaa111 1065763; run "$D"
check "1a exit 0" '[ "$(cat "$D/rc")" = 0 ]'
check "1b up 1" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 1"'
check "1c memory current" 'has "$OUT" "pft_resources_memory_current_bytes{container=\"postfiatd\"} 851116032"'
check "1d memory max (own limit)" 'has "$OUT" "pft_resources_memory_max_bytes{container=\"postfiatd\"} 2415919104" && has "$OUT" "pft_resources_limit_set{container=\"postfiatd\",resource=\"memory\"} 1"'
check "1e oom_kill counter" 'has "$OUT" "pft_resources_memory_events_total{container=\"postfiatd\",event=\"oom_kill\"} 1"'
check "1f fds 43 of 1024 (postfiatd, not the cron pid listed first)" 'has "$OUT" "pft_resources_fd_open{container=\"postfiatd\"} 43" && has "$OUT" "pft_resources_fd_limit_soft{container=\"postfiatd\"} 1024"'
check "1g pids" 'has "$OUT" "pft_resources_pids_current{container=\"postfiatd\"} 31" && has "$OUT" "pft_resources_pids_max{container=\"postfiatd\"} 256"'
check "1h PSI avg60 as ratio (3.27% -> 0.0327)" 'has "$OUT" "pft_resources_pressure_avg60_ratio{container=\"postfiatd\",resource=\"cpu\",kind=\"some\"} 0.0327"'
check "1i PSI total in seconds" 'has "$OUT" "pft_resources_pressure_stall_seconds_total{container=\"postfiatd\",resource=\"cpu\",kind=\"some\"} 3380.818249"'
check "1j cpu throttling" 'has "$OUT" "pft_resources_cpu_throttled_periods_total{container=\"postfiatd\"} 4" && has "$OUT" "pft_resources_cpu_throttled_seconds_total{container=\"postfiatd\"} 2.500000"'
check "1k no memory.peak on this fixture -> supported 0, no peak metric" 'has "$OUT" "pft_resources_file_supported{container=\"postfiatd\",file=\"memory.peak\"} 0" && ! grep -q "^pft_resources_memory_peak_bytes" "$OUT"'
check "1l one TYPE line per family, each family contiguous" '[ -z "$(grep "^# TYPE" "$OUT" | awk "{print \$3}" | sort | uniq -d)" ] && [ -z "$(grep -v "^#" "$OUT" | sed "s/[{ ].*//" | uniq | sort | uniq -d)" ]'
check "1m history line is JSON with the same values" 'python3 -c "import json,sys; d=json.loads(open(sys.argv[1]).read()); assert d[\"mem_current\"]==851116032 and d[\"fds\"]==43 and d[\"oom_kill\"]==1 and d[\"psi_cpu_some_avg60\"]==3.27 and d[\"ts\"]==1793081423" "$D/hist.jsonl"'
check "1n textfile mode 644, no temp files left" '[ "$(stat -c %a "$OUT")" = 644 ] && [ "$(ls -A "$D/tf" | wc -l)" = 1 ]'
check "1o docker restarts 0 + oom_killed 0" 'has "$OUT" "pft_resources_container_restarts{container=\"postfiatd\"} 0" && has "$OUT" "pft_resources_container_oom_killed{container=\"postfiatd\"} 0"'
if command -v docker >/dev/null && docker image inspect prom/prometheus:v3.5.0 >/dev/null 2>&1; then
  check "1p promtool check metrics clean" 'docker run --rm -i --entrypoint promtool prom/prometheus:v3.5.0 check metrics < "$OUT" > "$D/lint" 2>&1'
else
  echo "SKIP 1p promtool check metrics (no docker / prom/prometheus:v3.5.0 image)"
fi

echo "== 2 no limits: memory.max/pids.max = max, cpu quota set"
D="$(new nolimit 2000)"; mkfix "$D" bbb222 2000; echo max > "$CG/memory.max"; echo max > "$CG/pids.max"; echo '200000 100000' > "$CG/cpu.max"; run "$D"
check "2a up 1" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 1"'
check "2b memory max = MemTotal bytes, limit_set 0" 'has "$OUT" "pft_resources_memory_max_bytes{container=\"postfiatd\"} 8322691072" && has "$OUT" "pft_resources_limit_set{container=\"postfiatd\",resource=\"memory\"} 0"'
check "2c pids max = kernel.pid_max, limit_set 0" 'has "$OUT" "pft_resources_pids_max{container=\"postfiatd\"} 4194304" && has "$OUT" "pft_resources_limit_set{container=\"postfiatd\",resource=\"pids\"} 0"'
check "2d cpu quota 2 cores" 'has "$OUT" "pft_resources_cpu_limit_cores{container=\"postfiatd\"} 2.000" && has "$OUT" "pft_resources_limit_set{container=\"postfiatd\",resource=\"cpu\"} 1"'

echo "== 3 PSI files missing (CONFIG_PSI off / psi=0) + memory.peak present (kernel >= 5.19)"
D="$(new nopsi 3000)"; mkfix "$D" ccc333 3000; rm -f "${CG:?}/memory.pressure" "${CG:?}/cpu.pressure" "${CG:?}/io.pressure"
echo 999999999 > "$CG/memory.peak"; run "$D"
check "3a exit 0, up 1" '[ "$(cat "$D/rc")" = 0 ] && has "$OUT" "pft_resources_up{container=\"postfiatd\"} 1"'
check "3b file_supported 0 for each PSI file" 'for r in memory cpu io; do has "$OUT" "pft_resources_file_supported{container=\"postfiatd\",file=\"$r.pressure\"} 0" || exit 1; done'
check "3c no pressure series" '! grep -q "^pft_resources_pressure_" "$OUT"'
check "3d memory.peak exported" 'has "$OUT" "pft_resources_memory_peak_bytes{container=\"postfiatd\"} 999999999" && has "$OUT" "pft_resources_file_supported{container=\"postfiatd\",file=\"memory.peak\"} 1"'
check "3e history has no psi keys but is valid JSON" 'python3 -c "import json,sys; d=json.loads(open(sys.argv[1]).read()); assert not any(k.startswith(\"psi_\") for k in d)" "$D/hist.jsonl"'

echo "== 4 restarted container: new PID + new cgroup scope, old scope still on disk"
D="$(new restart 4000)"; mkfix "$D" old444 4000; echo 111 > "$CG/memory.current"
mkfix "$D" new555 4100; echo 222333444 > "$CG/memory.current"; printf 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n' > "$CG/memory.events"
echo "4100 new555deadbeefcafe true 1" > "$D/inspect"; run "$D"
check "4a reads the NEW scope (memory 222333444, not 111)" 'has "$OUT" "pft_resources_memory_current_bytes{container=\"postfiatd\"} 222333444"'
check "4b new cgroup's oom_kill restarted at 0" 'has "$OUT" "pft_resources_memory_events_total{container=\"postfiatd\",event=\"oom_kill\"} 0"'
check "4c docker OOMKilled=true and RestartCount 1 still visible" 'has "$OUT" "pft_resources_container_oom_killed{container=\"postfiatd\"} 1" && has "$OUT" "pft_resources_container_restarts{container=\"postfiatd\"} 1"'
check "4d container id label changes" 'has "$OUT" "pft_resources_container_info{container=\"postfiatd\",id=\"new555deadbe\"} 1"'

echo "== 5 malformed memory.current after a good run: up 0, no stale values, no history line, exit 1"
D="$(new malformed 5000)"; mkfix "$D" ddd666 5000; run "$D"; good_lines="$(wc -l < "$D/hist.jsonl")"
echo 'garbage!' > "$CG/memory.current"; run "$D"
check "5a exit 1" '[ "$(cat "$D/rc")" = 1 ]'
check "5b up 0" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 0"'
check "5c only up + timestamp series (stale values gone)" '[ "$(grep -vc "^#" "$OUT")" = 2 ] && has "$OUT" "pft_resources_collect_timestamp_seconds{container=\"postfiatd\"} 1793081423"'
check "5d stderr names the file" 'grep -q "malformed .*memory.current" "$D/err"'
check "5e no history line for the failed run" '[ "$good_lines" = 1 ] && [ "$(wc -l < "$D/hist.jsonl")" = 1 ]'

echo "== 6 other malformed / unreadable inputs -> up 0"
for c in psi events cpumax limits; do
  D="$(new "bad-$c" 6000)"; mkfix "$D" "e$c" 6000
  case "$c" in
    psi) echo 'some avg10=x avg60=0.00 avg300=0.00 total=0' > "$CG/cpu.pressure" ;;
    events) printf 'low 0\nhigh 0\n' > "$CG/memory.events" ;;
    cpumax) echo 'lots 100000' > "$CG/cpu.max" ;;
    limits) echo 'nothing here' > "$D/proc/6000/limits" ;;
  esac
  run "$D"
  check "6-$c up 0 + exit 1" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 0" && [ "$(cat "$D/rc")" = 1 ]'
done

echo "== 7 container problems -> up 0"
D="$(new stopped 7000)"; mkfix "$D" fff777 7000; echo "0 407cf9b6ffa6 false 3" > "$D/inspect"; run "$D"
check "7a stopped container (pid 0): up 0, stderr 'not running'" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 0" && grep -q "not running" "$D/err"'
D="$(new noinspect 7100)"; mkfix "$D" ggg888 7100; rm -f "${D:?}/inspect"; run "$D"
check "7b docker inspect fails: up 0" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 0" && grep -q "docker inspect" "$D/err"'
D="$(new noproc 7200)"; mkfix "$D" hhh999 7200; echo java > "$D/proc/7200/comm"; run "$D"
check "7c no postfiatd process in the cgroup: up 0" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 0" && grep -q "no process named postfiatd" "$D/err"'
D="$(new v1 7300)"; mkfix "$D" iii000 7300; echo "12:memory:/docker/iii000" > "$D/proc/7300/cgroup"; run "$D"
check "7d cgroup v1 line only: up 0" 'has "$OUT" "pft_resources_up{container=\"postfiatd\"} 0" && grep -q "no cgroup v2 entry" "$D/err"'

echo "== 8 usage errors"
PFT_RES_CONF=/nonexistent bash "$S" collect --container 'bad name;x' --stdout > /dev/null 2>&1; rc=$?
check "8a bad container name -> exit 3" '[ "$rc" = 3 ]'
D="$(new usage 8000)"; mkfix "$D" jjj111 8000
PFT_RES_CONF=/nonexistent PFT_RES_CGROOT="$D/cg" PFT_RES_PROC="$D/proc" PFT_RES_DOCKER="$D/bin/docker" \
  bash "$S" collect --textfile-dir "$D/missing" > /dev/null 2>&1; rc=$?
check "8b missing textfile dir -> exit 3" '[ "$rc" = 3 ]'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
