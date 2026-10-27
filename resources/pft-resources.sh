#!/usr/bin/env bash
# pft-resources: read-only cgroup v2 resource-pressure collector for a postfiatd container (validator or sentry).
# Writes pft_resources_* Prometheus textfile metrics for the pft exporter (../exporter, PFT_TEXTFILE_DIR) and,
# optionally, one JSON line per run for the 24h baseline report (report.py). Changes nothing on the host.
#
# Usage: sudo pft-resources collect [--container NAME] [--textfile-dir DIR] [--history FILE] [--stdout]
#        pft-resources version
#
#  collect  resolves the container's main PID (docker inspect), its cgroup v2 path (/proc/PID/cgroup), and reads
#           memory.current/max/peak, memory.events, memory.stat, cpu.stat, cpu.max, pids.current/max, PSI
#           (memory/cpu/io .pressure), plus open fds vs the soft RLIMIT_NOFILE of the PROC_NAME process.
#           Writes DIR/pft_resources_NAME.prom atomically (temp file + rename). On any read/parse error of a
#           required file it writes only pft_resources_up 0 + the timestamp (no stale values) and exits 1.
#           Optional files (memory.peak: kernel >= 5.19 only; *.pressure: PSI may be off) are reported as
#           pft_resources_file_supported{file=...} 0 and are not errors. A limit of "max" is exported as the host
#           value (MemTotal, kernel.pid_max) with pft_resources_limit_set{resource=...} 0.
#           Docker's State.OOMKilled and RestartCount are exported too: an OOM kill of the container's main
#           process restarts the container into a NEW cgroup whose memory.events starts at 0, so the cgroup
#           counter alone would miss exactly that kill.
#
# Exit codes: 0 ok, 1 collection failed (up 0 written), 3 usage/config error.
# Conf: PFT_RES_CONF (/etc/pft-resources.env, root-owned, sourced first): CONTAINER (postfiatd), PROC_NAME
#       (postfiatd), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), HISTORY (empty = none)
# Test hooks: PFT_RES_CGROOT (/sys/fs/cgroup)  PFT_RES_PROC (/proc)  PFT_RES_DOCKER (docker)  PFT_RES_NOW

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_RES_CONF:-/etc/pft-resources.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
CONTAINER="${CONTAINER:-postfiatd}"
PROC_NAME="${PROC_NAME:-postfiatd}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
HISTORY="${HISTORY:-}"
CGROOT="${PFT_RES_CGROOT:-/sys/fs/cgroup}"
PROC="${PFT_RES_PROC:-/proc}"
read -r -a DOCKER <<< "${PFT_RES_DOCKER:-docker}"
STDOUT=0

die() { printf 'pft-resources: %s\n' "$1" >&2; exit "${2:-3}"; }
ERR="" FAILED=0
fail() { FAILED=1; [ -n "$ERR" ] || ERR="${1:-unspecified read error}"; } # first error wins; an empty message still fails

# --- readers: print the value (rc 0) or the error message (rc 1). They run in $(...) subshells, so they must
# not call fail() themselves (the ERR it sets would be lost with the subshell); the caller passes the message on -------------------------------------------------------------
read_num() { # FILE -> non-negative integer, or "max" if ALLOW_MAX=1
  local v
  if ! v="$(cat "$1" 2>/dev/null)"; then printf '%s' "cannot read $1"; return 1; fi
  v="${v%%[[:space:]]*}"
  if [ "${ALLOW_MAX:-0}" = 1 ] && [ "$v" = max ]; then printf 'max'; return 0; fi
  [[ "$v" =~ ^[0-9]+$ ]] || { printf '%s' "malformed $1: '${v:0:40}'"; return 1; }
  printf '%s' "$v"
}
read_kv() { # FILE KEY -> integer value of "KEY N" line
  local v
  [ -r "$1" ] || { printf '%s' "cannot read $1"; return 1; }
  v="$(awk -v k="$2" '$1 == k { print $2; exit }' "$1")"
  [[ "$v" =~ ^[0-9]+$ ]] || { printf '%s' "malformed $1: no integer for $2"; return 1; }
  printf '%s' "$v"
}
# PSI line: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0" -> "avg10 avg60 avg300 total" ; rc 2 = file absent
read_psi() { # FILE KIND
  local v
  [ -e "$1" ] || return 2
  [ -r "$1" ] || { printf '%s' "cannot read $1"; return 1; }
  v="$(awk -v k="$2" '$1 == k {
        n = 0
        for (i = 2; i <= NF; i++) { split($i, a, "="); m[a[1]] = a[2]; n++ }
        if (m["avg10"] ~ /^[0-9]+\.[0-9]+$/ && m["avg60"] ~ /^[0-9]+\.[0-9]+$/ && m["avg300"] ~ /^[0-9]+\.[0-9]+$/ && m["total"] ~ /^[0-9]+$/)
          print m["avg10"], m["avg60"], m["avg300"], m["total"]
        exit }' "$1")"
  [ -n "$v" ] || { printf '%s' "malformed $1: no valid '$2' line"; return 1; }
  printf '%s' "$v"
}

usec_to_s() { awk -v u="$1" 'BEGIN { printf "%.6f", u / 1000000 }'; }

# --- collection ----------------------------------------------------------------------------------------------
collect() {
  local now info pid cid oomk restarts cgrel cg main fds lim
  now="${PFT_RES_NOW:-$(date +%s)}"
  M=() # metric lines (without HELP/TYPE), rendered at the end
  L="container=\"$CONTAINER\""

  info="$("${DOCKER[@]}" inspect -f '{{.State.Pid}} {{.Id}} {{.State.OOMKilled}} {{.RestartCount}}' "$CONTAINER" 2>/dev/null)" \
    || { fail "docker inspect $CONTAINER failed"; return; }
  read -r pid cid oomk restarts <<< "$info"
  if ! [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then fail "container $CONTAINER not running (pid '$pid')"; return; fi
  M+=("pft_resources_container_restarts{$L} ${restarts:-0}")
  M+=("pft_resources_container_oom_killed{$L} $([ "$oomk" = true ] && echo 1 || echo 0)")
  M+=("pft_resources_container_info{$L,id=\"${cid:0:12}\"} 1")

  # cgroup v2: a single "0::/path" line
  cgrel="$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "$PROC/$pid/cgroup" 2>/dev/null)"
  [ -n "$cgrel" ] || { fail "no cgroup v2 entry in $PROC/$pid/cgroup"; return; }
  case "$cgrel" in *..*) fail "suspicious cgroup path $cgrel"; return ;; esac
  cg="$CGROOT$cgrel"
  [ -d "$cg" ] || { fail "cgroup dir missing: $cg"; return; }

  # memory
  local cur max peak memtotal v ev
  cur="$(read_num "$cg/memory.current")" || { fail "$cur"; return; }
  max="$(ALLOW_MAX=1 read_num "$cg/memory.max")" || { fail "$max"; return; }
  if [ "$max" = max ]; then
    memtotal="$(awk '$1 == "MemTotal:" { print $2 * 1024; exit }' "$PROC/meminfo" 2>/dev/null)"
    [[ "$memtotal" =~ ^[0-9]+$ ]] || { fail "memory.max is max and $PROC/meminfo has no MemTotal"; return; }
    max="$memtotal"; M+=("pft_resources_limit_set{$L,resource=\"memory\"} 0")
  else
    M+=("pft_resources_limit_set{$L,resource=\"memory\"} 1")
  fi
  M+=("pft_resources_memory_current_bytes{$L} $cur" "pft_resources_memory_max_bytes{$L} $max")
  if [ -e "$cg/memory.peak" ]; then
    peak="$(read_num "$cg/memory.peak")" || { fail "$peak"; return; }
    M+=("pft_resources_memory_peak_bytes{$L} $peak" "pft_resources_file_supported{$L,file=\"memory.peak\"} 1")
  else
    M+=("pft_resources_file_supported{$L,file=\"memory.peak\"} 0")
  fi
  for v in anon file kernel_stack sock shmem; do
    ev="$(read_kv "$cg/memory.stat" "$v")" || { fail "$ev"; return; }
    M+=("pft_resources_memory_stat_bytes{$L,item=\"$v\"} $ev")
  done
  for v in oom_kill oom max high; do
    ev="$(read_kv "$cg/memory.events" "$v")" || { fail "$ev"; return; }
    M+=("pft_resources_memory_events_total{$L,event=\"$v\"} $ev")
  done
  MEM_CUR=$cur MEM_MAX=$max
  OOM_KILL="$(read_kv "$cg/memory.events" oom_kill)" || { fail "$OOM_KILL"; return; }

  # cpu
  local usage periods throttled tusec quota period
  usage="$(read_kv "$cg/cpu.stat" usage_usec)" || { fail "$usage"; return; }
  periods="$(read_kv "$cg/cpu.stat" nr_periods)" || { fail "$periods"; return; }
  throttled="$(read_kv "$cg/cpu.stat" nr_throttled)" || { fail "$throttled"; return; }
  tusec="$(read_kv "$cg/cpu.stat" throttled_usec)" || { fail "$tusec"; return; }
  read -r quota period < "$cg/cpu.max" 2>/dev/null || { fail "cannot read $cg/cpu.max"; return; }
  if [ "$quota" = max ]; then
    M+=("pft_resources_limit_set{$L,resource=\"cpu\"} 0" "pft_resources_cpu_limit_cores{$L} 0")
  elif [[ "$quota" =~ ^[0-9]+$ && "$period" =~ ^[0-9]+$ && "$period" -gt 0 ]]; then
    M+=("pft_resources_limit_set{$L,resource=\"cpu\"} 1"
        "pft_resources_cpu_limit_cores{$L} $(awk -v q="$quota" -v p="$period" 'BEGIN { printf "%.3f", q / p }')")
  else
    fail "malformed $cg/cpu.max: '$quota $period'"; return
  fi
  M+=("pft_resources_cpu_usage_seconds_total{$L} $(usec_to_s "$usage")"
      "pft_resources_cpu_periods_total{$L} $periods"
      "pft_resources_cpu_throttled_periods_total{$L} $throttled"
      "pft_resources_cpu_throttled_seconds_total{$L} $(usec_to_s "$tusec")")
  CPU_USEC=$usage THR=$throttled

  # pids
  local pcur pmax
  pcur="$(read_num "$cg/pids.current")" || { fail "$pcur"; return; }
  pmax="$(ALLOW_MAX=1 read_num "$cg/pids.max")" || { fail "$pmax"; return; }
  if [ "$pmax" = max ]; then
    pmax="$(read_num "$PROC/sys/kernel/pid_max")" || { fail "$pmax"; return; }
    M+=("pft_resources_limit_set{$L,resource=\"pids\"} 0")
  else
    M+=("pft_resources_limit_set{$L,resource=\"pids\"} 1")
  fi
  M+=("pft_resources_pids_current{$L} $pcur" "pft_resources_pids_max{$L} $pmax")
  PIDS=$pcur PIDS_MAX=$pmax

  # PSI (optional per resource)
  local r k p rc a10 a60 a300 tot
  PSI_H=""
  for r in memory cpu io; do
    for k in some full; do
      p="$(read_psi "$cg/$r.pressure" "$k")"; rc=$?
      if [ "$rc" = 2 ]; then
        [ "$k" = some ] && M+=("pft_resources_file_supported{$L,file=\"$r.pressure\"} 0")
        continue
      fi
      [ "$rc" = 0 ] || { fail "$p"; return; }
      read -r a10 a60 a300 tot <<< "$p"
      [ "$k" = some ] && M+=("pft_resources_file_supported{$L,file=\"$r.pressure\"} 1")
      M+=("pft_resources_pressure_avg10_ratio{$L,resource=\"$r\",kind=\"$k\"} $(awk -v x="$a10" 'BEGIN { printf "%.4f", x / 100 }')"
          "pft_resources_pressure_avg60_ratio{$L,resource=\"$r\",kind=\"$k\"} $(awk -v x="$a60" 'BEGIN { printf "%.4f", x / 100 }')"
          "pft_resources_pressure_avg300_ratio{$L,resource=\"$r\",kind=\"$k\"} $(awk -v x="$a300" 'BEGIN { printf "%.4f", x / 100 }')"
          "pft_resources_pressure_stall_seconds_total{$L,resource=\"$r\",kind=\"$k\"} $(usec_to_s "$tot")")
      [ "$k" = some ] && PSI_H="$PSI_H,\"psi_${r}_some_avg60\":$a60"
    done
  done

  # fds of the main process (PROC_NAME; first match among cgroup.procs, else the container's init pid)
  main=""
  while read -r p; do
    [ "$(cat "$PROC/$p/comm" 2>/dev/null)" = "$PROC_NAME" ] && { main="$p"; break; }
  done < "$cg/cgroup.procs"
  [ -n "$main" ] || { fail "no process named $PROC_NAME in $cg/cgroup.procs"; return; }
  if ! [ -d "$PROC/$main/fd" ] || ! [ -r "$PROC/$main/fd" ]; then fail "cannot list $PROC/$main/fd"; return; fi
  fds="$(find "$PROC/$main/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
  lim="$(awk '/^Max open files/ { print $4; exit }' "$PROC/$main/limits" 2>/dev/null)"
  [ "$lim" = unlimited ] && lim=0
  [[ "$lim" =~ ^[0-9]+$ ]] || { fail "malformed $PROC/$main/limits (Max open files)"; return; }
  M+=("pft_resources_fd_open{$L} $fds" "pft_resources_fd_limit_soft{$L} $lim")
  FDS=$fds FD_LIM=$lim
  HIST="{\"ts\":$now,\"container\":\"$CONTAINER\",\"id\":\"${cid:0:12}\",\"restarts\":${restarts:-0},\"mem_current\":$MEM_CUR,\"mem_max\":$MEM_MAX,\"oom_kill\":$OOM_KILL,\"cpu_usec\":$CPU_USEC,\"nr_throttled\":$THR,\"pids\":$PIDS,\"pids_max\":$PIDS_MAX,\"fds\":$FDS,\"fd_limit\":$FD_LIM$PSI_H}"
}

HELP="pft_resources_container_restarts docker RestartCount of the container
pft_resources_container_oom_killed 1 if docker State.OOMKilled is true (the last run of the main process was OOM-killed)
pft_resources_container_info container id (first 12 hex) of the running container; changes on recreate
pft_resources_limit_set 1 if the cgroup has its own limit for the resource, 0 if it is max (host value exported)
pft_resources_memory_current_bytes cgroup memory.current
pft_resources_memory_max_bytes cgroup memory.max (MemTotal if max)
pft_resources_memory_peak_bytes cgroup memory.peak (kernel >= 5.19)
pft_resources_file_supported 1 if an optional cgroup file exists (memory.peak, *.pressure)
pft_resources_memory_stat_bytes selected memory.stat items
pft_resources_memory_events_total cgroup memory.events counters (reset when the container gets a new cgroup)
pft_resources_cpu_limit_cores cpu.max quota/period in cores (0 = no quota)
pft_resources_cpu_usage_seconds_total cpu.stat usage_usec in seconds
pft_resources_cpu_periods_total cpu.stat nr_periods (enforcement periods; 0 without a quota)
pft_resources_cpu_throttled_periods_total cpu.stat nr_throttled
pft_resources_cpu_throttled_seconds_total cpu.stat throttled_usec in seconds
pft_resources_pids_current cgroup pids.current
pft_resources_pids_max cgroup pids.max (kernel.pid_max if max)
pft_resources_pressure_avg10_ratio PSI avg10 as a 0-1 ratio
pft_resources_pressure_avg60_ratio PSI avg60 as a 0-1 ratio
pft_resources_pressure_avg300_ratio PSI avg300 as a 0-1 ratio
pft_resources_pressure_stall_seconds_total PSI total stall time in seconds
pft_resources_fd_open open file descriptors of the PROC_NAME process
pft_resources_fd_limit_soft soft RLIMIT_NOFILE of the PROC_NAME process (0 = unlimited)"

render() { # UP NOW -> full textfile body
  local up="$1" now="$2"
  printf '# pft-resources v%s (cgroup v2 collector, ../resources)\n' "$VERSION"
  printf '# HELP pft_resources_up 1 if every required cgroup/proc file was read and parsed\n# TYPE pft_resources_up gauge\n'
  printf 'pft_resources_up{container="%s"} %s\n' "$CONTAINER" "$up"
  printf '# HELP pft_resources_collect_timestamp_seconds Unix time of this collection\n'
  printf '# TYPE pft_resources_collect_timestamp_seconds gauge\npft_resources_collect_timestamp_seconds{container="%s"} %s\n' "$CONTAINER" "$now"
  [ "$up" = 1 ] || return 0
  # group each metric family together (the text format needs one contiguous block per name), first-seen order
  printf '%s\n' "${M[@]}" | awk -v help="$HELP" '
    BEGIN { n = split(help, h, "\n"); for (i = 1; i <= n; i++) { j = index(h[i], " "); if (j) H[substr(h[i], 1, j - 1)] = substr(h[i], j + 1) } }
    { n = $0; sub(/[{ ].*/, "", n); if (!(n in seen)) { seen[n] = ++k; names[k] = n }; body[n] = body[n] $0 "\n" }
    END { for (i = 1; i <= k; i++) { n = names[i]
            printf "# HELP %s %s\n# TYPE %s %s\n%s", n, (n in H ? H[n] : "pft-resources metric"), n, (n ~ /_total$/ ? "counter" : "gauge"), body[n] } }'
}

write_textfile() { # BODY
  local d="$TEXTFILE_DIR" f tmp
  f="pft_resources_${CONTAINER//[^A-Za-z0-9_-]/_}.prom"
  [ -d "$d" ] || die "textfile dir $d missing (is the pft exporter installed?)" 3
  tmp="$(mktemp "$d/.$f.XXXXXX")" || die "cannot write in $d" 3
  printf '%s\n' "$1" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$d/$f"
}

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    version) echo "pft-resources v$VERSION"; exit 0 ;;
    collect) ;;
    *) die "usage: pft-resources collect [--container NAME] [--textfile-dir DIR] [--history FILE] [--stdout] | version" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift 2 ;;
      --proc-name) PROC_NAME="${2:?}"; shift 2 ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift 2 ;;
      --history) HISTORY="${2:?}"; shift 2 ;;
      --stdout) STDOUT=1; shift ;;
      *) die "unknown option $1" ;;
    esac
  done
  [[ "$CONTAINER" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "bad container name"
  local now body up=1
  now="${PFT_RES_NOW:-$(date +%s)}"
  HIST=""
  collect
  [ "$FAILED" = 0 ] || up=0
  body="$(render "$up" "$now")"
  if [ "$STDOUT" = 1 ]; then printf '%s\n' "$body"; else write_textfile "$body"; fi
  if [ "$up" = 1 ] && [ -n "$HISTORY" ]; then
    printf '%s\n' "$HIST" >> "$HISTORY" || die "cannot append to $HISTORY" 3
  fi
  [ "$up" = 1 ] || { printf 'pft-resources: %s: %s\n' "$CONTAINER" "$ERR" >&2; exit 1; }
}

main "$@"
