#!/usr/bin/env bash
# pft-coredump: can a crash of postfiatd (validator or sentry) write its process memory - including the node and
# validator key material it holds - to disk, now or after the next reboot / container re-create?
# Ubuntu 22.04, Docker with a compose container (postfiatd) or a `docker run` container (postfiatd-sentry).
#
# Usage: pft-coredump audit [--json]
#        pft-coredump apply --yes [--recreate]   (root; --recreate only for a `docker run` container, inside pft-maint)
#        pft-coredump rollback --yes             (root; restores the exact snapshot taken by the last apply)
#
#  audit  read-only. One line per check, PASS / WARN / FAIL / INFO, then RESULT. Core files are only counted and
#         sized, never opened. Exit: 0 PASS (INFO allowed), 1 WARN (no FAIL), 2 FAIL, 3 error (container missing,
#         docker or /proc unreadable), 65 usage.
#   CD01 pattern-live    kernel.core_pattern now: non-writing pipe (|/bin/false, |/bin/true, or systemd-coredump with
#                        CD05 PASS) = PASS; a file pattern (e.g. "core": the dump lands in the crashing process's cwd)
#                        or a pipe to another handler (apport writes /var/crash) = FAIL
#   CD02 pattern-boot    the value the next boot sets: last kernel.core_pattern across sysctl.d (same order as
#                        systemd-sysctl: /etc > /run > /usr/local/lib > /usr/lib > /lib per file name, names sorted),
#                        then apport's init script when enabled=1 (it rewrites the pattern) -> same rule as CD01
#   CD03 suid-dumpable   fs.suid_dumpable = 0 PASS; 1/2 WARN (setuid/credential-changing processes may dump)
#   CD04 apport          not installed or enabled=0 in /etc/default/apport = PASS; enabled = FAIL
#   CD05 systemd-coredump not installed = PASS (n/a); installed: Storage=none and ProcessSizeMax=0 = PASS, else FAIL
#   CD06 rlimit-live     RLIMIT_CORE of every process in the container's cgroup (/proc/PID/limits): soft and hard 0 =
#                        PASS; soft 0, hard > 0 = WARN (the process could raise it); soft > 0 = FAIL
#   CD07 dump-filter     /proc/PID/coredump_filter of the container's PID 1: INFO when CD06 PASS (no file dump can
#                        happen); WARN when a dump is possible and anonymous memory (bits 0/1) is included
#   CD08 container-ulimit  the running container's HostConfig.Ulimits core = 0:0 PASS; otherwise FAIL, or WARN
#                        "pending re-create" when CD09 already passes (compose overlay written, container not yet
#                        re-created) - the state after `apply` on a validator that must not be restarted
#   CD09 recreate-ulimit  what the NEXT re-create gives: compose = `docker compose config` ulimits core 0/0 (its JSON
#                        omits zero fields: core {} = soft 0, hard 0; compose 2.40 also normalizes `core: 0` to it); docker run
#                        = core 0:0 in HostConfig AND every installed recreate tool (RECREATE_TOOLS) copies
#                        HostConfig.Ulimits (grep), a tool that drops it = FAIL naming it
#   CD10 docker-default  INFO: LimitCORE of docker.service / containerd.service and daemon.json default-ulimits (what
#                        a container gets without its own ulimit); never gates, CD08/CD09 cover postfiatd
#   CD11 swap            no active swap, or only dm-crypt swap = PASS; plain swap = WARN (memory pages can reach disk)
#   CD12 hibernate       PASS when no hibernation image can be written (no swap, or /sys/power/disk [disabled], or
#                        AllowHibernation=no in /etc/systemd/sleep.conf[.d]); otherwise WARN
#   CD13 core-files      count and total size of existing core/crash files (core, core.*, *.core, *.crash) in
#                        SCAN_DIRS (maxdepth SCAN_DEPTH): 0 = PASS, else FAIL (names are not printed)
#
#  apply  root + --yes, refused otherwise (exit 4). Takes a snapshot to STATE_DIR/snap-<id>/ first (live
#         core_pattern, the drop-in file or its absence, systemd-coredump drop-in, soft:hard RLIMIT_CORE of every
#         container process, compose .env + overlay, or the container's Ulimits), then:
#           1. writes /etc/sysctl.d/60-pft-coredump.conf (kernel.core_pattern=|/bin/false) and sets it live
#           2. if systemd-coredump is installed: /etc/systemd/coredump.conf.d/60-pft-coredump.conf Storage=none,
#              ProcessSizeMax=0
#           3. `prlimit --pid P --core=0:0` for every process of the container (live, no restart)
#           4. persistent core 0:0: compose = docker-compose.coredump.yml + COMPOSE_FILE, validated with `docker
#              compose config`, NEVER `up` (takes effect at the next planned re-create; CD08 WARN until then);
#              docker run = with --recreate (and `pft-maint active`): stop, rename to NAME-precd-<id>, `docker run`
#              with the same arguments + --ulimit core=0:0, gate (re-created, Ulimits core 0:0, every other setting
#              unchanged, server_state full within RECOVER_TIMEOUT); gate fail -> the old container is restored.
#              Without --recreate the docker run container is left alone (CD08/CD09 FAIL, reported).
#         Exit: 0 applied, 1 a step failed (everything rolled back), 4 refused, 5 rollback failed, 64 error.
#  rollback  restores the snapshot of the last apply exactly: drop-ins back (or removed), live core_pattern, each
#         process's previous soft:hard RLIMIT_CORE (processes that no longer exist are reported), compose files;
#         a container re-created by apply is re-created with its previous Ulimits (same gate). Exit as apply.
#  A second apply after a rollback (re-apply) takes a new snapshot. apply while an un-rolled-back apply exists = refused.
#
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  STATE_DIR (/var/lib/pft-coredump)  RECOVER_TIMEOUT (900)
#      POLL_SEC (5)  SCAN_DEPTH (3)  SCAN_DIRS (newline list; default /var/crash, /var/lib/systemd/coredump, /root,
#      /tmp, /var/tmp, /opt/postfiatd, the container's host-side mount sources)  RECREATE_TOOLS (newline list,
#      default /usr/local/bin/pft-seccomp, /usr/local/bin/pft-apparmor, /usr/local/bin/pft-shutdown)
#      SECCOMP_FILE (/etc/pft-seccomp/pft-postfiatd.json: re-create of a container with a stored seccomp profile)
#      Test hooks: PFT_COREDUMP_ROOT (path prefix for /proc, /etc, /sys, /var, /opt, ...)  PFT_COREDUMP_DOCKER,
#      _PRLIMIT, _SYSCTL, _SYSTEMCTL, _MAINT, _DPKG (commands)  PFT_COREDUMP_UID (uid seen by
#      the root check)  PFT_COREDUMP_RPC (command printing server_info JSON)
#      PFT_COREDUMP_INJECT=gate (apply's re-create gate fails: automatic-rollback drill)

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_COREDUMP_ROOT:-}"
DOCKER="${PFT_COREDUMP_DOCKER:-docker}"
PRLIMIT="${PFT_COREDUMP_PRLIMIT:-prlimit}"
SYSCTL="${PFT_COREDUMP_SYSCTL:-sysctl}"
SYSTEMCTL="${PFT_COREDUMP_SYSTEMCTL:-systemctl}"
MAINT="${PFT_COREDUMP_MAINT:-pft-maint}"
DPKG="${PFT_COREDUMP_DPKG:-dpkg-query}"
UID_NOW="${PFT_COREDUMP_UID:-$(id -u)}"
STATE_DIR="$R${STATE_DIR:-/var/lib/pft-coredump}"
RECOVER_TIMEOUT="${RECOVER_TIMEOUT:-900}"
POLL_SEC="${POLL_SEC:-5}"
SCAN_DEPTH="${SCAN_DEPTH:-3}"
SECCOMP_FILE="${SECCOMP_FILE:-/etc/pft-seccomp/pft-postfiatd.json}"
RECREATE_TOOLS="${RECREATE_TOOLS:-/usr/local/bin/pft-seccomp
/usr/local/bin/pft-apparmor
/usr/local/bin/pft-shutdown}"
DROPIN=/etc/sysctl.d/60-pft-coredump.conf
CD_DROPIN=/etc/systemd/coredump.conf.d/60-pft-coredump.conf
OVERLAY=docker-compose.coredump.yml
SAFE_PATTERN='|/bin/false'
NOJ='{}'

die() { echo "pft-coredump: $*" >&2; exit "${2:-3}"; }
ts() { date -u +%FT%TZ; }
usage() { sed -n '5,7p' "$0" | sed 's/^# //' >&2; exit 65; }
inspect0() { "$DOCKER" inspect "$1" 2>/dev/null | jq -c '.[0] // empty' 2>/dev/null; }

detect_container() {
  [ -n "${CONTAINER:-}" ] && return 0
  local c
  for c in postfiatd postfiatd-sentry; do
    [ -n "$(inspect0 "$c")" ] && { CONTAINER="$c"; return 0; }
  done
  die "no postfiatd or postfiatd-sentry container (set CONTAINER)" 3
}

# --- small readers (all paths under $R) ---------------------------------------------------------------------
rd() { [ -r "$R$1" ] && cat -- "$R$1" 2>/dev/null; }
pkg_installed() { "$DPKG" -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
# kernel.core_pattern classification: safe | file | pipe:<prog>
pattern_kind() {
  local p="$1" prog
  case "$p" in
    '|'*) prog="${p#|}"; prog="${prog%% *}"
          case "$prog" in
            /bin/false|/usr/bin/false|/bin/true|/usr/bin/true) echo safe ;;
            */systemd-coredump) [ "$CD05" = PASS ] && echo safe || echo "pipe:$prog" ;;
            *) echo "pipe:$prog" ;;
          esac ;;
    *) echo file ;;
  esac
}
# last value of KEY over the sysctl.d set + /etc/sysctl.conf, in systemd-sysctl order -> "value<TAB>file" or nothing
sysctl_boot() { # KEY
  local key="$1" d f n out=""
  local -A pick=()
  for d in /lib/sysctl.d /usr/lib/sysctl.d /usr/local/lib/sysctl.d /run/sysctl.d /etc/sysctl.d; do
    for f in "$R$d"/*.conf; do [ -e "$f" ] || continue; pick["$(basename "$f")"]="$f"; done   # later dir wins
  done
  [ -e "$R/etc/sysctl.conf" ] && [ -z "${pick[99-sysctl.conf]:-}" ] && pick["zz-sysctl.conf"]="$R/etc/sysctl.conf"
  for n in $(printf '%s\n' "${!pick[@]}" | LC_ALL=C sort); do
    f="${pick[$n]}"
    while IFS= read -r line; do
      line="${line#"${line%%[![:space:]]*}"}"
      case "$line" in '#'*|';'*|'') continue ;; esac
      local k="${line%%=*}" v="${line#*=}"
      k="${k%"${k##*[![:space:]]}"}"; k="${k#-}"; k="${k//\//.}"
      v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
      [ "$k" = "$key" ] && out="$v	${f#"$R"}"
    done < "$f"
  done
  [ -n "$out" ] && printf '%s\n' "$out"
}
apport_enabled() { # 0 = enabled at boot (installed and enabled != 0)
  pkg_installed apport || return 1
  local e; e="$(sed -n 's/^[[:space:]]*enabled[[:space:]]*=[[:space:]]*//p' "$R/etc/default/apport" 2>/dev/null | tail -1)"
  [ "${e:-1}" != 0 ]
}
coredump_conf() { # KEY -> effective value from coredump.conf + coredump.conf.d (last wins)
  local f v last=""
  for f in "$R/etc/systemd/coredump.conf" "$R"/etc/systemd/coredump.conf.d/*.conf; do
    [ -r "$f" ] || continue
    v="$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$f" | tail -1)"; [ -n "$v" ] && last="$v"
  done
  echo "$last"
}
# soft and hard RLIMIT_CORE of PID ("soft hard", "unlimited" kept as is) or nothing
core_limit() { awk '/^Max core file size/ { print $5, $6 }' "$R/proc/$1/limits" 2>/dev/null; }
# every PID in the same cgroup as PID1 (the container's processes), PID1 first
container_pids() { # PID1
  local cg p; cg="$(cat "$R/proc/$1/cgroup" 2>/dev/null)" || return 1
  [ -n "$cg" ] || return 1
  echo "$1"
  for p in "$R"/proc/[0-9]*; do
    p="${p##*/}"; [ "$p" = "$1" ] && continue
    [ "$(cat "$R/proc/$p/cgroup" 2>/dev/null)" = "$cg" ] && echo "$p"
  done
}
limit_ok() { [ "$1" = 0 ]; }

# --- audit --------------------------------------------------------------------------------------------------
RES=()
CODE=0
add() { RES+=("$1|$2|$3"); case "$1" in FAIL) CODE=2 ;; WARN) [ "$CODE" -lt 1 ] && CODE=1 ;; esac; }

audit_checks() {
  local i pid1 p kind boot bv bf n soft hard bad warn tot filt swap t miss sz cnt dirs d
  RES=(); CODE=0
  i="$(inspect0 "$CONTAINER")"; [ -n "$i" ] || die "container $CONTAINER missing" 3
  pid1="$(jq -r '.State.Pid // 0' <<<"$i")"
  [ "$pid1" -gt 0 ] 2>/dev/null && [ -r "$R/proc/$pid1/limits" ] || die "container $CONTAINER not running or /proc/$pid1 unreadable" 3

  # CD05 first: CD01/CD02 accept systemd-coredump only when its storage is off
  if pkg_installed systemd-coredump; then
    local st psm; st="$(coredump_conf Storage)"; psm="$(coredump_conf ProcessSizeMax)"
    [ "$st" = none ] && [ "$psm" = 0 ] && CD05=PASS || CD05=FAIL
    add "$CD05" "CD05 systemd-coredump" "installed: Storage=${st:-external(default)} ProcessSizeMax=${psm:-default}"
  else
    CD05=PASS; add PASS "CD05 systemd-coredump" "not installed (n/a)"
  fi

  p="$(rd /proc/sys/kernel/core_pattern)"; kind="$(pattern_kind "$p")"
  case "$kind" in
    safe) add PASS "CD01 pattern-live" "kernel.core_pattern '$p' (pipe, nothing written)" ;;
    file) add FAIL "CD01 pattern-live" "kernel.core_pattern '$p' writes a core file (relative = the crashing process's cwd)" ;;
    *)    add FAIL "CD01 pattern-live" "kernel.core_pattern pipes to ${kind#pipe:} (a handler that stores dumps)" ;;
  esac

  boot="$(sysctl_boot kernel.core_pattern)"; bv="${boot%%	*}"; bf="${boot#*	}"
  [ -n "$boot" ] || { bv=core; bf="kernel default"; }
  if apport_enabled; then
    add FAIL "CD02 pattern-boot" "apport enabled: its init script sets kernel.core_pattern to its handler at boot (over $bf)"
  else
    kind="$(pattern_kind "$bv")"
    case "$kind" in
      safe) add PASS "CD02 pattern-boot" "next boot: '$bv' from $bf" ;;
      *)    add FAIL "CD02 pattern-boot" "next boot: '$bv' from $bf ($kind)" ;;
    esac
  fi

  n="$(rd /proc/sys/fs/suid_dumpable)"
  [ "$n" = 0 ] && add PASS "CD03 suid-dumpable" "fs.suid_dumpable 0" \
    || add WARN "CD03 suid-dumpable" "fs.suid_dumpable ${n:-unreadable} (setuid / credential-changing processes may dump)"

  if ! pkg_installed apport; then add PASS "CD04 apport" "not installed"
  elif apport_enabled; then add FAIL "CD04 apport" "installed and enabled (/etc/default/apport)"
  else add PASS "CD04 apport" "installed, enabled=0"; fi

  bad=0; warn=0; tot=0
  while read -r p; do
    [ -n "$p" ] || continue
    read -r soft hard <<<"$(core_limit "$p")"
    [ -n "${soft:-}" ] || continue
    tot=$((tot + 1))
    if ! limit_ok "$soft"; then bad=$((bad + 1)); elif ! limit_ok "$hard"; then warn=$((warn + 1)); fi
  done < <(container_pids "$pid1")
  [ "$tot" -gt 0 ] || die "no readable process limits for $CONTAINER" 3
  read -r soft hard <<<"$(core_limit "$pid1")"
  if [ "$bad" -gt 0 ]; then add FAIL "CD06 rlimit-live" "$bad/$tot container processes with RLIMIT_CORE soft > 0 (PID 1: $soft:$hard)"
  elif [ "$warn" -gt 0 ]; then add WARN "CD06 rlimit-live" "$tot/$tot soft 0, $warn with hard > 0 (PID 1: $soft:$hard; can be raised)"
  else add PASS "CD06 rlimit-live" "$tot/$tot container processes RLIMIT_CORE 0:0"; fi
  local cd06="${RES[-1]%%|*}"

  filt="$(rd "/proc/$pid1/coredump_filter")"
  if [ "$cd06" = PASS ]; then add INFO "CD07 dump-filter" "coredump_filter ${filt:-?} (no dump possible: CD06 PASS)"
  elif [ -n "$filt" ] && [ $((16#$filt & 3)) -ne 0 ]; then
    add WARN "CD07 dump-filter" "coredump_filter $filt includes anonymous memory (heap, where keys live)"
  else add INFO "CD07 dump-filter" "coredump_filter ${filt:-?} (anonymous memory excluded)"; fi

  local cur nxt kindc
  cur="$(jq -r '[.HostConfig.Ulimits // [] | .[] | select(.Name == "core") | "\(.Soft):\(.Hard)"] | first // "unset"' <<<"$i")"
  kindc="$( [ -n "$(jq -r '.Config.Labels["com.docker.compose.project"] // ""' <<<"$i")" ] && echo compose || echo run)"
  if [ "$kindc" = compose ]; then
    local wd; wd="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"] // ""' <<<"$i")"
    nxt="$( cd "$R$wd" 2>/dev/null && "$DOCKER" compose config --format json 2>/dev/null \
      | jq -r --arg s "$(jq -r '.Config.Labels["com.docker.compose.service"]' <<<"$i")" \
          '.services[$s].ulimits.core | if . == null then "unset" elif type == "object" then "\(.soft // 0):\(.hard // 0)" else "\(.):\(.)" end' 2>/dev/null)"
    [ -n "$nxt" ] || nxt=error
    [ "$nxt" = 0:0 ] && CD09=PASS || CD09=FAIL
    local cd09msg="compose config ($wd) ulimits core $nxt"
  else
    miss=""
    while IFS= read -r t; do
      [ -n "$t" ] && [ -f "$R$t" ] || continue
      grep -q 'HostConfig.Ulimits' "$R$t" || miss+=" $(basename "$t")"
    done <<<"$RECREATE_TOOLS"
    if [ "$cur" = 0:0 ] && [ -z "$miss" ]; then CD09=PASS; local cd09msg="docker run: HostConfig core 0:0, every installed recreate tool copies Ulimits"
    else CD09=FAIL; local cd09msg="docker run: HostConfig core $cur${miss:+; recreate tools that drop Ulimits:$miss}"; fi
  fi
  if [ "$cur" = 0:0 ]; then add PASS "CD08 container-ulimit" "running container ulimit core 0:0"
  elif [ "$CD09" = PASS ]; then add WARN "CD08 container-ulimit" "running container core $cur, pending re-create (next re-create gives 0:0; live limit: CD06)"
  else add FAIL "CD08 container-ulimit" "running container ulimit core $cur"; fi
  add "$CD09" "CD09 recreate-ulimit" "$cd09msg"

  local dl cl du
  dl="$("$SYSTEMCTL" show docker -p LimitCORE --value 2>/dev/null)"; cl="$("$SYSTEMCTL" show containerd -p LimitCORE --value 2>/dev/null)"
  du="$(jq -r '."default-ulimits".core // empty | "\(.Soft):\(.Hard)"' "$R/etc/docker/daemon.json" 2>/dev/null)"
  add INFO "CD10 docker-default" "docker.service LimitCORE=${dl:-?} containerd.service LimitCORE=${cl:-?} daemon default-ulimits core=${du:-unset}"

  swap="$(awk 'NR > 1 { print $1 }' "$R/proc/swaps" 2>/dev/null)"
  if [ -z "$swap" ]; then add PASS "CD11 swap" "no active swap"
  else
    local plain=0 s
    while read -r s; do case "$s" in /dev/dm-*|/dev/mapper/*) ;; *) plain=$((plain + 1)) ;; esac; done <<<"$swap"
    [ "$plain" = 0 ] && add PASS "CD11 swap" "only dm-crypt/mapper swap" || add WARN "CD11 swap" "$plain plain swap device(s)/file(s): memory pages can reach disk"
  fi

  local hd ah
  hd="$(rd /sys/power/disk)"; ah="$(cat "$R/etc/systemd/sleep.conf" "$R"/etc/systemd/sleep.conf.d/*.conf 2>/dev/null | sed -n 's/^[[:space:]]*AllowHibernation[[:space:]]*=[[:space:]]*//p' | tail -1)"
  if [ -z "$swap" ]; then add PASS "CD12 hibernate" "no swap: no hibernation image can be written"
  elif [[ "$hd" == *"[disabled]"* ]] || [ "$ah" = no ]; then add PASS "CD12 hibernate" "hibernation disabled (${ah:+AllowHibernation=no }${hd:+/sys/power/disk $hd})"
  else add WARN "CD12 hibernate" "swap present and hibernation not disabled"; fi

  if [ -n "${SCAN_DIRS:-}" ]; then dirs="$SCAN_DIRS"
  else dirs="$(printf '%s\n' /var/crash /var/lib/systemd/coredump /root /tmp /var/tmp /opt/postfiatd; jq -r '.Mounts // [] | .[].Source' <<<"$i")"; fi
  cnt=0; sz=0
  while IFS= read -r d; do
    [ -n "$d" ] && [ -d "$R$d" ] || continue
    while read -r b; do cnt=$((cnt + 1)); sz=$((sz + b)); done < <(find "$R$d" -xdev -maxdepth "$SCAN_DEPTH" -type f \
      \( -name core -o -name 'core.[0-9]*' -o -name '*.core' -o -name '*.crash' \) -printf '%s\n' 2>/dev/null)
  done < <(printf '%s\n' "$dirs" | sort -u)
  [ "$cnt" = 0 ] && add PASS "CD13 core-files" "0 core/crash files in $(printf '%s\n' "$dirs" | grep -c .) scanned dirs (depth $SCAN_DEPTH)" \
    || add FAIL "CD13 core-files" "$cnt core/crash file(s), $sz bytes (names withheld)"
}

sorted() { printf '%s\n' "${RES[@]}" | sort -t'|' -k2,2; }   # by check ID
print_text() {
  local s n m
  echo "pft-coredump audit - $(ts) - container $CONTAINER"
  while IFS='|' read -r s n m; do printf '  [%s] %s: %s\n' "$s" "$n" "$m"; done < <(sorted)
  local f w; f="$(printf '%s\n' "${RES[@]}" | grep -c '^FAIL|')"; w="$(printf '%s\n' "${RES[@]}" | grep -c '^WARN|')"
  echo "RESULT: $(case "$CODE" in 0) echo PASS ;; 1) echo WARN ;; *) echo FAIL ;; esac) - $f fail, $w warn -> exit $CODE"
}
print_json() {
  sorted | jq -R 'split("|") | {status: .[0], id: (.[1] | split(" ")[0]), check: (.[1] | split(" ")[1]), detail: .[2]}' \
    | jq -s --arg c "$CONTAINER" --arg t "$(ts)" --argjson e "$CODE" '{tool: "pft-coredump", time: $t, container: $c, exit: $e, checks: .}'
}

# --- apply / rollback ---------------------------------------------------------------------------------------
SNAP=""
snap_put() { cp -p -- "$R$1" "$SNAP/files/$(echo "$1" | tr / _)" 2>/dev/null; }   # copy FILE into the snapshot
snap_get() { echo "$SNAP/files/$(echo "$1" | tr / _)"; }
rpc_info() { # server_info .result.info JSON or nothing (host RPC port, else docker exec curl as in shutdown/)
  local port
  if [ -n "${PFT_COREDUMP_RPC:-}" ]; then $PFT_COREDUMP_RPC 2>/dev/null
  else
    port="$("$DOCKER" port "$CONTAINER" 5005/tcp 2>/dev/null | sed -n 's/^127\.0\.0\.1://p' | head -1)"
    if [ -n "$port" ]; then curl -s -m 10 -d '{"method":"server_info"}' "http://127.0.0.1:$port/"
    else "$DOCKER" exec "$CONTAINER" curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005/; fi 2>/dev/null
  fi | jq -c '.result.info // empty' 2>/dev/null
}
is_full() { [ -n "$1" ] && jq -e '.server_state == "full" or .server_state == "proposing"' >/dev/null 2>&1 <<<"$1"; }

# configuration that a re-create must keep (everything but Ulimits and the container identity)
keep_sig() { jq -cS '{image: .Config.Image, cmd: .Config.Cmd, env: .Config.Env, user: .Config.User, stop: .Config.StopTimeout,
  restart: .HostConfig.RestartPolicy, log: .HostConfig.LogConfig, net: .HostConfig.NetworkMode, ports: .HostConfig.PortBindings,
  mounts: [.Mounts[]? | {Type, Source, Destination, RW}], capadd: .HostConfig.CapAdd, capdrop: .HostConfig.CapDrop,
  ro: .HostConfig.ReadonlyRootfs, tmpfs: .HostConfig.Tmpfs, pids: .HostConfig.PidsLimit, mem: .HostConfig.Memory,
  swap: .HostConfig.MemorySwap, cpu: .HostConfig.CpuShares, memres: .HostConfig.MemoryReservation, sec: .HostConfig.SecurityOpt}' <<<"$1"; }
ulimits_of() { jq -c '.HostConfig.Ulimits // []' <<<"$1"; }

# docker run args re-creating a `docker run` container exactly, with Ulimits = ULIMITS_JSON (same set as the
# recreate tools in seccomp/, apparmor/, shutdown/, plus Ulimits)
run_args() { # INSPECT0 IMAGE_ENV_JSON ULIMITS_JSON
  jq -r --argjson ienv "$2" --argjson ul "$3" --arg scf "$SECCOMP_FILE" '
    "--name=\(.Name[1:])",
    "--restart=\(.HostConfig.RestartPolicy.Name)\(if .HostConfig.RestartPolicy.Name == "on-failure" then ":\(.HostConfig.RestartPolicy.MaximumRetryCount)" else "" end)",
    (if (.Config.StopTimeout // null) != null then "--stop-timeout=\(.Config.StopTimeout)" else empty end),
    (if (.Config.StopSignal // "") != "" then "--stop-signal=\(.Config.StopSignal)" else empty end),
    (if (.Config.User // "") != "" then "--user=\(.Config.User)" else empty end),
    "--log-driver=\(.HostConfig.LogConfig.Type)",
    ((.HostConfig.LogConfig.Config // {}) | to_entries[] | "--log-opt=\(.key)=\(.value)"),
    (if (.HostConfig.NetworkMode // "default") != "default" then "--network=\(.HostConfig.NetworkMode)" else empty end),
    ((.HostConfig.PortBindings // {}) | to_entries[] | .key as $k | .value[]
      | "--publish=\(if (.HostIp // "") != "" then .HostIp + ":" else "" end)\(.HostPort):\($k | sub("/tcp$"; ""))"),
    (.Mounts // [] | .[] | if .Type == "volume" then "--volume=\(.Name):\(.Destination)\(if .RW then "" else ":ro" end)"
                           elif .Type == "bind" then "--volume=\(.Source):\(.Destination)\(if .RW then "" else ":ro" end)"
                           else empty end),
    (.Config.Env // [] | map(select(. as $e | $ienv | index($e) | not)) | .[] | "--env=\(.)"),
    (.HostConfig.CapDrop // [] | .[] | "--cap-drop=\(.)"),
    (.HostConfig.CapAdd // [] | .[] | "--cap-add=\(.)"),
    (if .HostConfig.ReadonlyRootfs then "--read-only" else empty end),
    (.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\(.key)\(if .value != "" then ":" + .value else "" end)"),
    (if (.HostConfig.PidsLimit // 0) > 0 then "--pids-limit=\(.HostConfig.PidsLimit)" else empty end),
    (if (.HostConfig.Memory // 0) > 0 then "--memory=\(.HostConfig.Memory)" else empty end),
    (if (.HostConfig.MemorySwap // 0) != 0 then "--memory-swap=\(.HostConfig.MemorySwap)" else empty end),
    (if (.HostConfig.CpuShares // 0) > 0 then "--cpu-shares=\(.HostConfig.CpuShares)" else empty end),
    (if (.HostConfig.MemoryReservation // 0) > 0 then "--memory-reservation=\(.HostConfig.MemoryReservation)" else empty end),
    ($ul[] | "--ulimit=\(.Name)=\(.Soft):\(.Hard)"),
    (.HostConfig.SecurityOpt // [] | .[] | if startswith("seccomp") then "--security-opt=seccomp=\($scf)" else "--security-opt=\(.)" end),
    .Config.Image, (.Config.Cmd // [])[]' <<<"$1"
}
show_args() { sed -E 's/^(--env=[^=]*)=.*/\1=<value>/; s/([0-9]{1,3}\.){3}[0-9]{1,3}/<redacted-ip>/g' | paste -sd' '; }

gate() { # WHAT BEFORE_STARTED WANT_ULIMITS_JSON SIG
  local i s info hard soft t0=$SECONDS
  while :; do
    i="$(inspect0 "$CONTAINER")"; hard=""; soft=""
    if [ -z "$i" ]; then hard=" container missing;"; else
      s="$(jq -r '.State.StartedAt // ""' <<<"$i")"; [ -n "$s" ] && [ "$s" != "$2" ] || hard+=" not re-created;"
      [ "$(ulimits_of "$i")" = "$3" ] || hard+=" Ulimits $(ulimits_of "$i") want $3;"
      [ "$(keep_sig "$i")" = "$4" ] || hard+=" configuration changed;"
      [ "${PFT_COREDUMP_INJECT:-}" = gate ] && hard+=" injected gate failure;"
    fi
    info="$(rpc_info)"; is_full "$info" || soft=" server_state $(jq -r '.server_state // "unreachable"' <<<"${info:-$NOJ}");"
    if [ -z "$hard$soft" ]; then
      echo "  $1 gate PASS after $((SECONDS - t0))s: re-created, Ulimits $3, configuration unchanged, server_state $(jq -r .server_state <<<"$info")"
      return 0
    fi
    [ -n "$hard" ] && break
    [ $((SECONDS - t0)) -ge "$RECOVER_TIMEOUT" ] && break
    sleep "$POLL_SEC"
  done
  echo "  $1 gate FAIL:$hard$soft"; return 1
}

# re-create a docker run container with ULIMITS_JSON; the previous container is kept stopped as NAME-precd-ID-HOW
recreate_run() { # ULIMITS_JSON HOW
  local i ienv old args
  i="$(inspect0 "$CONTAINER")"; [ -n "$i" ] || { echo "  container $CONTAINER missing"; return 1; }
  ienv="$("$DOCKER" image inspect "$(jq -r .Config.Image <<<"$i")" 2>/dev/null | jq -c '.[0].Config.Env // []' 2>/dev/null)"; [ -n "$ienv" ] || ienv='[]'
  mapfile -t args < <(run_args "$i" "$ienv" "$1")
  old="$CONTAINER-precd-$(basename "$SNAP")-$2"
  echo "  recreate: docker run -d $(printf '%s\n' "${args[@]}" | show_args)"
  "$DOCKER" stop -t "$(jq -r '.Config.StopTimeout // 30' <<<"$i")" "$CONTAINER" >/dev/null 2>&1 && "$DOCKER" rename "$CONTAINER" "$old" >/dev/null 2>&1 \
    && "$DOCKER" update --restart=no "$old" >/dev/null 2>&1 || { echo "  could not stop/rename $CONTAINER"; "$DOCKER" start "$CONTAINER" >/dev/null 2>&1; return 2; }
  echo "$old" > "$SNAP/old_container"
  "$DOCKER" run -d "${args[@]}" >/dev/null 2>&1 || { echo "  docker run failed"; return 1; }
}
restore_old() {
  local old rp; old="$(cat "$SNAP/old_container" 2>/dev/null)"; rp="$(jq -r .HostConfig.RestartPolicy.Name "$SNAP/inspect.json")"
  [ -n "$old" ] && [ -n "$(inspect0 "$old")" ] || { echo "  previous container ${old:-?} missing"; return 1; }
  "$DOCKER" rm -f "$CONTAINER" >/dev/null 2>&1
  "$DOCKER" rename "$old" "$CONTAINER" >/dev/null 2>&1 && "$DOCKER" update --restart="$rp" "$CONTAINER" >/dev/null 2>&1 \
    && "$DOCKER" start "$CONTAINER" >/dev/null 2>&1 && { echo "  previous container restored as $CONTAINER (restart=$rp)"; rm -f "$SNAP/old_container"; return 0; }
  echo "  restoring the previous container FAILED"; return 1
}
drop_old() {
  local old; old="$(cat "$SNAP/old_container" 2>/dev/null)"; [ -n "$old" ] || return 0
  "$DOCKER" rm "$old" >/dev/null 2>&1 && echo "  previous container $old removed (volumes kept)"; rm -f "$SNAP/old_container"
}

last_snap() { find "$STATE_DIR" -maxdepth 1 -type d -name 'snap-*' 2>/dev/null | LC_ALL=C sort | tail -1; }

take_snapshot() {
  local i pid1 p wd
  SNAP="$STATE_DIR/snap-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$SNAP/files" && chmod 700 "$STATE_DIR" "$SNAP" || return 1
  i="$(inspect0 "$CONTAINER")"; echo "$i" > "$SNAP/inspect.json"
  rd /proc/sys/kernel/core_pattern > "$SNAP/core_pattern"
  for p in "$DROPIN" "$CD_DROPIN"; do [ -e "$R$p" ] && snap_put "$p" || echo "$p" >> "$SNAP/absent"; done
  touch "$SNAP/absent"
  pid1="$(jq -r .State.Pid <<<"$i")"
  : > "$SNAP/limits"
  while read -r p; do [ -n "$p" ] || continue; printf '%s %s\n' "$p" "$(core_limit "$p")" >> "$SNAP/limits"; done < <(container_pids "$pid1")
  if [ -n "$(jq -r '.Config.Labels["com.docker.compose.project"] // ""' <<<"$i")" ]; then
    wd="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"]' <<<"$i")"
    echo compose > "$SNAP/kind"; echo "$wd" > "$SNAP/working_dir"
    jq -r '.Config.Labels["com.docker.compose.service"]' <<<"$i" > "$SNAP/service"
    snap_put "$wd/.env" || { echo "$wd/.env" >> "$SNAP/absent"; }
    [ -e "$R$wd/$OVERLAY" ] && snap_put "$wd/$OVERLAY" || echo "$wd/$OVERLAY" >> "$SNAP/absent"
  else
    echo run > "$SNAP/kind"
  fi
  echo "  snapshot $(basename "$SNAP"): core_pattern '$(cat "$SNAP/core_pattern")', $(grep -c . "$SNAP/limits") process limits, kind $(cat "$SNAP/kind")"
}
# put FILE back from the snapshot, or remove it if it did not exist
restore_file() { if grep -qxF -- "$1" "$SNAP/absent"; then rm -f -- "$R$1"; else cp -p -- "$(snap_get "$1")" "$R$1"; fi; }

set_pattern() { "$SYSCTL" -q -w "kernel.core_pattern=$1" >/dev/null 2>&1 && [ "$(rd /proc/sys/kernel/core_pattern)" = "$1" ]; }

do_rollback() { # auto|manual
  local how="$1" rc=0 p soft hard cur kind wd before i
  [ -n "$SNAP" ] || SNAP="$(last_snap)"
  [ -n "$SNAP" ] && [ -d "$SNAP" ] || { echo "$(ts) rollback: no snapshot - nothing to do"; return 0; }
  [ -e "$SNAP/rolled_back" ] && { echo "$(ts) rollback: $(basename "$SNAP") already rolled back - nothing to do"; return 0; }
  echo "$(ts) rollback ($how) to $(basename "$SNAP") on $CONTAINER"
  kind="$(cat "$SNAP/kind")"
  if [ "$kind" = run ] && [ -e "$SNAP/recreated" ]; then
    i="$(inspect0 "$CONTAINER")"; before="$(jq -r '.State.StartedAt // ""' <<<"${i:-$NOJ}")"
    if [ "$how" = auto ] && [ -e "$SNAP/old_container" ]; then restore_old || rc=5
    else
      recreate_run "$(ulimits_of "$(cat "$SNAP/inspect.json")")" restore \
        && gate rollback "$before" "$(ulimits_of "$(cat "$SNAP/inspect.json")")" "$(keep_sig "$(cat "$SNAP/inspect.json")")" && drop_old || rc=5
    fi
  fi
  if [ "$kind" = compose ]; then
    wd="$(cat "$SNAP/working_dir")"
    restore_file "$wd/.env" && restore_file "$wd/$OVERLAY" && echo "  compose: .env and $OVERLAY as before apply" || { echo "  compose files restore FAILED"; rc=5; }
    ( cd "$R$wd" && "$DOCKER" compose config -q >/dev/null 2>&1 ) || { echo "  docker compose config invalid after restore"; rc=5; }
  fi
  # live limits: the processes of the snapshot that still exist get their previous soft:hard back
  while read -r p soft hard; do
    [ -n "$p" ] || continue
    if [ ! -r "$R/proc/$p/limits" ]; then echo "  pid $p gone (limit $soft:$hard not restored)"; continue; fi
    [ "$soft" = unlimited ] && soft=unlimited; [ "$hard" = unlimited ] && hard=unlimited
    "$PRLIMIT" --pid "$p" --core="$soft:$hard" >/dev/null 2>&1 && cur="$(core_limit "$p")" && [ "$cur" = "$soft $hard" ] \
      || { echo "  pid $p: prlimit back to $soft:$hard FAILED (now ${cur:-?})"; rc=5; }
  done < "$SNAP/limits"
  echo "  live RLIMIT_CORE restored for $(grep -c . "$SNAP/limits") snapshot processes"
  restore_file "$DROPIN" && restore_file "$CD_DROPIN" || { echo "  drop-in restore FAILED"; rc=5; }
  set_pattern "$(cat "$SNAP/core_pattern")" && echo "  kernel.core_pattern '$(cat "$SNAP/core_pattern")' again" || { echo "  kernel.core_pattern restore FAILED"; rc=5; }
  [ "$rc" = 0 ] || { echo "$(ts) rollback RESULT: FAILED"; return 5; }
  date -u +%FT%TZ > "$SNAP/rolled_back"
  echo "$(ts) rollback RESULT: PASS - $(basename "$SNAP") restored"
}

do_apply() { # RECREATE(0|1)
  local i pid1 p kind wd eb before sig out n=0
  [ "$UID_NOW" = 0 ] || { echo "apply: refused - root required"; return 4; }
  p="$(last_snap)"
  if [ -n "$p" ] && [ ! -e "$p/rolled_back" ]; then echo "apply: refused - $(basename "$p") is applied and not rolled back (rollback first)"; return 4; fi
  i="$(inspect0 "$CONTAINER")"; [ -n "$i" ] || { echo "apply: refused - container $CONTAINER missing"; return 4; }
  kind="$( [ -n "$(jq -r '.Config.Labels["com.docker.compose.project"] // ""' <<<"$i")" ] && echo compose || echo run)"
  if [ "$1" = 1 ]; then
    [ "$kind" = run ] || { echo "apply: refused - --recreate is only for a docker run container (compose: files only, re-create at the next planned up)"; return 4; }
    "$MAINT" active >/dev/null 2>&1 || { echo "apply: refused - --recreate needs an active pft-maint window"; return 4; }
    is_full "$(rpc_info)" || { echo "apply: refused - node not full"; return 4; }
  fi
  echo "$(ts) apply on $CONTAINER ($kind)"
  take_snapshot || { echo "apply: snapshot failed"; return 64; }
  trap 'echo "$(ts) apply interrupted -> automatic rollback"; do_rollback auto; exit 6' INT TERM

  mkdir -p "$R/etc/sysctl.d" && printf '# written by pft-coredump apply; undo with: sudo pft-coredump rollback --yes\n# a crash must never write postfiatd memory (key material) to disk\nkernel.core_pattern = %s\n' "$SAFE_PATTERN" > "$R$DROPIN" \
    && set_pattern "$SAFE_PATTERN" && echo "  1. $DROPIN written, kernel.core_pattern '$SAFE_PATTERN' live" \
    || { echo "  1. core_pattern FAILED -> automatic rollback"; do_rollback auto; trap - INT TERM; return 1; }
  if pkg_installed systemd-coredump; then
    mkdir -p "$(dirname "$R$CD_DROPIN")" && printf '# written by pft-coredump apply\n[Coredump]\nStorage=none\nProcessSizeMax=0\n' > "$R$CD_DROPIN" \
      && echo "  2. $CD_DROPIN written (Storage=none, ProcessSizeMax=0)" || { echo "  2. FAILED -> automatic rollback"; do_rollback auto; trap - INT TERM; return 1; }
  else echo "  2. systemd-coredump not installed (n/a)"; fi
  pid1="$(jq -r .State.Pid <<<"$i")"
  while read -r p; do
    [ -n "$p" ] || continue
    "$PRLIMIT" --pid "$p" --core=0:0 >/dev/null 2>&1 && [ "$(core_limit "$p")" = "0 0" ] && n=$((n + 1)) \
      || { echo "  3. prlimit pid $p FAILED -> automatic rollback"; do_rollback auto; trap - INT TERM; return 1; }
  done < <(container_pids "$pid1")
  echo "  3. live RLIMIT_CORE 0:0 on $n container processes (no restart)"
  if [ "$kind" = compose ]; then
    wd="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"]' <<<"$i")"; eb="$(snap_get "$wd/.env")"
    printf '# written by pft-coredump apply; undo with: sudo pft-coredump rollback --yes\nservices:\n  %s:\n    ulimits:\n      core:\n        soft: 0\n        hard: 0\n' \
      "$(cat "$SNAP/service")" > "$R$wd/$OVERLAY" || { echo "  4. overlay FAILED -> automatic rollback"; do_rollback auto; trap - INT TERM; return 1; }
    out="$(grep '^COMPOSE_FILE=' "$eb" 2>/dev/null | tail -1)"; out="${out#COMPOSE_FILE=}"; [ -n "$out" ] || out=docker-compose.yml
    case ":$out:" in *":$OVERLAY:"*) ;; *) out="$out:$OVERLAY" ;; esac
    { grep -v '^COMPOSE_FILE=' "$eb" 2>/dev/null; echo "COMPOSE_FILE=$out"; } > "$R$wd/.env.tmp" && chmod --reference="$eb" "$R$wd/.env.tmp" 2>/dev/null; mv -f "$R$wd/.env.tmp" "$R$wd/.env"
    ( cd "$R$wd" && "$DOCKER" compose config -q >/dev/null 2>&1 ) || { echo "  4. docker compose config invalid -> automatic rollback"; do_rollback auto; trap - INT TERM; return 1; }
    echo "  4. $wd/$OVERLAY written, COMPOSE_FILE += $OVERLAY, compose config valid; container NOT re-created (next planned re-create applies it)"
  elif [ "$1" = 1 ]; then
    before="$(jq -r .State.StartedAt <<<"$i")"; sig="$(keep_sig "$i")"
    touch "$SNAP/recreated"
    recreate_run '[{"Name":"core","Hard":0,"Soft":0}]' apply && gate apply "$before" '[{"Name":"core","Hard":0,"Soft":0}]' "$sig" \
      || { echo "  4. re-create FAILED -> automatic rollback"; do_rollback auto; trap - INT TERM; return 1; }
    drop_old
    i="$(inspect0 "$CONTAINER")"; n=0
    while read -r p; do [ -n "$p" ] && [ "$(core_limit "$p")" = "0 0" ] && n=$((n + 1)); done < <(container_pids "$(jq -r .State.Pid <<<"$i")")
    echo "  4. re-created with --ulimit core=0:0 ($n processes 0:0)"
  else
    echo "  4. docker run container left as is (no --recreate): CD08/CD09 stay FAIL"
  fi
  trap - INT TERM
  echo "$(ts) apply RESULT: PASS - $(basename "$SNAP") applied"
}

# --- main ---------------------------------------------------------------------------------------------------
cmd="${1:-}"; shift || true
JSON=0; YES=0; RECREATE=0
for a in "$@"; do
  case "$a" in --json) JSON=1 ;; --yes) YES=1 ;; --recreate) RECREATE=1 ;; *) usage ;; esac
done
command -v jq >/dev/null || die "jq missing" 3
case "$cmd" in
  audit)
    detect_container; audit_checks
    [ "$JSON" = 1 ] && print_json || print_text
    exit "$CODE" ;;
  apply)
    [ "$YES" = 1 ] || { echo "apply: refused - needs --yes"; exit 4; }
    detect_container; do_apply "$RECREATE"; exit $? ;;
  rollback)
    [ "$YES" = 1 ] || { echo "rollback: refused - needs --yes"; exit 4; }
    [ "$UID_NOW" = 0 ] || { echo "rollback: refused - root required"; exit 4; }
    detect_container; do_rollback manual; exit $? ;;
  *) usage ;;
esac
