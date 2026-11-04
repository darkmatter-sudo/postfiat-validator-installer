#!/usr/bin/env bash
# pft-seccomp: replace Docker's default seccomp profile on the postfiatd container with a tailored syscall allowlist
# (pft-postfiatd.json) on a Post Fiat validator or sentry host (Ubuntu 22.04, kernel 5.15, Docker 29, postfiatd 1.0.9).
# Profile math lives in pft_seccomp.py (stdlib); this script runs containers, bpftrace and the audit log.
#
# Usage: sudo pft-seccomp learn --out DIR [--minutes N] [--phase census|log|both]   (throwaway containers only)
#        pft-seccomp generate --learn DIR [--margin FILE]     (final profile JSON on stdout)
#        pft-seccomp diff --learn DIR [--margin FILE]         (per-syscall table vs Docker's default, TSV)
#        pft-seccomp check FILE                               (structural checks, exit 1 + reason)
#
#  learn     Never touches the live container. Two phases on throwaways built from the live container's confine
#            arguments (same image by ID, caps, read-only root, tmpfs, pids/memory, no-new-privileges) with fresh
#            anonymous volumes, no published ports, AppArmor docker-default, named pftsc-learn-* and started by
#            image ID, so tools that pick "the" node by name or image (pft-integrity) never pick a throwaway.
#    census  throwaway under Docker's default seccomp profile (what the live node runs today); a system-wide
#            bpftrace counts raw_syscalls:sys_enter per (cgroup id, syscall nr); the throwaway's scope cgroup ids
#            (before and after its restart) select its rows. runc's own stages (comm runc:[0:PARENT], [1:CHILD],
#            [2:INIT]: namespace setup before the filter is loaded, e.g. unshare) are counted apart and left out: what
#            runc needs after the filter is loaded (openat2) shows up in the log phase. Syscalls that seccomp rejects never reach the tracepoint.
#    log     throwaway under a LEARN profile: defaultAction SCMP_ACT_LOG, ALLOW = census ∩ Docker-allowed, every
#            syscall Docker denies -> ERRNO EPERM, Docker's clone3 -> ENOSYS rule kept, flag
#            SECCOMP_FILTER_FLAG_LOG. So behaviour matches Docker's default and every syscall the census missed
#            (action log) or that is denied (action errno) leaves an audit type=1326 (SECCOMP) record. A watchdog
#            (every GUARD_SEC s) removes the throwaway as soon as more than LOG_MAX records arrived since T0: a
#            census gap on a hot syscall logs ~40k records/min and rotates the whole /var/log/audit set (dev run 1).
#            Both phases: wait for server_state full, exercise (RPC, cron identity switch, cron.hourly/daily, the
#            crontab logrotate line, a forced rotation, e2scrub's cron lines, the read-only commands the host add-ons
#            docker exec), docker restart, full again, keep running --minutes (default 65: real cron ticks), exercise.
#            Output in DIR: census.json, census-runc.json, cgroups, learn-profile.json, events.tsv, meta.json.
#  generate  final profile: defaultAction ERRNO (EPERM), SECCOMP_FILTER_FLAG_LOG (every denial is audited),
#            x86_64 only, ALLOW = (census ∪ log-phase LOG records ∪ margin) ∩ Docker-allowed for the container's
#            caps; Docker's argument-filtered rules (socket, personality, clone) and clone3 -> ENOSYS kept verbatim.
#            Deterministic: same inputs, same bytes.
#
# Exit codes: 0 ok, 1 findings / check failed, 2 error, 3 usage, 4 refused.
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  LEARN_DIR (/var/lib/pft-seccomp)  SYNC_BUDGET (1200 s)
#      LOG_MAX (2000 records)  GUARD_SEC (5)  HELPER (pft_seccomp.py next to this script, else /usr/local/lib/pft-seccomp/)
#      DOCKER_PROFILE (ref/docker-default-29.1.3.json next to this script, else /usr/local/lib/pft-seccomp/)
#      SYSCALL_TABLE (file from `pft_seccomp.py table`; default: generated from libseccomp.so.2 on each run)
#      Test hooks: PFT_SC_DOCKER / _BPFTRACE (commands)  PFT_SC_ROOT (prefix for /sys, /var/log/audit)  PFT_SC_NOW

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_SC_ROOT:-}"
DOCKER="${PFT_SC_DOCKER:-docker}"
BPFTRACE="${PFT_SC_BPFTRACE:-bpftrace}"
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
LIB=/usr/local/lib/pft-seccomp
HELPER="${HELPER:-$( [ -r "$HERE/pft_seccomp.py" ] && echo "$HERE/pft_seccomp.py" || echo "$LIB/pft_seccomp.py")}"
DOCKER_PROFILE="${DOCKER_PROFILE:-$( [ -r "$HERE/ref/docker-default-29.1.3.json" ] && echo "$HERE/ref/docker-default-29.1.3.json" || echo "$LIB/docker-default-29.1.3.json")}"
LEARN_DIR="${LEARN_DIR:-$R/var/lib/pft-seccomp}"
SYNC_BUDGET="${SYNC_BUDGET:-1200}"
LOG_MAX="${LOG_MAX:-2000}"
GUARD_SEC="${GUARD_SEC:-5}"
CFG_DIR="${CFG_DIR:-/etc/postfiatd}"   # inside the container (exercise_addons)
DB_DIR="${DB_DIR:-/var/lib/postfiatd/db}"
TABLE_TMP="$(mktemp "${TMPDIR:-/tmp}/pft-seccomp-table.XXXXXX")" || { echo "pft-seccomp: mktemp failed" >&2; exit 2; }
trap 'rm -f "$TABLE_TMP"' EXIT

die() { echo "pft-seccomp: $1" >&2; exit "${2:-2}"; }
now() { echo "${PFT_SC_NOW:-$(date +%s)}"; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
lx() { local rc; echo "\$ $*"; "$@"; rc=$?; echo "(exit $rc)"; return "$rc"; }
py() { python3 -I "$HELPER" "$@"; }

pick_container() {
  [ -n "${CONTAINER:-}" ] && { echo "$CONTAINER"; return; }
  local c
  for c in postfiatd postfiatd-sentry; do
    "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }
  done
  echo postfiatd
}
caps_of() { # INSPECT_JSON -> CAP_X,CAP_Y (effective set for Docker's includes/excludes: CapDrop ALL + CapAdd)
  jq -r '.[0].HostConfig as $h | if (($h.CapDrop // []) | map(ascii_upcase) | index("ALL")) then
    ($h.CapAdd // [] | map(ascii_upcase | if startswith("CAP_") then . else "CAP_" + . end) | sort | join(","))
    else "DEFAULT" end' <<<"$1"
}
table_file() { # -> path of the x86_64 syscall table in libseccomp's names (what Docker/runc resolve)
  if [ -n "${SYSCALL_TABLE:-}" ]; then echo "$SYSCALL_TABLE"; return; fi
  [ -n "$TABLE_TMP" ] || die "table file not prepared" 2
  [ -s "$TABLE_TMP" ] || py table > "$TABLE_TMP" || die "cannot build the syscall table from libseccomp.so.2" 2
  echo "$TABLE_TMP"
}

# ---------------------------------------------------------------------------------------------------- learn
learn_args() { # INSPECT_JSON SECCOMP(default|FILE) -> docker run args, one per line (image ID + cmd last)
  jq -r --arg sc "$2" '.[0] as $i |
    "--security-opt=apparmor=docker-default",
    (if $sc != "default" then "--security-opt=seccomp=\($sc)" else empty end),
    ($i.HostConfig.SecurityOpt // [] | map(select((startswith("apparmor") or startswith("seccomp")) | not))[] | "--security-opt=\(.)"),
    ($i.HostConfig.CapDrop // [] | .[] | "--cap-drop=\(.)"),
    ($i.HostConfig.CapAdd // [] | .[] | "--cap-add=\(.)"),
    (if $i.HostConfig.ReadonlyRootfs then "--read-only" else empty end),
    ($i.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\(.key):\(.value)"),
    ($i.Mounts // [] | .[] | "--volume=\(.Destination)"),
    (if ($i.HostConfig.PidsLimit // 0) > 0 then "--pids-limit=\($i.HostConfig.PidsLimit)" else empty end),
    (if ($i.HostConfig.Memory // 0) > 0 then "--memory=\($i.HostConfig.Memory)" else empty end),
    ($i.Config.User // "" | select(length > 0) | "--user=\(.)"),
    $i.Image,
    ($i.Config.Cmd // [] | .[])' <<<"$1"
}

rpc_state() { # CONTAINER -> server_state or ""
  "$DOCKER" exec "$1" curl -s -m 10 -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null \
    | jq -r '.result.info.server_state // empty' 2>/dev/null
}
wait_full() { # CONTAINER -> waits up to SYNC_BUDGET; prints the state
  local i st=""
  for ((i = 0; i < SYNC_BUDGET / 10; i++)); do st="$(rpc_state "$1")"; [ "$st" = full ] && break; sleep 10; done
  echo "${st:-none}"
}

# The read-only commands host add-ons docker exec into the node (pft-retention du/df/ls, pft-egress cat + /dev/tcp,
# pft-upgradewatch/pft-peerexpose grep, pft-cfglint/pft-integrity sha256sum/sed, pft-mounts/pft-timesync sh -c curl,
# postfiat-monitor's postfiatd client call). Output is reduced to counts so no config text reaches a log.
exercise_addons() { # CONTAINER
  local c="$1"
  lx "$DOCKER" exec "$c" sh -c 'command -v curl >/dev/null'
  lx "$DOCKER" exec "$c" sh -c 'curl -s -m 5 -o /dev/null -w "%{http_code}\n" -d "{\"method\":\"server_info\"}" http://127.0.0.1:${RPC_PORT:-5005}/'
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' -d '{"method":"fee"}' http://localhost:5005/
  lx "$DOCKER" exec "$c" stat -c %a "$CFG_DIR/postfiatd.cfg"
  lx "$DOCKER" exec "$c" sh -c 'cat "$1/postfiatd.cfg" /etc/resolv.conf "$1/validators.txt" | wc -l' sh "$CFG_DIR"
  lx "$DOCKER" exec "$c" sh -c 'grep -cE "^\[" "$1/postfiatd.cfg"; grep -c -A4 "^\[amendment_majority_time\]" "$1/postfiatd.cfg"' sh "$CFG_DIR"
  lx "$DOCKER" exec "$c" sh -c 'sha256sum "$1/postfiatd.cfg" | wc -c; sed -n "/^\[node_db\]/,/^\[/p" "$1/postfiatd.cfg" | wc -l' sh "$CFG_DIR"
  lx "$DOCKER" exec "$c" sh -c 'postfiatd --conf "$1/postfiatd.cfg" server_info 2>/dev/null | wc -l' sh "$CFG_DIR"
  lx "$DOCKER" exec "$c" sh -c 'du -sb "$1/nudb" | cut -f1' sh "$DB_DIR"
  lx "$DOCKER" exec "$c" sh -c 'du -cb "$1"/*.db "$1"/*.db-* "$1"/*.sqlite 2>/dev/null | tail -n1' sh "$DB_DIR"
  lx "$DOCKER" exec "$c" df -B1 -P "$DB_DIR"
  lx "$DOCKER" exec "$c" sh -c 'ls -1 "$1/nudb" 2>/dev/null | wc -l; tail -n 3 /var/log/postfiatd/debug.log | wc -l' sh "$DB_DIR"
  lx "$DOCKER" exec "$c" timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5005'
}

exercise() { # CONTAINER (throwaway only: forced rotation)
  local c="$1" lr
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"peers"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" setpriv --reuid=0 --regid=0 --init-groups true
  lx "$DOCKER" exec "$c" sh -c 'cd / && run-parts --report /etc/cron.hourly'
  lx "$DOCKER" exec "$c" sh -c 'for j in /etc/cron.daily/*; do [ "${j##*/}" = apt-compat ] && continue; echo "cron.daily/${j##*/}"; "$j"; done'
  lr="$("$DOCKER" exec "$c" sh -c "grep -h logrotate /etc/cron.d/* 2>/dev/null | grep -v '^#' | head -1 | sed 's/^\([^ ]* *\)\{6\}//'")"
  [ -n "$lr" ] && lx "$DOCKER" exec "$c" sh -c "$lr"
  lx "$DOCKER" exec "$c" sh -c 'logrotate -f -s /var/log/postfiatd/.logrotate.status /etc/logrotate.d/postfiatd'
  lx "$DOCKER" exec "$c" sh -c 'test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r'
  lx "$DOCKER" exec "$c" sh -c 'test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron'
  exercise_addons "$c"
  lx "$DOCKER" exec "$c" ps -eo pid,comm
}

secopt() { # CONTAINER -> HostConfig.SecurityOpt; the inline seccomp profile Docker stores is shown as its sha256
  "$DOCKER" inspect "$1" 2>/dev/null | python3 -I -c 'import hashlib, json, sys
o = (json.load(sys.stdin) or [{}])[0].get("HostConfig", {}).get("SecurityOpt") or []
print(json.dumps([("seccomp=<sha256 %s>" % hashlib.sha256(x[8:].encode()).hexdigest()) if x.startswith("seccomp=") and
                  x != "seccomp=unconfined" else x for x in o]))' 2>/dev/null
}
cgroup_id() { # CONTAINER -> inode of its cgroup v2 scope (= bpftrace's cgroup id)
  local id; id="$("$DOCKER" inspect -f '{{.Id}}' "$1" 2>/dev/null)" || return 1
  stat -c %i "$R/sys/fs/cgroup/system.slice/docker-$id.scope" 2>/dev/null
}
seccomp_records() { # SINCE_EPOCH -> number of type=SECCOMP records since then (all audit files)
  local f files=()
  for f in "$R"/var/log/audit/audit.log*; do [ -r "$f" ] && files+=("$f"); done
  [ ${#files[@]} -gt 0 ] || { echo 0; return; }
  cat -- "${files[@]}" | awk -v t="$1" 'index($0, "type=SECCOMP ") && match($0, /audit\([0-9]+/) &&
    substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0 { n++ } END { print n + 0 }'
}
other_node_check() { # THROWAWAY: the first postfiatd-image container in `docker ps` must still be the live one
  local first
  first="$("$DOCKER" ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /postfiatd/ {print $1; exit}')"
  echo "$(ts) node auto-detection (pft-integrity's rule) picks: ${first:-none} (throwaway $1 is not a candidate)"
  [ "$first" != "$1" ]
}

seccomp_records_now() { # SINCE_EPOCH -> type=SECCOMP records since then in the CURRENT audit.log (cheap: watchdog)
  awk -v t="$1" 'index($0, "type=SECCOMP ") && match($0, /audit\([0-9]+/) &&
    substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0 { n++ } END { print n + 0 }' "$R/var/log/audit/audit.log" 2>/dev/null || echo 0
}
start_guard() { # THROWAWAY T0 FLAG: background watchdog; removes the throwaway when the record count passes LOG_MAX
  local tc="$1" t0="$2" flag="$3"
  (
    trap - INT TERM EXIT
    while sleep "$GUARD_SEC"; do
      n="$(seccomp_records_now "$t0")"
      if [ "$n" -gt "$LOG_MAX" ]; then
        echo "$(ts) GUARD: $n SECCOMP records since T0 > LOG_MAX $LOG_MAX - removing $tc"
        "$DOCKER" rm -f -v "$tc" >/dev/null 2>&1; echo "$n" > "$flag"; exit 0
      fi
    done
  ) &
  GUARD_PID=$!
}

# One throwaway lifetime: start, full, exercise, restart, full, steady until T0+MIN, exercise. Sets CGIDS.
# GUARD=1: a watchdog removes the throwaway on an audit flood; the run then returns 3.
run_throwaway() { # NAME SECCOMP(default|FILE) MIN GUARD(0|1) T0
  local tc="$1" sc="$2" min="$3" guard="$4" t0="$5" rc flag
  flag="$(mktemp "${TMPDIR:-/tmp}/pft-seccomp-guard.XXXXXX")" && rm -f "$flag"
  GUARD_PID=""
  mapfile -t A < <(learn_args "$INS" "$sc")
  echo "\$ $DOCKER run -d --name $tc ${A[*]}"
  "$DOCKER" run -d --name "$tc" "${A[@]}" >/dev/null || return 2
  [ "$guard" = 1 ] && start_guard "$tc" "$t0" "$flag"
  throwaway_life "$tc" "$min" "$t0"; rc=$?
  [ -n "$GUARD_PID" ] && { kill "$GUARD_PID" 2>/dev/null; wait "$GUARD_PID" 2>/dev/null; }
  if [ -s "$flag" ]; then echo "$(ts) log: stopped by the flood guard ($(cat "$flag") records)"; rm -f "$flag"; return 3; fi
  return "$rc"
}
throwaway_life() { # NAME MIN T0
  local tc="$1" min="$2" t0="$3" st end id
  id="$(cgroup_id "$tc")" && CGIDS+="${CGIDS:+,}$id"
  echo "$(ts) throwaway $tc started; cgroup id ${id:-unknown}; SecurityOpt $(secopt "$tc")"
  other_node_check "$tc" || return 2
  st="$(wait_full "$tc")"; echo "$(ts) throwaway server_state: $st"
  [ "$st" = full ] || return 2
  exercise "$tc"
  lx "$DOCKER" restart -t 30 "$tc" >/dev/null
  id="$(cgroup_id "$tc")" && CGIDS+="${CGIDS:+,}$id"
  st="$(wait_full "$tc")"; echo "$(ts) after restart: cgroup id ${id:-unknown}, server_state $st"
  [ "$st" = full ] || return 2
  end=$((t0 + min * 60))
  while [ "$(now)" -lt "$end" ]; do
    "$DOCKER" inspect "$tc" >/dev/null 2>&1 || return 2
    sleep 30
  done
  exercise "$tc"
  echo "$(ts) throwaway peers: $("$DOCKER" exec "$tc" curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r '.result.info.peers // 0')"
  return 0
}

phase_census() { # DIR MIN TABLE
  local d="$1" min="$2" tbl="$3" tc t0 bp rc
  tc="pftsc-learn-census-$(date -u +%Y%m%d%H%M%S)"; CGIDS=""
  t0="$(now)"; echo "$(ts) census: T0=$t0, throwaway $tc under Docker's default seccomp profile"
  # shellcheck disable=SC2089
  bp='tracepoint:raw_syscalls:sys_enter /strncmp(comm, "runc:[", 6) != 0/ { @[cgroup, args->id] = count(); }
tracepoint:raw_syscalls:sys_enter /strncmp(comm, "runc:[", 6) == 0/ { @r[cgroup, args->id] = count(); }'
  echo "  bpftrace program:"; printf '%s\n' "$bp" | sed 's/^/  | /'
  BPFTRACE_MAP_KEYS_MAX=65536 "$BPFTRACE" -o "$d/census.raw" -e "$bp" &
  local bpid=$! i
  for ((i = 0; i < 60; i++)); do grep -q '^Attaching' "$d/census.raw" 2>/dev/null && break; kill -0 "$bpid" 2>/dev/null || break; sleep 1; done
  grep -q '^Attaching' "$d/census.raw" 2>/dev/null && kill -0 "$bpid" 2>/dev/null || { kill "$bpid" 2>/dev/null; echo "$(ts) census: bpftrace did not attach"; return 2; }
  echo "$(ts) census: bpftrace attached ($(head -1 "$d/census.raw"))"
  trap 'kill -INT $bpid 2>/dev/null; "$DOCKER" rm -f -v "$tc" >/dev/null 2>&1; exit 6' INT TERM
  run_throwaway "$tc" default "$min" 0 "$t0"; rc=$?
  kill -INT "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null
  lx "$DOCKER" rm -f -v "$tc" >/dev/null; trap - INT TERM
  [ "$rc" = 0 ] || { echo "$(ts) census: throwaway run failed (rc $rc)"; return 2; }
  echo "$CGIDS" > "$d/cgroups"
  py census --table "$tbl" --cgroups "$CGIDS" "$d/census.raw" > "$d/census.json" || return 2
  grep '^@r\[' "$d/census.raw" | sed 's/^@r\[/@[/' > "$d/census-runc.raw"
  py census --table "$tbl" --cgroups "$CGIDS" "$d/census-runc.raw" > "$d/census-runc.json" || return 2
  rm -f "$d/census.raw" "$d/census-runc.raw"   # system-wide per-cgroup counts: only the throwaway's rows are kept
  echo "$(ts) census: cgroups $CGIDS; $(jq 'length' "$d/census.json") distinct syscalls ($(jq '[.[]] | add' "$d/census.json") calls) in the node + exec'd processes; runc init (pre-filter, left out): $(jq 'length' "$d/census-runc.json")"
  jq -r 'to_entries | sort_by(-.value) | .[] | "  \(.key) \(.value)"' "$d/census.json"
}

phase_log() { # DIR MIN TABLE CAPS
  local d="$1" min="$2" tbl="$3" caps="$4" tc t0 rc
  [ -s "$d/census.json" ] || die "no census.json in $d (run --phase census first)" 2
  py learnprofile --docker "$DOCKER_PROFILE" --table "$tbl" --census "$d/census.json" --caps "$caps" > "$d/learn-profile.json" || return 2
  echo "$(ts) log: learn profile sha256 $(sha256sum < "$d/learn-profile.json" | cut -c1-64): $(jq -c '{defaultAction, flags, rules: [.syscalls[] | {action, errnoRet, n: (.names | length)}]}' "$d/learn-profile.json")"
  tc="pftsc-learn-log-$(date -u +%Y%m%d%H%M%S)"; CGIDS=""
  t0="$(now)"; echo "$(ts) log: T0=$t0, throwaway $tc under the learn profile (SCMP_ACT_LOG default)"
  trap '"$DOCKER" rm -f -v "$tc" >/dev/null 2>&1; exit 6' INT TERM
  run_throwaway "$tc" "$d/learn-profile.json" "$min" 1 "$t0"; rc=$?
  sleep 5
  lx "$DOCKER" rm -f -v "$tc" >/dev/null; trap - INT TERM
  [ "$rc" = 0 ] || { echo "$(ts) log: throwaway run failed (rc $rc)"; return 2; }
  py audit --table "$tbl" --since "$t0" "$R"/var/log/audit/audit.log* > "$d/events.tsv" || return 2
  echo "$(ts) log: $(seccomp_records "$t0") SECCOMP records since T0; distinct (action, syscall, comm, exe): $(wc -l < "$d/events.tsv")"
  sed 's/^/  /' "$d/events.tsv"
}

do_learn() { # OUT MIN PHASE
  local d="$1" min="$2" phase="$3" tbl caps
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "learn needs root" 4
  local c; c="$(pick_container)"; INS="$("$DOCKER" inspect "$c" 2>/dev/null)" || die "container $c not found" 2
  command -v "$BPFTRACE" >/dev/null || [ "$phase" = log ] || die "bpftrace not installed (apt-get install bpftrace)" 2
  [ -r "$HELPER" ] && [ -r "$DOCKER_PROFILE" ] || die "helper or Docker profile missing ($HELPER, $DOCKER_PROFILE)" 2
  mkdir -p "$d" "$LEARN_DIR" && chmod 0700 "$LEARN_DIR" || die "cannot create $d" 2
  tbl="$(table_file)"; caps="$(caps_of "$INS")"
  [ "$caps" != DEFAULT ] || die "$c does not drop ALL capabilities (confine/ first)" 4
  echo "$(ts) learn on $c: phase $phase, --minutes $min, caps $caps, image $(jq -r '.[0].Image' <<<"$INS" | cut -c1-19)"
  echo "  helper sha256 $(sha256sum < "$HELPER" | cut -c1-64), Docker profile sha256 $(sha256sum < "$DOCKER_PROFILE" | cut -c1-64), syscall table $(grep -c . "$tbl") lines"
  jq -n --arg c "$c" --arg caps "$caps" --arg img "$(jq -r '.[0].Image' <<<"$INS")" --arg k "$(uname -r)" --argjson m "$min" \
    '{container: $c, caps: $caps, image: $img, kernel: $k, minutes: $m}' > "$d/meta.json"
  case "$phase" in
    census) phase_census "$d" "$min" "$tbl" ;;
    log) phase_log "$d" "$min" "$tbl" "$caps" ;;
    both) phase_census "$d" "$min" "$tbl" && phase_log "$d" "$min" "$tbl" "$caps" ;;
  esac || die "learn phase failed" 2
  echo "$(ts) learn: done -> $d"
}

learn_inputs() { # DIR -> helper args for generate/diff
  [ -s "$1/census.json" ] || die "no census.json in $1" 2
  printf '%s\n' --docker "$DOCKER_PROFILE" --table "$(table_file)" --census "$1/census.json" \
    --caps "$(jq -r '.caps' "$1/meta.json" 2>/dev/null || echo CAP_SETGID,CAP_SETUID)"
  [ -s "$1/events.tsv" ] && printf '%s\n' --events "$1/events.tsv"
  [ -n "$MARGIN" ] && printf '%s\n' --margin "$MARGIN"
  return 0
}

# ---------------------------------------------------------------------------------------------------- main
cmd="${1:-}"; shift || true
ARG=""; OUT=""; MIN=65; PHASE=both; LD=""
MARGIN="$( [ -r "$HERE/margin.tsv" ] && echo "$HERE/margin.tsv" || { [ -r "$LIB/margin.tsv" ] && echo "$LIB/margin.tsv"; } )"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:-}"; [ -n "$OUT" ] || die "--out needs a directory" 3; shift ;;
    --minutes) MIN="${2:-}"; [[ "$MIN" =~ ^[0-9]+$ ]] || die "--minutes needs a number" 3; shift ;;
    --phase) PHASE="${2:-}"; [[ "$PHASE" =~ ^(census|log|both)$ ]] || die "--phase census|log|both" 3; shift ;;
    --learn) LD="${2:-}"; [ -d "$LD" ] || die "--learn needs a learn directory" 3; shift ;;
    --margin) MARGIN="${2:-}"; [ -r "$MARGIN" ] || die "--margin: cannot read $MARGIN" 3; shift ;;
    -*) die "unknown option $1" 3 ;;
    *) [ -z "$ARG" ] && ARG="$1" || die "too many arguments" 3 ;;
  esac
  shift
done
case "$cmd" in
  learn) [ -n "$OUT" ] || die "usage: pft-seccomp learn --out DIR [--minutes N] [--phase census|log|both]" 3
         do_learn "$OUT" "$MIN" "$PHASE"; exit $? ;;
  generate|diff) [ -n "$LD" ] || die "usage: pft-seccomp $cmd --learn DIR [--margin FILE]" 3
         mapfile -t GA < <(learn_inputs "$LD"); py "$cmd" "${GA[@]}"; exit $? ;;
  check) [ -n "$ARG" ] || die "usage: pft-seccomp check FILE" 3
         py check "$ARG" --table "$(table_file)"; exit $? ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
