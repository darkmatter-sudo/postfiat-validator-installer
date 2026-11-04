#!/usr/bin/env bash
# pft-seccomp: replace Docker's default seccomp profile on the postfiatd container with a tailored syscall allowlist
# (pft-postfiatd.json) on a Post Fiat validator or sentry host (Ubuntu 22.04, kernel 5.15, Docker 29, postfiatd 1.0.9).
# Profile math lives in pft_seccomp.py (stdlib); this script runs containers, bpftrace and the audit log.
#
# Usage: sudo pft-seccomp learn --out DIR [--minutes N] [--phase census|log|both]   (throwaway containers only)
#        pft-seccomp generate --learn DIR [--learn DIR2] [--margin FILE]   (final profile JSON on stdout)
#        pft-seccomp diff --learn DIR [--learn DIR2] [--margin FILE]       (per-syscall table vs Docker's default, TSV)
#        pft-seccomp check FILE                               (structural checks, exit 1 + reason)
#        pft-seccomp audit [--json] [--prom FILE | --textfile] [--since SEC]   (read-only)
#        sudo pft-seccomp apply --profile-file FILE --yes     (inside a pft-maint window)
#        sudo pft-seccomp rollback --yes                      (undo the last apply; inside a pft-maint window)
#        sudo pft-seccomp ack-denials --reason TEXT [--until EPOCH] --yes   (after a drill's negative controls)
#        sudo pft-seccomp pull                                (validator: copy the peer's textfile)
#        pft-seccomp validate FILE HOST                       (the check pull applies to a fetched textfile)
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
#  audit     read-only. One line per check: PASS / FAIL / WARN.
#              kernel     seccomp filter support; logging: kernel.seccomp.actions_logged includes errno
#              profile    PROFILE_FILE exists and passes check
#              container  the container's stored seccomp profile (HostConfig.SecurityOpt, json.Compact of the file
#                         Docker read at create time) has the same canonical sha256 as PROFILE_FILE. FAIL: Docker's
#                         default (no seccomp option), unconfined, or another profile (drift: file edited after create)
#              filter     the container's init has Seccomp: 2 in /proc/<pid>/status
#              recreate   compose: a listed compose file sets seccomp=PROFILE_FILE; docker run: HostConfig keeps it
#              confine:*  cap_drop ALL, no-new-privileges still set
#              denials    type=SECCOMP records with action errno, subj = the container's AppArmor label, in the last
#                         --since s (default 86400), minus an ack-denials range. WARN with the top three syscalls.
#  apply     refuses (exit 4, nothing changed) without --yes, without an active pft-maint window holding
#            2*HEALTH_BUDGET+MAINT_MARGIN s and no data-collection lock, when the node is not full, not confined, has
#            no AppArmor label (denials could not be attributed), when FILE fails check, already runs FILE, or the
#            last apply is still in place. Then: backs up PROFILE_FILE, installs FILE there and re-creates the
#            container with seccomp=PROFILE_FILE: compose = docker-compose.seccomp.yml + COMPOSE_FILE in .env
#            (backed up), `docker compose up -d`; docker run = stop, rename to NAME-presc-<id> (kept, restart=no),
#            `docker run` with the old container's own arguments. Gate (HEALTH_BUDGET s, every POLL_SEC s):
#            re-created, stored profile = FILE, init Seccomp 2, server_state full, peers >= MIN_PEERS, confine
#            signature (everything above except the seccomp option, including the AppArmor label) unchanged, every
#            running pft-* service still active; then the live exercise (RPC, cron identity switch, hourly cron,
#            the add-ons' docker exec commands) and 0 denials since T0. Any failure, a failed step or SIGINT/SIGTERM
#            -> automatic rollback. Finally pft-integrity accept, only if every changed item is the container or its
#            compose files.
#  rollback  restores the previous profile file (or removes it), then the previous container (compose: .env
#            byte-identical, override removed; run: the kept NAME-presc-<id>) and runs the same gate for the
#            previous seccomp state. Exit 5 if the rollback gate does not pass.
#  pull / validate / ack-denials: as in apparmor/ (textfile pull from the sentry, strict file check, ack file).
#
# Exit codes: 0 ok, 1 findings / check failed / gate failed and rolled back, 2 error, 3 usage, 4 refused,
#             5 rollback did not pass its gate, 6 interrupted (rolled back).
# Config: /etc/pft-seccomp.env (KEY=VALUE, read, never sourced): HOST_LABEL (validator), PEER_LABEL (sentry),
#         PULL_SSH (validator only: command prefix that reaches the peer)
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  LEARN_DIR (/var/lib/pft-seccomp)  SYNC_BUDGET (1200 s)
#      LOG_MAX (2000 records)  GUARD_SEC (5)  HELPER (pft_seccomp.py next to this script, else /usr/local/lib/pft-seccomp/)
#      DOCKER_PROFILE (ref/docker-default-29.1.3.json next to this script, else /usr/local/lib/pft-seccomp/)
#      SYSCALL_TABLE (file from `pft_seccomp.py table`; default: generated from libseccomp.so.2 on each run)
#      PROFILE_PATH (/etc/pft-seccomp/pft-postfiatd.json)  TEXTFILE_DIR  STATE_DIR (LEARN_DIR: apply-CONTAINER.json,
#      backup/, denials-ack.json)  HEALTH_BUDGET (900)  POLL_SEC (10)  MAINT_MARGIN (300)  MIN_PEERS (1)
#      PFT_SC_INJECT=health (apply's gate fails: live automatic-rollback drill)  PULL_TIMEOUT (30)
#      Test hooks: PFT_SC_DOCKER / _BPFTRACE / _SYSTEMCTL / _MAINT / _INTEGRITY (commands)
#      PFT_SC_ROOT (prefix for /sys, /proc/<pid>/status, /var/log/audit, /etc)  PFT_SC_NOW

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
SYSTEMCTL="${PFT_SC_SYSTEMCTL:-systemctl}"
MAINT="${PFT_SC_MAINT:-pft-maint}"
INTEGRITY="${PFT_SC_INTEGRITY:-pft-integrity}"
CONF="$R/etc/pft-seccomp.env"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
STATE_DIR="${STATE_DIR:-$LEARN_DIR}"
HEALTH_BUDGET="${HEALTH_BUDGET:-900}"
POLL_SEC="${POLL_SEC:-10}"
MAINT_MARGIN="${MAINT_MARGIN:-300}"
MIN_PEERS="${MIN_PEERS:-1}"
INJECT="${PFT_SC_INJECT:-}" # "health": apply's gate fails (live automatic-rollback drill)
NOJ='{}'
TABLE_TMP="$(mktemp "${TMPDIR:-/tmp}/pft-seccomp-table.XXXXXX")" || { echo "pft-seccomp: mktemp failed" >&2; exit 2; }
trap 'rm -f "$TABLE_TMP" "$TABLE_TMP.census.json" "$TABLE_TMP.events.tsv"' EXIT

die() { echo "pft-seccomp: $1" >&2; exit "${2:-2}"; }
now() { echo "${PFT_SC_NOW:-$(date +%s)}"; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
lx() { local rc; echo "\$ $*"; "$@"; rc=$?; echo "(exit $rc)"; return "$rc"; }
py() { python3 -I "$HELPER" "$@"; }
conf_get() { # KEY DEFAULT: value from the env file (never sourced), else DEFAULT
  local v=""
  [ -r "$CONF" ] && v="$(sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'"'")"
  echo "${v:-$2}"
}
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9-]{0,31}$ ]]; }
HOST_LABEL="$(conf_get HOST_LABEL validator)"
valid_label "$HOST_LABEL" || die "bad HOST_LABEL in $CONF" 2
PROFILE_NAME=pft-postfiatd
PROFILE_PATH="${PROFILE_PATH:-/etc/pft-seccomp/$PROFILE_NAME.json}"   # as Docker / compose see it on the host
PROFILE_FILE="$R$PROFILE_PATH"
ACK_FILE="$STATE_DIR/denials-ack.json"
PEER_LABEL="$(conf_get PEER_LABEL sentry)"
PULL_SSH="$(conf_get PULL_SSH "")"; PULL_TIMEOUT="${PULL_TIMEOUT:-30}"

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

learn_inputs() { # DIR... -> helper args for generate/diff. Several learn dirs (same image + caps, e.g. the validator's
  # and the sentry's): census counts are summed and events concatenated, so one profile covers both hosts.
  local d c c0="" cen ev cs=() es=()
  for d in "$@"; do
    [ -s "$d/census.json" ] || die "no census.json in $d" 2
    c="$(jq -r '.caps' "$d/meta.json" 2>/dev/null || echo CAP_SETGID,CAP_SETUID)"
    [ -z "$c0" ] || [ "$c" = "$c0" ] || die "learn dirs differ in caps ($c0 vs $c)" 2
    c0="$c"; cs+=("$d/census.json"); [ -s "$d/events.tsv" ] && es+=("$d/events.tsv")
  done
  if [ $# -eq 1 ]; then cen="${cs[0]}"; ev="${es[0]:-}"
  else
    cen="$TABLE_TMP.census.json"; ev=""
    jq -S -s 'reduce .[] as $c ({}; reduce ($c | to_entries[]) as $e (.; .[$e.key] += $e.value))' "${cs[@]}" > "$cen" \
      || die "cannot merge the census files" 2
    if [ ${#es[@]} -gt 0 ]; then ev="$TABLE_TMP.events.tsv"; cat -- "${es[@]}" > "$ev" || die "cannot merge the events files" 2; fi
  fi
  printf '%s\n' --docker "$DOCKER_PROFILE" --table "$(table_file)" --census "$cen" --caps "$c0"
  [ -n "$ev" ] && printf '%s\n' --events "$ev"
  [ -n "$MARGIN" ] && printf '%s\n' --margin "$MARGIN"
  return 0
}

# ---------------------------------------------------------------------------------------------------- audit
RESULTS=""; FINDINGS=0; DENIED=0; ACKED_UNTIL=0
add() { # STATUS CHECK DETAIL
  RESULTS+="$1"$'\t'"$2"$'\t'"$3"$'\n'
  case "$1" in FAIL|WARN) FINDINGS=$((FINDINGS + 1)) ;; esac
}
inspect0() { "$DOCKER" inspect "$1" 2>/dev/null | jq -c '.[0] // empty' 2>/dev/null; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
canon() { py canon "$1" 2>/dev/null; }
sc_state() { # INSPECT0 -> "default" | "unconfined" | "sha256:<hex of the stored inline profile>" (Docker stores json.Compact(FILE))
  python3 -I -c 'import hashlib, json, sys
o = (json.loads(sys.stdin.read() or "{}").get("HostConfig") or {}).get("SecurityOpt") or []
s = [x[8:] for x in o if x.startswith("seccomp=")]
print("default" if not s else "unconfined" if s[0] == "unconfined" else "sha256:" + hashlib.sha256(s[0].encode()).hexdigest())' <<<"${1:-$NOJ}" 2>/dev/null
}
proc_seccomp() { # INSPECT0 -> "MODE FILTERS" from /proc/<pid>/status of the container's init (2 = filter)
  local pid; pid="$(jq -r '.State.Pid // 0' <<<"${1:-$NOJ}" 2>/dev/null)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo "none"; return; }
  awk '$1 == "Seccomp:" { m = $2 } $1 == "Seccomp_filters:" { f = $2 } END { print (m == "" ? "none" : m " " f + 0) }' \
    "$R/proc/$pid/status" 2>/dev/null || echo none
}
# type=SECCOMP records with action errno (our filter's denials; SECCOMP_FILTER_FLAG_LOG makes the kernel log them)
# whose subj is the container's AppArmor label (throwaways run under docker-default, the live node under its own
# label, see README). -> "COUNT<TAB>top3 syscall/comm summary"; rc 1 if no audit log is readable.
denials() { # SINCE_EPOCH SUBJ
  local f files=()
  for f in "$R"/var/log/audit/audit.log*; do [ -r "$f" ] && files+=("$f"); done
  [ ${#files[@]} -gt 0 ] || { printf '0\tno readable audit log\n'; return 1; }
  [ -n "$2" ] || { printf '0\tcontainer has no AppArmor label to attribute records\n'; return 0; }
  py audit --table "$(table_file)" --since "$1" --subj "$2" "${files[@]}" | awk -F'\t' '
    $1 == "errno" { n += $5; k[$2 " (" $3 ")"] += $5 }
    END { s = ""; for (i = 0; i < 3; i++) { b = ""; bn = 0; for (x in k) if (k[x] > bn) { bn = k[x]; b = x }
            if (bn == 0) break; s = s (s == "" ? "" : "; ") b " x" bn; delete k[b] }
          printf "%d\t%s\n", n + 0, s }'
}
subj_of() { # INSPECT0 -> the AppArmor label audit records carry for the container's processes
  jq -r '.AppArmorProfile // ""' <<<"${1:-$NOJ}" 2>/dev/null | sed 's/^unconfined$//'
}
compose_files() { jq -r '.Config.Labels["com.docker.compose.project.config_files"] // ""' <<<"${1:-$NOJ}"; }

audit_checks() {
  local c="$1" since="$2" ins st want pm m f found=0 fl d al
  al="$(cat "$R/proc/sys/kernel/seccomp/actions_logged" 2>/dev/null)"
  if grep -q '^Seccomp:' "$R/proc/1/status" 2>/dev/null; then add PASS kernel "seccomp filter support (CONFIG_SECCOMP_FILTER)"
  else add FAIL kernel "no Seccomp field in /proc/1/status"; fi
  [[ " $al " == *" errno "* ]] && add PASS logging "kernel logs errno actions (actions_logged: $al)" \
    || add FAIL logging "kernel.seccomp.actions_logged lacks errno ('${al:-unreadable}'): denials would be silent"
  if [ ! -f "$PROFILE_FILE" ]; then add FAIL profile "$PROFILE_FILE missing"; want=""
  elif ! d="$(py check "$PROFILE_FILE" --table "$(table_file)")"; then add FAIL profile "$PROFILE_FILE: $d"; want=""
  else want="sha256:$(canon "$PROFILE_FILE")"; add PASS profile "$PROFILE_FILE $d, canonical ${want:0:19}"
  fi
  if ins="$(inspect0 "$c")" && [ -n "$ins" ]; then
    st="$(sc_state "$ins")"
    case "$st" in
      "$want") add PASS container "$c runs under $PROFILE_NAME (stored profile = $PROFILE_FILE)" ;;
      default) add FAIL container "$c runs under Docker's default seccomp profile" ;;
      unconfined) add FAIL container "$c runs with seccomp=unconfined" ;;
      *) add FAIL container "$c stored seccomp profile ${st:0:19} != $PROFILE_FILE ${want:0:19} (drift)" ;;
    esac
    pm="$(proc_seccomp "$ins")"
    [ "${pm%% *}" = 2 ] && add PASS filter "container init: Seccomp 2 (filter), ${pm#* } filter(s)" \
      || add FAIL filter "container init not in seccomp filter mode ('$pm')"
    m="$(compose_files "$ins")"
    if [ -n "$m" ]; then
      IFS=, read -r -a fl <<<"$m"
      for f in "${fl[@]}"; do grep -qE "seccomp[=:] *\"?$PROFILE_PATH\"?" "$R$f" 2>/dev/null && found=1; done
      [ "$found" = 1 ] && add PASS recreate "compose file sets seccomp=$PROFILE_PATH" \
        || add FAIL recreate "no listed compose file sets seccomp=$PROFILE_PATH: the next 'docker compose up' drops it"
    else
      [ "$st" = "$want" ] && add PASS recreate "docker run container: HostConfig keeps the profile across restarts" \
        || add FAIL recreate "docker run container not created with seccomp=$PROFILE_PATH"
    fi
    jq -e '.HostConfig.CapDrop // [] | map(ascii_upcase) | index("ALL") != null' <<<"$ins" >/dev/null \
      && add PASS confine:cap_drop "cap_drop ALL" || add FAIL confine:cap_drop "cap_drop ALL missing"
    jq -e '.HostConfig.SecurityOpt // [] | map(select(test("^no-new-privileges(:true|=true)?$"))) | length > 0' <<<"$ins" >/dev/null \
      && add PASS confine:nnp "no-new-privileges" || add FAIL confine:nnp "no-new-privileges missing"
  else
    add FAIL container "container $c not found"; ins=""
  fi
  local eff="$since" note="" au subj
  subj="$(subj_of "$ins")"
  if [ -e "$ACK_FILE" ]; then
    if ! au="$(jq -er 'select(type == "object" and (.until | type) == "number" and (.reason | type) == "string") | .until' "$ACK_FILE" 2>/dev/null)" \
      || ! [[ "$au" =~ ^[0-9]+$ ]]; then
      add FAIL denials-ack "$ACK_FILE unreadable or malformed: no denial is treated as acknowledged"
    else
      ACKED_UNTIL="$au"
      if [ "$au" -ge "$since" ]; then
        eff=$((au + 1))
        note="; up to $(date -u -d "@$au" +%FT%TZ) acknowledged: $(jq -r '.reason' "$ACK_FILE" | tr -cd '[:print:]' | cut -c1-120)"
      fi
    fi
  fi
  if ! d="$(denials "$eff" "$subj")"; then DENIED=0; add FAIL denials "${d#*$'\t'} (run as root)"
  else
    DENIED="${d%%$'\t'*}"
    if [ "$DENIED" = 0 ]; then add PASS denials "0 seccomp denials (subj ${subj:-none}) in the last $(( $(now) - since ))s$note"
    else add WARN denials "$DENIED seccomp denial(s) in the last $(( $(now) - since ))s: ${d#*$'\t'}$note"
    fi
  fi
}

print_results() {
  local c="$1"
  if [ "$JSON" = 1 ]; then
    printf '%s' "$RESULTS" | jq -R -s --arg h "$HOST_LABEL" --arg c "$c" --arg p "$PROFILE_PATH" --arg t "$(ts)" \
      --argjson n "$FINDINGS" --argjson d "$DENIED" --argjson a "$ACKED_UNTIL" '
      {host: $h, container: $c, profile_file: $p, time: $t, findings: $n, denied_events: $d, denied_acknowledged_until: $a,
       checks: (split("\n") | map(select(length > 0) | split("\t") | {status: .[0], check: .[1], detail: .[2]}))}'
  else
    echo "pft-seccomp audit - $(ts) | host $HOST_LABEL | container $c | profile $PROFILE_PATH"
    printf '%s' "$RESULTS" | awk -F'\t' '{printf "  [%-4s] %-18s %s\n", $1, $2, $3}'
    echo "RESULT: $([ "$FINDINGS" = 0 ] && echo PASS || echo "FAIL - $FINDINGS finding(s)")"
  fi
}

write_prom() { # FILE: node_exporter textfile, written atomically
  local f="$1" tmp h="$HOST_LABEL"
  tmp="$(mktemp "${f}.XXXXXX")" || return 2
  {
    echo "# HELP pft_seccomp_check 1 if the seccomp check passes, 0 if FAIL or WARN."
    echo "# TYPE pft_seccomp_check gauge"
    printf '%s' "$RESULTS" | awk -F'\t' -v h="$h" '$1 != "INFO" { printf "pft_seccomp_check{host=\"%s\",check=\"%s\",status=\"%s\"} %d\n", h, $2, $1, ($1 == "PASS") }'
    echo "# HELP pft_seccomp_findings Number of FAIL + WARN seccomp checks."
    echo "# TYPE pft_seccomp_findings gauge"
    echo "pft_seccomp_findings{host=\"$h\"} $FINDINGS"
    echo "# HELP pft_seccomp_denied_events Seccomp errno denials for the node container in the audit window."
    echo "# TYPE pft_seccomp_denied_events gauge"
    echo "pft_seccomp_denied_events{host=\"$h\"} $DENIED"
    echo "# HELP pft_seccomp_last_run_timestamp_seconds Unix time of the last completed audit."
    echo "# TYPE pft_seccomp_last_run_timestamp_seconds gauge"
    echo "pft_seccomp_last_run_timestamp_seconds{host=\"$h\"} $(now)"
  } > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$f"
}

validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout (a pulled file must look like ours)
  local f="$1" h="$2" n
  [ -f "$f" ] || { echo "missing"; return 1; }
  [ "$(stat -c %s "$f")" -le 65536 ] || { echo "larger than 65536 bytes"; return 1; }
  n="$(grep -cvE '^(# (HELP|TYPE) pft_seccomp_.*|pft_seccomp_[a-z_]+\{host="'"$h"'"(,[a-z]+="[A-Za-z0-9_./:-]+")*\} [0-9.e+-]+)$' "$f")"
  [ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }
  grep -qE '^pft_seccomp_last_run_timestamp_seconds\{host="'"$h"'"\} [0-9]+$' "$f" || { echo "no last_run sample"; return 1; }
  return 0
}

do_pull() { # validator: the peer's textfile through PULL_SSH; a file that fails validate never replaces the last good one
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  tmp="$TEXTFILE_DIR/.pft_seccomp_$PEER_LABEL.prom.pull"
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "/var/lib/pft-exporter/textfile/pft_seccomp_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "pull from $PEER_LABEL failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "pulled file rejected: $why" 2; fi
  chmod 0644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_seccomp_$PEER_LABEL.prom"
}

do_ack() { # UNTIL REASON: acknowledge the denials up to UNTIL (after a drill's negative controls)
  local u="$1" why="$2" prev=0 a b n tmp c subj
  [[ "$u" =~ ^[0-9]+$ ]] && [ "$u" -le "$(now)" ] || die "--until must be a unix time, not in the future" 3
  [ -n "$why" ] && [ "${#why}" -le 200 ] && [[ "$why" != *[![:print:]]* ]] || die "--reason: 1-200 printable characters" 3
  if [ -e "$ACK_FILE" ]; then
    prev="$(jq -er '.until | select(type == "number")' "$ACK_FILE" 2>/dev/null)" || prev=0
  fi
  [ "$u" -gt "$prev" ] || die "already acknowledged up to $prev" 4
  c="$(pick_container)"; subj="$(subj_of "$(inspect0 "$c")")"
  a="$(denials "$((prev + 1))" "$subj")" || die "audit log unreadable (run as root)" 2
  b="$(denials "$((u + 1))" "$subj")" || die "audit log unreadable (run as root)" 2
  n=$(( ${a%%$'\t'*} - ${b%%$'\t'*} ))
  mkdir -p "$STATE_DIR" || die "cannot create $STATE_DIR" 2
  tmp="$(mktemp "$ACK_FILE.XXXXXX")" || die "cannot write $ACK_FILE" 2
  jq -n --argjson u "$u" --argjson n "$n" --arg r "$why" --arg t "$(ts)" \
    '{until: $u, records: $n, reason: $r, at: $t}' > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$ACK_FILE" \
    || { rm -f "$tmp"; die "cannot write $ACK_FILE" 2; }
  echo "$(ts) ack-denials: $n seccomp denial(s) after $prev up to $u ($(date -u -d "@$u" +%FT%TZ)) acknowledged: $why"
}

# ---------------------------------------------------------------------------------------------------- apply
# Everything a re-create must keep (confine/'s runtime profile, the AppArmor label, the container's identity) but NOT
# the seccomp option. Canonical JSON: apply's gate requires it unchanged, so a lost flag rolls back.
confine_sig() { # INSPECT0
  jq -cS '{image: .Config.Image, cmd: (.Config.Cmd // []), entrypoint: (.Config.Entrypoint // []),
    user: (.Config.User // ""), env: (.Config.Env // [] | sort),
    cap_add: (.HostConfig.CapAdd // [] | map(ascii_upcase | sub("^CAP_"; "")) | sort),
    cap_drop: (.HostConfig.CapDrop // [] | map(ascii_upcase) | sort),
    read_only: (.HostConfig.ReadonlyRootfs // false), tmpfs: (.HostConfig.Tmpfs // {}),
    pids: (.HostConfig.PidsLimit // 0), memory: (.HostConfig.Memory // 0), memory_swap: (.HostConfig.MemorySwap // 0),
    cpu_shares: (.HostConfig.CpuShares // 0), memory_reservation: (.HostConfig.MemoryReservation // 0),
    apparmor: (.AppArmorProfile // ""),
    security_opt: (.HostConfig.SecurityOpt // [] | map(select(startswith("seccomp") | not)
                   | sub("^no-new-privileges([:=]true)?$"; "no-new-privileges")) | sort),
    mounts: (.Mounts // [] | map({type: .Type, name: (if .Type == "volume" then .Name else null end),
             source: (if .Type == "bind" then .Source else null end), dest: .Destination, rw: .RW}) | sort_by(.dest)),
    ports: (.HostConfig.PortBindings // {}), network: (.HostConfig.NetworkMode // ""), log: (.HostConfig.LogConfig // {})}' <<<"$1"
}
sig_diff() { # SIG_A SIG_B -> names of the keys that differ (values are not printed: env may hold secrets)
  jq -rn --argjson a "$1" --argjson b "$2" '[($a + $b) | keys[] | select($a[.] != $b[.])] | join(",")'
}
# docker run arguments that re-create a `docker run` container exactly with seccomp=FILE instead of its current
# seccomp option (SECCOMP = default: no seccomp option, i.e. Docker's default profile). Image + cmd last.
run_args() { # INSPECT0 IMAGE_ENV_JSON SECCOMP(FILE|default)
  jq -r --argjson ienv "$2" --arg sc "$3" '
    "--name=\(.Name[1:])",
    "--restart=\(.HostConfig.RestartPolicy.Name)\(if .HostConfig.RestartPolicy.Name == "on-failure" then ":\(.HostConfig.RestartPolicy.MaximumRetryCount)" else "" end)",
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
    (.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\(.key):\(.value)"),
    (if (.HostConfig.PidsLimit // 0) > 0 then "--pids-limit=\(.HostConfig.PidsLimit)" else empty end),
    (if (.HostConfig.Memory // 0) > 0 then "--memory=\(.HostConfig.Memory)" else empty end),
    (if (.HostConfig.MemorySwap // 0) != 0 then "--memory-swap=\(.HostConfig.MemorySwap)" else empty end),
    (if (.HostConfig.CpuShares // 0) > 0 then "--cpu-shares=\(.HostConfig.CpuShares)" else empty end),
    (if (.HostConfig.MemoryReservation // 0) > 0 then "--memory-reservation=\(.HostConfig.MemoryReservation)" else empty end),
    (.HostConfig.SecurityOpt // [] | map(select(startswith("seccomp") | not))[] | "--security-opt=\(.)"),
    (if $sc != "default" then "--security-opt=seccomp=\($sc)" else empty end),
    .Config.Image, (.Config.Cmd // [])[]' <<<"$1"
}
show_args() { # args on stdin, one per line -> one line, env values and IPv4 addresses masked (publishable)
  sed -E 's/^(--env=[^=]*)=.*/\1=<value>/; s/([0-9]{1,3}\.){3}[0-9]{1,3}/<redacted-ip>/g' | paste -sd' '
}

# CPU weight and memory.low set live with `docker update` (the node's protection against host load) are not in the
# compose files, so `compose up` re-creates without them. Put them back from the pre-apply signature; the gate's
# confine signature includes both, so a value that did not come back fails the gate.
keep_resources() { # CONTAINER SIG
  local cs mr ins cur
  cs="$(jq -r '.cpu_shares // 0' <<<"$2")"; mr="$(jq -r '.memory_reservation // 0' <<<"$2")"
  [ "$cs" -gt 0 ] || [ "$mr" -gt 0 ] || return 0
  ins="$(inspect0 "$1")"
  cur="$(jq -r '"\(.HostConfig.CpuShares // 0) \(.HostConfig.MemoryReservation // 0)"' <<<"${ins:-$NOJ}")"
  [ "$cur" = "$cs $mr" ] && return 0
  local a=(); [ "$cs" -gt 0 ] && a+=("--cpu-shares=$cs"); [ "$mr" -gt 0 ] && a+=("--memory-reservation=$mr")
  "$DOCKER" update "${a[@]}" "$1" >/dev/null || { echo "$(ts) resources: docker update ${a[*]} $1 FAILED"; return 1; }
  echo "$(ts) resources: $1 had cpu_shares/memory_reservation '$cur', restored ${a[*]}"
}

maint_gate() { # -> "ok <remaining>" or "refuse <reason>"; apply + a possible rollback must fit the window
  local j w rem nl need=$((2 * HEALTH_BUDGET + MAINT_MARGIN))
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "refuse pft-maint status failed (is pft-maint installed?)"; return; }
  w="$(jq -r '.window // "none"' <<<"$j" 2>/dev/null)"
  rem="$(jq -r '.remaining_sec // 0' <<<"$j" 2>/dev/null)"; [[ "$rem" =~ ^[0-9]+$ ]] || rem=0
  nl="$(jq -r '.locks | length' <<<"$j" 2>/dev/null)"; [[ "$nl" =~ ^[0-9]+$ ]] || nl=1
  if [ "$w" != active ]; then echo "refuse no active pft-maint window (window=${w:-none}); run: sudo pft-maint start --ttl 45m --reason ..."
  elif [ "$rem" -lt "$need" ]; then echo "refuse window has ${rem}s left, needs 2*HEALTH_BUDGET+MAINT_MARGIN=${need}s"
  elif [ "$nl" -gt 0 ]; then echo "refuse $nl pft-maint data-collection lock(s) held: $(jq -r '.locks | join("; ")' <<<"$j")"
  else echo "ok $rem"; fi
}
daemon_units() { # long-running pft units that are active now; the gate requires them to stay active
  "$SYSTEMCTL" list-units --type=service --state=running --no-legend 'pft-*' 2>/dev/null | awk '{print $1}' | grep -E '^pft-' | sort -u
}
exercise_live() { # CONTAINER: what the live node does on its own (no forced rotation, no restart: the live node is not a throwaway)
  local c="$1"
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"peers"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" setpriv --reuid=0 --regid=0 --init-groups true
  lx "$DOCKER" exec "$c" sh -c 'cd / && run-parts --report /etc/cron.hourly'
  exercise_addons "$c"
  lx "$DOCKER" exec "$c" ps -eo pid,comm
}

# Health gate after a re-create. apply: the container is new (StartedAt changed), its stored seccomp profile is the
# wanted one, its init is in filter mode, server_state full, peers >= MIN_PEERS, confine signature unchanged, every
# pft daemon still active; then the live exercise and 0 denials since T0. rollback: the same for the pre-apply
# seccomp state, without the exercise/denial part.
health_gate() { # MODE(apply|rollback) CONTAINER BEFORE_STARTED_AT WANT_STATE SIG DAEMONS T0
  local mode="$1" c="$2" before="$3" want="$4" sig="$5" daemons="$6" t0="$7" i n ins sa st pm rs peers why u d
  n=$(( HEALTH_BUDGET / POLL_SEC )); [ "$n" -ge 1 ] || n=1
  for ((i = 1; i <= n; i++)); do
    ins="$(inspect0 "$c")"; why=""
    sa="$(jq -r '.State.StartedAt // ""' <<<"${ins:-$NOJ}" 2>/dev/null)"
    st="$(sc_state "$ins")"; pm="$(proc_seccomp "$ins")"
    rs="$(rpc_state "$c")"
    peers="$("$DOCKER" exec "$c" curl -s -m 10 -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null \
      | jq -r '.result.info.peers // 0' 2>/dev/null)"; [[ "$peers" =~ ^[0-9]+$ ]] || peers=0
    [ -n "$ins" ] || why+=" container missing;"
    [ -n "$sa" ] && [ "$sa" != "$before" ] || why+=" not re-created (StartedAt unchanged);"
    [ "$st" = "$want" ] || why+=" seccomp ${st:0:19} want ${want:0:19};"
    [ "${pm%% *}" = 2 ] || why+=" init Seccomp '$pm' want 2;"
    [ "$rs" = full ] || why+=" server_state ${rs:-none};"
    [ "$peers" -ge "$MIN_PEERS" ] || why+=" peers $peers < $MIN_PEERS;"
    [ -n "$ins" ] && [ "$(confine_sig "$ins")" = "$sig" ] || why+=" confine changed: $(sig_diff "$sig" "$(confine_sig "${ins:-$NOJ}")");"
    for u in $daemons; do [ "$("$SYSTEMCTL" is-active "$u" 2>/dev/null)" = active ] || why+=" $u inactive;"; done
    [ "$mode" = apply ] && [ "$INJECT" = health ] && why+=" injected failure (PFT_SC_INJECT=health);"
    [ -z "$why" ] && break
    [ "$i" -lt "$n" ] && sleep "$POLL_SEC"
  done
  if [ -n "$why" ]; then echo "$(ts) $mode: health FAIL after $i poll(s):$why"; return 1; fi
  echo "$(ts) $mode: health PASS after $i poll(s) ($c re-created, seccomp ${st:0:19}, init Seccomp $pm, server_state full, peers $peers, confine signature unchanged, $(wc -w <<<"$daemons") pft daemons active)"
  [ "$mode" = apply ] || return 0
  exercise_live "$c" | sed 's/^/  | /'
  sleep 2
  d="$(denials "$t0" "$(subj_of "$ins")")" || { echo "$(ts) apply: gate FAIL - audit log unreadable"; return 1; }
  if [ "${d%%$'\t'*}" != 0 ]; then echo "$(ts) apply: gate FAIL - ${d%%$'\t'*} seccomp denial(s) since T0: ${d#*$'\t'}"; return 1; fi
  echo "$(ts) apply: gate PASS - exercise done, seccomp denials since T0: 0"
}

integrity_accept() { # CONTAINER REASON: accept a new baseline only if every changed item is ours
  command -v "$INTEGRITY" >/dev/null 2>&1 || { echo "$(ts) integrity: pft-integrity not installed, skipped"; return 0; }
  local out items other
  out="$("$INTEGRITY" verify 2>&1)"
  items="$(grep -E '^  \[(WARN|FAIL)\] ' <<<"$out" | awk '{print $2}' | sort -u)"
  [ -n "$items" ] || { echo "$(ts) integrity: baseline already current"; return 0; }
  other="$(grep -vxE "container:$1|compose:\.env|compose:docker-compose\.seccomp\.yml" <<<"$items")"
  if [ -n "$other" ]; then
    echo "$(ts) integrity: NOT accepted - changed items besides the container/compose: $(paste -sd' ' <<<"$other")"
    return 1
  fi
  "$INTEGRITY" accept --reason "$2" >/dev/null 2>&1 && echo "$(ts) integrity: accepted ($(paste -sd' ' <<<"$items")): $2" \
    || { echo "$(ts) integrity: accept FAILED"; return 1; }
}

do_apply() { # PROFILE_SRC
  local src="$1" c ins sig before daemons gate id rs wd svc cfgs files eb ov pb pre want iimg ienv old rp t0 d
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "apply needs root" 4
  [ "$YES" = 1 ] || { echo "$(ts) apply: REFUSED - apply re-creates the container; re-run with --yes"; return 4; }
  [ -r "$src" ] || die "cannot read --profile-file $src" 2
  d="$(py check "$src" --table "$(table_file)")" || { echo "$(ts) apply: REFUSED - $src fails check: $d; nothing changed"; return 4; }
  c="$(pick_container)"; ins="$(inspect0 "$c")"; [ -n "$ins" ] || die "container $c not found" 2
  pre="$(sc_state "$ins")"; want="sha256:$(canon "$src")"
  gate="$(maint_gate)"
  case "$gate" in ok*) ;; *) echo "$(ts) apply: REFUSED - ${gate#refuse }; nothing changed"; return 4 ;; esac
  rs="$(rpc_state "$c")"; [ "$rs" = full ] || { echo "$(ts) apply: REFUSED - node is ${rs:-down}, not full; nothing changed"; return 4; }
  jq -e '.HostConfig.SecurityOpt // [] | map(select(test("^no-new-privileges"))) | length > 0' <<<"$ins" >/dev/null \
    && jq -e '.HostConfig.CapDrop // [] | map(ascii_upcase) | index("ALL") != null' <<<"$ins" >/dev/null \
    || { echo "$(ts) apply: REFUSED - $c is not confined (confine/ first: cap_drop ALL + no-new-privileges)"; return 4; }
  [ -n "$(subj_of "$ins")" ] || { echo "$(ts) apply: REFUSED - $c has no AppArmor label: denials could not be attributed"; return 4; }
  [ "$pre" = "$want" ] && { echo "$(ts) apply: REFUSED - $c already runs under this profile; nothing changed"; return 4; }
  [ -f "$STATE_FILE" ] && [ "$(jq -r '.rolled_back // false' "$STATE_FILE" 2>/dev/null)" != true ] \
    && { echo "$(ts) apply: REFUSED - the last apply ($(jq -r .id "$STATE_FILE" 2>/dev/null)) is still in place; rollback first"; return 4; }
  id="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"; t0="$(now)"
  sig="$(confine_sig "$ins")"; before="$(jq -r '.State.StartedAt // ""' <<<"$ins")"; daemons="$(daemon_units)"
  mkdir -p "$STATE_DIR/backup" "$(dirname "$PROFILE_FILE")" && chmod 0700 "$STATE_DIR" || die "cannot create $STATE_DIR" 2
  echo "$(ts) apply $id on $c (host $HOST_LABEL): maintenance gate: $gate; before: seccomp ${pre:0:19}, server_state $rs"
  echo "$(ts) apply: candidate $src: $d, canonical ${want:0:19}; confine signature sha256 $(sha256sum <<<"$sig" | cut -c1-12) ($(jq -r 'keys | length' <<<"$sig") keys); $(wc -w <<<"$daemons") pft daemons active"
  # 1. the profile file Docker reads at create time (compose override / docker run point at it)
  pb=""
  if [ -f "$PROFILE_FILE" ]; then pb="$STATE_DIR/backup/$PROFILE_NAME.json.$id"; cp -p "$PROFILE_FILE" "$pb" || die "backup of $PROFILE_FILE failed" 2; fi
  jq -n --arg id "$id" --arg c "$c" --arg pf "$PROFILE_FILE" --arg pb "$pb" --arg pre "$pre" --arg want "$want" --arg sig "$sig" \
    '{id:$id, container:$c, profile_file:$pf, profile_backup:$pb, pre_state:$pre, want_state:$want, sig:$sig, phase:"profile"}' > "$STATE_FILE"
  install -m 0644 "$src" "$PROFILE_FILE" || { do_rollback auto; return 5; }
  echo "$(ts) apply: installed $PROFILE_FILE (sha256 $(sha "$PROFILE_FILE" | cut -c1-12))${pb:+; previous file kept as backup/$(basename "$pb")}"
  # 2. re-create the container with seccomp=PROFILE_FILE
  trap 'echo "$(ts) apply: interrupted -> automatic rollback"; do_rollback auto; exit 6' INT TERM
  cfgs="$(compose_files "$ins")"
  if [ -n "$cfgs" ]; then
    wd="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"] // ""' <<<"$ins")"
    svc="$(jq -r '.Config.Labels["com.docker.compose.service"] // ""' <<<"$ins")"
    [ -d "$R$wd" ] && [ -n "$svc" ] || { do_rollback auto; die "compose working dir/service unknown" 2; }
    files="$(tr ',' '\n' <<<"$cfgs" | sed 's#.*/##' | grep -vx 'docker-compose.seccomp.yml' | paste -sd:)"
    eb="$STATE_DIR/backup/env.$id"; ov="$R$wd/docker-compose.seccomp.yml"; ob=""
    touch "$R$wd/.env"; cp -p "$R$wd/.env" "$eb" || { do_rollback auto; die "cannot back up .env" 2; }
    if [ -f "$ov" ]; then ob="$STATE_DIR/backup/docker-compose.seccomp.yml.$id"; cp -p "$ov" "$ob" || { do_rollback auto; die "cannot back up $ov" 2; }; fi
    jq --arg wd "$wd" --arg eb "$eb" --arg ov "$ov" --arg ob "$ob" '. + {kind:"compose", working_dir:$wd, env_backup:$eb, override:$ov, override_backup:$ob, phase:"container"}' \
      "$STATE_FILE" > "$STATE_FILE.tmp" && mv -f "$STATE_FILE.tmp" "$STATE_FILE"
    printf '# written by pft-seccomp apply; remove with: sudo pft-seccomp rollback --yes\nservices:\n  %s:\n    security_opt:\n      - "seccomp=%s"\n' \
      "$svc" "$PROFILE_PATH" > "$ov"
    { grep -v '^COMPOSE_FILE=' "$eb"; echo "COMPOSE_FILE=$files:docker-compose.seccomp.yml"; } > "$R$wd/.env"
    chmod --reference="$eb" "$R$wd/.env" 2>/dev/null
    echo "$(ts) apply: wrote $wd/docker-compose.seccomp.yml; .env backed up, COMPOSE_FILE=$files:docker-compose.seccomp.yml"
    ( cd "$R$wd" && "$DOCKER" compose config -q ) || { echo "$(ts) apply: compose config invalid -> automatic rollback"; do_rollback auto && return 1; return 5; }
    ( cd "$R$wd" && "$DOCKER" compose up -d 2>&1 ) | sed 's/^/  | /'
    [ "${PIPESTATUS[0]}" = 0 ] || { echo "$(ts) apply: compose up failed -> automatic rollback"; do_rollback auto && return 1; return 5; }
    keep_resources "$c" "$sig" || { echo "$(ts) apply: resources not restored -> automatic rollback"; do_rollback auto && return 1; return 5; }
  else
    iimg="$(jq -r .Config.Image <<<"$ins")"
    ienv="$("$DOCKER" image inspect "$iimg" 2>/dev/null | jq -c '.[0].Config.Env // []' 2>/dev/null)"; [ -n "$ienv" ] || ienv='[]'
    old="$c-presc-$id"; rp="$(jq -r '.HostConfig.RestartPolicy.Name' <<<"$ins")"
    mapfile -t A < <(run_args "$ins" "$ienv" "$PROFILE_PATH")
    jq --arg o "$old" --arg rp "$rp" '. + {kind:"run", old_container:$o, restart:$rp, phase:"container"}' \
      "$STATE_FILE" > "$STATE_FILE.tmp" && mv -f "$STATE_FILE.tmp" "$STATE_FILE"
    echo "$(ts) apply: recreate: docker run -d $(printf '%s\n' "${A[@]}" | show_args)"
    "$DOCKER" stop -t 60 "$c" >/dev/null && "$DOCKER" rename "$c" "$old" && "$DOCKER" update --restart=no "$old" >/dev/null \
      || { echo "$(ts) apply: could not stop/rename $c -> automatic rollback"; do_rollback auto && return 1; return 5; }
    echo "$(ts) apply: previous container kept as $old (stopped, restart=no)"
    "$DOCKER" run -d "${A[@]}" >/dev/null || { echo "$(ts) apply: docker run failed -> automatic rollback"; do_rollback auto && return 1; return 5; }
  fi
  # 3. gate
  if ! health_gate apply "$c" "$before" "$want" "$sig" "$daemons" "$t0"; then
    echo "$(ts) apply: gate failed -> automatic rollback"; do_rollback auto; local rc=$?; trap - INT TERM
    [ "$rc" = 0 ] && return 1; return "$rc"
  fi
  trap - INT TERM
  jq --arg t "$(ts)" '. + {phase:"applied", applied_at:$t, rolled_back:false}' "$STATE_FILE" > "$STATE_FILE.tmp" && mv -f "$STATE_FILE.tmp" "$STATE_FILE"
  integrity_accept "$c" "pft-seccomp apply $id: $c re-created with seccomp=$PROFILE_PATH" || true
  echo "$(ts) apply RESULT: PASS - $c runs under $PROFILE_FILE (${want:0:19}), node full (state $STATE_FILE)"
}

do_rollback() { # auto|manual: undo the last apply from the state file
  local how="$1" s c kind before ins sig daemons pre pf pb old
  [ -f "$STATE_FILE" ] || { echo "$(ts) rollback: no apply state ($STATE_FILE)"; return 2; }
  s="$(cat "$STATE_FILE")"; c="$(jq -r .container <<<"$s")"; kind="$(jq -r '.kind // ""' <<<"$s")"
  [ "$(jq -r '.rolled_back // false' <<<"$s")" = true ] && { echo "$(ts) rollback: apply $(jq -r .id <<<"$s") already rolled back"; return 0; }
  pre="$(jq -r '.pre_state' <<<"$s")"; pf="$(jq -r .profile_file <<<"$s")"; pb="$(jq -r '.profile_backup // ""' <<<"$s")"; sig="$(jq -r .sig <<<"$s")"
  echo "$(ts) rollback ($how) of apply $(jq -r .id <<<"$s") on $c: back to seccomp ${pre:0:19}"
  ins="$(inspect0 "$c")"; before="$(jq -r '.State.StartedAt // ""' <<<"${ins:-$NOJ}")"; daemons="$(daemon_units)"
  # the previous profile file first: a compose re-create below must read the previous bytes, not the candidate's
  if [ -n "$pb" ] && [ -f "$pb" ]; then
    cp -p "$pb" "$pf" || { echo "$(ts) ROLLBACK FAILED: profile restore"; return 5; }
    echo "$(ts) rollback: previous $pf restored (sha256 $(sha "$pf" | cut -c1-12))"
  fi
  case "$kind" in
    compose)
      local wd ob; wd="$(jq -r .working_dir <<<"$s")"; ob="$(jq -r '.override_backup // ""' <<<"$s")"
      if [ -n "$ob" ]; then # an override existed before this apply (re-apply over an older profile): put it back
        cp -p -- "$(jq -r .env_backup <<<"$s")" "$R$wd/.env" && cp -p -- "$ob" "$(jq -r .override <<<"$s")" \
          || { echo "$(ts) ROLLBACK FAILED: cannot restore .env / override"; return 5; }
        echo "$(ts) rollback: .env and the previous docker-compose.seccomp.yml restored"
      else
        cp -p -- "$(jq -r .env_backup <<<"$s")" "$R$wd/.env" && rm -f -- "$(jq -r .override <<<"$s")" \
          || { echo "$(ts) ROLLBACK FAILED: cannot restore .env / remove override"; return 5; }
        echo "$(ts) rollback: .env restored, docker-compose.seccomp.yml removed"
      fi
      ( cd "$R$wd" && "$DOCKER" compose up -d 2>&1 ) | sed 's/^/  | /'
      [ "${PIPESTATUS[0]}" = 0 ] || { echo "$(ts) ROLLBACK FAILED: compose up"; return 5; }
      keep_resources "$c" "$sig" || { echo "$(ts) ROLLBACK FAILED: resources"; return 5; } ;;
    run)
      old="$(jq -r .old_container <<<"$s")"
      if [ -n "$(inspect0 "$old")" ]; then
        "$DOCKER" rm -f "$c" >/dev/null 2>&1
        "$DOCKER" rename "$old" "$c" && "$DOCKER" update --restart="$(jq -r .restart <<<"$s")" "$c" >/dev/null \
          && "$DOCKER" start "$c" >/dev/null || { echo "$(ts) ROLLBACK FAILED: could not restore $old as $c"; return 5; }
        echo "$(ts) rollback: previous container $old restored as $c (restart=$(jq -r .restart <<<"$s"))"
      else
        echo "$(ts) ROLLBACK FAILED: previous container $old is gone"; return 5
      fi ;;
    *) echo "$(ts) rollback: container was not touched yet" ;;
  esac
  if [ -z "$pb" ] && [ -f "$pf" ]; then rm -f "$pf"; echo "$(ts) rollback: $pf removed (there was none before)"; fi
  if [ -n "$kind" ]; then
    health_gate rollback "$c" "$before" "$pre" "$sig" "$daemons" 0 || return 5
  fi
  jq --arg t "$(ts)" --arg h "$how" '. + {rolled_back:true, rolled_back_at:$t, rollback:$h}' <<<"$s" > "$STATE_FILE"
  integrity_accept "$c" "pft-seccomp rollback ($how) of apply $(jq -r .id <<<"$s"): $c back to seccomp ${pre:0:19}" || true
  echo "$(ts) rollback RESULT: PASS - $c back under seccomp ${pre:0:19}"
}

# ---------------------------------------------------------------------------------------------------- main
cmd="${1:-}"; shift || true
ARG=""; ARG2=""; OUT=""; MIN=65; PHASE=both; LDS=(); JSON=0; PROM=""; SINCE=86400; YES=0; PF=""; UNTIL=""; REASON=""
MARGIN="$( [ -r "$HERE/margin.tsv" ] && echo "$HERE/margin.tsv" || { [ -r "$LIB/margin.tsv" ] && echo "$LIB/margin.tsv"; } )"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:-}"; [ -n "$OUT" ] || die "--out needs a directory" 3; shift ;;
    --minutes) MIN="${2:-}"; [[ "$MIN" =~ ^[0-9]+$ ]] || die "--minutes needs a number" 3; shift ;;
    --phase) PHASE="${2:-}"; [[ "$PHASE" =~ ^(census|log|both)$ ]] || die "--phase census|log|both" 3; shift ;;
    --learn) [ -d "${2:-}" ] || die "--learn needs a learn directory" 3; LDS+=("$2"); shift ;;
    --margin) MARGIN="${2:-}"; [ -r "$MARGIN" ] || die "--margin: cannot read $MARGIN" 3; shift ;;
    --json) JSON=1 ;;
    --prom) PROM="${2:-}"; [ -n "$PROM" ] || die "--prom needs a file" 3; shift ;;
    --textfile) PROM="$TEXTFILE_DIR/pft_seccomp_$HOST_LABEL.prom" ;;
    --since) SINCE="${2:-}"; [[ "$SINCE" =~ ^[0-9]+$ ]] || die "--since needs seconds" 3; shift ;;
    --profile-file) PF="${2:-}"; [ -n "$PF" ] || die "--profile-file needs a file" 3; shift ;;
    --until) UNTIL="${2:-}"; [[ "$UNTIL" =~ ^[0-9]+$ ]] || die "--until needs a unix time" 3; shift ;;
    --reason) REASON="${2:-}"; shift ;;
    --yes) YES=1 ;;
    -*) die "unknown option $1" 3 ;;
    *) if [ -z "$ARG" ]; then ARG="$1"; elif [ -z "$ARG2" ]; then ARG2="$1"; else die "too many arguments" 3; fi ;;
  esac
  shift
done
case "$cmd" in
  learn) [ -n "$OUT" ] || die "usage: pft-seccomp learn --out DIR [--minutes N] [--phase census|log|both]" 3
         do_learn "$OUT" "$MIN" "$PHASE"; exit $? ;;
  generate|diff) [ ${#LDS[@]} -gt 0 ] || die "usage: pft-seccomp $cmd --learn DIR [--learn DIR2] [--margin FILE]" 3
         GA="$(learn_inputs "${LDS[@]}")" || exit $?
         mapfile -t GA <<<"$GA"; py "$cmd" "${GA[@]}"; exit $? ;;
  check) [ -n "$ARG" ] || die "usage: pft-seccomp check FILE" 3
         py check "$ARG" --table "$(table_file)"; exit $? ;;
  audit)
    C="$(pick_container)"
    audit_checks "$C" "$(( $(now) - SINCE ))"; print_results "$C"
    [ -n "$PROM" ] && { write_prom "$PROM" || die "cannot write $PROM" 2; }
    [ "$FINDINGS" = 0 ] && exit 0 || exit 1 ;;
  apply) [ -n "$PF" ] || die "usage: pft-seccomp apply --profile-file FILE --yes" 3
         STATE_FILE="$STATE_DIR/apply-$(pick_container).json"; do_apply "$PF"; exit $? ;;
  rollback) [ "$YES" = 1 ] || { echo "pft-seccomp: rollback re-creates the container; re-run with --yes" >&2; exit 4; }
            [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "rollback needs root" 4
            STATE_FILE="$STATE_DIR/apply-$(pick_container).json"
            gate="$(maint_gate)"; case "$gate" in ok*) ;; *) echo "$(ts) rollback: REFUSED - ${gate#refuse }; nothing changed"; exit 4 ;; esac
            do_rollback manual; exit $? ;;
  validate) [ -n "$ARG" ] && [ -n "$ARG2" ] && valid_label "$ARG2" || die "usage: pft-seccomp validate FILE HOST" 3
            why="$(validate "$ARG" "$ARG2")" && exit 0; echo "$why"; exit 2 ;;
  ack-denials) [ "$YES" = 1 ] || { echo "pft-seccomp: ack-denials hides denials from the audit; re-run with --yes" >&2; exit 4; }
               [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "ack-denials needs root" 4
               do_ack "${UNTIL:-$(now)}" "$REASON"; exit 0 ;;
  pull) [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "pull needs root" 4
        do_pull; exit 0 ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
