#!/usr/bin/env bash
# pft-confine: discover, plan, test and apply a least-privilege runtime profile for a postfiatd container
# (cap_drop ALL + only the capabilities it needs, read-only root filesystem with tmpfs for the paths it writes,
# pids limit, memory limit sized from observed RSS). Run it on a SENTRY first.
#
# Usage: pft-confine discover [--container NAME] [--json]
#        pft-confine plan     [--container NAME] [--json]
#        sudo pft-confine probe [--container NAME]
#        sudo pft-confine apply --yes [--container NAME] [--timeout SEC]
#        pft-confine verify   [--container NAME] [--min-uptime SEC]
#        sudo pft-confine rollback --yes [--container NAME]
#
#  discover  read-only: CapAdd/CapDrop, ReadonlyRootfs, PidsLimit, memory/CPU limits, tmpfs, user, security_opt,
#            mounts, writable paths outside the mounts (docker diff + files open for writing in /proc/*/fd),
#            processes, PID 1 RSS/threads, task count, host memory. Changes nothing.
#  plan      the proposed profile derived from discover (see "How the plan is derived" in README.md), plus the
#            exact compose override / docker run command apply would use. Changes nothing.
#  probe     runs the planned profile in a THROWAWAY container (same image, --network none, fresh anonymous
#            volumes) and exercises what the entrypoint and cron do at runtime: cron job identity switch
#            (initgroups), a write to every planned tmpfs and mount, every /etc/cron.daily job except apt-compat,
#            the crontab logrotate line, and that postfiatd is still alive. The live container is not touched.
#  apply     refuses (exit 4) unless --yes is given, a pft-maint window is active with TIMEOUT + 300 s left and no
#            data-collection lock, and the node is full. Compose containers: writes docker-compose.confine.yml next
#            to the compose files, backs up .env and adds COMPOSE_FILE to it (so a plain `docker compose up -d`
#            keeps the profile), then `docker compose up -d`. `docker run` containers: stops the container, renames
#            it to NAME-preconfine-<id> (kept, restart policy set to no), and recreates NAME with the same image,
#            mounts, ports, user, restart/log policy and security_opt plus the profile. Then polls server_info:
#            not full within TIMEOUT (900 s) or SIGINT/SIGTERM -> automatic rollback to the previous config.
#  verify    re-reads HostConfig and checks every profile item, running/restarts/OOMKilled, uptime >= --min-uptime,
#            RSS and task count under their limits, server_state full and peers >= MIN_PEERS.
#  rollback  manual rollback of the last apply (uses the state file written by apply).
#
# Exit codes: 0 ok/PASS, 1 check failed / timed out and rolled back, 3 usage/config error, 4 refused,
#             5 rollback failed, 6 interrupted (rolled back).
# Env: CONTAINER (postfiatd)  TIMEOUT (900)  POLL_SEC (10)  MAINT_MARGIN (300)  MIN_PEERS (1)
#      STATE_DIR (/var/lib/pft-confine)  PROBE_SEC (20)  CONFINE_CAP_ADD ("" = derive; "none" = no caps)
#      CONFINE_TMPFS (replace derived tmpfs list)  CONFINE_TMPFS_OPTS (rw,noexec,nosuid,size=64m)
#      CONFINE_MEMORY_MB / CONFINE_PIDS (override sizing)  MEM_FLOOR_MB (2048)  PIDS_FLOOR (256)
#      Test hooks: PFT_CONFINE_TEST=1 (no root)  PFT_CONFINE_NOW_FILE (fake clock)  PFT_CONFINE_DOCKER_CMD
#      PFT_CONFINE_MAINT_CMD  PFT_CONFINE_RPC_CMD (prints the server_info .result JSON)  PFT_CONFINE_MEMINFO

# jq programs are single-quoted on purpose ($x are jq variables). "A && B || die" is intended: die always exits.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

CONTAINER="${CONTAINER:-postfiatd}"
TIMEOUT="${TIMEOUT:-900}"
POLL_SEC="${POLL_SEC:-10}"
MAINT_MARGIN="${MAINT_MARGIN:-300}"
MIN_PEERS="${MIN_PEERS:-1}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-confine}"
PROBE_SEC="${PROBE_SEC:-20}"
TMPFS_OPTS="${CONFINE_TMPFS_OPTS:-rw,noexec,nosuid,size=64m}"
MEM_FLOOR_MB="${MEM_FLOOR_MB:-2048}"
PIDS_FLOOR="${PIDS_FLOOR:-256}"
TEST="${PFT_CONFINE_TEST:-}"
DOCKER="${PFT_CONFINE_DOCKER_CMD:-docker}"
MAINT="${PFT_CONFINE_MAINT_CMD:-pft-maint}"
MEMINFO="${PFT_CONFINE_MEMINFO:-/proc/meminfo}"

usage() { sed -n '4,40p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "pft-confine: $1" >&2; exit "${2:-3}"; }
now() { if [ -n "${PFT_CONFINE_NOW_FILE:-}" ]; then cat "$PFT_CONFINE_NOW_FILE"; else date -u +%s; fi; }
nap() { if [ -n "${PFT_CONFINE_NOW_FILE:-}" ]; then echo $(( $(now) + $1 )) > "$PFT_CONFINE_NOW_FILE"; else sleep "$1"; fi; }
iso() { date -u -d "@$1" +%FT%TZ; }
log() { echo "[$(iso "$(now)")] $*"; }

server_info() { # NAME -> .result.info JSON, {} when the RPC does not answer
  local r
  if [ -n "${PFT_CONFINE_RPC_CMD:-}" ]; then r="$("$PFT_CONFINE_RPC_CMD" server_info)"
  else r="$("$DOCKER" exec "$1" curl -s --max-time 5 http://127.0.0.1:5005/ -X POST \
              -H 'Content-Type: application/json' -d '{"method":"server_info","params":[{}]}' 2>/dev/null \
            | jq -c '.result // empty' 2>/dev/null)"; fi
  [ -n "$r" ] || r='{}'
  jq -c '.info // {}' <<<"$r" 2>/dev/null || echo '{}'
}
node_state() { jq -r '.server_state // "down"' <<<"$1"; }
is_full() { case "$1" in full|validating|proposing) return 0 ;; esac; return 1; }

maint_gate() { # -> "ok <remaining>" or "refuse <reason>"
  local j w rem nl
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "refuse pft-maint status failed (is pft-maint installed?)"; return; }
  w="$(jq -r '.window // "none"' <<<"$j" 2>/dev/null)"
  rem="$(jq -r '.remaining_sec // 0' <<<"$j" 2>/dev/null)"; [[ "$rem" =~ ^[0-9]+$ ]] || rem=0
  nl="$(jq -r '.locks | length' <<<"$j" 2>/dev/null)"; [[ "$nl" =~ ^[0-9]+$ ]] || nl=1
  if [ "$w" != active ]; then echo "refuse no active pft-maint window (window=$w); run: sudo pft-maint start --ttl 30m --reason ..."
  elif [ "$rem" -lt $((TIMEOUT + MAINT_MARGIN)) ]; then echo "refuse window has ${rem}s left, apply needs TIMEOUT+MAINT_MARGIN=$((TIMEOUT + MAINT_MARGIN))s"
  elif [ "$nl" -gt 0 ]; then echo "refuse $nl pft-maint data-collection lock(s) held: $(jq -r '.locks | join("; ")' <<<"$j")"
  else echo "ok $rem"; fi
}

# ---------- discover ----------
# Runs inside the container: PID 1 RSS/threads, task count, process names, files open for writing.
# fdinfo flags are octal; (flags & 3) != 0 means O_WRONLY or O_RDWR.
PROC_SCRIPT='awk "/^VmRSS:|^Threads:/{print \$1, \$2}" /proc/1/status
echo "Tasks: $(ls -d /proc/[0-9]*/task/[0-9]* 2>/dev/null | wc -l)"
for p in /proc/[0-9]*; do [ "$p" = /proc/self ] || echo "Proc: $(cat "$p/comm" 2>/dev/null)"; done
for f in /proc/[0-9]*/fd/*; do t=$(readlink "$f" 2>/dev/null) || continue
  case "$t" in /proc/*|/dev/*) continue ;; /*) ;; *) continue ;; esac
  fl=$(awk "/^flags:/{print \$2}" "${f%/fd/*}/fdinfo/${f##*/}" 2>/dev/null)
  [ -n "$fl" ] && [ $(( 0$fl & 3 )) -ne 0 ] && echo "Wfile: $t"
done 2>/dev/null; true'

discover_json() { # NAME -> one JSON document
  local c="$1" insp diff procs memtotal dirs
  insp="$("$DOCKER" inspect "$c" 2>/dev/null)" || die "container $c not found" 3
  insp="$(jq -c '.[0]' <<<"$insp")"
  diff="$("$DOCKER" diff "$c" 2>/dev/null)"
  procs="$("$DOCKER" exec "$c" sh -c "$PROC_SCRIPT" 2>/dev/null)"
  memtotal="$(awk '/^MemTotal:/{print $2 * 1024}' "$MEMINFO")"
  dirs="$(awk '$1 == "A" {print $2}' <<<"$diff" | "$DOCKER" exec -i "$c" sh -c 'while read -r p; do [ -d "$p" ] && echo "$p"; done' 2>/dev/null)"
  jq -n --argjson i "$insp" --arg diff "$diff" --arg procs "$procs" --arg dirs "$dirs" --argjson mt "${memtotal:-0}" '
    def under($p; $roots): any($roots[]; . as $r | $p == $r or ($p | startswith($r + "/")));
    ($i.Mounts | map(.Destination)) as $mnt
    | ($procs | split("\n")) as $pl
    | ($diff | split("\n") | map(select(length > 2) | {kind: .[0:1], path: .[2:]})) as $d
    | {container: $i.Name[1:], image: $i.Config.Image, image_id: $i.Image,
       mode: (if ($i.Config.Labels["com.docker.compose.project.working_dir"] // "") != "" then "compose" else "run" end),
       compose: {working_dir: ($i.Config.Labels["com.docker.compose.project.working_dir"] // null),
                 config_files: ($i.Config.Labels["com.docker.compose.project.config_files"] // null),
                 service: ($i.Config.Labels["com.docker.compose.service"] // null)},
       user: ($i.Config.User // ""),
       cap_add: ($i.HostConfig.CapAdd // []), cap_drop: ($i.HostConfig.CapDrop // []),
       readonly_rootfs: $i.HostConfig.ReadonlyRootfs,
       pids_limit: ($i.HostConfig.PidsLimit // 0), memory: $i.HostConfig.Memory, nano_cpus: $i.HostConfig.NanoCpus,
       tmpfs: ((($i.HostConfig.Tmpfs // {}) | keys) + ($i.Mounts | map(select(.Type == "tmpfs") | .Destination))),
       security_opt: ($i.HostConfig.SecurityOpt // []),
       mounts: [$i.Mounts[] | {type: .Type, name: (.Name // null), source: .Source, destination: .Destination, rw: .RW}],
       running: $i.State.Running, started_at: $i.State.StartedAt, restart_count: $i.RestartCount,
       diff_outside_mounts: [$d[] | select(under(.path; $mnt) | not)],
       added_dirs: ($dirs | split("\n") | map(select(length > 0))),
       write_open_outside_mounts: ([$pl[] | select(startswith("Wfile: ")) | .[7:] | select(under(.; $mnt) | not)] | unique),
       processes: ([$pl[] | select(startswith("Proc: ")) | .[6:]] | unique),
       pid1_rss_bytes: (([$pl[] | select(startswith("VmRSS:")) | split(" ")[1] | tonumber] | first // 0) * 1024),
       pid1_threads: ([$pl[] | select(startswith("Threads:")) | split(" ")[1] | tonumber] | first // 0),
       tasks: ([$pl[] | select(startswith("Tasks:")) | split(" ")[1] | tonumber] | first // 0),
       host_mem_bytes: $mt}'
}

# ---------- plan ----------
# Derivation: tmpfs = /tmp + for every docker-diff "A" entry outside the mounts the entry itself if it is a
# directory, else its parent directory, + the parent of every file open for writing outside the mounts; nested entries collapse into their
# parent; "/" and the top-level dirs (/var, /usr, /etc ...) are never mounted over - they go to "unresolved".
plan_json() { # DISCOVER_JSON -> profile JSON
  jq -c --arg capenv "${CONFINE_CAP_ADD:-}" --arg tmpenv "${CONFINE_TMPFS:-}" --arg opts "$TMPFS_OPTS" \
        --arg memmb "${CONFINE_MEMORY_MB:-}" --arg pidsov "${CONFINE_PIDS:-}" \
        --argjson floor "$MEM_FLOOR_MB" --argjson pfloor "$PIDS_FLOOR" '
    def parent: sub("/[^/]+$"; "") | if . == "" then "/" else . end;
    def depth: [scan("/")] | length;
    . as $d
    | ([$d.diff_outside_mounts[] | select(.kind == "A") | .path
        | if (. as $p | $d.added_dirs | index($p)) != null then . else parent end]
       + [$d.write_open_outside_mounts[] | parent]) as $cand1
    | (if $tmpenv != "" then ($tmpenv | split(" ") | map(select(length > 0)))
       else (["/tmp"] + $cand1) end | unique) as $c
    | ([$c[] | select(depth >= 2 or . == "/tmp" or . == "/run")]) as $ok
    | ([$c[] | select((depth >= 2 or . == "/tmp" or . == "/run") | not)]) as $unres
    | ([$ok[] as $p | select(any($ok[]; . != $p and ($p | startswith(. + "/"))) | not) | $p] | unique) as $tmpfs
    | (if $capenv == "none" then []
       elif $capenv != "" then ($capenv | split(" ") | map(select(length > 0) | ascii_upcase | sub("^CAP_"; "")))
       elif any($d.processes[]; . == "cron") then ["SETGID", "SETUID"] else [] end) as $caps
    | (if $memmb != "" then ($memmb | tonumber)
       else ([$floor, (($d.pid1_rss_bytes * 3 / 1048576 / 256) | ceil) * 256] | max) end) as $mb
    | (if $pidsov != "" then ($pidsov | tonumber) else ([$pfloor, $d.tasks * 4] | max) end) as $pids
    | {container: $d.container, mode: $d.mode, image: $d.image,
       cap_drop: ["ALL"], cap_add: $caps, read_only: true,
       tmpfs: $tmpfs, tmpfs_opts: $opts, pids_limit: $pids, memory_bytes: ($mb * 1048576),
       security_opt: (($d.security_opt + ["no-new-privileges"]) | map(sub(":true$"; "")) | unique),
       unresolved: $unres,
       rationale: {
         cap_add: (if $capenv != "" then "CONFINE_CAP_ADD override"
                   elif ($caps | length) > 0 then "cron runs in the container; it calls setgid/initgroups/setuid before every job"
                   else "no process needing capabilities found" end),
         tmpfs: "/tmp + directories written outside the mounts (docker diff A entries, files open for writing)",
         memory: (if $memmb != "" then "CONFINE_MEMORY_MB override"
                  else "max(\($floor) MiB, 3 x PID1 RSS \(($d.pid1_rss_bytes / 1048576) | floor) MiB) rounded up to 256 MiB" end),
         pids: (if $pidsov != "" then "CONFINE_PIDS override" else "max(\($pfloor), 4 x \($d.tasks) tasks)" end)},
       warnings: ([if $mb * 1048576 > $d.host_mem_bytes * 0.75 and $d.host_mem_bytes > 0
                   then "memory limit exceeds 75% of host memory" else empty end])}' <<<"$1"
}

profile_run_args() { # PROFILE -> one docker-run flag per line
  jq -r '"--cap-drop=ALL", (.cap_add[] | "--cap-add=\(.)"), "--read-only",
         (.tmpfs_opts as $o | .tmpfs[] | "--tmpfs=\(.):\($o)"),
         "--pids-limit=\(.pids_limit)", "--memory=\(.memory_bytes)", "--memory-swap=\(.memory_bytes)",
         (.security_opt[] | "--security-opt=\(.)")' <<<"$1"
}

compose_override() { # PROFILE SERVICE -> docker-compose.confine.yml body
  jq -r --arg svc "$2" '
    "# written by pft-confine apply (least-privilege profile); remove with: sudo pft-confine rollback --yes",
    "services:", "  \($svc):", "    cap_drop:", "      - ALL",
    (if (.cap_add | length) > 0 then "    cap_add:", (.cap_add[] | "      - \(.)") else empty end),
    "    read_only: true", "    tmpfs:", (.tmpfs_opts as $o | .tmpfs[] | "      - \"\(.):\($o)\""),
    "    pids_limit: \(.pids_limit)", "    mem_limit: \(.memory_bytes)", "    memswap_limit: \(.memory_bytes)"' <<<"$1"
}

# Recreate args for a `docker run` container from its inspect JSON (everything except the profile).
recreate_args() { # INSPECT_JSON(.[0]) IMAGE_ENV_JSON -> one arg per line (NUL-free), image + cmd last
  jq -r --argjson ienv "$2" '
    "--name=\(.Name[1:])",
    "--restart=\(.HostConfig.RestartPolicy.Name)\(if .HostConfig.RestartPolicy.Name == "on-failure" then ":\(.HostConfig.RestartPolicy.MaximumRetryCount)" else "" end)",
    (if (.Config.User // "") != "" then "--user=\(.Config.User)" else empty end),
    "--log-driver=\(.HostConfig.LogConfig.Type)",
    ((.HostConfig.LogConfig.Config // {}) | to_entries[] | "--log-opt=\(.key)=\(.value)"),
    (if .HostConfig.NetworkMode != "default" then "--network=\(.HostConfig.NetworkMode)" else empty end),
    ((.HostConfig.PortBindings // {}) | to_entries[] | .key as $k | .value[]
      | "--publish=\(if .HostIp != "" then .HostIp + ":" else "" end)\(.HostPort):\($k | sub("/tcp$"; ""))"),
    (.Mounts[] | if .Type == "volume" then "--volume=\(.Name):\(.Destination)\(if .RW then "" else ":ro" end)"
                 elif .Type == "bind" then "--volume=\(.Source):\(.Destination)\(if .RW then "" else ":ro" end)"
                 else empty end),
    (.Config.Env // [] | map(select(. as $e | $ienv | index($e) | not)) | .[] | "--env=\(.)"),
    .Config.Image, (.Config.Cmd // [])[]' <<<"$1"
}

# ---------- apply / rollback ----------
wait_full() { # NAME TIMEOUT -> 0 when full; logs each poll
  local c="$1" to="$2" t0 info s
  t0="$(now)"
  while :; do
    info="$(server_info "$c")"; s="$(node_state "$info")"
    log "poll +$(( $(now) - t0 ))s server_state=$s peers=$(jq -r '.peers // 0' <<<"$info")"
    is_full "$s" && return 0
    [ $(( $(now) - t0 )) -ge "$to" ] && return 1
    nap "$POLL_SEC"
  done
}

hostconfig_summary() { # NAME -> compact JSON of the profile-relevant HostConfig fields
  "$DOCKER" inspect "$1" 2>/dev/null | jq -c '.[0] | {Id: .Id[0:12], CapAdd: .HostConfig.CapAdd, CapDrop: .HostConfig.CapDrop,
    ReadonlyRootfs: .HostConfig.ReadonlyRootfs, Tmpfs: .HostConfig.Tmpfs, PidsLimit: .HostConfig.PidsLimit,
    Memory: .HostConfig.Memory, MemorySwap: .HostConfig.MemorySwap, SecurityOpt: .HostConfig.SecurityOpt,
    User: .Config.User, Restart: .HostConfig.RestartPolicy.Name}'
}

do_rollback() { # uses $STATE_FILE
  local st mode c
  st="$(cat "$STATE_FILE")" || { log "ROLLBACK FAILED: no state file $STATE_FILE"; return 5; }
  mode="$(jq -r .mode <<<"$st")"; c="$(jq -r .container <<<"$st")"
  log "rollback ($mode) of apply $(jq -r .id <<<"$st")"
  if [ "$mode" = compose ]; then
    local wd; wd="$(jq -r .working_dir <<<"$st")"
    cp -p -- "$(jq -r .env_backup <<<"$st")" "$wd/.env" && rm -f -- "$wd/docker-compose.confine.yml" \
      && (cd "$wd" && "$DOCKER" compose up -d 2>&1) || { log "ROLLBACK FAILED (compose)"; return 5; }
  else
    local old; old="$(jq -r .old_container <<<"$st")"
    "$DOCKER" rm -f "$c" >/dev/null 2>&1
    "$DOCKER" rename "$old" "$c" && "$DOCKER" update --restart="$(jq -r .restart <<<"$st")" "$c" >/dev/null \
      && "$DOCKER" start "$c" >/dev/null || { log "ROLLBACK FAILED (run)"; return 5; }
  fi
  if wait_full "$c" "$TIMEOUT"; then log "rollback complete: previous config restored, node full"; jq -c '.rolled_back = true' <<<"$st" > "$STATE_FILE"; return 0; fi
  log "ROLLBACK: previous config restored but node not full after ${TIMEOUT}s"; return 5
}

# ---------- main ----------
CMD="${1:-}"; [ $# -gt 0 ] && shift
YES=0; JSON=0; MIN_UPTIME=0
while [ $# -gt 0 ]; do
  case "$1" in
    --container) CONTAINER="${2:?}"; shift 2 ;;
    --timeout) TIMEOUT="${2:?}"; shift 2 ;;
    --min-uptime) MIN_UPTIME="${2:?}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 3 ;;
  esac
done
[[ "$TIMEOUT" =~ ^[0-9]+$ && "$MIN_UPTIME" =~ ^[0-9]+$ ]] || die "--timeout/--min-uptime must be seconds"
command -v jq >/dev/null || die "jq is required"
STATE_FILE="$STATE_DIR/$CONTAINER.json"
disc() { D="$(discover_json "$CONTAINER")" && [ -n "$D" ] || die "discover failed for $CONTAINER" 3; }
need_root() { [ -n "$TEST" ] || [ "$(id -u)" -eq 0 ] || die "$CMD needs root (sudo)" 3; }

case "$CMD" in
  discover)
    disc
    if [ "$JSON" = 1 ]; then echo "$D"; exit 0; fi
    jq -r '"container:        \(.container) (\(.mode)) image \(.image)",
      "user:             \(.user)",
      "cap_add/cap_drop: \(.cap_add) / \(.cap_drop)",
      "readonly_rootfs:  \(.readonly_rootfs)",
      "pids_limit:       \(.pids_limit)   memory: \(.memory)   nano_cpus: \(.nano_cpus)",
      "tmpfs:            \(.tmpfs)",
      "security_opt:     \(.security_opt)",
      "mounts:           \([.mounts[] | "\(.destination)(\(.type))"] | join(" "))",
      "processes:        \(.processes | join(" "))",
      "pid1:             rss \((.pid1_rss_bytes / 1048576) | floor) MiB, threads \(.pid1_threads); tasks in container \(.tasks); host memory \((.host_mem_bytes / 1048576) | floor) MiB",
      "written outside mounts (docker diff):", (.diff_outside_mounts[] | "  \(.kind) \(.path)"),
      "open for writing outside mounts:", (if (.write_open_outside_mounts | length) == 0 then "  (none)" else (.write_open_outside_mounts[] | "  \(.)") end)' <<<"$D"
    ;;
  plan)
    disc; P="$(plan_json "$D")"
    if [ "$JSON" = 1 ]; then echo "$P"; exit 0; fi
    jq -r '"proposed profile for \(.container) (\(.mode)):",
      "  cap_drop:     ALL", "  cap_add:      \(.cap_add | join(" "))   (\(.rationale.cap_add))",
      "  read_only:    true", "  tmpfs:        \(.tmpfs | join(" ")) [\(.tmpfs_opts)]   (\(.rationale.tmpfs))",
      "  pids_limit:   \(.pids_limit)   (\(.rationale.pids))",
      "  memory:       \(.memory_bytes / 1048576) MiB, no swap   (\(.rationale.memory))",
      "  security_opt: \(.security_opt | join(" "))",
      (if (.unresolved | length) > 0 then "  UNRESOLVED (not mounted over, review): \(.unresolved | join(" "))" else empty end),
      (.warnings[] | "  WARNING: \(.)")' <<<"$P"
    if [ "$(jq -r .mode <<<"$D")" = compose ]; then
      echo "apply would write $(jq -r .compose.working_dir <<<"$D")/docker-compose.confine.yml:"
      compose_override "$P" "$(jq -r .compose.service <<<"$D")" | sed 's/^/  | /'
    else
      I="$("$DOCKER" inspect "$CONTAINER" | jq -c '.[0]')"
      IENV="$("$DOCKER" image inspect "$(jq -r .Config.Image <<<"$I")" 2>/dev/null | jq -c '.[0].Config.Env // []')"
      echo "apply would recreate with: docker run -d \\"
      { profile_run_args "$P"; recreate_args "$I" "${IENV:-[]}"; } | sed 's/^/    /; s/$/ \\/'
    fi
    ;;
  probe)
    need_root
    disc; P="$(plan_json "$D")"
    PC="pft-confine-probe-$$"
    mapfile -t PARGS < <(profile_run_args "$P")
    mapfile -t VARGS < <(jq -r '.mounts[] | "--volume=\(.destination)"' <<<"$D")
    U="$(jq -r .user <<<"$D")"
    log "probe: throwaway container $PC, image $(jq -r .image <<<"$D"), --network none, fresh anonymous volumes"
    log "probe profile: $(jq -c '{cap_add, tmpfs, pids_limit, memory_bytes}' <<<"$P")"
    "$DOCKER" run -d --name "$PC" --network none ${U:+--user="$U"} "${PARGS[@]}" "${VARGS[@]}" "$(jq -r .image <<<"$D")" >/dev/null \
      || die "probe container failed to start" 1
    trap '"$DOCKER" rm -fv "$PC" >/dev/null 2>&1' EXIT
    nap "$PROBE_SEC"
    fails=0
    chk() { if [ "$1" = 0 ]; then echo "  [PASS] $2"; else echo "  [FAIL] $2"; fails=$((fails + 1)); fi; [ -n "${3:-}" ] && while IFS= read -r l; do echo "         | $l"; done <<<"$3"; true; }
    r="$("$DOCKER" inspect -f '{{.State.Running}} {{.RestartCount}}' "$PC" 2>/dev/null)"
    [ "$r" = "true 0" ]; chk $? "container running, 0 restarts ($r)"
    if [ "$r" != "true 0" ]; then # nothing else can be exercised; show why it stopped
      "$DOCKER" logs "$PC" 2>&1 | tail -5 | while IFS= read -r l; do echo "  log: $l"; done
      log "probe RESULT: FAIL (container not running)"; exit 1
    fi
    o="$("$DOCKER" exec "$PC" sh -c 'grep CapEff /proc/1/status' 2>&1)"
    [[ "$o" == CapEff:* ]]; chk $? "capabilities in effect: ${o##*:	}"
    if jq -e '.processes | index("cron")' <<<"$D" >/dev/null; then
      o="$("$DOCKER" exec "$PC" setpriv --reuid=0 --regid=0 --init-groups true 2>&1)"; chk $? "cron job identity switch (setpriv --init-groups, as cron does before each job)" "$o"
    fi
    while read -r p; do
      o="$("$DOCKER" exec "$PC" sh -c "touch '$p/.pft-confine-probe' && rm -f '$p/.pft-confine-probe'" 2>&1)"; chk $? "write $p" "$o"
    done < <(jq -r '(.tmpfs[]), (input | .mounts[] | select(.rw) | .destination)' <<<"$P"$'\n'"$D")
    for j in $("$DOCKER" exec "$PC" sh -c 'ls /etc/cron.daily 2>/dev/null'); do
      [ "$j" = apt-compat ] && { echo "  [SKIP] cron.daily/apt-compat (sleeps a random time up to 30 min; its only write, /var/lib/apt/daily_lock, is covered above if planned)"; continue; }
      o="$("$DOCKER" exec "$PC" sh -c "/etc/cron.daily/$j" 2>&1)"; chk $? "cron.daily/$j" "$o"
    done
    lr="$("$DOCKER" exec "$PC" sh -c "grep -h logrotate /etc/cron.d/* 2>/dev/null | grep -v '^#' | head -1 | sed 's/^\([^ ]* *\)\{6\}//'")"
    if [ -n "$lr" ]; then o="$("$DOCKER" exec "$PC" sh -c "$lr" 2>&1)"; chk $? "crontab job: $lr" "$o"; fi
    o="$("$DOCKER" exec "$PC" sh -c 'tr "\0" " " </proc/1/cmdline' 2>&1)"
    case "$o" in *postfiatd*) chk 0 "postfiatd still PID 1: $o" ;; *) chk 1 "postfiatd still PID 1" "$o" ;; esac
    "$DOCKER" logs "$PC" 2>&1 | grep -iE 'read-only|permission denied|operation not permitted|cannot' | head -5 | sed 's/^/  log: /'
    [ "$fails" -eq 0 ] && { log "probe RESULT: PASS"; exit 0; }
    log "probe RESULT: FAIL ($fails check(s))"; exit 1
    ;;
  apply)
    need_root
    [ "$YES" = 1 ] || die "apply recreates the container; re-run with --yes" 4
    GATE="$(maint_gate)"
    case "$GATE" in ok*) ;; *) die "REFUSED: ${GATE#refuse }" 4 ;; esac
    INFO="$(server_info "$CONTAINER")"; S="$(node_state "$INFO")"
    is_full "$S" || die "REFUSED: node is $S, not full" 4
    disc; P="$(plan_json "$D")"
    [ "$(jq '.unresolved | length' <<<"$P")" -eq 0 ] || die "REFUSED: unresolved writable paths $(jq -c .unresolved <<<"$P")" 4
    MODE="$(jq -r .mode <<<"$D")"; ID="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"
    mkdir -p "$STATE_DIR" || die "cannot create $STATE_DIR"
    log "apply $ID on $CONTAINER ($MODE); maintenance gate: $GATE; pre: server_state=$S peers=$(jq -r '.peers // 0' <<<"$INFO")"
    log "before HostConfig: $(hostconfig_summary "$CONTAINER")"
    log "profile: $(jq -c 'del(.rationale)' <<<"$P")"
    if [ "$MODE" = compose ]; then
      WD="$(jq -r .compose.working_dir <<<"$D")"; SVC="$(jq -r .compose.service <<<"$D")"
      [ -d "$WD" ] || die "compose working dir $WD missing" 3
      FILES="$(jq -r '.compose.config_files | split(",") | map(sub(".*/"; "")) | map(select(. != "docker-compose.confine.yml")) | join(":")' <<<"$D")"
      EB="$WD/.env.pre-confine-$ID"; touch "$WD/.env"; cp -p -- "$WD/.env" "$EB" || die "cannot back up .env"
      jq -n --arg id "$ID" --arg c "$CONTAINER" --arg wd "$WD" --arg eb "$EB" --argjson p "$P" \
        '{id:$id,mode:"compose",container:$c,working_dir:$wd,env_backup:$eb,profile:$p}' > "$STATE_FILE"
      compose_override "$P" "$SVC" > "$WD/docker-compose.confine.yml"
      { grep -v '^COMPOSE_FILE=' "$EB"; echo "COMPOSE_FILE=$FILES:docker-compose.confine.yml"; } > "$WD/.env"
      chmod --reference="$EB" "$WD/.env" 2>/dev/null
      log "wrote $WD/docker-compose.confine.yml; .env backed up to $EB, COMPOSE_FILE=$FILES:docker-compose.confine.yml"
      ( cd "$WD" && "$DOCKER" compose config -q ) || { log "compose config invalid"; do_rollback; exit 1; }
      trap 'log "interrupted"; do_rollback; exit 6' INT TERM
      ( cd "$WD" && "$DOCKER" compose up -d 2>&1 ) || { log "compose up failed"; do_rollback; exit 1; }
    else
      I="$("$DOCKER" inspect "$CONTAINER" | jq -c '.[0]')"
      IENV="$("$DOCKER" image inspect "$(jq -r .Config.Image <<<"$I")" 2>/dev/null | jq -c '.[0].Config.Env // []')"
      OLD="$CONTAINER-preconfine-$ID"; RP="$(jq -r '.HostConfig.RestartPolicy.Name' <<<"$I")"
      mapfile -t ARGS < <(profile_run_args "$P"; recreate_args "$I" "${IENV:-[]}")
      jq -n --arg id "$ID" --arg c "$CONTAINER" --arg o "$OLD" --arg rp "$RP" --argjson p "$P" \
        '{id:$id,mode:"run",container:$c,old_container:$o,restart:$rp,profile:$p}' > "$STATE_FILE"
      log "recreate: docker run -d ${ARGS[*]}"
      "$DOCKER" stop -t 60 "$CONTAINER" >/dev/null && "$DOCKER" rename "$CONTAINER" "$OLD" \
        && "$DOCKER" update --restart=no "$OLD" >/dev/null || { log "could not stop/rename $CONTAINER"; do_rollback; exit 1; }
      log "previous container kept as $OLD (stopped, restart=no)"
      trap 'log "interrupted"; do_rollback; exit 6' INT TERM
      "$DOCKER" run -d "${ARGS[@]}" >/dev/null || { log "docker run failed"; do_rollback; exit 1; }
    fi
    if wait_full "$CONTAINER" "$TIMEOUT"; then
      trap - INT TERM
      log "after HostConfig: $(hostconfig_summary "$CONTAINER")"
      jq -c --arg t "$(iso "$(now)")" '.applied_at = $t' "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"
      log "apply RESULT: PASS - profile active, node full (state $STATE_FILE)"; exit 0
    fi
    log "node not full within ${TIMEOUT}s - rolling back"
    do_rollback; rc=$?; [ "$rc" -eq 0 ] && exit 1; exit "$rc"
    ;;
  rollback)
    need_root
    [ "$YES" = 1 ] || die "rollback recreates the container; re-run with --yes" 4
    [ -f "$STATE_FILE" ] || die "no apply state for $CONTAINER ($STATE_FILE)" 3
    do_rollback; exit $?
    ;;
  verify)
    [ -f "$STATE_FILE" ] && P="$(jq -c .profile "$STATE_FILE")" || { disc; P="$(plan_json "$D")"; }
    I="$("$DOCKER" inspect "$CONTAINER" 2>/dev/null | jq -c '.[0]')" || die "container $CONTAINER not found"
    PR="$("$DOCKER" exec "$CONTAINER" sh -c "$PROC_SCRIPT" 2>/dev/null)"
    INFO="$(server_info "$CONTAINER")"
    fails=0
    chk() { if [ "$1" = 0 ]; then echo "  [PASS] $2"; else echo "  [FAIL] $2"; fails=$((fails + 1)); fi; }
    echo "pft-confine verify $CONTAINER - $(iso "$(now)")"
    j() { jq -r "$1" <<<"$I"; }
    [ "$(j '(.HostConfig.CapDrop // []) | map(ascii_upcase) | index("ALL") != null')" = true ]; chk $? "cap_drop ALL (got $(j '.HostConfig.CapDrop | tojson'))"
    want="$(jq -c '.cap_add | sort' <<<"$P")"; got="$(j '(.HostConfig.CapAdd // []) | map(ascii_upcase | sub("^CAP_"; "")) | sort | tojson')"
    [ "$want" = "$got" ]; chk $? "cap_add = $want (got $got)"
    [ "$(j .HostConfig.ReadonlyRootfs)" = true ]; chk $? "read-only root filesystem"
    want="$(jq -c '.tmpfs | sort' <<<"$P")"; got="$(j '(((.HostConfig.Tmpfs // {}) | keys) + (.Mounts | map(select(.Type == "tmpfs") | .Destination))) | unique | tojson')"
    [ "$want" = "$got" ]; chk $? "tmpfs = $want (got $got)"
    want="$(jq .pids_limit <<<"$P")"; [ "$(j '.HostConfig.PidsLimit // 0')" = "$want" ]; chk $? "pids_limit $want (got $(j '.HostConfig.PidsLimit // 0'))"
    want="$(jq .memory_bytes <<<"$P")"; [ "$(j .HostConfig.Memory)" = "$want" ]; chk $? "memory limit $want (got $(j .HostConfig.Memory))"
    [ "$(j '(.HostConfig.SecurityOpt // []) | map(sub(":true$"; "")) | index("no-new-privileges") != null')" = true ]; chk $? "no-new-privileges"
    [ "$(j .State.Running)" = true ] && [ "$(j .State.OOMKilled)" = false ]; chk $? "running, OOMKilled=$(j .State.OOMKilled)"
    [ "$(j .RestartCount)" = 0 ]; chk $? "restart count $(j .RestartCount)"
    up=$(( $(now) - $(date -u -d "$(j .State.StartedAt)" +%s) ))
    [ "$up" -ge "$MIN_UPTIME" ]; chk $? "uptime ${up}s >= ${MIN_UPTIME}s (started $(j .State.StartedAt))"
    rss="$(awk '/^VmRSS:/{print $2 * 1024}' <<<"$PR")"; lim="$(j .HostConfig.Memory)"
    [ "$lim" -gt 0 ] && pct="$(( ${rss:-0} * 100 / lim ))%" || pct="no limit set"
    [ -n "$rss" ] && [ "$lim" -gt 0 ] && [ "$rss" -lt "$lim" ]; chk $? "PID1 RSS $(( ${rss:-0} / 1048576 )) MiB < limit $(( lim / 1048576 )) MiB ($pct)"
    tasks="$(awk '/^Tasks:/{print $2}' <<<"$PR")"; pl="$(j '.HostConfig.PidsLimit // 0')"
    [ -n "$tasks" ] && [ "$pl" -gt 0 ] && [ "$tasks" -lt "$pl" ]; chk $? "tasks ${tasks:-?} < pids_limit $pl"
    s="$(node_state "$INFO")"; is_full "$s"; chk $? "server_state $s"
    pe="$(jq -r '.peers // 0' <<<"$INFO")"; [ "$pe" -ge "$MIN_PEERS" ]; chk $? "peers $pe >= $MIN_PEERS"
    [ "$fails" -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
    echo "RESULT: FAIL ($fails)"; exit 1
    ;;
  *) usage >&2; exit 3 ;;
esac
