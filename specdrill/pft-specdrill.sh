#!/usr/bin/env bash
# pft-specdrill: measure postfiatd resource floors on DISPOSABLE throwaway nodes, one cell at a time, without
# touching the live validator/sentry. Each cell runs the live node's own image (never pulled) with its baked config
# (no validator token, no ports published) on its own bridge network and its own docker volume, under one
# --cpus / --memory / --device-{read,write}-bps limit, and records server_state, ledger lag vs the public reference
# RPC, peers, close times, OOM/restart events and peak RSS. specdrill.py turns the cells into cells.json/csv + REPORT.md.
#
# Usage: pft-specdrill plan [--axes cpu,mem,io]           print the matrix, every guard's current verdict; no changes
#        sudo pft-specdrill run-cell --out DIR --axis A --cpus N --mem MIB [--io BPS]   one cell (DIR/<cell>/)
#        sudo pft-specdrill matrix --out DIR --axes cpu,io --yes       every cell of the axes in sequence
#        pft-specdrill report CELLS_DIR OUT_DIR                        specdrill.py report (offline, deterministic)
#        sudo pft-specdrill cleanup                                    remove every pft-specdrill labelled resource
# Guards (checked before every cell; any failure -> exit 4, nothing created): root + exclusive lock; an active
#   pft-maint window with >= the cell's worst-case duration left; live node full and its lag <= LIVE_LAG_MAX;
#   pft-integrity verify PASS (its timer is then paused for the cell and re-armed by the trap and by a failsafe
#   transient timer); MemAvailable - cell memory >= HEADROOM_MIB; free disk >= DISK_MIN_GB; the image is the live
#   container's image id, present locally (run with --pull never); no leftover labelled resources.
#   After `docker create` and before start: the cell config has no [validator_token]/[validation_seed]/[ips_fixed],
#   and the container publishes no ports, mounts only its own volume, is unprivileged and on its own network.
# Per-poll aborts (cell torn down, meta.abort = reason): live node not full or lag > LIVE_LAG_MAX for LIVE_ABORT_POLLS
#   polls (live_lag); the maint window ended (maint_window_ended); MemAvailable < HEADROOM_MIB/2 (host_mem_low).
# Exit codes: 0 ok, 1 cell ran but failed to record, 3 usage, 4 refused by a guard.
# Env: LIVE_CONTAINER (postfiatd)  REF_RPC (https://rpc.testnet.postfiat.org/)  LIVE_RPC (http://127.0.0.1:5005/)
#      POLL_SEC (10)  FULL_DEADLINE_S (600)  FULL_TIMEOUT_S (900)  WINDOW_S (1200)  LIVE_LAG_MAX (3)
#      LIVE_ABORT_POLLS (2)  HEADROOM_MIB (1536)  DISK_MIN_GB (10)  LOCK (/run/pft-specdrill.lock)
#      Test seams: PFT_SPECDRILL_TEST=1 (no root check)  DOCKER  CURL  SYSTEMCTL  SYSTEMD_RUN  PFT_MAINT_BIN
#      PFT_INTEGRITY_BIN  MEMINFO (/proc/meminfo)  PROC_ROOT (/proc)  CGROUP_ROOT (/sys/fs/cgroup/system.slice)
#      DF_PATH (/var/lib/docker)  IO_DEV (disk of DF_PATH)  NOW_FILE (fake clock; naps advance it)

set -uo pipefail
umask 022

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PY="${PY:-python3}"
HELPER="${HELPER:-$HERE/specdrill.py}"
[ -f "$HELPER" ] || HELPER=/usr/local/lib/pft-specdrill/specdrill.py
LIVE_CONTAINER="${LIVE_CONTAINER:-postfiatd}"
REF_RPC="${REF_RPC:-https://rpc.testnet.postfiat.org/}"
LIVE_RPC="${LIVE_RPC:-http://127.0.0.1:5005/}"
POLL_SEC="${POLL_SEC:-10}"
FULL_DEADLINE_S="${FULL_DEADLINE_S:-600}"
FULL_TIMEOUT_S="${FULL_TIMEOUT_S:-900}"
WINDOW_S="${WINDOW_S:-1200}"
LIVE_LAG_MAX="${LIVE_LAG_MAX:-3}"
LIVE_ABORT_POLLS="${LIVE_ABORT_POLLS:-2}"
HEADROOM_MIB="${HEADROOM_MIB:-1536}"
DISK_MIN_GB="${DISK_MIN_GB:-10}"
LOCK="${LOCK:-/run/pft-specdrill.lock}"
DOCKER="${DOCKER:-docker}"
CURL="${CURL:-curl}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
SYSTEMD_RUN="${SYSTEMD_RUN:-systemd-run}"
PFT_MAINT_BIN="${PFT_MAINT_BIN:-/usr/local/bin/pft-maint}"
PFT_INTEGRITY_BIN="${PFT_INTEGRITY_BIN:-/usr/local/bin/pft-integrity}"
MEMINFO="${MEMINFO:-/proc/meminfo}"
PROC_ROOT="${PROC_ROOT:-/proc}"
CGROUP_ROOT="${CGROUP_ROOT:-/sys/fs/cgroup/system.slice}"
DF_PATH="${DF_PATH:-/var/lib/docker}"
TEST="${PFT_SPECDRILL_TEST:-}"
LABEL=pft-specdrill
REARM_UNIT=specdrill-rearm-integrity   # a transient SERVICE, not a timer: schedaudit lists every loaded timer and
                                       # jobwatch every pft-*.timer, neither lists a sleeping service
CFG=/etc/postfiatd/postfiatd.cfg
SLACK_S=120

# The matrix: one factor at a time from the base cell (2 vCPU, 2048 MiB, unlimited I/O).
BASE_CPUS=2 BASE_MEM=2048 BASE_IO=0
MATRIX_CPU="0.25 0.5 1 2"
MATRIX_MEM="512 768 1024 1536 2048"
MATRIX_IO="1000000 4000000 16000000"

now() { if [ -n "${NOW_FILE:-}" ]; then cat "$NOW_FILE"; else date -u +%s; fi; }
nap() { if [ -n "${NOW_FILE:-}" ]; then echo $(( $(now) + $1 )) >"$NOW_FILE"; else sleep "$1"; fi; }
log() { echo "[$(date -u -d "@$(now)" +%FT%TZ)] $*"; }
die() { echo "specdrill: $2" >&2; exit "$1"; }
refuse() { echo "REFUSED: $*" >&2; exit 4; }
cell_budget_s() { echo $(( FULL_TIMEOUT_S + WINDOW_S + SLACK_S )); }

# ---------- readers (print a value, rc != 0 when unreadable; callers decide) ----------
rpc_post() { # URL METHOD PARAMS_JSON -> result JSON
  local out
  out="$("$CURL" -s -m 10 -H 'Content-Type: application/json' \
    -d "{\"method\":\"$2\",\"params\":[$3]}" "$1" 2>/dev/null)" || return 1
  jq -e '.result | select(type == "object")' <<<"$out" 2>/dev/null || return 1
}
ref_seq() { rpc_post "$REF_RPC" ledger '{"ledger_index":"validated"}' | jq -er '.ledger.ledger_index | tonumber'; }
live_info() { # -> "state seq"
  rpc_post "$LIVE_RPC" server_info '{}' | jq -er '.info | "\(.server_state) \(.validated_ledger.seq // "null")"'
}
cell_cli() { # CONTAINER CLI-ARGS... -> JSON result (the CLI prints Loading:/HTTPClient lines before the JSON)
  local c="$1"; shift
  "$DOCKER" exec "$c" postfiatd --conf "$CFG" "$@" 2>/dev/null | sed -n '/^{/,$p' | jq -e '.result' 2>/dev/null
}
mem_avail_mib() { awk '$1 == "MemAvailable:" {print int($2 / 1024); f = 1} END {exit !f}' "$MEMINFO"; }
disk_free_gb() { df -BG --output=avail "$DF_PATH" 2>/dev/null | awk 'NR == 2 {sub(/G/, ""); print $1 + 0; f = 1} END {exit !f}'; }
live_image() { "$DOCKER" inspect -f '{{.Image}}' "$LIVE_CONTAINER" 2>/dev/null; }
leftovers() {
  { "$DOCKER" ps -aq --filter "label=$LABEL"; "$DOCKER" volume ls -q --filter "label=$LABEL"
    "$DOCKER" network ls -q --filter "label=$LABEL"; } 2>/dev/null | grep -c . || true
}

# ---------- guards ----------
# Each prints "ok|FAIL <guard>: detail"; preflight refuses on the first FAIL. `plan` prints all of them.
g_maint() {
  local j st rem need; need="$(cell_budget_s)"
  j="$("$PFT_MAINT_BIN" status --json 2>/dev/null)"
  st="$(jq -r '.window // "none"' <<<"$j" 2>/dev/null)"; rem="$(jq -r '.remaining_sec // 0' <<<"$j" 2>/dev/null)"
  "$PFT_MAINT_BIN" active >/dev/null 2>&1 || { echo "FAIL maint: no active pft-maint window (window=${st:-?})"; return; }
  [ "${rem:-0}" -ge "$need" ] 2>/dev/null || { echo "FAIL maint: window has ${rem:-?}s left, cell needs ${need}s"; return; }
  echo "ok maint: active, ${rem}s left >= ${need}s"
}
g_live() {
  local li st seq ref lag
  li="$(live_info)" || { echo "FAIL live: live server_info unreadable"; return; }
  st="${li% *}"; seq="${li#* }"
  [ "$st" = full ] || { echo "FAIL live: live server_state=$st"; return; }
  ref="$(ref_seq)" || { echo "FAIL live: reference RPC unreadable"; return; }
  [[ "$seq" =~ ^[0-9]+$ ]] || { echo "FAIL live: live validated seq unreadable"; return; }
  lag=$(( ref - seq )); [ "$lag" -lt 0 ] && lag=0
  [ "$lag" -le "$LIVE_LAG_MAX" ] || { echo "FAIL live: live lag $lag > $LIVE_LAG_MAX"; return; }
  echo "ok live: full, lag $lag <= $LIVE_LAG_MAX"
}
g_integrity() {
  local out rc
  out="$("$PFT_INTEGRITY_BIN" verify 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] || { echo "FAIL integrity: verify rc=$rc ($(tail -1 <<<"$out"))"; return; }
  "$SYSTEMCTL" is-active --quiet pft-integrity.service && { echo "FAIL integrity: pft-integrity.service is running now"; return; }
  echo "ok integrity: verify PASS"
}
g_headroom() { # CELL_MEM_MIB
  local a; a="$(mem_avail_mib)" || { echo "FAIL headroom: MemAvailable unreadable"; return; }
  [ $(( a - $1 )) -ge "$HEADROOM_MIB" ] || { echo "FAIL headroom: MemAvailable ${a} MiB - cell $1 MiB < ${HEADROOM_MIB} MiB"; return; }
  echo "ok headroom: ${a} MiB - $1 MiB >= ${HEADROOM_MIB} MiB"
}
g_disk() {
  local g; g="$(disk_free_gb)" || { echo "FAIL disk: free space unreadable"; return; }
  [ "$g" -ge "$DISK_MIN_GB" ] || { echo "FAIL disk: ${g} GB free < ${DISK_MIN_GB} GB"; return; }
  echo "ok disk: ${g} GB free"
}
g_image() {
  local img; img="$(live_image)"
  [ -n "$img" ] || { echo "FAIL image: live container $LIVE_CONTAINER not found"; return; }
  "$DOCKER" image inspect "$img" >/dev/null 2>&1 || { echo "FAIL image: $img not present locally"; return; }
  echo "ok image: $img"
}
g_leftovers() {
  local n; n="$(leftovers)"
  [ "$n" -eq 0 ] || { echo "FAIL leftovers: $n labelled resources from an earlier run (run cleanup)"; return; }
  echo "ok leftovers: none"
}
all_guards() { g_maint; g_live; g_integrity; g_headroom "$1"; g_disk; g_image; g_leftovers; }

take_lock() {
  exec 9>"$LOCK" || refuse "lock: cannot open $LOCK"
  flock -n 9 || refuse "lock: another pft-specdrill run holds $LOCK"
}
need_root() { [ "$(id -u)" -eq 0 ] || [ -n "$TEST" ] || die 3 "run as root"; }

# ---------- teardown ----------
CELL_C="" CELL_V="" CELL_N="" PAUSED=0
teardown() {
  local id
  for id in $("$DOCKER" ps -aq --filter "label=$LABEL" 2>/dev/null); do "$DOCKER" rm -f "$id" >/dev/null 2>&1; done
  for id in $("$DOCKER" volume ls -q --filter "label=$LABEL" 2>/dev/null); do "$DOCKER" volume rm -f "$id" >/dev/null 2>&1; done
  for id in $("$DOCKER" network ls -q --filter "label=$LABEL" 2>/dev/null); do "$DOCKER" network rm "$id" >/dev/null 2>&1; done
  if [ "$PAUSED" -eq 1 ]; then   # failsafe first: pft-integrity must never run while its transient unit exists
    "$SYSTEMCTL" stop "$REARM_UNIT.service" >/dev/null 2>&1
    "$SYSTEMCTL" start pft-integrity.timer && log "integrity timer re-armed"
    PAUSED=0
  fi
  log "teardown: leftovers=$(leftovers)"
}
pause_integrity() {
  local ttl=$(( $(cell_budget_s) + 300 ))
  "$SYSTEMD_RUN" --collect --unit "$REARM_UNIT" /bin/sh -c "sleep $ttl && $SYSTEMCTL start pft-integrity.timer" \
    >/dev/null 2>&1 || refuse "integrity: failsafe re-arm unit could not be started"
  "$SYSTEMCTL" stop pft-integrity.timer || { "$SYSTEMCTL" stop "$REARM_UNIT.service"; refuse "integrity: timer stop failed"; }
  PAUSED=1
  log "integrity timer paused (failsafe $REARM_UNIT re-arms in ${ttl}s)"
}

# ---------- one cell ----------
# Containment check of the created (not yet started) container; prints the reason of the first violation.
containment() { # CONTAINER NET VOL
  local j cfg
  cfg="$("$DOCKER" cp "$1:$CFG" - 2>/dev/null | tar -xO 2>/dev/null)"
  [ -n "$cfg" ] || { echo "cell config unreadable"; return; }
  grep -qE '^\[(validator_token|validation_seed|ips_fixed)\]' <<<"$cfg" && { echo "cell config has a validator/fixed-peer stanza"; return; }
  j="$("$DOCKER" inspect "$1" 2>/dev/null)" || { echo "inspect failed"; return; }
  jq -e --arg n "$2" --arg v "$3" '.[0] |
    (.HostConfig.PortBindings // {} | length) == 0 and (.HostConfig.Privileged | not)
    and .HostConfig.NetworkMode == $n and ([.Mounts[] | select(.Type != "volume" or .Name != $v)] | length) == 0
    and (.Mounts | length) == 1' <<<"$j" >/dev/null || { echo "container publishes ports, mounts more than its volume, is privileged or off its network"; return; }
}
run_cell() { # OUT AXIS CPUS MEM IO
  local out="$1" axis="$2" cpus="$3" mem="$4" io="$5" g cell id dir t0 t full_t="" abort="" s j st seq close peers
  local li lst lseq ref llag pid hwm=0 v oomk=0 info state
  cell="${axis}-c${cpus}-m${mem}-io${io}"
  dir="$out/$cell"
  while read -r g; do echo "  $g"; [ "${g%% *}" = ok ] || refuse "${g#FAIL }"; done < <(all_guards "$mem")
  mkdir -p "$dir" || die 1 "cannot create $dir"; : >"$dir/samples.jsonl"
  id="${cell//./_}-$(now)"; CELL_C="$LABEL-$id"; CELL_V="$LABEL-$id"; CELL_N="$LABEL-$id"
  trap 'teardown' EXIT; trap 'abort=signal; teardown; exit 130' INT TERM
  pause_integrity
  "$DOCKER" network create --label "$LABEL=$id" "$CELL_N" >/dev/null || refuse "network create failed"
  "$DOCKER" volume create --label "$LABEL=$id" "$CELL_V" >/dev/null || refuse "volume create failed"
  local args=(create --name "$CELL_C" --label "$LABEL=$id" --network "$CELL_N" --pull never --restart no
              --cpus "$cpus" --memory "${mem}m" --memory-swap "${mem}m" -v "$CELL_V:/var/lib/postfiatd/db")
  if [ "$io" -gt 0 ]; then
    local dev="${IO_DEV:-}"
    [ -n "$dev" ] || dev="$(df --output=source "$DF_PATH" | awk 'NR == 2 {print $1}' | sed 's/[0-9]*$//')"
    [ -b "$dev" ] || [ -n "$TEST" ] || refuse "io: block device '$dev' not found (set IO_DEV)"
    args+=(--device-read-bps "$dev:$io" --device-write-bps "$dev:$io")
  fi
  "$DOCKER" "${args[@]}" "$(live_image)" >/dev/null || refuse "container create failed"
  v="$(containment "$CELL_C" "$CELL_N" "$CELL_V")"; [ -z "$v" ] || refuse "containment: $v"
  "$DOCKER" start "$CELL_C" >/dev/null || refuse "container start failed"
  t0="$(now)"; log "cell $cell started (cpus=$cpus mem=${mem}MiB io=$io)"
  while :; do
    t="$(now)"
    state="$("$DOCKER" inspect -f '{{.State.Running}} {{.State.OOMKilled}} {{.RestartCount}} {{.State.Pid}}' "$CELL_C" 2>/dev/null)"
    pid="${state##* }"
    if [ "${pid:-0}" -gt 0 ] 2>/dev/null; then
      v="$(awk '$1 == "VmHWM:" {print $2 * 1024}' "$PROC_ROOT/$pid/status" 2>/dev/null)"
      [ -n "$v" ] && [ "$v" -gt "$hwm" ] && hwm="$v"
    fi
    info="$(cell_cli "$CELL_C" server_info)"; st="$(jq -r '.info.server_state // empty' <<<"$info" 2>/dev/null)"
    peers="$(jq -r '.info.peers // "null"' <<<"$info" 2>/dev/null)"; seq=null close=null
    if [ "$st" = full ]; then
      j="$(cell_cli "$CELL_C" ledger validated)"
      seq="$(jq -r '.ledger.ledger_index // "null"' <<<"$j" 2>/dev/null)"; close="$(jq -r '.ledger.close_time // "null"' <<<"$j" 2>/dev/null)"
      [ -z "$full_t" ] && { full_t="$t"; log "cell full after $(( t - t0 ))s"; }
    fi
    ref="$(ref_seq)" || ref=null
    li="$(live_info)" || li="unreadable null"; lst="${li% *}"; lseq="${li#* }"
    llag=null
    if [[ "$ref" =~ ^[0-9]+$ ]] && [[ "$lseq" =~ ^[0-9]+$ ]]; then llag=$(( ref - lseq )); [ "$llag" -lt 0 ] && llag=0; fi
    jq -nc --argjson t "$t" --arg st "${st:-unreachable}" --arg seq "$seq" --arg close "$close" --arg ref "$ref" \
      --arg peers "$peers" --arg lst "$lst" --arg llag "$llag" \
      '{t:$t, state:$st, seq:($seq|tonumber? // null), close:($close|tonumber? // null), ref_seq:($ref|tonumber? // null),
        peers:($peers|tonumber? // null), live_state:$lst, live_lag:($llag|tonumber? // null)}' >>"$dir/samples.jsonl"
    # aborts, in order of severity
    "$PY" "$HELPER" live-gate "$dir/samples.jsonl" "$LIVE_LAG_MAX" "$LIVE_ABORT_POLLS" >/dev/null || { abort=live_lag; break; }
    "$PFT_MAINT_BIN" active >/dev/null 2>&1 || { abort=maint_window_ended; break; }
    v="$(mem_avail_mib)" && [ "$v" -lt $(( HEADROOM_MIB / 2 )) ] && { abort=host_mem_low; break; }
    [ "${state%% *}" = true ] || { log "cell container stopped ($state)"; break; }
    [ -z "$full_t" ] && [ $(( t - t0 )) -ge "$FULL_TIMEOUT_S" ] && { log "cell never full within ${FULL_TIMEOUT_S}s"; break; }
    [ -n "$full_t" ] && [ $(( t - full_t )) -ge "$WINDOW_S" ] && break
    nap "$POLL_SEC"
  done
  [ -n "$abort" ] && log "cell ABORTED: $abort"
  state="$("$DOCKER" inspect -f '{{.State.Running}} {{.State.OOMKilled}} {{.RestartCount}} {{.State.Pid}}' "$CELL_C" 2>/dev/null)"
  local cid; cid="$("$DOCKER" inspect -f '{{.Id}}' "$CELL_C" 2>/dev/null)"
  oomk="$(awk '$1 == "oom_kill" {print $2}' "$CGROUP_ROOT/docker-$cid.scope/memory.events" 2>/dev/null)"
  read -r _ s v _ <<<"$state"
  jq -n --arg cell "$cell" --arg axis "$axis" --argjson cpus "$cpus" --argjson mem "$mem" --argjson io "$io" \
    --argjson start "$t0" --argjson endt "$(now)" --argjson fd "$FULL_DEADLINE_S" --argjson win "$WINDOW_S" \
    --arg abort "$abort" --arg oom "${s:-false}" --arg oomk "${oomk:-0}" --arg rs "${v:-0}" --argjson hwm "$hwm" \
    '{cell:$cell, axis:$axis, cpus:$cpus, mem_mib:$mem, io_bps:$io, start:$start, "end":$endt, full_deadline_s:$fd,
      window_s:$win, abort:(if $abort == "" then null else $abort end), oom_killed:($oom == "true" or ($oomk|tonumber) > 0),
      restarts:($rs|tonumber), peak_rss_bytes:(if $hwm > 0 then $hwm else null end)}' >"$dir/meta.json" || die 1 "meta.json write failed"
  teardown; trap - EXIT INT TERM
  "$PY" "$HELPER" summarize "$dir" >/dev/null || die 1 "summarize failed"
  log "cell $cell: $(jq -r '.verdict + " " + (.reasons | join(";"))' "$dir/cell.json")"
}

matrix_cells() { # AXES (comma list) -> "axis cpus mem io" lines
  local a v
  for a in ${1//,/ }; do
    case "$a" in
      cpu) for v in $MATRIX_CPU; do echo "cpu $v $BASE_MEM $BASE_IO"; done ;;
      mem) for v in $MATRIX_MEM; do echo "mem $BASE_CPUS $v $BASE_IO"; done ;;
      io) for v in $MATRIX_IO; do echo "io $BASE_CPUS $BASE_MEM $v"; done ;;
      *) die 3 "unknown axis: $a" ;;
    esac
  done
}

# ---------- commands ----------
CMD="${1:-}"; [ $# -gt 0 ] && shift
OUT="" AXIS="" CPUS="" MEM="" IO=0 AXES="cpu,mem,io" YES=0
while [ $# -gt 0 ] && [ "$CMD" != report ]; do
  case "$1" in
    --out) OUT="${2:?--out needs a dir}"; shift ;;
    --axis) AXIS="${2:?}"; shift ;;
    --cpus) CPUS="${2:?}"; shift ;;
    --mem) MEM="${2:?}"; shift ;;
    --io) IO="${2:?}"; shift ;;
    --axes) AXES="${2:?}"; shift ;;
    --yes) YES=1 ;;
    *) die 3 "unknown argument: $1" ;;
  esac
  shift
done
case "$CMD" in
  plan)
    matrix_cells "$AXES" | while read -r a c m i; do echo "cell $a cpus=$c mem=${m}MiB io=$i budget=$(cell_budget_s)s"; done
    all_guards "$BASE_MEM"; echo "lock: $LOCK  pull: never  failsafe: $REARM_UNIT" ;;
  run-cell)
    need_root
    if [ -z "$OUT" ] || [ -z "$AXIS" ] || ! [[ "$CPUS" =~ ^[0-9]+(\.[0-9]+)?$ ]] || ! [[ "$MEM" =~ ^[0-9]+$ ]] \
       || ! [[ "$IO" =~ ^[0-9]+$ ]]; then die 3 "run-cell needs --out --axis --cpus N --mem MIB [--io BPS]"; fi
    take_lock; run_cell "$OUT" "$AXIS" "$CPUS" "$MEM" "$IO" ;;
  matrix)
    need_root; [ -n "$OUT" ] || die 3 "matrix needs --out"; [ "$YES" -eq 1 ] || die 3 "matrix runs live throwaway nodes: add --yes"
    take_lock
    matrix_cells "$AXES" >/dev/null || exit 3
    while read -r a c m i; do ( run_cell "$OUT" "$a" "$c" "$m" "$i" ) || exit $?; done < <(matrix_cells "$AXES") ;;
  report) [ $# -eq 2 ] || die 3 "report CELLS_DIR OUT_DIR"; exec "$PY" "$HELPER" report "$1" "$2" ;;
  cleanup) need_root; take_lock; PAUSED=0; teardown ;;
  *) sed -n '9,29p' "$0" | sed 's/^# \{0,1\}//'; [ -z "$CMD" ] || [ "$CMD" = help ] || exit 3 ;;
esac
