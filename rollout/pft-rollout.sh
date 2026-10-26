#!/usr/bin/env bash
# pft-rollout: two-host canary image rollout for a Post Fiat validator + sentry, on top of what
# upgrade/postfiat-upgrade.sh does for one host. Hosts are rolled one at a time in hosts.conf order (sentry first =
# canary). Per host: record the running image (ID + repo digest), open a pft-maint window and an Alertmanager
# silence, deploy, health gate, soak. A failed gate or soak rolls back THAT host to the recorded image, re-gates it,
# and stops: the next host is never touched.
#
# Usage: pft-rollout plan    [--target REF] [--json]
#        pft-rollout run     --yes [--target REF] [--no-pull]
#        pft-rollout status  [--json]
#        pft-rollout rollback --yes [--host LABEL]
#
#  plan      read-only: per host the container, mode (compose | docker run), running image ID + repo digest, whether
#            that image is still present (rollback needs it), current health, locks, thresholds. Changes nothing.
#  run       preflight on every host first (recorded image present, gate conditions true now, no pft-maint
#            data-collection lock, foundation build_version known), then host by host:
#            target = `docker pull IMAGE_TAG` (default) or a local image REF (--target REF --no-pull, for drills);
#            if target == running image this is a no-op rollout (plain `docker restart`, still gated);
#            otherwise IMAGE_TAG is retagged to the target and the container is recreated:
#              compose   -> `docker compose up -d` in the project dir (keeps COMPOSE_FILE overrides from .env)
#              docker run -> stop, rename to NAME-prerollout-<run>, `docker run` with the same config, then the new
#                           container's config is compared with the old one (any drift = rollback)
#            gate: every POLL_SEC until GATE_TIMEOUT, pass on the first poll where ALL of: server_state full|proposing,
#            build_version == foundation RPC, peers >= the host's min_peers, validated ledger age <= MAX_LEDGER_AGE.
#            soak: SOAK_SEC more; SOAK_BAD_POLLS consecutive failing polls, or validated seq advancing less than
#            MIN_ADVANCE over the soak, fails it. Pass -> pft-maint end, next host.
#  rollback  manual: restore the recorded image on hosts the last run changed (all, or --host), with window,
#            silence and gate. `run` rolls back automatically; this is for later regret.
#  status    last run (state file) and the running image on each host.
#
# Exit codes: 0 all hosts promoted / PASS, 1 a host failed and was rolled back (hosts after it untouched),
#   3 usage/config error, 4 refused by preflight (nothing changed), 5 rollback FAILED (manual action needed),
#   6 interrupted (current host rolled back).
# Config: CONF (/etc/pft-rollout/hosts.conf), lines `host LABEL local|ssh SSH_TARGET|- CONTAINER MIN_PEERS`,
#   in rollout order. Commands on a host run through `sudo -n` (local) or `ssh SSH_TARGET sudo -n` (ssh).
# Env: IMAGE_TAG (agtipft/postfiatd:testnet-light-latest)  FOUNDATION_RPC (https://rpc.testnet.postfiat.org)
#      GATE_TIMEOUT (1800)  SOAK_SEC (300)  SOAK_BAD_POLLS (3)  MIN_ADVANCE (10)  MAX_LEDGER_AGE (20)  POLL_SEC (10)
#      ROLLBACK_TIMEOUT (1800)  AM (http://127.0.0.1:9093, "none" = no silence)  SILENCE_MATCHER (alertname=~.+)
#      MAINT_CMD (pft-maint, "none" = no window)  MAINT_HOST (first `local` host)  STATE_DIR (~/.local/state/pft-rollout)
#      Test hooks: PFT_ROLLOUT_NOW_FILE (fake clock; sleeps advance it)

# jq programs are single-quoted on purpose ($x are jq variables). "A && B || fail" is intended (fail returns).
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

CONF="${CONF:-/etc/pft-rollout/hosts.conf}"
IMAGE_TAG="${IMAGE_TAG:-agtipft/postfiatd:testnet-light-latest}"
FOUNDATION_RPC="${FOUNDATION_RPC:-https://rpc.testnet.postfiat.org}"
GATE_TIMEOUT="${GATE_TIMEOUT:-1800}"
SOAK_SEC="${SOAK_SEC:-300}"
SOAK_BAD_POLLS="${SOAK_BAD_POLLS:-3}"
MIN_ADVANCE="${MIN_ADVANCE:-10}"
MAX_LEDGER_AGE="${MAX_LEDGER_AGE:-20}"
POLL_SEC="${POLL_SEC:-10}"
ROLLBACK_TIMEOUT="${ROLLBACK_TIMEOUT:-1800}"
AM="${AM:-http://127.0.0.1:9093}"
SILENCE_MATCHER="${SILENCE_MATCHER:-alertname=~.+}"
MAINT_CMD="${MAINT_CMD:-pft-maint}"
STATE_DIR="${STATE_DIR:-${HOME:-/root}/.local/state/pft-rollout}"
AUDIT="$STATE_DIR/audit.jsonl"
STATE="$STATE_DIR/last-run.json"
LOCK="$STATE_DIR/rollout.lock"

now() { if [ -n "${PFT_ROLLOUT_NOW_FILE:-}" ]; then cat "$PFT_ROLLOUT_NOW_FILE"; else date -u +%s; fi; }
nap() { if [ -n "${PFT_ROLLOUT_NOW_FILE:-}" ]; then echo $(( $(now) + $1 )) > "$PFT_ROLLOUT_NOW_FILE"; else sleep "$1"; fi; }
iso() { date -u -d "@$1" +%FT%TZ; }
log() { printf '[%s] %s\n' "$(iso "$(now)")" "$*"; }
die() { log "ERROR: $1"; exit "${2:-3}"; }
usage() { sed -n '7,11p' "$0" | sed 's/^# \{0,1\}//'; }

RUN_ID=""
audit() { # EVENT HOST [jq --arg/--argjson pairs as k=v strings: key=value]
  local ev="$1" h="$2" a=() kv; shift 2
  for kv in "$@"; do a+=(--arg "${kv%%=*}" "${kv#*=}"); done
  mkdir -p "$STATE_DIR"
  jq -nc --arg ts "$(iso "$(now)")" --arg run "$RUN_ID" --arg ev "$ev" --arg host "$h" "${a[@]}" \
    '{ts:$ts, run:$run, event:$ev, host:$host} + ($ARGS.named | del(.ts, .run, .ev, .host))' >> "$AUDIT"
}

# ---------- hosts ----------
declare -a HOSTS=()
declare -A H_MODE=() H_SSH=() H_CONT=() H_PEERS=()
load_conf() {
  [ -r "$CONF" ] || die "no hosts config $CONF (see hosts.conf.example)" 3
  local kw l m s c p
  while read -r kw l m s c p _; do
    [ "$kw" = host ] || continue
    case "$m" in local|ssh) ;; *) die "$CONF: host $l: mode must be local or ssh" 3 ;; esac
    [[ "$p" =~ ^[0-9]+$ ]] || die "$CONF: host $l: min_peers must be a number" 3
    HOSTS+=("$l"); H_MODE[$l]="$m"; H_SSH[$l]="$s"; H_CONT[$l]="$c"; H_PEERS[$l]="$p"
  done < <(grep -v '^[[:space:]]*#' "$CONF")
  [ "${#HOSTS[@]}" -ge 1 ] || die "$CONF lists no hosts" 3
  if [ -z "${MAINT_HOST:-}" ]; then
    for l in "${HOSTS[@]}"; do [ "${H_MODE[$l]}" = local ] && { MAINT_HOST="$l"; break; }; done
  fi
}
hx() { # LABEL CMD... : run CMD as root on that host
  local h="$1"; shift
  if [ "${H_MODE[$h]}" = ssh ]; then
    ssh -o BatchMode=yes -o ConnectTimeout=10 "${H_SSH[$h]}" "sudo -n $(printf '%q ' "$@")"
  elif [ "$(id -u)" -eq 0 ]; then "$@"
  else sudo -n "$@"
  fi
}
inspect() { hx "$1" docker inspect "${H_CONT[$1]}" 2>/dev/null | jq -c '.[0] // empty' 2>/dev/null; }
image_id() { hx "$1" docker image inspect "$2" 2>/dev/null | jq -r '.[0].Id // empty' 2>/dev/null; }
image_digest() { hx "$1" docker image inspect "$2" 2>/dev/null | jq -r '(.[0].RepoDigests // [])[0] // "none"' 2>/dev/null; }
server_info() { # LABEL -> .result.info JSON or {}
  local r
  r="$(hx "$1" docker exec "${H_CONT[$1]}" curl -s --max-time 8 -X POST -H 'Content-Type: application/json' \
    http://127.0.0.1:5005/ -d '{"method":"server_info","params":[{}]}' 2>/dev/null | jq -c '.result.info // empty' 2>/dev/null)"
  echo "${r:-{\}}"
}
foundation_build() {
  curl -s --max-time 10 -X POST -H 'Content-Type: application/json' "$FOUNDATION_RPC" \
    -d '{"method":"server_info","params":[{}]}' 2>/dev/null | jq -r '.result.info.build_version // empty' 2>/dev/null
}

# ---------- health ----------
REF_BUILD=""
POLL_LINE=""; POLL_SEQ=0
poll_ok() { # LABEL -> 0 when every gate condition holds; sets POLL_LINE, POLL_SEQ
  local i st b p age why=()
  i="$(server_info "$1")"
  read -r st b p age POLL_SEQ < <(jq -r '[.server_state // "down", .build_version // "none", .peers // 0,
    .validated_ledger.age // 999999, .validated_ledger.seq // 0] | map(tostring) | join(" ")' <<<"$i")
  case "$st" in full|proposing) ;; *) why+=("state=$st") ;; esac
  [ "$b" = "$REF_BUILD" ] || why+=("build=$b!=$REF_BUILD")
  [ "$p" -ge "${H_PEERS[$1]}" ] || why+=("peers=$p<${H_PEERS[$1]}")
  [ "$age" -le "$MAX_LEDGER_AGE" ] || why+=("age=${age}s>${MAX_LEDGER_AGE}s")
  POLL_LINE="state=$st build=$b peers=$p age=${age}s seq=$POLL_SEQ"
  [ "${#why[@]}" -eq 0 ] && return 0
  POLL_LINE="$POLL_LINE FAIL(${why[*]})"; return 1
}
gate() { # LABEL TIMEOUT -> 0 pass; sets GATE_SEC
  local t0; t0="$(now)"; GATE_SEC=0
  while :; do
    if poll_ok "$1"; then GATE_SEC=$(( $(now) - t0 )); log "  gate poll +${GATE_SEC}s $POLL_LINE -> PASS"; return 0; fi
    log "  gate poll +$(( $(now) - t0 ))s $POLL_LINE"
    [ $(( $(now) - t0 )) -ge "$2" ] && { GATE_SEC=$(( $(now) - t0 )); return 1; }
    nap "$POLL_SEC"
  done
}
soak() { # LABEL -> 0 pass
  local t0 bad=0 seq0 adv; t0="$(now)"; poll_ok "$1"; seq0="$POLL_SEQ"
  while [ $(( $(now) - t0 )) -lt "$SOAK_SEC" ]; do
    nap "$POLL_SEC"
    if poll_ok "$1"; then bad=0; else bad=$((bad + 1)); fi
    log "  soak +$(( $(now) - t0 ))s $POLL_LINE bad_streak=$bad"
    [ "$bad" -ge "$SOAK_BAD_POLLS" ] && { log "  soak FAIL: $bad consecutive failing polls"; return 1; }
  done
  adv=$(( POLL_SEQ - seq0 ))
  [ "$adv" -ge "$MIN_ADVANCE" ] || { log "  soak FAIL: validated seq advanced $adv < $MIN_ADVANCE"; return 1; }
  log "  soak PASS: ${SOAK_SEC}s, validated seq +$adv"
}

# ---------- container config (docker run mode) ----------
run_args() { # INSPECT_JSON IMAGE_ENV_JSON NAME -> one --opt=value per line, then IMAGE_TAG and cmd
  jq -r --argjson ienv "$2" --arg name "$3" --arg tag "$IMAGE_TAG" '
    "--name=\($name)",
    "--restart=\(.HostConfig.RestartPolicy.Name)\(if .HostConfig.RestartPolicy.Name == "on-failure" then ":\(.HostConfig.RestartPolicy.MaximumRetryCount)" else "" end)",
    (if (.Config.User // "") != "" then "--user=\(.Config.User)" else empty end),
    "--log-driver=\(.HostConfig.LogConfig.Type)",
    ((.HostConfig.LogConfig.Config // {}) | to_entries[] | "--log-opt=\(.key)=\(.value)"),
    (if .HostConfig.NetworkMode != "default" then "--network=\(.HostConfig.NetworkMode)" else empty end),
    ((.HostConfig.PortBindings // {}) | to_entries[] | .key as $k | .value[]
      | "--publish=\(if .HostIp != "" then .HostIp + ":" else "" end)\(.HostPort):\($k | sub("/tcp$"; ""))"),
    ((.Mounts // [])[] | if .Type == "volume" then "--volume=\(.Name):\(.Destination)\(if .RW then "" else ":ro" end)"
                 elif .Type == "bind" then "--volume=\(.Source):\(.Destination)\(if .RW then "" else ":ro" end)"
                 else empty end),
    (.Config.Env // [] | map(select(. as $e | $ienv | index($e) | not)) | .[] | "--env=\(.)"),
    ((.HostConfig.SecurityOpt // [])[] | "--security-opt=\(.)"),
    ((.HostConfig.CapDrop // [])[] | "--cap-drop=\(.)"),
    ((.HostConfig.CapAdd // [])[] | "--cap-add=\(.)"),
    (if .HostConfig.ReadonlyRootfs then "--read-only" else empty end),
    ((.HostConfig.Tmpfs // {}) | to_entries[] | "--tmpfs=\(.key):\(.value)"),
    (if (.HostConfig.PidsLimit // 0) > 0 then "--pids-limit=\(.HostConfig.PidsLimit)" else empty end),
    (if (.HostConfig.Memory // 0) > 0 then "--memory=\(.HostConfig.Memory)" else empty end),
    (if (.HostConfig.MemorySwap // 0) != 0 then "--memory-swap=\(.HostConfig.MemorySwap)" else empty end),
    $tag, (.Config.Cmd // [])[]' <<<"$1"
}
config_summary() { # INSPECT_JSON -> the config a recreate must keep (image and identity excluded)
  jq -cS '{User: .Config.User, Cmd: .Config.Cmd, Env: .Config.Env, Restart: .HostConfig.RestartPolicy,
    Log: .HostConfig.LogConfig, Net: .HostConfig.NetworkMode, Ports: .HostConfig.PortBindings,
    Mounts: [(.Mounts // [])[] | {Type, Name, Source, Destination, RW}], SecurityOpt: .HostConfig.SecurityOpt,
    CapAdd: .HostConfig.CapAdd, CapDrop: .HostConfig.CapDrop, ReadonlyRootfs: .HostConfig.ReadonlyRootfs,
    Tmpfs: .HostConfig.Tmpfs, PidsLimit: .HostConfig.PidsLimit, Memory: .HostConfig.Memory,
    MemorySwap: .HostConfig.MemorySwap, Ulimits: .HostConfig.Ulimits, Dns: .HostConfig.Dns,
    ExtraHosts: .HostConfig.ExtraHosts, Privileged: .HostConfig.Privileged}' <<<"$1"
}

# ---------- deploy / restore ----------
# Per-host run record (in memory): MODE PREV_ID PREV_DIGEST TARGET_ID KEPT (old container name, run mode)
declare -A R_MODE=() R_PREV=() R_DIG=() R_TGT=() R_KEPT=() R_WD=() R_RP=() R_RESULT=()
compose_up() { # LABEL
  hx "$1" bash -c "cd $(printf '%q' "${R_WD[$1]}") && docker compose up -d 2>&1" | sed 's/^/  compose: /'
  return "${PIPESTATUS[0]}"
}
deploy() { # LABEL -> 0 deployed (container running the target), 1 failed before/while deploying
  local h="$1" c="${H_CONT[$1]}" i ienv args new
  if [ "${R_TGT[$h]}" = "${R_PREV[$h]}" ]; then
    log "  no-op: target is the running image ${R_PREV[$h]:7:12}; docker restart"
    hx "$h" docker restart -t 60 "$c" >/dev/null || return 1
    return 0
  fi
  hx "$h" docker tag "${R_TGT[$h]}" "$IMAGE_TAG" || return 1
  log "  $IMAGE_TAG -> ${R_TGT[$h]:7:12}"
  if [ "${R_MODE[$h]}" = compose ]; then
    compose_up "$h" || return 1
  else
    i="$(inspect "$h")"
    ienv="$(hx "$h" docker image inspect "${R_TGT[$h]}" | jq -c '.[0].Config.Env // []')"
    mapfile -t args < <(run_args "$i" "${ienv:-[]}" "$c")
    R_KEPT[$h]="$c-prerollout-$RUN_ID"; R_RP[$h]="$(jq -r '.HostConfig.RestartPolicy.Name' <<<"$i")"
    hx "$h" docker stop -t 60 "$c" >/dev/null && hx "$h" docker rename "$c" "${R_KEPT[$h]}" \
      && hx "$h" docker update --restart=no "${R_KEPT[$h]}" >/dev/null || { log "  could not stop/rename $c"; return 1; }
    log "  previous container kept as ${R_KEPT[$h]} (stopped, restart=no)"
    log "  docker run -d ${args[*]}"
    hx "$h" docker run -d "${args[@]}" >/dev/null || { log "  docker run failed"; return 1; }
    new="$(inspect "$h")"
    if [ "$(config_summary "$new")" != "$(config_summary "$i")" ]; then
      log "  config DRIFT after recreate: $(diff <(config_summary "$i" | jq -S .) <(config_summary "$new" | jq -S .) | tr '\n' ' ')"
      return 1
    fi
    log "  config preserved (user, env, mounts, ports, log, restart, caps, read-only, tmpfs, limits, security_opt)"
  fi
  new="$(inspect "$h" | jq -r '.Image // empty')"
  [ "$new" = "${R_TGT[$h]}" ] || { log "  container runs ${new:7:12}, expected ${R_TGT[$h]:7:12}"; return 1; }
}
restore() { # LABEL -> 0 container back on the recorded image
  local h="$1" c="${H_CONT[$1]}" img
  log "  ROLLBACK $h -> recorded image ${R_PREV[$h]:7:12} (${R_DIG[$h]})"
  audit rollback_start "$h" prev="${R_PREV[$h]}"
  if [ "${R_TGT[$h]}" = "${R_PREV[$h]}" ]; then
    hx "$h" docker restart -t 60 "$c" >/dev/null || return 1
  else
    hx "$h" docker tag "${R_PREV[$h]}" "$IMAGE_TAG" || return 1
    if [ "${R_MODE[$h]}" = compose ]; then
      compose_up "$h" || return 1
    elif [ -n "${R_KEPT[$h]:-}" ] && hx "$h" docker inspect "${R_KEPT[$h]}" >/dev/null 2>&1; then
      hx "$h" docker rm -f "$c" >/dev/null 2>&1
      hx "$h" docker rename "${R_KEPT[$h]}" "$c" && hx "$h" docker update --restart="${R_RP[$h]:-unless-stopped}" "$c" >/dev/null \
        && hx "$h" docker start "$c" >/dev/null || return 1
      log "  previous container ${R_KEPT[$h]} renamed back to $c and started"
    else
      log "  no kept container for $c"; return 1
    fi
  fi
  img="$(inspect "$h" | jq -r '.Image // empty')"
  [ "$img" = "${R_PREV[$h]}" ] || { log "  after restore $c runs ${img:7:12}, expected ${R_PREV[$h]:7:12}"; return 1; }
}

# ---------- window + silence ----------
SIL=""
window_open() { # LABEL TTL_SEC
  SIL=""
  if [ "$MAINT_CMD" != none ]; then
    hx "$MAINT_HOST" "$MAINT_CMD" start --ttl "$2" --reason "pft-rollout $RUN_ID $1" | sed 's/^/  maint: /'
    [ "${PIPESTATUS[0]}" -eq 0 ] || { log "  pft-maint start failed"; return 1; }
  fi
  if [ "$AM" != none ]; then
    local n v re=false e
    n="${SILENCE_MATCHER%%[=!]*}"; v="${SILENCE_MATCHER#"$n"}"; case "$v" in =~*) re=true; v="${v#=~}" ;; *) v="${v#=}" ;; esac
    e="$(iso $(( $(now) + $2 )))"
    SIL="$(curl -s --max-time 10 -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc \
      --arg n "$n" --arg v "$v" --argjson re "$re" --arg s "$(iso "$(now)")" --arg e "$e" \
      --arg c "pft-rollout $RUN_ID $1 planned restart" \
      '{matchers:[{name:$n,value:$v,isRegex:$re,isEqual:true}],startsAt:$s,endsAt:$e,createdBy:"pft-rollout",comment:$c}')" \
      | jq -r '.silenceID // empty' 2>/dev/null)"
    [ -n "$SIL" ] || { log "  Alertmanager silence failed"; window_close "$1"; return 1; }
    log "  Alertmanager silence ${SIL:0:8} ($SILENCE_MATCHER) until $e"
  fi
  audit window_open "$1" ttl="$2" silence="$SIL"
}
window_close() { # LABEL: ends the pft-maint window. The silence runs out at its own end time on purpose
  # (PFTContainerRestarted stays true for 15 min after a start; expiring early would page).
  [ "$MAINT_CMD" = none ] || hx "$MAINT_HOST" "$MAINT_CMD" end --reason "pft-rollout $RUN_ID $1 done" | sed 's/^/  maint: /'
  audit window_close "$1" silence_kept="$SIL"
}

# ---------- run ----------
record_host() { # LABEL -> fills R_*; 0 ok, 1 refuse
  local h="$1" i
  i="$(inspect "$h")"; [ -n "$i" ] || { log "PREFLIGHT $h: container ${H_CONT[$h]} not found"; return 1; }
  R_PREV[$h]="$(jq -r .Image <<<"$i")"
  R_WD[$h]="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"] // empty' <<<"$i")"
  if [ -n "${R_WD[$h]}" ]; then R_MODE[$h]=compose; else R_MODE[$h]=run; fi
  [ -n "$(image_id "$h" "${R_PREV[$h]}")" ] \
    || { log "PREFLIGHT $h: running image ${R_PREV[$h]:7:12} is not in the local image store - cannot roll back, refusing"; return 1; }
  R_DIG[$h]="$(image_digest "$h" "${R_PREV[$h]}")"
  log "PREFLIGHT $h: ${H_CONT[$h]} mode=${R_MODE[$h]} image=${R_PREV[$h]:7:12} digest=${R_DIG[$h]}"
}
write_state() { # RESULT
  local h js="[]"
  for h in "${HOSTS[@]}"; do
    js="$(jq -c --arg l "$h" --arg m "${R_MODE[$h]:-}" --arg p "${R_PREV[$h]:-}" --arg d "${R_DIG[$h]:-}" \
      --arg t "${R_TGT[$h]:-}" --arg k "${R_KEPT[$h]:-}" --arg rp "${R_RP[$h]:-}" --arg w "${R_WD[$h]:-}" --arg r "${R_RESULT[$h]:-untouched}" \
      '. + [{label:$l,mode:$m,prev_id:$p,prev_digest:$d,target_id:$t,kept_container:$k,restart_policy:$rp,working_dir:$w,result:$r}]' <<<"$js")"
  done
  jq -n --arg id "$RUN_ID" --arg r "$1" --arg t "$(iso "$(now)")" --arg tag "$IMAGE_TAG" --argjson h "$js" \
    '{run:$id, result:$r, time:$t, image_tag:$tag, hosts:$h}' > "$STATE"
}
finish() { # RESULT EXIT
  write_state "$1"; audit run_end "" result="$1" exit="$2"
  log "RESULT: $1 (exit $2)"; exit "$2"
}
take_lock() {
  mkdir -p "$STATE_DIR"
  exec 9>>"$LOCK"
  flock -n 9 || die "another pft-rollout holds $LOCK ($(cat "$LOCK.info" 2>/dev/null || echo unknown))" 4
  echo "pid $$ since $(iso "$(now)")" > "$LOCK.info"
}
host_ttl() { echo $(( GATE_TIMEOUT + SOAK_SEC + ROLLBACK_TIMEOUT + 25 * 60 )); }

roll_host() { # LABEL -> 0 promoted, 1 failed + rolled back, 5 rollback failed
  local h="$1" t0 tgt
  t0="$(now)"
  log "=== $h (${H_CONT[$h]}, ${R_MODE[$h]}) ==="
  audit host_start "$h" prev="${R_PREV[$h]}" digest="${R_DIG[$h]}"
  if [ "$PULL" = 1 ]; then
    log "  docker pull $IMAGE_TAG"
    hx "$h" docker pull -q "$IMAGE_TAG" | sed 's/^/  pull: /'
    [ "${PIPESTATUS[0]}" -eq 0 ] || { log "  pull failed - $h not changed"; R_RESULT[$h]=pull_failed; return 1; }
    tgt="$IMAGE_TAG"
  else
    tgt="$TARGET"
  fi
  R_TGT[$h]="$(image_id "$h" "$tgt")"
  [ -n "${R_TGT[$h]}" ] || { log "  target $tgt not present on $h - $h not changed"; R_RESULT[$h]=no_target; return 1; }
  log "  target $tgt = ${R_TGT[$h]:7:12} ($(image_digest "$h" "${R_TGT[$h]}"))"
  audit target "$h" target="${R_TGT[$h]}"
  window_open "$h" "$(host_ttl)" || { R_RESULT[$h]=window_failed; return 1; }
  CUR="$h"
  trap 'log "interrupted"; restore "$CUR"; window_close "$CUR"; R_RESULT[$CUR]=interrupted_rolled_back; finish interrupted 6' INT TERM
  local ok=1
  if deploy "$h"; then
    audit deployed "$h" target="${R_TGT[$h]}"
    if gate "$h" "$GATE_TIMEOUT"; then
      log "  GATE PASS after ${GATE_SEC}s"; audit gate_pass "$h" secs="$GATE_SEC"
      if soak "$h"; then ok=0; audit soak_pass "$h" secs="$SOAK_SEC"; else audit soak_fail "$h"; fi
    else
      log "  GATE FAIL: not healthy within ${GATE_TIMEOUT}s"; audit gate_fail "$h" secs="$GATE_SEC"
    fi
  else
    audit deploy_fail "$h"
  fi
  if [ "$ok" -eq 0 ]; then
    trap - INT TERM
    R_RESULT[$h]=promoted; window_close "$h"
    log "  $h PROMOTED in $(( $(now) - t0 ))s"; audit host_done "$h" result=promoted secs="$(( $(now) - t0 ))"
    return 0
  fi
  if restore "$h" && gate "$h" "$ROLLBACK_TIMEOUT"; then
    trap - INT TERM
    log "  rollback re-gate PASS after ${GATE_SEC}s"; audit rollback_done "$h" secs="$GATE_SEC"
    R_RESULT[$h]=rolled_back; window_close "$h"; return 1
  fi
  trap - INT TERM
  log "  ROLLBACK FAILED on $h - manual action needed (recorded image ${R_PREV[$h]} ${R_DIG[$h]})"
  audit rollback_fail "$h"; R_RESULT[$h]=rollback_failed
  window_close "$h"; return 5
}

cmd_run() {
  take_lock
  RUN_ID="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"
  log "pft-rollout run $RUN_ID: hosts ${HOSTS[*]} (in this order), tag $IMAGE_TAG, $([ "$PULL" = 1 ] && echo pull || echo "target $TARGET")"
  log "thresholds: gate ${GATE_TIMEOUT}s, soak ${SOAK_SEC}s (fail after $SOAK_BAD_POLLS bad polls, seq +>=$MIN_ADVANCE), ledger age <= ${MAX_LEDGER_AGE}s, poll ${POLL_SEC}s, rollback re-gate ${ROLLBACK_TIMEOUT}s"
  audit run_start "" tag="$IMAGE_TAG" target="${TARGET:-pull}" hosts="${HOSTS[*]}"
  REF_BUILD="$(foundation_build)"
  [ -n "$REF_BUILD" ] || { log "PREFLIGHT: foundation RPC build_version unknown ($FOUNDATION_RPC)"; finish refused 4; }
  log "PREFLIGHT: foundation build_version $REF_BUILD"
  if [ "$MAINT_CMD" != none ]; then
    local locks; locks="$(hx "$MAINT_HOST" "$MAINT_CMD" lock list 2>&1)"
    [ "$locks" = "no data-collection locks" ] || { log "PREFLIGHT: pft-maint data-collection lock held: $locks"; finish refused 4; }
  fi
  local h rc
  for h in "${HOSTS[@]}"; do record_host "$h" || finish refused 4; done
  for h in "${HOSTS[@]}"; do
    poll_ok "$h" || { log "PREFLIGHT $h: not healthy before any change: $POLL_LINE"; finish refused 4; }
    log "PREFLIGHT $h: $POLL_LINE ok"
  done
  audit preflight_ok ""
  for h in "${HOSTS[@]}"; do
    roll_host "$h"; rc=$?
    [ "$rc" -eq 0 ] && continue
    log "STOP: $h did not promote; hosts after it are untouched"
    [ "$rc" -eq 5 ] && finish rollback_failed 5
    finish "failed_rolled_back:$h" 1
  done
  finish promoted 0
}

cmd_rollback() {
  take_lock
  [ -r "$STATE" ] || die "no state file $STATE" 3
  RUN_ID="rb-$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"
  REF_BUILD="$(foundation_build)"; [ -n "$REF_BUILD" ] || die "foundation build_version unknown" 4
  local h st rc=0
  st="$(cat "$STATE")"
  audit rollback_run_start "" of="$(jq -r .run <<<"$st")"
  for h in "${HOSTS[@]}"; do
    [ -n "$ONLY" ] && [ "$h" != "$ONLY" ] && continue
    local e; e="$(jq -c --arg l "$h" '.hosts[] | select(.label == $l and .result == "promoted")' <<<"$st")"
    [ -n "$e" ] || { log "$h: not promoted by the last run - skipped"; continue; }
    R_MODE[$h]="$(jq -r .mode <<<"$e")"; R_PREV[$h]="$(jq -r .prev_id <<<"$e")"; R_DIG[$h]="$(jq -r .prev_digest <<<"$e")"
    R_TGT[$h]="$(jq -r .target_id <<<"$e")"; R_KEPT[$h]="$(jq -r .kept_container <<<"$e")"; R_RP[$h]="$(jq -r .restart_policy <<<"$e")"; R_WD[$h]="$(jq -r .working_dir <<<"$e")"
    [ -n "$(image_id "$h" "${R_PREV[$h]}")" ] || { log "$h: recorded image ${R_PREV[$h]:7:12} missing"; rc=5; continue; }
    window_open "$h" "$(host_ttl)" || { rc=5; continue; }
    if restore "$h" && gate "$h" "$ROLLBACK_TIMEOUT"; then log "$h rolled back, gate PASS"; audit rollback_done "$h"
    else log "$h ROLLBACK FAILED"; audit rollback_fail "$h"; rc=5; fi
    window_close "$h"
  done
  audit run_end "" result=manual_rollback exit="$rc"; exit "$rc"
}

cmd_plan() {
  local h i id dig p_ok rows="[]" locks="n/a"
  REF_BUILD="$(foundation_build)"
  [ "$MAINT_CMD" != none ] && locks="$(hx "$MAINT_HOST" "$MAINT_CMD" lock list 2>&1)"
  for h in "${HOSTS[@]}"; do
    i="$(inspect "$h")"; id="$(jq -r '.Image // "none"' <<<"${i:-{\}}")"
    dig="$(image_digest "$h" "$id")"; p_ok=no; [ -n "$(image_id "$h" "$id")" ] && p_ok=yes
    if poll_ok "$h"; then hl="ok $POLL_LINE"; else hl="$POLL_LINE"; fi
    rows="$(jq -c --arg l "$h" --arg c "${H_CONT[$h]}" --arg m "$(jq -r 'if .Config.Labels["com.docker.compose.project"] then "compose" else "run" end' <<<"${i:-{\}}")" \
      --arg id "$id" --arg d "$dig" --arg p "$p_ok" --arg hl "$hl" --arg mp "${H_PEERS[$h]}" \
      '. + [{host:$l,container:$c,mode:$m,image:$id,digest:$d,rollback_image_present:$p,health:$hl,min_peers:($mp|tonumber)}]' <<<"$rows")"
  done
  if [ "$JSON" = 1 ]; then
    jq -n --argjson h "$rows" --arg b "$REF_BUILD" --arg l "$locks" --arg tag "$IMAGE_TAG" \
      --argjson g "$GATE_TIMEOUT" --argjson s "$SOAK_SEC" --argjson a "$MAX_LEDGER_AGE" \
      '{image_tag:$tag, foundation_build:$b, locks:$l, gate_timeout:$g, soak_sec:$s, max_ledger_age:$a, order:[$h[].host], hosts:$h}'
  else
    echo "order: ${HOSTS[*]} | tag $IMAGE_TAG | foundation build ${REF_BUILD:-unknown} | locks: $locks"
    echo "gate: full|proposing, build == foundation, peers >= min, ledger age <= ${MAX_LEDGER_AGE}s within ${GATE_TIMEOUT}s; soak ${SOAK_SEC}s"
    jq -r '.[] | "\(.host): \(.container) mode=\(.mode) image=\(.image[7:19]) digest=\(.digest) rollback_image_present=\(.rollback_image_present) min_peers=\(.min_peers) health: \(.health)"' <<<"$rows"
  fi
}

cmd_status() {
  local h rows="[]" i
  for h in "${HOSTS[@]}"; do
    i="$(inspect "$h")"
    rows="$(jq -c --arg l "$h" --arg id "$(jq -r '.Image // "none"' <<<"${i:-{\}}")" \
      --arg st "$(jq -r '.State.StartedAt // "none"' <<<"${i:-{\}}")" '. + [{host:$l,image:$id,started_at:$st}]' <<<"$rows")"
  done
  local last='null'; [ -r "$STATE" ] && last="$(cat "$STATE")"
  local out; out="$(jq -n --argjson h "$rows" --argjson last "$last" \
    --argjson lock "$( { exec 8>>"$LOCK"; flock -n 8 && echo false || echo true; } 2>/dev/null)" \
    '{lock_held:$lock, hosts:$h, last_run:$last}')"
  if [ "$JSON" = 1 ]; then echo "$out"; else
    jq -r '"lock held: \(.lock_held)", (.hosts[] | "\(.host): image \(.image[7:19]) started \(.started_at)"),
      (if .last_run then "last run \(.last_run.run): \(.last_run.result) [" + ([.last_run.hosts[] | "\(.label)=\(.result)"] | join(", ")) + "]" else "no run yet" end)' <<<"$out"
  fi
}

# ---------- main ----------
CMD="${1:-}"; [ $# -gt 0 ] && shift
YES=0; JSON=0; PULL=1; TARGET=""; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;;
    --json) JSON=1 ;;
    --no-pull) PULL=0 ;;
    --target) TARGET="${2:?--target REF}"; shift ;;
    --host) ONLY="${2:?--host LABEL}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 3 ;;
  esac
  shift
done
for c in jq curl flock; do command -v "$c" >/dev/null || die "$c required" 3; done
case "$CMD" in
  plan) load_conf; cmd_plan ;;
  status) load_conf; cmd_status ;;
  run)
    [ "$YES" = 1 ] || die "run restarts nodes; re-run with --yes" 4
    [ "$PULL" = 0 ] && [ -z "$TARGET" ] && die "--no-pull needs --target REF" 3
    [ -n "$TARGET" ] && [ "$PULL" = 1 ] && die "--target REF needs --no-pull (the image must already be on each host)" 3
    load_conf; cmd_run ;;
  rollback) [ "$YES" = 1 ] || die "rollback restarts nodes; re-run with --yes" 4; load_conf; cmd_rollback ;;
  *) usage >&2; exit 3 ;;
esac
