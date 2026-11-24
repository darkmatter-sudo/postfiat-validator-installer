#!/usr/bin/env bash
# pft-shutdown: does Docker give postfiatd enough time to stop cleanly before SIGKILL, on every stop path?
# Validator (compose container postfiatd) or sentry (`docker run` container postfiatd-sentry), Ubuntu 22.04,
# Docker 29 with live-restore. postfiatd is PID 1 in its container (the image entrypoint `exec`s it), so the
# container's stop signal reaches it directly.
#
# Usage: pft-shutdown audit [--json] [--required SEC]
#        pft-shutdown measure --yes [--timeout SEC] [--json]
#        pft-shutdown kill-drill --yes [--json]
#        pft-shutdown apply --yes [--required SEC]     (inside a pft-maint window)
#        pft-shutdown rollback --yes                   (undo the last apply; inside a pft-maint window)
#
#  measure     ONE guarded clean stop of the local postfiatd container: `docker stop -t TIMEOUT` (default 120 s,
#              far above any expected stop), wall time, container ExitCode/OOMKilled, the shutdown markers postfiatd
#              writes to debug.log ("Received signal", "Server stopping", "Application stopping"), then `docker
#              start`, time until server_state is full/proposing, complete_ledgers holes, and database errors in the
#              startup log. clean = exit 0, not OOM-killed, stopped before TIMEOUT, "Received signal" logged. Each run
#              is appended to STATE_DIR/measure-<container>.json (the basis of REQUIRED).
#  kill-drill  the same cycle with `docker kill -s KILL` instead of a stop (crash recovery; recorded as mode
#              sigkill, never counted as a clean stop).
#              Guards (refused, exit 4, before any change): --yes, `pft-maint active` (a planned-maintenance window:
#              alerting is silenced by the caller), container running, server_state full/proposing.
#              Exit: 0 recorded, node back to full, no database errors (measure: stop clean); 1 measure: stop not
#              clean / kill-drill: database errors after restart (reasons listed); 2 not back to full within
#              RECOVER_TIMEOUT (container started); 4 refused; 64 error.
#
#  apply     sets the container's StopTimeout to REQUIRED (below: measured p100 x SAFETY_FACTOR) with ONE re-create.
#            Refused (exit 4, nothing changed) without --yes, root, an active pft-maint window, a running full node,
#            >= MIN_RUNS clean measured stops (or --required), when the image tag no longer names the running image,
#            or while an earlier apply with another value is in place. Idempotent: StopTimeout already = REQUIRED ->
#            "nothing to do", exit 0. Compose container: backs up .env (and an existing overlay) to STATE_DIR/backup,
#            writes docker-compose.shutdown.yml (stop_grace_period REQUIREDs) + COMPOSE_FILE, validates it with
#            `docker compose config`, then `docker compose up -d`. docker run container: stop, rename to
#            NAME-preshutdown-<id>-apply (restart=no), `docker run` with the same configuration + --stop-timeout.
#            Gate: re-created, StopTimeout = REQUIRED, every other setting unchanged (signature: image, cmd, env,
#            mounts, ports, restart, log, network, caps, read-only, tmpfs, limits, AppArmor, security_opt incl. the
#            stored seccomp profile), server_state full within RECOVER_TIMEOUT. Gate fail / error / INT -> automatic
#            rollback. On PASS the stopped previous container is removed (volumes kept).
#  rollback  the previous StopTimeout back (compose: .env + overlay from the backups, compose up; run: re-create with
#            the previous value), same gate. Exit (apply/rollback): 0 PASS or nothing to do, 1 failed + rolled back,
#            4 refused, 5 rollback failed, 6 interrupted (rolled back), 64 error.
#
#  audit   read-only. One line per check, PASS / FAIL / INFO, then RESULT. REQUIRED is the stop budget postfiatd
#          needs: max(MIN_TIMEOUT, ceil(p100 * SAFETY_FACTOR)) where p100 is the slowest clean stop recorded by
#          `measure` in STATE_DIR/measure-<container>.json; without measurements REQUIRED = MIN_TIMEOUT (basis
#          "default", reported). --required overrides both.
#   F1 signal        effective stop signal (container StopSignal, else the image's, else SIGTERM) is SIGTERM/SIGINT
#   F2 stop-timeout  the running container's StopTimeout (unset = Docker's default 10 s) >= REQUIRED: the budget
#                    of `docker stop`, `docker compose stop/up/down` and `docker restart` without -t
#   F3 recreate      the value the NEXT re-creation gives the container >= REQUIRED: compose stop_grace_period
#                    (`docker compose config`, unset = 10 s) for a compose container; for a `docker run` container
#                    EVERY installed recreate tool (RECREATE_TOOLS that exist) must carry --stop-timeout over (they
#                    are grepped; a tool without it = FAIL naming it; none installed = FAIL)
#   F4 daemon        dockerd shutdown-timeout (daemon.json, default 15 s): with live-restore off, stopping dockerd
#                    stops every container and waits at most this long -> must be >= REQUIRED; with live-restore on
#                    dockerd leaves containers running (PASS, not on the stop path)
#   F5 docker-unit   docker.service TimeoutStopUSec >= REQUIRED (infinity passes): systemd's limit on dockerd's own
#                    stop, which with live-restore off includes the container stops
#   F6 reboot        the budget postfiatd gets when the host shuts down: with live-restore on, systemd stops the
#                    container's docker-<id>.scope directly (KillSignal, then SIGKILL after TimeoutStopUSec); with
#                    live-restore off, min(StopTimeout, shutdown-timeout, docker.service TimeoutStopUSec) -> >= REQUIRED
#
# Exit codes: 0 PASS; otherwise the OR of the failed findings: 1 F1, 2 F2, 4 F3, 8 F4, 16 F5, 32 F6 (1..63);
#             64 error (container missing, docker unreadable); 65 usage.
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  MIN_TIMEOUT (30)  SAFETY_FACTOR (3)
#      STATE_DIR (/var/lib/pft-shutdown)  RECREATE_TOOLS (newline list, default /usr/local/bin/pft-seccomp,
#      /usr/local/bin/pft-apparmor, /usr/local/sbin/pft-confine, /usr/local/bin/pft-confine)
#      apply/rollback: MIN_RUNS (3)  SECCOMP_FILE (/etc/pft-seccomp/pft-postfiatd.json: docker run re-create of a
#      container with a seccomp profile)  PFT_SHUTDOWN_INJECT=gate (apply's gate fails: automatic-rollback drill)
#      measure/kill-drill: RECOVER_TIMEOUT (900)  POLL_SEC (5)  SETTLE_SEC (60, wait after full before the
#      complete_ledgers hole check)
#      Test hooks: PFT_SHUTDOWN_ROOT (path prefix for files)  PFT_SHUTDOWN_DOCKER / _SYSTEMCTL / _MAINT (commands)
#      PFT_SHUTDOWN_RPC (command printing a server_info JSON response; default host port or docker exec curl)

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_SHUTDOWN_ROOT:-}"
DOCKER="${PFT_SHUTDOWN_DOCKER:-docker}"
SYSTEMCTL="${PFT_SHUTDOWN_SYSTEMCTL:-systemctl}"
MAINT="${PFT_SHUTDOWN_MAINT:-pft-maint}"
RECOVER_TIMEOUT="${RECOVER_TIMEOUT:-900}"
POLL_SEC="${POLL_SEC:-5}"
SETTLE_SEC="${SETTLE_SEC:-60}"
MIN_TIMEOUT="${MIN_TIMEOUT:-30}"
SAFETY_FACTOR="${SAFETY_FACTOR:-3}"
STATE_DIR="${STATE_DIR:-$R/var/lib/pft-shutdown}"
DJSON="$R/etc/docker/daemon.json"
RECREATE_TOOLS="${RECREATE_TOOLS:-$R/usr/local/bin/pft-seccomp
$R/usr/local/bin/pft-apparmor
$R/usr/local/sbin/pft-confine
$R/usr/local/bin/pft-confine}"
MIN_RUNS="${MIN_RUNS:-3}"
INJECT="${PFT_SHUTDOWN_INJECT:-}"   # "gate": apply's gate fails (automatic-rollback drill)
SECCOMP_FILE="${SECCOMP_FILE:-/etc/pft-seccomp/pft-postfiatd.json}"
NOJ='{}'
DOCKER_DEFAULT_STOP=10   # Docker's StopTimeout when unset (also compose's stop_grace_period default)
DOCKERD_DEFAULT_SHUTDOWN=15

die() { echo "pft-shutdown: $*" >&2; exit "${2:-64}"; }
ts() { date -u +%FT%TZ; }
usage() {
  sed -n '/^# Usage:/,/^#$/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
  exit 65
}

detect_container() {
  [ -n "${CONTAINER:-}" ] && return 0
  local c
  for c in postfiatd postfiatd-sentry; do
    "$DOCKER" inspect "$c" >/dev/null 2>&1 && { CONTAINER="$c"; return 0; }
  done
  die "no postfiatd container found (set CONTAINER)"
}

# systemd time span ("1min 30s", "90s", "500ms", "infinity", "5min") -> whole seconds, or "inf"
span_s() {
  local v="$1" t=0 n u
  [ "$v" = infinity ] && { echo inf; return 0; }
  [ -n "$v" ] || return 1
  for tok in $v; do
    n="${tok%%[a-z]*}"; u="${tok#"$n"}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    case "$u" in
      h) t=$((t + n * 3600)) ;; min) t=$((t + n * 60)) ;; s|'') t=$((t + n)) ;;
      ms) t=$((t + (n + 999) / 1000)) ;; us) t=$((t + (n + 999999) / 1000000)) ;; *) return 1 ;;
    esac
  done
  echo "$t"
}

# Go/compose duration ("1m30s", "45s", "2m", "1h", "500ms") -> whole seconds (rounded up)
dur_s() {
  local v="$1" t=0 n u
  [ -n "$v" ] || return 1
  while [ -n "$v" ]; do
    [[ "$v" =~ ^([0-9]+)(h|ms|m|s)(.*)$ ]] || return 1
    n="${BASH_REMATCH[1]}"; u="${BASH_REMATCH[2]}"; v="${BASH_REMATCH[3]}"
    case "$u" in h) t=$((t + n * 3600)) ;; m) t=$((t + n * 60)) ;; s) t=$((t + n)) ;; ms) t=$((t + (n + 999) / 1000)) ;; esac
  done
  echo "$t"
}

ge() { [ "$1" = inf ] || [ "$1" -ge "$2" ]; }   # SEC|inf REQUIRED
min_s() { local m=inf v; for v in "$@"; do [ "$v" = inf ] && continue; [ "$m" = inf ] || [ "$v" -lt "$m" ] && m="$v"; done; echo "$m"; }

# REQUIRED and its basis from the measure state (or --required / MIN_TIMEOUT)
required() {
  local f="$STATE_DIR/measure-$CONTAINER.json" p
  if [ -n "${REQ_OVERRIDE:-}" ]; then REQ="$REQ_OVERRIDE"; REQ_BASIS="--required"; return 0; fi
  REQ="$MIN_TIMEOUT"; REQ_BASIS="default (no measurements in $f)"
  [ -f "$f" ] || return 0
  p="$(jq -r '[.runs[] | select(.clean == true) | .stop_s] | if length == 0 then empty else max end' "$f" 2>/dev/null)"
  [ -n "$p" ] || { REQ_BASIS="default (no clean run in $f)"; return 0; }
  local need
  need="$(awk -v p="$p" -v f="$SAFETY_FACTOR" 'BEGIN { x = p * f; n = int(x); if (n < x) n++; print n }')"
  REQ_BASIS="p100 ${p}s x $SAFETY_FACTOR = ${need}s, floor ${MIN_TIMEOUT}s ($(jq '[.runs[] | select(.clean == true)] | length' "$f") clean runs)"
  [ "$need" -gt "$REQ" ] && REQ="$need"
  return 0
}

RES=()   # "STATUS|ID|MESSAGE"
res() { RES+=("$1|$2|$3"); }
CODE=0
fail() { res FAIL "$1" "$3"; CODE=$((CODE | $2)); }

audit_checks() {
  local I img_sig sig st lr djson sd unit scope sc cmpwd cmpfiles svc g gs reboot tool hit miss
  I="$("$DOCKER" inspect "$CONTAINER" 2>/dev/null | jq -c '.[0] // empty')"
  [ -n "$I" ] || die "cannot inspect container $CONTAINER"
  djson='{}'; [ -f "$DJSON" ] && { djson="$(jq -c . "$DJSON" 2>/dev/null)" || die "daemon.json is not valid JSON"; }
  lr="$(jq -r '."live-restore" // false' <<<"$djson")"
  required

  # F1 signal
  sig="$(jq -r '.Config.StopSignal // ""' <<<"$I")"
  if [ -z "$sig" ]; then
    img_sig="$("$DOCKER" image inspect -f '{{.Config.StopSignal}}' "$(jq -r .Image <<<"$I")" 2>/dev/null)"
    sig="${img_sig:-SIGTERM}"; [ "$sig" = "<no value>" ] && sig=SIGTERM
  fi
  case "$sig" in
    SIGTERM|TERM|15|SIGINT|INT|2) res PASS F1 "stop signal $sig (postfiatd shuts down cleanly on SIGTERM/SIGINT)" ;;
    *) fail F1 1 "stop signal $sig: postfiatd only shuts down cleanly on SIGTERM/SIGINT" ;;
  esac

  # F2 stop-timeout of the running container
  st="$(jq -r '.Config.StopTimeout // empty' <<<"$I")"
  if [ -z "$st" ]; then st="$DOCKER_DEFAULT_STOP"; gs="unset -> Docker default ${st}s"; else gs="${st}s"; fi
  ge "$st" "$REQ" && res PASS F2 "container StopTimeout $gs >= required ${REQ}s" \
    || fail F2 2 "container StopTimeout $gs < required ${REQ}s: docker stop/restart sends SIGKILL too early"

  # F3 what the next re-creation gives
  cmpwd="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"] // empty' <<<"$I")"
  if [ -n "$cmpwd" ]; then
    cmpfiles="$(jq -r '.Config.Labels["com.docker.compose.project.config_files"] // ""' <<<"$I")"
    svc="$(jq -r '.Config.Labels["com.docker.compose.service"] // "postfiatd"' <<<"$I")"
    g="$(cd "$R$cmpwd" 2>/dev/null && "$DOCKER" compose config --format json 2>/dev/null)"
    if [ -z "$g" ] || ! jq -e --arg s "$svc" '.services[$s]' >/dev/null 2>&1 <<<"$g"; then
      fail F3 4 "compose project $cmpwd: cannot read service $svc from docker compose config"
    else
      gs="$(jq -r --arg s "$svc" '.services[$s].stop_grace_period // empty' <<<"$g")"
      if [ -z "$gs" ]; then sd="$DOCKER_DEFAULT_STOP"; gs="unset -> ${sd}s"
      else sd="$(dur_s "$gs")" || { fail F3 4 "compose stop_grace_period '$gs' unparseable"; sd=""; }; fi
      if [ -n "$sd" ]; then
        ge "$sd" "$REQ" && res PASS F3 "compose stop_grace_period $gs >= required ${REQ}s (files: ${cmpfiles//"$cmpwd/"/})" \
          || fail F3 4 "compose stop_grace_period $gs < required ${REQ}s: the next compose up re-creates it short"
      fi
    fi
  else
    hit=""; miss=""
    while IFS= read -r tool; do
      [ -n "$tool" ] && [ -f "$tool" ] || continue
      if grep -q -- '--stop-timeout' "$tool"; then hit="${hit:+$hit, }${tool#"$R"}"; else miss="${miss:+$miss, }${tool#"$R"}"; fi
    done <<<"$RECREATE_TOOLS"
    if [ -n "$miss" ]; then fail F3 4 "docker run container: recreate tool(s) without --stop-timeout: $miss (a re-creation resets StopTimeout to ${DOCKER_DEFAULT_STOP}s)"
    elif [ -n "$hit" ]; then res PASS F3 "docker run container: every recreate tool carries --stop-timeout ($hit)"
    else fail F3 4 "docker run container: no recreate tool carries --stop-timeout, a re-creation resets StopTimeout to ${DOCKER_DEFAULT_STOP}s"; fi
  fi

  # F4 daemon shutdown-timeout
  sd="$(jq -r '."shutdown-timeout" // empty' <<<"$djson")"
  [ -n "$sd" ] && gs="${sd}s" || { sd="$DOCKERD_DEFAULT_SHUTDOWN"; gs="unset -> ${sd}s"; }
  if [ "$lr" = true ]; then res PASS F4 "live-restore on: stopping dockerd leaves containers running (shutdown-timeout $gs not on the stop path)"
  else ge "$sd" "$REQ" && res PASS F4 "live-restore off, dockerd shutdown-timeout $gs >= required ${REQ}s" \
    || fail F4 8 "live-restore off, dockerd shutdown-timeout $gs < required ${REQ}s: a dockerd stop kills postfiatd"; fi

  # F5 docker.service TimeoutStopUSec
  unit="$("$SYSTEMCTL" show docker.service -p TimeoutStopUSec --value 2>/dev/null)"
  unit="$(span_s "$unit")" || { fail F5 16 "docker.service TimeoutStopUSec unreadable"; unit=""; }
  if [ -n "$unit" ]; then
    ge "$unit" "$REQ" && res PASS F5 "docker.service TimeoutStopUSec ${unit} >= required ${REQ}s" \
      || fail F5 16 "docker.service TimeoutStopUSec ${unit}s < required ${REQ}s"
  fi

  # F6 reboot path
  if [ "$lr" = true ]; then
    scope="docker-$(jq -r .Id <<<"$I").scope"
    sc="$("$SYSTEMCTL" show "$scope" -p TimeoutStopUSec --value 2>/dev/null)"
    local ks; ks="$("$SYSTEMCTL" show "$scope" -p KillSignal --value 2>/dev/null)"
    sc="$(span_s "$sc")" || { fail F6 32 "reboot: cannot read TimeoutStopUSec of the container scope"; return 0; }
    case "$ks" in 15|2|'') ;; *) fail F6 32 "reboot: container scope KillSignal $ks is not SIGTERM/SIGINT"; return 0 ;; esac
    ge "$sc" "$REQ" && res PASS F6 "reboot (live-restore): systemd stops the container scope with signal ${ks:-15}, SIGKILL after ${sc}s >= required ${REQ}s" \
      || fail F6 32 "reboot (live-restore): container scope SIGKILLs after ${sc}s < required ${REQ}s"
  else
    reboot="$(min_s "$st" "$sd" "${unit:-0}")"
    ge "$reboot" "$REQ" && res PASS F6 "reboot (live-restore off): min(StopTimeout, shutdown-timeout, docker.service) ${reboot}s >= required ${REQ}s" \
      || fail F6 32 "reboot (live-restore off): budget ${reboot}s < required ${REQ}s"
  fi
}

# ---- measure / kill-drill
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }
rpc_info() { # server_info .result.info JSON or nothing
  local port
  if [ -n "${PFT_SHUTDOWN_RPC:-}" ]; then $PFT_SHUTDOWN_RPC server_info 2>/dev/null
  else
    port="$("$DOCKER" port "$CONTAINER" 5005/tcp 2>/dev/null | sed -n 's/^127\.0\.0\.1://p' | head -1)"
    if [ -n "$port" ]; then curl -s -m 10 -d '{"method":"server_info"}' "http://127.0.0.1:$port/"
    else "$DOCKER" exec "$CONTAINER" curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005/; fi 2>/dev/null
  fi | jq -c '.result.info // empty' 2>/dev/null
}
is_full() { [ -n "$1" ] && jq -e '.server_state == "full" or .server_state == "proposing"' >/dev/null 2>&1 <<<"$1"; }
# holes of complete_ledgers ("a-b,c,d-e") at or above LO: "from-to ..." and their total ledger count
holes() { # RANGES LO
  jq -rn --arg r "$1" --argjson lo "${2:-0}" '
    [$r | split(",")[] | select(test("^[0-9]+(-[0-9]+)?$")) | split("-") | map(tonumber) | {a: .[0], b: (.[1] // .[0])}] | sort_by(.a) as $s
    | [range(1; $s | length) | {from: ($s[. - 1].b + 1), to: ($s[.].a - 1)} | select(.to >= .from and .to >= $lo)
       | .from = ([.from, $lo] | max)]
    | "\(map("\(.from)-\(.to)") | join(" "))|\(map(.to - .from + 1) | add // 0)"' 2>/dev/null || echo "?|?"
}
log_file() { # host path of the container's debug.log
  local src; src="$(jq -r '[.Mounts[]? | select(.Destination == "/var/log/postfiatd") | .Source][0] // empty' <<<"$1")"
  [ -n "$src" ] && echo "$R$src/debug.log"
}
DB_ERR='(FTL|FATL|Fatal|fatal)|[Cc]orrupt|NodeStore.*(ERR|[Ee]rror)|(SQLite|sqlite|database).*(ERR|[Ee]rror|malformed)|Unable to open'

cycle() { # MODE: clean | sigkill
  local mode="$1" I lf off size t0 t1 rc st ec oom fin i0 i1 pre_lo pre_hi pre_rng post_rng h hs hn tr tf rs reasons=() \
    m_sig m_srv m_app tail_new dberr full_at="" st_after="?" E0="{}"
  [ "$YES" = 1 ] || die "refused: pass --yes (this stops the live $CONTAINER once)" 4
  "$MAINT" active >/dev/null 2>&1 || die "refused: no active pft-maint window (start one and silence alerting first)" 4
  I="$("$DOCKER" inspect "$CONTAINER" 2>/dev/null | jq -c '.[0] // empty')"
  [ -n "$I" ] || die "cannot inspect container $CONTAINER"
  [ "$(jq -r '.State.Running' <<<"$I")" = true ] || die "refused: $CONTAINER is not running" 4
  i0="$(rpc_info)"; is_full "$i0" || die "refused: $CONTAINER server_state is $(jq -r '.server_state // "unreachable"' <<<"${i0:-$E0}") (want full/proposing)" 4
  pre_rng="$(jq -r '.complete_ledgers // ""' <<<"$i0")"; pre_hi="$(jq -r '.validated_ledger.seq // 0' <<<"$i0")"
  pre_lo="${pre_rng%%[-,]*}"; [[ "$pre_lo" =~ ^[0-9]+$ ]] || pre_lo=0
  lf="$(log_file "$I")"; off=0; [ -n "$lf" ] && [ -f "$lf" ] && off="$(stat -c %s "$lf")"
  echo "pft-shutdown $mode $CONTAINER - $(ts) - complete_ledgers $pre_rng validated $pre_hi"

  t0="$(now)"
  if [ "$mode" = clean ]; then "$DOCKER" stop -t "$TIMEOUT" "$CONTAINER" >/dev/null 2>&1; rc=$?
  else "$DOCKER" kill -s KILL "$CONTAINER" >/dev/null 2>&1; rc=$?
    for _ in $(seq 1 100); do [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = false ] && break; sleep 0.1; done
  fi
  t1="$(now)"; st="$(since "$t0" "$t1")"
  I="$("$DOCKER" inspect "$CONTAINER" 2>/dev/null | jq -c '.[0] // empty')"
  ec="$(jq -r '.State.ExitCode // "?"' <<<"$I")"; oom="$(jq -r '.State.OOMKilled // false' <<<"$I")"
  fin="$(jq -r '.State.FinishedAt // ""' <<<"$I")"
  m_sig=0; m_srv=0; m_app=0; tail_new=""
  if [ -n "$lf" ] && [ -f "$lf" ]; then
    size="$(stat -c %s "$lf")"; [ "$size" -lt "$off" ] && off=0
    tail_new="$(tail -c +"$((off + 1))" "$lf")"
    m_sig="$(grep -c 'Received signal' <<<"$tail_new")"; m_srv="$(grep -c 'Server stopping' <<<"$tail_new")"
    m_app="$(grep -c 'Application stopping' <<<"$tail_new")"
  fi
  echo "  stop: ${mode} rc $rc wall ${st}s exit_code $ec oom_killed $oom finished $fin"
  echo "  markers in debug.log since the stop: Received signal $m_sig, Server stopping $m_srv, Application stopping $m_app${lf:+ ($(basename "$lf"))}"
  [ -n "$tail_new" ] && grep -E 'Received signal|Server stopping|Application stopping' <<<"$tail_new" | tail -3 | cut -c1-200 | sed 's/^/    | /'
  if [ "$mode" = clean ]; then
    [ "$rc" = 0 ] || reasons+=("docker stop rc $rc")
    [ "$ec" = 0 ] || reasons+=("exit code $ec (137 = SIGKILL after the timeout)")
    [ "$oom" = false ] || reasons+=("OOM-killed")
    awk -v s="$st" -v t="$TIMEOUT" 'BEGIN { exit !(s < t) }' || reasons+=("stop took ${st}s >= timeout ${TIMEOUT}s")
    [ "$m_sig" -gt 0 ] || reasons+=("no 'Received signal' marker in debug.log")
  else
    [ "$ec" = 137 ] || reasons+=("exit code $ec after SIGKILL (expected 137)")
  fi

  tr="$(now)"; "$DOCKER" start "$CONTAINER" >/dev/null 2>&1 || die "docker start $CONTAINER failed - start it by hand" 64
  while :; do
    i1="$(rpc_info)"
    if is_full "$i1"; then full_at="$(now)"; st_after="$(jq -r .server_state <<<"$i1")"; break; fi
    [ -n "$i1" ] && st_after="$(jq -r '.server_state // "?"' <<<"$i1")"
    awk -v a="$tr" -v b="$(now)" -v t="$RECOVER_TIMEOUT" 'BEGIN { exit !(b - a >= t) }' && break
    sleep "$POLL_SEC"
  done
  tf=""; [ -n "$full_at" ] && tf="$(since "$tr" "$full_at")"
  if [ -n "$full_at" ]; then
    sleep "$SETTLE_SEC"; i1="$(rpc_info)"; [ -n "$i1" ] && st_after="$(jq -r '.server_state // "?"' <<<"$i1")"
  fi
  post_rng="$(jq -r '.complete_ledgers // ""' <<<"${i1:-$E0}")"
  h="$(holes "$post_rng" "$pre_lo")"; hs="${h%|*}"; hn="${h#*|}"
  dberr=0
  if [ -n "$lf" ] && [ -f "$lf" ]; then
    # the entrypoint rotates debug.log at start: the startup log is the current file (its lines after the start)
    dberr="$(grep -cE "$DB_ERR" "$lf" 2>/dev/null)"; dberr="${dberr:-0}"
  fi
  rs="${tf:-none}"
  echo "  start: server_state ${st_after} after ${rs}s (timeout ${RECOVER_TIMEOUT}s); complete_ledgers $post_rng"
  echo "  holes at/above $pre_lo: ${hs:-none} (${hn} ledgers); database error lines in the startup log: $dberr"
  [ "$dberr" = 0 ] || grep -E "$DB_ERR" "$lf" | head -5 | cut -c1-200 | sed 's/^/    | /'
  [ "$dberr" = 0 ] || reasons+=("$dberr database error line(s) after restart")

  local clean=false; [ "$mode" = clean ] && [ "${#reasons[@]}" = 0 ] && clean=true
  local rj; rj="$(jq -nc --arg t "$(ts)" --arg c "$CONTAINER" --arg m "$mode" --argjson to "${TIMEOUT:-0}" --argjson st "$st" \
    --arg ec "$ec" --argjson oom "$oom" --arg fin "$fin" --argjson ms "$m_sig" --argjson mv "$m_srv" --argjson ma "$m_app" \
    --argjson clean "$clean" --arg rs "$tf" --arg sa "$st_after" --arg pr "$pre_rng" --argjson ph "$pre_hi" --arg po "$post_rng" \
    --arg hs "$hs" --arg hn "$hn" --argjson db "$dberr" --args '{time: $t, container: $c, mode: $m, timeout_s: $to, stop_s: $st,
      exit_code: ($ec | tonumber? // $ec), oom_killed: $oom, finished_at: $fin,
      markers: {received_signal: $ms, server_stopping: $mv, application_stopping: $ma}, clean: $clean,
      recover_s: ($rs | tonumber? // null), state_after: $sa, ledgers_before: $pr, validated_before: $ph, ledgers_after: $po,
      holes: $hs, hole_ledgers: ($hn | tonumber? // null), db_error_lines: $db, reasons: $ARGS.positional}' "${reasons[@]}")"
  mkdir -p "$STATE_DIR" && local f="$STATE_DIR/measure-$CONTAINER.json"
  { [ -f "$f" ] && cat "$f" || echo '{"runs":[]}'; } | jq --argjson r "$rj" '.runs += [$r]' > "$f.tmp" && mv "$f.tmp" "$f" \
    || die "cannot write $f"
  [ "$JSON" = 1 ] && echo "$rj"
  local n; n="$(jq '[.runs[] | select(.mode == "clean" and .clean == true)] | length' "$f")"
  echo "  recorded in $f (${n} clean stop(s); p100 $(jq -r '[.runs[] | select(.clean == true) | .stop_s] | max // "-"' "$f")s)"
  local i2; for i2 in "${reasons[@]}"; do echo "  reason: $i2"; done
  if [ -z "$full_at" ]; then echo "RESULT: FAIL - not back to full within ${RECOVER_TIMEOUT}s"; return 2; fi
  if [ "${#reasons[@]}" -gt 0 ]; then echo "RESULT: FAIL - $mode: ${#reasons[@]} reason(s)"; return 1; fi
  echo "RESULT: PASS - $mode stop ${st}s, back to full in ${tf}s, holes ${hn}, database errors 0"; return 0
}

# ---- apply / rollback
# Signature of everything a re-create must keep (image, cmd, user, env, mounts, ports, restart, log, network, the
# confine/AppArmor/seccomp profile, resources) - all but StopTimeout. The gate requires it unchanged.
keep_sig() { # INSPECT0
  jq -cS '{image: .Config.Image, image_id: .Image, cmd: (.Config.Cmd // []), entrypoint: (.Config.Entrypoint // []),
    user: (.Config.User // ""), env: (.Config.Env // [] | sort), stop_signal: (.Config.StopSignal // ""),
    cap_add: (.HostConfig.CapAdd // [] | sort), cap_drop: (.HostConfig.CapDrop // [] | sort),
    read_only: (.HostConfig.ReadonlyRootfs // false), tmpfs: (.HostConfig.Tmpfs // {}),
    pids: (.HostConfig.PidsLimit // 0), memory: (.HostConfig.Memory // 0), memory_swap: (.HostConfig.MemorySwap // 0),
    cpu_shares: (.HostConfig.CpuShares // 0), memory_reservation: (.HostConfig.MemoryReservation // 0),
    apparmor: (.AppArmorProfile // ""), security_opt: (.HostConfig.SecurityOpt // [] | sort),
    mounts: (.Mounts // [] | map({type: .Type, name: (if .Type == "volume" then .Name else null end),
             source: (if .Type == "bind" then .Source else null end), dest: .Destination, rw: .RW}) | sort_by(.dest)),
    ports: (.HostConfig.PortBindings // {}), network: (.HostConfig.NetworkMode // ""), log: (.HostConfig.LogConfig // {}),
    restart: (.HostConfig.RestartPolicy.Name // "")}' <<<"$1"
}
sig_diff() { jq -rn --argjson a "$1" --argjson b "$2" '[($a + $b) | keys[] | select($a[.] != $b[.])] | join(",")'; }
inspect0() { "$DOCKER" inspect "$1" 2>/dev/null | jq -c '.[0] // empty' 2>/dev/null; }
stop_of() { jq -r '.Config.StopTimeout // "unset"' <<<"${1:-$NOJ}"; }   # INSPECT0 -> seconds or "unset"

# docker run args that re-create a `docker run` container exactly, with --stop-timeout STOP (unset: none).
# Docker stores a seccomp profile inline (json.Compact of the file): it is passed again as seccomp=SECCOMP_FILE,
# and the gate's signature (stored SecurityOpt verbatim) proves the bytes are the same.
run_args() { # INSPECT0 IMAGE_ENV_JSON STOP
  jq -r --argjson ienv "$2" --arg st "$3" --arg scf "$SECCOMP_FILE" '
    "--name=\(.Name[1:])",
    "--restart=\(.HostConfig.RestartPolicy.Name)\(if .HostConfig.RestartPolicy.Name == "on-failure" then ":\(.HostConfig.RestartPolicy.MaximumRetryCount)" else "" end)",
    (if $st != "unset" then "--stop-timeout=\($st)" else empty end),
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
    (.HostConfig.SecurityOpt // [] | .[] | if startswith("seccomp") then "--security-opt=seccomp=\($scf)" else "--security-opt=\(.)" end),
    .Config.Image, (.Config.Cmd // [])[]' <<<"$1"
}
show_args() { sed -E 's/^(--env=[^=]*)=.*/\1=<value>/; s/([0-9]{1,3}\.){3}[0-9]{1,3}/<redacted-ip>/g' | paste -sd' '; }

# CPU weight / memory.low set live with `docker update` are not in the compose files: put them back after compose up
keep_resources() { # CONTAINER SIG
  local cs mr cur a=()
  cs="$(jq -r '.cpu_shares' <<<"$2")"; mr="$(jq -r '.memory_reservation' <<<"$2")"
  [ "$cs" -gt 0 ] || [ "$mr" -gt 0 ] || return 0
  cur="$(inspect0 "$1" | jq -r '"\(.HostConfig.CpuShares // 0) \(.HostConfig.MemoryReservation // 0)"')"
  [ "$cur" = "$cs $mr" ] && return 0
  [ "$cs" -gt 0 ] && a+=("--cpu-shares=$cs"); [ "$mr" -gt 0 ] && a+=("--memory-reservation=$mr")
  "$DOCKER" update "${a[@]}" "$1" >/dev/null 2>&1 && echo "  resources: restored ${a[*]} (compose up dropped '$cur')"
}

# After a re-create: new container (StartedAt changed), StopTimeout = WANT, keep-signature unchanged, full.
gate() { # WHAT BEFORE_STARTED WANT_STOP SIG
  local what="$1" before="$2" want="$3" sig="$4" t0 i hard soft s st info
  t0="$(now)"
  while :; do
    i="$(inspect0 "$CONTAINER")"; hard=""; soft=""
    if [ -z "$i" ]; then hard=" container missing;"; else
      s="$(jq -r '.State.StartedAt // ""' <<<"$i")"; [ -n "$s" ] && [ "$s" != "$before" ] || hard+=" not re-created (StartedAt unchanged);"
      st="$(stop_of "$i")"; [ "$st" = "$want" ] || hard+=" StopTimeout $st want $want;"
      [ "$(keep_sig "$i")" = "$sig" ] || hard+=" configuration changed: $(sig_diff "$sig" "$(keep_sig "$i")");"
    fi
    info="$(rpc_info)"; is_full "$info" || soft=" server_state $(jq -r '.server_state // "unreachable"' <<<"${info:-$NOJ}");"
    if [ -z "$hard$soft" ]; then
      echo "  $what gate PASS after $(since "$t0" "$(now)")s: re-created, StopTimeout $st, configuration unchanged, server_state $(jq -r .server_state <<<"$info")"
      return 0
    fi
    # a configuration difference never heals: fail at once; only "not full yet" is waited for
    [ -n "$hard" ] && break
    awk -v a="$t0" -v b="$(now)" -v t="$RECOVER_TIMEOUT" 'BEGIN { exit !(b - a >= t) }' && break
    sleep "$POLL_SEC"
  done
  echo "  $what gate FAIL:$hard$soft"; return 1
}

state_set() { jq "$@" "$ASTATE" > "$ASTATE.tmp" && mv -f "$ASTATE.tmp" "$ASTATE"; }

# re-create the container with StopTimeout STOP (compose: overlay present/absent from the state's backups)
recreate() { # STOP(seconds|unset) HOW(apply|restore) -> rc
  local stop="$1" how="$2" i ienv old args
  i="$(inspect0 "$CONTAINER")"
  if [ "$(jq -r .kind "$ASTATE")" = compose ]; then
    local wd; wd="$R$(jq -r .working_dir "$ASTATE")"
    ( cd "$wd" && "$DOCKER" compose up -d --timeout "$(jq -r .stop_budget "$ASTATE")" 2>&1 ) | sed 's/^/  | /'
    [ "${PIPESTATUS[0]}" = 0 ] || { echo "  compose up failed"; return 1; }
    keep_resources "$CONTAINER" "$(jq -r .sig "$ASTATE")"
    return 0
  fi
  [ -n "$i" ] || { echo "  container $CONTAINER missing"; return 1; }
  ienv="$("$DOCKER" image inspect "$(jq -r .Config.Image <<<"$i")" 2>/dev/null | jq -c '.[0].Config.Env // []' 2>/dev/null)"; [ -n "$ienv" ] || ienv='[]'
  mapfile -t args < <(run_args "$i" "$ienv" "$stop")
  old="$CONTAINER-preshutdown-$(jq -r .id "$ASTATE")-$how"
  echo "  recreate: docker run -d $(printf '%s\n' "${args[@]}" | show_args)"
  "$DOCKER" stop -t "$(jq -r .stop_budget "$ASTATE")" "$CONTAINER" >/dev/null 2>&1 && "$DOCKER" rename "$CONTAINER" "$old" >/dev/null 2>&1 \
    && "$DOCKER" update --restart=no "$old" >/dev/null 2>&1 || { echo "  could not stop/rename $CONTAINER"; "$DOCKER" start "$CONTAINER" >/dev/null 2>&1; return 2; }
  state_set --arg o "$old" '.old_container = $o'
  "$DOCKER" run -d "${args[@]}" >/dev/null 2>&1 || { echo "  docker run failed"; return 1; }
  return 0
}
restore_old() { # run kind: the stopped previous container back under its name
  local old rp; old="$(jq -r '.old_container // ""' "$ASTATE")"; rp="$(jq -r '.restart' "$ASTATE")"
  [ -n "$old" ] && [ -n "$(inspect0 "$old")" ] || { echo "  previous container ${old:-?} missing"; return 1; }
  "$DOCKER" rm -f "$CONTAINER" >/dev/null 2>&1
  "$DOCKER" rename "$old" "$CONTAINER" >/dev/null 2>&1 && "$DOCKER" update --restart="$rp" "$CONTAINER" >/dev/null 2>&1 \
    && "$DOCKER" start "$CONTAINER" >/dev/null 2>&1 && { echo "  previous container restored as $CONTAINER (restart=$rp)"; state_set '.old_container = ""'; return 0; }
  echo "  restoring the previous container FAILED"; return 1
}
drop_old() { # run kind, gate passed: the stopped previous container is not needed (volumes are kept: no -v)
  local old; old="$(jq -r '.old_container // ""' "$ASTATE")"; [ -n "$old" ] || return 0
  "$DOCKER" rm "$old" >/dev/null 2>&1 && echo "  previous container $old removed (volumes kept)"; state_set '.old_container = ""'
}
# compose kind: write (apply) or restore (rollback) .env and docker-compose.shutdown.yml
compose_files_set() { # apply SEC | restore
  local wd ov eb ob; wd="$R$(jq -r .working_dir "$ASTATE")"; ov="$wd/docker-compose.shutdown.yml"
  eb="$(jq -r .env_backup "$ASTATE")"; ob="$(jq -r '.override_backup // ""' "$ASTATE")"
  if [ "$1" = apply ]; then
    printf '# written by pft-shutdown apply (measured stop budget); undo with: sudo pft-shutdown rollback --yes\nservices:\n  %s:\n    stop_grace_period: %ss\n' \
      "$(jq -r .service "$ASTATE")" "$2" > "$ov.tmp" && mv -f "$ov.tmp" "$ov" || return 1
    { grep -v '^COMPOSE_FILE=' "$eb"; echo "COMPOSE_FILE=$(jq -r .files "$ASTATE"):docker-compose.shutdown.yml"; } > "$wd/.env.tmp" \
      && chmod --reference="$eb" "$wd/.env.tmp" 2>/dev/null; mv -f "$wd/.env.tmp" "$wd/.env" || return 1
    echo "  wrote $(jq -r .working_dir "$ASTATE")/docker-compose.shutdown.yml (stop_grace_period ${2}s); COMPOSE_FILE += docker-compose.shutdown.yml"
  else
    cp -p -- "$eb" "$wd/.env" || return 1
    if [ -n "$ob" ]; then cp -p -- "$ob" "$ov" || return 1; else rm -f -- "$ov"; fi
    echo "  .env restored$([ -n "$ob" ] && echo ", previous docker-compose.shutdown.yml restored" || echo ", docker-compose.shutdown.yml removed")"
  fi
  ( cd "$wd" && "$DOCKER" compose config -q >/dev/null 2>&1 ) || { echo "  docker compose config invalid"; return 1; }
}

do_rollback() { # auto|manual
  local how="$1" s pre before i
  s="$(cat "$ASTATE")"; pre="$(jq -r .pre_stop <<<"$s")"
  [ "$(jq -r '.rolled_back // false' <<<"$s")" = true ] && { echo "$(ts) rollback: apply $(jq -r .id <<<"$s") already rolled back - nothing to do"; return 0; }
  echo "$(ts) rollback ($how) of apply $(jq -r .id <<<"$s") on $CONTAINER: back to StopTimeout $pre"
  i="$(inspect0 "$CONTAINER")"; before="$(jq -r '.State.StartedAt // ""' <<<"${i:-$NOJ}")"
  if [ "$(jq -r .kind <<<"$s")" = compose ] && [ "$(jq -r '.recreated // false' <<<"$s")" != true ]; then
    # failed before the re-create: only the files go back, the running container was never touched
    compose_files_set restore || { echo "$(ts) ROLLBACK FAILED (compose files)"; return 5; }
    state_set --arg t "$(ts)" --arg h "$how" '. + {rolled_back: true, rolled_back_at: $t, rollback: $h}'
    echo "$(ts) rollback RESULT: PASS - files restored, $CONTAINER was not re-created"; return 0
  elif [ "$(jq -r .kind <<<"$s")" = compose ]; then
    compose_files_set restore && recreate "$pre" restore || { echo "$(ts) ROLLBACK FAILED (compose)"; return 5; }
  elif [ "$how" = auto ] && [ -n "$(jq -r '.old_container // ""' <<<"$s")" ]; then
    restore_old || { echo "$(ts) ROLLBACK FAILED (run)"; return 5; }
    i="$(inspect0 "$CONTAINER")"; before=""   # the old container itself: started again, not re-created
  else
    recreate "$pre" restore || { echo "$(ts) ROLLBACK FAILED (run)"; return 5; }
  fi
  gate rollback "$before" "$pre" "$(jq -r .sig <<<"$s")" || { echo "$(ts) ROLLBACK: previous StopTimeout restored but the gate failed"; return 5; }
  [ "$(jq -r .kind <<<"$s")" = run ] && drop_old
  state_set --arg t "$(ts)" --arg h "$how" '. + {rolled_back: true, rolled_back_at: $t, rollback: $h}'
  echo "$(ts) rollback RESULT: PASS - $CONTAINER StopTimeout $pre again, node full"
}

do_apply() {
  local i st want sig before id kind wd svc cfgs files eb ov ob rest info tag
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "apply needs root" 4
  [ "$YES" = 1 ] || die "refused: pass --yes (apply re-creates the live $CONTAINER once)" 4
  "$MAINT" active >/dev/null 2>&1 || die "refused: no active pft-maint window (start one and silence alerting first)" 4
  i="$(inspect0 "$CONTAINER")"; [ -n "$i" ] || die "cannot inspect container $CONTAINER"
  [ "$(jq -r '.State.Running' <<<"$i")" = true ] || die "refused: $CONTAINER is not running" 4
  required
  [ -n "${REQ_OVERRIDE:-}" ] || [[ "$REQ_BASIS" == p100* ]] || die "refused: no measured basis for the stop budget ($REQ_BASIS); run measure first or pass --required" 4
  [ -n "${REQ_OVERRIDE:-}" ] || [ "$(jq '[.runs[] | select(.mode == "clean" and .clean == true)] | length' "$STATE_DIR/measure-$CONTAINER.json")" -ge "$MIN_RUNS" ] \
    || die "refused: fewer than MIN_RUNS=$MIN_RUNS clean measured stops for $CONTAINER" 4
  want="$REQ"; st="$(stop_of "$i")"
  if [ "$st" = "$want" ]; then echo "$(ts) apply: $CONTAINER StopTimeout is already ${want}s ($REQ_BASIS) - nothing to do"; return 0; fi
  [ -f "$ASTATE" ] && [ "$(jq -r '.rolled_back // false' "$ASTATE")" != true ] \
    && die "refused: the last apply ($(jq -r .id "$ASTATE")) set a different value and is still in place; rollback first" 4
  info="$(rpc_info)"; is_full "$info" || die "refused: $CONTAINER server_state is $(jq -r '.server_state // "unreachable"' <<<"${info:-$NOJ}") (want full/proposing)" 4
  cfgs="$(jq -r '.Config.Labels["com.docker.compose.project.config_files"] // ""' <<<"$i")"
  if [ -n "$cfgs" ]; then kind=compose; else kind=run; fi
  tag="$(jq -r .Config.Image <<<"$i")"
  [ "$("$DOCKER" image inspect -f '{{.Id}}' "$tag" 2>/dev/null)" = "$(jq -r .Image <<<"$i")" ] \
    || die "refused: tag $tag no longer names the running image (a re-create would upgrade it)" 4
  [ "$kind" = run ] && jq -e '.HostConfig.SecurityOpt // [] | map(select(startswith("seccomp"))) | length > 0' >/dev/null <<<"$i" \
    && { [ -f "$R$SECCOMP_FILE" ] || die "refused: $CONTAINER has a seccomp profile but SECCOMP_FILE $SECCOMP_FILE is missing" 4; }
  id="$(date -u +%Y%m%dT%H%M%SZ)"; sig="$(keep_sig "$i")"; before="$(jq -r '.State.StartedAt // ""' <<<"$i")"
  mkdir -p "$STATE_DIR/backup" && chmod 0700 "$STATE_DIR" || die "cannot create $STATE_DIR"
  # stop budget for the stop that the re-create itself does: the measured value, never less than the current one
  rest="$want"; [ "$st" != unset ] && [ "$st" -gt "$rest" ] && rest="$st"
  jq -n --arg id "$id" --arg c "$CONTAINER" --arg k "$kind" --arg pre "$st" --argjson want "$want" --arg basis "$REQ_BASIS" \
    --arg sig "$sig" --argjson sb "$rest" --arg rp "$(jq -r .HostConfig.RestartPolicy.Name <<<"$i")" \
    '{id: $id, container: $c, kind: $k, pre_stop: $pre, want_stop: $want, basis: $basis, sig: $sig, stop_budget: $sb, restart: $rp,
      old_container: "", rolled_back: false}' > "$ASTATE" || die "cannot write $ASTATE"
  echo "$(ts) apply $id on $CONTAINER ($kind): StopTimeout $st -> ${want}s ($REQ_BASIS)"
  if [ "$kind" = compose ]; then
    wd="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"] // ""' <<<"$i")"
    svc="$(jq -r '.Config.Labels["com.docker.compose.service"] // ""' <<<"$i")"
    [ -d "$R$wd" ] && [ -n "$svc" ] || die "compose working dir/service unknown"
    files="$(tr ',' '\n' <<<"$cfgs" | sed 's#.*/##' | grep -vx 'docker-compose.shutdown.yml' | paste -sd:)"
    eb="$STATE_DIR/backup/env.$id"; ov="$R$wd/docker-compose.shutdown.yml"; ob=""
    touch "$R$wd/.env"; cp -p -- "$R$wd/.env" "$eb" || die "cannot back up .env"
    if [ -f "$ov" ]; then ob="$STATE_DIR/backup/docker-compose.shutdown.yml.$id"; cp -p -- "$ov" "$ob" || die "cannot back up $ov"; fi
    state_set --arg wd "$wd" --arg s "$svc" --arg f "$files" --arg eb "$eb" --arg ob "$ob" \
      '. + {working_dir: $wd, service: $s, files: $f, env_backup: $eb, override_backup: $ob}'
    echo "  backups: .env -> $eb${ob:+, docker-compose.shutdown.yml -> $ob}"
    trap 'echo "$(ts) apply: interrupted -> automatic rollback"; do_rollback auto; exit 6' INT TERM
    if ! compose_files_set apply "$want"; then echo "$(ts) apply: overlay invalid -> automatic rollback"; do_rollback auto && return 1; return 5; fi
    local g; g="$(cd "$R$wd" && "$DOCKER" compose config --format json 2>/dev/null | jq -r --arg s "$svc" '.services[$s].stop_grace_period // ""')"
    if [ "$(dur_s "$g" 2>/dev/null)" != "$want" ]; then echo "$(ts) apply: compose config gives stop_grace_period '${g}', not ${want}s -> automatic rollback"; do_rollback auto && return 1; return 5; fi
    echo "  validated: docker compose config -> stop_grace_period $g"
  else
    trap 'echo "$(ts) apply: interrupted -> automatic rollback"; do_rollback auto; exit 6' INT TERM
  fi
  state_set '.recreated = true'
  recreate "$want" apply; local rc=$?
  if [ "$rc" = 2 ]; then trap - INT TERM; state_set '.rolled_back = true | .rollback = "not re-created"'; echo "$(ts) apply: FAIL - $CONTAINER could not be stopped/renamed, nothing re-created"; return 1; fi
  if [ "$rc" != 0 ]; then echo "$(ts) apply: re-create failed -> automatic rollback"; do_rollback auto && return 1; return 5; fi
  if [ "$INJECT" = gate ]; then sig="$(jq -c '.injected = true' <<<"$sig")"; echo "  PFT_SHUTDOWN_INJECT=gate: the gate compares against a wrong signature"; fi
  if ! gate apply "$before" "$want" "$sig"; then
    echo "$(ts) apply: gate failed -> automatic rollback"; do_rollback auto; rc=$?; trap - INT TERM; [ "$rc" = 0 ] && return 1; return "$rc"
  fi
  trap - INT TERM
  [ "$kind" = run ] && drop_old
  state_set --arg t "$(ts)" '. + {applied_at: $t}'
  echo "$(ts) apply RESULT: PASS - $CONTAINER StopTimeout ${want}s, configuration unchanged, node full (state $ASTATE)"
}

print_text() {
  local r s id m
  echo "pft-shutdown audit $CONTAINER - $(ts)"
  echo "required stop budget: ${REQ}s ($REQ_BASIS)"
  for r in "${RES[@]}"; do
    IFS='|' read -r s id m <<<"$r"
    printf '  [%-4s] %s %s\n' "$s" "$id" "$m"
  done
  if [ "$CODE" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL - exit $CODE"; fi
}

print_json() {
  local r
  for r in "${RES[@]}"; do printf '%s\n' "$r"; done | jq -R -s --arg c "$CONTAINER" --arg t "$(ts)" \
    --argjson req "$REQ" --arg basis "$REQ_BASIS" --argjson code "$CODE" '
    split("\n") | map(select(length > 0) | split("|") | {status: .[0], id: .[1], message: (.[2:] | join("|"))})
    | {container: $c, time: $t, required_s: $req, required_basis: $basis, exit: $code,
       result: (if $code == 0 then "PASS" else "FAIL" end), checks: .}'
}

cmd="${1:-}"; [ -n "$cmd" ] && shift
case "$cmd" in
  audit)
    JSON=0; REQ_OVERRIDE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --json) JSON=1 ;;
        --required) [[ "${2:-}" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ] || usage; REQ_OVERRIDE="$2"; shift ;;
        *) usage ;;
      esac
      shift
    done
    command -v jq >/dev/null || die "jq missing"
    detect_container
    audit_checks
    if [ "$JSON" = 1 ]; then print_json; else print_text; fi
    exit "$CODE"
    ;;
  measure|kill-drill)
    JSON=0; YES=0; TIMEOUT=120
    while [ $# -gt 0 ]; do
      case "$1" in
        --json) JSON=1 ;;
        --yes) YES=1 ;;
        --timeout) [ "$cmd" = measure ] && [[ "${2:-}" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ] || usage; TIMEOUT="$2"; shift ;;
        *) usage ;;
      esac
      shift
    done
    command -v jq >/dev/null || die "jq missing"
    detect_container
    [ "$cmd" = measure ] && { cycle clean; exit $?; }
    TIMEOUT=0; cycle sigkill; exit $?
    ;;
  apply|rollback)
    YES=0; JSON=0; REQ_OVERRIDE=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --yes) YES=1 ;;
        --required) [ "$cmd" = apply ] && [[ "${2:-}" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ] || usage; REQ_OVERRIDE="$2"; shift ;;
        *) usage ;;
      esac
      shift
    done
    command -v jq >/dev/null || die "jq missing"
    detect_container
    ASTATE="$STATE_DIR/apply-$CONTAINER.json"
    [ "$cmd" = apply ] && { do_apply; exit $?; }
    [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "rollback needs root" 4
    [ "$YES" = 1 ] || die "refused: pass --yes (rollback re-creates the live $CONTAINER once)" 4
    "$MAINT" active >/dev/null 2>&1 || die "refused: no active pft-maint window (start one and silence alerting first)" 4
    [ -f "$ASTATE" ] || die "no apply state for $CONTAINER ($ASTATE)" 4
    do_rollback manual; exit $?
    ;;
  *) usage ;;
esac
