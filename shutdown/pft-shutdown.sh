#!/usr/bin/env bash
# pft-shutdown: does Docker give postfiatd enough time to stop cleanly before SIGKILL, on every stop path?
# Validator (compose container postfiatd) or sentry (`docker run` container postfiatd-sentry), Ubuntu 22.04,
# Docker 29 with live-restore. postfiatd is PID 1 in its container (the image entrypoint `exec`s it), so the
# container's stop signal reaches it directly.
#
# Usage: pft-shutdown audit [--json] [--required SEC]
#        pft-shutdown measure --yes [--timeout SEC] [--json]
#        pft-shutdown kill-drill --yes [--json]
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
#  audit   read-only. One line per check, PASS / FAIL / INFO, then RESULT. REQUIRED is the stop budget postfiatd
#          needs: max(MIN_TIMEOUT, ceil(p100 * SAFETY_FACTOR)) where p100 is the slowest clean stop recorded by
#          `measure` in STATE_DIR/measure-<container>.json; without measurements REQUIRED = MIN_TIMEOUT (basis
#          "default", reported). --required overrides both.
#   F1 signal        effective stop signal (container StopSignal, else the image's, else SIGTERM) is SIGTERM/SIGINT
#   F2 stop-timeout  the running container's StopTimeout (unset = Docker's default 10 s) >= REQUIRED: the budget
#                    of `docker stop`, `docker compose stop/up/down` and `docker restart` without -t
#   F3 recreate      the value the NEXT re-creation gives the container >= REQUIRED: compose stop_grace_period
#                    (`docker compose config`, unset = 10 s) for a compose container; for a `docker run` container
#                    the recreate tooling must carry --stop-timeout (RECREATE_TOOLS are grepped; none = FAIL)
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
#      STATE_DIR (/var/lib/pft-shutdown)  RECREATE_TOOLS (newline list, default /usr/local/sbin/pft-confine and
#      /usr/local/lib/pft-shutdown/recreate.sh)
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
RECREATE_TOOLS="${RECREATE_TOOLS:-$R/usr/local/sbin/pft-confine
$R/usr/local/lib/pft-shutdown/recreate.sh}"
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
  local I img_sig sig st lr djson sd unit scope sc cmpwd cmpfiles svc g gs reboot tool hit
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
    hit=""
    while IFS= read -r tool; do
      [ -n "$tool" ] && [ -f "$tool" ] && grep -q -- '--stop-timeout' "$tool" && hit="${hit:+$hit, }${tool#"$R"}"
    done <<<"$RECREATE_TOOLS"
    [ -n "$hit" ] && res PASS F3 "docker run container: recreate tooling carries --stop-timeout ($hit)" \
      || fail F3 4 "docker run container: no recreate tool carries --stop-timeout, a re-creation resets StopTimeout to ${DOCKER_DEFAULT_STOP}s"
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
  *) usage ;;
esac
