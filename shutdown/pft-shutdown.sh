#!/usr/bin/env bash
# pft-shutdown: does Docker give postfiatd enough time to stop cleanly before SIGKILL, on every stop path?
# Validator (compose container postfiatd) or sentry (`docker run` container postfiatd-sentry), Ubuntu 22.04,
# Docker 29 with live-restore. postfiatd is PID 1 in its container (the image entrypoint `exec`s it), so the
# container's stop signal reaches it directly.
#
# Usage: pft-shutdown audit [--json] [--required SEC]
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
#      Test hooks: PFT_SHUTDOWN_ROOT (path prefix for files)  PFT_SHUTDOWN_DOCKER / _SYSTEMCTL (commands)

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_SHUTDOWN_ROOT:-}"
DOCKER="${PFT_SHUTDOWN_DOCKER:-docker}"
SYSTEMCTL="${PFT_SHUTDOWN_SYSTEMCTL:-systemctl}"
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
  sed -n '/^# Usage:/,/^#  audit/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
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
  *) usage ;;
esac
