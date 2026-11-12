#!/usr/bin/env bash
# pft-selfheal: guarded auto-remediation for a Post Fiat validator or sentry container.
# Once a minute (pft-selfheal@NAME.timer) it observes the node, lets selfheal_decide.py pick at most one action and,
# in enforce mode, runs it. Actions are limited to starting the container (compose `up -d --no-recreate` for compose
# containers, `docker start` for `docker run` ones) and `docker restart`; nothing is ever exec'd for remediation and
# no key/token file is read. Every action is followed by `pft-egress reapply --container NAME`.
#
# Usage: sudo pft-selfheal run [--container NAME] [--dry-run] [--textfile-dir DIR] [--stdout]
#        sudo pft-selfheal status [--container NAME] [--json]    exit 0 healthy, 1 suppressed/would act,
#                                                                2 breaker open, 4 no or stale decision
#        sudo pft-selfheal reset [--container NAME] --reason "text"   close the circuit breaker (manual reset)
#        pft-selfheal version
#
#  run     observation: `docker inspect` (exists, running, StartedAt), `docker exec NAME curl ... server_info` on the
#          container's loopback admin port (the shape pft-statewatch and pft-peerwatch use, curl is the exec'd
#          binary), `pft-maint active` and `pft-maint lock list`, and - only when the local sample looks stalled
#          (validated seq unchanged since the last sample or server_state not full/proposing/validating) - one
#          server_info against REF_URL as the network-stall reference. The decision is appended to
#          STATE_DIR/journal-NAME.jsonl when it is not "healthy", together with every action and its result.
#  Guards (selfheal_decide.py): breaker, maintenance window, data lock, startup grace, network stall, backoff,
#          K actions per 24 h (the next needed action opens the breaker; only `reset` closes it).
#
# Exit codes: run 0 decided (healthy, suppressed or acted ok), 1 action failed, 3 usage/config error,
#             5 state unreadable/unwritable (refuses to act); status as above; reset 0 ok, 3 usage, 5 state.
# Conf: PFT_SH_CONF (/etc/pft-selfheal.env, root-owned; sourced for the shell keys, read as KEY=VALUE text by
#       selfheal_decide.py for MODE and the thresholds): CONTAINER (postfiatd), TEXTFILE_DIR
#       (/var/lib/pft-exporter/textfile), STATE_DIR (/var/lib/pft-selfheal), RPC_TIMEOUT (8),
#       REF_URL (https://rpc.testnet.postfiat.org), REF_TIMEOUT (10), RESTART_TIMEOUT (60), STALE_DECISION_SEC (300)
# Test hooks: PFT_SH_DOCKER (docker)  PFT_SH_CURL (curl)  PFT_SH_MAINT (pft-maint)  PFT_SH_EGRESS (pft-egress)
#             PFT_SH_NOW (epoch)  PFT_SH_TEST=1 (conf may be owned by the caller)  PFT_SH_DECIDER (/usr/local/lib/pft-selfheal/selfheal_decide.py)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_SH_CONF:-/etc/pft-selfheal.env}"
CONF_OWNER=0; [ "${PFT_SH_TEST:-}" = 1 ] && CONF_OWNER="$(id -u)"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = "$CONF_OWNER" ] && . "$CONF"
CONTAINER="${CONTAINER:-postfiatd}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-selfheal}"
RPC_TIMEOUT="${RPC_TIMEOUT:-8}"
REF_URL="${REF_URL:-https://rpc.testnet.postfiat.org}"
REF_TIMEOUT="${REF_TIMEOUT:-10}"
RESTART_TIMEOUT="${RESTART_TIMEOUT:-60}"
STALE_DECISION_SEC="${STALE_DECISION_SEC:-300}"
DECIDER="${PFT_SH_DECIDER:-/usr/local/lib/pft-selfheal/selfheal_decide.py}"
read -r -a DOCKER <<< "${PFT_SH_DOCKER:-docker}"
read -r -a CURL <<< "${PFT_SH_CURL:-curl}"
read -r -a MAINT <<< "${PFT_SH_MAINT:-pft-maint}"
read -r -a EGRESS <<< "${PFT_SH_EGRESS:-pft-egress}"

die() { printf 'pft-selfheal: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }
conf_arg() { if [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = "$CONF_OWNER" ]; then printf '%s' "$CONF"; fi; }
now() { printf '%s' "${PFT_SH_NOW:-$(date +%s)}"; }

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

# journal JSON: one append-only line per non-healthy decision, action, action result and reset
journal() { printf '%s\n' "$1" >> "$STATE_DIR/journal-$CONTAINER.jsonl"; }

# container_obs -> JSON {exists, running, started_at}
container_obs() {
  local out started
  if ! out="$(timeout 20 "${DOCKER[@]}" inspect -f '{{.State.Running}} {{.State.StartedAt}}' "$CONTAINER" 2>/dev/null)"; then
    printf '{"exists":false,"running":false,"started_at":null}'; return 0
  fi
  local r=false
  started="$(date -d "${out#* }" +%s 2>/dev/null)" || started=null
  [ "${out%% *}" = true ] && r=true
  printf '{"exists":true,"running":%s,"started_at":%s}' "$r" "$started"
}

# rpc_obs -> JSON {ok, server_state, validated_seq, peers}; never fails, a bad answer is ok:false
rpc_obs() {
  local ans
  ans="$(timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" curl -s --max-time "$RPC_TIMEOUT" \
    -H 'Content-Type: application/json' -d '{"method":"server_info","params":[{}]}' http://127.0.0.1:5005/ 2>/dev/null)"
  local o
  # jq -e exits 0 on empty input: an empty answer must still be ok:false, so test the output, not only the rc
  o="$(jq -ce '.result | select(.status == "success") | .info
    | {ok: true, server_state: (.server_state | strings),
       validated_seq: (.validated_ledger.seq // 0 | numbers), peers: (.peers | numbers)}' <<< "$ans" 2>/dev/null)"
  if [ -n "$o" ] && [ "${o:0:1}" = "{" ]; then printf '%s' "$o"
  else printf '{"ok":false,"server_state":null,"validated_seq":null,"peers":null}'
  fi
}

# ref_seq -> validated seq of the reference node, or empty
ref_seq() {
  local ans seq
  ans="$(timeout "$((REF_TIMEOUT + 5))" "${CURL[@]}" -s --max-time "$REF_TIMEOUT" -X POST \
    -H 'Content-Type: application/json' -d '{"method":"server_info","params":[{}]}' "$REF_URL" 2>/dev/null)"
  seq="$(jq -e '.result.info.validated_ledger.seq | numbers' <<< "$ans" 2>/dev/null)"
  [[ "$seq" =~ ^[0-9]+$ ]] && printf '%s' "$seq"
}

# act ACTION -> rc of the remediation command (egress reapply is reported but does not change the rc)
act() {
  local labels files project service svc_dir f rc erc
  local -a argv list
  if [ "$1" = restart ]; then
    argv=("${DOCKER[@]}" restart -t "$RESTART_TIMEOUT" "$CONTAINER")
  else
    labels="$(timeout 20 "${DOCKER[@]}" inspect -f '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$CONTAINER" 2>/dev/null)" \
      || labels=""
    if [ -z "$labels" ] && [ -s "$STATE_DIR/compose-$CONTAINER" ]; then labels="$(cat "$STATE_DIR/compose-$CONTAINER")"; fi
    IFS='|' read -r project service files svc_dir <<< "$labels"
    if [ -n "$project" ] && [ -n "$service" ] && [ -n "$files" ]; then
      argv=("${DOCKER[@]}" compose --project-name "$project" --project-directory "$svc_dir")
      IFS=',' read -r -a list <<< "$files"
      for f in "${list[@]}"; do argv+=(-f "$f"); done
      argv+=(up -d --no-recreate "$service")
    else
      argv=("${DOCKER[@]}" start "$CONTAINER")
    fi
  fi
  journal "$(jq -cn --argjson ts "$(now)" --arg a "$1" --arg c "${argv[*]}" '{ts:$ts, event:"action", action:$a, cmd:$c}')"
  timeout "$((RESTART_TIMEOUT + 120))" "${argv[@]}" </dev/null >"$STATE_DIR/.act.out" 2>&1; rc=$?
  if [ -n "${EGRESS[0]}" ]; then
    timeout 120 "${EGRESS[@]}" reapply --container "$CONTAINER" </dev/null >>"$STATE_DIR/.act.out" 2>&1; erc=$?
  else erc=-1
  fi
  journal "$(jq -cn --argjson ts "$(now)" --arg a "$1" --argjson rc "$rc" --argjson erc "$erc" \
    --arg out "$(tail -c 300 "$STATE_DIR/.act.out")" '{ts:$ts, event:"result", action:$a, rc:$rc, egress_rc:$erc, out:$out}')"
  return "$rc"
}

metrics() { # DECISION_JSON UP -> textfile body
  local d="$1" L="container=\"$CONTAINER\"" v total
  total=0
  if [ -f "$STATE_DIR/journal-$CONTAINER.jsonl" ]; then
    total="$(jq -c 'select(.event == "action")' "$STATE_DIR/journal-$CONTAINER.jsonl" 2>/dev/null | wc -l)"
  fi
  printf '# HELP pft_selfheal_up 1 if the last run observed, decided and saved state\n# TYPE pft_selfheal_up gauge\n'
  printf 'pft_selfheal_up{%s} %s\n' "$L" "$2"
  printf '# HELP pft_selfheal_run_timestamp_seconds Unix time of the last run\n# TYPE pft_selfheal_run_timestamp_seconds gauge\n'
  printf 'pft_selfheal_run_timestamp_seconds{%s} %s\n' "$L" "$(now)"
  [ "$2" = 1 ] || return 0
  printf '# HELP pft_selfheal_enforce 1 in enforce mode, 0 in dry-run\n# TYPE pft_selfheal_enforce gauge\n'
  printf 'pft_selfheal_enforce{%s} %s\n' "$L" "$(jq -r 'if .mode == "enforce" then 1 else 0 end' <<< "$d")"
  printf '# HELP pft_selfheal_verdict 1 for the verdict of the last run\n# TYPE pft_selfheal_verdict gauge\n'
  for v in healthy suppressed would_act act; do
    printf 'pft_selfheal_verdict{%s,verdict="%s"} %s\n' "$L" "$v" "$(jq -r --arg v "$v" 'if .verdict == $v then 1 else 0 end' <<< "$d")"
  done
  printf '# HELP pft_selfheal_detector 1 if this detector matched in the last run\n# TYPE pft_selfheal_detector gauge\n'
  for v in container_down rpc_failures stale_ledger stuck_state zero_peers; do
    printf 'pft_selfheal_detector{%s,detector="%s"} %s\n' "$L" "$v" "$(jq -r --arg v "$v" 'if .detector == $v then 1 else 0 end' <<< "$d")"
  done
  printf '# HELP pft_selfheal_actions_24h Remediation actions in the last 24 h\n# TYPE pft_selfheal_actions_24h gauge\n'
  printf 'pft_selfheal_actions_24h{%s} %s\n' "$L" "$(jq -r .actions_24h <<< "$d")"
  printf '# HELP pft_selfheal_max_actions K, the 24 h action budget\n# TYPE pft_selfheal_max_actions gauge\n'
  printf 'pft_selfheal_max_actions{%s} %s\n' "$L" "$(jq -r .max_actions <<< "$d")"
  printf '# HELP pft_selfheal_actions_total Remediation actions in the journal\n# TYPE pft_selfheal_actions_total counter\n'
  printf 'pft_selfheal_actions_total{%s} %s\n' "$L" "$total"
  printf '# HELP pft_selfheal_breaker_open 1 while the circuit breaker is open (manual reset needed)\n# TYPE pft_selfheal_breaker_open gauge\n'
  printf 'pft_selfheal_breaker_open{%s} %s\n' "$L" "$(jq -r 'if .breaker_open then 1 else 0 end' <<< "$d")"
}

run() {
  local stdout=0 dry=0 c r maint locks lrc ref ref_ok last_seq obs d rc=0 arc rec verdict up=1 err=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --dry-run) dry=1 ;;
      --stdout) stdout=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_name "$CONTAINER" || die "bad container name"
  [[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad RPC_TIMEOUT"
  [[ "$REF_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad REF_TIMEOUT"
  [[ "$RESTART_TIMEOUT" =~ ^[1-9][0-9]{0,2}$ ]] || die "bad RESTART_TIMEOUT"
  [ -r "$DECIDER" ] || die "decider not found: $DECIDER"
  [ -d "$STATE_DIR" ] || die "state dir missing: $STATE_DIR"
  exec 8>"$STATE_DIR/.lock-$CONTAINER"
  flock -n 8 || die "another run for $CONTAINER is in progress" 3

  c="$(container_obs)"
  if [ "$(jq -r .running <<< "$c")" = true ]; then
    r="$(rpc_obs)"
    # cache the compose identity while the container exists, `up` needs it if the container is later removed
    timeout 20 "${DOCKER[@]}" inspect -f '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$CONTAINER" \
      2>/dev/null | command grep -v '^|||$' > "$STATE_DIR/.compose.tmp" && mv -f "$STATE_DIR/.compose.tmp" "$STATE_DIR/compose-$CONTAINER"
    rm -f "$STATE_DIR/.compose.tmp"
  else
    r='{"ok":false,"server_state":null,"validated_seq":null,"peers":null}'
  fi
  if timeout 20 "${MAINT[@]}" active >/dev/null 2>&1; then maint=true; else maint=false; fi
  locks="$(timeout 20 "${MAINT[@]}" lock list 2>/dev/null)"; lrc=$?
  if [ "$lrc" != 0 ]; then locks='["lock state unreadable"]'   # fail safe: an unreadable lock state is a lock
  else locks="$(command grep -v '^no data-collection locks$' <<< "$locks" | jq -Rsc 'split("\n") | map(select(length > 0))')"
  fi
  ref=null ref_ok=false
  last_seq="$(jq -r '.last_seq // empty' "$STATE_DIR/state-$CONTAINER.json" 2>/dev/null)"
  if jq -e --arg l "$last_seq" '.ok and ((.validated_seq | tostring) == $l
      or (.server_state | IN("full", "proposing", "validating") | not))' <<< "$r" >/dev/null 2>&1; then
    if ref="$(ref_seq)"; then ref_ok=true; else ref=null; fi
  fi
  obs="$(jq -cn --argjson now "$(now)" --argjson c "$c" --argjson r "$r" --argjson m "$maint" --argjson l "$locks" \
    --argjson ref "$ref" --argjson rok "$ref_ok" \
    '{now:$now, container:$c, rpc:$r, guards:{maint_active:$m, locks:$l, reference_seq:$ref, reference_ok:$rok}}')" \
    || die "cannot build observation" 1
  if [ "$dry" = 1 ]; then
    d="$(SELFHEAL_FORCE_DRYRUN=1 python3 -I "$DECIDER" decide "$STATE_DIR/state-$CONTAINER.json" "$(conf_arg)" <<< "$obs")"; rc=$?
  else
    d="$(python3 -I "$DECIDER" decide "$STATE_DIR/state-$CONTAINER.json" "$(conf_arg)" <<< "$obs")"; rc=$?
  fi
  if [ "$rc" != 0 ]; then
    up=0 err="decider exit $rc"
  else
    verdict="$(jq -r .verdict <<< "$d")"
    d="$(jq -c --argjson o "$obs" '. + {observation: $o}' <<< "$d")"
    write_atomic "$STATE_DIR" "last-$CONTAINER.json" "$d"$'\n' || { up=0; err="cannot write last decision"; }
    [ "$verdict" = healthy ] || journal "$(jq -c '. + {event: "decision"}' <<< "$d")"
    if [ "$verdict" = act ]; then
      act "$(jq -r .action <<< "$d")"; arc=$?
      if rec="$(PFT_SH_NOW="$(now)" python3 -I "$DECIDER" record "$STATE_DIR/state-$CONTAINER.json" \
          "$(jq -r .action <<< "$d")" "$arc")"; then
        d="$(jq -c --argjson rc "$arc" --argjson r "$rec" '. + {action_rc: $rc, actions_24h: $r.actions_24h}' <<< "$d")"
      else
        up=0 err="cannot record action"
      fi
      write_atomic "$STATE_DIR" "last-$CONTAINER.json" "$d"$'\n' || { up=0; err="cannot write last decision"; }
      [ "$arc" = 0 ] || { err="action exit $arc"; rc=1; }
    fi
  fi
  if [ "$stdout" = 1 ]; then metrics "$d" "$up"
  else write_atomic "$TEXTFILE_DIR" "pft_selfheal_$CONTAINER.prom" "$(metrics "$d" "$up")"$'\n' || die "cannot write $TEXTFILE_DIR" 1
  fi
  [ -n "$d" ] && [ "$up" = 1 ] && printf '%s\n' "$(jq -c 'del(.observation)' <<< "$d")" >&2
  if [ -n "$err" ]; then
    printf 'pft-selfheal: %s\n' "$err" >&2
    [ "$rc" = 0 ] && rc=5   # decider rc (3 config, 5 state) and action failure (1) are kept as they are
  fi
  return "$rc"
}

status() {
  local json=0 d age
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --json) json=1 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_name "$CONTAINER" || die "bad container name"
  if ! d="$(cat "$STATE_DIR/last-$CONTAINER.json" 2>/dev/null)" || ! jq -e .ts <<< "$d" >/dev/null 2>&1; then
    echo "pft-selfheal $CONTAINER: no decision recorded"; return 4
  fi
  age=$(( $(now) - $(jq -r .ts <<< "$d") ))
  if [ "$json" = 1 ]; then jq -c --argjson age "$age" 'del(.observation) + {age_sec: $age}' <<< "$d"
  else
    jq -r --argjson age "$age" '"pft-selfheal \(.observation.container // {} | if .exists then "" else "(container missing) " end)mode \(.mode) | verdict \(.verdict)"
      + (if .detector then " | detector \(.detector) (\(.detail)) action \(.action)" else "" end)
      + (if .suppressed_by then " | suppressed by \(.suppressed_by)" else "" end)
      + " | actions_24h \(.actions_24h)/\(.max_actions) | breaker \(if .breaker_open then "OPEN: \(.breaker_reason)" else "closed" end)"
      + " | \($age)s ago"' <<< "$d"
  fi
  if [ "$age" -gt "$STALE_DECISION_SEC" ]; then echo "pft-selfheal $CONTAINER: STALE (${age}s old)"; return 4; fi
  if jq -e .breaker_open <<< "$d" >/dev/null; then return 2; fi
  case "$(jq -r .verdict <<< "$d")" in healthy|act) return 0 ;; *) return 1 ;; esac
}

reset() {
  local reason="" out
  while [ $# -gt 0 ]; do
    case "$1" in
      --container) CONTAINER="${2:?}"; shift ;;
      --reason) reason="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_name "$CONTAINER" || die "bad container name"
  [ -n "$reason" ] || die "reset needs --reason"
  [ -r "$DECIDER" ] || die "decider not found: $DECIDER"
  exec 8>"$STATE_DIR/.lock-$CONTAINER"
  flock -w 120 8 || die "another run for $CONTAINER is in progress" 3
  out="$(PFT_SH_NOW="$(now)" python3 -I "$DECIDER" reset "$STATE_DIR/state-$CONTAINER.json" "$reason")" || die "reset failed" 5
  journal "$(jq -c '. + {event: "reset"}' <<< "$out")"
  printf '%s\n' "$out"
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  run) run "$@" ;;
  status) status "$@" ;;
  reset) reset "$@" ;;
  version) echo "pft-selfheal $VERSION" ;;
  *) sed -n '8,12p' "$0" >&2; exit 3 ;;
esac
