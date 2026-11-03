#!/usr/bin/env bash
# pft-backfill: find ledger-history gaps inside a postfiatd node's [node_db] online_delete window and (opt-in, capped)
# ask the node to re-acquire them with loopback ledger_request. Dockerized postfiatd 1.0.9 on Ubuntu 22.04; the same
# script runs on the validator and the sentry. Gap accounting lives in backfill_parse.py (stdlib only).
#
# Usage: pft-backfill status [--json] [--textfile | --prom FILE]   read-only
#        pft-backfill plan [--max-ledgers N]                      read-only: the sequences a repair would request
#        pft-backfill repair [--apply] [--max-ledgers N] [--interval S] [--wait S] [--max-runtime S] [--textfile]
#          dry run unless --apply. Caps (hard limits): ledgers 16 (256), interval 2 s (1-60), per-ledger arrival
#          wait 90 s (600), runtime 600 s (1800); ledger_request is re-sent at most every 5 polls. Refuses (exit 4)
#          when the node is not full, a pft-maint window is open (or pft-maint cannot say), or another repair runs.
#          Each arrived ledger is checked: hash from the validated chain (ledger_request), parent link to the
#          held neighbours (seq-1 / seq+1, at least one required), and the public RPC when it holds the ledger.
#        pft-backfill validate FILE NODE   check a status textfile the way pull checks a pulled one
#        pft-backfill pull     (validator, root) copy the peer's pft_backfill*.prom over PULL_SSH and validate them
#
# Reads: server_info through `docker exec CONTAINER curl` to the container's own loopback admin port (the host-mapped
# port answers admin calls with "Forbidden"), and postfiatd.cfg through the config volume's HOST path (docker inspect
# Mounts[].Source): no shell and no file read inside the container, so an AppArmor profile on the node needs no
# extra rule for this tool.
# Exit codes: 0 no gap inside the window (repair: every planned ledger fetched + verified), 1 gaps found / node
# not full (repair: some ledgers timed out or were skipped by the runtime cap), 2 error or hash MISMATCH, 3 usage,
# 4 repair refused.
# jq programs are single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
umask 022

R="${PFT_BACKFILL_ROOT:-}"
DOCKER="${PFT_BACKFILL_DOCKER:-docker}"
PYTHON="${PFT_BACKFILL_PYTHON:-python3}"
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PARSER="${PFT_BACKFILL_PARSER:-$HERE/backfill_parse.py}" # repo checkout; installed: /usr/local/lib/pft-backfill
[ -f "$PARSER" ] || PARSER=/usr/local/lib/pft-backfill/backfill_parse.py
CONF="${PFT_BACKFILL_CONF:-$R/etc/pft-backfill.env}"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
conf_get() { [ -f "$CONF" ] && sed -n "s/^$1=//p" "$CONF" | tail -1 | sed -E 's/^"(.*)"$/\1/'; return 0; }
CONTAINER="$(conf_get CONTAINER)"; CONTAINER="${CONTAINER:-postfiatd}"
HOST_LABEL="$(conf_get HOST_LABEL)"; HOST_LABEL="${HOST_LABEL:-validator}"
ADMIN_PORT="$(conf_get ADMIN_PORT)"; ADMIN_PORT="${ADMIN_PORT:-5005}"
PUBLIC_RPC="$(conf_get PUBLIC_RPC)"; PUBLIC_RPC="${PUBLIC_RPC:-https://rpc.testnet.postfiat.org/}" # "none" = off
MAINT="${PFT_BACKFILL_MAINT:-pft-maint}"
CURL="${PFT_BACKFILL_CURL:-curl}"
SLEEP="${PFT_BACKFILL_SLEEP:-sleep}"
NOWCMD="${PFT_BACKFILL_NOW:-}"
LOCK="${PFT_BACKFILL_LOCK:-$R/run/lock/pft-backfill.lock}"
PEER_LABEL="$(conf_get PEER_LABEL)"; PEER_LABEL="${PEER_LABEL:-sentry}"
PULL_SSH="$(conf_get PULL_SSH)"; PULL_TIMEOUT="${PULL_TIMEOUT:-30}"
CFG_DEST="${CFG_DEST:-/etc/postfiatd}"
RPC_TIMEOUT="${RPC_TIMEOUT:-5}"

die() { echo "pft-backfill: $*" >&2; exit "${2:-2}"; }
ts() { date -u +%FT%TZ; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
valid_container() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; }

WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; return 0; }
trap cleanup EXIT

RPC_ALLOW="server_info ledger ledger_request" # the only methods this tool ever sends to the node

rpc() { # METHOD [PARAMS_JSON] -> answer on stdout; rc 1 + message on stdout on failure (caller records it)
  local body err out params="${2:-}"
  [[ " $RPC_ALLOW " == *" $1 "* ]] || { echo "rpc $1: method not allowlisted"; return 1; }
  [ -n "$params" ] || params='{}'
  body="{\"method\":\"$1\",\"params\":[$params]}"
  err="$WORK/rpc.err"
  out="$("$DOCKER" exec "$CONTAINER" curl -s -m "$RPC_TIMEOUT" -d "$body" "http://127.0.0.1:$ADMIN_PORT/" 2>"$err")" \
    || { echo "rpc $1 failed: $(head -c 200 "$err")"; return 1; }
  [ -n "$out" ] || { echo "rpc $1: empty answer"; return 1; }
  jq -e '.result | type == "object"' >/dev/null 2>&1 <<<"$out" || { echo "rpc $1: not a JSON result"; return 1; }
  printf '%s\n' "$out"
}

cfg_path() { # host path of postfiatd.cfg (config volume source)
  local src
  src="$("$DOCKER" inspect -f '{{range .Mounts}}{{if eq .Destination "'"$CFG_DEST"'"}}{{.Source}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null)" \
    || { echo "docker inspect $CONTAINER failed"; return 1; }
  [ -n "$src" ] || { echo "no $CFG_DEST mount on $CONTAINER"; return 1; }
  [ -f "$R$src/postfiatd.cfg" ] || { echo "no postfiatd.cfg in the config volume"; return 1; }
  echo "$R$src/postfiatd.cfg"
}

collect() { # -> WORK/info.json WORK/cfg.txt ; rc 1 + message on stdout
  local m cfg
  m="$(rpc server_info)" || { echo "$m"; return 1; }
  printf '%s\n' "$m" > "$WORK/info.json"
  cfg="$(cfg_path)" || { echo "$cfg"; return 1; }
  # only the sections the parser reads: the file holds secrets ([node_seed], [validator_token]) that stay out of WORK
  awk '/^\[/{s=$0} (s=="[node_db]") && !/^[[:space:]]*#/ && NF' "$cfg" > "$WORK/cfg.txt" \
    || { echo "cannot read postfiatd.cfg"; return 1; }
}

write_prom() { # CONTENT DEST -> atomic replace
  local dest="$1" tmp
  tmp="$(mktemp "$dest.XXXXXX")" || return 1
  cat > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$dest"
}

down_prom() { # MESSAGE -> textfile lines for a failed run (up 0)
  printf '# HELP pft_backfill_up 1 if the status run read server_info and the node config.\n'
  printf '# TYPE pft_backfill_up gauge\npft_backfill_up{node="%s"} 0\n' "$HOST_LABEL"
  printf '# HELP pft_backfill_status_timestamp_seconds Unix time of the status run.\n'
  printf '# TYPE pft_backfill_status_timestamp_seconds gauge\npft_backfill_status_timestamp_seconds{node="%s"} %s\n' "$HOST_LABEL" "$(date +%s)"
}

cmd_status() {
  local json=0 prom="" msg sum rc
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=1 ;;
      --textfile) prom="$TEXTFILE_DIR/pft_backfill.prom" ;;
      --prom) [ $# -ge 2 ] || die "--prom needs a FILE" 3; prom="$2"; shift ;;
      *) die "status: unknown option $1" 3 ;;
    esac
    shift
  done
  if ! msg="$(collect)"; then
    [ -n "$prom" ] && { down_prom | write_prom "$prom" || die "cannot write $prom"; }
    die "$msg" 2
  fi
  sum="$("$PYTHON" "$PARSER" summary --info "$WORK/info.json" --cfg "$WORK/cfg.txt")" || die "parser failed (summary)"
  if [ -n "$prom" ]; then
    "$PYTHON" "$PARSER" status --info "$WORK/info.json" --cfg "$WORK/cfg.txt" --node "$HOST_LABEL" > "$WORK/prom" \
      || die "parser failed (status)"
    write_prom "$prom" < "$WORK/prom" || die "cannot write $prom"
  fi
  rc=0
  jq -e '(.server_state | IN("full","proposing","validating")) and .missing_interior == 0 and .missing_edge == 0' \
    >/dev/null <<<"$sum" || rc=1
  if [ "$json" = 1 ]; then
    jq -c --arg h "$HOST_LABEL" '{host: $h} + .' <<<"$sum"
  else
    echo "pft-backfill status - $(ts) | host $HOST_LABEL | container $CONTAINER"
    jq -r '
      "  server_state     \(.server_state)",
      "  validated        \(.validated)",
      "  online_delete    \(.online_delete // "unset (full history: nothing to account)")",
      "  complete_ledgers \(if (.ranges|length) == 0 then "empty" else ([.ranges[] | if .[0] == .[1] then "\(.[0])" else "\(.[0])-\(.[1])" end] | join(",")) end)",
      "  window           \(if .window then "\(.window[0])-\(.window[1])" else "-" end)",
      "  held in window   \(.held)",
      "  missing          interior \(.missing_interior), edge \(.missing_edge)",
      (.gaps[] | "  gap              \(.kind) \(.lo)-\(.hi) (\(.size))")' <<<"$sum"
    [ "$rc" = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
  fi
  return "$rc"
}

cmd_plan() {
  local max=256 msg
  while [ $# -gt 0 ]; do
    case "$1" in
      --max-ledgers) { [ $# -ge 2 ] && [[ "$2" =~ ^[0-9]+$ ]]; } || die "--max-ledgers needs a number" 3; max="$2"; shift ;;
      *) die "plan: unknown option $1" 3 ;;
    esac
    shift
  done
  msg="$(collect)" || die "$msg" 2
  "$PYTHON" "$PARSER" plan --info "$WORK/info.json" --cfg "$WORK/cfg.txt" --max-ledgers "$max" || die "parser failed (plan)"
}

now_s() { if [ -n "$NOWCMD" ]; then "$NOWCMD"; else date +%s; fi; }
is_hash() { [[ "$1" =~ ^[0-9A-F]{64}$ ]]; }

maint_check() { # rc 0 only when pft-maint positively reports no window; else message on stdout + rc 1 (fail closed)
  local j w
  command -v "$MAINT" >/dev/null 2>&1 || { echo "pft-maint not installed: cannot prove that no maintenance window is open"; return 1; }
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "pft-maint status --json failed"; return 1; }
  w="$(jq -er '.window | strings' <<<"$j" 2>/dev/null)" || { echo "pft-maint status: no window field"; return 1; }
  [ "$w" = none ] || { echo "pft-maint window is open (window=$w)"; return 1; }
}

local_ledger() { # SEQ -> "HASH PARENT_HASH" (rc 0) | not servable (rc 1) | message (rc 2, RPC failure)
  local a
  a="$(rpc ledger "{\"ledger_index\":$1}")" || { echo "$a"; return 2; }
  a="$(jq -er --arg s "$1" '.result | select(.status == "success" and (.ledger.ledger_index | tostring) == $s)
        | .ledger | "\(.ledger_hash) \(.parent_hash)"' <<<"$a" 2>/dev/null)" || return 1
  is_hash "${a% *}" && is_hash "${a#* }" || return 1
  echo "$a"
}

public_hash() { # SEQ -> HASH (rc 0) | not available after 3 tries (rc 1); every failed try is printed on stderr
  local a h i
  for i in 1 2 3; do
    a="$("$CURL" -s -m 20 -H 'Content-Type: application/json' \
      -d "{\"method\":\"ledger\",\"params\":[{\"ledger_index\":$1}]}" "$PUBLIC_RPC" 2>/dev/null)"
    h="$(jq -er '.result.ledger.ledger_hash | strings' <<<"$a" 2>/dev/null)" && is_hash "$h" && { echo "$h"; return 0; }
    h="$(jq -r '.result.error // empty' <<<"$a" 2>/dev/null)"
    echo "    public rpc try $i/3 for $1: ${h:-no answer}" >&2
    [ "$i" -lt 3 ] && "$SLEEP" $((i * 2))
  done
  return 1
}

repair_prom() { # DRY RC -> textfile lines (counts from the C_* globals)
  local lab="node=\"$HOST_LABEL\"" k
  printf '# HELP pft_backfill_repair_ledgers Ledgers in the last repair run, by result.\n# TYPE pft_backfill_repair_ledgers gauge\n'
  for k in planned fetched verified failed timeout skipped; do
    printf 'pft_backfill_repair_ledgers{%s,result="%s"} %s\n' "$lab" "$k" "$(eval "echo \$C_$k")"
  done
  printf '# HELP pft_backfill_repair_dry_run 1 if the last repair run was a dry run.\n# TYPE pft_backfill_repair_dry_run gauge\n'
  printf 'pft_backfill_repair_dry_run{%s} %s\n' "$lab" "$1"
  printf '# HELP pft_backfill_repair_exit_code Exit code of the last repair run.\n# TYPE pft_backfill_repair_exit_code gauge\n'
  printf 'pft_backfill_repair_exit_code{%s} %s\n' "$lab" "$2"
  printf '# HELP pft_backfill_repair_timestamp_seconds Unix time the last repair run ended.\n# TYPE pft_backfill_repair_timestamp_seconds gauge\n'
  printf 'pft_backfill_repair_timestamp_seconds{%s} %s\n' "$lab" "$(now_s)"
}

repair_one() { # SEQ -> sets R_RESULT (fetched|timeout|skipped|failed) R_HASH R_PARENT R_EXPECT R_WHY; uses RUN_END
  local s="$1" a e err polls=0 l rc start
  R_RESULT=""; R_HASH=""; R_PARENT=""; R_EXPECT=""; R_WHY=""
  start="$(now_s)"
  while :; do
    if [ $((polls % 5)) = 0 ]; then
      if a="$(rpc ledger_request "{\"ledger_index\":$s}")"; then
        C_requests=$((C_requests + 1))
        err="$(jq -r '.result.error // empty' <<<"$a")"
        case "$err" in
          ""|lgrNotFound|notReady) ;;
          *) R_RESULT=failed; R_WHY="ledger_request: $err $(jq -r '.result.error_message // empty' <<<"$a")"; return ;;
        esac
        # the ledger itself, or the inbound acquisition of exactly this ledger (hash taken from the validated
        # chain); an lgrNotFound "acquiring" answer names the REFERENCE ledger's hash, so it is not used
        e="$(jq -r 'if .result.error then empty else (.result.ledger.ledger_hash // .result.hash // empty) end' <<<"$a")"
        if [ -n "$e" ]; then
          is_hash "$e" || { R_RESULT=failed; R_WHY="ledger_request: malformed hash"; return; }
          if [ -n "$R_EXPECT" ] && [ "$e" != "$R_EXPECT" ]; then
            R_RESULT=failed; R_WHY="ledger_request hash changed $R_EXPECT -> $e"; return
          fi
          R_EXPECT="$e"
        fi
      else
        R_RESULT=failed; R_WHY="$a"; return
      fi
    fi
    l="$(local_ledger "$s")"; rc=$?
    [ "$rc" = 2 ] && { R_RESULT=failed; R_WHY="$l"; return; }
    if [ "$rc" = 0 ]; then
      R_RESULT=fetched; R_HASH="${l% *}"; R_PARENT="${l#* }"; R_WHY="arrived after $(($(now_s) - start)) s"; return
    fi
    [ "$(now_s)" -ge "$RUN_END" ] && { R_RESULT=skipped; R_WHY="runtime cap reached while waiting"; return; }
    [ $(($(now_s) - start)) -ge "$WAIT" ] && { R_RESULT=timeout; R_WHY="not servable after ${WAIT} s"; return; }
    "$SLEEP" "$INTERVAL"
    polls=$((polls + 1))
  done
}

verify_one() { # SEQ (after repair_one fetched) -> rc 0 verified, 1 not verifiable, 2 mismatch; prints the checks
  local s="$1" v l links=0 bad=0 chain prev next pub
  if [ -z "$R_EXPECT" ]; then chain="n/a"
  elif [ "$R_EXPECT" = "$R_HASH" ]; then chain=ok
  else chain="MISMATCH(chain $R_EXPECT)"; bad=$((bad + 1)); fi
  l="$(local_ledger $((s - 1)))"; v=$?
  if [ "$v" = 0 ]; then
    if [ "${l% *}" = "$R_PARENT" ]; then prev=ok; links=$((links + 1)); else prev="MISMATCH(seq-1 is ${l% *})"; bad=$((bad + 1)); fi
  else prev="n/a"; fi
  l="$(local_ledger $((s + 1)))"; v=$?
  if [ "$v" = 0 ]; then
    if [ "${l#* }" = "$R_HASH" ]; then next=ok; links=$((links + 1)); else next="MISMATCH(seq+1 parent ${l#* })"; bad=$((bad + 1)); fi
  else next="n/a"; fi
  if [ "$PUBLIC_RPC" = none ]; then pub="off"
  elif l="$(public_hash "$s")"; then
    if [ "$l" = "$R_HASH" ]; then pub=ok; else pub="MISMATCH(public $l)"; bad=$((bad + 1)); fi
  else pub="n/a"; fi
  echo "    hash $R_HASH chain $chain prev $prev next $next public $pub"
  [ "$bad" -gt 0 ] && return 2
  [ "$chain" = ok ] && [ "$links" -ge 1 ] && return 0
  return 1
}

cmd_repair() {
  local apply=0 max=16 prom="" msg sum before after plan s rc=0 vr
  INTERVAL=2; WAIT=90; local runtime=600
  num() { { [ $# -ge 2 ] && [[ "$2" =~ ^[0-9]+$ ]]; } || die "$1 needs a number" 3; }
  while [ $# -gt 0 ]; do
    case "$1" in
      --apply) apply=1 ;;
      --max-ledgers) num "$@"; max="$2"; shift ;;
      --interval) num "$@"; INTERVAL="$2"; shift ;;
      --wait) num "$@"; WAIT="$2"; shift ;;
      --max-runtime) num "$@"; runtime="$2"; shift ;;
      --textfile) prom="$TEXTFILE_DIR/pft_backfill_repair.prom" ;;
      *) die "repair: unknown option $1" 3 ;;
    esac
    shift
  done
  { [ "$max" -ge 1 ] && [ "$max" -le 256 ]; } || die "--max-ledgers must be 1..256" 3
  { [ "$INTERVAL" -ge 1 ] && [ "$INTERVAL" -le 60 ]; } || die "--interval must be 1..60 s" 3
  { [ "$WAIT" -ge 1 ] && [ "$WAIT" -le 600 ]; } || die "--wait must be 1..600 s" 3
  { [ "$runtime" -ge 1 ] && [ "$runtime" -le 1800 ]; } || die "--max-runtime must be 1..1800 s" 3
  C_planned=0; C_fetched=0; C_verified=0; C_failed=0; C_timeout=0; C_skipped=0; C_requests=0
  mkdir -p "$(dirname "$LOCK")" 2>/dev/null
  exec 9>>"$LOCK" || die "cannot open lock $LOCK"
  flock -n 9 || die "another pft-backfill repair is running" 4
  echo "pft-backfill repair - $(ts) | host $HOST_LABEL | container $CONTAINER | $([ "$apply" = 1 ] && echo APPLY || echo DRY RUN)"
  echo "  caps: max-ledgers $max, interval ${INTERVAL} s, wait ${WAIT} s, max-runtime ${runtime} s, public rpc $([ "$PUBLIC_RPC" = none ] && echo off || echo on)"
  msg="$(collect)" || die "$msg" 2
  sum="$("$PYTHON" "$PARSER" summary --info "$WORK/info.json" --cfg "$WORK/cfg.txt")" || die "parser failed (summary)"
  before="$(jq -r '.ranges | if length == 0 then "empty" else [.[] | if .[0] == .[1] then "\(.[0])" else "\(.[0])-\(.[1])" end] | join(",") end' <<<"$sum")"
  echo "  before: complete_ledgers $before | window $(jq -r 'if .window then "\(.window[0])-\(.window[1])" else "-" end' <<<"$sum") | missing interior $(jq -r .missing_interior <<<"$sum"), edge $(jq -r .missing_edge <<<"$sum")"
  jq -e '.server_state | IN("full","proposing","validating")' >/dev/null <<<"$sum" \
    || die "refused: server_state is $(jq -r .server_state <<<"$sum") (repair needs a full node)" 4
  msg="$(maint_check)" || die "refused: $msg" 4
  plan="$("$PYTHON" "$PARSER" plan --info "$WORK/info.json" --cfg "$WORK/cfg.txt" --max-ledgers "$max")" \
    || die "parser failed (plan)"
  C_planned="$(grep -c . <<<"$plan")"
  echo "  plan: $C_planned ledger(s), newest first: $(tr '\n' ' ' <<<"$plan")"
  if [ "$apply" = 0 ] || [ "$C_planned" = 0 ]; then
    [ "$apply" = 0 ] && echo "RESULT: DRY RUN - nothing requested (add --apply)" || echo "RESULT: PASS - nothing to repair"
    [ -n "$prom" ] && { repair_prom "$((1 - apply))" 0 | write_prom "$prom" || die "cannot write $prom"; }
    return 0
  fi
  RUN_END=$(($(now_s) + runtime))
  for s in $plan; do
    if [ "$(now_s)" -ge "$RUN_END" ]; then
      C_skipped=$((C_skipped + 1)); echo "  seq $s skipped: runtime cap"; continue
    fi
    repair_one "$s"
    echo "  seq $s $R_RESULT: $R_WHY"
    case "$R_RESULT" in
      fetched)
        C_fetched=$((C_fetched + 1))
        verify_one "$s"; vr=$?
        case "$vr" in
          0) C_verified=$((C_verified + 1)); echo "    -> VERIFIED" ;;
          1) echo "    -> UNVERIFIED (no validated-chain hash or no held neighbour to link to)" ;;
          *) C_failed=$((C_failed + 1)); echo "    -> MISMATCH" ;;
        esac ;;
      timeout) C_timeout=$((C_timeout + 1)) ;;
      skipped) C_skipped=$((C_skipped + 1)) ;;
      *) C_failed=$((C_failed + 1)) ;;
    esac
    "$SLEEP" "$INTERVAL"
  done
  if msg="$(collect)"; then
    after="$("$PYTHON" "$PARSER" summary --info "$WORK/info.json" --cfg "$WORK/cfg.txt")" || after=""
  else after=""; fi
  if [ -n "$after" ]; then
    echo "  after:  complete_ledgers $(jq -r '.ranges | if length == 0 then "empty" else [.[] | if .[0] == .[1] then "\(.[0])" else "\(.[0])-\(.[1])" end] | join(",") end' <<<"$after") | missing interior $(jq -r .missing_interior <<<"$after"), edge $(jq -r .missing_edge <<<"$after")"
  else
    echo "  after:  status re-read failed: $msg"
  fi
  echo "  counts: planned $C_planned fetched $C_fetched verified $C_verified failed $C_failed timeout $C_timeout skipped $C_skipped (ledger_request calls $C_requests)"
  if [ "$C_failed" -gt 0 ]; then rc=2; echo "RESULT: FAIL - $C_failed ledger(s) failed or MISMATCHED"
  elif [ "$C_verified" = "$C_planned" ]; then rc=0; echo "RESULT: PASS - every planned ledger fetched and verified"
  else rc=1; echo "RESULT: INCOMPLETE - $((C_planned - C_verified)) ledger(s) not fetched+verified"; fi
  [ -n "$prom" ] && { repair_prom 0 "$rc" | write_prom "$prom" || echo "pft-backfill: cannot write $prom" >&2; }
  return "$rc"
}

validate_prom() { # FILE NODE TS_METRIC -> rc 0, or rc 1 with the first reason on stdout (a pulled file must look like ours)
  local f="$1" n
  [ -f "$f" ] || { echo "missing"; return 1; }
  [ "$(stat -c %s "$f")" -le 65536 ] || { echo "larger than 65536 bytes"; return 1; }
  n="$(grep -cvE '^(# (HELP|TYPE) pft_backfill_.*|pft_backfill_[a-z_]+\{node="'"$2"'"(,[a-z]+="[A-Za-z0-9_.:-]+")*\} [0-9.e+-]+)$' "$f")"
  [ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }
  grep -qE '^'"$3"'\{node="'"$2"'"\} [0-9]+$' "$f" || { echo "no $3 sample"; return 1; }
}

cmd_pull() { # status file required; repair file only if the peer has one (remote exit 1 = absent, other = failure)
  local name ts tmp why rc
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL in $CONF"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  for name in pft_backfill:pft_backfill_status_timestamp_seconds pft_backfill_repair:pft_backfill_repair_timestamp_seconds; do
    ts="${name#*:}"; name="${name%%:*}"
    tmp="$TEXTFILE_DIR/.${name}_$PEER_LABEL.prom.pull"
    # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
    timeout "$PULL_TIMEOUT" $PULL_SSH test -f "/var/lib/pft-exporter/textfile/$name.prom" '&&' \
      cat -- "/var/lib/pft-exporter/textfile/$name.prom" > "$tmp" 2>/dev/null; rc=$?
    if [ "$rc" = 1 ] && [ "$name" = pft_backfill_repair ]; then rm -f "$tmp"; echo "$name: none on $PEER_LABEL yet"; continue; fi
    [ "$rc" = 0 ] || { rm -f "$tmp"; die "pull of $name from $PEER_LABEL failed (rc $rc)" 1; }
    if ! why="$(validate_prom "$tmp" "$PEER_LABEL" "$ts")"; then rm -f "$tmp"; die "pulled $name rejected: $why" 2; fi
    { chmod 0644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/${name}_$PEER_LABEL.prom"; } || die "cannot install $name"
    echo "$name: pulled from $PEER_LABEL"
  done
}

main() {
  [ $# -ge 1 ] || die "usage: pft-backfill status [--json] [--textfile|--prom FILE] | plan [--max-ledgers N] | repair [--apply] ..." 3
  valid_label "$HOST_LABEL" || die "bad HOST_LABEL in $CONF" 2
  valid_container "$CONTAINER" || die "bad CONTAINER in $CONF" 2
  [[ "$ADMIN_PORT" =~ ^[0-9]{1,5}$ ]] || die "bad ADMIN_PORT in $CONF" 2
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/pft-backfill.XXXXXX")" || die "mktemp failed"
  local cmd="$1" msg; shift
  case "$cmd" in
    status) cmd_status "$@" ;;
    plan) cmd_plan "$@" ;;
    repair) cmd_repair "$@" ;;
    validate) [ $# = 2 ] || die "usage: pft-backfill validate FILE NODE" 3
              valid_label "$2" || die "bad NODE" 3
              msg="$(validate_prom "$1" "$2" pft_backfill_status_timestamp_seconds)" || die "$1 rejected: $msg" 1 ;;
    pull) [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "pull needs root" 4
          cmd_pull ;;
    -h|--help|help) sed -n '2,23p' "$0"; return 0 ;;
    *) die "unknown command $cmd" 3 ;;
  esac
}

main "$@"
