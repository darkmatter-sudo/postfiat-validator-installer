#!/usr/bin/env bash
# pft-backfill: find ledger-history gaps inside a postfiatd node's [node_db] online_delete window and (opt-in, capped)
# ask the node to re-acquire them with loopback ledger_request. Dockerized postfiatd 1.0.9 on Ubuntu 22.04; the same
# script runs on the validator and the sentry. Gap accounting lives in backfill_parse.py (stdlib only).
#
# Usage: pft-backfill status [--json] [--textfile | --prom FILE]   read-only
#        pft-backfill plan [--max-ledgers N]                      read-only: the sequences a repair would request
#
# Reads: server_info through `docker exec CONTAINER curl` to the container's own loopback admin port (the host-mapped
# port answers admin calls with "Forbidden"), and postfiatd.cfg through the config volume's HOST path (docker inspect
# Mounts[].Source): no shell and no file read inside the container, so an AppArmor profile on the node needs no
# extra rule for this tool.
# Exit codes: 0 no gap inside the window, 1 gaps found (or node not full), 2 error, 3 usage.
# jq programs are single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
umask 022

R="${PFT_BACKFILL_ROOT:-}"
DOCKER="${PFT_BACKFILL_DOCKER:-docker}"
PYTHON="${PFT_BACKFILL_PYTHON:-python3}"
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PARSER="${PFT_BACKFILL_PARSER:-$HERE/backfill_parse.py}"
CONF="${PFT_BACKFILL_CONF:-$R/etc/pft-backfill.env}"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
conf_get() { [ -f "$CONF" ] && sed -n "s/^$1=//p" "$CONF" | tail -1 | sed -E 's/^"(.*)"$/\1/'; return 0; }
CONTAINER="$(conf_get CONTAINER)"; CONTAINER="${CONTAINER:-postfiatd}"
HOST_LABEL="$(conf_get HOST_LABEL)"; HOST_LABEL="${HOST_LABEL:-validator}"
ADMIN_PORT="$(conf_get ADMIN_PORT)"; ADMIN_PORT="${ADMIN_PORT:-5005}"
CFG_DEST="${CFG_DEST:-/etc/postfiatd}"
RPC_TIMEOUT="${RPC_TIMEOUT:-5}"

die() { echo "pft-backfill: $*" >&2; exit "${2:-2}"; }
ts() { date -u +%FT%TZ; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
valid_container() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; }

WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; return 0; }
trap cleanup EXIT

rpc() { # METHOD [PARAMS_JSON] -> answer on stdout; rc 1 + message on stdout on failure (caller records it)
  local body err out params="${2:-}"
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

main() {
  [ $# -ge 1 ] || die "usage: pft-backfill status [--json] [--textfile|--prom FILE] | plan [--max-ledgers N]" 3
  valid_label "$HOST_LABEL" || die "bad HOST_LABEL in $CONF" 2
  valid_container "$CONTAINER" || die "bad CONTAINER in $CONF" 2
  [[ "$ADMIN_PORT" =~ ^[0-9]{1,5}$ ]] || die "bad ADMIN_PORT in $CONF" 2
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/pft-backfill.XXXXXX")" || die "mktemp failed"
  local cmd="$1"; shift
  case "$cmd" in
    status) cmd_status "$@" ;;
    plan) cmd_plan "$@" ;;
    -h|--help|help) sed -n '2,15p' "$0"; return 0 ;;
    *) die "unknown command $cmd" 3 ;;
  esac
}

main "$@"
