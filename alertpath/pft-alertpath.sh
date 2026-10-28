#!/usr/bin/env bash
# pft-alertpath: dead-man's switch for the alerting pipeline (Prometheus -> Alertmanager -> webhook/ntfy bridge),
# checked from a second host (the sentry).
#
# validator host (runs ../alerts)                          sentry host
#   PFTAlertPipelineWatchdog (always firing)
#   -> Alertmanager route "alertpath" (repeat 1m)
#   -> alertpath_sink.py 127.0.0.1:9096 -> last.json
#   pft-alertpath push (timer, 30s):                        pft-alertpath check --notify (timer, 60s):
#     last.json + Prometheus/Alertmanager self-metrics       verify HMAC, keep 10 min of snapshots,
#     + bridge state -> signed snapshot -- ssh forced  --->  decide OK / DEGRADED / STALE, ntfy on change
#                                          command `pft-alertpath receive` (spool)
#
# States (check):
#   STALE     no valid snapshot for SNAP_STALE_SEC, or the last watchdog delivery is older than WD_STALE_SEC
#             (Alertmanager/Prometheus/route/sink dead, or the validator host itself is down)
#   DEGRADED  deliveries still arrive but a part reports failure: Prometheus or Alertmanager unreachable or last
#             config reload failed, rule evaluation failures / notification errors / webhook failures increased in
#             the window, the alertpath rule group not evaluated for EVAL_STALE_SEC, bridge container not running or
#             not listening, new bridge ntfy ERROR lines, a mis-routed delivery, or a rejected (bad HMAC) message
#   OK        none of the above
# ntfy (--notify): one message per state change, RECOVERED when it returns to OK. Uses its own ntfy.env on the
# sentry, so it still works when everything on the validator is down.
#
# Usage: pft-alertpath snapshot                        (validator; print the unsigned snapshot JSON)
#        pft-alertpath push [--print]                  (validator, root; sign + send to the sentry)
#        pft-alertpath receive                         (sentry; ssh forced command, reads stdin)
#        pft-alertpath check [--notify] [--json]       (sentry, root)
#        pft-alertpath status                          (sentry; current state file)
# Exit codes (check): 0 OK, 1 DEGRADED, 2 STALE, 3 usage/config error.
# Env: CONF_DIR (/etc/pft-alertpath: hmac.key, id_ed25519, known_hosts, push.conf, ntfy.env)
#      STATE_DIR (/var/lib/pft-alertpath)  SPOOL_DIR (/var/lib/pft-alertpath-spool)
#      SINK_STATE (/var/lib/pft-alertpath/last.json)  PROM_URL (http://127.0.0.1:9090)  AM_URL (http://127.0.0.1:9093)
#      BRIDGE_CONTAINER (pft-alert-bridge)  BRIDGE_PORT (9095)  DOCKER ("docker")
#      SNAP_STALE_SEC (150)  WD_STALE_SEC (180)  EVAL_STALE_SEC (120)  WINDOW_SEC (600)  SKEW_TOL_SEC (30)
#      NTFY_OUTBOX (if set, ntfy messages are appended to this file instead of sent; used by the tests)

set -uo pipefail
umask 077

CONF_DIR="${CONF_DIR:-/etc/pft-alertpath}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-alertpath}"
SPOOL_DIR="${SPOOL_DIR:-/var/lib/pft-alertpath-spool}"
SINK_STATE="${SINK_STATE:-/var/lib/pft-alertpath/last.json}"
PROM_URL="${PROM_URL:-http://127.0.0.1:9090}"
AM_URL="${AM_URL:-http://127.0.0.1:9093}"
BRIDGE_CONTAINER="${BRIDGE_CONTAINER:-pft-alert-bridge}"
BRIDGE_PORT="${BRIDGE_PORT:-9095}"
read -r -a DOCKER <<< "${DOCKER:-docker}"
SNAP_STALE_SEC="${SNAP_STALE_SEC:-150}"
WD_STALE_SEC="${WD_STALE_SEC:-180}"
EVAL_STALE_SEC="${EVAL_STALE_SEC:-120}"
WINDOW_SEC="${WINDOW_SEC:-600}"
SKEW_TOL_SEC="${SKEW_TOL_SEC:-30}"
MAX_MSG=8192
MAX_SPOOL=200

CMD="${1:-}"; [ $# -gt 0 ] && shift
NOTIFY=0 JSON=0 PRINT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --notify) NOTIFY=1 ;;
    --json) JSON=1 ;;
    --print) PRINT=1 ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done

usage() { sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------- receive: forced command, unprivileged, never sees the key ----------
if [ "$CMD" = receive ]; then
  [ -d "$SPOOL_DIR" ] || { echo "no spool dir" >&2; exit 3; }
  n=$(find "$SPOOL_DIR" -maxdepth 1 -name '*.msg' | wc -l)
  [ "$n" -lt "$MAX_SPOOL" ] || { echo "spool full" >&2; exit 3; }
  tmp="$(mktemp "$SPOOL_DIR/.in.XXXXXX")" || exit 3
  head -c $((MAX_MSG + 1)) > "$tmp"
  if [ "$(stat -c %s -- "$tmp")" -gt "$MAX_MSG" ]; then
    printf 'oversize\n' > "$tmp"   # kept so check rejects it visibly
  fi
  mv -- "$tmp" "$SPOOL_DIR/$(date -u +%s%N).msg"
  exit 0
fi

key_ok() { # key file must exist, not be group/other-readable and hold 64 hex chars
  [ -f "$1" ] || { echo "missing key file $1" >&2; return 1; }
  case "$(stat -c %a -- "$1")" in ?00) ;; *) echo "$1 must be mode 0600 or stricter" >&2; return 1 ;; esac
  grep -qxE '[0-9a-fA-F]{64}' "$1" || { echo "$1 must contain exactly 64 hex characters" >&2; return 1; }
}

# HMAC-SHA256 (RFC 2104) with bash builtins: key hex in $1 (<=64 bytes), message on stdin, hex digest out.
# Same construction as ../watchdog/pft-heartbeat.sh; the key never appears in argv or the environment.
hmac_sha256_hex() {
  local key="$1" ip="" op="" i b inner esc
  while [ "${#key}" -lt 128 ]; do key+=0; done
  for ((i = 0; i < 128; i += 2)); do
    b=$((16#${key:i:2}))
    printf -v esc '\\x%02x' $((b ^ 0x36)); ip+=$esc
    printf -v esc '\\x%02x' $((b ^ 0x5c)); op+=$esc
  done
  inner="$({ printf '%b' "$ip"; cat; } | sha256sum)"; inner="${inner%% *}"
  esc=""; for ((i = 0; i < 64; i += 2)); do esc+="\\x${inner:i:2}"; done
  { printf '%b' "$op"; printf '%b' "$esc"; } | sha256sum | cut -c1-64
}

# Sum of every sample of metric $1 whose label set contains $2 (literal, may be empty), from a scrape on stdin.
# Prints "null" if the metric is absent, so "absent" and "0" stay different.
msum() {
  awk -v m="$1" -v f="${2:-}" '
    index($0, "#") == 1 { next }
    { name = $1; sub(/\{.*/, "", name) }
    name == m && (f == "" || index($1, f) > 0) { s += $NF; n++ }
    END { if (n) printf "%.17g\n", s; else print "null" }'
}

snapshot() {
  local prom am pu=0 au=0 wd=null running=0 listening=0 nerr=null
  if prom="$(curl -fsS --max-time 5 "$PROM_URL/metrics" 2>/dev/null)" && [ -n "$prom" ]; then pu=1; fi
  if am="$(curl -fsS --max-time 5 "$AM_URL/metrics" 2>/dev/null)" && [ -n "$am" ]; then au=1; fi
  if [ -r "$SINK_STATE" ] && jq -e 'type == "object" and (.received | type) == "number"' "$SINK_STATE" >/dev/null 2>&1; then
    wd="$(jq -c '{received, count, status, unexpected}' "$SINK_STATE")"
  fi
  [ "$("${DOCKER[@]}" inspect -f '{{.State.Running}}' "$BRIDGE_CONTAINER" 2>/dev/null)" = true ] && running=1
  ss -Htln "sport = :$BRIDGE_PORT" 2>/dev/null | grep -q . && listening=1
  if [ "$running" -eq 1 ]; then
    nerr="$("${DOCKER[@]}" logs --tail 500 "$BRIDGE_CONTAINER" 2>&1 | grep -c -- '-> ERROR')"
  fi
  jq -nc --arg node "${NODE_LABEL:-validator}" --argjson ts "$(date -u +%s)" --argjson wd "$wd" \
    --argjson pu "$pu" --argjson au "$au" --argjson running "$running" --argjson listening "$listening" \
    --argjson nerr "$nerr" \
    --argjson reload "$(printf '%s' "${prom:-}" | msum prometheus_config_last_reload_successful)" \
    --argjson evalfail "$(printf '%s' "${prom:-}" | msum prometheus_rule_evaluation_failures_total)" \
    --argjson nerrs "$(printf '%s' "${prom:-}" | msum prometheus_notifications_errors_total)" \
    --argjson ndrop "$(printf '%s' "${prom:-}" | msum prometheus_notifications_dropped_total)" \
    --argjson amdisc "$(printf '%s' "${prom:-}" | msum prometheus_notifications_alertmanagers_discovered)" \
    --argjson wdeval "$(printf '%s' "${prom:-}" | msum prometheus_rule_group_last_evaluation_timestamp_seconds ';alertpath"')" \
    --argjson amreload "$(printf '%s' "${am:-}" | msum alertmanager_config_last_reload_successful)" \
    --argjson amfail "$(printf '%s' "${am:-}" | msum alertmanager_notifications_failed_total 'integration="webhook"')" \
    --argjson amtotal "$(printf '%s' "${am:-}" | msum alertmanager_notifications_total 'integration="webhook"')" \
    '{v:1, type:"alertpath", node:$node, ts:$ts, wd:$wd,
      prom:{up:$pu, reload_ok:$reload, rule_eval_failures:$evalfail, notif_errors:$nerrs, notif_dropped:$ndrop,
            am_discovered:$amdisc, wd_last_eval:$wdeval},
      am:{up:$au, reload_ok:$amreload, notif_failed:$amfail, notif_total:$amtotal},
      bridge:{running:$running, listening:$listening, ntfy_errors:$nerr}}'
}

case "$CMD" in
  snapshot) snapshot; exit $? ;;
  push)
    [ "$(id -u)" -eq 0 ] || [ -n "${PFT_ALERTPATH_TEST:-}" ] || { echo "run as root" >&2; exit 3; }
    RELAY_TARGET="" RELAY_PORT=22 NODE_LABEL=validator
    if [ -f "$CONF_DIR/push.conf" ]; then
      while IFS='=' read -r k v; do
        case "$k" in RELAY_TARGET|RELAY_PORT|NODE_LABEL) printf -v "$k" '%s' "${v//\"/}" ;; esac
      done < <(grep -E '^(RELAY_TARGET|RELAY_PORT|NODE_LABEL)=' "$CONF_DIR/push.conf")
    fi
    key_ok "$CONF_DIR/hmac.key" || exit 3
    body="$(snapshot)" || { echo "snapshot failed" >&2; exit 3; }
    KEY="$(tr -d '[:space:]' < "$CONF_DIR/hmac.key")"
    sig="$(printf '%s' "$body" | hmac_sha256_hex "$KEY")"
    unset KEY
    if [ "$PRINT" -eq 1 ]; then printf '%s\n%s\n' "$body" "$sig"; exit 0; fi
    [ -n "$RELAY_TARGET" ] || { echo "RELAY_TARGET not set in $CONF_DIR/push.conf" >&2; exit 3; }
    [ -f "$CONF_DIR/id_ed25519" ] || { echo "missing SSH key $CONF_DIR/id_ed25519" >&2; exit 3; }
    if printf '%s\n%s\n' "$body" "$sig" | ssh -T -i "$CONF_DIR/id_ed25519" -p "$RELAY_PORT" \
         -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=yes \
         -o UserKnownHostsFile="$CONF_DIR/known_hosts" "$RELAY_TARGET" >/dev/null; then
      echo "snapshot sent: $body"; exit 0
    fi
    echo "snapshot send failed" >&2; exit 2 ;;
  check|status) ;;
  -h|--help|"") usage; exit 0 ;;
  *) usage >&2; exit 3 ;;
esac

# ---------- check / status (sentry) ----------
[ "$(id -u)" -eq 0 ] || [ -n "${PFT_ALERTPATH_TEST:-}" ] || { echo "run as root" >&2; exit 3; }
mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"
STATE="$STATE_DIR/state.json"
HIST="$STATE_DIR/history.jsonl"
[ -f "$STATE" ] || jq -n --argjson t "$(date -u +%s)" '{state:"OK", since:$t, last_ts:0, rejected:0}' > "$STATE"
[ -f "$HIST" ] || : > "$HIST"
if [ "$CMD" = status ]; then jq . "$STATE"; exit 0; fi

exec 9>"$STATE_DIR/.lock"
flock -w 50 9 || { echo "another check holds the lock" >&2; exit 3; }
key_ok "$CONF_DIR/hmac.key" || exit 3
KEY="$(tr -d '[:space:]' < "$CONF_DIR/hmac.key")"
NOW="$(date -u +%s)"
last_ts="$(jq -r '.last_ts // 0' "$STATE")"

# Verify and absorb spooled snapshots, oldest first. Anything that fails is counted and deleted.
rejected=0 accepted=0
if [ -d "$SPOOL_DIR" ]; then
  while IFS= read -r f; do
    body="$(sed -n 1p -- "$f")"; sig="$(sed -n 2p -- "$f")"
    want="$(printf '%s' "$body" | hmac_sha256_hex "$KEY")"
    ts="$(jq -r 'select(.v == 1 and .type == "alertpath") | .ts | numbers' <<<"$body" 2>/dev/null)"
    if [ -z "$sig" ] || [ "$sig" != "$want" ] || [ -z "$ts" ] \
       || [ "$ts" -le "$last_ts" ] || [ "$ts" -gt $((NOW + SKEW_TOL_SEC)) ]; then
      rejected=$((rejected + 1))
    else
      printf '%s\n' "$body" >> "$HIST"; last_ts="$ts"; accepted=$((accepted + 1))
    fi
    rm -f -- "$f"
  done < <(find "$SPOOL_DIR" -maxdepth 1 -name '*.msg' -printf '%f\n' | sort -n | sed "s|^|$SPOOL_DIR/|")
fi
unset KEY

# Keep WINDOW_SEC of history (by signed ts).
tmp="$(mktemp "$STATE_DIR/.hist.XXXXXX")"
jq -c --argjson cut $((NOW - WINDOW_SEC)) 'select(.ts >= $cut)' "$HIST" > "$tmp" 2>/dev/null && mv -- "$tmp" "$HIST"
rm -f -- "$tmp"

# Decide. inc(path): counter increase across the window, Prometheus-style (a drop = reset, counts the new value).
verdict="$(jq -sc --argjson now "$NOW" --argjson rejected "$rejected" \
  --argjson snap_stale "$SNAP_STALE_SEC" --argjson wd_stale "$WD_STALE_SEC" --argjson eval_stale "$EVAL_STALE_SEC" '
  def num: if type == "number" then . else null end;
  def inc(f): [ .[] | f | num ] | map(select(. != null)) as $v
    | if ($v | length) < 2 then 0
      else reduce range(1; $v | length) as $i (0; . + (if $v[$i] >= $v[$i-1] then $v[$i] - $v[$i-1] else $v[$i] end))
      end;
  sort_by(.ts) as $h | ($h | last) as $c
  | (if $c == null then null else $now - $c.ts end) as $snap_age
  | (if $c == null or $c.wd == null then null else $c.ts - $c.wd.received end) as $wd_age
  | [ if $c == null then "no snapshot received from the validator"
      elif $snap_age > $snap_stale then "last snapshot \($snap_age)s old (> \($snap_stale)s)" else empty end,
      if $c != null and $c.wd == null then "no watchdog delivery recorded by the sink"
      elif $wd_age != null and $wd_age > $wd_stale then "last watchdog delivery \($wd_age)s before the snapshot (> \($wd_stale)s)"
      else empty end ] as $stale
  | [ if $rejected > 0 then "\($rejected) spooled message(s) rejected (HMAC/format/replay/clock)" else empty end,
      if $c == null then empty else
        ( if $c.wd != null and $c.wd.status != "firing" then "watchdog delivery status \($c.wd.status)" else empty end,
          if $c.prom.up != 1 then "Prometheus unreachable"
          else
            ( if $c.prom.reload_ok != 1 then "Prometheus last config reload failed" else empty end,
              (($h | inc(.prom.rule_eval_failures)) as $d | if $d > 0 then "Prometheus rule evaluation failures +\($d)" else empty end),
              (($h | inc(.prom.notif_errors)) as $d | if $d > 0 then "Prometheus notification errors +\($d)" else empty end),
              (($h | inc(.prom.notif_dropped)) as $d | if $d > 0 then "Prometheus notifications dropped +\($d)" else empty end),
              if ($c.prom.am_discovered | num) == null or $c.prom.am_discovered < 1 then "Prometheus has no Alertmanager" else empty end,
              if ($c.prom.wd_last_eval | num) == null then "alertpath rule group not loaded"
              elif ($c.ts - $c.prom.wd_last_eval) > $eval_stale then "alertpath rule group last evaluated \(($c.ts - $c.prom.wd_last_eval) | floor)s ago" else empty end )
          end,
          if $c.am.up != 1 then "Alertmanager unreachable"
          else
            ( if $c.am.reload_ok != 1 then "Alertmanager last config reload failed" else empty end,
              (($h | inc(.am.notif_failed)) as $d | if $d > 0 then "Alertmanager webhook notifications failed +\($d)" else empty end) )
          end,
          if $c.bridge.running != 1 then "ntfy bridge container not running"
          elif $c.bridge.listening != 1 then "ntfy bridge not listening" else empty end,
          (($h | inc(.bridge.ntfy_errors)) as $d | if $d > 0 then "ntfy bridge delivery errors +\($d)" else empty end),
          (($h | inc(.wd.unexpected)) as $d | if $d > 0 then "alertpath sink got \($d) mis-routed delivery(ies)" else empty end) )
      end ] as $degraded
  | {checked_at:$now, state:(if ($stale|length) > 0 then "STALE" elif ($degraded|length) > 0 then "DEGRADED" else "OK" end),
     reasons:($stale + $degraded), snapshot_age:$snap_age, delivery_age:$wd_age, snapshots:($h|length)}
  ' "$HIST")" || { echo "evaluation failed" >&2; exit 3; }

state="$(jq -r .state <<<"$verdict")"
prev="$(jq -r .state "$STATE")"
since="$(jq -r .since "$STATE")"
[ "$state" != "$prev" ] && since="$NOW"
jq -c --arg s "$state" --argjson since "$since" --argjson ts "$last_ts" --argjson r "$rejected" \
  --argjson v "$verdict" '{state:$s, since:$since, last_ts:$ts, rejected:((.rejected // 0) + $r), last:$v}' "$STATE" \
  > "$STATE.tmp" && mv -- "$STATE.tmp" "$STATE"

ntfy() { # title, priority, body
  if [ -n "${NTFY_OUTBOX:-}" ]; then
    printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$NTFY_OUTBOX"; return 0
  fi
  local NTFY_SERVER="" NTFY_TOPIC="" NTFY_TOKEN="" k v auth=()
  [ -r "$CONF_DIR/ntfy.env" ] || { echo "no $CONF_DIR/ntfy.env; notification skipped" >&2; return 1; }
  while IFS='=' read -r k v; do
    case "$k" in NTFY_SERVER|NTFY_TOPIC|NTFY_TOKEN) printf -v "$k" '%s' "${v//\"/}" ;; esac
  done < <(grep -E '^(NTFY_SERVER|NTFY_TOPIC|NTFY_TOKEN)=' "$CONF_DIR/ntfy.env")
  if [ -z "$NTFY_SERVER" ] || [ -z "$NTFY_TOPIC" ]; then echo "ntfy.env incomplete" >&2; return 1; fi
  [ -n "$NTFY_TOKEN" ] && auth=(-H "Authorization: Bearer $NTFY_TOKEN")
  curl -fsS --max-time 15 -o /dev/null -H "Title: $1" -H "Priority: $2" -H "Tags: rotating_light" "${auth[@]}" \
    --data-binary "$3" "$NTFY_SERVER/$NTFY_TOPIC" || { echo "ntfy send failed" >&2; return 1; }
}

reasons="$(jq -r '.reasons | join("; ")' <<<"$verdict")"
if [ "$state" != "$prev" ]; then
  # --json keeps stdout pure JSON; the transition line then goes to stderr (journal)
  if [ "$JSON" -eq 1 ]; then exec 8>&2; else exec 8>&1; fi
  echo "transition $prev -> $state at $NOW: ${reasons:-all checks pass}" >&8
  if [ "$NOTIFY" -eq 1 ]; then
    case "$state" in
      OK) ntfy "[alertpath] RECOVERED" low "Alert pipeline OK again (was $prev)" ;;
      STALE) ntfy "[alertpath] STALE" high "$reasons" ;;
      DEGRADED) ntfy "[alertpath] DEGRADED" default "$reasons" ;;
    esac
  fi
fi

if [ "$JSON" -eq 1 ]; then
  jq -c --argjson a "$accepted" --argjson since "$since" '. + {accepted:$a, since:$since}' <<<"$verdict"
else
  printf '%s state=%s accepted=%d rejected=%d snapshot_age=%s delivery_age=%s%s\n' "$(date -u -d "@$NOW" +%FT%TZ)" \
    "$state" "$accepted" "$rejected" "$(jq -r .snapshot_age <<<"$verdict")" "$(jq -r .delivery_age <<<"$verdict")" \
    "${reasons:+ reasons: $reasons}"
fi
case "$state" in OK) exit 0 ;; DEGRADED) exit 1 ;; *) exit 2 ;; esac
