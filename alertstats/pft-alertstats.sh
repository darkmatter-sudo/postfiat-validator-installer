#!/usr/bin/env bash
# pft-alertstats: observed alert behaviour (episodes, flaps, near misses, time to resolve, silenced time,
# notifications) from Prometheus ALERTS history, plus static rule hygiene. pft-rulecheck grades rules statically;
# this answers "how did each rule actually behave over the last N days" so rules can be tuned on evidence.
# Read-only: HTTP GETs to Prometheus/Alertmanager and `docker logs` of the ntfy bridge. It never sends a
# notification, never creates or expires a silence and never touches a container.
#
# Usage: sudo pft-alertstats run                          collect + reports + textfile (the daily timer)
#        sudo pft-alertstats collect [--since D] [--out FILE[.gz]]   write a bundle (default: stdout)
#        pft-alertstats report --offline BUNDLE [--format md|json|csv|textfile]
#                                                         rebuild a report from a bundle alone (no host access)
#        pft-alertstats version
#
#  collect  query_range ALERTS, ALERTS_FOR_STATE and count(present_over_time(UP_SELECTOR[2*STEP])) from now-SINCE
#           to now (STEP grid, <= 10000 points per call), /api/v1/rules, /api/v2/silences (Alertmanager keeps
#           expired silences for its data retention, 120h by default) and the bridge's delivery lines
#           (`docker logs --timestamps BRIDGE`; they start at the bridge container's last start). Public IPs and
#           ntfy topics are redacted before anything is written. SINCE defaults to 7d and is capped at 15d.
#  report   a pure function of the bundle: same bundle, same bytes (see alertstats_build.py for the episode model).
#  run      collect -> STATE_DIR/bundles/alertstats-YYYYMMDDTHHMMSSZ.json.gz, reports md/json/csv next to it in
#           STATE_DIR/reports/, TEXTFILE_DIR/pft_alertstats.prom (atomic rename; on a failed Prometheus capture only
#           pft_alertstats_up 0 + timestamp). Bundles/reports older than KEEP_DAYS are deleted.
#
# Exit codes: 0 ok, 3 usage/config, 4 Prometheus capture failed (textfile up 0), 5 cannot write output.
# Conf: PFT_AS_CONF (/etc/pft-alertstats.env, root-owned): PROM_URL (http://127.0.0.1:9090),
#       AM_URL (http://127.0.0.1:9093), SINCE (7d), STEP (15), UP_SELECTOR (up{job="postfiat"}),
#       BRIDGE_CONTAINER (pft-alert-bridge; "" = no delivery log), FLAP_WINDOW (1h), FLAP_MIN (3), FLAP_RECENT (24h),
#       ALLOW_NO_FOR (PFTAlertPipelineWatchdog), HOST_LABEL (validator), STATE_DIR (/var/lib/pft-alertstats),
#       TEXTFILE_DIR (/var/lib/pft-exporter/textfile), KEEP_DAYS (15), HTTP_TIMEOUT (60)
# Test hooks: PFT_AS_BUILD (/usr/local/lib/pft-alertstats/alertstats_build.py), PFT_AS_TEST=1 (no root check),
#       PFT_AS_DOCKER (docker command), PFT_AS_NOW (fixed epoch for collect/run)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_AS_CONF:-/etc/pft-alertstats.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
PROM_URL="${PROM_URL:-http://127.0.0.1:9090}"
AM_URL="${AM_URL:-http://127.0.0.1:9093}"
SINCE="${SINCE:-7d}"
STEP="${STEP:-15}"
UP_SELECTOR="${UP_SELECTOR:-up{job=\"postfiat\"}}"
BRIDGE_CONTAINER="${BRIDGE_CONTAINER-pft-alert-bridge}"
FLAP_WINDOW="${FLAP_WINDOW:-1h}"
FLAP_MIN="${FLAP_MIN:-3}"
FLAP_RECENT="${FLAP_RECENT:-24h}"
ALLOW_NO_FOR="${ALLOW_NO_FOR-PFTAlertPipelineWatchdog}"
HOST_LABEL="${HOST_LABEL:-validator}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-alertstats}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
KEEP_DAYS="${KEEP_DAYS:-15}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-60}"
BUILD="${PFT_AS_BUILD:-/usr/local/lib/pft-alertstats/alertstats_build.py}"
DOCKER="${PFT_AS_DOCKER:-docker}"
TMP=""

die() { echo "pft-alertstats: $1" >&2; exit "${2:-3}"; }
tmpdir() { [ -n "$TMP" ] || { TMP="$(mktemp -d)" || die "mktemp failed" 5; trap 'rm -rf "$TMP"' EXIT; }; }
need_root() { [ "${PFT_AS_TEST:-0}" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root (sudo): docker logs and $TEXTFILE_DIR" 3; }
py() { python3 -I "$BUILD" "$@"; }

check_conf() {
  [ -r "$BUILD" ] || die "helper $BUILD not readable" 3
  [[ "$STEP" =~ ^[1-9][0-9]*$ ]] || die "STEP must be a positive integer (got '$STEP')" 3
  if ! [[ "$FLAP_MIN" =~ ^[0-9]+$ ]] || [ "$FLAP_MIN" -lt 2 ]; then die "FLAP_MIN must be >= 2 (got '$FLAP_MIN')" 3; fi
  [[ "$KEEP_DAYS" =~ ^[1-9][0-9]*$ ]] || die "KEEP_DAYS must be a positive integer (got '$KEEP_DAYS')" 3
  [[ "$HOST_LABEL" =~ ^[A-Za-z0-9_.-]+$ ]] || die "HOST_LABEL has characters outside [A-Za-z0-9_.-]" 3
}

deliveries() { # FILE: the bridge's delivery log, or nothing when BRIDGE_CONTAINER is empty / not running
  local f="$1"
  : >"$f"
  [ -n "$BRIDGE_CONTAINER" ] || return 1
  # `docker logs` only reads the container's json log; no exec, nothing inside the container runs
  "$DOCKER" logs --timestamps "$BRIDGE_CONTAINER" >"$f" 2>&1 || { : >"$f"; return 1; }
}

collect() { # OUT [SINCE] -> rc of the helper (0 ok, 4 Prometheus failed)
  local out="$1" since="${2:-$SINCE}" d=() now=()
  tmpdir
  if deliveries "$TMP/bridge.log"; then d=(--deliveries "$TMP/bridge.log"); fi
  [ -n "${PFT_AS_NOW:-}" ] && now=(--now "$PFT_AS_NOW")
  py collect --prometheus "$PROM_URL" --alertmanager "$AM_URL" --since "$since" --step "$STEP" \
    --up-selector "$UP_SELECTOR" --flap-window "$FLAP_WINDOW" --flap-min "$FLAP_MIN" --flap-recent "$FLAP_RECENT" \
    --allow-no-for "$ALLOW_NO_FOR" --host "$HOST_LABEL" --timeout "$HTTP_TIMEOUT" "${d[@]}" "${now[@]}" --out "$out"
}

write_textfile() { # FILE-WITH-CONTENT
  local t
  t="$(mktemp "$TEXTFILE_DIR/.pft_alertstats.XXXXXX" 2>/dev/null)" || { echo "pft-alertstats: cannot write $TEXTFILE_DIR" >&2; return 1; }
  if ! { cat -- "$1" >"$t" && chmod 644 "$t" && mv -f "$t" "$TEXTFILE_DIR/pft_alertstats.prom"; }; then
    rm -f "$t"; echo "pft-alertstats: cannot write $TEXTFILE_DIR" >&2; return 1
  fi
}

down_textfile() { # FILE: up 0 + timestamp only
  local ts="${PFT_AS_NOW:-$(date -u +%s)}"
  printf '%s\n' "# HELP pft_alertstats_up 1 = the report was built from a complete Prometheus capture." \
    "# TYPE pft_alertstats_up gauge" "pft_alertstats_up{host=\"$HOST_LABEL\"} 0" \
    "# HELP pft_alertstats_last_run_timestamp_seconds When the report was built." \
    "# TYPE pft_alertstats_last_run_timestamp_seconds gauge" \
    "pft_alertstats_last_run_timestamp_seconds{host=\"$HOST_LABEL\"} $ts" >"$1"
}

run() {
  local stamp b rc fmt ts
  need_root; check_conf; tmpdir
  mkdir -p "$STATE_DIR/bundles" "$STATE_DIR/reports" || die "cannot create $STATE_DIR" 5
  ts="${PFT_AS_NOW:-$(date -u +%s)}"
  stamp="$(date -u -d "@$ts" +%Y%m%dT%H%M%SZ)"
  b="$STATE_DIR/bundles/alertstats-$stamp.json.gz"
  collect "$b"; rc=$?
  if [ "$rc" != 0 ]; then
    down_textfile "$TMP/t.prom"; write_textfile "$TMP/t.prom"
    echo "pft-alertstats: Prometheus capture failed (rc=$rc), wrote up 0; bundle kept: $b" >&2
    return 4
  fi
  for fmt in md json csv; do
    py report --offline "$b" --format "$fmt" >"$STATE_DIR/reports/alertstats-$stamp.$fmt" || die "report $fmt failed" 5
  done
  py report --offline "$b" --format textfile --now "$ts" >"$TMP/t.prom" || die "textfile report failed" 5
  write_textfile "$TMP/t.prom" || return 5
  find "$STATE_DIR/bundles" "$STATE_DIR/reports" -maxdepth 1 -type f -name 'alertstats-*' -mtime +"$KEEP_DAYS" -delete
  echo "pft-alertstats: bundle $b"
  echo "pft-alertstats: report $STATE_DIR/reports/alertstats-$stamp.md"
  sed -n '/^## Headline/,/^## Per alert/p' "$STATE_DIR/reports/alertstats-$stamp.md" | sed '$d'
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  run) [ $# = 0 ] || die "usage: pft-alertstats run" 3; run ;;
  collect)
    out="" since="$SINCE"
    while [ $# -gt 0 ]; do
      case "$1" in
        --since) [ $# -ge 2 ] || die "--since needs a value" 3; since="$2"; shift 2 ;;
        --out) [ $# -ge 2 ] || die "--out needs a value" 3; out="$2"; shift 2 ;;
        *) die "unknown option $1" 3 ;;
      esac
    done
    need_root; check_conf
    if [ -z "$out" ]; then
      tmpdir; collect "$TMP/b.json" "$since"; rc=$?; cat "$TMP/b.json"; exit "$rc"
    fi
    collect "$out" "$since" ;;
  report)
    [ -r "$BUILD" ] || die "helper $BUILD not readable" 3
    py report "$@" ;;
  version) echo "pft-alertstats $VERSION" ;;
  *) sed -n '8,13p' "$0" >&2; exit 3 ;;
esac
