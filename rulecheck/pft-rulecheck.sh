#!/usr/bin/env bash
# pft-rulecheck: make dead alert rules and stale textfile collector inputs visible. A rule whose selectors match no
# series can never fire, and a collector that stopped writing (or a pulled copy whose peer stopped collecting) keeps
# serving its last values: both switch monitoring off silently. Read-only except the metrics file.
#
# Usage: pft-rulecheck check [--json] [--no-prom] [--lookback 10m]   table (or one JSON object) to stdout
#        sudo pft-rulecheck run                                       timer: check + write TEXTFILE_DIR/pft_rulecheck_HOST.prom
#        sudo pft-rulecheck pull                                      validator: copy the peer's textfile (see below)
#        pft-rulecheck validate FILE HOST                             exit 0 if FILE is an acceptable textfile for HOST
#        pft-rulecheck selectors 'EXPR'                               print the selectors pft-rulecheck sees in EXPR
#        pft-rulecheck version
#
#  rules      every rule from PROM_URL/api/v1/rules; each selector (absent()/absent_over_time() arguments and
#             ALERTS* excluded) is queried as count(last_over_time(SEL[LOOKBACK])). LIVE = every selector has
#             series, PARTIAL = some do not, DEAD = none do, ERROR = Prometheus reports the rule unhealthy or the
#             expression cannot be parsed, IGNORED = ignore-rule in CONF. Constant rules (vector(1)) are LIVE.
#  textfiles  every file in TEXTFILE_DIR: *.prom files get FRESH/STALE from the first matching `textfile` line in
#             CONF (age = max(mtime age, now - smallest TS_METRIC value in the file), so a pulled copy refreshed
#             every minute with an old collector timestamp is STALE); a *.prom file no line matches is
#             UNCONFIGURED; a `require`d file that is not there is MISSING; a dot/temp/non-.prom file older than
#             leftover-age (10m) is LEFTOVER (an interrupted pull or collector).
#  Exit: 0 all LIVE/FRESH, 1 findings, 2 the check could not run (Prometheus unreachable/error, bad config).
#  run   same check with --metrics-out; the unit treats exit 1 as success (the findings are in the metrics).
#  pull  "$PULL_SSH cat -- REMOTE_DIR/pft_rulecheck_PEER.prom" (timeout PULL_TIMEOUT), validated (only
#        pft_rulecheck_ samples with host="PEER", size <= 256 KiB, up + last_run present), renamed into TEXTFILE_DIR.
#        Exit 1 fetch failed, 2 validation failed; the old copy stays, so a dead peer goes STALE here.
#
# Config: /etc/pft-rulecheck.env (KEY=VALUE, root-owned; PFT_RC_ENV overrides the path): HOST_LABEL (validator),
#   PROM_URL (http://127.0.0.1:9090), NO_PROM (0; 1 on a host without Prometheus, e.g. the sentry), CONF
#   (/etc/pft-rulecheck.conf, see pft-rulecheck.conf.example), TEXTFILE_DIR (/var/lib/pft-exporter/textfile),
#   LOOKBACK (10m), PEER_LABEL (sentry), REMOTE_DIR (= TEXTFILE_DIR), PULL_SSH, PULL_TIMEOUT (30).
# Test hooks: PFT_RC_LIB (helper path), PFT_RC_NOW (epoch).
set -euo pipefail
VERSION=1.0.0
ENVF="${PFT_RC_ENV:-/etc/pft-rulecheck.env}"
LIB="${PFT_RC_LIB:-/usr/local/lib/pft-rulecheck/rulecheck_lib.py}"
HOST_LABEL=validator; PROM_URL=http://127.0.0.1:9090; NO_PROM=0; CONF=/etc/pft-rulecheck.conf
TEXTFILE_DIR=/var/lib/pft-exporter/textfile; LOOKBACK=10m; PEER_LABEL=sentry; REMOTE_DIR=""; PULL_SSH=""
PULL_TIMEOUT=30; MAX_BYTES=262144

die() { echo "pft-rulecheck: $1" >&2; exit "${2:-2}"; }
valid_label() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }

# KEY=VALUE only, no shell evaluation; values may be quoted
load_env() {
  local line k v
  [ -f "$ENVF" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    [[ "$line" =~ ^([A-Z_]+)=(.*)$ ]] || die "$ENVF: bad line: $line"
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
    case "$k" in
      HOST_LABEL|PROM_URL|NO_PROM|CONF|TEXTFILE_DIR|LOOKBACK|PEER_LABEL|REMOTE_DIR|PULL_SSH|PULL_TIMEOUT) printf -v "$k" '%s' "$v" ;;
      *) die "$ENVF: unknown key $k" ;;
    esac
  done < "$ENVF"
}
load_env
REMOTE_DIR="${REMOTE_DIR:-$TEXTFILE_DIR}"
valid_label "$HOST_LABEL" || die "bad HOST_LABEL"
url_re='^https?://[][A-Za-z0-9.:-]+(/[A-Za-z0-9._/-]*)?$'
[[ "$PROM_URL" =~ $url_re ]] || die "bad PROM_URL"
[[ "$NO_PROM" =~ ^[01]$ ]] || die "NO_PROM must be 0 or 1"
[[ "$LOOKBACK" =~ ^[1-9][0-9]*[smhd]$ ]] || die "bad LOOKBACK"

helper() { # common check arguments + extra args
  local a=(python3 -I "$LIB" check --host "$HOST_LABEL" --lookback "$LOOKBACK" --textfile-dir "$TEXTFILE_DIR")
  if [ "$NO_PROM" = 1 ]; then a+=(--no-prom); else a+=(--prom "$PROM_URL"); fi
  [ -z "$CONF" ] || { [ -r "$CONF" ] || die "config $CONF not readable"; a+=(--conf "$CONF"); }
  [ -z "${PFT_RC_NOW:-}" ] || a+=(--now "$PFT_RC_NOW")
  "${a[@]}" "$@"
}

check() {
  local extra=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) extra+=(--json) ;;
      --no-prom) NO_PROM=1 ;;
      --lookback) [[ "${2:-}" =~ ^[1-9][0-9]*[smhd]$ ]] || die "bad --lookback"; LOOKBACK="$2"; shift ;;
      *) die "check: unknown argument $1" ;;
    esac
    shift
  done
  helper "${extra[@]}"
}

run() {
  [ $# -eq 0 ] || die "run takes no arguments"
  if [ ! -d "$TEXTFILE_DIR" ] || [ ! -w "$TEXTFILE_DIR" ]; then die "textfile dir $TEXTFILE_DIR missing or not writable"; fi
  helper --metrics-out "$TEXTFILE_DIR/pft_rulecheck_$HOST_LABEL.prom"
}

validate() { # FILE HOST -> prints why on failure
  local f="$1" h="$2" sz
  [ -f "$f" ] || { echo "not a file"; return 1; }
  sz="$(stat -c %s -- "$f")"
  [ "$sz" -gt 0 ] || { echo "empty"; return 1; }
  [ "$sz" -le "$MAX_BYTES" ] || { echo "too large ($sz bytes)"; return 1; }
  awk -v h="$h" '
    /^#/ || /^$/ { next }
    {
      if ($0 !~ /^pft_rulecheck_[a-z_]+\{host="[^"]*"[,}]/) { print "line " NR ": not a pft_rulecheck_ sample with a host label first"; bad = 1; exit }
      split($0, p, "\""); if (p[2] != h) { print "line " NR ": host is not " h; bad = 1; exit }
      if ($NF !~ /^-?[0-9.eE+]+$/) { print "line " NR ": bad value"; bad = 1; exit }
      if ($0 ~ /^pft_rulecheck_up\{/) up = 1
      if ($0 ~ /^pft_rulecheck_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_rulecheck_up sample"; exit 1 }
      if (!ts) { print "no pft_rulecheck_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  [ $# -eq 0 ] || die "pull takes no arguments (PEER_LABEL in $ENVF)"
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $ENVF)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-rulecheck-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned env file
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_rulecheck_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_rulecheck_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_rulecheck_$PEER_LABEL.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  check) check "$@" ;;
  run) run "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-rulecheck validate FILE HOST"; valid_label "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  selectors) [ $# -eq 1 ] || die "usage: pft-rulecheck selectors 'EXPR'"; python3 -I "$LIB" selectors "$1" ;;
  version) echo "pft-rulecheck $VERSION" ;;
  *) die "usage: pft-rulecheck check|run|pull|validate|selectors|version (see the header of this script)" ;;
esac
