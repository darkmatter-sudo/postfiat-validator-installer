#!/usr/bin/env bash
# pft-upstreamwatch: tell a QUIET upstream vulnerability feed from a BROKEN local fetch, and notice when a newer
# postfiatd image or build is published, on a Post Fiat validator/sentry host. Read-only: it never changes a feed,
# a container or an image.
#
# Usage: sudo pft-upstreamwatch run [--textfile-dir DIR] [--no-heal]
#                                                    collect + bounded heal + report + textfile metrics (atomic)
#        pft-upstreamwatch report [--obs FILE] [--format text|json|prom]
#                                                    re-render offline from an observation file (no network/docker)
#        sudo pft-upstreamwatch pull                 validator: copy the peer's textfile (like ../vulnscan)
#        pft-upstreamwatch validate FILE HOST        check a textfile before it is served
#        sudo pft-upstreamwatch digest [--dry-run] [--force]
#                                                    host running ../alerts: at most one low ntfy summary a day of
#                                                    the digest-only alerts (quiet feeds, release available)
#
# Why: ../vulnscan's PFTVulnFeedStale looks only at the feed's own timestamp, so when Canonical simply does not
# republish its USN OVAL for 3+ days (2026-11-19 -> 11-23) it pages on both hosts with nothing wrong locally. This
# keeps two clocks per feed: the LOCAL fetch clock (when our fetcher last downloaded/revalidated) and the CONTENT
# clock (our copy's own timestamp vs upstream's Last-Modified / ETag / content index, read with a conditional
# HEAD). States: ok, upstream_quiet (never paged; daily digest), local_stale and fetch_failing (paged), unreachable
# (not paged; if it persists the fetcher goes overdue -> fetch_failing). See upstreamwatch_lib.py for the rules.
# local_lagging (not paged, digest): upstream has content we lack, for no longer than STALE_GRACE_HOURS.
#
# Bounded heal (2026-11-24 and 11-27: a Canonical cache served ../vulnscan's daily fetch an older copy, so both
# hosts sat on an old USN feed while upstream had a newer one): when usn-host has lagged for more than
# LAG_HEAL_HOURS, run starts HEAL_UNIT (pft-vulnscan-heal.service = `pft-vulnscan scan --force-fetch`: one
# unconditional no-cache GET with a cache-busting query, then a scan). At most one start per feed per
# HEAL_INTERVAL_HOURS (counted from the last start, persisted in HEAL_STATE before the start), never while a
# pft-maint window is active (MAINT_CMD exit 0/2; only exit 1 = no window allows it), never while one of
# HEAL_BUSY_UNITS is active, and only with HEAL_LOCK held (flock -n). Every decision of an eligible feed and every
# result (healed | still_lagging | failed) is appended to HEAL_JOURNAL (JSON lines) and printed (systemd journal).
# The run then collects again, so the textfile shows the state after the heal.
# The same bounded heal covers the ../imagescan feeds (ubuntu-*, debian, go; 2026-11-27: the ubuntu OCI feeds sat on
# an older CDN copy on both hosts): IMAGESCAN_HEAL_UNIT (pft-imagescan-heal.service = `pft-imagescan fetch`,
# fetch-only, with its own cache-busting retry) never while one of IMAGESCAN_HEAL_BUSY_UNITS is active. Decisions,
# lock and cooldown are per FETCHER (heal-state key usn-host for vulnscan, imagescan for imagescan): any number of
# lagging imagescan feeds cause at most one start per HEAL_INTERVAL_HOURS; the result is healed only if every one of
# them is back at lag 0.
#
# Feeds (FEEDS): usn-host (../vulnscan, jammy host USN OVAL), ubuntu-<codename> / debian / go (../imagescan feed
# cache), debian-oval-<codename> (Debian OVAL; upstream clock only, no host consumes a local copy).
# Release watch: registry HEAD of the running container's tag (anonymous Bearer token if the registry asks) vs the
# running image's RepoDigest, and the foundation RPC build_version vs this node's (read from ../upgradewatch's
# textfile, so no docker exec). Docker is only asked `inspect` and `image inspect`: never pull/exec/run/create.
#
# Config: /etc/pft-upstreamwatch.env (KEY=VALUE, root-owned; PFT_UW_CONF overrides): HOST_LABEL (validator),
#   PEER_LABEL (sentry), FEEDS, CONTAINER (postfiatd), BUILD_TEXTFILE, QUIET_AGE_HOURS (72), STALE_GRACE_HOURS (30),
#   FETCH_MAX_AGE_HOURS (50), CONTENT_TOLERANCE_SECONDS (21600), SKEW_MAX_SECONDS (300), RETRIES (3),
#   BACKOFF_SECONDS (2), HTTP_TIMEOUT (20), FOUNDATION_RPC, REGISTRY_URL (derived from the image ref),
#   VULNSCAN_CACHE, IMAGESCAN_CACHE, DATA_DIR (/var/lib/pft-upstreamwatch), TEXTFILE_DIR / REMOTE_DIR
#   (/var/lib/pft-exporter/textfile), PULL_SSH, PULL_TIMEOUT (30), PROM_URL (http://127.0.0.1:9090),
#   NTFY_ENV (/etc/postfiat-monitor.env), DIGEST_STAMP (DATA_DIR/digest-last), LAG_HEAL_HOURS (2, 0 = off),
#   HEAL_INTERVAL_HOURS (6), HEAL_TIMEOUT (1500 s), HEAL_UNIT (pft-vulnscan-heal.service), HEAL_BUSY_UNITS
#   (pft-vulnscan.service pft-vulnscan-heal.service), IMAGESCAN_HEAL_UNIT (pft-imagescan-heal.service),
#   IMAGESCAN_HEAL_BUSY_UNITS (pft-imagescan.service pft-imagescan-heal.service), MAINT_CMD (pft-maint active), HEAL_STATE
#   (DATA_DIR/heal-state.json), HEAL_LOCK (DATA_DIR/heal.lock), HEAL_JOURNAL (DATA_DIR/heal.jsonl, last 1000 lines).
# Test hooks: PFT_UW_LIB, PFT_UW_DOCKER, PFT_UW_SYSTEMCTL, PFT_UW_NOW (epoch), PFT_UW_UBUNTU_BASE PFT_UW_DEBIAN_TRACKER_URL
#   PFT_UW_DEBIAN_OVAL_BASE PFT_UW_GO_BASE (fixture servers).
# Exit: run 0 = no paged state, 1 = local_stale/fetch_failing present, 2 = collect error (textfile up 0).
set -uo pipefail
umask 022
VERSION=1.2.0

HOST_LABEL=validator; PEER_LABEL=sentry; FEEDS="usn-host ubuntu-jammy ubuntu-noble debian go debian-oval-bookworm"
CONTAINER=postfiatd; BUILD_TEXTFILE=""; QUIET_AGE_HOURS=72; STALE_GRACE_HOURS=30; FETCH_MAX_AGE_HOURS=50
CONTENT_TOLERANCE_SECONDS=21600; SKEW_MAX_SECONDS=300; RETRIES=3; BACKOFF_SECONDS=2; HTTP_TIMEOUT=20
FOUNDATION_RPC=https://rpc.testnet.postfiat.org/; REGISTRY_URL=""
VULNSCAN_CACHE=/var/cache/pft-vulnscan; IMAGESCAN_CACHE=/var/cache/pft-imagescan; DATA_DIR=/var/lib/pft-upstreamwatch
TEXTFILE_DIR=/var/lib/pft-exporter/textfile; REMOTE_DIR=/var/lib/pft-exporter/textfile; PULL_SSH=""; PULL_TIMEOUT=30
PROM_URL=http://127.0.0.1:9090; NTFY_ENV=/etc/postfiat-monitor.env; DIGEST_STAMP=""
LAG_HEAL_HOURS=2; HEAL_INTERVAL_HOURS=6; HEAL_TIMEOUT=1500; HEAL_UNIT=pft-vulnscan-heal.service
HEAL_BUSY_UNITS="pft-vulnscan.service pft-vulnscan-heal.service"; MAINT_CMD="pft-maint active"
IMAGESCAN_HEAL_UNIT=pft-imagescan-heal.service; IMAGESCAN_HEAL_BUSY_UNITS="pft-imagescan.service pft-imagescan-heal.service"
HEAL_STATE=""; HEAL_LOCK=""; HEAL_JOURNAL=""
MAX_BYTES=32768

die() { printf 'pft-upstreamwatch: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { if [ -n "${PFT_UW_NOW:-}" ]; then echo "$PFT_UW_NOW"; else date -u +%s; fi; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }

CONF="${PFT_UW_CONF:-/etc/pft-upstreamwatch.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in ''|\#*) continue ;; esac
    v="${v%\"}"; v="${v#\"}"
    case "$k" in
      HOST_LABEL|PEER_LABEL|FEEDS|CONTAINER|BUILD_TEXTFILE|QUIET_AGE_HOURS|STALE_GRACE_HOURS|FETCH_MAX_AGE_HOURS|\
CONTENT_TOLERANCE_SECONDS|SKEW_MAX_SECONDS|RETRIES|BACKOFF_SECONDS|HTTP_TIMEOUT|FOUNDATION_RPC|REGISTRY_URL|\
VULNSCAN_CACHE|IMAGESCAN_CACHE|DATA_DIR|TEXTFILE_DIR|REMOTE_DIR|PULL_SSH|PULL_TIMEOUT|PROM_URL|NTFY_ENV|DIGEST_STAMP|\
LAG_HEAL_HOURS|HEAL_INTERVAL_HOURS|HEAL_TIMEOUT|HEAL_UNIT|HEAL_BUSY_UNITS|MAINT_CMD|HEAL_STATE|HEAL_LOCK|HEAL_JOURNAL|\
IMAGESCAN_HEAL_UNIT|IMAGESCAN_HEAL_BUSY_UNITS)
        printf -v "$k" '%s' "$v" ;;
      *) die "unknown key in $CONF: $k" ;;
    esac
  done < "$CONF"
fi
for n in QUIET_AGE_HOURS STALE_GRACE_HOURS FETCH_MAX_AGE_HOURS CONTENT_TOLERANCE_SECONDS RETRIES HTTP_TIMEOUT \
         PULL_TIMEOUT HEAL_INTERVAL_HOURS HEAL_TIMEOUT; do
  [[ "${!n}" =~ ^[1-9][0-9]{0,6}$ ]] || die "$n must be a positive whole number (got: ${!n})"
done
[[ "$LAG_HEAL_HOURS" =~ ^[0-9]{1,4}$ ]] || die "LAG_HEAL_HOURS must be a whole number (got: $LAG_HEAL_HOURS)"
[[ "$HEAL_UNIT" =~ ^[a-zA-Z0-9@_.-]+\.service$ ]] || die "bad HEAL_UNIT"
[[ "$IMAGESCAN_HEAL_UNIT" =~ ^[a-zA-Z0-9@_.-]+\.service$ ]] || die "bad IMAGESCAN_HEAL_UNIT"
[[ "$SKEW_MAX_SECONDS" =~ ^[0-9]{1,6}$ ]] || die "SKEW_MAX_SECONDS must be a whole number (got: $SKEW_MAX_SECONDS)"
[[ "$BACKOFF_SECONDS" =~ ^[0-9]{1,3}(\.[0-9]+)?$ ]] || die "BACKOFF_SECONDS must be a number (got: $BACKOFF_SECONDS)"
valid_label "$HOST_LABEL" || die "bad HOST_LABEL"
[[ "$CONTAINER" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$ ]] || die "bad CONTAINER"
[ -n "$BUILD_TEXTFILE" ] || BUILD_TEXTFILE="$TEXTFILE_DIR/pft_upgradewatch_$CONTAINER.prom"
[ -n "$DIGEST_STAMP" ] || DIGEST_STAMP="$DATA_DIR/digest-last"
[ -n "$HEAL_STATE" ] || HEAL_STATE="$DATA_DIR/heal-state.json"
[ -n "$HEAL_LOCK" ] || HEAL_LOCK="$DATA_DIR/heal.lock"
[ -n "$HEAL_JOURNAL" ] || HEAL_JOURNAL="$DATA_DIR/heal.jsonl"
LIB="${PFT_UW_LIB:-/usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py}"
DOCKER="${PFT_UW_DOCKER:-docker}"
SYSTEMCTL="${PFT_UW_SYSTEMCTL:-systemctl}"
OBS="$DATA_DIR/last-obs.json"

# config JSON for the helper (every value passes through jq, so no quoting issues)
cfg_json() {
  jq -n --arg host "$HOST_LABEL" --arg feeds "$FEEDS" --arg container "$CONTAINER" --arg bt "$BUILD_TEXTFILE" \
    --arg vc "$VULNSCAN_CACHE" --arg ic "$IMAGESCAN_CACHE" --arg rpc "$FOUNDATION_RPC" --arg reg "$REGISTRY_URL" \
    --arg docker "$DOCKER" --argjson q "$QUIET_AGE_HOURS" --argjson g "$STALE_GRACE_HOURS" \
    --argjson fm "$FETCH_MAX_AGE_HOURS" --argjson tol "$CONTENT_TOLERANCE_SECONDS" --argjson sk "$SKEW_MAX_SECONDS" \
    --argjson r "$RETRIES" --argjson b "$BACKOFF_SECONDS" --argjson t "$HTTP_TIMEOUT" \
    --argjson lh "$LAG_HEAL_HOURS" --argjson hi "$HEAL_INTERVAL_HOURS" --arg hs "$HEAL_STATE" \
    --arg ub "${PFT_UW_UBUNTU_BASE:-https://security-metadata.canonical.com/oval}" \
    --arg dt "${PFT_UW_DEBIAN_TRACKER_URL:-https://security-tracker.debian.org/tracker/data/json}" \
    --arg dob "${PFT_UW_DEBIAN_OVAL_BASE:-https://www.debian.org/security/oval}" \
    --arg gb "${PFT_UW_GO_BASE:-https://vuln.go.dev}" \
    '{host: $host, feeds: $feeds, container: $container, build_textfile: $bt, vulnscan_cache: $vc,
      imagescan_cache: $ic, foundation_rpc: $rpc, registry_url: $reg, docker: $docker, quiet_age_hours: $q,
      stale_grace_hours: $g, fetch_max_age_hours: $fm, content_tolerance_seconds: $tol, skew_max_seconds: $sk,
      retries: $r, backoff_seconds: $b, http_timeout: $t, ubuntu_base: $ub, debian_tracker_url: $dt,
      debian_oval_base: $dob, go_base: $gb, lag_heal_hours: $lh, heal_interval_hours: $hi, heal_state: $hs}'
}

# put_textfile DIR NAME CONTENT: validate, then atomic rename
put_textfile() {
  local tmp why
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  printf '%s' "$3" > "$tmp" || { rm -f "$tmp"; return 1; }
  if [ "$(stat -c %s "$tmp")" -gt "$MAX_BYTES" ]; then rm -f "$tmp"; echo "textfile over $MAX_BYTES bytes"; return 1; fi
  if ! why="$(python3 -I "$LIB" validate "$tmp" "$HOST_LABEL")"; then rm -f "$tmp"; echo "invalid textfile: $why"; return 1; fi
  if chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

# collect_obs TEXTFILE_DIR T0: observations into $OBS; on failure write up 0 and exit 2
collect_obs() {
  local cfg err
  cfg="$(mktemp "$DATA_DIR/.cfg.XXXXXX")" || die "cannot create a temp file in $DATA_DIR"
  cfg_json > "$cfg" || { rm -f "$cfg"; die "cannot build the helper config"; }
  local -a nowarg=()
  [ -n "${PFT_UW_NOW:-}" ] && nowarg=(--now "$PFT_UW_NOW")
  if ! err="$(python3 -I "$LIB" collect --config "$cfg" --out "$OBS" "${nowarg[@]}" 2>&1)"; then
    rm -f "$cfg"
    echo "collect failed: $err"
    put_textfile "$1" "pft_upstreamwatch_$HOST_LABEL.prom" "$(python3 -I "$LIB" down "$HOST_LABEL" --now "$2")" \
      || echo "cannot write the up 0 textfile"
    exit 2
  fi
  rm -f "$cfg"
}

# heal_log FEED EVENT REASON [RC]: one JSON line in HEAL_JOURNAL (last 1000 kept) and on stdout
heal_log() {
  local line
  line="$(jq -cn --argjson t "$(now)" --arg f "$1" --arg e "$2" --arg r "$3" --argjson rc "${4:-0}" \
    '{epoch: $t, feed: $f, event: $e, reason: $r, rc: $rc}')" || return 0
  echo "heal: $1 $2 - $3${4:+ (rc $4)}"
  { tail -n 999 "$HEAL_JOURNAL" 2>/dev/null; echo "$line"; } > "$HEAL_JOURNAL.tmp" && mv -f "$HEAL_JOURNAL.tmp" "$HEAL_JOURNAL"
}

# heal TEXTFILE_DIR T0 -> rc 0 if nothing was started, 10 if a heal ran (the caller re-renders from $OBS)
heal() {
  local maint=0 busy="" plan d key fetcher feeds action reason u unit out hrc lags result ran=0 mrc
  # shellcheck disable=SC2086 # MAINT_CMD / *_BUSY_UNITS are word lists from the root-owned conf
  $MAINT_CMD > /dev/null 2>&1; mrc=$?
  [ "$mrc" -eq 1 ] || maint=1  # 0 active, 2 malformed flag, anything else unknown: all block the heal
  # shellcheck disable=SC2086
  for u in $HEAL_BUSY_UNITS; do "$SYSTEMCTL" is-active --quiet "$u" && busy+="vulnscan,"; done
  # shellcheck disable=SC2086
  for u in $IMAGESCAN_HEAL_BUSY_UNITS; do "$SYSTEMCTL" is-active --quiet "$u" && busy+="imagescan,"; done
  plan="$(python3 -I "$LIB" heal-plan --obs "$OBS" --now "$(now)" --maint "$maint" --busy "${busy%,}")" \
    || { echo "heal: planning failed"; return 0; }
  [ -n "$plan" ] || return 0
  while IFS= read -r d; do
    key="$(jq -r .feed <<< "$d")"; fetcher="$(jq -r .fetcher <<< "$d")"; feeds="$(jq -c .feeds <<< "$d")"
    action="$(jq -r .action <<< "$d")"; reason="$(jq -r .reason <<< "$d")"
    if [ "$action" != heal ]; then heal_log "$key" skip "$reason"; continue; fi
    case "$fetcher" in
      vulnscan) unit="$HEAL_UNIT" ;;
      imagescan) unit="$IMAGESCAN_HEAL_UNIT" ;;
      *) heal_log "$key" skip "no heal unit for fetcher $fetcher"; continue ;;
    esac
    exec 8> "$HEAL_LOCK" || { heal_log "$key" skip "locked: cannot open $HEAL_LOCK"; continue; }
    if ! flock -n 8; then heal_log "$key" skip "locked: another heal holds $HEAL_LOCK"; exec 8>&-; continue; fi
    # the start is persisted BEFORE the unit runs: a crash or timeout still counts against the rate limit
    python3 -I "$LIB" heal-record --state "$HEAL_STATE" --feed "$key" --now "$(now)" --result started \
      --note "$reason" > /dev/null || { heal_log "$key" skip "cannot write $HEAL_STATE"; exec 8>&-; continue; }
    heal_log "$key" start "$reason; systemctl start $unit"
    out="$(timeout "$HEAL_TIMEOUT" "$SYSTEMCTL" start "$unit" 2>&1)"; hrc=$?
    ran=1
    collect_obs "$1" "$2"
    if [ "$hrc" -ne 0 ]; then
      result=failed; reason="systemctl start $unit failed: $(head -c 150 <<< "$out" | tr '\n' ' ')"
    else
      # healed only if EVERY feed of this decision is back at lag 0
      lags="$(python3 -I "$LIB" render --obs "$OBS" --format json \
        | jq -r --argjson fs "$feeds" '[.feeds[] | select(.name as $n | $fs | index($n)) | "\(.name)=\(.lag)"] | join(" ")')"
      if [ -n "$lags" ] && ! grep -qvE '=0$' <<< "${lags// /$'\n'}"; then result=healed; reason="lag 0 after the refetch ($lags)"
      else result=still_lagging; reason="lag after the refetch: ${lags:-unknown} s (upstream cache still old?)"; fi
    fi
    python3 -I "$LIB" heal-record --state "$HEAL_STATE" --feed "$key" --now "$(now)" --result "$result" \
      --rc "$hrc" --note "$reason" --obs "$OBS" > /dev/null || echo "heal: cannot record the result"
    heal_log "$key" "$result" "$reason" "$hrc"
    exec 8>&-
  done <<< "$plan"
  [ "$ran" = 0 ] || return 10
  return 0
}

run() {
  local tdir="$TEXTFILE_DIR" t0 prom text err rc=0 doheal=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --textfile-dir) tdir="${2:?--textfile-dir needs a directory}"; shift ;;
      --no-heal) doheal=0 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  mkdir -p "$DATA_DIR" || die "cannot create $DATA_DIR"
  t0="$(now)"
  collect_obs "$tdir" "$t0"
  [ "$doheal" = 0 ] || heal "$tdir" "$t0"
  text="$(python3 -I "$LIB" render --obs "$OBS" --format text)" || die "render failed"
  prom="$(python3 -I "$LIB" render --obs "$OBS" --format prom)" || die "render failed"
  if ! { python3 -I "$LIB" render --obs "$OBS" --format json > "$DATA_DIR/last-report.json.tmp" \
         && mv -f "$DATA_DIR/last-report.json.tmp" "$DATA_DIR/last-report.json"; }; then
    die "render failed"
  fi
  printf '%s\n' "$text"
  if ! err="$(put_textfile "$tdir" "pft_upstreamwatch_$HOST_LABEL.prom" "$prom")"; then
    die "textfile not written: $err"
  fi
  grep -q -- '-> PAGE' <<< "$text" && rc=1
  exit "$rc"
}

report() {
  local obs="$OBS" fmt=text
  while [ $# -gt 0 ]; do
    case "$1" in
      --obs) obs="${2:?--obs needs a file}"; shift ;;
      --format) fmt="${2:?--format needs text|json|prom}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  python3 -I "$LIB" render --obs "$obs" --format "$fmt"
}

pull() {
  local tmp why
  [ $# -eq 0 ] || die "pull takes no arguments (PEER_LABEL in $CONF)"
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-upstreamwatch-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_upstreamwatch_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_upstreamwatch_$PEER_LABEL.prom failed" 1
  fi
  if [ "$(stat -c %s "$tmp")" -gt "$MAX_BYTES" ]; then rm -f "$tmp"; die "peer textfile over $MAX_BYTES bytes" 2; fi
  if ! why="$(python3 -I "$LIB" validate "$tmp" "$PEER_LABEL")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_upstreamwatch_$PEER_LABEL.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

# digest [--dry-run] [--force]: one low-priority ntfy summary per UTC day of the digest-only upstreamwatch alerts
digest() {
  local dry=false force=false day out lines title body
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) dry=true ;;
      --force) force=true ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  day="$(date -u +%F)"
  if ! $force && [ "$(cat "$DIGEST_STAMP" 2>/dev/null)" = "$day" ]; then echo "digest: already sent for $day"; return 0; fi
  out="$(curl -fsS --max-time 15 "$PROM_URL/api/v1/query" --data-urlencode \
    'query=sum by (alertname, host, feed) (count_over_time(ALERTS{alertname=~"PFTUpstreamFeedQuiet|PFTUpstreamFeedLagging|PFTUpstreamReleaseAvailable",alertstate="firing"}[24h:1m]))')" \
    || die "Prometheus query failed ($PROM_URL)" 1
  # jq -e passes on empty input: test non-empty first (dead endpoint control in the tests)
  if [ -z "$out" ] || ! jq -e '.status == "success"' <<< "$out" > /dev/null; then die "unexpected Prometheus answer" 1; fi
  lines="$(jq -r '.data.result | sort_by(.metric.alertname, .metric.host, .metric.feed) | .[]
    | "\(.metric.alertname | sub("^PFTUpstream"; "")) \(.metric.feed // "postfiatd") on \(.metric.host // "?"): \(.value[1]) min"' <<< "$out")" \
    || die "unexpected Prometheus answer" 1
  if [ -z "$lines" ] && ! $force; then echo "digest: no PFTUpstreamFeedQuiet/FeedLagging/ReleaseAvailable in the last 24 h, nothing to send"; return 0; fi
  title="Upstream feeds/releases digest $day"
  body="$(printf '%s\n%s\n%s\n' "Digest-only upstreamwatch alerts in the last 24 h, minutes firing (not paged):" \
    "${lines:-none}" "FeedQuiet = upstream has not republished; our copy is its latest. FeedLagging = our copy lags upstream within the grace period (bounded heal). Local faults page as PFTUpstreamFeedLocalStale / FetchFailing.")"
  if $dry; then printf '%s\n%s\n' "$title" "$body"; return 0; fi
  local NTFY_SERVER="" NTFY_TOPIC="" NTFY_TOKEN=""
  if [ -f "$NTFY_ENV" ]; then
    [ "$(stat -c %u "$NTFY_ENV")" = "$(id -u)" ] || die "$NTFY_ENV is not owned by uid $(id -u)"
    # shellcheck disable=SC1090
    . "$NTFY_ENV"
  fi
  if [ -z "$NTFY_SERVER" ] || [ -z "$NTFY_TOPIC" ]; then die "NTFY_SERVER/NTFY_TOPIC not set in $NTFY_ENV"; fi
  local -a auth=()
  [ -n "$NTFY_TOKEN" ] && auth=(-H "Authorization: Bearer $NTFY_TOKEN")
  curl -fsS --max-time 20 -o /dev/null "${auth[@]}" -H "Title: $title" -H "Priority: low" -H "Tags: satellite" \
    --data-binary "$body" "${NTFY_SERVER%/}/$NTFY_TOPIC" || die "ntfy send failed" 1
  mkdir -p "$(dirname "$DIGEST_STAMP")" && echo "$day" > "$DIGEST_STAMP"
  echo "digest: sent for $day ($(wc -l <<< "$body") lines)"
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  run) run "$@" ;;
  report) report "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-upstreamwatch validate FILE HOST"; valid_label "$2" || die "bad host label"
            why="$(python3 -I "$LIB" validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  digest) digest "$@" ;;
  version) echo "pft-upstreamwatch $VERSION" ;;
  *) die "usage: pft-upstreamwatch run|report|pull|validate|digest|version (see the header of this script)" ;;
esac
