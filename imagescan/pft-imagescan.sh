#!/usr/bin/env bash
# pft-imagescan: offline vulnerability + provenance audit of the Docker IMAGES on a Post Fiat validator/sentry host.
# ../vulnscan audits the host's own packages, ../aptrust the host's apt sources, ../integrity the host's files; none
# of them looks inside the images that actually run postfiatd, Prometheus and Alertmanager. This does, without
# running them: every image is read with `docker image save` (layers applied in order, whiteouts honoured) and matched
# against pinned offline feeds (Canonical OCI USN OVAL per Ubuntu release, Debian security tracker, Go vuln DB).
#
# Usage: pft-imagescan scan [--no-fetch] [--textfile-dir DIR] [--bundle DIR]   inventory + scan + report + metrics
#        pft-imagescan fetch                     refresh the pinned feeds (CACHE_DIR/feeds, feeds.json)
#        pft-imagescan report --bundle DIR [--public] [--before SCAN.json] [--withheld FILE]
#                                                rebuild a report offline from a saved bundle (no docker, no network)
#        sudo pft-imagescan pull                 validator: copy the sentry's textfile (like ../vulnscan)
#        pft-imagescan validate FILE HOST        check a textfile before it is served
#
# Docker is only ever asked: `ps`, `inspect`, `image ls`, `image inspect`, `image save`. Never exec/run/create/
# start/pull (tests/test_imagescan.py runs the script against a docker stub that fails on anything else).
# Inventories are cached per image ID (CACHE_DIR/inv/<id>.<EXTRACT_VERSION>.json; an image ID names immutable
# content), so the 8 GB postfiatd image is read once per image change, not once per day.
#
#  fetch  for each feed in FEEDS: GET (Cache-Control: no-cache) into a temp file, check it fully (bzip2 stream /
#         zip CRCs + index/db.json / JSON with > 1000 source packages), read its own timestamp, then compare it with
#         the UPSTREAM clock (ubuntu/debian: the later of this response's Last-Modified and a no-cache HEAD's;
#         go: index/db.json "modified"). Within CONTENT_TOLERANCE_SECONDS -> outcome fresh. Otherwise (or when no
#         upstream clock can be read) ONE retry: cache-busting query (?pftcb=...), Cache-Control/Pragma no-cache and
#         a conditional on the copy just received (If-None-Match its ETag, else If-Modified-Since its Last-Modified;
#         304 = the cache still holds that copy). The newer complete copy is kept; outcome retried_fresh if it is
#         within tolerance of upstream, else still_behind ("not proven fresh"). A download older than the installed
#         copy never replaces it (the installed entry stays, only its outcome is updated). Only then is the file
#         moved into CACHE_DIR/feeds and file, sha256, url, timestamp_epoch, fetched_epoch, outcome, upstream_epoch,
#         upstream_clock, outcome_epoch, outcome_note recorded in feeds.json (atomic). A failed feed keeps its
#         previous entry; the scan's age check decides whether it is still usable. Standalone `fetch` (and
#         pft-imagescan-heal.service, which ../upstreamwatch starts) also refreshes the fetch-outcome series in this
#         host's textfile, leaving the scan series as they are.
#  scan   1. fetch (unless --no-fetch; a failed fetch is reported, not fatal).
#         2. inventory: running containers (name, configured ref, running image ID) and every local image.
#         3. imagescan_lib.py scan: refuses (exit 2) a feed whose sha256 differs from feeds.json, a feed fetched more
#            than MAX_FEED_AGE_DAYS ago or whose own timestamp is older than MAX_CONTENT_AGE_DAYS, an Ubuntu/Debian
#            image without its feed, and any version it cannot compare.
#         4. report on stdout, scan JSON in CACHE_DIR/last-scan.json, textfile metrics (atomic).
#         Exit 0 clean, 1 fixable high/critical finding in an image a container runs (not accepted) or drift,
#         2 scan error (metrics then carry up 0 and the previous last_success).
#  accept /etc/pft-imagescan.accept: "IMAGE_ID_PREFIX(>=12 hex) FINDING_ID YYYY-MM-DD reason..." per line, at most 90
#         days ahead. Accepted findings stay in the report and in pft_imagescan_findings but leave
#         pft_imagescan_fixable_high_critical (the alert input); expired lines count in pft_imagescan_accept_expired.
#
# Config: /etc/pft-imagescan.env (KEY=VALUE, root-owned; PFT_IS_CONF overrides): HOST_LABEL (validator), PEER_LABEL
#   (sentry), FEEDS ("ubuntu-jammy ubuntu-noble debian go"), MAX_FEED_AGE_DAYS (7), MAX_CONTENT_AGE_DAYS (30),
#   CACHE_DIR (/var/cache/pft-imagescan), TEXTFILE_DIR / REMOTE_DIR (/var/lib/pft-exporter/textfile), FETCH_TIMEOUT
#   (300), SAVE_TIMEOUT (1800), PULL_SSH, PULL_TIMEOUT (30), ACCEPT_FILE (/etc/pft-imagescan.accept),
#   CONTENT_TOLERANCE_SECONDS (21600, as ../upstreamwatch).
# Test hooks: PFT_IS_DOCKER PFT_IS_CURL PFT_IS_LIB (commands/paths), PFT_IS_NOW (epoch), PFT_IS_UBUNTU_BASE
#   PFT_IS_DEBIAN_URL PFT_IS_GO_BASE (fixture HTTP servers).
# shellcheck disable=SC2016
set -uo pipefail
umask 022
VERSION=1.1.0
EXTRACT_VERSION=e1

HOST_LABEL=validator; PEER_LABEL=sentry; FEEDS="ubuntu-jammy ubuntu-noble debian go"
MAX_FEED_AGE_DAYS=7; MAX_CONTENT_AGE_DAYS=30; CACHE_DIR=/var/cache/pft-imagescan
TEXTFILE_DIR=/var/lib/pft-exporter/textfile; REMOTE_DIR=/var/lib/pft-exporter/textfile
FETCH_TIMEOUT=300; SAVE_TIMEOUT=1800; PULL_SSH=""; PULL_TIMEOUT=30; ACCEPT_FILE=/etc/pft-imagescan.accept
CONTENT_TOLERANCE_SECONDS=21600
MAX_BYTES=262144

die() { printf 'pft-imagescan: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { if [ -n "${PFT_IS_NOW:-}" ]; then echo "$PFT_IS_NOW"; else date -u +%s; fi; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
sha() { sha256sum < "$1" | cut -c1-64; }

CONF="${PFT_IS_CONF:-/etc/pft-imagescan.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|PEER_LABEL|FEEDS|MAX_FEED_AGE_DAYS|MAX_CONTENT_AGE_DAYS|CACHE_DIR|TEXTFILE_DIR|REMOTE_DIR|FETCH_TIMEOUT|SAVE_TIMEOUT|PULL_SSH|PULL_TIMEOUT|ACCEPT_FILE|\
CONTENT_TOLERANCE_SECONDS)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi
for n in MAX_FEED_AGE_DAYS MAX_CONTENT_AGE_DAYS FETCH_TIMEOUT SAVE_TIMEOUT PULL_TIMEOUT CONTENT_TOLERANCE_SECONDS; do
  [[ "${!n}" =~ ^[1-9][0-9]{0,6}$ ]] || die "$n must be a positive whole number (got: ${!n})"
done
DOCKER="${PFT_IS_DOCKER:-docker}"
CURL="${PFT_IS_CURL:-curl}"
LIB="${PFT_IS_LIB:-/usr/local/lib/pft-imagescan/imagescan_lib.py}"
UBUNTU_BASE="${PFT_IS_UBUNTU_BASE:-https://security-metadata.canonical.com/oval}"
DEBIAN_URL="${PFT_IS_DEBIAN_URL:-https://security-tracker.debian.org/tracker/data/json}"
GO_BASE="${PFT_IS_GO_BASE:-https://vuln.go.dev}"

feed_def() { # NAME -> "KIND URL FILE" (rc 1: unknown feed name)
  case "$1" in
    ubuntu-[a-z]*) echo "ubuntu-oval $UBUNTU_BASE/oci.com.ubuntu.${1#ubuntu-}.usn.oval.xml.bz2 oci.com.ubuntu.${1#ubuntu-}.usn.oval.xml.bz2" ;;
    debian) echo "debian-tracker $DEBIAN_URL debian-tracker.json" ;;
    go) echo "go-osv $GO_BASE/vulndb.zip vulndb.zip" ;;
    *) return 1 ;;
  esac
}

# check_feed KIND FILE [LAST_MODIFIED] -> the feed's own timestamp (epoch) on stdout, rc 1 + reason if unusable
check_feed() {
  python3 -I - "$@" <<'PY'
import bz2, json, sys, zipfile
from email.utils import parsedate_to_datetime
kind, path = sys.argv[1], sys.argv[2]
lm = sys.argv[3] if len(sys.argv) > 3 else ""
try:
    if kind == "ubuntu-oval":
        with bz2.open(path, "rb") as f:
            while f.read(1 << 20):
                pass
    elif kind == "go-osv":
        with zipfile.ZipFile(path) as z:
            bad = z.testzip()
            if bad:
                raise ValueError(f"zip member {bad} fails its CRC")
            json.loads(z.read("index/db.json"))
    elif kind == "debian-tracker":
        with open(path, "rb") as f:
            d = json.load(f)
        if not isinstance(d, dict) or len(d) < 1000:
            raise ValueError("tracker JSON has fewer than 1000 source packages")
        if not lm:
            raise ValueError("no Last-Modified header (the tracker JSON has no timestamp of its own)")
        print(int(parsedate_to_datetime(lm).timestamp()))
        sys.exit(0)
except (OSError, EOFError, ValueError, KeyError, zipfile.BadZipFile) as e:
    print(f"{kind} feed unusable: {e}")
    sys.exit(1)
PY
  local rc=$?
  [ "$rc" -eq 0 ] || return 1
  [ "$1" = debian-tracker ] && return 0
  python3 -I "$LIB" feedts "$1" "$2" 2>&1 || return 1
}

# get URL DEST [CURL ARGS...] -> HTTP code on stdout (body DEST, headers DEST.hdr, curl errors DEST.err)
get() {
  local u="$1" d="$2"; shift 2
  "$CURL" -sS -L --compressed --max-time "$FETCH_TIMEOUT" -H 'Cache-Control: no-cache' "$@" -D "$d.hdr" -o "$d" \
    -w '%{http_code}' "$u" 2> "$d.err"
}
# hdr FILE NAME -> the last value of header NAME (case-insensitive; with -L the final response's)
hdr() { tr -d '\r' < "$1" 2>/dev/null | sed -n "s/^$2: //Ip" | tail -1; }
http_epoch() { [ -n "$1" ] && date -u -d "$1" +%s 2>/dev/null; }

# upstream_clock KIND URL RESPONSE_LAST_MODIFIED -> "EPOCH SOURCE" (rc 1: no upstream clock readable)
upstream_clock() {
  local e1 e2 h m
  if [ "$1" = go-osv ]; then
    # vulndb.zip's Last-Modified moves on every rebuild; the content clock is index/db.json "modified"
    m="$("$CURL" -sS -L --max-time 60 -H 'Cache-Control: no-cache' "$GO_BASE/index/db.json" 2>/dev/null \
         | jq -r '.modified // empty' 2>/dev/null)"
    e1="$(http_epoch "$m")" || return 1
    echo "$e1 index_modified"; return 0
  fi
  h="$("$CURL" -sS -I -L --max-time 60 -H 'Cache-Control: no-cache' "$2" 2>/dev/null | tr -d '\r' \
       | sed -n 's/^last-modified: //Ip' | tail -1)"
  e1="$(http_epoch "$h")" || e1=""
  e2="$(http_epoch "$3")" || e2=""
  if [ -n "$e1" ] && { [ -z "$e2" ] || [ "$e1" -ge "$e2" ]; }; then echo "$e1 head_last_modified"; return 0; fi
  [ -n "$e2" ] || return 1
  echo "$e2 response_last_modified"
}

# installed_ts NAME -> timestamp_epoch of the installed copy (empty if none)
installed_ts() {
  python3 -I -c 'import json, sys
try:
    print(json.load(open(sys.argv[1]))["feeds"][sys.argv[2]]["timestamp_epoch"])
except (OSError, ValueError, KeyError, TypeError):
    pass' "$CACHE_DIR/feeds/feeds.json" "$1" 2>/dev/null
}

fetch() {
  local fdir="$CACHE_DIR/feeds" name kind url file tmp code ts lm etag out="" fails=0 entries="" t
  local ref refsrc r outcome note ru rcode rlm rts old action
  local -a cond
  mkdir -p "$fdir" || { echo "cannot create $fdir"; return 1; }
  tmp="$(mktemp -d "$fdir/.fetch.XXXXXX")" || { echo "cannot create a temp dir"; return 1; }
  for name in $FEEDS; do
    read -r kind url file <<< "$(feed_def "$name")" || { out+="$name: unknown feed; "; fails=$((fails + 1)); continue; }
    t="$(now)"
    code="$(get "$url" "$tmp/$file")"
    if [ "$code" != 200 ]; then
      out+="$name: FAILED (HTTP ${code:-none}: $(head -c 120 "$tmp/$file.err")); "; fails=$((fails + 1)); continue
    fi
    lm="$(hdr "$tmp/$file.hdr" last-modified)"; etag="$(hdr "$tmp/$file.hdr" etag)"
    if ! ts="$(check_feed "$kind" "$tmp/$file" "$lm")"; then
      out+="$name: REFUSED ($ts); "; fails=$((fails + 1)); continue
    fi
    ref=""; refsrc=""; note=""
    if r="$(upstream_clock "$kind" "$url" "$lm")"; then read -r ref refsrc <<< "$r"; fi
    if [ -n "$ref" ] && [ $((ref - ts)) -le "$CONTENT_TOLERANCE_SECONDS" ]; then
      outcome=fresh; note="own timestamp within $CONTENT_TOLERANCE_SECONDS s of $refsrc"
    else
      # ONE retry past the cache: unique query string, no-cache, conditional on the copy we were just given
      case "$url" in *\?*) ru="$url&pftcb=$t-$$" ;; *) ru="$url?pftcb=$t-$$" ;; esac
      cond=()
      if [ -n "$etag" ]; then cond=(-H "If-None-Match: $etag"); elif [ -n "$lm" ]; then cond=(-H "If-Modified-Since: $lm"); fi
      rcode="$(get "$ru" "$tmp/$file.retry" -H 'Pragma: no-cache' "${cond[@]}")"
      if [ "$rcode" = 304 ]; then
        note="retry HTTP 304 (the cache still holds that copy)"
      elif [ "$rcode" != 200 ]; then
        note="retry HTTP ${rcode:-none}"
      else
        rlm="$(hdr "$tmp/$file.retry.hdr" last-modified)"
        if ! rts="$(check_feed "$kind" "$tmp/$file.retry" "$rlm")"; then
          note="retry copy refused ($rts)"
        elif [ "$rts" -gt "$ts" ]; then
          mv -f "$tmp/$file.retry" "$tmp/$file"; ts="$rts"; lm="$rlm"; note="retry copy is newer, kept"
        else
          note="retry copy is not newer, first copy kept"
        fi
      fi
      if [ -z "$ref" ] && r="$(upstream_clock "$kind" "$url" "$lm")"; then read -r ref refsrc <<< "$r"; fi
      if [ -n "$ref" ] && [ $((ref - ts)) -le "$CONTENT_TOLERANCE_SECONDS" ]; then
        outcome=retried_fresh; note+="; own timestamp within $CONTENT_TOLERANCE_SECONDS s of $refsrc"
      elif [ -n "$ref" ]; then
        outcome=still_behind; note+="; own timestamp $((ref - ts)) s behind $refsrc"
      else
        outcome=still_behind; note+="; no upstream clock readable (not proven fresh)"
      fi
    fi
    # older-copy protection: a download older than the installed copy never replaces it
    action=replace; old="$(installed_ts "$name")"
    if [[ "$old" =~ ^[0-9]+$ ]] && [ "$ts" -lt "$old" ]; then
      action=keep; outcome=still_behind; note+="; download older than the installed copy, installed copy kept"
    fi
    entries+="$(jq -cn --arg n "$name" --arg k "$kind" --arg f "$file" --arg s "$(sha "$tmp/$file")" \
      --argjson ts "$ts" --argjson t "$t" --arg u "$url" --arg o "$outcome" --argjson ref "${ref:-0}" \
      --arg rs "${refsrc:-none}" --arg note "$note" --arg a "$action" --argjson oe "$(now)" \
      '{name: $n, kind: $k, file: $f, sha256: $s, timestamp_epoch: $ts, fetched_epoch: $t, url: $u, outcome: $o,
        upstream_epoch: $ref, upstream_clock: $rs, outcome_note: $note, outcome_epoch: $oe, action: $a}')"$'\n'
    if [ "$action" = keep ]; then
      out+="$name: $outcome (download own timestamp $(date -u -d "@$ts" +%FT%TZ) is older than the installed copy, kept installed); "
    else
      out+="$name: $outcome (own timestamp $(date -u -d "@$ts" +%FT%TZ)); "
    fi
  done
  if [ -n "$entries" ]; then
    # merge: new entries replace old ones (action keep: outcome fields only); files move in before feeds.json
    if ! printf '%s' "$entries" | python3 -I "$LIB" feedmerge "$fdir" "$tmp"; then
      rm -rf "$tmp"; echo "${out}feeds.json update FAILED"; return 1
    fi
  fi
  rm -rf "$tmp"
  echo "${out%; }"
  [ "$fails" -eq 0 ]
}

# fetch_textfile: replace the fetch-outcome series in this host's textfile (scan series untouched). No textfile yet
# (never scanned) = nothing to do: the first scan writes them.
fetch_textfile() {
  local f="$TEXTFILE_DIR/pft_imagescan_$HOST_LABEL.prom" body why t
  [ -f "$f" ] || { echo "textfile: $f absent (written by the first scan)"; return 0; }
  body="$(grep -v -E '^(# (HELP|TYPE) )?pft_imagescan_feed_(fetch_outcome|upstream_timestamp_seconds|outcome_timestamp_seconds)[{ ]' "$f"
          python3 -I "$LIB" fetchmetrics --feeds "$CACHE_DIR/feeds/feeds.json" --host "$HOST_LABEL")" \
    || { echo "textfile: fetchmetrics failed"; return 1; }
  t="$(mktemp "$TEXTFILE_DIR/.pft_imagescan_$HOST_LABEL.prom.XXXXXX")" || { echo "textfile: cannot write $TEXTFILE_DIR"; return 1; }
  printf '%s\n' "$body" > "$t" || { rm -f "$t"; echo "textfile: cannot write $t"; return 1; }
  if ! why="$(validate "$t" "$HOST_LABEL")"; then rm -f "$t"; echo "textfile: invalid ($why)"; return 1; fi
  if ! { chmod 644 "$t" && mv -f "$t" "$f"; }; then rm -f "$t"; echo "textfile: rename failed"; return 1; fi
  echo "textfile: fetch outcome series updated in $f"
}

# inventory WORK -> WORK/containers.json + WORK/inv/*.json; rc 1 + reason on stdout
inventory() {
  local w="$1" id ref n=0 cid crun key f tab=$'\t'
  mkdir -p "$w/inv" "$CACHE_DIR/inv" || { echo "cannot create inventory dirs"; return 1; }
  # a redirect into an unwritable cache fails in the shell, not in extract, and would leave $w/err empty
  [ -w "$CACHE_DIR/inv" ] || { echo "inventory cache $CACHE_DIR/inv is not writable by uid $(id -u)"; return 1; }
  "$DOCKER" ps --no-trunc -q > "$w/ps" 2> "$w/err" || { echo "docker ps failed: $(head -c 200 "$w/err")"; return 1; }
  : > "$w/containers.tsv"
  while read -r cid; do
    [ -n "$cid" ] || continue
    "$DOCKER" inspect --format "{{.Name}}$tab{{.Config.Image}}$tab{{.Image}}" "$cid" >> "$w/containers.tsv" 2> "$w/err" \
      || { echo "docker inspect $cid failed: $(head -c 200 "$w/err")"; return 1; }
  done < "$w/ps"
  "$DOCKER" image ls --no-trunc --format "{{.Repository}}:{{.Tag}}$tab{{.ID}}" > "$w/images.tsv" 2> "$w/err" \
    || { echo "docker image ls failed: $(head -c 200 "$w/err")"; return 1; }
  # running image IDs that no tag points at any more are scanned by ID (that is what is running)
  while IFS=$'\t' read -r _ _ crun; do
    grep -qF "$tab$crun" "$w/images.tsv" || printf '%s\t%s\n' "$crun" "$crun" >> "$w/images.tsv"
  done < "$w/containers.tsv"
  python3 -I -c 'import json, sys
out = []
for line in open(sys.argv[1]):
    name, ref, img = line.rstrip("\n").split("\t")
    out.append({"name": name.lstrip("/"), "ref": ref, "image_id": img})
json.dump(out, open(sys.argv[2], "w"), indent=1, sort_keys=True)' "$w/containers.tsv" "$w/containers.json" \
    || { echo "cannot write containers.json"; return 1; }
  sort -u "$w/images.tsv" > "$w/images.sorted"
  while IFS=$'\t' read -r ref id; do
    [ -n "$id" ] || continue
    [ "$ref" = "<none>:<none>" ] && ref="$id"
    [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "unexpected image ID: $id"; return 1; }
    n=$((n + 1)); key="${id#sha256:}"; f="$CACHE_DIR/inv/$key.$EXTRACT_VERSION.json"
    "$DOCKER" image inspect "$id" > "$w/inspect.json" 2> "$w/err" || { echo "docker image inspect $ref failed"; return 1; }
    if [ ! -s "$f" ] || ! python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' "$f" 2>/dev/null; then
      if ! timeout "$SAVE_TIMEOUT" "$DOCKER" image save "$id" 2> "$w/err" \
           | python3 -I "$LIB" extract --ref "$ref" --image-id "$id" --inspect "$w/inspect.json" > "$f.tmp" 2>> "$w/err"; then
        rm -f "$f.tmp"; echo "extract of $ref failed: $(tail -c 300 "$w/err" | tr '\n' ' ')"; return 1
      fi
      mv -f "$f.tmp" "$f"
    fi
    # the same image ID can carry several tags: one inventory per ref, content from the per-ID cache
    python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1])); d["ref"] = sys.argv[2]
json.dump(d, open(sys.argv[3], "w"), indent=1, sort_keys=True)' "$f" "$ref" "$w/inv/$n.json" \
      || { echo "cannot write inventory for $ref"; return 1; }
  done < "$w/images.sorted"
  [ "$n" -gt 0 ] || { echo "no images"; return 1; }
}

write_atomic() { # DIR NAME CONTENT
  local t
  t="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if ! { printf '%s' "$3" > "$t" && chmod 644 "$t" && mv -f "$t" "$1/$2"; }; then rm -f "$t"; return 1; fi
}

# base_metrics UP RUN_TS DURATION -> the always-present samples
base_metrics() {
  local L="host=\"$HOST_LABEL\"" last
  last="$(sed -n "s/^pft_imagescan_last_success_timestamp_seconds{$L} //p" "$TEXTFILE_DIR/pft_imagescan_$HOST_LABEL.prom" 2>/dev/null)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  [ "$1" = 1 ] && last="$2"
  cat <<EOF
# HELP pft_imagescan_up 1 if the last scan completed (fresh pinned feeds, every image inventoried and matched).
# TYPE pft_imagescan_up gauge
pft_imagescan_up{$L} $1
# HELP pft_imagescan_last_run_timestamp_seconds When the last scan ran (success or not).
# TYPE pft_imagescan_last_run_timestamp_seconds gauge
pft_imagescan_last_run_timestamp_seconds{$L} $2
# HELP pft_imagescan_last_success_timestamp_seconds When the last successful scan ran (0 = never).
# TYPE pft_imagescan_last_success_timestamp_seconds gauge
pft_imagescan_last_success_timestamp_seconds{$L} $last
# HELP pft_imagescan_scan_duration_seconds Wall time of the last scan.
# TYPE pft_imagescan_scan_duration_seconds gauge
pft_imagescan_scan_duration_seconds{$L} $3
EOF
}

scan() {
  local nofetch=0 bundle="" t0 w fetchmsg="skipped (--no-fetch)" why rc
  while [ $# -gt 0 ]; do
    case "$1" in
      --no-fetch) nofetch=1 ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --bundle) bundle="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_label "$HOST_LABEL" || die "bad HOST_LABEL"
  t0="$(now)"
  w="$(mktemp -d)" || die "cannot create a temp dir"
  # shellcheck disable=SC2064 # expand $w now
  trap "rm -rf '$w'" EXIT
  fail() {
    write_atomic "$TEXTFILE_DIR" "pft_imagescan_$HOST_LABEL.prom" "$(base_metrics 0 "$t0" $(($(now) - t0)))"$'\n' \
      || printf 'pft-imagescan: cannot write %s\n' "$TEXTFILE_DIR" >&2
    printf 'RESULT: ERROR - %s: up 0 -> exit 2\n' "$1"
    die "$1"
  }
  [ -r "$LIB" ] || fail "helper $LIB missing"
  mkdir -p "$CACHE_DIR" || fail "cannot create $CACHE_DIR"
  if [ "$nofetch" = 0 ]; then fetchmsg="$(fetch)" || fetchmsg="FAILED: $fetchmsg"; fi
  printf 'pft-imagescan scan - %s  host=%s  v%s\nfetch: %s\n' "$(date -u -d "@$t0" +%FT%TZ)" "$HOST_LABEL" "$VERSION" "$fetchmsg"
  why="$(inventory "$w")" || fail "inventory: $why"
  local accept=() invs=()
  [ -f "$ACCEPT_FILE" ] && accept=(--accept "$ACCEPT_FILE")
  # a host without images (or a public bundle whose every image is withheld) has no inventory: an unmatched glob
  # would reach the helper as a literal path
  shopt -s nullglob; invs=("$w"/inv/*.json); shopt -u nullglob
  python3 -I "$LIB" scan --inventory "${invs[@]}" --containers "$w/containers.json" --feeds "$CACHE_DIR/feeds" \
    --now "$t0" --max-age-days "$MAX_FEED_AGE_DAYS" --max-content-age-days "$MAX_CONTENT_AGE_DAYS" "${accept[@]}" \
    > "$w/scan.json" 2> "$w/err" || fail "$(head -1 "$w/err")"
  python3 -I "$LIB" render --scan "$w/scan.json"
  rc=$?
  [ "$rc" -le 1 ] || fail "render failed"
  python3 -I "$LIB" metrics --scan "$w/scan.json" --host "$HOST_LABEL" > "$w/m.prom" || fail "metrics failed"
  if [ -f "$CACHE_DIR/feeds/feeds.json" ]; then
    python3 -I "$LIB" fetchmetrics --feeds "$CACHE_DIR/feeds/feeds.json" --host "$HOST_LABEL" >> "$w/m.prom" \
      || fail "fetch metrics failed"
  fi
  write_atomic "$TEXTFILE_DIR" "pft_imagescan_$HOST_LABEL.prom" \
    "$(base_metrics 1 "$t0" $(($(now) - t0)); cat "$w/m.prom")"$'\n' || fail "cannot write $TEXTFILE_DIR"
  cp -f "$w/scan.json" "$CACHE_DIR/last-scan.json.tmp" && mv -f "$CACHE_DIR/last-scan.json.tmp" "$CACHE_DIR/last-scan.json"
  if [ -n "$bundle" ]; then
    mkdir -p "$bundle/inv" "$bundle/feeds" || fail "cannot create bundle $bundle"
    if ! { { [ "${#invs[@]}" = 0 ] || cp -f "${invs[@]}" "$bundle/inv/"; } && cp -f "$w/containers.json" "$bundle/" && echo "$t0" > "$bundle/now" \
           && cp -f "$CACHE_DIR/feeds/feeds.json" "$bundle/feeds/"; }; then fail "bundle copy failed"; fi
    [ -f "$ACCEPT_FILE" ] && cp -f "$ACCEPT_FILE" "$bundle/accept"
    printf 'bundle: %s (inventories, containers, feeds.json, now; feed files stay in %s/feeds)\n' "$bundle" "$CACHE_DIR"
  fi
  exit "$rc"
}

# report --bundle DIR [--public] [--before SCAN] [--withheld FILE]: offline, from saved inputs only
report() {
  local b="" pub=() before=() wh=() w acc=() invs=() max_age="$MAX_FEED_AGE_DAYS" content="$MAX_CONTENT_AGE_DAYS"
  while [ $# -gt 0 ]; do
    case "$1" in
      --bundle) b="${2:?}"; shift ;;
      --public) pub=(--public) ;;
      --before) before=(--before "${2:?}"); shift ;;
      --withheld) wh=(--withheld "${2:?}"); shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  if ! { [ -d "$b/inv" ] && [ -s "$b/now" ] && [ -s "$b/feeds/feeds.json" ]; }; then die "not a bundle: $b"; fi
  [ -f "$b/accept" ] && acc=(--accept "$b/accept")
  shopt -s nullglob; invs=("$b"/inv/*.json); shopt -u nullglob
  w="$(mktemp -d)" || die "cannot create a temp dir"
  # shellcheck disable=SC2064
  trap "rm -rf '$w'" EXIT
  python3 -I "$LIB" scan --inventory "${invs[@]}" --containers "$b/containers.json" --feeds "$b/feeds" \
    --now "$(cat "$b/now")" --max-age-days "$max_age" --max-content-age-days "$content" "${acc[@]}" \
    > "$w/scan.json" || exit 2
  python3 -I "$LIB" render --scan "$w/scan.json" "${pub[@]}" "${before[@]}" "${wh[@]}"
}

# validate FILE HOST -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" h="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v h="$h" '
    BEGIN { pre = "host=\"" h "\"" }
    /^# (HELP|TYPE) pft_imagescan_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_imagescan_[a-z_]+\{/) == 0) { printf "line %d: not a pft_imagescan_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_imagescan_up\{/) up = 1
      if ($0 ~ /^pft_imagescan_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_imagescan_up sample"; exit 1 }
      if (!ts) { print "no pft_imagescan_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  [ $# -eq 0 ] || die "pull takes no arguments (PEER_LABEL in $CONF)"
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-imagescan-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_imagescan_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_imagescan_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_imagescan_$PEER_LABEL.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  scan) scan "$@" ;;
  fetch) valid_label "$HOST_LABEL" || die "bad HOST_LABEL"
         msg="$(fetch)"; rc=$?; echo "$msg"
         fetch_textfile || rc=1
         exit $(( rc == 0 ? 0 : 1 )) ;;
  report) report "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-imagescan validate FILE HOST"; valid_label "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-imagescan $VERSION (extract $EXTRACT_VERSION)" ;;
  *) die "usage: pft-imagescan scan|fetch|report|pull|validate|version (see the header of this script)" ;;
esac
