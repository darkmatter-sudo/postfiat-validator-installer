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
#         zip CRCs + index/db.json / JSON with > 1000 source packages), read its own timestamp, and only then move
#         it into CACHE_DIR/feeds and record file, sha256, url, timestamp_epoch, fetched_epoch in feeds.json
#         (atomic). A failed feed keeps its previous entry; the scan's age check decides whether it is still usable.
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
#   (300), SAVE_TIMEOUT (1800), PULL_SSH, PULL_TIMEOUT (30), ACCEPT_FILE (/etc/pft-imagescan.accept).
# Test hooks: PFT_IS_DOCKER PFT_IS_CURL PFT_IS_LIB (commands/paths), PFT_IS_NOW (epoch).
# shellcheck disable=SC2016
set -uo pipefail
umask 022
VERSION=1.0.0
EXTRACT_VERSION=e1

HOST_LABEL=validator; PEER_LABEL=sentry; FEEDS="ubuntu-jammy ubuntu-noble debian go"
MAX_FEED_AGE_DAYS=7; MAX_CONTENT_AGE_DAYS=30; CACHE_DIR=/var/cache/pft-imagescan
TEXTFILE_DIR=/var/lib/pft-exporter/textfile; REMOTE_DIR=/var/lib/pft-exporter/textfile
FETCH_TIMEOUT=300; SAVE_TIMEOUT=1800; PULL_SSH=""; PULL_TIMEOUT=30; ACCEPT_FILE=/etc/pft-imagescan.accept
MAX_BYTES=262144

die() { printf 'pft-imagescan: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { if [ -n "${PFT_IS_NOW:-}" ]; then echo "$PFT_IS_NOW"; else date -u +%s; fi; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
sha() { sha256sum < "$1" | cut -c1-64; }

CONF="${PFT_IS_CONF:-/etc/pft-imagescan.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|PEER_LABEL|FEEDS|MAX_FEED_AGE_DAYS|MAX_CONTENT_AGE_DAYS|CACHE_DIR|TEXTFILE_DIR|REMOTE_DIR|FETCH_TIMEOUT|SAVE_TIMEOUT|PULL_SSH|PULL_TIMEOUT|ACCEPT_FILE)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi
for n in MAX_FEED_AGE_DAYS MAX_CONTENT_AGE_DAYS FETCH_TIMEOUT SAVE_TIMEOUT PULL_TIMEOUT; do
  [[ "${!n}" =~ ^[1-9][0-9]{0,5}$ ]] || die "$n must be a positive whole number (got: ${!n})"
done
DOCKER="${PFT_IS_DOCKER:-docker}"
CURL="${PFT_IS_CURL:-curl}"
LIB="${PFT_IS_LIB:-/usr/local/lib/pft-imagescan/imagescan_lib.py}"

feed_def() { # NAME -> "KIND URL FILE" (rc 1: unknown feed name)
  case "$1" in
    ubuntu-[a-z]*) echo "ubuntu-oval https://security-metadata.canonical.com/oval/oci.com.ubuntu.${1#ubuntu-}.usn.oval.xml.bz2 oci.com.ubuntu.${1#ubuntu-}.usn.oval.xml.bz2" ;;
    debian) echo "debian-tracker https://security-tracker.debian.org/tracker/data/json debian-tracker.json" ;;
    go) echo "go-osv https://vuln.go.dev/vulndb.zip vulndb.zip" ;;
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

fetch() {
  local fdir="$CACHE_DIR/feeds" name kind url file tmp code ts lm out="" fails=0 entries="" t
  mkdir -p "$fdir" || { echo "cannot create $fdir"; return 1; }
  tmp="$(mktemp -d "$fdir/.fetch.XXXXXX")" || { echo "cannot create a temp dir"; return 1; }
  for name in $FEEDS; do
    read -r kind url file <<< "$(feed_def "$name")" || { out+="$name: unknown feed; "; fails=$((fails + 1)); continue; }
    t="$(now)"
    code="$("$CURL" -sS -L --compressed --max-time "$FETCH_TIMEOUT" -H 'Cache-Control: no-cache' -D "$tmp/$file.hdr" \
            -o "$tmp/$file" -w '%{http_code}' "$url" 2> "$tmp/err")"
    if [ "$code" != 200 ]; then
      out+="$name: FAILED (HTTP ${code:-none}: $(head -c 120 "$tmp/err")); "; fails=$((fails + 1)); continue
    fi
    lm="$(tr -d '\r' < "$tmp/$file.hdr" | sed -n 's/^[Ll]ast-[Mm]odified: //p' | tail -1)"
    if ! ts="$(check_feed "$kind" "$tmp/$file" "$lm")"; then
      out+="$name: REFUSED ($ts); "; fails=$((fails + 1)); continue
    fi
    entries+="$name $kind $file $(sha "$tmp/$file") $ts $t $url"$'\n'
    out+="$name: fetched (own timestamp $(date -u -d "@$ts" +%FT%TZ)); "
  done
  if [ -n "$entries" ]; then
    # merge: new entries replace old ones; files are moved in before feeds.json is replaced
    if ! printf '%s' "$entries" | python3 -I -c '
import json, os, sys
fdir, tmp = sys.argv[1], sys.argv[2]
p = os.path.join(fdir, "feeds.json")
try:
    with open(p) as f:
        meta = json.load(f)
except (OSError, ValueError):
    meta = {"feeds": {}}
for line in sys.stdin.read().splitlines():
    name, kind, file, sha, ts, fetched, url = line.split(" ")
    os.replace(os.path.join(tmp, file), os.path.join(fdir, file))
    meta["feeds"][name] = {"kind": kind, "file": file, "sha256": sha, "timestamp_epoch": int(ts),
                           "fetched_epoch": int(fetched), "url": url}
with open(p + ".tmp", "w") as f:
    json.dump(meta, f, indent=1, sort_keys=True)
os.replace(p + ".tmp", p)' "$fdir" "$tmp"; then
      rm -rf "$tmp"; echo "${out}feeds.json update FAILED"; return 1
    fi
  fi
  rm -rf "$tmp"
  echo "${out%; }"
  [ "$fails" -eq 0 ]
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
  local accept=()
  [ -f "$ACCEPT_FILE" ] && accept=(--accept "$ACCEPT_FILE")
  python3 -I "$LIB" scan --inventory "$w"/inv/*.json --containers "$w/containers.json" --feeds "$CACHE_DIR/feeds" \
    --now "$t0" --max-age-days "$MAX_FEED_AGE_DAYS" --max-content-age-days "$MAX_CONTENT_AGE_DAYS" "${accept[@]}" \
    > "$w/scan.json" 2> "$w/err" || fail "$(head -1 "$w/err")"
  python3 -I "$LIB" render --scan "$w/scan.json"
  rc=$?
  [ "$rc" -le 1 ] || fail "render failed"
  python3 -I "$LIB" metrics --scan "$w/scan.json" --host "$HOST_LABEL" > "$w/m.prom" || fail "metrics failed"
  write_atomic "$TEXTFILE_DIR" "pft_imagescan_$HOST_LABEL.prom" \
    "$(base_metrics 1 "$t0" $(($(now) - t0)); cat "$w/m.prom")"$'\n' || fail "cannot write $TEXTFILE_DIR"
  cp -f "$w/scan.json" "$CACHE_DIR/last-scan.json.tmp" && mv -f "$CACHE_DIR/last-scan.json.tmp" "$CACHE_DIR/last-scan.json"
  if [ -n "$bundle" ]; then
    mkdir -p "$bundle/inv" "$bundle/feeds" || fail "cannot create bundle $bundle"
    if ! { cp -f "$w"/inv/*.json "$bundle/inv/" && cp -f "$w/containers.json" "$bundle/" && echo "$t0" > "$bundle/now" \
           && cp -f "$CACHE_DIR/feeds/feeds.json" "$bundle/feeds/"; }; then fail "bundle copy failed"; fi
    [ -f "$ACCEPT_FILE" ] && cp -f "$ACCEPT_FILE" "$bundle/accept"
    printf 'bundle: %s (inventories, containers, feeds.json, now; feed files stay in %s/feeds)\n' "$bundle" "$CACHE_DIR"
  fi
  exit "$rc"
}

# report --bundle DIR [--public] [--before SCAN] [--withheld FILE]: offline, from saved inputs only
report() {
  local b="" pub=() before=() wh=() w acc=() max_age="$MAX_FEED_AGE_DAYS" content="$MAX_CONTENT_AGE_DAYS"
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
  w="$(mktemp -d)" || die "cannot create a temp dir"
  # shellcheck disable=SC2064
  trap "rm -rf '$w'" EXIT
  python3 -I "$LIB" scan --inventory "$b"/inv/*.json --containers "$b/containers.json" --feeds "$b/feeds" \
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
  fetch) msg="$(fetch)"; rc=$?; echo "$msg"; exit $(( rc == 0 ? 0 : 1 )) ;;
  report) report "$@" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-imagescan validate FILE HOST"; valid_label "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-imagescan $VERSION (extract $EXTRACT_VERSION)" ;;
  *) die "usage: pft-imagescan scan|fetch|report|pull|validate|version (see the header of this script)" ;;
esac
