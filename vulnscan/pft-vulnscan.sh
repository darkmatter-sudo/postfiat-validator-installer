#!/usr/bin/env bash
# pft-vulnscan: audit the installed Ubuntu 22.04 packages of a Post Fiat validator or sentry host against Canonical's
# Jammy USN OVAL feed (OpenSCAP), plus running-vs-installed kernel (reboot owed). Complements ../patch: pft-patch
# says which updates apt can install; pft-vulnscan says which published USNs/CVEs still apply to what is installed,
# including the ones apt cannot fix (fix only in Ubuntu Pro / ESM pockets).
#
# Usage: pft-vulnscan scan [--json] [--no-fetch] [--textfile-dir DIR]   fetch the feed if changed, evaluate, report
#        pft-vulnscan fetch                                             only refresh the cached feed
#        sudo pft-vulnscan pull                                         validator: copy the peer's textfile (see below)
#        pft-vulnscan validate FILE HOST                                exit 0 if FILE is an acceptable textfile for HOST
#        pft-vulnscan version
#
#  fetch  curl FEED_URL into CACHE_DIR/feed.xml.bz2 with the saved ETag (If-None-Match): 304 keeps the cached copy,
#         200 is accepted only if it decompresses as bzip2 and then replaces the cache atomically. CACHE_DIR/feed.meta
#         records sha256 (of the .bz2), fetched_at and last_checked (UTC epoch). A failed fetch keeps the cache.
#  scan   1. fetch (unless --no-fetch); if that fails a cached feed is still used (the age check below decides).
#         2. the cached .bz2 must match the sha256 in feed.meta (else exit 2: cache changed behind our back).
#         3. decompress, `oscap oval eval --results`, then vulnscan_parse.py: refuses (exit 2) a feed older than
#            MAX_FEED_AGE_DAYS by its own <oval:timestamp>, a corrupt/truncated feed, results that do not cover every
#            definition, any definition that evaluated to error/unknown, and a feed whose inventory check (Ubuntu
#            22.04 installed) is not true.
#         4. kernel: running `uname -r` vs the newest installed linux-image-<release> (dpkg, sort -V) and
#            /var/run/reboot-required. Either one = reboot owed.
#         Output: one table row per affected USN (severity, fix = archive | esm, CVE count, binary packages), the
#         kernel line and a RESULT line; --json prints one object (findings with installed/fixed versions).
#         Exit: 0 no affected USN and no reboot owed; 1 affected USNs and/or reboot owed; 2 scan error.
#         Every run (also a failed one) writes TEXTFILE_DIR/pft_vulnscan_HOST.prom atomically: up 0/1,
#         last_run/last_success timestamps (last_success carried over from the previous file on failure), feed
#         timestamp, affected USNs by severity and fix, affected CVEs, reboot owed, kernel outdated, duration.
#  pull   runs "$PULL_SSH cat -- REMOTE_DIR/pft_vulnscan_PEER.prom" (timeout PULL_TIMEOUT), validates it (only
#         pft_vulnscan_ samples whose first label is host="PEER", size <= MAX_BYTES) and renames it into
#         TEXTFILE_DIR. Exit 1 fetch failed, 2 validation failed (the old file stays, so a dead peer goes stale).
#
# Config: /etc/pft-vulnscan.env (KEY=VALUE, root-owned; PFT_VS_CONF overrides the path): HOST_LABEL (validator),
#   PEER_LABEL (sentry), FEED_URL (Canonical jammy USN OVAL .bz2), MAX_FEED_AGE_DAYS (7), CACHE_DIR
#   (/var/cache/pft-vulnscan), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), REMOTE_DIR (same), FETCH_TIMEOUT (120),
#   OSCAP_TIMEOUT (900), PULL_SSH, PULL_TIMEOUT (30).
# Test hooks: PFT_VS_OSCAP PFT_VS_CURL PFT_VS_DPKG_QUERY PFT_VS_PARSER (commands/paths), PFT_VS_NOW (epoch),
#   PFT_VS_UNAME_R (running kernel), PFT_VS_ROOT (prefix for /var/run/reboot-required).
# dpkg-query formats and python programs are single-quoted on purpose; /etc/os-release is read at run time.
# shellcheck disable=SC2016,SC1091
set -uo pipefail
umask 022
VERSION=1.0.0

HOST_LABEL=validator; PEER_LABEL=sentry
FEED_URL=https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2
MAX_FEED_AGE_DAYS=7; CACHE_DIR=/var/cache/pft-vulnscan; TEXTFILE_DIR=/var/lib/pft-exporter/textfile
REMOTE_DIR=/var/lib/pft-exporter/textfile; FETCH_TIMEOUT=120; OSCAP_TIMEOUT=900; PULL_SSH=""; PULL_TIMEOUT=30
MAX_BYTES=16384
CONF="${PFT_VS_CONF:-/etc/pft-vulnscan.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|PEER_LABEL|FEED_URL|MAX_FEED_AGE_DAYS|CACHE_DIR|TEXTFILE_DIR|REMOTE_DIR|FETCH_TIMEOUT|OSCAP_TIMEOUT|PULL_SSH|PULL_TIMEOUT)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi
OSCAP="${PFT_VS_OSCAP:-oscap}"
CURL="${PFT_VS_CURL:-curl}"
DPKG_QUERY="${PFT_VS_DPKG_QUERY:-dpkg-query}"
PARSER="${PFT_VS_PARSER:-/usr/local/lib/pft-vulnscan/vulnscan_parse.py}"
REBOOT_FILE="${PFT_VS_ROOT:-}/var/run/reboot-required"
SEVERITIES="critical high medium low negligible none unknown"

die() { printf 'pft-vulnscan: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { if [ -n "${PFT_VS_NOW:-}" ]; then echo "$PFT_VS_NOW"; else date -u +%s; fi; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
sha() { sha256sum < "$1" | cut -c1-64; }
meta_get() { sed -n "s/^$1=//p" "$CACHE_DIR/feed.meta" 2>/dev/null | head -1; }

# decompress SRC.bz2 DST -> rc 0, or rc 1 (not bzip2 / truncated)
unbz2() {
  python3 -I -c 'import bz2, shutil, sys
with bz2.open(sys.argv[1]) as s, open(sys.argv[2], "wb") as d:
    shutil.copyfileobj(s, d)' "$1" "$2" 2>/dev/null
}

# fetch -> rc 0 (stdout: "fetched" | "not modified"), rc 1 with the reason on stdout
fetch() {
  local tmp etag_args=() code
  mkdir -p "$CACHE_DIR" || { echo "cannot create $CACHE_DIR"; return 1; }
  tmp="$(mktemp -d "$CACHE_DIR/.fetch.XXXXXX")" || { echo "cannot create a temp dir in $CACHE_DIR"; return 1; }
  if [ -s "$CACHE_DIR/feed.xml.bz2" ] && [ -s "$CACHE_DIR/feed.etag" ]; then
    etag_args=(--etag-compare "$CACHE_DIR/feed.etag")
  fi
  code="$("$CURL" -sS -f --max-time "$FETCH_TIMEOUT" "${etag_args[@]}" --etag-save "$tmp/etag" \
          -o "$tmp/feed.xml.bz2" -w '%{http_code}' "$FEED_URL" 2> "$tmp/err")"
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "download failed (curl rc $rc, http ${code:-none}: $(head -c 200 "$tmp/err" | tr '\n' ' '))"; rm -rf "$tmp"; return 1
  fi
  if [ "$code" = 304 ]; then
    sed -i "s/^last_checked=.*/last_checked=$(now)/" "$CACHE_DIR/feed.meta"
    rm -rf "$tmp"; echo "not modified"; return 0
  fi
  if [ "$code" != 200 ]; then echo "unexpected HTTP $code"; rm -rf "$tmp"; return 1; fi
  if ! unbz2 "$tmp/feed.xml.bz2" "$tmp/check.xml"; then
    echo "downloaded file is not a complete bzip2 stream (cache kept)"; rm -rf "$tmp"; return 1
  fi
  printf 'sha256=%s\nfetched_at=%s\nlast_checked=%s\nurl=%s\n' "$(sha "$tmp/feed.xml.bz2")" "$(now)" "$(now)" "$FEED_URL" \
    > "$tmp/feed.meta"
  # the .bz2 first, its meta last: a crash in between leaves a sha mismatch, which scan refuses
  if ! { mv -f "$tmp/feed.xml.bz2" "$CACHE_DIR/feed.xml.bz2" && mv -f "$tmp/etag" "$CACHE_DIR/feed.etag" \
          && mv -f "$tmp/feed.meta" "$CACHE_DIR/feed.meta"; }; then
    echo "cannot update the cache"; rm -rf "$tmp"; return 1
  fi
  rm -rf "$tmp"; echo "fetched"
}

# kernel -> "running newest flag" (flag: present|absent)
kernel_state() {
  local running newest
  running="${PFT_VS_UNAME_R:-$(uname -r)}"
  newest="$("$DPKG_QUERY" -W -f='${Package} ${db:Status-Abbrev}\n' 'linux-image-[0-9]*' 2>/dev/null \
            | awk '$2 ~ /^[ih]i/ { sub(/^linux-image-/, "", $1); print $1 }' | sort -V | tail -1)"
  printf '%s %s %s\n' "$running" "${newest:--}" "$([ -e "$REBOOT_FILE" ] && echo present || echo absent)"
}

write_atomic() { # DIR NAME CONTENT
  local t
  t="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if ! { printf '%s' "$3" > "$t" && chmod 644 "$t" && mv -f "$t" "$1/$2"; }; then rm -f "$t"; return 1; fi
}

# metrics UP RUN_TS FEED_TS DURATION [PARSED_JSON REBOOT_OWED KERNEL_OUTDATED] -> textfile content on stdout
metrics() {
  local up="$1" ts="$2" fts="$3" dur="$4" js="${5:-}" owed="${6:-}" kout="${7:-}" L last
  L="host=\"$HOST_LABEL\""
  last="$(sed -n "s/^pft_vulnscan_last_success_timestamp_seconds{$L} //p" "$TEXTFILE_DIR/pft_vulnscan_$HOST_LABEL.prom" 2>/dev/null)"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  [ "$up" = 1 ] && last="$ts"
  cat <<EOF
# HELP pft_vulnscan_up 1 if the last scan completed (feed fresh and valid, every OVAL definition evaluated).
# TYPE pft_vulnscan_up gauge
pft_vulnscan_up{$L} $up
# HELP pft_vulnscan_last_run_timestamp_seconds When the last scan ran (success or not).
# TYPE pft_vulnscan_last_run_timestamp_seconds gauge
pft_vulnscan_last_run_timestamp_seconds{$L} $ts
# HELP pft_vulnscan_last_success_timestamp_seconds When the last successful scan ran (0 = never).
# TYPE pft_vulnscan_last_success_timestamp_seconds gauge
pft_vulnscan_last_success_timestamp_seconds{$L} $last
# HELP pft_vulnscan_feed_timestamp_seconds <oval:timestamp> of the cached USN OVAL feed (0 = unknown).
# TYPE pft_vulnscan_feed_timestamp_seconds gauge
pft_vulnscan_feed_timestamp_seconds{$L} $fts
# HELP pft_vulnscan_scan_duration_seconds Wall time of the last scan.
# TYPE pft_vulnscan_scan_duration_seconds gauge
pft_vulnscan_scan_duration_seconds{$L} $dur
EOF
  [ "$up" = 1 ] || return 0
  echo "# HELP pft_vulnscan_affected_usns USNs that apply to installed packages, by USN priority and where the fix is (archive = apt can install it, esm = Ubuntu Pro only)."
  echo "# TYPE pft_vulnscan_affected_usns gauge"
  python3 -I -c 'import json, sys
d = json.loads(sys.argv[1])
for s in sys.argv[3].split():
    for f in ("archive", "esm", "unknown"):
        print("pft_vulnscan_affected_usns{%s,severity=\"%s\",fix=\"%s\"} %d" % (sys.argv[2], s, f, d["by_severity"][s][f]))
print("# HELP pft_vulnscan_affected_cves Distinct CVEs of the affected USNs.")
print("# TYPE pft_vulnscan_affected_cves gauge")
print("pft_vulnscan_affected_cves{%s} %d" % (sys.argv[2], d["affected_cves"]))' "$js" "$L" "$SEVERITIES"
  cat <<EOF
# HELP pft_vulnscan_reboot_owed 1 if the running kernel is not the newest installed one or /var/run/reboot-required exists.
# TYPE pft_vulnscan_reboot_owed gauge
pft_vulnscan_reboot_owed{$L} $owed
# HELP pft_vulnscan_kernel_outdated 1 if a newer linux-image is installed than the running kernel.
# TYPE pft_vulnscan_kernel_outdated gauge
pft_vulnscan_kernel_outdated{$L} $kout
EOF
}

scan() {
  local json=0 nofetch=0 t0 t1 fetchmsg="skipped (--no-fetch)" work js err fts=0 rc
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=1 ;;
      --no-fetch) nofetch=1 ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_label "$HOST_LABEL" || die "bad HOST_LABEL"
  [[ "$MAX_FEED_AGE_DAYS" =~ ^[1-9][0-9]*$ ]] || die "bad MAX_FEED_AGE_DAYS"
  t0="$(now)"
  work="$(mktemp -d)" || die "cannot create a temp dir"
  # shellcheck disable=SC2064 # expand $work now
  trap "rm -rf '$work'" EXIT
  fail() { # MESSAGE: up 0 metrics, report, exit 2
    t1="$(now)"
    write_atomic "$TEXTFILE_DIR" "pft_vulnscan_$HOST_LABEL.prom" "$(metrics 0 "$t0" "$fts" $((t1 - t0)))"$'\n' \
      || printf 'pft-vulnscan: cannot write %s\n' "$TEXTFILE_DIR" >&2
    if [ "$json" = 1 ]; then
      python3 -I -c 'import json, sys; print(json.dumps({"ok": False, "host": sys.argv[1], "error": sys.argv[2], "exit_code": 2}))' \
        "$HOST_LABEL" "$1"
    else
      printf 'RESULT: ERROR - %s: up 0 -> exit 2\n' "$1"
    fi
    printf 'pft-vulnscan: %s\n' "$1" >&2
    exit 2
  }
  for c in "$OSCAP" python3; do command -v "$c" >/dev/null || fail "$c not installed"; done
  [ -r "$PARSER" ] || fail "parser $PARSER missing"
  if [ "$nofetch" = 0 ]; then
    fetchmsg="$(fetch)" || fetchmsg="FAILED: $fetchmsg (using the cached feed if there is one)"
  fi
  [ -s "$CACHE_DIR/feed.xml.bz2" ] || fail "no cached feed in $CACHE_DIR (fetch: $fetchmsg)"
  local want got; want="$(meta_get sha256)"; got="$(sha "$CACHE_DIR/feed.xml.bz2")"
  [ "$want" = "$got" ] || fail "cached feed sha256 $got does not match feed.meta (${want:-none})"
  unbz2 "$CACHE_DIR/feed.xml.bz2" "$work/feed.xml" || fail "cached feed is not a complete bzip2 stream"
  [ "$json" = 1 ] || printf 'pft-vulnscan scan - %s  host=%s  OS: %s\nfeed     %s\n         sha256 %s  fetch: %s\n' \
    "$(date -u -d "@$t0" +%FT%TZ)" "$HOST_LABEL" "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")" \
    "$FEED_URL" "$got" "$fetchmsg"
  timeout "$OSCAP_TIMEOUT" "$OSCAP" oval eval --results "$work/results.xml" "$work/feed.xml" > "$work/oscap.out" 2> "$work/oscap.err"
  rc=$?
  [ "$rc" -eq 0 ] || fail "oscap oval eval failed (rc $rc: $(grep -v '^$' "$work/oscap.err" | head -2 | tr '\n' ' '))"
  js="$(python3 -I "$PARSER" "$work/feed.xml" "$work/results.xml" --now "$t0" --max-age-days "$MAX_FEED_AGE_DAYS" 2> "$work/parse.err")"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    err="$(head -1 "$work/parse.err")"
    fts="$(sed -n 's/.*<oval:timestamp>\([^<]*\)<.*/\1/p' "$work/feed.xml" | head -1 | xargs -r -I{} date -u -d '{}Z' +%s 2>/dev/null)"
    [[ "$fts" =~ ^[0-9]+$ ]] || fts=0
    fail "${err:-parser rc $rc}"
  fi
  local running newest flag owed=0 kout=0 n
  read -r running newest flag <<< "$(kernel_state)"
  if [ "$newest" != - ] && [ "$running" != "$newest" ] \
     && [ "$(printf '%s\n%s\n' "$running" "$newest" | sort -V | tail -1)" = "$newest" ]; then kout=1; fi
  { [ "$kout" = 1 ] || [ "$flag" = present ]; } && owed=1
  n="$(python3 -I -c 'import json, sys; print(json.loads(sys.argv[1])["affected_usns"])' "$js")"
  fts="$(python3 -I -c 'import json, sys; print(json.loads(sys.argv[1])["feed"]["timestamp_epoch"])' "$js")"
  rc=0; { [ "$n" -gt 0 ] || [ "$owed" = 1 ]; } && rc=1
  t1="$(now)"
  write_atomic "$TEXTFILE_DIR" "pft_vulnscan_$HOST_LABEL.prom" "$(metrics 1 "$t0" "$fts" $((t1 - t0)) "$js" "$owed" "$kout")"$'\n' \
    || printf 'pft-vulnscan: cannot write %s\n' "$TEXTFILE_DIR" >&2
  python3 -I -c 'import json, sys
d = json.loads(sys.argv[1]); mode = sys.argv[2]
d.update(ok=True, host=sys.argv[3], exit_code=int(sys.argv[4]), feed_sha256=sys.argv[5], fetch=sys.argv[6],
         kernel={"running": sys.argv[7], "newest_installed": sys.argv[8], "reboot_required_flag": sys.argv[9] == "present",
                 "outdated": sys.argv[10] == "1", "reboot_owed": sys.argv[11] == "1"},
         scan_seconds=int(sys.argv[12]))
if mode == "1":
    print(json.dumps(d, sort_keys=True)); sys.exit(0)
fe = d["feed"]
print("oval     %d patch definitions, feed timestamp %s UTC (age %.1f h), evaluated in %d s"
      % (fe["patch_definitions"], fe["timestamp"], fe["age_seconds"] / 3600, d["scan_seconds"]))
if d["findings"]:
    print("%-14s %-10s %-8s %-5s %s" % ("USN", "SEVERITY", "FIX", "CVES", "PACKAGES (installed -> fixed)"))
    for f in d["findings"]:
        pk = ", ".join("%s %s -> %s" % (p["binary"], p["installed"], p["fixed"]) for p in f["packages"])
        print("%-14s %-10s %-8s %-5d %s" % (f["usn"] or f["id"], f["severity"], f["fix"], len(f["cves"]), pk))
k = d["kernel"]
print("kernel   running %s, newest installed %s, reboot-required flag %s -> reboot owed: %s"
      % (k["running"], k["newest_installed"], "present" if k["reboot_required_flag"] else "absent", "YES" if k["reboot_owed"] else "no"))
s = d["by_severity"]
parts = ", ".join("%d %s" % (sum(s[x].values()), x) for x in ("critical", "high", "medium", "low", "negligible", "none", "unknown"))
esm = sum(v["esm"] for v in s.values())
print("RESULT: %d affected USNs (%s; %d fixable only via Ubuntu Pro/ESM), %d CVEs; reboot owed: %s -> exit %d"
      % (d["affected_usns"], parts, esm, d["affected_cves"], "yes" if k["reboot_owed"] else "no", d["exit_code"]))' \
    "$js" "$json" "$HOST_LABEL" "$rc" "$got" "$fetchmsg" "$running" "$newest" "$flag" "$kout" "$owed" $((t1 - t0))
  exit "$rc"
}

# validate FILE HOST -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" h="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v h="$h" '
    BEGIN { pre = "host=\"" h "\"" }
    /^# (HELP|TYPE) pft_vulnscan_[a-z_]+ / { next }
    /^$/ { next }
    {
      if (match($0, /^pft_vulnscan_[a-z_]+\{/) == 0) { printf "line %d: not a pft_vulnscan_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_vulnscan_up\{/) up = 1
      if ($0 ~ /^pft_vulnscan_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_vulnscan_up sample"; exit 1 }
      if (!ts) { print "no pft_vulnscan_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  [ $# -eq 0 ] || die "pull takes no arguments (PEER_LABEL in $CONF)"
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-vulnscan-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_vulnscan_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_vulnscan_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_vulnscan_$PEER_LABEL.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  scan) scan "$@" ;;
  fetch) msg="$(fetch)" || die "fetch failed: $msg" 1; echo "$msg (sha256 $(meta_get sha256))" ;;
  pull) pull "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-vulnscan validate FILE HOST"; valid_label "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-vulnscan $VERSION" ;;
  *) die "usage: pft-vulnscan scan|fetch|pull|validate|version (see the header of this script)" ;;
esac
