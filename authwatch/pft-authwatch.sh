#!/usr/bin/env bash
# pft-authwatch: SSH/sudo authentication monitor for a Post Fiat validator and its sentry (Ubuntu 22.04, journald).
#   sudo pft-authwatch collect [--host NAME] [--stdout]   read new sshd/sudo journal entries (after the saved cursor)
#        and write TEXTFILE_DIR/pft_authwatch_NAME.prom (NAME = HOST_LABEL, default validator). The first run only
#        stores the journal tail as its cursor (counts start at install, history is not replayed).
#   sudo pft-authwatch pull [--host sentry]   (validator) copy the sentry's textfile: "$PULL_SSH cat -- \
#        REMOTE_DIR/pft_authwatch_NAME.prom", validate, rename into TEXTFILE_DIR
#   sudo pft-authwatch allow list|count|add FP [COMMENT]|remove FP|import FILE...   manage the key allowlist
#        (ALLOWLIST, one "SHA256:..." per line). import runs ssh-keygen -lf on authorized_keys files.
#   sudo pft-authwatch sources list|count|add CIDR [COMMENT]|remove CIDR|seed [--since SPEC]   manage the known
#        source list (SOURCES, one CIDR per line). seed adds the addresses of accepted logins with an allowlisted key
#        found in the journal (default --since -30d); it prints counts only. Empty list = source check off.
#   sudo pft-authwatch digest [--dry-run] [--force]   (host running ../alerts) at most one low-priority ntfy summary
#        per UTC day of routine SSH brute force, sent only if PFTAuthFailedBurst fired on any host in the last 24 h
#        (that alert is routed to a silent receiver). Reads PROM_URL; ntfy settings from NTFY_ENV.
#   sudo pft-authwatch scan [--since SPEC] [--window S]   one-off totals + max failed attempts per window (baseline)
#   sudo pft-authwatch status    timer, cursor age, allowlist size, current counters (no identities)
#   pft-authwatch validate FILE NAME | version
# Privacy: usernames, addresses and fingerprints never leave the journal/allowlist; metrics only carry the host,
# a method, a key class (allowlisted|unknown|none), a source class (known|unknown|unconfigured) and a failure reason.
# Conf: /etc/pft-authwatch.env (root-owned, optional): HOST_LABEL, TEXTFILE_DIR (/var/lib/pft-exporter/textfile),
#   STATE_DIR (/var/lib/pft-authwatch), ALLOWLIST (/etc/pft-authwatch/allowlist), SOURCES (/etc/pft-authwatch/sources),
#   PULL_SSH, PULL_TIMEOUT (20),
#   REMOTE_DIR (/var/lib/pft-exporter/textfile), JOURNAL_TIMEOUT (30), PROM_URL (http://127.0.0.1:9090),
#   NTFY_ENV (/etc/postfiat-monitor.env: NTFY_SERVER, NTFY_TOPIC, NTFY_TOKEN).
# Exit: 0 ok, 1 runtime error (journal/pull/rename), 2 validation failed, 3 usage/config error.
set -euo pipefail
VERSION=1.1.0
CONF="${PFT_AW_CONF:-/etc/pft-authwatch.env}"
# defaults (the environment may preset them; the conf file, if any, wins)
: "${HOST_LABEL:=validator}" "${TEXTFILE_DIR:=/var/lib/pft-exporter/textfile}" "${STATE_DIR:=/var/lib/pft-authwatch}"
: "${ALLOWLIST:=/etc/pft-authwatch/allowlist}" "${SOURCES:=/etc/pft-authwatch/sources}" "${PULL_SSH:=}" "${PULL_TIMEOUT:=20}"
: "${REMOTE_DIR:=/var/lib/pft-exporter/textfile}" "${JOURNAL_TIMEOUT:=30}"
: "${PROM_URL:=http://127.0.0.1:9090}" "${NTFY_ENV:=/etc/postfiat-monitor.env}"
if [ -f "$CONF" ]; then
  [ "$(stat -c %u "$CONF")" = 0 ] || { echo "pft-authwatch: $CONF is not root-owned, ignoring it" >&2; exit 3; }
  # shellcheck disable=SC1090
  . "$CONF"
fi
JOURNALCTL="${PFT_AW_JOURNALCTL:-journalctl}"
SSHKEYGEN="${PFT_AW_SSHKEYGEN:-ssh-keygen}"
PARSER="${PFT_AW_PARSER:-/usr/local/lib/pft-authwatch/authwatch_parse.py}"
NOW="${PFT_AW_NOW:-}"
die() { echo "pft-authwatch: $1" >&2; exit "${2:-3}"; }
valid_host() { [[ "$1" =~ ^[a-z][a-z0-9_-]*$ ]]; }
FP_RX='^SHA256:[A-Za-z0-9+/]{43}$'

collect() {
  local host="$HOST_LABEL" stdout=false cur tmp err rc out
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) host="${2:?}"; shift ;;
      --stdout) stdout=true ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      --state-dir) STATE_DIR="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_host "$host" || die "bad host label"
  [[ "$JOURNAL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad JOURNAL_TIMEOUT"
  mkdir -p "$STATE_DIR"
  local state="$STATE_DIR/state-$host.json"
  cur=""
  [ -f "$state" ] && cur="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("cursor") or "")' "$state")"
  tmp="$(mktemp "$STATE_DIR/.journal.XXXXXX")"; err="$(mktemp "$STATE_DIR/.journal-err.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -f '$tmp' '$err'" EXIT
  local -a q=(-o json --no-pager -q SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sudo)
  rc=0
  if [ -n "$cur" ]; then
    timeout "$JOURNAL_TIMEOUT" "$JOURNALCTL" "${q[@]}" --after-cursor "$cur" > "$tmp" 2> "$err" || rc=$?
  else
    # first run: take the newest entry's cursor, count nothing before it
    timeout "$JOURNAL_TIMEOUT" "$JOURNALCTL" "${q[@]}" -n 1 > "$tmp" 2> "$err" || rc=$?
  fi
  # journalctl exits 1 with no output when --after-cursor has nothing newer on some versions; only output on
  # stderr or a timeout is an error
  if [ "$rc" -ne 0 ] && { [ "$rc" -eq 124 ] || [ -s "$err" ]; }; then
    die "journalctl failed (rc $rc): $(head -c 200 "$err" | tr '\n' ' ')" 1
  fi
  local -a pa=(collect --allowlist "$ALLOWLIST" --sources "$SOURCES" --host "$host")
  [ -n "$NOW" ] && pa+=(--now "$NOW")
  [ -z "$cur" ] && pa+=(--baseline)
  if $stdout; then
    # dry run: work on a copy of the state, print the textfile, change nothing
    out="$(mktemp -d "$STATE_DIR/.stdout.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp' '$err' '$out'" EXIT
    if [ -f "$state" ]; then cp "$state" "$out/state.json"; fi
    python3 -I "$PARSER" "${pa[@]}" --state "$out/state.json" --textfile "$out/t.prom" < "$tmp" || die "parser failed" 1
    cat "$out/t.prom"
    return 0
  fi
  mkdir -p "$TEXTFILE_DIR"
  python3 -I "$PARSER" "${pa[@]}" --state "$state" --textfile "$TEXTFILE_DIR/pft_authwatch_$host.prom" < "$tmp" \
    || die "parser failed" 1
}

validate() { # FILE HOST -> exit 0, or print the reason and exit 1
  local f="$1" host="$2"
  [ -s "$f" ] || { echo "empty file"; return 1; }
  awk -v h="host=\"$host\"" '
    /^#/ { next }
    !/^pft_authwatch_[a-z_]+\{[^}]*\} -?[0-9]+(\.[0-9]+)?$/ { print "bad line " NR; bad = 1; exit }
    index($0, "{" h) == 0 { print "wrong host label on line " NR; bad = 1; exit }
    /^pft_authwatch_up\{/ { up = 1 }
    /^pft_authwatch_collect_timestamp_seconds\{/ { ts = 1 }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_authwatch_up sample"; exit 1 }
      if (!ts) { print "no pft_authwatch_collect_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local host=sentry tmp why
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) host="${2:?}"; shift ;;
      --textfile-dir) TEXTFILE_DIR="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  valid_host "$host" || die "bad host label"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-authwatch.env)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-authwatch-$host.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_authwatch_$host.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_authwatch_$host.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$host")"; then
    rm -f "$tmp"; die "validation failed: $why" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_authwatch_$host.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

fps_of() { # FILE... -> fingerprints of every key in authorized_keys-style files (ssh-keygen -lf)
  local f
  for f in "$@"; do
    [ -f "$f" ] || die "no such file: $f"
    "$SSHKEYGEN" -lf "$f" -E sha256 2>/dev/null | awk '{ print $2 }' | grep -E "$FP_RX" || true
  done
}

allow() {
  local sub="${1:-list}" fp added=0
  [ $# -gt 0 ] && shift
  case "$sub" in
    list) if [ -f "$ALLOWLIST" ]; then grep -E '^SHA256:' "$ALLOWLIST" || true; fi ;;
    count) if [ -f "$ALLOWLIST" ]; then grep -cE '^SHA256:' "$ALLOWLIST" || true; else echo 0; fi ;;
    add|import)
      install -d -m 700 "$(dirname "$ALLOWLIST")"
      [ -f "$ALLOWLIST" ] || install -m 600 /dev/null "$ALLOWLIST"
      local -a fps; local note; note="# $sub $(date -u +%FT%TZ)"
      if [ "$sub" = add ]; then
        [[ "${1:-}" =~ $FP_RX ]] || die "usage: pft-authwatch allow add SHA256:<43 chars> [COMMENT]"
        fps=("$1"); shift
        [ $# -gt 0 ] && note="$note $*"
      else
        [ $# -gt 0 ] || die "usage: pft-authwatch allow import FILE..."
        mapfile -t fps < <(fps_of "$@")
      fi
      for fp in "${fps[@]}"; do
        awk -v fp="$fp" '$1 == fp { found = 1 } END { exit !found }' "$ALLOWLIST" && continue
        printf '%s %s\n' "$fp" "$note" >> "$ALLOWLIST"; added=$((added + 1))
      done
      echo "allowlist: $added added, $(allow count) total" ;;
    remove)
      [[ "${1:-}" =~ $FP_RX ]] || die "usage: pft-authwatch allow remove SHA256:<43 chars>"
      [ -f "$ALLOWLIST" ] || die "no allowlist"
      local t; t="$(mktemp "$(dirname "$ALLOWLIST")/.allow.XXXXXX")"
      awk -v fp="$1" '$1 != fp' "$ALLOWLIST" > "$t"; chmod 600 "$t"; mv -f "$t" "$ALLOWLIST"
      echo "allowlist: $(allow count) total" ;;
    *) die "usage: pft-authwatch allow list|count|add FP [COMMENT]|remove FP|import FILE..." ;;
  esac
}

CIDR_RX='^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)(/[0-9]{1,3})?$'
sources() {
  local sub="${1:-list}" c added=0 since="-30d"
  [ $# -gt 0 ] && shift
  case "$sub" in
    list) if [ -f "$SOURCES" ]; then grep -E '^[0-9a-fA-F:.]+' "$SOURCES" || true; fi ;;
    count) if [ -f "$SOURCES" ]; then grep -cE '^[0-9a-fA-F:.]+' "$SOURCES" || true; else echo 0; fi ;;
    add|seed)
      install -d -m 700 "$(dirname "$SOURCES")"
      [ -f "$SOURCES" ] || install -m 600 /dev/null "$SOURCES"
      local -a cs; local note; note="# $sub $(date -u +%FT%TZ)"
      if [ "$sub" = add ]; then
        [[ "${1:-}" =~ $CIDR_RX ]] || die "usage: pft-authwatch sources add CIDR [COMMENT]"
        cs=("$1"); shift
        [ $# -gt 0 ] && note="$note $*"
      else
        [ "${1:-}" = --since ] && since="${2:?}"
        mapfile -t cs < <("$JOURNALCTL" -o cat --no-pager -q SYSLOG_IDENTIFIER=sshd --since "$since" \
          | awk 'FNR == NR { if ($1 ~ /^SHA256:/) a[$1] = 1; next }
                 /^Accepted publickey for / { fp = $NF; if (fp in a) print $6 }' "${ALLOWLIST}" - 2>/dev/null | sort -u)
      fi
      for c in "${cs[@]}"; do
        [[ "$c" =~ $CIDR_RX ]] || continue
        awk -v c="$c" '$1 == c { found = 1 } END { exit !found }' "$SOURCES" && continue
        printf '%s %s\n' "$c" "$note" >> "$SOURCES"; added=$((added + 1))
      done
      echo "sources: $added added, $(sources count) total" ;;
    remove)
      [[ "${1:-}" =~ $CIDR_RX ]] || die "usage: pft-authwatch sources remove CIDR"
      [ -f "$SOURCES" ] || die "no sources file"
      local t; t="$(mktemp "$(dirname "$SOURCES")/.sources.XXXXXX")"
      awk -v c="$1" '$1 != c' "$SOURCES" > "$t"; chmod 600 "$t"; mv -f "$t" "$SOURCES"
      echo "sources: $(sources count) total" ;;
    *) die "usage: pft-authwatch sources list|count|add CIDR [COMMENT]|remove CIDR|seed [--since SPEC]" ;;
  esac
}
promq() { # QUERY -> "host value" lines (value rounded)
  curl -fsS --max-time 15 "$PROM_URL/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric.host // "-") \(.value[1] | tonumber | round)"'
}
digest() {
  local dry=false force=false day stamp hosts body title
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) dry=true ;;
      --force) force=true ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  mkdir -p "$STATE_DIR"
  day="$(date -u +%F)"; stamp="$STATE_DIR/digest-last"
  if ! $force && [ "$(cat "$stamp" 2>/dev/null)" = "$day" ]; then echo "digest: already sent for $day"; return 0; fi
  hosts="$(promq 'max by (host) (max_over_time(ALERTS{alertname="PFTAuthFailedBurst",alertstate="firing"}[24h]))')" \
    || die "Prometheus query failed ($PROM_URL)" 1
  if [ -z "$hosts" ] && ! $force; then echo "digest: no PFTAuthFailedBurst in the last 24 h, nothing to send"; return 0; fi
  body="$({
    echo "Routine SSH brute force, last 24 h (keys only; summarised, not paged):"
    promq 'sum by (host) (increase(pft_authwatch_ssh_failed_total[24h]))' | sed 's/^\([^ ]*\) /\1: failed attempts /'
    promq 'max by (host) (max_over_time((sum by (host) (increase(pft_authwatch_ssh_failed_total[10m])))[24h:5m]))' \
      | sed 's/^\([^ ]*\) /\1: peak per 10 min /'
    echo "burst alert fired on: $(awk '{ printf "%s ", $1 }' <<< "$hosts")"
    promq 'sum by (host) (increase(pft_authwatch_ssh_accepted_total{key_class!="allowlisted"}[24h]))' \
      | sed 's/^\([^ ]*\) /\1: unknown-key logins (paged at once) /'
    promq 'sum by (host) (increase(pft_authwatch_ssh_accepted_source_total{source_class="unknown"}[24h]))' \
      | sed 's/^\([^ ]*\) /\1: unknown-source logins (paged at once) /'
    if command -v fail2ban-client >/dev/null && fail2ban-client ping >/dev/null 2>&1; then
      fail2ban-client status sshd | awk -F'\t' '/Currently banned|Total banned/ { gsub(/[|` -]+/, " ", $1); printf "this host fail2ban:%s %s\n", $1, $2 }'
    fi
  })"
  title="SSH brute-force digest $day"
  if $dry; then printf '%s\n%s\n' "$title" "$body"; return 0; fi
  local NTFY_SERVER="" NTFY_TOPIC="" NTFY_TOKEN=""
  if [ -f "$NTFY_ENV" ]; then
    # owned by the account running the digest (root for the unit), as for the conf above
    [ "$(stat -c %u "$NTFY_ENV")" = "$(id -u)" ] || die "$NTFY_ENV is not owned by uid $(id -u)"
    # shellcheck disable=SC1090
    . "$NTFY_ENV"
  fi
  if [ -z "$NTFY_SERVER" ] || [ -z "$NTFY_TOPIC" ]; then die "NTFY_SERVER/NTFY_TOPIC not set in $NTFY_ENV"; fi
  local -a auth=()
  [ -n "$NTFY_TOKEN" ] && auth=(-H "Authorization: Bearer $NTFY_TOKEN")
  curl -fsS --max-time 20 -o /dev/null "${auth[@]}" -H "Title: $title" -H "Priority: low" -H "Tags: shield" \
    --data-binary "$body" "${NTFY_SERVER%/}/$NTFY_TOPIC" || die "ntfy send failed" 1
  echo "$day" > "$stamp"
  echo "digest: sent for $day ($(wc -l <<< "$body") lines)"
}
scan() {
  local since="-24h" window=600
  while [ $# -gt 0 ]; do
    case "$1" in
      --since) since="${2:?}"; shift ;;
      --window) window="${2:?}"; shift ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
  [[ "$window" =~ ^[1-9][0-9]*$ ]] || die "bad --window"
  "$JOURNALCTL" -o json --no-pager -q SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sudo --since "$since" \
    | python3 -I "$PARSER" scan --window "$window" --allowlist "$ALLOWLIST"
}

status() {
  local host="${1:-$HOST_LABEL}" f
  valid_host "$host" || die "bad host label"
  echo "pft-authwatch $VERSION host=$host"
  echo "timer: $(systemctl is-active pft-authwatch.timer 2>/dev/null || true)"
  echo "allowlist entries: $(allow count)"
  echo "source entries: $(sources count)"
  f="$TEXTFILE_DIR/pft_authwatch_$host.prom"
  if [ -f "$f" ]; then
    echo "textfile age: $(( $(date +%s) - $(stat -c %Y "$f") ))s"
    grep -E '^pft_authwatch_(ssh_accepted_total|ssh_accepted_source_total|ssh_failed_total|sudo_total|allowlist_entries|last_)' "$f" \
      | sed -E 's/\{host="[^"]*",?/{/; s/\{\}//'
  else
    echo "textfile: missing ($f)"
  fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  collect) collect "$@" ;;
  pull) pull "$@" ;;
  allow) allow "$@" ;;
  sources) sources "$@" ;;
  digest) digest "$@" ;;
  scan) scan "$@" ;;
  status) status "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-authwatch validate FILE NAME"; valid_host "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-authwatch $VERSION" ;;
  *) die "usage: pft-authwatch collect|pull|allow|sources|digest|scan|status|validate|version (see the header of this script)" ;;
esac
