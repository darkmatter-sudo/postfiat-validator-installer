#!/usr/bin/env bash
# pft-authwatch: SSH/sudo authentication monitor for a Post Fiat validator and its sentry (Ubuntu 22.04, journald).
#   sudo pft-authwatch collect [--host NAME] [--stdout]   read new sshd/sudo journal entries (after the saved cursor)
#        and write TEXTFILE_DIR/pft_authwatch_NAME.prom (NAME = HOST_LABEL, default validator). The first run only
#        stores the journal tail as its cursor (counts start at install, history is not replayed).
#   sudo pft-authwatch pull [--host sentry]   (validator) copy the sentry's textfile: "$PULL_SSH cat -- \
#        REMOTE_DIR/pft_authwatch_NAME.prom", validate, rename into TEXTFILE_DIR
#   sudo pft-authwatch allow list|count|add FP [COMMENT]|remove FP|import FILE...   manage the key allowlist
#        (ALLOWLIST, one "SHA256:..." per line). import runs ssh-keygen -lf on authorized_keys files.
#   sudo pft-authwatch scan [--since SPEC] [--window S]   one-off totals + max failed attempts per window (baseline)
#   sudo pft-authwatch status    timer, cursor age, allowlist size, current counters (no identities)
#   pft-authwatch validate FILE NAME | version
# Privacy: usernames, addresses and fingerprints never leave the journal/allowlist; metrics only carry the host,
# a method, a key class (allowlisted|unknown|none) and a failure reason.
# Conf: /etc/pft-authwatch.env (root-owned, optional): HOST_LABEL, TEXTFILE_DIR (/var/lib/pft-exporter/textfile),
#   STATE_DIR (/var/lib/pft-authwatch), ALLOWLIST (/etc/pft-authwatch/allowlist), PULL_SSH, PULL_TIMEOUT (20),
#   REMOTE_DIR (/var/lib/pft-exporter/textfile), JOURNAL_TIMEOUT (30).
# Exit: 0 ok, 1 runtime error (journal/pull/rename), 2 validation failed, 3 usage/config error.
set -euo pipefail
VERSION=1.0.0
CONF="${PFT_AW_CONF:-/etc/pft-authwatch.env}"
# defaults (the environment may preset them; the conf file, if any, wins)
: "${HOST_LABEL:=validator}" "${TEXTFILE_DIR:=/var/lib/pft-exporter/textfile}" "${STATE_DIR:=/var/lib/pft-authwatch}"
: "${ALLOWLIST:=/etc/pft-authwatch/allowlist}" "${PULL_SSH:=}" "${PULL_TIMEOUT:=20}"
: "${REMOTE_DIR:=/var/lib/pft-exporter/textfile}" "${JOURNAL_TIMEOUT:=30}"
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
  local -a pa=(collect --allowlist "$ALLOWLIST" --host "$host")
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
  f="$TEXTFILE_DIR/pft_authwatch_$host.prom"
  if [ -f "$f" ]; then
    echo "textfile age: $(( $(date +%s) - $(stat -c %Y "$f") ))s"
    grep -E '^pft_authwatch_(ssh_accepted_total|ssh_failed_total|sudo_total|allowlist_entries|last_)' "$f" \
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
  scan) scan "$@" ;;
  status) status "$@" ;;
  validate) [ $# -eq 2 ] || die "usage: pft-authwatch validate FILE NAME"; valid_host "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-authwatch $VERSION" ;;
  *) die "usage: pft-authwatch collect|pull|allow|scan|status|validate|version (see the header of this script)" ;;
esac
