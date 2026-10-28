#!/usr/bin/env bash
# pft-timesync-pull: copy a peer host's pft_timesync.prom (the sentry's) into this host's textfile dir with a
# host="LABEL" label on every sample, so the validator's single Prometheus + Alertmanager (../alerts) evaluates
# alerts/timesync.rules.yml for the sentry's clock too. Same design as ../resources/pft-resources-pull.sh: the sentry
# runs no Prometheus, no exporter and no new listener; the pull rides the existing admin ssh link.
#
# Usage: sudo pft-timesync-pull pull [--host LABEL]     LABEL default "sentry" -> TEXTFILE_DIR/pft_timesync_peer_LABEL.prom
#        pft-timesync-pull relabel FILE LABEL           print FILE relabelled, or exit 2 with the reason on stderr
#
#  pull     runs "$PULL_SSH cat -- REMOTE_FILE" (timeout PULL_TIMEOUT s), relabels it and renames it into TEXTFILE_DIR
#           atomically. Relabel is all-or-nothing: the file must be <= MAX_BYTES; every line must be a blank line,
#           a "# HELP/TYPE pft_timesync_*" line, or a pft_timesync_* sample with well-formed labels, no host label of
#           its own (the peer cannot pick its host) and a numeric value; it must carry pft_timesync_state and
#           pft_timesync_collect_timestamp_seconds. Other comments are dropped. Each sample gets host="LABEL" first.
#           On any failure the previous copy is left as it is and the exit code is non-zero: its collect timestamp
#           then ages and PFTTimesyncStale{host="LABEL"} fires after 5 + 2 min.
#
# Exit codes: 0 ok, 1 fetch failed, 2 validation failed, 3 usage/config error.
# Conf: PFT_TS_PULL_CONF (/etc/pft-timesync-pull.env, root-owned, sourced first): PULL_SSH (required, e.g.
#       "runuser -u OPERATOR -- ssh -o BatchMode=yes -o ConnectTimeout=10 relay"), REMOTE_FILE
#       (/var/lib/pft-exporter/textfile/pft_timesync.prom), TEXTFILE_DIR (/var/lib/pft-exporter/textfile),
#       PULL_TIMEOUT (20), MAX_BYTES (65536)

set -uo pipefail
umask 022

CONF="${PFT_TS_PULL_CONF:-/etc/pft-timesync-pull.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
PULL_SSH="${PULL_SSH:-}"
REMOTE_FILE="${REMOTE_FILE:-/var/lib/pft-exporter/textfile/pft_timesync.prom}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"

die() { printf 'pft-timesync-pull: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_label() { [[ "$1" =~ ^[a-z0-9][a-z0-9_.-]{0,31}$ ]]; }

# relabel FILE LABEL -> relabelled text on stdout, rc 0; or rc 1 with the first reason on stderr
relabel() {
  local f="$1" label="$2" size
  [ -f "$f" ] || { echo "not a regular file" >&2; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -gt 0 ] || { echo "empty file" >&2; return 1; }
  [ "$size" -le "$MAX_BYTES" ] || { echo "file is $size bytes > MAX_BYTES $MAX_BYTES" >&2; return 1; }
  awk -v h="host=\"$label\"" '
    BEGIN { lbl = "[a-z_][a-z0-9_]*=\"[^\"\\\\\n]*\"" }
    function bad(why) { printf "line %d: %s\n", NR, why > "/dev/stderr"; err = 1; exit 1 }
    /^[ \t]*$/ { next }
    /^# (HELP|TYPE) pft_timesync_[a-z0-9_]+( |$)/ { out[++n] = $0; next }
    /^# (HELP|TYPE) / { bad("HELP/TYPE for a foreign metric") }
    /^#/ { next }
    {
      if (match($0, /^pft_timesync_[a-z0-9_]+/) == 0) bad("not a pft_timesync_ sample")
      name = substr($0, 1, RLENGTH); rest = substr($0, RLENGTH + 1); labels = ""
      if (substr(rest, 1, 1) == "{") {
        rest = substr(rest, 2)
        if (match(rest, "^" lbl "(," lbl ")*") == 0) bad("malformed labels")
        labels = substr(rest, 1, RLENGTH); rest = substr(rest, RLENGTH + 1)
        if (substr(rest, 1, 1) != "}") bad("malformed labels")
        rest = substr(rest, 2)
        if (("," labels) ~ /,host=/) bad("sample already has a host label")
      }
      if (rest !~ /^ -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) bad("malformed value")
      out[++n] = name "{" h (labels == "" ? "" : "," labels) "}" rest
      if (name == "pft_timesync_state") st = 1
      if (name == "pft_timesync_collect_timestamp_seconds") ts = 1
    }
    END {
      if (err) exit 1
      if (!st) { print "no pft_timesync_state sample" > "/dev/stderr"; exit 1 }
      if (!ts) { print "no pft_timesync_collect_timestamp_seconds sample" > "/dev/stderr"; exit 1 }
      for (i = 1; i <= n; i++) print out[i]
    }' "$f"
}

pull() {
  local label="$1" dst raw tmp why
  [ -n "$PULL_SSH" ] || die "PULL_SSH is not set (see $CONF)"
  if ! [[ "$PULL_TIMEOUT" =~ ^[0-9]+$ && "$MAX_BYTES" =~ ^[0-9]+$ ]]; then die "PULL_TIMEOUT and MAX_BYTES must be integers"; fi
  [ -d "$TEXTFILE_DIR" ] || die "textfile dir $TEXTFILE_DIR missing"
  dst="$TEXTFILE_DIR/pft_timesync_peer_$label.prom"
  raw="$(mktemp "$TEXTFILE_DIR/.tspull-raw-$label.XXXXXX")" || die "cannot create temp file in $TEXTFILE_DIR" 1
  tmp="$(mktemp "$TEXTFILE_DIR/.tspull-$label.XXXXXX")" || { rm -f "$raw"; die "cannot create temp file in $TEXTFILE_DIR" 1; }
  # shellcheck disable=SC2086  # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_FILE" > "$raw" 2>/dev/null </dev/null; then
    rm -f "$raw" "$tmp"; die "fetch of $REMOTE_FILE failed or timed out; kept the previous copy" 1
  fi
  if ! why="$(relabel "$raw" "$label" 2>&1 >"$tmp")"; then
    rm -f "$raw" "$tmp"; die "rejected the peer file: ${why:-validation failed}; kept the previous copy" 2
  fi
  rm -f "$raw"
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$dst"; }; then rm -f "$tmp"; die "cannot rename into $dst" 1; fi
  printf 'pft-timesync-pull: %s ok (%s samples)\n' "$dst" "$(grep -vc '^#' "$dst")"
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  pull)
    label=sentry
    while [ $# -gt 0 ]; do
      case "$1" in
        --host) label="${2:-}"; shift ;;
        *) die "unknown argument: $1" ;;
      esac
      shift
    done
    valid_label "$label" || die "bad host label (a-z 0-9 _ . -, max 32)"
    pull "$label" ;;
  relabel)
    [ $# -eq 2 ] || die "usage: pft-timesync-pull relabel FILE LABEL"
    valid_label "$2" || die "bad host label (a-z 0-9 _ . -, max 32)"
    relabel "$1" "$2" || exit 2 ;;
  *) die "usage: pft-timesync-pull pull [--host LABEL] | relabel FILE LABEL" ;;
esac
