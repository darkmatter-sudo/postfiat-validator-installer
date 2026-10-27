#!/usr/bin/env bash
# pft-resources-pull: copy a peer host's pft_resources_NAME.prom (e.g. the sentry's) into this host's textfile dir,
# so ONE Prometheus + Alertmanager (the validator's ../alerts stack) scrapes and alerts on both hosts' metrics.
# The sentry runs no Prometheus, no exporter and no new listener; the pull rides the existing admin ssh link.
#
# Usage: sudo pft-resources-pull pull [--container NAME]      NAME = the peer's container (default postfiatd-sentry)
#        pft-resources-pull validate FILE NAME                 exit 0 if FILE is an acceptable textfile for NAME
#
#  pull  runs "$PULL_SSH cat -- REMOTE_DIR/pft_resources_NAME.prom" (timeout PULL_TIMEOUT s), validates it and
#        renames it into TEXTFILE_DIR atomically. Validation is all-or-nothing: the file must be <= MAX_BYTES, every
#        line must be a comment ("# HELP/TYPE" only for pft_resources_*) or a pft_resources_* sample whose FIRST label is
#        container="NAME" and whose value is a number, and it must carry pft_resources_up and
#        pft_resources_collect_timestamp_seconds for NAME. A peer can therefore never inject other metric names,
#        other containers' series or exposition-breaking lines into this host's exporter.
#        On any failure (ssh, timeout, validation) the previous copy is left as it is and the exit code is non-zero:
#        its collect timestamp then ages and PFTResourcesStale (alerts/resources.rules.yml) fires after 5 + 2 min.
#
# Exit codes: 0 ok, 1 fetch failed, 2 validation failed, 3 usage/config error.
# Conf: PFT_RES_PULL_CONF (/etc/pft-resources-pull.env, root-owned, sourced first): PULL_SSH (required, e.g.
#       "runuser -u OPERATOR -- ssh -o BatchMode=yes -o ConnectTimeout=10 relay"), REMOTE_DIR
#       (/var/lib/pft-exporter/textfile), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), PULL_TIMEOUT (20),
#       MAX_BYTES (65536)

set -uo pipefail
umask 022

CONF="${PFT_RES_PULL_CONF:-/etc/pft-resources-pull.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
PULL_SSH="${PULL_SSH:-}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
PULL_TIMEOUT="${PULL_TIMEOUT:-20}"
MAX_BYTES="${MAX_BYTES:-65536}"

die() { printf 'pft-resources-pull: %s\n' "$1" >&2; exit "${2:-3}"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; }

# validate FILE NAME -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" name="$2" size
  [ -f "$f" ] || { printf 'not a regular file'; return 1; }
  size="$(stat -c %s "$f")"
  [ "$size" -gt 0 ] || { printf 'empty file'; return 1; }
  [ "$size" -le "$MAX_BYTES" ] || { printf 'file is %s bytes > MAX_BYTES %s' "$size" "$MAX_BYTES"; return 1; }
  awk -v c="container=\"$name\"" '
    BEGIN { lbl = "[a-z_]+=\"[^\"\\\\\n]*\"" }
    /^# (HELP|TYPE) pft_resources_[a-z0-9_]+( |$)/ { next }
    /^# (HELP|TYPE) / { printf "line %d: HELP/TYPE for a foreign metric", NR; bad = 1; exit }
    /^#( |$)/ { next }
    {
      if (substr($0, 1, 14) != "pft_resources_") { printf "line %d: not a pft_resources_ line", NR; bad = 1; exit }
      if (match($0, /^pft_resources_[a-z0-9_]+\{/) == 0) { printf "line %d: sample without labels", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, c) != 1) { printf "line %d: first label is not %s", NR, c; bad = 1; exit }
      rest = substr(rest, length(c) + 1)
      while (match(rest, "^," lbl) == 1) rest = substr(rest, RLENGTH + 1)
      if (rest !~ /^\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/) { printf "line %d: malformed labels or value", NR; bad = 1; exit }
      if ($0 ~ /^pft_resources_up\{/) up = 1
      if ($0 ~ /^pft_resources_collect_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { printf "no pft_resources_up sample"; exit 1 }
      if (!ts) { printf "no pft_resources_collect_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local name="$1" dst tmp why
  [ -n "$PULL_SSH" ] || die "PULL_SSH is not set (see $CONF)"
  if ! [[ "$PULL_TIMEOUT" =~ ^[0-9]+$ && "$MAX_BYTES" =~ ^[0-9]+$ ]]; then die "PULL_TIMEOUT and MAX_BYTES must be integers"; fi
  [ -d "$TEXTFILE_DIR" ] || die "textfile dir $TEXTFILE_DIR missing"
  dst="$TEXTFILE_DIR/pft_resources_$name.prom"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-$name.XXXXXX")" || die "cannot create temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086  # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_resources_$name.prom" > "$tmp" 2>/dev/null </dev/null; then
    rm -f "$tmp"; die "fetch of pft_resources_$name.prom failed or timed out; kept the previous copy" 1
  fi
  if ! why="$(validate "$tmp" "$name")"; then
    rm -f "$tmp"; die "rejected pft_resources_$name.prom: ${why:-validation failed}; kept the previous copy" 2
  fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$dst"; }; then rm -f "$tmp"; die "cannot rename into $dst" 1; fi
  printf 'pft-resources-pull: %s ok (%s lines)\n' "$dst" "$(grep -c . "$dst")"
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  pull)
    name=postfiatd-sentry
    while [ $# -gt 0 ]; do
      case "$1" in
        --container) name="${2:-}"; shift ;;
        *) die "unknown argument: $1" ;;
      esac
      shift
    done
    valid_name "$name" || die "bad container name"
    pull "$name" ;;
  validate)
    [ $# -eq 2 ] || die "usage: pft-resources-pull validate FILE NAME"
    valid_name "$2" || die "bad container name"
    if why="$(validate "$1" "$2")"; then echo "valid"; else echo "invalid: ${why:-validation failed}"; exit 2; fi ;;
  *) die "usage: pft-resources-pull pull [--container NAME] | validate FILE NAME" ;;
esac
