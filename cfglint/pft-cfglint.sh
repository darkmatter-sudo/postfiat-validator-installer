#!/usr/bin/env bash
# pft-cfglint - read-only linter for postfiatd.cfg: flags sections/keys the running build silently ignores.
#
# Usage:
#   pft-cfglint.sh [--json] [--registry FILE] [--container NAME] [--ssh ALIAS]   # lint a running node's cfg
#   pft-cfglint.sh [--json] [--registry FILE] --file PATH                        # lint a file (no build check)
# Defaults: --container postfiatd, cfg /etc/postfiatd/postfiatd.cfg inside the container, registry next to this script.
# Exit: 0 = clean, 1 = findings, 2 = usage / read / registry error.
# Read-only: runs `docker exec <c> cat <cfg>` and `docker exec <c> postfiatd --version`; never writes or restarts.
# Output names sections/keys and line numbers only; config values (tokens, seeds) are never printed.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REGISTRY="$HERE/registry.json"
HELPER="$HERE/cfglint.py"
CONTAINER=postfiatd
CFG_IN_CONTAINER=/etc/postfiatd/postfiatd.cfg
SSH_ALIAS=""
FILE=""
JSON=()

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=(--json) ;;
    --registry) [ $# -ge 2 ] || usage; REGISTRY="$2"; shift ;;
    --container) [ $# -ge 2 ] || usage; CONTAINER="$2"; shift ;;
    --ssh) [ $# -ge 2 ] || usage; SSH_ALIAS="$2"; shift ;;
    --file) [ $# -ge 2 ] || usage; FILE="$2"; shift ;;
    -h|--help) usage ;;
    *) echo "pft-cfglint: unknown argument: $1" >&2; usage ;;
  esac
  shift
done

[ -r "$REGISTRY" ] || { echo "pft-cfglint: registry not readable: $REGISTRY" >&2; exit 2; }
command -v python3 >/dev/null || { echo "pft-cfglint: python3 not found" >&2; exit 2; }

if [ -n "$FILE" ]; then
  [ -z "$SSH_ALIAS" ] || { echo "pft-cfglint: --file and --ssh are exclusive" >&2; exit 2; }
  [ -r "$FILE" ] || { echo "pft-cfglint: cannot read $FILE" >&2; exit 2; }
  exec python3 -I "$HELPER" --registry "$REGISTRY" "${JSON[@]}" "$FILE"
fi

# run a command on the target host (this host, or the --ssh alias); arguments are quoted for the remote shell
on_host() {
  if [ -n "$SSH_ALIAS" ]; then
    ssh -o BatchMode=yes "$SSH_ALIAS" "$(printf '%q ' "$@")"
  else
    "$@"
  fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
if ! on_host sudo -n docker exec "$CONTAINER" cat "$CFG_IN_CONTAINER" > "$WORK/cfg" 2> "$WORK/err" || [ ! -s "$WORK/cfg" ]; then
  echo "pft-cfglint: could not read $CFG_IN_CONTAINER from container $CONTAINER: $(head -c 200 "$WORK/err")" >&2
  exit 2
fi
build="$(on_host sudo -n docker exec "$CONTAINER" postfiatd --version 2>/dev/null \
  | sed -n 's/^Git commit hash: *\([0-9a-f]\{40\}\)$/\1/p')"
if [ -z "$build" ]; then
  echo "pft-cfglint: could not read the build commit (postfiatd --version) from $CONTAINER" >&2
  exit 2
fi
python3 -I "$HELPER" --registry "$REGISTRY" --build-commit "$build" "${JSON[@]}" "$WORK/cfg"
