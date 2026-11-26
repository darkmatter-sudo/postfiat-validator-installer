#!/usr/bin/env bash
# usage: record.sh LOGNAME REPO_DIR   (commands from stdin, one per line, run in REPO_DIR)
# Raw log -> ~/work/runlogs/LOGNAME (private). Publish with scripts/redact-log.py.
set -uo pipefail
log=~/work/runlogs/$1
cd "$2" || exit 1
{
  echo "# $(date -u +%FT%TZ) $(lsb_release -ds 2>/dev/null) | $(systemctl --version | head -1) | kernel $(uname -r) | $(shellcheck --version | sed -n 2p)"
  if git rev-parse -q HEAD >/dev/null 2>&1; then echo "# repo HEAD $(git rev-parse HEAD) ($(git rev-parse --abbrev-ref HEAD))"; else echo "# cwd is not a git repo (the first command clones)"; fi
  while IFS= read -r c; do
    echo "\$ $c"
    bash -c "$c" 2>&1
    echo "exit=${PIPESTATUS[0]}"
  done
  echo "# end $(date -u +%FT%TZ)"
} | tee "$log"
