#!/usr/bin/env bash
# backupwatch/drill/checks-run.sh: recorded lint + offline suite + one read-only live `check` of the newest local
# archive, at a pushed commit. Run from the repo root: bash backupwatch/drill/checks-run.sh | tee LOG
# The live check runs twice: the helper (JSON) and the pft-backupwatch.sh wrapper (table); both exits must agree.
# Read-only on the host: the live step reads /var/backups/postfiat and the node's config volume (host path from
# docker inspect); no docker exec, nothing extracted, gpg/age scratch only under /dev/shm and removed.
export TZ=UTC
set -o pipefail
cd "$(dirname "$0")/../.." || exit 3
x() { echo "\$ $*"; eval "$*"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
fails=0
echo "OS: $(grep ^PRETTY_NAME= /etc/os-release | cut -d= -f2- | tr -d '"')"
echo "date: $(date -u +%FT%TZ)  commit: $(git rev-parse HEAD)  dirty: $(git status --short | wc -l)"
x "sha256sum backupwatch/pft-backupwatch.sh backupwatch/backupwatch_lib.py backupwatch/tests/test_backupwatch.py backupwatch/drill/checks-run.sh"
x "shellcheck --version | sed -n 2p && shellcheck backupwatch/pft-backupwatch.sh backupwatch/drill/checks-run.sh" || fails=$((fails + 1))
x "ruff --version && ruff check backupwatch/ && ruff format --check backupwatch/" || fails=$((fails + 1))
x "TEST_TMPDIR=\$HOME/.cache timeout 300 nice -n 15 python3 -u backupwatch/tests/test_backupwatch.py" || fails=$((fails + 1))
CFG="$(sudo -n docker inspect postfiatd --format '{{range .Mounts}}{{if eq .Destination "/etc/postfiatd"}}{{.Source}}{{end}}{{end}}')"
echo "config volume host path: ${CFG:+found (docker inspect .Mounts, /etc/postfiatd)}"
x "ls /dev/shm | grep -c '^pft-bw' || true"
x "sudo -n python3 -u backupwatch/backupwatch_lib.py check --dir /var/backups/postfiat --now \$(date +%s) --cfg-dir \"\$CFG\" | python3 -m json.tool"
live=$?
x "sudo -n PFT_BW_HELPER=backupwatch/backupwatch_lib.py bash backupwatch/pft-backupwatch.sh check"
wrap=$?
x "ls /dev/shm | grep -c '^pft-bw' || true"
[ "$wrap" = "$live" ] || { echo "wrapper exit $wrap != helper exit $live"; fails=$((fails + 1)); }
echo "live check exit: $live (0 OK / 1 WARN / 2 FAIL)"
echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo FAIL) (lint+suite failures: $fails; live check exit $live)"
