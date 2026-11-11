#!/usr/bin/env bash
# shellcheck disable=SC1091  # /etc/os-release is sourced for PRETTY_NAME only
# read-only verification of an installed peerwatch (no change on either host); first used after fix-up run 07
#   bash peerwatch/drill/verify-installed.sh 2>&1 | tee LOG   (from the repo root)
set -uo pipefail
export TZ=UTC
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
red() { sed -E "s#$HOME#~#g; s#\b$(id -un)\b#<user>#g; s#$(hostname)#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g"; }
x() { echo "\$ $*" | red; out="$(eval "$*" 2>&1)"; rc=$?; printf '%s\n' "$out" | red | sed 's/^/  /'; echo "  (exit $rc)"; }
echo "peerwatch installed-state verification (read-only, script sha256 $(sha256sum < "${BASH_SOURCE[0]}" | cut -c1-64)) - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $(git rev-parse HEAD)"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |offpkg|^RESULT'"
x "R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |offpkg|^RESULT'"
x "grep -c '/usr/local/bin/pft-peerwatch' fleet/manifest.tsv; sudo -n grep -c '/usr/local/bin/pft-peerwatch' /usr/local/lib/pft-aptrust/manifest.tsv; R 'grep -c /usr/local/bin/pft-peerwatch /usr/local/lib/pft-aptrust/manifest.tsv'"
x "sudo -n pft-fleet skew | grep -E 'peerwatch|aptrust|SUMMARY'"
x "sudo -n pft-peerwatch status; R 'sudo -n pft-peerwatch status --container postfiatd-sentry'"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
echo "done $(date -u +%FT%TZ)"
