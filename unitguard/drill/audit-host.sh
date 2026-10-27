#!/usr/bin/env bash
# Read-only audit capture for one host: OS, systemd, tool/profile hashes, add-on unit inventory,
# `pft-unitguard audit --detail`, existing drop-ins. Usage: bash audit-host.sh DIR LABEL   (DIR holds pft-unitguard.sh + profiles/)
set -uo pipefail
d="$1"; label="$2"
echo "===== $label"
grep PRETTY_NAME /etc/os-release
systemd --version | head -1
date -u +%FT%TZ
echo "pft-unitguard.sh sha256 $(sha256sum "$d/pft-unitguard.sh" | cut -c1-64)"
echo "profiles sha256 $(cat "$d"/profiles/*.conf | sha256sum | cut -c1-64) ($(find "$d/profiles" -name '*.conf' | wc -l) files)"
echo "--- add-on unit files on this host (systemctl list-unit-files 'pft-*' 'postfiat*')"
systemctl list-unit-files 'pft-*' 'postfiat*' --no-legend | awk '{print $1, $2}'
echo "--- \$ pft-unitguard audit --detail"
PROFILE_DIR="$d/profiles" bash "$d/pft-unitguard.sh" audit --detail
echo "audit exit $?"
echo "--- unitguard drop-ins present"
find /etc/systemd/system -path '*.d/50-unitguard.conf' 2>/dev/null | sort | sed 's/^/  /'
find /etc/systemd/system -path '*.d/50-unitguard.conf' 2>/dev/null | grep -q . || echo "  (none)"
