#!/usr/bin/env bash
# Install pft-patch. On the host that runs `pft-patch run` (validator): sudo ./install.sh
# On every other patched host (sentry): sudo ./install.sh --host-only   (only the binary: run calls it over ssh)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
install -m 0755 "$HERE/pft-patch.sh" /usr/local/sbin/pft-patch
echo "installed /usr/local/sbin/pft-patch sha256 $(sha256sum /usr/local/sbin/pft-patch | cut -c1-64)"
[ "${1:-}" = --host-only ] && exit 0
install -d -m 0755 /etc/pft-patch /var/lib/pft-patch/run
[ -e /etc/pft-patch/hosts.conf ] || { install -m 0644 "$HERE/hosts.conf.example" /etc/pft-patch/hosts.conf; echo "wrote /etc/pft-patch/hosts.conf (edit it)"; }
install -m 0644 "$HERE/pft-patch-resume.service" /etc/systemd/system/pft-patch-resume.service
systemctl daemon-reload
systemctl enable pft-patch-resume.service
echo "enabled pft-patch-resume.service (runs only when /var/lib/pft-patch/run/resume.json exists)"
