#!/usr/bin/env bash
# Install / uninstall pft-vulnscan (+ daily timer).
#   sudo ./install.sh [--host LABEL]   installs OpenSCAP (libopenscap8) if missing, the script ->
#       /usr/local/bin/pft-vulnscan, parser -> /usr/local/lib/pft-vulnscan/vulnscan_parse.py, pft-vulnscan.service/
#       .timer, writes HOST_LABEL into /etc/pft-vulnscan.env (validator by default; use --host sentry on a sentry),
#       runs one scan through the sandboxed unit (must give up 1), then enables pft-vulnscan.timer (daily 04:20 UTC
#       + up to 30 min random delay, Persistent).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-vulnscan-pull.service/.timer; needs
#       PULL_SSH (and PEER_LABEL, default sentry) in /etc/pft-vulnscan.env. Runs one pull (must exit 0), then enables
#       pft-vulnscan-pull.timer (every 15 min).
#   sudo ./install.sh --uninstall | --pull --uninstall   disables the timer and removes that host's textfile (keeps
#       the feed cache, the script and OpenSCAP).
# Alert rules: copy ../alerts/vulnscan.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-vulnscan
CONF=/etc/pft-vulnscan.env
label=""; uninstall=false; pull=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) label="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
[ -z "$label" ] || [[ "$label" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || { echo "bad host label" >&2; exit 3; }
conf_get() { sed -n "s/^$1=//p" "$CONF" 2>/dev/null | tail -1 | tr -d '"'; }

install_bin() {
  install -m 755 "$HERE/pft-vulnscan.sh" /usr/local/bin/pft-vulnscan
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/vulnscan_parse.py" "$LIBDIR/vulnscan_parse.py"
  log "installed /usr/local/bin/pft-vulnscan (sha256 $(sha256sum < "$HERE/pft-vulnscan.sh" | cut -c1-64))"
  log "installed $LIBDIR/vulnscan_parse.py (sha256 $(sha256sum < "$HERE/vulnscan_parse.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-vulnscan-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_vulnscan_$peer.prom"
    log "disabled pft-vulnscan-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-vulnscan.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  install -m 644 "$HERE/systemd/pft-vulnscan-pull.service" "$HERE/systemd/pft-vulnscan-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-vulnscan-pull.service || true
  if systemctl is-failed -q pft-vulnscan-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-vulnscan-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_vulnscan_(up|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_vulnscan_$peer.prom"
  systemctl enable --now pft-vulnscan-pull.timer
  log "enabled pft-vulnscan-pull.timer (every 15 min)"
  log "remember: sudo pft-integrity accept --reason 'pft-vulnscan pull installed'"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  systemctl disable --now pft-vulnscan.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_vulnscan_$host.prom"
  log "disabled pft-vulnscan.timer, removed its textfile (kept /var/cache/pft-vulnscan, the script and OpenSCAP)"
  exit 0
fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
if ! command -v oscap >/dev/null; then
  log "installing libopenscap8 (OpenSCAP, Ubuntu archive)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends libopenscap8 >/dev/null
fi
log "$(oscap --version | head -1)"
install_bin
if [ -f "$CONF" ]; then
  if grep -q '^HOST_LABEL=' "$CONF"; then sed -i "s/^HOST_LABEL=.*/HOST_LABEL=$host/" "$CONF"; else echo "HOST_LABEL=$host" >> "$CONF"; fi
else
  printf '# pft-vulnscan config (see pft-vulnscan.env.example)\nHOST_LABEL=%s\n' "$host" > "$CONF"
fi
chown root:root "$CONF"; chmod 600 "$CONF"
install -m 644 "$HERE/systemd/pft-vulnscan.service" "$HERE/systemd/pft-vulnscan.timer" /etc/systemd/system/
systemctl daemon-reload
log "first scan (through the sandboxed unit, HOST_LABEL=$host):"
systemctl start pft-vulnscan.service || true
if systemctl is-failed -q pft-vulnscan.service; then
  log "ERROR: first scan failed"; journalctl -u pft-vulnscan.service -n 5 --no-pager --utc; exit 1
fi
grep -E "^pft_vulnscan_(up|feed_timestamp_seconds|affected_cves|reboot_owed)\{" "$TEXTDIR/pft_vulnscan_$host.prom"
grep -qx "pft_vulnscan_up{host=\"$host\"} 1" "$TEXTDIR/pft_vulnscan_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-vulnscan.timer
log "enabled pft-vulnscan.timer (daily 04:20 UTC + up to 30 min)"
log "remember: sudo pft-integrity accept --reason 'pft-vulnscan installed'"
