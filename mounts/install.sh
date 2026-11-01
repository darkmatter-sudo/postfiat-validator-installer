#!/usr/bin/env bash
# Install / uninstall pft-mounts (+ hourly audit timer). Installing changes NO mount and no fstab line; `apply` does.
#   sudo ./install.sh [--host LABEL]   script -> /usr/local/bin/pft-mounts, writes HOST_LABEL (validator by default;
#       --host sentry on a sentry) into /etc/pft-mounts.env, adds `textfile pft_mounts_*.prom 3h ...` to
#       /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one audit through the sandboxed unit (it must
#       write a textfile that passes `pft-mounts validate`), then enables pft-mounts.timer (hourly).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-mounts-pull.service/.timer; needs PULL_SSH
#       (and PEER_LABEL, default sentry) in /etc/pft-mounts.env. One pull (must exit 0), then enables the timer.
#   sudo ./install.sh --uninstall | --pull --uninstall   refuses while apply's fstab block is installed (run
#       `pft-mounts rollback --yes` first); disables the timer and removes the textfile.
# Alert rule: copy ../alerts/mounts.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, units, env).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
CONF=/etc/pft-mounts.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_mounts_*.prom   3h   pft_mounts_last_run_timestamp_seconds'
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
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }
conf_set() { # conf_set KEY VALUE
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
}
install_bin() {
  install -m 755 "$HERE/pft-mounts.sh" /usr/local/bin/pft-mounts
  log "installed /usr/local/bin/pft-mounts (sha256 $(sha256sum < "$HERE/pft-mounts.sh" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-mounts-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_mounts_$peer.prom"
    log "disabled pft-mounts-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-mounts.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  install -m 644 "$HERE/systemd/pft-mounts-pull.service" "$HERE/systemd/pft-mounts-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-mounts-pull.service || true
  if systemctl is-failed -q pft-mounts-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-mounts-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_mounts_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_mounts_$peer.prom"
  systemctl enable --now pft-mounts-pull.timer
  log "enabled pft-mounts-pull.timer (every 15 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  if grep -q '^# BEGIN pft-mounts' /etc/fstab; then
    echo "the pft-mounts fstab block is installed: run 'sudo pft-mounts rollback --yes' first (or keep it)" >&2; exit 3
  fi
  systemctl disable --now pft-mounts.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_mounts_$host.prom"
  log "disabled pft-mounts.timer, removed its textfile"
  exit 0
fi
install_bin
[ -f "$CONF" ] || printf '# pft-mounts config (see pft-mounts.env.example)\n' > "$CONF"
conf_set HOST_LABEL "$host"
chown root:root "$CONF"; chmod 600 "$CONF"
if [ -f "$RC_CONF" ] && ! grep -q 'pft_mounts_' "$RC_CONF"; then
  printf '# pft-mounts (hourly audit; sentry copy pulled every 15 min)\n%s\n' "$RC_LINE" >> "$RC_CONF"
  log "added the pft_mounts textfile line to $RC_CONF"
fi
install -m 644 "$HERE/systemd/pft-mounts.service" "$HERE/systemd/pft-mounts.timer" /etc/systemd/system/
systemctl daemon-reload
log "first audit (through the sandboxed unit, HOST_LABEL=$host):"
systemctl start pft-mounts.service || true
if systemctl is-failed -q pft-mounts.service; then
  log "ERROR: first audit failed"; journalctl -u pft-mounts.service -n 5 --no-pager --utc; exit 1
fi
/usr/local/bin/pft-mounts validate "$TEXTDIR/pft_mounts_$host.prom" "$host" || { log "ERROR: textfile rejected"; exit 1; }
grep -E "^pft_mounts_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_mounts_$host.prom"
systemctl enable --now pft-mounts.timer
log "enabled pft-mounts.timer (hourly + up to 10 min)"
log "remember: sudo pft-integrity accept --reason 'pft-mounts installed'"
