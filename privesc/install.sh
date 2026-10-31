#!/usr/bin/env bash
# Install / uninstall pft-privesc (+ hourly audit timer). Installing changes NO permission on the host; `apply` does.
#   sudo ./install.sh [--host LABEL] [--agent ACCOUNT]   script -> /usr/local/bin/pft-privesc, classifier ->
#       /usr/local/lib/pft-privesc/, writes HOST_LABEL (validator by default; --host sentry on a sentry) and
#       AGENT_USER (default: $SUDO_USER, the account whose sudo apply/undo must keep) into /etc/pft-privesc.env,
#       adds `textfile pft_privesc_*.prom 3h ...` to /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one
#       audit through the sandboxed unit (must write up 1), then enables pft-privesc.timer (hourly).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-privesc-pull.service/.timer; needs
#       PULL_SSH (and PEER_LABEL, default sentry) in /etc/pft-privesc.env. One pull (must exit 0), then enables
#       pft-privesc-pull.timer (every 15 min).
#   sudo ./install.sh --uninstall | --pull --uninstall   refuses while apply changes are recorded (run undo first);
#       disables the timer and removes the textfile.
# Alert rules: copy ../alerts/privesc.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, classifier, units, env).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-privesc
STATE=/var/lib/pft-privesc
CONF=/etc/pft-privesc.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_privesc_*.prom   3h   pft_privesc_last_run_timestamp_seconds'
label=""; agent="${SUDO_USER:-}"; uninstall=false; pull=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) label="${2:?}"; shift ;;
    --agent) agent="${2:?}"; shift ;;
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
  install -m 755 "$HERE/pft-privesc.sh" /usr/local/bin/pft-privesc
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/privesc_classify.py" "$LIBDIR/privesc_classify.py"
  log "installed /usr/local/bin/pft-privesc (sha256 $(sha256sum < "$HERE/pft-privesc.sh" | cut -c1-64))"
  log "installed $LIBDIR/privesc_classify.py (sha256 $(sha256sum < "$HERE/privesc_classify.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-privesc-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_privesc_$peer.prom"
    log "disabled pft-privesc-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-privesc.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  install -m 644 "$HERE/systemd/pft-privesc-pull.service" "$HERE/systemd/pft-privesc-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-privesc-pull.service || true
  if systemctl is-failed -q pft-privesc-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-privesc-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_privesc_(up|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_privesc_$peer.prom"
  systemctl enable --now pft-privesc-pull.timer
  log "enabled pft-privesc-pull.timer (every 15 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  if [ -s "$STATE/backup/manifest.tsv" ]; then
    echo "apply changes are recorded: run 'sudo pft-privesc undo' first (or keep them and remove the manifest)" >&2; exit 3
  fi
  systemctl disable --now pft-privesc.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_privesc_$host.prom"
  log "disabled pft-privesc.timer, removed its textfile"
  exit 0
fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
if [ -z "$agent" ] || ! id "$agent" > /dev/null 2>&1; then echo "agent account missing: pass --agent ACCOUNT" >&2; exit 3; fi
install_bin
[ -f "$CONF" ] || printf '# pft-privesc config (see pft-privesc.env.example)\n' > "$CONF"
conf_set HOST_LABEL "$host"; conf_set AGENT_USER "$agent"
chown root:root "$CONF"; chmod 600 "$CONF"
install -d -m 700 "$STATE"
if [ -f "$RC_CONF" ] && ! grep -q 'pft_privesc_' "$RC_CONF"; then
  printf '# pft-privesc (hourly audit; sentry copy pulled every 15 min)\n%s\n' "$RC_LINE" >> "$RC_CONF"
  log "added the pft_privesc textfile line to $RC_CONF"
fi
install -m 644 "$HERE/systemd/pft-privesc.service" "$HERE/systemd/pft-privesc.timer" /etc/systemd/system/
systemctl daemon-reload
log "first audit (through the sandboxed unit, HOST_LABEL=$host):"
systemctl start pft-privesc.service || true
if systemctl is-failed -q pft-privesc.service; then
  log "ERROR: first audit failed"; journalctl -u pft-privesc.service -n 5 --no-pager --utc; exit 1
fi
grep -qx "pft_privesc_up{host=\"$host\"} 1" "$TEXTDIR/pft_privesc_$host.prom" || { log "ERROR: up != 1"; exit 1; }
grep -E "^pft_privesc_(up|fixable|backup_entries)\{" "$TEXTDIR/pft_privesc_$host.prom"
systemctl enable --now pft-privesc.timer
log "enabled pft-privesc.timer (hourly + up to 10 min)"
log "remember: sudo pft-integrity accept --reason 'pft-privesc installed'"
