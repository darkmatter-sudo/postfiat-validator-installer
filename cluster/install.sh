#!/usr/bin/env bash
# Install / uninstall pft-cluster (+ 5-minute audit timer). Installing changes neither postfiatd.cfg nor the node;
# `keygen` stores a seed, `apply` writes the config block and restarts.
#   sudo ./install.sh [--host LABEL]   script -> /usr/local/bin/pft-cluster, writes HOST_LABEL (validator by default;
#       --host sentry on a sentry) into /etc/pft-cluster.env, adds `textfile pft_cluster_*.prom 20m ...` to
#       /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one audit through the sandboxed unit (it must
#       write a textfile that passes `pft-cluster validate`), then enables pft-cluster.timer (every 5 min).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-cluster-pull.service/.timer; needs PULL_SSH
#       (and PEER_LABEL, default sentry) in /etc/pft-cluster.env. One pull (must exit 0), then enables the timer.
#   sudo ./install.sh --uninstall | --pull --uninstall   disables the timer and removes the textfile; the config block,
#       the stored seed and the backups stay (remove the block with `pft-cluster rollback --yes`).
# Alert rule: copy ../alerts/cluster.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, units, env).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
CONF=/etc/pft-cluster.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_cluster_*.prom   20m  pft_cluster_last_run_timestamp_seconds'
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
  install -m 755 "$HERE/pft-cluster.sh" /usr/local/bin/pft-cluster
  log "installed /usr/local/bin/pft-cluster (sha256 $(sha256sum < "$HERE/pft-cluster.sh" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-cluster-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_cluster_$peer.prom"
    log "disabled pft-cluster-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-cluster.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  install -m 644 "$HERE/systemd/pft-cluster-pull.service" "$HERE/systemd/pft-cluster-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-cluster-pull.service || true
  if systemctl is-failed -q pft-cluster-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-cluster-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_cluster_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_cluster_$peer.prom"
  systemctl enable --now pft-cluster-pull.timer
  log "enabled pft-cluster-pull.timer (every 5 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  systemctl disable --now pft-cluster.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_cluster_$host.prom"
  log "disabled pft-cluster.timer, removed its textfile"
  exit 0
fi
install_bin
[ -f "$CONF" ] || printf '# pft-cluster config (see pft-cluster.env.example)\n' > "$CONF"
conf_set HOST_LABEL "$host"
[ -n "$(conf_get PEER_LABEL)" ] || conf_set PEER_LABEL "$([ "$host" = validator ] && echo sentry || echo validator)"
chown root:root "$CONF"; chmod 600 "$CONF"
if [ -f "$RC_CONF" ] && ! grep -q 'pft_cluster_' "$RC_CONF"; then
  printf '# pft-cluster (audit every 5 min; sentry copy pulled every 5 min)\n%s\n' "$RC_LINE" >> "$RC_CONF"
  log "added the pft_cluster textfile line to $RC_CONF"
fi
install -m 644 "$HERE/systemd/pft-cluster.service" "$HERE/systemd/pft-cluster.timer" /etc/systemd/system/
systemctl daemon-reload
log "first audit (through the sandboxed unit, HOST_LABEL=$host):"
systemctl start pft-cluster.service || true
if systemctl is-failed -q pft-cluster.service; then
  log "ERROR: first audit failed"; journalctl -u pft-cluster.service -n 5 --no-pager --utc; exit 1
fi
/usr/local/bin/pft-cluster validate "$TEXTDIR/pft_cluster_$host.prom" "$host" || { log "ERROR: textfile rejected"; exit 1; }
grep -E "^pft_cluster_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_cluster_$host.prom"
systemctl enable --now pft-cluster.timer
log "enabled pft-cluster.timer (every 5 min)"
log "remember: sudo pft-integrity accept --reason 'pft-cluster installed'"
