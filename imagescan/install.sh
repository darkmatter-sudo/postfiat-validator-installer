#!/usr/bin/env bash
# Install / uninstall pft-imagescan (+ daily timer).
#   sudo ./install.sh [--host LABEL]   the script -> /usr/local/bin/pft-imagescan, helper ->
#       /usr/local/lib/pft-imagescan/imagescan_lib.py, pft-imagescan.service/.timer, writes HOST_LABEL into
#       /etc/pft-imagescan.env (validator by default; use --host sentry on a sentry), runs one scan through the
#       sandboxed unit (must give up 1; the first run reads every local image once, minutes for a large image), then
#       enables pft-imagescan.timer (daily 05:10 UTC + up to 30 min random delay, Persistent).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-imagescan-pull.service/.timer; needs
#       PULL_SSH (and PEER_LABEL, default sentry) in /etc/pft-imagescan.env. Runs one pull (must exit 0), then enables
#       pft-imagescan-pull.timer (every 15 min).
#   sudo ./install.sh --uninstall | --pull --uninstall   disables the timer and removes that host's textfile (keeps
#       the feed + inventory cache and the script).
# Alert rules: copy ../alerts/imagescan.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# pft-rulecheck: if /etc/pft-rulecheck.conf exists, the textfile age line (36h, daily timer + 30 min delay) and
# `require pft_imagescan_NAME.prom` (own host; with --pull the peer) are appended once, before the first scan.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units), pft-schedaudit accept + collect and
# pft-jobwatch inventory (new timers), as for every add-on with a timer.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-imagescan
CONF=/etc/pft-imagescan.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE="textfile pft_imagescan_*.prom   36h   pft_imagescan_last_run_timestamp_seconds"
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
# KEY -> value from CONF, empty if the file or key is missing (must not fail: set -e + pipefail)
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }

rc_add() { # $1 = exact line; appended once to the pft-rulecheck conf if pft-rulecheck is installed
  [ -f "$RC_CONF" ] || return 0
  grep -qxF "$1" "$RC_CONF" || { echo "$1" >> "$RC_CONF"; log "added to $RC_CONF: $1"; }
}
rc_del() { # $1 = host: drop its require line (the shared textfile line stays)
  [ ! -f "$RC_CONF" ] || sed -i "/^require pft_imagescan_$1\\.prom\$/d" "$RC_CONF"
}

install_bin() {
  install -m 755 "$HERE/pft-imagescan.sh" /usr/local/bin/pft-imagescan
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/imagescan_lib.py" "$LIBDIR/imagescan_lib.py"
  log "installed /usr/local/bin/pft-imagescan (sha256 $(sha256sum < "$HERE/pft-imagescan.sh" | cut -c1-64))"
  log "installed $LIBDIR/imagescan_lib.py (sha256 $(sha256sum < "$HERE/imagescan_lib.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-imagescan-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_imagescan_$peer.prom"; rc_del "$peer"
    log "disabled pft-imagescan-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-imagescan.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  install -m 644 "$HERE/systemd/pft-imagescan-pull.service" "$HERE/systemd/pft-imagescan-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  rc_add "$RC_LINE"; rc_add "require pft_imagescan_$peer.prom"
  log "first pull (through the sandboxed unit):"
  systemctl start pft-imagescan-pull.service || true
  if systemctl is-failed -q pft-imagescan-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-imagescan-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_imagescan_(up|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_imagescan_$peer.prom"
  systemctl enable --now pft-imagescan-pull.timer
  log "enabled pft-imagescan-pull.timer (every 15 min)"
  log "remember: sudo pft-integrity accept --reason 'pft-imagescan pull installed'"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  systemctl disable --now pft-imagescan.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_imagescan_$host.prom"; rc_del "$host"
  log "disabled pft-imagescan.timer, removed its textfile (kept /var/cache/pft-imagescan and the script)"
  exit 0
fi
for c in python3 docker curl; do command -v "$c" >/dev/null || { echo "$c missing" >&2; exit 3; }; done
install_bin
if [ -f "$CONF" ]; then
  if grep -q '^HOST_LABEL=' "$CONF"; then sed -i "s/^HOST_LABEL=.*/HOST_LABEL=$host/" "$CONF"; else echo "HOST_LABEL=$host" >> "$CONF"; fi
else
  printf '# pft-imagescan config (see pft-imagescan.env.example)\nHOST_LABEL=%s\n' "$host" > "$CONF"
fi
chown root:root "$CONF"; chmod 600 "$CONF"
install -m 644 "$HERE/systemd/pft-imagescan.service" "$HERE/systemd/pft-imagescan.timer" /etc/systemd/system/
systemctl daemon-reload
rc_add "$RC_LINE"; rc_add "require pft_imagescan_$host.prom"
log "first scan (through the sandboxed unit, HOST_LABEL=$host):"
systemctl start pft-imagescan.service || true
if systemctl is-failed -q pft-imagescan.service; then
  log "ERROR: first scan failed"; journalctl -u pft-imagescan.service -n 5 --no-pager --utc; exit 1
fi
grep -E "^pft_imagescan_(up|last_run_timestamp_seconds|drift|fixable_high_critical)\{" "$TEXTDIR/pft_imagescan_$host.prom"
grep -qx "pft_imagescan_up{host=\"$host\"} 1" "$TEXTDIR/pft_imagescan_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-imagescan.timer
log "enabled pft-imagescan.timer (daily 05:10 UTC + up to 30 min)"
log "remember: sudo pft-integrity accept --reason 'pft-imagescan installed'"
