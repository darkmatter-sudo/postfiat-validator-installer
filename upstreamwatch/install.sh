#!/usr/bin/env bash
# Install / uninstall pft-upstreamwatch (+ hourly timer).
#   sudo ./install.sh [--host LABEL] [--container NAME]   the script -> /usr/local/bin/pft-upstreamwatch, helper ->
#       /usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py, pft-upstreamwatch.service/.timer, writes HOST_LABEL
#       and CONTAINER into /etc/pft-upstreamwatch.env (validator/postfiatd by default; a sentry uses
#       --host sentry --container postfiatd-sentry), runs one collect through the sandboxed unit (must give up 1),
#       then enables pft-upstreamwatch.timer (hourly at :41 + up to 4 min).
#   sudo ./install.sh --pull     on the host that runs ../alerts: pft-upstreamwatch-pull.service/.timer; needs PULL_SSH
#       (and PEER_LABEL, default sentry) in /etc/pft-upstreamwatch.env. One pull (must exit 0), then the timer.
#   sudo ./install.sh --digest   on the host that runs ../alerts: pft-upstreamwatch-digest.service/.timer (07:20 UTC,
#       at most one low ntfy a day of the digest-only alerts; NTFY_ENV as ../valwatch). Runs `digest --dry-run`.
#   sudo ./install.sh [--pull|--digest] --uninstall   disables that timer (and removes that host's textfile).
# Alert rules: ../alerts/upstreamwatch.rules.yml listed in prometheus.yml (../alerts); the retuned PFTVulnFeedStale
# is in ../alerts/vulnscan.rules.yml.
# pft-rulecheck: if /etc/pft-rulecheck.conf exists, the textfile age line (3h) and `require pft_upstreamwatch_NAME.prom`
# are appended once, before the first run.
# Afterwards (the install runner does it): pft-integrity accept, pft-schedaudit accept + collect, pft-jobwatch
# inventory, pft-fleet sync (manifest rows), as for every add-on with a timer.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-upstreamwatch
CONF=/etc/pft-upstreamwatch.env
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE="textfile pft_upstreamwatch_*.prom   3h   pft_upstreamwatch_last_run_timestamp_seconds"
label=""; container=""; uninstall=false; pull=false; digest=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) label="${2:?}"; shift ;;
    --container) container="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    --digest) digest=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
[ -z "$label" ] || [[ "$label" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || { echo "bad host label" >&2; exit 3; }
[ -z "$container" ] || [[ "$container" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$ ]] || { echo "bad container" >&2; exit 3; }
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }
conf_set() { # KEY VALUE
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
}
rc_add() {
  [ -f "$RC_CONF" ] || return 0
  grep -qxF "$1" "$RC_CONF" || { echo "$1" >> "$RC_CONF"; log "added to $RC_CONF: $1"; }
}
rc_del() { [ ! -f "$RC_CONF" ] || sed -i "/^require pft_upstreamwatch_$1\\.prom\$/d" "$RC_CONF"; }

install_bin() {
  install -m 755 "$HERE/pft-upstreamwatch.sh" /usr/local/bin/pft-upstreamwatch
  install -d -m 755 "$LIBDIR"
  install -m 644 "$HERE/upstreamwatch_lib.py" "$LIBDIR/upstreamwatch_lib.py"
  log "installed /usr/local/bin/pft-upstreamwatch (sha256 $(sha256sum < "$HERE/pft-upstreamwatch.sh" | cut -c1-64))"
  log "installed $LIBDIR/upstreamwatch_lib.py (sha256 $(sha256sum < "$HERE/upstreamwatch_lib.py" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}
need_conf() {
  if [ ! -f "$CONF" ]; then install -o root -g root -m 600 /dev/null "$CONF"; echo "# pft-upstreamwatch (see pft-upstreamwatch.env.example)" > "$CONF"; fi
  chown root:root "$CONF"; chmod 600 "$CONF"
}

if $digest; then
  if $uninstall; then
    systemctl disable --now pft-upstreamwatch-digest.timer 2>/dev/null || true
    log "disabled pft-upstreamwatch-digest.timer"; exit 0
  fi
  need_conf; install_bin
  install -m 644 "$HERE/systemd/pft-upstreamwatch-digest.service" "$HERE/systemd/pft-upstreamwatch-digest.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "digest dry run (no send):"
  /usr/local/bin/pft-upstreamwatch digest --dry-run --force
  systemctl enable --now pft-upstreamwatch-digest.timer
  log "enabled pft-upstreamwatch-digest.timer (07:20 UTC)"
  exit 0
fi

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    systemctl disable --now pft-upstreamwatch-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_upstreamwatch_$peer.prom"; rc_del "$peer"
    log "disabled pft-upstreamwatch-pull.timer, removed the pulled textfile"; exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-upstreamwatch.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"; install_bin
  install -m 644 "$HERE/systemd/pft-upstreamwatch-pull.service" "$HERE/systemd/pft-upstreamwatch-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  rc_add "$RC_LINE"; rc_add "require pft_upstreamwatch_$peer.prom"
  log "first pull (through the sandboxed unit):"
  systemctl start pft-upstreamwatch-pull.service || true
  if systemctl is-failed -q pft-upstreamwatch-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-upstreamwatch-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_upstreamwatch_(up|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_upstreamwatch_$peer.prom"
  systemctl enable --now pft-upstreamwatch-pull.timer
  log "enabled pft-upstreamwatch-pull.timer (every 15 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  systemctl disable --now pft-upstreamwatch.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_upstreamwatch_$host.prom"; rc_del "$host"
  log "disabled pft-upstreamwatch.timer, removed its textfile (kept /var/lib/pft-upstreamwatch and the script)"
  exit 0
fi
for c in python3 docker jq curl; do command -v "$c" >/dev/null || { echo "$c missing" >&2; exit 3; }; done
need_conf; install_bin
conf_set HOST_LABEL "$host"
[ -z "$container" ] || conf_set CONTAINER "$container"
install -m 644 "$HERE/systemd/pft-upstreamwatch.service" "$HERE/systemd/pft-upstreamwatch.timer" /etc/systemd/system/
systemctl daemon-reload
rc_add "$RC_LINE"; rc_add "require pft_upstreamwatch_$host.prom"
log "first run (through the sandboxed unit, HOST_LABEL=$host):"
systemctl start pft-upstreamwatch.service || true
if systemctl is-failed -q pft-upstreamwatch.service; then
  log "ERROR: first run failed"; journalctl -u pft-upstreamwatch.service -n 5 --no-pager --utc; exit 1
fi
grep -E "^pft_upstreamwatch_(up|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_upstreamwatch_$host.prom"
grep -qx "pft_upstreamwatch_up{host=\"$host\"} 1" "$TEXTDIR/pft_upstreamwatch_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-upstreamwatch.timer
log "enabled pft-upstreamwatch.timer (hourly :41 + up to 4 min)"
