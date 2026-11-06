#!/usr/bin/env bash
# Install / uninstall pft-jobwatch (+ 2-minute sandboxed timer). Idempotent: a second run changes nothing.
#   sudo ./install.sh [--host NAME]   script -> /usr/local/bin/pft-jobwatch, helper ->
#       /usr/local/lib/pft-jobwatch/, pft-jobwatch.service/.timer, state dir /var/lib/pft-jobwatch (0700).
#       NAME (default validator; sentry on the sentry) goes to HOST_LABEL in /etc/pft-jobwatch.env (0600 root).
#       Runs one collection through the sandboxed unit (must give up 1), prints the job inventory, then enables
#       pft-jobwatch.timer (even minutes at :40).
#   sudo ./install.sh --pull [--host sentry]   on the host that runs ../alerts: pft-jobwatch-pull.service/.timer;
#       needs PULL_SSH in /etc/pft-jobwatch.env (see pft-jobwatch.env.example). Runs one pull (must exit 0), then
#       enables pft-jobwatch-pull.timer (odd minutes at :10; the peer collects at even minutes :40).
#   sudo ./install.sh --uninstall | --pull --uninstall   disable the timer, remove the textfile (keeps state + conf)
# Alert rules: ../alerts/jobwatch.rules.yml, listed in ../alerts/prometheus.yml. rulecheck lines: see README.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, helper, units, conf).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-jobwatch
LIBDIR=/usr/local/lib/pft-jobwatch
CONF=/etc/pft-jobwatch.env
host=""; uninstall=false; pull=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
if [ -z "$host" ]; then if $pull; then host=sentry; else host=validator; fi; fi
[[ "$host" =~ ^[a-z][a-z0-9_-]{0,30}$ ]] || { echo "bad host label" >&2; exit 3; }

same() { [ -f "$2" ] && cmp -s "$1" "$2"; }
put() { # SRC DST MODE: install only if the bytes differ, report either way
  if same "$1" "$2" && [ "$(stat -c %a "$2")" = "$3" ]; then log "unchanged $2"; else
    install -D -m "$3" "$1" "$2"; log "installed $2 (sha256 $(sha256sum < "$1" | cut -c1-64))"; changed=true; fi
}
changed=false
install_bin() {
  put "$HERE/pft-jobwatch.sh" /usr/local/bin/pft-jobwatch 755
  put "$HERE/jobwatch_lib.py" "$LIBDIR/jobwatch_lib.py" 644
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}
conf_set() { # KEY VALUE: set KEY in the root-owned conf (create it 0600)
  [ -f "$CONF" ] || { install -m 600 /dev/null "$CONF"; echo "# pft-jobwatch settings (see jobwatch/pft-jobwatch.env.example)" > "$CONF"; }
  if grep -qx "$1=$2" "$CONF"; then return 0; fi
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
  log "set $1=$2 in $CONF"; changed=true
}
run_unit() { # UNIT: start it, print this run's journal (a finished oneshot has no InvocationID left), fail if it failed
  local t0; t0="$(date -u +%s)"
  systemctl start "$1" || true
  journalctl -u "$1" --since "@$t0" --no-pager --utc -o cat | grep -v 'pam_limits\|pam_unix' || true
  if systemctl is-failed -q "$1"; then log "ERROR: $1 failed"; exit 1; fi
}

if $pull; then
  if $uninstall; then
    systemctl disable --now pft-jobwatch-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_jobwatch_$host.prom"
    log "disabled pft-jobwatch-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-jobwatch.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  [ "$host" = sentry ] || { echo "the pull unit is for --host sentry" >&2; exit 3; }
  install_bin
  put "$HERE/systemd/pft-jobwatch-pull.service" /etc/systemd/system/pft-jobwatch-pull.service 644
  put "$HERE/systemd/pft-jobwatch-pull.timer" /etc/systemd/system/pft-jobwatch-pull.timer 644
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  run_unit pft-jobwatch-pull.service
  grep -E '^pft_jobwatch_(up|collect_timestamp_seconds|jobs)\{' "$TEXTDIR/pft_jobwatch_$host.prom"
  systemctl enable --now pft-jobwatch-pull.timer 2>&1 | sed 's/^/  /'
  log "pft-jobwatch-pull.timer $(systemctl is-active pft-jobwatch-pull.timer) (odd minutes at :10); changed=$changed"
  exit 0
fi
if $uninstall; then
  systemctl disable --now pft-jobwatch.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_jobwatch_$host.prom"
  log "disabled pft-jobwatch.timer, removed its textfile (kept $STATEDIR, $CONF and the script/units)"
  exit 0
fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
command -v systemctl >/dev/null || { echo "systemctl missing" >&2; exit 3; }
install_bin
install -d -m 700 "$STATEDIR"
conf_set HOST_LABEL "$host"
put "$HERE/systemd/pft-jobwatch.service" /etc/systemd/system/pft-jobwatch.service 644
put "$HERE/systemd/pft-jobwatch.timer" /etc/systemd/system/pft-jobwatch.timer 644
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
run_unit pft-jobwatch.service
grep -E '^pft_jobwatch_(up|collect_timestamp_seconds|jobs)\{' "$TEXTDIR/pft_jobwatch_$host.prom"
log "job inventory:"
/usr/local/bin/pft-jobwatch inventory
grep -qx "pft_jobwatch_up{host=\"$host\"} 1" "$TEXTDIR/pft_jobwatch_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-jobwatch.timer 2>&1 | sed 's/^/  /'
log "pft-jobwatch.timer $(systemctl is-active pft-jobwatch.timer) (even minutes at :40); changed=$changed"
log "remember: sudo pft-integrity accept --reason 'pft-jobwatch installed'"
