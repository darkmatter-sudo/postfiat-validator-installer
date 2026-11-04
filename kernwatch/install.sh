#!/usr/bin/env bash
# Install / uninstall pft-kernwatch (+ 2-minute sandboxed timer). Idempotent: a second run changes nothing.
#   sudo ./install.sh [--host NAME]   script -> /usr/local/bin/pft-kernwatch, helper + catalogue ->
#       /usr/local/lib/pft-kernwatch/, pft-kernwatch.service/.timer, state dir /var/lib/pft-kernwatch (0700).
#       NAME (default validator; sentry on the sentry) goes to HOST_LABEL in /etc/pft-kernwatch.env (0600 root).
#       Runs one collection through the sandboxed unit (the first run only seeds the cursor at the newest kernel
#       record, so an install never alerts on old events; must give up 1), then enables pft-kernwatch.timer.
#   sudo ./install.sh --pull [--host sentry]   on the host that runs ../alerts: pft-kernwatch-pull.service/.timer;
#       needs PULL_SSH in /etc/pft-kernwatch.env (see pft-kernwatch.env.example). Runs one pull (must exit 0), then
#       enables pft-kernwatch-pull.timer (odd minutes at :00; the peer collects at even minutes :15).
#   sudo ./install.sh --uninstall | --pull --uninstall   disable the timer, remove the textfile (keeps state + conf)
# Alert rules: ../alerts/kernwatch.rules.yml, listed in ../alerts/prometheus.yml. rulecheck lines: see README.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, helper, catalogue, units, conf).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-kernwatch
LIBDIR=/usr/local/lib/pft-kernwatch
CONF=/etc/pft-kernwatch.env
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
  put "$HERE/pft-kernwatch.sh" /usr/local/bin/pft-kernwatch 755
  put "$HERE/kernwatch_parse.py" "$LIBDIR/kernwatch_parse.py" 644
  put "$HERE/catalogue.tsv" "$LIBDIR/catalogue.tsv" 644
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
  /usr/local/bin/pft-kernwatch check-catalogue | sed "s/^/$(date -u +%FT%TZ) check-catalogue: /"
}
conf_set() { # KEY VALUE: set KEY in the root-owned conf (create it 0600)
  [ -f "$CONF" ] || { install -m 600 /dev/null "$CONF"; echo "# pft-kernwatch settings (see kernwatch/pft-kernwatch.env.example)" > "$CONF"; }
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
    systemctl disable --now pft-kernwatch-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_kernwatch_$host.prom"
    log "disabled pft-kernwatch-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-kernwatch.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  [ "$host" = sentry ] || { echo "the pull unit is for --host sentry" >&2; exit 3; }
  install_bin
  put "$HERE/systemd/pft-kernwatch-pull.service" /etc/systemd/system/pft-kernwatch-pull.service 644
  put "$HERE/systemd/pft-kernwatch-pull.timer" /etc/systemd/system/pft-kernwatch-pull.timer 644
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  run_unit pft-kernwatch-pull.service
  grep -E '^pft_kernwatch_(up|collect_timestamp_seconds|catalogue_info)\{' "$TEXTDIR/pft_kernwatch_$host.prom"
  systemctl enable --now pft-kernwatch-pull.timer 2>&1 | sed 's/^/  /'
  log "pft-kernwatch-pull.timer $(systemctl is-active pft-kernwatch-pull.timer) (odd minutes at :00); changed=$changed"
  exit 0
fi
if $uninstall; then
  systemctl disable --now pft-kernwatch.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_kernwatch_$host.prom"
  log "disabled pft-kernwatch.timer, removed its textfile (kept $STATEDIR, $CONF and the script/units)"
  exit 0
fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
command -v journalctl >/dev/null || { echo "journalctl missing" >&2; exit 3; }
install_bin
install -d -m 700 "$STATEDIR"
conf_set HOST_LABEL "$host"
put "$HERE/systemd/pft-kernwatch.service" /etc/systemd/system/pft-kernwatch.service 644
put "$HERE/systemd/pft-kernwatch.timer" /etc/systemd/system/pft-kernwatch.timer 644
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
run_unit pft-kernwatch.service
grep -E '^pft_kernwatch_(up|collect_timestamp_seconds|catalogue_info|records_total|seeded_timestamp_seconds)\{' \
  "$TEXTDIR/pft_kernwatch_$host.prom"
grep -qx "pft_kernwatch_up{host=\"$host\"} 1" "$TEXTDIR/pft_kernwatch_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-kernwatch.timer 2>&1 | sed 's/^/  /'
log "pft-kernwatch.timer $(systemctl is-active pft-kernwatch.timer) (even minutes at :15); changed=$changed"
log "remember: sudo pft-integrity accept --reason 'pft-kernwatch installed'"
