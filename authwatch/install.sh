#!/usr/bin/env bash
# Install / uninstall pft-authwatch (+ 1-minute sandboxed timer). Idempotent: a second run changes nothing.
#   sudo ./install.sh [--host NAME]   script -> /usr/local/bin/pft-authwatch, parser ->
#       /usr/local/lib/pft-authwatch/authwatch_parse.py, pft-authwatch.service/.timer, state dir /var/lib/pft-authwatch
#       (0700), allowlist /etc/pft-authwatch/allowlist (0600). NAME (default validator; sentry on the sentry) goes to
#       HOST_LABEL in /etc/pft-authwatch.env. Imports the fingerprints of every key in /root/.ssh/authorized_keys and
#       /home/*/.ssh/authorized_keys (the keys that are allowed today), runs one collection through the sandboxed
#       unit (must give up 1), then enables pft-authwatch.timer.
#   sudo ./install.sh --pull [--host sentry]   on the host that runs ../alerts: pft-authwatch-pull.service/.timer;
#       needs PULL_SSH in /etc/pft-authwatch.env (see pft-authwatch.env.example). Runs one pull (must exit 0), then
#       enables pft-authwatch-pull.timer (every minute at :50; the peer collects at :25).
#   sudo ./install.sh --uninstall | --pull --uninstall   disable the timer, remove the textfile (keeps state/allowlist)
# Alert rules: copy ../alerts/authwatch.rules.yml to /etc/pft-alerts/ and list it in prometheus.yml (../alerts).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units + conf).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-authwatch
LIBDIR=/usr/local/lib/pft-authwatch
CONF=/etc/pft-authwatch.env
ALLOWDIR=/etc/pft-authwatch
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
[[ "$host" =~ ^[a-z][a-z0-9_-]*$ ]] || { echo "bad host label" >&2; exit 3; }

same() { [ -f "$2" ] && cmp -s "$1" "$2"; }
put() { # SRC DST MODE: install only if the bytes differ, report either way
  if same "$1" "$2" && [ "$(stat -c %a "$2")" = "$3" ]; then log "unchanged $2"; else
    install -D -m "$3" "$1" "$2"; log "installed $2 (sha256 $(sha256sum < "$1" | cut -c1-64))"; changed=true; fi
}
changed=false
install_bin() {
  put "$HERE/pft-authwatch.sh" /usr/local/bin/pft-authwatch 755
  put "$HERE/authwatch_parse.py" "$LIBDIR/authwatch_parse.py" 644
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}
conf_set() { # KEY VALUE: set KEY in the root-owned conf (create it 0600)
  [ -f "$CONF" ] || { install -m 600 /dev/null "$CONF"; echo "# pft-authwatch settings (see authwatch/pft-authwatch.env.example)" > "$CONF"; }
  if grep -qx "$1=$2" "$CONF"; then return 0; fi
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
  log "set $1=$2 in $CONF"; changed=true
}

if $pull; then
  if $uninstall; then
    systemctl disable --now pft-authwatch-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_authwatch_$host.prom"
    log "disabled pft-authwatch-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-authwatch.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  [ "$host" = sentry ] || { echo "the pull unit is for --host sentry" >&2; exit 3; }
  install_bin
  put "$HERE/systemd/pft-authwatch-pull.service" /etc/systemd/system/pft-authwatch-pull.service 644
  put "$HERE/systemd/pft-authwatch-pull.timer" /etc/systemd/system/pft-authwatch-pull.timer 644
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-authwatch-pull.service || true
  if systemctl is-failed -q pft-authwatch-pull.service; then
    log "ERROR: first pull failed"; journalctl -u pft-authwatch-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E '^pft_authwatch_(up|collect_timestamp_seconds|allowlist_entries)\{' "$TEXTDIR/pft_authwatch_$host.prom"
  systemctl enable --now pft-authwatch-pull.timer 2>&1 | sed 's/^/  /'
  log "pft-authwatch-pull.timer $(systemctl is-active pft-authwatch-pull.timer) (every minute at :50); changed=$changed"
  exit 0
fi
if $uninstall; then
  systemctl disable --now pft-authwatch.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_authwatch_$host.prom"
  log "disabled pft-authwatch.timer, removed its textfile (kept $STATEDIR, $ALLOWDIR and the script/units)"
  exit 0
fi
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 3; }
command -v ssh-keygen >/dev/null || { echo "ssh-keygen missing" >&2; exit 3; }
install_bin
install -d -m 700 "$STATEDIR" "$ALLOWDIR"
conf_set HOST_LABEL "$host"
put "$HERE/systemd/pft-authwatch.service" /etc/systemd/system/pft-authwatch.service 644
put "$HERE/systemd/pft-authwatch.timer" /etc/systemd/system/pft-authwatch.timer 644
shopt -s nullglob
keys=()
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && keys+=("$f"); done
if [ ${#keys[@]} -gt 0 ]; then
  log "allowlist import from ${#keys[@]} authorized_keys file(s): $(/usr/local/bin/pft-authwatch allow import "${keys[@]}")"
else
  log "no authorized_keys files found; every login will be 'unknown' until you run: pft-authwatch allow add SHA256:..."
fi
systemctl daemon-reload
log "first collection (through the sandboxed unit):"
systemctl start pft-authwatch.service || true
if systemctl is-failed -q pft-authwatch.service; then
  log "ERROR: first collection failed"; journalctl -u pft-authwatch.service -n 5 --no-pager --utc; exit 1
fi
grep -E '^pft_authwatch_(up|collect_timestamp_seconds|allowlist_entries)\{' "$TEXTDIR/pft_authwatch_$host.prom"
grep -qx "pft_authwatch_up{host=\"$host\"} 1" "$TEXTDIR/pft_authwatch_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-authwatch.timer 2>&1 | sed 's/^/  /'
log "pft-authwatch.timer $(systemctl is-active pft-authwatch.timer) (every minute at :25); changed=$changed"
log "remember: sudo pft-integrity accept --reason 'pft-authwatch installed'"
