#!/usr/bin/env bash
# Install / uninstall pft-apparmor (+ hourly audit timer). Installing loads NO profile and re-creates no container;
# `apply` does.
#   sudo ./install.sh [--host LABEL]   script -> /usr/local/bin/pft-apparmor, writes HOST_LABEL (validator by
#       default; --host sentry on a sentry) into /etc/pft-apparmor.env, adds `textfile pft_apparmor_*.prom 3h ...` to
#       /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one audit through the sandboxed unit (it must
#       write a textfile that passes `pft-apparmor validate`), then enables pft-apparmor.timer (hourly).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-apparmor-pull.service/.timer; needs
#       PULL_SSH (and PEER_LABEL, default sentry) in /etc/pft-apparmor.env. One pull (must exit 0), then the timer.
#   sudo ./install.sh --uninstall | --pull --uninstall   refuses while an apply is in place (run
#       `pft-apparmor rollback --yes` first); disables the timer and removes the textfile.
# Alert rule: ../alerts/apparmor.rules.yml, listed in ../alerts/prometheus.yml.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, units, env).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P="${PFT_AA_ROOT:-}"   # test hook: path prefix for every file this script writes
SRC="${PFT_AA_SRC:-$HERE/pft-apparmor.sh}"   # test hooks: the tool and the unit files to install
UNITSRC="${PFT_AA_UNITSRC:-$HERE/systemd}"
SYSTEMCTL="${PFT_AA_SYSTEMCTL:-systemctl}"
JOURNALCTL="${PFT_AA_JOURNALCTL:-journalctl}"
TEXTDIR="$P/var/lib/pft-exporter/textfile"
CONF="$P/etc/pft-apparmor.env"
RC_CONF="$P/etc/pft-rulecheck.conf"
BIN="$P/usr/local/bin/pft-apparmor"
UNITDIR="$P/etc/systemd/system"
STATE_DIR="${STATE_DIR:-$P/var/lib/pft-apparmor}"
RC_LINE='textfile pft_apparmor_*.prom   3h   pft_apparmor_last_run_timestamp_seconds'
label=""; uninstall=false; pull=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || [ -n "$P" ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) label="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    --pull) pull=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
[ -z "$label" ] || [[ "$label" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "bad host label" >&2; exit 3; }
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }
conf_set() { # conf_set KEY VALUE
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
}
install_bin() {
  mkdir -p "$(dirname "$BIN")"
  install -m 755 "$SRC" "$BIN"
  log "installed /usr/local/bin/pft-apparmor (sha256 $(sha256sum < "$SRC" | cut -c1-64))"
  mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
}
applied() { # -> the first apply state file whose apply is still in place (not rolled back)
  local f
  for f in "$STATE_DIR"/apply-*.json; do
    [ -f "$f" ] || continue
    jq -e '.rolled_back != true' "$f" >/dev/null 2>&1 && { echo "$f"; return 0; }
  done
  return 1
}

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if $uninstall; then
    "$SYSTEMCTL" disable --now pft-apparmor-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_apparmor_$peer.prom"
    log "disabled pft-apparmor-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && { [ -n "$P" ] || [ "$(stat -c %u "$CONF")" = 0 ]; } && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-apparmor.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  mkdir -p "$UNITDIR"
  install -m 644 "$UNITSRC/pft-apparmor-pull.service" "$UNITSRC/pft-apparmor-pull.timer" "$UNITDIR/"
  "$SYSTEMCTL" daemon-reload
  log "first pull (through the sandboxed unit):"
  "$SYSTEMCTL" start pft-apparmor-pull.service || true
  if "$SYSTEMCTL" is-failed -q pft-apparmor-pull.service; then
    log "ERROR: first pull failed"; "$JOURNALCTL" -u pft-apparmor-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_apparmor_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_apparmor_$peer.prom"
  "$SYSTEMCTL" enable --now pft-apparmor-pull.timer
  log "enabled pft-apparmor-pull.timer (every 15 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  if st="$(applied)"; then
    echo "an apply is in place ($st): run 'sudo pft-apparmor rollback --yes' first (or keep it)" >&2; exit 3
  fi
  "$SYSTEMCTL" disable --now pft-apparmor.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_apparmor_$host.prom"
  log "disabled pft-apparmor.timer, removed its textfile"
  exit 0
fi
install_bin
mkdir -p "$(dirname "$CONF")"
[ -f "$CONF" ] || printf '# pft-apparmor config (see pft-apparmor.env.example)\n' > "$CONF"
conf_set HOST_LABEL "$host"
[ -n "$P" ] || chown root:root "$CONF"
chmod 600 "$CONF"
if [ -f "$RC_CONF" ] && ! grep -q 'pft_apparmor_' "$RC_CONF"; then
  printf '# pft-apparmor (hourly audit; sentry copy pulled every 15 min)\n%s\n' "$RC_LINE" >> "$RC_CONF"
  log "added the pft_apparmor textfile line to /etc/pft-rulecheck.conf"
fi
mkdir -p "$UNITDIR"
install -m 644 "$UNITSRC/pft-apparmor.service" "$UNITSRC/pft-apparmor.timer" "$UNITDIR/"
"$SYSTEMCTL" daemon-reload
log "first audit (through the sandboxed unit, HOST_LABEL=$host):"
"$SYSTEMCTL" start pft-apparmor.service || true
if "$SYSTEMCTL" is-failed -q pft-apparmor.service; then
  log "ERROR: first audit failed"; "$JOURNALCTL" -u pft-apparmor.service -n 5 --no-pager --utc; exit 1
fi
"$BIN" validate "$TEXTDIR/pft_apparmor_$host.prom" "$host" || { log "ERROR: textfile rejected"; exit 1; }
grep -E "^pft_apparmor_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_apparmor_$host.prom"
"$SYSTEMCTL" enable --now pft-apparmor.timer
log "enabled pft-apparmor.timer (hourly + up to 10 min)"
log "remember: sudo pft-integrity accept --reason 'pft-apparmor installed'"
