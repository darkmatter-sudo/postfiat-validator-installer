#!/usr/bin/env bash
# Install / uninstall pft-rulecheck.
#   sudo ./install.sh [--no-prom] [--host-label NAME] [--conf FILE]
#       script -> /usr/local/bin/pft-rulecheck, helper -> /usr/local/lib/pft-rulecheck/rulecheck_lib.py,
#       pft-rulecheck.service/.timer (hourly at :17). Writes /etc/pft-rulecheck.env (HOST_LABEL, NO_PROM) if it does
#       not exist, and /etc/pft-rulecheck.conf from FILE (default: pft-rulecheck.conf.example, or
#       pft-rulecheck.sentry.conf.example with --no-prom) if it does not exist. Runs one check through the
#       sandboxed unit (must succeed: exit 0 or 1, up 1), then enables the timer.
#       --no-prom: a host without Prometheus (the sentry): textfile checks only. HOST_LABEL defaults to validator,
#       or sentry with --no-prom.
#   sudo ./install.sh --pull     on the Prometheus host: pft-rulecheck-pull.service/.timer (every 15 min); needs
#       PEER_LABEL and PULL_SSH in /etc/pft-rulecheck.env (see pft-rulecheck.env.example). Runs one pull (must
#       exit 0), then enables the timer.
#   sudo ./install.sh --uninstall | --pull --uninstall
# Alert rules: ../alerts/rulecheck.rules.yml (listed in ../alerts/prometheus.yml; reload Prometheus).
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
LIBDIR=/usr/local/lib/pft-rulecheck
ENVF=/etc/pft-rulecheck.env
CONFF=/etc/pft-rulecheck.conf
noprom=false; label=""; conf=""; pull=false; uninstall=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --no-prom) noprom=true ;;
    --host-label) label="${2:?}"; shift ;;
    --conf) conf="${2:?}"; shift ;;
    --pull) pull=true ;;
    --uninstall) uninstall=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
if [ -z "$label" ]; then if $noprom; then label=sentry; else label=validator; fi; fi
[[ "$label" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo "bad host label" >&2; exit 3; }

if $pull; then
  if $uninstall; then
    systemctl disable --now pft-rulecheck-pull.timer 2>/dev/null || true
    rm -f /etc/systemd/system/pft-rulecheck-pull.service /etc/systemd/system/pft-rulecheck-pull.timer
    systemctl daemon-reload
    log "disabled pft-rulecheck-pull.timer (pulled textfile kept; remove it by hand if wanted)"
    exit 0
  fi
  if ! { [ -f "$ENVF" ] && [ "$(stat -c %u "$ENVF")" = 0 ] && grep -q '^PULL_SSH=' "$ENVF" && grep -q '^PEER_LABEL=' "$ENVF"; }; then
    echo "$ENVF missing, not root-owned or without PEER_LABEL/PULL_SSH (see pft-rulecheck.env.example)" >&2; exit 3
  fi
  [ -x /usr/local/bin/pft-rulecheck ] || { echo "install pft-rulecheck first (sudo ./install.sh)" >&2; exit 3; }
  chmod 600 "$ENVF"
  install -m 644 "$HERE/systemd/pft-rulecheck-pull.service" "$HERE/systemd/pft-rulecheck-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "first pull (through the sandboxed unit):"
  systemctl start pft-rulecheck-pull.service || { journalctl -u pft-rulecheck-pull.service -n 5 --no-pager; exit 1; }
  systemctl enable --now pft-rulecheck-pull.timer
  log "pft-rulecheck-pull.timer enabled: $(systemctl show -p NextElapseUSecRealtime --value pft-rulecheck-pull.timer)"
  exit 0
fi

if $uninstall; then
  systemctl disable --now pft-rulecheck.timer 2>/dev/null || true
  rm -f /etc/systemd/system/pft-rulecheck.service /etc/systemd/system/pft-rulecheck.timer \
        /usr/local/bin/pft-rulecheck "$TEXTDIR/pft_rulecheck_$label.prom"
  rm -rf "$LIBDIR"
  systemctl daemon-reload
  log "removed pft-rulecheck (kept $ENVF and $CONFF)"
  exit 0
fi

install -m 755 "$HERE/pft-rulecheck.sh" /usr/local/bin/pft-rulecheck
install -d -m 755 "$LIBDIR"
install -m 644 "$HERE/rulecheck_lib.py" "$LIBDIR/rulecheck_lib.py"
log "installed /usr/local/bin/pft-rulecheck (sha256 $(sha256sum < "$HERE/pft-rulecheck.sh" | cut -c1-64))"
log "installed $LIBDIR/rulecheck_lib.py (sha256 $(sha256sum < "$HERE/rulecheck_lib.py" | cut -c1-64))"
if [ ! -e "$ENVF" ]; then
  ( umask 077; printf '# pft-rulecheck config (see pft-rulecheck.env.example)\nHOST_LABEL=%s\nNO_PROM=%s\n' \
      "$label" "$($noprom && echo 1 || echo 0)" > "$ENVF" )
  log "wrote $ENVF (HOST_LABEL=$label NO_PROM=$($noprom && echo 1 || echo 0))"
else
  log "kept existing $ENVF"
fi
if [ ! -e "$CONFF" ]; then
  if [ -z "$conf" ]; then if $noprom; then conf="$HERE/pft-rulecheck.sentry.conf.example"; else conf="$HERE/pft-rulecheck.conf.example"; fi; fi
  install -m 644 "$conf" "$CONFF"
  log "wrote $CONFF from $(basename "$conf")"
else
  log "kept existing $CONFF"
fi
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
install -m 644 "$HERE/systemd/pft-rulecheck.service" "$HERE/systemd/pft-rulecheck.timer" /etc/systemd/system/
systemctl daemon-reload
log "first check (through the sandboxed unit; exit 1 = findings is a success for the unit):"
systemctl start pft-rulecheck.service || { journalctl -u pft-rulecheck.service -n 20 --no-pager; exit 1; }
grep -qx "pft_rulecheck_up{host=\"$label\"} 1" "$TEXTDIR/pft_rulecheck_$label.prom" \
  || { echo "first run did not give up 1" >&2; journalctl -u pft-rulecheck.service -n 20 --no-pager; exit 1; }
journalctl -u pft-rulecheck.service -n 200 --no-pager -o cat --since "-2min" | grep -E '^(RESULT|ERROR)' | tail -2
systemctl enable --now pft-rulecheck.timer
log "pft-rulecheck.timer enabled: $(systemctl show -p NextElapseUSecRealtime --value pft-rulecheck.timer)"
