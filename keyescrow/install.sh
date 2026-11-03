#!/usr/bin/env bash
# Install / uninstall pft-keyescrow. Installing changes no secret, no add-on and not the node.
#   sudo ./install.sh [--host validator|sentry]
#       script -> /usr/local/bin/pft-keyescrow, tar helper -> /usr/local/lib/pft-keyescrow/, writes HOST_LABEL into
#       /etc/pft-keyescrow.env (0600), runs keygen if this host has no age identity yet (prints the PUBLIC
#       recipient), adds two textfile lines to /etc/pft-rulecheck.conf if pft-rulecheck is installed, installs
#       pft-keyescrow.service/.timer (hourly inventory + verify) but does NOT enable it: before the first escrow,
#       verify would report "no generation held" (PFTKeyEscrowVerifyFailed).
#   Then: on each host `sudo pft-keyescrow set-peer <the other host's recipient>`; on the validator PEER_SSH in
#       /etc/pft-keyescrow.env (see pft-keyescrow.env.example).
#   sudo ./install.sh --escrow-host    (validator) escrow + pull units; runs one escrow through the sandboxed unit
#       (must pass both directions), then enables pft-keyescrow-escrow.timer (nightly) and pft-keyescrow-pull.timer.
#   sudo ./install.sh --enable         (each host, after the first escrow) one run of pft-keyescrow.service (verify
#       must find a good held generation), then enables pft-keyescrow.timer.
#   sudo ./install.sh --uninstall      disables every pft-keyescrow timer and removes the textfiles; keeps STATE_DIR
#       (identity + held generations) and the conf.
# Alert rules: ../alerts/keyescrow.rules.yml, listed in ../alerts/prometheus.yml.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, helper, units, conf).
# shellcheck disable=SC2015 # "A && B || exit" is intended (the right side always exits)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
CONF=/etc/pft-keyescrow.env
RC_CONF=/etc/pft-rulecheck.conf
BIN=/usr/local/bin/pft-keyescrow
# first matching line wins; hourly timer (+5 min random delay), pulled copies lag up to 15 min more
RC_LINES='textfile pft_keyescrow_held*.prom  2h  pft_keyescrow_verify_timestamp_seconds
textfile pft_keyescrow*.prom       2h  pft_keyescrow_collect_timestamp_seconds'
label=""; mode=install
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) label="${2:?}"; shift ;;
    --escrow-host) mode=escrow-host ;;
    --enable) mode=enable ;;
    --uninstall) mode=uninstall ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
[ -z "$label" ] || [[ "$label" =~ ^(validator|sentry)$ ]] || { echo "--host must be validator or sentry" >&2; exit 3; }
conf_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'; }
run_unit() { # UNIT: start it, print this run's journal (a finished oneshot has no InvocationID left), fail if it failed
  local t0; t0="$(date -u +%s)"
  systemctl start "$1" || true
  journalctl -u "$1" --since "@$t0" --no-pager --utc -o cat | grep -v 'pam_limits\|pam_unix'
  if systemctl is-failed -q "$1"; then log "ERROR: $1 failed"; exit 1; fi
}

case "$mode" in
  uninstall)
    systemctl disable --now pft-keyescrow.timer pft-keyescrow-escrow.timer pft-keyescrow-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR"/pft_keyescrow*.prom
    log "disabled the pft-keyescrow timers, removed the textfiles (kept /var/lib/pft-keyescrow and $CONF)"
    exit 0 ;;
  escrow-host)
    [ -x "$BIN" ] || { echo "run ./install.sh first" >&2; exit 3; }
    [ -n "$(conf_get PEER_SSH)" ] && [ -n "$(conf_get PEER_RECIPIENT)" ] \
      || { echo "$CONF needs PEER_SSH and PEER_RECIPIENT (set-peer) first" >&2; exit 3; }
    install -m 644 "$HERE/systemd/pft-keyescrow-escrow.service" "$HERE/systemd/pft-keyescrow-escrow.timer" \
      "$HERE/systemd/pft-keyescrow-pull.service" "$HERE/systemd/pft-keyescrow-pull.timer" /etc/systemd/system/
    systemctl daemon-reload
    log "first escrow (through the sandboxed unit):"
    run_unit pft-keyescrow-escrow.service
    systemctl enable --now pft-keyescrow-escrow.timer pft-keyescrow-pull.timer
    log "enabled pft-keyescrow-escrow.timer (nightly 02:40 UTC) and pft-keyescrow-pull.timer (every 15 min)"
    exit 0 ;;
  enable)
    [ -x "$BIN" ] || { echo "run ./install.sh first" >&2; exit 3; }
    out="$("$BIN" verify 2>&1)" && ! grep -q 'no generation held' <<<"$out" \
      || { echo "verify does not pass yet (no good held generation): escrow first" >&2; exit 1; }
    log "one run of pft-keyescrow.service (inventory + verify, sandboxed):"
    run_unit pft-keyescrow.service
    grep -hE '^pft_keyescrow_(items|drift_items|inventory_exit_code|held_verify_ok)\{' \
      "$TEXTDIR/pft_keyescrow.prom" "$TEXTDIR/pft_keyescrow_held.prom"
    systemctl enable --now pft-keyescrow.timer
    log "enabled pft-keyescrow.timer (hourly)"
    exit 0 ;;
esac

command -v age >/dev/null && command -v age-keygen >/dev/null \
  || { echo "age and age-keygen are required (Ubuntu 22.04: apt-get install age)" >&2; exit 3; }
install -m 755 "$HERE/pft-keyescrow.sh" "$BIN"
install -d -m 755 /usr/local/lib/pft-keyescrow
install -m 644 "$HERE/keyescrow_tar.py" /usr/local/lib/pft-keyescrow/keyescrow_tar.py
log "installed $BIN (sha256 $(sha256sum < "$HERE/pft-keyescrow.sh" | cut -c1-64))"
log "installed /usr/local/lib/pft-keyescrow/keyescrow_tar.py (sha256 $(sha256sum < "$HERE/keyescrow_tar.py" | cut -c1-64))"
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if [ ! -f "$CONF" ]; then (umask 077; printf '# pft-keyescrow config (see pft-keyescrow.env.example)\n' > "$CONF"); fi
if grep -q '^HOST_LABEL=' "$CONF"; then sed -i "s|^HOST_LABEL=.*|HOST_LABEL=$host|" "$CONF"; else echo "HOST_LABEL=$host" >> "$CONF"; fi
chown root:root "$CONF"; chmod 600 "$CONF"
log "HOST_LABEL=$host in $CONF (0600 root)"
if [ -e /var/lib/pft-keyescrow/age.key ]; then log "age identity: kept; recipient $("$BIN" pubkey)"
else "$BIN" keygen | sed "s/^/$(date -u +%FT%TZ) keygen: /"; fi
if [ -f "$RC_CONF" ] && ! grep -q 'pft_keyescrow' "$RC_CONF"; then
  printf '# pft-keyescrow (inventory + verify hourly; sentry copy pulled every 15 min)\n%s\n' "$RC_LINES" >> "$RC_CONF"
  log "added the pft_keyescrow textfile lines to $RC_CONF"
fi
install -m 644 "$HERE/systemd/pft-keyescrow.service" "$HERE/systemd/pft-keyescrow.timer" /etc/systemd/system/
systemctl daemon-reload
log "pft-keyescrow.service/.timer installed, timer NOT enabled yet (./install.sh --enable after the first escrow)"
log "remember: sudo pft-integrity accept --reason 'pft-keyescrow installed'"
