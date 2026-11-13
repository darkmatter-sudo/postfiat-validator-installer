#!/usr/bin/env bash
# Install / uninstall pft-aptrust (+ twice-daily audit timer). Installing changes NO APT file; `pft-aptrust apply` does.
#   sudo ./install.sh [--host LABEL]   script -> /usr/local/bin/pft-aptrust, ../fleet/manifest.tsv ->
#       /usr/local/lib/pft-aptrust/manifest.tsv (the off-package allowlist: INSTALL_PATH column), pft-aptrust.service/
#       .timer, writes HOST_LABEL into /etc/pft-aptrust.env (validator by default; --host sentry on a sentry), adds
#       `textfile pft_aptrust_*.prom 15h pft_aptrust_last_run_timestamp_seconds` + `require pft_aptrust_LABEL.prom`
#       to /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one audit through the sandboxed unit (must
#       write up 1), then enables the timer.
#       Re-run it after installing more add-ons so the allowlist copy knows their files (until then: offpkg WARN only).
#   sudo ./install.sh --pull           on the host that runs ../alerts (after the line above): a drop-in that makes the
#       same run pull the peer's textfile, plus pft-aptrust-pull.timer (hourly :23 UTC: the peer's run may start after
#       this host's, RandomizedDelaySec) and `require pft_aptrust_PEER.prom`. Needs PULL_SSH (and PEER_LABEL, default
#       sentry) in /etc/pft-aptrust.env. Runs the unit and the pull unit once (both must succeed).
#   sudo ./install.sh --uninstall      refuses while an apply is in place (rollback first); disables the timers,
#       removes the drop-in, this host's textfile(s) and the pft_aptrust lines in /etc/pft-rulecheck.conf.
# Alert rules: ../alerts/aptrust.rules.yml, listed in ../alerts/prometheus.yml.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units), pft-schedaudit accept + collect,
#   pft-jobwatch inventory (interval 43200; validator pft-aptrust-pull.timer 3600).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
CONF=/etc/pft-aptrust.env
LIBDIR=/usr/local/lib/pft-aptrust
DROPIN=/etc/systemd/system/pft-aptrust.service.d/pull.conf
RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_aptrust_*.prom   15h  pft_aptrust_last_run_timestamp_seconds'
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
host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"

rc_add() { # $1 = exact line; appended once to the pft-rulecheck conf if pft-rulecheck is installed
  [ -f "$RC_CONF" ] || return 0
  grep -qxF "$1" "$RC_CONF" || { echo "$1" >> "$RC_CONF"; log "added to $RC_CONF: $1"; }
}

run_unit() { # one run through the sandboxed unit; must not fail
  systemctl start pft-aptrust.service || true
  if systemctl is-failed -q pft-aptrust.service; then
    log "ERROR: pft-aptrust.service failed"; journalctl -u pft-aptrust.service -n 8 --no-pager --utc; exit 1
  fi
}

if $uninstall; then
  [ ! -f /var/lib/pft-aptrust/apply.json ] || { echo "an apply is in place: sudo pft-aptrust rollback --yes first" >&2; exit 4; }
  systemctl disable --now pft-aptrust.timer 2>/dev/null || true
  systemctl disable --now pft-aptrust-pull.timer 2>/dev/null || true
  rm -f "$DROPIN"; rmdir "$(dirname "$DROPIN")" 2>/dev/null || true; systemctl daemon-reload
  rm -f "$TEXTDIR/pft_aptrust_$host.prom"
  [ ! -f "$RC_CONF" ] || sed -i '/pft_aptrust_/d' "$RC_CONF"
  peer="$(conf_get PEER_LABEL)"; [ -z "$(conf_get PULL_SSH)" ] || rm -f "$TEXTDIR/pft_aptrust_${peer:-sentry}.prom"
  log "disabled pft-aptrust.timer, removed the drop-in, textfile(s) and rulecheck lines (kept the script, $LIBDIR and $CONF)"
  exit 0
fi

if $pull; then
  peer="$(conf_get PEER_LABEL)"; peer="${peer:-sentry}"
  if ! { [ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-aptrust.env.example)" >&2; exit 3
  fi
  [ -x /usr/local/bin/pft-aptrust ] || { echo "run ./install.sh first" >&2; exit 3; }
  chmod 600 "$CONF"
  install -d -m 755 "$(dirname "$DROPIN")"
  printf '[Service]\nEnvironment=PFT_AT_PULL=1\n' > "$DROPIN"; chmod 644 "$DROPIN"
  systemctl daemon-reload
  install -m 644 "$HERE/systemd/pft-aptrust-pull.service" "$HERE/systemd/pft-aptrust-pull.timer" /etc/systemd/system/
  systemctl daemon-reload
  log "audit + pull (through the sandboxed unit):"
  run_unit
  log "pull (through the sandboxed pull unit):"
  systemctl start pft-aptrust-pull.service || { log "ERROR: pft-aptrust-pull.service failed"; journalctl -u pft-aptrust-pull.service -n 8 --no-pager --utc; exit 1; }
  grep -E "^pft_aptrust_(up|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_aptrust_$peer.prom"
  rc_add "require pft_aptrust_$peer.prom"
  systemctl enable --now pft-aptrust-pull.timer
  log "every pft-aptrust run now also pulls pft_aptrust_$peer.prom, and pft-aptrust-pull.timer pulls it hourly (:23 UTC)"
  exit 0
fi

for c in gpg gpgv jq apt-config dpkg; do command -v "$c" >/dev/null || { echo "$c is required" >&2; exit 3; }; done
[ -f "$HERE/../fleet/manifest.tsv" ] || { echo "../fleet/manifest.tsv missing (run from a repo checkout)" >&2; exit 3; }
install -m 755 "$HERE/pft-aptrust.sh" /usr/local/bin/pft-aptrust
install -d -m 755 "$LIBDIR"; install -m 644 "$HERE/../fleet/manifest.tsv" "$LIBDIR/manifest.tsv"
log "installed /usr/local/bin/pft-aptrust (sha256 $(sha256sum < "$HERE/pft-aptrust.sh" | cut -c1-64))"
log "installed $LIBDIR/manifest.tsv (sha256 $(sha256sum < "$HERE/../fleet/manifest.tsv" | cut -c1-64))"
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
if [ -f "$CONF" ]; then
  if grep -q '^HOST_LABEL=' "$CONF"; then sed -i "s/^HOST_LABEL=.*/HOST_LABEL=$host/" "$CONF"; else echo "HOST_LABEL=$host" >> "$CONF"; fi
else
  printf '# pft-aptrust config (see pft-aptrust.env.example)\nHOST_LABEL=%s\n' "$host" > "$CONF"
fi
chown root:root "$CONF"; chmod 600 "$CONF"
install -m 644 "$HERE/systemd/pft-aptrust.service" "$HERE/systemd/pft-aptrust.timer" /etc/systemd/system/
systemctl daemon-reload
grep -qF 'pft_aptrust_*.prom' "$RC_CONF" 2>/dev/null || rc_add "$RC_LINE"
rc_add "require pft_aptrust_$host.prom"
log "first audit (through the sandboxed unit, HOST_LABEL=$host):"
run_unit
grep -E "^pft_aptrust_(up|checks|sources|keys)\{" "$TEXTDIR/pft_aptrust_$host.prom"
grep -qx "pft_aptrust_up{host=\"$host\"} 1" "$TEXTDIR/pft_aptrust_$host.prom" || { log "ERROR: up != 1"; exit 1; }
systemctl enable --now pft-aptrust.timer
log "enabled pft-aptrust.timer (04:41 and 16:41 UTC + up to 10 min)"
log "remember: sudo pft-integrity accept --reason 'pft-aptrust installed'; pft-schedaudit accept + collect; pft-jobwatch inventory"
