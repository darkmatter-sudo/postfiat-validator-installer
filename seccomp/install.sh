#!/usr/bin/env bash
# Install / uninstall pft-seccomp (+ hourly audit timer). Installing re-creates no container and changes no
# profile; `apply` does.
#   sudo ./install.sh [--host LABEL]   script -> /usr/local/bin/pft-seccomp, helper + pinned Docker profile + margin +
#       the libseccomp syscall table -> /usr/local/lib/pft-seccomp/, writes HOST_LABEL (validator by
#       default; --host sentry on a sentry) into /etc/pft-seccomp.env, adds `textfile pft_seccomp_*.prom 3h ...` to
#       /etc/pft-rulecheck.conf if pft-rulecheck is installed, runs one audit through the sandboxed unit (it must
#       write a textfile that passes `pft-seccomp validate`), then enables pft-seccomp.timer (hourly).
#   sudo ./install.sh --pull           on the host that runs ../alerts: pft-seccomp-pull.service/.timer; needs
#       PULL_SSH (and PEER_LABEL, default sentry) in /etc/pft-seccomp.env. One pull (must exit 0), then the timer.
#   sudo ./install.sh --uninstall | --pull --uninstall   refuses while an apply is in place (run
#       `pft-seccomp rollback --yes` first); disables the timer and removes the textfile.
# Alert rules: ../alerts/seccomp.rules.yml (PFTSeccompDrift, PFTSeccompDenied), listed in ../alerts/prometheus.yml.
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary, units, env).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P="${PFT_SC_ROOT:-}"   # test hook: path prefix for every file this script writes
SRC="${PFT_SC_SRC:-$HERE/pft-seccomp.sh}"   # test hooks: the tool and the unit files to install
UNITSRC="${PFT_SC_UNITSRC:-$HERE/systemd}"
LIBSRC="${PFT_SC_LIBSRC:-$HERE}"
SYSTEMCTL="${PFT_SC_SYSTEMCTL:-systemctl}"
JOURNALCTL="${PFT_SC_JOURNALCTL:-journalctl}"
TEXTDIR="$P/var/lib/pft-exporter/textfile"
CONF="$P/etc/pft-seccomp.env"
RC_CONF="$P/etc/pft-rulecheck.conf"
BIN="$P/usr/local/bin/pft-seccomp"
LIBDIR="$P/usr/local/lib/pft-seccomp"
UNITDIR="$P/etc/systemd/system"
STATE_DIR="${STATE_DIR:-$P/var/lib/pft-seccomp}"
RC_LINE='textfile pft_seccomp_*.prom   3h   pft_seccomp_last_run_timestamp_seconds'
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
  local f
  mkdir -p "$(dirname "$BIN")" "$LIBDIR"
  install -m 755 "$SRC" "$BIN"
  log "installed /usr/local/bin/pft-seccomp (sha256 $(sha256sum < "$SRC" | cut -c1-64))"
  for f in pft_seccomp.py ref/docker-default-29.1.3.json margin.tsv; do
    install -m 644 "$LIBSRC/$f" "$LIBDIR/${f##*/}"
    log "installed /usr/local/lib/pft-seccomp/${f##*/} (sha256 $(sha256sum < "$LIBSRC/$f" | cut -c1-64))"
  done
  if ! python3 -I "$LIBDIR/pft_seccomp.py" table > "$LIBDIR/syscall-table.tsv.tmp"; then
    rm -f "$LIBDIR/syscall-table.tsv.tmp"; log "ERROR: cannot build the syscall table from libseccomp.so.2"; exit 1
  fi
  chmod 644 "$LIBDIR/syscall-table.tsv.tmp"; mv -f "$LIBDIR/syscall-table.tsv.tmp" "$LIBDIR/syscall-table.tsv"
  log "wrote /usr/local/lib/pft-seccomp/syscall-table.tsv ($(grep -c $'\t' "$LIBDIR/syscall-table.tsv") syscalls)"
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
    "$SYSTEMCTL" disable --now pft-seccomp-pull.timer 2>/dev/null || true
    rm -f "$TEXTDIR/pft_seccomp_$peer.prom"
    log "disabled pft-seccomp-pull.timer, removed the pulled textfile"
    exit 0
  fi
  if ! { [ -f "$CONF" ] && { [ -n "$P" ] || [ "$(stat -c %u "$CONF")" = 0 ]; } && grep -q '^PULL_SSH=' "$CONF"; }; then
    echo "$CONF missing, not root-owned or without PULL_SSH (see pft-seccomp.env.example)" >&2; exit 3
  fi
  chmod 600 "$CONF"
  install_bin
  mkdir -p "$UNITDIR"
  install -m 644 "$UNITSRC/pft-seccomp-pull.service" "$UNITSRC/pft-seccomp-pull.timer" "$UNITDIR/"
  "$SYSTEMCTL" daemon-reload
  log "first pull (through the sandboxed unit):"
  "$SYSTEMCTL" start pft-seccomp-pull.service || true
  if "$SYSTEMCTL" is-failed -q pft-seccomp-pull.service; then
    log "ERROR: first pull failed"; "$JOURNALCTL" -u pft-seccomp-pull.service -n 5 --no-pager --utc; exit 1
  fi
  grep -E "^pft_seccomp_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_seccomp_$peer.prom"
  "$SYSTEMCTL" enable --now pft-seccomp-pull.timer
  log "enabled pft-seccomp-pull.timer (every 15 min)"
  exit 0
fi

host="${label:-$(conf_get HOST_LABEL)}"; host="${host:-validator}"
if $uninstall; then
  if st="$(applied)"; then
    echo "an apply is in place ($st): run 'sudo pft-seccomp rollback --yes' first (or keep it)" >&2; exit 3
  fi
  "$SYSTEMCTL" disable --now pft-seccomp.timer 2>/dev/null || true
  rm -f "$TEXTDIR/pft_seccomp_$host.prom"
  log "disabled pft-seccomp.timer, removed its textfile"
  exit 0
fi
install_bin
mkdir -p "$(dirname "$CONF")"
[ -f "$CONF" ] || printf '# pft-seccomp config (see pft-seccomp.env.example)\n' > "$CONF"
conf_set HOST_LABEL "$host"
[ -n "$P" ] || chown root:root "$CONF"
chmod 600 "$CONF"
if [ -f "$RC_CONF" ] && ! grep -q 'pft_seccomp_' "$RC_CONF"; then
  printf '# pft-seccomp (hourly audit; sentry copy pulled every 15 min)\n%s\n' "$RC_LINE" >> "$RC_CONF"
  log "added the pft_seccomp textfile line to /etc/pft-rulecheck.conf"
fi
mkdir -p "$UNITDIR"
install -m 644 "$UNITSRC/pft-seccomp.service" "$UNITSRC/pft-seccomp.timer" "$UNITDIR/"
"$SYSTEMCTL" daemon-reload
log "first audit (through the sandboxed unit, HOST_LABEL=$host):"
"$SYSTEMCTL" start pft-seccomp.service || true
if "$SYSTEMCTL" is-failed -q pft-seccomp.service; then
  log "ERROR: first audit failed"; "$JOURNALCTL" -u pft-seccomp.service -n 5 --no-pager --utc; exit 1
fi
SYSCALL_TABLE="$LIBDIR/syscall-table.tsv" "$BIN" validate "$TEXTDIR/pft_seccomp_$host.prom" "$host" || { log "ERROR: textfile rejected"; exit 1; }
grep -E "^pft_seccomp_(findings|last_run_timestamp_seconds)\{" "$TEXTDIR/pft_seccomp_$host.prom"
"$SYSTEMCTL" enable --now pft-seccomp.timer
log "enabled pft-seccomp.timer (hourly + up to 10 min)"
log "remember: sudo pft-integrity accept --reason 'pft-seccomp installed'"
