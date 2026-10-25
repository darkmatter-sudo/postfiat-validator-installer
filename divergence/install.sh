#!/usr/bin/env bash
# Install / uninstall pft-divergence (+ 1-minute timer).
#   sudo ./install.sh --sources "..." [--ssh-runas USER] [--no-exporter]
#       script -> /usr/local/bin/pft-divergence, units, /etc/pft-divergence/divergence.env (written once from the
#       example with --sources/--ssh-runas filled in; an existing file is kept), textfile dir
#       /var/lib/pft-exporter/textfile (0755). If ../exporter is installed (/opt/pft-exporter) and differs, the
#       textfile-capable pft_exporter.py is installed and pft-exporter restarted (the node is not touched).
#       Then one check is run in the foreground and the timer is enabled.
#   sudo ./install.sh --uninstall      removes script, units, state and the .prom file; keeps /etc/pft-divergence
# Afterwards: sudo pft-integrity accept --reason "<why>" (new binary + units).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
CONF_DIR=/etc/pft-divergence
TEXTDIR=/var/lib/pft-exporter/textfile
sources=""; runas=""; exporter=true
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --sources) sources="$2"; shift ;;
    --ssh-runas) runas="$2"; shift ;;
    --no-exporter) exporter=false ;;
    --uninstall)
      systemctl disable --now pft-divergence.timer 2>/dev/null || true
      rm -f /etc/systemd/system/pft-divergence.service /etc/systemd/system/pft-divergence.timer \
        /usr/local/bin/pft-divergence "$TEXTDIR/pft_divergence.prom"
      systemctl daemon-reload; rm -rf /var/lib/pft-divergence
      echo "removed (kept $CONF_DIR)"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done
command -v jq >/dev/null || { echo "jq required (apt-get install jq)" >&2; exit 3; }
[ -n "$sources" ] || [ -f "$CONF_DIR/divergence.env" ] || { echo "--sources required on first install" >&2; exit 3; }
# validate the source list with the script itself before installing anything
if [ -n "$sources" ]; then
  PFT_DIVERGENCE_CONF=/nonexistent bash "$HERE/pft-divergence.sh" --sources "$sources" --check-config
fi

install -m 755 "$HERE/pft-divergence.sh" /usr/local/bin/pft-divergence
log "installed /usr/local/bin/pft-divergence (sha256 $(sha256sum "$HERE/pft-divergence.sh" | cut -c1-12))"
mkdir -p "$CONF_DIR" "$TEXTDIR" /var/lib/pft-divergence
chmod 755 "$CONF_DIR" "$TEXTDIR"
if [ ! -f "$CONF_DIR/divergence.env" ]; then
  awk -v s="$sources" -v u="$runas" '
    /^SOURCES=/ { print "SOURCES=\"" s "\""; next }
    /^SSH_RUNAS=/ { print "SSH_RUNAS=\"" u "\""; next } { print }' "$HERE/divergence.env.example" > "$CONF_DIR/divergence.env"
  chmod 644 "$CONF_DIR/divergence.env"
  log "wrote $CONF_DIR/divergence.env"
else
  log "kept existing $CONF_DIR/divergence.env"
fi

if $exporter && [ -f /opt/pft-exporter/pft_exporter.py ]; then
  if cmp -s "$ROOT/exporter/pft_exporter.py" /opt/pft-exporter/pft_exporter.py; then
    log "exporter already textfile-capable"
  else
    install -m 0644 -o root -g root "$ROOT/exporter/pft_exporter.py" /opt/pft-exporter/pft_exporter.py
    systemctl restart pft-exporter
    log "exporter updated (sha256 $(sha256sum "$ROOT/exporter/pft_exporter.py" | cut -c1-12)), pft-exporter restarted"
  fi
else
  log "no exporter on this host: the textfile is written but not scraped"
fi

install -m 644 "$HERE/pft-divergence.service" "$HERE/pft-divergence.timer" /etc/systemd/system/
systemctl daemon-reload
log "first check:"
rc=0; /usr/local/bin/pft-divergence || rc=$?
log "first check exit $rc (0 AGREE, 1 UNKNOWN, 2 DIVERGED)"
systemctl enable --now pft-divergence.timer
log "enabled pft-divergence.timer (every 60 s)"
if [ -f /opt/pft-exporter/pft_exporter.py ]; then
  for _ in $(seq 1 10); do curl -fsS --max-time 2 http://127.0.0.1:9877/metrics 2>/dev/null | grep -q '^pft_divergence_check_timestamp ' && break; sleep 1; done
  curl -fsS --max-time 2 http://127.0.0.1:9877/metrics | grep -E '^pft_(divergence_(state|overall_state|last_agree_ledger)|textfile_errors)' \
    || { log "ERROR: exporter does not expose pft_divergence_*"; exit 1; }
fi
log "remember: sudo pft-integrity accept --reason 'pft-divergence installed'"
