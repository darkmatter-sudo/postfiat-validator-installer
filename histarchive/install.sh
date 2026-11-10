#!/usr/bin/env bash
# Install / uninstall pft-histarchive. Idempotent: a second run changes nothing.
#   sudo ./install.sh --role replica [--host sentry]       (the peer that stores the encrypted replica)
#       script -> /usr/local/bin/pft-histarchive, helper + lib -> /usr/local/lib/pft-histarchive/, replica dir
#       /var/lib/pft-histarchive/replica (0700 root), conf /etc/pft-histarchive.env (0600: HOST_LABEL). No units:
#       the archive host drives replication over PEER_SSH (`pft-histarchive serve ...`).
#   sudo ./install.sh --role archive [--host validator] [--adopt DIR]   (the host with the node)
#       same files + system user pft-histarchive, archive dir (0755, owned by that user), outbox (0700 root),
#       PEER_SSH copied from /etc/pft-keyescrow.env unless set, an age identity (keygen) unless present,
#       pft-histarchive.service (the follower) + pft-histarchive-periodic.service/.timer (every 5 min).
#       --adopt DIR: copy an existing archive (e.g. a pre-install live run) into the archive dir first; it must
#       verify, and the follower resumes it at its last ledger + 1. Install the replica role on the peer first:
#       this starts the follower, waits for its first ledger, runs one periodic through the sandboxed unit
#       (verify + replicate must PASS), then enables the timer.
#   sudo ./install.sh --uninstall   stop the follower and the timer, remove the textfiles (keeps data, conf, units)
# Alert rules: ../alerts/histarchive.rules.yml (listed in ../alerts/prometheus.yml with the install commit).
# Afterwards: sudo pft-integrity accept --reason "<why>"; sudo pft-schedaudit accept + collect; sudo pft-jobwatch
# inventory (new timer); pft-fleet manifest lines are in ../fleet/manifest.tsv.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-histarchive
LIBDIR=/usr/local/lib/pft-histarchive
CONF=/etc/pft-histarchive.env
KE=/etc/pft-keyescrow.env
USER_NAME=pft-histarchive
host=""; role=""; adopt=""; uninstall=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host="${2:?}"; shift ;;
    --role) role="${2:?}"; shift ;;
    --adopt) adopt="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done

if $uninstall; then
  systemctl disable --now pft-histarchive-periodic.timer pft-histarchive.service 2>/dev/null || true
  rm -f "$TEXTDIR"/pft_histarchive*.prom
  log "stopped the follower and the timer, removed the textfiles (kept $STATEDIR, $CONF, the script and the units)"
  exit 0
fi
case "$role" in
  archive) host="${host:-validator}" ;;
  replica) host="${host:-sentry}" ;;
  *) echo "--role archive|replica is required" >&2; exit 3 ;;
esac
[[ "$host" =~ ^[a-z][a-z0-9_-]{0,30}$ ]] || { echo "bad host label" >&2; exit 3; }
for c in python3 systemctl age age-keygen sha256sum tar; do command -v "$c" >/dev/null || { echo "$c missing" >&2; exit 3; }; done

same() { [ -f "$2" ] && cmp -s "$1" "$2"; }
changed=false
put() { # SRC DST MODE: install only if the bytes or mode differ, report either way
  if same "$1" "$2" && [ "$(stat -c %a "$2")" = "$3" ]; then log "unchanged $2"; else
    install -D -m "$3" "$1" "$2"; log "installed $2 (sha256 $(sha256sum < "$1" | cut -c1-64))"; changed=true; fi
}
conf_set() { # KEY VALUE: set KEY in the root-owned conf (create it 0600); VALUE is written as given
  [ -f "$CONF" ] || { install -m 600 /dev/null "$CONF"; echo "# pft-histarchive settings (see histarchive/README.md)" > "$CONF"; }
  if grep -qxF "$1=$2" "$CONF"; then return 0; fi
  if grep -q "^$1=" "$CONF"; then
    local tmp; tmp="$(mktemp "$CONF.XXXXXX")"
    awk -v k="$1" -v line="$1=$2" 'index($0, k "=") == 1 { print line; next } { print }' "$CONF" > "$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$CONF"
  else echo "$1=$2" >> "$CONF"; fi
  log "set $1 in $CONF"; changed=true
}
conf_has() { grep -q "^$1=" "$CONF" 2>/dev/null; }
run_unit() { # UNIT: start it, print this run's journal, fail if it failed
  local t0; t0="$(date -u +%s)"
  systemctl start "$1" || true
  journalctl -u "$1" --since "@$t0" --no-pager --utc -o cat | grep -v 'pam_limits\|pam_unix' || true
  if systemctl is-failed -q "$1"; then log "ERROR: $1 failed"; exit 1; fi
}

put "$HERE/pft-histarchive.sh" /usr/local/bin/pft-histarchive 755
put "$HERE/histarchive.py" "$LIBDIR/histarchive.py" 644
put "$HERE/lib_hashverify.py" "$LIBDIR/lib_hashverify.py" 644
install -d -m 755 "$STATEDIR"
conf_set HOST_LABEL "$host"
chmod 600 "$CONF"

if [ "$role" = replica ]; then
  install -d -m 700 "$STATEDIR/replica"
  log "replica role ready: $(pft-histarchive replica-check 2>&1 | tail -n 1)"
  log "changed=$changed"
  exit 0
fi

# ---- archive role
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$USER_NAME"
  log "created system user $USER_NAME"; changed=true
fi
install -d -m 700 "$STATEDIR/outbox"
if [ -n "$adopt" ] && [ ! -e "$STATEDIR/archive/state.json" ]; then
  [ -f "$adopt/state.json" ] || { echo "--adopt $adopt: no state.json there" >&2; exit 3; }
  log "adopting the archive in $adopt (must verify first):"
  python3 "$LIBDIR/histarchive.py" verify --dir "$adopt" | tail -n 1
  python3 "$LIBDIR/histarchive.py" verify --dir "$adopt" > /dev/null || { log "ERROR: $adopt does not verify"; exit 1; }
  install -d -m 755 -o "$USER_NAME" -g "$USER_NAME" "$STATEDIR/archive"
  cp -a "$adopt/." "$STATEDIR/archive/"
  rm -f "$STATEDIR/archive/follow.log"
  chown -R "$USER_NAME:$USER_NAME" "$STATEDIR/archive"
  log "adopted: $(python3 "$LIBDIR/histarchive.py" verify --dir "$STATEDIR/archive" | tail -n 1)"
  changed=true
fi
install -d -m 755 -o "$USER_NAME" -g "$USER_NAME" "$STATEDIR/archive"
if ! conf_has PEER_SSH; then
  v="$(sed -n 's/^PEER_SSH=//p' "$KE" 2>/dev/null)"; [ -n "$v" ] || { echo "PEER_SSH not set and not in $KE" >&2; exit 3; }
  conf_set PEER_SSH "$v"
fi
if [ ! -s "$STATEDIR/age.key" ]; then pft-histarchive keygen; changed=true; fi
for u in pft-histarchive.service pft-histarchive-periodic.service pft-histarchive-periodic.timer; do
  put "$HERE/systemd/$u" "/etc/systemd/system/$u" 644
done
systemctl daemon-reload
systemctl enable --now pft-histarchive.service 2>&1 | sed 's/^/  /'
if $changed; then systemctl restart pft-histarchive.service; fi
for _ in $(seq 1 60); do
  [ -f "$STATEDIR/archive/status.json" ] && [ "$(stat -c %Y "$STATEDIR/archive/status.json")" -ge "$(( $(date +%s) - 30 ))" ] && break
  sleep 2
done
systemctl is-active -q pft-histarchive.service || { log "ERROR: follower not active"; journalctl -u pft-histarchive.service -n 20 --no-pager --utc -o cat; exit 1; }
log "follower: $(journalctl -u pft-histarchive.service -n 3 --no-pager --utc -o cat | tr '\n' ' ')"
rm -f "$STATEDIR/last-verify" "$STATEDIR/last-replicate" # the first periodic run does both
log "first periodic run (through the sandboxed unit):"
run_unit pft-histarchive-periodic.service
grep -hE '^pft_histarchive_(verify_ok|replica_ok|follow_last_ledger|lag_ledgers)\{' "$TEXTDIR"/pft_histarchive*.prom
grep -qx "pft_histarchive_verify_ok{host=\"$host\"} 1" "$TEXTDIR/pft_histarchive.prom" || { log "ERROR: verify not OK"; exit 1; }
if [ -s "$STATEDIR/archive/MANIFEST.jsonl" ]; then
  grep -qx "pft_histarchive_replica_ok{host=\"$host\"} 1" "$TEXTDIR/pft_histarchive_replica.prom" || { log "ERROR: replica not OK"; exit 1; }
fi
systemctl enable --now pft-histarchive-periodic.timer 2>&1 | sed 's/^/  /'
log "units: follower=$(systemctl is-active pft-histarchive.service) timer=$(systemctl is-active pft-histarchive-periodic.timer) changed=$changed"
log "remember: pft-integrity accept, pft-schedaudit accept + collect, pft-jobwatch inventory"
