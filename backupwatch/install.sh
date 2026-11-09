#!/usr/bin/env bash
# Install / uninstall pft-backupwatch. Idempotent: a second run changes nothing.
#   sudo ./install.sh --role replica [--host sentry]      (the peer that holds the encrypted replicas)
#       script -> /usr/local/bin/pft-backupwatch, helper -> /usr/local/lib/pft-backupwatch/, state + replica dirs
#       (0700), conf /etc/pft-backupwatch.env (0600 root: ROLE=replica, HOST_LABEL), pft-backupwatch.service/.timer
#       (collect every 15 min at :07:20). Needs REPLICA_IDENTITY (default: ../keyescrow's /var/lib/pft-keyescrow/age.key).
#       Runs one collection through the sandboxed unit (must give up 1), then enables the timer.
#   sudo ./install.sh --role archive [--host validator]   (the host with the pft-backup archives)
#       same files + ROLE=archive, OFFHOST=1, PEER_SSH and REPLICA_RECIPIENT copied from /etc/pft-keyescrow.env
#       (PEER_SSH / PEER_RECIPIENT: the same admin link and the peer's age recipient keyescrow uses) unless already
#       set; pft-backupwatch-replicate.service (started by pft-backup.service's OnSuccess= drop-in right after each
#       backup, then OnSuccess= a collect) + .timer (fallback, daily 04:05 + up to 10 min) and pft-backupwatch-pull
#       .service/.timer (:09:20 every 15 min). The replica role must be installed on the peer first: this runs one
#       replicate, one collect and one pull through the sandboxed units (each must succeed, offhost OK), then
#       enables the three timers.
#   sudo ./install.sh --uninstall   disable this host's timers, remove its textfiles (keeps state, replicas, conf)
# Alert rules: ../alerts/backupwatch.rules.yml, listed in ../alerts/prometheus.yml. rulecheck lines: see README.
# Afterwards: sudo pft-integrity accept --reason "<why>"; pft-schedaudit accept (new timers).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEXTDIR=/var/lib/pft-exporter/textfile
STATEDIR=/var/lib/pft-backupwatch
LIBDIR=/usr/local/lib/pft-backupwatch
CONF=/etc/pft-backupwatch.env
KE=/etc/pft-keyescrow.env
host=""; role=""; uninstall=false
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host="${2:?}"; shift ;;
    --role) role="${2:?}"; shift ;;
    --uninstall) uninstall=true ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done

if $uninstall; then
  systemctl disable --now pft-backupwatch.timer pft-backupwatch-pull.timer pft-backupwatch-replicate.timer 2>/dev/null || true
  rm -f "$TEXTDIR"/pft_backupwatch_*.prom /etc/systemd/system/pft-backup.service.d/pft-backupwatch.conf
  systemctl daemon-reload
  log "disabled the pft-backupwatch timers, removed the textfiles and the pft-backup OnSuccess drop-in (kept $STATEDIR, $CONF and the script/units)"
  exit 0
fi
case "$role" in
  archive) host="${host:-validator}" ;;
  replica) host="${host:-sentry}" ;;
  *) echo "--role archive|replica is required" >&2; exit 3 ;;
esac
[[ "$host" =~ ^[a-z][a-z0-9_-]{0,30}$ ]] || { echo "bad host label" >&2; exit 3; }
for c in python3 systemctl age sha256sum; do command -v "$c" >/dev/null || { echo "$c missing" >&2; exit 3; }; done

same() { [ -f "$2" ] && cmp -s "$1" "$2"; }
changed=false
put() { # SRC DST MODE: install only if the bytes or mode differ, report either way
  if same "$1" "$2" && [ "$(stat -c %a "$2")" = "$3" ]; then log "unchanged $2"; else
    install -D -m "$3" "$1" "$2"; log "installed $2 (sha256 $(sha256sum < "$1" | cut -c1-64))"; changed=true; fi
}
conf_set() { # KEY VALUE: set KEY in the root-owned conf (create it 0600); VALUE is written as given
  [ -f "$CONF" ] || { install -m 600 /dev/null "$CONF"; echo "# pft-backupwatch settings (see backupwatch/README.md)" > "$CONF"; }
  if grep -qxF "$1=$2" "$CONF"; then return 0; fi
  if grep -q "^$1=" "$CONF"; then
    local tmp; tmp="$(mktemp "$CONF.XXXXXX")"
    awk -v k="$1" -v line="$1=$2" 'index($0, k "=") == 1 { print line; next } { print }' "$CONF" > "$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$CONF"
  else echo "$1=$2" >> "$CONF"; fi
  log "set $1 in $CONF"; changed=true
}
conf_has() { grep -q "^$1=" "$CONF" 2>/dev/null; }
run_unit() { # UNIT: start it, print this run's journal (a finished oneshot has no InvocationID left), fail if it failed
  local t0; t0="$(date -u +%s)"
  systemctl start "$1" || true
  journalctl -u "$1" --since "@$t0" --no-pager --utc -o cat | grep -v 'pam_limits\|pam_unix' || true
  if systemctl is-failed -q "$1"; then log "ERROR: $1 failed"; exit 1; fi
}

put "$HERE/pft-backupwatch.sh" /usr/local/bin/pft-backupwatch 755
put "$HERE/backupwatch_lib.py" "$LIBDIR/backupwatch_lib.py" 644
mkdir -p "$TEXTDIR"; chmod 755 "$TEXTDIR"
install -d -m 700 "$STATEDIR"
conf_set ROLE "$role"
conf_set HOST_LABEL "$host"
chmod 600 "$CONF"
units=(pft-backupwatch)
if [ "$role" = replica ]; then
  install -d -m 700 "$STATEDIR/replicas"
  idf="$(sed -n 's/^REPLICA_IDENTITY=//p' "$CONF" | tr -d "\"'")"; idf="${idf:-/var/lib/pft-keyescrow/age.key}"
  [ -s "$idf" ] || { echo "replica identity $idf missing (install ../keyescrow first, or set REPLICA_IDENTITY)" >&2; exit 3; }
else
  # the admin link and the peer's age recipient: the ones ../keyescrow already uses (never printed)
  if ! conf_has PEER_SSH; then
    v="$(sed -n 's/^PEER_SSH=//p' "$KE" 2>/dev/null)"; [ -n "$v" ] || { echo "PEER_SSH not set and not in $KE" >&2; exit 3; }
    conf_set PEER_SSH "$v"
  fi
  if ! conf_has REPLICA_RECIPIENT; then
    v="$(sed -n 's/^PEER_RECIPIENT=//p' "$KE" 2>/dev/null | tr -d "\"'")"
    [[ "$v" =~ ^age1[a-z0-9]{58}$ ]] || { echo "REPLICA_RECIPIENT not set and no age recipient in $KE" >&2; exit 3; }
    conf_set REPLICA_RECIPIENT "$v"
  fi
  conf_set OFFHOST 1
  units+=(pft-backupwatch-replicate pft-backupwatch-pull)
  # pft-backup.service -> replicate as soon as a backup succeeds (the 04:05 timer stays as the fallback)
  put "$HERE/systemd/pft-backup.service.d/pft-backupwatch.conf" /etc/systemd/system/pft-backup.service.d/pft-backupwatch.conf 644
fi
for u in "${units[@]}"; do
  put "$HERE/systemd/$u.service" "/etc/systemd/system/$u.service" 644
  put "$HERE/systemd/$u.timer" "/etc/systemd/system/$u.timer" 644
done
systemctl daemon-reload
if [ "$role" = archive ]; then
  log "first replicate (through the sandboxed unit):"
  run_unit pft-backupwatch-replicate.service
fi
log "first collection (through the sandboxed unit):"
run_unit pft-backupwatch.service
grep -E '^pft_backupwatch_(up|check_state|replicas|replica_verify_ok)\{' "$TEXTDIR/pft_backupwatch_$host.prom"
grep -qx "pft_backupwatch_up{host=\"$host\"} 1" "$TEXTDIR/pft_backupwatch_$host.prom" || { log "ERROR: up != 1"; exit 1; }
if [ "$role" = archive ]; then
  grep -qx "pft_backupwatch_check_state{host=\"$host\",check=\"offhost\"} 0" "$TEXTDIR/pft_backupwatch_$host.prom" \
    || { log "ERROR: offhost check not OK after the first replicate"; exit 1; }
  log "first pull of the peer's textfile (through the sandboxed unit):"
  run_unit pft-backupwatch-pull.service
  peer="$(sed -n 's/^PEER_LABEL=//p' "$CONF")"; peer="${peer:-sentry}"
  grep -E '^pft_backupwatch_(up|replicas|replica_verify_ok)\{' "$TEXTDIR/pft_backupwatch_$peer.prom"
fi
for u in "${units[@]}"; do systemctl enable --now "$u.timer" 2>&1 | sed 's/^/  /'; done
log "timers: $(for u in "${units[@]}"; do printf '%s=%s ' "$u.timer" "$(systemctl is-active "$u.timer")"; done)changed=$changed"
log "remember: sudo pft-integrity accept --reason 'pft-backupwatch installed'; pft-schedaudit accept (new timers)"
