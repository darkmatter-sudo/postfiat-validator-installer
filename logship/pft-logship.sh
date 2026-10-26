#!/usr/bin/env bash
# pft-logship: cross-host journald forwarding between two Post Fiat node hosts (validator <-> sentry), so that a
# host's logs survive on its peer when the host itself is wiped or tampered with. Uses the distro's
# systemd-journal-upload (sender) and systemd-journal-remote (receiver, socket on TCP 19532) with mutual TLS from a
# private two-host CA. Each host makes its own private key; only CSRs and certificates travel. No node restart.
#
# Usage: pft-logship plan  [--peer-name NAME]
#        sudo pft-logship apply|rollback [--dry-run] [--purge-keys]
#        sudo pft-logship sign CSR_FILE > host.crt          (CA host only)
#        sudo pft-logship check|lag [--textfile]
#
#  plan     read-only. Prints the drop-ins, the vacuum timer, the peer-scoped UFW rule (address from the root-only
#           conf, printed as <peer>), and every step apply will take.
#  apply    installs the package, makes this host's key + CSR, and once host.crt/ca.crt are in place writes the
#           drop-ins, the vacuum timer and the UFW rule and starts the units. --dry-run prints every action only.
#  sign     CA host: creates the pair CA once (its key stays on this host) and signs a CSR from either host.
#  check    units active, cert valid, mutual-TLS handshake with the peer, send lag <= MAX_LAG, cursor not stalled,
#           newest entry received from the peer <= MAX_LAG old. Exit 1 on any failure. --textfile as for lag.
#  lag      reads journal-upload's saved cursor and the newest local journal entry and prints the forwarding lag
#           (newest local entry time - time of the last uploaded entry, from the cursor's t= field). With
#           --textfile also writes pft_logship_up / pft_logship_lag_seconds for the pft exporter (atomic rename).
#  rollback disables the units, removes drop-ins/timer/UFW rule; keeps received journals (and keys unless --purge-keys).
#
# Exit codes: 0 ok, 1 lag/check failure, 3 usage/config error, 4 apply waiting for a signed certificate.
# Conf: PFT_LS_CONF (/etc/pft-logship.env, root-owned, sourced first): SELF_NAME, PEER_NAME (labels such as
#       validator-host; the receiver names stored files after the sender's cert CN), SELF_ADDR, PEER_ADDR (IPs, kept
#       out of the repo), CA_HERE (1 on the CA host), MAX_LAG (120 s), STORE_CAP (2G per sender),
#       TEXTFILE_DIR (/var/lib/pft-exporter/textfile), DOCKER_CONTAINERS (names, space-separated: containers whose
#       docker json-file logs are copied into the journal by pft-logship-dockerlog@NAME so they are shipped too)
# Test hooks: PFT_LS_TEST=1 (no root)  PFT_LS_ROOT (prefix for host paths)  PFT_LS_JOURNALCTL  PFT_LS_NEWEST_USEC
#             PFT_LS_SYSTEMCTL  PFT_LS_CURL  PFT_LS_NOW

set -uo pipefail
umask 022

TEST="${PFT_LS_TEST:-}"
R="${PFT_LS_ROOT:-}"
CONF="${PFT_LS_CONF:-$R/etc/pft-logship.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = "$(id -u)" ] && . "$CONF"
PEER_NAME="${PEER_NAME:-}"
PEER_ADDR="${PEER_ADDR:-}"
SELF_NAME="${SELF_NAME:-}"
SELF_ADDR="${SELF_ADDR:-}"
CA_HERE="${CA_HERE:-0}"
PORT=19532
MAX_LAG="${MAX_LAG:-120}"
STORE_CAP="${STORE_CAP:-2G}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
DOCKER_CONTAINERS="${DOCKER_CONTAINERS:-}"
TLS_DIR=/etc/pft-logship/tls
CA_DIR=/etc/pft-logship/ca
REMOTE_DIR=/var/log/journal/remote
UPLOAD_DROPIN=/etc/systemd/journal-upload.conf.d/pft-logship.conf
REMOTE_DROPIN=/etc/systemd/journal-remote.conf.d/pft-logship.conf
UNIT_DROPIN=/etc/systemd/system/systemd-journal-upload.service.d/pft-logship.conf
VAC_UNIT=/etc/systemd/system/pft-logship-vacuum
CHECK_STATE=/var/lib/pft-logship/check.state
DL_BIN=/usr/local/sbin/pft-logship-dockerlog
DL_UNIT=/etc/systemd/system/pft-logship-dockerlog@.service
DL_SRC="${PFT_LS_DL_SRC:-$(dirname "${BASH_SOURCE[0]}")/pft-logship-dockerlog.py}"
# journal-upload runs with DynamicUser=yes: it gets the root-only key as a credential at this fixed path
UPLOAD_CRED=/run/credentials/systemd-journal-upload.service
# ... and StateDirectory=systemd/journal-upload, so the real state dir is under private/
UPLOAD_STATE="${UPLOAD_STATE:-/var/lib/private/systemd/journal-upload/state}"
JOURNALCTL="${PFT_LS_JOURNALCTL:-journalctl}"
SYSTEMCTL="${PFT_LS_SYSTEMCTL:-systemctl}"
CURL="${PFT_LS_CURL:-curl}"
OPENSSL=openssl

usage() { sed -n '7,10p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "pft-logship: $1" >&2; exit "${2:-3}"; }
need_root() { [ -n "$TEST" ] || [ "$(id -u)" -eq 0 ] || die "$CMD needs root (sudo)" 3; }

cursor_usec() { # CURSOR -> realtime (usec, decimal) from its t= field; empty + rc 1 if absent/malformed
  local t
  t="$(tr ';' '\n' <<<"$1" | sed -nE 's/^t=([0-9a-f]{1,16})$/\1/p')"
  [ -n "$t" ] || return 1
  printf '%d\n' "0x$t"
}
lag_seconds() { # NEWEST_USEC CURSOR_USEC -> whole seconds, never negative (an uploaded entry can't be newer)
  awk -v n="$1" -v c="$2" 'BEGIN { d = (n - c) / 1e6; if (d < 0) d = 0; printf "%d\n", d }'
}
saved_cursor() { sed -nE 's/^LAST_CURSOR=(.+)$/\1/p' "$R$UPLOAD_STATE" 2>/dev/null | tail -n 1; }
newest_local_usec() { "$JOURNALCTL" -n 1 -o json --no-pager 2>/dev/null | jq -r '.__REALTIME_TIMESTAMP // empty'; }

render_metrics() { # UP LAG -> textfile body (LAG may be empty when up=0)
  printf '# HELP pft_logship_up 1 if journal-upload has a saved cursor that could be read\n'
  printf '# TYPE pft_logship_up gauge\npft_logship_up %d\n' "$1"
  if [ -n "$2" ]; then
    printf '# HELP pft_logship_lag_seconds Newest local journal entry minus last uploaded entry\n'
    printf '# TYPE pft_logship_lag_seconds gauge\npft_logship_lag_seconds %d\n' "$2"
  fi
}
write_textfile() { # BODY: atomic replace, the exporter never sees a half-written file
  local d="$R$TEXTFILE_DIR" tmp
  [ -d "$d" ] || die "textfile dir $TEXTFILE_DIR missing (is the pft exporter installed?)" 3
  tmp="$(mktemp "$d/.pft_logship.prom.XXXXXX")" || die "cannot write in $TEXTFILE_DIR" 3
  printf '%s\n' "$1" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$d/pft_logship.prom"
}

render_upload_conf() { # [URLHOST] -> journal-upload.conf drop-in (the key comes in as a systemd credential)
  printf '# pft-logship: upload this host'"'"'s journal to %s over mutual TLS\n[Upload]\n' "${PEER_NAME:-<peer>}"
  printf 'URL=https://%s:%d\n' "${1:-<peer>}" "$PORT"
  printf 'ServerKeyFile=%s/host.key\nServerCertificateFile=%s/host.crt\nTrustedCertificateFile=%s/ca.crt\n' \
    "$UPLOAD_CRED" "$TLS_DIR" "$TLS_DIR"
}
render_remote_conf() { # -> journal-remote.conf drop-in
  printf '# pft-logship: receive the peer'"'"'s journal; clients must present a cert from the pft-logship CA\n[Remote]\n'
  printf 'Seal=false\nSplitMode=host\nServerKeyFile=%s/host.key\nServerCertificateFile=%s/host.crt\n' "$TLS_DIR" "$TLS_DIR"
  printf 'TrustedCertificateFile=%s/ca.crt\n' "$TLS_DIR"
}
render_unit_dropin() { # -> systemd-journal-upload.service drop-in: a DynamicUser can't read a root key, so hand it over
  printf '# pft-logship: journal-upload runs as a DynamicUser; pass the root-only key as a credential\n[Unit]\n'
  printf 'StartLimitIntervalSec=0\n[Service]\nLoadCredential=host.key:%s/host.key\nRestart=always\nRestartSec=10\n' "$TLS_DIR"
}
render_vacuum_service() {
  printf '# pft-logship: cap stored peer journals at %s (archived files only; the active file is never removed)\n' "$STORE_CAP"
  printf '[Unit]\nDescription=pft-logship: cap received peer journals\n[Service]\nType=oneshot\n'
  printf 'ExecStart=journalctl --directory=%s --vacuum-size=%s\n' "$REMOTE_DIR" "$STORE_CAP"
}
render_vacuum_timer() {
  printf '[Unit]\nDescription=pft-logship: hourly cap of received peer journals\n[Timer]\nOnCalendar=hourly\n'
  printf 'Persistent=true\n[Install]\nWantedBy=timers.target\n'
}
render_dockerlog_unit() { # -> pft-logship-dockerlog@.service: one bridge per container, its stdout is the journal
  printf '# pft-logship: copy container %%i'"'"'s docker json-file log into the journal (SyslogIdentifier=%%i)\n'
  printf '[Unit]\nDescription=pft-logship: container %%i logs -> journal\nAfter=docker.service\nWants=docker.service\n'
  printf 'StartLimitIntervalSec=0\n[Service]\nExecStart=/usr/bin/python3 -I %s %%i\nSyslogIdentifier=%%i\n' "$DL_BIN"
  printf 'StandardOutput=journal\nStandardError=journal\n'
  printf '# ~800 lines/min steady, more while catching up after a restart: no journald rate limit for this unit\n'
  printf 'LogRateLimitIntervalSec=0\nRestart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n'
}
render_ufw() { # [ADDR] [allow|delete allow] -> the one UFW rule apply adds (peer address only; <peer> when printed)
  printf 'ufw %s proto tcp from %s to any port %d comment pft-logship\n' "${2:-allow}" "${1:-<peer>}" "$PORT"
}

print_plan() {
  echo "pft-logship plan - $(date -u +%FT%TZ) - $(grep PRETTY_NAME "$R/etc/os-release" 2>/dev/null | cut -d'"' -f2)"
  echo "this host: ${SELF_NAME:-<unset>} | peer: ${PEER_NAME:-<unset: PEER_NAME in /etc/pft-logship.env>} | peer address: $([ -n "$PEER_ADDR" ] && echo '<set, not printed>' || echo '<unset>') | CA here: $CA_HERE"
  echo "systemd-journal-remote package: $(dpkg-query -W -f '${Status} ${Version}' systemd-journal-remote 2>/dev/null || echo 'not installed')"
  echo
  echo "== $UPLOAD_DROPIN"; render_upload_conf ""
  echo; echo "== $REMOTE_DROPIN"; render_remote_conf
  echo; echo "== $UNIT_DROPIN"; render_unit_dropin
  echo; echo "== $VAC_UNIT.service"; render_vacuum_service
  echo; echo "== $VAC_UNIT.timer"; render_vacuum_timer
  echo; echo "== $DL_UNIT (containers: ${DOCKER_CONTAINERS:-none})"; render_dockerlog_unit
  echo; echo "== firewall"; render_ufw ""
  echo; echo "== steps apply will take"
  echo "1. apt-get install systemd-journal-remote (receiver + uploader units, disabled until configured)"
  echo "2. $TLS_DIR: this host makes its own key + CSR (the key never leaves the host). On the CA host, 'sign' turns"
  echo "   a CSR into a cert (CSR and certificate travel over ssh, keys do not). apply exits 4 until host.crt + ca.crt exist."
  echo "3. host.key 0640 root:systemd-journal-remote; journal-upload gets it via LoadCredential (it runs as a DynamicUser)"
  echo "4. write the drop-ins and timer above and the UFW rule (peer address only), then enable --now"
  echo "   systemd-journal-remote.socket, systemd-journal-upload and pft-logship-vacuum.timer (cap $STORE_CAP per"
  echo "   sender: journal-remote in systemd 249 has no MaxUse=)"
  echo "5. containers log through docker's json-file driver, not journald: install $DL_BIN and start"
  echo "   pft-logship-dockerlog@NAME for each of DOCKER_CONTAINERS (${DOCKER_CONTAINERS:-none}); resumes from its saved"
  echo "   docker timestamp, so the container is never touched (no log-driver change, no restart)"
  echo "6. pft-integrity accept for the new package/units/config (no postfiatd restart at any step)"
}

# --- apply / sign / check / rollback ---------------------------------------------------------------------------
mask() { # TEXT -> TEXT with both host addresses replaced, so apply/rollback output can be published as is
  local t="$1"
  [ -n "$PEER_ADDR" ] && t="${t//"$PEER_ADDR"/<peer>}"
  [ -n "$SELF_ADDR" ] && t="${t//"$SELF_ADDR"/<self>}"
  printf '%s\n' "$t"
}
run() { # CMD... : print (addresses masked), and run unless --dry-run
  mask "+ $*"
  [ "$DRY" -eq 1 ] && return 0
  "$@"
}
put() { # PATH MODE BODY : write a file (dry-run: only show it)
  echo "+ write $1 ($2)"
  if [ "$DRY" -eq 1 ]; then mask "$3" | sed 's/^/    /'; return 0; fi
  mkdir -p "$(dirname "$R$1")" && printf '%s\n' "$3" > "$R$1" && chmod "$2" "$R$1"
}
need_conf() {
  local v
  for v in SELF_NAME PEER_NAME SELF_ADDR PEER_ADDR; do
    [ -n "${!v}" ] || die "$v is not set in $CONF" 3
  done
  [[ "$SELF_NAME" =~ ^[a-z0-9-]+$ && "$PEER_NAME" =~ ^[a-z0-9-]+$ ]] || die "SELF_NAME/PEER_NAME must be [a-z0-9-] labels" 3
  for v in $DOCKER_CONTAINERS; do
    [[ "$v" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "DOCKER_CONTAINERS: bad container name $v" 3
  done
}
make_csr() { # this host's key (never leaves it) + CSR: CN = SELF_NAME, SAN = IP:SELF_ADDR (the peer's upload URL host)
  if [ -f "$R$TLS_DIR/host.key" ]; then echo "= $TLS_DIR/host.key exists (kept)"
  else run "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$R$TLS_DIR/host.key"; fi
  run "$OPENSSL" req -new -key "$R$TLS_DIR/host.key" -subj "/CN=$SELF_NAME/O=pft-logship" \
    -addext "subjectAltName=IP:$SELF_ADDR" -out "$R$TLS_DIR/host.csr"
}
cert_ok() { # 0 if host.crt chains to ca.crt, matches host.key and is valid for at least another day; else prints why
  local d="$R$TLS_DIR"
  if [ ! -f "$d/host.crt" ] || [ ! -f "$d/ca.crt" ]; then echo "host.crt or ca.crt missing"; return 1; fi
  "$OPENSSL" verify -CAfile "$d/ca.crt" "$d/host.crt" >/dev/null 2>&1 || { echo "host.crt does not chain to ca.crt"; return 1; }
  [ "$("$OPENSSL" x509 -noout -pubkey -in "$d/host.crt" | sha256sum)" = "$("$OPENSSL" pkey -pubout -in "$d/host.key" 2>/dev/null | sha256sum)" ] \
    || { echo "host.crt does not match host.key"; return 1; }
  "$OPENSSL" x509 -noout -checkend 86400 -in "$d/host.crt" >/dev/null || { echo "host.crt expires within 24h"; return 1; }
}
do_sign() { # CSR_FILE -> certificate PEM on stdout (CA host only). The CA key is made here once and never leaves.
  local csr="$1" ca="$R$CA_DIR" ext rc
  [ "$CA_HERE" = 1 ] || die "CA_HERE=1 is not set in $CONF: sign only on the CA host" 3
  [ -f "$csr" ] || die "no CSR file $csr" 3
  # OpenSSL 3.0.2 'req -verify' exits 0 even on "self-signature verify failure": judge by the OK line
  "$OPENSSL" req -verify -noout -in "$csr" 2>&1 | grep -q 'self-signature verify OK' || die "CSR signature does not verify" 3
  "$OPENSSL" req -noout -text -in "$csr" | grep -q 'IP Address:' || die "CSR has no IP subjectAltName" 3
  mkdir -p "$ca" && chmod 700 "$ca"
  if [ ! -f "$ca/ca.key" ]; then
    (umask 077; "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$ca/ca.key" 2>/dev/null) \
      || die "CA key creation failed" 1
    "$OPENSSL" req -x509 -new -key "$ca/ca.key" -days 3650 -subj "/CN=pft-logship pair CA/O=pft-logship" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$ca/ca.crt" 2>/dev/null || die "CA creation failed" 1
    echo "pft-logship: new pair CA in $CA_DIR" >&2
  fi
  ext="$(mktemp)"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n' > "$ext"
  # the SAN comes from the CSR (checked above); every other extension from $ext
  "$OPENSSL" x509 -req -in "$csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -CAcreateserial -days 825 -sha256 \
    -copy_extensions copy -extfile "$ext" 2>/dev/null; rc=$?
  rm -f "$ext"; [ "$rc" -eq 0 ] || die "signing failed" 1
}
do_apply() {
  local c
  need_conf
  echo "pft-logship apply$([ "$DRY" -eq 1 ] && echo ' --dry-run') - $(date -u +%FT%TZ) - this host $SELF_NAME -> peer $PEER_NAME"
  if dpkg-query -W -f '${Status}' systemd-journal-remote 2>/dev/null | grep -q 'ok installed'; then
    echo "= systemd-journal-remote installed"
  else run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q systemd-journal-remote || die "package install failed" 1; fi
  run mkdir -p "$R$TLS_DIR" && run chmod 755 "$R$TLS_DIR"
  if [ -f "$R$TLS_DIR/host.csr" ] && [ -f "$R$TLS_DIR/host.key" ]; then echo "= $TLS_DIR/host.key + host.csr exist (kept)"
  else make_csr || die "key/CSR creation failed" 1; fi
  run chown root:systemd-journal-remote "$R$TLS_DIR/host.key" && run chmod 640 "$R$TLS_DIR/host.key"
  if [ "$DRY" -eq 0 ] && ! cert_ok >/dev/null; then
    echo "PENDING: $(cert_ok). Sign $TLS_DIR/host.csr on the CA host (pft-logship sign FILE), install the result"
    echo "         as $TLS_DIR/host.crt and the CA cert as $TLS_DIR/ca.crt, then run apply again."
    return 4
  fi
  put "$UPLOAD_DROPIN" 644 "$(render_upload_conf "$PEER_ADDR")"
  put "$REMOTE_DROPIN" 644 "$(render_remote_conf)"
  put "$UNIT_DROPIN" 644 "$(render_unit_dropin)"
  put "$VAC_UNIT.service" 644 "$(render_vacuum_service)"
  put "$VAC_UNIT.timer" 644 "$(render_vacuum_timer)"
  # shellcheck disable=SC2046  # word splitting of the rendered rule is intended
  run $(render_ufw "$PEER_ADDR") || die "ufw rule failed" 1
  run "$SYSTEMCTL" daemon-reload
  run "$SYSTEMCTL" enable --now systemd-journal-remote.socket pft-logship-vacuum.timer || die "enable failed" 1
  run "$SYSTEMCTL" enable systemd-journal-upload.service
  run "$SYSTEMCTL" restart systemd-journal-upload.service || die "journal-upload did not start" 1
  if [ -n "$DOCKER_CONTAINERS" ]; then
    [ -f "$DL_SRC" ] || die "bridge source $DL_SRC missing (run apply from the logship/ folder)" 3
    run install -m 755 "$DL_SRC" "$R$DL_BIN" || die "bridge install failed" 1
    put "$DL_UNIT" 644 "$(render_dockerlog_unit)"
    run "$SYSTEMCTL" daemon-reload
    for c in $DOCKER_CONTAINERS; do
      run "$SYSTEMCTL" enable --now "pft-logship-dockerlog@$c.service" || die "bridge for $c did not start" 1
    done
  fi
  if [ "$DRY" -eq 1 ]; then echo "dry-run: nothing changed"
  else echo "applied. Next: sudo pft-integrity accept --reason 'pft-logship apply', then pft-logship check"; fi
}
tls_probe() { # 0 if the peer's journal-remote completes a mutual-TLS handshake with our cert (any HTTP status)
  local code
  code="$("$CURL" -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$R$TLS_DIR/ca.crt" \
    --cert "$R$TLS_DIR/host.crt" --key "$R$TLS_DIR/host.key" "https://$PEER_ADDR:$PORT/" 2>/dev/null)"
  code="${code:-000}"
  if [ "$code" != 000 ]; then echo "tls: mutual-TLS handshake with $PEER_NAME journal-remote ok (HTTP $code)"
  else echo "tls: mutual-TLS handshake with $PEER_NAME journal-remote FAILED"; return 1; fi
}
peer_rx_age() { # seconds since the newest entry received FROM the peer; rc 1 if there is none
  local nu
  nu="$("$JOURNALCTL" --directory="$R$REMOTE_DIR" -n 1 -o json --no-pager 2>/dev/null | jq -r '.__REALTIME_TIMESTAMP // empty')"
  [ -n "$nu" ] || return 1
  echo $(( ${PFT_LS_NOW:-$(date +%s)} - nu / 1000000 ))
}
ident_age() { # NAME -> seconds since the newest LOCAL journal entry with SyslogIdentifier NAME; rc 1 if none
  local nu
  nu="$("$JOURNALCTL" -t "$1" -n 1 -o json --no-pager 2>/dev/null | jq -r '.__REALTIME_TIMESTAMP // empty')"
  [ -n "$nu" ] || return 1
  echo $(( ${PFT_LS_NOW:-$(date +%s)} - nu / 1000000 ))
}
stalled() { # CURSOR LAG: 0 (stalled) if the cursor has not moved for >= MAX_LAG while the local journal is ahead of it
  local f="$R$CHECK_STATE" now prev prevt
  now="${PFT_LS_NOW:-$(date +%s)}"
  prev="$(sed -n 1p "$f" 2>/dev/null)"; prevt="$(sed -n 2p "$f" 2>/dev/null)"
  # keep the time the cursor was FIRST seen at this value, so a check every minute still detects a stall
  [ "$prev" = "$1" ] && [ -n "$prevt" ] || prevt="$now"
  mkdir -p "$(dirname "$f")" && printf '%s\n%s\n' "$1" "$prevt" > "$f"
  [ "$2" -gt 0 ] && [ $((now - prevt)) -ge "$MAX_LAG" ]
}
do_check() { # TEXTFILE(0|1)
  local rc=0 out lag age u why c
  need_conf
  echo "pft-logship check - $(date -u +%FT%TZ) - $SELF_NAME -> $PEER_NAME (max lag ${MAX_LAG}s)"
  for u in systemd-journal-upload.service systemd-journal-remote.socket pft-logship-vacuum.timer; do
    if [ "$("$SYSTEMCTL" is-active "$u" 2>/dev/null)" = active ]; then echo "unit: $u active"
    else echo "unit: $u NOT active"; rc=1; fi
  done
  for c in $DOCKER_CONTAINERS; do
    if [ "$("$SYSTEMCTL" is-active "pft-logship-dockerlog@$c.service" 2>/dev/null)" != active ]; then
      echo "unit: pft-logship-dockerlog@$c.service NOT active"; rc=1
    elif ! age="$(ident_age "$c")"; then echo "bridge: no journal entries from $c"; rc=1
    else
      echo "bridge: pft-logship-dockerlog@$c active, newest $c journal entry ${age}s old"
      [ "$age" -le "$MAX_LAG" ] || { echo "bridge: older than ${MAX_LAG}s"; rc=1; }
    fi
  done
  if why="$(cert_ok)"; then echo "cert: host.crt chains to ca.crt, matches host.key, valid > 24h"
  else echo "cert: $why"; rc=1; fi
  tls_probe || rc=1
  out="$(do_lag "$1")" || rc=1
  echo "send: $out"
  lag="$(sed -nE 's/^lag: ([0-9]+)s.*/\1/p' <<<"$out")"
  if [ -n "$lag" ] && stalled "$(saved_cursor)" "$lag"; then
    echo "send: cursor STALLED (unchanged for >= ${MAX_LAG}s while the local journal is ${lag}s ahead)"; rc=1
  fi
  if age="$(peer_rx_age)"; then
    echo "receive: newest entry from $PEER_NAME is ${age}s old"
    [ "$age" -le "$MAX_LAG" ] || { echo "receive: older than ${MAX_LAG}s"; rc=1; }
  else echo "receive: no entries from $PEER_NAME in $REMOTE_DIR"; rc=1; fi
  echo "RESULT: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL) -> exit $rc"
  return "$rc"
}
do_rollback() { # removes config, units and the UFW rule; keeps received journals (evidence) and the package
  local c
  echo "pft-logship rollback$([ "$DRY" -eq 1 ] && echo ' --dry-run') - $(date -u +%FT%TZ)"
  run "$SYSTEMCTL" disable --now systemd-journal-upload.service systemd-journal-remote.socket pft-logship-vacuum.timer
  run "$SYSTEMCTL" stop systemd-journal-remote.service
  for c in $DOCKER_CONTAINERS; do run "$SYSTEMCTL" disable --now "pft-logship-dockerlog@$c.service"; done
  run rm -f "$R$DL_UNIT" "$R$DL_BIN"
  run rm -f "$R$UPLOAD_DROPIN" "$R$REMOTE_DROPIN" "$R$UNIT_DROPIN" "$R$VAC_UNIT.service" "$R$VAC_UNIT.timer" "$R$CHECK_STATE"
  if [ -n "$PEER_ADDR" ]; then
    # shellcheck disable=SC2046  # word splitting of the rendered rule is intended
    run $(render_ufw "$PEER_ADDR" "delete allow")
  else echo "= PEER_ADDR unset: remove the pft-logship UFW rule by hand (ufw status numbered)"; fi
  run "$SYSTEMCTL" daemon-reload
  [ "$PURGE_KEYS" -eq 1 ] && run rm -rf "$R$TLS_DIR"
  echo "kept: received journals in $REMOTE_DIR, bridge resume state in /var/lib/pft-logship/dockerlog, the systemd-journal-remote package$([ "$PURGE_KEYS" -eq 1 ] || echo ", $TLS_DIR (--purge-keys removes it)")"
}

do_lag() { # TEXTFILE(0|1)
  local cur cu nu lag up=1 rc=0
  cur="$(saved_cursor)"
  if [ -z "$cur" ]; then echo "journal-upload: no saved cursor in $UPLOAD_STATE"; up=0; rc=1
  elif ! cu="$(cursor_usec "$cur")"; then echo "journal-upload: saved cursor has no t= field"; up=0; rc=1
  else
    nu="${PFT_LS_NEWEST_USEC:-$(newest_local_usec)}"
    [ -n "$nu" ] || die "cannot read the newest local journal entry" 1
    lag="$(lag_seconds "$nu" "$cu")"
    echo "lag: ${lag}s (last uploaded entry $(date -u -d "@$((cu / 1000000))" +%FT%TZ), max $MAX_LAG s)"
    [ "$lag" -le "$MAX_LAG" ] || rc=1
  fi
  [ "$1" -eq 1 ] && write_textfile "$(render_metrics "$up" "${lag:-}")"
  return "$rc"
}

CMD="${1:-}"; [ -n "$CMD" ] || { usage; exit 3; }; shift
TXT=0; DRY=0; PURGE_KEYS=0; ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --textfile) TXT=1 ;; --peer-name) PEER_NAME="${2:?}"; shift ;;
    --dry-run) DRY=1 ;; --purge-keys) PURGE_KEYS=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option $1" 3 ;;
    *) [ -z "$ARG" ] || die "extra argument $1" 3; ARG="$1" ;;
  esac; shift
done
case "$CMD" in
  plan) print_plan ;;
  lag) need_root; do_lag "$TXT" ;;
  check) need_root; do_check "$TXT" ;;
  apply) [ "$DRY" -eq 1 ] || need_root; do_apply ;;
  rollback) [ "$DRY" -eq 1 ] || need_root; do_rollback ;;
  sign) need_root; [ -n "$ARG" ] || die "sign needs a CSR file" 3; do_sign "$ARG" ;;
  -h|--help|help) usage ;;
  *) usage; exit 3 ;;
esac
