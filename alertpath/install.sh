#!/usr/bin/env bash
# Install / uninstall the alertpath add-on.
#
# Validator host (runs ../alerts):  sudo ./install.sh validator --relay HOST [--port 22] [--label validator]
#   installs pft-alertpath, the loopback sink (pft-alertpath-sink.service, 127.0.0.1:9096, DynamicUser) and the 30s
#   push timer; creates /etc/pft-alertpath (0700) with hmac.key (64 hex, 0600) and its own SSH key if missing,
#   and pins the sentry host key (compare the printed fingerprint with
#   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the sentry). The watchdog rule and route live in
#   ../alerts (alertmanager.yml route "alertpath", prometheus.yml rule_files /etc/pft-alertpath/*.rules.yml);
#   re-run `../alerts/run-stack.sh up` once so Prometheus mounts this folder.
#   Then copy hmac.key and id_ed25519.pub to the sentry over an existing secure channel.
# Sentry host:  sudo ./install.sh sentry --pubkey FILE --hmac-key FILE --ntfy-env FILE
#   creates the system user pftap (locked password) whose authorized_keys entry is
#   `restrict,command="/usr/local/bin/pft-alertpath receive"` - it can only drop a message into the spool;
#   installs hmac.key and ntfy.env (NTFY_SERVER/NTFY_TOPIC[/NTFY_TOKEN]) as 0600 root, and the 60s check timer.
# Remove:  sudo ./install.sh uninstall validator|sentry [--purge]   (--purge also deletes keys and state)
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF_DIR=/etc/pft-alertpath
SPOOL=/var/lib/pft-alertpath-spool
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
role="${1:-}"; [ $# -gt 0 ] && shift
relay="" port=22 label=validator pubkey="" hmac="" ntfy="" purge=0 target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --relay) relay="$2"; shift ;;
    --port) port="$2"; shift ;;
    --label) label="$2"; shift ;;
    --pubkey) pubkey="$2"; shift ;;
    --hmac-key) hmac="$2"; shift ;;
    --ntfy-env) ntfy="$2"; shift ;;
    --purge) purge=1 ;;
    validator|sentry) target="$1" ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
  shift
done

case "$role" in
validator)
  [ -n "$relay" ] || { echo "--relay HOST required" >&2; exit 3; }
  for b in curl jq ssh ssh-keygen ssh-keyscan sha256sum ss python3; do
    command -v "$b" >/dev/null || { echo "missing $b" >&2; exit 3; }
  done
  install -d -m 700 "$CONF_DIR"
  [ -f "$CONF_DIR/hmac.key" ] || { od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$CONF_DIR/hmac.key"; echo "created $CONF_DIR/hmac.key"; }
  [ -f "$CONF_DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C pft-alertpath -f "$CONF_DIR/id_ed25519"
  if [ ! -s "$CONF_DIR/known_hosts" ]; then
    ssh-keyscan -T 10 -p "$port" -t ed25519 "$relay" 2>/dev/null > "$CONF_DIR/known_hosts"
    [ -s "$CONF_DIR/known_hosts" ] || { echo "ssh-keyscan of the sentry failed" >&2; exit 2; }
    echo "pinned sentry host key: $(ssh-keygen -lf "$CONF_DIR/known_hosts" | awk '{print $2}')"
  fi
  printf 'RELAY_TARGET=pftap@%s\nRELAY_PORT=%s\nNODE_LABEL=%s\n' "$relay" "$port" "$label" > "$CONF_DIR/push.conf"
  chmod 600 "$CONF_DIR"/*
  install -m 755 "$HERE/pft-alertpath.sh" /usr/local/bin/pft-alertpath
  install -d -m 755 /usr/local/lib/pft-alertpath
  install -m 644 "$HERE/alertpath_sink.py" /usr/local/lib/pft-alertpath/alertpath_sink.py
  install -m 644 "$HERE/pft-alertpath-sink.service" "$HERE/pft-alertpath-push.service" "$HERE/pft-alertpath-push.timer" \
    /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now pft-alertpath-sink.service pft-alertpath-push.timer
  echo "installed. Copy $CONF_DIR/hmac.key and $CONF_DIR/id_ed25519.pub to the sentry."
  ;;
sentry)
  for f in "$pubkey" "$hmac" "$ntfy"; do [ -f "$f" ] || { echo "--pubkey, --hmac-key and --ntfy-env files required" >&2; exit 3; }; done
  grep -qxE '[0-9a-fA-F]{64}' "$hmac" || { echo "hmac key must be 64 hex characters" >&2; exit 3; }
  grep -q '^NTFY_TOPIC=.' "$ntfy" || { echo "ntfy env needs NTFY_TOPIC=" >&2; exit 3; }
  for b in curl jq flock sha256sum; do command -v "$b" >/dev/null || { echo "missing $b" >&2; exit 3; }; done
  install -d -m 700 "$CONF_DIR"
  install -m 600 -o root -g root "$hmac" "$CONF_DIR/hmac.key"
  install -m 600 -o root -g root "$ntfy" "$CONF_DIR/ntfy.env"
  install -m 755 "$HERE/pft-alertpath.sh" /usr/local/bin/pft-alertpath
  id pftap >/dev/null 2>&1 || useradd --system --home-dir "$SPOOL" --shell /bin/sh pftap
  passwd -l pftap >/dev/null
  install -d -m 700 -o pftap -g pftap "$SPOOL" "$SPOOL/.ssh"
  printf 'restrict,command="/usr/local/bin/pft-alertpath receive" %s\n' "$(head -1 "$pubkey")" > "$SPOOL/.ssh/authorized_keys"
  chown pftap:pftap "$SPOOL/.ssh/authorized_keys"; chmod 600 "$SPOOL/.ssh/authorized_keys"
  install -m 644 "$HERE/pft-alertpath-check.service" "$HERE/pft-alertpath-check.timer" /etc/systemd/system/
  systemctl daemon-reload; systemctl enable --now pft-alertpath-check.timer
  echo "installed. State: sudo pft-alertpath status"
  ;;
uninstall)
  case "$target" in
    validator)
      systemctl disable --now pft-alertpath-push.timer pft-alertpath-sink.service 2>/dev/null || true
      rm -f /etc/systemd/system/pft-alertpath-sink.service /etc/systemd/system/pft-alertpath-push.service \
        /etc/systemd/system/pft-alertpath-push.timer /usr/local/bin/pft-alertpath
      rm -rf /usr/local/lib/pft-alertpath
      [ "$purge" -eq 1 ] && rm -rf /var/lib/private/pft-alertpath /var/lib/pft-alertpath ;;
    sentry)
      systemctl disable --now pft-alertpath-check.timer 2>/dev/null || true
      rm -f /etc/systemd/system/pft-alertpath-check.service /etc/systemd/system/pft-alertpath-check.timer \
        /usr/local/bin/pft-alertpath
      if id pftap >/dev/null 2>&1; then userdel pftap; fi
      rm -rf "$SPOOL"
      [ "$purge" -eq 1 ] && rm -rf /var/lib/pft-alertpath ;;
    *) echo "uninstall validator|sentry" >&2; exit 3 ;;
  esac
  [ "$purge" -eq 1 ] && rm -rf "$CONF_DIR"
  systemctl daemon-reload; echo "uninstalled $target" ;;
*) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
