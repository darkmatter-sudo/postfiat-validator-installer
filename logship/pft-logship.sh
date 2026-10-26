#!/usr/bin/env bash
# pft-logship: cross-host journald forwarding between two Post Fiat node hosts (validator <-> sentry), so that a
# host's logs survive on its peer when the host itself is wiped or tampered with. Uses the distro's
# systemd-journal-upload (sender) and systemd-journal-remote (receiver, socket on TCP 19532) with mutual TLS from a
# private two-host CA. Each host makes its own private key; only CSRs and certificates travel. No node restart.
#
# Usage: pft-logship plan  [--peer-name NAME]
#        sudo pft-logship lag  [--textfile]
#        (apply / check / rollback: in progress, see logship/README.md once published)
#
#  plan     read-only. Prints the journal-upload and journal-remote drop-ins, the upload unit drop-in, the
#           peer-scoped UFW rule (address from the root-only conf, printed as <peer>), and every step apply will take.
#  lag      reads journal-upload's saved cursor and the newest local journal entry and prints the forwarding lag
#           (newest local entry time - time of the last uploaded entry, from the cursor's t= field). With
#           --textfile also writes pft_logship_up / pft_logship_lag_seconds for the pft exporter (atomic rename).
#
# Exit codes: 0 ok, 1 lag/check failure, 3 usage/config error.
# Conf: PFT_LS_CONF (/etc/pft-logship.env, root-owned, sourced first): PEER_NAME, PEER_ADDR (kept out of the repo),
#       MAX_LAG (120 s), STORE_CAP (2G per sender), TEXTFILE_DIR (/var/lib/pft-exporter/textfile)
# Test hooks: PFT_LS_TEST=1 (no root)  PFT_LS_ROOT (prefix for host paths)  PFT_LS_JOURNALCTL  PFT_LS_NEWEST_USEC

set -uo pipefail
umask 022

TEST="${PFT_LS_TEST:-}"
R="${PFT_LS_ROOT:-}"
CONF="${PFT_LS_CONF:-$R/etc/pft-logship.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = "$(id -u)" ] && . "$CONF"
PEER_NAME="${PEER_NAME:-}"
PEER_ADDR="${PEER_ADDR:-}"
PORT=19532
MAX_LAG="${MAX_LAG:-120}"
STORE_CAP="${STORE_CAP:-2G}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
TLS_DIR=/etc/pft-logship/tls
UPLOAD_DROPIN=/etc/systemd/journal-upload.conf.d/pft-logship.conf
REMOTE_DROPIN=/etc/systemd/journal-remote.conf.d/pft-logship.conf
UNIT_DROPIN=/etc/systemd/system/systemd-journal-upload.service.d/pft-logship.conf
# journal-upload runs with DynamicUser=yes + StateDirectory=systemd/journal-upload, so the real dir is under private/
UPLOAD_STATE="${UPLOAD_STATE:-/var/lib/private/systemd/journal-upload/state}"
JOURNALCTL="${PFT_LS_JOURNALCTL:-journalctl}"

usage() { sed -n '7,9p' "$0" | sed 's/^# \{0,1\}//'; }
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

render_upload_conf() { # -> journal-upload.conf drop-in (key/cert paths from systemd credentials, see unit drop-in)
  printf '# pft-logship: upload this host'"'"'s journal to %s over mutual TLS\n[Upload]\n' "${PEER_NAME:-<peer>}"
  printf 'URL=https://%s:%d\n' "${PEER_NAME:-<peer>}" "$PORT"
  printf 'ServerKeyFile=%s/upload.key\nServerCertificateFile=%s/upload.crt\nTrustedCertificateFile=%s/ca.crt\n' \
    "$TLS_DIR" "$TLS_DIR" "$TLS_DIR"
}
render_remote_conf() { # -> journal-remote.conf drop-in
  printf '# pft-logship: receive the peer'"'"'s journal; clients must present a cert from the pft-logship CA\n[Remote]\n'
  printf 'Seal=false\nSplitMode=host\nServerKeyFile=%s/remote.key\nServerCertificateFile=%s/remote.crt\n' "$TLS_DIR" "$TLS_DIR"
  printf 'TrustedCertificateFile=%s/ca.crt\n' "$TLS_DIR"
}
render_ufw() { # -> the one UFW rule apply adds (peer address only; <peer> when printed)
  printf 'ufw allow proto tcp from %s to any port %d comment pft-logship\n' "${1:-<peer>}" "$PORT"
}

print_plan() {
  echo "pft-logship plan - $(date -u +%FT%TZ) - $(grep PRETTY_NAME "$R/etc/os-release" 2>/dev/null | cut -d'"' -f2)"
  echo "peer: ${PEER_NAME:-<unset: PEER_NAME in /etc/pft-logship.env>} | peer address: $([ -n "$PEER_ADDR" ] && echo '<set, not printed>' || echo '<unset>')"
  echo "systemd-journal-remote package: $(dpkg-query -W -f '${Status} ${Version}' systemd-journal-remote 2>/dev/null || echo 'not installed')"
  echo
  echo "== $UPLOAD_DROPIN"; render_upload_conf
  echo; echo "== $REMOTE_DROPIN"; render_remote_conf
  echo; echo "== firewall"; render_ufw ""
  echo; echo "== steps apply will take"
  cat <<EOF
1. apt-get install systemd-journal-remote (receiver + uploader units, disabled until configured)
2. $TLS_DIR: this host makes its own key + CSR (keys never leave the host); the CA on the validator signs both CSRs
   (CSR and certificate travel over ssh, keys do not); 0640 root:systemd-journal-remote for remote.key
3. write the two drop-ins above + $UNIT_DROPIN (LoadCredential for upload.key: journal-upload runs as a DynamicUser)
4. UFW rule above (peer address only), then enable --now systemd-journal-remote.socket and systemd-journal-upload
5. storage cap $STORE_CAP per sender: pft-logship-vacuum.timer runs journalctl --directory=/var/log/journal/remote
   --vacuum-size (journal-remote.conf in systemd 249 has no MaxUse=)
6. pft-integrity accept for the new package/units/config (no postfiatd restart at any step)
EOF
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
TXT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --textfile) TXT=1 ;; --peer-name) PEER_NAME="${2:?}"; shift ;;
    -h|--help) usage; exit 0 ;; *) die "unknown option $1" 3 ;;
  esac; shift
done
case "$CMD" in
  plan) print_plan ;;
  lag) need_root; do_lag "$TXT" ;;
  -h|--help|help) usage ;;
  *) usage; exit 3 ;;
esac
