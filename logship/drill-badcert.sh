#!/usr/bin/env bash
# Bad-client-cert drill for pft-logship: run as root on one host of the pair (the client side). It POSTs one marker
# entry (journal export format) to the PEER's journal-remote /upload (TCP 19532) three times:
#   1. no client certificate                              -> must be refused (HTTP 4xx, or no answer)
#   2. a client cert from a throwaway rogue CA, same CN    -> must be refused (HTTP 4xx, or no answer)
#   3. control: this host's real pft-logship cert           -> must be stored (HTTP 2xx)
# journal-remote completes the TLS handshake without a client cert and checks it per request on POST /upload (a GET /
# answers 406 to anyone: drill run 1), so only an upload attempt tests client authentication. Every case verifies the
# peer's server cert against the pair CA. Each marker carries DRILL_ID=<id>-<case>; on the receiver,
# `journalctl --directory=/var/log/journal/remote DRILL_ID=...` must find case 3 and must not find 1 or 2. The rogue key/cert live in a mktemp dir under umask 077 and are deleted on exit; no file outside it
# changes. The peer address comes from /etc/pft-logship.env and is never printed.
# Usage: sudo bash logship/drill-badcert.sh        Exit: 0 all three as expected, 1 otherwise, 3 setup error
set -uo pipefail
CONF="${PFT_LS_CONF:-/etc/pft-logship.env}"
TLS=/etc/pft-logship/tls
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
# shellcheck source=/dev/null
. "$CONF" || exit 3
{ [ -n "${PEER_ADDR:-}" ] && [ -n "${PEER_NAME:-}" ]; } || { echo "PEER_ADDR/PEER_NAME missing in $CONF" >&2; exit 3; }
W="$(umask 077; mktemp -d)"; trap 'rm -rf "$W"' EXIT
echo "pft-logship bad-cert drill - $(date -u +%FT%TZ) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "client ${SELF_NAME:-?} -> receiver $PEER_NAME:19532 (server cert verified against the pair CA in every case)"
cn="$(openssl x509 -in "$TLS/host.crt" -noout -subject -nameopt multiline | sed -nE 's/^ *commonName *= *//p')"
( umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/rogue-ca.key" -out "$W/rogue-ca.crt" \
    -subj "/CN=rogue-ca" -days 1 2>/dev/null
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/rogue.key" -out "$W/rogue.csr" \
    -subj "/CN=$cn" 2>/dev/null
  openssl x509 -req -in "$W/rogue.csr" -CA "$W/rogue-ca.crt" -CAkey "$W/rogue-ca.key" -CAcreateserial -days 1 \
    -out "$W/rogue.crt" 2>/dev/null ) || { echo "rogue cert creation failed" >&2; exit 3; }
echo "rogue client cert: CN=$cn (same CN as the real one), issuer $(openssl x509 -in "$W/rogue.crt" -noout -issuer | sed 's/^issuer=//')"
rc=0
ID="badcert-$(date -u +%Y%m%dT%H%M%S)-$$"
echo "DRILL_ID prefix: $ID"
probe() { # CASE LABEL EXPECT(stored|refused) CURL_CERT_ARGS...
  local n="$1" label="$2" want="$3" out crc code err body got; shift 3
  printf 'MESSAGE=pft-logship bad-cert drill %s case %s\nSYSLOG_IDENTIFIER=pft-logship-drill\nDRILL_ID=%s-%s\n__REALTIME_TIMESTAMP=%s\n\n' \
    "$ID" "$n" "$ID" "$n" "$(date +%s%6N)" > "$W/entry"
  out="$(curl -sS -o "$W/body" -w '%{http_code}' --max-time 10 --cacert "$TLS/ca.crt" "$@" \
    -H 'Content-Type: application/vnd.fdo.journal' --data-binary @"$W/entry" "https://$PEER_ADDR:19532/upload" 2>"$W/err")"
  crc=$?; code="${out:-000}"
  err="$(head -c 300 "$W/err" | tr '\n' ' ' | sed "s/$PEER_ADDR/<peer>/g")"
  body="$(stat -c %s "$W/body" 2>/dev/null || echo 0)"   # journal-remote's reply body is not plain text: length only
  case "$code" in 2??) got=stored ;; 000|4??) got=refused ;; *) got="unexpected" ;; esac
  printf '%s. %-30s curl exit %-3s HTTP %s body %s bytes -> %s (expected %s) %s\n' "$n" "$label" "$crc" "$code" "$body" "$got" "$want" "${err:+| $err}"
  if [ "$got" = "$want" ]; then echo "  PASS"; else echo "  FAIL"; rc=1; fi
}
probe 1 "no client certificate" refused
probe 2 "rogue-CA cert, same CN" refused --cert "$W/rogue.crt" --key "$W/rogue.key"
probe 3 "control: real pft-logship cert" stored --cert "$TLS/host.crt" --key "$TLS/host.key"
echo "receiver check: journalctl --directory=/var/log/journal/remote DRILL_ID=$ID-1|2|3 (expect 0, 0, 1)"
echo "RESULT: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL) -> exit $rc"
exit "$rc"
