#!/usr/bin/env bash
# "cond && ok || bad" is intended: ok() always returns 0, so bad runs only when cond fails.
# shellcheck disable=SC2015
# Offline tests for pft-logship.sh - no root, no network, no journald changes. journalctl is a stub; every host
# path lives under a temp PFT_LS_ROOT. fixtures/cursor-validator.txt + realtime-validator.txt are a real journal
# cursor and its __REALTIME_TIMESTAMP captured on the validator (logs/logship/cursor-fixture.log).
# Usage: bash logship/tests/run-tests.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LS="${PFT_LS_SCRIPT:-$HERE/../pft-logship.sh}"   # PFT_LS_SCRIPT: run the suite against another build
FX="$HERE/fixtures"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }

CUR="$(cat "$FX/cursor-validator.txt")"; RT="$(cat "$FX/realtime-validator.txt")"
export PFT_LS_TEST=1 PFT_LS_ROOT="$WORK/root" PFT_LS_CONF="$WORK/none.env" PFT_LS_JOURNALCTL="$WORK/bin/journalctl"
mkdir -p "$WORK/bin" "$WORK/root/var/lib/private/systemd/journal-upload" "$WORK/root/var/lib/pft-exporter/textfile" \
  "$WORK/root/etc"
printf 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n' > "$WORK/root/etc/os-release"
cat > "$WORK/bin/journalctl" <<STUB
#!/usr/bin/env bash
# --directory=... is the receive side (peer's journal); RX=none -> no entries
# -t NAME is the bridge's local entries (pft-logship-dockerlog@NAME); DLRX=none -> no entries
if [[ " \$* " == *" -t "* ]]; then
  [ "\${DLRX:-}" = none ] && exit 0
  echo "{\"__REALTIME_TIMESTAMP\":\"\${DLRX:-$RT}\",\"MESSAGE\":\"bridge\"}"; exit 0
fi
if [[ "\$*" == *--directory=* ]]; then
  [ "\${RX:-}" = none ] && exit 0
  echo "{\"__REALTIME_TIMESTAMP\":\"\${RX:-$RT}\",\"MESSAGE\":\"rx\"}"; exit 0
fi
echo "{\"__REALTIME_TIMESTAMP\":\"\${NEWEST:-$RT}\",\"MESSAGE\":\"x\"}"
STUB
chmod +x "$WORK/bin/journalctl"
STATE="$WORK/root/var/lib/private/systemd/journal-upload/state"
PROM="$WORK/root/var/lib/pft-exporter/textfile/pft_logship.prom"
lag() { bash "$LS" lag "$@" 2>&1; }

# the real cursor's t= field is its own __REALTIME_TIMESTAMP (hex usec)
printf 'LAST_CURSOR=%s\n' "$CUR" > "$STATE"
out="$(NEWEST="$RT" lag --textfile)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^lag: 0s (last uploaded entry 2026-' <<<"$out" && ok "real cursor at the newest entry -> lag 0, exit 0" || bad "lag 0: rc=$rc $out"
grep -qx 'pft_logship_up 1' "$PROM" && grep -qx 'pft_logship_lag_seconds 0' "$PROM" && ok "textfile up 1 lag 0" || bad "textfile: $(cat "$PROM")"

out="$(NEWEST=$((RT + 95500000)) lag --textfile)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^lag: 95s' <<<"$out" && grep -qx 'pft_logship_lag_seconds 95' "$PROM" && ok "95.5 s behind -> 95, within MAX_LAG 120" || bad "lag 95: rc=$rc $out"

out="$(NEWEST=$((RT + 121000000)) lag --textfile)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^lag: 121s' <<<"$out" && grep -qx 'pft_logship_lag_seconds 121' "$PROM" && ok "121 s behind -> exit 1, metric still written" || bad "lag 121: rc=$rc $out"

out="$(NEWEST=$((RT - 5000000)) lag)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^lag: 0s' <<<"$out" && ok "cursor newer than newest local entry (clock step) -> clamped to 0" || bad "negative: rc=$rc $out"

# several LAST_CURSOR lines (should not happen, but take the last one, never concatenate)
printf 'LAST_CURSOR=s=0;i=1;t=1\nLAST_CURSOR=%s\n' "$CUR" > "$STATE"
out="$(NEWEST="$RT" lag)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^lag: 0s' <<<"$out" && ok "last LAST_CURSOR line wins" || bad "multi: rc=$rc $out"

# no state file / no t= field -> up 0, no lag series, exit 1 (a stalled or never-started uploader must not read as 0 lag)
rm -f "$STATE"
out="$(lag --textfile)"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'no saved cursor' <<<"$out" && grep -qx 'pft_logship_up 0' "$PROM" && ! grep -q '^pft_logship_lag_seconds' "$PROM" \
  && ok "no cursor -> exit 1, up 0, no lag series" || bad "no cursor: rc=$rc $out $(cat "$PROM")"
grep -q '^# TYPE pft_logship_up gauge' "$PROM" && ok "presence control: textfile has the up series header" || bad "header missing"
printf 'LAST_CURSOR=s=1e60;i=a7fb2;b=21cc;m=5b4c\n' > "$STATE"
out="$(lag --textfile)"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'no t= field' <<<"$out" && grep -qx 'pft_logship_up 0' "$PROM" && ok "cursor without t= -> exit 1, up 0" || bad "no t=: rc=$rc $out"

# atomic write leaves no temp files behind
[ -z "$(find "$WORK/root/var/lib/pft-exporter/textfile" -name '.pft_logship*')" ] && ok "no temp files left in the textfile dir" || bad "temp files left"

# plan: read-only, never prints the peer address even when it is set
printf 'PEER_NAME=sentry-host\nPEER_ADDR=198.51.100.7\n' > "$WORK/peer.env"
out="$(PFT_LS_CONF="$WORK/peer.env" bash "$LS" plan 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^URL=https://<peer>:19532$' <<<"$out" && grep -q '| peer: sentry-host |' <<<"$out" && ok "plan shows the upload URL with <peer> and the peer label" || bad "plan URL: rc=$rc"
! grep -q '198\.51\.100\.7' <<<"$out" && grep -q 'peer address: <set, not printed>' <<<"$out" && grep -q '^ufw allow proto tcp from <peer> to any port 19532 comment pft-logship$' <<<"$out" \
  && ok "plan never prints PEER_ADDR (rule shown with <peer>)" || bad "plan leaked the peer address"
grep -q '^TrustedCertificateFile=/etc/pft-logship/tls/ca.crt$' <<<"$out" && [ "$(grep -c '^TrustedCertificateFile=' <<<"$out")" -eq 2 ] \
  && ok "both drop-ins pin the pft-logship CA" || bad "CA pin"

# ---- sign (real openssl, temp root): CA made once, key stays, cert = SAN from CSR + fixed extensions -------------
TLS="$WORK/root/etc/pft-logship/tls"; CA="$WORK/root/etc/pft-logship/ca"
mkdir -p "$TLS"
printf 'CA_HERE=1\n' > "$WORK/ca.env"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TLS/host.key" 2>/dev/null
openssl req -new -key "$TLS/host.key" -subj "/CN=validator-host/O=pft-logship" -addext "subjectAltName=IP:192.0.2.10" -out "$WORK/v.csr" 2>/dev/null
out="$(PFT_LS_CONF="$WORK/ca.env" bash "$LS" sign "$WORK/v.csr" 2>"$WORK/sign.err")"; rc=$?
printf '%s\n' "$out" > "$TLS/host.crt"; cp "$CA/ca.crt" "$TLS/ca.crt" 2>/dev/null
[ "$rc" -eq 0 ] && openssl verify -CAfile "$CA/ca.crt" "$TLS/host.crt" >/dev/null 2>&1 && grep -q 'new pair CA' "$WORK/sign.err" \
  && ok "sign: creates the pair CA, cert verifies against it" || bad "sign: rc=$rc $(cat "$WORK/sign.err")"
txt="$(openssl x509 -noout -text -in "$TLS/host.crt" 2>/dev/null)"
grep -q 'IP Address:192.0.2.10' <<<"$txt" && grep -q 'TLS Web Server Authentication, TLS Web Client Authentication' <<<"$txt" \
  && grep -q 'CA:FALSE' <<<"$txt" && grep -q 'Subject: CN = validator-host' <<<"$txt" \
  && ok "sign: SAN from the CSR, serverAuth+clientAuth, CA:FALSE, CN kept" || bad "sign extensions"
[ "$(stat -c %a "$CA/ca.key")" = 600 ] && [ "$(stat -c %a "$CA")" = 700 ] && ok "sign: ca.key 0600 in a 0700 dir" || bad "ca.key mode $(stat -c %a "$CA/ca.key")"
k1="$(sha256sum < "$CA/ca.key")"
PFT_LS_CONF="$WORK/ca.env" bash "$LS" sign "$WORK/v.csr" >/dev/null 2>"$WORK/sign2.err"; rc=$?
[ "$rc" -eq 0 ] && [ "$(sha256sum < "$CA/ca.key")" = "$k1" ] && ! grep -q 'new pair CA' "$WORK/sign2.err" \
  && ok "sign again: same CA key reused, no new CA" || bad "sign reuse rc=$rc"
out="$(PFT_LS_CONF="$WORK/none.env" bash "$LS" sign "$WORK/v.csr" 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'CA_HERE=1 is not set' <<<"$out" && ok "sign without CA_HERE=1 -> exit 3 (wrong host)" || bad "sign no CA_HERE: rc=$rc $out"
openssl req -new -key "$TLS/host.key" -subj "/CN=x" -out "$WORK/nosan.csr" 2>/dev/null
out="$(PFT_LS_CONF="$WORK/ca.env" bash "$LS" sign "$WORK/nosan.csr" 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'no IP subjectAltName' <<<"$out" && ok "sign: CSR without IP SAN -> exit 3" || bad "nosan: rc=$rc $out"
# CN validator-host -> validator-hosu in the DER: still parses, self-signature no longer matches. OpenSSL 3.0.2
# 'req -verify' exits 0 on that, so this case fails unless sign checks the "verify OK" line.
openssl req -in "$WORK/v.csr" -outform DER -out "$WORK/v.der" 2>/dev/null
python3 -c 'import sys; b = open(sys.argv[1], "rb").read(); open(sys.argv[2], "wb").write(b.replace(b"validator-host", b"validator-hosu", 1))' \
  "$WORK/v.der" "$WORK/bad.der"
openssl req -inform DER -in "$WORK/bad.der" -out "$WORK/bad.csr" 2>/dev/null
openssl req -noout -subject -in "$WORK/bad.csr" 2>/dev/null | grep -q 'validator-hosu' && ok "presence control: tampered CSR parses (subject changed)" || bad "tampered CSR did not parse"
out="$(PFT_LS_CONF="$WORK/ca.env" bash "$LS" sign "$WORK/bad.csr" 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'CSR signature does not verify' <<<"$out" && ok "sign: CSR with a bad self-signature -> exit 3" || bad "bad sig csr: rc=$rc $out"
printf 'not a csr\n' > "$WORK/junk.csr"
out="$(PFT_LS_CONF="$WORK/ca.env" bash "$LS" sign "$WORK/junk.csr" 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'CSR signature does not verify' <<<"$out" && ok "sign: unparsable CSR -> exit 3" || bad "junk csr: rc=$rc $out"

# ---- check (stub systemctl/curl/journalctl, real certs from above) ---------------------------------------------
printf 'SELF_NAME=validator-host\nPEER_NAME=sentry-host\nSELF_ADDR=192.0.2.10\nPEER_ADDR=198.51.100.7\n' > "$WORK/pair.env"
cat > "$WORK/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
[ "$1" = is-active ] || exit 0
[[ " ${DOWN:-} " == *" $2 "* ]] && { echo inactive; exit 3; }
echo active
STUB
cat > "$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s' "${CODE:-404}"
STUB
chmod +x "$WORK/bin/systemctl" "$WORK/bin/curl"
export PFT_LS_SYSTEMCTL="$WORK/bin/systemctl" PFT_LS_CURL="$WORK/bin/curl"
NOW0=$((RT / 1000000 + 20))
chk() { PFT_LS_CONF="$WORK/pair.env" bash "$LS" check "$@" 2>&1; }
printf 'LAST_CURSOR=%s\n' "$CUR" > "$STATE"; rm -f "$WORK/root/var/lib/pft-logship/check.state"
out="$(NEWEST="$RT" PFT_LS_NOW=$NOW0 chk --textfile)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^RESULT: PASS -> exit 0$' <<<"$out" && grep -q '^receive: newest entry from sentry-host is 20s old$' <<<"$out" \
  && grep -q '^tls: mutual-TLS handshake with sentry-host journal-remote ok (HTTP 404)$' <<<"$out" && grep -qx 'pft_logship_up 1' "$PROM" \
  && ok "check: all good -> PASS exit 0 (presence control for the FAIL cases below)" || bad "check pass: rc=$rc $out"
! grep -q -e '198\.51\.100\.7' -e '192\.0\.2\.10' <<<"$out" && ok "check output carries no addresses" || bad "check leaked an address"
# check --textfile: up is the whole check's verdict, not just "cursor readable" (the lag itself is fine here)
out="$(CODE=000 NEWEST="$RT" PFT_LS_NOW=$NOW0 chk --textfile)"; rc=$?
[ "$rc" -eq 1 ] && grep -qx 'pft_logship_up 0' "$PROM" && grep -qx 'pft_logship_lag_seconds 0' "$PROM" \
  && ok "check --textfile: TLS fails, lag 0 -> pft_logship_up 0 (lag still written)" || bad "up on failed check: rc=$rc $(cat "$PROM")"
out="$(DOWN=pft-logship-check.timer NEWEST="$RT" PFT_LS_NOW=$NOW0 chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^unit: pft-logship-check.timer NOT active$' <<<"$out" && ok "check: metrics timer down -> exit 1" || bad "timer down: rc=$rc"
out="$(DOWN=systemd-journal-remote.socket NEWEST="$RT" PFT_LS_NOW=$NOW0 chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^unit: systemd-journal-remote.socket NOT active$' <<<"$out" && ok "check: receiver socket down -> exit 1" || bad "unit down: rc=$rc"
out="$(CODE=000 NEWEST="$RT" PFT_LS_NOW=$NOW0 chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'journal-remote FAILED$' <<<"$out" && ok "check: TLS handshake fails (curl 000) -> exit 1" || bad "tls: rc=$rc"
out="$(NEWEST=$((RT + 300000000)) PFT_LS_NOW=$NOW0 chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^send: lag: 300s' <<<"$out" && ok "check: send lag 300s > 120 -> exit 1" || bad "lag: rc=$rc $out"
out="$(RX=none NEWEST="$RT" PFT_LS_NOW=$NOW0 chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^receive: no entries from sentry-host' <<<"$out" && ok "check: nothing received from the peer -> exit 1" || bad "rx none: rc=$rc"
out="$(NEWEST="$RT" PFT_LS_NOW=$((NOW0 + 400)) chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^receive: newest entry from sentry-host is 420s old$' <<<"$out" && ok "check: peer's newest entry 420s old -> exit 1" || bad "rx old: rc=$rc"
# stall: same cursor, local journal 30 s ahead, seen at t0 and t0+130 (>= MAX_LAG) -> stalled; a moving cursor resets it
rm -f "$WORK/root/var/lib/pft-logship/check.state"
out="$(NEWEST=$((RT + 30000000)) PFT_LS_NOW=$NOW0 RX=$((RT + 20000000)) chk)"; rc1=$?
out="$(NEWEST=$((RT + 30000000)) PFT_LS_NOW=$((NOW0 + 60)) RX=$((RT + 60000000)) chk)"; rc2=$?
out3="$(NEWEST=$((RT + 30000000)) PFT_LS_NOW=$((NOW0 + 130)) RX=$((RT + 130000000)) chk)"; rc3=$?
[ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$rc3" -eq 1 ] && grep -q 'cursor STALLED' <<<"$out3" \
  && ok "check: cursor unchanged 130s with lag 30s -> STALLED exit 1 (0 at 0s and 60s)" || bad "stall: $rc1 $rc2 $rc3 $out3"
printf 'LAST_CURSOR=%s\n' "${CUR/t=/t=0}" > "$STATE"   # same instant, different cursor text = the cursor moved
out="$(NEWEST=$((RT + 30000000)) PFT_LS_NOW=$((NOW0 + 200)) RX=$((RT + 200000000)) chk)"; rc=$?
[ "$rc" -eq 0 ] && ! grep -q STALLED <<<"$out" && ok "check: cursor moved -> stall timer resets" || bad "stall reset: rc=$rc $out"
printf 'LAST_CURSOR=%s\n' "$CUR" > "$STATE"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/other.key" 2>/dev/null
cp "$TLS/host.key" "$WORK/host.key.good"; cp "$WORK/other.key" "$TLS/host.key"
out="$(NEWEST="$RT" PFT_LS_NOW=$NOW0 chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^cert: host.crt does not match host.key$' <<<"$out" && ok "check: cert/key mismatch -> exit 1" || bad "mismatch: rc=$rc $out"
cp "$WORK/host.key.good" "$TLS/host.key"
cp "$TLS/ca.crt" "$WORK/ca.good"; openssl req -x509 -new -key "$WORK/other.key" -subj /CN=rogue -days 1 -out "$TLS/ca.crt" 2>/dev/null
out="$(NEWEST="$RT" PFT_LS_NOW=$NOW0 chk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q '^cert: host.crt does not chain to ca.crt$' <<<"$out" && ok "check: cert from another CA -> exit 1" || bad "chain: rc=$rc $out"
cp "$WORK/ca.good" "$TLS/ca.crt"
out="$(PFT_LS_CONF="$WORK/none.env" bash "$LS" check 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'SELF_NAME is not set' <<<"$out" && ok "check without conf -> exit 3" || bad "check no conf: rc=$rc"

# ---- apply / rollback --dry-run: change nothing, never print an address ----------------------------------------
before="$(find "$WORK/root" -type f | sort | xargs sha256sum)"
out="$(PFT_LS_CONF="$WORK/pair.env" bash "$LS" apply --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^dry-run: nothing changed$' <<<"$out" && grep -qx '+ ufw allow proto tcp from <peer> to any port 19532 comment pft-logship' <<<"$out" \
  && grep -qx '    URL=https://<peer>:19532' <<<"$out" && grep -qx '    LoadCredential=host.key:/etc/pft-logship/tls/host.key' <<<"$out" \
  && grep -qx '    ExecStart=journalctl --directory=/var/log/journal/remote --vacuum-size=2G' <<<"$out" \
  && ok "apply --dry-run: prints UFW rule, upload URL, credential and vacuum cap" || bad "apply dry: rc=$rc $out"
grep -q '^+ install -m 755 [^ ]* .*/usr/local/sbin/pft-logship$' <<<"$out" \
  && grep -qx '    ExecStart=/usr/local/sbin/pft-logship check --textfile' <<<"$out" && grep -qx '    OnUnitActiveSec=1min' <<<"$out" \
  && grep -qx '+ .*systemctl enable --now pft-logship-check.timer' <<<"$out" \
  && ok "apply --dry-run: installs itself + pft-logship-check.timer (check --textfile every minute)" || bad "apply check timer: $out"
[ "$(find "$WORK/root" -type f | sort | xargs sha256sum)" = "$before" ] && ok "apply --dry-run: no file under the root changed" || bad "apply dry-run wrote files"
! grep -q -e '198\.51\.100\.7' -e '192\.0\.2\.10' <<<"$out" && grep -q 'subjectAltName=IP:<self>' <<<"$out" \
  && ok "apply --dry-run: addresses masked (<peer>/<self>)" || bad "apply leaked an address"
out="$(PFT_LS_CONF="$WORK/pair.env" bash "$LS" rollback --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && grep -qx '+ ufw delete allow proto tcp from <peer> to any port 19532 comment pft-logship' <<<"$out" \
  && grep -q '^kept: received journals in /var/log/journal/remote' <<<"$out" && ! grep -q '198\.51\.100\.7' <<<"$out" \
  && [ "$(find "$WORK/root" -type f | sort | xargs sha256sum)" = "$before" ] \
  && ok "rollback --dry-run: deletes the same UFW rule, keeps received journals, changes nothing" || bad "rollback dry: rc=$rc $out"
grep -q 'pft-logship-check.timer' <<<"$out" && grep -q '^+ rm -f .*pft-logship-check.timer .*/usr/local/sbin/pft-logship .*pft_logship.prom$' <<<"$out" \
  && ok "rollback --dry-run: stops the check timer, removes it, the installed script and the metrics file" || bad "rollback timer: $out"
out="$(PFT_LS_CONF="$WORK/none.env" bash "$LS" apply --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && ok "apply without conf -> exit 3" || bad "apply no conf: rc=$rc"
printf 'SELF_NAME=Bad_Name\nPEER_NAME=sentry-host\nSELF_ADDR=192.0.2.10\nPEER_ADDR=198.51.100.7\n' > "$WORK/badname.env"
out="$(PFT_LS_CONF="$WORK/badname.env" bash "$LS" apply --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'must be \[a-z0-9-\] labels' <<<"$out" && ok "apply: non-label SELF_NAME -> exit 3" || bad "badname: rc=$rc"

# ---- docker log bridge (pft-logship-dockerlog@NAME) in plan / check / apply / rollback ---------------------------
printf 'SELF_NAME=validator-host\nPEER_NAME=sentry-host\nSELF_ADDR=192.0.2.10\nPEER_ADDR=198.51.100.7\nDOCKER_CONTAINERS=postfiatd\n' > "$WORK/dl.env"
out="$(PFT_LS_CONF="$WORK/dl.env" bash "$LS" plan 2>&1)"
grep -qx '== /etc/systemd/system/pft-logship-dockerlog@.service (containers: postfiatd)' <<<"$out" \
  && grep -qx 'ExecStart=/usr/bin/python3 -I /usr/local/sbin/pft-logship-dockerlog %i' <<<"$out" && grep -qx 'LogRateLimitIntervalSec=0' <<<"$out" \
  && ok "plan: bridge unit for postfiatd, python -I, no journald rate limit" || bad "plan bridge: $out"
dchk() { PFT_LS_CONF="$WORK/dl.env" bash "$LS" check 2>&1; }
rm -f "$WORK/root/var/lib/pft-logship/check.state"
out="$(NEWEST="$RT" DLRX=$((RT + 15000000)) PFT_LS_NOW=$NOW0 dchk)"; rc=$?
[ "$rc" -eq 0 ] && grep -qx 'bridge: pft-logship-dockerlog@postfiatd active, newest postfiatd journal entry 5s old' <<<"$out" \
  && ok "check: bridge active + postfiatd entry 5s old -> PASS (presence control)" || bad "bridge pass: rc=$rc $out"
out="$(DOWN=pft-logship-dockerlog@postfiatd.service NEWEST="$RT" PFT_LS_NOW=$NOW0 dchk)"; rc=$?
[ "$rc" -eq 1 ] && grep -qx 'unit: pft-logship-dockerlog@postfiatd.service NOT active' <<<"$out" && ok "check: bridge unit down -> exit 1" || bad "bridge down: rc=$rc"
out="$(DLRX=none NEWEST="$RT" PFT_LS_NOW=$NOW0 dchk)"; rc=$?
[ "$rc" -eq 1 ] && grep -qx 'bridge: no journal entries from postfiatd' <<<"$out" && ok "check: no postfiatd entries in the journal -> exit 1" || bad "bridge none: rc=$rc"
out="$(DLRX=$((RT - 300000000)) NEWEST="$RT" PFT_LS_NOW=$NOW0 dchk)"; rc=$?
[ "$rc" -eq 1 ] && grep -q 'newest postfiatd journal entry 320s old' <<<"$out" && grep -qx 'bridge: older than 120s' <<<"$out" \
  && ok "check: newest postfiatd entry 320s old (bridge stuck) -> exit 1" || bad "bridge old: rc=$rc $out"
out="$(PFT_LS_CONF="$WORK/dl.env" PFT_LS_DL_SRC="$HERE/../pft-logship-dockerlog.py" bash "$LS" apply --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && grep -q '^+ install -m 755 .*pft-logship-dockerlog.py .*/usr/local/sbin/pft-logship-dockerlog$' <<<"$out" \
  && grep -qx '+ .*systemctl enable --now pft-logship-dockerlog@postfiatd.service' <<<"$out" \
  && [ "$(find "$WORK/root" -type f | sort | xargs sha256sum)" = "$before" ] \
  && ok "apply --dry-run: installs the bridge and enables pft-logship-dockerlog@postfiatd, changes nothing" || bad "apply bridge: rc=$rc $out"
out="$(PFT_LS_CONF="$WORK/dl.env" PFT_LS_DL_SRC="$WORK/missing.py" bash "$LS" apply --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'bridge source .* missing' <<<"$out" && ok "apply: bridge source missing -> exit 3" || bad "src missing: rc=$rc"
out="$(PFT_LS_CONF="$WORK/dl.env" bash "$LS" rollback --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && grep -qx '+ .*systemctl disable --now pft-logship-dockerlog@postfiatd.service' <<<"$out" \
  && grep -q '^+ rm -f .*pft-logship-dockerlog@.service .*/usr/local/sbin/pft-logship-dockerlog ' <<<"$out" \
  && ok "rollback --dry-run: stops + removes the bridge, keeps its state" || bad "rollback bridge: rc=$rc $out"
printf 'SELF_NAME=a\nPEER_NAME=b\nSELF_ADDR=192.0.2.10\nPEER_ADDR=198.51.100.7\nDOCKER_CONTAINERS="postfiatd ../x"\n' > "$WORK/dlbad.env"
out="$(PFT_LS_CONF="$WORK/dlbad.env" bash "$LS" apply --dry-run 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && grep -q 'bad container name ../x' <<<"$out" && ok "apply: bad container name -> exit 3" || bad "dl badname: rc=$rc"

# ---- apply (real, under the temp root): the new host.key is created under umask 077 --------------------------------
# PATH stubs: dpkg-query says installed (apt-get must never run: its stub fails), openssl records the umask it runs under
SB="$WORK/keybin"; mkdir -p "$SB"
printf '#!/bin/sh\necho "install ok installed"\n' > "$SB/dpkg-query"
for b in apt-get ufw systemctl; do printf '#!/bin/sh\necho "%s must not run in this test" >&2; exit 99\n' "$b" > "$SB/$b"; done
cat > "$SB/openssl" <<STUB
#!/usr/bin/env bash
umask > "$WORK/umask.\$1"
out=""; while [ \$# -gt 0 ]; do [ "\$1" = -out ] && out="\$2"; shift; done
[ -n "\$out" ] && echo stub > "\$out"
exit 0
STUB
chmod +x "$SB"/*
mv "$WORK/root/etc/pft-logship" "$WORK/pft-logship.saved"   # earlier tests left a valid cert pair: start with no key
printf 'SELF_NAME=validator-host\nPEER_NAME=sentry-host\nSELF_ADDR=192.0.2.10\nPEER_ADDR=198.51.100.7\n' > "$WORK/key.env"
out="$(PATH="$SB:$PATH" PFT_LS_SYSTEMCTL="$SB/systemctl" PFT_LS_CONF="$WORK/key.env" bash "$LS" apply 2>&1)"; rc=$?
[ "$rc" -eq 4 ] && grep -q '^PENDING: host.crt or ca.crt missing' <<<"$out" && [ "$(cat "$WORK/umask.genpkey" 2>/dev/null)" = 0077 ] \
  && grep -qx '+ (umask 077) openssl genpkey .*/etc/pft-logship/tls/host.key' <<<"$out" \
  && ok "apply: new host.key is created under umask 077, then exit 4 (waiting for the cert)" \
  || bad "key umask: rc=$rc umask=$(cat "$WORK/umask.genpkey" 2>/dev/null) $out"
rm -rf "$WORK/root/etc/pft-logship"; mv "$WORK/pft-logship.saved" "$WORK/root/etc/pft-logship"

# usage errors
bash "$LS" bogus >/dev/null 2>&1; [ $? -eq 3 ] && ok "unknown command -> exit 3" || bad "unknown command"
bash "$LS" lag --nope >/dev/null 2>&1; [ $? -eq 3 ] && ok "unknown option -> exit 3" || bad "unknown option"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
