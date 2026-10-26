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
[ "$rc" -eq 0 ] && grep -q '^URL=https://sentry-host:19532$' <<<"$out" && ok "plan renders the upload URL from PEER_NAME" || bad "plan URL: rc=$rc"
! grep -q '198\.51\.100\.7' <<<"$out" && grep -q 'peer address: <set, not printed>' <<<"$out" && grep -q '^ufw allow proto tcp from <peer> to any port 19532 comment pft-logship$' <<<"$out" \
  && ok "plan never prints PEER_ADDR (rule shown with <peer>)" || bad "plan leaked the peer address"
grep -q '^TrustedCertificateFile=/etc/pft-logship/tls/ca.crt$' <<<"$out" && [ "$(grep -c '^TrustedCertificateFile=' <<<"$out")" -eq 2 ] \
  && ok "both drop-ins pin the pft-logship CA" || bad "CA pin"

# usage errors
bash "$LS" bogus >/dev/null 2>&1; [ $? -eq 3 ] && ok "unknown command -> exit 3" || bad "unknown command"
bash "$LS" lag --nope >/dev/null 2>&1; [ $? -eq 3 ] && ok "unknown option -> exit 3" || bad "unknown option"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
