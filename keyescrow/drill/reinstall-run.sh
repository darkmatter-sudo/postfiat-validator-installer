#!/usr/bin/env bash
# reinstall-run: recorded re-install of pft-keyescrow on both hosts (identities and held generations kept), one more
# live escrow in both directions through the sandboxed unit, verify of every held generation, pull, leak check and
# integrity baselines. Same helpers and redaction as install-run.sh.
#   bash keyescrow/drill/reinstall-run.sh 2>&1 | tee LOG
# Env: RELAY (relay)  LOG (the raw tee'd log, scanned in step 6)
# shellcheck disable=SC2016,SC2034,SC2015  # x() evaluates its argument later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"
RELAY="${RELAY:-relay}"; LOG="${LOG:-}"
TASK=task_2361bde7
SHA_HEAD="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
RDIR="/var/tmp/pft-keyescrow-live-$SHORT"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
trap 'rm -rf "$SEC"' EXIT
printf 'user\t%s\n' "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@" </dev/null; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }

echo "# keyescrow reinstall-run - $(ts) - commit $SHA_HEAD - $(lsb_release -ds 2>/dev/null)"
echo "== 0. preflight (nothing changed yet)"
x "sha256sum keyescrow/pft-keyescrow.sh keyescrow/keyescrow_tar.py keyescrow/install.sh keyescrow/drill/reinstall-run.sh keyescrow/drill/leakcheck.py keyescrow/systemd/*"
git fetch -q origin
[ -z "$(git status --short -- keyescrow alerts fleet)" ] && [ "$SHA_HEAD" = "$(git rev-parse origin/main)" ]
check "HEAD is clean and pushed (origin/main = $SHORT)" $?
RHN="$(R hostname)"; [ -n "$RHN" ] || { echo "relay unreachable - stopping"; exit 4; }
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; [ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
for f in /etc/postfiat-monitor.env /etc/pft-maint/ntfy.env "$HOME/.config/pft-alerts/ntfy.env"; do
  sudo -n cat "$f" 2>/dev/null; done | sed -nE 's#^NTFY_(TOPIC|URL)=.*[/=]##p' | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' \
  | sort -u | while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done
VAPUB="$(sudo -n pft-keyescrow pubkey)"; SEPUB="$(R 'sudo -n pft-keyescrow pubkey')"
printf 'key\t%s\nkey\t%s\n' "$VAPUB" "$SEPUB" >> "$LIT"
echo "  literals for redaction: $(wc -l < "$LIT") (not printed)"
for h in local relay; do
  if [ "$h" = relay ]; then r="$(R 'sudo -n pft-integrity verify' 2>&1 | grep '^RESULT')"; else r="$(sudo -n pft-integrity verify 2>&1 | grep '^RESULT')"; fi
  echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping"; exit 4 ;; esac
done
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
check "redaction positive control" "$RCTL"
[ "$RCTL" = 0 ] || exit 3
x "sha256sum /usr/local/bin/pft-keyescrow; R 'sha256sum /usr/local/bin/pft-keyescrow'"
x "sudo -n pft-keyescrow verify --all | tail -1; R 'sudo -n pft-keyescrow verify --all' | tail -1"
check "before: each holder has 1 good generation of the other" "$(ok_if '[ "$(grep -c "^RESULT: 1 generation(s) checked, 0 failed" <<<"$XOUT")" = 2 ]')"

echo "== 1. re-install on both hosts ($(ts))"
x "git archive $SHA_HEAD keyescrow | ssh -o BatchMode=yes $RELAY 'rm -rf $RDIR && mkdir -m 700 $RDIR && tar -x -C $RDIR && sha256sum $RDIR/keyescrow/pft-keyescrow.sh'"
x "R 'sudo -n bash $RDIR/keyescrow/install.sh --host sentry'"
check "sentry re-install (identity kept)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "age identity: kept" <<<"$XOUT"')"
x "sudo -n bash keyescrow/install.sh --host validator"
check "validator re-install (identity kept)" "$(ok_if '[ "$XRC" = 0 ] && grep -q "age identity: kept" <<<"$XOUT"')"
x "sha256sum /usr/local/bin/pft-keyescrow; R 'sha256sum /usr/local/bin/pft-keyescrow'"
check "both hosts run the committed script" "$(ok_if '[ "$(grep -c "^$(sha256sum < keyescrow/pft-keyescrow.sh | cut -c1-64) " <<<"$XOUT")" = 2 ]')"

echo "== 2. escrow both directions through the sandboxed unit ($(ts))"
x "sudo -n bash keyescrow/install.sh --escrow-host"
ESC="$XOUT"
check "escrow unit: both directions PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "RESULT: PASS - both directions sealed, held and verified" <<<"$ESC"')"
check "sentry decrypted + checked the validator generation in memory" "$(ok_if 'grep -qE "\| VERIFIED from=validator gen=[0-9TZ]+ items=[0-9]+$" <<<"$ESC"')"
check "validator decrypted + checked the sentry generation, sentry acked" "$(ok_if 'grep -qE "VERIFIED from=sentry gen=[0-9TZ]+ items=[0-9]+$" <<<"$ESC" && grep -qE "\| ACKED gen=[0-9TZ]+ items=[0-9]+$" <<<"$ESC"')"
check "pull after the escrow (sentry textfiles exist now)" "$(ok_if 'grep -q "pft_keyescrow_held: pulled from sentry" <<<"$ESC"')"

echo "== 3. verify every held generation, inventory, metrics ($(ts))"
x "sudo -n pft-keyescrow verify --all --textfile"
check "validator: 2 sentry generations held, both verified" "$(ok_if '[ "$XRC" = 0 ] && grep -q "RESULT: 2 generation(s) checked, 0 failed" <<<"$XOUT"')"
x "R 'sudo -n pft-keyescrow verify --all --textfile'"
check "sentry: 2 validator generations held, both verified" "$(ok_if '[ "$XRC" = 0 ] && grep -q "RESULT: 2 generation(s) checked, 0 failed" <<<"$XOUT"')"
x "sudo -n pft-keyescrow inventory --textfile | tail -1; R 'sudo -n pft-keyescrow inventory --textfile' | tail -1"
check "inventory on both: no drift, nothing new, exit 0" "$(ok_if '[ "$(grep -c "escrow drift 0, new 0 -> exit 0" <<<"$XOUT")" = 2 ]')"
x "sudo -n pft-keyescrow pull && grep -h '^pft_keyescrow_[a-z_]*{' /var/lib/pft-exporter/textfile/pft_keyescrow*.prom | grep -v collect_timestamp | grep -v verify_timestamp"
check "validator exports both nodes: held ok=1 and 2 generations each way, no drift" "$(ok_if 'grep -q "^pft_keyescrow_held_verify_ok{node=\"validator\",peer=\"sentry\"} 1$" <<<"$XOUT" && grep -q "^pft_keyescrow_held_verify_ok{node=\"sentry\",peer=\"validator\"} 1$" <<<"$XOUT" && grep -q "^pft_keyescrow_held_generations{node=\"sentry\",peer=\"validator\"} 2$" <<<"$XOUT" && grep -q "^pft_keyescrow_held_generations{node=\"validator\",peer=\"sentry\"} 2$" <<<"$XOUT" && grep -q "^pft_keyescrow_drift_items{node=\"sentry\"} 0$" <<<"$XOUT" && grep -q "^pft_keyescrow_drift_items{node=\"validator\"} 0$" <<<"$XOUT"')"
x "TZ=UTC systemctl list-timers 'pft-keyescrow*' --no-pager | grep -c pft-keyescrow; R 'TZ=UTC systemctl list-timers pft-keyescrow* --no-pager' | grep -c pft-keyescrow"
check "timers: 3 on the validator (hourly, nightly, pull), 1 on the sentry (hourly)" "$(ok_if '[ "$(head -1 <<<"$XOUT")" = 3 ] && [ "$(tail -1 <<<"$XOUT")" = 1 ]')"

echo "== 4. zero-leak check ($(ts))"
x "sudo -n python3 -I keyescrow/drill/leakcheck.py --tool /usr/local/bin/pft-keyescrow --conf /etc/pft-keyescrow.env --host validator --scan /var/lib/pft-keyescrow --scan /var/lib/pft-exporter/textfile ${LOG:+--scan-file $LOG}"
check "validator: every secret probed, 0 leaks${LOG:+ (incl. the raw log of this run)}" "$(ok_if '[ "$XRC" = 0 ] && ! grep -q "^scanned files: 0 " <<<"$XOUT"')"
x "R 'sudo -n python3 -I $RDIR/keyescrow/drill/leakcheck.py --tool /usr/local/bin/pft-keyescrow --conf /etc/pft-keyescrow.env --host sentry --scan /var/lib/pft-keyescrow --scan /var/lib/pft-exporter/textfile --scan $RDIR'"
check "sentry: every secret probed, 0 leaks" "$(ok_if '[ "$XRC" = 0 ] && ! grep -q "^scanned files: 0 " <<<"$XOUT"')"
x "grep -c 'AGE-SECRET-KEY' <<<\"\$ESC\"; sudo -n grep -c 'AGE-SECRET-KEY' /var/lib/pft-keyescrow/age.key"
check "no age identity in the escrow output (control: the identity file has one)" "$(ok_if '[ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = 1 ]')"

echo "== 5. integrity baselines ($(ts))"
x "sudo -n pft-integrity accept --reason '$TASK: pft-keyescrow $SHORT re-installed (binary, install output fix)' | tail -3"
x "R \"sudo -n pft-integrity accept --reason '$TASK: pft-keyescrow $SHORT re-installed (binary, install output fix)'\" | tail -3"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify' | tail -1"
check "pft-integrity PASS on both after accept" "$(ok_if '[ "$(grep -c "^RESULT: PASS" <<<"$XOUT")" = 2 ]')"

echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed check(s) - $(ts)"
[ "$FAILS" = 0 ]
