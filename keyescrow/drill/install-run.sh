#!/usr/bin/env bash
# install-run: recorded two-host install of pft-keyescrow and the first live escrow in both directions.
# Changes no secret, no add-on and not the node (nothing is restarted; no alert rule is loaded by this run:
# ../alerts/prometheus.yml gets the keyescrow line only after both hosts export metrics).
# Helpers (x, red, R, check) and the redaction setup come from ../../backfill/drill/live-run.sh (PASS run 10).
#   bash keyescrow/drill/install-run.sh 2>&1 | tee LOG     (as the agent user, from the repo root; sudo -n, ssh relay)
# 0  preflight: clean pushed HEAD; relay reachable; pft-integrity PASS on both; age on both (the sentry gets the
#    Ubuntu package if missing); no earlier keyescrow identity; redaction positive control.
# 1  install on both hosts (git archive of HEAD to the sentry); validator conf: PEER_SSH + the alert stack's ntfy env.
# 2  exchange the two PUBLIC age recipients (set-peer on each host); inventory on both (before: everything new).
# 3  first escrow through the sandboxed unit (install.sh --escrow-host): both directions sealed, pushed/pulled,
#    decrypted in memory and checked by the holder; nightly escrow + 15-min pull timers enabled.
# 4  verify --all on both hosts; inventory after (all same, exit 0); install.sh --enable (hourly unit) on both.
# 5  the validator's pull of the sentry textfiles; metrics on both hosts.
# 6  zero-leak check on both hosts (leakcheck.py: probes of every secret vs STATE_DIR, textfiles, the copied tree,
#    and on the validator this run's raw log so far).
# 7  pft-integrity accept on both hosts (new binary, helper, units, conf, rulecheck lines), verify PASS after.
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

echo "# keyescrow install-run - $(ts) - commit $SHA_HEAD - $(lsb_release -ds 2>/dev/null)"
echo "== 0. preflight (nothing changed yet)"
x "sha256sum keyescrow/pft-keyescrow.sh keyescrow/keyescrow_tar.py keyescrow/install.sh keyescrow/drill/install-run.sh keyescrow/drill/leakcheck.py keyescrow/systemd/*"
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
echo "  literals for redaction: $(wc -l < "$LIT") (not printed)"
for h in local relay; do
  if [ "$h" = relay ]; then r="$(R 'sudo -n pft-integrity verify' 2>&1 | grep '^RESULT')"; else r="$(sudo -n pft-integrity verify 2>&1 | grep '^RESULT')"; fi
  echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping"; exit 4 ;; esac
done
x "sudo -n test ! -e /var/lib/pft-keyescrow/age.key && R 'sudo -n test ! -e /var/lib/pft-keyescrow/age.key'"
check "no earlier keyescrow identity on either host" "$XRC"
[ "$XRC" = 0 ] || exit 4
x "age --version && R 'command -v age >/dev/null || sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -q age' | tail -3 && R 'age --version; dpkg-query -W age'"
check "age on both hosts" "$XRC"
[ "$XRC" = 0 ] || exit 4
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
check "redaction positive control" "$RCTL"
[ "$RCTL" = 0 ] || exit 3

echo "== 1. install on both hosts ($(ts))"
x "git archive $SHA_HEAD keyescrow | ssh -o BatchMode=yes $RELAY 'rm -rf $RDIR && mkdir -m 700 $RDIR && tar -x -C $RDIR && sha256sum $RDIR/keyescrow/pft-keyescrow.sh'"
x "R 'sudo -n bash $RDIR/keyescrow/install.sh --host sentry'"
check "sentry install" "$XRC"
x "sudo -n bash keyescrow/install.sh --host validator"
check "validator install" "$XRC"
ANE="$HOME/.config/pft-alerts/ntfy.env"; ANO="$(id -un)"
PSSH="runuser -u $(id -un) -- ssh -o BatchMode=yes -o ConnectTimeout=10 $RELAY"
x 'printf "ALERTS_NTFY_ENV=%s\nALERTS_NTFY_OWNER=%s\nPEER_SSH=\"%s\"\n" "$ANE" "$ANO" "$PSSH" | sudo -n tee -a /etc/pft-keyescrow.env >/dev/null && sudo -n stat -c "%a %U:%G" /etc/pft-keyescrow.env && sudo -n grep -c . /etc/pft-keyescrow.env'

echo "== 2. exchange PUBLIC age recipients, inventory before ($(ts))"
VAPUB="$(sudo -n pft-keyescrow pubkey)"; SEPUB="$(R 'sudo -n pft-keyescrow pubkey')"
printf 'key\t%s\nkey\t%s\n' "$VAPUB" "$SEPUB" >> "$LIT"
[[ "$VAPUB" =~ ^age1 ]] && [[ "$SEPUB" =~ ^age1 ]] && [ "$VAPUB" != "$SEPUB" ]
check "two different age recipients (printed redacted)" $?
x 'sudo -n pft-keyescrow set-peer "$SEPUB"'
check "validator set-peer" "$XRC"
x 'R "sudo -n pft-keyescrow set-peer $VAPUB"'
check "sentry set-peer" "$XRC"
x "sudo -n pft-keyescrow inventory"
check "validator inventory before: nothing perm/missing/unreadable, all new (exit 1)" "$(ok_if '[ "$XRC" = 1 ] && grep -q "perm 0, missing 0, unreadable 0" <<<"$XOUT"')"
x "R 'sudo -n pft-keyescrow inventory'"
check "sentry inventory before: nothing perm/missing/unreadable, all new (exit 1)" "$(ok_if '[ "$XRC" = 1 ] && grep -q "perm 0, missing 0, unreadable 0" <<<"$XOUT"')"

echo "== 3. first escrow through the sandboxed unit ($(ts))"
x "sudo -n bash keyescrow/install.sh --escrow-host"
ESC="$XOUT"
check "escrow unit: both directions PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "RESULT: PASS - both directions sealed, held and verified" <<<"$ESC"')"
check "sentry decrypted + checked the validator generation in memory" "$(ok_if 'grep -qE "\| VERIFIED from=validator gen=[0-9TZ]+ items=[0-9]+$" <<<"$ESC"')"
check "validator decrypted + checked the sentry generation, sentry acked" "$(ok_if 'grep -qE "VERIFIED from=sentry gen=[0-9TZ]+ items=[0-9]+$" <<<"$ESC" && grep -qE "\| ACKED gen=[0-9TZ]+ items=[0-9]+$" <<<"$ESC"')"
x "TZ=UTC systemctl list-timers pft-keyescrow-escrow.timer pft-keyescrow-pull.timer --no-pager"
check "nightly escrow + pull timers enabled" "$(ok_if 'systemctl is-enabled -q pft-keyescrow-escrow.timer && systemctl is-enabled -q pft-keyescrow-pull.timer')"

echo "== 4. verify both holders, inventory after, hourly unit ($(ts))"
x "sudo -n pft-keyescrow verify --all"
check "validator verify of the sentry generation it holds" "$(ok_if '[ "$XRC" = 0 ] && grep -q "RESULT: 1 generation(s) checked, 0 failed" <<<"$XOUT"')"
x "R 'sudo -n pft-keyescrow verify --all'"
check "sentry verify of the validator generation it holds" "$(ok_if '[ "$XRC" = 0 ] && grep -q "RESULT: 1 generation(s) checked, 0 failed" <<<"$XOUT"')"
x "sudo -n pft-keyescrow inventory --json | jq -c '{host, exit, escrow: ([.items[] | select(.state == \"ok\") | .escrow] | group_by(.) | map({(.[0]): length}) | add)}'"
check "validator inventory after: every ok item same, exit 0" "$(ok_if 'grep -q "\"exit\":0" <<<"$XOUT" && ! grep -qE "\"(new|drift)\"" <<<"$XOUT"')"
x "R 'sudo -n pft-keyescrow inventory --json' | jq -c '{host, exit, escrow: ([.items[] | select(.state == \"ok\") | .escrow] | group_by(.) | map({(.[0]): length}) | add)}'"
check "sentry inventory after: every ok item same, exit 0" "$(ok_if 'grep -q "\"exit\":0" <<<"$XOUT" && ! grep -qE "\"(new|drift)\"" <<<"$XOUT"')"
x "sudo -n bash keyescrow/install.sh --enable"
check "validator hourly unit run + timer enabled" "$XRC"
x "R 'sudo -n bash $RDIR/keyescrow/install.sh --enable'"
check "sentry hourly unit run + timer enabled" "$XRC"

echo "== 5. pull + metrics ($(ts))"
x "sudo -n systemctl start pft-keyescrow-pull.service && journalctl -u pft-keyescrow-pull.service -n 2 --no-pager --utc -o cat"
check "pull unit" "$XRC"
x "grep -h '^pft_keyescrow_[a-z_]*{' /var/lib/pft-exporter/textfile/pft_keyescrow*.prom | grep -v collect_timestamp | grep -v verify_timestamp"
check "validator exports both nodes: items, last escrow, held ok=1 each way" "$(ok_if 'grep -q "^pft_keyescrow_held_verify_ok{node=\"validator\",peer=\"sentry\"} 1$" <<<"$XOUT" && grep -q "^pft_keyescrow_held_verify_ok{node=\"sentry\",peer=\"validator\"} 1$" <<<"$XOUT" && grep -q "^pft_keyescrow_drift_items{node=\"sentry\"} 0$" <<<"$XOUT" && grep -q "^pft_keyescrow_drift_items{node=\"validator\"} 0$" <<<"$XOUT" && grep -q "^pft_keyescrow_inventory_exit_code{node=\"sentry\"} 0$" <<<"$XOUT"')"

echo "== 6. zero-leak check ($(ts))"
x "sudo -n python3 -I keyescrow/drill/leakcheck.py --tool /usr/local/bin/pft-keyescrow --conf /etc/pft-keyescrow.env --host validator --scan /var/lib/pft-keyescrow --scan /var/lib/pft-exporter/textfile ${LOG:+--scan-file $LOG}"
check "validator: every secret probed, 0 leaks${LOG:+ (incl. the raw log of this run)}" "$(ok_if '[ "$XRC" = 0 ] && ! grep -q "^scanned files: 0 " <<<"$XOUT"')"
x "R 'sudo -n python3 -I $RDIR/keyescrow/drill/leakcheck.py --tool /usr/local/bin/pft-keyescrow --conf /etc/pft-keyescrow.env --host sentry --scan /var/lib/pft-keyescrow --scan /var/lib/pft-exporter/textfile --scan $RDIR'"
check "sentry: every secret probed, 0 leaks" "$(ok_if '[ "$XRC" = 0 ] && ! grep -q "^scanned files: 0 " <<<"$XOUT"')"
x "grep -c 'AGE-SECRET-KEY' <<<\"\$ESC\"; sudo -n grep -c 'AGE-SECRET-KEY' /var/lib/pft-keyescrow/age.key"
check "no age identity in the escrow output (control: the identity file has one)" "$(ok_if '[ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = 1 ]')"

echo "== 7. integrity baselines ($(ts))"
x "sudo -n pft-integrity accept --reason '$TASK: pft-keyescrow $SHORT installed (binary, helper, units, conf, rulecheck lines)' | tail -3"
x "R \"sudo -n pft-integrity accept --reason '$TASK: pft-keyescrow $SHORT installed (binary, helper, units, conf, rulecheck lines)'\" | tail -3"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify' | tail -1"
check "pft-integrity PASS on both after accept" "$(ok_if '[ "$(grep -c "^RESULT: PASS" <<<"$XOUT")" = 2 ]')"

echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed check(s) - $(ts)"
[ "$FAILS" = 0 ]
