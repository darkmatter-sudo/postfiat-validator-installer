#!/usr/bin/env bash
# Recorded two-host install of feewatch at the current HEAD (task_448dd0bfb8860c914e018ceba393cdf5).
#   bash feewatch/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user; HEAD clean + pushed)
# Built from privesc/drill/install-run.sh + fleet-run.sh. pft-fleet sync needs a pft-maint window; its [MAINT]
# messages go to a throwaway ntfy topic, and the real pft-maint target is restored and compared at the end. An
# Alertmanager silence scoped to the rules a new textfile/rule can touch covers the rollout and is expired at the end.
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"
TT="pft-drill-feewatch-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-feewatch
SWAPPED=0; MAINT=0; HAD=0; SIL=""
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap 'restore; R "rm -rf /tmp/pft-feewatch-$SHORT" || true' EXIT
echo "feewatch two-host install - $(date -u +%FT%TZ) - $(lsb_release -ds) - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-feewatch /etc/pft-feewatch.env 2>&1; R 'ls /usr/local/bin/pft-feewatch 2>&1'"
check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "sha256sum feewatch/pft-feewatch.sh feewatch/feewatch_parse.py alerts/feewatch.rules.yml"

echo; echo "== 1. pft-maint target -> throwaway topic (real file kept with mode/owner/mtime as \$BK), window"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason 'task_448dd0bf feewatch install + fleet manifest sync'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"

echo; echo "== 2. rollout silence (new rules + new textfiles; rulecheck/fleet see new files)"
ends="$(date -u -d '+40 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "task_448dd0bf feewatch rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTTxQueueNearFull|PFTFeeEscalated|PFTLocalLoadHigh|PFTFeewatchStale|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "feewatch-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (4 feewatch rules, PFTRuleDead, PFTTextfileStale, PFTRulecheck*, PFTFleet*) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 3. sentry: install"
x "git archive $SHA feewatch | R 'rm -rf /tmp/pft-feewatch-$SHORT && mkdir -m 700 /tmp/pft-feewatch-$SHORT && tar -x -C /tmp/pft-feewatch-$SHORT'"
x "R 'sudo -n /tmp/pft-feewatch-$SHORT/feewatch/install.sh --container postfiatd-sentry'"
check "sentry install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_feewatch_up{container="postfiatd-sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n /tmp/pft-feewatch-$SHORT/feewatch/install.sh --container postfiatd-sentry'"
check "sentry second install exit 0 (idempotent)" "$XRC"
x "R 'sudo -n stat -c \"%a %U %n\" /usr/local/bin/pft-feewatch /usr/local/lib/pft-feewatch/feewatch_parse.py /var/lib/pft-feewatch; systemctl is-active pft-feewatch@postfiatd-sentry.timer'"

echo; echo "== 4. validator: install"
x "sudo -n feewatch/install.sh"
check "validator install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_feewatch_up{container="postfiatd"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n feewatch/install.sh"
check "validator second install exit 0 (idempotent)" "$XRC"
x "sudo -n stat -c '%a %U %n' /usr/local/bin/pft-feewatch /usr/local/lib/pft-feewatch/feewatch_parse.py /var/lib/pft-feewatch; systemctl is-active pft-feewatch@postfiatd.timer"

echo; echo "== 5. validator: pull of the sentry file (PULL_SSH copied from /etc/pft-statewatch.env, not printed)"
x "sudo -n test -e /etc/pft-feewatch.env || sudo -n install -m 600 -o root -g root /dev/null /etc/pft-feewatch.env; sudo -n grep -q '^PULL_SSH=' /etc/pft-feewatch.env || sudo -n sh -c 'grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-feewatch.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-feewatch.env; sudo -n stat -c '%a %U' /etc/pft-feewatch.env"
x "sudo -n feewatch/install.sh --pull postfiatd-sentry"
check "pull install exit 0, sentry file present on the validator" "$([ "$XRC" = 0 ] && grep -q 'pft_feewatch_up{container="postfiatd-sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 6. rulecheck: feewatch textfiles must stay fresh (both hosts)"
x "sudo -n grep -q '^textfile pft_feewatch_' /etc/pft-rulecheck.conf || printf '%s\n' '# pft-feewatch (1-minute collector; sentry copy pulled every minute)' 'textfile pft_feewatch_*.prom   5m   pft_feewatch_collect_timestamp_seconds' 'require pft_feewatch_postfiatd.prom' 'require pft_feewatch_postfiatd-sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n feewatch /etc/pft-rulecheck.conf"
x "R \"sudo -n grep -q '^textfile pft_feewatch_' /etc/pft-rulecheck.conf || printf '%s\n' '# pft-feewatch (1-minute collector)' 'textfile pft_feewatch_*.prom   5m   pft_feewatch_collect_timestamp_seconds' 'require pft_feewatch_postfiatd-sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n feewatch /etc/pft-rulecheck.conf\""

echo; echo "== 7. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-feewatch\") | .rules[] | [.name, .health, .state] | @tsv'"
check "4 feewatch rules loaded, health ok, inactive" "$([ "$(grep -c '	ok	inactive' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sleep 35; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_feewatch_up' | jq -r '.data.result[] | \"\(.metric.container) \(.value[1])\"' | sort"
check "Prometheus scrapes pft_feewatch_up 1 for postfiatd and postfiatd-sentry" "$([ "$(grep -cE '^postfiatd(-sentry)? 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_feewatch_(queue_fill_ratio|escalation_multiple|admin|local_load_exceeds_net)\"}' | jq -r '.data.result[] | \"\(.metric.container) \(.metric.__name__) \(.value[1])\"' | sort"

echo; echo "== 8. integrity: accept the new files on both hosts, verify"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "sudo -n pft-integrity accept --reason 'task_448dd0bf: feewatch $SHORT installed (script, parser, units, pull, env, rulecheck.conf)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | head -20"
x "R \"sudo -n pft-integrity accept --reason 'task_448dd0bf: feewatch $SHORT installed (script, parser, units, rulecheck.conf)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 9. fleet: sync the fleet add-on (manifest.tsv with the feewatch lines) to HEAD, skew, rulecheck"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason 'task_448dd0bf feewatch manifest lines'"
check "fleet sync exit 0" "$XRC"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, feewatch CURRENT on both hosts" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +feewatch +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK (feewatch rules LIVE, textfiles FRESH)" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT '"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after the sync" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 10. end window, restore the real pft-maint target, compare; expire the silence"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=30m\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query=ALERTS{alertname=~\"PFTTxQueueNearFull|PFTFeeEscalated|PFTLocalLoadHigh|PFTFeewatchStale|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*\"}' | jq -r '.data.result | length'"
check "no alert covered by the silence is pending/firing before it is expired" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x "curl -s -o /dev/null -w '%{http_code}' -X DELETE $AM/api/v2/silence/$SIL"
check "rollout silence expired" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"
x "TZ=UTC systemctl list-timers 'pft-feewatch*' --no-pager | head -4; R 'systemctl is-active pft-feewatch@postfiatd-sentry.timer'"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
