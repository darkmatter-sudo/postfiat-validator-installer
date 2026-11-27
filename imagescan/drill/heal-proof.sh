#!/usr/bin/env bash
# heal-proof.sh HOST: one recorded heal-or-noop run on one host (validator = local, sentry = relay) after
# heal-install-run.sh. 1. the sandboxed pft-imagescan-heal.service once (fetch only: every feed compared with
# upstream's clock, cache-busting retry when behind) -> feeds.json outcomes + the textfile outcome series;
# 2. the real pft-upstreamwatch.service once -> heal-or-noop decision (heal.jsonl / unit journal) and every feed's
# state. Gates: every imagescan feed fresh or retried_fresh, upstreamwatch ok (or upstream_quiet) for every imagescan
# feed and nothing paged, textfile valid with the series (and in Prometheus), pft-integrity PASS, postfiatd container
# ID + StartedAt unchanged, no new pending/firing alert, 0 messages on both operator topics. Read-mostly: it writes only the feed
# cache, the textfiles and upstreamwatch's data dir, as the hourly/daily units do.
# Usage (validator): bash imagescan/drill/heal-proof.sh validator|sentry 2>&1 | tee runlog
set -uo pipefail
H="${1:?validator|sentry}"
case "$H" in validator) C=postfiatd ;; sentry) C=postfiatd-sentry ;; *) echo "validator|sentry" >&2; exit 3 ;; esac
OPS="$(sudo -n sed -n 's/^NTFY_TOPIC=//p' /etc/postfiat-monitor.env | head -1)"
BRIDGE_URL="$(sed -n 's/^NTFY_URL=//p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null | tr -d '"' | head -1)"
BRT="${BRIDGE_URL##*/}"
since="$(date -u +%s)"; FAILS=0
red() { sed -E "s#${OPS:-@@none@@}#<redacted>#g; s#${BRT:-@@none@@}#<redacted>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#/home/[a-z0-9_-]+#~#g"; }
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
gate() { if [ "$1" = 0 ]; then echo "GATE PASS $2"; else echo "GATE FAIL $2"; FAILS=$((FAILS + 1)); fi; }
# on CMD: run CMD on the host under test (validator: here; sentry: ssh relay)
on() { if [ "$H" = validator ]; then bash -c "$1"; else ssh -o BatchMode=yes relay "$1" </dev/null; fi; }
alerts() { curl -s -m 10 http://127.0.0.1:9090/api/v1/alerts | jq -r '.data.alerts[] | "\(.state) \(.labels.alertname) \(.labels.host // "-") \(.labels.feed // "")"' | sort; }
TF=/var/lib/pft-exporter/textfile
echo "isheal proof on $H - $(date -u +%FT%TZ)"
x "on \"docker inspect -f '{{.Name}} {{.Id}} {{.State.StartedAt}} {{.State.Status}}' $C\""
PRE_ID="$XOUT"
x "alerts"
PRE_AL="$XOUT"
x "on 'pft-imagescan version; pft-upstreamwatch version; systemctl show -p LoadState,ActiveState --value pft-imagescan-heal.service'"
x "on \"sudo -n jq -c '.feeds | to_entries[] | {feed: .key, own: (.value.timestamp_epoch | todate), fetched: (.value.fetched_epoch | todate), outcome: (.value.outcome // \\\"none\\\")}' /var/cache/pft-imagescan/feeds/feeds.json\""
# 1. the sandboxed fetch-only heal unit, exactly as upstreamwatch would start it
T1="$(date -u +%s)"
x "on 'sudo -n systemctl start pft-imagescan-heal.service; echo rc=\$?; systemctl show -p Result,ExecMainStatus --value pft-imagescan-heal.service'"
grep -q '^rc=0$' <<< "$XOUT"; gate $? "pft-imagescan-heal.service ran (fetch only, sandboxed) and succeeded"
x "on \"journalctl -u pft-imagescan-heal.service --since @$T1 --no-pager -o cat | grep -E '^(ubuntu|debian|go)|^textfile:|fresh|behind|FAILED|REFUSED'\""
x "on \"sudo -n jq -r '.feeds | to_entries[] | \\\"\\(.key) \\(.value.outcome) own=\\(.value.timestamp_epoch | todate) upstream=\\(.value.upstream_epoch) clock=\\(.value.upstream_clock) note=\\(.value.outcome_note)\\\"' /var/cache/pft-imagescan/feeds/feeds.json\""
OUTC="$XOUT"
[ "$(grep -cE '^(ubuntu-jammy|ubuntu-noble|debian|go) (fresh|retried_fresh) ' <<< "$OUTC")" = 4 ]
gate $? "all 4 imagescan feeds fresh or retried_fresh"
x "on \"grep -E '^pft_imagescan_feed_(fetch_outcome|upstream_timestamp_seconds)' $TF/pft_imagescan_$H.prom; pft-imagescan validate $TF/pft_imagescan_$H.prom $H && echo valid\""
[ "$(grep -cE 'outcome=\"(fresh|retried_fresh)\"\} 1$' <<< "$XOUT")" = 4 ] && grep -q '^valid$' <<< "$XOUT"
gate $? "textfile valid, outcome series = 1 for fresh/retried_fresh on all 4 feeds"
# 2. the real hourly upstreamwatch unit: heal-or-noop
T2="$(date -u +%s)"
x "on 'sudo -n tail -n 1 /var/lib/pft-upstreamwatch/heal.jsonl 2>/dev/null | wc -l; sudo -n wc -l < /var/lib/pft-upstreamwatch/heal.jsonl 2>/dev/null || echo 0'"
x "on 'sudo -n systemctl start pft-upstreamwatch.service; echo rc=\$?'"
grep -q '^rc=0$' <<< "$XOUT"; gate $? "pft-upstreamwatch.service ran"
x "on \"journalctl -u pft-upstreamwatch.service --since @$T2 --no-pager -o cat | grep -E '^heal:|^(usn-host|ubuntu|debian|go)|^RESULT'\""
UW="$XOUT"
if grep -q '^heal: ' <<< "$UW"; then echo "decision: HEAL (see heal: lines)"; else echo "decision: NOOP (no feed lagged > LAG_HEAL_HOURS)"; fi
! grep -qE '^heal: .* (failed|still_lagging) ' <<< "$UW"; gate $? "no failed / still_lagging heal"
# ok or upstream_quiet: both mean "our copy is upstream's latest" (go's upstream often goes > QUIET_AGE_HOURS unchanged)
[ "$(grep -cE '^(ubuntu-jammy|ubuntu-noble|debian|go) +(ok|upstream_quiet) ' <<< "$UW")" = 4 ] && ! grep -q -- '-> PAGE' <<< "$UW"
gate $? "upstreamwatch: every imagescan feed ok/upstream_quiet (local copy = upstream's latest), nothing paged"
x "on \"sudo -n jq -c 'select(.epoch >= $T2)' /var/lib/pft-upstreamwatch/heal.jsonl 2>/dev/null; sudo -n jq -c . /var/lib/pft-upstreamwatch/heal-state.json 2>/dev/null\""
[ "$H" = sentry ] && x "sudo -n systemctl start pft-imagescan-pull.service pft-upstreamwatch-pull.service; echo rc=\$?"
sleep 75  # one scrape + one rule evaluation
x "curl -s -m 10 http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=pft_imagescan_feed_fetch_outcome{host=\"$H\"} == 1' | jq -r '.data.result[] | \"\\(.metric.feed) \\(.metric.outcome)\"' | sort"
[ "$(wc -l <<< "$XOUT")" = 4 ]; gate $? "Prometheus has the outcome series for $H"
x "on 'sudo -n pft-integrity verify | tail -1'"
grep -q 'RESULT: PASS' <<< "$XOUT"; gate $? "pft-integrity PASS on $H"
x "on \"docker inspect -f '{{.Name}} {{.Id}} {{.State.StartedAt}} {{.State.Status}}' $C\""
[ "$XOUT" = "$PRE_ID" ]; gate $? "$C container ID + StartedAt unchanged"
x "alerts"
NEW_AL="$(comm -13 <(printf '%s\n' "$PRE_AL") <(printf '%s\n' "$XOUT"))"
echo "new pending/firing alerts: ${NEW_AL:-none}"
[ -z "$NEW_AL" ]; gate $? "no new pending/firing alert (Prometheus /api/v1/alerts)"
sleep 20
x "curl -s -m 15 'https://ntfy.sh/$OPS/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title' | wc -l"
[ "$XOUT" = 0 ]; gate $? "operator monitor topic: 0 messages since the run started"
x "curl -s -m 15 '$BRIDGE_URL/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title' | wc -l"
[ -n "$BRT" ] && [ "$XOUT" = 0 ]; gate $? "operator alert-bridge topic: 0 messages since the run started"
echo "RESULT: $FAILS gate(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
