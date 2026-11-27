#!/usr/bin/env bash
# heal-proof.sh: recorded live proof, on the SENTRY, of local_lagging + exactly one bounded heal (README "Bounded heal").
# Runs on the validator (Prometheus/Alertmanager host); every sentry step is sent as a script to `ssh relay sudo bash -s`.
#
#  0  installed files on the sentry == this commit's bytes (pft-upstreamwatch, lib, units, pft-vulnscan, heal unit)
#  1  preconditions: no pft-maint window, no upstreamwatch/vulnscan unit active, next upstreamwatch timer run >= 10 min
#     away, upstream's USN Last-Modified newer than the committed older feed and published < STALE_GRACE_HOURS ago
#  2  backup (cache + heal state) to DATA_DIR/drill-<epoch>/; the heal state is moved aside, so the attempt counted
#     here is the first one (an earlier natural heal would otherwise rate-limit this proof)
#  3  install the committed older feed (fixtures/usn-jammy-20261126T0855Z.xml.bz2, a real Canonical copy that a cache
#     served on 2026-11-27) into the sentry's vulnscan cache, under vulnscan's cache lock, fetch clock = now
#  A  `pft-upstreamwatch run --no-heal`: usn-host local_lagging, LAG > LAG_HEAL_HOURS, lag metric in the textfile;
#     validator pulls it: Prometheus has pft_upstreamwatch_feed_lag_seconds{host="sentry"} and the one-hot state
#  B  `systemctl start pft-upstreamwatch.service` (the real sandboxed unit): one heal (start + healed in heal.jsonl,
#     attempts 1), pft-vulnscan-heal.service ran scan --force-fetch, the cache now holds upstream's copy (content clock
#     within tolerance of upstream's Last-Modified), pft_vulnscan_feed_timestamp_seconds moved, usn-host ok, lag 0
#  C  the unit again: nothing to heal (no new journal line, attempts still 1), still ok
#  D  validator pulls: Prometheus shows sentry ok / lag 0 / heal healed; no PFTUpstream*/PFTVuln* alert for the sentry
#     pending or firing; the operator ntfy topic received 0 messages since step 0
# Nothing here touches postfiatd. Exit 0 only if every gate passed.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
FEED="$HERE/fixtures/usn-jammy-20261126T0855Z.xml.bz2"
ETAG="$(cat "$HERE/fixtures/usn-jammy-20261126T0855Z.etag")"
FEED_SHA=fb0df633af327dbbd35b93b15f4c7dde8df6065e9172cfe5188545f21d7f865a
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15 relay)
PROM=http://127.0.0.1:9090
OPS="$(sudo -n sed -n 's/^NTFY_TOPIC=//p' /etc/postfiat-monitor.env | head -1)"
FAILS=0; T0="$(date -u +%s)"
red() { sed -E "s#${OPS:-@@none@@}#<redacted>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#/home/[a-z0-9_-]+#~#g"; }
# x CMD: run locally; rx CMD: run on the sentry as root (the text goes over stdin, no ssh argv quoting)
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
rx() { echo "\$ [sentry] $*" | red; XOUT="$(printf '%s\n' "$*" | "${SSH[@]}" 'sudo -n bash -s' 2>&1)"; XRC=$?
       printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
gate() { if [ "$1" = 0 ]; then echo "GATE PASS $2"; else echo "GATE FAIL $2"; FAILS=$((FAILS + 1)); fi; }
q() { curl -s -m 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric | del(.__name__, .job, .instance) | tostring) \(.value[1])"'; }
# wait_prom QUERY WANT: poll Prometheus (scrape 15 s) until the single value equals WANT, up to 120 s
wait_prom() { local i v; for i in $(seq 1 24); do v="$(curl -s -m 10 "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[0].value[1] // empty')"; [ "$v" = "$2" ] && { echo "  prom: $1 = $v (after $((i * 5)) s)"; return 0; }; sleep 5; done; echo "  prom: $1 = ${v:-none}, wanted $2"; return 1; }
abort() { echo "ABORT: $1"; echo "RESULT: aborted at a precondition -> FAIL"; exit 1; }

echo "heal-proof (sentry) - $(date -u +%FT%TZ)"
echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)  heal-proof.sh sha256 $(sha256sum < "${BASH_SOURCE[0]}" | cut -c1-64)"
echo "older feed $(basename "$FEED") sha256 $(sha256sum < "$FEED" | cut -c1-64) etag $ETAG"
[ "$(sha256sum < "$FEED" | cut -c1-64)" = "$FEED_SHA" ]; gate $? "committed older feed has the recorded sha256"
[ -z "$(git -C "$REPO" status --short -- upstreamwatch vulnscan alerts)" ]; gate $? "working tree clean for upstreamwatch/ vulnscan/ alerts/"

echo "== 0. installed bytes on the sentry == repo HEAD"
want="$(cd "$REPO" && sha256sum upstreamwatch/pft-upstreamwatch.sh upstreamwatch/upstreamwatch_lib.py \
  upstreamwatch/systemd/pft-upstreamwatch.service vulnscan/pft-vulnscan.sh vulnscan/systemd/pft-vulnscan-heal.service | cut -c1-64)"
rx "sha256sum /usr/local/bin/pft-upstreamwatch /usr/local/lib/pft-upstreamwatch/upstreamwatch_lib.py /etc/systemd/system/pft-upstreamwatch.service /usr/local/bin/pft-vulnscan /etc/systemd/system/pft-vulnscan-heal.service"
[ "$(printf '%s\n' "$XOUT" | cut -c1-64)" = "$want" ]; gate $? "sentry runs this commit's pft-upstreamwatch, lib, unit, pft-vulnscan and heal unit"

echo "== 1. preconditions"
rx "pft-maint active; echo maint_rc=\$?; systemctl is-active pft-upstreamwatch.service pft-vulnscan.service pft-vulnscan-heal.service; echo next=\$(( \$(systemctl show -p NextElapseUSecRealtime --value pft-upstreamwatch.timer | xargs -I{} date -u -d {} +%s) - \$(date -u +%s) ))"
grep -q '^maint_rc=1$' <<< "$XOUT" || abort "a pft-maint window is active (or pft-maint failed)"
[ "$(grep -c '^active$' <<< "$XOUT")" = 0 ] || abort "an upstreamwatch/vulnscan unit is running"
nx="$(sed -n 's/^next=//p' <<< "$XOUT")"
if ! { [[ "$nx" =~ ^[0-9]+$ ]] && [ "$nx" -ge 600 ]; }; then abort "upstreamwatch timer fires within 10 min ($nx s)"; fi
rx "curl -sSI -m 20 -H 'Cache-Control: no-cache' \"https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2?pft-heal-proof=\$(date -u +%s)\" | grep -i -E '^(date|last-modified|etag):'"
up_lm="$(date -u -d "$(sed -n 's/^[Ll]ast-[Mm]odified: //p' <<< "$XOUT" | tr -d '\r')" +%s 2>/dev/null)"
fts="$(python3 -I -c 'import bz2, calendar, re, sys, time
m = re.search(rb"<oval:timestamp>([0-9T:-]{19})", bz2.open(sys.argv[1]).read(65536))
print(calendar.timegm(time.strptime(m.group(1).decode(), "%Y-%m-%dT%H:%M:%S")))' "$FEED")"
echo "  older feed <oval:timestamp> $fts ($(date -u -d "@$fts" +%FT%TZ)); upstream Last-Modified ${up_lm:-?} ($(date -u -d "@${up_lm:-0}" +%FT%TZ))"
if ! { [ -n "$up_lm" ] && [ $((up_lm - fts)) -gt 21600 ]; }; then abort "upstream is not newer than the older feed by more than CONTENT_TOLERANCE_SECONDS"; fi
[ $(( $(date -u +%s) - up_lm )) -le $((30 * 3600)) ] || abort "upstream published more than STALE_GRACE_HOURS ago (would be local_stale, not local_lagging)"
[ $(( $(date -u +%s) - up_lm )) -gt 7200 ] || abort "upstream published less than LAG_HEAL_HOURS ago (no heal due)"
gate 0 "preconditions (no window, units idle, timer >= 10 min away, upstream newer and within grace)"

echo "== 2. backup + heal state aside"
B="/var/lib/pft-upstreamwatch/drill-$T0"
rx "set -e; mkdir -m 700 $B; cp -p /var/cache/pft-vulnscan/feed.xml.bz2 /var/cache/pft-vulnscan/feed.meta /var/cache/pft-vulnscan/feed.etag $B/; if [ -e /var/lib/pft-upstreamwatch/heal-state.json ]; then mv /var/lib/pft-upstreamwatch/heal-state.json $B/; echo 'heal-state moved aside:'; cat $B/heal-state.json; else echo 'no heal state yet'; fi; touch /var/lib/pft-upstreamwatch/heal.jsonl; echo journal_lines=\$(wc -l < /var/lib/pft-upstreamwatch/heal.jsonl); ls $B"
gate "$XRC" "backup taken"
J0="$(sed -n 's/^journal_lines=//p' <<< "$XOUT")"

echo "== 3. install the committed older feed into the sentry's vulnscan cache"
x "${SSH[*]} 'umask 077; mkdir -p ~/.cache && cat > ~/.cache/uwheal-older.xml.bz2' < '$FEED'"
rx "set -e; cd /var/cache/pft-vulnscan; exec 7> .lock; flock -w 60 7; install -m 644 ~/.cache/uwheal-older.xml.bz2 feed.xml.bz2; rm -f ~/.cache/uwheal-older.xml.bz2; printf '%s\n' '$ETAG' > feed.etag; t=\$(date -u +%s); printf 'sha256=%s\nfetched_at=%s\nlast_checked=%s\nurl=%s\n' \"\$(sha256sum < feed.xml.bz2 | cut -c1-64)\" \$t \$t https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2 > feed.meta; cat feed.meta; cat feed.etag"
grep -q "^sha256=$FEED_SHA$" <<< "$XOUT"; gate $? "older feed installed (sha256 $FEED_SHA)"

echo "== A. report without healing: local_lagging + lag metric"
rx "pft-upstreamwatch run --no-heal; echo run_rc=\$?; grep -E 'feed=\"usn-host\"' /var/lib/pft-exporter/textfile/pft_upstreamwatch_sentry.prom | grep -E 'feed_state.*local_lagging|lag_seconds'"
grep -qE '^usn-host +local_lagging ' <<< "$XOUT"; gate $? "A: usn-host local_lagging"
lagA="$(sed -n 's/^pft_upstreamwatch_feed_lag_seconds{host="sentry",feed="usn-host"} //p' <<< "$XOUT")"
[[ "$lagA" =~ ^[0-9]+$ ]] && [ "$lagA" -gt 7200 ]; gate $? "A: textfile pft_upstreamwatch_feed_lag_seconds = ${lagA:-none} > LAG_HEAL_HOURS (7200 s)"
grep -q 'feed="usn-host",state="local_lagging"} 1' <<< "$XOUT"; gate $? "A: textfile one-hot local_lagging 1"
! grep -q '^heal:' <<< "$XOUT"; gate $? "A: --no-heal made no heal decision"
x "sudo -n systemctl start pft-upstreamwatch-pull.service; systemctl is-failed pft-upstreamwatch-pull.service"
wait_prom 'pft_upstreamwatch_feed_state{host="sentry",feed="usn-host",state="local_lagging"}' 1; gate $? "A: Prometheus has sentry usn-host local_lagging = 1"
wait_prom 'pft_upstreamwatch_feed_lag_seconds{host="sentry",feed="usn-host"}' "$lagA"; gate $? "A: Prometheus pft_upstreamwatch_feed_lag_seconds{host=sentry} = $lagA"

echo "== B. the real unit: exactly one bounded heal"
TB="$(date -u +%s)"
rx "systemctl start pft-upstreamwatch.service; echo start_rc=\$?; systemctl show -p Result -p ExecMainStatus pft-upstreamwatch.service; journalctl --utc -o short-iso -u pft-upstreamwatch.service -u pft-vulnscan-heal.service --since @$TB --no-pager | grep -E 'heal|fetch|RESULT|usn-host|Started|Finished|Deactivated'"
grep -q '^start_rc=0$' <<< "$XOUT"; gate $? "B: pft-upstreamwatch.service ran (rc 0)"
grep -q 'heal: usn-host start - lag' <<< "$XOUT" && grep -q 'heal: usn-host healed - lag 0 after the refetch (rc 0)' <<< "$XOUT"; gate $? "B: journal shows heal start + healed"
grep -q 'fetch: forced unconditional GET: fetched' <<< "$XOUT"; gate $? "B: pft-vulnscan-heal.service did the forced cache-busting GET"
rx "tail -n +\$(( $J0 + 1 )) /var/lib/pft-upstreamwatch/heal.jsonl; echo ---; cat /var/lib/pft-upstreamwatch/heal-state.json; echo ---; cat /var/cache/pft-vulnscan/feed.meta; grep -E '^pft_vulnscan_(up|feed_timestamp_seconds)' /var/lib/pft-exporter/textfile/pft_vulnscan_sentry.prom; pft-upstreamwatch report | sed -n '1,4p;/^heal/p;/^RESULT/p'; jq -r '.feeds[] | select(.name == \"usn-host\") | \"obs upstream last-modified: \(.upstream.headers[\"last-modified\"])  local content_epoch: \(.local_obs.content_epoch)\"' /var/lib/pft-upstreamwatch/last-obs.json; grep -E 'feed=\"usn-host\"' /var/lib/pft-exporter/textfile/pft_upstreamwatch_sentry.prom | grep -E 'state=\"ok\"|lag_seconds|heal_'"
[ "$(sed -n '1,/^---$/p' <<< "$XOUT" | grep -c '"feed": *"usn-host"')" = 2 ] && [ "$(sed -n '1,/^---$/p' <<< "$XOUT" | grep -c '"event": *"start"')" = 1 ] && [ "$(sed -n '1,/^---$/p' <<< "$XOUT" | grep -c '"event": *"healed"')" = 1 ]
gate $? "B: heal.jsonl got exactly 2 new lines: start + healed"
grep -qE '"attempts": 1,' <<< "$XOUT" && grep -qE '"last_result": "healed"' <<< "$XOUT"; gate $? "B: heal-state attempts 1, last_result healed"
newsha="$(sed -n 's/^sha256=//p' <<< "$XOUT")"; [ -n "$newsha" ] && [ "$newsha" != "$FEED_SHA" ]; gate $? "B: cache replaced (sha256 ${newsha:0:12}... != older feed)"
nts="$(sed -n 's/^pft_vulnscan_feed_timestamp_seconds{host="sentry"} //p' <<< "$XOUT")"
[[ "$nts" =~ ^[0-9]+$ ]] && [ "$nts" -gt "$fts" ] && [ $((up_lm - nts)) -le 21600 ] && [ $((nts - up_lm)) -le 21600 ]
gate $? "B: pft_vulnscan_feed_timestamp_seconds $nts ($(date -u -d "@${nts:-0}" +%FT%TZ)) moved past the older feed ($fts) to upstream's Last-Modified ($up_lm) within tolerance"
grep -q 'pft_vulnscan_up{host="sentry"} 1' <<< "$XOUT"; gate $? "B: heal scan up 1"
grep -qE '^usn-host +ok ' <<< "$XOUT" && grep -q 'pft_upstreamwatch_feed_lag_seconds{host="sentry",feed="usn-host"} 0' <<< "$XOUT"; gate $? "B: usn-host back to ok, lag 0"
grep -q 'heal_last_result{host="sentry",feed="usn-host",result="healed"} 1' <<< "$XOUT"; gate $? "B: textfile heal_last_result healed 1"

echo "== C. the unit again: nothing left to heal"
rx "systemctl start pft-upstreamwatch.service; echo start_rc=\$?; echo journal_lines=\$(wc -l < /var/lib/pft-upstreamwatch/heal.jsonl); jq -c '.\"usn-host\" | {attempts, last_result}' /var/lib/pft-upstreamwatch/heal-state.json; pft-upstreamwatch report | grep -E '^usn-host'"
[ "$(sed -n 's/^journal_lines=//p' <<< "$XOUT")" = $((J0 + 2)) ] && grep -q '{"attempts":1,"last_result":"healed"}' <<< "$XOUT"; gate $? "C: no new heal (journal +0, attempts still 1)"
grep -qE '^usn-host +ok ' <<< "$XOUT"; gate $? "C: usn-host still ok"

echo "== D. validator view + operator topic"
x "sudo -n systemctl start pft-upstreamwatch-pull.service pft-vulnscan-pull.service; systemctl is-failed pft-upstreamwatch-pull.service pft-vulnscan-pull.service"
wait_prom 'pft_upstreamwatch_feed_state{host="sentry",feed="usn-host",state="ok"}' 1; gate $? "D: Prometheus sentry usn-host ok = 1"
wait_prom 'pft_upstreamwatch_feed_lag_seconds{host="sentry",feed="usn-host"}' 0; gate $? "D: Prometheus sentry lag 0"
wait_prom 'pft_upstreamwatch_heal_last_result{host="sentry",feed="usn-host",result="healed"}' 1; gate $? "D: Prometheus sentry heal_last_result healed = 1"
wait_prom 'pft_upstreamwatch_heal_attempts{host="sentry",feed="usn-host"}' 1; gate $? "D: Prometheus sentry heal_attempts = 1"
wait_prom 'pft_vulnscan_feed_timestamp_seconds{host="sentry"}' "$nts"; gate $? "D: Prometheus sentry vulnscan feed timestamp = healed copy"
x "curl -s -m 10 '$PROM/api/v1/alerts' | jq -r '.data.alerts[] | select(.labels.host == \"sentry\" and (.labels.alertname | test(\"^PFT(Upstream|Vuln)\"))) | \"\(.labels.alertname) \(.state)\"' | wc -l"
[ "$XOUT" = 0 ]; gate $? "D: no PFTUpstream*/PFTVuln* alert for the sentry pending or firing"
x "curl -s -m 10 http://127.0.0.1:9093/api/v2/alerts | jq -r '.[] | select(.labels.host == \"sentry\" and (.labels.alertname | test(\"^PFT(Upstream|Vuln)\"))) | .labels.alertname' | wc -l"
[ "$XOUT" = 0 ]; gate $? "D: Alertmanager holds none of them for the sentry"
rx "pft-integrity verify | tail -1; rm -rf $B && echo backup-removed"
gate "$XRC" "D: sentry integrity verify PASS (cache + heal state are not integrity items)"
sleep 30
x "curl -s -m 15 'https://ntfy.sh/$OPS/json?poll=1&since=$T0' | jq -r 'select(.event == \"message\") | .title' | wc -l"
[ "$XOUT" = 0 ]; gate $? "D: operator topic: 0 messages since step 0"
echo "RESULT: $FAILS gate(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
