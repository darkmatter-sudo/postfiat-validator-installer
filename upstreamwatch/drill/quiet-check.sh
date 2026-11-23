#!/usr/bin/env bash
# shellcheck disable=SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Quiet-reclassification check (task_62b5fc29b42bbe4e484a03a450c97616), read-only, after drill/install-run.sh.
# The live condition: Canonical has not republished its USN OVAL since 2026-11-19, so ../../vulnscan's own-timestamp
# rule PFTVulnFeedStale fired on both hosts with nothing wrong locally. After the install, upstreamwatch classifies
# those feeds upstream_quiet; this proves, once PFTUpstreamFeedQuiet has passed its for: 65m:
#   1. the feed is STILL older than PFTVulnFeedStale's 3 days on both hosts (nothing was fixed by hand: the
#      condition persists), yet PFTVulnFeedStale is neither pending nor firing (the retuned `unless`);
#   2. PFTUpstreamFeedQuiet is FIRING for every (host, feed) whose textfile state is upstream_quiet, and nothing else
#      of PFTUpstream* is pending/firing;
#   3. Alertmanager routes every PFTUpstreamFeedQuiet alert to the `digest` receiver only (no integration) and the
#      ntfy bridge never logged one;
#   4. every operator topic received 0 messages since the install run started (SINCE).
# Nothing is silenced for PFTUpstream*; the install's rollout silence (PFTVulnFeedStale's resolve) must have ended.
#   SINCE=<epoch printed by install-run.sh> bash upstreamwatch/drill/quiet-check.sh 2>&1 | tee LOG
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
SINCE="${SINCE:?SINCE=<install run start epoch> required}"
[[ "$SINCE" =~ ^[0-9]{10}$ ]] || { echo "SINCE must be an epoch"; exit 3; }
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"; trap 'rm -f "$OPS"' EXIT
prom_q() { # $1 = PromQL; label/value lines, or query-error (fails closed)
  local j
  j="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1")"
  if [ -n "$j" ] && jq -e '.status == "success"' <<<"$j" >/dev/null 2>&1; then
    jq -r '.data.result[] | "\(.metric.host // "-") \(.metric.feed // "-") \(.value[1])"' <<<"$j" | sort
  else echo query-error; fi
}
echo "upstreamwatch quiet-reclassification check - $(date -u +%FT%TZ) - repo HEAD $SHA - window since $(date -u -d "@$SINCE" +%FT%TZ)"

echo; echo "== 1. the stale-feed condition persists, PFTVulnFeedStale is reclassified"
x "prom_q 'time() - pft_vulnscan_feed_timestamp_seconds > 3 * 86400'"
check "USN feed still older than 3 days on validator and sentry (condition unchanged, not fixed by hand)" "$(! grep -q query-error <<<"$XOUT" && [ "$(grep -cE '^(validator|sentry) ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "prom_q 'pft_upstreamwatch_feed_state{feed=\"usn-host\",state=\"upstream_quiet\"} == 1'"
check "usn-host upstream_quiet on both hosts" "$([ "$(grep -cE '^(validator|sentry) usn-host 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname == \"PFTVulnFeedStale\")] | length'"
check "PFTVulnFeedStale neither pending nor firing" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | [.id[0:8], .comment, (.matchers | map(.name + \"=\" + .value) | join(\",\"))] | @tsv'"
check "no active silence covers PFTUpstream* or PFTVulnFeedStale (rollout silence ended)" "$(! grep -qE 'Upstream|VulnFeedStale' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 2. PFTUpstreamFeedQuiet fires for every upstream_quiet feed, nothing else of PFTUpstream*"
x "prom_q 'pft_upstreamwatch_feed_state{state=\"upstream_quiet\"} == 1'"
QUIET="$(grep -vx query-error <<<"$XOUT" | awk '{print $1, $2}' | sort)"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | select(.labels.alertname | startswith(\"PFTUpstream\")) | \"\(.labels.alertname) \(.labels.host) \(.labels.feed // \"-\") \(.state)\"' | sort"
FIRING="$(awk '$1 == "PFTUpstreamFeedQuiet" && $4 == "firing" {print $2, $3}' <<<"$XOUT" | sort)"
check "PFTUpstreamFeedQuiet firing for exactly the upstream_quiet (host, feed) pairs" "$([ -n "$QUIET" ] && [ "$QUIET" = "$FIRING" ] && echo 0 || echo 1)" "$(grep -c . <<<"$QUIET") pair(s)"
check "no other PFTUpstream* alert pending or firing (LocalStale, FetchFailing, ReleaseAvailable, Failing, NotRunning)" "$(! grep -v '^PFTUpstreamFeedQuiet ' <<<"$XOUT" | grep -q . && echo 0 || echo 1)"

echo; echo "== 3. Alertmanager routing and the bridge"
x "curl -s '$AM/api/v2/alerts?active=true&silenced=false&inhibited=false' | jq -r '.[] | select(.labels.alertname == \"PFTUpstreamFeedQuiet\") | \"\(.labels.host) \(.labels.feed) \(.labels.notify) \([.receivers[].name] | join(\",\")) \(.status.state)\"' | sort"
check "every PFTUpstreamFeedQuiet alert in Alertmanager is active, notify=digest, receiver digest only" "$([ "$(grep -c . <<<"$XOUT")" = "$(grep -c . <<<"$QUIET")" ] && [ "$(grep -c ' digest digest active$' <<<"$XOUT")" = "$(grep -c . <<<"$QUIET")" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/status | jq -r '.config.original' | grep -n -A2 'notify=\"digest\"'; curl -s $AM/api/v2/status | jq -r '.config.original' | grep -n -A3 'name: digest'"
check "loaded Alertmanager config: notify=\"digest\" route -> receiver digest, which has no integration" "$(grep -q 'receiver: digest' <<<"$XOUT" && ! grep -A3 'name: digest' <<<"$XOUT" | grep -qE '_configs:' && echo 0 || echo 1)"
x "sudo -n docker logs --since $SINCE pft-alert-bridge 2>&1 | wc -l; sudo -n docker logs --since $SINCE pft-alert-bridge 2>&1 | grep -cE 'PFTUpstream|PFTVulnFeedStale'"
check "the ntfy bridge (container pft-alert-bridge) logged no PFTUpstream*/PFTVulnFeedStale alert since the install started" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)" "$(head -1 <<<"$XOUT") bridge log line(s) in the window"

echo; echo "== 4. operator topics"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$SINCE" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s) since $(date -u -d "@$SINCE" +%FT%TZ)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing since the install started (upstream_quiet never paged)" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "quiet-check done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
