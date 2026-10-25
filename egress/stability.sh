#!/usr/bin/env bash
# Stability evidence for a container under the pft-egress policy (read-only, changes nothing).
#   sudo bash stability.sh [--container NAME] [--since ISO] [--samples N] [--interval SEC]
# 1  container start time + restart count (a restart inside the window would reset the node)
# 2  --since ISO (default: applied_at from the pft-egress state file): every NetworkOPs heartbeat line in the
#    node's debug.log since then, bucketed per 10 min up to now, with the operating mode it reports; a heartbeat
#    line without a "mode: x." field counts as not full, an empty bucket counts as a gap
# 3  --samples N (default 1): N server_info samples, INTERVAL s apart: server_state, peers, ledger range,
#    egress DROP counter; each judged against "state full and peers >= baseline_peers" from the state file
# Exit 0 = every heartbeat in the window says full, every sample is full with peers >= baseline; 1 otherwise.
# Test hooks: PFT_EGRESS_TEST=1 (no root)  PFT_EGRESS_NOW (epoch, end of the heartbeat window)
# Public IPv4 addresses are not printed (none of the fields above contain one).
set -uo pipefail
CONTAINER=postfiatd; SINCE=""; SAMPLES=1; INTERVAL=60
STATE_DIR="${STATE_DIR:-/var/lib/pft-egress}"; CHAIN="${CHAIN:-PFT-EGRESS}"
while [ $# -gt 0 ]; do
  case "$1" in --container) CONTAINER="$2"; shift 2 ;; --since) SINCE="$2"; shift 2 ;;
               --samples) SAMPLES="$2"; shift 2 ;; --interval) INTERVAL="$2"; shift 2 ;; *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || [ -n "${PFT_EGRESS_TEST:-}" ] || { echo "run as root" >&2; exit 3; }
SF="$STATE_DIR/$CONTAINER.json"
[ -f "$SF" ] || { echo "no pft-egress state for $CONTAINER ($SF): policy not applied" >&2; exit 3; }
BASE="$(jq -r .baseline_peers "$SF")"; APPLIED="$(jq -r .applied_at "$SF")"
[ -n "$SINCE" ] || SINCE="$APPLIED"
fails=0

echo "pft-egress stability - $(date -u +%FT%TZ) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - container $CONTAINER"
echo "policy applied_at $APPLIED, dead-man passed $(jq -r '.deadman_passed_at // "n/a"' "$SF"), baseline_peers $BASE"

echo; echo "== 1. container"
read -r started restarts < <(docker inspect "$CONTAINER" --format '{{.State.StartedAt}} {{.RestartCount}}')
echo "StartedAt $started  RestartCount $restarts"
if [ "$(date -u -d "$started" +%s)" -gt "$(date -u -d "$SINCE" +%s)" ]; then
  echo "  FAIL container (re)started inside the window"; fails=$((fails + 1))
else echo "  ok   no container start since $SINCE"; fi

echo; echo "== 2. node heartbeat modes in debug.log since $SINCE (10-min buckets)"
since_s="$(date -u -d "$SINCE" +%s)"
# heartbeat line: "2026-Oct-25 05:08:29.107 UTC NetworkOPs:NFO ConsensusLogger Heartbeat Timer: ... mode: full. ..."
# gawk: mktime(..., 1) reads the debug.log timestamp as UTC whatever the host time zone is.
docker exec "$CONTAINER" grep -h -F 'Heartbeat Timer' /var/log/postfiatd/debug.log \
  | gawk -v since="$since_s" -v now="${PFT_EGRESS_NOW:-$(date -u +%s)}" '
      BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " "); for (k in M) mon[M[k]] = k }
      match($0, /^([0-9]{4})-([A-Za-z]{3})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})[^ ]* UTC /, f) {
        s = mktime(f[1] " " mon[f[2]] " " f[3] " " f[4] " " f[5] " " f[6], 1); if (s < since || s > now) next
        # "set mode to DISCONNECTED: ..." heartbeats carry no "mode: x." field: count them, never skip them
        md = match($0, / mode: ([a-z]+)\./, g) ? g[1] : "no-mode-field"
        b = int((s - since) / 600); n[b]++; mode[b, md]++; seen[md] = 1; tot++; if (md != "full") bad++
        if (!first) first = s; last = s }
      END {
        if (!tot) { print "  no heartbeat lines in the window"; exit 1 }
        # the node logs one heartbeat a second: an empty bucket up to now is a gap (node down or log lost)
        for (i = 0; i <= int((now - since) / 600); i++) {
          line = ""; for (m in seen) if ((i, m) in mode) line = line " " m "=" mode[i, m]
          if (!(i in n)) { line = " GAP"; gaps++ }
          printf "  +%3d..+%3d min  heartbeats %4d %s\n", i * 10, i * 10 + 10, n[i] + 0, line
        }
        printf "  total %d heartbeats, %d not full, %d empty buckets, first %s, last %s\n", tot, bad + 0, gaps + 0,
          strftime("%FT%TZ", first, 1), strftime("%FT%TZ", last, 1)
        exit (bad || gaps) ? 1 : 0
      }'
if [ "${PIPESTATUS[1]}" -eq 0 ]; then echo "  ok   every heartbeat since $SINCE reports mode full"
else echo "  FAIL heartbeats missing or not full"; fails=$((fails + 1)); fi

echo; echo "== 3. server_info samples ($SAMPLES x ${INTERVAL}s), pass = full and peers >= $BASE"
for i in $(seq 1 "$SAMPLES"); do
  [ "$i" -gt 1 ] && sleep "$INTERVAL"
  info="$(docker exec "$CONTAINER" curl -s --max-time 10 http://127.0.0.1:5005/ -X POST \
          -d '{"method":"server_info","params":[{}]}' | jq -c '.result.info // {}')"
  st="$(jq -r '.server_state // "down"' <<<"$info")"; pe="$(jq -r '.peers // 0' <<<"$info")"
  cl="$(jq -r '.complete_ledgers // "-"' <<<"$info")"
  drops="$(iptables -nvxL "$CHAIN" 2>/dev/null | awk '$3 == "DROP" { print $1 }')"
  if [ "$st" = full ] && [ "$pe" -ge "$BASE" ]; then v=ok; else v=FAIL; fails=$((fails + 1)); fi
  printf '  %s  %-4s state %-8s peers %3s  ledgers %s  egress DROP pkts %s\n' "$(date -u +%FT%TZ)" "$v" "$st" "$pe" "$cl" "${drops:-n/a}"
done

echo; [ "$fails" -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL ($fails)"; exit 1
