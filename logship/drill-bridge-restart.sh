#!/usr/bin/env bash
# shellcheck disable=SC2024  # output files are owned by the calling user; only docker/journalctl/systemctl need root
# shellcheck disable=SC1091  # os-release is read at run time
# Live resume drill for the INSTALLED docker-log bridge pft-logship-dockerlog@<container> (validator-host).
#   0. Alertmanager silence for PFTLogshipBroken (a stopped bridge makes the check fail; the operator's phone stays quiet)
#   1. systemctl stop the bridge; record its saved state (last docker timestamp ns + same-timestamp count)
#   2. postfiatd keeps logging for STOP_S seconds while nothing copies it to the journal
#   3. systemctl start the bridge; wait until its saved state is past the restart time (resume = `docker logs --since`)
#   4. journal (-t <container>) vs `docker logs` for one span that starts STOP_S s before the stop and ends after the
#      catch-up: the two must be the same lines in the same order -> 0 missed, 0 repeated. Lines that postfiatd wrote
#      while the bridge was stopped are counted from docker's own timestamps and must all be in the journal.
#   5. expire the silence once PFTLogshipBroken is back to inactive
# The node is never touched. Usage: bash logship/drill-bridge-restart.sh [CONTAINER=postfiatd] [STOP_S=60]  Exit 0 PASS
set -uo pipefail
C="${1:-postfiatd}"; STOP_S="${2:-60}"
U="pft-logship-dockerlog@$C.service"; SF="/var/lib/pft-logship/dockerlog/$C.state"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
T="$(mktemp -d)"; rc=0; sil=""
step() { printf '%s %s\n' "$(date -u +%T)" "$*"; }
check() { if [ "$2" = "$3" ]; then step "  PASS $1: $2"; else step "  FAIL $1: got '$2', want '$3'"; rc=1; fi; }
alert_state() { curl -s "$PROM/api/v1/rules" | jq -r '[.data.groups[].rules[] | select(.name=="PFTLogshipBroken") | .state][0] // "missing"'; }
# compare JOURNAL REF -> "journal=<n> docker_span=<n> missed=<n> repeated=<n> order=<same|differs>"
# docker_span = REF lines from JOURNAL's first line to its last line; missed/repeated counted per exact line (multiset)
compare() {
  local first last
  first="$(head -n 1 "$1")"; last="$(tail -n 1 "$1")"
  awk -v a="$first" -v b="$last" '!on && $0==a{on=1} on{print} on && $0==b{exit}' "$2" > "$T/span"
  local missed repeated
  missed="$(comm -13 <(sort "$1") <(sort "$T/span") | wc -l)"
  repeated="$(comm -23 <(sort "$1") <(sort "$T/span") | wc -l)"
  printf 'journal=%s docker_span=%s missed=%s repeated=%s order=%s\n' "$(wc -l < "$1")" "$(wc -l < "$T/span")" \
    "$missed" "$repeated" "$(cmp -s "$1" "$T/span" && echo same || echo differs)"
}
restore() { sudo systemctl start "$U"; step "restore: $U $(systemctl is-active "$U")"; }
trap 'restore; rm -rf "$T"; exit 1' INT TERM
echo "pft-logship bridge restart drill - $(date -u +%FT%TZ) - validator-host - unit $U - stopped ${STOP_S}s"
echo "OS: $(. /etc/os-release; echo "$PRETTY_NAME") | docker $(sudo docker version -f '{{.Server.Version}}')"
echo "installed bridge sha256 $(sudo sha256sum < /usr/local/sbin/pft-logship-dockerlog | cut -c1-16) | repo logship/pft-logship-dockerlog.py sha256 $(sha256sum < "$(dirname "$0")/pft-logship-dockerlog.py" | cut -c1-16)"
# self-test of compare() on synthetic data before it judges the live run: exact, one repeat, one missing, swapped
printf 'x\na\nb\nc\nd\ny\n' > "$T/r"
printf 'a\nb\nc\nd\n' > "$T/j1"; printf 'a\nb\nb\nc\nd\n' > "$T/j2"; printf 'a\nc\nd\n' > "$T/j3"; printf 'a\nc\nb\nd\n' > "$T/j4"
st="$(for j in j1 j2 j3 j4; do compare "$T/$j" "$T/r" | sed -E 's/journal=[0-9]+ docker_span=[0-9]+ //'; done | paste -sd'|')"
check "compare self-test (exact|repeat|missing|swapped)" "$st" \
  "missed=0 repeated=0 order=same|missed=0 repeated=1 order=differs|missed=1 repeated=0 order=differs|missed=0 repeated=0 order=differs"
check "bridge unit active before the drill" "$(systemctl is-active "$U")" active
step "0. Alertmanager silence alertname=PFTLogshipBroken for 20 min"
sil="$(curl -s -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(date -u +%FT%TZ)" \
  --arg e "$(date -u -d '+20 min' +%FT%TZ)" '{matchers:[{name:"alertname",value:"PFTLogshipBroken",isRegex:false}],
  startsAt:$s, endsAt:$e, createdBy:"pft-logship drill", comment:"task_5ad83103 bridge restart drill"}')" | jq -r '.silenceID // empty')"
[ -n "$sil" ] || { step "  FAIL could not create the silence: not stopping anything"; echo "RESULT: FAIL -> exit 1"; exit 1; }
step "  silence $sil"
t_span_s="$(date +%s)"; t_span="$(date -u -d "@$t_span_s" +%FT%TZ)"
step "   (comparison span starts at journal time $t_span; ${STOP_S}s of normal bridging first)"
sleep "$STOP_S"
step "1. systemctl stop $U"
sudo systemctl stop "$U"
check "bridge unit after stop" "$(systemctl is-active "$U")" inactive
read -r s_ns s_n < <(sudo cat "$SF"); step "  saved state at stop: ns=$s_ns ($(date -u -d "@${s_ns:0:10}" +%T).${s_ns:10}) same-timestamp count=$s_n"
step "2. bridge stopped; postfiatd keeps logging for ${STOP_S}s"
sleep "$STOP_S"
step "3. systemctl start $U"
t_start_ns="$(date +%s%N)"; sudo systemctl start "$U"
check "bridge unit after start" "$(systemctl is-active "$U")" active
caught=no
for _ in $(seq 1 60); do
  read -r n_ns _ < <(sudo cat "$SF")
  if [ "$n_ns" -gt $((t_start_ns + 10000000000)) ]; then caught=yes; break; fi
  sleep 2
done
step "  saved state now: ns=$n_ns ($(date -u -d "@${n_ns:0:10}" +%T)); past restart time + 10 s: $caught"
check "bridge caught up after restart" "$caught" yes
sleep 3
step "4. journal vs docker logs"
# journalctl 249 rejects RFC3339 "...Z" ("Failed to parse timestamp", drill run 1): pass epoch seconds
sudo journalctl -t "$C" --since "@$t_span_s" -o cat --no-pager > "$T/jall" || { step "  FAIL journalctl"; rc=1; }
grep '^pft-logship-dockerlog: ' "$T/jall" | sed 's/^/  bridge stderr (journal): /'
# span ends = first/last line carrying postfiatd's own timestamp (unique); blank lines can't anchor a span
grep -v '^pft-logship-dockerlog: ' "$T/jall" > "$T/jraw"
awk 'NR==FNR{ if (/ UTC /) { if (!f) f=FNR; l=FNR }; next } FNR>=f && FNR<=l' "$T/jraw" "$T/jraw" > "$T/j"
sudo docker logs --timestamps --since "$(date -u -d "@$((t_span_s - 60))" +%FT%TZ)" "$C" > "$T/refts" 2>&1
# journald's stdout transport drops trailing whitespace from every line (drill run 2: 187 heartbeat lines end in a
# space, so a byte-exact compare showed them as 187 missed + 187 repeated). Strip it on docker's side too.
step "  docker lines ending in whitespace (journald stores them without it): $(grep -c '[[:space:]]$' "$T/refts")"
cut -d' ' -f2- "$T/refts" | sed 's/[[:space:]]*$//' > "$T/ref"
# lines postfiatd wrote while the bridge was stopped (docker's timestamps, between the saved state and the start).
# ns values have 19 digits (> 2^53, a double would round them): compared as equal-length digit strings
awk -v a="$s_ns" -v b="$t_start_ns" '{ s=$1; sub(/Z$/,"",s); split(s,p,"."); gsub(/[-T:]/," ",p[1]);
  ns=mktime(p[1], 1) substr(p[2] "000000000",1,9); if (ns "" > a "" && ns "" < b "") print }' "$T/refts" | cut -d' ' -f2- | sed 's/[[:space:]]*$//' > "$T/gap"
ingap="$(grep -cFxf "$T/gap" "$T/j")"
step "  lines postfiatd wrote while the bridge was down (docker timestamps): $(wc -l < "$T/gap"); found in journal: $ingap"
check "every line written during the stop is in the journal" "$ingap" "$(wc -l < "$T/gap")"
[ "$(wc -l < "$T/gap")" -gt 0 ] || { step "  FAIL no lines were written during the stop: the drill proves nothing"; rc=1; }
res="$(compare "$T/j" "$T/ref")"; step "  $res"
# an empty journal side compares "equal" to an empty span (drill run 1): require real lines on both sides
read -r nj nd < <(sed -E 's/journal=([0-9]+) docker_span=([0-9]+) .*/\1 \2/' <<<"$res")
check "journal span > STOP_S lines and same length as docker span" "$([ "$nj" -gt "$STOP_S" ] && [ "$nj" = "$nd" ] && echo yes || echo no)" yes
check "journal == docker span (missed, repeated, order)" "$(sed -E 's/journal=[0-9]+ docker_span=[0-9]+ //' <<<"$res")" "missed=0 repeated=0 order=same"
step "  same-ns docker timestamps in the span: $(cut -d' ' -f1 "$T/refts" | sort | uniq -d | wc -l) (the count>1 resume case is covered by tests/test-dockerlog.sh)"
step "5. PFTLogshipBroken state: $(alert_state); waiting for inactive (max 5 min)"
for _ in $(seq 1 30); do [ "$(alert_state)" = inactive ] && break; sleep 10; done
check "PFTLogshipBroken after the drill" "$(alert_state)" inactive
curl -s -o /dev/null -w '%{http_code}' -X DELETE "$AM/api/v2/silence/$sil" | sed "s/^/$(date -u +%T)   silence $sil expired: HTTP /"; echo
check "Alertmanager active alerts" "$(curl -s "$AM/api/v2/alerts?active=true&silenced=true" | jq length)" 0
rm -rf "$T"
if [ "$rc" = 0 ]; then echo "RESULT: PASS -> exit 0"; else echo "RESULT: FAIL -> exit 1"; fi
exit "$rc"
