#!/usr/bin/env bash
# shellcheck disable=SC2029,SC1091,SC2016  # remote commands are built here on purpose; os-release is read at run time
# Peer-outage catch-up drill for pft-logship. Run on the validator (sender); the sentry (`ssh relay`) is the receiver.
#   0. Alertmanager silence for PFTLogshipBroken (this drill makes it fire; the operator's phone must stay quiet)
#   1. sentry: stop systemd-journal-remote.socket + .service (only the receiver; postfiatd is never touched)
#   2. validator: pft-logship check must FAIL; then one marker per minute for OUTAGE_MIN minutes
#      (logger -t pft-logship-outage-drill "outage <id> <n>"), sampling the send lag and the alert state
#   3. sentry: start the socket again; journal-upload (Restart=always) resumes from its saved cursor
#   4. wait until the sentry holds every marker: each of 1..N exactly once (no gap, no duplicate); catch-up time
#   5. validator: pft-logship check PASS; PFTLogshipBroken back to inactive; ntfy bridge sent nothing; expire silence
# Usage: bash logship/drill-outage.sh [OUTAGE_MIN=10]      Exit: 0 PASS, 1 FAIL
set -uo pipefail
N="${1:-10}"
TAG=pft-logship-outage-drill
ID="outage-$(date -u +%Y%m%dT%H%M%S)-$$"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0; sil=""
step() { printf '%s %s\n' "$(date -u +%T)" "$*"; }
check() { if [ "$2" = "$3" ]; then step "  PASS $1: $2"; else step "  FAIL $1: got '$2', want '$3'"; rc=1; fi; }
# markers_ok N < "outage <id> <n>" lines: "ok" if each of 1..N appears exactly once, else what is wrong
markers_ok() {
  awk -v n="$1" '{c[$3]++} END{bad=""; for(i=1;i<=n;i++){ if(c[i]!=1) bad=bad " " i "x" (c[i]+0) }
    for(k in c) if(k+0<1 || k+0>n+0) bad=bad " extra:" k; print (bad=="" ? "ok" : "bad" bad)}'
}
peer_markers() { ssh relay "sudo journalctl --directory=/var/log/journal/remote -t $TAG -o cat --no-pager" | grep "^outage $ID "; }
alert_state() { curl -s "$PROM/api/v1/rules" | jq -r '[.data.groups[].rules[] | select(.name=="PFTLogshipBroken") | .state][0] // "missing"'; }
send_lag() { sudo bash "$HERE/pft-logship.sh" lag 2>&1 | sed -nE 's/^lag: ([0-9]+)s.*/\1/p'; }
restore() { # always bring the receiver back, even on interrupt
  ssh relay 'sudo systemctl start systemd-journal-remote.socket' && step "sentry: systemd-journal-remote.socket started"
}
trap 'restore; exit 1' INT TERM
echo "pft-logship peer-outage drill - $(date -u +%FT%TZ) - sender validator-host, receiver sentry-host - $N min - id $ID"
echo "sender OS: $(. /etc/os-release; echo "$PRETTY_NAME") | receiver OS: $(ssh relay '. /etc/os-release; echo "$PRETTY_NAME"')"
# self-test of the marker checker on synthetic input (positive + negatives) before it judges the live run
t1="$(printf 'outage x %s\n' 1 2 3 | markers_ok 3)"; t2="$(printf 'outage x %s\n' 1 3 3 | markers_ok 3)"
t3="$(printf 'outage x %s\n' 1 2 3 4 | markers_ok 3)"
# two-digit N: keys must compare as numbers ("2" > "10" as strings: drill run 1 read 2..9 as extra)
t4="$(seq 1 10 | sed 's/^/outage x /' | markers_ok 10)"; t5="$(seq 1 11 | sed 's/^/outage x /' | markers_ok 10)"
check "checker self-test (1 2 3 | 1 3 3 | 1 2 3 4 | 1..10 | 1..11)" "$t1|$t2|$t3|$t4|$t5" "ok|bad 2x0 3x2|bad extra:4|ok|bad extra:11"
step "0. Alertmanager silence alertname=PFTLogshipBroken for $((N + 35)) min"
sil="$(curl -s -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(date -u +%FT%TZ)" \
  --arg e "$(date -u -d "+$((N + 35)) min" +%FT%TZ)" '{matchers:[{name:"alertname",value:"PFTLogshipBroken",isRegex:false}],
  startsAt:$s, endsAt:$e, createdBy:"pft-logship drill", comment:"task_5ad83103 peer-outage drill"}')" | jq -r '.silenceID // empty')"
[ -n "$sil" ] || { step "  FAIL could not create the silence: not stopping anything"; echo "RESULT: FAIL -> exit 1"; exit 1; }
step "  silence $sil"
step "1. sentry: systemctl stop systemd-journal-remote.socket systemd-journal-remote.service"
ssh relay 'sudo systemctl stop systemd-journal-remote.socket systemd-journal-remote.service; systemctl is-active systemd-journal-remote.socket' \
  | sed 's/^/  socket now: /'
t_stop=$(date +%s)
out="$(sudo bash "$HERE/pft-logship.sh" check 2>&1)"; c=$?
grep -E '^(tls|send|RESULT):' <<<"$out" | sed 's/^/  /'
check "check exit during the outage" "$c" 1
step "2. one marker per minute for $N min (lag / PFTLogshipBroken state sampled after each)"
for i in $(seq 1 "$N"); do
  logger -t "$TAG" "outage $ID $i"
  step "  marker $i written; send lag $(send_lag)s; PFTLogshipBroken $(alert_state)"
  [ "$i" -lt "$N" ] && sleep 60
done
fired="$(alert_state)"
step "  alert state at the end of the outage: $fired"
step "  received by the sentry so far: $(peer_markers | wc -l) of $N"
step "3. sentry: systemctl start systemd-journal-remote.socket (outage $(( $(date +%s) - t_stop )) s)"
trap - INT TERM; restore; t_start=$(date +%s)
res=""; for _ in $(seq 1 60); do res="$(peer_markers | markers_ok "$N")"; [ "$res" = ok ] && break; sleep 5; done
step "4. catch-up: all markers on the sentry after $(( $(date +%s) - t_start )) s"
check "markers 1..$N on the sentry, each exactly once" "$res" ok
peer_markers | sed 's/^/  sentry has: /'
step "5. after recovery"
sleep 70   # one pft-logship-check.timer run, so the metrics and the rule see the recovery
out="$(sudo bash "$HERE/pft-logship.sh" check 2>&1)"; c=$?
grep -E '^(tls|send|receive|RESULT):' <<<"$out" | sed 's/^/  /'
check "check exit after catch-up" "$c" 0
st=""; for _ in $(seq 1 12); do st="$(alert_state)"; [ "$st" = inactive ] && break; sleep 10; done
check "PFTLogshipBroken after recovery" "$st" inactive
case "$fired" in firing|pending) step "  PASS the rule saw the outage (state at end of outage: $fired)" ;;
  *) step "  FAIL the rule did not react to a $N-min outage (state $fired)"; rc=1 ;; esac
sent="$(sudo docker logs --since "$(( $(date +%s) - t_stop + 60 ))s" pft-alert-bridge 2>&1 | grep -c PFTLogshipBroken)"
check "ntfy bridge lines mentioning PFTLogshipBroken during the drill (silenced)" "$sent" 0
am="$(curl -s "$AM/api/v2/alerts?filter=alertname%3D%22PFTLogshipBroken%22" | jq -r '[.[] | select(.status.state != "unprocessed")] | length')"
if [ "$st" = inactive ] && [ "$am" = 0 ]; then
  curl -s -o /dev/null -w '%{http_code}' -X DELETE "$AM/api/v2/silence/$sil" | sed 's/^/  silence expired (Alertmanager holds 0 PFTLogshipBroken alerts): HTTP /'; echo
else step "  silence $sil kept until its end time (rule $st, Alertmanager holds $am PFTLogshipBroken alerts)"; fi
echo "RESULT: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL) -> exit $rc"
exit "$rc"
