#!/usr/bin/env bash
# Live PFTLedgerDiverged drill on the VALIDATOR host (no node restart, no postfiatd config change).
#   sudo bash divergence/drill.sh [--out DIR] [--port 18559]
# 1  preflight: Prometheus/Alertmanager ready, bridge on the real env file, no PFTLedgerDiverged active, a real
#    pft-divergence check AGREE.
# 2  pft-alert-bridge -> throwaway ntfy topic (alerts/run-stack.sh up with a temp NTFY_ENV_FILE), and
#    pft-divergence.timer stopped so only the drill writes the textfile.
# 3  "wrong": drill_stub.py (loopback proxy to the public RPC) rewrites every ledger_hash; checks run every 30 s
#    with sources validator + sentry + stub. Polls until PFTLedgerDiverged is firing and "[FIRING]" is on the topic.
# 4  "fixed": the stub passes answers through; polls until the alert is gone and "[RESOLVED]" is on the topic.
# 5  restore on ANY exit (trap): bridge back to the real env file (mount source checked), timer started, stub
#    stopped, one real check. Then drill_verdict.py on the samples and the topic read-back.
# Output: DIR/samples.jsonl, DIR/ntfy.jsonl (titles only), DIR/verdict.txt. Topic printed as <redacted>.
set -euo pipefail
OUT=""; PORT=18559
while [ $# -gt 0 ]; do
  case "$1" in --out) OUT="$2"; shift 2 ;; --port) PORT="$2"; shift 2 ;; *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
PROM=http://127.0.0.1:9090
AM=http://127.0.0.1:9093
BIN=/usr/local/bin/pft-divergence
RUSER="${SUDO_USER:?run with sudo from the operator user (the bridge env file belongs to that user)}"
RUID="$(id -u "$RUSER")"; RGID="$(id -g "$RUSER")"
REAL_BRIDGE_ENV="$(getent passwd "$RUSER" | cut -d: -f6)/.config/pft-alerts/ntfy.env"
OUT="${OUT:-$HERE/drill-out-$(date -u +%Y%m%dT%H%M%SZ)}"
SAMPLES="$OUT/samples.jsonl"; NTFY="$OUT/ntfy.jsonl"
topic="divdrill-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TDIR="$(mktemp -d /run/pft-div-drill.XXXXXX)"; TBRIDGE="$TDIR/ntfy.env"; FLAG="$TDIR/wrong"
since="$(date -u +%s)"; RESTORED=0; BRIDGE_REDIR=0; TIMER_STOPPED=0; STUB_PID=""
# the drill's own sources: the two real nodes from the host config + the stub in place of the public RPC
REAL_SOURCES="$(sed -n 's/^SOURCES="\(.*\)"$/\1/p' /etc/pft-divergence/divergence.env)"
NODE_SOURCES="$(tr ' ' '\n' <<<"$REAL_SOURCES" | grep -v '^public=' | tr '\n' ' ')"
DRILL_SOURCES="${NODE_SOURCES}stub=http:http://127.0.0.1:$PORT/"
ts() { date -u +%FT%TZ; }
red() { sed -E "s/$topic/<redacted>/g; s|/home/[^ ]*|<home>|g; s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/<redacted-ip>/g"; }
bridge_src() { docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}' pft-alert-bridge 2>/dev/null; }
alert_state() { # none|pending|firing for PFTLedgerDiverged in Prometheus; "error" if the API fails
  curl -fsS --max-time 10 "$PROM/api/v1/alerts" \
    | jq -r '[.data.alerts[] | select(.labels.alertname=="PFTLedgerDiverged") | .state] | if length==0 then "none" elif index("firing") then "firing" else "pending" end' \
    2>/dev/null || echo error
}
am_active() { curl -fsS --max-time 10 "$AM/api/v2/alerts" | jq '[.[] | select(.labels.alertname=="PFTLedgerDiverged")] | length' 2>/dev/null || echo 99; }
read_topic() { curl -s --max-time 20 "https://ntfy.sh/$topic/json?poll=1&since=$since" | python3 "$HERE/drill_verdict.py" ntfy > "$NTFY" || true; }
sample() { # phase: one drill check, then Prometheus state after the next scrape
  local out st
  out="$("$BIN" --sources "$DRILL_SOURCES" --state "$TDIR/state.json" --backoff "1 2" 2>&1)" || true
  printf '%s\n' "$out" | red | sed "s/^/  [$1] /"
  sleep 20   # exporter scrape interval is 15 s
  st="$(curl -fsS --max-time 10 "$PROM/api/v1/query" --data-urlencode 'query=pft_divergence_state' \
        | jq -c '[.data.result[] | {(.metric.source): (.value[1]|tonumber)}] | add // {}' 2>/dev/null || echo '{}')"
  jq -nc --argjson t "$(date -u +%s)" --arg p "$1" --argjson s "$st" --arg a "$(alert_state)" \
    '{t:$t, phase:$p, state:$s, alert:$a}' >> "$SAMPLES"
  tail -n 1 "$SAMPLES" | jq -rc '"  \(.t|todate) phase=\(.phase) prom pft_divergence_state=\(.state|tojson) PFTLedgerDiverged=\(.alert)"'
}

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  echo; echo "== 5. restore"
  if [ -n "$STUB_PID" ]; then kill "$STUB_PID" 2>/dev/null || true; echo "  stub stopped"; fi
  if [ "$BRIDGE_REDIR" -eq 1 ]; then
    echo "  \$ NTFY_ENV_FILE=<real bridge env> alerts/run-stack.sh up"
    NTFY_ENV_FILE="$REAL_BRIDGE_ENV" DOCKER=docker bash "$ROOT/alerts/run-stack.sh" up 2>&1 | red | tail -n 4 | sed 's/^/  /' || true
    echo "  pft-alert-bridge mount source is the real env file: $([ "$(bridge_src)" = "$(readlink -f "$REAL_BRIDGE_ENV")" ] && echo yes || echo NO)"
    # Alertmanager was just recreated: if the stub alert is somehow still active (loop timed out), it must not
    # reach the real topic. Scoped to source="stub", which only the drill writes.
    if [ "$(alert_state)" != none ]; then
      sil="$(curl -fsS -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(ts)" \
        --arg e "$(date -u -d '+30 min' +%FT%TZ)" '{matchers:[{name:"alertname",value:"PFTLedgerDiverged",isRegex:false,isEqual:true},
        {name:"source",value:"stub",isRegex:false,isEqual:true}], startsAt:$s, endsAt:$e, createdBy:"divergence drill.sh",
        comment:"drill tail: stub series goes stale"}')" | jq -r '.silenceID // empty')" || true
      echo "  PFTLedgerDiverged still active -> silence ${sil:0:8} source=stub for 30m"
    fi
  fi
  if [ "$TIMER_STOPPED" -eq 1 ]; then
    systemctl start pft-divergence.service pft-divergence.timer || true
    echo "  pft-divergence.timer: $(systemctl is-active pft-divergence.timer); one real check:"
    "$BIN" 2>&1 | red | sed 's/^/  /' || true
  fi
  rm -rf "$TDIR"
}
trap restore EXIT

mkdir -p "$OUT"; chown "$RUID:$RGID" "$OUT"
echo "pft-divergence alert drill (validator) - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "sha256: drill.sh $(sha256sum "$HERE/drill.sh" | cut -c1-12) | drill_stub.py $(sha256sum "$HERE/drill_stub.py" | cut -c1-12) | drill_verdict.py $(sha256sum "$HERE/drill_verdict.py" | cut -c1-12) | pft-divergence $(sha256sum "$BIN" | cut -c1-12) | divergence.rules.yml $(sha256sum "$ROOT/alerts/divergence.rules.yml" | cut -c1-12)"

echo; echo "== 1. preflight"
if ! curl -fsS --max-time 5 -o /dev/null "$PROM/-/ready" || ! curl -fsS --max-time 5 -o /dev/null "$AM/-/ready"; then
  echo "  Prometheus/Alertmanager not ready - stopping"; exit 3
fi
[ "$(bridge_src)" = "$(readlink -f "$REAL_BRIDGE_ENV")" ] || { echo "  bridge not on the real env file now - stopping"; exit 3; }
if [ "$(alert_state)" != none ] || [ "$(am_active)" -ne 0 ]; then echo "  PFTLedgerDiverged already active - stopping"; exit 4; fi
echo "  Prometheus alerts now: $(curl -fsS "$PROM/api/v1/alerts" | jq -c '[.data.alerts[].labels.alertname]')"
"$BIN" 2>&1 | red | sed 's/^/  real check: /'
echo "  drill sources: $DRILL_SOURCES"
"$BIN" --sources "$DRILL_SOURCES" --check-config >/dev/null

echo; echo "== 2. bridge -> throwaway topic, timer stopped, stub started"
( umask 077; printf 'NTFY_URL=https://ntfy.sh/%s\n' "$topic" > "$TBRIDGE" ); chown "$RUID:$RGID" "$TBRIDGE"; chmod 755 "$TDIR"
BRIDGE_REDIR=1
NTFY_ENV_FILE="$TBRIDGE" DOCKER=docker bash "$ROOT/alerts/run-stack.sh" up 2>&1 | red | tail -n 4 | sed 's/^/  /'
[ "$(bridge_src)" = "$TBRIDGE" ] || { echo "  bridge not on the throwaway file - stopping"; exit 1; }
echo "  pft-alert-bridge -> https://ntfy.sh/<redacted> (throwaway; mount source checked)"
systemctl stop pft-divergence.timer; TIMER_STOPPED=1
echo "  pft-divergence.timer: $(systemctl is-active pft-divergence.timer || true)"
python3 -I "$HERE/drill_stub.py" --port "$PORT" --flag "$FLAG" & STUB_PID=$!
sleep 2; kill -0 "$STUB_PID" || { echo "  stub did not start"; exit 1; }
echo "  stub on 127.0.0.1:$PORT (pid $STUB_PID), passthrough"

echo; echo "== 3. wrong: the stub rewrites ledger_hash ($(ts))"
touch "$FLAG"
end=$(( $(date +%s) + 600 ))
while [ "$(date +%s)" -lt "$end" ]; do
  sample wrong
  read_topic
  if [ "$(tail -n 1 "$SAMPLES" | jq -r .alert)" = firing ] && grep -q '"\[FIRING\] PFTLedgerDiverged"' "$NTFY"; then
    echo "  $(ts) PFTLedgerDiverged firing and [FIRING] seen on the topic"; break
  fi
done

echo; echo "== 4. fixed: the stub passes answers through ($(ts))"
rm -f "$FLAG"
end=$(( $(date +%s) + 600 ))
while [ "$(date +%s)" -lt "$end" ]; do
  sample fixed
  read_topic
  if [ "$(tail -n 1 "$SAMPLES" | jq -r .alert)" = none ] && [ "$(am_active)" -eq 0 ] \
     && grep -q '"\[RESOLVED\] PFTLedgerDiverged"' "$NTFY"; then
    echo "  $(ts) alert gone from Prometheus + Alertmanager and [RESOLVED] seen on the topic"; break
  fi
done

restore
read_topic
echo; echo "== 6. throwaway topic read back (titles only)"
jq -rc '"  \(.time|todate) \(.title)"' "$NTFY"
chown "$RUID:$RGID" "$SAMPLES" "$NTFY"
echo "\$ python3 divergence/drill_verdict.py samples.jsonl ntfy.jsonl"
set +e; python3 "$HERE/drill_verdict.py" "$SAMPLES" "$NTFY" | tee "$OUT/verdict.txt"; rc=${PIPESTATUS[0]}; set -e
echo "drill done $(ts): verdict exit $rc"
exit "$rc"
