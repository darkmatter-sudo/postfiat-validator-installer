#!/usr/bin/env bash
# Live SLO drill on the VALIDATOR host. Stops postfiatd twice, with every notifier pointed at one throwaway topic:
#   sudo bash slo/drill.sh [--container NAME] [--stop-min 7] [--out DIR]
#   B  planned stop inside `pft-maint start`: pft:sli_maint 1, pft:sli_bad 0, no PFTSLO* alert, no PFTSLO* message
#   A  unplanned stop, no window: pft:sli_bad 1, PFTSLOFastBurn pending -> firing -> "[FIRING]" on the topic,
#      node back to full, FastBurn resolved
# A 7 min stop is about 8 bad minutes with the restart: above FastBurn (14.4x over 1h AND 5m = 4.3 min/h, for 2m) and
# below SlowBurn (6x over 6h = 10.8 min/6h), so PFTSLOSlowBurn should not fire. The checker reports it either way.
# 1  redirect: /etc/postfiat-monitor.env and /etc/pft-integrity.env (NTFY_* lines), /etc/pft-maint/ntfy.env (drill
#    only), sentry /etc/pft-watchdog/ntfy.env (`ssh relay`) and the pft-alert-bridge (alerts/run-stack.sh up with a
#    throwaway NTFY_ENV_FILE) all point at the topic. Then an Alertmanager silence for every NON-SLO alert (90 min).
#    run-stack.sh recreates Alertmanager, so the silence is created after it. Everything is restored on ANY exit
#    (trap), files compared by sha256, the bridge's mount source compared with the real env file.
# 2  B, then 2 min of normal samples, then A. drill_check.py samples Prometheus every 15 s (read-only).
# 3  before the bridge goes back to the real topic: no PFTSLO* alert pending/firing in Prometheus or Alertmanager,
#    and the "[RESOLVED] PFTSLOFastBurn" message seen on the topic (or 3 min after Alertmanager dropped it).
# 4  restore, expire the silence if no non-SLO alert is active, read the topic back, run drill_check.py.
# Refuses to start while a pft-maint data-collection lock or window is active, or the node is not full.
# Output: DIR/samples.jsonl, DIR/ntfy.jsonl (titles only), DIR/check.txt. Topic printed as <redacted>.
set -euo pipefail
CONTAINER=postfiatd; STOP_MIN=7; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in --container) CONTAINER="$2"; shift 2 ;; --stop-min) STOP_MIN="$2"; shift 2 ;; --out) OUT="$2"; shift 2 ;;
               *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
if ! [[ "$STOP_MIN" =~ ^[0-9]+$ ]] || [ "$STOP_MIN" -lt 5 ] || [ "$STOP_MIN" -gt 9 ]; then echo "--stop-min 5..9" >&2; exit 3; fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
CHECK="$HERE/drill_check.py"
PROM=http://127.0.0.1:9090
AM=http://127.0.0.1:9093
ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
MENV=/etc/pft-maint/ntfy.env
WENV=/etc/pft-watchdog/ntfy.env
RUSER="${SUDO_USER:?run with sudo from the operator user (the bridge env file belongs to that user)}"
RUID="$(id -u "$RUSER")"; RGID="$(id -g "$RUSER")"
REAL_BRIDGE_ENV="$(getent passwd "$RUSER" | cut -d: -f6)/.config/pft-alerts/ntfy.env"
OUT="${OUT:-$HERE/drill-out-$(date -u +%Y%m%dT%H%M%SZ)}"
SAMPLES="$OUT/samples.jsonl"; NTFY="$OUT/ntfy.jsonl"
R() { sudo -u "$RUSER" ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes relay "$@"; }
topic="slodrill-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TDIR="$(mktemp -d /run/slo-drill.XXXXXX)"; TBRIDGE="$TDIR/ntfy.env"
since="$(date -u +%s)"; WINDOW=0; RESTORED=0; SIL=""; WREDIR=0; MENV_CREATED=0; BRIDGE_REDIR=0
ts() { date -u +%FT%TZ; }
shafile() { echo "$TDIR/$(basename "$1").sha"; }
red() { sed -E "s/by [a-z_][a-z0-9_-]*/by <user>/g; s/$topic/<redacted>/g"; }
node_state() {
  docker exec "$CONTAINER" curl -s -m 5 -X POST -H 'Content-Type: application/json' \
    -d '{"method":"server_info","params":[{}]}' http://127.0.0.1:5005/ 2>/dev/null \
    | jq -r '.result.info.server_state // "unreachable"' 2>/dev/null || echo unreachable
}
poll() { # poll PHASE SECONDS [until-full]: one sample every 15 s; with until-full stop early once the node is full
  local phase="$1" end=$(( $(date +%s) + $2 )) st
  while [ "$(date +%s)" -lt "$end" ]; do
    st="$(node_state)"
    python3 "$CHECK" sample "$PROM" "$phase" "$st" >> "$SAMPLES"
    tail -n 1 "$SAMPLES" | jq -rc '"  \(.t|todate) \(.phase) node=\(.node) maint=\(.maint) bad=\(.bad) r5m=\(.r5m) r1h=\(.r1h) alerts=\(.alerts // .error)"'
    [ "${3:-}" = until-full ] && [ "$st" = full ] && return 0
    sleep 15
  done
  [ "${3:-}" != until-full ]
}
slo_active() { # count of PFTSLO* pending/firing in Prometheus or active in Alertmanager; 99 if either API fails
  local p a
  p="$(curl -fsS --max-time 10 "$PROM/api/v1/alerts" | jq -r '.data.alerts[].labels.alertname')" || { echo 99; return; }
  a="$(curl -fsS --max-time 10 "$AM/api/v2/alerts" | jq -r '.[].labels.alertname')" || { echo 99; return; }
  printf '%s\n%s\n' "$p" "$a" | grep -c '^PFTSLO' || true
}
bridge_src() { docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}' pft-alert-bridge 2>/dev/null; }
read_topic() {
  curl -s --max-time 20 "https://ntfy.sh/$topic/json?poll=1&since=$since" | python3 "$CHECK" ntfy > "$NTFY" || true
}

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != true ]; then
    echo "trap: starting $CONTAINER"; docker start "$CONTAINER" >/dev/null || true
  fi
  if [ "$WINDOW" -eq 1 ]; then pft-maint end --reason "slo drill finished (trap)" 2>&1 | red || true; fi
  if [ "$BRIDGE_REDIR" -eq 1 ]; then
    echo "\$ NTFY_ENV_FILE=<real bridge env> alerts/run-stack.sh up"
    NTFY_ENV_FILE="$REAL_BRIDGE_ENV" DOCKER=docker bash "$ROOT/alerts/run-stack.sh" up 2>&1 | sed -E 's|/home/[^ ]*|<home>|g' | tail -n 6 || true
    echo "restored pft-alert-bridge: mount source is the real env file: $([ "$(bridge_src)" = "$(readlink -f "$REAL_BRIDGE_ENV")" ] && echo yes || echo NO)"
  fi
  local f
  for f in $ENVS; do
    [ -f "$f.pre-slo-drill" ] || continue
    mv -f "$f.pre-slo-drill" "$f"
    echo "restored $f: sha256 matches pre-drill copy: $([ "$(sha256sum < "$f")" = "$(cat "$(shafile "$f")")" ] && echo yes || echo NO) ($(stat -c '%U %a' "$f"))"
  done
  if [ "$MENV_CREATED" -eq 1 ]; then rm -f "$MENV"; echo "removed drill-only $MENV: $([ -e "$MENV" ] && echo NO || echo yes)"; fi
  if [ "$WREDIR" -eq 1 ]; then
    R "sudo mv -f $WENV.pre-slo-drill $WENV" || true
    echo "restored sentry $WENV: sha256 matches pre-drill copy: $([ "$(R "sudo sha256sum < $WENV")" = "$WSHA" ] && echo yes || echo NO)"
  fi
  rm -rf "$TDIR"
}
trap restore EXIT

mkdir -p "$OUT"; chown "$RUID:$RGID" "$OUT"
echo "pft SLO drill (validator) - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - container $CONTAINER, stop ${STOP_MIN}m x2"
echo "script sha256: drill.sh $(sha256sum "$HERE/drill.sh" | cut -c1-64) | drill_check.py $(sha256sum "$CHECK" | cut -c1-64) | slo.rules.yml $(sha256sum "$HERE/slo.rules.yml" | cut -c1-64)"

echo; echo "== 0. preflight"
MS="$(pft-maint status --json)"; echo "  pft-maint: window=$(jq -r .window <<<"$MS") locks=$(jq -r '.locks|length' <<<"$MS")"
[ "$(jq -r '.locks|length' <<<"$MS")" -eq 0 ] || { echo "  data-collection lock held - no node stops:"; jq -r '.locks[]' <<<"$MS" | sed 's/^/    /'; exit 4; }
[ "$(jq -r .window <<<"$MS")" = none ] || { echo "  a maintenance window is open - stopping"; exit 4; }
[ "$(node_state)" = full ] || { echo "  node not full - stopping"; exit 4; }
[ -e "$MENV" ] && { echo "  $MENV already exists - refusing to overwrite it" >&2; exit 3; }
[ -f "$REAL_BRIDGE_ENV" ] || { echo "  real bridge env file missing - stopping" >&2; exit 3; }
[ "$(bridge_src)" = "$(readlink -f "$REAL_BRIDGE_ENV")" ] || { echo "  pft-alert-bridge is not using the real env file now - stopping" >&2; exit 3; }
R "sudo test -f $WENV" || { echo "  sentry $WENV missing or relay unreachable - stopping" >&2; exit 3; }
if ! curl -fsS --max-time 5 -o /dev/null "$AM/-/ready" || ! curl -fsS --max-time 5 -o /dev/null "$PROM/-/ready"; then
  echo "  Prometheus/Alertmanager not ready - stopping" >&2; exit 3
fi
[ "$(slo_active)" -eq 0 ] || { echo "  a PFTSLO* alert is already active - stopping"; exit 4; }
echo "  r1h=$(curl -fsS "$PROM/api/v1/query?query=pft:sli_error:ratio_rate1h" | jq -r '.data.result[0].value[1]') r6h=$(curl -fsS "$PROM/api/v1/query?query=pft:sli_error:ratio_rate6h" | jq -r '.data.result[0].value[1]')"
echo "  notifier timers: $(systemctl list-timers --all --no-legend 2>/dev/null | grep -oE '(pft|postfiat)[a-z-]*\.timer' | sort -u | tr '\n' ' ')"
echo "  containers: $(docker ps --format '{{.Names}}' | tr '\n' ' ')"

echo; echo "== 1. every notifier -> throwaway topic, Alertmanager silence for non-SLO alerts"
for f in $ENVS; do
  [ -f "$f" ] || { echo "  $f: absent"; continue; }
  sf="$(shafile "$f")"; sha256sum < "$f" > "$sf"; cp -p "$f" "$f.pre-slo-drill"
  { grep -vE '^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=' "$f.pre-slo-drill" || true
    printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic"; } > "$f.new"
  chmod 600 "$f.new"; mv -f "$f.new" "$f"
  echo "  $f -> https://ntfy.sh/<redacted> (throwaway)"
done
MENV_CREATED=1; ( umask 077; printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic" > "$MENV" )
echo "  $MENV created for the drill only -> throwaway"
WSHA="$(R "sudo sha256sum < $WENV")"
R "sudo cp -p $WENV $WENV.pre-slo-drill && sudo sh -c 'umask 077; printf \"NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n\" $topic > $WENV'"
WREDIR=1; echo "  sentry $WENV -> throwaway"
( umask 077; printf 'NTFY_URL=https://ntfy.sh/%s\n' "$topic" > "$TBRIDGE" ); chown "$RUID:$RGID" "$TBRIDGE"; chmod 755 "$TDIR"
BRIDGE_REDIR=1
NTFY_ENV_FILE="$TBRIDGE" DOCKER=docker bash "$ROOT/alerts/run-stack.sh" up 2>&1 | red | sed -E 's|/home/[^ ]*|<home>|g' | tail -n 6
[ "$(bridge_src)" = "$TBRIDGE" ] || { echo "  bridge not on the throwaway file - stopping"; exit 1; }
echo "  pft-alert-bridge -> throwaway (mount source checked)"
SIL="$(curl -fsS -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(ts)" \
  --arg e "$(date -u -d '+90 min' +%FT%TZ)" '{matchers:[{name:"alertname",value:"PFTSLO.*",isRegex:true,isEqual:false}],
  startsAt:$s, endsAt:$e, createdBy:"slo drill.sh", comment:"planned: SLO drill node stops (non-SLO alerts only)"}')" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  Alertmanager silence ${SIL:0:8} alertname!~PFTSLO.* for 90m"

echo; echo "== 2. drill B: planned stop inside a maintenance window"
echo "\$ pft-maint start --ttl 25m --reason \"[DRILL] slo planned stop\""
pft-maint start --ttl 25m --reason "[DRILL] slo planned stop" 2>&1 | red; WINDOW=1
poll B 30
echo "$(ts) \$ docker stop $CONTAINER"; docker stop "$CONTAINER" >/dev/null
poll B $((STOP_MIN * 60))
echo "$(ts) \$ docker start $CONTAINER"; docker start "$CONTAINER" >/dev/null
poll B 900 until-full || { echo "node not full 15 min after drill B start - stopping"; exit 1; }
poll B 120
echo "\$ pft-maint end"; pft-maint end --reason "[DRILL] slo planned stop done" 2>&1 | red; WINDOW=0
poll gap 120

echo; echo "== 3. drill A: unplanned stop, no window"
echo "$(ts) \$ docker stop $CONTAINER"; docker stop "$CONTAINER" >/dev/null
poll A-down $((STOP_MIN * 60))
echo "$(ts) \$ docker start $CONTAINER"; docker start "$CONTAINER" >/dev/null
poll A-recover 900 until-full || { echo "node not full 15 min after drill A start - stopping"; exit 1; }
end=$(( $(date +%s) + 1500 ))
while [ "$(date +%s)" -lt "$end" ] && [ "$(slo_active)" -ne 0 ]; do poll A-resolve 15; done
poll A-resolve 15
echo "$(ts) PFTSLO* active after A: $(slo_active)"

echo; echo "== 4. wait for the resolved webhook before the bridge goes back to the real topic"
end=$(( $(date +%s) + 180 ))
until [ "$(date +%s)" -ge "$end" ]; do
  read_topic
  grep -q '"\[RESOLVED\] PFTSLOFastBurn"' "$NTFY" && { echo "  $(ts) [RESOLVED] PFTSLOFastBurn seen on the topic"; break; }
  sleep 20
done
[ "$(slo_active)" -eq 0 ] || { echo "  PFTSLO* still active - extending silence to all SLO alerts for 60m"
  curl -fsS -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(ts)" \
    --arg e "$(date -u -d '+60 min' +%FT%TZ)" '{matchers:[{name:"alertname",value:"PFTSLO.*",isRegex:true,isEqual:true}],
    startsAt:$s, endsAt:$e, createdBy:"slo drill.sh", comment:"SLO drill tail"}')" | jq -r '"  silence \(.silenceID[0:8])"'; }

echo; echo "== 5. restore + check"
restore
active="$(curl -fsS "$AM/api/v2/alerts" | jq -r '[.[] | .labels.alertname] | unique | join(",")')"
echo "Alertmanager alerts (any state): ${active:-none}"
if [ -z "$active" ]; then curl -s -X DELETE "$AM/api/v2/silence/$SIL" -o /dev/null -w "Alertmanager silence ${SIL:0:8} expired (HTTP %{http_code})\n"
else echo "Alertmanager silence ${SIL:0:8} left to run out at its end time"; fi
echo "node: $(node_state) | pft-maint: $(pft-maint status --json | jq -r .window)"
sleep 5; read_topic
echo "throwaway topic read back (titles only):"; jq -rc '"  \(.time|todate) \(.title)"' "$NTFY"
chown "$RUID:$RGID" "$SAMPLES" "$NTFY"
echo "\$ python3 slo/drill_check.py samples.jsonl ntfy.jsonl"
set +e; python3 "$CHECK" "$SAMPLES" "$NTFY" | tee "$OUT/check.txt"; rc=${PIPESTATUS[0]}; set -e
echo "slo drill done $(ts): checker exit $rc"
exit "$rc"
