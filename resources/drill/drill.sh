#!/usr/bin/env bash
# Live two-host drill for pft-resources + alerts/resources.rules.yml. Run on the VALIDATOR (the host with the
# ../alerts stack); the sentry is driven over the admin ssh link ("ssh relay" as the operator account).
#   sudo bash resources/drill/drill.sh [--out DIR]
# Never touches postfiatd: the load runs in a THROWAWAY container per host (python:3.12-alpine, same image digest on
# both, --network none, read-only, no capabilities) with small limits: memory 128m (no swap), pids 32, nofile 64.
# Its main process is drill_load.py, which follows a phase file mounted read-only from the host.
# 1  preflight: stack ready, bridge on the real env file, no drill containers/alerts, both nodes full
# 2  pft-alert-bridge -> throwaway ntfy topic (alerts/run-stack.sh bridge: Prometheus/Alertmanager keep running)
# 3  start pft-res-drill-v (validator) and pft-res-drill-s (sentry); every ~30 s: pft-resources collect for both
#    (--proc-name python3, PFT_RES_CONF=/dev/null so the 24h baseline history is not touched), pull the sentry
#    file with pft-resources-pull, then sample node state + Prometheus/Alertmanager state into samples.jsonl
#    idle  -> load (fds 87.5%, pids 94%, memory 93%: PFTFdNearLimit, PFTPidsNearLimit, PFTMemoryNearLimit)
#          -> oom  (one child OOM-killed inside the cgroup: PFTContainerOOMKill)
#          -> calm (container idle until every drill alert resolved and [RESOLVED] is on the topic)
# 4  restore on ANY exit (trap): containers removed, drill textfiles removed, wait for the drill alerts to leave
#    Alertmanager (else a scoped silence), bridge back to the real env file (mount source checked), sentry image
#    removed if the drill pulled it, temp dirs removed. Then drill_verdict.py on samples + topic read-back.
# Output: DIR/samples.jsonl, DIR/ntfy.jsonl (titles + bodies, no topic), DIR/verdict.txt. Topic printed as <redacted>.
set -euo pipefail
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in --out) OUT="$2"; shift 2 ;; *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PROM=http://127.0.0.1:9090
AM=http://127.0.0.1:9093
TEXTDIR=/var/lib/pft-exporter/textfile
CV=pft-res-drill-v; CS=pft-res-drill-s
IMG_TAG=python:3.12-alpine
LOAD_ALERTS="PFTFdNearLimit PFTPidsNearLimit PFTMemoryNearLimit"; OOM_ALERT=PFTContainerOOMKill
RUSER="${SUDO_USER:?run with sudo from the operator user (the bridge env file and the ssh key belong to that user)}"
RUID="$(id -u "$RUSER")"; RGID="$(id -g "$RUSER")"
REAL_BRIDGE_ENV="$(getent passwd "$RUSER" | cut -d: -f6)/.config/pft-alerts/ntfy.env"
OUT="${OUT:-$HERE/drill-out-$(date -u +%Y%m%dT%H%M%SZ)}"
SAMPLES="$OUT/samples.jsonl"; NTFY="$OUT/ntfy.jsonl"
topic="resdrill-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TDIR="$(mktemp -d /run/pft-res-drill.XXXXXX)"; TBRIDGE="$TDIR/ntfy.env"; CDIR="$TDIR/ctl"
since="$(date -u +%s)"; RESTORED=0; BRIDGE_REDIR=0; RDIR=""; SENTRY_PULLED=0; STARTED=0; IMG=""
ts() { date -u +%FT%TZ; }
red() { sed -E "s/$topic/<redacted>/g; s|/home/[^ ]*|<home>|g; s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/<redacted-ip>/g"; }
rssh() { runuser -u "$RUSER" -- ssh -o BatchMode=yes -o ConnectTimeout=10 relay "$@" </dev/null; }
bridge_src() { docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}' pft-alert-bridge 2>/dev/null; }
RPC='{"method":"server_info","params":[{}]}'
node_v() { docker exec postfiatd curl -s -m 5 -X POST -H 'Content-Type: application/json' -d "$RPC" http://127.0.0.1:5005/ 2>/dev/null \
  | jq -r '.result.info.server_state // "unreachable"' 2>/dev/null || echo unreachable; }
node_s() { rssh "sudo docker exec postfiatd-sentry curl -s -m 5 -X POST -H 'Content-Type: application/json' -d '$RPC' http://127.0.0.1:5005/" 2>/dev/null \
  | jq -r '.result.info.server_state // "unreachable"' 2>/dev/null || echo unreachable; }
set_phase() { printf '%s\n' "$1" > "$CDIR/phase"; [ -z "$RDIR" ] || rssh "printf '%s\n' '$1' > $RDIR/ctl/phase"; }
read_topic() { curl -s --max-time 20 "https://ntfy.sh/$topic/json?poll=1&since=$since" | python3 -I "$HERE/drill_verdict.py" ntfy > "$NTFY" || true; }
topic_has() { # STATUS ALERT CONTAINER -> rc 0 if such a message is on the topic
  jq -se --arg t "[$1] $2" --arg c "$3" 'any(.[]; .title == $t and ((.message // "") | split(" ") | index($c)) != null)' "$NTFY" >/dev/null 2>&1
}
DRILL_RE='pft-res-drill-[vs]'
prom_drill() { curl -fsS --max-time 10 "$PROM/api/v1/alerts" | jq -c --arg re "^$DRILL_RE\$" \
  '[.data.alerts[] | select((.labels.container // "") | test($re))] | group_by(.labels.container)
   | map({key: .[0].labels.container, value: (map({key: .labels.alertname, value: .state}) | from_entries)}) | from_entries' 2>/dev/null || echo null; }
am_drill() { curl -fsS --max-time 10 "$AM/api/v2/alerts?active=true&silenced=false&inhibited=false" | jq -c --arg re "^$DRILL_RE\$" \
  '[.[] | select((.labels.container // "") | test($re))] | group_by(.labels.container)
   | map({key: .[0].labels.container, value: (map(.labels.alertname) | sort)}) | from_entries' 2>/dev/null || echo null; }
am_other() { curl -fsS --max-time 10 "$AM/api/v2/alerts?active=true" | jq -c --arg re "^$DRILL_RE\$" \
  '[.[] | select((.labels.container // "") | test($re) | not) | .labels.alertname] | sort' 2>/dev/null || echo null; }
real_res() { curl -fsS --max-time 10 "$PROM/api/v1/alerts" | jq -c --argjson names "$RES_ALERTS" \
  '[.data.alerts[] | select(.labels.container == "postfiatd" or .labels.container == "postfiatd-sentry")
    | select(.labels.alertname as $a | $names | index($a)) | .labels.alertname] | sort' 2>/dev/null || echo null; }
promq() { curl -fsS --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1" 2>/dev/null; }
metrics() { # per drill container: up fd/limit pids/max mem% oom_kill oom_killed
  promq "{__name__=~\"pft_resources_(up|fd_open|fd_limit_soft|pids_current|pids_max|memory_current_bytes|memory_max_bytes|container_oom_killed|memory_events_total)\",container=~\"$DRILL_RE\"}" \
    | jq -c '[.data.result[] | select(.metric.__name__ != "pft_resources_memory_events_total" or .metric.event == "oom_kill")
        | {c: .metric.container, k: (.metric.__name__ | sub("pft_resources_"; "")), v: (.value[1] | tonumber)}]
        | group_by(.c) | map({key: .[0].c, value: (map({key: .k, value: .v}) | from_entries)}) | from_entries' 2>/dev/null || echo '{}'
}
collect() {
  local e
  e="$(PFT_RES_CONF=/dev/null /usr/local/bin/pft-resources collect --container "$CV" --proc-name python3 2>&1)" || printf '  collect %s: %s\n' "$CV" "$e"
  e="$(rssh "sudo env PFT_RES_CONF=/dev/null /usr/local/bin/pft-resources collect --container $CS --proc-name python3" 2>&1)" || printf '  collect %s: %s\n' "$CS" "$e"
  e="$(/usr/local/bin/pft-resources-pull pull --container "$CS" 2>&1)" || printf '  pull %s: %s\n' "$CS" "$e" | red
}
sample() { # PHASE
  local nv ns pd ad m up
  collect
  sleep 20   # exporter scrape 15 s, rule evaluation 15 s
  nv="$(node_v)"; ns="$(node_s)"; pd="$(prom_drill)"; ad="$(am_drill)"; m="$(metrics)"
  up="$(jq -c --arg v "$CV" --arg s "$CS" '{($v): .[$v].up, ($s): .[$s].up}' <<<"$m")"
  jq -nc --argjson t "$(date -u +%s)" --arg p "$1" --arg nv "$nv" --arg ns "$ns" --argjson pd "$pd" --argjson ad "$ad" \
    --argjson real "$(real_res)" --argjson up "$up" --argjson m "$m" --argjson other "$(am_other)" \
    '{t:$t, phase:$p, nodes:{validator:$nv, sentry:$ns}, prom:$pd, am:$ad, real:$real, up:$up, m:$m, am_other:$other}' >> "$SAMPLES"
  tail -n 1 "$SAMPLES" | jq -r '"  \(.t|todate) \(.phase) nodes v=\(.nodes.validator) s=\(.nodes.sentry)"
    + (.m | to_entries | map(" | \(.key) up=\(.value.up) fd=\(.value.fd_open)/\(.value.fd_limit_soft) pids=\(.value.pids_current)/\(.value.pids_max) mem=\(if .value.memory_max_bytes then (.value.memory_current_bytes * 100 / .value.memory_max_bytes | floor) else null end)% oom_kill=\(.value.memory_events_total) oomkilled=\(.value.container_oom_killed)") | join(""))'
  tail -n 1 "$SAMPLES" | jq -r '"      prometheus \(.prom | tojson) | alertmanager \(.am | tojson) | real-container resources alerts \(.real | tojson) | other AM alerts \(.am_other | tojson)"'
}
prom_all() { # STATE ALERT... -> rc 0 if every ALERT is STATE in Prometheus for BOTH drill containers
  local st="$1" a c; shift
  for c in "$CV" "$CS"; do for a in "$@"; do
    [ "$(tail -n 1 "$SAMPLES" | jq -r --arg c "$c" --arg a "$a" '.prom[$c][$a] // "none"')" = "$st" ] || return 1
  done; done
}
topic_all() { # STATUS ALERT...
  local s="$1" a c; shift
  for c in "$CV" "$CS"; do for a in "$@"; do topic_has "$s" "$a" "$c" || return 1; done; done
}
drill_quiet() { [ "$(prom_drill)" = '{}' ] && [ "$(am_drill)" = '{}' ]; }

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  set +e
  echo; echo "== 4. restore ($(ts))"
  if [ "$STARTED" -eq 1 ]; then
    set_phase "done"; sleep 3
    echo "  $CV: $(docker inspect -f 'exit={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}' "$CV" 2>&1); docker logs (drill_load.py):"
    docker logs "$CV" 2>&1 | sed 's/^/    /'
    echo "  $CS: $(rssh "sudo docker inspect -f 'exit={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}' $CS" 2>&1); docker logs (drill_load.py):"
    rssh "sudo docker logs $CS" 2>&1 | sed 's/^/    /'
  fi
  docker rm -f "$CV" >/dev/null 2>&1; rssh "sudo docker rm -f $CS" >/dev/null 2>&1
  rm -f "$TEXTDIR/pft_resources_$CV.prom" "$TEXTDIR/pft_resources_$CS.prom"
  rssh "sudo rm -f $TEXTDIR/pft_resources_$CS.prom"
  echo "  containers removed: validator $(docker ps -a --filter "name=^$CV\$" -q | grep -c . ) left, sentry $(rssh "sudo docker ps -a --filter name=^$CS\$ -q" | grep -c .) left"
  echo "  drill textfiles left: validator $(find "$TEXTDIR" -name 'pft_resources_pft-res-drill-*' | grep -c .), sentry $(rssh "sudo find $TEXTDIR -name 'pft_resources_pft-res-drill-*'" | grep -c .)"
  if [ "$BRIDGE_REDIR" -eq 1 ]; then
    local _
    for _ in $(seq 1 18); do drill_quiet && break; sleep 10; done
    if drill_quiet; then
      echo "  no drill alert in Prometheus/Alertmanager; one group_interval (65 s) for late notifications"; sleep 65
    else
      sil="$(curl -fsS -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(ts)" \
        --arg e "$(date -u -d '+60 min' +%FT%TZ)" '{matchers:[{name:"container",value:"pft-res-drill-[vs]",isRegex:true,isEqual:true}],
        startsAt:$s, endsAt:$e, createdBy:"resources drill.sh", comment:"drill tail: drill series removed"}')" | jq -r '.silenceID // empty')"
      echo "  drill alerts still active after 3 min -> silence ${sil:0:8} container=~pft-res-drill-[vs] for 60m"
    fi
    echo "  \$ NTFY_ENV_FILE=<real bridge env> alerts/run-stack.sh bridge"
    NTFY_ENV_FILE="$REAL_BRIDGE_ENV" DOCKER=docker bash "$ROOT/alerts/run-stack.sh" bridge 2>&1 | red | sed 's/^/  /'
    echo "  pft-alert-bridge mount source is the real env file: $([ "$(bridge_src)" = "$(readlink -f "$REAL_BRIDGE_ENV")" ] && echo yes || echo NO)"
  fi
  if [ "$SENTRY_PULLED" -eq 1 ]; then
    rssh "sudo docker rmi $IMG" >/dev/null 2>&1
    echo "  sentry: drill image removed again (it was not there before): $(rssh "sudo docker image inspect $IMG >/dev/null 2>&1 && echo STILL-PRESENT || echo gone")"
  fi
  [ -z "$RDIR" ] || rssh "rm -rf $RDIR"
  rm -rf "$TDIR"
  echo "  nodes after restore: validator $(node_v), sentry $(node_s)"
  set -e
}
trap restore EXIT

mkdir -p "$OUT" "$CDIR"; chown "$RUID:$RGID" "$OUT"; chmod 755 "$TDIR" "$CDIR"
echo "pft-resources live drill (validator + sentry) - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "sha256: drill.sh $(sha256sum "$HERE/drill.sh" | cut -c1-12) | drill_load.py $(sha256sum "$HERE/drill_load.py" | cut -c1-12) | drill_verdict.py $(sha256sum "$HERE/drill_verdict.py" | cut -c1-12) | resources.rules.yml $(sha256sum "$ROOT/alerts/resources.rules.yml" | cut -c1-12) | pft-resources $(sha256sum /usr/local/bin/pft-resources | cut -c1-12) (sentry $(rssh "sha256sum /usr/local/bin/pft-resources" | cut -c1-12)) | pft-resources-pull $(sha256sum /usr/local/bin/pft-resources-pull | cut -c1-12)"

echo; echo "== 1. preflight"
if ! curl -fsS --max-time 5 -o /dev/null "$PROM/-/ready" || ! curl -fsS --max-time 5 -o /dev/null "$AM/-/ready"; then
  echo "  Prometheus/Alertmanager not ready - stopping"; exit 3
fi
[ "$(bridge_src)" = "$(readlink -f "$REAL_BRIDGE_ENV")" ] || { echo "  bridge not on the real env file now - stopping"; exit 3; }
RES_ALERTS="$(curl -fsS "$PROM/api/v1/rules" | jq -c '[.data.groups[] | select(.name == "pft-resources") | .rules[].name]')"
echo "  pft-resources rule group loaded: $RES_ALERTS"
[ "$(jq length <<<"$RES_ALERTS")" -ge 10 ] || { echo "  pft-resources rules not loaded - stopping"; exit 3; }
if docker ps -a --format '{{.Names}}' | grep -qx "$CV" || rssh "sudo docker ps -a --format '{{.Names}}'" | grep -qx "$CS"; then
  echo "  a drill container already exists - stopping"; exit 4
fi
drill_quiet || { echo "  drill alerts already active - stopping"; exit 4; }
v="$(node_v)"; s="$(node_s)"; echo "  nodes: validator $v, sentry $s"
if [ "$v" != full ] || [ "$s" != full ]; then echo "  a node is not full - stopping"; exit 4; fi
IMG="$(docker image inspect -f '{{index .RepoDigests 0}}' "$IMG_TAG")"
echo "  drill image $IMG"
echo "  Alertmanager: active silences $(curl -fsS "$AM/api/v2/silences" | jq '[.[] | select(.status.state == "active")] | length'), active alerts $(am_other)"

echo; echo "== 2. bridge -> throwaway topic"
( umask 077; printf 'NTFY_URL=https://ntfy.sh/%s\n' "$topic" > "$TBRIDGE" ); chown "$RUID:$RGID" "$TBRIDGE"
BRIDGE_REDIR=1
echo "  \$ NTFY_ENV_FILE=<throwaway env> alerts/run-stack.sh bridge"
NTFY_ENV_FILE="$TBRIDGE" DOCKER=docker bash "$ROOT/alerts/run-stack.sh" bridge 2>&1 | red | sed 's/^/  /'
[ "$(bridge_src)" = "$TBRIDGE" ] || { echo "  bridge not on the throwaway file - stopping"; exit 1; }
echo "  pft-alert-bridge -> https://ntfy.sh/<redacted> (throwaway; mount source checked); Prometheus/Alertmanager not recreated: $(docker inspect -f '{{.Name}} {{.State.StartedAt}}' pft-prometheus pft-alertmanager | tr '\n' ' ')"

echo; echo "== 3. throwaway containers"
if rssh "sudo docker image inspect $IMG" >/dev/null 2>&1; then echo "  sentry already has the image"
else SENTRY_PULLED=1; echo "  sentry: docker pull $IMG"; rssh "sudo docker pull -q $IMG" | sed 's/^/    /'; fi
RDIR="$(rssh "mktemp -d /tmp/pft-res-drill.XXXXXX")"
rssh "mkdir -p $RDIR/ctl && chmod 755 $RDIR $RDIR/ctl && printf 'idle\n' > $RDIR/ctl/phase && chmod 644 $RDIR/ctl/phase"
# rssh reads /dev/null; the copy needs the file on stdin
runuser -u "$RUSER" -- ssh -o BatchMode=yes -o ConnectTimeout=10 relay "cat > $RDIR/drill_load.py && chmod 644 $RDIR/drill_load.py" < "$HERE/drill_load.py"
cmp -s <(rssh "cat $RDIR/drill_load.py") "$HERE/drill_load.py" || { echo "  copy of drill_load.py to the sentry differs - stopping"; exit 1; }
echo "  sentry drill_load.py sha256 $(rssh "sha256sum $RDIR/drill_load.py" | cut -c1-12)"
printf 'idle\n' > "$CDIR/phase"; chmod 644 "$CDIR/phase"
LIM="--network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --memory-swap 128m --pids-limit 32 --ulimit nofile=64:64"
echo "  docker run -d --name NAME $LIM -v CTL:/ctl:ro -v drill_load.py:/app/drill_load.py:ro $IMG python3 -u /app/drill_load.py"
STARTED=1
# shellcheck disable=SC2086  # LIM is a fixed option list
docker run -d --name "$CV" $LIM -v "$CDIR:/ctl:ro" -v "$HERE/drill_load.py:/app/drill_load.py:ro" "$IMG" python3 -u /app/drill_load.py >/dev/null
rssh "sudo docker run -d --name $CS $LIM -v $RDIR/ctl:/ctl:ro -v $RDIR/drill_load.py:/app/drill_load.py:ro $IMG python3 -u /app/drill_load.py" >/dev/null
sleep 3
echo "  running: validator $(docker inspect -f '{{.State.Status}}' "$CV"), sentry $(rssh "sudo docker inspect -f '{{.State.Status}}' $CS")"

echo; echo "== 3a. idle ($(ts))"
for _ in 1 2 3; do sample idle; done

echo; echo "== 3b. load: fds 87.5%, pids 94%, memory 93% ($(ts))"
set_phase load
end=$(( $(date +%s) + 900 ))
while [ "$(date +%s)" -lt "$end" ]; do
  sample load; read_topic
  # shellcheck disable=SC2086
  if prom_all firing $LOAD_ALERTS && topic_all FIRING $LOAD_ALERTS; then
    echo "  $(ts) all 3 load alerts firing for both containers and [FIRING] x6 seen on the topic"; break
  fi
done

echo; echo "== 3c. oom: release, one child OOM-killed in each cgroup ($(ts))"
set_phase oom
end=$(( $(date +%s) + 480 ))
while [ "$(date +%s)" -lt "$end" ]; do
  sample oom; read_topic
  if prom_all firing "$OOM_ALERT" && topic_all FIRING "$OOM_ALERT"; then
    echo "  $(ts) $OOM_ALERT firing for both containers and [FIRING] x2 seen on the topic"; break
  fi
done

echo; echo "== 3d. calm: container idle until every drill alert resolved ($(ts))"
set_phase idle
end=$(( $(date +%s) + 1200 ))
while [ "$(date +%s)" -lt "$end" ]; do
  sample calm; read_topic
  # shellcheck disable=SC2086
  if [ "$(tail -n 1 "$SAMPLES" | jq -c '[.prom, .am]')" = '[{},{}]' ] && topic_all RESOLVED $LOAD_ALERTS "$OOM_ALERT"; then
    echo "  $(ts) no drill alert in Prometheus or Alertmanager and [RESOLVED] x8 seen on the topic"; break
  fi
done

restore
read_topic
echo; echo "== 5. throwaway topic read back"
jq -rc '"  \(.time|todate) \(.title) | \(.message)"' "$NTFY"
chown "$RUID:$RGID" "$SAMPLES" "$NTFY"
echo "\$ python3 resources/drill/drill_verdict.py samples.jsonl ntfy.jsonl"
set +e; python3 -I "$HERE/drill_verdict.py" "$SAMPLES" "$NTFY" | tee "$OUT/verdict.txt"; rc=${PIPESTATUS[0]}; set -e
chown "$RUID:$RGID" "$OUT/verdict.txt"
echo "drill done $(ts): verdict exit $rc"
exit "$rc"
