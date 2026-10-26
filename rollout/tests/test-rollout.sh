#!/usr/bin/env bash
# Offline tests for pft-rollout.sh: fake docker/ssh/sudo/curl/pft-maint (tests/stubs), fake clock, no root,
# no network, nothing on the real hosts is touched. Two fake hosts: "relay" (sentry, docker run container with a
# confined profile) and "local" (validator, compose container).
#   ./test-rollout.sh             run the suite against ../pft-rollout.sh
#   ./test-rollout.sh --mutants   also run every mutation control; each must make at least one test FAIL
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${SCRIPT:-$HERE/../pft-rollout.sh}"
STUBS="$HERE/stubs"
OLD=sha256:aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111
NEW=sha256:bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222
BAD=sha256:dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444
TAG=agtipft/postfiatd:testnet-light-latest
PASSN=0; FAILN=0; FAILED=()

fixture() { # fresh $T with both fake hosts on OLD, NEW available to pull
  T="$(mktemp -d)"; export STUB="$T"
  mkdir -p "$T/hosts/relay" "$T/hosts/local" "$T/wd" "$T/state" "$T/home"
  echo 1800000000 > "$T/now"
  printf 'host sentry ssh relay postfiatd-sentry 5\nhost validator local - postfiatd 5\n' > "$T/hosts.conf"
  local imgs
  imgs="$(jq -nc --arg o "$OLD" --arg n "$NEW" '{($o): {Id:$o, RepoDigests:["agtipft/postfiatd@sha256:0ld"], Config:{Env:["PATH=/usr/bin"],Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"]}},
    ($n): {Id:$n, RepoDigests:["agtipft/postfiatd@sha256:new"], Config:{Env:["PATH=/usr/bin"],Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"]}}}')"
  jq -n --arg o "$OLD" --arg tag "$TAG" --argjson imgs "$imgs" '{gen:0, polls:0, seq:1000, gens:["good"], images:$imgs, tags:{($tag):$o},
    containers:{"postfiatd-sentry":{Name:"/postfiatd-sentry", Image:$o, State:{Running:true,StartedAt:"gen-0"},
      Config:{User:"0:0", Env:["PATH=/usr/bin"], Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"], Labels:{}, Image:$tag},
      HostConfig:{RestartPolicy:{Name:"unless-stopped",MaximumRetryCount:0}, LogConfig:{Type:"json-file",Config:{"max-file":"10","max-size":"100m"}},
        NetworkMode:"bridge", PortBindings:{"2559/tcp":[{HostIp:"127.0.0.1",HostPort:"2560"}]}, SecurityOpt:["no-new-privileges"],
        CapAdd:["CAP_SETGID","CAP_SETUID"], CapDrop:["ALL"], ReadonlyRootfs:true, Tmpfs:{"/run":"rw,noexec,nosuid,size=64m","/tmp":"rw,noexec,nosuid,size=64m"},
        PidsLimit:256, Memory:2147483648, MemorySwap:2147483648, Ulimits:null, Dns:null, ExtraHosts:null, Privileged:false},
      Mounts:[{Type:"volume",Name:"pft-sentry-config",Source:"/var/lib/docker/volumes/pft-sentry-config/_data",Destination:"/etc/postfiatd",RW:true},
              {Type:"volume",Name:"pft-sentry-data",Source:"/var/lib/docker/volumes/pft-sentry-data/_data",Destination:"/var/lib/postfiatd/db",RW:true}]}}}' \
    > "$T/hosts/relay/state.json"
  jq -n --arg o "$OLD" --arg tag "$TAG" --arg wd "$T/wd" --argjson imgs "$imgs" '{gen:0, polls:0, seq:1000, gens:["good"], images:$imgs, tags:{($tag):$o},
    containers:{"postfiatd":{Name:"/postfiatd", Image:$o, State:{Running:true,StartedAt:"gen-0"},
      Config:{User:"0:0", Env:[], Cmd:[], Image:$tag, Labels:{"com.docker.compose.project":"postfiatd","com.docker.compose.project.working_dir":$wd,"com.docker.compose.service":"postfiatd"}},
      HostConfig:{RestartPolicy:{Name:"unless-stopped"}}, Mounts:[]}}}' > "$T/hosts/local/state.json"
  echo "$NEW" > "$T/hosts/relay/pull_to"; echo "$NEW" > "$T/hosts/local/pull_to"
}
gens() { # HOST behaviours...
  local h="$1"; shift
  jq --argjson g "$(printf '%s\n' "$@" | jq -R . | jq -sc .)" '.gens = $g' "$T/hosts/$h/state.json" > "$T/x" && mv "$T/x" "$T/hosts/$h/state.json"
}
ro() { # run pft-rollout with the stubs; output in $T/out, exit code in RC
  PATH="$STUBS:$PATH" CONF="$T/hosts.conf" STATE_DIR="$T/state" HOME="$T/home" PFT_ROLLOUT_NOW_FILE="$T/now" \
    GATE_TIMEOUT=300 SOAK_SEC=60 POLL_SEC=10 MIN_ADVANCE=10 ROLLBACK_TIMEOUT=300 AM=http://am.test:9093 \
    FOUNDATION_RPC=https://foundation.test bash "$SCRIPT" "$@" > "$T/out" 2>&1
  RC=$?
}
img() { jq -r --arg c "$2" '.containers[$c].Image' "$T/hosts/$1/state.json"; }
tagid() { jq -r --arg t "$TAG" '.tags[$t]' "$T/hosts/$1/state.json"; }
gen() { jq -r .gen "$T/hosts/$1/state.json"; }
mutating() { cnt "$T/calls.log" -E "^$1 docker (tag|pull|restart|stop|rename|update|rm|run|start|compose)"; }
cnt() { # FILE GREP-ARGS... -> match count, 0 when the file does not exist (yet)
  local f="$1"; shift
  { cat "$f" 2>/dev/null || true; } | grep -c "$@"
}
summ() { jq -cS --arg c "$2" '.containers[$c] | {U:.Config.User, Cmd:.Config.Cmd, Env:.Config.Env, R:.HostConfig.RestartPolicy.Name, L:.HostConfig.LogConfig,
  P:.HostConfig.PortBindings, M:[.Mounts[]|{Name,Destination,RW}], S:.HostConfig.SecurityOpt, CA:.HostConfig.CapAdd, CD:.HostConfig.CapDrop,
  RO:.HostConfig.ReadonlyRootfs, TF:.HostConfig.Tmpfs, PL:.HostConfig.PidsLimit, MEM:.HostConfig.Memory}' "$T/hosts/$1/state.json"; }
events() { jq -r '"\(.event):\(.host)"' "$T/state/audit.jsonl" | tr '\n' ' '; }

CASE=""; CERR=()
ok() { :; }
no() { CERR+=("$1"); }
check() { # DESC CONDITION...
  local d="$1"; shift
  if "$@"; then ok; else no "$d"; fi
}
begin() { CASE="$1"; CERR=(); fixture; }
end() {
  if [ "${#CERR[@]}" -eq 0 ]; then PASSN=$((PASSN + 1)); echo "PASS $CASE"
  else FAILN=$((FAILN + 1)); FAILED+=("$CASE"); echo "FAIL $CASE: ${CERR[*]}"; [ -n "${VERBOSE:-}" ] && sed 's/^/    | /' "$T/out"; fi
  rm -rf "$T"
}
eq() { [ "$1" = "$2" ]; }
has() { grep -qF -- "$1" "$T/out"; }

t_gate_pass() {
  begin "gate pass: both hosts promoted, canary first, config kept, window+silence per host"
  local before; before="$(summ relay postfiatd-sentry)"
  ro run --yes
  check "rc=0 (got $RC)" eq "$RC" 0
  check "sentry on NEW" eq "$(img relay postfiatd-sentry)" "$NEW"
  check "validator on NEW" eq "$(img local postfiatd)" "$NEW"
  check "sentry config preserved" eq "$(summ relay postfiatd-sentry)" "$before"
  check "old sentry container kept" eq "$(jq -r '[.containers|keys[]|select(startswith("postfiatd-sentry-prerollout-"))]|length' "$T/hosts/relay/state.json")" 1
  check "sentry promoted before validator starts" eq "$(events | grep -o 'host_done:sentry.*host_start:validator' | wc -l)" 1
  check "2 maint starts" eq "$(grep -c ' start --ttl' "$T/maint.log")" 2
  check "2 maint ends" eq "$(grep -c ' end ' "$T/maint.log")" 2
  check "2 silences" eq "$(wc -l < "$T/silences.log")" 2
  check "silence matcher alertname=~.+" eq "$(jq -r '.matchers[0] | "\(.name) \(.value) \(.isRegex)"' "$T/silences.log" | sort -u)" "alertname .+ true"
  check "state promoted" eq "$(jq -r .result "$T/state/last-run.json")" promoted
  check "GATE PASS x2" eq "$(grep -c 'GATE PASS' "$T/out")" 2
  check "soak PASS x2" eq "$(grep -c 'soak PASS' "$T/out")" 2
  end
}
t_gate_timeout() {
  begin "gate timeout on canary: rolled back to recorded image, validator untouched"
  gens relay good connected good
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "GATE FAIL logged" has "GATE FAIL: not healthy within 300s"
  check "sentry back on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  check "sentry TAG back on OLD" eq "$(tagid relay)" "$OLD"
  check "original sentry container restored (no prerollout left)" eq "$(jq -r '[.containers|keys[]]|join(",")' "$T/hosts/relay/state.json")" postfiatd-sentry
  check "sentry restart policy restored" eq "$(jq -r '.containers["postfiatd-sentry"].HostConfig.RestartPolicy.Name' "$T/hosts/relay/state.json")" unless-stopped
  check "validator: 0 mutating docker calls" eq "$(mutating local)" 0
  check "validator gen unchanged" eq "$(gen local)" 0
  check "re-gate PASS" has "rollback re-gate PASS"
  check "result" eq "$(jq -r .result "$T/state/last-run.json")" "failed_rolled_back:sentry"
  check "validator untouched in state" eq "$(jq -r '.hosts[1].result' "$T/state/last-run.json")" untouched
  check "1 maint start (sentry only)" eq "$(grep -c ' start --ttl' "$T/maint.log")" 1
  check "window closed" eq "$(grep -c ' end ' "$T/maint.log")" 1
  end
}
t_second_host_failure() {
  begin "second-host failure: validator rolled back, sentry stays promoted"
  gens local good down good
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "sentry stays on NEW" eq "$(img relay postfiatd-sentry)" "$NEW"
  check "validator back on OLD" eq "$(img local postfiatd)" "$OLD"
  check "validator TAG back on OLD" eq "$(tagid local)" "$OLD"
  check "states" eq "$(jq -r '[.hosts[].result]|join(",")' "$T/state/last-run.json")" "promoted,rolled_back"
  check "result" eq "$(jq -r .result "$T/state/last-run.json")" "failed_rolled_back:validator"
  end
}
t_regate_failure() {
  begin "rollback re-gate failure: exit 5, validator untouched"
  gens relay good down down
  ro run --yes
  check "rc=5 (got $RC)" eq "$RC" 5
  check "ROLLBACK FAILED logged" has "ROLLBACK FAILED on sentry"
  check "validator: 0 mutating docker calls" eq "$(mutating local)" 0
  check "result" eq "$(jq -r .result "$T/state/last-run.json")" rollback_failed
  check "audit rollback_fail" eq "$(events | grep -c 'rollback_fail:sentry')" 1
  end
}
t_lock() {
  begin "lock contention: second run refused, nothing touched"
  mkdir -p "$T/state"; flock -n "$T/state/rollout.lock" sleep 30 & local holder=$!
  sleep 0.3
  ro run --yes
  kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
  check "rc=4 (got $RC)" eq "$RC" 4
  check "message" has "another pft-rollout holds"
  check "0 mutating calls relay" eq "$(mutating relay)" 0
  check "0 mutating calls local" eq "$(mutating local)" 0
  check "no maint start" eq "$(cnt "$T/maint.log" ' start ')" 0
  end
}
t_missing_prev() {
  begin "missing previous digest: refused before any change"
  jq --arg o "$OLD" 'del(.images[$o])' "$T/hosts/relay/state.json" > "$T/x" && mv "$T/x" "$T/hosts/relay/state.json"
  ro run --yes
  check "rc=4 (got $RC)" eq "$RC" 4
  check "message" has "is not in the local image store - cannot roll back, refusing"
  check "0 mutating calls relay" eq "$(mutating relay)" 0
  check "0 mutating calls local" eq "$(mutating local)" 0
  check "no maint start" eq "$(cnt "$T/maint.log" ' start ')" 0
  check "result refused" eq "$(jq -r .result "$T/state/last-run.json")" refused
  end
}
t_noop() {
  begin "no-op rollout (target == running image): restart + gate on both"
  rm -f "$T/hosts/relay/pull_to" "$T/hosts/local/pull_to"
  ro run --yes
  check "rc=0 (got $RC)" eq "$RC" 0
  check "no-op x2" eq "$(grep -c 'no-op: target is the running image' "$T/out")" 2
  check "sentry restarted (gen 1)" eq "$(gen relay)" 1
  check "validator restarted (gen 1)" eq "$(gen local)" 1
  check "images unchanged" eq "$(img relay postfiatd-sentry)$(img local postfiatd)" "$OLD$OLD"
  check "no retag/recreate" eq "$(grep -cE ' docker (tag|run|rename|compose)' "$T/calls.log")" 0
  end
}
t_soak_fail() {
  begin "soak failure after gate pass: rolled back"
  gens relay good flap2 good
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "gate passed first" has "GATE PASS"
  check "soak FAIL" has "soak FAIL: 3 consecutive failing polls"
  check "sentry back on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  check "validator untouched" eq "$(mutating local)" 0
  end
}
t_collect_lock() {
  begin "pft-maint data-collection lock: refused"
  echo "govern-24h 2026-10-27T16:20:00Z read-only collector" > "$T/locks"
  ro run --yes
  check "rc=4 (got $RC)" eq "$RC" 4
  check "message" has "data-collection lock held: govern-24h"
  check "0 mutating calls" eq "$(( $(mutating relay) + $(mutating local) ))" 0
  end
}
t_drift() {
  begin "config drift after docker run recreate: rolled back to the original container"
  touch "$T/hosts/relay/run_drop_capdrop"
  jq '.containers["postfiatd-sentry"].HostConfig.RestartPolicy.Name = "always"' "$T/hosts/relay/state.json" > "$T/x" && mv "$T/x" "$T/hosts/relay/state.json"
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "drift logged" has "config DRIFT after recreate"
  check "original container back with CapDrop ALL" eq "$(jq -r '.containers["postfiatd-sentry"].HostConfig.CapDrop // [] | join(",")' "$T/hosts/relay/state.json")" ALL
  check "sentry on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  check "original restart policy (always) restored" eq "$(jq -r '.containers["postfiatd-sentry"].HostConfig.RestartPolicy.Name' "$T/hosts/relay/state.json")" always
  check "validator untouched" eq "$(mutating local)" 0
  end
}
t_oldbuild() {
  begin "build_version != foundation: gate fails"
  gens relay good oldbuild good
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "build reason" has "build=1.0.8!=1.0.9"
  end
}
t_fewpeers() {
  begin "peers < min_peers: gate fails"
  gens relay good fewpeers good
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "peers reason" has "peers=1<5"
  end
}
t_stale() {
  begin "validated ledger age > MAX_LEDGER_AGE: gate fails"
  gens relay good stale good
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "age reason" has "age=120s>20s"
  end
}
t_drill_target() {
  begin "drill path: --no-pull --target local bad image on sentry only"
  jq --arg b "$BAD" '.images[$b] = {Id:$b, RepoDigests:[], Config:{Env:["PATH=/usr/bin"],Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"]}} | .tags["pft-rollout-drill:bad"] = $b' \
    "$T/hosts/relay/state.json" > "$T/x" && mv "$T/x" "$T/hosts/relay/state.json"
  gens relay good down good
  ro run --yes --no-pull --target pft-rollout-drill:bad
  check "rc=1 (got $RC)" eq "$RC" 1
  check "target logged" has "target pft-rollout-drill:bad = dddd4444dddd"
  check "sentry on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  check "sentry TAG on OLD" eq "$(tagid relay)" "$OLD"
  check "validator untouched" eq "$(mutating local)" 0
  check "no pull anywhere" eq "$(grep -c ' docker pull' "$T/calls.log")" 0
  end
}
t_manual_rollback() {
  begin "manual rollback after a promoted run restores both hosts"
  ro run --yes
  local rc1=$RC
  ro rollback --yes
  check "run rc=0 (got $rc1)" eq "$rc1" 0
  check "rollback rc=0 (got $RC)" eq "$RC" 0
  check "sentry on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  check "validator on OLD" eq "$(img local postfiatd)" "$OLD"
  end
}
t_readonly_cmds() {
  begin "plan --json and status --json change nothing"
  ro plan --json
  check "plan rc=0 (got $RC)" eq "$RC" 0
  check "plan order" eq "$(jq -r '.order|join(",")' "$T/out")" "sentry,validator"
  check "plan rollback image present" eq "$(jq -r '[.hosts[].rollback_image_present]|join(",")' "$T/out")" "yes,yes"
  ro status --json
  check "status rc=0 (got $RC)" eq "$RC" 0
  check "status lock_held false" eq "$(jq -r .lock_held "$T/out")" false
  check "0 mutating calls" eq "$(( $(mutating relay) + $(mutating local) ))" 0
  end
}

t_post_hook() {
  begin "post command: runs on its host after deploy, before the gate; shown by plan"
  printf 'post sentry echo sentry-post >> %s/post.log\n' "$T" >> "$T/hosts.conf"
  ro run --yes
  check "rc=0 (got $RC)" eq "$RC" 0
  check "1 post run" eq "$(cnt "$T/post.log" sentry-post)" 1
  check "post before deployed/gate" eq "$(events | grep -o 'post_hook:sentry deployed:sentry gate_pass:sentry' | wc -l)" 1
  check "no post for validator" eq "$(events | grep -c 'post_hook:validator')" 0
  ro plan --json
  check "plan shows post" eq "$(jq -r '[.hosts[].post]|join("|")' "$T/out" | grep -c '^echo sentry-post >> .*/post.log|$')" 1
  end
}
t_post_rollback() {
  begin "post command: runs again after a rollback restore"
  printf 'post sentry echo sentry-post >> %s/post.log\n' "$T" >> "$T/hosts.conf"
  gens relay good connected good
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "2 post runs (deploy + restore)" eq "$(cnt "$T/post.log" sentry-post)" 2
  check "post after rollback_start" eq "$(events | grep -o 'rollback_start:sentry post_hook:sentry' | wc -l)" 1
  check "sentry on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  end
}
t_post_fail() {
  begin "post command failure after deploy: rolled back, validator untouched"
  printf 'post sentry [ -e %s/post.once ] || { touch %s/post.once; echo boom; exit 7; }\n' "$T" "$T" >> "$T/hosts.conf"
  ro run --yes
  check "rc=1 (got $RC)" eq "$RC" 1
  check "failure logged" has "post command FAILED (exit 7)"
  check "command output shown" has "  post: boom"
  check "no gate on the bad deploy" eq "$(events | grep -c 'gate_pass:sentry')" 0
  check "sentry on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  check "validator untouched" eq "$(mutating local)" 0
  check "result" eq "$(jq -r .result "$T/state/last-run.json")" "failed_rolled_back:sentry"
  end
}
t_post_conf() {
  begin "post line for an unknown host: config error, nothing touched"
  echo 'post nosuchhost true' >> "$T/hosts.conf"
  ro run --yes
  check "rc=3 (got $RC)" eq "$RC" 3
  check "message" has "post nosuchhost: no host line for nosuchhost"
  check "0 mutating calls" eq "$(( $(mutating relay) + $(mutating local) ))" 0
  end
}

ALL=(t_gate_pass t_gate_timeout t_second_host_failure t_regate_failure t_lock t_missing_prev t_noop t_soak_fail
     t_collect_lock t_drift t_oldbuild t_fewpeers t_stale t_drill_target t_manual_rollback t_readonly_cmds
     t_post_hook t_post_rollback t_post_fail t_post_conf)
suite() { PASSN=0; FAILN=0; FAILED=(); for t in "${ALL[@]}"; do "$t"; done; echo "TOTAL: $PASSN passed, $FAILN failed"; }

# name | sed expression applied to a copy of pft-rollout.sh | test(s) expected to catch it
# sed programs, not shell expansions:
# shellcheck disable=SC2016
MUTANTS=(
  'M1 build check off|s/\[ "\$b" = "\$REF_BUILD" \] || why/true || why/'
  'M2 continue to next host after a failure|s/\[ "\$rc" -eq 0 \] && continue/continue/'
  'M3 no lock|s/flock -n 9 ||/true ||/'
  'M4 no recorded-image check|s/\[ -n "\$(image_id "\$h" "\${R_PREV\[\$h\]}")" \] \\$/true \\/'
  'M5 rollback without re-gate|s/if restore "\$h" && gate "\$h" "\$ROLLBACK_TIMEOUT"; then$/if restore "$h"; then/'
  'M6 no soak|s/if soak "\$h"; then/if true; then/'
  'M7 no config drift check|s/if \[ "\$(config_summary "\$new")" != "\$(config_summary "\$i")" \]; then/if false; then/'
  'M8 peers check off|s/\[ "\$p" -ge "\${H_PEERS\[\$1\]}" \] ||/true ||/'
  'M9 ledger age check off|s/\[ "\$age" -le "\$MAX_LEDGER_AGE" \] ||/true ||/'
  'M10 no data-collection lock check|s/\[ "\$locks" = "no data-collection locks" \] ||/true ||/'
  'M11 restore forces restart=unless-stopped|s/--restart="\${R_RP\[\$h\]:-unless-stopped}"/--restart=unless-stopped/'
  'M12 post command failure ignored|s/\[ "\$rc" -eq 0 \] || { log "  post command FAILED/true || { log "  post command FAILED/'
  'M13 no post command after deploy|/container runs \${new:7:12}/{n;d;}'
  'M14 no post command after restore|/after restore \$c runs/{n;d;}'
  'M15 post lines not parsed|s/H_POST\[\$l\]="\${H_POST\[\$l\]:+\${H_POST\[\$l\]} \&\& }\$rest"/:/'
)

suite; RES=$FAILN
if [ "${1:-}" = --mutants ]; then
  echo; echo "== mutation controls =="
  MC=0
  for m in "${MUTANTS[@]}"; do
    name="${m%%|*}"; expr="${m#*|}"
    mf="$(mktemp --suffix=.sh)"; sed "$expr" "$SCRIPT" > "$mf"
    if cmp -s "$mf" "$SCRIPT"; then echo "MUTANT $name: sed changed nothing - INVALID"; MC=$((MC + 1)); rm -f "$mf"; continue; fi
    out="$(SCRIPT="$mf"; suite)"
    rm -f "$mf"
    nf="$(grep -c '^FAIL ' <<<"$out")"
    if [ "$nf" -gt 0 ]; then echo "MUTANT $name: CAUGHT by $nf test(s): $(grep '^FAIL ' <<<"$out" | sed 's/: .*//; s/^FAIL //' | paste -sd ';')"
    else echo "MUTANT $name: NOT CAUGHT"; MC=$((MC + 1)); fi
  done
  echo "mutants not caught/invalid: $MC"
  [ "$MC" -eq 0 ] || RES=1
fi
exit "$RES"
