# apply / rollback tests (sourced by run-tests.sh): stateful docker stub (stub_docker.py), a compose validator and a
# `docker run` sentry, 3 clean measured stops each (p100 10.1 s x 3 = 31 s). Every refusal must leave the container,
# .env and overlay untouched; every injected failure must roll back to the exact previous container.
# shellcheck shell=bash
# shellcheck disable=SC2016,SC2015
afresh() { # KIND(compose|run)
  N=$((N + 1)); E="$T/e$N"; local r="$E/root" d="$E/d"
  mkdir -p "$r/opt/postfiatd" "$r/etc/pft-seccomp" "$r/etc/docker" "$r/var/lib/pft-shutdown" "$d/containers" "$E/bin"
  echo '{"live-restore":true}' > "$r/etc/docker/daemon.json"
  echo '{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}' > "$r/etc/pft-seccomp/pft-postfiatd.json"
  local sc; sc="seccomp=$(jq -c . "$r/etc/pft-seccomp/pft-postfiatd.json")"
  echo '{"agtipft/postfiatd:testnet-light-latest":{"Id":"sha256:img1","Env":["PATH=/usr/bin"]}}' > "$d/images.json"
  if [ "$1" = compose ]; then
    CN=postfiatd
    printf 'NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.seccomp.yml\n' > "$r/opt/postfiatd/.env"; chmod 600 "$r/opt/postfiatd/.env"
    printf 'services:\n  postfiatd:\n    image: x\n' > "$r/opt/postfiatd/docker-compose.yml"
    printf 'services:\n  postfiatd:\n    security_opt: ["seccomp=/etc/pft-seccomp/pft-postfiatd.json"]\n' > "$r/opt/postfiatd/docker-compose.seccomp.yml"
    jq -n --arg sc "$sc" '{Id:"c1", Name:"/postfiatd", Image:"sha256:img1", AppArmorProfile:"pft-postfiatd",
      Config:{Image:"agtipft/postfiatd:testnet-light-latest", Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"], User:"", Env:["PATH=/usr/bin","NETWORK=testnet"],
        Labels:{"com.docker.compose.project.working_dir":"/opt/postfiatd", "com.docker.compose.service":"postfiatd",
          "com.docker.compose.project.config_files":"/opt/postfiatd/docker-compose.yml,/opt/postfiatd/docker-compose.seccomp.yml"}},
      HostConfig:{CapDrop:["ALL"], CapAdd:[], SecurityOpt:["no-new-privileges", $sc], ReadonlyRootfs:true, Tmpfs:{"/tmp":"rw,noexec"},
        PidsLimit:256, Memory:2147483648, MemorySwap:2147483648, CpuShares:512, RestartPolicy:{Name:"unless-stopped"},
        LogConfig:{Type:"json-file", Config:{}}, NetworkMode:"postfiatd_default", PortBindings:{"2559/tcp":[{HostIp:"",HostPort:"2559"}]}},
      Mounts:[{Type:"volume", Name:"pfd-db", Destination:"/var/lib/postfiatd/db", RW:true}],
      State:{Running:true, StartedAt:"2026-11-24T01:00:00Z"}}' > "$d/containers/postfiatd.json"
  else
    CN=postfiatd-sentry
    jq -n --arg sc "$sc" '{Id:"s1", Name:"/postfiatd-sentry", Image:"sha256:img1", AppArmorProfile:"pft-postfiatd",
      Config:{Image:"agtipft/postfiatd:testnet-light-latest", Cmd:["--conf","/etc/postfiatd/postfiatd.cfg"], User:"0:0", Env:["PATH=/usr/bin","NETWORK=testnet"], Labels:{}},
      HostConfig:{CapDrop:["ALL"], CapAdd:["SETGID","SETUID"], SecurityOpt:["no-new-privileges","apparmor=pft-postfiatd", $sc], ReadonlyRootfs:true,
        Tmpfs:{"/tmp":"rw,noexec,nosuid,size=64m"}, PidsLimit:256, Memory:2147483648, MemorySwap:2147483648,
        RestartPolicy:{Name:"unless-stopped", MaximumRetryCount:0}, LogConfig:{Type:"json-file", Config:{"max-size":"50m"}}, NetworkMode:"bridge",
        PortBindings:{"2559/tcp":[{HostIp:"203.0.113.7",HostPort:"2559"}]}},
      Mounts:[{Type:"volume", Name:"pfs-db", Destination:"/var/lib/postfiatd/db", RW:true},
              {Type:"bind", Source:"/opt/postfiatd-sentry/postfiatd.cfg", Destination:"/etc/postfiatd/postfiatd.cfg", RW:false}],
      State:{Running:true, StartedAt:"2026-11-24T01:00:00Z"}}' > "$d/containers/postfiatd-sentry.json"
  fi
  jq -n '{runs:[{mode:"clean",clean:true,stop_s:5.0},{mode:"clean",clean:true,stop_s:10.1},{mode:"clean",clean:true,stop_s:3.2},
    {mode:"sigkill",clean:false,stop_s:0.3}]}' > "$r/var/lib/pft-shutdown/measure-$CN.json"
  printf '#!/bin/sh\nexec python3 -I %s "$@"\n' "$HERE/stub_docker.py" > "$E/bin/docker"
  printf '#!/bin/sh\n[ -e %s/d/nomaint ] && exit 1; exit 0\n' "$E" > "$E/bin/maint"
  printf '#!/bin/sh\nif [ -e %s/d/notfull ]; then echo '"'"'{"result":{"info":{"server_state":"syncing"}}}'"'"'; else echo '"'"'{"result":{"info":{"server_state":"full","complete_ledgers":"1-9"}}}'"'"'; fi\n' "$E" > "$E/bin/rpc"
  printf '#!/bin/sh\ncase "$4" in TimeoutStopUSec) case "$2" in docker.service) echo infinity ;; *) echo "1min 30s" ;; esac ;; KillSignal) echo 15 ;; esac\n' > "$E/bin/systemctl"
  mkdir -p "$r/usr/local/bin"; printf '#!/bin/sh\n# recreate carries --stop-timeout\n' > "$r/usr/local/bin/pft-seccomp"
  chmod 755 "$E/bin/docker" "$E/bin/maint" "$E/bin/rpc" "$E/bin/systemctl"
  export PFT_SHUTDOWN_ROOT="$r" PFT_SHUTDOWN_DOCKER="$E/bin/docker" PFT_SHUTDOWN_SYSTEMCTL="$E/bin/systemctl" PFT_SHUTDOWN_MAINT="$E/bin/maint" PFT_SHUTDOWN_RPC="$E/bin/rpc" \
    STUB_D="$d" STUB_ROOT="$r" STATE_DIR="$r/var/lib/pft-shutdown" CONTAINER="$CN" POLL_SEC=0 RECOVER_TIMEOUT=2
  unset MIN_TIMEOUT SAFETY_FACTOR RECREATE_TOOLS PFT_SHUTDOWN_INJECT MIN_RUNS
  ENV0="$(cat "$r/opt/postfiatd/.env" 2>/dev/null)"; SIG0="$(csig "$CN")"
}
cj() { jq -r "$2" "$E/d/containers/$1.json" 2>/dev/null; }
# every setting but StopTimeout / Id / StartedAt, as the fixture wrote it
csig() { jq -cS 'del(.Id, .State, .Config.StopTimeout, .Config.Labels["com.docker.compose.project.config_files"])' "$E/d/containers/$1.json" 2>/dev/null; }
AS() { jq -r "$1" "$STATE_DIR/apply-$CN.json" 2>/dev/null; }
recreated() { [ -f "$E/d/calls" ] || { echo 0; return; }; grep -cE '^(run|compose up)' "$E/d/calls"; }
untouched() { # NAME: no stop/run/rename/compose up, .env + container as before, no overlay
  if [ "$(recreated)" = 0 ] && ! grep -qE '^(stop|rename|rm)' "$E/d/calls" 2>/dev/null && [ "$(csig "$CN")" = "$SIG0" ] \
     && [ "$(cj "$CN" '.Config.StopTimeout // "unset"')" = unset ] && [ ! -e "$E/root/opt/postfiatd/docker-compose.shutdown.yml" ] \
     && [ "$(cat "$E/root/opt/postfiatd/.env" 2>/dev/null)" = "$ENV0" ]; then ok "$1: nothing changed"
  else ko "$1: something changed" "$(cat "$E/d/calls" 2>/dev/null)"; fi
}
back_to_before() { # NAME: StopTimeout unset again, every other setting as before, .env as before, no overlay, one container
  if [ "$(cj "$CN" '.Config.StopTimeout // "unset"')" = unset ] && [ "$(csig "$CN")" = "$SIG0" ] \
     && [ ! -e "$E/root/opt/postfiatd/docker-compose.shutdown.yml" ] && [ "$(cat "$E/root/opt/postfiatd/.env" 2>/dev/null)" = "$ENV0" ] \
     && [ "$(find "$E/d/containers" -name '*.json' | wc -l)" = 1 ]; then ok "$1: back to the previous container/config"
  else ko "$1: not restored" "$(diff <(echo "$SIG0" | jq -S .) <(csig "$CN" | jq -S .); ls "$E/d/containers"; cat "$E/root/opt/postfiatd/.env")"; fi
}

# --- compose (validator)
afresh compose; run apply --yes
expect "apply compose -> PASS" 0 'apply RESULT: PASS - postfiatd StopTimeout 31s, configuration unchanged, node full'
expect "apply compose: basis p100 10.1 x 3" 0 'StopTimeout unset -> 31s \(p100 10.1s x 3 = 31s, floor 30s \(3 clean runs\)\)'
[ "$(cj "$CN" .Config.StopTimeout)" = 31 ] && ok "apply compose: container StopTimeout 31" || ko "apply compose: StopTimeout $(cj "$CN" .Config.StopTimeout)" "$OUT"
grep -qx '    stop_grace_period: 31s' "$E/root/opt/postfiatd/docker-compose.shutdown.yml" && ok "apply compose: overlay stop_grace_period 31s" || ko "apply compose: overlay" "$(cat "$E/root/opt/postfiatd/docker-compose.shutdown.yml")"
[ "$(cat "$E/root/opt/postfiatd/.env")" = "$(printf 'NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.seccomp.yml:docker-compose.shutdown.yml')" ] \
  && [ "$(stat -c %a "$E/root/opt/postfiatd/.env")" = 600 ] && ok "apply compose: COMPOSE_FILE keeps the other overlays + adds shutdown, mode 600 kept" || ko "apply compose: .env" "$(cat "$E/root/opt/postfiatd/.env")"
[ "$(csig "$CN")" = "$SIG0" ] && ok "apply compose: every other setting unchanged (live CpuShares 512 put back)" || ko "apply compose: settings" "$(diff <(echo "$SIG0" | jq -S .) <(csig "$CN" | jq -S .))"
grep -q '^compose up -d --timeout 31$' "$E/d/calls" && [ "$(recreated)" = 1 ] && ok "apply compose: one re-create, compose up --timeout 31" || ko "apply compose: calls" "$(cat "$E/d/calls")"
expect "apply compose: config validated" 0 'validated: docker compose config -> stop_grace_period 31s'
[ "$(AS .kind)" = compose ] && [ "$(AS .pre_stop)" = unset ] && [ -f "$(AS .env_backup)" ] && ok "apply compose: state + .env backup" || ko "apply compose: state" "$(cat "$STATE_DIR/apply-$CN.json")"
run apply --yes; expect "apply compose again -> nothing to do" 0 'already 31s .* nothing to do'
[ "$(recreated)" = 1 ] && ok "apply compose again: no second re-create (idempotent)" || ko "apply again re-created" "$(cat "$E/d/calls")"
run audit; expect "audit after apply: F2 PASS" 0 '\[PASS\] F2 container StopTimeout 31s >= required 31s'
expect "audit after apply: F3 PASS" 0 '\[PASS\] F3 compose stop_grace_period 31s >= required 31s'
run apply --yes --required 45; expect "apply another value while applied -> refused" 4 'still in place; rollback first'
run rollback; expect "rollback without --yes -> refused" 4 'refused: pass --yes'
run rollback --yes; expect "rollback compose -> PASS" 0 'rollback RESULT: PASS - postfiatd StopTimeout unset again'
back_to_before "rollback compose"
[ "$(AS .rolled_back)" = true ] && [ "$(AS .rollback)" = manual ] && ok "rollback compose: state rolled_back (manual)" || ko "rollback state"
run audit; expect "audit after rollback: F2+F3 FAIL again" 6 'RESULT: FAIL - exit 6'
run rollback --yes; expect "rollback twice -> nothing to do" 0 'already rolled back'
run apply --yes; expect "re-apply after rollback -> PASS" 0 'apply RESULT: PASS'
[ "$(cj "$CN" .Config.StopTimeout)" = 60 ] || [ "$(cj "$CN" .Config.StopTimeout)" = 31 ] && ok "re-apply: StopTimeout 31" || ko "re-apply" "$OUT"

afresh compose; touch "$E/d/fail_compose_up"; run apply --yes
expect "compose up fails -> rolled back, exit 1" 1 'rollback RESULT: PASS'
back_to_before "compose up fails"
afresh compose; PFT_SHUTDOWN_INJECT=gate run apply --yes
expect "gate fails (injected) -> exit 1" 1 'apply gate FAIL: configuration changed: injected'
expect "gate fails (injected): automatic rollback PASS" 1 'rollback \(auto\) of apply .* rollback RESULT: PASS|rollback RESULT: PASS'
back_to_before "gate fails"
[ "$(AS .rollback)" = auto ] && ok "gate fails: state rollback auto" || ko "gate fails: state"
afresh compose; echo 5s > "$E/d/config_grace"
run apply --yes; expect "compose config does not give the value -> validation rolls back" 1 "compose config gives stop_grace_period '5s', not 31s"
[ ! -e "$E/root/opt/postfiatd/docker-compose.shutdown.yml" ] && [ "$(cat "$E/root/opt/postfiatd/.env")" = "$ENV0" ] && [ "$(recreated)" = 0 ] \
  && ok "validation failure: overlay removed, .env restored, nothing re-created" || ko "validation failure" "$(cat "$E/d/calls")"

# refusals
afresh compose; run apply; expect "apply without --yes -> 4" 4 'refused: pass --yes'; untouched "no --yes"
afresh compose; touch "$E/d/nomaint"; run apply --yes; expect "no maint window -> 4" 4 'refused: no active pft-maint window'; untouched "no window"
afresh compose; rm "$STATE_DIR/measure-$CN.json"; run apply --yes; expect "no measurements -> 4" 4 'refused: no measured basis'; untouched "no measurements"
afresh compose; jq '.runs |= .[1:]' "$STATE_DIR/measure-$CN.json" > "$E/m" && mv "$E/m" "$STATE_DIR/measure-$CN.json"; run apply --yes
expect "2 clean runs < MIN_RUNS 3 -> 4" 4 'fewer than MIN_RUNS=3 clean measured stops'; untouched "2 runs"
afresh compose; jq '.["agtipft/postfiatd:testnet-light-latest"].Id = "sha256:img2"' "$E/d/images.json" > "$E/m" && mv "$E/m" "$E/d/images.json"
run apply --yes; expect "tag moved to another image -> 4" 4 'no longer names the running image'; untouched "tag moved"
afresh compose; touch "$E/d/notfull"; run apply --yes; expect "node not full -> 4" 4 'server_state is syncing'; untouched "not full"
afresh compose; run apply --yes --required 45; expect "--required 45 overrides the basis" 0 'StopTimeout unset -> 45s \(--required\)'

# --- docker run (sentry)
afresh run; run apply --yes
expect "apply run -> PASS" 0 'apply RESULT: PASS - postfiatd-sentry StopTimeout 31s, configuration unchanged, node full'
[ "$(cj "$CN" .Config.StopTimeout)" = 31 ] && ok "apply run: container StopTimeout 31" || ko "apply run: StopTimeout" "$OUT"
[ "$(csig "$CN")" = "$SIG0" ] && ok "apply run: every other setting unchanged (incl. inline seccomp, AppArmor, caps, tmpfs, mounts, ports)" \
  || ko "apply run: settings" "$(diff <(echo "$SIG0" | jq -S .) <(csig "$CN" | jq -S .))"
grep -q '^stop -t 31 postfiatd-sentry$' "$E/d/calls" && grep -q -- '--stop-timeout=31' "$E/d/calls" && [ "$(recreated)" = 1 ] \
  && ok "apply run: stop -t 31, one docker run with --stop-timeout=31" || ko "apply run: calls" "$(cat "$E/d/calls")"
[ "$(find "$E/d/containers" -name '*.json' | wc -l)" = 1 ] && expect "apply run: previous container removed" 0 'previous container postfiatd-sentry-preshutdown-.*-apply removed \(volumes kept\)' \
  || ko "apply run: leftover containers" "$(ls "$E/d/containers")"
grep -q '^rm postfiatd-sentry-preshutdown-' "$E/d/calls" && ! grep -q '^rm -v\|^rm -f postfiatd-sentry-preshutdown' "$E/d/calls" && ok "apply run: old container removed without -v/-f" || ko "apply run: rm" "$(grep '^rm' "$E/d/calls")"
grep -q '203\.0\.113\.7\|NETWORK=testnet' <<<"$OUT" && ko "apply run: IP or env value printed" "$OUT" || ok "apply run: IP and env values masked"
run apply --yes; expect "apply run again -> nothing to do" 0 'nothing to do'
run audit; expect "audit after run apply: F2 + F3 PASS" 0 '\[PASS\] F3 docker run container: every recreate tool carries --stop-timeout \(/usr/local/bin/pft-seccomp\)'
run rollback --yes; expect "rollback run -> PASS" 0 'rollback RESULT: PASS - postfiatd-sentry StopTimeout unset again'
back_to_before "rollback run"
grep -q -- '--stop-timeout' <<<"$(grep '^run' "$E/d/calls" | tail -1)" && ko "rollback run: re-created with a stop timeout" || ok "rollback run: re-created without --stop-timeout"

afresh run; touch "$E/d/run_drop_tmpfs"; t0=$SECONDS; RECOVER_TIMEOUT=30 run apply --yes
[ $((SECONDS - t0)) -lt 15 ] && ok "lost setting: gate fails at once (does not wait RECOVER_TIMEOUT 30 s)" || ko "lost setting: gate waited $((SECONDS - t0))s"
expect "run re-create loses a setting -> gate FAIL" 1 'apply gate FAIL: configuration changed: tmpfs'
expect "lost setting: previous container restored" 1 'previous container restored as postfiatd-sentry \(restart=unless-stopped\)'
back_to_before "lost setting"
[ "$(cj "$CN" .HostConfig.RestartPolicy.Name)" = unless-stopped ] && ok "lost setting: restart policy back to unless-stopped" || ko "lost setting: restart"
afresh run; touch "$E/d/run_drop_stop_timeout"; run apply --yes
expect "run re-create without the stop timeout -> gate FAIL" 1 'apply gate FAIL: StopTimeout unset want 31;'
back_to_before "stop timeout lost"
afresh run; touch "$E/d/fail_run"; run apply --yes
expect "docker run fails -> exit 1, rolled back" 1 'rollback RESULT: PASS'
back_to_before "docker run fails"
afresh run; rm "$E/root/etc/pft-seccomp/pft-postfiatd.json"; run apply --yes
expect "seccomp profile file missing -> 4" 4 'SECCOMP_FILE /etc/pft-seccomp/pft-postfiatd.json is missing'; untouched "seccomp file missing"
afresh run; run rollback --yes; expect "rollback without apply state -> 4" 4 'no apply state'
