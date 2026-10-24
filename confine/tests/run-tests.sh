#!/usr/bin/env bash
# "cond && ok || bad" is intended: ok() always returns 0, so bad runs only when cond fails.
# shellcheck disable=SC2015
# Offline test suite for pft-confine.sh - no root, no node, no docker: the docker CLI, server_info and pft-maint
# are stubs and the clock is fake (PFT_CONFINE_NOW_FILE, every poll sleep advances it). Compose-mode cases use a
# temp project dir with a real .env, so the .env backup/COMPOSE_FILE edit and its rollback are the real code paths.
# server_info stub: the 1st call (apply's pre-check) answers full; later calls answer the case's "after" state,
# except once the previous config is back (compose up without docker-compose.confine.yml, or the old container
# renamed back) - then full.
# Usage: bash confine/tests/run-tests.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PC="$HERE/../pft-confine.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }
ind() { sed 's/^/    /'; }

# --- stubs ---
cat > "$WORK/docker" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/docker.log"
case "$1" in
  inspect) cat "$STUB_DIR/inspect.json" ;;
  diff) cat "$STUB_DIR/diff.txt" ;;
  exec) case "$*" in
          *VmRSS*) cat "$STUB_DIR/procs.txt" ;;
          *"while read"*) cat >/dev/null; printf '%s\n' /var/opt/postfiat ;;
        esac ;;
  image) echo '[{"Config":{"Env":["PATH=/usr/local/sbin:/usr/bin"]}}]' ;;
  compose) case "$2" in
             up) [ -e "$STUB_DIR/fail-up" ] && exit 1
                 [ -e docker-compose.confine.yml ] || touch "$STUB_DIR/restored" ;;
           esac ;;
  rename) case "$2" in *-preconfine-*) touch "$STUB_DIR/restored" ;; esac ;;
  run) [ -e "$STUB_DIR/fail-run" ] && exit 1; echo deadbeef ;;
esac
exit 0
EOF
cat > "$WORK/rpc" <<'EOF'
#!/usr/bin/env bash
n="$(cat "$STUB_DIR/rpc.n" 2>/dev/null || echo 0)"; n=$((n + 1)); echo "$n" > "$STUB_DIR/rpc.n"
s="$(cat "$STUB_DIR/after")"
{ [ "$n" -eq 1 ] || [ -e "$STUB_DIR/restored" ]; } && s=full
echo "{\"info\":{\"server_state\":\"$s\",\"peers\":11}}"
EOF
cat > "$WORK/maint" <<'EOF'
#!/usr/bin/env bash
cat "$STUB_DIR/maint.json"
EOF
chmod +x "$WORK/docker" "$WORK/rpc" "$WORK/maint"

WIN_OK='{"window":"active","remaining_sec":3600,"locks":[]}'

# inspect_json MODE PROJDIR [confined] -> docker inspect output
inspect_json() {
  jq -n --arg mode "$1" --arg wd "$2" --arg conf "${3:-}" '
    [{Name: "/postfiatd", Id: "0123456789abcdef", Image: "sha256:cc13", RestartCount: 0,
      Config: {Image: "agtipft/postfiatd:testnet-light-latest", User: "0:0", Cmd: ["--conf", "/etc/postfiatd/postfiatd.cfg"],
               Env: ["PATH=/usr/local/sbin:/usr/bin", "EXTRA=1"],
               Labels: (if $mode == "compose" then {"com.docker.compose.project.working_dir": $wd,
                         "com.docker.compose.project.config_files": "\($wd)/docker-compose.yml,\($wd)/docker-compose.override.yml",
                         "com.docker.compose.service": "postfiatd"} else {} end)},
      State: {Running: true, OOMKilled: false, StartedAt: "2027-01-15T07:00:00Z"},
      HostConfig: ({CapAdd: null, CapDrop: null, ReadonlyRootfs: false, PidsLimit: null, Memory: 0, NanoCpus: 0,
                    Tmpfs: null, SecurityOpt: ["no-new-privileges:true"],
                    RestartPolicy: {Name: "unless-stopped", MaximumRetryCount: 0},
                    LogConfig: {Type: "json-file", Config: {"max-size": "100m", "max-file": "10"}},
                    NetworkMode: "bridge", PortBindings: {"2559/tcp": [{HostIp: "", HostPort: "2559"}]}}
                   + (if $conf != "" then {CapAdd: ["CAP_SETGID", "CAP_SETUID"], CapDrop: ["ALL"], ReadonlyRootfs: true,
                        PidsLimit: 256, Memory: 2415919104,
                        Tmpfs: {"/run": "", "/tmp": "", "/var/backups": "", "/var/lib/apt": "", "/var/lib/logrotate": "", "/var/opt/postfiat": ""}}
                      else {} end)),
      Mounts: [{Type: "volume", Name: "pfd-config", Source: "/v/c", Destination: "/etc/postfiatd", RW: true},
               {Type: "volume", Name: "pfd-data", Source: "/v/d", Destination: "/var/lib/postfiatd/db", RW: true},
               {Type: "bind", Source: "\($wd)/logs", Destination: "/var/log/postfiatd", RW: true}]}]'
}

# setup NAME MODE -> fresh case dir: stubs' data, a compose project dir with .env, window open, node full
setup() {
  C="$WORK/$1"; P="$C/proj"; mkdir -p "$P" "$C/state"
  printf 'NETWORK=testnet\n' > "$P/.env"; chmod 600 "$P/.env"
  echo 'services: {}' > "$P/docker-compose.yml"
  inspect_json "$2" "$P" > "$C/inspect.json"
  printf 'C /run\nA /run/crond.pid\nC /var\nC /var/backups\nA /var/backups/dpkg.status.0\nC /var/lib/logrotate\nA /var/lib/logrotate/status\nC /var/lib/apt\nA /var/lib/apt/daily_lock\nC /var/opt\nA /var/opt/postfiat\nA /var/lib/postfiatd/db/x.db\nA /var/log/postfiatd/debug.log\n' > "$C/diff.txt"
  printf 'VmRSS: 724000\nThreads: 30\nTasks: 35\nProc: cron\nProc: postfiatd\nWfile: /run/crond.pid\nWfile: /var/lib/postfiatd/db/ledger.db\n' > "$C/procs.txt"
  printf 'MemTotal: 8127000 kB\n' > "$C/meminfo"
  echo "$WIN_OK" > "$C/maint.json"; echo full > "$C/after"; echo 1800000000 > "$C/now"; : > "$C/docker.log"
}
run() { # run pft-confine with the case's stubs; output -> $C/out, exit code -> $rc
  ( cd "$C" && STUB_DIR="$C" PFT_CONFINE_TEST=1 PFT_CONFINE_DOCKER_CMD="$WORK/docker" PFT_CONFINE_RPC_CMD="$WORK/rpc" \
      PFT_CONFINE_MAINT_CMD="$WORK/maint" PFT_CONFINE_NOW_FILE="$C/now" PFT_CONFINE_MEMINFO="$C/meminfo" \
      STATE_DIR="$C/state" POLL_SEC=10 bash "$PC" "$@" ) > "$C/out" 2>&1
  rc=$?
}

echo "# pft-confine offline tests - $(date -u +%FT%TZ) - script sha256 $(sha256sum "$PC" | cut -c1-16)"

# 1. plan generation
setup plan compose; run plan --json; J="$(cat "$C/out")"
[ "$rc" = 0 ] && ok "1a plan exits 0" || { bad "1a plan rc=$rc"; ind < "$C/out"; }
[ "$(jq -c .tmpfs <<<"$J")" = '["/run","/tmp","/var/backups","/var/lib/apt","/var/lib/logrotate","/var/opt/postfiat"]' ] \
  && ok "1b tmpfs = /tmp + written dirs outside mounts (file -> parent, added dir -> itself, mounts ignored)" || bad "1b tmpfs $(jq -c .tmpfs <<<"$J")"
[ "$(jq -c '[.cap_drop, .cap_add]' <<<"$J")" = '[["ALL"],["SETGID","SETUID"]]' ] && ok "1c cap_drop ALL, cap_add SETGID SETUID because cron runs" || bad "1c caps $(jq -c '[.cap_drop,.cap_add]' <<<"$J")"
[ "$(jq .memory_bytes <<<"$J")" = $((2304 * 1048576)) ] && ok "1d memory = 3 x RSS 707 MiB -> 2304 MiB (256 MiB steps)" || bad "1d memory $(jq .memory_bytes <<<"$J")"
[ "$(jq .pids_limit <<<"$J")" = 256 ] && ok "1e pids_limit = max(256, 4 x 35)" || bad "1e pids $(jq .pids_limit <<<"$J")"
[ "$(jq -c .security_opt <<<"$J")" = '["no-new-privileges"]' ] && [ "$(jq .read_only <<<"$J")" = true ] && ok "1f read_only + no-new-privileges kept" || bad "1f"
sed -i 's/^VmRSS: .*/VmRSS: 200000/' "$C/procs.txt"; sed -i 's/^Proc: cron$//' "$C/procs.txt"; run plan --json; J="$(cat "$C/out")"
[ "$(jq .memory_bytes <<<"$J")" = $((2048 * 1048576)) ] && [ "$(jq -c .cap_add <<<"$J")" = '[]' ] \
  && ok "1g small RSS -> 2048 MiB floor; no cron -> no capabilities" || bad "1g $(jq -c '[.memory_bytes,.cap_add]' <<<"$J")"
printf 'A /var/x.lock\n' >> "$C/diff.txt"; run plan --json
[ "$(jq -c .unresolved "$C/out")" = '["/var"]' ] && ! jq -e '.tmpfs | index("/var")' "$C/out" >/dev/null \
  && ok "1h a write directly in /var is never mounted over - listed as unresolved" || bad "1h $(jq -c '[.tmpfs,.unresolved]' "$C/out")"
CONFINE_CAP_ADD=none CONFINE_TMPFS=/tmp run plan --json
[ "$(jq -c '[.cap_add,.tmpfs]' "$C/out")" = '[[],["/tmp"]]' ] && ok "1i CONFINE_CAP_ADD=none / CONFINE_TMPFS overrides" || bad "1i $(jq -c '[.cap_add,.tmpfs]' "$C/out")"
setup planrun run; run plan
grep -q -- '--cap-drop=ALL' "$C/out" && grep -q -- '--tmpfs=/run:rw,noexec,nosuid,size=64m' "$C/out" && grep -q -- '--volume=pfd-data:/var/lib/postfiatd/db' "$C/out" \
  && grep -q -- '--env=EXTRA=1' "$C/out" && ! grep -q -- '--env=PATH' "$C/out" && grep -q -- '--restart=unless-stopped' "$C/out" \
  && ok "1j run-mode plan shows the recreate command (profile + mounts, ports, restart, non-image env only)" || { bad "1j"; ind < "$C/out"; }

# 2. refusals
setup noyes compose; run apply
[ "$rc" = 4 ] && grep -q -- '--yes' "$C/out" && ! grep -qE '^(compose|stop|run)' "$C/docker.log" && [ ! -e "$C/proj/docker-compose.confine.yml" ] \
  && ok "2a apply without --yes refused (exit 4), nothing changed" || { bad "2a rc=$rc"; ind < "$C/out"; }
setup nowin compose; echo '{"window":"none","remaining_sec":null,"locks":[]}' > "$C/maint.json"; run apply --yes
[ "$rc" = 4 ] && grep -q 'no active pft-maint window' "$C/out" && ! grep -qE '^(compose|stop|run)' "$C/docker.log" && cmp -s "$C/proj/.env" <(printf 'NETWORK=testnet\n') \
  && ok "2b apply without a maintenance window refused (exit 4), nothing changed" || { bad "2b rc=$rc"; ind < "$C/out"; }
setup short compose; echo '{"window":"active","remaining_sec":900,"locks":[]}' > "$C/maint.json"; run apply --yes
[ "$rc" = 4 ] && grep -q 'apply needs TIMEOUT+MAINT_MARGIN=1200s' "$C/out" && ok "2c window shorter than TIMEOUT+300s refused" || { bad "2c rc=$rc"; ind < "$C/out"; }
setup locked compose; echo '{"window":"active","remaining_sec":3600,"locks":["vlwatch 24h"]}' > "$C/maint.json"; run apply --yes
[ "$rc" = 4 ] && grep -q 'data-collection lock' "$C/out" && ok "2d data-collection lock refused" || { bad "2d rc=$rc"; ind < "$C/out"; }
setup notfull run; echo syncing > "$C/after"; echo 1 > "$C/rpc.n"; run apply --yes
[ "$rc" = 4 ] && grep -q 'node is syncing, not full' "$C/out" && ! grep -qE '^(stop|run)' "$C/docker.log" && ok "2e node not full refused" || { bad "2e rc=$rc"; ind < "$C/out"; }

# 3. apply success
setup okcompose compose; run apply --yes
E="$C/proj/.env"
[ "$rc" = 0 ] && grep -q 'apply RESULT: PASS' "$C/out" && grep -qx 'COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml' "$E" \
  && grep -qx 'NETWORK=testnet' "$E" && [ "$(stat -c %a "$E")" = 600 ] && grep -q 'cap_drop:' "$C/proj/docker-compose.confine.yml" \
  && grep -q '^compose config -q' "$C/docker.log" && grep -q '^compose up -d' "$C/docker.log" \
  && ok "3a compose apply: confine file written, .env keeps vars + mode 600, COMPOSE_FILE added, config checked, up -d" || { bad "3a rc=$rc"; ind < "$C/out"; ind < "$E"; }
cmp -s "$(ls "$C"/proj/.env.pre-confine-*)" <(printf 'NETWORK=testnet\n') && jq -e '.applied_at and .mode == "compose"' "$C/state/postfiatd.json" >/dev/null \
  && ok "3b .env backup is the original; state file records the apply" || bad "3b"
setup okrun run; run apply --yes
grep -q '^stop -t 60 postfiatd' "$C/docker.log" && grep -q '^rename postfiatd postfiatd-preconfine-20270115T080000Z' "$C/docker.log" \
  && grep -q '^update --restart=no postfiatd-preconfine-' "$C/docker.log" && grep -q '^run -d --cap-drop=ALL .*--read-only .*--name=postfiatd .*agtipft/postfiatd:testnet-light-latest --conf /etc/postfiatd/postfiatd.cfg$' "$C/docker.log" \
  && [ "$rc" = 0 ] && ok "3c run-mode apply: stop, keep old as NAME-preconfine-<id> (restart=no), recreate with profile" || { bad "3c rc=$rc"; ind < "$C/out"; ind < "$C/docker.log"; }

# 4. rollback when the node never reaches full
setup rbcompose compose; echo connected > "$C/after"; run apply --yes
[ "$rc" = 1 ] && grep -q 'node not full within 900s - rolling back' "$C/out" && grep -q 'rollback complete' "$C/out" \
  && cmp -s "$C/proj/.env" <(printf 'NETWORK=testnet\n') && [ ! -e "$C/proj/docker-compose.confine.yml" ] && [ "$(grep -c '^compose up -d' "$C/docker.log")" = 2 ] \
  && ok "4a compose: never full -> rollback after 900 s (.env restored byte-identical, confine file removed, up -d again), exit 1" || { bad "4a rc=$rc"; ind < "$C/out"; }
[ "$(cat "$C/now")" -ge $((1800000000 + 900)) ] && [ "$(cat "$C/now")" -lt $((1800000000 + 960)) ] && ok "4b rollback started at the 900 s timeout, not before" || bad "4b now=$(cat "$C/now")"
setup rbrun run; echo connected > "$C/after"; run apply --yes
[ "$rc" = 1 ] && grep -q '^rm -f postfiatd' "$C/docker.log" && grep -q '^rename postfiatd-preconfine-[0-9TZ]* postfiatd' "$C/docker.log" \
  && grep -q '^update --restart=unless-stopped postfiatd' "$C/docker.log" && grep -q '^start postfiatd' "$C/docker.log" && jq -e .rolled_back "$C/state/postfiatd.json" >/dev/null \
  && ok "4c run mode: never full -> new container removed, old renamed back, restart policy restored, started" || { bad "4c rc=$rc"; ind < "$C/out"; ind < "$C/docker.log"; }
setup rbfail run; touch "$C/fail-run"; run apply --yes
[ "$rc" = 1 ] && grep -q 'docker run failed' "$C/out" && grep -q 'rollback complete' "$C/out" && ok "4d docker run fails -> immediate rollback" || { bad "4d rc=$rc"; ind < "$C/out"; }
setup rbmanual compose; run apply --yes; rm -f "$C/restored"; run rollback
[ "$rc" = 4 ] && ok "4e manual rollback needs --yes" || bad "4e rc=$rc"
run rollback --yes
[ "$rc" = 0 ] && cmp -s "$C/proj/.env" <(printf 'NETWORK=testnet\n') && [ ! -e "$C/proj/docker-compose.confine.yml" ] && ok "4f manual rollback --yes restores the previous compose config" || { bad "4f rc=$rc"; ind < "$C/out"; }

# 5. verify
setup vok compose; inspect_json compose "$C/proj" confined > "$C/inspect.json"; run verify --min-uptime 3600
[ "$rc" = 0 ] && grep -q 'RESULT: PASS' "$C/out" && grep -q 'uptime 3600s >= 3600s' "$C/out" && ok "5a verify PASS on a confined container (all items, 1 h uptime)" || { bad "5a rc=$rc"; ind < "$C/out"; }
run verify --min-uptime 3601
[ "$rc" = 1 ] && grep -q '\[FAIL\] uptime 3600s >= 3601s' "$C/out" && ok "5b verify FAILs when uptime < --min-uptime" || { bad "5b rc=$rc"; ind < "$C/out"; }
setup vbad compose; run verify
[ "$rc" = 1 ] && [ "$(grep -c '\[FAIL\]' "$C/out")" = 8 ] && grep -q 'no limit set' "$C/out" && ok "5c verify on an unconfined container FAILs the 6 profile items + RSS/tasks (no limits)" || { bad "5c rc=$rc"; ind < "$C/out"; }
setup voom compose; inspect_json compose "$C/proj" confined | jq '.[0].State.OOMKilled = true | .[0].RestartCount = 2' > "$C/inspect.json"
sed -i 's/^VmRSS: .*/VmRSS: 2400000/' "$C/procs.txt"; echo 1 > "$C/rpc.n"; echo connected > "$C/after"; run verify
grep -q '\[FAIL\] running, OOMKilled=true' "$C/out" && grep -q '\[FAIL\] restart count 2' "$C/out" && grep -q '\[FAIL\] PID1 RSS 2343 MiB < limit 2304 MiB' "$C/out" \
  && grep -q '\[FAIL\] server_state connected' "$C/out" && [ "$rc" = 1 ] && ok "5d verify FAILs on OOMKilled, restarts, RSS over limit, not full" || { bad "5d rc=$rc"; ind < "$C/out"; }

echo "# $pass passed, $fail failed"
[ "$fail" -eq 0 ]
