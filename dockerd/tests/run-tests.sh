#!/usr/bin/env bash
# Offline tests for pft-dockerd.sh: every audit check passes on a good fixture and fails on its bad fixture,
# --json, plan/dry-run, the bad-key refusal, reload-before-restart, the health-gated automatic rollback
# (byte-identical daemon.json), auditd immutable staging, idempotence and rollback. No root, no docker.
# Usage: tests/run-tests.sh [path/to/pft-dockerd.sh]
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-dockerd.sh}"
# shellcheck source=tests/stubs.sh
. "$HERE/stubs.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -15; }
fresh() { N=$((N + 1)); E="$T/e$N"; mk_env "$E"; use_env "$E"; }
run() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
expect() { # NAME RC REGEX
  if [ "$RC" = "$2" ] && grep -qE -- "$3" <<<"$OUT"; then ok "$1"; else ko "$1 (rc=$RC want $2, /$3/)" "$OUT"; fi
}
good() { # a fully hardened fake host
  printf '{"live-restore":true,"no-new-privileges":true,"log-driver":"json-file","log-opts":{"max-size":"100m","max-file":"5"}}\n' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"
  cp "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" "$STUB_S/loaded.json"
  printf -- '-w /run/containerd -p wa\n-w /lib/systemd/system/docker.service -p wa\n-w /lib/systemd/system/docker.socket -p wa\n-w /usr/bin/containerd-shim-runc-v2 -p wa\n-w /usr/bin/runc -p wa\n' >> "$STUB_S/rules"
}

# --- audit: good fixture
fresh; good; run audit; expect "audit good host -> PASS exit 0" 0 '^RESULT: PASS$'
if grep -q '\[FAIL' <<<"$OUT"; then ko "good host has no FAIL lines" "$OUT"; else ok "good host has no FAIL lines"; fi
run audit --json
if [ "$RC" = 0 ] && jq -e '.result=="PASS" and .fails==0 and (.checks|length) > 30 and (.checks|all(has("cis")))' <<<"$OUT" >/dev/null; then ok "--json good host"; else ko "--json good host" "$OUT"; fi

# --- audit: one bad fixture per check (NAME | setup | expected FAIL line regex)
while IFS='|' read -r name setup want; do
  [ -z "$name" ] && continue
  fresh; good; eval "$setup"; run audit
  expect "audit $name -> FAIL" 1 "$want"
done <<'CASES'
live-restore off|echo '{}' > "$STUB_S/loaded.json"|\[FAIL +\] 2.14 +live-restore
no-new-privileges missing|jq 'del(."no-new-privileges")' "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" > x && mv x "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"|\[FAIL +\] 2.18 +no-new-privileges
log max-size missing|jq 'del(."log-opts")' "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" > x && mv x "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"|\[FAIL +\] n/a +log-rotation
hosts tcp in daemon.json|jq '.hosts=["unix:///run/docker.sock","tcp://0.0.0.0:2375"]' "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" > x && mv x "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"|\[FAIL +\] 2.7 +tcp-socket
-H tcp on cmdline|echo "-H tcp://0.0.0.0:2376" > "$STUB_S/extra_args"|\[FAIL +\] 2.7 +tcp-socket
dockerd TCP listener|echo 'LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:(("dockerd",pid=9,fd=7))' >> "$STUB_S/ss"|\[FAIL +\] 2.7 +tcp-socket
insecure registry CIDR|jq '.RegistryConfig.InsecureRegistryCIDRs += ["10.0.0.0/8"]' "$STUB_S/info.json" > x && mv x "$STUB_S/info.json"|\[FAIL +\] 2.5 +insecure-registries .*1 non-loopback
insecure registry name|jq '.RegistryConfig.IndexConfigs["reg.example:5000"]={"Name":"reg.example:5000","Secure":false}' "$STUB_S/info.json" > x && mv x "$STUB_S/info.json"|\[FAIL +\] 2.5 +insecure-registries
iptables=false|jq '.iptables=false' "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" > x && mv x "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"|\[FAIL +\] 2.4 +iptables
experimental on|jq '.ExperimentalBuild=true' "$STUB_S/info.json" > x && mv x "$STUB_S/info.json"|\[FAIL +\] 2.17 +experimental
no seccomp|jq '.SecurityOptions=["name=apparmor"]' "$STUB_S/info.json" > x && mv x "$STUB_S/info.json"|\[FAIL +\] 2.16 +seccomp
no apparmor|jq '.SecurityOptions=["name=seccomp,profile=builtin"]' "$STUB_S/info.json" > x && mv x "$STUB_S/info.json"|\[FAIL +\] n/a +apparmor
swarm active|jq '.Swarm.LocalNodeState="active"' "$STUB_S/info.json" > x && mv x "$STUB_S/info.json"|\[FAIL +\] 7.1 +swarm
daemon.json not an object|echo '[1]' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"|\[FAIL +\] 3.17 +daemon-json
docker.service mode 666|sed -i 's#^/lib/systemd/system/docker.service .*#/lib/systemd/system/docker.service 666 root:root#' "$STUB_S/perms"|\[FAIL +\] 3.1-3.2 .*mode 666
docker.socket owner|sed -i 's#^/lib/systemd/system/docker.socket .*#/lib/systemd/system/docker.socket 644 user:user#' "$STUB_S/perms"|\[FAIL +\] 3.3-3.4 .*owner user:user
/etc/docker mode 777|sed -i 's#^/etc/docker .*#/etc/docker 777 root:root#' "$STUB_S/perms"|\[FAIL +\] 3.5-3.6
docker.sock mode 666|sed -i 's#^/run/docker.sock .*#/run/docker.sock 666 root:docker#' "$STUB_S/perms"|\[FAIL +\] 3.15-3.16 .*mode 666
docker.sock owner root:root|sed -i 's#^/run/docker.sock .*#/run/docker.sock 660 root:root#' "$STUB_S/perms"|\[FAIL +\] 3.15-3.16 .*owner root:root
daemon.json mode 664|sed -i 's#^/etc/docker/daemon.json .*#/etc/docker/daemon.json 664 root:root#' "$STUB_S/perms"|\[FAIL +\] 3.17-3.18 .*mode 664
/etc/default/docker mode 666|touch "$PFT_DOCKERD_ROOT/etc/default" 2>/dev/null; rm -f "$PFT_DOCKERD_ROOT/etc/default"; mkdir -p "$PFT_DOCKERD_ROOT/etc/default"; : > "$PFT_DOCKERD_ROOT/etc/default/docker"; echo "/etc/default/docker 666 root:root" >> "$STUB_S/perms"|\[FAIL +\] 3.19-3.20
containerd.sock mode 666|sed -i 's#^/run/containerd/containerd.sock .*#/run/containerd/containerd.sock 666 root:root#' "$STUB_S/perms"|\[FAIL +\] 3.23-3.24
audit dockerd missing|sed -i '\#^-w /usr/bin/dockerd #d' "$STUB_S/rules"|\[FAIL +\] 1.1.3 +audit:/usr/bin/dockerd +no auditd watch
audit /run/containerd missing|sed -i '\#^-w /run/containerd #d' "$STUB_S/rules"|\[FAIL +\] 1.1.4 +audit:/run/containerd +no auditd
audit docker.service missing|sed -i '\#docker.service #d' "$STUB_S/rules"|\[FAIL +\] 1.1.7 +audit:/lib/systemd/system/docker.service
audit runc missing|sed -i '\#/usr/bin/runc #d' "$STUB_S/rules"|\[FAIL +\] 1.1.18 +audit:/usr/bin/runc
audit /etc/docker missing|sed -i '\#^-w /etc/docker #d' "$STUB_S/rules"|\[FAIL +\] 1.1.6 +audit:/etc/docker
CASES

# containerd.sock covered by the /run/containerd dir watch; daemon.json by /etc/docker; a prefix must not count
fresh; good; run audit
expect "containerd.sock covered by /run/containerd watch" 0 '\[PASS +\] 1.1.8 +audit:/run/containerd/containerd.sock +watched'
expect "daemon.json covered by /etc/docker watch" 0 '\[PASS +\] 1.1.11 +audit:/etc/docker/daemon.json +watched'
fresh; good; sed -i 's#^-w /usr/bin/runc #-w /usr/bin/runcx #' "$STUB_S/rules"; run audit
expect "watch on a longer path (/usr/bin/runcx) does not cover runc" 1 '\[FAIL +\] 1.1.18 +audit:/usr/bin/runc +no auditd'
fresh; good; printf 'docker:x:999:alice,bob\n' > "$STUB_S/group"; run audit
expect "docker group members counted, never named" 0 'INFO +\] 1.1.2 +docker-group +2 member'
grep -qE 'alice|bob' <<<"$OUT" && ko "group member names not printed" "$OUT" || ok "group member names not printed"
fresh; good; jq '.icc=false | ."userland-proxy"=false' "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" > "$E/x" && mv "$E/x" "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"; run audit
expect "explicit false is reported as false (jq // trap)" 0 'DECISION\] 2.15 +userland-proxy +userland-proxy=false'
expect "icc=false reported" 0 'DECISION\] 2.2 +icc +icc=false'
fresh; good; run audit
expect "decisions listed (icc, userland-proxy, userns-remap)" 0 'DECISION\] 2.2 +icc.*'
grep -c 'DECISION' <<<"$OUT" | grep -qx 5 && ok "5 DECISION lines" || ko "5 DECISION lines" "$OUT"
fresh; good; chmod 000 "$E/bin/docker"; run audit; expect "docker info failure -> exit 2" 2 'docker info failed'

# --- plan / dry-run / bad key
fresh; run plan
if [ "$RC" = 0 ] && grep -q '"live-restore": true' <<<"$OUT" && grep -q -- '-w /usr/bin/runc -p wa -k pft-dockerd' <<<"$OUT"; then ok "plan prints merged json + missing watches"; else ko plan "$OUT"; fi
grep -q -- '-w /usr/bin/dockerd ' <<<"$OUT" && ko "plan omits watches already loaded" "$OUT" || ok "plan omits watches already loaded"
fresh; run apply --dry-run
expect "apply --dry-run" 0 'dry run, nothing changed'
[ ! -e "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" ] && ! grep -q systemctl "$STUB_S/calls" && ok "dry-run changed nothing" || ko "dry-run changed nothing" "$(cat "$STUB_S/calls")"
fresh; run apply; expect "apply without --yes refused" 4 'needs --yes'
fresh; echo '{"debug":false}' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"; s0="$(sha256sum < "$PFT_DOCKERD_ROOT/etc/docker/daemon.json")"
PFT_DOCKERD_INJECT=bad-key run apply --yes
expect "injected bad key -> REFUSED exit 4" 4 'REFUSED - candidate failed dockerd --validate'
[ "$(sha256sum < "$PFT_DOCKERD_ROOT/etc/docker/daemon.json")" = "$s0" ] && ! grep -q systemctl "$STUB_S/calls" && ok "bad key: daemon.json byte-identical, dockerd untouched" || ko "bad key: file untouched" "$OUT"
fresh; echo '{"labels":["no-equals-sign"]}' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"; run apply --yes
expect "label without key=value -> REFUSED exit 4 (stub mirrors dockerd)" 4 'REFUSED - candidate failed dockerd --validate'
fresh; echo '{not json' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"; run apply --yes
expect "unparseable daemon.json -> refused" 4 'cannot merge'

# --- apply happy path from an absent daemon.json
fresh; run apply --yes
expect "apply from absent -> done" 0 'apply: done'
expect "live-restore enabled by reload first" 0 'live-restore enabled by reload \(no restart\); snapshot unchanged: yes'
expect "health gate PASS" 0 'health: PASS'
r="$(grep -n 'systemctl reload' "$STUB_S/calls" | cut -d: -f1)"; s="$(grep -n 'systemctl restart' "$STUB_S/calls" | head -1 | cut -d: -f1)"
[ -n "$r" ] && [ -n "$s" ] && [ "$r" -lt "$s" ] && ok "reload happens before restart" || ko "reload before restart" "$(cat "$STUB_S/calls")"
grep -q 'augenrules --load' "$STUB_S/calls" && ok "audit watches loaded" || ko "audit watches loaded" "$OUT"
run audit; expect "re-audit after apply -> PASS" 0 '^RESULT: PASS$'
run apply --yes; expect "second apply -> no change" 0 'already as planned \(no change\)'
[ "$(grep -c 'systemctl restart' "$STUB_S/calls")" = 1 ] && ok "second apply did not restart dockerd" || ko "no second restart" "$(cat "$STUB_S/calls")"
expect "second apply: watches complete" 0 'auditd watches already complete'

# existing keys are kept, never overwritten
fresh; echo '{"log-opts":{"max-size":"10m"},"debug":true}' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"; cp "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" "$STUB_S/loaded.json"
run apply --yes
expect "conflicting existing key kept + reported" 0 'kept existing log-opts='
jq -e '."log-opts"=={"max-size":"10m"} and .debug==true and ."live-restore"==true' "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" >/dev/null && ok "merge kept log-opts/debug, added live-restore" || ko merge "$(cat "$PFT_DOCKERD_ROOT/etc/docker/daemon.json")"

# --- health-gated automatic rollback
fresh; printf '{"debug":false}\n' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"; cp "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" "$E/pre"
PFT_DOCKERD_INJECT=health run apply --yes
expect "injected health miss -> rollback exit 1" 1 'health gate missed -> automatic rollback'
cmp -s "$E/pre" "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" && ok "health rollback: daemon.json byte-identical" || ko "health rollback byte-identical" "$OUT"
expect "health rollback reports byte-identical" 1 'byte-identical to the pre-apply state'
# the live drill order: real apply first, then the injected health miss on the applied host (backup has
# live-restore) -> the label makes the candidate differ, dockerd restarts, rollback restores the applied file
fresh; run apply --yes; cp "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" "$E/applied"; n0="$(grep -c 'systemctl restart' "$STUB_S/calls")"
PFT_DOCKERD_INJECT=health run apply --yes
expect "health drill on applied host -> rollback exit 1" 1 'health gate missed -> automatic rollback'
expect "health drill candidate carries the drill label" 1 'pft\.dockerd-drill=1'
[ "$(grep -c 'systemctl restart' "$STUB_S/calls")" = $((n0 + 2)) ] && ok "health drill restarted dockerd (apply + rollback)" || ko "health drill restarts" "$(cat "$STUB_S/calls")"
cmp -s "$E/applied" "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" && ok "health drill: applied daemon.json byte-identical after rollback" || ko "health drill byte-identical" "$OUT"
grep -q 'no live-restore' <<<"$OUT" && ko "no live-restore warning when the backup has live-restore" "$OUT" || ok "no live-restore warning when the backup has live-restore"
fresh; touch "$STUB_S/kill_on_restart"; run apply --yes
expect "containers restarted by dockerd restart -> rollback" 1 'snapshot CHANGED'
[ ! -e "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" ] && ok "rollback to absent removes daemon.json" || ko "rollback to absent" "$OUT"
expect "rollback to a file without live-restore warns" 1 'WARNING the restored daemon.json has no live-restore'
expect "rollback gate: DOCKER-USER as before, StartedAt changed reported" 1 'rollback: health: PASS .*DOCKER-USER as before apply, StartedAt changed'
# a node that stays unhealthy after the rollback is a failed rollback (exit 5), not a clean one
fresh; echo stuck > "$STUB_S/state"; run apply --yes
expect "server_state not full -> rollback" 5 '^[^ ]+ health: FAIL .*server_state=stuck'
expect "server_state still not full after rollback -> exit 5" 5 'rollback: health: FAIL .*server_state=stuck'
fresh; : > "$STUB_S/ss"; run apply --yes
expect "peer port not listening -> rollback, still down -> exit 5" 5 'rollback: health: FAIL'
fresh; touch "$STUB_S/restart_fails"; run apply --yes
expect "dockerd does not come back -> rollback attempted, fails -> exit 5" 5 'rollback: dockerd did not come back'

# --- egress/ installed: every dockerd restart drops the DOCKER-USER -> PFT-EGRESS jump
fresh; run apply --yes
grep -q 'egress:' <<<"$OUT" || grep -q pft-egress "$STUB_S/calls" && ko "no egress/ installed -> no reapply" "$OUT" || ok "no egress/ installed -> no reapply"
fresh; egress_env "$E"; run apply --yes
expect "egress: jump dropped by restart -> reapply -> gate PASS" 0 'egress: pft-egress reapply --container postfiatd: ok'
expect "egress: apply done" 0 'apply: done'
grep -q PFT-EGRESS "$STUB_S/ipt" && ok "egress: jump present after apply" || ko "egress: jump present after apply" "$(cat "$STUB_S/ipt")"
cp "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" "$E/applied"
PFT_DOCKERD_INJECT=health run apply --yes
expect "egress: health drill -> rollback exit 1" 1 'health gate missed -> automatic rollback'
expect "egress: rollback gated, PASS with the jump restored" 1 'rollback: health: PASS .*StartedAt unchanged'
[ "$(grep -c 'pft-egress reapply' "$STUB_S/calls")" -ge 3 ] && ok "egress: reapplied after the apply AND the rollback restart" || ko "egress reapply count" "$(cat "$STUB_S/calls")"
grep -q PFT-EGRESS "$STUB_S/ipt" && cmp -s "$E/applied" "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" && ok "egress: jump present + daemon.json byte-identical after drill" || ko "egress after drill" "$OUT"
run rollback --yes
expect "egress: rollback command gated too" 0 'rollback: health: PASS'
grep -q PFT-EGRESS "$STUB_S/ipt" && ok "egress: jump present after rollback command" || ko "egress after rollback command" "$(cat "$STUB_S/ipt")"
fresh; egress_env "$E"; touch "$STUB_S/egress_fail"; run apply --yes
expect "egress reapply fails -> apply gate misses" 5 '^[^ ]+ health: FAIL .*snapshot CHANGED'
expect "egress reapply fails -> rollback gate FAIL -> exit 5" 5 'rollback: health: FAIL'
expect "egress reapply failure is reported" 5 'pft-egress reapply --container postfiatd: FAILED'

# --- auditd immutable
fresh; good; echo 2 > "$STUB_S/enabled"; sed -i '\#/usr/bin/runc #d' "$STUB_S/rules"; run apply --yes
expect "immutable auditd -> staged, not loaded" 0 'auditd immutable \(-e 2\): 1 watch\(es\) staged'
grep -q augenrules "$STUB_S/calls" && ko "no augenrules under -e 2" "$(cat "$STUB_S/calls")" || ok "no augenrules under -e 2"
run audit; expect "audit reports staged-until-boot" 1 '1.1.18 +audit:/usr/bin/runc +staged in .*next boot'

# --- rollback command
fresh; echo '{"debug":false}' > "$PFT_DOCKERD_ROOT/etc/docker/daemon.json"; cp "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" "$E/pre"
run apply --yes; run rollback --yes
expect "rollback --yes restores backup" 0 'byte-identical to the pre-apply state'
cmp -s "$E/pre" "$PFT_DOCKERD_ROOT/etc/docker/daemon.json" && ok "rollback file identical" || ko "rollback file identical" "$OUT"
fresh; run rollback --yes; expect "rollback without backup refused" 4 'no backup recorded'
run bogus; expect "unknown command -> usage exit 3" 3 'Usage'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
