#!/usr/bin/env bash
# Offline tests for pft-seccomp.sh: audit grading (fake /proc, audit log, stored profiles), --json/--prom/validate,
# ack-denials, pull, and apply/rollback for a compose (validator) and a docker run (sentry) container against the
# stateful stub tests/stub_docker.py (`run` builds the container from its ARGUMENTS, seccomp=FILE is stored as
# json.Compact like Docker does), pft-maint / systemctl / pft-integrity stubs. Then the helper's unit tests
# (tests/test_pft_seccomp.py). No root, no containers, no kernel.
# Usage: tests/run-tests.sh [path/to/pft-seccomp.sh]
# Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts (mounts/).
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-seccomp.sh}"
FIX="$HERE/fixtures"
base="${TEST_TMPDIR:-$HOME/.cache}"; mkdir -p "$base"
T="$(mktemp -d "$base/pft-sc-tests.XXXXXX")"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0; NOW=1793770000
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -20; }
export SYSCALL_TABLE="$FIX/syscall-table.tsv"
PROFILE="$T/profile.json"
bash "$TOOL" generate --learn "$FIX/learn" > "$PROFILE" || { echo "cannot generate the test profile"; exit 2; }
compact() { python3 -I -c 'import json, sys; print(json.dumps(json.load(open(sys.argv[1])), separators=(",", ":"), ensure_ascii=False))' "$1"; }

# ---- fake host -------------------------------------------------------------------------------------------
# $A/root: fake filesystem (PFT_SC_ROOT, STUB_ROOT); $A/d: stub state (containers/, maint.json, daemons, calls)
# what `compose up` creates: the compose files do not carry the docker-update'd CPU weight / memory.low (as live)
nores() { jq 'del(.HostConfig.CpuShares, .HostConfig.MemoryReservation)' "$1"; }
mk() { # KIND(run|compose) STATE(default|applied)
  N=$((N + 1)); A="$T/a$N"; local k="$1" r="$T/a$N/root" f
  mkdir -p "$r/proc/1" "$r/proc/sys/kernel/seccomp" "$r/proc/4242" "$r/var/log/audit" "$r/opt/postfiatd" "$r/textfile" \
    "$r/etc" "$A/s" "$A/d/containers"
  printf 'Name:\tsystemd\nSeccomp:\t0\nSeccomp_filters:\t0\n' > "$r/proc/1/status"
  printf 'Name:\tpostfiatd\nSeccomp:\t2\nSeccomp_filters:\t1\n' > "$r/proc/4242/status"
  echo 'kill_process kill_thread trap errno user_notif trace log' > "$r/proc/sys/kernel/seccomp/actions_logged"
  : > "$r/var/log/audit/audit.log"
  cp "$FIX/apply-image.json" "$A/d/image.json"
  if [ "$k" = run ]; then CN=postfiatd-sentry; cp "$FIX/apply-run.json" "$A/d/containers/$CN.json"
  else
    CN=postfiatd; cp "$FIX/apply-compose.json" "$A/d/containers/$CN.json"; nores "$FIX/apply-compose.json" > "$A/d/compose_base.json"
    printf 'NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml:docker-compose.apparmor.yml\n' > "$r/opt/postfiatd/.env"
    chmod 0640 "$r/opt/postfiatd/.env"
    for f in docker-compose.yml docker-compose.override.yml docker-compose.confine.yml docker-compose.apparmor.yml; do echo "services: {}" > "$r/opt/postfiatd/$f"; done
  fi
  if [ "${2:-default}" = applied ]; then # as after a successful apply
    mkdir -p "$r/etc/pft-seccomp"; cp "$PROFILE" "$r/etc/pft-seccomp/pft-postfiatd.json"
    jq --arg o "seccomp=$(compact "$PROFILE")" '.HostConfig.SecurityOpt += [$o]' "$A/d/containers/$CN.json" > "$A/d/x" && mv "$A/d/x" "$A/d/containers/$CN.json"
    if [ "$k" = compose ]; then
      printf 'services:\n  postfiatd:\n    security_opt:\n      - "seccomp=/etc/pft-seccomp/pft-postfiatd.json"\n' > "$r/opt/postfiatd/docker-compose.seccomp.yml"
      jq '.Config.Labels["com.docker.compose.project.config_files"] += ",/opt/postfiatd/docker-compose.seccomp.yml"' "$A/d/containers/$CN.json" > "$A/d/x" && mv "$A/d/x" "$A/d/containers/$CN.json"
    fi
  fi
  printf '{"window":"active","remaining_sec":2700,"locks":[]}\n' > "$A/d/maint.json"
  printf 'pft-exporter.service\npft-heartbeat.service\n' > "$A/d/daemons"; : > "$A/d/inactive"; : > "$A/d/integrity_out"
  printf '#!/usr/bin/env bash\nexec python3 "%s/stub_docker.py" "$@"\n' "$HERE" > "$A/s/docker"
  printf '#!/usr/bin/env bash\ncat "%s/d/maint.json"\n' "$A" > "$A/s/pft-maint"
  cat > "$A/s/systemctl" <<STUB
#!/usr/bin/env bash
case "\$1" in
  list-units) sed 's/\$/ loaded active running x/' "$A/d/daemons" ;;
  is-active) grep -qx "\$2" "$A/d/inactive" && { echo inactive; exit 3; }; echo active ;;
esac
STUB
  cat > "$A/s/pft-integrity" <<STUB
#!/usr/bin/env bash
echo "pft-integrity \$*" >> "$A/d/calls"
[ "\$1" = verify ] && cat "$A/d/integrity_out"
exit 0
STUB
  chmod +x "$A/s/"*
  export STUB_DIR="$A/d" STUB_ROOT="$r" AUDIT_LOG="$r/var/log/audit/audit.log" PFT_SC_ROOT="$r" PFT_SC_DOCKER="$A/s/docker" \
    PFT_SC_SYSTEMCTL="$A/s/systemctl" PFT_SC_MAINT="$A/s/pft-maint" PFT_SC_INTEGRITY="$A/s/pft-integrity" PFT_SC_NOW="$NOW" \
    CONTAINER="$CN" HEALTH_BUDGET=0 POLL_SEC=1 TEXTFILE_DIR="$r/textfile" PFT_SC_INJECT=""
  unset LEARN_DIR STATE_DIR PROFILE_PATH
}
run() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
line() { grep -E "^  \[[A-Z]+ *\] $1 " <<<"$OUT"; }
st() { line "$1" | sed -E 's/^ *\[([A-Z]+) *\].*/\1/'; }
expect() { # NAME CHECK STATUS [DETAIL-REGEX]
  local s; s="$(st "$2")"
  if [ "$s" = "$3" ] && { [ -z "${4:-}" ] || line "$2" | grep -qE -- "$4"; }; then ok "$1"; else ko "$1 (want $3${4:+ /$4/}, got '${s}')" "$OUT"; fi
}
cset() { jq "$1" "$A/d/containers/$CN.json" > "$A/d/x" && mv "$A/d/x" "$A/d/containers/$CN.json"; }
cj() { jq -r "$2" "$A/d/containers/$1.json" 2>/dev/null; }
scopt() { cj "$CN" '[.HostConfig.SecurityOpt[] | select(startswith("seccomp="))] | .[0] // "none"'; }
stf() { jq -r "$1" "$A/root/var/lib/pft-seccomp/apply-$CN.json" 2>/dev/null; }
rec() { # EPOCH CODE SUBJ NR COMM: one type=SECCOMP record
  printf 'type=SECCOMP msg=audit(%s.100:1): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=%s (enforce) pid=7 comm="%s" exe="/usr/bin/x" sig=0 arch=c000003e syscall=%s compat=0 ip=0x1 code=%s\n' \
    "$1" "$3" "$5" "$4" "$2" >> "$A/root/var/log/audit/audit.log"
}

# ---- audit -----------------------------------------------------------------------------------------------
for k in compose run; do
  mk "$k" applied; run audit
  [ "$RC" = 0 ] && grep -q '^RESULT: PASS$' <<<"$OUT" && ok "audit $k healthy: PASS, exit 0" || ko "audit $k healthy: rc=$RC" "$OUT"
  for c in kernel logging profile container filter recreate confine:cap_drop confine:nnp denials; do expect "audit $k healthy: $c PASS" "$c" PASS; done
done
mk compose; run audit
[ "$RC" = 1 ] && expect "default profile: container FAIL" container FAIL "Docker's default" || ko "default: rc=$RC" "$OUT"
expect "default: profile file missing FAIL" profile FAIL missing
expect "default: recreate FAIL" recreate FAIL "drops it"
mk run applied; cset '.HostConfig.SecurityOpt = (.HostConfig.SecurityOpt | map(select(startswith("seccomp=") | not)) + ["seccomp=unconfined"])'; run audit
expect "unconfined: container FAIL" container FAIL "seccomp=unconfined"
mk run applied; jq '.syscalls[0].names += ["ptrace"]' "$PROFILE" > "$A/root/etc/pft-seccomp/pft-postfiatd.json"; run audit
expect "file edited after create: container FAIL drift" container FAIL "drift"
mk run applied; jq -S . "$PROFILE" | jq . > "$A/root/etc/pft-seccomp/pft-postfiatd.json"; python3 -I -c 'import json,sys; o=json.load(open(sys.argv[1])); json.dump(o, open(sys.argv[1],"w"), indent=4)' "$A/root/etc/pft-seccomp/pft-postfiatd.json"; run audit
expect "same profile re-indented: container still PASS (canonical compare)" container PASS
mk run applied; echo '{"defaultAction":"SCMP_ACT_ALLOW"}' > "$A/root/etc/pft-seccomp/pft-postfiatd.json"; run audit
expect "allow-by-default file: profile FAIL" profile FAIL "defaultAction"
mk run applied; printf 'Name:\tpostfiatd\nSeccomp:\t0\n' > "$A/root/proc/4242/status"; run audit
expect "init not filtered: filter FAIL" filter FAIL "'0 0'"
mk run applied; cset '.State.Pid = 0'; run audit
expect "no pid: filter FAIL" filter FAIL "none"
mk run applied; echo 'kill_process kill_thread trap log' > "$A/root/proc/sys/kernel/seccomp/actions_logged"; run audit
expect "errno not logged: logging FAIL" logging FAIL "silent"
mk compose applied; sed -i 's#seccomp=/etc#seccomp=/var#' "$A/root/opt/postfiatd/docker-compose.seccomp.yml"; run audit
expect "override points elsewhere: recreate FAIL" recreate FAIL "drops it"
mk run applied; cset '.HostConfig.CapDrop = []'; run audit
expect "cap_drop lost: FAIL" confine:cap_drop FAIL
mk run applied; cset '.HostConfig.SecurityOpt |= map(select(startswith("no-new") | not))'; run audit
expect "nnp lost: FAIL" confine:nnp FAIL
mk run applied; CONTAINER=nope run audit
expect "missing container: container FAIL" container FAIL "not found"
# denials: errno records of the container's label only, inside the window
mk run applied
rec $((NOW - 100)) 0x50000 pft-postfiatd 101 sh; rec $((NOW - 90)) 0x50000 pft-postfiatd 101 sh; rec $((NOW - 80)) 0x50000 pft-postfiatd 165 du
rec $((NOW - 70)) 0x50000 docker-default 101 throwaway; rec $((NOW - 60)) 0x7ffc0000 pft-postfiatd 0 logonly
rec $((NOW - 90000)) 0x50000 pft-postfiatd 101 old
run audit
expect "denials: 3 errno records of pft-postfiatd counted (throwaway label, LOG action, older than 24h left out)" denials WARN "^.*3 seccomp denial\(s\)"
line denials | grep -q 'ptrace (sh) x2; mount (du) x1' && ok "denials: top syscalls named with comm" || ko "denials: summary" "$OUT"
[ "$RC" = 1 ] && ok "denials: exit 1" || ko "denials: rc=$RC" "$OUT"
run audit --since 85
expect "denials --since 85: only the last record" denials WARN "1 seccomp denial"
chmod 000 "$A/root/var/log/audit/audit.log"; run audit
if [ "$(id -u)" = 0 ]; then ok "unreadable audit log: skipped (root)"; else expect "unreadable audit log: denials FAIL" denials FAIL "no readable audit log"; fi
chmod 644 "$A/root/var/log/audit/audit.log"
# --json / --prom / validate
run audit --json
jq -e '.findings == 1 and .denied_events == 3 and (.checks | length) == 9 and .host == "validator"' <<<"$OUT" >/dev/null && ok "--json: findings, denied_events, 9 checks" || ko "--json" "$OUT"
run audit --textfile
P="$A/root/textfile/pft_seccomp_validator.prom"
grep -qx 'pft_seccomp_denied_events{host="validator"} 3' "$P" && grep -qx 'pft_seccomp_findings{host="validator"} 1' "$P" \
  && grep -qx 'pft_seccomp_check{host="validator",check="denials",status="WARN"} 0' "$P" && grep -qx "pft_seccomp_last_run_timestamp_seconds{host=\"validator\"} $NOW" "$P" \
  && ok "--textfile: samples written" || ko "--textfile" "$(cat "$P")"
[ "$(stat -c %a "$P")" = 644 ] && ok "--textfile: mode 644" || ko "--textfile mode"
run validate "$P" validator; [ "$RC" = 0 ] && ok "validate: own textfile ok" || ko "validate own: rc=$RC" "$OUT"
run validate "$P" sentry; [ "$RC" = 2 ] && ok "validate: other host label rejected" || ko "validate host: rc=$RC" "$OUT"
cp "$P" "$A/v"; echo 'node_load1 9' >> "$A/v"; run validate "$A/v" validator
[ "$RC" = 2 ] && grep -q '1 unexpected lines' <<<"$OUT" && ok "validate: foreign metric rejected" || ko "validate foreign: rc=$RC" "$OUT"
grep -v last_run "$P" > "$A/v"; run validate "$A/v" validator
[ "$RC" = 2 ] && grep -q 'no last_run' <<<"$OUT" && ok "validate: no last_run rejected" || ko "validate last_run: rc=$RC" "$OUT"
# ack-denials
run ack-denials --reason "drill negative controls"
[ "$RC" = 4 ] && ok "ack without --yes: exit 4" || ko "ack no --yes: rc=$RC" "$OUT"
run ack-denials --reason "drill negative controls" --until $((NOW - 85)) --yes
[ "$RC" = 0 ] && grep -q '3 seccomp denial(s) after 0 up to' <<<"$OUT" && ok "ack: 3 records up to --until counted (incl. the one older than 24h)" || ko "ack: rc=$RC" "$OUT"
run audit
expect "after ack: 1 denial left, reason shown" denials WARN "1 seccomp denial.*acknowledged: drill negative controls"
run ack-denials --reason "again" --until $((NOW - 85)) --yes
[ "$RC" = 4 ] && ok "ack: same --until twice refused" || ko "ack twice: rc=$RC" "$OUT"
run ack-denials --reason "future" --until $((NOW + 10)) --yes
[ "$RC" = 3 ] && ok "ack: future --until refused" || ko "ack future: rc=$RC" "$OUT"
run ack-denials --reason "$(printf 'bad\tchar')" --yes
[ "$RC" = 3 ] && ok "ack: non-printable reason refused" || ko "ack reason: rc=$RC" "$OUT"
run ack-denials --reason "all" --yes; run audit
expect "ack to now: denials PASS" denials PASS
echo '[1,2]' > "$A/root/var/lib/pft-seccomp/denials-ack.json"; run audit
expect "malformed ack file: FAIL" denials-ack FAIL malformed
expect "malformed ack file: every record counted again" denials WARN "3 seccomp denial"
# pull
mk run applied; run audit --textfile; mv "$A/root/textfile/pft_seccomp_validator.prom" "$A/peer.prom"; sed -i 's/host="validator"/host="sentry"/' "$A/peer.prom"
printf 'PULL_SSH=%s\n' "$A/s/fakessh" > "$A/root/etc/pft-seccomp.env"
printf '#!/usr/bin/env bash\n[ "$1" = cat ] && [ "$3" = /var/lib/pft-exporter/textfile/pft_seccomp_sentry.prom ] && cat "%s/peer.prom"\n' "$A" > "$A/s/fakessh"; chmod +x "$A/s/fakessh"
run pull; [ "$RC" = 0 ] && cmp -s "$A/peer.prom" "$A/root/textfile/pft_seccomp_sentry.prom" && ok "pull: peer textfile copied" || ko "pull: rc=$RC" "$OUT"
echo 'evil 1' >> "$A/peer.prom"; run pull
[ "$RC" = 2 ] && ! grep -q evil "$A/root/textfile/pft_seccomp_sentry.prom" && ok "pull: bad file rejected, last good copy kept" || ko "pull bad: rc=$RC" "$OUT"
printf 'PULL_SSH=false\n' > "$A/root/etc/pft-seccomp.env"; run pull
[ "$RC" = 1 ] && grep -q 'pull from sentry failed' <<<"$OUT" && ok "pull: ssh failure exit 1" || ko "pull ssh fail: rc=$RC" "$OUT"
printf 'HOST_LABEL=Bad Label\n' > "$A/root/etc/pft-seccomp.env"; run audit
[ "$RC" = 2 ] && grep -q 'bad HOST_LABEL' <<<"$OUT" && ok "conf: bad HOST_LABEL refused" || ko "conf label: rc=$RC" "$OUT"

# ---- apply / rollback ------------------------------------------------------------------------------------
SIGKEYS='[.HostConfig.CapAdd, .HostConfig.CapDrop, .HostConfig.ReadonlyRootfs, .HostConfig.Tmpfs, .HostConfig.PidsLimit,
  .HostConfig.Memory, .HostConfig.MemorySwap, .HostConfig.CpuShares, .HostConfig.MemoryReservation, (.HostConfig.SecurityOpt | map(select(startswith("seccomp") | not))), .AppArmorProfile,
  .HostConfig.PortBindings, .HostConfig.LogConfig, .HostConfig.RestartPolicy.Name, .HostConfig.NetworkMode,
  .Mounts, .Config.User, .Config.Env, .Config.Image, .Config.Cmd, .Config.Entrypoint]'
WANT="seccomp=$(compact "$PROFILE")"
nothing_changed() { # NAME
  if ! grep -qE '^docker (stop|run|rename|rm|compose up)' "$A/d/calls" 2>/dev/null && [ ! -e "$A/root/etc/pft-seccomp/pft-postfiatd.json" ] \
     && [ "$(scopt)" = none ]; then ok "$1: nothing changed"
  else ko "$1: something changed" "$(cat "$A/d/calls" 2>/dev/null)"; fi
}
mk run; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 0 ] && grep -q 'apply RESULT: PASS' <<<"$OUT" && ok "apply run: PASS, exit 0" || ko "apply run: rc=$RC" "$OUT"
[ "$(scopt)" = "$WANT" ] && ok "apply run: stored profile = json.Compact(profile)" || ko "apply run: seccomp opt" "$(scopt | cut -c1-80)"
[ "$(jq -cS "$SIGKEYS" "$FIX/apply-run.json")" = "$(cj "$CN" "$SIGKEYS | tostring" | jq -cS .)" ] \
  && ok "apply run: re-created container keeps every confine/identity field incl. AppArmor (built from the run args)" \
  || ko "apply run: fields differ" "$(diff <(jq -S "$SIGKEYS" "$FIX/apply-run.json") <(cj "$CN" "$SIGKEYS"))"
[ "$(jq -r .HostConfig.RestartPolicy.Name "$A"/d/containers/postfiatd-sentry-presc-*.json 2>/dev/null)" = no ] \
  && ok "apply run: previous container kept, restart=no" || ko "apply run: old container" "$(ls "$A/d/containers")"
cmp -s "$A/root/etc/pft-seccomp/pft-postfiatd.json" "$PROFILE" && ok "apply run: /etc/pft-seccomp file = candidate" || ko "apply run: file"
grep -q '203\.0\.113\.7' <<<"$OUT" && ko "apply run: host IP printed" "$(grep 203.0.113.7 <<<"$OUT")" || ok "apply run: host IP masked in output"
grep -q 'NETWORK=testnet' <<<"$OUT" && ko "apply run: env value printed" "$OUT" || ok "apply run: env values masked in output"
grep -q 'gate PASS - exercise done, seccomp denials since T0: 0' <<<"$OUT" && ok "apply run: gate exercised the node, 0 denials" || ko "apply run: gate" "$OUT"
grep -q 'exec postfiatd-sentry sh -c du -sb "$1/nudb" | cut -f1 sh /var/lib/postfiatd/db' "$A/d/calls" && grep -q 'exec postfiatd-sentry timeout 5 bash -c exec 3<>/dev/tcp/127.0.0.1/5005' "$A/d/calls" \
  && ok "apply run: gate ran the add-ons' docker exec commands" || ko "apply run: add-on exercise" "$(grep ' exec ' "$A/d/calls")"
[ "$(stf .phase)" = applied ] && [ "$(stf .kind)" = run ] && [ "$(stf .pre_state)" = default ] && ok "apply run: state applied, pre_state default" || ko "apply run: state"
run audit
[ "$RC" = 0 ] && ok "apply run: audit afterwards PASS" || ko "apply run: audit rc=$RC" "$OUT"
run apply --profile-file "$PROFILE" --yes
[ "$RC" = 4 ] && grep -q 'already runs under this profile' <<<"$OUT" && ok "apply run: same profile again refused" || ko "re-apply: rc=$RC" "$OUT"
jq '.syscalls[0].names -= ["mremap"]' "$PROFILE" > "$A/p2"; run apply --profile-file "$A/p2" --yes
[ "$RC" = 4 ] && grep -q 'still in place; rollback first' <<<"$OUT" && ok "apply run: other profile while applied refused" || ko "apply other: rc=$RC" "$OUT"
run rollback; [ "$RC" = 4 ] && ok "rollback without --yes: exit 4" || ko "rollback no --yes: rc=$RC" "$OUT"
run rollback --yes
[ "$RC" = 0 ] && grep -q 'rollback RESULT: PASS' <<<"$OUT" && ok "rollback run: PASS" || ko "rollback run: rc=$RC" "$OUT"
[ "$(scopt)" = none ] && [ "$(cj "$CN" .HostConfig.RestartPolicy.Name)" = unless-stopped ] && [ "$(cj "$CN" .AppArmorProfile)" = pft-postfiatd ] \
  && ok "rollback run: previous container back (Docker default seccomp, unless-stopped, AppArmor kept)" || ko "rollback run: container" "$(cj "$CN" '{a: .AppArmorProfile, r: .HostConfig.RestartPolicy}')"
[ ! -e "$A/root/etc/pft-seccomp/pft-postfiatd.json" ] && ok "rollback run: profile file removed (none before)" || ko "rollback run: file left"
[ "$(find "$A/d/containers" -name '*.json' | wc -l)" = 1 ] && ok "rollback run: no leftover container" || ko "rollback run: containers" "$(ls "$A/d/containers")"
[ "$(stf .rolled_back)" = true ] && [ "$(stf .rollback)" = manual ] && ok "rollback run: state rolled_back (manual)" || ko "rollback run: state"
run rollback --yes; [ "$RC" = 0 ] && grep -q 'already rolled back' <<<"$OUT" && ok "rollback twice: no-op" || ko "rollback twice: rc=$RC" "$OUT"
run apply --profile-file "$PROFILE" --yes
[ "$RC" = 0 ] && [ "$(scopt)" = "$WANT" ] && ok "re-apply after rollback: PASS" || ko "re-apply: rc=$RC" "$OUT"

mk compose; ENV0="$(cat "$A/root/opt/postfiatd/.env")"; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 0 ] && ok "apply compose: PASS" || ko "apply compose: rc=$RC" "$OUT"
grep -qx 'COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml:docker-compose.apparmor.yml:docker-compose.seccomp.yml' "$A/root/opt/postfiatd/.env" \
  && grep -qx 'NETWORK=testnet' "$A/root/opt/postfiatd/.env" && ok "apply compose: COMPOSE_FILE keeps the apparmor override + adds seccomp" || ko "apply compose: .env" "$(cat "$A/root/opt/postfiatd/.env")"
[ "$(stat -c %a "$A/root/opt/postfiatd/.env")" = 640 ] && ok "apply compose: .env mode kept" || ko "apply compose: .env mode"
[ "$(scopt)" = "$WANT" ] && [ "$(cj "$CN" .AppArmorProfile)" = pft-postfiatd ] && ok "apply compose: stored profile + AppArmor label" || ko "apply compose: container"
res() { cj "$CN" '"\(.HostConfig.CpuShares // 0) \(.HostConfig.MemoryReservation // 0)"'; }
[ "$(res)" = "8192 1342177280" ] && grep -q 'resources: postfiatd had cpu_shares/memory_reservation .0 0., restored --cpu-shares=8192 --memory-reservation=1342177280' <<<"$OUT" \
  && ok "apply compose: cpu_shares + memory_reservation (not in the compose files) restored after compose up" || ko "apply compose: resources '$(res)'" "$OUT"
run audit; [ "$RC" = 0 ] && expect "apply compose: audit recreate PASS" recreate PASS "compose file sets" || ko "apply compose audit: rc=$RC" "$OUT"
run rollback --yes
[ "$(res)" = "8192 1342177280" ] && grep -q 'resources: postfiatd had' <<<"$OUT" && ok "rollback compose: cpu_shares + memory_reservation restored too" || ko "rollback compose: resources '$(res)'" "$OUT"
[ "$RC" = 0 ] && [ "$(cat "$A/root/opt/postfiatd/.env")" = "$ENV0" ] && [ ! -e "$A/root/opt/postfiatd/docker-compose.seccomp.yml" ] && [ "$(scopt)" = none ] \
  && ok "rollback compose: .env byte-identical, override gone, Docker default" || ko "rollback compose: rc=$RC" "$OUT"

# pre-existing profile file: rollback restores it byte-identical BEFORE the re-create (compose re-reads it)
mk compose applied; jq '.syscalls[0].names -= ["mremap"]' "$PROFILE" > "$A/p2"
cset '.HostConfig.SecurityOpt |= map(select(startswith("seccomp=") | not))'; nores "$FIX/apply-compose.json" > "$A/d/compose_base.json"
printf 'NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml:docker-compose.apparmor.yml:docker-compose.seccomp.yml\n' > "$A/root/opt/postfiatd/.env"
jq --arg o "seccomp=$(compact "$PROFILE")" '.HostConfig.SecurityOpt += [$o]' "$A/d/containers/$CN.json" > "$A/d/x" && mv "$A/d/x" "$A/d/containers/$CN.json"
cp "$A/root/etc/pft-seccomp/pft-postfiatd.json" "$A/old"
run apply --profile-file "$A/p2" --yes
[ "$RC" = 0 ] && [ "$(scopt)" = "seccomp=$(compact "$A/p2")" ] && ok "apply over an older profile: PASS" || ko "apply over older: rc=$RC" "$OUT"
run rollback --yes
cmp -s "$A/old" "$A/root/etc/pft-seccomp/pft-postfiatd.json" && [ "$(scopt)" = "$WANT" ] && [ "$RC" = 0 ] \
  && ok "rollback: older file restored byte-identical and the container back on it" || ko "rollback older: rc=$RC" "$OUT"
grep -q 'docker-compose.seccomp.yml' "$A/root/opt/postfiatd/.env" && grep -q 'seccomp=/etc/pft-seccomp/pft-postfiatd.json' "$A/root/opt/postfiatd/docker-compose.seccomp.yml" \
  && ok "rollback: the pre-existing override file is restored, not deleted" || ko "rollback older: override" "$(ls "$A/root/opt/postfiatd")"

# integrity baselines
mk compose; printf '  [WARN] container:postfiatd   changed id\n  [WARN] compose:.env   changed sha256\n  [WARN] compose:docker-compose.seccomp.yml  new\n' > "$A/d/integrity_out"
run apply --profile-file "$PROFILE" --yes
grep -q 'pft-integrity accept --reason pft-seccomp apply' "$A/d/calls" && grep -q 'integrity: accepted (compose:.env compose:docker-compose.seccomp.yml container:postfiatd)' <<<"$OUT" \
  && ok "integrity: own items accepted" || ko "integrity: own items" "$OUT"
mk compose; printf '  [WARN] container:postfiatd   changed id\n  [FAIL] bin:pft-other   changed sha256\n' > "$A/d/integrity_out"
run apply --profile-file "$PROFILE" --yes
[ "$RC" = 0 ] && ! grep -q 'pft-integrity accept' "$A/d/calls" && grep -q 'NOT accepted .*bin:pft-other' <<<"$OUT" \
  && ok "integrity: foreign change -> not accepted" || ko "integrity foreign: rc=$RC" "$OUT"

# refusals
mk run; run apply --profile-file "$PROFILE"; [ "$RC" = 4 ] && ok "refuse: no --yes" || ko "refuse no --yes: rc=$RC" "$OUT"; nothing_changed "refuse no --yes"
mk run; printf '{"window":"none","remaining_sec":null,"locks":[]}\n' > "$A/d/maint.json"; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 4 ] && grep -q 'no active pft-maint window' <<<"$OUT" && ok "refuse: no window" || ko "refuse window: rc=$RC" "$OUT"; nothing_changed "refuse no window"
mk run; printf '{"window":"active","remaining_sec":2000,"locks":[]}\n' > "$A/d/maint.json"; HEALTH_BUDGET=900 run apply --profile-file "$PROFILE" --yes
[ "$RC" = 4 ] && grep -q 'needs 2\*HEALTH_BUDGET+MAINT_MARGIN=2100s' <<<"$OUT" && ok "refuse: window too short" || ko "refuse short: rc=$RC" "$OUT"
mk run; printf '{"window":"active","remaining_sec":2700,"locks":["growth-tx 2026-11-05 task"]}\n' > "$A/d/maint.json"; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 4 ] && grep -q 'data-collection lock' <<<"$OUT" && ok "refuse: data-collection lock" || ko "refuse lock: rc=$RC" "$OUT"; nothing_changed "refuse lock"
mk run; echo default > "$A/d/rpc_bad_sc"; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 4 ] && grep -q 'node is connected, not full' <<<"$OUT" && ok "refuse: node not full" || ko "refuse not full: rc=$RC" "$OUT"; nothing_changed "refuse not full"
mk run; cset '.HostConfig.CapDrop = []'; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 4 ] && grep -q 'not confined' <<<"$OUT" && ok "refuse: not confined" || ko "refuse confined: rc=$RC" "$OUT"
mk run; cset '.AppArmorProfile = "unconfined"'; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 4 ] && grep -q 'no AppArmor label' <<<"$OUT" && ok "refuse: no AppArmor label (denials unattributable)" || ko "refuse label: rc=$RC" "$OUT"; nothing_changed "refuse label"
mk run; jq '.defaultAction = "SCMP_ACT_ALLOW"' "$PROFILE" > "$A/p2"; run apply --profile-file "$A/p2" --yes
[ "$RC" = 4 ] && grep -q 'fails check: defaultAction' <<<"$OUT" && ok "refuse: allow-by-default candidate" || ko "refuse check: rc=$RC" "$OUT"; nothing_changed "refuse check"
mk run; run apply --yes; [ "$RC" = 3 ] && ok "apply without --profile-file: exit 3" || ko "apply usage: rc=$RC" "$OUT"
mk run; printf '{"window":"none","locks":[]}\n' > "$A/d/maint.json"; run rollback --yes
[ "$RC" = 4 ] && grep -q 'rollback: REFUSED' <<<"$OUT" && ok "refuse: rollback outside a window" || ko "refuse rollback: rc=$RC" "$OUT"

# automatic rollback
auto_rb() { # NAME
  if [ "$RC" = 1 ] && grep -q 'rollback RESULT: PASS' <<<"$OUT" && [ "$(scopt)" = none ] && [ "$(cj "$CN" .HostConfig.RestartPolicy.Name)" = unless-stopped ] \
     && [ ! -e "$A/root/etc/pft-seccomp/pft-postfiatd.json" ] && [ "$(stf .rollback)" = auto ] && [ "$(find "$A/d/containers" -name '*.json' | wc -l)" = 1 ]
  then ok "$1: rolled back (exit 1)"; else ko "$1: rc=$RC" "$OUT"; fi
}
mk run; echo ReadonlyRootfs > "$A/d/drop_on_recreate"; run apply --profile-file "$PROFILE" --yes
grep -q 'confine changed: read_only' <<<"$OUT" && ok "auto: lost read-only named" || ko "auto: read-only" "$OUT"; rm "$A/d/drop_on_recreate"; auto_rb "auto: lost read-only"
mk run; echo CpuShares > "$A/d/drop_on_recreate"; run apply --profile-file "$PROFILE" --yes
grep -q 'confine changed: cpu_shares' <<<"$OUT" && ok "auto: lost cpu_shares named" || ko "auto: cpu_shares" "$OUT"; rm "$A/d/drop_on_recreate"; auto_rb "auto: lost cpu_shares (run path)"
[ "$(cj "$CN" .HostConfig.CpuShares)" = 8192 ] && ok "auto: rolled-back sentry container keeps cpu_shares 8192" || ko "auto: cpu_shares after rollback" "$(cj "$CN" .HostConfig.CpuShares)"
for m in run compose; do
  mk "$m"; touch "$A/d/seccomp_ignored"; run apply --profile-file "$PROFILE" --yes
  grep -q 'health FAIL .*seccomp default want sha256:' <<<"$OUT" && ok "auto $m: profile not taken named" || ko "auto $m: ignored" "$OUT"
  rm "$A/d/seccomp_ignored"
  if [ "$m" = run ]; then auto_rb "auto run: profile not taken"
  else [ "$RC" = 1 ] && [ "$(scopt)" = none ] && [ ! -e "$A/root/opt/postfiatd/docker-compose.seccomp.yml" ] && ok "auto compose: profile not taken: rolled back" || ko "auto compose: rc=$RC" "$OUT"; fi
done
mk run; touch "$A/d/nofilter"; run apply --profile-file "$PROFILE" --yes
grep -q "init Seccomp '0 1' want 2" <<<"$OUT" && ok "auto: init not filtered named" || ko "auto: nofilter" "$OUT"
rm "$A/d/nofilter"; auto_rb "auto: init not filtered"
mk run; echo 'seccomp={' > "$A/d/rpc_bad_sc"; run apply --profile-file "$PROFILE" --yes
grep -q 'server_state connected' <<<"$OUT" && ok "auto: not full under the profile named" || ko "auto: not full" "$OUT"; auto_rb "auto: not full"
mk run; rec "$NOW" 0x50000 docker-default 101 throwaway; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 0 ] && ok "gate: denial of another label (throwaway) not counted" || ko "gate other label: rc=$RC" "$OUT"
mk run; touch "$A/d/deny_on_exercise"; run apply --profile-file "$PROFILE" --yes
grep -q 'gate FAIL - 1 seccomp denial(s) since T0: ptrace (run-parts)' <<<"$OUT" && ok "auto: denial during the exercise fails the gate" || ko "auto: denial" "$OUT"; auto_rb "auto: denial"
mk run; touch "$A/d/deny_on_addon"; run apply --profile-file "$PROFILE" --yes
grep -q 'gate FAIL - 1 seccomp denial(s) since T0: mount (du)' <<<"$OUT" && ok "auto: denial on an add-on command fails the gate" || ko "auto: add-on" "$OUT"; auto_rb "auto: add-on denial"
mk run; touch "$A/d/fail_run"; run apply --profile-file "$PROFILE" --yes; rm "$A/d/fail_run"; auto_rb "auto: docker run failed"
mk run; PFT_SC_INJECT=health run apply --profile-file "$PROFILE" --yes
grep -q 'injected failure' <<<"$OUT" && ok "auto: PFT_SC_INJECT=health named" || ko "auto: inject" "$OUT"; auto_rb "auto: injected"
mk run; echo pft-heartbeat.service > "$A/d/inactive"; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 5 ] && grep -q 'apply: health FAIL .*pft-heartbeat.service inactive' <<<"$OUT" && grep -q 'rollback: health FAIL' <<<"$OUT" && [ "$(scopt)" = none ] \
  && ok "auto: pft daemon down -> container restored, rollback gate fails honestly (exit 5)" || ko "auto: daemon rc=$RC" "$OUT"
mk compose; ENV0="$(cat "$A/root/opt/postfiatd/.env")"; touch "$A/d/fail_compose_up"; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 1 ] && [ "$(cat "$A/root/opt/postfiatd/.env")" = "$ENV0" ] && [ ! -e "$A/root/opt/postfiatd/docker-compose.seccomp.yml" ] && [ ! -e "$A/root/etc/pft-seccomp/pft-postfiatd.json" ] \
  && ok "auto compose: compose up failed -> .env restored, override + file gone" || ko "auto compose up: rc=$RC" "$OUT"
mk compose; PFT_SC_INJECT=health run apply --profile-file "$PROFILE" --yes
[ "$RC" = 1 ] && [ "$(scopt)" = none ] && grep -q 'rollback RESULT: PASS' <<<"$OUT" && ok "auto compose: injected failure rolled back" || ko "auto compose inject: rc=$RC" "$OUT"
mk compose; touch "$A/d/fail_update"; run apply --profile-file "$PROFILE" --yes
[ "$RC" = 5 ] && grep -q 'apply: resources not restored -> automatic rollback' <<<"$OUT" && grep -q 'ROLLBACK FAILED: resources' <<<"$OUT" \
  && ok "auto compose: docker update fails -> rollback, which cannot restore them either and says so (exit 5)" || ko "auto compose update: rc=$RC" "$OUT"

# ---- generate/diff over two learn dirs (validator + sentry) ---------------------------------------------
run diff --learn "$FIX/learn" --learn "$FIX/learn2"
r="$(jq -r '.read' "$FIX/learn/census.json")"
grep -qP "^read\tallow\tallow\tcensus $((r + 5))$" <<<"$OUT" && ok "merge: census counts summed (read $r + 5)" || ko "merge: read" "$(grep '^read' <<<"$OUT")"
grep -qP '^setpriority\tallow\tallow\tSCMP_ACT_LOG record' <<<"$OUT" && ok "merge: the second dir's LOG events count" || ko "merge: events" "$(grep '^setpriority' <<<"$OUT")"
grep -qP '^mremap\tallow\tallow\tcensus 7$' <<<"$OUT" && ok "merge: a census-only name from the second dir kept" || ko "merge: mremap" "$(grep '^mremap' <<<"$OUT")"
run generate --learn "$FIX/learn" --learn "$FIX/learn2"; G1="$OUT"; run generate --learn "$FIX/learn2" --learn "$FIX/learn"
[ "$G1" = "$OUT" ] && ok "merge: order of --learn does not change the profile" || ko "merge: order" "$(diff <(echo "$G1") <(echo "$OUT") | head)"
run generate --learn "$FIX/learn" --learn "$FIX/learn"
[ "$RC" = 0 ] && [ "$OUT" = "$(cat "$PROFILE")" ] && ok "merge: the same dir twice = that dir alone" || ko "merge: same dir twice rc=$RC" "$OUT"
mkdir -p "$T/l3"; cp "$FIX/learn2/census.json" "$T/l3/"; jq '.caps = "CAP_SETGID,CAP_SETUID,CAP_NET_RAW"' "$FIX/learn2/meta.json" > "$T/l3/meta.json"
run generate --learn "$FIX/learn" --learn "$T/l3"
[ "$RC" = 2 ] && grep -q 'learn dirs differ in caps' <<<"$OUT" && ok "merge: dirs with different caps refused" || ko "merge: caps rc=$RC" "$OUT"
run generate --learn "$FIX/learn" --learn "$T"
[ "$RC" = 2 ] && grep -q 'no census.json' <<<"$OUT" && ok "merge: dir without census refused" || ko "merge: no census rc=$RC" "$OUT"

# ---- helper unit tests -----------------------------------------------------------------------------------
if python3 -I "$HERE/test_pft_seccomp.py" > "$T/unit.log" 2>&1; then ok "helper unit tests: $(grep -oE '^Ran [0-9]+ tests' "$T/unit.log")"
else ko "helper unit tests" "$(tail -30 "$T/unit.log")"; fi

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
