# shellcheck shell=bash
# apply / rollback tests, sourced by run-tests.sh (uses ok, ko, T, TOOL, FIX, HERE, NOW).
# Fake host: $A/root (PFT_AA_ROOT) with the kernel profile list, /etc/apparmor.d, the compose dir and the audit log;
# stateful stubs in $A/s: docker (tests/stub_docker.py: `run` builds the container from its ARGS), apparmor_parser
# (-r/-R edit the kernel list), pft-maint (status JSON from a file), systemctl (pft daemons), pft-integrity.
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015

NA=0
mk_apply() { # KIND(run|compose)
  NA=$((NA + 1)); A="$T/a$NA"; local k="$1" r
  r="$A/root"
  mkdir -p "$r/sys/kernel/security/apparmor" "$r/sys/module/apparmor/parameters" "$r/etc/apparmor.d" "$r/var/log/audit" \
    "$r/opt/postfiatd" "$r/textfile" "$A/s" "$A/d/containers"
  echo Y > "$r/sys/module/apparmor/parameters/enabled"
  printf 'docker-default (enforce)\n/usr/sbin/chronyd (enforce)\n' > "$r/sys/kernel/security/apparmor/profiles"
  : > "$r/var/log/audit/audit.log"
  cp "$FIX/apply-image.json" "$A/d/image.json"
  if [ "$k" = run ]; then
    CN=postfiatd-sentry; cp "$FIX/apply-run.json" "$A/d/containers/$CN.json"
  else
    CN=postfiatd; cp "$FIX/apply-compose.json" "$A/d/containers/$CN.json"
    jq '.HostConfig.SecurityOpt = ["no-new-privileges:true"]' "$FIX/apply-compose.json" > "$A/d/compose_base.json"
    printf 'NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml\n' > "$r/opt/postfiatd/.env"
    chmod 0640 "$r/opt/postfiatd/.env"
    for f in docker-compose.yml docker-compose.override.yml docker-compose.confine.yml; do echo "services: {}" > "$r/opt/postfiatd/$f"; done
  fi
  printf '{"window":"active","remaining_sec":2700,"locks":[]}\n' > "$A/d/maint.json"
  printf 'pft-exporter.service\npft-heartbeat.service\n' > "$A/d/daemons"; : > "$A/d/inactive"
  : > "$A/d/integrity_out"; echo 0 > "$A/d/parser_rc"
  cat > "$A/s/docker" <<STUB
#!/usr/bin/env bash
exec python3 "$HERE/stub_docker.py" "\$@"
STUB
  cat > "$A/s/apparmor_parser" <<STUB
#!/usr/bin/env bash
echo "apparmor_parser \$*" >> "$A/d/calls"
k="$r/sys/kernel/security/apparmor/profiles"
case "\$1" in
  -Q) exit "\$(cat "$A/d/parser_rc")" ;;
  -r) n="\$(sed -nE 's/^profile ([^ ]+) .*/\1/p' "\$3")"; m=enforce; grep -qE '^profile .*flags=\(complain' "\$3" && m=complain
      sed -i "/^\$n (/d" "\$k"; echo "\$n (\$m)" >> "\$k" ;;
  -R) n="\$(sed -nE 's/^profile ([^ ]+) .*/\1/p' "\$2")"; sed -i "/^\$n (/d" "\$k" ;;
esac
exit 0
STUB
  cat > "$A/s/pft-maint" <<STUB
#!/usr/bin/env bash
cat "$A/d/maint.json"
STUB
  cat > "$A/s/systemctl" <<STUB
#!/usr/bin/env bash
case "\$1" in
  list-units) sed 's/\$/ loaded active running x/' "$A/d/daemons" ;;
  is-active) grep -qx "\$2" "$A/d/inactive" && { echo inactive; exit 3; }; echo active ;;
  is-enabled) echo enabled ;;
esac
STUB
  cat > "$A/s/pft-integrity" <<STUB
#!/usr/bin/env bash
echo "pft-integrity \$*" >> "$A/d/calls"
[ "\$1" = verify ] && cat "$A/d/integrity_out"
exit 0
STUB
  chmod +x "$A/s/"*
  export STUB_DIR="$A/d" AUDIT_LOG="$r/var/log/audit/audit.log" PFT_AA_ROOT="$r" PFT_AA_DOCKER="$A/s/docker" \
    PFT_AA_PARSER="$A/s/apparmor_parser" PFT_AA_SYSTEMCTL="$A/s/systemctl" PFT_AA_MAINT="$A/s/pft-maint" \
    PFT_AA_INTEGRITY="$A/s/pft-integrity" PFT_AA_NOW="$NOW" CONTAINER="$CN" HEALTH_BUDGET=0 POLL_SEC=1 \
    TEXTFILE_DIR="$r/textfile" PFT_AA_INJECT=""
  unset LEARN_DIR STATE_DIR
  bash "$TOOL" generate --events "$FIX/events.tsv" --caps "CAP_SETGID CAP_SETUID" > "$A/profile" 2>/dev/null
}
arun() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
cj() { jq -r "$2" "$A/d/containers/$1.json" 2>/dev/null; }
stf() { jq -r "$1" "$A/root/var/lib/pft-apparmor/apply-$CN.json" 2>/dev/null; }
kmode() { awk -v p="$1" '$1 == p { gsub(/[()]/, "", $2); print $2 }' "$A/root/sys/kernel/security/apparmor/profiles"; }
nothing_changed() { # NAME: no container change, no profile file, nothing loaded
  if ! grep -qE '^docker (stop|run|rename|rm|compose up)' "$A/d/calls" 2>/dev/null && [ ! -e "$A/root/etc/apparmor.d/pft-postfiatd" ] \
     && [ -z "$(kmode pft-postfiatd)" ] && [ "$(cj "$CN" .AppArmorProfile)" = docker-default ]; then ok "$1: nothing changed"
  else ko "$1: something changed" "$(cat "$A/d/calls" 2>/dev/null)"; fi
}
SIGKEYS='[.HostConfig.CapAdd, .HostConfig.CapDrop, .HostConfig.ReadonlyRootfs, .HostConfig.Tmpfs, .HostConfig.PidsLimit,
  .HostConfig.Memory, .HostConfig.MemorySwap, (.HostConfig.SecurityOpt | map(select(startswith("apparmor") | not))),
  .HostConfig.PortBindings, .HostConfig.LogConfig, .HostConfig.RestartPolicy.Name, .HostConfig.NetworkMode,
  .Mounts, .Config.User, .Config.Env, .Config.Image, .Config.Cmd, .Config.Entrypoint]'

# ---- docker run container (sentry) -----------------------------------------------------------------------
mk_apply run; arun apply --profile-file "$A/profile" --yes
[ "$RC" = 0 ] && grep -q 'apply RESULT: PASS' <<<"$OUT" && ok "apply run: PASS, exit 0" || ko "apply run: rc=$RC" "$OUT"
[ "$(cj postfiatd-sentry .AppArmorProfile)" = pft-postfiatd ] && ok "apply run: container under pft-postfiatd" || ko "apply run: profile $(cj postfiatd-sentry .AppArmorProfile)" "$OUT"
[ "$(jq -cS "$SIGKEYS" "$FIX/apply-run.json")" = "$(cj postfiatd-sentry "$SIGKEYS | tostring" | jq -cS .)" ] \
  && ok "apply run: re-created container keeps every confine/identity field (built from the run args)" \
  || ko "apply run: fields differ" "$(diff <(jq -S "$SIGKEYS" "$FIX/apply-run.json") <(cj postfiatd-sentry "$SIGKEYS"))"
[ "$(cj postfiatd-sentry '.HostConfig.SecurityOpt | sort | join(",")')" = "apparmor=pft-postfiatd,no-new-privileges" ] \
  && ok "apply run: security_opt = no-new-privileges + apparmor=pft-postfiatd" || ko "apply run: security_opt" "$(cj postfiatd-sentry .HostConfig.SecurityOpt)"
[ "$(jq -r .HostConfig.RestartPolicy.Name "$A"/d/containers/postfiatd-sentry-preaa-*.json 2>/dev/null)" = no ] \
  && ok "apply run: previous container kept, restart=no" || ko "apply run: old container" "$(ls "$A/d/containers")"
[ "$(kmode pft-postfiatd)" = enforce ] && ok "apply run: kernel enforce" || ko "apply run: kernel mode '$(kmode pft-postfiatd)'"
cmp -s "$A/root/etc/apparmor.d/pft-postfiatd" "$A/profile" && ok "apply run: /etc/apparmor.d file = generated profile (enforce)" || ko "apply run: profile file differs"
grep -q '203\.0\.113\.7' <<<"$OUT" && ko "apply run: host IP printed" "$(grep 203.0.113.7 <<<"$OUT")" || ok "apply run: host IP masked in output"
grep -q 'NETWORK=testnet' <<<"$OUT" && ko "apply run: env value printed" "$OUT" || ok "apply run: env values masked in output"
grep -q -- '--publish=<redacted-ip>:2560:2559' <<<"$OUT" && ok "apply run: publish arg shown masked" || ko "apply run: publish arg" "$OUT"
grep -q 'gate PASS - exercise done, DENIED since T0: 0' <<<"$OUT" && ok "apply run: gate exercised the node, 0 DENIED" || ko "apply run: gate line" "$OUT"
grep -q 'exec postfiatd-sentry sh -c du -sb "$1/nudb" | cut -f1 sh /var/lib/postfiatd/db' "$A/d/calls" && grep -q 'exec postfiatd-sentry timeout 5 bash -c exec 3<>/dev/tcp/127.0.0.1/5005' "$A/d/calls" \
  && ok "apply run: gate ran the add-ons' read-only commands (retention du, egress /dev/tcp)" || ko "apply run: add-on exercise" "$(grep ' exec ' "$A/d/calls")"
[ "$(stf .phase)" = applied ] && [ "$(stf .kind)" = run ] && ok "apply run: state applied" || ko "apply run: state" "$(cat "$A"/root/var/lib/pft-apparmor/apply-*.json)"
arun audit
grep -qE '^\s*\[PASS\] container ' <<<"$OUT" && grep -qE '^\s*\[PASS\] recreate ' <<<"$OUT" && grep -qE '^\s*\[PASS\] mode ' <<<"$OUT" \
  && ok "apply run: audit afterwards: container/recreate/mode PASS" || ko "apply run: audit" "$OUT"
arun apply --profile-file "$A/profile" --yes
[ "$RC" = 4 ] && grep -q 'already runs under pft-postfiatd' <<<"$OUT" && ok "apply run: second apply refused (exit 4)" || ko "apply run: re-apply rc=$RC" "$OUT"
arun rollback
[ "$RC" = 4 ] && ok "rollback without --yes: exit 4" || ko "rollback without --yes: rc=$RC" "$OUT"
arun rollback --yes
[ "$RC" = 0 ] && grep -q 'rollback RESULT: PASS' <<<"$OUT" && ok "rollback run: PASS" || ko "rollback run: rc=$RC" "$OUT"
[ "$(cj postfiatd-sentry .AppArmorProfile)" = docker-default ] && [ "$(cj postfiatd-sentry .HostConfig.RestartPolicy.Name)" = unless-stopped ] \
  && ok "rollback run: previous container back (docker-default, unless-stopped)" || ko "rollback run: container" "$(cj postfiatd-sentry '{AppArmorProfile, r: .HostConfig.RestartPolicy}')"
[ ! -e "$A/root/etc/apparmor.d/pft-postfiatd" ] && [ -z "$(kmode pft-postfiatd)" ] && ok "rollback run: profile file removed + unloaded" || ko "rollback run: profile left"
[ "$(find "$A/d/containers" -name "*.json" | wc -l)" = 1 ] && ok "rollback run: no leftover container" || ko "rollback run: containers" "$(ls "$A/d/containers")"
[ "$(stf .rolled_back)" = true ] && [ "$(stf .rollback)" = manual ] && ok "rollback run: state rolled_back (manual)" || ko "rollback run: state"
arun rollback --yes
[ "$RC" = 0 ] && grep -q 'already rolled back' <<<"$OUT" && ok "rollback twice: no-op" || ko "rollback twice: rc=$RC" "$OUT"
arun apply --profile-file "$A/profile" --yes
[ "$RC" = 0 ] && [ "$(cj postfiatd-sentry .AppArmorProfile)" = pft-postfiatd ] && ok "re-apply after rollback: PASS" || ko "re-apply: rc=$RC" "$OUT"

# ---- compose container (validator) -----------------------------------------------------------------------
mk_apply compose; ENV0="$(cat "$A/root/opt/postfiatd/.env")"
arun apply --profile-file "$A/profile" --yes
[ "$RC" = 0 ] && ok "apply compose: PASS, exit 0" || ko "apply compose: rc=$RC" "$OUT"
grep -qx 'COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml:docker-compose.apparmor.yml' "$A/root/opt/postfiatd/.env" \
  && grep -qx 'NETWORK=testnet' "$A/root/opt/postfiatd/.env" && ok "apply compose: .env COMPOSE_FILE + other lines kept" || ko "apply compose: .env" "$(cat "$A/root/opt/postfiatd/.env")"
[ "$(stat -c %a "$A/root/opt/postfiatd/.env")" = 640 ] && ok "apply compose: .env mode kept (640)" || ko "apply compose: .env mode $(stat -c %a "$A/root/opt/postfiatd/.env")"
grep -q '"apparmor=pft-postfiatd"' "$A/root/opt/postfiatd/docker-compose.apparmor.yml" && ok "apply compose: override written" || ko "apply compose: override"
[ "$(cj postfiatd .AppArmorProfile)" = pft-postfiatd ] && ok "apply compose: container under pft-postfiatd" || ko "apply compose: profile"
arun audit
grep -qE '^\s*\[PASS\] recreate .*compose file sets' <<<"$OUT" && ok "apply compose: audit recreate PASS (override listed)" || ko "apply compose: audit" "$OUT"
grep -q 'pft-integrity accept' "$A/d/calls" && ko "apply compose: accept called with an empty diff" || ok "apply compose: integrity baseline current -> no accept"
arun rollback --yes
[ "$RC" = 0 ] && [ "$(cat "$A/root/opt/postfiatd/.env")" = "$ENV0" ] && [ ! -e "$A/root/opt/postfiatd/docker-compose.apparmor.yml" ] \
  && [ "$(cj postfiatd .AppArmorProfile)" = docker-default ] && ok "rollback compose: .env byte-identical, override gone, docker-default" \
  || ko "rollback compose: rc=$RC" "$OUT"

# ---- integrity baselines ---------------------------------------------------------------------------------
mk_apply compose
printf '  [WARN] container:postfiatd   changed id\n  [WARN] compose:.env   changed sha256\n  [WARN] compose:docker-compose.apparmor.yml  new\n' > "$A/d/integrity_out"
arun apply --profile-file "$A/profile" --yes
grep -q 'pft-integrity accept --reason pft-apparmor apply' "$A/d/calls" && grep -q 'integrity: accepted (compose:.env compose:docker-compose.apparmor.yml container:postfiatd)' <<<"$OUT" \
  && ok "integrity: own items accepted" || ko "integrity: own items" "$OUT"
mk_apply compose; printf '  [WARN] container:postfiatd   changed id\n  [FAIL] bin:pft-other   changed sha256\n' > "$A/d/integrity_out"
arun apply --profile-file "$A/profile" --yes
[ "$RC" = 0 ] && ! grep -q 'pft-integrity accept' "$A/d/calls" && grep -q 'NOT accepted .*bin:pft-other' <<<"$OUT" \
  && ok "integrity: foreign change -> not accepted (apply still PASS)" || ko "integrity: foreign rc=$RC" "$OUT"

# ---- refusals: nothing changes ---------------------------------------------------------------------------
mk_apply run; arun apply --profile-file "$A/profile"
[ "$RC" = 4 ] && ok "refuse: no --yes (exit 4)" || ko "refuse no --yes: rc=$RC" "$OUT"; nothing_changed "refuse no --yes"
mk_apply run; printf '{"window":"none","remaining_sec":null,"locks":[]}\n' > "$A/d/maint.json"; arun apply --profile-file "$A/profile" --yes
[ "$RC" = 4 ] && grep -q 'no active pft-maint window' <<<"$OUT" && ok "refuse: no window" || ko "refuse no window: rc=$RC" "$OUT"; nothing_changed "refuse no window"
mk_apply run; printf '{"window":"active","remaining_sec":2000,"locks":[]}\n' > "$A/d/maint.json"; HEALTH_BUDGET=900 arun apply --profile-file "$A/profile" --yes
[ "$RC" = 4 ] && grep -q 'needs 2\*HEALTH_BUDGET+MAINT_MARGIN=2100s' <<<"$OUT" && ok "refuse: window too short for apply + rollback" || ko "refuse short window: rc=$RC" "$OUT"
mk_apply run; printf '{"window":"active","remaining_sec":2700,"locks":["senders-tx 2026-11-03 task"]}\n' > "$A/d/maint.json"; arun apply --profile-file "$A/profile" --yes
[ "$RC" = 4 ] && grep -q 'data-collection lock' <<<"$OUT" && ok "refuse: data-collection lock held" || ko "refuse lock: rc=$RC" "$OUT"; nothing_changed "refuse lock"
mk_apply run; echo docker-default > "$A/d/rpc_bad_profile"; arun apply --profile-file "$A/profile" --yes
[ "$RC" = 4 ] && grep -q 'node is connected, not full' <<<"$OUT" && ok "refuse: node not full" || ko "refuse not full: rc=$RC" "$OUT"; nothing_changed "refuse not full"
mk_apply run; jq '.HostConfig.ReadonlyRootfs = false' "$FIX/apply-run.json" > "$A/d/containers/$CN.json"; arun apply --profile-file "$A/profile" --yes
[ "$RC" = 4 ] && grep -q 'not confined' <<<"$OUT" && ok "refuse: container not confined" || ko "refuse unconfined: rc=$RC" "$OUT"
mk_apply run; sed 's/^profile pft-postfiatd /profile pft-other /' "$A/profile" > "$A/p2"; arun apply --profile-file "$A/p2" --yes
[ "$RC" = 4 ] && grep -q 'does not define profile pft-postfiatd' <<<"$OUT" && ok "refuse: profile file of another name" || ko "refuse name: rc=$RC" "$OUT"; nothing_changed "refuse name"
mk_apply run; echo 1 > "$A/d/parser_rc"; arun apply --profile-file "$A/profile" --yes
[ "$RC" = 4 ] && grep -q 'does not compile' <<<"$OUT" && ok "refuse: candidate does not compile" || ko "refuse compile: rc=$RC" "$OUT"; nothing_changed "refuse compile"
mk_apply run; arun apply --yes
[ "$RC" = 3 ] && ok "apply without --profile-file: exit 3" || ko "apply usage: rc=$RC" "$OUT"

# ---- automatic rollback ----------------------------------------------------------------------------------
auto_rb() { # NAME: apply exit 1, previous container back, profile gone, state rolled_back auto
  if [ "$RC" = 1 ] && grep -q 'rollback RESULT: PASS' <<<"$OUT" && [ "$(cj "$CN" .AppArmorProfile)" = docker-default ] \
     && [ "$(cj "$CN" .HostConfig.RestartPolicy.Name)" = unless-stopped ] && [ ! -e "$A/root/etc/apparmor.d/pft-postfiatd" ] \
     && [ -z "$(kmode pft-postfiatd)" ] && [ "$(stf .rollback)" = auto ] && [ "$(find "$A/d/containers" -name "*.json" | wc -l)" = 1 ]; then ok "$1: rolled back (exit 1)"
  else ko "$1: rc=$RC" "$OUT"; fi
}
mk_apply run; echo ReadonlyRootfs > "$A/d/drop_on_recreate"; arun apply --profile-file "$A/profile" --yes
grep -q 'confine changed: read_only' <<<"$OUT" && ok "auto: lost read-only named by the gate" || ko "auto: lost read-only" "$OUT"
rm "$A/d/drop_on_recreate"; auto_rb "auto: lost read-only"
for m in run compose; do # the runtime ignores apparmor=: the node is healthy but still unconfined by the new profile
  mk_apply "$m"; echo docker-default > "$A/d/profile_on_recreate"; arun apply --profile-file "$A/profile" --yes
  grep -q "health FAIL .*profile 'docker-default' want pft-postfiatd;" <<<"$OUT" && ok "auto $m: wrong container profile named by the gate" || ko "auto $m: wrong profile" "$OUT"
  rm "$A/d/profile_on_recreate"; auto_rb "auto $m: wrong container profile"
done
mk_apply run; echo pft-postfiatd > "$A/d/rpc_bad_profile"; arun apply --profile-file "$A/profile" --yes
grep -q 'server_state connected' <<<"$OUT" && ok "auto: node not full under the profile named" || ko "auto: not full" "$OUT"; auto_rb "auto: not full"
mk_apply run
printf 'type=AVC msg=audit(%s.200:3): apparmor="DENIED" operation="open" profile="pft-postfiatd-learn" name="/x" pid=3 comm="x" requested_mask="r" denied_mask="r" fsuid=0 ouid=0\n' "$NOW" >> "$AUDIT_LOG"
arun apply --profile-file "$A/profile" --yes
[ "$RC" = 0 ] && ok "gate: DENIED of another profile (pft-postfiatd-learn) not counted" || ko "gate: other-profile DENIED rc=$RC" "$OUT"
mk_apply run; touch "$A/d/deny_on_exercise"; arun apply --profile-file "$A/profile" --yes
grep -q 'gate FAIL - 1 DENIED record' <<<"$OUT" && ok "auto: DENIED during the exercise fails the gate" || ko "auto: DENIED" "$OUT"; auto_rb "auto: DENIED"
mk_apply run; touch "$A/d/deny_on_addon"; arun apply --profile-file "$A/profile" --yes
grep -q 'gate FAIL - 1 DENIED record.*/usr/bin/du' <<<"$OUT" && ok "auto: DENIED on an add-on command (retention du) fails the gate" || ko "auto: add-on DENIED" "$OUT"; auto_rb "auto: add-on DENIED"
mk_apply run; touch "$A/d/fail_run"; arun apply --profile-file "$A/profile" --yes
rm "$A/d/fail_run"; auto_rb "auto: docker run failed"
mk_apply run; PFT_AA_INJECT=health arun apply --profile-file "$A/profile" --yes
grep -q 'injected failure' <<<"$OUT" && ok "auto: PFT_AA_INJECT=health named" || ko "auto: inject" "$OUT"; auto_rb "auto: injected"
mk_apply run; echo pft-heartbeat.service > "$A/d/inactive"; arun apply --profile-file "$A/profile" --yes
# the daemon stays down, so the rollback gate cannot pass either: exit 5 (rollback incomplete) is the honest answer
[ "$RC" = 5 ] && grep -q 'apply: health FAIL .*pft-heartbeat.service inactive' <<<"$OUT" && grep -q 'rollback: health FAIL' <<<"$OUT" \
  && [ "$(cj "$CN" .AppArmorProfile)" = docker-default ] && ok "auto: pft daemon down -> apply gate fails, container restored, exit 5" || ko "auto: daemon rc=$RC" "$OUT"
mk_apply compose; ENV0="$(cat "$A/root/opt/postfiatd/.env")"; touch "$A/d/fail_compose_up"; arun apply --profile-file "$A/profile" --yes
[ "$RC" = 1 ] && [ "$(cat "$A/root/opt/postfiatd/.env")" = "$ENV0" ] && [ ! -e "$A/root/opt/postfiatd/docker-compose.apparmor.yml" ] \
  && [ ! -e "$A/root/etc/apparmor.d/pft-postfiatd" ] && ok "auto compose: compose up failed -> .env restored, override + profile gone" || ko "auto compose: rc=$RC" "$OUT"
mk_apply compose; PFT_AA_INJECT=health arun apply --profile-file "$A/profile" --yes
[ "$RC" = 1 ] && [ "$(cj postfiatd .AppArmorProfile)" = docker-default ] && grep -q 'rollback RESULT: PASS' <<<"$OUT" \
  && ok "auto compose: injected gate failure rolled back" || ko "auto compose inject: rc=$RC" "$OUT"

# ---- existing profile file, complain mode ----------------------------------------------------------------
mk_apply run; printf '#include <tunables/global>\nprofile pft-postfiatd flags=(attach_disconnected) {\n  # older\n}\n' > "$A/root/etc/apparmor.d/pft-postfiatd"
cp "$A/root/etc/apparmor.d/pft-postfiatd" "$A/old"
arun apply --profile-file "$A/profile" --yes; arun rollback --yes
cmp -s "$A/old" "$A/root/etc/apparmor.d/pft-postfiatd" && [ "$(kmode pft-postfiatd)" = enforce ] \
  && ok "rollback: a pre-existing profile file is restored byte-identical and re-loaded" || ko "rollback pre-existing" "$OUT"
mk_apply run; arun apply --profile-file "$A/profile" --complain --yes
[ "$RC" = 0 ] && [ "$(kmode pft-postfiatd)" = complain ] && grep -q '^profile pft-postfiatd flags=(complain,attach_disconnected,mediate_deleted) {$' "$A/root/etc/apparmor.d/pft-postfiatd" \
  && ok "apply --complain: complain flag in file + kernel" || ko "apply --complain: rc=$RC" "$OUT"
arun audit
grep -qE '^\s*\[WARN\] mode ' <<<"$OUT" && ok "apply --complain: audit mode WARN (blocks nothing)" || ko "complain audit" "$OUT"
arun rollback --yes; sed 's/flags=(/flags=(complain,/' "$A/profile" > "$A/pc"; arun apply --profile-file "$A/pc" --yes
[ "$RC" = 0 ] && [ "$(kmode pft-postfiatd)" = enforce ] && ok "apply (enforce) of a complain-flagged file strips the flag" || ko "enforce strip: rc=$RC" "$OUT"
