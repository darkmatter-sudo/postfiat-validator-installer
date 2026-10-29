#!/usr/bin/env bash
# run / upgrade / host-info / resume cases (sourced by run-tests.sh; uses its ok/ko/expect helpers and run-stubs.sh).
# shellcheck disable=SC2016,SC2015,SC2154,SC2034
NR=0
rfresh() { NR=$((NR + 1)); RD="$T/r$NR"; mk_run "$RD"; use_run "$RD" "$TOOL"; }
calls() { cat "$RD/calls"; }
vcalls() { cat "$RD/validator/s/calls"; }   # apt-get/needrestart calls on the validator
scalls() { cat "$RD/sentry/s/calls"; }
sec_both() { echo "$SIM_SEC" > "$RD/sentry/s/sim"; echo "$SIM_SEC" > "$RD/validator/s/sim"; }
first_line() { grep -n -- "$1" "$2" | head -1 | cut -d: -f1; }
vinstall() { grep -q '^apt-get .*install' "$RD/validator/s/calls"; }
vtouched() { vinstall || grep -q '^apt-get .*update' "$RD/validator/s/calls" || grep -q 'validator: pft-maint start .*validator' "$RD/calls"; }

# --- host-info and upgrade (one host)
rfresh; run host-info
expect "host-info format" 0 '^boot=boot-[0-9]+ dpkg=[0-9a-f]{64} reboot=0$'
run upgrade
expect "upgrade without --yes refused" 4 'add --yes'
grep -q '^apt-get .*install' "$STUB_S/calls" && ko "no install after refusal" || ok "no install after refusal"

rfresh
printf '%s\n%s\n%s\n%s\n%s\n' "$SIM_SEC" "$SIM_OTH" \
  'Inst docker.io [24.0.7-0ubuntu2~22.04.1] (24.0.7-0ubuntu2~22.04.2 Ubuntu:22.04/jammy-security [amd64])' \
  'Inst tmux [3.2a-4ubuntu0.1] (3.2a-4ubuntu0.2 Ubuntu:22.04/jammy-security [amd64])' \
  'Inst linux-image-5.15.0-202-generic (5.15.0-202.212 Ubuntu:22.04/jammy-updates [amd64])' > "$STUB_S/sim"
echo tmux > "$STUB_S/holds"; cp "$STUB_S/sim" "$T/sim5"
run upgrade --yes
expect "security-only installs only security, not runtime/held" 0 'PLAN libssl3 security 3.0.2-0ubuntu1.18 -> 3.0.2-0ubuntu1.19'
expect "other update skipped in security-only" 0 'SKIP nano other \(security-only run; use --all\)'
expect "runtime package skipped without --runtime" 0 'SKIP docker.io Docker runtime'
expect "held package skipped" 0 'SKIP tmux held'
expect "new package left to dependencies" 0 'DEP linux-image-5.15.0-202-generic'
expect "no services -> DECISION none" 0 '^DECISION none$'
[ "$(grep '^apt-get .*install' "$STUB_S/calls")" = "apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --only-upgrade libssl3" ] \
  && ok "install command line (only-upgrade libssl3, confold)" || ko "install command line" "$(cat "$STUB_S/calls")"
grep -q '^apt-get -q update' "$STUB_S/calls" && ok "apt-get update before install" || ko "apt-get update before install"
cp "$T/sim5" "$STUB_S/sim"; : > "$STUB_S/calls"; run upgrade --yes --all
grep -q 'install --only-upgrade libssl3 nano$' "$STUB_S/calls" && ok "--all adds other updates (still no runtime/held)" || ko "--all adds other updates" "$(cat "$STUB_S/calls")"
cp "$T/sim5" "$STUB_S/sim"; : > "$STUB_S/calls"; run upgrade --yes --all --runtime
grep -q 'install --only-upgrade libssl3 nano docker.io$' "$STUB_S/calls" && ok "--runtime adds Docker runtime packages" || ko "--runtime adds runtime" "$(cat "$STUB_S/calls")"

while IFS='|' read -r name setup want re; do
  [ -z "$name" ] && continue
  rfresh; echo "$SIM_SEC" > "$STUB_S/sim"; eval "$setup"; run upgrade --yes
  expect "upgrade: $name" "$want" "$re"
done <<'CASES'
reboot-required after install -> reboot|touch "$STUB_S/install_reboot"|0|^DECISION reboot \(reboot-required by: linux-base\)$
newer kernel after install -> reboot|touch "$STUB_S/install_ksta3"|0|^DECISION reboot \(newer kernel installed, needrestart KSTA 3\)$
services -> restarted, docker deferred|printf 'NEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: docker.service\nNEEDRESTART-SVC: cron.service\n' > "$STUB_S/install_svc"|0|DEFERRED docker.service \(not restarted by pft-patch
services decision line|printf 'NEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: dbus.service\n' > "$STUB_S/install_svc"|0|^DECISION restart ssh.service$
restart failure -> exit 2|printf 'NEEDRESTART-SVC: ssh.service\n' > "$STUB_S/install_svc"; mkdir -p "$RD/validator/s"; touch "$RD/validator/s/restart_fail"|2|UPGRADE FAIL systemctl restart ssh.service
install failure -> exit 2|touch "$STUB_S/install_fail"|2|UPGRADE FAIL apt-get install exit 100
update failure -> exit 2|touch "$STUB_S/update_fail"|2|UPGRADE FAIL apt-get update
needrestart without kernel state -> exit 2|printf 'NEEDRESTART-VER: 3.5\n' > "$STUB_S/nr"|2|UPGRADE FAIL needrestart gave no kernel state
nothing pending -> no install|: > "$STUB_S/sim"|0|INSTALLED 0 package
CASES
rfresh; echo "$SIM_SEC" > "$STUB_S/sim"; printf 'NEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: docker.service\n' > "$STUB_S/install_svc"; run upgrade --yes
grep -q 'validator: systemctl restart docker.service' "$RD/calls" && ko "docker.service never restarted" || ok "docker.service never restarted"
grep -q 'validator: systemctl restart ssh.service' "$RD/calls" && ok "ssh.service restarted via systemctl" || ko "ssh.service restarted" "$OUT"

# --- run: happy path, security-only, both hosts
rfresh; sec_both; run run
expect "run without --yes refused" 4 'add --yes'
[ -s "$RD/calls" ] && ko "refused run calls nothing" "$(calls)" || ok "refused run calls nothing"
run run --yes
expect "run both -> PASS" 0 'RESULT: PASS - sentry validator patched and gated'
expect "security-only mode logged" 0 'hosts sentry validator \(in this order\), mode security-only'
s1="$(grep -n 'sentry: pft-patch upgrade' "$RD/calls" | head -1 | cut -d: -f1)"; v1="$(grep -n 'validator: pft-patch upgrade' "$RD/calls" | head -1 | cut -d: -f1)"
[ -n "$s1" ] && [ -n "$v1" ] && [ "$s1" -lt "$v1" ] && ok "sentry upgraded before validator" || ko "sentry upgraded before validator" "$(calls)"
for g in "GATE pre sentry node: PASS" "GATE post sentry node: PASS" "GATE pre validator integrity: PASS" "GATE post validator egress: PASS" \
  "GATE post sentry audittrail: PASS" "GATE post validator reboot-flag: PASS" "STATUS before sentry:" "STATUS after validator:"; do
  grep -qF -- "$g" <<<"$OUT" && ok "logged: $g" || ko "logged: $g" "$OUT"
done
[ "$(grep -c 'pft-maint start' "$RD/calls")" = 2 ] && [ "$(grep -c 'pft-maint end' "$RD/calls")" = 2 ] && ok "one maint window per host" || ko "one maint window per host" "$(calls)"
grep -q 'sentry: pft-maint' "$RD/calls" && ko "pft-maint runs on the maint host only" || ok "pft-maint runs on the maint host only"
[ "$(grep -c 'curl POST http://am.test:9093/api/v2/silences' "$RD/calls")" = 2 ] && [ "$(grep -c 'curl DELETE http://am.test:9093/api/v2/silence/sil0123456789' "$RD/calls")" = 2 ] \
  && ok "silence per host, expired when nothing restarted" || ko "silence per host, expired" "$(calls)"
w="$(first_line 'pft-maint start' "$RD/calls")"; [ -n "$w" ] && [ "$w" -lt "$s1" ] && ok "window opened before the first install" || ko "window before install"
grep -q 'install --only-upgrade libssl3' "$RD/sentry/s/calls" && grep -q 'install --only-upgrade libssl3' "$RD/validator/s/calls" && ok "both hosts installed" || ko "both hosts installed"

rfresh; sec_both; run run --yes --hosts validator,sentry
expect "--hosts order ignored, config order used" 0 'hosts sentry validator \(in this order\)'
rfresh; sec_both; run run --yes --hosts validator
expect "--hosts validator only" 0 'RESULT: PASS - validator patched'
grep -q 'sentry: pft-patch upgrade' "$RD/calls" && ko "sentry not upgraded with --hosts validator" || ok "sentry not upgraded with --hosts validator"
rfresh; run run --yes --hosts sentry,nosuch
expect "--hosts unknown -> 3" 3 "unknown host 'nosuch'"
rfresh; sec_both; run run --yes --all
expect "--all mode logged" 0 'mode all'
grep -q 'sentry: pft-patch upgrade --yes --all' "$RD/calls" && ok "--all passed to the host step" || ko "--all passed to the host step" "$(calls)"

# --- injected sentry post-gate failure: validator untouched
rfresh; sec_both; PFT_PATCH_INJECT=sentry-postgate run run --yes
expect "injected: exit 1" 1 'RESULT: FAIL at sentry \(post-gate\)'
expect "injected failure labelled as drill" 1 'GATE post sentry INJECTED-FAILURE: drill \(PFT_PATCH_INJECT=sentry-postgate\), not a host fault'
expect "injected: real checks still reported" 1 'GATE post sentry node: PASS'
expect "injected: validator untouched proof" 1 'UNTOUCHED validator: boot id, dpkg.log sha256 and container StartedAt equal'
vtouched && ko "injected: no apt/window on the validator" "$(vcalls)" || ok "injected: no apt/window on the validator"
grep -q 'curl DELETE .*silence/sil0123456789' "$RD/calls" && ok "failed host: silence expired (alerts flow)" || ko "failed host: silence expired"
grep -q 'pft-maint end --reason pft-patch .* sentry fail' "$RD/calls" && ok "failed host: window ended" || ko "failed host: window ended" "$(calls)"

# a later host that DID change during the run is reported (exit 5), not called untouched
rfresh; sec_both; echo "post sentry echo late >> $RD/validator/root/var/log/dpkg.log" >> "$RD/hosts.conf"; touch "$RD/sentry/s/install_reboot"
PFT_PATCH_INJECT=sentry-postgate run run --yes
expect "changed later host -> exit 5" 5 'CHANGED validator: was'

# --- sentry reboot path
rfresh; sec_both; touch "$RD/sentry/s/install_reboot"; b0="$(cat "$RD/sentry/root/proc/sys/kernel/random/boot_id")"; run run --yes
expect "sentry reboot -> PASS" 0 'RESULT: PASS'
expect "sentry reboot decision" 0 'DECISION sentry: reboot \(reboot-required by: linux-base\)'
expect "sentry back with new boot id" 0 'REBOOT sentry: back after [0-9]+s'
[ "$(cat "$RD/sentry/root/proc/sys/kernel/random/boot_id")" != "$b0" ] && ok "boot id changed" || ko "boot id changed"
grep -q 'sentry: pft-egress reapply --container postfiatd-sentry' "$RD/calls" && ok "post hook after reboot" || ko "post hook after reboot" "$(calls)"
grep -q 'validator: systemd-run' "$RD/calls" && ko "validator not rebooted" || ok "validator not rebooted"
grep -q 'curl POST .*"id":"sil0123456789"' "$RD/calls" && ok "restarted host: silence kept SILENCE_TAIL (updated)" || ko "silence updated after reboot" "$(calls)"
expect "restarted host: silence kept message" 0 'silence sil01234 kept until'

rfresh; sec_both; touch "$RD/sentry/s/install_reboot" "$RD/sentry/s/ssh_down_after_reboot"; run run --yes
expect "sentry not back -> FAIL" 1 'REBOOT sentry: not back within 60s'
expect "sentry not back: validator untouched" 1 'UNTOUCHED validator'
vtouched && ko "sentry not back: validator not touched" || ok "sentry not back: validator not touched"

rfresh; sec_both; touch "$RD/sentry/s/install_reboot" "$RD/sentry/s/down_after_reboot"; run run --yes
expect "post-gate waits for full after reboot" 0 'GATE post sentry node: PASS state=full peers=12 age=2s \(\+[1-9][0-9]*s\)'

# --- gates fail closed
while IFS='|' read -r name setup want re; do
  [ -z "$name" ] && continue
  rfresh; sec_both; eval "$setup"; run run --yes
  expect "gate: $name" "$want" "$re"
  vinstall && ko "gate: $name -> validator not installed" || ok "gate: $name -> validator not installed"
done <<'CASES'
sentry not full before -> pre-gate fail|echo '{"server_state":"syncing","peers":9,"validated_ledger":{"age":2}}' > "$RD/sentry/s/info"|1|GATE pre sentry node: FAIL state=syncing
sentry few peers|echo '{"server_state":"full","peers":2,"validated_ledger":{"age":2}}' > "$RD/sentry/s/info"|1|FAIL\(peers=2<5\)
stale validated ledger|echo '{"server_state":"full","peers":9,"validated_ledger":{"age":300}}' > "$RD/sentry/s/info"|1|FAIL\(age=300s>20s\)
validator integrity WARN before -> refused at validator pre|touch "$RD/validator/s/integrity_warn"|1|GATE pre validator integrity: FAIL exit 1
sentry integrity changes in upgrade|touch "$RD/sentry/s/install_integrity"|1|GATE post sentry integrity: FAIL exit 1
sentry audittrail fails|touch "$RD/sentry/s/audit_fail"|1|GATE pre sentry audittrail: FAIL
sentry egress fails|touch "$RD/sentry/s/egress_fail"|1|GATE pre sentry egress: FAIL
sentry install fails|touch "$RD/sentry/s/install_fail"|1|STOP: sentry failed \(upgrade failed\)
sentry unreachable|touch "$RD/sentry/s/ssh_down"|4|PREFLIGHT sentry: unreachable or pft-patch not installed
sentry node never full after|echo 99 > "$RD/sentry/s/down_after_reboot"; touch "$RD/sentry/s/install_reboot"; sed -i 's/echo 2 >/echo 99 >/' "$RD/rbin/systemd-run"|1|GATE post sentry node: FAIL state=connected
maint lock held|touch "$RD/validator/s/lock"|4|PREFLIGHT: pft-maint data-collection lock held
maint start refused|touch "$RD/validator/s/maint_fail"|1|STOP: sentry failed \(maintenance window\)
Alertmanager silence fails|touch "$RD/am_fail"|1|WINDOW sentry: Alertmanager silence failed
CASES
rfresh; sec_both; touch "$RD/am_fail"; run run --yes
grep -q '^apt-get .*install' "$RD/sentry/s/calls" && ko "no silence -> sentry not installed" || ok "no silence -> sentry not installed"
rfresh; sec_both; touch "$RD/sentry/s/integrity_warn"; run run --yes
grep -q 'sentry: pft-maint\|validator: pft-maint start' "$RD/calls" && ko "pre-gate fail opens no window" "$(calls)" || ok "pre-gate fail opens no window"

# --- refusals
rfresh; printf 'host validator local - postfiatd 5\nhost sentry ssh relay postfiatd-sentry 5\n' > "$RD/hosts.conf"; run run --yes
expect "local host not last -> refused" 4 'the local host validator must be the last host'
rfresh; touch "$RD/state/resume.json"; run run --yes
expect "pending resume -> refused" 4 'resume.json exists'
rfresh; sec_both; OUT="$(flock "$RD/state/run.lock" bash "$TOOL" run --yes 2>&1)"; RC=$?
expect "concurrent run -> refused" 4 'another pft-patch run holds'
rfresh; rm "$RD/hosts.conf"; run run --yes
expect "no config -> 3" 3 'no hosts config'

# --- validator (local) reboot: schedule + resume at boot
rfresh; sec_both; touch "$RD/validator/s/install_reboot"; run run --yes
expect "local reboot -> exit 10" 10 'REBOOT validator: this host reboots in 15 s'
[ -f "$RD/state/resume.json" ] && jq -e '.host=="validator" and .silence=="sil0123456789"' "$RD/state/resume.json" >/dev/null && ok "resume.json written" || ko "resume.json written"
grep -q 'validator: systemd-run --on-active=15 .* systemctl reboot' "$RD/calls" && ok "local reboot scheduled via systemd-run" || ko "local reboot scheduled" "$(calls)"
[ "$(grep -c 'pft-maint end' "$RD/calls")" = 1 ] && ok "validator window stays open over the reboot" || ko "validator window stays open" "$(calls)"
run resume
expect "resume: post-gate and PASS" 0 'RESULT: PASS - validator patched, rebooted and gated'
expect "resume: post-gate reboot flag cleared" 0 'GATE post validator reboot-flag: PASS'
[ ! -e "$RD/state/resume.json" ] && ok "resume.json removed" || ko "resume.json removed"
[ "$(grep -c 'pft-maint end' "$RD/calls")" = 2 ] && grep -q 'curl POST .*"id":"sil0123456789"' "$RD/calls" && ok "resume closes the window, keeps silence tail" || ko "resume closes window" "$(calls)"
run resume
expect "resume with nothing pending" 0 'nothing to resume'
