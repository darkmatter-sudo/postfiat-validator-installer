#!/usr/bin/env bash
# shellcheck disable=SC2015  # ok() and no() always return 0
# Offline tests for pft-monupgrade apply / rollback against a stateful fake docker + Prometheus/Alertmanager/ntfy
# (tests/fake_stack.py). Every refusal asserts exit 4 AND zero container changes; every failed switch asserts the
# automatic rollback (previous images running, restart policy, silences, no leftover -premonupgrade container).
# Run: bash tests/run-apply-tests.sh
set -uo pipefail
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$T/../pft-monupgrade.sh"
SCRATCH="$(mktemp -d -p "${TMPDIR:-$HOME/.cache}" monupgrade-apply.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT
chmod 755 "$SCRATCH"
mkdir -p "$SCRATCH/bin" "$SCRATCH/alerts" "$SCRATCH/slo"
printf '#!/bin/sh\nexec python3 %q docker "$@"\n' "$T/fake_stack.py" >"$SCRATCH/bin/docker"
printf '#!/bin/sh\nexec python3 %q curl "$@"\n' "$T/fake_stack.py" >"$SCRATCH/bin/curl"
# shellcheck disable=SC2016  # the $ is for the stub script
printf '#!/bin/sh\nexit "${STUB_MAINT_RC:-0}"\n' >"$SCRATCH/bin/pft-maint"
cat >"$SCRATCH/bin/ss" <<'EOF'
#!/bin/sh
a=127.0.0.1; [ "${STUB_SS_EXPOSED:-0}" = 1 ] && a=0.0.0.0
printf 'LISTEN 0 4096 %s:9090 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:9093 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:9095 0.0.0.0:*\n' "$a"
EOF
chmod 755 "$SCRATCH/bin/"*
echo 'global: {}' >"$SCRATCH/alerts/prometheus.yml"; echo 'route: {}' >"$SCRATCH/alerts/alertmanager.yml"

D1=sha256:$(printf '1%.0s' {1..64}); D2=sha256:$(printf '2%.0s' {1..64})
DC=sha256:$(printf 'c%.0s' {1..64}); D7=sha256:$(printf '7%.0s' {1..64})
P_OLD=prom/prometheus:v3.5.0 A_OLD=prom/alertmanager:v0.28.1
P_NEW=prom/prometheus:v3.15.1@$DC A_NEW=prom/alertmanager:v0.35.0@$D7
TEST_URL=https://ntfy.example/throwaway-test

PASS=0 FAILN=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
no() { FAILN=$((FAILN + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

# fresh STUB_DIR with the original stack; ENV knobs apply to this case only
setup() {
  export STUB_DIR="$SCRATCH/stub-$1"; rm -rf "$STUB_DIR"; mkdir -p "$STUB_DIR/state"; : >"$STUB_DIR/calls"
  printf 'NTFY_URL=%s\n' "$TEST_URL" >"$STUB_DIR/ntfy.env"; touch -d '-1 min' "$STUB_DIR/ntfy.env"
  python3 - "$STUB_DIR" "$SCRATCH" <<'PY'
import json, sys, time
sd, scr = sys.argv[1], sys.argv[2]
d = lambda c: "sha256:" + c * 64
now = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
def cont(name, image, iid, ep, mounts, args, ro=False, user="nobody", log=None):
    return {"name": name, "image": image, "image_id": iid, "entrypoint": ep, "args": args, "running": True,
            "started": now, "user": user, "restart": "unless-stopped", "network": "host", "security": ["no-new-privileges"],
            "capdrop": ["ALL"], "readonly": ro, "mounts": mounts, "log": log or {"Type": "json-file", "Config": {}}}
bind = lambda s, t, rw=False: {"Type": "bind", "Name": None, "Source": s, "Destination": t, "RW": rw}
vol = lambda n, t: {"Type": "volume", "Name": n, "Source": f"/var/lib/docker/volumes/{n}/_data", "Destination": t, "RW": True}
st = {
 "images": [
  {"id": d("1"), "tags": ["prom/prometheus:v3.5.0"], "repo_digests": ["prom/prometheus@" + d("1")], "entrypoint": ["/bin/prometheus"]},
  {"id": d("2"), "tags": ["prom/alertmanager:v0.28.1"], "repo_digests": ["prom/alertmanager@" + d("2")], "entrypoint": ["/bin/alertmanager"]},
  {"id": d("c"), "tags": [], "repo_digests": ["prom/prometheus@" + d("c")], "entrypoint": ["/bin/prometheus"]},
  {"id": d("7"), "tags": [], "repo_digests": ["prom/alertmanager@" + d("7")], "entrypoint": ["/bin/alertmanager"]}],
 "containers": {
  "pft-prometheus": cont("pft-prometheus", "prom/prometheus:v3.5.0", d("1"), ["/bin/prometheus"],
     [bind(scr + "/alerts", "/etc/pft-alerts"), bind(scr + "/slo", "/etc/pft-slo"), vol("pft-prometheus-data", "/prometheus")],
     ["--config.file=/etc/pft-alerts/prometheus.yml", "--web.listen-address=127.0.0.1:9090", "--storage.tsdb.path=/prometheus"]),
  "pft-alertmanager": cont("pft-alertmanager", "prom/alertmanager:v0.28.1", d("2"), ["/bin/alertmanager"],
     [vol("anonvol286418", "/alertmanager"), bind(scr + "/alerts/alertmanager.yml", "/etc/pft-alerts/alertmanager.yml")],
     ["--config.file=/etc/pft-alerts/alertmanager.yml", "--web.listen-address=127.0.0.1:9093", "--cluster.listen-address=", "--storage.path=/alertmanager"]),
  "pft-alert-bridge": cont("pft-alert-bridge", "python:3.12-alpine", d("9"), None,
     [bind(sd + "/ntfy.env", "/run/secrets/ntfy.env")], ["python3", "-u", "/app/ntfy_bridge.py"], ro=True, user="1001:1001",
     log={"Type": "json-file", "Config": {"max-file": "5", "max-size": "100m"}})},
 "am_volume": "anonvol286418",
 "silences": [{"id": "sil-1", "status": {"state": "active"}}, {"id": "sil-old", "status": {"state": "expired"}}],
 "posted": [], "ntfy": []}
json.dump(st, open(sd + "/state.json", "w"), indent=1)
PY
  write_plan "$STUB_DIR/plan.json" "$(date -u +%FT%TZ)" "$D1" "$D2" '[]'
}
write_plan() { # FILE PLANNED_AT PROM_CURRENT_DIGEST AM_CURRENT_DIGEST FAILS_JSON
  jq -n --arg at "$2" --arg pc "$3" --arg ac "$4" --argjson f "$5" --arg dc "$DC" --arg d7 "$D7" '{planned_at: $at,
    control: "PASS", fails: $f, prometheus: {current_ref: "prom/prometheus:v3.5.0", current_digest: $pc, target_tag: "v3.15.1", target_digest: $dc},
    alertmanager: {current_ref: "prom/alertmanager:v0.28.1", current_digest: $ac, target_tag: "v0.35.0", target_digest: $d7}}' >"$1"
}

# run_tool [ENV=VAL ...] -- ARGS... (uses the current STUB_DIR); sets OUT RC
run_tool() {
  local envs=()
  while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
  : >"$STUB_DIR/calls"
  OUT="$(env PATH="$SCRATCH/bin:$PATH" DOCKER="$SCRATCH/bin/docker" CURL="$SCRATCH/bin/curl" SS="$SCRATCH/bin/ss" \
    PFT_MAINT_BIN="$SCRATCH/bin/pft-maint" PFT_MU_ALLOW_NONROOT=1 STATE_DIR="$STUB_DIR/state" \
    ALERTS_DIR="$SCRATCH/alerts" SLO_DIR="$SCRATCH/slo" NTFY_TEST_URL="$TEST_URL" \
    READY_TIMEOUT=3 SETTLE_TIMEOUT=3 DELIVERY_TIMEOUT=3 POLL=1 "${envs[@]}" "$TOOL" "$@" 2>&1)"
  RC=$?
}
st() { jq -r "$1" "$STUB_DIR/state.json"; }
expect_rc() { [ "$RC" -eq "$2" ] && ok "$1: exit $2" || no "$1" "exit $RC, want $2; output:"$'\n'"$OUT"; }
expect_out() { grep -qE -- "$2" <<<"$OUT" && ok "$1: output has /$2/" || no "$1" "output lacks /$2/:"$'\n'"$OUT"; }
expect_eq() { [ "$2" = "$3" ] && ok "$1: $3" || no "$1" "got '$2', want '$3'"; }
no_changes() {
  local n; n="$(grep -cE '^docker (stop|rename|update|run|rm|start) ' "$STUB_DIR/calls" || true)"
  expect_eq "$1: container-changing docker calls" "$n" 0
}
on_images() { # LABEL PROM_REF AM_REF -> both running on them, policy unless-stopped, no leftovers, silences intact
  expect_eq "$1: prometheus image" "$(st '.containers["pft-prometheus"].image')" "$2"
  expect_eq "$1: alertmanager image" "$(st '.containers["pft-alertmanager"].image')" "$3"
  expect_eq "$1: both running" "$(st '[.containers["pft-prometheus","pft-alertmanager"].running] | all')" true
  expect_eq "$1: restart policies" "$(st '[.containers["pft-prometheus","pft-alertmanager"].restart] | unique | join(",")')" unless-stopped
  expect_eq "$1: leftover -premonupgrade" "$(st '[.containers | keys[] | select(endswith("-premonupgrade"))] | length')" 0
  expect_eq "$1: AM data volume" "$(st '.containers["pft-alertmanager"].mounts[] | select(.Destination == "/alertmanager") | .Name')" anonvol286418
  expect_eq "$1: volumes removed" "$(st '.volumes_removed // [] | length')" 0
}

# --- happy path: apply -> second apply (no-op) -> rollback -> rollback (no-op) -> re-apply -------------------------
setup cycle
run_tool -- apply --plan "$STUB_DIR/plan.json" --yes
expect_rc apply 0
for c in prometheus-image alertmanager-image ready prometheus-version alertmanager-version rules-parity targets-parity \
  targets_up-parity receivers-parity rules-health silences-kept watchdog-unsilenced loopback-only test-alert \
  test-alert-resolved pft-prometheus-signature pft-alertmanager-signature; do
  expect_out apply "CHECK $c +ok"
done
expect_out apply "CHECK test-alert +ok delivered \"\[FIRING\] PFTMonupgradeTest\""
expect_out apply "CHECK test-alert-resolved +ok delivered \"\[RESOLVED\] PFTMonupgradeTest\""
expect_out apply "RESULT: PASS - apply: prometheus $P_OLD -> $P_NEW, alertmanager $A_OLD -> $A_NEW"
on_images apply "$P_NEW" "$A_NEW"
expect_eq "apply: config + user + args carried" "$(st '.containers["pft-alertmanager"] | [.user, .network, (.security|join(",")), (.capdrop|join(",")), (.args|length)] | join(" ")')" "nobody host no-new-privileges ALL 4"
expect_eq "apply: AM recreated before Prometheus" "$(grep -E '^docker run ' "$STUB_DIR/calls" | sed -E 's/.* (prom\/[a-z]+):.*/\1/' | tr '\n' ' ')" "prom/alertmanager prom/prometheus "
expect_eq "apply: test alert resolved" "$(st '[.posted[] | select(.labels.alertname == "PFTMonupgradeTest")] | length')" 2
expect_eq "apply: state mode" "$(jq -r '.mode + " " + .previous.prometheus' "$STUB_DIR/state/state.json")" "apply $P_OLD"
b="$(ls "$STUB_DIR/state/backup")"
(cd "$STUB_DIR/state/backup/$b" && sha256sum -c --quiet SHA256SUMS) && ok "apply: backup SHA256SUMS verify" || no apply "backup sums"
expect_eq "apply: backup silences" "$(jq '[.[] | select(.status.state == "active")] | length' "$STUB_DIR/state/backup/$b/silences.json")" 1

run_tool -- apply --plan "$STUB_DIR/plan.json" --yes
expect_rc apply2 0
expect_out apply2 "RESULT: NOTHING TO DO"
no_changes apply2

run_tool -- rollback --yes
expect_rc rollback 0
expect_out rollback "RESULT: PASS - rollback: prometheus $P_NEW -> $P_OLD, alertmanager $A_NEW -> $A_OLD"
expect_out rollback "CHECK silences-kept +ok 1 active"
on_images rollback "$P_OLD" "$A_OLD"

run_tool -- rollback --yes
expect_rc rollback2 0
expect_out rollback2 "RESULT: NOTHING TO DO"
no_changes rollback2

run_tool -- apply --plan "$STUB_DIR/plan.json" --yes
expect_rc reapply 0
on_images reapply "$P_NEW" "$A_NEW"

# --- refusals: exit 4, nothing changed ----------------------------------------------------------------------------
refusal() { # NAME REGEX [ENV...] -- ARGS
  local name="$1" rx="$2"; shift 2
  run_tool "$@"; expect_rc "$name" 4; expect_out "$name" "REFUSED: $rx"; no_changes "$name"
  on_images "$name" "$P_OLD" "$A_OLD"
}
setup r; refusal noyes "--yes missing" -- apply --plan "$STUB_DIR/plan.json"
setup r; refusal nonroot "run as root" PFT_MU_ALLOW_NONROOT=0 -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; refusal nomaint "no active pft-maint window" STUB_MAINT_RC=1 -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; refusal nourl "alert routing not isolated: NTFY_TEST_URL is not set" NTFY_TEST_URL= -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; printf 'NTFY_URL=https://ntfy.example/operator\n' >"$STUB_DIR/ntfy.env"; touch -d '-1 min' "$STUB_DIR/ntfy.env"
refusal operator "alert routing not isolated: bridge env does not point at NTFY_TEST_URL" -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; touch -d '+1 hour' "$STUB_DIR/ntfy.env"
refusal oldbridge "alert routing not isolated: bridge started before its env file changed" -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; write_plan "$STUB_DIR/plan.json" "$(date -u -d '-2 days' +%FT%TZ)" "$D1" "$D2" '[]'
refusal stale "plan is [0-9]+s old" -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; write_plan "$STUB_DIR/plan.json" "$(date -u +%FT%TZ)" "$D1" "$D2" '["prometheus","promtool-test-rules"]'
refusal planfail "plan has failures" -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; write_plan "$STUB_DIR/plan.json" "$(date -u +%FT%TZ)" "$D7" "$D2" '[]'
refusal changed "prometheus changed since the plan" -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; jq 'del(.images[2])' "$STUB_DIR/state.json" >"$STUB_DIR/s" && mv "$STUB_DIR/s" "$STUB_DIR/state.json"
refusal noimage "target prom/prometheus:v3.15.1@sha256:c+ not in the image store" -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; refusal wdsil "watchdog PFTAlertPipelineWatchdog not active or silenced" STUB_WATCHDOG_SILENCED=1 -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; refusal apidown "Prometheus/Alertmanager not ready" STUB_API_DOWN=1 -- apply --plan "$STUB_DIR/plan.json" --yes
setup r; jq '.containers["pft-prometheus-premonupgrade"] = (.containers["pft-prometheus"] | .name = "pft-prometheus-premonupgrade" | .running = false)' \
  "$STUB_DIR/state.json" >"$STUB_DIR/s" && mv "$STUB_DIR/s" "$STUB_DIR/state.json"
run_tool -- apply --plan "$STUB_DIR/plan.json" --yes
expect_rc leftover 4; expect_out leftover "REFUSED: pft-prometheus-premonupgrade exists"; no_changes leftover
setup r; refusal norollback "no earlier apply recorded" -- rollback --yes

# --- failed switches: automatic rollback to the previous containers, exit 1 ---------------------------------------
failure() { # NAME REGEX(expected failure text) ENV... (apply with the knob set)
  local name="$1" rx="$2"; shift 2
  setup "f-$name"
  run_tool "$@" -- apply --plan "$STUB_DIR/plan.json" --yes
  expect_rc "$name" 1
  expect_out "$name" "$rx"
  expect_out "$name" "RESULT: FAIL - apply rolled back \(exit 1\)"
  on_images "$name" "$P_OLD" "$A_OLD"
  [ -e "$STUB_DIR/state/state.json" ] && no "$name" "state.json written by a failed apply" || ok "$name: no state.json"
}
failure amrun "docker run failed for pft-alertmanager" STUB_RUN_FAIL='alertmanager:v0\.35'
failure promrun "docker run failed for pft-prometheus" STUB_RUN_FAIL='prometheus:v3\.15'
failure ready "CHECK ready +FAIL" STUB_READY_FAIL='prometheus:v3\.15'
failure rules "CHECK rules-parity +FAIL .*missing.*PFTC" STUB_RULES_DROP='prometheus:v3\.15'
failure ruleerr "CHECK rules-health +FAIL \[\"PFTB\"\]" STUB_RULE_ERR='prometheus:v3\.15'
failure target "CHECK targets_up-parity +FAIL" STUB_TARGET_DOWN='prometheus:v3\.15'
failure delivery "CHECK test-alert +FAIL not delivered to NTFY_TEST_URL" STUB_NO_DELIVERY=1
failure exposed "CHECK loopback-only +FAIL" STUB_SS_EXPOSED=1
failure noresolved "CHECK test-alert-resolved +FAIL \[RESOLVED\] not delivered to NTFY_TEST_URL" STUB_NO_RESOLVED=1
failure silences "CHECK silences-kept +FAIL lost \[\"sil-1\"\]" STUB_SILENCES_LOST='alertmanager:v0\.35'
failure secopt "CHECK pft-alertmanager-signature FAIL .*no-new-privileges" STUB_DROP_SECOPT='alertmanager:v0\.35'

# rollback whose gate fails goes back to the applied images
setup rbfail
run_tool -- apply --plan "$STUB_DIR/plan.json" --yes
expect_rc rbfail-apply 0
run_tool STUB_RULES_DROP='prometheus:v3\.5\.0' -- rollback --yes
expect_rc rbfail 1
expect_out rbfail "RESULT: FAIL - rollback rolled back"
on_images rbfail "$P_NEW" "$A_NEW"

# API bodies larger than one argv string (real rule set, dry run 2 on the sentry canary): read from files, not --argjson
setup big
run_tool STUB_RULES_BIG=1 -- apply --plan "$STUB_DIR/plan.json" --yes
expect_rc bigapi 0
expect_out bigapi "CHECK rules-parity +ok 3 items"
on_images bigapi "$P_NEW" "$A_NEW"

# dockerd adds its daemon.json log-opts to every new container (dry run 4 on the validator: signature FAIL, rolled back)
DJ="$SCRATCH/daemon.json"; printf '{"log-driver": "json-file", "log-opts": {"max-size": "100m", "max-file": "5"}}\n' >"$DJ"
setup dlog
run_tool DOCKER_DAEMON_JSON="$DJ" STUB_DAEMON_LOG_OPTS='{"max-file":"5","max-size":"100m"}' -- apply --plan "$STUB_DIR/plan.json" --yes
expect_rc dlog 0
expect_out dlog "CHECK pft-prometheus-signature ok \(log options = daemon.json log-opts defaults"
expect_out dlog "CHECK pft-alertmanager-signature ok \(log options = daemon.json log-opts defaults"
on_images dlog "$P_NEW" "$A_NEW"
run_tool DOCKER_DAEMON_JSON="$DJ" STUB_DAEMON_LOG_OPTS='{"max-file":"5","max-size":"100m"}' -- rollback --yes
expect_rc dlog-rollback 0
expect_out dlog-rollback "CHECK pft-prometheus-signature +ok$"
on_images dlog-rollback "$P_OLD" "$A_OLD"
failure dlog-other "CHECK pft-prometheus-signature FAIL .*max-size" DOCKER_DAEMON_JSON="$DJ" STUB_DAEMON_LOG_OPTS='{"max-file":"5","max-size":"1m"}'
failure dlog-nodaemon "CHECK pft-alertmanager-signature FAIL .*max-size" DOCKER_DAEMON_JSON="$SCRATCH/none.json" STUB_DAEMON_LOG_OPTS='{"max-file":"5","max-size":"100m"}'

# usage
setup u; run_tool -- apply --yes; expect_rc usage-noplan 2
run_tool -- rollback --bogus; expect_rc usage-rollback 2

printf '\nRESULT: %s passed, %s failed\n' "$PASS" "$FAILN"
[ "$FAILN" -eq 0 ]
