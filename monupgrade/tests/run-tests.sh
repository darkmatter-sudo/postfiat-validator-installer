#!/usr/bin/env bash
# shellcheck disable=SC2015  # ok() and no() always return 0
# Offline tests for pft-monupgrade (stub docker + Docker Hub fixtures; no network, no real docker).
# Every failure path asserts its exit code, its named reason AND what must NOT have happened (no pull, no check run).
# Run: bash tests/run-tests.sh
set -uo pipefail
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$T/../pft-monupgrade.sh"
SCRATCH="$(mktemp -d -p "${TMPDIR:-$HOME/.cache}" monupgrade-tests.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p "$SCRATCH/alerts" "$SCRATCH/slo"
cat >"$SCRATCH/alerts/prometheus.yml" <<'EOF'
global:
  scrape_interval: 15s
rule_files:
  - /etc/pft-alerts/a.rules.yml
  - /etc/pft-alerts/b.rules.yml   # comment
  - /etc/pft-slo/*.rules.yml    # glob
alerting:
  alertmanagers: []
EOF
touch "$SCRATCH/alerts/"{a.rules.yml,b.rules.yml,tests.yml,b.tests.yml,alertmanager.yml} "$SCRATCH/slo/"{slo.rules.yml,tests.yml}

PASS=0 FAILN=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
no() { FAILN=$((FAILN + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

# run_case NAME [ENV=VAL ...] -- ARGS... ; sets OUT, RC, CALLS
run_case() {
  local name="$1"; shift
  local envs=()
  while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
  export STUB_DIR="$SCRATCH/stub-$name"; rm -rf "$STUB_DIR"; mkdir -p "$STUB_DIR"; : >"$STUB_DIR/calls"
  OUT="$(env DOCKER="$T/stub_docker.sh" ALERTS_DIR="$SCRATCH/alerts" SLO_DIR="$SCRATCH/slo" \
    HUB_TAGS_DIR="$T/fixtures" HUB_URL=http://127.0.0.1:9 NOW=1795478400 "${envs[@]}" "$TOOL" "$@" 2>&1)"
  RC=$?
  CALLS="$(cat "$STUB_DIR/calls")"
}
expect_rc() { [ "$RC" -eq "$2" ] && ok "$1: exit $2" || no "$1" "exit $RC, want $2; output:"$'\n'"$OUT"; }
expect_out() { grep -qE -- "$2" <<<"$OUT" && ok "$1: output has /$2/" || no "$1" "output lacks /$2/:"$'\n'"$OUT"; }
expect_no_out() { grep -qE -- "$2" <<<"$OUT" && no "$1" "output has /$2/" || ok "$1: output lacks /$2/"; }
expect_calls() { local n; n="$(grep -cE -- "$2" <<<"$CALLS" || true)"; [ "$n" -eq "$3" ] && ok "$1: $3 docker calls /$2/" \
  || no "$1" "$n docker calls /$2/, want $3"; }

P15=prom/prometheus:v3.15.1@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
A35=prom/alertmanager:v0.35.0@sha256:7777777777777777777777777777777777777777777777777777777777777777

# 1 selection: highest vX.Y.Z of the same major, >= MIN_AGE_DAYS, no -rc/-distroless/latest, semver order
run_case select -- plan --out "$SCRATCH/plan.json"
expect_rc select 0
expect_out select "TARGET  prometheus   tag=v3.15.1 digest=sha256:c{64} pushed=2026-11-01T10:00:00Z"
expect_out select "TARGET  alertmanager tag=v0.35.0 digest=sha256:7{64}"
expect_calls select "^pull -q $P15\$" 1
expect_calls select "^pull -q $A35\$" 1
expect_out select "RESULT: READY - upgrade prometheus alertmanager: prometheus v3.5.0 -> v3.15.1, alertmanager v0.28.1 -> v0.35.0 \(control PASS\)"
# every check container is read-only, offline, nobody, removed, with read-only config mounts
expect_calls select "^run " 10
expect_calls select "^run --rm --network none --read-only --tmpfs /tmp:rw,mode=1777,size=256m --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 -v $SCRATCH/alerts:/etc/pft-alerts:ro -v $SCRATCH/slo:/etc/pft-slo:ro " 10
expect_calls select "^run .* --entrypoint promtool $P15 check rules /etc/pft-alerts/a.rules.yml /etc/pft-alerts/b.rules.yml /etc/pft-slo/slo.rules.yml\$" 1
expect_calls select "^run .* -w /etc/pft-alerts --entrypoint promtool $P15 test rules tests.yml b.tests.yml\$" 1
expect_calls select "^run .* -w /etc/pft-slo --entrypoint promtool $P15 test rules tests.yml\$" 1
expect_calls select "^run .* --entrypoint amtool $A35 check-config /etc/pft-alerts/alertmanager.yml\$" 1
expect_calls select "^run .* --entrypoint promtool prom/prometheus@sha256:1{64} check config" 1
if jq -e '.prometheus.target_tag == "v3.15.1" and .alertmanager.target_digest == "sha256:'"$(printf '7%.0s' {1..64})"'" and .control == "PASS" and .fails == []' "$SCRATCH/plan.json" >/dev/null; then
  ok "select: plan.json fields"; else no select "plan.json: $(cat "$SCRATCH/plan.json")"; fi

# 2 age gate: with MIN_AGE_DAYS=5 the 10-day-old v3.16.0 becomes the target
run_case age MIN_AGE_DAYS=5 -- plan
expect_rc age 0
expect_out age "TARGET  prometheus   tag=v3.16.0"

# 3 nothing old enough -> no-target, nothing pulled, nothing run
run_case notarget MIN_AGE_DAYS=999 -- plan
expect_rc notarget 1
expect_out notarget "FAIL prometheus reason=no-target"
expect_calls notarget "^(pull|run) " 0

# 4 hub unreachable (no fixture dir) -> hub-unreachable, nothing pulled
run_case hub HUB_TAGS_DIR="$SCRATCH/none" -- plan
expect_rc hub 1
expect_out hub "FAIL prometheus reason=hub-unreachable"
expect_out hub "FAIL alertmanager reason=hub-unreachable"
expect_calls hub "^(pull|run) " 0

# 5 invalid hub JSON -> hub-unreachable (fail closed, not "no target")
mkdir -p "$SCRATCH/badhub"; echo '<html>rate limited</html>' >"$SCRATCH/badhub/prom_prometheus.json"
cp "$T/fixtures/prom_alertmanager.json" "$SCRATCH/badhub/"
run_case badjson HUB_TAGS_DIR="$SCRATCH/badhub" -- plan
expect_rc badjson 1
expect_out badjson "FAIL prometheus reason=hub-unreachable"
expect_calls badjson "^(pull|run) " 0

# 6 already current -> exit 3, no pull, no checks
run_case current STUB_REF_PROM=prom/prometheus:v3.15.1 STUB_REF_AM=prom/alertmanager:v0.35.0 -- plan
expect_rc current 3
expect_out current "UPTODATE prometheus"
expect_out current "UPTODATE alertmanager"
expect_calls current "^(pull|run) " 0

# 7 never downgrade: running tag newer than the selected target -> up to date
run_case newer STUB_REF_PROM=prom/prometheus:v3.20.0 STUB_REF_AM=prom/alertmanager:v0.99.0 -- plan
expect_rc newer 3
expect_calls newer "^(pull|run) " 0

# 8 only one image behind -> only that one pulled; checks use the current digest for the other
run_case one STUB_REF_AM=prom/alertmanager:v0.35.0 -- plan
expect_rc one 0
expect_calls one "^pull " 1
expect_calls one "--entrypoint amtool prom/alertmanager:v0.35.0@sha256:2{64} check-config" 1

# 9 container missing / unpinned ref -> error before any pull
run_case missing STUB_MISSING=pft-alertmanager -- plan
expect_rc missing 1
expect_out missing "FAIL alertmanager reason=container-missing"
expect_calls missing "^(pull|run) " 0
run_case unpinned STUB_REF_PROM=prom/prometheus:latest -- plan
expect_rc unpinned 1
expect_out unpinned "FAIL prometheus reason=current-unpinned"
expect_calls unpinned "^(pull|run) " 0

# 10 pull failure / digest mismatch -> error, no check container runs
run_case pullfail STUB_FAIL_PULL=1 -- plan
expect_rc pullfail 1
expect_out pullfail "FAIL prometheus reason=pull-failed"
expect_calls pullfail "^run " 0
run_case mismatch STUB_MISMATCH=1 -- plan
expect_rc mismatch 1
expect_out mismatch "FAIL prometheus reason=digest-mismatch"
expect_out mismatch "FAIL alertmanager reason=digest-mismatch"
expect_calls mismatch "^run " 0

# 11 each target check fails on its own -> exit 4 with that reason only; control stays PASS
for c in "check config:promtool-check-config" "check rules:promtool-check-rules" "test rules:promtool-test-rules" \
  "check-config:amtool-check-config"; do
  args="${c%%:*}" reason="${c#*:}"
  run_case "t-$reason" STUB_FAIL_RUN=":v(3\.15\.1|0\.35\.0)@sha256:[0-9a-f]+ $args" -- plan --out "$SCRATCH/p-$reason.json"
  expect_rc "t-$reason" 4
  expect_out "t-$reason" "^FAIL (prometheus|alertmanager) reason=$reason\$"
  expect_out "t-$reason" "RESULT: BLOCKED - .*reason=$reason \(control PASS\)"
  [ "$(grep -c '^FAIL ' <<<"$OUT")" -eq 1 ] && ok "t-$reason: exactly one FAIL line" || no "t-$reason" "FAIL lines: $(grep '^FAIL ' <<<"$OUT")"
  expect_no_out "t-$reason" "CONTROL-FAIL"
  jq -e --arg r "$reason" '.fails | index($r) != null' "$SCRATCH/p-$reason.json" >/dev/null \
    && ok "t-$reason: plan.json lists the reason" || no "t-$reason" "plan.json: $(cat "$SCRATCH/p-$reason.json")"
done

# 12 a check that fails on BOTH images: CONTROL-FAIL + FAIL, exit 4 (config problem is still a blocker)
run_case both STUB_FAIL_RUN="check rules" -- plan
expect_rc both 4
expect_out both "^CONTROL-FAIL prometheus reason=promtool-check-rules"
expect_out both "^FAIL prometheus reason=promtool-check-rules"
expect_out both "\(control FAIL\)"

# 13 control fails, target passes (target fixes it) -> READY, control FAIL reported
run_case ctrlonly STUB_FAIL_RUN="prom/prometheus@sha256:1{64} check config" -- plan
expect_rc ctrlonly 0
expect_out ctrlonly "^CONTROL-FAIL prometheus reason=promtool-check-config"
expect_out ctrlonly "RESULT: READY .*\(control FAIL\)"

# 14 overrides: tag@digest skips the hub for that image; tag only resolves its digest from the hub; junk refused
run_case ovr TARGET_PROM=v3.9.10@sha256:"$(printf 'e%.0s' {1..64})" HUB_TAGS_DIR="$SCRATCH/badhub" -- plan
expect_out ovr "TARGET  prometheus   tag=v3.9.10 digest=sha256:e{64} pushed=override"
expect_rc ovr 0
run_case ovrtag TARGET_AM=v0.34.2 -- plan
expect_out ovrtag "TARGET  alertmanager tag=v0.34.2 digest=sha256:8{64} pushed=override"
expect_rc ovrtag 0
run_case ovrbad TARGET_AM=v0.99.9 -- plan
expect_rc ovrbad 1
expect_out ovrbad "FAIL alertmanager reason=no-target"
expect_calls ovrbad "^(pull|run) " 0

# 15 --no-pull: no pull call; the digest must already be in the store, else pull-failed
run_case nopull -- plan --no-pull
expect_rc nopull 1
expect_out nopull "FAIL prometheus reason=pull-failed"
expect_calls nopull "^(pull|run) " 0

# 16 usage
run_case usage -- bogus
expect_rc usage 2
run_case badopt -- plan --frobnicate
expect_rc badopt 2

printf '\nRESULT: %s passed, %s failed\n' "$PASS" "$FAILN"
[ "$FAILN" -eq 0 ]
