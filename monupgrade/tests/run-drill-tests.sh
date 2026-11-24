#!/usr/bin/env bash
# Offline tests of drill/live-run.sh others() (the drain check: which alerts would reach the operator once the run's
# own silence is expired). Synthetic Prometheus /api/v1/alerts and Alertmanager /api/v2/silences bodies through a
# curl shim; silence matchers (regex, negative, expired, the run's own) are evaluated by others() itself.
set -uo pipefail
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$(sed -n '/^others() {/,/^}/p' "$T/../drill/live-run.sh")"
D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT
# shellcheck disable=SC2034  # PROM, AM: read by the eval'd others()
PROM=P AM=A
PASS=0; FAILN=0
curl() { local u="${*: -1}"; case "$u" in P/*) cat "$D/p" ;; A/*) cat "$D/s" ;; *) return 7 ;; esac; }
expect() { # NAME WANT (lines joined by ;)
  local got; got="$(others 2>/dev/null | paste -sd ';')"
  if [ "$got" = "$2" ]; then PASS=$((PASS + 1)); printf 'ok   %s: %s\n' "$1" "${2:-(none)}"
  else FAILN=$((FAILN + 1)); printf 'FAIL %s: got "%s", want "%s"\n' "$1" "$got" "$2"; fi
}
cat >"$D/p" <<'EOF'
{"status":"success","data":{"alerts":[
 {"labels":{"alertname":"PFTPromDown","host":"validator"},"state":"pending"},
 {"labels":{"alertname":"PFTMonupgradeTest"},"state":"firing"},
 {"labels":{"alertname":"PFTAlertPipelineWatchdog"},"state":"firing"},
 {"labels":{"alertname":"PFTX","notify":"digest"},"state":"firing"},
 {"labels":{"alertname":"PFTBudgetCapReached","unit":"pft-budget-collect.service","host":"sentry"},"state":"firing"}]}}
EOF
cat >"$D/s" <<'EOF'
[{"id":"run","status":{"state":"active"},"matchers":[
   {"name":"alertname","value":"PFTAlertPipelineWatchdog|PFTMonupgradeTest","isRegex":true,"isEqual":false},
   {"name":"notify","value":"digest","isRegex":false,"isEqual":false}]},
 {"id":"old","status":{"state":"active"},"matchers":[
   {"name":"alertname","value":"PFTBudgetCapReached","isRegex":false,"isEqual":true},
   {"name":"unit","value":"pft-budget-collect.service","isRegex":false}]},
 {"id":"gone","status":{"state":"expired"},"matchers":[{"name":"alertname","value":".+","isRegex":true,"isEqual":true}]}]
EOF
SIL=run expect "own silence ignored, pre-existing one honoured, pending counted, watchdog/digest skipped, expired ignored" \
  "PFTPromDown validator pending;PFTMonupgradeTest - firing"
SIL=none expect "negative regex matcher: the run silence covers all but the watchdog and the test alert" "PFTMonupgradeTest - firing"
SIL=old expect "missing isEqual = equal; a label absent from the alert compares as empty" "PFTMonupgradeTest - firing"
sed -i 's/"unit","value":"pft-budget-collect.service"/"unit","value":"pft-budget-collect.serv"/' "$D/s"
SIL=run expect "regex-free matcher is exact (no prefix match)" \
  "PFTPromDown validator pending;PFTMonupgradeTest - firing;PFTBudgetCapReached sentry firing"
cp "$D/p" "$D/p.full"; echo '{"status":"success","data":{"alerts":[]}}' >"$D/p"
SIL=run expect "no alerts" ""
: >"$D/p"; SIL=run expect "empty Prometheus body fails closed" "query-error"
cp "$D/p.full" "$D/p"; : >"$D/s"; SIL=run expect "empty Alertmanager body fails closed" "query-error"
echo '{"error":"x"}' >"$D/s"; SIL=run expect "non-array silences fail closed" "query-error"
echo '[]' >"$D/s"; PROM=Z SIL=run expect "dead Prometheus fails closed" "query-error"

# test_drain(): nothing of the test alert may be left for Alertmanager to flush once the bridge moves back
eval "$(sed -n '/^test_drain() {/,/^}/p' "$T/../drill/live-run.sh")"
# shellcheck disable=SC2034  # TAU, since: read by the eval'd test_drain()
TAU=N since=0
curl() { local u="${*: -1}"; case "$u" in A/*) cat "$D/am" ;; N/*) cat "$D/nt" ;; *) return 7 ;; esac; }
msg() { printf '{"event":"message","title":"%s"}\n' "$@"; }
expect_drain() { # NAME WANT_RC
  local out rc; out="$(TEST_DRAIN_S=0 test_drain 2>&1)"; rc=$?
  if [ "$rc" = "$2" ]; then PASS=$((PASS + 1)); printf 'ok   %s: rc %s (%s)\n' "$1" "$rc" "$out"
  else FAILN=$((FAILN + 1)); printf 'FAIL %s: rc %s, want %s (%s)\n' "$1" "$rc" "$2" "$out"; fi
}
echo '[]' >"$D/am"; { echo '{"event":"open"}'; msg '[FIRING] PFTMonupgradeTest' '[RESOLVED] PFTMonupgradeTest' '[FIRING] PFTMonupgradeTest' '[RESOLVED] PFTMonupgradeTest'; } >"$D/nt"
expect_drain "every firing resolved, none active" 0
msg '[FIRING] PFTMonupgradeTest' >>"$D/nt"; expect_drain "dry run 5 shape: last firing without its resolved" 1
msg '[RESOLVED] PFTMonupgradeTest' >>"$D/nt"; echo '[{"labels":{"alertname":"PFTMonupgradeTest"}}]' >"$D/am"
expect_drain "still active in Alertmanager" 1
echo '[]' >"$D/am"; msg '[FIRING] PFTOther' >>"$D/nt"; expect_drain "other alerts on the topic are not counted" 0
: >"$D/am"; expect_drain "empty Alertmanager body fails closed" 1
echo '[]' >"$D/am"; AM_URL_O=Z expect_drain "dead Alertmanager fails closed" 1
TAU_O=Z expect_drain "dead throwaway topic fails closed" 1
: >"$D/nt"; expect_drain "empty topic body fails closed" 1
printf '\nRESULT: %s passed, %s failed\n' "$PASS" "$FAILN"
[ "$FAILN" -eq 0 ]
