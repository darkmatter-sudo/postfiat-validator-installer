#!/usr/bin/env bash
# Offline tests for pft-alertpath (no root, no network, ntfy to a file).
# Snapshots are signed with `openssl dgst -hmac` (independent of the script's bash HMAC), spooled the way
# `receive` does, then `check` must reach the expected state and exit code with the expected reason.
# Usage: bash tests/test-alertpath.sh      (APB=path/to/pft-alertpath.sh to test another copy, e.g. a mutant)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APB="${APB:-$HERE/../pft-alertpath.sh}"
SB="$(mktemp -d)"
trap 'rm -rf "$SB"' EXIT
export PFT_ALERTPATH_TEST=1
pass=0 fail=0

ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

reset() { # fresh sandbox per case
  rm -rf "$SB/c"; mkdir -p "$SB/c/conf" "$SB/c/state" "$SB/c/spool"
  printf '%s\n' "$KEY" > "$SB/c/conf/hmac.key"; chmod 600 "$SB/c/conf/hmac.key"
  NOW="$(date -u +%s)"
  export CONF_DIR="$SB/c/conf" STATE_DIR="$SB/c/state" SPOOL_DIR="$SB/c/spool" NTFY_OUTBOX="$SB/c/outbox"
}
KEY="$(openssl rand -hex 32)"
NOW="$(date -u +%s)"

# snap AGE JQ-EXPR: a healthy snapshot taken AGE seconds ago, then modified by JQ-EXPR
snap() {
  local ts=$((NOW - $1))
  jq -nc --argjson ts "$ts" '{v:1, type:"alertpath", node:"validator", ts:$ts,
    wd:{received:($ts - 30), count:10, status:"firing", unexpected:0},
    prom:{up:1, reload_ok:1, rule_eval_failures:0, notif_errors:0, notif_dropped:0, am_discovered:1, wd_last_eval:($ts - 10)},
    am:{up:1, reload_ok:1, notif_failed:0, notif_total:100},
    bridge:{running:1, listening:1, ntfy_errors:0}} | '"${2:-.}"
}
sign() { printf '%s' "$1" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$KEY" | awk '{print $NF}'; }
# spool BODY [SIG]: deliver through the real `receive` forced command
spool() { local sig="${2:-$(sign "$1")}"; printf '%s\n%s\n' "$1" "$sig" | "$APB" receive; sleep 0.01; }
run() { OUT="$("$APB" check "$@" 2>"$SB/err")"; RC=$?; }

# case NAME EXPECT_STATE EXPECT_RC REASON_REGEX  (spool messages before calling)
expect() {
  run --json
  local st; st="$(jq -r '.state // empty' <<<"$OUT" 2>/dev/null)"
  if [ "$st" = "$2" ] && [ "$RC" -eq "$3" ] && grep -qE -- "$4" <<<"$OUT"; then ok "$1 -> $st rc=$RC"
  else bad "$1 (want $2 rc=$3 /$4/, got ${st:-?} rc=$RC: $OUT)"; fi
}

reset; expect "no snapshot" STALE 2 'no snapshot received'
reset; spool "$(snap 5)"; expect "healthy snapshot" OK 0 '"reasons":\[\]'
reset; spool "$(snap 200)"; expect "snapshot 200s old" STALE 2 'last snapshot 20[0-9]s old'
reset; spool "$(snap 5 '.wd.received = .ts - 300')"; expect "watchdog delivery 300s old" STALE 2 'last watchdog delivery 300s'
reset; spool "$(snap 5 '.wd = null')"; expect "no delivery recorded" STALE 2 'no watchdog delivery recorded'
reset; spool "$(snap 5 '.wd.status = "resolved"')"; expect "watchdog resolved" DEGRADED 1 'status resolved'
reset; spool "$(snap 5 '.prom.up = 0')"; expect "Prometheus down" DEGRADED 1 '"reasons":\["Prometheus unreachable"\]'
reset; spool "$(snap 5 '.prom.reload_ok = 0')"; expect "Prometheus reload failed" DEGRADED 1 'Prometheus last config reload failed'
reset; spool "$(snap 65)"; spool "$(snap 5 '.prom.rule_eval_failures = 3')"
expect "rule eval failures +3" DEGRADED 1 'rule evaluation failures \+3'
reset; spool "$(snap 65)"; spool "$(snap 5 '.prom.notif_errors = 2')"; expect "Prom notification errors" DEGRADED 1 'notification errors \+2'
reset; spool "$(snap 65)"; spool "$(snap 5 '.prom.notif_dropped = 1')"; expect "Prom notifications dropped" DEGRADED 1 'dropped \+1'
reset; spool "$(snap 5 '.prom.am_discovered = 0')"; expect "no Alertmanager discovered" DEGRADED 1 'no Alertmanager'
reset; spool "$(snap 5 '.prom.wd_last_eval = null')"; expect "rule group not loaded" DEGRADED 1 'rule group not loaded'
reset; spool "$(snap 5 '.prom.wd_last_eval = .ts - 300')"; expect "rule group eval 300s old" DEGRADED 1 'last evaluated 300s ago'
reset; spool "$(snap 5 '.am.up = 0')"; expect "Alertmanager down" DEGRADED 1 'Alertmanager unreachable'
reset; spool "$(snap 5 '.am.reload_ok = 0')"; expect "Alertmanager reload failed" DEGRADED 1 'Alertmanager last config reload failed'
reset; spool "$(snap 65)"; spool "$(snap 5 '.am.notif_failed = 4')"; expect "webhook failures +4" DEGRADED 1 'webhook notifications failed \+4'
reset; spool "$(snap 5 '.bridge.running = 0 | .bridge.listening = 0 | .bridge.ntfy_errors = null')"
expect "bridge container stopped" DEGRADED 1 'bridge container not running'
reset; spool "$(snap 5 '.bridge.listening = 0')"; expect "bridge not listening" DEGRADED 1 'bridge not listening'
reset; spool "$(snap 65)"; spool "$(snap 5 '.bridge.ntfy_errors = 2')"; expect "bridge ntfy errors +2" DEGRADED 1 'delivery errors \+2'
reset; spool "$(snap 65)"; spool "$(snap 5 '.wd.unexpected = 1')"; expect "mis-routed delivery" DEGRADED 1 'mis-routed'
# counter reset (Prometheus restart): 5 -> 5 -> 0 is a reset to 0, not +N
reset; spool "$(snap 125 '.prom.rule_eval_failures = 5')"; spool "$(snap 65 '.prom.rule_eval_failures = 5')"
spool "$(snap 5 '.prom.rule_eval_failures = 0')"; expect "counter reset to 0" OK 0 '"reasons":\[\]'
# reset then new failures: 5 -> 2 counts +2
reset; spool "$(snap 65 '.prom.rule_eval_failures = 5')"; spool "$(snap 5 '.prom.rule_eval_failures = 2')"
expect "counter reset then +2" DEGRADED 1 'rule evaluation failures \+2'
# old failures outside the window do not count
reset; spool "$(snap 700 '.prom.rule_eval_failures = 0')"; spool "$(snap 5 '.prom.rule_eval_failures = 9')"
expect "increase only vs. window" OK 0 '"reasons":\[\]'
# authentication / replay / clock
reset; spool "$(snap 5)" "$(printf '0%.0s' {1..64})"; expect "bad HMAC alone" STALE 2 '1 spooled message\(s\) rejected'
reset; spool "$(snap 5)"; spool "$(snap 5 '.ts += 0')" ; expect "replayed ts" DEGRADED 1 'rejected'
reset; spool "$(snap -120)"; expect "ts 120s in the future" STALE 2 'rejected'
reset; spool "$(snap 5 '.type = "maint"')"; expect "wrong message type" STALE 2 'rejected'
reset; spool "$(snap 65)"; spool "$(snap 5 '.prom.up = 0')" "$(sign "$(snap 5)")"
expect "body swapped under a valid sig" DEGRADED 1 'rejected'
# receive limits
reset; head -c 9000 /dev/zero | tr '\0' a | "$APB" receive; expect "oversize message" STALE 2 'rejected'
reset; for i in $(seq 1 200); do : > "$SPOOL_DIR/$i.msg"; done
if printf 'x\n' | "$APB" receive 2>/dev/null; then bad "spool full accepted"; else ok "spool full refused"; fi
# notifications: one per state change, RECOVERED on return to OK, nothing while the state is unchanged
reset; spool "$(snap 5)"; run --notify; spool "$(snap 4 '.am.up = 0')"; run --notify; spool "$(snap 3 '.am.up = 0')"; run --notify
spool "$(snap 2 '.wd = null')"; run --notify; spool "$(snap 1)"; run --notify
got="$(cut -d'|' -f1,2 "$NTFY_OUTBOX" 2>/dev/null | tr '\n' ' ')"
if [ "$got" = "[alertpath] DEGRADED|default [alertpath] STALE|high [alertpath] RECOVERED|low " ]; then ok "notify sequence: $got"
else bad "notify sequence: got '$got'"; fi
# exit-code/text mode
reset; spool "$(snap 5 '.am.up = 0')"; run
if [ "$RC" -eq 1 ] && grep -q 'state=DEGRADED accepted=1 rejected=0' <<<"$OUT"; then ok "text output DEGRADED rc=1"; else bad "text output: rc=$RC $OUT"; fi
# bash HMAC on the sending side == openssl HMAC (push --print with file:// fixture scrapes, stub docker)
reset; mkdir -p "$SB/p/prom" "$SB/p/am"
cat > "$SB/p/prom/metrics" <<'EOF'
# HELP prometheus_config_last_reload_successful x
prometheus_config_last_reload_successful 1
prometheus_rule_evaluation_failures_total{rule_group="/etc/pft-alerts/postfiat.rules.yml;postfiat-ledger"} 2
prometheus_rule_evaluation_failures_total{rule_group="/etc/pft-alertpath/alertpath.rules.yml;alertpath"} 1
prometheus_notifications_errors_total{alertmanager="http://127.0.0.1:9093/api/v2/alerts"} 0
prometheus_notifications_dropped_total 0
prometheus_notifications_alertmanagers_discovered 1
prometheus_rule_group_last_evaluation_timestamp_seconds{rule_group="/etc/pft-alerts/postfiat.rules.yml;postfiat-ledger"} 1.0e+09
prometheus_rule_group_last_evaluation_timestamp_seconds{rule_group="/etc/pft-alertpath/alertpath.rules.yml;alertpath"} 1.7931967e+09
EOF
cat > "$SB/p/am/metrics" <<'EOF'
alertmanager_config_last_reload_successful 1
alertmanager_notifications_failed_total{integration="email",reason="other"} 7
alertmanager_notifications_failed_total{integration="webhook",reason="other"} 1
alertmanager_notifications_failed_total{integration="webhook",reason="serverError"} 2
alertmanager_notifications_total{integration="webhook"} 13
EOF
# shellcheck disable=SC2016  # the stub's $1 must stay literal
printf '#!/bin/sh\ncase "$1" in inspect) echo true ;; logs) printf "ntfy firing X -> ERROR URLError\\nok\\n" ;; esac\n' > "$SB/p/docker"
chmod +x "$SB/p/docker"
printf '{"v":1,"received":1793196600,"count":3,"status":"firing","unexpected":0,"startsAt":"x"}\n' > "$SB/p/last.json"
msg="$(PROM_URL="file://$SB/p/prom" AM_URL="file://$SB/p/am" DOCKER="$SB/p/docker" SINK_STATE="$SB/p/last.json" \
  BRIDGE_PORT=1 "$APB" push --print)"
body="$(sed -n 1p <<<"$msg")"; sig="$(sed -n 2p <<<"$msg")"
if [ -n "$sig" ] && [ "$sig" = "$(sign "$body")" ]; then ok "push --print bash HMAC == openssl HMAC"; else bad "HMAC mismatch: $sig"; fi
want='{"rule_eval_failures":3,"wd_last_eval":1793196700,"amfail":3,"amtotal":13,"running":1,"listening":0,"ntfy_errors":1,"wd_count":3}'
got="$(jq -c '{rule_eval_failures:.prom.rule_eval_failures, wd_last_eval:.prom.wd_last_eval, amfail:.am.notif_failed,
  amtotal:.am.notif_total, running:.bridge.running, listening:.bridge.listening, ntfy_errors:.bridge.ntfy_errors, wd_count:.wd.count}' <<<"$body")"
if [ "$got" = "$want" ]; then ok "snapshot parses fixture scrapes: $got"; else bad "snapshot fields: $got (want $want)"; fi
msg="$(PROM_URL="file://$SB/p/none" AM_URL="file://$SB/p/none" DOCKER=false SINK_STATE="$SB/p/none" BRIDGE_PORT=1 "$APB" push --print)"
got="$(sed -n 1p <<<"$msg" | jq -c '[.prom.up, .prom.reload_ok, .am.up, .wd, .bridge.running, .bridge.ntfy_errors]')"
if [ "$got" = '[0,null,0,null,0,null]' ]; then ok "snapshot with everything down: $got"; else bad "down snapshot: $got"; fi

echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
