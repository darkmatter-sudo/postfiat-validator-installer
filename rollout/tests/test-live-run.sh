#!/usr/bin/env bash
# Offline tests for drill/live-run.sh (the live drill wrapper) against the stubs of test-rollout.sh: fake docker/ssh/
# sudo/curl/pft-maint, fake clock, notifier env files in temp dirs standing in for /etc on each host. No root, no
# network, nothing on the real hosts is touched.
#   ./test-live-run.sh           run the suite against ../drill/live-run.sh (LIVE=... to test another copy)
# jq programs are single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LIVE="${LIVE:-$HERE/../drill/live-run.sh}"
# shellcheck source-path=SCRIPTDIR source=test-rollout.sh
. "$HERE/test-rollout.sh"
PASSN=0; FAILN=0; FAILED=()

setup() { # fixture + notifier env files on both fake hosts (originals copied to $T/orig for byte compares)
  begin "$1"
  mkdir -p "$T/etc-l/pft-maint" "$T/etc-r/pft-maint" "$T/etc-r/pft-watchdog" "$T/orig"
  printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=realtopic-monitor\nNTFY_TOKEN=tk_secret\nCHECK_INTERVAL=60\n' > "$T/etc-l/postfiat-monitor.env"
  printf 'NTFY_TOPIC=realtopic-integrity\nSTATE=/var/lib/x\n' > "$T/etc-l/pft-integrity.env"
  printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=realtopic-watchdog\n' > "$T/etc-r/pft-watchdog/ntfy.env"
  printf 'NTFY_TOPIC=realtopic-integrity-r\n' > "$T/etc-r/pft-integrity.env"
  chmod 600 "$T"/etc-l/*.env "$T"/etc-r/*.env "$T/etc-r/pft-watchdog/ntfy.env"
  ENVS="$T/etc-l/postfiat-monitor.env $T/etc-l/pft-integrity.env $T/etc-r/pft-watchdog/ntfy.env $T/etc-r/pft-integrity.env"
  for f in $ENVS; do cp -p "$f" "$T/orig/$(echo "$f" | tr / _)"; done
}
lr() { # MODE -> output in $T/out, exit code in RC
  PATH="$STUBS:$PATH" STUB="$T" CONF="$T/hosts.conf" STATE_DIR="$T/state" HOME="$T/home" PFT_ROLLOUT_NOW_FILE="$T/now" \
    GATE_TIMEOUT=300 SOAK_SEC=60 POLL_SEC=10 MIN_ADVANCE=10 ROLLBACK_TIMEOUT=300 AM=http://am.test:9093 \
    FOUNDATION_RPC=https://foundation.test NTFY=https://ntfy.test RELAY=relay NEED_ROOT=0 NTFY_WAIT=0 INTEGRITY_CMD=none LOGSHIP_WAIT=0 \
    LOCAL_ENVS="$T/etc-l/postfiat-monitor.env $T/etc-l/pft-integrity.env" \
    REMOTE_ENVS="$T/etc-r/pft-watchdog/ntfy.env $T/etc-r/pft-integrity.env" \
    MAINT_DIR_L="$T/etc-l/pft-maint" MAINT_DIR_R="$T/etc-r/pft-maint" \
    STUB_WATCH="$ENVS $T/etc-l/pft-maint/ntfy.env $T/etc-r/pft-maint/ntfy.env" \
    bash "$LIVE" "$1" > "$T/out" 2>&1
  RC=$?
}
restored() { # every env file byte-identical to its original (content, mode), no backups, no drill-only files left
  local f
  for f in $ENVS; do cmp -s "$f" "$T/orig/$(echo "$f" | tr / _)" || return 1
    [ "$(stat -c %a "$f")" = 600 ] || return 1; [ ! -e "$f.pre-rollout-drill" ] || return 1; done
  [ ! -e "$T/etc-l/pft-maint/ntfy.env" ] && [ ! -e "$T/etc-r/pft-maint/ntfy.env" ]
}
untouched() { # nothing redirected at all: originals, no backups, no drill files, no watch snapshot
  restored && [ ! -e "$T/watch.log" ]
}
watched_all() { # during every pft-maint start: 4 env files on the ALERT topic, 2 maint files on the MAINT topic, no token
  [ -s "$T/watch.log" ] || return 1
  [ "$(grep -c 'NTFY_TOPIC=rolloutdrill-[0-9a-f]\{24\} ' "$T/watch.log")" -eq $(( 4 * $1 )) ] || return 1
  [ "$(grep -c 'pft-maint/ntfy.env NTFY_SERVER=https://ntfy.test NTFY_TOPIC=rolloutmaint-[0-9a-f]\{24\} $' "$T/watch.log")" -eq $(( 2 * $1 )) ] || return 1
  ! grep -qE 'realtopic|NTFY_TOKEN' "$T/watch.log"
}
nolp() { ! grep -qE 'rolloutdrill-|rolloutmaint-|realtopic|tk_secret' "$T/out"; }
msg() { echo '{"id":"x","time":1800000100,"event":"message","topic":"t","title":"'"$1"'","message":"m"}'; }

t_noop() {
  setup "noop: both hosts restarted on the same image, verdict PASS, notifiers redirected then restored"
  lr noop
  check "rc=0 (got $RC)" eq "$RC" 0
  check "checker RESULT: PASS (21/21)" grep -qx "RESULT: PASS (21/21)" "$T/out"
  check "pft-rollout exit 0" has "pft-rollout exit 0"
  check "redirected during both windows" watched_all 2
  check "env files restored byte-identical + drill files removed" restored
  check "restore lines say yes x4" eq "$(grep -c 'sha256 matches pre-drill copy: yes' "$T/out")" 4
  check "no topic/token in output" nolp
  check "facts file written" eq "$(jq -r '.validator.before.started != .validator.after.started' "$T"/state/facts-*.json)" true
  check "facts logship: unit active, newest > after" eq "$(jq -r '.logship | "\(.unit) \(.nrestarts) \(.newest_us > .after_us)"' "$T"/state/facts-*.json)" "active 2 true"
  check "remote journal queried newest-first for the sentry" eq "$(cnt "$T/calls.log" -c '^local journalctl -D /var/log/journal/remote -t postfiatd-sentry -r -n 1 -o json')" 1
  check "bridge unit read on the relay" eq "$(cnt "$T/calls.log" -c '^relay systemctl show -p ActiveState -p NRestarts pft-logship-dockerlog@postfiatd-sentry$')" 1
  end
}
t_badimage() {
  setup "badimage: drill image fails the sentry gate, rollback, validator untouched, drill tag removed, PASS"
  gens relay good down good
  printf '%s\n' "$(msg '[MAINT] start sentry')" > "$T/ntfy_maint"
  lr badimage
  check "rc=0 (got $RC)" eq "$RC" 0
  check "checker RESULT: PASS (15/15)" grep -qx "RESULT: PASS (15/15)" "$T/out"
  check "pft-rollout exit 1" has "pft-rollout exit 1"
  check "Dockerfile FROM the running sentry image" has "Dockerfile: FROM $OLD"
  check "drill image built on relay" eq "$(grep -c '^relay docker build' "$T/calls.log")" 1
  check "drill tag removed" eq "$(jq -r '.tags["pft-rollout-drill:bad"] // "gone"' "$T/hosts/relay/state.json")" gone
  check "sentry back on OLD" eq "$(img relay postfiatd-sentry)" "$OLD"
  check "validator: 0 mutating docker calls" eq "$(mutating local)" 0
  check "redirected during the sentry window" watched_all 1
  check "env files restored" restored
  check "MAINT message not counted as alert" has "MAINT topic: 1 message(s)"
  check "ALERT topic 0" has "ALERT topic: 0 message(s)"
  check "no topic/token in output" nolp
  end
}
t_alert_seen() {
  setup "badimage: a message on the throwaway ALERT topic -> FAIL"
  gens relay good down good
  msg "UNHEALTHY sentry" > "$T/ntfy_alert"
  lr badimage
  check "rc=1 (got $RC)" eq "$RC" 1
  check "exact FAIL line" grep -qx "FAIL throwaway alert topic received nothing" "$T/out"
  check "env files restored" restored
  end
}
t_ntfy_down() {
  setup "badimage: ntfy unreadable -> alert count null -> FAIL (never read as 0)"
  gens relay good down good
  touch "$T/ntfy_down"
  lr badimage
  check "rc=1 (got $RC)" eq "$RC" 1
  check "could not be read" has "ALERT topic: could not be read from ntfy"
  check "exact FAIL line" grep -qx "FAIL throwaway alert topic received nothing" "$T/out"
  check "facts alert_msgs null" eq "$(jq -r '.alert_msgs' "$T"/state/facts-*.json)" null
  end
}
t_logship_stale() {
  setup "noop: newest forwarded sentry line older than the run end -> FAIL (forwarding not re-attached)"
  touch "$T/journal_stale"
  lr noop
  check "rc=1 (got $RC)" eq "$RC" 1
  check "exact FAIL line" grep -qx "FAIL sentry log forwarded after the run (logship re-attached)" "$T/out"
  check "only that check failed" grep -qx "RESULT: FAIL (20/21)" "$T/out"
  check "stale time printed" has "newest forwarded postfiatd-sentry line: 2001-09-09T01:46:40Z"
  check "env files restored" restored
  end
}
t_logship_empty() {
  setup "noop: no forwarded sentry line at all -> newest null -> FAIL"
  touch "$T/journal_empty"
  lr noop
  check "rc=1 (got $RC)" eq "$RC" 1
  check "exact FAIL line" grep -qx "FAIL sentry log forwarded after the run (logship re-attached)" "$T/out"
  check "printed none" has "newest forwarded postfiatd-sentry line: none"
  check "facts newest_us null" eq "$(jq -r '.logship.newest_us' "$T"/state/facts-*.json)" null
  end
}
t_logship_inactive() {
  setup "badimage: relay bridge unit not active -> FAIL even with a fresh line"
  gens relay good down good
  touch "$T/logship_inactive"
  lr badimage
  check "rc=1 (got $RC)" eq "$RC" 1
  check "exact FAIL line" grep -qx "FAIL sentry log forwarded after the run (logship re-attached)" "$T/out"
  check "only that check failed" grep -qx "RESULT: FAIL (14/15)" "$T/out"
  check "state printed" has "ActiveState=failed NRestarts=2"
  end
}
t_lock() {
  setup "pft-maint data-collection lock -> exit 4 before anything is changed"
  echo "govern-24h until 2026-10-27T16:20Z" > "$T/locks"
  lr noop
  check "rc=4 (got $RC)" eq "$RC" 4
  check "nothing redirected" untouched
  check "0 docker calls" eq "$(cnt "$T/calls.log" -c .)" 0
  end
}
t_leftover() {
  setup "relay pft-maint/ntfy.env already exists -> exit 3, nothing changed, file kept"
  echo "NTFY_TOPIC=operator-made" > "$T/etc-r/pft-maint/ntfy.env"
  lr noop
  check "rc=3 (got $RC)" eq "$RC" 3
  check "existing file kept" eq "$(cat "$T/etc-r/pft-maint/ntfy.env")" "NTFY_TOPIC=operator-made"
  rm -f "$T/etc-r/pft-maint/ntfy.env"
  check "nothing redirected" untouched
  end
}
t_drill_tag_present() {
  setup "badimage: drill tag already on the relay -> exit 3, nothing changed"
  jq --arg o "$OLD" '.tags["pft-rollout-drill:bad"] = $o' "$T/hosts/relay/state.json" > "$T/x" && mv "$T/x" "$T/hosts/relay/state.json"
  lr badimage
  check "rc=3 (got $RC)" eq "$RC" 3
  check "nothing redirected" untouched
  end
}
t_build_fail() {
  setup "badimage: drill build fails after the redirect -> exit 3, trap restores every notifier"
  touch "$T/hosts/relay/build_fail"
  lr badimage
  check "rc=3 (got $RC)" eq "$RC" 3
  check "stopped at build" has "drill image not built - stopping"
  check "env files restored" restored
  check "restore lines say yes x4" eq "$(grep -c 'sha256 matches pre-drill copy: yes' "$T/out")" 4
  check "pft-rollout never ran" eq "$(cnt "$T/calls.log" -c 'docker exec')" 0
  end
}

t_noop; t_badimage; t_alert_seen; t_ntfy_down; t_logship_stale; t_logship_empty; t_logship_inactive; t_lock; t_leftover; t_drill_tag_present; t_build_fail
echo "live-run tests: $PASSN passed, $FAILN failed${FAILED[*]:+ (${FAILED[*]})}"
[ "$FAILN" -eq 0 ]
