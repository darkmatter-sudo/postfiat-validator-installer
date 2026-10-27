#!/usr/bin/env bash
# live-run: one live pft-rollout drill (no-op rollout of both hosts, or bad-image canary drill on the sentry) with
# every notifier on both hosts pointed at throwaway topics, and a PASS/FAIL verdict from check-drill.sh.
#   sudo bash drill/live-run.sh noop|badimage        (run from the rollout/ directory, tee the output)
# 0  preflight (nothing changed yet): relay reachable, Alertmanager ready, no pft-maint data-collection lock, no
#    leftover drill files, badimage: drill tag not present yet.
# 1  redirect: LOCAL_ENVS here and REMOTE_ENVS on the relay get NTFY_SERVER/NTFY_TOPIC (NTFY_TOKEN dropped) of a random
#    throwaway ALERT topic; a drill-only pft-maint ntfy.env on both hosts points at a second throwaway MAINT topic, so
#    the expected [MAINT] start/end messages are not counted as alerts. Each file's sha256 is recorded under its full
#    host:path key; everything is restored on ANY exit (trap) and compared. Alertmanager is silenced by pft-rollout
#    itself (per host window), which is part of what is under test.
# 2  badimage only: on the relay, build pft-rollout-drill:bad FROM the sentry's running image ID with
#    ENTRYPOINT sh -c "exec sleep infinity": it starts and keeps running, but rippled never answers -> gate fails.
# 3  facts before (image ID + StartedAt of both containers), pft-rollout run --yes --no-pull --target T
#    (noop: T = IMAGE_TAG, already the running image on both hosts; badimage: T = the drill tag), facts after.
# 3b log forwarding re-attached: wait up to LOGSHIP_WAIT s for a sentry container line in the validator's remote
#    journal that is newer than the moment pft-rollout returned (by then the old container is gone or, after a
#    rollback, the original one runs again, so such a line can only come from the container now running), and read
#    the relay's bridge unit state. Recorded as facts .logship; check-drill.sh requires both in either mode.
# 4  badimage: rmi the drill tag on the relay. Restore notifiers, read both throwaway topics back from ntfy, write
#    facts JSON next to the audit log, run check-drill.sh on this run's audit lines. Exit = checker exit (0 PASS).
# Topics print as <redacted>, user names in pft-integrity output as <user>.
# Env: CONF (/etc/pft-rollout/hosts.conf)  STATE_DIR (/var/lib/pft-rollout)  RELAY (relay)  NTFY (https://ntfy.sh)
#      AM (http://127.0.0.1:9093)  SENTRY_C (postfiatd-sentry)  VALIDATOR_C (postfiatd)  IMAGE_TAG (as pft-rollout)
#      LOCAL_ENVS  REMOTE_ENVS  MAINT_DIR_L / MAINT_DIR_R (/etc/pft-maint)  INTEGRITY_CMD (pft-integrity, none = skip)
#      NEED_ROOT (1)  NTFY_WAIT (15 s before reading the topics back)  PFT_ROLLOUT / CHECK_DRILL (the scripts next to this one)
#      LOGSHIP_DIR (/var/log/journal/remote)  LOGSHIP_UNIT (pft-logship-dockerlog@SENTRY_C)  LOGSHIP_WAIT (120)
#      pft-rollout env (GATE_TIMEOUT, ...) passes through.
set -uo pipefail
MODE="${1:-}"
case "$MODE" in noop|badimage) ;; *) echo "usage: $0 noop|badimage" >&2; exit 3 ;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
RO="${PFT_ROLLOUT:-$HERE/../pft-rollout.sh}"; CHECK="${CHECK_DRILL:-$HERE/check-drill.sh}"
export CONF="${CONF:-/etc/pft-rollout/hosts.conf}" STATE_DIR="${STATE_DIR:-/var/lib/pft-rollout}"
IMAGE_TAG="${IMAGE_TAG:-agtipft/postfiatd:testnet-light-latest}"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"; AM="${AM:-http://127.0.0.1:9093}"
SENTRY_C="${SENTRY_C:-postfiatd-sentry}"; VALIDATOR_C="${VALIDATOR_C:-postfiatd}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env}"
MAINT_DIR_L="${MAINT_DIR_L:-/etc/pft-maint}"; MAINT_DIR_R="${MAINT_DIR_R:-/etc/pft-maint}"
INTEGRITY_CMD="${INTEGRITY_CMD:-pft-integrity}"; NEED_ROOT="${NEED_ROOT:-1}"; NTFY_WAIT="${NTFY_WAIT:-15}"
LOGSHIP_DIR="${LOGSHIP_DIR:-/var/log/journal/remote}"; LOGSHIP_UNIT="${LOGSHIP_UNIT:-pft-logship-dockerlog@$SENTRY_C}"
LOGSHIP_WAIT="${LOGSHIP_WAIT:-120}"
DRILL_TAG=pft-rollout-drill:bad
SUF=.pre-rollout-drill

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="rolloutdrill-$(rnd)"; MAINT="rolloutmaint-$(rnd)"
since="$(date -u +%s)"
ts() { date -u +%FT%TZ; }
red() { sed -E "s/$ALERT/<redacted>/g; s/$MAINT/<redacted>/g; s/by [a-z_][a-z0-9_-]*/by <user>/g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
cfact() { # HOST CONTAINER -> {"id","started"} or {"id":null,"started":null}
  local j; j="$(on "$1" "sudo -n docker inspect $2" 2>/dev/null | jq -c '.[0] | {id: .Image, started: .State.StartedAt}' 2>/dev/null)"
  echo "${j:-{\"id\":null,\"started\":null\}}"
}

declare -A SHA=()   # "host:path" -> sha256 before the drill
declare -a MOVED=() CREATED=()
RESTORED=0; DRILL_BUILT=0
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || echo "  restore $k: mv FAILED"
    now_sha="$(on "$h" "sudo -n sha256sum < $f")"
    echo "  restored $k: sha256 matches pre-drill copy: $([ "$now_sha" = "${SHA[$k]}" ] && echo yes || echo NO)"
  done
  for k in "${CREATED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n rm -f $f"
    echo "  removed drill-only $k: $(on "$h" "sudo -n test -e $f" && echo NO || echo yes)"
  done
}
trap 'restore' EXIT
trap 'echo "interrupted"; exit 6' INT TERM

echo "pft-rollout live-run $MODE - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "sha256: pft-rollout.sh $(sha256sum < "$RO" | cut -c1-64) | live-run.sh $(sha256sum < "$0" | cut -c1-64) | check-drill.sh $(sha256sum < "$CHECK" | cut -c1-64)"

echo; echo "== 0. preflight (nothing changed yet)"
[ "$NEED_ROOT" = 0 ] || [ "$(id -u)" -eq 0 ] || { echo "  run as root" >&2; exit 3; }
[ -r "$CONF" ] || { echo "  no $CONF" >&2; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
locks="$(pft-maint lock list 2>&1)"
[ "$locks" = "no data-collection locks" ] || { echo "  pft-maint data-collection lock held: $locks - stopping" >&2; exit 4; }
echo "  pft-maint: $locks"
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
! L "sudo -n test -e $MAINT_DIR_L/ntfy.env" || { echo "  local $MAINT_DIR_L/ntfy.env exists - refusing to overwrite" >&2; exit 3; }
! R "sudo -n test -e $MAINT_DIR_R/ntfy.env" || { echo "  relay $MAINT_DIR_R/ntfy.env exists - refusing to overwrite" >&2; exit 3; }
if [ "$MODE" = badimage ]; then
  ! R "sudo -n docker image inspect $DRILL_TAG" >/dev/null 2>&1 || { echo "  $DRILL_TAG already on the relay - stopping" >&2; exit 3; }
fi
echo "  ok: relay reachable, Alertmanager ready, env files present, no leftovers"

echo; echo "== 1. redirect notifiers (ALERT and MAINT throwaway topics)"
redirect() { # HOST PATH
  local h="$1" f="$2"
  SHA["$h:$f"]="$(on "$h" "sudo -n sha256sum < $f")"
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $h:$f -> $NTFY/<redacted> (ALERT), original kept as $f$SUF"
}
for f in $LOCAL_ENVS; do redirect local "$f"; done
for f in $REMOTE_ENVS; do redirect relay "$f"; done
for k in "local:$MAINT_DIR_L" "relay:$MAINT_DIR_R"; do
  h="${k%%:*}"; d="${k#*:}"
  CREATED+=("$h:$d/ntfy.env")
  on "$h" "sudo -n sh -c 'umask 077; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $MAINT > $d/ntfy.env'" \
    || { echo "  $h:$d/ntfy.env not created - stopping"; exit 3; }
  echo "  $h:$d/ntfy.env created for the drill only -> $NTFY/<redacted> (MAINT)"
done

TARGET="$IMAGE_TAG"
if [ "$MODE" = badimage ]; then
  echo; echo "== 2. drill image on the relay"
  base="$(cfact relay "$SENTRY_C" | jq -r .id)"
  case "$base" in sha256:*) ;; *) echo "  sentry image ID unknown - stopping"; exit 3 ;; esac
  DF="$(printf 'FROM %s\nENTRYPOINT ["/bin/sh","-c","exec sleep infinity"]' "$base")"
  while IFS= read -r l; do echo "  Dockerfile: $l"; done <<<"$DF"
  R "sudo -n docker build -q -t $DRILL_TAG -" <<<"$DF" 2>&1 | sed 's/^/  build: /'
  did="$(R "sudo -n docker image inspect $DRILL_TAG" 2>/dev/null | jq -r '.[0].Id // empty')"
  [ -n "$did" ] || { echo "  drill image not built - stopping"; exit 3; }
  DRILL_BUILT=1; TARGET="$DRILL_TAG"
  echo "  $DRILL_TAG = $did (base $base)"
fi

echo; echo "== 3. pft-rollout run"
SB="$(cfact relay "$SENTRY_C")"; VB="$(cfact local "$VALIDATOR_C")"
echo "  before: sentry $SB"; echo "  before: validator $VB"
echo "\$ pft-rollout.sh run --yes --no-pull --target $TARGET   (GATE_TIMEOUT=${GATE_TIMEOUT:-1800} SOAK_SEC=${SOAK_SEC:-300})"
bash "$RO" run --yes --no-pull --target "$TARGET" 2>&1 | red; RC="${PIPESTATUS[0]}"
echo "pft-rollout exit $RC"
SA="$(cfact relay "$SENTRY_C")"; VA="$(cfact local "$VALIDATOR_C")"
echo "  after:  sentry $SA"; echo "  after:  validator $VA"
RUN="$(jq -r '.run // empty' "$STATE_DIR/last-run.json" 2>/dev/null)"

echo; echo "== 3b. log forwarding re-attached (sentry container log -> validator remote journal)"
newest_us() { # realtime (us) of the newest $SENTRY_C entry in the remote journal, empty if none/unreadable
  local n
  n="$(L "sudo -n journalctl -D $LOGSHIP_DIR -t $SENTRY_C -r -n 1 -o json --no-pager" 2>/dev/null | jq -r '.__REALTIME_TIMESTAMP // empty' 2>/dev/null)"
  case "$n" in ''|*[!0-9]*) n="" ;; esac
  echo "$n"
}
T1="$(date -u +%s)"; AFTER_US=$((T1 * 1000000)); NEWEST=""
while :; do
  NEWEST="$(newest_us)"
  [ -n "$NEWEST" ] && [ "$NEWEST" -gt "$AFTER_US" ] && break
  [ "$(date -u +%s)" -ge $((T1 + LOGSHIP_WAIT)) ] && break
  sleep 5
done
US="$(R "systemctl show -p ActiveState -p NRestarts $LOGSHIP_UNIT" 2>/dev/null)"
UA="$(sed -n 's/^ActiveState=//p' <<<"$US")"; NR="$(sed -n 's/^NRestarts=//p' <<<"$US")"
case "$NR" in ''|*[!0-9]*) NR=null ;; esac
LS="$(jq -nc --arg u "$UA" --argjson nr "$NR" --arg n "$NEWEST" --argjson a "$AFTER_US" \
  '{unit: (if $u == "" then null else $u end), nrestarts: $nr, newest_us: (if $n == "" then null else ($n | tonumber) end), after_us: $a}')"
echo "  pft-rollout returned $(date -u -d "@$T1" +%FT%TZ); newest forwarded $SENTRY_C line: $([ -n "$NEWEST" ] && date -u -d "@$((NEWEST / 1000000))" +%FT%TZ || echo none) (waited $(($(date -u +%s) - T1)) s, max $LOGSHIP_WAIT)"
echo "  relay $LOGSHIP_UNIT: ActiveState=${UA:-unknown} NRestarts=$NR"

echo; echo "== 4. clean up, restore, read back, verdict"
if [ "$DRILL_BUILT" -eq 1 ]; then
  R "sudo -n docker rmi $DRILL_TAG" 2>&1 | sed 's/^/  rmi: /'
  echo "  $DRILL_TAG still present: $(R "sudo -n docker image inspect $DRILL_TAG" >/dev/null 2>&1 && echo YES || echo no)"
fi
restore
sleep "$NTFY_WAIT"
readback() { # TOPIC LABEL -> prints messages, sets N_MSG (number, or null if ntfy could not be read)
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else
    N_MSG=null; echo "  $2 topic: could not be read from ntfy"
  fi
}
readback "$MAINT" MAINT
readback "$ALERT" ALERT; ALERTS="$N_MSG"
if [ "$INTEGRITY_CMD" != none ]; then
  echo "  \$ $INTEGRITY_CMD verify (local)"; "$INTEGRITY_CMD" verify 2>&1 | red | tail -12 | sed 's/^/    /'
  echo "  \$ $INTEGRITY_CMD verify (relay)"; R "sudo -n $INTEGRITY_CMD verify" 2>&1 | red | tail -12 | sed 's/^/    /'
fi
FACTS="$STATE_DIR/facts-${RUN:-none}.json"
jq -n --argjson e "$RC" --argjson a "$ALERTS" --argjson sb "$SB" --argjson sa "$SA" --argjson vb "$VB" --argjson va "$VA" --argjson ls "$LS" \
  '{exit: $e, alert_msgs: $a, sentry: {before: $sb, after: $sa}, validator: {before: $vb, after: $va}, logship: $ls}' > "$FACTS"
echo "  facts: $(jq -c . "$FACTS")"
echo "\$ check-drill.sh $MODE <audit> ${RUN:-<none>} <facts>"
bash "$CHECK" "$MODE" "$STATE_DIR/audit.jsonl" "${RUN:-none}" "$FACTS"; CRC=$?
echo "live-run $MODE done $(ts): pft-rollout exit $RC, verdict exit $CRC"
exit "$CRC"
