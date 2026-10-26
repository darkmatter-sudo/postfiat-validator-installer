#!/usr/bin/env bash
# Live pft-egress rollback drill on a SENTRY host that already has the policy applied, then a re-apply, with every
# notifier on the host pointed at a throwaway ntfy topic (restored on ANY exit, then compared by sha256).
#   sudo bash drill-rollback.sh [--container NAME] [--target HOST:PORT] [--deadman MIN] [--pre-log FILE]  (from egress/)
# 1  redirect notifiers (pft-watchdog, pft-integrity, pft-maint) to a random throwaway topic
# 2  BEFORE: check PASS, probe blocked, filter table snapshot; expected DOCKER-USER = live minus the pft-egress jump
# 3  ROLLBACK: without --yes refuses (exit 4, nothing changed); rollback --yes; then DOCKER-USER identical to the
#    expected rules AND to the pre-apply listing in PRE_LOG; no PFT-EGRESS chain; whole filter table equal to the
#    before snapshot minus pft-egress lines; reapply timer disabled; probe CONNECTED again; validator list 200; node full
# 4  pft-integrity verify -> accept (rollback) -> verify
# 5  RE-APPLY (the policy stays on): pft-maint window -> apply --yes --foreground (dead-man inline) -> end;
#    check PASS, probe blocked; pft-integrity verify -> accept -> verify
# 6  restore notifiers, read the throwaway topic back
# Printed redactions: public IPv4 -> <redacted-ip>, MAC= -> <redacted-mac>, topic -> <redacted>, "by <user>".
set -euo pipefail
CONTAINER=postfiatd-sentry; TARGET=example.com:80; DEADMAN=10; PRE_LOG=logs/sentry-live-drill.log; TASK=""
VL_URL=https://postfiat.org/testnet_vl.json
while [ $# -gt 0 ]; do
  case "$1" in --container) CONTAINER="$2"; shift 2 ;; --target) TARGET="$2"; shift 2 ;;
               --deadman) DEADMAN="$2"; shift 2 ;; --pre-log) PRE_LOG="$2"; shift 2 ;; --task) TASK="$2"; shift 2 ;;
               *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
[ -f ./pft-egress.sh ] || { echo "run from the egress/ directory" >&2; exit 3; }
[ -f "$PRE_LOG" ] || { echo "pre-apply log $PRE_LOG missing" >&2; exit 3; }
PE=./pft-egress.sh
ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env"
MENV=/etc/pft-maint/ntfy.env
topic="egressdrill-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
since="$(date -u +%s)"; WINDOW=0; RESTORED=0; TMP="$(mktemp -d)"
shafile() { echo "/run/egress-drill.$(printf %s "$1" | tr -c "A-Za-z0-9._-" _).sha"; }  # one file per path (dir name alone collided for /etc/*.env)
red() {
  sed -uE "s/by [a-z_][a-z0-9_-]*/by <user>/g; s/$topic/<redacted>/g; s/MAC=[0-9a-f:]+/MAC=<redacted-mac>/g" \
  | python3 -c '
import ipaddress, re, sys
def sub(m):
    try:
        a = ipaddress.ip_address(m.group(0))
    except ValueError:
        return m.group(0)
    return m.group(0) if (a.is_private or a.is_loopback or a.is_unspecified) else "<redacted-ip>"
for line in sys.stdin:
    sys.stdout.write(re.sub(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", sub, line)); sys.stdout.flush()'
}
vl() { docker exec "$CONTAINER" curl -s -o /dev/null --max-time 15 -w '%{http_code}' "$VL_URL" || true; }
node() { docker exec "$CONTAINER" curl -s --max-time 5 http://127.0.0.1:5005/ -X POST -d '{"method":"server_info","params":[{}]}' \
         | jq -c '.result.info | {server_state, peers}'; }
same() { if cmp -s "$1" "$2"; then echo yes; else echo NO; diff "$1" "$2" | sed 's/^/    /'; fi; }
# "-A DOCKER-USER ... -j PFT-EGRESS" jump lines and every PFT-EGRESS chain line
strip_egress() { grep -v -E -- '(-j PFT-EGRESS( |$)|^-N PFT-EGRESS$|^-A PFT-EGRESS )' || true; }

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$WINDOW" -eq 1 ]; then pft-maint end --reason "pft-egress re-apply finished (trap)" || true; fi
  local f
  for f in $ENVS; do
    [ -f "$f.pre-egress-drill" ] || continue
    mv -f "$f.pre-egress-drill" "$f"
    echo "restored $f: sha256 matches pre-drill copy: $([ "$(sha256sum < "$f")" = "$(cat "$(shafile "$f")")" ] && echo yes || echo NO) ($(stat -c '%U %a' "$f"))"
    rm -f "$(shafile "$f")"
  done
  if [ "${MENV_CREATED:-0}" -eq 1 ]; then rm -f "$MENV"; echo "removed drill-only $MENV: $([ -e "$MENV" ] && echo NO || echo yes)"; fi
  rm -rf "$TMP"
}
trap restore EXIT

{
trap restore EXIT  # the block runs in a subshell (piped through red): restore from inside it
echo "pft-egress sentry rollback + re-apply drill - $(date -u +%FT%TZ) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - $(iptables -V) - container $CONTAINER"
echo "script sha256: pft-egress.sh $(sha256sum "$PE" | cut -c1-64) | drill-rollback.sh $(sha256sum "$0" | cut -c1-64)"
echo "installed /usr/local/sbin/pft-egress sha256 $(sha256sum /usr/local/sbin/pft-egress | cut -c1-64)"

echo; echo "== 1. redirect every notifier on this host to a throwaway topic"
if [ -e "$MENV" ]; then echo "  $MENV already exists - refusing to overwrite it" >&2; exit 3; fi
for f in $ENVS; do
  [ -f "$f" ] || { echo "  $f: absent (nothing to redirect)"; continue; }
  sf="$(shafile "$f")"; sha256sum < "$f" > "$sf"
  cp -p "$f" "$f.pre-egress-drill"
  printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic" > "$f"; chmod 600 "$f"
  echo "  $f -> https://ntfy.sh/<redacted> (throwaway), original kept as $f.pre-egress-drill"
done
MENV_CREATED=1
printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic" > "$MENV"; chmod 600 "$MENV"
echo "  $MENV created for the drill only -> https://ntfy.sh/<redacted> (throwaway)"

echo; echo "== 2. BEFORE: policy on"
echo "\$ pft-egress check --container $CONTAINER"; set +e; bash "$PE" check --container "$CONTAINER"; c0=$?; set -e
echo "check exit $c0"; [ "$c0" -eq 0 ] || { echo "policy not in a PASS state - stopping before any change"; exit 1; }
echo "\$ pft-egress probe --container $CONTAINER --target $TARGET"; bash "$PE" probe --container "$CONTAINER" --target "$TARGET"
echo "\$ iptables -S DOCKER-USER"; iptables -S DOCKER-USER | tee "$TMP/du-before"
iptables -S > "$TMP/filter-before"
strip_egress < "$TMP/du-before" > "$TMP/du-expected"
# the DOCKER-USER listing printed in section 3 of the apply drill log (before the policy existed)
awk '/^== 3\. FOUND/ { f = 1; next } f && /^\$ iptables -S DOCKER-USER$/ { g = 1; next } g && /^\$ / { exit } g' "$PRE_LOG" > "$TMP/du-pre-apply"
echo "expected after rollback = live DOCKER-USER minus pft-egress jump ($(wc -l < "$TMP/du-expected") rules);"
echo "pre-apply listing from $PRE_LOG: $(wc -l < "$TMP/du-pre-apply") lines"
echo "pft-egress state: $(jq -c '{applied_at, deadman_passed_at, baseline_peers}' "/var/lib/pft-egress/$CONTAINER.json")"
echo "timer: $(systemctl is-enabled "pft-egress-reapply@$CONTAINER.timer" 2>&1)/$(systemctl is-active "pft-egress-reapply@$CONTAINER.timer" 2>&1)"
echo "node before: $(node)"

echo; echo "== 3. ROLLBACK"
echo "\$ pft-egress rollback --container $CONTAINER   (no --yes)"; set +e; bash "$PE" rollback --container "$CONTAINER"; r0=$?; set -e
echo "exit $r0 (expect 4); filter table unchanged: $(iptables -S | cmp -s - "$TMP/filter-before" && echo yes || echo NO)"
[ "$r0" -eq 4 ] || { echo "rollback without --yes did not refuse - stopping"; exit 1; }
echo "\$ pft-egress rollback --yes --container $CONTAINER"; set +e; bash "$PE" rollback --yes --container "$CONTAINER"; RRC=$?; set -e
echo "rollback exit $RRC"
echo "\$ iptables -S DOCKER-USER"; iptables -S DOCKER-USER | tee "$TMP/du-after"
echo "DOCKER-USER identical to expected (live minus jump): $(same "$TMP/du-expected" "$TMP/du-after")"
echo "DOCKER-USER identical to the pre-apply listing in $PRE_LOG: $(same "$TMP/du-pre-apply" "$TMP/du-after")"
echo "\$ iptables -S PFT-EGRESS"; set +e; iptables -S PFT-EGRESS 2>&1; x=$?; set -e; echo "exit $x (expect 1: no such chain)"
iptables -S > "$TMP/filter-after"
strip_egress < "$TMP/filter-before" > "$TMP/filter-expected"
echo "whole filter table = before minus pft-egress lines ($(wc -l < "$TMP/filter-after") rules): $(same "$TMP/filter-expected" "$TMP/filter-after")"
echo "timer: $(systemctl is-enabled "pft-egress-reapply@$CONTAINER.timer" 2>&1)/$(systemctl is-active "pft-egress-reapply@$CONTAINER.timer" 2>&1) (expect disabled/inactive)"
echo "state file: $(find /var/lib/pft-egress/ -mindepth 1 -printf '%f ')"
echo "\$ pft-egress probe --container $CONTAINER --target $TARGET"; bash "$PE" probe --container "$CONTAINER" --target "$TARGET"
echo "validator-list fetch from the container ($VL_URL): HTTP $(vl)"
echo "node after rollback: $(node)"
echo "\$ pft-egress check --container $CONTAINER   (expect FAIL: no policy)"; set +e; bash "$PE" check --container "$CONTAINER"; c1=$?; set -e; echo "check exit $c1"

echo; echo "== 4. pft-integrity after rollback"
echo "\$ pft-integrity verify"; set +e; pft-integrity verify 2>&1; set -e
if [ "$RRC" -eq 0 ]; then
  echo "\$ pft-integrity accept --reason \"$TASK: pft-egress rollback drill (chain + jump removed, reapply timer disabled)\""
  pft-integrity accept --reason "$TASK: pft-egress rollback drill (chain + jump removed, reapply timer disabled)" 2>&1
  echo "\$ pft-integrity verify"; pft-integrity verify 2>&1
else echo "rollback not PASS - baseline NOT accepted"; fi

echo; echo "== 5. RE-APPLY (policy stays on after the drill)"
echo "\$ pft-maint start --ttl 30m --reason \"pft-egress re-apply after rollback drill\" --no-sentry"
pft-maint start --ttl 30m --reason "pft-egress re-apply after rollback drill" --no-sentry; WINDOW=1
echo "\$ pft-egress apply --yes --foreground --deadman $DEADMAN --container $CONTAINER"
set +e; bash "$PE" apply --yes --foreground --deadman "$DEADMAN" --container "$CONTAINER"; ARC=$?; set -e
echo "apply exit $ARC"
echo "\$ pft-maint end"; pft-maint end --reason "pft-egress re-apply done"; WINDOW=0
echo "\$ iptables -S DOCKER-USER"; iptables -S DOCKER-USER
iptables -S DOCKER-USER > "$TMP/du-reapplied"
echo "DOCKER-USER identical to the before-rollback listing: $(same "$TMP/du-before" "$TMP/du-reapplied")"
echo "\$ pft-egress probe --container $CONTAINER --target $TARGET"; bash "$PE" probe --container "$CONTAINER" --target "$TARGET"
echo "validator-list fetch from the container ($VL_URL): HTTP $(vl)"
echo "\$ pft-egress check --container $CONTAINER"; set +e; bash "$PE" check --container "$CONTAINER"; CRC=$?; set -e
echo "check exit $CRC"
echo "\$ pft-integrity verify"; set +e; pft-integrity verify 2>&1; set -e
if [ "$ARC" -eq 0 ] && [ "$CRC" -eq 0 ]; then
  echo "\$ pft-integrity accept --reason \"$TASK: pft-egress re-applied after rollback drill\""
  pft-integrity accept --reason "$TASK: pft-egress re-applied after rollback drill" 2>&1
  echo "\$ pft-integrity verify"; pft-integrity verify 2>&1
else echo "re-apply/check not PASS - baseline NOT accepted"; fi

echo; echo "== 6. after"
pft-maint status
restore
sleep 5
echo "throwaway topic read back from ntfy.sh (since drill start):"
curl -s --max-time 20 "https://ntfy.sh/$topic/json?poll=1&since=$since" | jq -c 'select(.event=="message") | {time: (.time|todate), title, message}'
echo "drill-rollback done: rollback exit $RRC, re-apply exit $ARC, check exit $CRC"
[ "$RRC" -eq 0 ] && [ "$ARC" -eq 0 ] && [ "$CRC" -eq 0 ]
} 2>&1 | red
exit "${PIPESTATUS[0]}"
