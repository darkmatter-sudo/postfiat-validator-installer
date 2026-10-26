#!/usr/bin/env bash
# Live pft-egress found -> fixed -> verified drill on a sentry or validator host, with every notifier on the host pointed
# at a throwaway ntfy topic (restored on ANY exit, then compared by sha256 against the backup). On a host that runs
# the alerts/ stack (validator), an Alertmanager silence for every alert covers the drill and is expired afterwards.
#   sudo bash drill-sentry.sh [--container NAME] [--target HOST:PORT] [--deadman MIN]   (run from egress/)
# 1  redirect notifiers (pft-watchdog, pft-integrity, postfiat-monitor, pft-maint) to a random throwaway topic,
#    Alertmanager silence (all alerts, 60 min) when Alertmanager answers on 127.0.0.1:9093
# 2  guard proof without a maintenance window: apply --yes must exit 4 and change nothing
# 3  FOUND: plan + before-probe (non-allowlisted TARGET connects) + validator-list fetch
# 4  FIXED: pft-maint start -> apply --yes --foreground (dead-man runs inline) -> pft-maint end
# 5  VERIFIED: same probe blocked, drop log line, validator-list fetch still 200, check PASS
# 6  pft-integrity verify -> accept with a task reason -> verify
# 7  restore notifiers, read the throwaway topic back
# Printed redactions: public IPv4 -> <redacted-ip>, MAC= -> <redacted-mac>, topic -> <redacted>, "by <user>".
set -euo pipefail
CONTAINER=postfiatd-sentry; TARGET=example.com:80; DEADMAN=10; REASON="pft-egress: default-deny egress policy applied"
VL_URL=https://postfiat.org/testnet_vl.json
while [ $# -gt 0 ]; do
  case "$1" in --container) CONTAINER="$2"; shift 2 ;; --target) TARGET="$2"; shift 2 ;;
               --deadman) DEADMAN="$2"; shift 2 ;; --reason) REASON="$2"; shift 2 ;; *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
[ -f ./pft-egress.sh ] || { echo "run from the egress/ directory" >&2; exit 3; }
PE=./pft-egress.sh
ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/postfiat-monitor.env"
AM=http://127.0.0.1:9093; SIL=""
MENV=/etc/pft-maint/ntfy.env
topic="egressdrill-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
since="$(date -u +%s)"; WINDOW=0; RESTORED=0
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

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$WINDOW" -eq 1 ]; then pft-maint end --reason "pft-egress live apply finished (trap)" || true; fi
  local f
  for f in $ENVS; do
    [ -f "$f.pre-egress-drill" ] || continue
    mv -f "$f.pre-egress-drill" "$f"
    echo "restored $f: sha256 matches pre-drill copy: $([ "$(sha256sum < "$f")" = "$(cat "$(shafile "$f")")" ] && echo yes || echo NO) ($(stat -c '%U %a' "$f"))"
    rm -f "$(shafile "$f")"
  done
  if [ "${MENV_CREATED:-0}" -eq 1 ]; then rm -f "$MENV"; echo "removed drill-only $MENV: $([ -e "$MENV" ] && echo NO || echo yes)"; fi
  if [ -n "$SIL" ]; then
    curl -s -X DELETE "$AM/api/v2/silence/$SIL" -o /dev/null -w "Alertmanager silence ${SIL:0:8} expired (HTTP %{http_code})\n" || true
  fi
}
trap restore EXIT

{
trap restore EXIT  # the block runs in a subshell (piped through red): restore from inside it
echo "pft-egress sentry live drill - $(date -u +%FT%TZ) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - $(iptables -V) - container $CONTAINER"
echo "script sha256: pft-egress.sh $(sha256sum "$PE" | cut -c1-64) | drill-sentry.sh $(sha256sum "$0" | cut -c1-64)"

echo; echo "== 1. redirect every notifier on this host to a throwaway topic"
for f in $ENVS; do
  [ -f "$f" ] || { echo "  $f: absent (nothing to redirect)"; continue; }
  sf="$(shafile "$f")"; sha256sum < "$f" > "$sf"
  cp -p "$f" "$f.pre-egress-drill"
  { grep -vE '^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER|NTFY_URL)=' "$f.pre-egress-drill" || true  # keep NODE_LABEL etc.
    printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic"; } > "$f.new"
  chmod 600 "$f.new"; mv -f "$f.new" "$f"
  echo "  $f -> https://ntfy.sh/<redacted> (throwaway, other settings kept), original kept as $f.pre-egress-drill"
done
if [ -e "$MENV" ]; then echo "  $MENV already exists - refusing to overwrite it" >&2; exit 3; fi
MENV_CREATED=1
printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic" > "$MENV"; chmod 600 "$MENV"
echo "  $MENV created for the drill only -> https://ntfy.sh/<redacted> (throwaway)"
echo "  notifier timers on this host: $(systemctl list-timers --all --no-legend 2>/dev/null | grep -oE '(pft|postfiat)[a-z-]*\.timer' | sort -u | tr '\n' ' ')"
echo "  alert containers on this host: $(docker ps --format '{{.Names}}' | grep -v "^$CONTAINER\$" | tr '\n' ' ')(none = no Alertmanager to silence)"
if curl -fsS --max-time 5 -o /dev/null "$AM/-/ready" 2>/dev/null; then
  SIL="$(curl -fsS -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc \
    --arg s "$(date -u +%FT%TZ)" --arg e "$(date -u -d '+60 min' +%FT%TZ)" '{matchers:[{name:"alertname",value:".+",
    isRegex:true,isEqual:true}], startsAt:$s, endsAt:$e, createdBy:"egress drill-sentry.sh",
    comment:"planned: pft-egress live apply"}')" | jq -r '.silenceID // empty')"
  [ -n "$SIL" ] || { echo "  Alertmanager is up but the silence was not created - stopping"; exit 3; }
  echo "  Alertmanager silence ${SIL:0:8} alertname=~.+ for 60m (expired again in restore)"
else echo "  Alertmanager: not running on this host (nothing to silence)"; fi

echo; echo "== 2. live guard proof: no maintenance window"
pft-maint status
before="$(iptables -S | sha256sum)"
echo "\$ pft-egress apply --yes --container $CONTAINER"; set +e; bash "$PE" apply --yes --container "$CONTAINER"; rc=$?; set -e
echo "exit $rc (expect 4); filter table unchanged: $([ "$(iptables -S | sha256sum)" = "$before" ] && echo yes || echo NO)"
[ "$rc" -eq 4 ] || { echo "guard did not refuse - stopping"; exit 1; }

echo; echo "== 3. FOUND: the container can open connections anywhere"
echo "\$ iptables -S DOCKER-USER"; iptables -S DOCKER-USER
echo "\$ pft-egress plan --container $CONTAINER"; bash "$PE" plan --container "$CONTAINER"
echo "\$ pft-egress apply --dry-run --container $CONTAINER"; bash "$PE" apply --dry-run --container "$CONTAINER"
echo "\$ pft-egress probe --container $CONTAINER --target $TARGET"; bash "$PE" probe --container "$CONTAINER" --target "$TARGET"
echo "validator-list fetch from the container ($VL_URL): HTTP $(vl)"
I0="$(docker exec "$CONTAINER" curl -s --max-time 5 http://127.0.0.1:5005/ -X POST -d '{"method":"server_info","params":[{}]}' | jq -c '.result.info | {server_state, peers}')"
echo "node before: $I0"

echo; echo "== 4. FIXED: maintenance window -> apply (dead-man ${DEADMAN} min, inline) -> end"
echo "\$ pft-maint start --ttl 30m --reason \"pft-egress live apply\" --no-sentry"
pft-maint start --ttl 30m --reason "pft-egress live apply" --no-sentry; WINDOW=1
pft-maint status
echo "\$ pft-egress apply --yes --foreground --deadman $DEADMAN --container $CONTAINER"
set +e; bash "$PE" apply --yes --foreground --deadman "$DEADMAN" --container "$CONTAINER"; ARC=$?; set -e
echo "apply exit $ARC"
echo "\$ pft-maint end"; pft-maint end --reason "pft-egress live apply done"; WINDOW=0

echo; echo "== 5. VERIFIED"
echo "\$ iptables -S DOCKER-USER"; iptables -S DOCKER-USER
echo "\$ iptables -S PFT-EGRESS"; iptables -S PFT-EGRESS || true
echo "\$ pft-egress probe --container $CONTAINER --target $TARGET"; bash "$PE" probe --container "$CONTAINER" --target "$TARGET"
sleep 2
echo "kernel drop log since drill start:"; journalctl -k --since "@$since" --no-pager -o short-iso 2>/dev/null | grep -F "pft-egress-drop:" | sed -E 's/^([^ ]+) [^ ]+ /\1 <host> /' | tail -5 || true
echo "validator-list fetch from the container ($VL_URL): HTTP $(vl)"
echo "\$ pft-egress check --container $CONTAINER"; set +e; bash "$PE" check --container "$CONTAINER"; CRC=$?; set -e
echo "check exit $CRC"
echo "\$ systemctl is-enabled pft-egress-reapply@$CONTAINER.timer: $(systemctl is-enabled "pft-egress-reapply@$CONTAINER.timer" 2>&1)"

echo; echo "== 6. pft-integrity rebaseline"
echo "\$ pft-integrity verify"; set +e; pft-integrity verify 2>&1; set -e
if [ "$ARC" -eq 0 ] && [ "$CRC" -eq 0 ]; then
  echo "\$ pft-integrity accept --reason \"$REASON\""; pft-integrity accept --reason "$REASON" 2>&1
  echo "\$ pft-integrity verify"; pft-integrity verify 2>&1
else echo "apply/check not PASS - baseline NOT accepted"; fi

echo; echo "== 7. after"
pft-maint status
restore
sleep 5
echo "throwaway topic read back from ntfy.sh (since drill start):"
curl -s --max-time 20 "https://ntfy.sh/$topic/json?poll=1&since=$since" | jq -c 'select(.event=="message") | {time: (.time|todate), title, message}'
echo "drill-sentry done: apply exit $ARC, check exit $CRC"
} 2>&1 | red
exit "${PIPESTATUS[0]}"
