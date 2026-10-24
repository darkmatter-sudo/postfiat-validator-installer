#!/usr/bin/env bash
# Live pft-confine apply on the VALIDATOR host (compose container), with every alert path on both hosts quiet:
#   sudo bash drill-validator.sh [--container NAME] [--ttl 30m] [--reason TEXT]   (run from the confine/ directory)
# 1  redirect: /etc/postfiat-monitor.env and /etc/pft-integrity.env (NTFY_TOPIC/NTFY_TOKEN lines replaced),
#    /etc/pft-maint/ntfy.env (created for the drill only) and, on the sentry (`ssh relay`), /etc/pft-watchdog/ntfy.env
#    all point at one random throwaway topic. Alertmanager gets a silence (alertname=~.+, TTL + 10 min) because the
#    pft-alert-bridge has no maintenance hook. Everything is restored on ANY exit (trap) and compared by sha256.
# 2  live guard proof with NO maintenance window: apply without --yes, apply --yes (both expect exit 4).
# 3  discover -> plan -> probe (throwaway container) -> pft-maint start (flag also sent to the sentry watchdog)
#    -> apply --yes -> verify -> pft-maint end.
# 4  pft-integrity verify -> accept ONLY if every changed item is compose:* or container:<NAME> -> verify again.
# 5  post state, restore, expire the silence (if nothing is firing), read the throwaway topic back from ntfy.sh.
# The topic is printed as <redacted>; the user name in pft-integrity output as <user>.
set -euo pipefail
CONTAINER=postfiatd; TTL=30m; REASON="pft-confine: least-privilege profile applied"
while [ $# -gt 0 ]; do
  case "$1" in --container) CONTAINER="$2"; shift 2 ;; --ttl) TTL="$2"; shift 2 ;; --reason) REASON="$2"; shift 2 ;;
               *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
[ -f ./pft-confine.sh ] || { echo "run from the confine/ directory" >&2; exit 3; }
case "$TTL" in *m) TTL_MIN="${TTL%m}" ;; *) echo "--ttl must be in minutes (e.g. 30m)" >&2; exit 3 ;; esac
PC=./pft-confine.sh
ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
MENV=/etc/pft-maint/ntfy.env
WENV=/etc/pft-watchdog/ntfy.env
AM=http://127.0.0.1:9093
RUSER="${SUDO_USER:-root}"
R() { sudo -u "$RUSER" ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes relay "$@"; }
topic="confinedrill-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
since="$(date -u +%s)"; WINDOW=0; RESTORED=0; SIL=""; WREDIR=0; MENV_CREATED=0
ts() { date -u +%FT%TZ; }
shafile() { echo "/run/confine-drill.$(basename "$1").sha"; }
red() { sed -E "s/by [a-z_][a-z0-9_-]*/by <user>/g; s/$topic/<redacted>/g"; }

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$WINDOW" -eq 1 ]; then pft-maint end --reason "pft-confine live apply finished (trap)" 2>&1 | red || true; fi
  local f
  for f in $ENVS; do
    [ -f "$f.pre-confine-drill" ] || continue
    mv -f "$f.pre-confine-drill" "$f"
    echo "restored $f: sha256 matches pre-drill copy: $([ "$(sha256sum < "$f")" = "$(cat "$(shafile "$f")")" ] && echo yes || echo NO) ($(stat -c '%U %a' "$f"))"
    rm -f "$(shafile "$f")"
  done
  if [ "$MENV_CREATED" -eq 1 ]; then rm -f "$MENV"; echo "removed drill-only $MENV: $([ -e "$MENV" ] && echo NO || echo yes)"; fi
  if [ "$WREDIR" -eq 1 ]; then
    R "sudo mv -f $WENV.pre-confine-drill $WENV" || true
    echo "restored sentry $WENV: sha256 matches pre-drill copy: $([ "$(R "sudo sha256sum < $WENV")" = "$WSHA" ] && echo yes || echo NO)"
  fi
}
trap restore EXIT

echo "pft-confine validator live apply - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - container $CONTAINER"
echo "script sha256: pft-confine.sh $(sha256sum "$PC" | cut -c1-64) | drill-validator.sh $(sha256sum "$0" | cut -c1-64)"

echo; echo "== 0. preflight"
pft-maint status
if [ -e "$MENV" ]; then echo "  $MENV already exists - refusing to overwrite it" >&2; exit 3; fi
R "sudo test -f $WENV" || { echo "  sentry $WENV missing or relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable at $AM - stopping" >&2; exit 3; }
echo "  notifier timers on this host: $(systemctl list-timers --all --no-legend 2>/dev/null | grep -oE '(pft|postfiat)[a-z-]*\.timer' | sort -u | tr '\n' ' ')"
echo "  alert containers on this host: $(docker ps --format '{{.Names}}' | grep -v "^$CONTAINER\$" | tr '\n' ' ')"

echo; echo "== 1. redirect every notifier to a throwaway topic + Alertmanager silence"
for f in $ENVS; do
  [ -f "$f" ] || { echo "  $f: absent (nothing to redirect)"; continue; }
  sf="$(shafile "$f")"; sha256sum < "$f" > "$sf"
  cp -p "$f" "$f.pre-confine-drill"
  { grep -vE '^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=' "$f.pre-confine-drill" || true
    printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic"; } > "$f.new"
  chmod 600 "$f.new"; mv -f "$f.new" "$f"
  echo "  $f -> https://ntfy.sh/<redacted> (throwaway), original kept as $f.pre-confine-drill"
done
MENV_CREATED=1
( umask 077; printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic" > "$MENV" )
echo "  $MENV created for the drill only -> https://ntfy.sh/<redacted> (throwaway)"
WSHA="$(R "sudo sha256sum < $WENV")"
R "sudo cp -p $WENV $WENV.pre-confine-drill && sudo sh -c 'umask 077; printf \"NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n\" $topic > $WENV'"
WREDIR=1
echo "  sentry $WENV -> https://ntfy.sh/<redacted> (throwaway), original kept as $WENV.pre-confine-drill"
SIL="$(curl -s -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(ts)" \
  --arg e "$(date -u -d "+$((TTL_MIN + 10)) min" +%FT%TZ)" '{matchers:[{name:"alertname",value:".+",isRegex:true,isEqual:true}],
  startsAt:$s, endsAt:$e, createdBy:"pft-confine drill-validator", comment:"planned: pft-confine validator apply"}')" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  Alertmanager silence ${SIL:0:8} alertname=~.+ for $((TTL_MIN + 10))m"

echo; echo "== 2. live guard proof: no maintenance window"
set +e
echo "\$ pft-confine apply --container $CONTAINER"; bash "$PC" apply --container "$CONTAINER" 2>&1; echo "exit $? (expect 4)"
echo "\$ pft-confine apply --yes --container $CONTAINER"; bash "$PC" apply --yes --container "$CONTAINER" 2>&1; rc=$?; echo "exit $rc (expect 4)"
set -e
[ "$rc" -eq 4 ] || { echo "guard did not refuse - stopping"; exit 1; }

echo; echo "== 3. discover -> plan -> probe -> window -> apply -> verify"
echo "\$ pft-confine discover --container $CONTAINER"; bash "$PC" discover --container "$CONTAINER" 2>&1
echo "\$ pft-confine plan --container $CONTAINER"; bash "$PC" plan --container "$CONTAINER" 2>&1
echo "\$ pft-confine probe --container $CONTAINER"; set +e; bash "$PC" probe --container "$CONTAINER" 2>&1; rc=$?; set -e
[ "$rc" -eq 0 ] || { echo "probe failed - not applying"; exit 1; }
echo "\$ pft-maint start --ttl $TTL --reason \"[DRILL] pft-confine live apply\""
pft-maint start --ttl "$TTL" --reason "[DRILL] pft-confine live apply" 2>&1 | red; WINDOW=1
pft-maint status
echo "\$ pft-confine apply --yes --container $CONTAINER"; set +e; bash "$PC" apply --yes --container "$CONTAINER" 2>&1; ARC=$?; set -e
echo "apply exit $ARC"
echo "\$ pft-confine verify --container $CONTAINER"; set +e; bash "$PC" verify --container "$CONTAINER" 2>&1; VRC=$?; set -e
echo "verify exit $VRC"
echo "\$ pft-maint end"; pft-maint end --reason "pft-confine live apply done" 2>&1 | red; WINDOW=0

echo; echo "== 4. pft-integrity rebaseline"
echo "\$ pft-integrity verify"; set +e; IV="$(pft-integrity verify 2>&1)"; set -e; red <<<"$IV"
other="$(grep -E '^\s+\[(WARN|FAIL)\]' <<<"$IV" | grep -vE "\] +(compose:[^ ]+|container:$CONTAINER) " || true)"
if [ "$ARC" -eq 0 ] && [ "$VRC" -eq 0 ] && [ -z "$other" ]; then
  echo "\$ pft-integrity accept --reason \"$REASON\""; pft-integrity accept --reason "$REASON" 2>&1 | red
  echo "\$ pft-integrity verify"; pft-integrity verify 2>&1 | red
elif [ -n "$other" ]; then echo "changed items outside compose:/container:$CONTAINER: - baseline NOT accepted:"; red <<<"$other"
else echo "apply/verify not PASS - baseline NOT accepted"; fi

echo; echo "== 5. after"
docker ps -a --filter "name=$CONTAINER" --format '{{.Names}} {{.Status}}'
pft-maint status
restore
firing="$(curl -s "$AM/api/v2/alerts" | jq -r '[.[] | select(.status.state != "unprocessed") | .labels.alertname] | unique | join(",")')"
echo "Alertmanager alerts (any state, incl. silenced): ${firing:-none}"
if [ -z "$firing" ]; then curl -s -X DELETE "$AM/api/v2/silence/$SIL" -o /dev/null -w "Alertmanager silence ${SIL:0:8} expired (HTTP %{http_code})\n"
else echo "Alertmanager silence ${SIL:0:8} left to run out at its end time"; fi
sleep 5
echo "throwaway topic read back from ntfy.sh (since drill start):"
curl -s --max-time 20 "https://ntfy.sh/$topic/json?poll=1&since=$since" | jq -c 'select(.event=="message") | {time: (.time|todate), title, message}' | red
echo "drill-validator done $(ts): apply exit $ARC, verify exit $VRC"
[ "$ARC" -eq 0 ] && [ "$VRC" -eq 0 ]
