#!/usr/bin/env bash
# Live pft-confine apply on a SENTRY host, with every alert path pointed at a throwaway ntfy topic.
#   sudo bash drill-sentry.sh [--container NAME] [--ttl 30m]      (run from the confine/ directory)
# 1  redirect: back up /etc/pft-watchdog/ntfy.env and /etc/pft-integrity.env, write a random throwaway topic
#    into both and into /etc/pft-maint/ntfy.env (created only for the drill). Restored on ANY exit (trap),
#    then compared by sha256 against the backup.
# 2  live guard proof with NO maintenance window: apply without --yes, apply --yes (both expect exit 4).
# 3  discover -> plan -> probe (throwaway container) -> pft-maint start --no-sentry -> apply --yes -> verify
#    -> pft-maint end.
# 4  pft-integrity verify (shows what the recreate changed) -> accept with a task reason -> verify again.
# 5  post state, restore, and read the throwaway topic back from ntfy.sh.
# The topic is printed as <redacted>; the user name in pft-integrity output as <user>.
set -euo pipefail
CONTAINER=postfiatd-sentry; TTL=30m; REASON="pft-confine: least-privilege profile applied"
while [ $# -gt 0 ]; do
  case "$1" in --container) CONTAINER="$2"; shift 2 ;; --ttl) TTL="$2"; shift 2 ;; --reason) REASON="$2"; shift 2 ;;
               *) echo "unknown $1" >&2; exit 3 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
[ -f ./pft-confine.sh ] || { echo "run from the confine/ directory" >&2; exit 3; }
PC=./pft-confine.sh
ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env"
MENV=/etc/pft-maint/ntfy.env
topic="confinedrill-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
since="$(date -u +%s)"; WINDOW=0; RESTORED=0
shafile() { echo "/run/confine-drill.$(basename "$(dirname "$1")").sha"; }
red() { sed -E "s/by [a-z_][a-z0-9_-]*/by <user>/g; s/$topic/<redacted>/g"; }

restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  if [ "$WINDOW" -eq 1 ]; then pft-maint end --reason "pft-confine live apply finished (trap)" || true; fi
  local f
  for f in $ENVS; do
    [ -f "$f.pre-confine-drill" ] || continue
    mv -f "$f.pre-confine-drill" "$f"
    echo "restored $f: sha256 matches pre-drill copy: $([ "$(sha256sum < "$f")" = "$(cat "$(shafile "$f")")" ] && echo yes || echo NO) ($(stat -c '%U %a' "$f"))"
    rm -f "$(shafile "$f")"
  done
  if [ "${MENV_CREATED:-0}" -eq 1 ]; then rm -f "$MENV"; echo "removed drill-only $MENV: $([ -e "$MENV" ] && echo NO || echo yes)"; fi
}
trap restore EXIT

echo "pft-confine sentry live apply - $(date -u +%FT%TZ) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - container $CONTAINER"
echo "script sha256: pft-confine.sh $(sha256sum "$PC" | cut -c1-64) | drill-sentry.sh $(sha256sum "$0" | cut -c1-64)"

echo; echo "== 1. redirect every notifier on this host to a throwaway topic"
for f in $ENVS; do
  [ -f "$f" ] || { echo "  $f: absent (nothing to redirect)"; continue; }
  sf="$(shafile "$f")"; sha256sum < "$f" > "$sf"
  cp -p "$f" "$f.pre-confine-drill"
  printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic" > "$f"; chmod 600 "$f"
  echo "  $f -> https://ntfy.sh/<redacted> (throwaway), original kept as $f.pre-confine-drill"
done
if [ -e "$MENV" ]; then echo "  $MENV already exists - refusing to overwrite it" >&2; exit 3; fi
MENV_CREATED=1
printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$topic" > "$MENV"; chmod 600 "$MENV"
echo "  $MENV created for the drill only -> https://ntfy.sh/<redacted> (throwaway)"
echo "  notifier timers on this host: $(systemctl list-timers --all --no-legend 2>/dev/null | grep -oE '(pft|postfiat)[a-z-]*\.timer' | sort -u | tr '\n' ' ')"
echo "  alert containers on this host: $(docker ps --format '{{.Names}}' | grep -v "^$CONTAINER\$" | tr '\n' ' ')(none = no Alertmanager to silence)"

echo; echo "== 2. live guard proof: no maintenance window"
set +e
echo "\$ pft-confine apply --container $CONTAINER"; bash "$PC" apply --container "$CONTAINER"; echo "exit $? (expect 4)"
echo "\$ pft-confine apply --yes --container $CONTAINER"; bash "$PC" apply --yes --container "$CONTAINER"; rc=$?; echo "exit $rc (expect 4)"
set -e
[ "$rc" -eq 4 ] || { echo "guard did not refuse - stopping"; exit 1; }

echo; echo "== 3. discover -> plan -> probe -> window -> apply -> verify"
echo "\$ pft-confine discover --container $CONTAINER"; bash "$PC" discover --container "$CONTAINER"
echo "\$ pft-confine plan --container $CONTAINER"; bash "$PC" plan --container "$CONTAINER"
echo "\$ pft-confine probe --container $CONTAINER"; set +e; bash "$PC" probe --container "$CONTAINER"; rc=$?; set -e
[ "$rc" -eq 0 ] || { echo "probe failed - not applying"; exit 1; }
echo "\$ pft-maint start --ttl $TTL --reason \"pft-confine live apply\" --no-sentry"
pft-maint start --ttl "$TTL" --reason "pft-confine live apply" --no-sentry; WINDOW=1
pft-maint status
echo "\$ pft-confine apply --yes --container $CONTAINER"; set +e; bash "$PC" apply --yes --container "$CONTAINER"; ARC=$?; set -e
echo "apply exit $ARC"
echo "\$ pft-confine verify --container $CONTAINER"; set +e; bash "$PC" verify --container "$CONTAINER"; VRC=$?; set -e
echo "verify exit $VRC"
echo "\$ pft-maint end"; pft-maint end --reason "pft-confine live apply done"; WINDOW=0

echo; echo "== 4. pft-integrity rebaseline"
echo "\$ pft-integrity verify"; set +e; pft-integrity verify 2>&1 | red; set -e
if [ "$ARC" -eq 0 ] && [ "$VRC" -eq 0 ]; then
  echo "\$ pft-integrity accept --reason \"$REASON\""; pft-integrity accept --reason "$REASON" 2>&1 | red
  echo "\$ pft-integrity verify"; pft-integrity verify 2>&1 | red
else echo "apply/verify not PASS - baseline NOT accepted"; fi

echo; echo "== 5. after"
docker ps -a --filter "name=$CONTAINER" --format '{{.Names}} {{.Status}}'
pft-maint status
restore
sleep 5
echo "throwaway topic read back from ntfy.sh (since drill start):"
curl -s --max-time 20 "https://ntfy.sh/$topic/json?poll=1&since=$since" | jq -c 'select(.event=="message") | {time: (.time|todate), title, message}'
echo "drill-sentry done: apply exit $ARC, verify exit $VRC"
[ "$ARC" -eq 0 ] && [ "$VRC" -eq 0 ]
