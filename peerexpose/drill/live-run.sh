#!/usr/bin/env bash
# live-run: the two-host pft-peerexpose drill, sentry first, with every notifier on both hosts pointed at throwaway
# topics, all output redacted on the way out, and a PASS/FAIL verdict from check-drill.sh.
#   bash drill/live-run.sh 2>&1 | tee LOG        (as the agent user, from peerexpose/; uses sudo -n and `ssh relay`)
# 0  preflight (nothing changed yet): relay reachable, Alertmanager ready, no pft-maint data-collection lock, no
#    leftover drill files, both nodes full. Host addresses (validator = the relay's view of us from $SSH_CLIENT,
#    sentry = the validator's [ips_fixed] entry), node pubkeys and the topics go into a 0600 literals file for
#    redact.py; nothing below prints a raw value. Redaction positive control runs here, before any change.
# 1  redirect: LOCAL_ENVS here and REMOTE_ENVS on the relay get a throwaway ALERT topic; a drill-only pft-maint
#    ntfy.env on both hosts points at a second throwaway MAINT topic. sha256 of each original is recorded and
#    everything is restored on ANY exit (trap) and compared. Alertmanager is silenced by pft-peerexpose itself.
# 2  sequence (each step: command line, redacted output, exit code -> STEPS jsonl):
#    a audit-sentry-initial (from here, public address)  b audit-validator-initial (from the relay)
#    c apply-sentry (--require-peer validator)            d audit-sentry-applied
#    e rollback-sentry                                    f audit-sentry-rolledback (violations must be back)
#    g reapply-sentry                                     h audit-sentry-reapplied
#    i apply-validator (required peer: its [ips_fixed])  j audit-validator-applied (from the relay)
#    k audit-sentry-final  l audit-validator-final       m peering + server_state on both hosts
# 3  restore notifiers, read both throwaway topics back, pft-integrity verify on both hosts, facts JSON,
#    check-drill.sh, and redact.py check over this run's own log if LOG_FILE is set. Exit = checker exit (0 PASS).
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  SENTRY_C (postfiatd-sentry)
#      VALIDATOR_C (postfiatd)  GATE (1800 s per gate)  LOCAL_ENVS  REMOTE_ENVS  MAINT_DIR_L / MAINT_DIR_R (/etc/pft-maint)
#      INTEGRITY_CMD (pft-integrity, none = skip)  NTFY_WAIT (15)  OUT (~/.local/state/pft-peerexpose/drill)
#      LOG_FILE (the tee target, scanned by redact.py check at the end)  PFT_PEEREXPOSE / CHECK_DRILL / REDACT
#      DRY (0; 1 = preflight + redirect + restore only, no pft-peerexpose step)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PX="${PFT_PEEREXPOSE:-$HERE/../pft-peerexpose.sh}"; CHECK="${CHECK_DRILL:-$HERE/check-drill.sh}"
REDACT="${REDACT:-$HERE/redact.py}"
# shellcheck source=lib.sh source-path=SCRIPTDIR
. "$HERE/lib.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"; AM="${AM:-http://127.0.0.1:9093}"
SENTRY_C="${SENTRY_C:-postfiatd-sentry}"; VALIDATOR_C="${VALIDATOR_C:-postfiatd}"; GATE="${GATE:-1800}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env}"
MAINT_DIR_L="${MAINT_DIR_L:-/etc/pft-maint}"; MAINT_DIR_R="${MAINT_DIR_R:-/etc/pft-maint}"
INTEGRITY_CMD="${INTEGRITY_CMD:-pft-integrity}"; NTFY_WAIT="${NTFY_WAIT:-15}"; DRY="${DRY:-0}"
OUT="${OUT:-$HOME/.local/state/pft-peerexpose/drill}"; LOG_FILE="${LOG_FILE:-}"
SUF=.pre-peerexpose-drill
CFG=/etc/postfiatd/postfiatd.cfg

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="peerdrill-$(rnd)"; MAINT="peermaint-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
printf 'topic\t%s\ntopic\t%s\nuser\t%s\n' "$ALERT" "$MAINT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -u -E 's/by [a-z_][a-z0-9_-]*/by <user>/g'; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
rpc() { # HOST CONTAINER METHOD -> admin RPC JSON
  on "$1" "sudo -n docker exec $2 curl -s -m 10 -d '{\"method\":\"$3\"}' http://127.0.0.1:5005"
}
peerfact() { # HOST CONTAINER OTHER_ADDR -> {"state","peers","has_other"}
  local si pa st p has=false
  si="$(rpc "$1" "$2" server_info)"; pa="$(rpc "$1" "$2" peers | jq -r '.result.peers[]?.address // empty' 2>/dev/null)"
  st="$(jq -r '.result.info.server_state // "down"' <<<"$si" 2>/dev/null)"; p="$(jq -r '.result.info.peers // 0' <<<"$si" 2>/dev/null)"
  grep -Eq "(^|[^0-9.])${3//./\\.}([]:]|$)" <<<"$pa" && has=true
  jq -nc --arg s "${st:-down}" --argjson p "${p:-0}" --argjson h "$has" '{state: $s, peers: $p, has_other: $h}'
}
mkdir -p "$OUT"; chmod 700 "$OUT"; STEPS="$OUT/steps-$RUN.jsonl"; : > "$STEPS"

declare -A SHA=()   # "host:path" -> sha256 before the drill
declare -a MOVED=() CREATED=()
RESTORED=0; RESTORE_OK=true; RDIR=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum < $f")"
    if [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
  for k in "${CREATED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n rm -f $f"
    if on "$h" "sudo -n test -e $f"; then echo "  removed drill-only $k: NO"; RESTORE_OK=false
    else echo "  removed drill-only $k: yes"; fi
  done
  [ -z "$RDIR" ] || R "rm -rf $RDIR"
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

# step NAME HOST(local|relay) ARGS... : runs pft-peerexpose (here, or the copy on the relay), redacted, records exit
step() {
  local name="$1" host="$2" rc res viol; shift 2
  echo; echo "-- $name ($(ts))"
  echo "\$ pft-peerexpose.sh $* $([ "$host" = relay ] && echo '   (on the sentry host)')" | red
  if [ "$host" = relay ]; then
    R "bash $RDIR/pft-peerexpose.sh $(printf '%q ' "$@")" > "$SEC/step.out" 2>&1; rc=$?
  else
    bash "$PX" "$@" > "$SEC/step.out" 2>&1; rc=$?
  fi
  red < "$SEC/step.out" | tee "$SEC/step.red"
  echo "exit $rc"
  res="$(parse_result "$SEC/step.red")"; viol="$(parse_viol "$SEC/step.red")"
  jq -nc --arg s "$name" --argjson e "$rc" --arg r "$res" --arg v "${viol:-}" \
    '{step: $s, exit: $e, result: (if $r == "" then null else $r end), violations: (if $v == "" then null else ($v | tonumber) end)}' >> "$STEPS"
}

{ echo "pft-peerexpose live-run - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN"
  echo "sha256: pft-peerexpose.sh $(sha256sum < "$PX" | cut -c1-64) | live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        check-drill.sh $(sha256sum < "$CHECK" | cut -c1-64) | redact.py $(sha256sum < "$REDACT" | cut -c1-64)"
  echo "        lib.sh $(sha256sum < "$HERE/lib.sh" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
locks="$(sudo -n pft-maint lock list 2>&1)"
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
# shellcheck disable=SC2016  # expands on the relay: the address it sees this host connect from
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"
SIP="$(sudo -n docker exec "$VALIDATOR_C" cat "$CFG" | awk '/^[[:space:]]*\[/ { on = (tolower($0) ~ /^[[:space:]]*\[ips_fixed\]/); next }
  on && !/^[[:space:]]*(#|$)/ { print $1; exit }')"
for v in "$VIP" "$SIP"; do
  python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$v" 2>/dev/null \
    || { echo "  could not determine both host addresses - stopping" >&2; exit 3; }
done
printf 'ip\t%s\nip\t%s\n' "$VIP" "$SIP" >> "$LIT"
for hc in "local:$VALIDATOR_C" "relay:$SENTRY_C"; do
  si="$(rpc "${hc%%:*}" "${hc#*:}" server_info)"
  st="$(jq -r '.result.info.server_state // "down"' <<<"$si" 2>/dev/null)"
  k="$(jq -r '.result.info.pubkey_node // empty' <<<"$si" 2>/dev/null)"
  [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  echo "  ${hc%%:*} ${hc#*:}: server_state=${st:-down} peers=$(jq -r '.result.info.peers // 0' <<<"$si" 2>/dev/null)"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
while read -r k; do [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"; done < <(rpc local "$VALIDATOR_C" validators \
  | jq -r '.result.publisher_lists[]?.pubkey_publisher // empty' 2>/dev/null)
pv="$(peerfact local "$VALIDATOR_C" "$SIP")"; ps="$(peerfact relay "$SENTRY_C" "$VIP")"
echo "  peering before: validator has sentry: $(jq -r .has_other <<<"$pv") | sentry has validator: $(jq -r .has_other <<<"$ps")"
[ "$(jq -r .has_other <<<"$pv")$(jq -r .has_other <<<"$ps")" = truetrue ] \
  || { echo "  sentry<->validator link not seen from both sides (or wrong address) - stopping" >&2; exit 4; }
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
RDIR="$(R 'mktemp -d')"
if [ -z "$RDIR" ] || ! R "cat > $RDIR/pft-peerexpose.sh" < "$PX" \
   || [ "$(R "sha256sum < $RDIR/pft-peerexpose.sh")" != "$(sha256sum < "$PX")" ]; then
  echo "  copy of pft-peerexpose.sh to the relay failed - stopping" >&2; exit 3
fi
echo "  pft-peerexpose.sh copied to the sentry host (temp dir, same sha256), removed on exit"
echo "  ok: relay reachable, Alertmanager ready, no locks, env files present, no leftovers, both nodes full"

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

SURL="https://$SIP:2559"; VURL="https://$VIP:2559"
S=(--role sentry --ssh "$RELAY" --container "$SENTRY_C" --url "$SURL" --gate-timeout "$GATE" --require-peer "$VIP")
if [ "$DRY" = 1 ]; then
  echo; echo "== 2. DRY=1: no pft-peerexpose step"
else
  echo; echo "== 2. sequence: sentry first, then validator"
  step audit-sentry-initial local audit --role sentry --url "$SURL"
  step audit-validator-initial relay audit --role validator --url "$VURL" --container "$SENTRY_C"
  step apply-sentry local apply "${S[@]}"
  step audit-sentry-applied local audit --role sentry --url "$SURL"
  step rollback-sentry local rollback "${S[@]}"
  step audit-sentry-rolledback local audit --role sentry --url "$SURL"
  step reapply-sentry local apply "${S[@]}"
  step audit-sentry-reapplied local audit --role sentry --url "$SURL"
  step apply-validator local apply --role validator --gate-timeout "$GATE"
  step audit-validator-applied relay audit --role validator --url "$VURL" --container "$SENTRY_C"
  step audit-sentry-final local audit --role sentry --url "$SURL"
  step audit-validator-final relay audit --role validator --url "$VURL" --container "$SENTRY_C"
fi

echo; echo "-- peering and server_state ($(ts))"
PV="$(peerfact local "$VALIDATOR_C" "$SIP")"; PS="$(peerfact relay "$SENTRY_C" "$VIP")"
echo "  validator: $PV   (has_other = the sentry is a connected peer)"
echo "  sentry:    $PS   (has_other = the validator is a connected peer)"

echo; echo "== 3. restore, read back, verdict"
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
readback "$MAINT" MAINT; MAINTS="$N_MSG"
readback "$ALERT" ALERT; ALERTS="$N_MSG"
if [ "$INTEGRITY_CMD" != none ]; then
  echo "  \$ $INTEGRITY_CMD verify (validator host)"; sudo -n "$INTEGRITY_CMD" verify 2>&1 | red | tail -12 | sed 's/^/    /'
  echo "  \$ $INTEGRITY_CMD verify (sentry host)"; R "sudo -n $INTEGRITY_CMD verify" 2>&1 | red | tail -12 | sed 's/^/    /'
fi
FACTS="$OUT/facts-$RUN.json"
jq -n --argjson a "$ALERTS" --argjson m "$MAINTS" --argjson r "$RESTORE_OK" --argjson rc "$RCTL" --argjson v "$PV" --argjson s "$PS" \
  --argjson dry "$([ "$DRY" = 1 ] && echo true || echo false)" \
  '{alert_msgs: $a, maint_msgs: $m, restore_ok: $r, redaction_control: $rc, dry: $dry, final: {validator: $v, sentry: $s}}' > "$FACTS"
echo "  facts: $(jq -c . "$FACTS")"
echo "  steps: $(wc -l < "$STEPS") recorded"
echo "\$ check-drill.sh <steps> <facts>"
bash "$CHECK" "$STEPS" "$FACTS"; CRC=$?
if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
  echo "\$ redact.py check --literals <literals> <this log so far>"
  python3 -u "$REDACT" check --literals "$LIT" "$LOG_FILE" | sed 's/^/  /'
fi
echo "live-run done $(ts): verdict exit $CRC"
exit "$CRC"
