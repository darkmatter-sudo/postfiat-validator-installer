#!/usr/bin/env bash
# restore-run: the pft-keyescrow live restore drill. The sentry "loses" its pinned node seed (cluster:node_seed,
# /var/lib/pft-cluster/node_seed), gets it back from the validator's escrow with `pft-keyescrow restore`, and is
# restarted to prove the node identity (pubkey_node) is unchanged. No seed byte is printed: the drill compares
# sha256 values and pubkeys inside the script and prints only yes/no and per-run HMAC tags (random key, never stored).
#   L1  loss: the seed file is MOVED (same inode, mode, owner) into a 0700 root drill dir on the sentry. pft-cluster
#       audit on the sentry must now FAIL seed:stored.
#   R1  restore --dry-run, then restore --yes (inside a pft-maint window on the sentry), only --item cluster:node_seed:
#       the restored file must be byte-identical to the moved copy, mode 600 root:root; pft-cluster audit PASS.
#   R2  `pft-maint restart-node` restarts postfiatd-sentry (guarded: window, locks, full before/after); pubkey_node
#       after == before; pft-cluster audit PASS on BOTH hosts (each counts the other as a cluster member again).
#   The node keeps running on its config during L1/R1 (postfiatd reads [node_seed] only at start), so the loss never
#   changes the live identity; R2 is the proof that the restored state starts the same identity.
# Built from ./tamper-run.sh (redirect / bridge swap / silence / window / read-back, PASS run 20) and the sentry restart
# + post-run PFTContainerRestarted silence of ../../backfill/drill/live-run.sh (PASS run 10).
#   bash keyescrow/drill/restore-run.sh > LOG 2>&1   (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet), 1 redirect notifiers + bridge + pft-maint env to a throwaway topic, silence every
#    alert except the pipeline watchdog, pft-maint window, 2 loss + restore, 3 restart + identity, 4 units/verify,
#    5 restore + read-back (operator topics: counts only). Exit 0 = every CHECK ok.
# Env: RELAY (relay) NTFY (https://ntfy.sh) AM PROM TTL (45m) SIL_TTL (60, min) CLEAR_WAIT (600, s)
#      READBACK_WAIT (150, s) PREFLIGHT_ONLY (0)
# shellcheck disable=SC2016  # ok_if conditions are single-quoted on purpose: evaluated later
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REDACT="${REDACT:-$REPO/peerexpose/drill/redact.py}"
RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_ENV=/etc/pft-maint/ntfy.env
TTL="${TTL:-45m}"; SIL_TTL="${SIL_TTL:-60}"; CLEAR_WAIT="${CLEAR_WAIT:-600}"; READBACK_WAIT="${READBACK_WAIT:-150}"
WATCHDOG_ALERT=PFTAlertPipelineWatchdog
SUF=.pre-keyescrow-restore
BIN=/usr/local/bin/pft-keyescrow
ST=/var/lib/pft-keyescrow
SEEDF=/var/lib/pft-cluster/node_seed
ITEM=cluster:node_seed
TASK=task_2361bde7

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="kerestore-$(rnd)"
HK="$(rnd)$(rnd)" # per-run HMAC key: tags show equality without exposing the value; never written anywhere
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
BKD="$ST/drill-restore-$RUN"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d "${TEST_TMPDIR:-$HOME/.cache}/kerestore.XXXXXX")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
tag() { printf '%s' "$1" | openssl dgst -sha256 -hmac "$HK" | sed 's/.*= //' | cut -c1-12; }
FAILS=0
check() { # NAME 0|1 DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { # print the exact command (redacted), run it, print its output (redacted) and exit code; output kept in XOUT
  echo "\$ $*" | red
  XOUT="$(eval "$*" 2>&1)"; XRC=$?
  printf '%s\n' "$XOUT" | red | sed 's/^/  /'
  echo "  (exit $XRC)"
}
pq() { # QUERY -> "labels value" lines
  curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric | del(.__name__) | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'
}
info() { # HOST CONTAINER FIELD
  on "$1" "sudo -n docker exec $2 curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
    | jq -r ".result.info.$3 // empty" 2>/dev/null
}
seed_sha() { R "sudo -n sha256sum $1 2>/dev/null" | cut -c1-64; }
seed_stat() { R "sudo -n stat -c '%a %U:%G' $1 2>/dev/null"; }
LAST_START=0; started() { LAST_START="$(date -u +%s)"; }

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0; MAINT_STARTED=0; MAINT_ENV_MADE=0; SIL=""; SEED_MOVED=0; SEED0=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha src n w
  if [ "$SEED_MOVED" = 1 ]; then
    if R "sudo -n test -f $SEEDF"; then
      echo "  seed file present (restored by the drill)"
    else
      echo "  seed file missing: moving the drill copy back"
      R "sudo -n mv $BKD/node_seed $SEEDF" || { echo "  mv back FAILED"; RESTORE_OK=false; }
    fi
    now_sha="$(seed_sha "$SEEDF")"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "$SEED0" ]; then echo "  seed sha256 equals the pre-drill seed: yes"
    else echo "  seed sha256 equals the pre-drill seed: NO (drill dir kept)"; RESTORE_OK=false; fi
    if [ "$RESTORE_OK" = true ]; then
      R "sudo -n rm -rf $BKD" && echo "  drill dir with the moved seed copy removed"
    fi
  fi
  if [ "$(R "sudo -n docker inspect -f '{{.State.Running}}' postfiatd-sentry")" != true ]; then
    echo "  postfiatd-sentry not running: starting it"; R "sudo -n docker start postfiatd-sentry" >/dev/null || { echo "  docker start FAILED"; RESTORE_OK=false; }
    started
  fi
  if [ "$MAINT_STARTED" = 1 ]; then
    echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'
  fi
  if [ "$MAINT_ENV_MADE" = 1 ]; then
    if sudo -n rm -f "$MAINT_ENV"; then echo "  removed $MAINT_ENV (absent before the run)"; else echo "  remove $MAINT_ENV FAILED"; RESTORE_OK=false; fi
  fi
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-drill copy: yes"
    else echo "  restored $k: sha256 matches pre-drill copy: NO"; RESTORE_OK=false; fi
  done
  if [ "$BRIDGE_SWAPPED" = 1 ]; then
    DOCKER="sudo -n docker" NTFY_ENV_FILE="$BRIDGE_ENV" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
    src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
    if [ "$src" = "$BRIDGE_ENV" ]; then echo "  restored bridge: mounts the operator env file again: yes"
    else echo "  restored bridge: mounts the operator env file again: NO"; RESTORE_OK=false; fi
  fi
  if [ "${#MOVED[@]}" -gt 0 ]; then
    # redirected ntfy env files are declared secrets: re-run the units on the restored files, require drift 0
    local dw=0 dn=0
    sudo -n systemctl start pft-keyescrow.service; R 'sudo -n systemctl start pft-keyescrow.service'
    sudo -n systemctl start pft-keyescrow-pull.service
    while :; do
      dn="$(pq 'pft_keyescrow_drift_items == 0' | grep -cE 'node=(validator|sentry)(,|$| )')"
      [ "$dn" = 2 ] && break
      dw=$((dw + 10)); [ "$dw" -le 180 ] || break; sleep 10
    done
    echo "  units re-run on the restored files: pft_keyescrow_drift_items 0 for $dn/2 nodes (${dw}s)"
    [ "$dn" = 2 ] || RESTORE_OK=false
  fi
  if [ -n "$SIL" ]; then
    # expiring the catch-all releases what it still holds: wait for those alerts to resolve first; PFTContainerRestarted
    # (looks back 15 min after a start) gets its own narrow silence that expires by itself
    held_n() { curl -s --max-time 10 "$AM/api/v2/alerts?active=true&silenced=true&inhibited=false" \
      | jq -r --arg id "$SIL" '[.[] | select(.status.silencedBy | index($id)) | select(.labels.alertname != "PFTContainerRestarted") | .labels.alertname] | unique | join(",")'; }
    w=0; n="$(held_n)"
    while [ -n "$n" ] && [ "$w" -lt "$CLEAR_WAIT" ]; do sleep 15; w=$((w + 15)); n="$(held_n)"; done
    if [ -n "$n" ]; then
      echo "  catch-all still holds active alerts after ${w}s: $n - kept until its end time (not expired)"; RESTORE_OK=false
    else
      echo "  catch-all holds no other active alert (${w}s)"
      local left=$(( LAST_START + 25 * 60 - $(date -u +%s) )) nb SIL2
      if [ "$LAST_START" -gt 0 ] && [ "$left" -gt 0 ]; then
        nb="$(jq -nc --arg s "$(ts)" --arg e "$(date -u -d "@$(( LAST_START + 25 * 60 ))" +%FT%TZ)" --arg c "$TASK restore drill post-run: PFTContainerRestarted only" \
          '{matchers: [{name: "alertname", value: "PFTContainerRestarted", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "keyescrow-restore", comment: $c}')"
        SIL2="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$nb" | jq -r '.silenceID // empty')"
        if [ -n "$SIL2" ]; then
          echo "  narrow silence alertname=PFTContainerRestarted until last node start + 25 min (${left}s); expires by itself"
          curl -s --max-time 10 -o /dev/null -w "  catch-all silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
        else echo "  narrow silence FAILED: catch-all kept until its end time"; RESTORE_OK=false; fi
      else curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"; fi
    fi
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-keyescrow restore drill (sentry node_seed, identity kept) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)"
  echo "sha256: restore-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        repo pft-keyescrow.sh $(sha256sum < "$REPO/keyescrow/pft-keyescrow.sh" | cut -c1-64) keyescrow_tar.py $(sha256sum < "$REPO/keyescrow/keyescrow_tar.py" | cut -c1-64)"
  echo "        installed validator $(sudo -n sha256sum "$BIN" | cut -c1-64) $(sudo -n sha256sum /usr/local/lib/pft-keyescrow/keyescrow_tar.py | cut -c1-64)"
  echo "        installed sentry    $(R "sudo -n sha256sum $BIN" | cut -c1-64) $(R 'sudo -n sha256sum /usr/local/lib/pft-keyescrow/keyescrow_tar.py' | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
x "R 'sudo -n pft-maint lock list'"
check "0 no data-collection lock on the sentry (restart-node would refuse)" "$(ok_if 'grep -qx "no data-collection locks" <<<"$XOUT"')"
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
sudo -n test -e "$MAINT_ENV" && { echo "  $MAINT_ENV exists (this runner expects it absent) - stopping" >&2; exit 3; }
[ -z "$(R "sudo -n find $ST -maxdepth 1 -name 'drill-*'")" ] || { echo "  leftover drill dir on the sentry - stopping" >&2; exit 3; }
echo "  pft-maint: no window on either host; notifier env files present, no leftovers, $MAINT_ENV absent"
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
# shellcheck disable=SC2016  # expands on the relay: the address it sees this host connect from
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
# shellcheck disable=SC2016  # expands on the relay
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"
[ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  k="$(info "$h" "$c" pubkey_node)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  [ "$h" = relay ] && P0="$k"
  st="$(info "$h" "$c" server_state)"; echo "  $c: server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
[ -n "${P0:-}" ] || { echo "  sentry pubkey_node unreadable - stopping" >&2; exit 3; }
for h in local relay; do k="$(on "$h" "sudo -n $BIN pubkey" 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"; done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
x "sudo -n $BIN verify --all | tail -1; R 'sudo -n $BIN verify --all' | tail -1"
check "0 verify --all exit 0 on both hosts" "$(ok_if '[ "$(grep -c "failed -> exit 0$" <<<"$XOUT")" = 2 ]')"
x "sudo -n pft-cluster audit | tail -1; R 'sudo -n pft-cluster audit' | tail -1"
check "0 pft-cluster audit PASS on both hosts" "$(ok_if '[ "$(grep -cx "RESULT: PASS" <<<"$XOUT")" = 2 ]')"
SEED0="$(seed_sha "$SEEDF")"; STAT0="$(seed_stat "$SEEDF")"
[[ "$SEED0" =~ ^[0-9a-f]{64}$ ]] || { echo "  sentry seed sha256 unreadable - stopping" >&2; exit 3; }
echo "  sentry $SEEDF: $STAT0, sha256 tag $(tag "$SEED0"); pubkey_node tag $(tag "$P0") (HMAC, per-run key)"
x "sudo -n $BIN restore --host sentry --item $ITEM --dry-run"
check "0 restore --dry-run of $ITEM from the validator's newest held generation: PASS, item unchanged" \
  "$(ok_if 'grep -q "item $ITEM unchanged" <<<"$XOUT" && grep -q "^RESULT: PASS - restore on sentry" <<<"$XOUT"')"
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }
if [ "${PREFLIGHT_ONLY:-0}" = 1 ]; then echo; echo "PREFLIGHT_ONLY=1: stopping after step 0, nothing changed ($FAILS check(s) failed)"; exit 0; fi

echo; echo "== 1. redirect notifiers + bridge + pft-maint env, silence everything except the watchdog, maintenance window"
redirect() { # HOST PATH
  local h="$1" f="$2"
  SHA["$h:$f"]="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
  [[ "${SHA[$h:$f]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $h:$f unreadable - stopping"; exit 3; }
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $h:$f sha256 ${SHA[$h:$f]:0:12} -> $NTFY/<redacted> (throwaway), original kept as $f$SUF"
}
for f in $LOCAL_ENVS; do redirect local "$f"; done
for f in $REMOTE_ENVS; do redirect relay "$f"; done
sudo -n sh -c "umask 077; printf 'NTFY_SERVER=%s\nNTFY_TOPIC=%s\n' $NTFY $ALERT > $MAINT_ENV" && MAINT_ENV_MADE=1
check "$MAINT_ENV created with the throwaway topic (0600)" "$(ok_if '[ "$MAINT_ENV_MADE" = 1 ] && [ "$(sudo -n stat -c %a "$MAINT_ENV")" = 600 ]')"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src" = "$SEC/bridge.env" ] || { echo "  bridge not pointed at the throwaway env - stopping"; exit 3; }
echo "  bridge -> $NTFY/<redacted> (throwaway env file in a 0700 temp dir)"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK keyescrow restore drill $RUN: planned sentry restart" --arg x "$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "keyescrow-restore", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"
x "sudo -n pft-maint start --ttl $TTL --reason '$TASK pft-keyescrow restore drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo "== 2. loss: move the sentry's pinned seed into a 0700 drill dir, then restore it from the validator's escrow"
x "R 'sudo -n sh -c \"umask 077; mkdir $BKD && mv $SEEDF $BKD/node_seed\" && sudo -n test ! -e $SEEDF && echo seed file gone'"
[ "$XRC" = 0 ] && SEED_MOVED=1
check "2a L1 seed file gone from $SEEDF (moved, not deleted)" "$XRC"
[ "$SEED_MOVED" = 1 ] || exit 4
x "R 'sudo -n pft-cluster audit' | grep -E '^ *\\[(FAIL|WARN)\\]|^RESULT'"
check "2b pft-cluster audit on the sentry now FAILs seed:stored" "$(ok_if 'grep -q "\[FAIL\] seed:stored" <<<"$XOUT" && ! grep -qx "RESULT: PASS" <<<"$XOUT"')"
x "sudo -n $BIN restore --host sentry --item $ITEM --dry-run"
check "2c restore --dry-run: the item would be written, nothing written" \
  "$(ok_if 'grep -q "item $ITEM would be" <<<"$XOUT" && grep -q "^RESULT: PASS - restore on sentry" <<<"$XOUT" && R "sudo -n test ! -e $SEEDF"')"
x "sudo -n $BIN restore --host sentry --item $ITEM --yes"
check "2d restore --yes: RESTORED on sentry, RESULT: PASS" "$(ok_if 'grep -q "RESTORED on sentry" <<<"$XOUT" && grep -q "^RESULT: PASS - restore on sentry" <<<"$XOUT"')"
S1="$(seed_sha "$SEEDF")"; STAT1="$(seed_stat "$SEEDF")"
echo "  restored $SEEDF: $STAT1, sha256 tag $(tag "$S1")"
x "R 'sudo -n cmp $BKD/node_seed $SEEDF && echo identical'"
check "2e restored seed byte-identical to the moved original (cmp), sha256 equal to the pre-drill seed" "$(ok_if '[ "$XRC" = 0 ] && [ "$S1" = "$SEED0" ]')"
check "2f restored seed mode/owner equal to the pre-drill file" "$(ok_if '[ "$STAT1" = "$STAT0" ] && [ "$STAT1" = "600 root:root" ]')" "$STAT1"
x "R 'sudo -n pft-cluster audit' | grep -E '^ *\\[(FAIL|WARN)\\] |seed:stored|cfg:node_seed|^RESULT'"
check "2g pft-cluster audit PASS on the sentry again (seed:stored, cfg:node_seed equal to the stored seed)" "$(ok_if 'grep -qx "RESULT: PASS" <<<"$XOUT"')"

echo; echo "== 3. restart postfiatd-sentry through pft-maint restart-node; identity must be unchanged"
started
x "R 'sudo -n env CONTAINER=postfiatd-sentry pft-maint restart-node'"
started
check "3a pft-maint restart-node PASS on the sentry" "$(ok_if '[ "$XRC" = 0 ] && grep -q "^restart-node PASS" <<<"$XOUT"')"
x "R 'sudo -n docker inspect -f \"{{.State.StartedAt}} running={{.State.Running}}\" postfiatd-sentry'"
P1="$(info relay postfiatd-sentry pubkey_node)"; ST1="$(info relay postfiatd-sentry server_state)"
echo "  postfiatd-sentry after restart: server_state=$ST1, pubkey_node tag $(tag "$P1") (before: $(tag "$P0"))"
check "3b pubkey_node after the restart == before the drill" "$(ok_if '[ -n "$P1" ] && [ "$P1" = "$P0" ]')"
w=0
while :; do
  XOUT="$(sudo -n pft-cluster audit 2>&1 | tail -1; R 'sudo -n pft-cluster audit' 2>&1 | tail -1)"
  [ "$(grep -cx "RESULT: PASS" <<<"$XOUT")" = 2 ] && break
  w=$((w + 15)); [ "$w" -le 300 ] || break; sleep 15
done
x "sudo -n pft-cluster audit | grep -E 'live:|^RESULT'; R 'sudo -n pft-cluster audit' | grep -E 'live:|^RESULT'"
check "3c pft-cluster audit PASS on both hosts after the restart (${w}s)" "$(ok_if '[ "$(grep -cx "RESULT: PASS" <<<"$XOUT")" = 2 ]')"

echo; echo "== 4. escrow units + verify after the restore"
x "R 'sudo -n $BIN inventory' | grep -E '$ITEM|^RESULT'"
check "4a sentry inventory: $ITEM ok after the restore" "$(ok_if 'grep -qE "^ *\\[ok\\] +$ITEM " <<<"$XOUT"')"
x "sudo -n $BIN verify --all | tail -1; R 'sudo -n $BIN verify --all' | tail -1"
check "4b verify --all exit 0 on both hosts" "$(ok_if '[ "$(grep -c "failed -> exit 0$" <<<"$XOUT")" = 2 ]')"

echo; echo "== 5. restore, read back"
restore
check "env files byte-identical, bridge on the operator env, pft-maint env removed, window ended, seed in place, drill dir gone" \
  "$(ok_if '[ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && ! sudo -n test -e "$MAINT_ENV" && [ -z "$(R "sudo -n find $ST -maxdepth 1 -name drill-\*")" ]')"
sleep "$READBACK_WAIT"
readback() { # TOPIC LABEL [quiet]
  local out
  if out="$(curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since")"; then
    N_MSG="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"
    echo "  $2 topic: $N_MSG message(s)"
    [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title, message}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
  else N_MSG=-1; echo "  $2 topic: could not be read from ntfy"; fi
}
readback "$ALERT" throwaway
i=0; OPN=0
while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N_MSG" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the drill" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
done
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  s="$(info "$h" "$c" server_state)"
  check "$c full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "restore-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
