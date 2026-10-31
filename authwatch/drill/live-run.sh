#!/usr/bin/env bash
# live-run: the pft-authwatch two-host alert drill (unknown-key login, failed-login burst, stopped collector).
# Built from ../../rulecheck/drill/live-run.sh (redirect / bridge swap / silence / read-back framework).
#   bash authwatch/drill/live-run.sh 2>&1 | tee LOG    (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): relay, Alertmanager, Prometheus reachable; no pft-maint window; notifier env files
#    present, no leftovers; the bridge mounts the operator env; no active silence covers the authwatch alerts; no
#    authwatch alert active; authwatch timers active and pft_authwatch_up 1 for both hosts; both nodes full;
#    pft-integrity PASS on both; redaction positive control. Operator topics, user name, host addresses, node keys
#    and the drill key's fingerprint go into a 0600 literals file for redact.py; fingerprints are never printed.
# 1  redirect: LOCAL_ENVS / REMOTE_ENVS get a throwaway topic (sha256 recorded, restored on ANY exit and compared),
#    the bridge is recreated with a throwaway NTFY_ENV_FILE; Alertmanager silence for every alert EXCEPT the three
#    authwatch alerts and the pipeline watchdog; sudo pft-maint start on the validator, wait until the sentry has it.
# 2  unknown key + burst, both hosts: a throwaway ed25519 key (0700 temp dir) is appended to one authorized_keys file
#    per host (validator: the agent account's, created if missing; sentry: root's, backed up with cp -p), one login
#    with it per host, then the file is restored (byte-identical, sha256 compared) or removed, the fingerprint is
#    shown to be gone from every authorized_keys file sshd reads, and a second login with the key must FAIL.
#    Burst: BURST sequential loopback connections per host as a user that does not exist, no auth method offered
#    (sshd logs "Invalid user", nothing can succeed). Checks: the textfile counters moved by exactly what was done,
#    PFTAuthUnknownKeyLogin + PFTAuthFailedBurst firing for host=validator and host=sentry, [FIRING] on the topic.
# 3  stale: stop pft-authwatch.timer on both hosts; PFTAuthwatchStale must fire for both hosts ([FIRING] delivered).
# 4  recover: start the timers, one collection + pull; every (alert, host) pair must leave Prometheus and deliver
#    [RESOLVED] (unknown-key needs 15 min after the login, burst 10 min) before anything is restored. ALERTS
#    query_range: first/last firing sample per series.
# 5  restore env files + bridge (mount source read back), pft-maint end, expire the silence, read back the throwaway
#    topic and count messages on every operator topic since the start (topics never printed); pft-integrity PASS on
#    both hosts, both nodes full, authwatch timers active. Exit 0 = every CHECK ok.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  PROM (http://127.0.0.1:9090)  BURST (500)
#      LOCAL_ENVS  REMOTE_ENVS  BRIDGE_ENV  AGENT_ENV  TTL (60m)  SIL_TTL (65, min)  FIRE_WAIT (420, s)
#      STALE_WAIT (720, s)  RESOLVE_WAIT (1500, s)  NTFY_WAIT (180, s)  REDACT (../../peerexpose/drill/redact.py)
# shellcheck disable=SC2016  # ok_if/fps_cmd/burst are single-quoted on purpose: evaluated later or on the other host
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REDACT="${REDACT:-$REPO/peerexpose/drill/redact.py}"
RUNSTACK="$REPO/alerts/run-stack.sh"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
BURST="${BURST:-500}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
TTL="${TTL:-60m}"; SIL_TTL="${SIL_TTL:-65}"
FIRE_WAIT="${FIRE_WAIT:-420}"; STALE_WAIT="${STALE_WAIT:-720}"; RESOLVE_WAIT="${RESOLVE_WAIT:-1500}"; NTFY_WAIT="${NTFY_WAIT:-180}"
AW_ALERTS='PFTAuthUnknownKeyLogin|PFTAuthFailedBurst|PFTAuthwatchStale'
WATCHDOG_ALERT=PFTAlertPipelineWatchdog
TF=/var/lib/pft-exporter/textfile
SUF=.pre-authwatch-drill
NOUSER=authwatch-drill-nouser

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="awdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#SHA256:[A-Za-z0-9+/]{43}#SHA256:<redacted-fp>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
FAILS=0
check() { # NAME 0|1 DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { # print the exact command, run it, print its output (redacted) and exit code; output kept in XOUT
  echo "\$ $*"
  XOUT="$(eval "$*" 2>&1)"; XRC=$?
  printf '%s\n' "$XOUT" | red | sed 's/^/  /'
  echo "  (exit $XRC)"
}
pq() { # QUERY -> "labels value" lines
  curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric | del(.__name__) | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'
}
node_state() { # HOST CONTAINER
  on "$1" "sudo -n docker exec $2 curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
    | jq -r '.result.info.server_state // "down"' 2>/dev/null
}
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }
metric() { # FILE-ON-VALIDATOR METRIC{LABELS} -> value
  sudo -n awk -v k="$2" 'index($0, k " ") == 1 { print $NF; f = 1 } END { if (!f) print "MISSING" }' "$TF/$1"
}
# counters for one host, read from the validator's textfile dir (the sentry's copy is the pulled one)
counts() { # HOST -> "unknown=N invalid=N"
  local f="pft_authwatch_$1.prom" h="host=\"$1\""
  echo "unknown=$(metric "$f" "pft_authwatch_ssh_accepted_total{$h,method=\"publickey\",key_class=\"unknown\"}") invalid=$(metric "$f" "pft_authwatch_ssh_failed_total{$h,reason=\"invalid_user\"}") ts=$(metric "$f" "pft_authwatch_collect_timestamp_seconds{$h}")"
}
# every authorized_keys file sshd reads on a host -> fingerprints (same rule as install.sh), never printed
fps_cmd='p="$(sudo -n sshd -T | awk '"'"'$1 == "authorizedkeysfile" { $1 = ""; print }'"'"')"; getent passwd | while IFS=: read -r u _ _ _ _ h _; do for q in $p; do f="${q//%h/$h}"; f="${f//%u/$u}"; case "$f" in /*) ;; *) f="$h/$f" ;; esac; sudo -n test -f "$f" && sudo -n ssh-keygen -lf "$f" -E sha256 2>/dev/null; done; done | awk '"'"'{ print $2 }'"'"''

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0; MAINT_STARTED=0; SIL=""
TIMERS_STOPPED=0; KEY_V=0; KEY_S=0; AKV=""; AKV_EXISTED=0
key_cleanup() {
  if [ "$KEY_V" = 1 ]; then
    if [ "$AKV_EXISTED" = 1 ]; then mv -f "$AKV$SUF" "$AKV"; else rm -f "$AKV"; fi
    KEY_V=0
  fi
  if [ "$KEY_S" = 1 ]; then R "sudo -n mv -f /root/.ssh/authorized_keys$SUF /root/.ssh/authorized_keys"; KEY_S=0; fi
}
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha src
  key_cleanup
  if [ "$TIMERS_STOPPED" = 1 ]; then
    sudo -n systemctl start pft-authwatch.timer; R "sudo -n systemctl start pft-authwatch.timer"
    if systemctl is-active --quiet pft-authwatch.timer && R "systemctl is-active --quiet pft-authwatch.timer"; then
      echo "  pft-authwatch.timer started on both hosts"
    else echo "  pft-authwatch.timer NOT active on both hosts"; RESTORE_OK=false; fi
  fi
  if [ "$MAINT_STARTED" = 1 ]; then
    echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'
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
  if [ -n "$SIL" ]; then
    curl -s --max-time 10 -o /dev/null -w "  drill silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-authwatch two-host alert drill - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)"
  echo "sha256: live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        repo pft-authwatch.sh $(sha256sum < "$REPO/authwatch/pft-authwatch.sh" | cut -c1-64) authwatch_parse.py $(sha256sum < "$REPO/authwatch/authwatch_parse.py" | cut -c1-64)"
  echo "        installed validator $(sudo -n sha256sum /usr/local/bin/pft-authwatch | cut -c1-64) $(sudo -n sha256sum /usr/local/lib/pft-authwatch/authwatch_parse.py | cut -c1-64)"
  echo "        installed sentry    $(R 'sudo -n sha256sum /usr/local/bin/pft-authwatch' | cut -c1-64) $(R 'sudo -n sha256sum /usr/local/lib/pft-authwatch/authwatch_parse.py' | cut -c1-64)"
  echo "        authwatch.rules.yml (repo, loaded by Prometheus) $(sha256sum < "$REPO/alerts/authwatch.rules.yml" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
echo "  pft-maint: no window open on either host"
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS /root/.ssh/authorized_keys; do
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }; done
AKV="$HOME/.ssh/authorized_keys"
[ ! -e "$AKV$SUF" ] || { echo "  leftover local authorized_keys backup - stopping" >&2; exit 3; }
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
nsil="$(curl -s --max-time 10 "$AM/api/v2/silences" | jq --arg r "$AW_ALERTS" '[.[] | select(.status.state == "active") | select(any(.matchers[]; .name == "alertname" and .isEqual != false and (.value as $v | if .isRegex then ("PFTAuthUnknownKeyLogin" | test("^(" + $v + ")$")) else ($v | test("^(" + $r + ")$")) end)))] | length')"
[ "$nsil" = 0 ] || { echo "  $nsil active silence(s) cover the authwatch alerts - stopping" >&2; exit 3; }
echo "  active silences covering the authwatch alerts: 0"
na="$(pq "ALERTS{alertname=~\"$AW_ALERTS\"}" | grep -c .)"
[ "$na" = 0 ] || { echo "  $na authwatch alert(s) already pending/firing - stopping" >&2; exit 3; }
echo "  authwatch alerts pending/firing: 0"
if ! { systemctl is-active --quiet pft-authwatch.timer pft-authwatch-pull.timer && R "systemctl is-active --quiet pft-authwatch.timer"; }; then
  echo "  authwatch timers not active - stopping" >&2; exit 3
fi
echo "  pft-authwatch.timer active on both hosts, pft-authwatch-pull.timer active on the validator"
up="$(pq 'pft_authwatch_up == 1' | grep -cE 'host=(validator|sentry)')"
[ "$up" = 2 ] || { echo "  pft_authwatch_up not 1 for both hosts - stopping" >&2; exit 3; }
echo "  pft_authwatch_up 1 for validator and sentry"
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
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; RPORT="$(ssh -G "$RELAY" | awk '$1 == "port" { print $2 }')"
RUSER="$(ssh -G "$RELAY" | awk '$1 == "user" { print $2 }')"
[ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  k="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null)"
  [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  st="$(node_state "$h" "$c")"; echo "  $c: server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
ssh-keygen -q -t ed25519 -N '' -C "authwatch-drill-$RUN" -f "$SEC/drillkey" || { echo "  ssh-keygen failed - stopping"; exit 3; }
DFP="$(ssh-keygen -lf "$SEC/drillkey.pub" -E sha256 | awk '{ print $2 }')"
printf 'key\t%s\n' "$DFP" >> "$LIT"
echo "  throwaway ed25519 key generated in the 0700 temp dir (fingerprint not printed)"
for h in local relay; do
  n="$(on "$h" "$fps_cmd" | grep -cxF "$DFP")"
  check "drill key not in any authorized_keys file on $h before the drill" "$([ "$n" = 0 ] && echo 0 || echo 1)" "$n"
done
n="$(sudo -n grep -cF "$DFP" /etc/pft-authwatch/allowlist; R "sudo -n grep -cF '$DFP' /etc/pft-authwatch/allowlist")"
check "drill key not in either allowlist" "$([ "$(tr -d '\n' <<<"$n")" = 00 ] && echo 0 || echo 1)"
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }

echo; echo "== 1. redirect notifiers + bridge, silence everything except the authwatch alerts, maintenance window"
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
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src" = "$SEC/bridge.env" ] || { echo "  bridge not pointed at the throwaway env - stopping"; exit 3; }
echo "  bridge -> $NTFY/<redacted> (throwaway env file in a 0700 temp dir)"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "authwatch drill $RUN: unrelated alerts" --arg x "$AW_ALERTS|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "authwatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"$AW_ALERTS|$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"
x "sudo -n pft-maint start --ttl $TTL --reason 'pft-authwatch drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. unknown-key login + failed-login burst on both hosts"
c0v="$(counts validator)"; c0s="$(counts sentry)"
echo "  before: validator $c0v | sentry $c0s"
SSHO=(-F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)
# validator: the agent account's authorized_keys (created if missing)
if [ -e "$AKV" ]; then AKV_EXISTED=1; cp -p "$AKV" "$AKV$SUF"; SHA[akv]="$(sha256sum < "$AKV" | cut -c1-64)"; fi
KEY_V=1
( umask 077; mkdir -p "$HOME/.ssh"; cat "$SEC/drillkey.pub" >> "$AKV" )
x "ssh ${SSHO[*]} -i \$SEC/drillkey -p 22 \$(id -un)@127.0.0.1 'echo drill-login-ok'"
check "2a validator: login with the throwaway key succeeded" "$(ok_if '[ "$XRC" = 0 ] && grep -q drill-login-ok <<<"$XOUT"')"
# sentry: root's authorized_keys (the relay alias logs in as root), backed up with cp -p
SHA[aks]="$(R 'sudo -n sha256sum /root/.ssh/authorized_keys' | cut -c1-64)"
R "sudo -n cp -p /root/.ssh/authorized_keys /root/.ssh/authorized_keys$SUF" && KEY_S=1
R "sudo -n tee -a /root/.ssh/authorized_keys >/dev/null" < "$SEC/drillkey.pub"
x "ssh ${SSHO[*]} -i \$SEC/drillkey -p $RPORT $RUSER@\$RHOST 'echo drill-login-ok'"
check "2b sentry: login with the throwaway key succeeded" "$(ok_if '[ "$XRC" = 0 ] && grep -q drill-login-ok <<<"$XOUT"')"
t_login="$(date -u +%s)"
echo "  removing the throwaway key from both hosts"
key_cleanup
if [ "$AKV_EXISTED" = 1 ]; then
  check "2c validator authorized_keys restored byte-identical" "$(ok_if '[ "$(sha256sum < "$AKV" | cut -c1-64)" = "${SHA[akv]}" ]')"
else
  check "2c validator authorized_keys (created for the drill) removed" "$(ok_if '[ ! -e "$AKV" ]')"
fi
check "2d sentry /root/.ssh/authorized_keys restored byte-identical" "$(ok_if '[ "$(R "sudo -n sha256sum /root/.ssh/authorized_keys" | cut -c1-64)" = "${SHA[aks]}" ]')"
for h in local relay; do
  n="$(on "$h" "$fps_cmd" | grep -cxF "$DFP")"
  check "2e drill key fingerprint in no authorized_keys file on $h" "$([ "$n" = 0 ] && echo 0 || echo 1)" "$n"
done
x "ssh ${SSHO[*]} -i \$SEC/drillkey -p 22 \$(id -un)@127.0.0.1 true"
check "2f validator: the throwaway key is refused now" "$([ "$XRC" = 255 ] && echo 0 || echo 1)"
x "ssh ${SSHO[*]} -i \$SEC/drillkey -p $RPORT $RUSER@\$RHOST true"
check "2g sentry: the throwaway key is refused now" "$([ "$XRC" = 255 ] && echo 0 || echo 1)"
burst='n=0; ok=0; for i in $(seq '"$BURST"'); do ssh -F /dev/null -o BatchMode=yes -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=QUIET -o ConnectTimeout=5 '"$NOUSER"'@127.0.0.1 true </dev/null && ok=$((ok + 1)); n=$((n + 1)); done; echo "attempts=$n succeeded=$ok"'
echo "  burst script (run as-is on each host, via stdin): $burst"
x "bash -s <<<\"\$burst\""
check "2h validator burst: $BURST attempts, 0 succeeded" "$(ok_if 'grep -qx "attempts=$BURST succeeded=0" <<<"$XOUT"')"
x "R 'bash -s' <<<\"\$burst\""
check "2i sentry burst: $BURST attempts, 0 succeeded" "$(ok_if 'grep -qx "attempts=$BURST succeeded=0" <<<"$XOUT"')"
x "sudo -n journalctl -t sshd --since @$t_login --no-pager -o cat | grep -c 'Invalid user $NOUSER from 127.0.0.1 port'"
# a connection dropped by sshd's MaxStartups (internet scanners run concurrently) logs no "Invalid user" line; the
# burst only has to clear the 400 threshold, and the counter check below uses the journal count, not BURST
NJV="$(tail -1 <<<"$XOUT")"
check "2j validator journal: 'Invalid user $NOUSER' lines > 400 (of $BURST)" "$(ok_if '[ "$NJV" -gt 400 ]')" "$NJV"
x "R \"sudo -n journalctl -t sshd --since @$t_login --no-pager -o cat | grep -c 'Invalid user $NOUSER from 127.0.0.1 port'\""
NJS="$(tail -1 <<<"$XOUT")"
check "2k sentry journal: 'Invalid user $NOUSER' lines > 400 (of $BURST)" "$(ok_if '[ "$NJS" -gt 400 ]')" "$NJS"
x "sudo -n journalctl -t sshd --since @$((t_login - 120)) --no-pager -o cat | grep -E '^Accepted publickey for .* from 127\.0\.0\.1 ' | grep -c '$DFP'"
check "2l validator journal: 1 accepted login with the drill key" "$(ok_if '[ "$(tail -1 <<<"$XOUT")" = 1 ]')"
x "R \"sudo -n journalctl -t sshd --since @$((t_login - 120)) --no-pager -o cat | grep -E '^Accepted publickey for ' | grep -c '$DFP'\""
check "2m sentry journal: 1 accepted login with the drill key" "$(ok_if '[ "$(tail -1 <<<"$XOUT")" = 1 ]')"
echo "  waiting for the next collection on both hosts + the pull (max 150 s)"
t_b="$(date -u +%s)"
while [ $(( $(date -u +%s) - t_b )) -lt 150 ]; do
  c1v="$(counts validator)"; c1s="$(counts sentry)"
  tv="${c1v##*ts=}"; tsn="${c1s##*ts=}"
  if [[ "$tv" =~ ^[0-9]+$ ]] && [[ "$tsn" =~ ^[0-9]+$ ]] && [ "$tv" -gt "$t_b" ] && [ "$tsn" -gt "$t_b" ]; then break; fi
  sleep 10
done
echo "  after:  validator $c1v | sentry $c1s"
d() { # BEFORE AFTER KEY -> after - before
  local a b; a="$(sed -nE "s/.*$3=([0-9]+).*/\1/p" <<<"$1")"; b="$(sed -nE "s/.*$3=([0-9]+).*/\1/p" <<<"$2")"; echo $(( b - a ))
}
check "2n validator counters: unknown +1, invalid_user >= +$NJV (journal count)" "$(ok_if '[ "$(d "$c0v" "$c1v" unknown)" = 1 ] && [ "$(d "$c0v" "$c1v" invalid)" -ge "$NJV" ]')" "unknown +$(d "$c0v" "$c1v" unknown), invalid_user +$(d "$c0v" "$c1v" invalid)"
check "2o sentry counters (pulled copy): unknown +1, invalid_user >= +$NJS (journal count)" "$(ok_if '[ "$(d "$c0s" "$c1s" unknown)" = 1 ] && [ "$(d "$c0s" "$c1s" invalid)" -ge "$NJS" ]')" "unknown +$(d "$c0s" "$c1s" unknown), invalid_user +$(d "$c0s" "$c1s" invalid)"
x "sudo -n grep -E '^pft_authwatch_(ssh_accepted_total|last_unknown_login).*' $TF/pft_authwatch_validator.prom $TF/pft_authwatch_sentry.prom | grep -vE '} 0$' | sed 's#^$TF/##'"
echo "  waiting for PFTAuthUnknownKeyLogin + PFTAuthFailedBurst firing for both hosts (max ${FIRE_WAIT}s, poll 15s)"
want=4; got=0; t_f="$(date -u +%s)"
while [ $(( $(date -u +%s) - t_f )) -lt "$FIRE_WAIT" ]; do
  F="$(pq 'ALERTS{alertstate="firing",alertname=~"PFTAuthUnknownKeyLogin|PFTAuthFailedBurst"}')"
  got=0
  for a in PFTAuthUnknownKeyLogin PFTAuthFailedBurst; do for h in validator sentry; do
    grep -qE "alertname=$a,.*host=$h(,|$| )" <<<"$F" && got=$((got + 1))
  done; done
  [ "$got" -ge "$want" ] && break
  sleep 15
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_login ))s after the logins):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "2p PFTAuthUnknownKeyLogin + PFTAuthFailedBurst firing for validator and sentry" "$([ "$got" -ge "$want" ] && echo 0 || echo 1)" "$got/$want"
echo "  waiting for [FIRING] delivery on the throwaway topic (max ${NTFY_WAIT}s)"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"
  nu="$(jq -r 'select(.title == "[FIRING] PFTAuthUnknownKeyLogin") | .message' <<<"$M" | grep -cE '^(validator|sentry): ')"
  nb="$(jq -r 'select(.title == "[FIRING] PFTAuthFailedBurst") | .message' <<<"$M" | grep -cE '^(validator|sentry): ')"
  uv="$(jq -r 'select(.title == "[FIRING] PFTAuthUnknownKeyLogin") | .message' <<<"$M" | grep -c '^validator: ')"
  us="$(jq -r 'select(.title == "[FIRING] PFTAuthUnknownKeyLogin") | .message' <<<"$M" | grep -c '^sentry: ')"
  bv="$(jq -r 'select(.title == "[FIRING] PFTAuthFailedBurst") | .message' <<<"$M" | grep -c '^validator: ')"
  bs="$(jq -r 'select(.title == "[FIRING] PFTAuthFailedBurst") | .message' <<<"$M" | grep -c '^sentry: ')"
  { [ "$uv" -ge 1 ] && [ "$us" -ge 1 ] && [ "$bv" -ge 1 ] && [ "$bs" -ge 1 ]; } && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "2q [FIRING] PFTAuthUnknownKeyLogin delivered for validator and sentry" "$(ok_if '[ "$uv" -ge 1 ] && [ "$us" -ge 1 ]')" "validator $uv, sentry $us (all: $nu)"
check "2r [FIRING] PFTAuthFailedBurst delivered for validator and sentry" "$(ok_if '[ "$bv" -ge 1 ] && [ "$bs" -ge 1 ]')" "validator $bv, sentry $bs (all: $nb)"

echo; echo "== 3. stopped collector on both hosts"
t_stop="$(date -u +%s)"
x "sudo -n systemctl stop pft-authwatch.timer && systemctl is-active pft-authwatch.timer; R 'sudo -n systemctl stop pft-authwatch.timer && systemctl is-active pft-authwatch.timer'"
TIMERS_STOPPED=1
check "3a pft-authwatch.timer inactive on both hosts (validator pull keeps running)" "$(ok_if '[ "$(grep -c "^inactive$" <<<"$XOUT")" = 2 ] && systemctl is-active --quiet pft-authwatch-pull.timer')"
echo "  waiting for PFTAuthwatchStale firing for both hosts (> 300 s old + for 2m; max ${STALE_WAIT}s, poll 20s)"
got=0
while [ $(( $(date -u +%s) - t_stop )) -lt "$STALE_WAIT" ]; do
  F="$(pq 'ALERTS{alertstate="firing",alertname="PFTAuthwatchStale"}')"
  got=$(( $(grep -c 'host=validator' <<<"$F") + $(grep -c 'host=sentry' <<<"$F") ))
  [ "$got" -ge 2 ] && break
  sleep 20
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_stop ))s after the stop):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "3b PFTAuthwatchStale firing for validator and sentry" "$([ "$got" -ge 2 ] && echo 0 || echo 1)" "$got/2"
x "for h in validator sentry; do echo \"\$h collect age \$(( \$(date +%s) - \$(sudo -n awk '/^pft_authwatch_collect_timestamp_seconds/ { print \$NF }' $TF/pft_authwatch_\$h.prom) ))s\"; done"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"
  sv="$(jq -r 'select(.title == "[FIRING] PFTAuthwatchStale") | .message' <<<"$M" | grep -c 'for validator are stale')"
  ss="$(jq -r 'select(.title == "[FIRING] PFTAuthwatchStale") | .message' <<<"$M" | grep -c 'for sentry are stale')"
  { [ "$sv" -ge 1 ] && [ "$ss" -ge 1 ]; } && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "3c [FIRING] PFTAuthwatchStale delivered for validator and sentry" "$(ok_if '[ "$sv" -ge 1 ] && [ "$ss" -ge 1 ]')" "validator $sv, sentry $ss"

echo; echo "== 4. recover: timers on, wait for every (alert, host) pair to resolve and deliver [RESOLVED]"
t_rec="$(date -u +%s)"
x "sudo -n systemctl start pft-authwatch.timer pft-authwatch.service && systemctl is-active pft-authwatch.timer; R 'sudo -n systemctl start pft-authwatch.timer pft-authwatch.service && systemctl is-active pft-authwatch.timer'; sudo -n systemctl start pft-authwatch-pull.service; echo pulled"
TIMERS_STOPPED=0
check "4a pft-authwatch.timer active on both hosts" "$(ok_if '[ "$(grep -c "^active$" <<<"$XOUT")" = 2 ]')"
echo "  unknown-key resolves ~15 min after the login ($(date -u -d "@$t_login" +%FT%TZ)), burst ~10 min after the burst (max ${RESOLVE_WAIT}s, poll 30s)"
declare -A RES=()
while :; do
  F="$(pq "ALERTS{alertname=~\"$AW_ALERTS\"}")"
  M="$(topic_msgs "$ALERT")"
  done_n=0
  for a in PFTAuthUnknownKeyLogin PFTAuthFailedBurst PFTAuthwatchStale; do
    for h in validator sentry; do
      case "$a" in
        PFTAuthwatchStale) pat="for $h are stale" ;;
        *) pat="^$h: " ;;
      esac
      r="$(jq -r --arg t "[RESOLVED] $a" 'select(.title == $t) | .message' <<<"$M" | grep -cE "$pat")"
      RES["$a/$h"]="$r"
      if ! grep -qE "alertname=$a,.*host=$h(,|$| )" <<<"$F" && [ "$r" -ge 1 ]; then done_n=$((done_n + 1)); fi
    done
  done
  [ "$done_n" -ge 6 ] && break
  [ $(( $(date -u +%s) - t_rec )) -lt "$RESOLVE_WAIT" ] || break
  sleep 30
done
echo "  $(ts): $done_n/6 pairs resolved in Prometheus with [RESOLVED] delivered ($(( $(date -u +%s) - t_login ))s after the logins)"
for k in "${!RES[@]}"; do echo "    [RESOLVED] $k: ${RES[$k]}"; done | sort
check "4b every (alert, host) pair left Prometheus and delivered [RESOLVED]" "$([ "$done_n" -ge 6 ] && echo 0 || echo 1)" "$done_n/6"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"$AW_ALERTS\",alertstate=\"firing\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) host=\(.metric.host) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "4c query_range shows all 6 (alert, host) series firing during the drill" "$(ok_if '[ "$(grep -c "samples=" <<<"$XOUT")" = 6 ]')"

echo; echo "== 5. restore, read back"
restore
check "authwatch timers active, env files byte-identical, bridge on the operator env, window ended, drill key gone" \
  "$([ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && [ "$KEY_V$KEY_S" = 00 ] && echo 0 || echo 1)"
sleep 20
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
  s="$(node_state "$h" "$c")"
  check "$c full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
