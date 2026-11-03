#!/usr/bin/env bash
# live-run: the pft-upgradewatch alert drill. No network load and no change to either node: the alert inputs come from
# fixture sets that drill/make_drill_fixtures.py builds at drill start from the real validator answers in
# ../tests/fixtures, fed to the INSTALLED `pft-upgradewatch replay`, which writes drill-only textfiles
# (container="drill-*") into the validator's textfile dir.
# Built from ../../feewatch/drill/live-run.sh (redirect / bridge swap / silence / read-back framework, PASS run 06).
#   bash upgradewatch/drill/live-run.sh 2>&1 | tee LOG    (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): relay, Alertmanager, Prometheus reachable; no pft-maint window; notifier env files
#    present, no leftovers; the bridge mounts the operator env; no active silence covers the upgradewatch alerts; no
#    upgradewatch alert active; no drill textfile; upgradewatch timers active and pft_upgradewatch_up 1 for both nodes;
#    both nodes full; pft-integrity PASS on both; fixture sets built and dry-run; redaction positive control. Operator
#    topics, user name, host addresses and node keys go into a 0600 literals file for redact.py; never printed.
# 1  redirect: LOCAL_ENVS / REMOTE_ENVS get a throwaway topic (sha256 recorded, restored on ANY exit and compared), the
#    bridge is recreated with a throwaway NTFY_ENV_FILE; Alertmanager silence for every alert EXCEPT the five
#    upgradewatch alerts and the pipeline watchdog; sudo pft-maint start on the validator, wait until the sentry has it.
# 2  fire: a refresher (every REFRESH s) replays six drill series:
#      drill-blocked   blocked fixtures            -> PFTAmendmentBlocked (for 2m)
#      drill-majority  majority, ETA now+2 days    -> PFTUnsupportedAmendmentMajority (for 10m)
#      drill-soon      majority, ETA now+12 h      -> PFTUnsupportedAmendmentMajority + ...ActivationSoon (for 5m)
#      drill-lag       foundation 1.0.10           -> PFTNodeVersionLag (for 15m)
#      drill-failing   server_info not JSON (up 0) -> PFTUpgradewatchStale (for 10m)
#      drill-stale     healthy, timestamp 1000 s in the past (> 900) -> PFTUpgradewatchStale (for 10m)
#    Checks: exactly these seven (alert, container) pairs fire, none for the real nodes, [FIRING] delivered for each.
# 3  recover: every drill series replays the healthy fixtures with a fresh timestamp; each pair must leave Prometheus
#    and deliver [RESOLVED]. Then the refresher stops and the drill textfiles are removed. ALERTS query_range: first/last
#    firing sample per series.
# 4  restore env files + bridge (mount source read back), pft-maint end, expire the silence, read back the throwaway
#    topic and count messages on every operator topic since the start (topics never printed); no drill textfile left;
#    pft-integrity PASS on both hosts, both nodes full, upgradewatch timers active, real pft_upgradewatch_up 1. Exit 0 =
#    every CHECK ok.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  PROM (http://127.0.0.1:9090)  REFRESH (20, s)
#      LOCAL_ENVS  REMOTE_ENVS  BRIDGE_ENV  AGENT_ENV  TTL (60m)  SIL_TTL (60, min)  FIRE_WAIT (1380, s)
#      RESOLVE_WAIT (900, s)  NTFY_WAIT (180, s)  REDACT (../../peerexpose/drill/redact.py)
#      CLEAR_WAIT (300, s: drill-file alerts must clear before the silence expires)  READBACK_WAIT (150, s)
#      PREFLIGHT_ONLY (0; 1 = run step 0 only and exit, nothing changed)
# shellcheck disable=SC2016  # ok_if conditions are single-quoted on purpose: evaluated later
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
REDACT="${REDACT:-$REPO/peerexpose/drill/redact.py}"
RUNSTACK="$REPO/alerts/run-stack.sh"
MAKEFX="$HERE/make_drill_fixtures.py"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
REFRESH="${REFRESH:-20}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
TTL="${TTL:-60m}"; SIL_TTL="${SIL_TTL:-60}"
FIRE_WAIT="${FIRE_WAIT:-1380}"; RESOLVE_WAIT="${RESOLVE_WAIT:-900}"; NTFY_WAIT="${NTFY_WAIT:-180}"
CLEAR_WAIT="${CLEAR_WAIT:-300}"; READBACK_WAIT="${READBACK_WAIT:-150}"
UW_ALERTS='PFTAmendmentBlocked|PFTUnsupportedAmendmentMajority|PFTUnsupportedAmendmentActivationSoon|PFTNodeVersionLag|PFTUpgradewatchStale'
WATCHDOG_ALERT=PFTAlertPipelineWatchdog
TF=/var/lib/pft-exporter/textfile
SUF=.pre-upgradewatch-drill
BIN=/usr/local/bin/pft-upgradewatch
# drill series: NAME FIXTURE-SET AGE(s)   (fixture sets: make_drill_fixtures.py, built in step 0)
SERIES="drill-blocked blocked 0
drill-majority majority 0
drill-soon soon 0
drill-lag lag 0
drill-failing failing 0
drill-stale healthy 1000"
# expected (container, alert) pairs: drill-soon fires both majority alerts' conditions
PAIRS="drill-blocked PFTAmendmentBlocked
drill-majority PFTUnsupportedAmendmentMajority
drill-soon PFTUnsupportedAmendmentMajority
drill-soon PFTUnsupportedAmendmentActivationSoon
drill-lag PFTNodeVersionLag
drill-failing PFTUpgradewatchStale
drill-stale PFTUpgradewatchStale"
NPAIRS="$(grep -c . <<<"$PAIRS")"; NSERIES="$(grep -c . <<<"$SERIES")"
DRILL_NAMES="$(cut -d' ' -f1 <<<"$SERIES" | tr '\n' ' ')"

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="uwdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; FX="$SEC/fx"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
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
node_state() { # HOST CONTAINER
  on "$1" "sudo -n docker exec $2 curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
    | jq -r '.result.info.server_state // "down"' 2>/dev/null
}
topic_msgs() { curl -s --max-time 20 "$NTFY/$1/json?poll=1&since=$since" | jq -c 'select(.event == "message")' 2>/dev/null; }

# replay one drill series with the installed tool; AGE > 0 back-dates the collect timestamp
replay_one() { # NAME SET AGE
  sudo -n "$BIN" replay --container "$1" --fixtures "$FX/$2" --now "$(( $(date +%s) - $3 ))" >/dev/null 2>&1
}
# refresher: PHASE file says fire|recover; every REFRESH s every series is replayed (fire: its case, recover: healthy)
refresher() {
  local n f a
  while [ -e "$SEC/phase" ]; do
    while read -r n f a; do
      if [ "$(cat "$SEC/phase" 2>/dev/null)" = recover ]; then replay_one "$n" healthy 0
      else replay_one "$n" "$f" "$a"; fi
    done <<<"$SERIES"
    sleep "$REFRESH"
  done
}

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0; MAINT_STARTED=0; SIL=""; LOOP_PID=""
stop_refresher() { # let the loop see the missing phase file and finish its current replay, then delete the files
  local w=0
  rm -f "$SEC/phase"
  if [ -n "$LOOP_PID" ]; then
    while kill -0 "$LOOP_PID" 2>/dev/null && [ "$w" -lt $((REFRESH + 30)) ]; do sleep 1; w=$((w + 1)); done
    kill "$LOOP_PID" 2>/dev/null; wait "$LOOP_PID" 2>/dev/null; LOOP_PID=""
  fi
  sudo -n find "$TF" -maxdepth 1 -name 'pft_upgradewatch_drill-*.prom' -delete
}
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha src
  stop_refresher
  if [ -n "$(sudo -n find "$TF" -maxdepth 1 -name 'pft_upgradewatch_drill-*')" ]; then
    echo "  drill textfiles still present"; RESTORE_OK=false
  else echo "  drill textfiles removed: yes"; fi
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
    # pft-rulecheck grades every textfile, so drill-stale (back-dated collect timestamp) is also PFTTextfileStale
    # there, under the drill silence. Run 10 expired the silence before rulecheck's next run noticed the file was
    # gone, and one [FIRING] PFTTextfileStale reached the operator. Re-run rulecheck now and keep the silence until
    # no alert names a drill file, in Prometheus or in Alertmanager.
    local w=0 n=1
    sudo -n systemctl start pft-rulecheck.service || { echo "  pft-rulecheck re-run FAILED"; RESTORE_OK=false; }
    while [ "$w" -le "$CLEAR_WAIT" ]; do
      n="$(( $(pq 'ALERTS{file=~".*drill-.*"}' | grep -c .) + $(curl -s --max-time 10 "$AM/api/v2/alerts" | jq '[.[] | select((.labels.file // "") | test("drill-"))] | length') ))"
      [ "$n" = 0 ] && break
      sleep 10; w=$((w + 10))
    done
    echo "  alerts naming a drill textfile after the rulecheck re-run (Prometheus + Alertmanager): $n (${w}s)"
    [ "$n" = 0 ] || RESTORE_OK=false
    curl -s --max-time 10 -o /dev/null -w "  drill silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
  fi
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-upgradewatch alert drill (fixture replay, no network load) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)"
  echo "sha256: live-run.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        repo pft-upgradewatch.sh $(sha256sum < "$REPO/upgradewatch/pft-upgradewatch.sh" | cut -c1-64) upgradewatch_parse.py $(sha256sum < "$REPO/upgradewatch/upgradewatch_parse.py" | cut -c1-64)"
  echo "        installed validator $(sudo -n sha256sum "$BIN" | cut -c1-64) $(sudo -n sha256sum /usr/local/lib/pft-upgradewatch/upgradewatch_parse.py | cut -c1-64)"
  echo "        installed sentry    $(R "sudo -n sha256sum $BIN" | cut -c1-64) $(R 'sudo -n sha256sum /usr/local/lib/pft-upgradewatch/upgradewatch_parse.py' | cut -c1-64)"
  echo "        upgradewatch.rules.yml (repo, loaded by Prometheus) $(sha256sum < "$REPO/alerts/upgradewatch.rules.yml" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64) make_drill_fixtures.py $(sha256sum < "$MAKEFX" | cut -c1-64)"
  echo "        source fixtures: $(cd "$REPO/upgradewatch/tests/fixtures" && sha256sum ./* | sha256sum | cut -c1-64) (sha256 of 'sha256sum ./*' in tests/fixtures)"; }

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
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
nsil="$(curl -s --max-time 10 "$AM/api/v2/silences" | jq --arg r "$UW_ALERTS" '[.[] | select(.status.state == "active") | select(any(.matchers[]; .name == "alertname" and .isEqual != false and (.value as $v | if .isRegex then ("PFTUpgradewatchStale" | test("^(" + $v + ")$")) else ($v | test("^(" + $r + ")$")) end)))] | length')"
[ "$nsil" = 0 ] || { echo "  $nsil active silence(s) cover the upgradewatch alerts - stopping" >&2; exit 3; }
echo "  active silences covering the upgradewatch alerts: 0"
na="$(pq "ALERTS{alertname=~\"$UW_ALERTS\"}" | grep -c .)"
[ "$na" = 0 ] || { echo "  $na upgradewatch alert(s) already pending/firing - stopping" >&2; exit 3; }
echo "  upgradewatch alerts pending/firing: 0"
[ -z "$(sudo -n find "$TF" -maxdepth 1 -name 'pft_upgradewatch_drill-*')" ] || { echo "  leftover drill textfile - stopping" >&2; exit 3; }
echo "  drill textfiles present: 0"
if ! { systemctl is-active --quiet pft-upgradewatch@postfiatd.timer pft-upgradewatch-pull@postfiatd-sentry.timer && R "systemctl is-active --quiet pft-upgradewatch@postfiatd-sentry.timer"; }; then
  echo "  upgradewatch timers not active - stopping" >&2; exit 3
fi
echo "  pft-upgradewatch@ timers active on both hosts, pft-upgradewatch-pull@postfiatd-sentry.timer active on the validator"
up="$(pq 'pft_upgradewatch_up == 1' | grep -cE 'container=postfiatd(-sentry)?(,|$| )')"
[ "$up" = 2 ] || { echo "  pft_upgradewatch_up not 1 for both nodes - stopping" >&2; exit 3; }
echo "  pft_upgradewatch_up 1 for postfiatd and postfiatd-sentry"
FXNOW="$(date -u +%s)"
echo "\$ python3 -I upgradewatch/drill/make_drill_fixtures.py --out <tmp>/fx --now $FXNOW   ($(date -u -d "@$FXNOW" +%FT%TZ))"
python3 -I "$MAKEFX" --out "$FX" --now "$FXNOW" 2>&1 | sed 's/^/  /'
[ "${PIPESTATUS[0]}" = 0 ] || { echo "  fixture build failed - stopping" >&2; exit 3; }
echo "  fixture sets: $(cd "$FX" && find . -type f | sort | xargs sha256sum | sha256sum | cut -c1-64) (sha256 of the sorted per-file sha256 list)"
# dry run of every set with the installed tool into a scratch dir (no textfile in the live dir yet)
DRY="$SEC/dry"; mkdir -m 755 "$DRY"
for c in healthy blocked majority soon lag failing; do
  sudo -n "$BIN" replay --container "drill-$c" --fixtures "$FX/$c" --textfile-dir "$DRY" --now "$FXNOW" >/dev/null 2>&1
  echo "  dry run $c: rc $? up $(sudo -n sed -n 's/^pft_upgradewatch_up{container="drill-[a-z]*"} //p' "$DRY/pft_upgradewatch_drill-$c.prom")"
done
x "sudo -n cat $DRY/pft_upgradewatch_drill-{blocked,majority,soon,lag,failing,healthy}.prom | grep -E '^pft_upgradewatch_(up|amendment_blocked|unsupported_majority_warning|majority_amendments\\{[^}]*supported=\"no\"|unsupported_activation_eta_seconds|node_expected_date_seconds|behind_foundation|foundation_build_info)'"
check "0 dry run: blocked 1, majority/soon 1 unsupported with ETA now+172800 / now+43200, lag behind 1, failing up 0, healthy all 0" "$(ok_if '
  grep -qx "pft_upgradewatch_amendment_blocked{container=\"drill-blocked\"} 1" <<<"$XOUT" &&
  grep -qx "pft_upgradewatch_majority_amendments{container=\"drill-majority\",supported=\"no\"} 1" <<<"$XOUT" &&
  grep -qx "pft_upgradewatch_unsupported_activation_eta_seconds{container=\"drill-majority\"} $((FXNOW + 172800))" <<<"$XOUT" &&
  grep -qx "pft_upgradewatch_unsupported_activation_eta_seconds{container=\"drill-soon\"} $((FXNOW + 43200))" <<<"$XOUT" &&
  grep -qx "pft_upgradewatch_behind_foundation{container=\"drill-lag\"} 1" <<<"$XOUT" &&
  grep -qx "pft_upgradewatch_up{container=\"drill-failing\"} 0" <<<"$XOUT" &&
  [ "$(grep -c "drill-healthy.* 1$" <<<"$XOUT")" = 2 ]')"
sudo -n rm -rf "$DRY"
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
  k="$(on "$h" "sudo -n docker exec $c curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null)"
  [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  st="$(node_state "$h" "$c")"; echo "  $c: server_state=${st:-down}"
  case "$st" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "  literals for redaction: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }
[ "$FAILS" = 0 ] || { echo "  baseline not clean - stopping before any change"; exit 4; }
if [ "${PREFLIGHT_ONLY:-0}" = 1 ]; then echo; echo "PREFLIGHT_ONLY=1: stopping after step 0, nothing changed ($FAILS check(s) failed)"; exit 0; fi

echo; echo "== 1. redirect notifiers + bridge, silence everything except the upgradewatch alerts, maintenance window"
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
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "upgradewatch drill $RUN: unrelated alerts" --arg x "$UW_ALERTS|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "upgradewatch-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"$UW_ALERTS|$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"
x "sudo -n pft-maint start --ttl $TTL --reason 'pft-upgradewatch drill $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. fire: replay the $NSERIES drill series every ${REFRESH}s (installed $BIN replay, fixture sets only)"
echo fire > "$SEC/phase"
refresher & LOOP_PID=$!
t_fire="$(date -u +%s)"
sleep 5
x "for n in $DRILL_NAMES; do sudo -n grep -E '^pft_upgradewatch_(up|collect_timestamp_seconds|amendment_blocked|majority_amendments.*supported=\"no\"|unsupported_activation_eta_seconds|behind_foundation)' $TF/pft_upgradewatch_\$n.prom; done"
check "2a drill textfiles written: up 1 x5, up 0 for drill-failing" "$(ok_if '[ "$(grep -c "^pft_upgradewatch_up{container=\"drill-[a-z]*\"} 1$" <<<"$XOUT")" = 5 ] && grep -qx "pft_upgradewatch_up{container=\"drill-failing\"} 0" <<<"$XOUT"')"
check "2b inputs: blocked 1, unsupported majority 1 x2 (ETA now+2d, now+12h), behind foundation 1, stale timestamp 1000 s old" "$(ok_if '
  grep -qx "pft_upgradewatch_amendment_blocked{container=\"drill-blocked\"} 1" <<<"$XOUT" &&
  [ "$(grep -cE "^pft_upgradewatch_majority_amendments\{container=\"drill-(majority|soon)\",supported=\"no\"\} 1$" <<<"$XOUT")" = 2 ] &&
  grep -qx "pft_upgradewatch_unsupported_activation_eta_seconds{container=\"drill-majority\"} $((FXNOW + 172800))" <<<"$XOUT" &&
  grep -qx "pft_upgradewatch_unsupported_activation_eta_seconds{container=\"drill-soon\"} $((FXNOW + 43200))" <<<"$XOUT" &&
  grep -qx "pft_upgradewatch_behind_foundation{container=\"drill-lag\"} 1" <<<"$XOUT" &&
  st="$(sed -n "s/^pft_upgradewatch_collect_timestamp_seconds{container=\"drill-stale\"} //p" <<<"$XOUT")" &&
  [ $(( $(date +%s) - st )) -ge 1000 ] && [ $(( $(date +%s) - st )) -le $((1000 + REFRESH + 30)) ]')"
echo "  waiting for the $NPAIRS (alert, container) pairs to fire (VersionLag needs 15m; max ${FIRE_WAIT}s, poll 30s)"
# a summary names its container followed by a space or a colon ("drill-soon: ...", "for drill-stale is ...")
named() { grep -cE "(^|[^a-z-])$1([: ]|$)"; }
got=0
while [ $(( $(date -u +%s) - t_fire )) -lt "$FIRE_WAIT" ]; do
  F="$(pq "ALERTS{alertstate=\"firing\",alertname=~\"$UW_ALERTS\"}")"
  got=0
  while read -r n e; do grep -qE "alertname=$e,.*container=$n(,| )" <<<"$F" && got=$((got + 1)); done <<<"$PAIRS"
  [ "$got" -ge "$NPAIRS" ] && break
  sleep 30
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_fire ))s after the first replay):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "2c all $NPAIRS (alert, container) pairs firing" "$([ "$got" -ge "$NPAIRS" ] && echo 0 || echo 1)" "$got/$NPAIRS"
check "2d exactly $NPAIRS upgradewatch alerts firing (no other container or rule)" "$(ok_if '[ "$(grep -c . <<<"$F")" = "$NPAIRS" ]')"
check "2e no upgradewatch alert for the real nodes" "$(ok_if '! grep -qE "container=postfiatd(-sentry)?(,| )" <<<"$F"')"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"; dl=0
  while read -r n e; do
    [ "$(jq -r --arg t "[FIRING] $e" 'select(.title == $t) | .message' <<<"$M" | named "$n")" -ge 1 ] && dl=$((dl + 1))
  done <<<"$PAIRS"
  [ "$dl" -ge "$NPAIRS" ] && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "2f [FIRING] delivered to the throwaway topic for all $NPAIRS pairs" "$([ "$dl" -ge "$NPAIRS" ] && echo 0 || echo 1)" "$dl/$NPAIRS"

echo; echo "== 3. recover: every drill series replays the healthy fixture set with a fresh timestamp"
echo recover > "$SEC/phase"
t_rec="$(date -u +%s)"
# the refresher sleeps REFRESH s between rounds: wait one full round before reading the files back (feewatch run 05)
sleep $((REFRESH + 10))
x "for n in $DRILL_NAMES; do sudo -n grep -E '^pft_upgradewatch_(up|amendment_blocked|majority_amendments.*supported=\"no\"|unsupported_activation_eta_seconds|behind_foundation)' $TF/pft_upgradewatch_\$n.prom; done"
check "3a every drill series healthy: up 1 x$NSERIES, blocked 0, unsupported 0, ETA 0, behind 0" "$(ok_if '[ "$(grep -c "^pft_upgradewatch_up{container=\"drill-[a-z]*\"} 1$" <<<"$XOUT")" = "$NSERIES" ] && [ "$(grep -c "} 0$" <<<"$XOUT")" = $((NSERIES * 4)) ]')"
declare -A RES=()
while :; do
  F="$(pq "ALERTS{alertname=~\"$UW_ALERTS\"}")"
  M="$(topic_msgs "$ALERT")"
  done_n=0
  while read -r n e; do
    r="$(jq -r --arg t "[RESOLVED] $e" 'select(.title == $t) | .message' <<<"$M" | named "$n")"
    RES["$e/$n"]="$r"
    if ! grep -qE "alertname=$e,.*container=$n(,| )" <<<"$F" && [ "$r" -ge 1 ]; then done_n=$((done_n + 1)); fi
  done <<<"$PAIRS"
  [ "$done_n" -ge "$NPAIRS" ] && break
  [ $(( $(date -u +%s) - t_rec )) -lt "$RESOLVE_WAIT" ] || break
  sleep 20
done
echo "  $(ts): $done_n/$NPAIRS pairs resolved in Prometheus with [RESOLVED] delivered ($(( $(date -u +%s) - t_rec ))s after the healthy replay)"
for k in "${!RES[@]}"; do echo "    [RESOLVED] $k: ${RES[$k]}"; done | sort
check "3b every (alert, container) pair left Prometheus and delivered [RESOLVED]" "$([ "$done_n" -ge "$NPAIRS" ] && echo 0 || echo 1)" "$done_n/$NPAIRS"
stop_refresher
x "sudo -n find $TF -maxdepth 1 -name 'pft_upgradewatch_*.prom' -printf '%f\n' | sort"
check "3c refresher stopped, drill textfiles removed, the two real upgradewatch files remain" "$(ok_if '[ -z "$LOOP_PID" ] && ! grep -q drill- <<<"$XOUT" && [ "$(grep -c . <<<"$XOUT")" = 2 ]')"
x "curl -s -G $PROM/api/v1/query_range --data-urlencode 'query=ALERTS{alertname=~\"$UW_ALERTS\",alertstate=\"firing\"}' --data-urlencode start=$since --data-urlencode end=$(date -u +%s) --data-urlencode step=15 | jq -r '.data.result[] | \"\(.metric.alertname) container=\(.metric.container) first=\(.values[0][0] | todate) last=\(.values[-1][0] | todate) samples=\(.values | length)\"' | sort"
check "3d query_range shows exactly the $NPAIRS drill series firing during the drill" "$(ok_if '[ "$(grep -c "samples=" <<<"$XOUT")" = "$NPAIRS" ] && [ "$(grep -c "container=drill-" <<<"$XOUT")" = "$NPAIRS" ]')"

echo; echo "== 4. restore, read back"
restore
check "env files byte-identical, bridge on the operator env, window ended, no drill textfile" \
  "$([ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && echo 0 || echo 1)"
# Alertmanager may notify anything the silence held back one group_interval (1m) after it expires: wait longer
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
  s="$(node_state "$h" "$c")"
  check "$c full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
up="$(pq 'pft_upgradewatch_up == 1' | grep -cE 'container=postfiatd(-sentry)?(,|$| )')"
check "real pft_upgradewatch_up 1 for both nodes, timers active" "$(ok_if '[ "$up" = 2 ] && systemctl is-active --quiet pft-upgradewatch@postfiatd.timer pft-upgradewatch-pull@postfiatd-sentry.timer && R "systemctl is-active --quiet pft-upgradewatch@postfiatd-sentry.timer"')"
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
