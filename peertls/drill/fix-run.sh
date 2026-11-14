#!/usr/bin/env bash
# shellcheck disable=SC2016,SC1091,SC2015  # remote commands are single-quoted on purpose (expand on the relay)
# fix-run: recorded two-host remediation of the pft-peertls findings cipher.kx_rsa / cipher.cbc_sha2 (task_2b0012da).
# Built from ../../patch/drill/live-run.sh (glibc roll 2026-11-14, PASS, operator topics 0). Every ntfy notifier on
# both hosts points at throwaway topics for the whole run, an outer Alertmanager silence (never the pipeline
# watchdog) covers the two planned node restarts, and all output is redacted on the way out.
#   bash peertls/drill/fix-run.sh 2>&1 | tee LOG        (from the repo root, as the agent user; sudo -n + `ssh relay`)
#   PREFLIGHT_ONLY=1 bash peertls/drill/fix-run.sh      (step 0 only; changes nothing)
# 0  preflight (nothing changed): clean tree, relay, Alertmanager, no pft-maint window/lock, notifier envs present and
#    no leftovers, both nodes full, Prometheus + AM show only the watchdog, fix script + audit copied to a relay scratch
#    dir (sha256 = this checkout), redaction positive control, FOUND: `plan` (not applied) and a pre-fix audit per host.
# 1  redirect notifiers (sha256 recorded, restored by trap on ANY exit) + outer silence (OUTER_TTL min).
# 2  pft-maint window (validator start pushes it to the sentry; wait until the sentry sees it).
# 3  sentry, then validator: sudo pft-peertls-fix apply --yes, exit 0 required (its own gate: restarted, full, same
#    pubkey_node, peers, listening, weak suites refused / good accepted; integrity accept of the cfg only). A failed
#    host stops the run before the next host.
# 4  VERIFIED: per host `plan` says already applied, audit exit 0 (PASS), pft-integrity verify PASS, nodes full,
#    sentry DOCKER-USER -> PFT-EGRESS jump once.
# 5  pft-maint end, restore notifiers (sha256 compare), re-run collectors that sampled redirected files (keyescrow
#    both hosts + validator pull).
# 6  drain: wait until newest container start + RESTART_TAIL min AND nothing but the watchdog pending/firing in
#    Prometheus; expire the outer silence; wait group_interval + 30 s; read back throwaway + operator topics.
# Env: OUTER_TTL (75)  RESTART_TAIL (16)  DRAIN_MAX (45, min)  NTFY (https://ntfy.sh)  KNOWN_PENDING ("")
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090; NTFY="${NTFY:-https://ntfy.sh}"
OUTER_TTL="${OUTER_TTL:-75}"; RESTART_TAIL="${RESTART_TAIL:-16}"; DRAIN_MAX="${DRAIN_MAX:-45}"
KNOWN_PENDING="${KNOWN_PENDING:-}"; WD=PFTAlertPipelineWatchdog
LOCAL_ENVS="/etc/postfiat-monitor.env /etc/pft-integrity.env"
REMOTE_ENVS="/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env"
BRIDGE_ENV="$HOME/.config/pft-alerts/ntfy.env"; AGENT_ENV=/opt/pft-agent/config.env
SUF=.pre-peertls-fix
FIX=peertls/pft-peertls-fix.sh; AUD=peertls/pft-peertls.sh; EVAL=peertls/peertls_eval.py
REDACT=peerexpose/drill/redact.py
rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="ptlsfix-$(rnd)"; MTOP="ptlsmaint-$(rnd)"
since="$(date -u +%s)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d -p "$HOME/.cache")"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; OPS="$SEC/ops"; : > "$OPS"
printf 'topic\t%s\ntopic\t%s\nuser\t%s\n' "$ALERT" "$MTOP" "$(id -un)" >> "$LIT"
red() { sed -u "s#$REPO#.#g; s#$HOME#~#g" | python3 -u "$REDACT" filter --literals "$LIT"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes relay "$@" </dev/null; }
Rin() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes relay "$@"; }   # stdin passed through
on() { if [ "$1" = sentry ]; then R "$2"; else bash -c "$2" </dev/null; fi; }
cof() { if [ "$1" = sentry ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
RS='$HOME/.cache/ptls-fixrun'   # relay scratch (expands on the relay)
fixcmd() { if [ "$1" = sentry ]; then echo "sudo -n bash $RS/pft-peertls-fix.sh"; else echo "sudo -n bash $REPO/$FIX"; fi; }
audcmd() { # HOST -> audit command (scratch root-owned conf, repo policy, no state, no textfile)
  if [ "$1" = sentry ]; then echo "sudo -n env PFT_PTLS_CONF=$RS/conf/env PFT_PTLS_EVAL=$RS/peertls_eval.py bash $RS/pft-peertls.sh audit --no-state"
  else echo "sudo -n env PFT_PTLS_CONF=$SEC/conf/env PFT_PTLS_EVAL=$REPO/$EVAL bash $REPO/$AUD audit --no-state"; fi
}
XRC=0
x() { # HOST CMD: echo + run + redact, rc in XRC
  echo "\$ [$1] $2" | red
  on "$1" "$2" > "$SEC/x.out" 2>&1; XRC=$?
  red < "$SEC/x.out" | sed 's/^/  /'; echo "  (exit $XRC)"
}
state() { local s; s="$(on "$1" "sudo -n docker exec $(cof "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" \
  | jq -r '.result.info.server_state // empty' 2>/dev/null)"; echo "${s:-down}"; }
started() { on "$1" "sudo -n docker inspect -f '{{.State.StartedAt}}' $(cof "$1")"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "STOP: $FAILS check(s) failed before '$1' ($(ts))"; exit 1; }; }
alerts_other() { # Prometheus pending+firing except the watchdog and KNOWN_PENDING pending ones -> "name host state" lines;
  # a failed query prints "query-error" (fail closed: never read as "nothing active")
  local j; j="$(curl -s -m 10 "$PROM/api/v1/alerts")"
  [ -n "$j" ] && jq -e '.data.alerts | type == "array"' <<<"$j" >/dev/null 2>&1 || { echo query-error; return; }
  jq -r --arg w "$WD" --arg k " $KNOWN_PENDING " '.data.alerts[] | .labels.alertname as $n | select($n != $w)
     | select(.state == "firing" or (($k | contains(" " + $n + " ")) | not)) | "\($n) \(.labels.host // "-") \(.state)"' <<<"$j"
}
am_other() {
  local j; j="$(curl -s -m 10 "$AM/api/v2/alerts")"
  [ -n "$j" ] && jq -e 'type == "array"' <<<"$j" >/dev/null 2>&1 || { echo query-error; return; }
  jq -r --arg w "$WD" '.[] | select(.labels.alertname != $w) | "\(.labels.alertname) \(.status.state)"' <<<"$j"
}

declare -A SHAS=(); declare -a MOVED=() CREATED=()
RESTORED=0; RESTORE_OK=true; SIL=""; MAINTW=0
restore() {
  [ "$RESTORED" = 1 ] && return 0; RESTORED=1
  local k h f now
  if [ "$MAINTW" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end --reason "task_2b00 peertls fix-run" 2>&1 | red | sed 's/^/  /'; MAINTW=0; fi
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [ "$now" = "${SHAS[$k]}" ]; then echo "  restored $k: sha256 matches pre-run copy: yes"
    else echo "  restored $k: sha256 matches pre-run copy: NO"; RESTORE_OK=false; fi
  done
  for k in "${CREATED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"; on "$h" "sudo -n rm -f $f"
    if on "$h" "sudo -n test -e $f"; then echo "  removed run-only $k: NO"; RESTORE_OK=false; else echo "  removed run-only $k: yes"; fi
  done
}
cleanup() { restore; sudo -n rm -rf "$SEC"; R "sudo -n rm -rf $RS" || true; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

echo "pft-peertls fix-run - $(ts) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
echo "sha256: pft-peertls-fix.sh $(sha256sum < $FIX | cut -c1-64) | pft-peertls.sh $(sha256sum < $AUD | cut -c1-64)"
echo "        peertls_eval.py $(sha256sum < $EVAL | cut -c1-64) | fix-run.sh $(sha256sum < "$0" | cut -c1-64)"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping"; exit 3; }
curl -s -m 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping"; exit 3; }
locks="$(sudo -n pft-maint lock list 2>&1)"
[ "$locks" = "no data-collection locks" ] || { echo "  pft-maint lock held: $locks - stopping"; exit 4; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is already open - stopping"; exit 4; }
echo "  pft-maint: $locks, no window open"
for f in $LOCAL_ENVS; do sudo -n test -f "$f" && ! sudo -n test -e "$f$SUF" || { echo "  local $f missing or leftover $SUF - stopping"; exit 3; }; done
for f in $REMOTE_ENVS; do R "sudo -n test -f $f && ! sudo -n test -e $f$SUF" || { echo "  relay $f missing or leftover $SUF - stopping"; exit 3; }; done
! sudo -n test -e /etc/pft-maint/ntfy.env || { echo "  local /etc/pft-maint/ntfy.env exists - stopping"; exit 3; }
! R "sudo -n test -e /etc/pft-maint/ntfy.env" || { echo "  relay /etc/pft-maint/ntfy.env exists - stopping"; exit 3; }
{ for f in $LOCAL_ENVS; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null; sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping"; exit 3; }
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
for hn in sentry validator; do
  si="$(on "$hn" "sudo -n docker exec $(cof "$hn") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005")"
  k="$(jq -r '.result.info.pubkey_node // empty' <<<"$si" 2>/dev/null)"; [ -z "$k" ] || printf 'key\t%s\n' "$k" >> "$LIT"
  st="$(jq -r '.result.info.server_state // "down"' <<<"$si" 2>/dev/null)"; echo "  $hn ($(cof "$hn")): server_state=$st"
  [ "$st" = full ] || { echo "  node not full - stopping"; exit 4; }
done
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; [ "${PIPESTATUS[0]}" = 0 ] || { echo "  redaction control FAILED - stopping"; exit 3; }
o="$(alerts_other)"; a="$(am_other)"
echo "  Prometheus besides the watchdog: ${o:-none} | Alertmanager besides the watchdog: ${a:-none}"
[ -z "$o" ] && [ -z "$a" ] || { echo "  alerts active before the run - stopping"; exit 4; }
[ "$(curl -s -m 10 "$AM/api/v2/silences" | jq '[.[] | select(.status.state == "active")] | length')" = 0 ] || { echo "  active silence before the run - stopping"; exit 4; }
# scratch audit confs (root-owned 0600, targets loopback only), relay copies of the tools
mkconf() { # DIR ROLE CONTAINER POLICYDIR (on the given host via sudo)
  printf 'ROLE=%s\nPOLICY_DIR=%s\nTARGETS=%s/conf/targets\nWAIVERS=%s/conf/waivers\nSTATE_DIR=%s/conf/state\nTEXTFILE_DIR=%s/conf/tf\n' \
    "$2" "$4" "$1" "$1" "$1" "$1"
}
sudo -n install -d -o root -g root -m 700 "$SEC/conf"
mkconf "$SEC" validator postfiatd "$REPO/peertls/policy" | sudo -n tee "$SEC/conf/env" >/dev/null
echo "validator 127.0.0.1 2559 local postfiatd" | sudo -n tee "$SEC/conf/targets" >/dev/null
sudo -n touch "$SEC/conf/waivers"; sudo -n chmod 600 "$SEC/conf/env" "$SEC/conf/targets" "$SEC/conf/waivers"
R "rm -rf $RS; mkdir -p $RS/policy && chmod 755 $RS" || { echo "  relay scratch failed - stopping"; exit 3; }
for f in "$FIX" "$AUD" "$EVAL" peertls/policy/sentry.policy; do
  d="$RS/$(basename "$f")"; [[ "$f" == */policy/* ]] && d="$RS/policy/$(basename "$f")"
  Rin "cat > $d" < "$f"; w="$(sha256sum < "$f" | cut -c1-64)"; g="$(R "sha256sum < $d" | cut -c1-64)"
  [ "$w" = "$g" ] || { echo "  relay copy of $f differs - stopping"; exit 3; }
done
mkconf "$RS" sentry postfiatd-sentry "$RS/policy" | Rin "sudo -n install -d -o root -g root -m 700 $RS/conf && sudo -n tee $RS/conf/env >/dev/null"
echo "sentry 127.0.0.1 2559 local postfiatd-sentry" | Rin "sudo -n tee $RS/conf/targets >/dev/null"
R "sudo -n touch $RS/conf/waivers && sudo -n chmod 600 $RS/conf/env $RS/conf/targets $RS/conf/waivers"
echo "  relay scratch: fix, audit, eval, sentry.policy copied (sha256 = checkout); scratch audit confs (loopback targets only, no waivers)"
for hn in sentry validator; do
  echo; echo "-- FOUND $hn"
  x "$hn" "$(fixcmd "$hn") plan"; check "$hn plan rc 0 (not applied, no refusal)" "$XRC"
  grep -q 'already applied' "$SEC/x.out" && check "$hn not yet applied" 1
  x "$hn" "$(audcmd "$hn")"; check "$hn pre-fix audit WARN (exit 1) as found" "$([ "$XRC" = 1 ] && echo 0 || echo 1)" "exit $XRC"
  for c in cipher.kx_rsa cipher.cbc_sha2; do
    n="$(command grep -cE "^\s*\[(WARN|FAIL)\] $c:" "$SEC/x.out")"; check "$hn pre-fix finding $c present" "$([ "$n" = 1 ] && echo 0 || echo 1)"
  done
done
gate preflight
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo; echo "PREFLIGHT_ONLY: preflight PASS, nothing changed ($(ts))"; exit 0; }

echo; echo "== 1. redirect notifiers, outer Alertmanager silence"
redirect() { # HOST PATH
  local h="$1" f="$2"
  SHAS["$h:$f"]="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
  [[ "${SHAS[$h:$f]}" =~ ^[0-9a-f]{64}$ ]] || { echo "  sha256 of $h:$f unreadable - stopping"; exit 3; }
  on "$h" "sudo -n cp -p $f $f$SUF" || { echo "  backup of $h:$f failed - stopping"; exit 3; }
  MOVED+=("$h:$f")
  on "$h" "sudo -n sh -c 'umask 077; { grep -vE \"^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER)=\" $f$SUF; printf \"NTFY_SERVER=%s\nNTFY_TOPIC=%s\n\" $NTFY $ALERT; } > $f.new && mv -f $f.new $f'" \
    || { echo "  redirect of $h:$f failed - stopping"; exit 3; }
  echo "  $h:$f sha256 ${SHAS[$h:$f]:0:12} -> throwaway ALERT topic (original kept as $f$SUF)"
}
for f in $LOCAL_ENVS; do redirect validator "$f"; done
for f in $REMOTE_ENVS; do redirect sentry "$f"; done
for h in validator sentry; do
  CREATED+=("$h:/etc/pft-maint/ntfy.env")
  on "$h" "sudo -n install -o root -g root -m 600 /dev/null /etc/pft-maint/ntfy.env && printf 'NTFY_SERVER=%s\nNTFY_TOPIC=%s\n' $NTFY $MTOP | sudo -n tee /etc/pft-maint/ntfy.env >/dev/null" \
    || { echo "  $h pft-maint ntfy.env not created - stopping"; exit 3; }
  echo "  $h:/etc/pft-maint/ntfy.env created for the run only -> throwaway MAINT topic"
done
ends="$(date -u -d "+$OUTER_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg w "$WD" '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
  {name: "alertname", value: $w, isRegex: false, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "pft-peertls-fix-run",
  comment: "task_2b00 peertls cipher fix: planned restarts of both nodes"}')"
SIL="$(curl -s -m 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  silence not created - stopping"; exit 3; }
echo "  outer silence alertname=~\".+\", alertname!=\"$WD\" until $ends (id ${SIL:0:8})"

echo; echo "== 2. pft-maint window"
x validator "sudo -n pft-maint start --ttl 45m --reason 'task_2b00 peertls cipher fix (planned node restarts)'"
check "pft-maint start" "$XRC"; [ "$XRC" = 0 ] && MAINTW=1
ok=1; for _i in $(seq 1 36); do R "sudo -n pft-maint active" >/dev/null 2>&1 && { ok=0; break; }; sleep 5; done
check "sentry sees the window" "$ok" "after $(( _i * 5 )) s"
gate "apply"

echo; echo "== 3. apply (sentry first)"
declare -A ST0=() ST1=()
for hn in sentry validator; do
  ST0[$hn]="$(started "$hn")"
  x "$hn" "$(fixcmd "$hn") apply --yes"
  check "$hn apply exit 0" "$XRC" "exit $XRC"
  ST1[$hn]="$(started "$hn")"
  check "$hn container restarted once by apply" "$([ "${ST0[$hn]}" != "${ST1[$hn]}" ] && echo 0 || echo 1)" "${ST0[$hn]} -> ${ST1[$hn]}"
  gate "$hn verified"
done

echo; echo "== 4. VERIFIED"
for hn in sentry validator; do
  echo "-- $hn"
  x "$hn" "$(fixcmd "$hn") plan"; check "$hn plan: already applied" "$(command grep -q 'already applied' "$SEC/x.out" && echo 0 || echo 1)"
  sleep 31   # UFW LIMIT window: 6 new connections / 30 s per source
  x "$hn" "$(audcmd "$hn")"; check "$hn post-fix audit PASS (exit 0)" "$XRC" "exit $XRC"
  for c in cipher.kx_rsa cipher.cbc_sha2; do
    n="$(command grep -cE "^\s*\[PASS\] $c:" "$SEC/x.out")"; check "$hn $c now PASS" "$([ "$n" = 1 ] && echo 0 || echo 1)"
  done
  s="$(state "$hn")"; check "$hn server_state full" "$([ "$s" = full ] && echo 0 || echo 1)" "$s"
  x "$hn" "sudo -n pft-integrity verify | tail -1"; check "$hn integrity PASS" "$(command grep -q 'RESULT: PASS' "$SEC/x.out" && echo 0 || echo 1)"
done
n="$(R "sudo -n iptables -S DOCKER-USER" | command grep -c -- '-j PFT-EGRESS')"
check "sentry DOCKER-USER -> PFT-EGRESS jump present once" "$([ "$n" = 1 ] && echo 0 || echo 1)" "$n"

echo; echo "== 5. window end, restore notifiers, re-run collectors"
restore
check "notifier envs restored byte-identical, run-only files removed" "$([ "$RESTORE_OK" = true ] && echo 0 || echo 1)"
x validator "sudo -n pft-keyescrow inventory --textfile | tail -1"; check "validator keyescrow inventory rc 0" "$XRC"
x sentry "sudo -n pft-keyescrow inventory --textfile | tail -1"; check "sentry keyescrow inventory rc 0" "$XRC"
x validator "sudo -n pft-keyescrow pull 2>&1 | tail -2"; check "validator keyescrow pull rc 0" "$XRC"

echo; echo "== 6. drain, expire silence, read back"
newest="$(for hn in sentry validator; do date -u -d "${ST1[$hn]}" +%s; done | sort -n | tail -1)"
until_t=$(( newest + RESTART_TAIL * 60 )); deadline=$(( $(date +%s) + DRAIN_MAX * 60 ))
while :; do
  o="$(alerts_other)"
  if [ "$(date +%s)" -ge "$until_t" ] && [ -z "$o" ]; then echo "  $(ts) drained: nothing but the watchdog in Prometheus"; break; fi
  [ "$(date +%s)" -lt "$deadline" ] || { echo "  $(ts) drain timeout; still: $(paste -sd';' <<<"$o")"; break; }
  sleep 30
done
check "drained (only the watchdog left)" "$([ -z "$o" ] && echo 0 || echo 1)" "$(paste -sd';' <<<"${o:-none}")"
if [ -z "$o" ]; then
  curl -s -m 10 -o /dev/null -w "  outer silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
else echo "  outer silence ${SIL:0:8} KEPT (alerts still active; expires $ends)"; fi
sleep 90
readback() { # TOPIC LABEL [quiet]
  local out; out="$(curl -s -m 20 "$NTFY/$1/json?poll=1&since=$since")" || { N=-1; echo "  $2: unreadable"; return; }
  N="$(jq -c 'select(.event == "message")' <<<"$out" 2>/dev/null | wc -l)"; echo "  $2 topic: $N message(s)"
  [ -n "${3:-}" ] || jq -c 'select(.event == "message") | {time: (.time | todate), title}' <<<"$out" 2>/dev/null | red | sed 's/^/    /'
}
readback "$MTOP" MAINT; readback "$ALERT" ALERT
i=0; OPN=0; while read -r t; do i=$((i + 1)); readback "$t" "operator #$i" quiet; [ "$N" = 0 ] || OPN=$((OPN + 1)); done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo "  Alertmanager besides the watchdog: $(am_other | paste -sd';' -)"
echo; echo "fix-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
