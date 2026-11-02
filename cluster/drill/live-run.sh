#!/usr/bin/env bash
# live-run: recorded two-host install + clustering of the validator and its sentry with pft-cluster, sentry first.
# Built from ../../mounts/drill/live-run.sh (redirect / silence / window / read-back framework). This run DOES
# restart both nodes (sentry several times), so every alert is silenced on the validator's Alertmanager for the run
# and until the last node start + 25 min (PFTContainerRestarted looks back 15 min), and every notifier on both hosts
# points at a throwaway topic.
#   bash cluster/drill/live-run.sh 2>&1 | tee LOG    (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# 0  preflight (nothing changed yet): clean pushed HEAD; relay, Alertmanager, Prometheus reachable; no pft-maint
#    window; no data collector reading the validator's node; notifier env files present, no leftovers; both nodes
#    full; pft-integrity PASS on both; redaction positive control. Topics, user, addresses and node keys go into a
#    0600 literals file for redact.py and are never printed.
# 1  redirect notifiers to a throwaway topic, silence alertname=~".+" , pft-maint window (sentry gets it too).
# 2  install on both hosts (+ the validator's pull of the sentry file); Prometheus loads PFTClusterMissing.
# 3  keys: keygen on the validator (creates fp_key), fp_key copied to the sentry, keygen there; pubkey/set-peer
#    exchange (keys go to the literals file, never printed).
# 4  before: audit (text + --json) on both hosts.
# 5  sentry: injected gate miss (PFT_CLUSTER_INJECT=health) -> automatic rollback (config sha256 and pubkey_node back).
# 6  sentry apply; 7 validator apply --require-peer; 8 after: --json audits, both directions from both sides.
# 9  secrets: seed in no docker inspect / ps / container log / textfile (audit) + the same greps by the runner.
# 10 sentry container re-creation (drill/recreate.sh): pubkey_node unchanged, cluster re-formed.
# 11 sentry-only rollback, then re-apply --require-peer.
# 12 metrics (units, pull, Prometheus), 13 baselines (integrity, fleet, rulecheck), 14 restore + read-back.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM  PROM  LOCAL_ENVS  REMOTE_ENVS  TTL (150m)  SIL_TTL (180, min)
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"
RELAY="${RELAY:-relay}"; NTFY="${NTFY:-https://ntfy.sh}"
AM="${AM:-http://127.0.0.1:9093}"; PROM="${PROM:-http://127.0.0.1:9090}"
LOCAL_ENVS="${LOCAL_ENVS:-/etc/postfiat-monitor.env /etc/pft-integrity.env}"
REMOTE_ENVS="${REMOTE_ENVS:-/etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env}"
BRIDGE_ENV="${BRIDGE_ENV:-$HOME/.config/pft-alerts/ntfy.env}"; AGENT_ENV="${AGENT_ENV:-/opt/pft-agent/config.env}"
MAINT_ENV=/etc/pft-maint/ntfy.env
TTL="${TTL:-150m}"; SIL_TTL="${SIL_TTL:-180}"
COLLECTORS="${COLLECTORS:-pft-payflow-tx.service pft-senders-tx.service}"
TASK=task_01cd4e81
SUF=.pre-cluster-live
SHA_HEAD="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
RDIR="/var/tmp/pft-cluster-live-$SHORT"   # sentry copy of the tree (read with bash, never executed from a noexec mount)

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="cllive-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"; LAST_START="$since"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
HN="$(hostname)"; RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
cn() { if [ "$1" = relay ]; then echo postfiatd-sentry; else echo postfiatd; fi; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
info() { on "$1" "sudo -n docker exec $(cn "$1") curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"; }
node_state() { info "$1" | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
node_key() { info "$1" | jq -r '.result.info.pubkey_node // empty' 2>/dev/null; }
fpk() { on "$1" "sudo -n sh -c '{ cat /var/lib/pft-cluster/fp_key; printf %s $2; } | sha256sum | cut -c1-12'" | sed 's/^/node:/'; } # HOST KEY
started() { LAST_START="$(date -u +%s)"; } # every node (re)start pushes the silence end out
audit_json() { on "$1" "sudo -n pft-cluster audit --json" | sed -n '/^{/,$p'; }
st_of() { jq -r --arg id "$2" '[.checks[] | select(.id == $id)][0].status' <<<"$1"; } # JSON ID

declare -A SHA=()
declare -a MOVED=()
RESTORED=0; RESTORE_OK=true; MAINT_STARTED=0; MAINT_ENV_MADE=0; SIL=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local k h f now_sha left
  if [ "$MAINT_STARTED" = 1 ]; then echo "  \$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/    /'; fi
  if [ "$MAINT_ENV_MADE" = 1 ]; then
    sudo -n rm -f "$MAINT_ENV" && echo "  removed $MAINT_ENV (absent before the run)" || { echo "  remove $MAINT_ENV FAILED"; RESTORE_OK=false; }
  fi
  for k in "${MOVED[@]}"; do
    h="${k%%:*}"; f="${k#*:}"
    on "$h" "sudo -n mv -f $f$SUF $f" || { echo "  restore $k: mv FAILED"; RESTORE_OK=false; }
    now_sha="$(on "$h" "sudo -n sha256sum -- $f" | cut -c1-64)"
    if [[ "$now_sha" =~ ^[0-9a-f]{64}$ ]] && [ "$now_sha" = "${SHA[$k]}" ]; then echo "  restored $k: sha256 matches pre-run copy: yes"
    else echo "  restored $k: sha256 matches pre-run copy: NO"; RESTORE_OK=false; fi
  done
  if [ -n "$SIL" ]; then
    left=$(( LAST_START + 25 * 60 - $(date -u +%s) ))
    if [ "$left" -gt 0 ]; then
      echo "  silence kept: last node start $(date -u -d "@$LAST_START" +%TZ) + 25 min is ${left}s away (PFTContainerRestarted window); it expires by itself at its end time"
    else curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"; fi
  fi
  R "rm -rf $RDIR" || true
}
cleanup() { restore; rm -rf "$SEC"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

{ echo "pft-cluster two-host live run (sentry first) - $(ts) - $(lsb_release -ds) - run $RUN"
  echo "repo HEAD $SHA_HEAD (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
  for f in cluster/drill/live-run.sh cluster/drill/recreate.sh cluster/pft-cluster.sh cluster/install.sh alerts/cluster.rules.yml "${REDACT#"$REPO"/}"; do
    echo "sha256 $(sha256sum < "$f" | cut -c1-64) $f"; done; }

echo; echo "== 0. preflight (nothing changed yet)"
[ -z "$(git status --short)" ] || { echo "  dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA_HEAD" ] || { echo "  HEAD is not pushed - stopping"; exit 3; }
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
for u in $COLLECTORS; do
  systemctl is-active -q "$u" && { echo "  $u is collecting from the validator's node - stopping (restarts would cut its window)" >&2; exit 4; }
done
echo "  pft-maint: no window on either host; data collectors inactive ($COLLECTORS)"
sudo -n test -e "$MAINT_ENV" && { echo "  $MAINT_ENV exists (this runner expects it absent) - stopping" >&2; exit 3; }
for f in $LOCAL_ENVS; do
  L "sudo -n test -f $f" || { echo "  local $f missing - stopping" >&2; exit 3; }
  ! L "sudo -n test -e $f$SUF" || { echo "  leftover local $f$SUF - stopping" >&2; exit 3; }
done
for f in $REMOTE_ENVS; do
  R "sudo -n test -f $f" || { echo "  relay $f missing - stopping" >&2; exit 3; }
  ! R "sudo -n test -e $f$SUF" || { echo "  leftover relay $f$SUF - stopping" >&2; exit 3; }
done
{ for f in $LOCAL_ENVS; do L "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  for f in $REMOTE_ENVS; do R "sudo -n sed -n 's/^NTFY_TOPIC=//p' $f"; done
  sed -n 's|^NTFY_URL=.*/||p' "$BRIDGE_ENV" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' "$AGENT_ENV" 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
while read -r t; do printf 'topic\t%s\n' "$t" >> "$LIT"; done < "$OPS"
echo "  operator topics to watch: $(wc -l < "$OPS") (not printed)"
[ -s "$OPS" ] || { echo "  no operator topic found - stopping" >&2; exit 3; }
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; [ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
RHN="$(R hostname)"; [ -n "$RHN" ] || RHN="$HN"
declare -A PRE=()
for h in relay local; do
  PRE[$h]="$(node_key "$h")"; [ -z "${PRE[$h]}" ] || printf 'key\t%s\n' "${PRE[$h]}" >> "$LIT"
  s="$(node_state "$h")"; echo "  $(cn "$h"): server_state=${s:-down}"
  case "$s" in full|proposing) ;; *) echo "  node not full - stopping" >&2; exit 4 ;; esac
done
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  case "$r" in "RESULT: PASS"*) ;; *) echo "  integrity not clean on $h - stopping" >&2; exit 4 ;; esac
done
echo "\$ redact.py control --literals <literals>"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping before any change" >&2; exit 3; }

echo; echo "== 1. redirect notifiers, silence every alert, maintenance window"
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
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK pft-cluster live run $RUN (planned restarts of both nodes)" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "cluster-live", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence alertname=~\".+\" until $ends" "$(ok_if '[ -n "$SIL" ]')"
x "sudo -n pft-maint start --ttl $TTL --reason '$TASK pft-cluster live run $RUN'"
[ "$XRC" = 0 ] || { echo "  pft-maint start failed - stopping"; exit 4; }
MAINT_STARTED=1
w=0
until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 4

echo; echo "== 2. install (sentry first, then validator, then the validator's pull of the sentry file)"
x "git archive $SHA_HEAD cluster | R 'rm -rf $RDIR && mkdir -m 700 $RDIR && tar -x -C $RDIR'"
x "R 'sudo -n bash $RDIR/cluster/install.sh --host sentry'"
check "sentry install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_cluster_findings{host=\"sentry\"}" <<<"$XOUT"')"
x "sudo -n bash cluster/install.sh"
check "validator install exit 0, first audit textfile valid" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_cluster_findings{host=\"validator\"}" <<<"$XOUT"')"
x "sudo -n grep -q '^PULL_SSH=' /etc/pft-cluster.env || sudo -n sh -c 'grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-cluster.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-cluster.env; sudo -n stat -c '%a %U' /etc/pft-cluster.env"
x "sudo -n bash cluster/install.sh --pull"
check "pull install exit 0, sentry file present on the validator" "$(ok_if '[ "$XRC" = 0 ] && grep -q "pft_cluster_findings{host=\"sentry\"}" <<<"$XOUT"')"
x "grep -n cluster.rules.yml alerts/prometheus.yml; sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 30 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-cluster\") | .rules[] | [.name, .health] | @tsv'"
check "PFTClusterMissing loaded, health ok" "$(ok_if 'grep -qE "^PFTClusterMissing	ok" <<<"$XOUT"')"

echo; echo "== 3. keys (validation_create on each node; only fingerprints are printed)"
x "sudo -n pft-cluster keygen"
check "validator keygen exit 0" "$XRC"
x "sudo -n cat /var/lib/pft-cluster/fp_key | R 'sudo -n sh -c \"umask 077; mkdir -p /var/lib/pft-cluster && chmod 700 /var/lib/pft-cluster && cat > /var/lib/pft-cluster/fp_key\"'; sudo -n sha256sum < /var/lib/pft-cluster/fp_key | cut -c1-12; R 'sudo -n sha256sum < /var/lib/pft-cluster/fp_key | cut -c1-12'"
check "fp_key identical on both hosts (sha256 prefix)" "$(ok_if '[ "$(sort -u <<<"$XOUT" | grep -cE "^[0-9a-f]{12}$")" = 1 ]')"
x "R 'sudo -n pft-cluster keygen'"
check "sentry keygen exit 0" "$XRC"
VKEY="$(sudo -n pft-cluster pubkey)"; SKEY="$(R 'sudo -n pft-cluster pubkey')"
printf 'key\t%s\nkey\t%s\n' "$VKEY" "$SKEY" >> "$LIT"
check "both pinned keys read (52 chars, n...), not printed" "$(ok_if '[[ "$VKEY" =~ ^n[1-9A-HJ-NP-Za-km-z]{51}$ ]] && [[ "$SKEY" =~ ^n[1-9A-HJ-NP-Za-km-z]{51}$ ]] && [ "$VKEY" != "$SKEY" ]')"
echo "  validator pinned $(fpk local "$VKEY") (running ${PRE[local]:+$(fpk local "${PRE[local]}")}), sentry pinned $(fpk local "$SKEY") (running ${PRE[relay]:+$(fpk local "${PRE[relay]}")})"
x "sudo -n pft-cluster set-peer \"\$SKEY\" sentry; R \"sudo -n pft-cluster set-peer \$VKEY validator\""
check "set-peer on both hosts" "$XRC"
x "on relay 'sudo -n stat -c \"%a %U %n\" /var/lib/pft-cluster /var/lib/pft-cluster/node_seed /var/lib/pft-cluster/fp_key /etc/pft-cluster.env'; sudo -n stat -c '%a %U %n' /var/lib/pft-cluster /var/lib/pft-cluster/node_seed /var/lib/pft-cluster/fp_key /etc/pft-cluster.env"
check "seed storage 0700/0600 root on both hosts" "$(ok_if '[ "$(grep -cE "^(700 root /var/lib/pft-cluster|600 root /var/lib/pft-cluster/(node_seed|fp_key)|600 root /etc/pft-cluster.env)$" <<<"$XOUT")" = 8 ]')"

echo; echo "== 4. before: not clustered (text + --json on both hosts)"
for h in relay local; do
  x "on $h 'sudo -n pft-cluster audit; echo audit-exit=\$?'"
  check "$h before: audit exit 1 (findings)" "$(ok_if 'grep -qx "audit-exit=1" <<<"$XOUT"')"
  J="$(audit_json "$h")"; echo "  --json: $(jq -c '{host, findings, result, failing: [.checks[] | select(.status != "PASS" and .status != "INFO") | .id]}' <<<"$J")"
  check "$h before: cfg:node_seed and live:peer FAIL in --json" "$(ok_if '[ "$(st_of "$J" cfg:node_seed)" = FAIL ] && [ "$(st_of "$J" live:peer)" = FAIL ]')"
done
x "on local \"sudo -n docker exec postfiatd curl -s -m 10 -d '{\\\"method\\\":\\\"peers\\\"}' http://127.0.0.1:5005\" | jq -c '{cluster: (.result.cluster | length), peers_with_cluster_flag: [.result.peers[] | select(.cluster == true)] | length}'"

echo; echo "== 5. sentry: injected gate miss -> automatic rollback"
CSHA="$(R 'sudo -n sh -c "sha256sum \$(docker inspect -f \"{{range .Mounts}}{{if eq .Destination \\\"/etc/postfiatd\\\"}}{{.Source}}{{end}}{{end}}\" postfiatd-sentry)/postfiatd.cfg"' | cut -c1-64)"
started; x "R 'sudo -n env HEALTH_BUDGET=600 PFT_CLUSTER_INJECT=health pft-cluster apply --yes'"; started
check "injected miss: exit 1, automatic rollback, rollback gate PASS" "$(ok_if '[ "$XRC" = 1 ] && grep -q "automatic rollback" <<<"$XOUT" && grep -q "rollback: health: PASS" <<<"$XOUT"')"
CSHA2="$(R 'sudo -n sh -c "sha256sum \$(docker inspect -f \"{{range .Mounts}}{{if eq .Destination \\\"/etc/postfiatd\\\"}}{{.Source}}{{end}}{{end}}\" postfiatd-sentry)/postfiatd.cfg"' | cut -c1-64)"
check "injected miss: sentry config sha256 back to the pre-run file" "$(ok_if '[[ "$CSHA" =~ ^[0-9a-f]{64}$ ]] && [ "$CSHA" = "$CSHA2" ]')" "${CSHA:0:12} -> ${CSHA2:0:12}"
check "injected miss: sentry pubkey_node back to its pre-run key" "$(ok_if '[ "$(node_key relay)" = "${PRE[relay]}" ]')"

echo; echo "== 6. sentry apply (its gate cannot require the validator yet: the validator still runs its old key)"
started; x "R 'sudo -n env HEALTH_BUDGET=900 pft-cluster apply --yes'"; started
check "sentry apply exit 0, gate PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "health: PASS" <<<"$XOUT" && grep -q "apply: done" <<<"$XOUT"')"
check "sentry runs its pinned key" "$(ok_if '[ "$(node_key relay)" = "$SKEY" ]')"

echo; echo "== 7. validator apply --require-peer"
started; x "sudo -n env HEALTH_BUDGET=900 pft-cluster apply --yes --require-peer"; started
check "validator apply exit 0, gate PASS incl. sentry connected as member + reporting" "$(ok_if '[ "$XRC" = 0 ] && grep -q "connected cluster=true, report" <<<"$XOUT"')"
check "validator runs its pinned key" "$(ok_if '[ "$(node_key local)" = "$VKEY" ]')"

after_both() { # LABEL: audits on both hosts must PASS, both directions
  local h J w=0
  for h in relay local; do
    until on "$h" "sudo -n pft-cluster audit" >/dev/null 2>&1; do w=$((w + 15)); [ "$w" -le 600 ] || break; sleep 15; done
    x "on $h 'sudo -n pft-cluster audit; echo audit-exit=\$?'"
    J="$(audit_json "$h")"
    check "$1 $h: audit PASS (exit 0), live:peer + live:reports PASS" "$(ok_if 'grep -qx "audit-exit=0" <<<"$XOUT" && [ "$(st_of "$J" live:peer)" = PASS ] && [ "$(st_of "$J" live:reports)" = PASS ]')"
  done
}
echo; echo "== 8. after: both directions from both sides"
after_both after
for h in local relay; do
  x "on $h \"sudo -n docker exec $(cn "$h") curl -s -m 10 -d '{\\\"method\\\":\\\"peers\\\"}' http://127.0.0.1:5005\" | jq -c '{cluster: (.result.cluster | to_entries | map({key: .key, tag: .value.tag, age: .value.age})), member_peers: [.result.peers[] | select(.cluster == true) | {public_key, cluster}]}'"
done

echo; echo "== 9. secrets: the seed is nowhere it should not be"
for h in local relay; do
  x "on $h 'sudo -n sh -c \"S=/var/lib/pft-cluster/node_seed; c=$(cn "$h"); printf \\\"inspect %s ps %s log %s textfile %s\\n\\\" \\\$(docker inspect \\\$c | grep -cFf \\\$S) \\\$(ps -eo args | grep -cFf \\\$S) \\\$(docker logs --tail 20000 \\\$c 2>&1 | grep -cFf \\\$S) \\\$(cat /var/lib/pft-exporter/textfile/*.prom | grep -cFf \\\$S)\"'"
  check "$h: seed found 0 times in docker inspect, ps, last 20000 log lines, textfiles" "$(ok_if 'grep -qx "inspect 0 ps 0 log 0 textfile 0" <<<"$XOUT"')"
done

echo; echo "== 10. sentry container re-creation: identity and cluster survive"
x "R 'sudo -n docker inspect -f \"{{.Id}}\" postfiatd-sentry | cut -c1-12'"; OLDID="$XOUT"
started; x "R 'sudo -n bash $RDIR/cluster/drill/recreate.sh postfiatd-sentry'"; started
check "recreate exit 0, config summary identical" "$(ok_if '[ "$XRC" = 0 ] && grep -q "config summary identical" <<<"$XOUT"')"
w=0; until [ "$(node_state relay)" = full ]; do w=$((w + 10)); [ "$w" -le 900 ] || break; sleep 10; done
check "re-created sentry full after ${w}s" "$(ok_if '[ "$(node_state relay)" = full ]')"
check "re-created sentry: new container Id, same pinned pubkey_node" "$(ok_if '[ "$(R "sudo -n docker inspect -f {{.Id}} postfiatd-sentry" | cut -c1-12)" != "$OLDID" ] && [ "$(node_key relay)" = "$SKEY" ]')"
after_both "after re-creation"

echo; echo "== 11. sentry-only rollback, then re-apply"
started; x "R 'sudo -n env HEALTH_BUDGET=900 pft-cluster rollback --yes'"; started
check "sentry rollback exit 0, back on its pre-apply key" "$(ok_if '[ "$XRC" = 0 ] && [ "$(node_key relay)" = "${PRE[relay]}" ]')"
x "R 'sudo -n pft-cluster audit; echo audit-exit=\$?'"
check "sentry after rollback: findings again (exit 1)" "$(ok_if 'grep -qx "audit-exit=1" <<<"$XOUT"')"
J="$(audit_json local)"
check "validator sees the sentry gone from the cluster (live:peer FAIL)" "$(ok_if '[ "$(st_of "$J" live:peer)" = FAIL ]')"
started; x "R 'sudo -n env HEALTH_BUDGET=900 pft-cluster apply --yes --require-peer'"; started
check "sentry re-apply --require-peer exit 0" "$(ok_if '[ "$XRC" = 0 ] && grep -q "connected cluster=true, report" <<<"$XOUT"')"
after_both "after re-apply"

echo; echo "== 12. metrics: units on both hosts, pull, Prometheus"
x "R 'sudo -n systemctl start pft-cluster.service; systemctl show -p Result --value pft-cluster.service'"
x "sudo -n systemctl start pft-cluster.service pft-cluster-pull.service; systemctl show -p Result --value pft-cluster.service pft-cluster-pull.service; grep -hE '^pft_cluster_(findings|peer_clustered)' /var/lib/pft-exporter/textfile/pft_cluster_*.prom"
check "textfiles: findings 0 and peer_clustered 1 for validator and sentry" "$(ok_if '[ "$(grep -cE "^pft_cluster_findings\{host=\"(validator|sentry)\"\} 0$" <<<"$XOUT")" = 2 ] && [ "$(grep -cE "^pft_cluster_peer_clustered\{host=\"(validator|sentry)\"\} 1$" <<<"$XOUT")" = 2 ]')"
x "sleep 45; curl -s $PROM/api/v1/query --data-urlencode 'query=pft_cluster_findings' | jq -r '.data.result[] | \"\(.metric.host) \(.value[1])\"' | sort"
check "Prometheus: pft_cluster_findings 0 for sentry and validator" "$(ok_if '[ "$(grep -cE "^(sentry|validator) 0$" <<<"$XOUT")" = 2 ]')"

echo; echo "== 13. baselines: integrity accept on both hosts, fleet manifest sync, skew, rulecheck"
x "sudo -n pft-integrity verify | grep -E '^  \[(WARN|FAIL)\]|^RESULT' | sed -E 's/ +sha256.*//' | head -30"
x "sudo -n pft-integrity accept --reason '$TASK: pft-cluster $SHORT installed (script, units, env, rulecheck.conf)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^  \[(WARN|FAIL)\]|^RESULT' | sed -E 's/ +sha256.*//' | head -30"
x "R \"sudo -n pft-integrity accept --reason '$TASK: pft-cluster $SHORT installed (script, units, env, rulecheck.conf); sentry container re-created'\" | tail -2"
x "sudo -n pft-fleet sync --addon fleet --to $SHA_HEAD --apply --reason '$TASK cluster manifest lines'"
check "fleet sync of the manifest exit 0" "$XRC"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, cluster CURRENT on both hosts" "$(ok_if '[ "$XRC" = 0 ] && [ "$(grep -cE "^ *(validator|sentry) +cluster +CURRENT" <<<"$XOUT")" = 2 ]')"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT '"
check "validator pft-rulecheck RESULT OK" "$(ok_if 'grep -q "^RESULT OK " <<<"$XOUT"')"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after accept + sync" "$(ok_if '[ "$(grep -c "RESULT: PASS" <<<"$XOUT")" = 2 ]')"

echo; echo "== 14. restore, read back"
restore
check "env files byte-identical, pft-maint env removed, window ended" "$(ok_if '[ "$RESTORE_OK" = true ] && ! sudo -n pft-maint active >/dev/null 2>&1 && ! sudo -n test -e "$MAINT_ENV"')"
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
check "operator topics received nothing during the run" "$(ok_if '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
for h in local relay; do
  r="$(on "$h" "sudo -n pft-integrity verify" 2>&1 | grep '^RESULT')"; echo "  pft-integrity $h: $r"
  check "pft-integrity PASS on $h at the end" "$(case "$r" in "RESULT: PASS"*) echo 0 ;; *) echo 1 ;; esac)"
  s="$(node_state "$h")"; check "$(cn "$h") full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "live-run done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
