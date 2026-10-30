#!/usr/bin/env bash
# live-alert-drill: the pft-sshcrypto alert drill on both hosts, with the alert bridge on a throwaway ntfy topic.
# Built from ../../rulecheck/drill/live-run.sh (bridge swap / silence / read-back framework).
#   bash sshcrypto/drill/live-alert-drill.sh 2>&1 | tee LOG    (as the agent user, from the repo root; sudo -n, `ssh relay`)
# The "fault" is real: both hosts still run the stock OpenSSH 8.9 algorithm lists (host-run.sh left them in their
# pre-apply state), which the audit grades FAIL. The fix is the real `pft-sshcrypto apply` on both hosts.
# 0 preflight (nothing changed): relay, Alertmanager, Prometheus reachable; no pft-maint window; the bridge mounts the
#   operator env; no active silence covers the sshcrypto alerts; both hosts have nothing applied; pft-integrity PASS
#   on both; both nodes full; redaction positive control. Operator topics, user name and host addresses go into a
#   0600 literals file for redact.py.
# 1 bridge -> throwaway topic (recreated with a throwaway NTFY_ENV_FILE); Alertmanager silence for every alert EXCEPT
#   the sshcrypto alerts and the pipeline watchdog.
# 2 load ../../alerts/sshcrypto.rules.yml (listed in alerts/prometheus.yml) with a Prometheus reload; audit both hosts
#   through the real units, pull the sentry's textfile.
# 3 detect: PFTSSHCryptoFailGrade firing for host=validator and host=sentry (for: 5m) and both [FIRING] messages on
#   the throwaway topic.
# 4 fix: `pft-sshcrypto apply` on both hosts (exit 0), audits through the units (RESULT OK), pull; both alerts leave
#   Prometheus and both [RESOLVED] messages reach the throwaway topic (every (alert, host) pair, lesson 151).
# 5 restore the bridge (mount source read back), expire the silence, read back the throwaway topic, count messages
#   on every operator topic since the start (topics never printed); both nodes full. Exit 0 = every CHECK ok.
# pft-integrity WARNs on the new drop-in afterwards by design; the run that published this log accepted it right after.
# Env: RELAY (relay)  NTFY (https://ntfy.sh)  AM (http://127.0.0.1:9093)  PROM (http://127.0.0.1:9090)
#      FIRE_WAIT (600, s)  NTFY_WAIT (240, s)  SIL_TTL (45, min)  REDACT (../../peerexpose/drill/redact.py)
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
FIRE_WAIT="${FIRE_WAIT:-600}"; NTFY_WAIT="${NTFY_WAIT:-240}"; SIL_TTL="${SIL_TTL:-45}"
SC_ALERTS='PFTSSHCrypto[A-Za-z]+'
WATCHDOG_ALERT=PFTAlertPipelineWatchdog
TF=/var/lib/pft-exporter/textfile

rnd() { head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ALERT="scdrill-$(rnd)"
since="$(date -u +%s)"; RUN="$(date -u +%Y%m%dT%H%M%SZ)"
ts() { date -u +%FT%TZ; }
SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
OPS="$SEC/operator-topics"; : > "$OPS"
printf 'topic\t%s\nuser\t%s\n' "$ALERT" "$(id -un)" >> "$LIT"
red() { python3 -u "$REDACT" filter --literals "$LIT"; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
FAILS=0
check() { # NAME 0|1 DETAIL
  if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi
}
XRC=0; XOUT=""
x() { # print the exact command, run it, print its output (redacted) and exit code; output kept in XOUT
  echo "\$ $*"
  XOUT="$(eval "$*" 2>&1 < /dev/null)"; XRC=$?
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
n_msgs() { # TITLE HOST -> number of messages on the throwaway topic with that title naming that host
  jq -r --arg t "$1" 'select(.title == $t) | .message' <<<"$M" | grep -c "on $2 "
}

RESTORED=0; RESTORE_OK=true; BRIDGE_SWAPPED=0; SIL=""
restore() {
  [ "$RESTORED" -eq 1 ] && return 0
  RESTORED=1
  local src
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

{ echo "pft-sshcrypto alert drill - $(ts) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - run $RUN"
  echo "repo HEAD $(git -C "$REPO" rev-parse HEAD)"
  echo "sha256: live-alert-drill.sh $(sha256sum < "$0" | cut -c1-64)"
  echo "        repo pft-sshcrypto.sh $(sha256sum < "$REPO/sshcrypto/pft-sshcrypto.sh" | cut -c1-64) sshcrypto_grade.py $(sha256sum < "$REPO/sshcrypto/sshcrypto_grade.py" | cut -c1-64)"
  echo "        installed validator $(sha256sum < /usr/local/bin/pft-sshcrypto | cut -c1-64) $(sha256sum < /usr/local/lib/pft-sshcrypto/sshcrypto_grade.py | cut -c1-64)"
  echo "        installed sentry    $(R 'sha256sum < /usr/local/bin/pft-sshcrypto' | cut -c1-64) $(R 'sha256sum < /usr/local/lib/pft-sshcrypto/sshcrypto_grade.py' | cut -c1-64)"
  echo "        sshcrypto.rules.yml (repo, loaded by Prometheus) $(sha256sum < "$REPO/alerts/sshcrypto.rules.yml" | cut -c1-64)"
  echo "        redact.py $(sha256sum < "$REDACT" | cut -c1-64)"; }

echo; echo "== 0. preflight (nothing changed yet)"
R true || { echo "  relay unreachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$AM/-/ready" || { echo "  Alertmanager not reachable - stopping" >&2; exit 3; }
curl -s --max-time 5 -o /dev/null "$PROM/-/ready" || { echo "  Prometheus not reachable - stopping" >&2; exit 3; }
sudo -n pft-maint active >/dev/null 2>&1 && { echo "  a pft-maint window is open on the validator - stopping" >&2; exit 4; }
R "sudo -n pft-maint active" >/dev/null 2>&1 && { echo "  a pft-maint window is open on the relay - stopping" >&2; exit 4; }
echo "  pft-maint: no window open on either host"
[ -r "$BRIDGE_ENV" ] || { echo "  bridge env not readable - stopping" >&2; exit 3; }
src0="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src0" = "$BRIDGE_ENV" ] || { echo "  bridge does not mount the operator env file now - stopping" >&2; exit 3; }
echo "  bridge mounts the operator env file: yes"
nsil="$(curl -s --max-time 10 "$AM/api/v2/silences" | jq '[.[] | select(.status.state == "active") | select(any(.matchers[]; .name == "alertname" and .isEqual != false and (.value as $v | if .isRegex then ("PFTSSHCryptoFailGrade" | test("^(" + $v + ")$")) else ($v | test("^PFTSSHCrypto")) end)))] | length')"
[ "$nsil" = 0 ] || { echo "  $nsil active silence(s) cover the sshcrypto alerts - stopping" >&2; exit 3; }
echo "  active silences covering the sshcrypto alerts: 0"
for h in local relay; do
  st="$(on "$h" "sudo -n pft-sshcrypto status" | head -1)"; echo "  $h: $st"
  [ "$st" = "state: none" ] || { echo "  $h: a policy is applied or pending - stopping" >&2; exit 4; }
done
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
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
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

echo; echo "== 1. bridge -> throwaway topic, silence everything except the sshcrypto alerts"
( umask 077; printf 'NTFY_URL=%s/%s\n' "$NTFY" "$ALERT" > "$SEC/bridge.env" )
BRIDGE_SWAPPED=1
DOCKER="sudo -n docker" NTFY_ENV_FILE="$SEC/bridge.env" "$RUNSTACK" bridge 2>&1 | red | sed 's/^/  /'
src="$(sudo -n docker inspect pft-alert-bridge --format '{{range .Mounts}}{{if eq .Destination "/run/secrets/ntfy.env"}}{{.Source}}{{end}}{{end}}')"
[ "$src" = "$SEC/bridge.env" ] || { echo "  bridge not pointed at the throwaway env - stopping"; exit 3; }
echo "  bridge -> $NTFY/<redacted> (throwaway env file in a 0700 temp dir)"
ends="$(date -u -d "+$SIL_TTL min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "sshcrypto drill $RUN: unrelated alerts" --arg x "$SC_ALERTS|$WATCHDOG_ALERT" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: $x, isRegex: true, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "sshcrypto-drill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
[ -n "$SIL" ] || { echo "  Alertmanager silence not created - stopping"; exit 3; }
echo "  silence alertname=~\".+\", alertname!~\"$SC_ALERTS|$WATCHDOG_ALERT\" until $ends (id ${SIL:0:8})"

echo; echo "== 2. load the rules, audit both hosts through the units"
x "grep -n sshcrypto $REPO/alerts/prometheus.yml"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 20 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-sshcrypto\") | .rules[] | [.name, .health] | @tsv'"
check "2a pft-sshcrypto rule group loaded (6 rules, health ok)" "$([ "$(grep -c '	ok$' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-sshcrypto.service; sudo -n journalctl -u pft-sshcrypto.service --since -1min --no-pager -o cat | grep '^RESULT'"
check "2b validator audit (unit): RESULT FAIL" "$(grep -q '^RESULT: FAIL' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'systemctl start pft-sshcrypto.service; journalctl -u pft-sshcrypto.service --since -1min --no-pager -o cat | grep ^RESULT'"
check "2c sentry audit (unit): RESULT FAIL" "$(grep -q '^RESULT: FAIL' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-sshcrypto-pull.service && grep -E '^pft_sshcrypto_(up|probes|probe_mismatches)|grade=\"fail\"' $TF/pft_sshcrypto_validator.prom $TF/pft_sshcrypto_sentry.prom"
x "sleep 20; pq 'sum by (host) (pft_sshcrypto_findings{grade=\"fail\"})'"
check "2d Prometheus sees FAIL findings for host=validator and host=sentry" "$(grep -qE '^host=validator [1-9]' <<<"$XOUT" && grep -qE '^host=sentry [1-9]' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 3. detect"
t_det="$(date -u +%s)"
echo "  waiting for PFTSSHCryptoFailGrade (host=validator, host=sentry) to fire (for: 5m; max ${FIRE_WAIT}s, poll 20s)"
got=0
while [ $(( $(date -u +%s) - t_det )) -lt "$FIRE_WAIT" ]; do
  F="$(pq 'ALERTS{alertstate="firing",alertname="PFTSSHCryptoFailGrade"}')"
  got=0
  grep -q 'host=validator' <<<"$F" && got=$((got + 1))
  grep -q 'host=sentry' <<<"$F" && got=$((got + 1))
  [ "$got" -ge 2 ] && break
  sleep 20
done
echo "  $(ts) firing ($(( $(date -u +%s) - t_det ))s after the audits):"; printf '%s\n' "$F" | red | sed 's/^/    /'
check "3a PFTSSHCryptoFailGrade firing for host=validator and host=sentry" "$([ "$got" -ge 2 ] && echo 0 || echo 1)" "$got/2"
echo "  waiting for both [FIRING] messages on the throwaway topic (max ${NTFY_WAIT}s)"
w=0
while :; do
  M="$(topic_msgs "$ALERT")"
  fv="$(n_msgs '[FIRING] PFTSSHCryptoFailGrade' validator)"; fs="$(n_msgs '[FIRING] PFTSSHCryptoFailGrade' sentry)"
  { [ "$fv" -ge 1 ] && [ "$fs" -ge 1 ]; } && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "3b [FIRING] PFTSSHCryptoFailGrade for validator and sentry delivered to the throwaway topic" "$([ "$fv" -ge 1 ] && [ "$fs" -ge 1 ] && echo 0 || echo 1)" "validator $fv, sentry $fs"

echo; echo "== 4. fix: apply the hardened policy on both hosts"
t_fix="$(date -u +%s)"
x "sudo -n pft-sshcrypto apply"
check "4a validator apply exit 0" "$([ "$XRC" = 0 ] && grep -q 'APPLIED' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'pft-sshcrypto apply'"
check "4b sentry apply exit 0" "$([ "$XRC" = 0 ] && grep -q 'APPLIED' <<<"$XOUT" && echo 0 || echo 1)"
x "R true && echo 'new ssh session validator -> sentry after the apply: OK'"
check "4c new ssh session from the validator to the sentry works after the apply" "$XRC"
x "sudo -n systemctl start pft-sshcrypto.service; sudo -n journalctl -u pft-sshcrypto.service --since -1min --no-pager -o cat | grep '^RESULT'"
check "4d validator audit (unit): RESULT OK" "$(grep -q '^RESULT: OK - .* 0 warn, 0 fail, .* 0 probe mismatches, 0 errors -> exit 0' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'systemctl start pft-sshcrypto.service; journalctl -u pft-sshcrypto.service --since -1min --no-pager -o cat | grep ^RESULT'"
check "4e sentry audit (unit): RESULT OK" "$(grep -q '^RESULT: OK - .* 0 warn, 0 fail, .* 0 probe mismatches, 0 errors -> exit 0' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-sshcrypto-pull.service && grep -E '^pft_sshcrypto_(up|probes|probe_mismatches|policy_applied)|grade=\"fail\"' $TF/pft_sshcrypto_validator.prom $TF/pft_sshcrypto_sentry.prom"
echo "  waiting for the alerts to leave Prometheus and both [RESOLVED] messages (max ${NTFY_WAIT}s)"
w=0
while :; do
  F="$(pq 'ALERTS{alertname=~"PFTSSHCrypto.*"}')"
  M="$(topic_msgs "$ALERT")"
  rv="$(n_msgs '[RESOLVED] PFTSSHCryptoFailGrade' validator)"; rs="$(n_msgs '[RESOLVED] PFTSSHCryptoFailGrade' sentry)"
  { [ -z "$F" ] && [ "$rv" -ge 1 ] && [ "$rs" -ge 1 ]; } && break
  w=$((w + 15)); [ "$w" -le "$NTFY_WAIT" ] || break; sleep 15
done
check "4f no PFTSSHCrypto* alert left in Prometheus" "$([ -z "$F" ] && echo 0 || echo 1)" "$(grep -c . <<<"${F:-}") alert(s)"
check "4g [RESOLVED] PFTSSHCryptoFailGrade for validator and sentry delivered" "$([ "$rv" -ge 1 ] && [ "$rs" -ge 1 ] && echo 0 || echo 1)" "validator $rv, sentry $rs"
echo "  fix to resolved took $(( $(date -u +%s) - t_fix ))s"
x "pq 'max_over_time(ALERTS{alertname=\"PFTSSHCryptoFailGrade\",alertstate=\"firing\"}[30m])'"

echo; echo "== 5. restore, read back"
restore
check "bridge back on the operator env file" "$([ "$RESTORE_OK" = true ] && echo 0 || echo 1)"
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
for h in relay local; do
  if [ "$h" = relay ]; then c=postfiatd-sentry; else c=postfiatd; fi
  s="$(node_state "$h" "$c")"
  check "$c full at the end" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)" "$s"
done
echo; echo "live-alert-drill done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
