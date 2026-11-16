#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016
# shellcheck disable=SC2034  # shared helper block copied from install-run.sh; some of its variables are unused here
# install-tail: the step-12 checks that install-run.sh (log 03) did not reach, because the agent's tool time limit
# killed it in the alert-drain loop AFTER its restore had run (window ended, real target restored, keyescrow 0).
# Read-only. SINCE = the epoch install-run.sh started (operator topics are read back from then).
#   SINCE=EPOCH bash internals/drill/install-tail.sh 2>&1 | tee LOG
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-internals-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-internals
SWAPPED=0; MAINT=0; HAD=0
since="${SINCE:?set SINCE to the install start epoch}"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
trap 'rm -f "$OPS"' EXIT
srv_state() { # both nodes' server_state, validator first (same exec shape as selfheal/install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
tf_check() { # NAME BYTES SAMPLES valid, per textfile on the validator (local + pulled sentry copy)
  local n f
  for n in postfiatd postfiatd-sentry; do
    f="$TF/pft_internals_$n.prom"
    echo "$n $(stat -c %s "$f") $(grep -vc '^#' "$f") $(pft-internals validate "$f" "$n" >/dev/null && echo valid)"
  done
}
prom_check() { # series per container, then up / restarts / anomalies per container
  curl -s "$PROM/api/v1/query" --data-urlencode 'query=count by (container) ({__name__=~"pft_internals_.+"})' \
    | jq -r '.data.result[] | "\(.metric.container) \(.value[1])"' | sort
  curl -s "$PROM/api/v1/query" \
    --data-urlencode 'query={__name__=~"pft_internals_(up|node_restarts_total|counter_anomalies_total)"}' \
    | jq -r '.data.result[] | "\(.metric.container) \(.metric.__name__) \(.value[1])"' | sort
}
echo "internals install tail - $(date -u +%FT%TZ) - repo HEAD $SHA - reading back from $(date -u -d @"$since" +%FT%TZ)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"\(.createdBy) \(.matchers | map(.value) | join(\",\"))\"'"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"InternalsNodeStore|InternalsCache|InternalsJob|InternalsStale|RuleDead|TextfileStale|Rulecheck|Fleet|Aptrust|Sched|PFTJob|KeyEscrow|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no internals/rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow/confinement alert pending or firing (PFTInternalsCounterAnomaly excluded: known defect, own silence)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R 'ls -d ~/pft-internals-* 2>/dev/null | wc -l'"
check "no transient run-u services/timers, no install copy left on the sentry" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R 'ls -d ~/pft-internals-* 2>/dev/null | wc -l'; sudo -n pft-maint active; echo maint=\$?; sudo -n test -e /etc/pft-maint/ntfy.env.pre-internals; echo backup=\$?"
check "no transient units, no install copy on the sentry, no maint window, no ntfy.env backup left" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 maint=1 backup=1 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-tail done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
