#!/usr/bin/env bash
# live-values: record the current live pft-upgradewatch values for both nodes (read-only).
#   bash upgradewatch/drill/live-values.sh 2>&1 | tee LOG    (as the agent user, from the repo root; uses sudo -n, `ssh relay`)
# Shows: timers on both hosts, the last collector run on each host, the validator's textfile for each node (the
# sentry's arrives through the pull timer), the same values as Prometheus serves them, and the upgradewatch alert
# state. Changes nothing.
# Env: RELAY (relay)  PROM (http://127.0.0.1:9090)
set -u
export TZ=UTC  # timestamps in UTC on both hosts
RELAY="${RELAY:-relay}"; PROM="${PROM:-http://127.0.0.1:9090}"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
x() { echo "\$ $*"; eval "$*" 2>&1 | sed -E "s#$HOME#~#g; s/^/  /"; echo "  (exit ${PIPESTATUS[0]})"; }
pq() {
  curl -fsS --max-time 20 "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '.data.result[] | "\(.metric | del(.__name__) | to_entries | map("\(.key)=\(.value)") | join(",")) \(.value[1])"'
}

echo "pft-upgradewatch live values - $(date -u +%FT%TZ) - $(lsb_release -ds)"
echo "installed: validator $(sudo -n pft-upgradewatch version) | sentry $(R "sudo -n pft-upgradewatch version")"
echo; echo "== timers and last runs"
x "systemctl list-timers --no-pager 'pft-upgradewatch*' | sed -E 's/ +/ /g'"
x "R \"TZ=UTC systemctl list-timers --no-pager 'pft-upgradewatch*' | sed -E 's/ +/ /g'\""
x "systemctl show -p Result -p ExecMainStatus pft-upgradewatch@postfiatd.service pft-upgradewatch-pull@postfiatd-sentry.service"
x "R 'systemctl show -p Result -p ExecMainStatus pft-upgradewatch@postfiatd-sentry.service'"
echo; echo "== textfiles on the validator (sentry: pulled copy)"
for c in postfiatd postfiatd-sentry; do
  x "grep -v '^#' $TF/pft_upgradewatch_$c.prom"
  echo "  age: $(( $(date +%s) - $(stat -c %Y "$TF/pft_upgradewatch_$c.prom") )) s"
done
echo; echo "== as served by Prometheus"
for q in pft_upgradewatch_up pft_upgradewatch_amendment_blocked 'pft_upgradewatch_majority_amendments' \
  pft_upgradewatch_unsupported_activation_eta_seconds pft_upgradewatch_majority_time_seconds \
  pft_upgradewatch_build_info pft_upgradewatch_foundation_build_info pft_upgradewatch_behind_foundation \
  pft_upgradewatch_peers_versioned pft_upgradewatch_peers_newer_ratio \
  'time() - pft_upgradewatch_collect_timestamp_seconds'; do
  echo "\$ query $q"; pq "$q" | sed 's/^/  /'
done
echo; echo "== upgradewatch alerts (pending or firing)"
n="$(pq 'ALERTS{alertname=~"PFTAmendmentBlocked|PFTUnsupportedAmendment.*|PFTNodeVersionLag|PFTUpgradewatchStale"}' | grep -c .)"
echo "  $n"
echo; echo "live-values done $(date -u +%FT%TZ)"
