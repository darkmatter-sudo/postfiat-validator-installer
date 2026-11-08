#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Read-only re-verification of the installed backupwatch on both hosts (task_e65845e5a1921cf388ffb4d25035676e, step 4),
# with install-run.sh's corrected fleet-skew check (run 11's only FAIL: it expected a sentry row for the
# validator-only fleet add-on). Changes nothing: no window, no silence, no notifier touched, no unit started except
# the read-only `check --offhost` (CLI) and `serve verify`.
#   bash backupwatch/drill/verify-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
PROM=http://127.0.0.1:9090; AM=http://127.0.0.1:9093
ME="$(id -un)"; HN="$(hostname)"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#age1[a-z0-9]{58}#<age-recipient>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
echo "backupwatch two-host re-verify - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
x "sha256sum backupwatch/drill/verify-run.sh backupwatch/pft-backupwatch.sh backupwatch/backupwatch_lib.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-backupwatch /usr/local/lib/pft-backupwatch/backupwatch_lib.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-backupwatch /usr/local/lib/pft-backupwatch/backupwatch_lib.py | cut -c1-64'"
check "installed script + helper = repo bytes on both hosts" "$([ "$(sed 1d <<<"$XOUT" | sort | uniq -c | awk '$1 == 3' | wc -l)" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, backupwatch CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +backupwatch +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-backupwatch check --offhost"
check "validator check --offhost: every check OK, exit 0" "$([ "$XRC" = 0 ] && grep -q '^RESULT: OK' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n tail -1 /var/lib/pft-backupwatch/replica.tsv | cut -f1-3"
RNAME="$(awk '{print $1}' <<<"$XOUT")"; RCS="$(awk '{print $2}' <<<"$XOUT")"
x "R 'cd /var/lib/pft-backupwatch/replicas && sha256sum *.age && pft-backupwatch serve verify $RNAME'"
check "sentry: ciphertext sha256 == the validator's record, serve verify OK" "$([ -n "$RCS" ] && grep -q "^$RCS  $RNAME.age$" <<<"$XOUT" && grep -q "^VERIFY $RNAME OK" <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-active pft-backupwatch.timer pft-backupwatch-pull.timer pft-backupwatch-replicate.timer; R 'systemctl is-active pft-backupwatch.timer'; systemctl is-failed pft-backupwatch.service pft-backupwatch-pull.service pft-backupwatch-replicate.service; R 'systemctl is-failed pft-backupwatch.service'"
check "4 timers active, no backupwatch unit failed" "$([ "$(grep -cx active <<<"$XOUT")" = 4 ] && ! grep -qx failed <<<"$XOUT" && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_backupwatch_(up|check_state|replica_verify_ok|replicas|drift_overdue)\"}' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.__name__) \(.metric.check // \"-\") \(.value[1])\"' | sort"
check "Prometheus: up 1 both hosts, 7 validator check states 0, drift_overdue 0, sentry replicas 1 + verify_ok 1" "$([ "$(grep -cE ' pft_backupwatch_up - 1$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^validator pft_backupwatch_check_state [a-z]+ 0$' <<<"$XOUT")" = 7 ] && grep -q '^validator pft_backupwatch_drift_overdue - 0$' <<<"$XOUT" && grep -q '^sentry pft_backupwatch_replicas - 1$' <<<"$XOUT" && grep -q '^sentry pft_backupwatch_replica_verify_ok - 1$' <<<"$XOUT" && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name | test(\"backupwatch\")) | .rules[] | [.name, .health, .state] | @tsv'; curl -s $AM/api/v2/alerts | jq -r '.[].labels.alertname' | sort | uniq -c"
check "5 backupwatch rules ok + inactive; Alertmanager holds only the pipeline watchdog" "$([ "$(grep -cE '	ok	inactive$' <<<"$XOUT")" = 5 ] && [ "$(grep -E '^ +[0-9]+ ' <<<"$XOUT" | grep -vc PFTAlertPipelineWatchdog)" = 0 ] && echo 0 || echo 1)"
echo; echo "verify-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
