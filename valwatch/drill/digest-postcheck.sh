#!/usr/bin/env bash
# Read-only post-check of the digest install (changes nothing): re-runs digest-install-run.sh's step-6 jobwatch check
# with the fixed pattern (log 19's pattern `digest` also matched pft-authwatch-digest.timer: 6 lines, not 3) and the
# installed end state.   bash valwatch/drill/digest-postcheck.sh 2>&1 | tee LOG   (repo root, agent user)
set -uo pipefail
export TZ=UTC
U=pft-valwatch-digest; TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
XRC=0; XOUT=""
x() { echo "\$ $*"; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; FAILS=$((FAILS + 1)); fi; }
echo "valwatch digest post-check - $(date -u +%FT%TZ) - repo HEAD $(git rev-parse HEAD)"
x "sudo -n pft-jobwatch inventory 2>&1 | grep -E 'valwatch-digest' | cut -c1-200; sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\\{.*valwatch-digest' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees $U.timer (86400 s): not failed, missed or disabled; textfile under 61440" "$([ "$(grep -cE 'valwatch-digest.* 0$' <<<"$XOUT")" = 3 ] && grep -qE "^$U\.timer\s+calendar\s+86400\s" <<<"$XOUT" && [ "$(tail -1 <<<"$XOUT")" -le 61440 ] && echo 0 || echo 1)"
x "systemctl is-enabled $U.timer; systemctl is-active $U.timer; systemctl show -p NextElapseUSecRealtime $U.timer; systemctl show -p DropInPaths -p Result $U.service; sudo -n ls /var/lib/pft-valwatch/digest-last /var/lib/pft-valwatch/digest-drill /run/pft-valwatch-drill.env 2>&1 | grep -c 'No such file'"
check "timer enabled + active, next $(date -u -d tomorrow +%F) 07:05 UTC, no drop-in, no real or drill stamp, no drill env" "$(grep -qx enabled <<<"$XOUT" && grep -qx active <<<"$XOUT" && grep -q "NextElapseUSecRealtime=.* $(date -u -d tomorrow +%F) 07:05:00 UTC" <<<"$XOUT" && grep -qx 'DropInPaths=' <<<"$XOUT" && [ "$(tail -1 <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit both hosts: 0 unexpected, 0 new/removed" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E '^SUMMARY'"
check "pft-fleet: every add-on CURRENT on both hosts" "$(grep -q '^SUMMARY CURRENT=[0-9]* BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0' <<<"$XOUT" && echo 0 || echo 1)"
echo "digest-postcheck done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
