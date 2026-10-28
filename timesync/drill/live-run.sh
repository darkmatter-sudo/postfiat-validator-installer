#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034  # v() conditions are eval'd on purpose; H0 is read inside them
# Live two-step proof on ONE host (run as root on that host; the installed /usr/local/sbin/pft-timesync is used):
#   1. injected failure: PFT_TIMESYNC_INJECT=unreachable apply (TEST-NET-1 sources, never reachable, no traffic to
#      anyone) must miss the sync gate and roll back automatically: exit 1, timesyncd.conf sha256 as before, no chrony
#      files/package, timesyncd package + daemon back.
#   2. real apply: exit 0, audit OK.
# Throughout: postfiatd's StartedAt unchanged and server_state full (the tool never touches the container).
# Usage: sudo bash live-run.sh ROLE        ROLE = validator | sentry (label only)   Env: INJ_BUDGET (120)
set -uo pipefail
ROLE="${1:?role}"; T=/usr/local/sbin/pft-timesync; INJ_BUDGET="${INJ_BUDGET:-120}"
c=postfiatd; docker inspect postfiatd >/dev/null 2>&1 || c=postfiatd-sentry
st() { docker inspect -f '{{.State.StartedAt}}' "$c"; }
ss_() { docker exec "$c" sh -c 'curl -s -m 5 -d "{\"method\":\"server_info\"}" http://127.0.0.1:5005/' | jq -r '.result.info.server_state'; }
facts() { echo "  timesyncd.conf sha256 $(sha256sum /etc/systemd/timesyncd.conf | cut -c1-64)"
  echo "  chrony.conf $( [ -e /etc/chrony/chrony.conf ] && echo present || echo absent), drop-in $( [ -e /etc/systemd/system/chrony.service.d/50-pft-timesync.conf ] && echo present || echo absent)"
  echo "  packages: $(dpkg-query -W -f '${Package}=${db:Status-Status}/${Version} ' chrony systemd-timesyncd 2>/dev/null)"
  echo "  active: chrony=$(systemctl is-active chrony) systemd-timesyncd=$(systemctl is-active systemd-timesyncd); NTPSynchronized=$(timedatectl show -p NTPSynchronized --value)"
  echo "  $c StartedAt $(st), server_state $(ss_)"; }
echo "# pft-timesync live run ($ROLE) $(date -u +%FT%TZ)"; head -1 /etc/os-release
echo "tool $T sha256 $(sha256sum "$T" | cut -c1-64)"
S0="$(st)"; H0="$(sha256sum /etc/systemd/timesyncd.conf | cut -c1-64)"; L0="$(wc -l < /var/log/dpkg.log)"
echo "== 0. before"; facts
echo "== 1. injected failure: PFT_TIMESYNC_INJECT=unreachable SYNC_BUDGET=$INJ_BUDGET pft-timesync apply --yes"
PFT_TIMESYNC_INJECT=unreachable SYNC_BUDGET="$INJ_BUDGET" "$T" apply --yes; R1=$?
echo "apply (injected) exit $R1"; facts; H1="$(sha256sum /etc/systemd/timesyncd.conf | cut -c1-64)"
echo "== 2. real apply: pft-timesync apply --yes"
"$T" apply --yes; R2=$?
echo "apply exit $R2"; facts
echo "== dpkg.log lines written during this run (chrony / systemd-timesyncd)"
tail -n +"$((L0 + 1))" /var/log/dpkg.log | grep -E ' (install|remove|purge|status installed|status not-installed) (chrony|systemd-timesyncd)' | awk '{$1=$2=""; sub(/^ +/, ""); print "  " $0}'   # dpkg.log stamps are local time: dropped
echo "== verdict"
v() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; F=1; fi; }; F=0
v "injected apply exit 1 (automatic rollback)" '[ "$R1" = 1 ]'
v "timesyncd.conf byte-identical after rollback ($H1)" '[ "$H1" = "$H0" ]'
v "real apply exit 0" '[ "$R2" = 0 ]'
v "postfiatd StartedAt unchanged through both steps ($S0)" '[ "$(st)" = "$S0" ]'
v "server_state full at the end" '[ "$(ss_)" = full ]'
v "chrony active, timesyncd inactive at the end" '[ "$(systemctl is-active chrony)" = active ] && [ "$(systemctl is-active systemd-timesyncd)" != active ]'
echo "RESULT: $([ "$F" = 0 ] && echo PASS || echo FAIL) $(date -u +%FT%TZ)"
exit "$F"
