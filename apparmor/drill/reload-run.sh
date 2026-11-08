#!/usr/bin/env bash
# reload-run: recorded in-place update of the live pft-postfiatd profile (no container re-create, no node restart).
# apparmor_parser -r replaces a loaded profile atomically and the running container's processes move to the new
# rules, so a rules-only change (here: the cron.daily fix) does not need `apply` (which re-creates the container).
#   sudo [REASON=TEXT] [ACK_REASON=TEXT] bash reload-run.sh NEW_PROFILE HOSTLABEL TASK_REF [CONTAINER]
# REASON: the pft-integrity accept text after TASK_REF (default: the 2026-11-04 cron.daily fix). ACK_REASON: if set,
# `pft-apparmor ack-denials` up to the reload time runs before the final audit (the records the fix is for).
# Steps: preflight (container under pft-postfiatd enforce, node full, NEW compiles and defines pft-postfiatd) ->
# back up /etc/apparmor.d/pft-postfiatd -> install NEW 0644 root -> apparmor_parser -r -W -> checks (file sha = NEW,
# container still pft-postfiatd enforce, same container ID and start time, node full) -> pft-integrity accept with
# TASK_REF -> pft-apparmor audit. A failed reload restores the backup and reloads it (exit 1).
set -uo pipefail
NEW="${1:-}"; HL="${2:-}"; REF="${3:-}"; C="${4:-postfiatd}"; P=pft-postfiatd; DST="/etc/apparmor.d/$P"
if [ ! -r "$NEW" ] || [ -z "$HL" ] || [ -z "$REF" ]; then echo "usage: reload-run.sh NEW_PROFILE HOSTLABEL TASK_REF [CONTAINER]" >&2; exit 3; fi
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 3; }
FAILS=0
check() { if [ "$1" = 0 ]; then echo "CHECK PASS $2"; else echo "CHECK FAIL $2"; FAILS=$((FAILS + 1)); fi; }
state() { docker inspect "$C" --format '{{.Id}} {{.State.StartedAt}} {{.AppArmorProfile}}'; }
mode() { sed -n "s/^$P (\(.*\))$/\1/p" /sys/kernel/security/apparmor/profiles; }
full() { docker exec "$C" sh -c 'curl -s -m 10 -d "{\"method\":\"server_info\"}" http://127.0.0.1:5005/' | grep -q '"server_state" *: *"full"'; }

echo "== reload-run $HL $(date -u +%FT%TZ) on $(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release)"
before="$(state)"; echo "container before: ${before:0:12} ${before#* }"
[ "${before##* }" = "$P" ] && [ "$(mode)" = enforce ]; check $? "preflight: $C runs under $P (enforce)"
full; check $? "preflight: server_state full"
grep -q "^profile $P " "$NEW" && apparmor_parser -Q -K "$NEW"; check $? "preflight: new profile defines $P and compiles"
echo "installed sha256: $(sha256sum < "$DST" | cut -c1-64)"
echo "new       sha256: $(sha256sum < "$NEW" | cut -c1-64)"
echo "-- diff installed -> new"; diff "$DST" "$NEW"
[ "$FAILS" = 0 ] || { echo "RESULT: FAIL - preflight, nothing changed"; exit 1; }

BAK="$DST.bak-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p /var/lib/pft-apparmor/reload-backups; BAK="/var/lib/pft-apparmor/reload-backups/${BAK##*/}"
t_reload="$(date +%s)"
cp -p "$DST" "$BAK" && install -m 0644 -o root -g root "$NEW" "$DST" && apparmor_parser -r -W "$DST"
rc=$?; check "$rc" "install + apparmor_parser -r -W (backup ${BAK##*/})"
if [ "$rc" != 0 ]; then
  install -m 0644 -o root -g root "$BAK" "$DST" && apparmor_parser -r -W "$DST"; echo "restored backup: rc $?"
  echo "RESULT: FAIL - reload failed, previous profile restored"; exit 1
fi
sleep 5
[ "$(sha256sum < "$DST" | cut -c1-64)" = "$(sha256sum < "$NEW" | cut -c1-64)" ]; check $? "installed file = new profile"
after="$(state)"; echo "container after:  ${after:0:12} ${after#* }"
[ "$after" = "$before" ]; check $? "same container ID + start time, still $P (no re-create, no restart)"
[ "$(mode)" = enforce ]; check $? "$P loaded in enforce mode"
full; check $? "server_state full"
pft-integrity accept --reason "$REF: ${REASON:-pft-postfiatd AppArmor profile reloaded (cron.daily: quiet deny apt-compat, allow / r)}" | tail -2
check "${PIPESTATUS[0]}" "pft-integrity accept"
pft-integrity verify | tail -1; check "${PIPESTATUS[0]}" "pft-integrity verify after accept"
if [ -n "${ACK_REASON:-}" ]; then
  echo "-- pft-apparmor ack-denials (records up to the reload: the gap this profile fixes)"
  pft-apparmor ack-denials --reason "$REF: $ACK_REASON" --until "$t_reload" --yes; check $? "pft-apparmor ack-denials"
fi
echo "-- pft-apparmor audit"; pft-apparmor audit; check $? "pft-apparmor audit exit 0"
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed"
[ "$FAILS" = 0 ]
