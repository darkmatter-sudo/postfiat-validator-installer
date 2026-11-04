#!/usr/bin/env bash
# crondaily-probe: before/after proof for the cron.daily profile gap (2026-11-04 06:25Z DENIED on both hosts).
# Loads OLD and NEW profile files under throwaway names (pft-aa-probe-old / pft-aa-probe-new), and for each runs a
# throwaway container from the live container's image with its confine arguments (cap_drop ALL + SETGID SETUID,
# read-only root, no-new-privileges, noexec tmpfs; --network none, no volumes) that executes the container's real
# cron.daily line (`cd / && run-parts --report /etc/cron.daily`, as /etc/crontab does). Then it counts the DENIED
# records each probe profile wrote. The live container and the live pft-postfiatd profile are not touched.
#   sudo bash crondaily-probe.sh OLD_PROFILE NEW_PROFILE [CONTAINER]
# Expect: OLD writes the apt-compat exec denials and logrotate's open of / (its daily job fails: the gap reproduced);
# NEW writes 0, refuses apt-compat's exec, and every other job (dpkg, logrotate) exits 0.
# The container command uses only binaries the profile allows (sh, run-parts), so the probe itself adds no denial.
# Exit 0 only if both expectations hold; probe profiles and containers are always removed.
# shellcheck disable=SC2016
set -uo pipefail
OLD="${1:-}"; NEW="${2:-}"; C="${3:-postfiatd}"
if [ ! -r "$OLD" ] || [ ! -r "$NEW" ]; then echo "usage: crondaily-probe.sh OLD_PROFILE NEW_PROFILE [CONTAINER]" >&2; exit 3; fi
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 3; }
FAILS=0; T="$(mktemp -d /var/lib/pft-aa-probe.XXXXXX)"
cleanup() {
  local n
  for n in old new; do
    docker rm -f "pft-aa-probe-$n" >/dev/null 2>&1
    [ -f "$T/pft-aa-probe-$n" ] && apparmor_parser -R "$T/pft-aa-probe-$n" >/dev/null 2>&1
  done
  rm -rf "$T"
}
trap cleanup EXIT
check() { if [ "$1" = 0 ]; then echo "CHECK PASS $2"; else echo "CHECK FAIL $2"; FAILS=$((FAILS + 1)); fi; }
denied() { # PROFILE SINCE_EPOCH -> DENIED records (operation name comm), one per line
  cat /var/log/audit/audit.log* 2>/dev/null | awk -v p="profile=\"$1\"" -v t="$2" '
    index($0, "apparmor=\"DENIED\"") && index($0, p) && match($0, /audit\([0-9]+/) && substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0' |
    sed -E 's/.* (operation="[^"]*").* (name="[^"]*").* (comm="[^"]*").*/\1 \2 \3/' | sort | uniq -c
}

echo "== crondaily-probe $(date -u +%FT%TZ) on $(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release)"
IMG="$(docker inspect "$C" --format '{{.Config.Image}}')" || { echo "container $C not found" >&2; exit 2; }
echo "image: $IMG"
echo "live container profile: $(docker inspect "$C" --format '{{.AppArmorProfile}}')"
echo "old profile sha256: $(sha256sum < "$OLD" | cut -c1-64)"
echo "new profile sha256: $(sha256sum < "$NEW" | cut -c1-64)"
echo "-- diff old -> new"; diff "$OLD" "$NEW"
echo "-- container's cron.daily line and jobs"
docker exec "$C" sh -c 'grep -E "cron\.daily" /etc/crontab; ls -1 /etc/cron.daily'

for n in old new; do
  src="$OLD"; [ "$n" = new ] && src="$NEW"
  p="pft-aa-probe-$n"
  sed -E "s/\bpft-postfiatd\b/$p/g" "$src" > "$T/$p"
  apparmor_parser -r -W "$T/$p"; check $? "$n: probe profile $p loaded"
  t0="$(date +%s)"; sleep 1
  echo "-- $n: run-parts cron.daily in a throwaway container under $p (since $t0)"
  timeout 300 docker run --name "$p" --rm --network none --user 0:0 --entrypoint /bin/sh \
    --security-opt "apparmor=$p" --security-opt no-new-privileges:true \
    --cap-drop ALL --cap-add SETGID --cap-add SETUID --read-only --pids-limit 256 --memory 512m \
    --tmpfs /run:rw,noexec,nosuid,size=64m --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --tmpfs /var/backups:rw,noexec,nosuid,size=64m --tmpfs /var/lib/apt:rw,noexec,nosuid,size=64m \
    --tmpfs /var/lib/logrotate:rw,noexec,nosuid,size=64m --tmpfs /var/log/postfiatd:rw,noexec,nosuid,size=64m \
    "$IMG" -c 'cd / && run-parts --report /etc/cron.daily; echo "run-parts exit $?"' > "$T/$n.out" 2>&1
  cat "$T/$n.out"
  sleep 3
  echo "-- $n: DENIED records for $p"
  D="$(denied "$p" "$t0")"; echo "${D:-(none)}"
  if [ "$n" = old ]; then
    grep -q 'operation="exec".*comm="apt-compat"' <<<"$D"; check $? "old: apt-compat exec denials reproduced (the 06:25Z gap)"
    grep -q 'operation="open" name="/" comm="logrotate"' <<<"$D" && grep -q 'logrotate exited with return code' "$T/$n.out"
    check $? "old: logrotate's open of / denied and the daily logrotate job failed (reproduced)"
  else
    [ -z "$D" ]; check $? "new: 0 DENIED records"
    grep -q 'failed to exec /etc/cron.daily/apt-compat: Permission denied' "$T/$n.out"; check $? "new: apt-compat refused before it runs anything"
    ! grep -E 'exited with return code' "$T/$n.out" | grep -v '/etc/cron.daily/apt-compat exited'; check $? "new: every other cron.daily job (dpkg, logrotate) exited 0"
  fi
  apparmor_parser -R "$T/$p"; check $? "$n: probe profile $p unloaded"
done
grep -q 'pft-aa-probe' /sys/kernel/security/apparmor/profiles; [ $? = 1 ]; check $? "no probe profile left loaded"
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed"
[ "$FAILS" = 0 ]
