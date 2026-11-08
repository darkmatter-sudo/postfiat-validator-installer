#!/usr/bin/env bash
# backupwatch/drill/backupfix-run.sh: recorded found -> fixed -> verified run for the first real backupwatch finding
# (log 01/02: timer-made pft-backup archives hold no firewall reference copy). Validator only (pft-backup runs there).
#  1. before: `pft-backupwatch check` (content WARN) and the unit's live sandbox properties
#  2. probe: pft-backup's two firewall commands under the OLD and NEW unitguard profile (unitguard/drill/probe.sh,
#     transient unit, nothing installed; only the first output line is printed, never the rules)
#  3. fix: `pft-unitguard apply pft-backup.service` (writes the drop-in, daemon-reload, runs one real backup, runs the
#     profile's check: newest archive has firewall/docker-user.rules and a ufw-status.txt that is not an error; rolls
#     back by itself on failure), then `pft-integrity accept` (integrity tracks drop-ins) + verify
#  4. after: `pft-backupwatch check` on the new archive: every check OK
# Run from the repo root as the agent user: bash backupwatch/drill/backupfix-run.sh > LOG 2>&1
export TZ=UTC
cd "$(dirname "$0")/../.." || exit 3
TASK=task_e65845e5
x() { echo "\$ $*"; eval "$*"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; FAILS=$((FAILS + 1)); fi; }
probe() { # PROFILE CMD -> probe.sh with output reduced to the first line
  sudo -n bash unitguard/drill/probe.sh "$1" -- sh -c "out=\$($2 2>&1); r=\$?; printf '%s\n' \"\$out\" | head -1 | cut -c1-80; exit \$r"
}
echo "OS: $(grep ^PRETTY_NAME= /etc/os-release | cut -d= -f2- | tr -d '"')"
echo "date: $(date -u +%FT%TZ)  commit: $(git rev-parse HEAD)  dirty: $(git status --short | wc -l)"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
x "sha256sum backupwatch/pft-backupwatch.sh backupwatch/backupwatch_lib.py backupwatch/drill/backupfix-run.sh unitguard/pft-unitguard.sh unitguard/profiles/pft-backup.service.conf"
BW="sudo -n PFT_BW_HELPER=backupwatch/backupwatch_lib.py bash backupwatch/pft-backupwatch.sh check"

echo; echo "== 1. before"
x "$BW"; [ $? = 1 ]; check "before: check exit 1 (WARN)" $?
x "systemctl show pft-backup.service -p CapabilityBoundingSet -p RestrictAddressFamilies -p ReadWritePaths"
x "sudo -n pft-integrity verify | tail -1"; check "before: pft-integrity PASS" $?

echo; echo "== 2. probe: firewall commands under the old (HEAD~ drop-in, as installed) and new profile"
OLD="$(mktemp)"; trap 'rm -f "$OLD"' EXIT
sed -n '/^\[Service\]/,$p' /etc/systemd/system/pft-backup.service.d/50-unitguard.conf > "$OLD"
x "diff <(sed -n '/^\[Service\]/,\$p' unitguard/profiles/pft-backup.service.conf) \"\$OLD\""
for c in 'ufw status verbose' 'iptables -S DOCKER-USER'; do
  echo "-- old (installed drop-in): $c"; probe "$OLD" "$c" | grep -v '^probe profile'; [ "${PIPESTATUS[0]}" = 1 ]
  check "old profile: '$c' fails" $?
  echo "-- new (repo profile): $c"; probe unitguard/profiles/pft-backup.service.conf "$c" | grep -v '^probe profile'; [ "${PIPESTATUS[0]}" = 0 ]
  check "new profile: '$c' works" $?
done

echo; echo "== 3. fix: unitguard apply (one real backup + the profile's check) + integrity accept"
x "sudo -n bash unitguard/pft-unitguard.sh apply pft-backup.service"; check "unitguard apply pft-backup.service exit 0" $?
x "systemctl show pft-backup.service -p CapabilityBoundingSet -p RestrictAddressFamilies -p ReadWritePaths -p Result"
x "sudo -n pft-integrity verify | grep -E 'WARN|FAIL|RESULT'"
x "sudo -n pft-integrity accept --reason '$TASK: unitguard pft-backup drop-in += CAP_NET_ADMIN CAP_NET_RAW AF_NETLINK (firewall reference copy)' | tail -1 | sed 's/ by .*//'"
check "pft-integrity accept" $?
x "sudo -n pft-integrity verify | tail -1"; check "pft-integrity PASS after accept" $?

echo; echo "== 4. after: the new archive"
x "sudo -n ls -1 /var/backups/postfiat | tail -4"
x "$BW"; check "after: check exit 0 (every check OK)" $?
x "sudo -n bash -c 'f=\$(ls -t /var/backups/postfiat/pft-backup-*.tar.gz | head -1); tar -tzf \"\$f\" | grep /firewall/ | sed \"s#^[^/]*/##\"'"
x "ls /dev/shm | grep -c '^pft-bw' || true"
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS failed"
[ "$FAILS" = 0 ]
