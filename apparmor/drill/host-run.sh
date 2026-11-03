#!/usr/bin/env bash
# host-run: the recorded per-host part of the pft-apparmor live proof. Run as root on the host, inside the pft-maint
# window that live-run.sh opened (apply/rollback refuse without one), with pft-apparmor installed:
#   sudo bash host-run.sh sentry --drill --learn EVENTS --out-profile FILE [--complain-min N]
#   sudo bash host-run.sh validator --profile FILE
# sentry --drill:
#   0 before: audit (container docker-default -> exit 1), node full
#   1 generate P0 from the throwaway learn events; apparmor_parser -Q -K
#   2 automatic rollback drill: apply P0 with PFT_AA_INJECT=health (gate fails on purpose) -> exit 1, back on
#     docker-default, node full
#   3 bounded complain window on the live sentry: apply P0 --complain, wait N min (default 20), collect the ALLOWED
#     events, explicit rollback; then generate P1 from learn + complain events (generate refuses any allow that
#     overlaps an explicit deny), compile, diff P0 -> P1
#   4 apply P1 (enforce) -> PASS
#   5 after: positive controls (0 DENIED), negative controls (each must fail AND log a matching DENIED record, or be
#     reported as blocked by an earlier layer when that is the design), ack-denials, audit PASS
#   6 enforced restart: docker restart -> same profile, enforce, full, 0 DENIED since the restart
#   7 explicit rollback -> docker-default, full; re-apply P1 -> PASS; audit PASS
#   5b host add-ons that docker exec into the node, run by hand under the profile; then one real
#      pft-retention-sample.timer tick (validator) with the DENIED gate open; audit PASS
# validator: 0, 4 (with the merged profile), 5, 5b, 6.
# Exit 0 only if every check passed. Never edits postfiatd.cfg: the volume-write control creates a new file name.
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later (they read rc, before, ...); A && B || C only reports
set -uo pipefail
HOST="${1:-}"; shift || true
DRILL=0; LEARN=""; OUTP=""; PROF=""; CMIN=20
while [ $# -gt 0 ]; do
  case "$1" in
    --drill) DRILL=1 ;;
    --learn) LEARN="${2:-}"; shift ;;
    --out-profile) OUTP="${2:-}"; shift ;;
    --profile) PROF="${2:-}"; shift ;;
    --complain-min) CMIN="${2:-}"; [[ "$CMIN" =~ ^[0-9]+$ ]] || { echo "bad --complain-min" >&2; exit 3; }; shift ;;
    *) echo "unknown argument $1" >&2; exit 3 ;;
  esac
  shift
done
case "$HOST" in sentry) C=postfiatd-sentry ;; validator) C=postfiatd ;; *) echo "usage: host-run.sh sentry|validator ..." >&2; exit 3 ;; esac
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 3; }
if [ "$DRILL" = 1 ]; then [ -r "$LEARN" ] && [ -n "$OUTP" ] || { echo "--drill needs --learn EVENTS and --out-profile FILE" >&2; exit 3; }
else [ -r "$PROF" ] || { echo "need --profile FILE" >&2; exit 3; }; fi
PA="${PA:-/usr/local/bin/pft-apparmor}"; P=pft-postfiatd
install -d -m 700 /var/lib/pft-apparmor && WD="$(mktemp -d /var/lib/pft-apparmor/hostrun.XXXXXX)" || exit 2
trap 'rm -rf "$WD"' EXIT
FAILS=0; NPASS=0
ts() { date -u +%FT%TZ; }
res() { if [ "$2" = 0 ]; then echo "PASS $1${3:+ ($3)}"; NPASS=$((NPASS + 1)); else echo "FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*"; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | sed 's/^/  /'; echo "  (exit $XRC)"; }
state() { docker exec "$C" curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
prof() { docker inspect -f '{{.AppArmorProfile}}' "$C" 2>/dev/null; }
kmode() { awk -v p="$P" '$1 == p { gsub(/[()]/, "", $2); print $2 }' /sys/kernel/security/apparmor/profiles; }
denied() { # SINCE_EPOCH [NAME] -> DENIED records for the profile since SINCE (optionally with name="NAME")
  cat /var/log/audit/audit.log* 2>/dev/null | awk -v t="$1" -v n="${2:-}" -v p="$P" '
    index($0, "apparmor=\"DENIED\"") && index($0, "profile=\"" p "\"") && (n == "" || index($0, "name=\"" n "\"")) {
      if (match($0, /audit\([0-9]+/) && substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0) c++ }
    END { print c + 0 }'
}
show_denied() { # SINCE NAME: the matching records, trimmed to the fields that matter
  cat /var/log/audit/audit.log* 2>/dev/null | grep -F 'apparmor="DENIED"' | grep -F "profile=\"$P\"" | grep -F "name=\"$2\"" \
    | awk -v t="$1" 'match($0, /audit\([0-9]+/) && substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0' \
    | grep -oE 'apparmor="[A-Z]+" operation="[^"]*" profile="[^"]*" name="[^"]*" .*requested_mask="[^"]*" denied_mask="[^"]*"' \
    | sed -E 's/ (pid|comm)=[^ ]*//g' | head -2 | sed 's/^/    /'
}
wait_full() { local i s; for ((i = 0; i < 90; i++)); do s="$(state)"; [ "$s" = full ] && break; sleep 10; done; echo "${s:-down}"; }
audit_json() { "$PA" audit --json --since "${1:-86400}" 2>/dev/null; }

echo "host-run $HOST - $(ts) - $(lsb_release -ds) - container $C"
echo "sha256: host-run.sh $(sha256sum < "$0" | cut -c1-64) pft-apparmor $(sha256sum < "$PA" | cut -c1-64)"
T_START="$(date +%s)"

echo; echo "== 0. before"
x "$PA audit; echo audit-exit=\$?"
res "before: container not under $P (docker-default or unconfined) -> audit FAIL" \
  "$(ok_if 'grep -qx "audit-exit=1" <<<"$XOUT" && grep -qE "\[FAIL\] container " <<<"$XOUT"')" "$(prof)"
s="$(state)"; res "before: $C server_state full" "$(ok_if '[ "$s" = full ]')" "$s"
[ "$FAILS" = 0 ] || { echo "RESULT: FAIL - $FAILS check(s) (stopped before any change)"; exit 1; }

if [ "$DRILL" = 1 ]; then
  echo; echo "== 1. generate P0 from the throwaway learn events"
  echo "  learn events: $(wc -l < "$LEARN") lines, sha256 $(sha256sum < "$LEARN" | cut -c1-64)"
  x "$PA generate --events '$LEARN' > '$WD/p0' && $PA check '$WD/p0' && sha256sum < '$WD/p0' | cut -c1-64; grep -c . '$WD/p0'"
  res "P0 generated and compiles (apparmor_parser -Q -K)" "$XRC"
  [ "$XRC" = 0 ] || { echo "RESULT: FAIL - P0 not usable"; exit 1; }

  echo; echo "== 2. automatic rollback drill: injected gate failure"
  t2="$(date +%s)"
  x "PFT_AA_INJECT=health HEALTH_BUDGET=600 $PA apply --profile-file '$WD/p0' --yes"
  res "injected gate failure -> apply exit 1 (automatic rollback)" \
    "$(ok_if '[ "$XRC" = 1 ] && grep -q "injected failure" <<<"$XOUT" && grep -q "rollback RESULT: PASS" <<<"$XOUT"')"
  s="$(wait_full)"; p="$(prof)"
  res "after the automatic rollback: back on docker-default, full, $P unloaded" \
    "$(ok_if '[ "$p" = docker-default ] && [ "$s" = full ] && [ -z "$(kmode)" ] && [ ! -e /etc/apparmor.d/$P ]')" "$p, $s"
  res "0 DENIED records during the drill" "$(ok_if '[ "$(denied "$t2")" = 0 ]')"

  echo; echo "== 3. bounded complain window on the live sentry ($CMIN min)"
  t3a="$(date +%s)"
  x "$PA apply --profile-file '$WD/p0' --complain --yes"
  res "apply P0 --complain -> PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "apply RESULT: PASS" <<<"$XOUT"')"
  if [ "$XRC" = 0 ]; then
    t3="$(date +%s)"; echo "  $(ts) complain window open (kernel: $P $(kmode)); T3=$t3"
    sleep $((CMIN * 60))
    x "docker exec $C sh -c 'cd / && run-parts --report /etc/cron.hourly'; docker exec $C ps -eo pid,comm"
    x "$PA events --since-epoch $t3a --profile $P > '$WD/complain.tsv'; wc -l < '$WD/complain.tsv'; cut -f1 '$WD/complain.tsv' | sort | uniq -c"
    res "complain events collected" "$XRC" "$(wc -l < "$WD/complain.tsv") distinct"
    echo "  complain-only events (not in the learn set):"
    comm -13 <(LC_ALL=C sort -u "$LEARN") <(LC_ALL=C sort -u "$WD/complain.tsv") | sed 's/^/    /' | head -40
    x "$PA rollback --yes"
    res "explicit rollback of the complain apply -> PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "rollback RESULT: PASS" <<<"$XOUT"')"
  fi
  LC_ALL=C sort -u "$LEARN" "$WD/complain.tsv" > "$WD/events.tsv" 2>/dev/null
  x "$PA generate --events '$WD/events.tsv' > '$WD/p1' && $PA check '$WD/p1' && sha256sum < '$WD/p1' | cut -c1-64"
  res "P1 generated from learn + complain events, compiles" "$XRC"
  x "diff '$WD/p0' '$WD/p1'"; echo "  (diff exit 0 = the complain window added nothing)"
  [ "$FAILS" = 0 ] || { echo "RESULT: FAIL - $FAILS check(s) before the enforce apply"; exit 1; }
  install -m 0644 "$WD/p1" "$OUTP" && cp "$WD/events.tsv" "$OUTP.events.tsv" && echo "  P1 -> $OUTP (events -> $OUTP.events.tsv)"
  PROF="$OUTP"
fi

echo; echo "== 4. apply (enforce)"
echo "  profile sha256 $(sha256sum < "$PROF" | cut -c1-64)"
x "$PA apply --profile-file '$PROF' --yes"
res "apply (enforce) -> PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "apply RESULT: PASS" <<<"$XOUT"')"
[ "$XRC" = 0 ] || { echo "RESULT: FAIL - apply did not pass (exit $XRC: 4 = refused, nothing changed; 1/6 = rolled back; 5 = rollback gate failed); nothing more to check"; exit 1; }

echo; echo "== 5. after: positive controls, negative controls, ack, audit"
p="$(prof)"; m="$(kmode)"; s="$(state)"
res "container under $P, kernel mode enforce, node full" "$(ok_if '[ "$p" = "$P" ] && [ "$m" = enforce ] && [ "$s" = full ]')" "$p, $m, $s"
x "docker inspect -f '{{.HostConfig.SecurityOpt}} RO={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} CapAdd={{.HostConfig.CapAdd}}' $C"
res "confine/ kept: no-new-privileges, read-only root, cap_drop ALL" \
  "$(ok_if 'grep -q no-new-privileges <<<"$XOUT" && grep -q "RO=true" <<<"$XOUT" && grep -q "CapDrop=\[ALL\]" <<<"$XOUT"')"
t5="$(date +%s)"
echo "-- positive controls (what the node needs)"
x "docker exec $C curl -s -m 10 -o /dev/null -w '%{http_code}' -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"
res "RPC server_info HTTP 200" "$(ok_if '[ "$XOUT" = 200 ]')"
x "docker exec $C curl -s -m 10 -d '{\"method\":\"peers\"}' http://127.0.0.1:5005 | jq '.result.peers | length'"
res "peers >= 1" "$(ok_if '[ "${XOUT:-0}" -ge 1 ] 2>/dev/null')" "$XOUT"
x "docker exec $C setpriv --reuid=0 --regid=0 --init-groups true"; res "cron identity switch (setpriv --init-groups)" "$XRC"
x "docker exec $C sh -c 'cd / && run-parts --report /etc/cron.hourly'"; res "run-parts /etc/cron.hourly" "$XRC"
x "docker exec $C logrotate -d -s /var/log/postfiatd/.logrotate.status /etc/logrotate.d/postfiatd 2>&1 | tail -3"; res "logrotate config check (-d, no rotation)" "$XRC"
x "docker exec $C ls /var/log/postfiatd /var/lib/postfiatd/db | wc -l"; res "list log + data dirs" "$XRC"
x "docker exec $C sh -c 'echo ok > /var/log/postfiatd/.pft-aa-probe && grep -x ok /var/log/postfiatd/.pft-aa-probe && rm /var/log/postfiatd/.pft-aa-probe'"
res "write + delete in the log volume" "$(ok_if '[ "$XRC" = 0 ] && [ "$XOUT" = ok ]')"
x "docker exec $C ps -eo pid,comm | head -8"; res "ps (ptrace read on the same profile)" "$XRC"
sleep 3
d="$(denied "$t5")"; res "0 DENIED records from the positive controls" "$(ok_if '[ "$d" = 0 ]')" "$d"
echo "-- negative controls (only the profile can block these: each must fail AND log a matching DENIED record)"
neg() { # LABEL PATH COMMAND
  local t; t="$(date +%s)"
  x "docker exec $C sh -c '$3'"
  local rc="$XRC"; sleep 2; local n; n="$(denied "$t" "$2")"
  echo "  DENIED records with name=\"$2\" since $t: $n"; show_denied "$t" "$2"
  res "negative: $1 (fails + DENIED logged)" "$(ok_if '[ "$rc" != 0 ] && [ "$n" -ge 1 ]')"
}
neg "write a NEW file in the /etc/postfiatd volume (rw mount)" /etc/postfiatd/pft-aa-probe ': > /etc/postfiatd/pft-aa-probe'
neg "read /etc/gshadow" /etc/gshadow 'grep -c . /etc/gshadow'
neg "exec an unlisted binary (/usr/bin/id)" /usr/bin/id '/usr/bin/id'
x "docker exec $C sh -c 'cp /etc/cron.daily/dpkg /var/log/postfiatd/.pft-aa-exec && stat -c %a /var/log/postfiatd/.pft-aa-exec'"
res "exec control setup: copy a 0755 cron.daily script into the log volume (read + write there are allowed; /bin/true is not readable under the profile, dev probe 17)" "$XRC"
neg "exec from the log volume (rw, exec-capable mount)" /var/log/postfiatd/.pft-aa-exec '/var/log/postfiatd/.pft-aa-exec'
x "docker exec $C rm -f /var/log/postfiatd/.pft-aa-exec; docker exec $C ls -a /etc/postfiatd /var/log/postfiatd | grep -c pft-aa-"
res "no probe file left (log volume cleaned, nothing created in /etc/postfiatd)" "$(ok_if '[ "$(tail -1 <<<"$XOUT")" = 0 ]')"
echo "-- blocked by an earlier layer (no AppArmor record expected; reported, not counted as AppArmor proof)"
x "docker exec $C sh -c 'echo x > /usr/bin/pft-aa-probe'"; res "write into /usr fails (read-only root, EROFS)" "$(ok_if '[ "$XRC" != 0 ]')"
x "docker exec $C sh -c 'cp /etc/cron.daily/dpkg /tmp/t && stat -c %a /tmp/t && /tmp/t'"; docker exec "$C" rm -f /tmp/t; res "exec from /tmp fails (noexec tmpfs)" "$(ok_if '[ "$XRC" != 0 ]')"
s="$(state)"; res "node still full after the controls" "$(ok_if '[ "$s" = full ]')" "$s"
x "$PA ack-denials --reason 'task_faf99695 live drill: deliberate negative controls on $HOST (gshadow, unlisted exec, volume write, volume exec)' --yes"
res "ack-denials for the deliberate records" "$XRC"
x "$PA audit; echo audit-exit=\$?"
res "audit after apply + ack: RESULT PASS" "$(ok_if 'grep -qx "audit-exit=0" <<<"$XOUT"')"

echo; echo "== 5b. host add-ons that docker exec into the node: run each by hand, then wait for a real retention tick"
# The sentry-learned P1 passed every control above on the validator, then blocked pft-retention sample 10 min later
# (live run 26). So every installed unit that execs into the node runs here under the enforced profile, and the
# DENIED gate stays open across one real pft-retention-sample.timer tick (every 10 min) where that timer exists.
t5b="$(date +%s)"
for u in pft-retention-sample.service "pft-statewatch@$C.service" "pft-feewatch@$C.service" "pft-upgradewatch@$C.service" \
         pft-mounts.service pft-timesync.service pft-divergence.service postfiat-monitor.service \
         "pft-egress-reapply@$C.service" pft-maint-tick.service; do
  systemctl cat "$u" >/dev/null 2>&1 || { echo "  $u: not installed on this host, skipped"; continue; }
  x "systemctl start $u; systemctl show -p Result --value $u"
  res "add-on $u ran under the profile: Result=success" "$(ok_if '[ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = success ]')"
done
if [ -r /var/lib/pft-retention/samples.csv ]; then
  x "tail -1 /var/lib/pft-retention/samples.csv | cut -d, -f2,3,7,8,9"
  res "pft-retention sample read the store (nudb_bytes > 0, the field P1 zeroed)" \
    "$(ok_if '[ "$(tail -1 /var/lib/pft-retention/samples.csv | cut -d, -f7)" -gt 0 ] 2>/dev/null')"
fi
if systemctl cat pft-retention-sample.timer >/dev/null 2>&1; then
  inv0="$(systemctl show -p InvocationID --value pft-retention-sample.service)"
  echo "  $(ts) waiting for the next real pft-retention-sample.timer tick (InvocationID changes and the run ends), up to 12 min"
  inv=""; for ((i = 0; i < 72; i++)); do
    inv="$(systemctl show -p InvocationID --value pft-retention-sample.service)"
    [ "$inv" != "$inv0" ] && [ "$(systemctl show -p ActiveState --value pft-retention-sample.service)" != activating ] && break
    sleep 10
  done
  x "TZ=UTC systemctl show -p Result -p ExecMainExitTimestamp pft-retention-sample.service; tail -1 /var/lib/pft-retention/samples.csv | cut -d, -f2,3,7"
  res "a real timer tick ran under the profile: new invocation, Result=success, nudb_bytes > 0" \
    "$(ok_if '[ "$inv" != "$inv0" ] && grep -qx "Result=success" <<<"$XOUT" && [ "$(tail -1 /var/lib/pft-retention/samples.csv | cut -d, -f7)" -gt 0 ] 2>/dev/null')"
fi
sleep 3; d="$(denied "$t5b")"; res "0 DENIED records from the add-ons and the timer tick" "$(ok_if '[ "$d" = 0 ]')" "$d"
x "$PA audit; echo audit-exit=\$?"
res "audit after the add-on runs: RESULT PASS" "$(ok_if 'grep -qx "audit-exit=0" <<<"$XOUT"')"

echo; echo "== 6. enforced restart"
t6="$(date +%s)"; before="$(docker inspect -f '{{.State.StartedAt}}' "$C")"
x "docker restart -t 60 $C"
s="$(wait_full)"; p="$(prof)"; m="$(kmode)"; after="$(docker inspect -f '{{.State.StartedAt}}' "$C")"
res "restarted (StartedAt changed), still under $P enforce, full" \
  "$(ok_if '[ "$before" != "$after" ] && [ "$p" = "$P" ] && [ "$m" = enforce ] && [ "$s" = full ]')" "$p, $m, $s"
x "docker exec $C ps -eo pid,comm | grep -c postfiatd"; res "postfiatd running" "$XRC"
sleep 5; d="$(denied "$t6")"; res "0 DENIED records since the restart" "$(ok_if '[ "$d" = 0 ]')" "$d"

if [ "$DRILL" = 1 ]; then
  echo; echo "== 7. explicit rollback, then re-apply"
  x "$PA rollback --yes"
  s="$(wait_full)"; p="$(prof)"
  res "rollback -> PASS, back on docker-default, full, $P unloaded" \
    "$(ok_if 'grep -q "rollback RESULT: PASS" <<<"$XOUT" && [ "$p" = docker-default ] && [ "$s" = full ] && [ -z "$(kmode)" ]')" "$p, $s"
  x "$PA audit | grep -E '\[FAIL\]|RESULT'"; res "audit after rollback shows the finding again" "$(ok_if 'grep -q "\[FAIL\] container" <<<"$XOUT"')"
  t7="$(date +%s)"
  x "$PA apply --profile-file '$PROF' --yes"
  res "re-apply (enforce) -> PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "apply RESULT: PASS" <<<"$XOUT"')"
  d="$(denied "$t7")"; res "0 DENIED records since the re-apply" "$(ok_if '[ "$d" = 0 ]')" "$d"
fi

echo; echo "== final"
x "$PA audit; echo audit-exit=\$?"
res "final audit RESULT PASS" "$(ok_if 'grep -qx "audit-exit=0" <<<"$XOUT"')"
x "ls /etc/apparmor.d/$P && sha256sum < /etc/apparmor.d/$P | cut -c1-64 && systemctl is-enabled apparmor.service"
echo "host-run $HOST done $(ts) ($(( $(date +%s) - T_START ))s): $NPASS PASS, $FAILS FAIL"
if [ "$FAILS" = 0 ]; then echo "RESULT: PASS"; exit 0; fi
echo "RESULT: FAIL - $FAILS check(s)"; exit 1
