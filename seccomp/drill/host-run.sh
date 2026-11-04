#!/usr/bin/env bash
# host-run: the recorded per-host part of the pft-seccomp live proof. Run as root on the host, inside the pft-maint
# window that live-run.sh opened (apply/rollback refuse without one), with pft-seccomp installed. Two phases, so that
# live-run.sh can run the PFTSeccompDenied FIRING -> RESOLVED drill between them (the negative controls' denials are
# what fires it; `post` acknowledges them):
#   sudo bash host-run.sh sentry|validator pre --profile FILE [--drill]
#   sudo bash host-run.sh sentry|validator post --profile FILE [--drill]
# pre:
#   0 before: audit (container on Docker's default -> exit 1), node full, init Seccomp 2 (Docker's default filter)
#   1 profile: check, canonical sha256 (= what Docker will store)
#   2 (--drill) automatic rollback drill: apply with PFT_SC_INJECT=health (gate fails on purpose) -> exit 1, previous
#     profile state restored (Docker's default, profile file removed), node full
#   3 apply -> PASS; docker inspect SecurityOpt (inline profile shown as its sha256) = canonical sha256 of FILE
#   4 positive controls (RPC, peers, cron identity switch, cron.hourly, logrotate -d, volumes, ps): 0 denials
#   5 negative controls: syscalls Docker's default allows and the tailored profile does not (symlinkat, linkat,
#     inotify_init): each must fail with EPERM ("Operation not permitted") AND leave a matching type=SECCOMP
#     errno record for this container's AppArmor label. The records stay unacknowledged (live-run's alert drill).
# post:
#   6 ack-denials for the negative controls, audit PASS
#   7 host add-ons that docker exec into the node, run by hand under the profile (+ one real pft-retention tick on
#     the validator); 0 denials
#   8 enforced restart: same stored profile, Seccomp 2, full, 0 denials since the restart
#   9 (--drill) explicit rollback -> Docker's default restored, audit shows the finding; re-apply -> PASS
#   final audit PASS
# Exit 0 only if every check passed. Probe files live in the container's /tmp tmpfs and are removed.
# shellcheck disable=SC2016,SC2034,SC2015  # ok_if conditions are evaluated later; A && B || C only reports
set -uo pipefail
HOST="${1:-}"; PHASE="${2:-}"; shift 2 2>/dev/null || true
DRILL=0; PROF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --drill) DRILL=1 ;;
    --profile) PROF="${2:-}"; shift ;;
    *) echo "unknown argument $1" >&2; exit 3 ;;
  esac
  shift
done
case "$HOST" in sentry) C=postfiatd-sentry ;; validator) C=postfiatd ;; *) echo "usage: host-run.sh sentry|validator pre|post --profile FILE [--drill]" >&2; exit 3 ;; esac
case "$PHASE" in pre|post) ;; *) echo "usage: host-run.sh sentry|validator pre|post --profile FILE [--drill]" >&2; exit 3 ;; esac
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 3; }
[ -r "$PROF" ] || { echo "need --profile FILE" >&2; exit 3; }
SC="${SC:-/usr/local/bin/pft-seccomp}"; HELPER=/usr/local/lib/pft-seccomp/pft_seccomp.py
PF=/etc/pft-seccomp/pft-postfiatd.json
FAILS=0; NPASS=0
ts() { date -u +%FT%TZ; }
res() { if [ "$2" = 0 ]; then echo "PASS $1${3:+ ($3)}"; NPASS=$((NPASS + 1)); else echo "FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok_if() { if eval "$1"; then echo 0; else echo 1; fi; }
XRC=0; XOUT=""
x() { echo "\$ $*"; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | sed 's/^/  /'; echo "  (exit $XRC)"; }
state() { docker exec "$C" curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null | jq -r '.result.info.server_state // "down"' 2>/dev/null; }
wait_full() { local i s; for ((i = 0; i < 90; i++)); do s="$(state)"; [ "$s" = full ] && break; sleep 10; done; echo "${s:-down}"; }
label() { docker inspect -f '{{.AppArmorProfile}}' "$C" 2>/dev/null; }
stored() { # the container's seccomp option: "default", "unconfined" or "sha256:<hex>" of the inline profile Docker stored
  docker inspect "$C" 2>/dev/null | python3 -I -c 'import hashlib, json, sys
o = (json.load(sys.stdin)[0].get("HostConfig") or {}).get("SecurityOpt") or []
s = [x[8:] for x in o if x.startswith("seccomp=")]
print("default" if not s else "unconfined" if s[0] == "unconfined" else "sha256:" + hashlib.sha256(s[0].encode()).hexdigest())'
}
secopt_shown() { # SecurityOpt with the inline profile replaced by its sha256 (publishable, one line)
  docker inspect "$C" 2>/dev/null | python3 -I -c 'import hashlib, json, sys
o = (json.load(sys.stdin)[0].get("HostConfig") or {}).get("SecurityOpt") or []
print(json.dumps(["seccomp=<inline profile, sha256 " + hashlib.sha256(x[8:].encode()).hexdigest() + ">" if x.startswith("seccomp=") and x != "seccomp=unconfined" else x for x in o]))'
}
init_mode() { local p; p="$(docker inspect -f '{{.State.Pid}}' "$C" 2>/dev/null)"; awk '$1 == "Seccomp:" { print $2 }' "/proc/$p/status" 2>/dev/null; }
denied() { # SINCE_EPOCH [SYSCALL] -> errno type=SECCOMP records for the container's AppArmor label since SINCE
  local l; l="$(label)"
  cat /var/log/audit/audit.log* 2>/dev/null | awk -v t="$1" -v n="${2:-}" -v l="$l" '
    index($0, "type=SECCOMP ") && index($0, " subj=" l " ") && index($0, " code=0x50000") && (n == "" || $0 ~ ("SYSCALL=" n "$")) {
      if (match($0, /audit\([0-9]+/) && substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0) c++ }
    END { print c + 0 }'
}
show_denied() { # SINCE SYSCALL: matching records, trimmed (no pid/ip)
  local l; l="$(label)"
  cat /var/log/audit/audit.log* 2>/dev/null | grep -F 'type=SECCOMP ' | grep -F " subj=$l " | grep -E "SYSCALL=$2\$" \
    | awk -v t="$1" 'match($0, /audit\([0-9]+/) && substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0' \
    | grep -oE 'subj=[^ ]+ .*' | sed -E 's/ (pid|ip|ses|auid)=[^ ]*//g; s/ (AUID|UID|GID)="[^"]*"//g' | head -2 | sed 's/^/    /'
}
audit_denied() { "$SC" audit --json --since "$1" 2>/dev/null | jq -r '.denied_events // "?"'; }
canon() { python3 -I "$HELPER" canon "$1" 2>/dev/null; }
WANT="sha256:$(canon "$PROF")"

echo "host-run $HOST $PHASE - $(ts) - $(lsb_release -ds) - container $C"
echo "sha256: host-run.sh $(sha256sum < "$0" | cut -c1-64) pft-seccomp $(sha256sum < "$SC" | cut -c1-64) pft_seccomp.py $(sha256sum < "$HELPER" | cut -c1-64)"
echo "profile $PROF: file sha256 $(sha256sum < "$PROF" | cut -c1-64), canonical (json.Compact) ${WANT}"
T_START="$(date +%s)"

if [ "$PHASE" = pre ]; then
  echo; echo "== 0. before"
  x "$SC audit; echo audit-exit=\$?"
  res "before: container on Docker's default seccomp profile -> audit FAIL" \
    "$(ok_if 'grep -qx "audit-exit=1" <<<"$XOUT" && grep -qE "\[FAIL\] container .*Docker.s default" <<<"$XOUT"')"
  echo "  SecurityOpt: $(secopt_shown)"
  s="$(state)"; m="$(init_mode)"
  res "before: $C full, init Seccomp $m (Docker's default filter)" "$(ok_if '[ "$s" = full ] && [ "$m" = 2 ]')" "$s"
  [ "$FAILS" = 0 ] || { echo "RESULT: FAIL - $FAILS check(s) (stopped before any change)"; exit 1; }

  echo; echo "== 1. profile"
  x "$SC check '$PROF'"; res "profile passes check" "$XRC"
  [ "$XRC" = 0 ] || { echo "RESULT: FAIL - profile not usable"; exit 1; }

  if [ "$DRILL" = 1 ]; then
    echo; echo "== 2. automatic rollback drill: injected gate failure"
    t2="$(date +%s)"
    x "PFT_SC_INJECT=health HEALTH_BUDGET=600 $SC apply --profile-file '$PROF' --yes"
    res "injected gate failure -> apply exit 1 (automatic rollback, its gate passed)" \
      "$(ok_if '[ "$XRC" = 1 ] && grep -q "injected failure" <<<"$XOUT" && grep -q "rollback RESULT: PASS" <<<"$XOUT"')"
    s="$(wait_full)"; st="$(stored)"; m="$(init_mode)"
    res "previous profile state restored: Docker's default, $PF removed, init Seccomp 2, full" \
      "$(ok_if '[ "$st" = default ] && [ ! -e "$PF" ] && [ "$m" = 2 ] && [ "$s" = full ]')" "$st, $s"
    echo "  SecurityOpt: $(secopt_shown)"
    d="$(denied "$t2")"; res "0 denials during the drill" "$(ok_if '[ "$d" = 0 ]')" "$d"
  fi

  echo; echo "== 3. apply"
  x "$SC apply --profile-file '$PROF' --yes"
  res "apply -> PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "apply RESULT: PASS" <<<"$XOUT"')"
  [ "$XRC" = 0 ] || { echo "RESULT: FAIL - apply did not pass (exit $XRC: 4 = refused, nothing changed; 1/6 = rolled back; 5 = rollback gate failed)"; exit 1; }
  st="$(stored)"; m="$(init_mode)"; s="$(state)"
  echo "  SecurityOpt: $(secopt_shown)"
  x "sha256sum < '$PF' | cut -c1-64; sha256sum < '$PROF' | cut -c1-64"
  res "installed $PF byte-identical to the profile" "$(ok_if '[ "$(sed -n 1p <<<"$XOUT")" = "$(sed -n 2p <<<"$XOUT")" ]')"
  res "stored profile sha256 = canonical sha256 of the profile, init Seccomp 2, full" \
    "$(ok_if '[ "$st" = "$WANT" ] && [ "$m" = 2 ] && [ "$s" = full ]')" "$st"

  echo; echo "== 4. positive controls (what the node, cron and the add-ons do)"
  t4="$(date +%s)"
  x "docker exec $C curl -s -m 10 -o /dev/null -w '%{http_code}' -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005"
  res "RPC server_info HTTP 200" "$(ok_if '[ "$XOUT" = 200 ]')"
  x "docker exec $C curl -s -m 10 -d '{\"method\":\"peers\"}' http://127.0.0.1:5005 | jq '.result.peers | length'"
  res "peers >= 1" "$(ok_if '[ "${XOUT:-0}" -ge 1 ] 2>/dev/null')" "$XOUT"
  x "docker exec $C setpriv --reuid=0 --regid=0 --init-groups true"; res "cron identity switch (setpriv --init-groups)" "$XRC"
  x "docker exec $C sh -c 'cd / && run-parts --report /etc/cron.hourly'"; res "run-parts /etc/cron.hourly" "$XRC"
  x "docker exec $C logrotate -d -s /var/log/postfiatd/.logrotate.status /etc/logrotate.d/postfiatd 2>&1 | tail -3"; res "logrotate config check (-d, no rotation)" "$XRC"
  x "docker exec $C ls /var/log/postfiatd /var/lib/postfiatd/db | wc -l"; res "list log + data dirs" "$XRC"
  x "docker exec $C ps -eo pid,comm | head -6"; res "ps" "$XRC"
  sleep 3
  d="$(denied "$t4")"; res "0 denials from the positive controls" "$(ok_if '[ "$d" = 0 ]')" "$d"

  echo; echo "== 5. negative controls (Docker's default allows these; each must fail with EPERM and leave a SECCOMP record)"
  neg() { # LABEL SYSCALL COMMAND
    local t rc n; t="$(date +%s)"
    x "docker exec $C bash -c '$3'"
    rc="$XRC"; sleep 2; n="$(denied "$t" "$2")"
    echo "  errno SECCOMP records with SYSCALL=$2 since $t: $n"; show_denied "$t" "$2"
    res "negative: $1 (EPERM + record)" "$(ok_if 'grep -q "Operation not permitted" <<<"$XOUT" && [ "$n" -ge 1 ]')" "exit $rc"
  }
  neg "symlink (cp -s)" symlinkat 'touch /tmp/.pft-sc-a && cp -s /tmp/.pft-sc-a /tmp/.pft-sc-s'
  neg "hard link (cp -l)" linkat 'touch /tmp/.pft-sc-a && cp -l /tmp/.pft-sc-a /tmp/.pft-sc-h'
  neg "inotify (tail -f)" inotify_init 'touch /tmp/.pft-sc-a; tail -n0 -f /tmp/.pft-sc-a 2>&1 & p=$!; SECONDS=0; while [ $SECONDS -lt 2 ]; do :; done; kill $p'
  x "docker exec $C bash -c 'rm -f /tmp/.pft-sc-a /tmp/.pft-sc-s /tmp/.pft-sc-h; ls -a /tmp | grep -c pft-sc'"
  res "probe files removed" "$(ok_if '[ "$(tail -1 <<<"$XOUT")" = 0 ]')"
  s="$(state)"; res "node still full after the controls" "$(ok_if '[ "$s" = full ]')" "$s"
  x "$SC audit; echo audit-exit=\$?"
  res "audit sees the denials (WARN denials, no FAIL)" "$(ok_if 'grep -qE "\[WARN\] denials " <<<"$XOUT" && ! grep -q "\[FAIL\]" <<<"$XOUT"')"
  date +%s > /var/lib/pft-seccomp/hostrun-neg-until
else
  echo; echo "== 6. acknowledge the negative controls"
  u="$(cat /var/lib/pft-seccomp/hostrun-neg-until 2>/dev/null)"
  [[ "$u" =~ ^[0-9]+$ ]] || { echo "RESULT: FAIL - no pre phase marker"; exit 1; }
  st="$(stored)"; res "container still under the profile" "$(ok_if '[ "$st" = "$WANT" ]')" "$st"
  x "$SC ack-denials --until $u --reason 'task_d4a0a82d live drill: deliberate negative controls on $HOST (symlinkat, linkat, inotify_init)' --yes"
  res "ack-denials up to the end of the negative controls" "$XRC"
  x "$SC audit; echo audit-exit=\$?"
  res "audit after ack: RESULT PASS" "$(ok_if 'grep -qx "audit-exit=0" <<<"$XOUT"')"
  rm -f /var/lib/pft-seccomp/hostrun-neg-until

  echo; echo "== 7. host add-ons that docker exec into the node, run by hand under the profile"
  t7="$(date +%s)"
  for u in pft-retention-sample.service "pft-statewatch@$C.service" "pft-feewatch@$C.service" "pft-upgradewatch@$C.service" \
           pft-mounts.service pft-timesync.service pft-divergence.service postfiat-monitor.service pft-apparmor.service \
           "pft-egress-reapply@$C.service" pft-maint-tick.service; do
    systemctl cat "$u" >/dev/null 2>&1 || { echo "  $u: not installed on this host, skipped"; continue; }
    x "systemctl start $u; systemctl show -p Result --value $u"
    res "add-on $u ran under the profile: Result=success" "$(ok_if '[ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = success ]')"
  done
  if systemctl cat pft-retention-sample.timer >/dev/null 2>&1; then
    inv0="$(systemctl show -p InvocationID --value pft-retention-sample.service)"
    echo "  $(ts) waiting for the next real pft-retention-sample.timer tick, up to 12 min"
    inv=""; for ((i = 0; i < 72; i++)); do
      inv="$(systemctl show -p InvocationID --value pft-retention-sample.service)"
      [ "$inv" != "$inv0" ] && [ "$(systemctl show -p ActiveState --value pft-retention-sample.service)" != activating ] && break
      sleep 10
    done
    x "TZ=UTC systemctl show -p Result -p ExecMainExitTimestamp pft-retention-sample.service; tail -1 /var/lib/pft-retention/samples.csv | cut -d, -f2,3,7"
    res "a real timer tick ran under the profile: new invocation, Result=success, nudb_bytes > 0" \
      "$(ok_if '[ "$inv" != "$inv0" ] && grep -qx "Result=success" <<<"$XOUT" && [ "$(tail -1 /var/lib/pft-retention/samples.csv | cut -d, -f7)" -gt 0 ] 2>/dev/null')"
  fi
  sleep 3; d="$(denied "$t7")"; res "0 denials from the add-ons" "$(ok_if '[ "$d" = 0 ]')" "$d"

  echo; echo "== 8. enforced restart"
  t8="$(date +%s)"; before="$(docker inspect -f '{{.State.StartedAt}}' "$C")"
  x "docker restart -t 60 $C"
  s="$(wait_full)"; st="$(stored)"; m="$(init_mode)"; after="$(docker inspect -f '{{.State.StartedAt}}' "$C")"
  res "restarted (StartedAt changed), same stored profile, init Seccomp 2, full" \
    "$(ok_if '[ "$before" != "$after" ] && [ "$st" = "$WANT" ] && [ "$m" = 2 ] && [ "$s" = full ]')" "$s"
  sleep 5; d="$(denied "$t8")"; res "0 denials since the restart" "$(ok_if '[ "$d" = 0 ]')" "$d"

  if [ "$DRILL" = 1 ]; then
    echo; echo "== 9. explicit rollback, then re-apply"
    x "$SC rollback --yes"
    s="$(wait_full)"; st="$(stored)"
    res "rollback -> PASS, Docker's default restored, $PF removed, full" \
      "$(ok_if 'grep -q "rollback RESULT: PASS" <<<"$XOUT" && [ "$st" = default ] && [ ! -e "$PF" ] && [ "$s" = full ]')" "$st, $s"
    echo "  SecurityOpt: $(secopt_shown)"
    x "$SC audit | grep -E '\[FAIL\]|RESULT'"; res "audit after rollback shows the finding again" "$(ok_if 'grep -q "\[FAIL\] container" <<<"$XOUT"')"
    t9="$(date +%s)"
    x "$SC apply --profile-file '$PROF' --yes"
    res "re-apply -> PASS" "$(ok_if '[ "$XRC" = 0 ] && grep -q "apply RESULT: PASS" <<<"$XOUT"')"
    st="$(stored)"; res "stored profile = canonical sha256 again" "$(ok_if '[ "$st" = "$WANT" ]')" "$st"
    d="$(denied "$t9")"; res "0 denials since the re-apply" "$(ok_if '[ "$d" = 0 ]')" "$d"
  fi
fi

echo; echo "== final"
x "$SC audit; echo audit-exit=\$?"
if [ "$PHASE" = post ]; then res "final audit RESULT PASS" "$(ok_if 'grep -qx "audit-exit=0" <<<"$XOUT"')"; fi
echo "  denied_events (24h, acknowledged excluded): $(audit_denied 86400)"
echo "host-run $HOST $PHASE done $(ts) ($(( $(date +%s) - T_START ))s): $NPASS PASS, $FAILS FAIL"
if [ "$FAILS" = 0 ]; then echo "RESULT: PASS"; exit 0; fi
echo "RESULT: FAIL - $FAILS check(s)"; exit 1
