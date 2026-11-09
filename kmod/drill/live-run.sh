#!/usr/bin/env bash
# Recorded two-host kmod rollout, sentry first (run on the validator from the repo root, as the agent user, on a
# clean committed HEAD; pushed only after the rollout):  bash kmod/drill/live-run.sh sentry|validator 2>&1 | tee LOG
#  sentry     ship the commit to the sentry, install, accept (integrity + schedaudit), host-run apply,
#             sentry REBOOT, host-run after-reboot, host-run rollback-reapply
#  validator  install, accept, host-run apply, host-run rollback-reapply, install --pull (sentry textfile)
# Alerting during the run: every notifier that can fire points at a throwaway ntfy topic (validator pft-maint +
# postfiat-monitor + pft-integrity env, sentry pft-watchdog + pft-alertpath + pft-integrity env), a pft-maint window is open on both hosts, and an Alertmanager
# silence covers every alert EXCEPT PFTAlertPipelineWatchdog (lesson: a catch-all silence starves the dead-man).
# Everything is restored (sha256-compared) on exit; the silence is expired once nothing is firing.
# shellcheck disable=SC1091,SC2016
set -uo pipefail
WHO="${1:?sentry|validator}"
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; ME="$(id -un)"
TASK=task_07a6e13e99620b3df65ef2056ed835f9
AM=http://127.0.0.1:9093
PROM=http://127.0.0.1:9090
REBOOT_EPOCH=0
TT="pft-drill-kmod-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#$(hostname)#validator-host#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
R() { ssh -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=10 relay "$@"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; FAILS=$((FAILS + 1)); fi; }
is() { [ "$@" ] && echo 0 || echo 1; }
ts() { date -u +%FT%TZ; }

# notifier env files: host path (validator: local; sentry: R)
V_FILES="/etc/pft-maint/ntfy.env /etc/postfiat-monitor.env /etc/pft-integrity.env"
S_FILES="/etc/pft-watchdog/ntfy.env /etc/pft-alertpath/ntfy.env /etc/pft-integrity.env"
declare -A PRE=()
swap() { # HOST FILE: keep FILE as FILE.pre-kmod (cp -p), write the throwaway target into FILE
  local h="$1" f="$2" run
  if [ "$h" = validator ]; then run="sudo -n"; else run="R sudo -n"; fi
  if $run test -e "$f"; then
    PRE[$h:$f]="$($run sha256sum "$f" | cut -c1-64)"
    $run cp -p "$f" "$f.pre-kmod" && $run sed -i -E "s#^NTFY_TOPIC=.*#NTFY_TOPIC=$TT#; s#^NTFY_SERVER=.*#NTFY_SERVER=https://ntfy.sh#; s#^NTFY_TOKEN=.*#NTFY_TOKEN=#" "$f"
    $run grep -q "^NTFY_TOPIC=$TT\$" "$f"
  else
    PRE[$h:$f]=absent
    printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$TT" | $run tee "$f" >/dev/null && $run chmod 600 "$f"
  fi
}
unswap() {
  local h="$1" f="$2" run now
  if [ "$h" = validator ]; then run="sudo -n"; else run="R sudo -n"; fi
  [ -n "${PRE[$h:$f]:-}" ] || return 0
  if [ "${PRE[$h:$f]}" = absent ]; then $run rm -f "$f"; now=absent
  else $run mv -f "$f.pre-kmod" "$f"; now="$($run sha256sum "$f" | cut -c1-64)"; fi
  check "$h $f restored ($([ "$now" = absent ] && echo 'absent again' || echo 'sha256 equal, not printed'))" "$(is "$now" = "${PRE[$h:$f]}")"
  unset "PRE[$h:$f]"
}
MAINT=0; SIL=""; ends=""
restore() {
  trap - EXIT
  echo; echo "== restore ($(ts))"
  if [ "$MAINT" = 1 ]; then x "sudo -n pft-maint end --reason 'kmod $WHO rollout done'"; MAINT=0; fi
  local f
  for f in $V_FILES; do unswap validator "$f"; done
  for f in $S_FILES; do unswap sentry "$f"; done
  if [ -n "$SIL" ]; then
    # Expire only when nothing the run caused can still fire: no alert held by the silence in Alertmanager, nothing
    # pending/firing in Prometheus (except the dead-man), and >= 25 min since the last node start (the reboot), since
    # PFTContainerRestarted (resets(uptime[15m])) fires up to ~15 min + for after a restart.
    local firing pend wait_s
    firing="$(curl -s "$AM/api/v2/alerts?silenced=true" | jq -r --arg id "$SIL" '[.[] | select(.status.silencedBy | index($id)) | .labels.alertname] | unique | join(",")')"
    pend="$(curl -s "$PROM/api/v1/alerts" | jq -r '[.data.alerts[] | select(.labels.alertname != "PFTAlertPipelineWatchdog") | .labels.alertname] | unique | join(",")')"
    wait_s=$(( ${REBOOT_EPOCH:-0} + 1500 - $(date -u +%s) ))
    if [ -z "$firing" ] && [ -z "$pend" ] && [ "$wait_s" -le 0 ]; then x "curl -s -X DELETE $AM/api/v2/silence/$SIL -o /dev/null -w '%{http_code}'"
    else echo "silence ${SIL:0:8} left to run out until $ends (held: ${firing:-none}; prometheus pending/firing: ${pend:-none}; reboot + 25 min in ${wait_s}s)"; fi
  fi
  x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=2h\" | jq -r '.title'"
  echo "throwaway topic received $(grep -c . <<<"$XOUT") message(s) (operator topics: none of the above)"
  echo; echo "live-run $WHO done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
  exit "$([ "$FAILS" = 0 ] && echo 0 || echo 1)"
}

echo "kmod live-run $WHO - $(ts) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
# Not "pushed": the commit is published only after both hosts are fixed (found -> fixed -> verified, never an open
# finding of a live host); the SHA run here is the one that gets pushed.
git cat-file -e "$SHA^{commit}" || { echo "HEAD is not a commit - stopping"; exit 3; }
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "preflight: pft-integrity PASS on both hosts" "$(is "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }

echo; echo "== 1. alert targets -> throwaway topic, silence (all but the watchdog), pft-maint window"
trap restore EXIT
for f in $V_FILES; do swap validator "$f"; check "validator $f -> throwaway" "$?"; done
for f in $S_FILES; do swap sentry "$f"; check "sentry $f -> throwaway" "$?"; done
ends="$(date -u -d '+70 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK kmod $WHO rollout (planned$([ "$WHO" = sentry ] && echo ': sentry reboot'))" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true},
               {name: "alertname", value: "PFTAlertPipelineWatchdog", isRegex: false, isEqual: false}],
    startsAt: $s, endsAt: $e, createdBy: "kmod-live-run", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence ${SIL:0:8} (alertname=~.+, alertname!=PFTAlertPipelineWatchdog) until $ends" "$(is -n "$SIL")"
x "sudo -n pft-maint start --ttl 60m --reason '$TASK kmod $WHO rollout'"
[ "$XRC" = 0 ] && MAINT=1; check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || { echo "setup failed - restoring, nothing changed"; exit 1; }

accept() { # HOST REASON: schedaudit accept + collect (unexpected 0), integrity accept + verify PASS
  local run; if [ "$1" = validator ]; then run=""; else run="R"; fi
  x "$run sudo -n pft-schedaudit accept --reason '$TASK: $2' | tail -2; $run sudo -n pft-schedaudit collect >/dev/null; $run sudo -n grep -E '^pft_schedaudit_unexpected' /var/lib/pft-exporter/textfile/pft_schedaudit_$1.prom"
  check "$1 schedaudit unexpected all 0 after accept + collect" "$(is -z "$(grep -E '^pft_schedaudit_unexpected.* [1-9]' <<<"$XOUT")")"
  x "$run sudo -n pft-integrity accept --reason '$TASK: $2' | tail -2; $run sudo -n pft-integrity verify | tail -1"
  check "$1 pft-integrity PASS after accept" "$(is -n "$(grep 'RESULT: PASS' <<<"$XOUT")")"
}

if [ "$WHO" = sentry ]; then
  echo; echo "== 2. ship $SHA to the sentry (git archive -> fresh temp dir), install"
  D="$(R 'mktemp -d')"
  x "git archive --format=tar $SHA kmod | R \"tar -x -C $D\" && R \"cd $D && sha256sum kmod/pft-kmod.sh kmod/install.sh kmod/systemd/*\""
  x "R \"cd $D && sudo -n bash kmod/install.sh --host sentry\""; check "sentry install exit 0 (first audit up 1)" "$XRC"
  accept sentry "pft-kmod installed (binary, service, timer)"
  echo; echo "== 3. sentry: apply (found -> fixed -> verified)"
  x "R \"cd $D && bash kmod/drill/host-run.sh apply sentry\""; check "sentry host-run apply PASS" "$XRC"
  echo; echo "== 4. sentry reboot (persistence)"
  B0="$(R 'cat /proc/sys/kernel/random/boot_id')"
  REBOOT_EPOCH="$(date -u +%s)"; echo "$(ts) \$ sudo systemctl reboot   (sentry)"; R 'sudo -n systemctl reboot' >/dev/null 2>&1 || true
  sleep 45; up=0
  for _ in $(seq 1 60); do R true 2>/dev/null && { up=1; break; }; sleep 10; done
  check "sentry back over ssh ($(ts))" "$(is "$up" = 1)"
  check "boot_id changed (really rebooted)" "$(is "$(R 'cat /proc/sys/kernel/random/boot_id')" != "$B0")"
  st=""; for i in $(seq 1 50); do
    st="$(R "sudo -n docker exec postfiatd-sentry postfiatd --conf /etc/postfiatd/postfiatd.cfg server_info 2>/dev/null | jq -r '.result.info.server_state'")"
    [ "$st" = full ] && break; sleep 30
  done
  echo "$(ts) sentry server_state $st after poll $i"; check "sentry full after reboot" "$(is "$st" = full)"
  x "R \"cd $D && bash kmod/drill/host-run.sh after-reboot sentry\""; check "sentry host-run after-reboot PASS" "$XRC"
  echo; echo "== 5. sentry: rollback + re-apply"
  x "R \"cd $D && bash kmod/drill/host-run.sh rollback-reapply sentry\""; check "sentry host-run rollback-reapply PASS" "$XRC"
  x "R 'sudo -n pft-integrity verify | tail -1'"; check "sentry integrity PASS at the end" "$(is -n "$(grep 'RESULT: PASS' <<<"$XOUT")")"
  x "R \"rm -rf $D\""
else
  echo; echo "== 2. validator: install"
  x "sha256sum kmod/pft-kmod.sh kmod/install.sh kmod/systemd/*"
  x "sudo -n bash kmod/install.sh --host validator"; check "validator install exit 0 (first audit up 1)" "$XRC"
  accept validator "pft-kmod installed (binary, service, timer)"
  echo; echo "== 3. validator: apply (found -> fixed -> verified)"
  x "bash kmod/drill/host-run.sh apply validator"; check "validator host-run apply PASS" "$XRC"
  echo; echo "== 4. validator: rollback + re-apply"
  x "bash kmod/drill/host-run.sh rollback-reapply validator"; check "validator host-run rollback-reapply PASS" "$XRC"
  echo; echo "== 5. validator: pull the sentry's textfile in the same hourly run"
  x "sudo -n grep -q '^PULL_SSH=' /etc/pft-kmod.env || sudo -n sh -c 'grep -E \"^(PEER_LABEL|PULL_SSH)=\" /etc/pft-sshcrypto.env >> /etc/pft-kmod.env'; sudo -n grep -c '^PULL_SSH=' /etc/pft-kmod.env"
  x "sudo -n bash kmod/install.sh --pull"; check "install --pull exit 0 (sentry file pulled)" "$XRC"
  accept validator "pft-kmod pull drop-in"
fi
restore
