#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded install of pft-aptrust-pull.{service,timer} (validator, hourly). FOUND 2026-11-13: the validator's same-run
# pull copied the sentry's textfile before the sentry's own audit had run (both timers add up to 10 min of random
# delay), so the validator held a 12 h old copy for another 12 h and PFTTextfileStale{file="pft_aptrust_sentry.prom"}
# fired. FIX: an independent hourly pull timer on the validator. Installed through pft-fleet sync --addon aptrust
# (new unit files + the allowlist copy that now lists them, both hosts) inside a pft-maint window whose [MAINT]
# messages go to a throwaway topic; then enable the timer, pft-integrity accept (the timers.target.wants link),
# pft-schedaudit accept + collect on both hosts, jobwatch inventory. VERIFIED: pull unit run rc 0 + fresh copy, timer
# scheduled at :23, aptrust audit 0 warn / 0 fail on both hosts, skew rc 0, integrity PASS, operator topics 0.
#   bash aptrust/drill/pull-timer-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
# KNOWN_PENDING: alert names already pending/firing before the run that the preflight accepts (each is printed).
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=ops-aptrust-pull
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-aptrust-pull-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-aptrust-pull
SWAPPED=0; MAINT=0; HAD=0
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap 'restore; rm -f "$OPS"' EXIT
echo "aptrust pull-timer install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sudo -n pft-fleet skew | grep -vE ' CURRENT *\$'"
# run 01: pft-fleet keeps its own manifest copy (validator role), so it is BEHIND too; the new pull units are not
# listed (skew reports files a host already has). Expect exactly: aptrust BEHIND on both hosts, fleet BEHIND on the validator.
check "skew: only aptrust (both hosts) and fleet (validator) BEHIND" "$([ "$(grep -cE '^ *(validator|sentry) +[a-z]+ +(BEHIND|MODIFIED|MISSING|UNEXPECTED|DIVERGED)' <<<"$XOUT")" = 3 ] && [ "$(grep -cE '^ *(validator|sentry) +aptrust +BEHIND' <<<"$XOUT")" = 2 ] && grep -qE '^ *validator +fleet +BEHIND +/usr/local/lib/pft-fleet/manifest.tsv' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl list-unit-files --no-legend 'pft-aptrust-pull*' | wc -l"
check "no pft-aptrust-pull unit installed yet" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\\(.labels.alertname) \\(.state)\"' | sort -u"
others="$(grep -vE '^PFTAlertPipelineWatchdog ' <<<"$XOUT" | awk '{print $1}' | sort -u)"
bad=""; for n in $others; do case " $KNOWN_PENDING " in *" $n "*) echo "  known pending: $n";; *) bad="$bad $n";; esac; done
check "no alert pending/firing except the watchdog and KNOWN_PENDING" "$([ -z "$bad" ] && echo 0 || echo 1)" "${bad:-none}"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.state == \"firing\" and .labels.alertname != \"PFTAlertPipelineWatchdog\")] | length'"
check "nothing but the watchdog FIRING (the bridge would re-send it)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }

echo; echo "== 1. silence (aptrust, fleet, keyescrow, schedaudit, jobwatch, integrity; not the watchdog)"
ends="$(date -u -d '+40 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK aptrust pull timer $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTAptrust.*|PFTFleet.*|PFTKeyEscrow.*|PFTSched.*|PFTJob.*|PFTIntegrity.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "aptrust-pull-run", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 20m --reason '$TASK aptrust pull timer'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window after ${w}s" "$?"

echo; echo "== 3. FIX: pft-fleet sync --addon fleet, then aptrust (new pull units on the validator, edited units + allowlist copy both hosts)"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK manifest += aptrust pull units'"
check "fleet sync exit 0 (its manifest copy)" "$XRC"
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust: hourly validator pull timer'"
check "aptrust sync exit 0" "$XRC"
x "sha256sum fleet/manifest.tsv | cut -c1-64; sudo -n sha256sum /usr/local/lib/pft-aptrust/manifest.tsv | cut -c1-64; R 'sha256sum /usr/local/lib/pft-aptrust/manifest.tsv | cut -c1-64'"
check "aptrust's manifest copy = repo fleet/manifest.tsv on both hosts" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"
x "for f in pft-aptrust-pull.service pft-aptrust-pull.timer; do cmp aptrust/systemd/\$f /etc/systemd/system/\$f && echo \"same \$f\"; done"
check "both pull units installed byte-identical on the validator" "$([ "$(grep -c '^same ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "R 'ls /etc/systemd/system/pft-aptrust-pull.service /etc/systemd/system/pft-aptrust-pull.timer 2>/dev/null | wc -l'"
check "no pull unit on the sentry (role validator)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust-pull.service; systemctl show -p Result,ExecMainStatus pft-aptrust-pull.service"
check "pull unit run: Result=success, ExecMainStatus=0" "$(grep -qx 'Result=success' <<<"$XOUT" && grep -qx 'ExecMainStatus=0' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'grep -h ^pft_aptrust_last_run_timestamp_seconds /var/lib/pft-exporter/textfile/pft_aptrust_sentry.prom'; grep -h ^pft_aptrust_last_run_timestamp_seconds $TF/pft_aptrust_sentry.prom"
check "pulled copy = the sentry's current file (same last_run)" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"
x "sudo -n systemctl enable --now pft-aptrust-pull.timer; TZ=UTC systemctl list-timers --no-legend pft-aptrust-pull.timer"
check "pft-aptrust-pull.timer enabled and scheduled" "$([ "$XRC" = 0 ] && systemctl is-enabled -q pft-aptrust-pull.timer && grep -q 'pft-aptrust-pull.timer' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl show -p TimersCalendar pft-aptrust-pull.timer"
check "timer calendar is hourly at :23 UTC" "$(grep -q 'OnCalendar=\*-\*-\* \*:23:00 UTC' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E '^ *(WARN|FAIL)|RESULT'"
x "sudo -n pft-integrity accept --reason '$TASK: pft-aptrust-pull.timer enabled (timers.target.wants link), schedule' | tail -2"
check "pft-integrity accept exit 0" "$XRC"
x "sudo -n pft-schedaudit accept --reason '$TASK: pft-aptrust-pull.timer (validator, hourly :23)' && sudo -n pft-schedaudit collect && R 'sudo -n pft-schedaudit accept --reason \"$TASK: pft-aptrust units re-synced\" && sudo -n pft-schedaudit collect' && sudo -n systemctl start pft-schedaudit-pull.service; grep -hE '^pft_schedaudit_unexpected' $TF/pft_schedaudit_*.prom"
check "schedaudit accept + collect both hosts, 0 unexpected" "$([ "$XRC" = 0 ] && ! grep -qE '} [1-9]' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-jobwatch inventory | grep -E 'aptrust'"
check "jobwatch inventory lists pft-aptrust-pull.timer with interval 3600" "$(grep -E 'pft-aptrust-pull.timer' <<<"$XOUT" | grep -qw 3600 && echo 0 || echo 1)"
x "sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout | wc -c"
check "jobwatch textfile under TEXT_BUDGET 61440" "$([ "$(tail -1 <<<"$XOUT")" -lt 61440 ] && echo 0 || echo 1)"
echo; echo "== 4. VERIFIED: aptrust audit (CLI and the timer's unit run, textfile), skew, integrity"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^INFO  offpkg |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^INFO  offpkg |^RESULT'"
# per-host add-on file counts differ by role: assert the verdict, not a count
check "aptrust audit on both hosts: 0 warn, 0 fail, no WARN/FAIL line" "$([ "$(grep -c ' 0 warn, 0 fail -> exit 0' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust.service; R 'sudo -n systemctl start pft-aptrust.service'; sudo -n systemctl start pft-aptrust-pull.service; grep -hE '^pft_aptrust_checks\{.*result=\"(warn|fail)\"' $TF/pft_aptrust_*.prom"
check "aptrust textfiles (validator + pulled sentry): warn 0, fail 0" "$([ "$(grep -c '} 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | tail -1"
check "pft-fleet skew exit 0, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 5. end window, restore, keyescrow, read back"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Aptrust|Fleet|KeyEscrow|Integrity|Sched|Job\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no aptrust/fleet/keyescrow/integrity/sched/job alert pending or firing" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l"
check "no transient run-u services/timers (login-session run-user-N.mount units are not transient units)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "aptrust pull-timer install done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
