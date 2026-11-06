#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host UPDATE of the installed schedaudit to the current HEAD (task_63b12600036365c3f4249ba43596cd52),
# through pft-fleet inside a pft-maint window. Built from ./install-run.sh (run 03 PASS). Nothing is restarted.
# 1ad593b: package-verified run-parts scripts and packaged timers are identified by package, so their ids change once:
# the run checks that every NEW id has a REMOVED partner with the same SOURCE/NAME (a pure re-identification, no
# entry added or lost), then accepts it with a reason and verifies 0 unexpected on both hosts.
# pft-maint's [MAINT] start/end messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow
# is re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the schedaudit/rulecheck/fleet alerts (never the pipeline watchdog) and is left to run out.
#   bash schedaudit/drill/update-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash schedaudit/drill/update-run.sh   (step 0 only; changes nothing)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_63b12600
TT="pft-drill-schedaudit-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
# the operator's own agent (cron.d file + its script dir) is internal: never named in a published log
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g; s#cron\.d/pft-agent#cron.d/<operator-agent>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-schedaudit
SWAPPED=0; MAINT=0; HAD=0
since="$(date -u +%s)"
OPS="$(mktemp)"; chmod 600 "$OPS"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap 'restore; rm -f "$OPS"' EXIT
echo "schedaudit two-host update - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight"
x "sha256sum schedaudit/pft-schedaudit.sh schedaudit/schedaudit_lib.py schedaudit/drill/update-run.sh"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the update" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|CRIT|WARN|SUMMARY)'; R 'sudo -n pft-schedaudit audit' | grep -E '^(NEW|REMOVED|CRIT|WARN|SUMMARY)'"
check "installed tool: 0 unexpected on both hosts before the update" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 baseline=yes' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet sync --addon schedaudit --to $SHA | grep -E '^PLAN .* (write|keep)$' | awk '{print \$2, \$4, \$6, \$NF}'"
check "dry run: schedaudit_lib.py written on both hosts, nothing else (2 writes)" "$([ "$(grep -c ' write$' <<<"$XOUT")" = 2 ] && [ "$(grep ' write$' <<<"$XOUT" | grep -c 'schedaudit_lib.py')" = 2 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | .createdBy' | sort | uniq -c; curl -s $AM/api/v2/alerts | jq -r '.[].labels.alertname' | sort | uniq -c"
check "active silences only from the schedaudit install; only the pipeline watchdog active" "$([ "$(grep -v PFTAlertPipelineWatchdog <<<"$XOUT" | grep -vc 'schedaudit-install')" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (the new helper re-identifies packaged entries until the accept; not the watchdog)"
ends="$(date -u -d '+30 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK schedaudit update $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTSchedEntryUnexpected|PFTSchedauditStale|PFTFleet.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "schedaudit-update", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (PFTSchedEntryUnexpected, PFTSchedauditStale, PFTFleet*; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
[ "$SWAPPED" = 1 ] || { echo "no throwaway target - stopping before the window"; exit 3; }
x "sudo -n pft-maint start --ttl 30m --reason '$TASK schedaudit update $SHORT'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: schedaudit files to HEAD on both hosts (writes + integrity accept by pft-fleet)"
x "sudo -n pft-fleet sync --addon schedaudit --to $SHA --apply --reason '$TASK: schedaudit package ids ($SHORT)'"
check "schedaudit sync exit 0" "$XRC"
x "sha256sum schedaudit/schedaudit_lib.py | cut -c1-64; sudo -n sha256sum /usr/local/lib/pft-schedaudit/schedaudit_lib.py | cut -c1-64; R 'sha256sum /usr/local/lib/pft-schedaudit/schedaudit_lib.py | cut -c1-64'"
check "installed helper = repo bytes on both hosts" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"

echo; echo "== 4. id migration: every NEW id has a REMOVED partner with the same SOURCE/NAME, then accept, then 0 unexpected"
migrate() { # HOSTCMD-PREFIX LABEL
  local pre="$1" lbl="$2" out nn nr diffn
  out="$(eval "$pre 'sudo -n pft-schedaudit audit'" 2>&1)"
  printf '%s\n' "$out" | grep -E '^(NEW|REMOVED|CRIT|WARN|SUMMARY)' | red | sed 's/^/  /'
  nn="$(grep -c '^NEW' <<<"$out")"; nr="$(grep -c '^REMOVED' <<<"$out")"
  diffn="$(diff <(grep '^NEW' <<<"$out" | cut -f3 | sed 's/@.*//' | sort) <(grep '^REMOVED' <<<"$out" | cut -f3 | sed 's/@.*//' | sort) | grep -c '^[<>]')"
  check "$lbl: $nn new / $nr removed ids, same SOURCE/NAME set (re-identification only), no unexpected finding" "$([ "$nn" = "$nr" ] && [ "$diffn" = 0 ] && grep -q ' unexpected_findings=0 ' <<<"$out" && echo 0 || echo 1)"
  x "$pre \"sudo -n pft-schedaudit accept --reason '$TASK: $SHORT package ids for package-verified run-parts scripts and timers ($nn re-identified)'\""
  x "$pre 'sudo -n systemctl start pft-schedaudit.service; sudo -n pft-schedaudit audit' | grep -E '^(NEW|REMOVED|CRIT|WARN|SUMMARY)'"
  check "$lbl: 0 unexpected findings, 0 new/removed after the accept" "$(grep -q '^SUMMARY .* unexpected_findings=0 new=0 removed=0 baseline=yes' <<<"$XOUT" && echo 0 || echo 1)"
}
migrate "bash -c" validator
migrate R sentry
x "sudo -n systemctl start pft-schedaudit-pull.service; sleep 40; curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_schedaudit_(up|unexpected)\"}' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.__name__) \(.metric.kind // \"-\") \(.value[1])\"' | sort"
check "Prometheus: pft_schedaudit_up 1 for both hosts" "$([ "$(grep -cE ' pft_schedaudit_up - 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
check "Prometheus: all 8 unexpected series 0" "$([ "$(grep -cE ' pft_schedaudit_unexpected [a-z]+ 0$' <<<"$XOUT")" = 8 ] && echo 0 || echo 1)"

echo; echo "== 5. integrity and fleet skew"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E 'schedaudit|SUMMARY'"
check "schedaudit CURRENT on both hosts" "$([ "$(grep -cE '^ *(validator|sentry) +schedaudit +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 6. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' /var/lib/pft-exporter/textfile/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"PFTSched|Fleet|Integrity\"))] | length'"
check "no schedaudit/fleet alert pending or firing (silence left to run out, lesson 185)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "update-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
