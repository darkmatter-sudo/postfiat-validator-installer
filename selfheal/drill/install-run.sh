#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host install of selfheal at the current HEAD (task_29073d4c5d752dc0d42b5f9bafe85732), through
# pft-fleet inside a pft-maint window. Built from ../../peerwatch/drill/install-run.sh (PASS, peerwatch log 06 + the
# aptrust fix-up of log 07 folded into step 3). Installs in MODE=dryrun on both hosts: nothing is restarted and no node
# config is touched; switching a host to enforce is a separate, deliberate step (README runbook).
#   0. preflight: integrity PASS, nodes full, not installed, HEAD carries the manifest/prometheus/rulecheck lines,
#      tools on both hosts, jobwatch textfile budget on both hosts, the pull's ssh source, operator topics, alerts.
#   3. pft-fleet writes the manifest, then the selfheal files on both hosts (and accepts them in pft-integrity).
#   4. sentry: install.sh --container postfiatd-sentry.  5. validator: install.sh, PULL_SSH, install.sh --pull.
#   6. rulecheck lines.  7. rules loaded.  8. schedaudit + jobwatch + integrity accept, both hosts.
#   9. VERIFIED: status PASS on both hosts, Prometheus series, no AppArmor/seccomp denial from the new exec path.
#  10. skew, rulecheck, timers, jobwatch.  11. restore + read-back.
# pft-maint's [MAINT] messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow is
# re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the selfheal/rulecheck/fleet/schedaudit/jobwatch/keyescrow alerts (never the pipeline watchdog)
# and is left to run out.
#   bash selfheal/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash selfheal/drill/install-run.sh  (step 0 only; changes nothing)
# KNOWN_PENDING: alert names already pending/firing before the run that the preflight accepts (each is printed).
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_29073d4c
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-selfheal-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-selfheal
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
  R "rm -rf ~/pft-selfheal-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
echo "selfheal two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum selfheal/pft-selfheal.sh selfheal/selfheal_decide.py selfheal/install.sh selfheal/drill/install-run.sh selfheal/systemd/* alerts/selfheal.rules.yml fleet/manifest.tsv"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-selfheal /etc/pft-selfheal.env 2>&1; R 'ls /usr/local/bin/pft-selfheal /etc/pft-selfheal.env 2>&1'"
check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "grep -c '^selfheal ' fleet/manifest.tsv; grep -c selfheal.rules.yml alerts/prometheus.yml; grep -c pft_selfheal rulecheck/pft-rulecheck.conf.example; grep -c pft_selfheal rulecheck/pft-rulecheck.sentry.conf.example"
check "HEAD lists 6 selfheal manifest lines, the rule file and 3 + 2 rulecheck lines" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "6 1 3 2 " ] && echo 0 || echo 1)"
x "command -v python3 jq curl | wc -l; R 'command -v python3 jq curl | wc -l'; sudo -n test -f /etc/pft-rulecheck.conf && echo rc-conf; R 'sudo -n test -f /etc/pft-rulecheck.conf && echo rc-conf'"
check "python3, jq, curl and a pft-rulecheck conf on both hosts" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "3 3 rc-conf rc-conf " ] && echo 0 || echo 1)"
x "sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout 2>/dev/null | wc -c; R 'sudo -n env TEXT_BUDGET=999999 pft-jobwatch collect --stdout 2>/dev/null | wc -c'; sudo -n sed -n 's/^TEXT_BUDGET=//p' /etc/pft-jobwatch.env"
JW_V="$(sed -n 1p <<<"$XOUT")"; JW_S="$(sed -n 2p <<<"$XOUT")"; JW_BUDGET="$(sed -n 3p <<<"$XOUT")"; JW_BUDGET="${JW_BUDGET:-61440}"
check "jobwatch textfiles have room for the new timers (validator $JW_V + 2x1200, sentry $JW_S + 1200 <= budget $JW_BUDGET / 61440)" "$([ $((JW_V + 2400)) -le "$JW_BUDGET" ] && [ $((JW_S + 1200)) -le 61440 ] && echo 0 || echo 1)"
pull_probe() { # run pft-statewatch's PULL_SSH (as root, like the unit) with `true`; prints nothing of the command
  sudo -n grep -c '^PULL_SSH=' /etc/pft-statewatch.env
  sudo -n bash -c 'c="$(sed -n "s/^PULL_SSH=//p" /etc/pft-statewatch.env | tr -d "\"")"; [ -n "$c" ] && $c true' >/dev/null 2>&1 && echo pull-ssh-ok
}
x "pull_probe"
check "the pull's ssh command (pft-statewatch's PULL_SSH, non-empty) reaches the sentry when run as root" "$(grep -qx 1 <<<"$XOUT" && grep -qx pull-ssh-ok <<<"$XOUT" && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
echo "known pending/firing before the run (accepted by the preflight): ${KNOWN_PENDING:-none}"
UNK="$(sed 1d <<<"$XOUT" | awk '{print $2}' | grep -vx PFTAlertPipelineWatchdog | while read -r a; do case " $KNOWN_PENDING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "no active silence; only the pipeline watchdog (+ KNOWN_PENDING) pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$UNK" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (new rules; rulecheck/fleet/schedaudit/jobwatch/keyescrow see new files and timers; not the watchdog)"
ends="$(date -u -d '+60 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK selfheal rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTSelfheal.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "selfheal-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (selfheal rules, rulecheck, fleet, schedaudit, jobwatch, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK selfheal install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: manifest (fleet add-on), then selfheal"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK selfheal manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon selfheal --to $SHA --apply --reason '$TASK selfheal $SHORT first install'"
check "selfheal sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
# run 06 FOUND: pft-aptrust keeps a copy of fleet/manifest.tsv as its offpkg allowlist; new manifest rows leave it BEHIND
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust allowlist copy += selfheal rows'"
check "aptrust sync exit 0 (its manifest copy follows the new rows)" "$XRC"
x "sha256sum selfheal/pft-selfheal.sh selfheal/selfheal_decide.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-selfheal /usr/local/lib/pft-selfheal/selfheal_decide.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-selfheal /usr/local/lib/pft-selfheal/selfheal_decide.py | cut -c1-64'"
check "installed script + parser = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 2 ] && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 4. sentry: install.sh --container postfiatd-sentry"
x "git archive $SHA selfheal | R 'rm -rf ~/pft-selfheal-$SHORT && mkdir -m 700 ~/pft-selfheal-$SHORT && tar -x -C ~/pft-selfheal-$SHORT'"
x "R 'sudo -n bash ~/pft-selfheal-$SHORT/selfheal/install.sh --container postfiatd-sentry'"
check "sentry install exit 0, up 1, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'pft_selfheal_up{container="postfiatd-sentry"} 1' <<<"$XOUT" && grep -q 'enabled pft-selfheal@postfiatd-sentry.timer' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 5. validator: install.sh, then PULL_SSH and install.sh --pull postfiatd-sentry"
x "sudo -n bash selfheal/install.sh"
check "validator install exit 0, up 1, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'pft_selfheal_up{container="postfiatd"} 1' <<<"$XOUT" && grep -q 'enabled pft-selfheal@postfiatd.timer' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash -c 'grep -q \"^PULL_SSH=\" /etc/pft-selfheal.env || grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-selfheal.env; grep -c \"^PULL_SSH=\" /etc/pft-selfheal.env; stat -c \"%a %U\" /etc/pft-selfheal.env'"
check "validator conf: one PULL_SSH (copied, not printed), root-owned" "$(grep -qx 1 <<<"$XOUT" && grep -qE '^6[0-4]4 root$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash selfheal/install.sh --pull postfiatd-sentry"
check "validator --pull exit 0, pulled sentry textfile has up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_selfheal_up{container="postfiatd-sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash selfheal/install.sh 2>&1 | grep -E 'added to|enabled|created'"
check "second install run adds no rulecheck line and creates no conf again" "$([ "$XRC" = 0 ] && ! grep -qE 'added to|created' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 6. rulecheck inputs (written by install.sh)"
x "sudo -n grep -n pft_selfheal /etc/pft-rulecheck.conf; R 'sudo -n grep -n pft_selfheal /etc/pft-rulecheck.conf'"
check "validator 3 + sentry 2 pft_selfheal rulecheck lines" "$([ "$(grep -c pft_selfheal <<<"$XOUT")" = 5 ] && [ "$(grep -c 'require pft_selfheal_postfiatd-sentry.prom' <<<"$XOUT")" = 2 ] && grep -q 'require pft_selfheal_postfiatd.prom' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 7. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 40 && curl -s $PROM/api/v1/status/runtimeinfo | jq -r .data.reloadConfigSuccess && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-selfheal\") | .rules[] | [.name, .health, .state] | @tsv'"
check "config reload ok, 2 selfheal rules loaded, health ok, none firing" "$(grep -qx true <<<"$XOUT" && [ "$(grep -c '	ok	' <<<"$XOUT")" = 2 ] && ! grep -q 'firing' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 8. new units/timers + conf: pft-schedaudit accept + collect, jobwatch inventory, then pft-integrity accept, both hosts"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160; R 'sudo -n pft-schedaudit audit' | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160"
x "sudo -n pft-schedaudit accept --reason '$TASK: pft-selfheal@postfiatd + pull timers installed' | tail -2; sudo -n pft-schedaudit collect | tail -1"
x "R \"sudo -n pft-schedaudit accept --reason '$TASK: pft-selfheal@postfiatd-sentry timer installed' | tail -2; sudo -n pft-schedaudit collect | tail -1\""
x "sudo -n pft-jobwatch inventory 2>&1 | grep -E 'selfheal|SUMMARY' | cut -c1-200; R 'sudo -n pft-jobwatch inventory 2>&1' | grep -E 'selfheal|SUMMARY' | cut -c1-200"
check "jobwatch learns a 60 s interval for the 3 selfheal timers (validator 2, sentry 1)" "$([ "$(grep -E 'selfheal' <<<"$XOUT" | grep -cw 60)" = 3 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "sudo -n pft-integrity accept --reason '$TASK: selfheal $SHORT installed (conf, units, timers, rulecheck.conf, sched items)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "R \"sudo -n pft-integrity accept --reason '$TASK: selfheal $SHORT installed (conf, units, timer, rulecheck.conf, sched items)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit on both hosts: 0 unexpected, 0 new/removed" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit-pull.service; grep -h '^pft_schedaudit_unexpected' $TF/pft_schedaudit_*.prom | grep -vc ' 0$'"
check "schedaudit textfiles: every pft_schedaudit_unexpected series 0 (validator + pulled sentry copy)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 9. VERIFIED: status on both hosts, Prometheus series, confinement unchanged by the new exec path"
x "sudo -n pft-selfheal status"
check "validator status exit 0: mode dryrun, verdict healthy, breaker closed" "$([ "$XRC" = 0 ] && grep -q 'mode dryrun | verdict healthy' <<<"$XOUT" && grep -q 'breaker closed' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n pft-selfheal status --container postfiatd-sentry'"
check "sentry status exit 0: mode dryrun, verdict healthy, breaker closed" "$([ "$XRC" = 0 ] && grep -q 'mode dryrun | verdict healthy' <<<"$XOUT" && grep -q 'breaker closed' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n grep -c '^MODE=dryrun$' /etc/pft-selfheal.env; R 'sudo -n grep -c ^MODE=dryrun\$ /etc/pft-selfheal.env'; sudo -n cat /var/lib/pft-selfheal/journal-postfiatd.jsonl 2>/dev/null | grep -c 'event.:.action.,'; R 'sudo -n cat /var/lib/pft-selfheal/journal-postfiatd-sentry.jsonl 2>/dev/null | grep -c event.:.action.,'"
check "both confs MODE=dryrun, no action journalled on either host" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "1 1 0 0 " ] && echo 0 || echo 1)"
x "sleep 45; curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_selfheal_(up|enforce|breaker_open|verdict)\"}' | jq -r '.data.result[] | \"\(.metric.container) \(.metric.__name__) \(.metric.verdict // \"-\") \(.value[1])\"' | sort"
check "Prometheus, postfiatd and postfiatd-sentry: up 1, enforce 0, breaker_open 0, verdict healthy 1" "$([ "$(grep -cE '^postfiatd(-sentry)? pft_selfheal_up - 1$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^postfiatd(-sentry)? pft_selfheal_enforce - 0$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^postfiatd(-sentry)? pft_selfheal_breaker_open - 0$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^postfiatd(-sentry)? pft_selfheal_verdict healthy 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts with 0 denials after the first collections" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 10. fleet skew, rulecheck, timers, jobwatch"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, selfheal CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +selfheal +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-jobwatch.service'; sudo -n systemctl start pft-jobwatch-pull.service; echo pulled"
x "s=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat | grep -E '^RESULT |selfheal'"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 's=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat' | grep -E '^RESULT |selfheal'"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck-pull.service; echo pulled"
x "systemctl is-active pft-selfheal@postfiatd.timer pft-selfheal-pull@postfiatd-sentry.timer; R 'systemctl is-active pft-selfheal@postfiatd-sentry.timer'; systemctl is-failed pft-selfheal@postfiatd.service pft-selfheal-pull@postfiatd-sentry.service; R 'systemctl is-failed pft-selfheal@postfiatd-sentry.service'"
check "timers active and services not failed on both hosts" "$([ "$(grep -cx active <<<"$XOUT")" = 3 ] && [ "$(grep -cx failed <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*selfheal' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees both validator selfheal timers: not failed, missed or disabled" "$([ "$(grep -cE 'selfheal.* 0$' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"

echo; echo "== 11. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Selfheal|RuleDead|TextfileStale|Rulecheck|Fleet|Sched|PFTJob|KeyEscrow|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no selfheal/rulecheck/fleet/schedaudit/jobwatch/keyescrow/confinement alert pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R 'ls -d ~/pft-selfheal-* 2>/dev/null | wc -l'"
check "no transient run-u services/timers (run-user-N.mount login mounts are not transient units), no install copy left on the sentry" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
