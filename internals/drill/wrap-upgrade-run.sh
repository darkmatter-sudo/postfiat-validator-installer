#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host UPGRADE of internals to the counter-wrap fix (87e8400), through pft-fleet inside a pft-maint
# window. Built from ./upgrade-run.sh (logs/07 PASS). Ships the fix for the false PFTInternalsCounterAnomaly of
# 2026-11-20T12:23:40Z (postfiatd 1.0.9 node_read_bytes wraps at 2^32, logs/13): parser only; collector, units,
# timers, conf and rules unchanged. Restarts no node.
#   0. preflight: integrity PASS, nodes full, both hosts at the old parser (6c6425e), no silence active,
#      only the watchdog (+ KNOWN_PENDING) pending/firing, PFTInternalsCounterAnomaly inactive.
#   3. pft-fleet: internals (parser), bytes = repo on both hosts.
#   4. state re-baseline on both hosts (the 12:23Z false anomaly is dropped: restarts/anomalies start at 0).
#  10. VERIFIED: status, textfiles, Prometheus, confinement.  11. skew, rulecheck, timers.
#  12. restore, drain, expire the rollout silence, read back every operator topic (0 messages).
#   KNOWN_PENDING="PFTValwatchValidatorLow" bash internals/drill/wrap-upgrade-run.sh 2>&1 | tee LOG   (repo root)
#   PREFLIGHT_ONLY=1 bash internals/drill/wrap-upgrade-run.sh
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
OLD=6c6425ed9af9
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=internals-wrap
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-internals-wrap-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@" </dev/null; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-internals-wrap
SWAPPED=0; MAINT=0; HAD=0; SIL=""
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
srv_state() { # both nodes' server_state, validator first (same exec shape as selfheal/install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
tf_check() { # NAME BYTES SAMPLES valid, per textfile on the validator (local + pulled sentry copy)
  local n f
  for n in postfiatd postfiatd-sentry; do
    f="$TF/pft_internals_$n.prom"
    echo "$n $(stat -c %s "$f") $(grep -vc '^#' "$f") $(pft-internals validate "$f" "$n" >/dev/null && echo valid)"
  done
}
prom_check() { # series per container, then up / restarts / anomalies per container
  curl -s "$PROM/api/v1/query" --data-urlencode 'query=count by (container) ({__name__=~"pft_internals_.+"})' \
    | jq -r '.data.result[] | "\(.metric.container) \(.value[1])"' | sort
  curl -s "$PROM/api/v1/query" \
    --data-urlencode 'query={__name__=~"pft_internals_(up|node_restarts_total|counter_anomalies_total)"}' \
    | jq -r '.data.result[] | "\(.metric.container) \(.metric.__name__) \(.value[1])"' | sort
}
echo "internals counter-wrap upgrade - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum internals/pft-internals.sh internals/internals_parse.py internals/systemd/* alerts/internals.rules.yml fleet/manifest.tsv internals/drill/wrap-upgrade-run.sh"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the upgrade" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "git show $OLD:internals/internals_parse.py | sha256sum | cut -c1-64; sudo -n sha256sum /usr/local/lib/pft-internals/internals_parse.py | cut -c1-64; R 'sha256sum /usr/local/lib/pft-internals/internals_parse.py | cut -c1-64'; sha256sum internals/internals_parse.py | cut -c1-64"
check "both hosts run the old parser ($OLD), which differs from HEAD's" "$([ "$(sed -n 1p <<<"$XOUT")" = "$(sed -n 2p <<<"$XOUT")" ] && [ "$(sed -n 2p <<<"$XOUT")" = "$(sed -n 3p <<<"$XOUT")" ] && [ "$(sed -n 3p <<<"$XOUT")" != "$(sed -n 4p <<<"$XOUT")" ] && [ "$(wc -l <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "git diff $OLD $SHA -- fleet/manifest.tsv | grep -cE '^[-+]internals[[:space:]]'; git diff --stat $OLD $SHA -- internals/pft-internals.sh internals/systemd alerts/internals.rules.yml | tail -1; git diff --name-only $OLD $SHA -- internals | grep -v -e '^internals/logs/' -e '^internals/tests/' -e '^internals/drill/' -e '^internals/README.md$'"
check "since $OLD only the parser changed (internals manifest rows, collector, units, rules unchanged)" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 internals/internals_parse.py " ] && echo 0 || echo 1)"
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
x "curl -s --max-time 10 $PROM/api/v1/alerts | jq -r .status; curl -s --max-time 10 $AM/api/v2/status | jq -r 'if (.uptime // \"\") != \"\" then \"up\" else \"down\" end'"
check "Prometheus and Alertmanager answer (alert gates below fail closed)" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "success up " ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
echo "known pending/firing before the run (accepted by the preflight): ${KNOWN_PENDING:-none}"
UNK="$(sed 1d <<<"$XOUT" | awk '{print $2}' | grep -vx PFTAlertPipelineWatchdog | while read -r a; do case " $KNOWN_PENDING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "no active silence; only the watchdog (+ KNOWN_PENDING) pending/firing; PFTInternalsCounterAnomaly inactive" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$UNK" = 0 ] && ! grep -q PFTInternals <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n test -e $NE && echo present || echo absent; systemctl list-units --all --no-legend 'agent-*' 'run-u*.service' 'run-u*.timer' | wc -l"
check "no drill unit running" "$([ "$(sed -n 2p <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (parser swap + state re-baseline; integrity/fleet/aptrust/jobwatch/keyescrow; not the watchdog)"
ends="$(date -u -d '+60 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK internals upgrade $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTInternals.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "internals-wrap-upgrade", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (internals rules, rulecheck, fleet, aptrust, schedaudit, jobwatch, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK internals upgrade'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: internals only (manifest rows unchanged, so no fleet/aptrust sync)"
x "sudo -n pft-fleet sync --addon internals --to $SHA --apply --reason 'internals $SHORT parser fix (2^32 counter wrap, false anomaly 2026-11-20T12:23Z)'"
check "internals sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum internals/pft-internals.sh internals/internals_parse.py internals/systemd/pft-internals@.service internals/systemd/pft-internals@.timer | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-internals /usr/local/lib/pft-internals/internals_parse.py /etc/systemd/system/pft-internals@.service /etc/systemd/system/pft-internals@.timer | cut -c1-64; R 'sha256sum /usr/local/bin/pft-internals /usr/local/lib/pft-internals/internals_parse.py /etc/systemd/system/pft-internals@.service /etc/systemd/system/pft-internals@.timer | cut -c1-64'"
check "installed collector + parser + units = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 4 ] && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 4. state re-baseline on both hosts (the one anomaly counted was the 12:23Z wrap), one collection each"
x "R 'sudo -n rm -f /var/lib/pft-internals/state-postfiatd-sentry.json && sudo -n systemctl start pft-internals@postfiatd-sentry.service && sudo -n pft-internals status --container postfiatd-sentry'"
check "sentry: state re-baselined, collection ok, restarts 0, anomalies 0" "$([ "$XRC" = 0 ] && grep -q '^RESULT: OK' <<<"$XOUT" && [ "$(grep -cE '^  (restarts|anomalies) +0$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n rm -f /var/lib/pft-internals/state-postfiatd.json && sudo -n systemctl start pft-internals@postfiatd.service pft-internals-pull@postfiatd-sentry.service && sudo -n pft-internals status"
check "validator: state re-baselined, collection + pull ok, restarts 0, anomalies 0" "$([ "$XRC" = 0 ] && grep -q '^RESULT: OK' <<<"$XOUT" && [ "$(grep -cE '^  (restarts|anomalies) +0$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after the sync" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 10. VERIFIED: status + textfiles on both hosts, Prometheus series, aptrust, confinement"
x "sudo -n pft-internals status; R 'sudo -n pft-internals status --container postfiatd-sentry'"
check "pft-internals status OK on both hosts, no restart or anomaly counted" "$([ "$(grep -c '^RESULT: OK' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^  (restarts|anomalies) +0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "tf_check"
check "both textfiles valid, under 61440 bytes and carry > 200 series" "$([ "$(awk '$2 < 61440 && $3 > 200 && $4 == "valid"' <<<"$XOUT" | wc -l)" = 2 ] && echo 0 || echo 1)"
x "sleep 45; prom_check"
check "Prometheus, validator and sentry: > 200 series each, up 1, restarts 0, anomalies 0" "$([ "$(awk 'NF == 2 && $2 > 200' <<<"$XOUT" | wc -l)" = 2 ] && [ "$(grep -cE '^postfiatd(-sentry)? pft_internals_up 1$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^postfiatd(-sentry)? pft_internals_(node_restarts|counter_anomalies)_total 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^RESULT'"
check "aptrust audit on both hosts: 0 warn, 0 fail (new binaries are in its allowlist copy)" "$([ "$(grep -c ' 0 warn, 0 fail -> exit 0' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust.service; R 'sudo -n systemctl start pft-aptrust.service'; sudo -n systemctl start pft-aptrust-pull.service; grep -hE '^pft_aptrust_checks\{.*result=\"(warn|fail)\"' $TF/pft_aptrust_*.prom"
check "aptrust textfiles (validator + pulled sentry): warn 0, fail 0" "$([ "$(grep -c '} 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts with 0 denials (the collector's docker exec curl is allowed)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 11. fleet skew, rulecheck, timers, jobwatch"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, internals CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +internals +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-jobwatch.service'; sudo -n systemctl start pft-jobwatch-pull.service; echo pulled"
x "s=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat | grep -E '^RESULT |internals'"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 's=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat' | grep -E '^RESULT |internals'"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck-pull.service; echo pulled"
x "systemctl is-active pft-internals@postfiatd.timer pft-internals-pull@postfiatd-sentry.timer; R 'systemctl is-active pft-internals@postfiatd-sentry.timer'; systemctl is-failed pft-internals@postfiatd.service pft-internals-pull@postfiatd-sentry.service; R 'systemctl is-failed pft-internals@postfiatd-sentry.service'"
check "timers active and services not failed on both hosts" "$([ "$(grep -cx active <<<"$XOUT")" = 3 ] && [ "$(grep -cx failed <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "TZ=UTC systemctl show -p TimersCalendar pft-internals@postfiatd.timer pft-internals-pull@postfiatd-sentry.timer"
check "timer calendars: collect every minute at :40, pull at :52" "$(grep -q 'OnCalendar=\*-\*-\* \*:\*:40' <<<"$XOUT" && grep -q 'OnCalendar=\*-\*-\* \*:\*:52' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*internals' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees both validator internals timers: not failed, missed or disabled" "$([ "$(grep -cE 'internals.* 0$' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"

echo; echo "== 12. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Internals|RuleDead|TextfileStale|Rulecheck|Fleet|Aptrust|Sched|PFTJob|KeyEscrow|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no internals/rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow/confinement alert pending or firing" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 30 600); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | .labels.alertname | select(. != \"PFTAlertPipelineWatchdog\")] | map(select(. as \$a | \"$KNOWN_PENDING\" | split(\" \") | index(\$a) | not)) | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 30; done; echo \$n"
check "drained: only the watchdog (+ KNOWN_PENDING) pending/firing in Prometheus" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
if [ "$(tail -1 <<<"$XOUT")" = 0 ] && [ -n "$SIL" ]; then
  x "curl -s -o /dev/null -w '%{http_code}' -X DELETE $AM/api/v2/silence/$SIL"
  check "rollout silence ${SIL:0:8} expired" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"
else echo "rollout silence left to run out (not drained)"; fi
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l"
check "no transient run-u services/timers" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s after the silence expiry (>= group_interval + 30 s)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "wrap-upgrade-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
