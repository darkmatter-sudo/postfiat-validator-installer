#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host install of backupwatch at the current HEAD (task_e65845e5a1921cf388ffb4d25035676e, step 4), through
# pft-fleet inside a pft-maint window. Built from ../../schedaudit/drill/install-run.sh (PASS). Nothing is restarted;
# no backup is restored; the node is never touched (docker inspect + RPC server_info only).
#   0. preflight: integrity PASS, nodes full, not installed, HEAD carries the manifest/prometheus/rulecheck lines, the
#      keyescrow link (PEER_SSH, PEER_RECIPIENT = the sentry's age.pub) and the sentry identity exist; read-only check.
#   3. pft-fleet writes the manifest and the backupwatch files on both hosts (and accepts them in pft-integrity).
#   4. sentry: install.sh --role replica.  5. validator: install.sh --role archive (first replicate + collect + pull).
#   6. rulecheck lines.  7. rules loaded.  8. schedaudit + integrity accept the new timers/conf on both hosts.
#   9. VERIFIED: check --offhost exit 0, replica ciphertext sha256 on the sentry == the validator's record, Prometheus.
# pft-maint's [MAINT] messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow is
# re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the backupwatch/rulecheck/fleet/schedaudit/jobwatch alerts (never the pipeline watchdog) and is
# left to run out.
#   bash backupwatch/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash backupwatch/drill/install-run.sh   (step 0 only; changes nothing)
#   RESUME=<run> bash ...   re-run after a stopped run at the same HEAD (checks installed bytes == HEAD instead of absent)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_e65845e5
TT="pft-drill-backupwatch-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#age1[a-z0-9]{58}#<age-recipient>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-backupwatch
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
  R "rm -rf /tmp/pft-backupwatch-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
echo "backupwatch two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum backupwatch/pft-backupwatch.sh backupwatch/backupwatch_lib.py backupwatch/install.sh backupwatch/drill/install-run.sh backupwatch/systemd/* alerts/backupwatch.rules.yml"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-backupwatch /etc/pft-backupwatch.env 2>&1; R 'ls /usr/local/bin/pft-backupwatch /etc/pft-backupwatch.env 2>&1'"
if [ -n "${RESUME:-}" ]; then
  # re-run after a stopped run that installed at this same HEAD (steps 3-5 are idempotent: they must change nothing)
  x "sha256sum backupwatch/pft-backupwatch.sh backupwatch/backupwatch_lib.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-backupwatch /usr/local/lib/pft-backupwatch/backupwatch_lib.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-backupwatch /usr/local/lib/pft-backupwatch/backupwatch_lib.py | cut -c1-64'"
  check "RESUME after run $RESUME: installed script + helper = HEAD bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 2 ] && echo 0 || echo 1)"
else
  check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
fi
x "grep -c backupwatch fleet/manifest.tsv; grep -c backupwatch.rules.yml alerts/prometheus.yml; grep -c pft_backupwatch_ rulecheck/pft-rulecheck.conf.example rulecheck/pft-rulecheck.sentry.conf.example"
check "HEAD lists 8 manifest lines, the rule file and 3 + 2 rulecheck lines" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "8 1 rulecheck/pft-rulecheck.conf.example:3 rulecheck/pft-rulecheck.sentry.conf.example:2 " ] && echo 0 || echo 1)"
x "sudo -n grep -c '^PEER_SSH=' /etc/pft-keyescrow.env; sudo -n sed -n 's/^PEER_RECIPIENT=//p' /etc/pft-keyescrow.env | tr -d '\"\n' | sha256sum | cut -c1-16; R 'tr -d \"\\n\" < /var/lib/pft-keyescrow/age.pub | sha256sum | cut -c1-16; test -s /var/lib/pft-keyescrow/age.key && echo identity present'"
check "keyescrow link: PEER_SSH set, PEER_RECIPIENT == the sentry's age.pub (hash prefix), sentry identity present" "$([ "$(sed -n 1p <<<"$XOUT")" = 1 ] && [ "$(sed -n 2p <<<"$XOUT")" = "$(sed -n 3p <<<"$XOUT")" ] && grep -qx 'identity present' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'command -v age python3 sha256sum | wc -l'; command -v age python3 sha256sum | wc -l"
check "age, python3, sha256sum on both hosts" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "3 3 " ] && echo 0 || echo 1)"
x "sudo -n env PFT_BW_CONF=/nonexistent PFT_BW_HELPER=\$PWD/backupwatch/backupwatch_lib.py STATE_DIR=/nonexistent bash backupwatch/pft-backupwatch.sh check"
check "FOUND: read-only check of the newest archive with the HEAD code: every local check OK" "$([ "$XRC" = 0 ] && grep -q '^RESULT: OK' <<<"$XOUT" && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\" and (env.RESUME == null or .createdBy != \"backupwatch-install\"))] | length'; curl -s $AM/api/v2/alerts | jq -r '.[].labels.alertname' | sort | uniq -c"
check "no active silence (RESUME: other than the stopped run's own rollout silence); only the pipeline watchdog active in Alertmanager" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$(sed 1d <<<"$XOUT" | grep -vc PFTAlertPipelineWatchdog)" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (new rules; rulecheck/fleet/schedaudit/jobwatch see new files and timers; not the watchdog)"
ends="$(date -u -d '+60 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK backupwatch rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTBackup.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "backupwatch-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (backupwatch rules, rulecheck, fleet, schedaudit, jobwatch, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK backupwatch install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: manifest (fleet add-on), then the backupwatch files"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK backupwatch manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon backupwatch --to $SHA --apply --reason '$TASK backupwatch $SHORT first install'"
check "backupwatch sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum backupwatch/pft-backupwatch.sh backupwatch/backupwatch_lib.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-backupwatch /usr/local/lib/pft-backupwatch/backupwatch_lib.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-backupwatch /usr/local/lib/pft-backupwatch/backupwatch_lib.py | cut -c1-64'"
check "installed script + helper = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 2 ] && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 4. sentry: install.sh --role replica (collect through the sandboxed unit)"
x "git archive $SHA backupwatch | R 'rm -rf /tmp/pft-backupwatch-$SHORT && mkdir -m 700 /tmp/pft-backupwatch-$SHORT && tar -x -C /tmp/pft-backupwatch-$SHORT'"
x "R 'sudo -n bash /tmp/pft-backupwatch-$SHORT/backupwatch/install.sh --role replica --host sentry'"
check "sentry install exit 0, up 1" "$([ "$XRC" = 0 ] && grep -q 'pft_backupwatch_up{host="sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 5. validator: install.sh --role archive (first replicate, collect with --offhost, pull of the sentry file)"
x "sudo -n bash backupwatch/install.sh --role archive --host validator"
check "validator install exit 0, up 1, offhost 0" "$([ "$XRC" = 0 ] && grep -q 'pft_backupwatch_up{host="validator"} 1' <<<"$XOUT" && grep -q 'check_state{host="validator",check="offhost"} 0' <<<"$XOUT" && echo 0 || echo 1)"
# the sentry wrote its textfile at its own install (0 replicas); its next timer collect is up to 15 min away, so
# collect there now and pull again (run 08 checked the stale copy and stopped here)
x "R 'sudo -n systemctl start pft-backupwatch.service; systemctl is-failed pft-backupwatch.service'; sudo -n systemctl start pft-backupwatch-pull.service; systemctl is-failed pft-backupwatch-pull.service"
x "sudo -n grep -E '^pft_backupwatch_(up|replicas|replica_verify_ok)' $TF/pft_backupwatch_sentry.prom"
check "pulled sentry file on the validator: up 1, replicas 1, replica_verify_ok 1" "$(grep -q 'up{host="sentry"} 1' <<<"$XOUT" && grep -q 'replicas{host="sentry"} 1' <<<"$XOUT" && grep -q 'replica_verify_ok{host="sentry"} 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash -c 'grep -E \"^(ROLE|HOST_LABEL|OFFHOST)=\" /etc/pft-backupwatch.env; grep -c \"^PEER_SSH=\" /etc/pft-backupwatch.env; grep -c \"^REPLICA_RECIPIENT=age1\" /etc/pft-backupwatch.env; stat -c \"%a %U\" /etc/pft-backupwatch.env'"
check "validator conf: ROLE archive, OFFHOST 1, one PEER_SSH, one recipient, 600 root" "$(grep -qx ROLE=archive <<<"$XOUT" && grep -qx OFFHOST=1 <<<"$XOUT" && [ "$(grep -cx 1 <<<"$XOUT")" = 2 ] && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash backupwatch/install.sh --role archive --host validator 2>&1 | grep -E 'installed|set |changed='"
check "second install run is idempotent (changed=false, nothing installed or set)" "$(grep -q 'changed=false' <<<"$XOUT" && ! grep -qE ' installed | set ' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 6. rulecheck inputs: append the backupwatch lines (idempotent; the live confs carry earlier add-ons' lines)"
RC_TF='textfile pft_backupwatch_*.prom   45m   pft_backupwatch_collect_timestamp_seconds'
x "sudo -n grep -qF 'pft_backupwatch_' /etc/pft-rulecheck.conf || printf '%s\n' '# pft-backupwatch (15-minute collector; sentry copy pulled every 15 min)' '$RC_TF' 'require pft_backupwatch_validator.prom' 'require pft_backupwatch_sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n backupwatch /etc/pft-rulecheck.conf"
check "validator rulecheck.conf has the 4 backupwatch lines" "$([ "$(grep -c backupwatch <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "R \"sudo -n grep -qF 'pft_backupwatch_' /etc/pft-rulecheck.conf || printf '%s\\n' '# pft-backupwatch (15-minute collector, replica role)' '$RC_TF' 'require pft_backupwatch_sentry.prom' | sudo -n tee -a /etc/pft-rulecheck.conf >/dev/null; sudo -n grep -n backupwatch /etc/pft-rulecheck.conf\""
check "sentry rulecheck.conf has the 3 backupwatch lines" "$([ "$(grep -c backupwatch <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 7. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 40 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name | test(\"backupwatch\")) | .rules[] | [.name, .health, .state] | @tsv'"
check "5 backupwatch rules loaded, health ok, none firing" "$([ "$(grep -c '	ok	' <<<"$XOUT")" = 5 ] && ! grep -q 'firing' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 8. new timers + conf: pft-schedaudit accept, then pft-integrity accept, on both hosts"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160"
x "sudo -n pft-schedaudit accept --reason '$TASK: pft-backupwatch timers (collect, pull, replicate) installed' | tail -2"
x "R 'sudo -n pft-schedaudit audit' | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160"
x "R \"sudo -n pft-schedaudit accept --reason '$TASK: pft-backupwatch collect timer installed'\" | tail -2"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "sudo -n pft-integrity accept --reason '$TASK: backupwatch $SHORT installed (env, timers, state dir, rulecheck.conf, sched items)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "R \"sudo -n pft-integrity accept --reason '$TASK: backupwatch $SHORT installed (env, timer, state + replica dirs, rulecheck.conf, sched items)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit.service; sudo -n pft-schedaudit audit | grep -E '^SUMMARY'"
check "validator schedaudit: 0 unexpected, 0 new/removed" "$(grep -q '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-schedaudit.service; sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "sentry schedaudit: 0 unexpected, 0 new/removed" "$(grep -q '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit-pull.service; sudo -n systemctl is-failed pft-schedaudit-pull.service"

echo; echo "== 9. VERIFIED: offhost check, cross-host replica sha256, Prometheus"
x "sudo -n pft-backupwatch check --offhost"
check "validator check --offhost: every check OK, exit 0" "$([ "$XRC" = 0 ] && grep -q '^RESULT: OK' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n cat /var/lib/pft-backupwatch/replica.tsv | tail -1 | cut -f1-3"
VREC="$XOUT"
x "R 'cd /var/lib/pft-backupwatch/replicas && ls -1 && sha256sum *.age'"
RNAME="$(awk '{print $1}' <<<"$VREC")"; RCS="$(awk '{print $2}' <<<"$VREC")"
check "replica ciphertext sha256 on the sentry == the validator's record for $RNAME" "$([ -n "$RCS" ] && grep -q "^$RCS  $RNAME.age$" <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n sha256sum /var/backups/postfiat/$RNAME | cut -c1-64; sudo -n cut -c1-64 /var/backups/postfiat/$RNAME.sha256"
RPS="$(awk '{print $3}' <<<"$VREC")"
check "recorded plaintext sha256 == the archive's sha256 == its sidecar" "$([ "$(sort -u <<<"$XOUT$(printf '\n%s' "$RPS")" | grep -c .)" = 1 ] && echo 0 || echo 1)"
x "R 'sudo -n pft-backupwatch serve verify $RNAME'"
check "sentry serve verify: OK (re-hash + in-memory decrypt)" "$(grep -q "^VERIFY $RNAME OK" <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 30; curl -s $PROM/api/v1/query --data-urlencode 'query={__name__=~\"pft_backupwatch_(up|check_state|replica_verify_ok|replicas|drift_overdue)\"}' | jq -r '.data.result[] | \"\(.metric.host) \(.metric.__name__) \(.metric.check // \"-\") \(.value[1])\"' | sort"
check "Prometheus: pft_backupwatch_up 1 for both hosts" "$([ "$(grep -cE ' pft_backupwatch_up - 1$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
check "Prometheus: 7 validator check states 0, drift_overdue 0, sentry replicas 1 + verify_ok 1" "$([ "$(grep -cE '^validator pft_backupwatch_check_state [a-z]+ 0$' <<<"$XOUT")" = 7 ] && grep -q '^validator pft_backupwatch_drift_overdue - 0$' <<<"$XOUT" && grep -q '^sentry pft_backupwatch_replicas - 1$' <<<"$XOUT" && grep -q '^sentry pft_backupwatch_replica_verify_ok - 1$' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 10. fleet skew, rulecheck, timers, jobwatch"
x "sudo -n pft-fleet skew"
# fleet is a validator-only add-on (no sentry row): run 11 expected 4 rows here and printed a false FAIL
check "pft-fleet skew exit 0, backupwatch CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +backupwatch +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT |backupwatch'"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat' | grep -E '^RESULT |backupwatch'"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "systemctl is-active pft-backupwatch.timer pft-backupwatch-pull.timer pft-backupwatch-replicate.timer; R 'systemctl is-active pft-backupwatch.timer'"
check "4 timers active" "$([ "$(grep -cx active <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*backupwatch' $TF/pft_jobwatch_validator.prom"
check "jobwatch sees the 3 validator backupwatch timers: none failed, missed or disabled" "$([ "$(grep -cE 'backupwatch.* 0$' <<<"$XOUT")" = 9 ] && echo 0 || echo 1)"

echo; echo "== 11. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"PFTBackup|RuleDead|TextfileStale|Rulecheck|Fleet|Sched|PFTJob|KeyEscrow|Integrity\"))] | length'"
check "no backupwatch/rulecheck/fleet/schedaudit/jobwatch/keyescrow alert pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /dev/shm | grep -c pft-bw; R 'ls /dev/shm | grep -c pft-bw'"
check "no backupwatch scratch left in /dev/shm on either host" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
