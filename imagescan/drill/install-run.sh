#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host install of imagescan at the current HEAD (task_76248c8a4b04f05417f1bd7088735a54), through
# pft-fleet inside a pft-maint window. Built from ../../budget/drill/install-run.sh (PASS, budget log 15). Installing
# changes NO node config, restarts nothing, never enters a container and pulls nothing: it adds the daily read-only
# image audit (pft-imagescan.service/.timer) on both hosts, the validator's 15-minute pull of the sentry textfile,
# the rulecheck lines and the six alert rules.
#   0. preflight: integrity PASS, nodes full, not installed, accept file present (same bytes both hosts), HEAD
#      carries the manifest/prometheus/rulecheck lines, tools, jobwatch budget, the pull's ssh source, operator
#      topics, Prometheus, alerts.
#   3. pft-fleet writes the manifest copy (fleet), the imagescan files on both hosts, then aptrust's allowlist copy.
#   5. sentry: install.sh --host sentry (first scan).  6. validator: install.sh --host validator, PULL_SSH,
#      install.sh --pull.  7. rulecheck lines.  8. rules loaded.  9. schedaudit + jobwatch + integrity accept.
#  10. VERIFIED: scan results, textfiles valid, Prometheus series, 0 unaccepted fixable high/critical in use,
#      docker image events (no pull/load/import/tag), aptrust 0/0, confinement 0 denials.
#  11. skew, rulecheck, timers, jobwatch.  12. restore + read-back.
# pft-maint's [MAINT] messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow is
# re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the imagescan/rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow/budget alerts (never the
# pipeline watchdog) and is left to run out.
#   bash imagescan/drill/install-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash imagescan/drill/install-run.sh  (step 0 only; changes nothing)
# KNOWN_PENDING: alert names already pending (long `for:`) before the run that the preflight accepts.
# KNOWN_FIRING: alert names already firing for an explained outside reason (digest-only routing, upstream feed not
# republished) that the preflight accepts; each is printed, and none of them is in the rollout silence.
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_76248c8a
KNOWN_PENDING="${KNOWN_PENDING:-}"
KNOWN_FIRING="${KNOWN_FIRING:-}"
TT="pft-drill-imagescan-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
ACC=/etc/pft-imagescan.accept
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-imagescan
SWAPPED=0; MAINT=0; HAD=0
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
restore() {
  ev_stop
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
  R "rm -rf ~/pft-imagescan-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
srv_state() { # both nodes' server_state, validator first (same exec shape as budget/drill/install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
tf_check() { # NAME BYTES SAMPLES valid, per textfile on the validator (local + pulled sentry copy)
  local n f
  for n in validator sentry; do
    f="$TF/pft_imagescan_$n.prom"
    echo "$n $(stat -c %s "$f") $(grep -vc '^#' "$f") $(pft-imagescan validate "$f" "$n" >/dev/null && echo valid)"
  done
}
prom_q() { # $1 = PromQL; "host value" lines, or query-error (fails closed)
  local j
  j="$(curl -s --max-time 10 "$PROM/api/v1/query" --data-urlencode "query=$1")"
  if [ -n "$j" ] && jq -e '.status == "success"' <<<"$j" >/dev/null 2>&1; then
    jq -r '.data.result[] | "\(.metric.host // "-") \(.value[1])"' <<<"$j" | sort
  else echo query-error; fi
}
scan_summary() { # allowlist of report lines (header, feeds, containers, per-image counts); never advisory/package lines
  grep -E '^(pft-imagescan (scan|report)|fetch:|feed |container |IMAGE |  provenance:|  count |  fixable high/critical|  findings_sha256)' | cut -c1-200
}
# stream files: EVR is relative to the sentry login home
EVL="$HOME/.cache/imagescan-imgev-$SHORT.txt"; EVR=".cache/imagescan-imgev-$SHORT.txt"
EVPID=""; EVRPID=""
ev_start() { # live docker image event streams on both hosts for the whole run (the daemon keeps only ~256 past
  # events, and the existing collectors' execs fill that buffer within hours, so a look-back query is not proof)
  # shellcheck disable=SC2024  # the stream file belongs to the agent user on purpose
  sudo -n timeout 7200 docker events --filter type=image --format '{{.Action}}' > "$EVL" 2>&1 &
  EVPID=$!
  EVRPID="$(R "nohup sudo -n timeout 7200 docker events --filter type=image --format '{{.Action}}' > $EVR 2>&1 < /dev/null & echo \$!")"
  sleep 2; echo "  image event streams started (validator pid ${EVPID:-none}, sentry pid ${EVRPID:-none})"
}
ev_stop() { # stop both streams (by saved PID), print the action counts of each host
  # sudo does not relay a signal sent from its own process group (the runner's), so signal its child (timeout),
  # by parent PID; run 10 hung in `wait` on `sudo kill $EVPID` until the child was killed by hand
  [ -z "$EVPID" ] || { sudo -n pkill -TERM -P "$EVPID" 2>/dev/null; wait "$EVPID" 2>/dev/null; EVPID=""; }
  [ -z "$EVRPID" ] || { R "sudo -n kill $EVRPID" 2>/dev/null; EVRPID=""; }
}
ev_counts() {
  echo "validator:"; sort "$EVL" | uniq -c; echo "sentry:"; R "sort $EVR | uniq -c; rm -f $EVR"; rm -f "$EVL"; echo image-events-end
}
echo "imagescan two-host install - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum imagescan/pft-imagescan.sh imagescan/imagescan_lib.py imagescan/install.sh imagescan/drill/install-run.sh imagescan/systemd/* alerts/imagescan.rules.yml alerts/imagescan.tests.yml fleet/manifest.tsv"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before install" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-imagescan /etc/pft-imagescan.env /var/cache/pft-imagescan 2>&1; R 'ls /usr/local/bin/pft-imagescan /etc/pft-imagescan.env /var/cache/pft-imagescan 2>&1'"
check "not installed yet on either host (no script, conf or cache)" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"
x "sudo -n sha256sum $ACC | cut -c1-64; R 'sudo -n sha256sum $ACC | cut -c1-64'; stat -c '%a %U' $ACC; R 'stat -c \"%a %U\" $ACC'; sudo -n grep -vc '^#' $ACC"
check "accept file (operator decision A, 30 days) present, same bytes, root 644 on both hosts, 10 lines" "$([ "$(sed -n 1p <<<"$XOUT")" = "$(sed -n 2p <<<"$XOUT")" ] && [ "$(grep -cx '644 root' <<<"$XOUT")" = 2 ] && [ "$(tail -1 <<<"$XOUT")" = 10 ] && echo 0 || echo 1)"
x "python3 -I -c 'import sys, time; sys.path.insert(0, \"imagescan\"); import imagescan_lib as L; e, x = L.load_accept(sys.argv[1], int(time.time())); print(len(e), x)' $ACC"
check "accept file parses with the repo's own reader: 10 entries, 0 expired" "$([ "$(tail -1 <<<"$XOUT")" = "10 0" ] && echo 0 || echo 1)"
x "grep -c '^imagescan ' fleet/manifest.tsv; grep -c imagescan.rules.yml alerts/prometheus.yml; grep -c pft_imagescan rulecheck/pft-rulecheck.conf.example; grep -c pft_imagescan rulecheck/pft-rulecheck.sentry.conf.example"
check "HEAD lists 6 imagescan manifest lines, the rule file and 3 + 2 rulecheck lines" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "6 1 3 2 " ] && echo 0 || echo 1)"
x "for h in L R; do if [ \$h = L ]; then bash -c 'for c in python3 docker curl jq; do command -v \$c; done | wc -l; sudo -n test -f /etc/pft-rulecheck.conf && echo rc-conf'; else R 'for c in python3 docker curl jq; do command -v \$c; done | wc -l; sudo -n test -f /etc/pft-rulecheck.conf && echo rc-conf'; fi; done"
check "python3 docker curl jq and a pft-rulecheck conf on both hosts" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "4 rc-conf 4 rc-conf " ] && echo 0 || echo 1)"
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
x "curl -s --max-time 10 $PROM/api/v1/alerts | jq -r .status; curl -s --max-time 10 $AM/api/v2/status | jq -r 'if (.uptime // \"\") != \"\" then \"up\" else \"down\" end'"
check "Prometheus and Alertmanager answer (alert gates below fail closed)" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "success up " ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
echo "known pending before the run (accepted by the preflight): ${KNOWN_PENDING:-none}"
echo "known firing before the run (explained outside events, accepted by the preflight): ${KNOWN_FIRING:-none}"
UNK="$(sed 1d <<<"$XOUT" | awk '{print $2}' | grep -vx PFTAlertPipelineWatchdog | while read -r a; do case " $KNOWN_PENDING $KNOWN_FIRING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "no active silence; only the pipeline watchdog (+ KNOWN_PENDING/KNOWN_FIRING) pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$UNK" = 0 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | select(.state == \"firing\") | .labels.alertname' | grep -vx PFTAlertPipelineWatchdog | sort -u"
UNKF="$(grep -v '^$' <<<"$XOUT" | while read -r a; do case " $KNOWN_FIRING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "nothing but the watchdog (+ KNOWN_FIRING) FIRING; KNOWN_PENDING may only be pending" "$([ "$XRC" -le 1 ] && [ "$UNKF" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 0b. live docker image event streams (both hosts, read-only)"
echo "\$ ev_start   (called directly, not through x: the stream PIDs must stay in this shell)"
ev_start
check "image event streams running on both hosts" "$([ -n "$EVPID" ] && sudo -n kill -0 "$EVPID" 2>/dev/null && [ -n "$EVRPID" ] && R "sudo -n kill -0 $EVRPID" 2>/dev/null && echo 0 || echo 1)"

echo; echo "== 1. rollout silence (new rules; rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow/budget see new files, units and timers; not the watchdog)"
ends="$(date -u -d '+90 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK imagescan rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTImagescan.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTSchedEntryUnexpected|PFTSchedFinding.*|PFTJob.*|PFTKeyEscrow.*|PFTBudget.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "imagescan-install", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (imagescan rules, rulecheck, fleet, aptrust, schedaudit, jobwatch, keyescrow, budget; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 75m --reason '$TASK imagescan install'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"

echo; echo "== 3. pft-fleet: manifest (fleet add-on), imagescan, then aptrust's allowlist copy"
[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the first host change (restore runs)"; exit 1; }
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK imagescan manifest lines'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon imagescan --to $SHA --apply --reason '$TASK imagescan $SHORT first install'"
check "imagescan sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust allowlist copy += imagescan rows'"
check "aptrust sync exit 0 (its manifest copy follows the new rows)" "$XRC"
x "sha256sum imagescan/pft-imagescan.sh imagescan/imagescan_lib.py imagescan/systemd/pft-imagescan.service imagescan/systemd/pft-imagescan.timer | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-imagescan /usr/local/lib/pft-imagescan/imagescan_lib.py /etc/systemd/system/pft-imagescan.service /etc/systemd/system/pft-imagescan.timer | cut -c1-64; R 'sha256sum /usr/local/bin/pft-imagescan /usr/local/lib/pft-imagescan/imagescan_lib.py /etc/systemd/system/pft-imagescan.service /etc/systemd/system/pft-imagescan.timer | cut -c1-64'"
check "installed script + helper + units = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 4 ] && echo 0 || echo 1)"
x "sha256sum imagescan/systemd/pft-imagescan-pull.service imagescan/systemd/pft-imagescan-pull.timer | cut -c1-64; sudo -n sha256sum /etc/systemd/system/pft-imagescan-pull.service /etc/systemd/system/pft-imagescan-pull.timer | cut -c1-64; R 'ls /etc/systemd/system/pft-imagescan-pull.service 2>&1'"
check "pull units = repo bytes on the validator, absent on the sentry (role validator)" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 2' | wc -l)" = 2 ] && grep -q 'No such file' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 5. sentry: install.sh --host sentry (first scan reads every local image once)"
x "git archive $SHA imagescan | R 'rm -rf ~/pft-imagescan-$SHORT && mkdir -m 700 ~/pft-imagescan-$SHORT && tar -x -C ~/pft-imagescan-$SHORT'"
x "R 'sudo -n bash ~/pft-imagescan-$SHORT/imagescan/install.sh --host sentry'"
check "sentry install exit 0, rulecheck lines added, first scan up 1, timer enabled" "$([ "$XRC" = 0 ] && [ "$(grep -c 'added to /etc/pft-rulecheck.conf' <<<"$XOUT")" = 2 ] && grep -q 'pft_imagescan_up{host="sentry"} 1' <<<"$XOUT" && grep -q 'enabled pft-imagescan.timer' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n journalctl -u pft-imagescan.service --since @$since --no-pager -o cat' | scan_summary"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 6. validator: install.sh --host validator, then PULL_SSH and install.sh --pull"
x "sudo -n bash imagescan/install.sh --host validator"
check "validator install exit 0, rulecheck lines added, first scan up 1, timer enabled" "$([ "$XRC" = 0 ] && [ "$(grep -c 'added to /etc/pft-rulecheck.conf' <<<"$XOUT")" = 2 ] && grep -q 'pft_imagescan_up{host="validator"} 1' <<<"$XOUT" && grep -q 'enabled pft-imagescan.timer' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n journalctl -u pft-imagescan.service --since @$since --no-pager -o cat | scan_summary"
x "sudo -n bash -c 'grep -q \"^PULL_SSH=\" /etc/pft-imagescan.env || grep \"^PULL_SSH=\" /etc/pft-statewatch.env >> /etc/pft-imagescan.env; grep -c \"^PULL_SSH=\" /etc/pft-imagescan.env; stat -c \"%a %U\" /etc/pft-imagescan.env'"
check "validator conf: one PULL_SSH (copied, not printed), root-owned 600" "$(grep -qx 1 <<<"$XOUT" && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash imagescan/install.sh --pull"
check "validator --pull exit 0, rulecheck require line added, pulled sentry textfile has up 1, timer enabled" "$([ "$XRC" = 0 ] && grep -q 'added to /etc/pft-rulecheck.conf: require pft_imagescan_sentry.prom' <<<"$XOUT" && grep -q 'pft_imagescan_up{host="sentry"} 1' <<<"$XOUT" && grep -q 'enabled pft-imagescan-pull.timer' <<<"$XOUT" && echo 0 || echo 1)"

[ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }
echo; echo "== 7. rulecheck inputs (written once by install.sh)"
x "sudo -n grep -n pft_imagescan /etc/pft-rulecheck.conf; R 'sudo -n grep -n pft_imagescan /etc/pft-rulecheck.conf'"
check "validator 3 + sentry 2 pft_imagescan rulecheck lines, each once" "$([ "$(grep -c pft_imagescan <<<"$XOUT")" = 5 ] && [ "$(grep -c 'require pft_imagescan_sentry.prom' <<<"$XOUT")" = 2 ] && [ "$(grep -c 'require pft_imagescan_validator.prom' <<<"$XOUT")" = 1 ] && [ "$(grep -c 'textfile pft_imagescan_' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 8. load the alert rules (alerts/ is mounted at /etc/pft-alerts) and check them"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 40 && curl -s $PROM/api/v1/status/runtimeinfo | jq -r .data.reloadConfigSuccess && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-imagescan\") | .rules[] | [.name, .health, .state] | @tsv'"
check "config reload ok, 6 imagescan rules loaded, health ok, inactive" "$(grep -qx true <<<"$XOUT" && [ "$(grep -c '	ok	inactive' <<<"$XOUT")" = 6 ] && [ "$(grep -c '^PFTImagescan' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"

echo; echo "== 9. new units/timers + conf: pft-schedaudit accept + collect, jobwatch inventory, then pft-integrity accept, both hosts"
x "sudo -n pft-schedaudit audit | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160; R 'sudo -n pft-schedaudit audit' | grep -E '^(NEW|REMOVED|SUMMARY)' | cut -c1-160"
x "sudo -n pft-schedaudit accept --reason '$TASK: pft-imagescan + pft-imagescan-pull installed' | tail -2; sudo -n pft-schedaudit collect | tail -1"
x "R \"sudo -n pft-schedaudit accept --reason '$TASK: pft-imagescan installed' | tail -2; sudo -n pft-schedaudit collect | tail -1\""
x "sudo -n pft-jobwatch inventory 2>&1 | grep -E 'imagescan|SUMMARY' | cut -c1-200; R 'sudo -n pft-jobwatch inventory 2>&1' | grep -E 'imagescan|SUMMARY' | cut -c1-200"
check "jobwatch learns 86400 s for both pft-imagescan.timer and 900 s for the validator pull" "$([ "$(grep -E '^pft-imagescan\.timer' <<<"$XOUT" | grep -cw 86400)" = 2 ] && [ "$(grep -E '^pft-imagescan-pull\.timer' <<<"$XOUT" | grep -cw 900)" = 1 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "sudo -n pft-integrity accept --reason '$TASK: imagescan $SHORT installed (conf, cache dir, units, timers, rulecheck.conf, sched items)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -40"
x "R \"sudo -n pft-integrity accept --reason '$TASK: imagescan $SHORT installed (conf, cache dir, units, timer, rulecheck.conf, sched items)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit on both hosts: 0 unexpected, 0 new/removed" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-schedaudit-pull.service; grep -h '^pft_schedaudit_unexpected' $TF/pft_schedaudit_*.prom | grep -vc ' 0$'"
check "schedaudit textfiles: every pft_schedaudit_unexpected series 0 (validator + pulled sentry copy)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 10. VERIFIED: scan results, textfiles, Prometheus series, docker image events, aptrust, confinement"
x "TZ=UTC systemctl show -p Result -p ExecMainStatus -p MemoryPeak pft-imagescan.service; R 'TZ=UTC systemctl show -p Result -p ExecMainStatus -p MemoryPeak pft-imagescan.service'"
check "first scan unit result success (exit 0/1) on both hosts" "$([ "$(grep -cx 'Result=success' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^ExecMainStatus=[01]$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-imagescan-pull.service; tf_check"
check "both textfiles valid and under 61440 bytes" "$([ "$(awk '$2 < 61440 && $3 > 3 && $4 == "valid"' <<<"$XOUT" | wc -l)" = 2 ] && echo 0 || echo 1)"
x "grep -hE '^pft_imagescan_(up|drift|accept_expired|fixable_high_critical)\{' $TF/pft_imagescan_validator.prom $TF/pft_imagescan_sentry.prom"
check "textfiles: up 1, drift 0, accept_expired 0, every fixable_high_critical series 0 (both hosts)" "$([ "$(grep -c '^pft_imagescan_up{.*} 1$' <<<"$XOUT")" = 2 ] && [ "$(grep -E '^pft_imagescan_(drift|accept_expired|fixable_high_critical)\{' <<<"$XOUT" | grep -vc ' 0$')" = 0 ] && echo 0 || echo 1)"
x "grep -hE '^pft_imagescan_findings\{.*accepted=\"true\"' $TF/pft_imagescan_validator.prom $TF/pft_imagescan_sentry.prom | awk '{s[\$0 ~ /host=\"sentry\"/ ? \"sentry\" : \"validator\"] += \$NF} END {for (h in s) print h, s[h]}' | sort"
check "10 accepted findings (the upstream postfiatd image) on each host" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "sentry 10 validator 10 " ] && echo 0 || echo 1)"
x "sleep 45; prom_q 'count by (host) ({__name__=~\"pft_imagescan_.+\"})'; prom_q 'pft_imagescan_up'; prom_q 'sum by (host) (pft_imagescan_fixable_high_critical{in_use=\"true\"})'"
check "Prometheus has pft_imagescan series and up 1 for validator and sentry, 0 unaccepted fixable high/critical in use" "$(! grep -q query-error <<<"$XOUT" && [ "$(grep -cE '^(validator|sentry) 1$' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(validator|sentry) 0$' <<<"$XOUT")" = 2 ] && [ "$(awk '$2 > 10' <<<"$XOUT" | wc -l)" = 2 ] && echo 0 || echo 1)"
echo "\$ ev_stop   (called directly)"; ev_stop
x "ev_counts"
check "docker image events during the run on both hosts: saves seen on each (presence control), no pull, push, load, import, tag, untag or delete" "$(grep -q image-events-end <<<"$XOUT" && [ "$(sed -n '/^validator:/,/^sentry:/p' <<<"$XOUT" | grep -cwE '[0-9]+ save')" = 1 ] && [ "$(sed -n '/^sentry:/,/image-events-end/p' <<<"$XOUT" | grep -cwE '[0-9]+ save')" = 1 ] && ! grep -qwE 'pull|push|load|import|tag|untag|delete' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n docker events --since $since --until \$(date -u +%s) --filter event=exec_create --format '{{.Actor.Attributes.name}} {{.Action}}' | cut -c1-60 | sed -E 's/[0-9]{4,}/N/g' | sort | uniq -c"
echo "  (exec_create events above come from the existing collectors' fixed curl/cat shapes; imagescan's no-exec guarantee is the docker-stub test test_shell_scan_only_readonly_docker_calls_and_cache)"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^RESULT'"
check "aptrust audit on both hosts: 0 warn, 0 fail (new binaries are in its allowlist copy)" "$([ "$(grep -c ' 0 warn, 0 fail -> exit 0' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust.service; R 'sudo -n systemctl start pft-aptrust.service'; sudo -n systemctl start pft-aptrust-pull.service; grep -hE '^pft_aptrust_checks\{.*result=\"(warn|fail)\"' $TF/pft_aptrust_*.prom"
check "aptrust textfiles (validator + pulled sentry): warn 0, fail 0" "$([ "$(grep -c '} 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts with 0 denials (imagescan never enters the containers)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 11. fleet skew, rulecheck, timers, jobwatch"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, imagescan CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +imagescan +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n systemctl start pft-jobwatch.service'; sudo -n systemctl start pft-jobwatch-pull.service; echo pulled"
x "s=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat | grep -E '^RESULT |imagescan'"
check "validator pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "R 's=\$(date +%s); sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since @\$s --no-pager -o cat' | grep -E '^RESULT |imagescan'"
check "sentry pft-rulecheck RESULT OK" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-rulecheck-pull.service; echo pulled"
x "systemctl is-active pft-imagescan.timer pft-imagescan-pull.timer; R 'systemctl is-active pft-imagescan.timer'; systemctl is-failed pft-imagescan.service pft-imagescan-pull.service; R 'systemctl is-failed pft-imagescan.service'"
check "timers active and services not failed on both hosts" "$([ "$(grep -cx active <<<"$XOUT")" = 3 ] && [ "$(grep -cx failed <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "TZ=UTC systemctl show -p TimersCalendar pft-imagescan.timer pft-imagescan-pull.timer"
check "timer calendars: scan daily 05:10 UTC, pull every 15 min at :08" "$(grep -q 'OnCalendar=\*-\*-\* 05:10:00 UTC' <<<"$XOUT" && grep -q 'OnCalendar=\*-\*-\* \*:08/15:00' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*imagescan' $TF/pft_jobwatch_validator.prom; wc -c < $TF/pft_jobwatch_validator.prom"
check "jobwatch sees both validator imagescan timers: not failed, missed or disabled" "$([ "$(grep -cE 'imagescan.* 0$' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"

echo; echo "== 12. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Imagescan|RuleDead|TextfileStale|Rulecheck|Fleet|Aptrust|Sched|PFTJob|KeyEscrow|Budget|Integrity|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no imagescan/rulecheck/fleet/aptrust/schedaudit/jobwatch/keyescrow/budget/confinement alert pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R 'ls -d ~/pft-imagescan-* 2>/dev/null | wc -l'"
check "no transient run-u services/timers, no install copy left on the sentry" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "install-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
