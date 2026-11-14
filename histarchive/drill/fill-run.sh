#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded gap repair on the live validator archive (task_290beaeb808e4a988e422c2f5575972f). Built from install-run.sh
# (PASS, logs/07). Nothing on the node is restarted; only the histarchive follower is restarted to load the new code.
#   0. preflight (read-only): clean pushed HEAD, integrity PASS both, nodes full, installed on both hosts, the live
#      archive verifies with gaps 1 = 8042619-8042680, the committed capture's sha256 is the one recorded at capture.
#   1. rollout silence (histarchive/rulecheck/fleet/jobwatch/keyescrow alerts only; never the pipeline watchdog).
#   2. pft-maint window with [MAINT] to a throwaway topic.  3. pft-fleet sync --addon histarchive (both hosts).
#   4. validator: FILL_RPC in the conf, rulecheck lines for pft_histarchive_gaps.prom, follower restart (new code),
#      rules reload.  5. FOUND: verify gaps 1, gaps FILLABLE, gap_fillable 1 in Prometheus, alert pending, seqcheck.
#   6. FIX: fill-gap --dry-run, fill-gap from the committed capture, duplicate fill refused (no byte changed).
#   7. VERIFIED: verify gaps 0, seqcheck, gaps textfile + Prometheus 0, alert inactive, replicate, verify-replica,
#      sentry replica-check, restore-verify (SAME fill-...), follower advancing, no new gap.
#   8. scratch peer-RPC fill: a copy of the live archive with a deliberate 30-ledger gap is filled from the public
#      testnet RPC (read-only, 2 req/s) and verified (verify + seqcheck); the copy is removed.
#   9. integrity accept (conf, rulecheck.conf), skew, rulecheck, aptrust.  10. restore + read back every operator topic.
#   bash histarchive/drill/fill-run.sh 2>&1 | tee LOG          (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash histarchive/drill/fill-run.sh        (step 0 only; changes nothing)
#   RESUMED=1 SINCE=<unix> bash histarchive/drill/fill-run.sh  after a run that stopped at a gate once its steps 1-4 had
#      run: the preflight then expects the installed files to equal HEAD (instead of differing); active silences must all
#      be this drill's own (createdBy histarchive-fill*) and are kept until the clean end; PFTHistarchiveGapFillable may be
#      pending (FILL_RPC is configured and the gap is open: the expected FOUND state); the operator read-back starts at
#      SINCE (the first run's start). Steps 1-4 are idempotent and run again.
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_290beaeb
GAP=8042619-8042680
CAP=histarchive/logs/data/gap-8042619-8042680/capture-8042618-8042681.jsonl
CAP_SHA=3de3e996f83db302ca62b95eac33e0ac2ccb8f1a63463c5ebaf05bab38b96c0f
PUB=https://rpc.testnet.postfiat.org/
LIVE=/var/lib/pft-histarchive/archive
TT="pft-drill-histfill-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#age1[a-z0-9]{58}#<age-recipient>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-histfill
SWAPPED=0; MAINT=0; HAD=0; SCR=""
since="${SINCE:-$(date -u +%s)}"
RESUMED="${RESUMED:-0}"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
  if [ -n "$SCR" ]; then rm -rf "$SCR"; SCR=""; fi
}
trap 'restore; rm -f "$OPS"' EXIT
prom_q() { curl -s "$PROM/api/v1/query" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric.host) \(.metric.__name__) \(.value[1])"'; }
rule_state() { curl -s "$PROM/api/v1/rules" | jq -r --arg n "$1" '.data.groups[].rules[] | select(.name == $n) | "\(.name) \(.health) \(.state)"'; }
echo "histarchive gap repair - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum histarchive/pft-histarchive.sh histarchive/histarchive.py histarchive/lib_hashverify.py histarchive/tests/seqcheck.py histarchive/drill/fill-run.sh alerts/histarchive.rules.yml $CAP"
check "the committed capture is the one recorded when it was taken (sha256 $CAP_SHA)" "$(grep -q "^$CAP_SHA  $CAP$" <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sha256sum histarchive/pft-histarchive.sh histarchive/histarchive.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-histarchive /usr/local/lib/pft-histarchive/histarchive.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-histarchive /usr/local/lib/pft-histarchive/histarchive.py | cut -c1-64'"
if [ "$RESUMED" = 1 ]; then
  check "RESUMED: installed script + helper already equal HEAD on both hosts (synced by the stopped run)" "$([ "$(wc -l <<<"$XOUT")" = 6 ] && [ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 2 ] && echo 0 || echo 1)"
else
  check "installed on both hosts, script + helper differ from HEAD (the sync has something to do)" "$([ "$(wc -l <<<"$XOUT")" = 6 ] && [ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 0 ] && echo 0 || echo 1)"
fi
x "sudo -n pft-histarchive verify | tail -n 3"
check "FOUND: live archive verifies with the recorded gap $GAP open" "$([ "$XRC" = 0 ] && grep -q "NOTE recorded gap $GAP" <<<"$XOUT" && grep -q 'gaps 1 (62 ledgers)' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n cat $LIVE/gaps.jsonl; sudo -n test -e $LIVE/gapfills.jsonl && echo gapfills present || echo no gapfills.jsonl"
check "gaps.jsonl holds exactly the reboot gap; no fill yet" "$([ "$(grep -c '"from"' <<<"$XOUT")" = 1 ] && grep -q '"from":8042619,.*"to":8042680' <<<"$XOUT" && grep -qx 'no gapfills.jsonl' <<<"$XOUT" && echo 0 || echo 1)"
x "curl -s -m 15 -d '{\"method\":\"server_info\"}' $PUB | jq -r .result.info.complete_ledgers"
PUBR="$(tail -1 <<<"$XOUT")"
check "public RPC answers server_info (range $PUBR)" "$(grep -qE '^[0-9]+-[0-9]+' <<<"$PUBR" && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
OLD_SIL=""
if [ "$RESUMED" = 1 ]; then
  x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"\(.id) \(.createdBy) until \(.endsAt)\"'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"ALERT \(.labels.alertname) \(.state)\"' | sort"
  OLD_SIL="$(grep -v '^ALERT ' <<<"$XOUT" | grep ' histarchive-fill' | cut -d' ' -f1 | tr '\n' ' ')"
  check "RESUMED: active silences are all this drill's own (kept: ${OLD_SIL:-none}); only the watchdog + PFTHistarchiveGapFillable pending" "$([ "$(grep -v '^ALERT ' <<<"$XOUT" | grep -vc ' histarchive-fill')" = 0 ] && [ "$(grep '^ALERT ' <<<"$XOUT" | grep -v 'PFTAlertPipelineWatchdog' | grep -vc '^ALERT PFTHistarchiveGapFillable pending$')" = 0 ] && echo 0 || echo 1)"
else
  x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[].labels.alertname' | sort | uniq -c"
  check "no active silence; only the pipeline watchdog pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$(sed 1d <<<"$XOUT" | grep -vc PFTAlertPipelineWatchdog)" = 0 ] && echo 0 || echo 1)"
fi
x "systemctl list-units --all --no-legend 'run-u*' | wc -l"
check "no transient run-u units" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (histarchive rules incl. the new GapFillable, rulecheck, fleet, jobwatch, keyescrow; not the watchdog)"
ends="$(date -u -d '+60 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK histarchive gap repair $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTHistarchive.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "histarchive-fill", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && sudo -n install -o root -g root -m 600 /dev/null \$NE && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed (600 root)" "$([ "$XRC" = 0 ] && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK histarchive gap repair'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
gate

echo; echo "== 3. pft-fleet: histarchive files at HEAD on both hosts (manifest rows unchanged)"
x "sudo -n pft-fleet sync --addon histarchive --to $SHA --apply --reason '$TASK histarchive $SHORT gap repair (fill-gap, gaps)'"
check "histarchive sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum histarchive/pft-histarchive.sh histarchive/histarchive.py histarchive/lib_hashverify.py | cut -c1-64; sudo -n sha256sum /usr/local/bin/pft-histarchive /usr/local/lib/pft-histarchive/histarchive.py /usr/local/lib/pft-histarchive/lib_hashverify.py | cut -c1-64; R 'sha256sum /usr/local/bin/pft-histarchive /usr/local/lib/pft-histarchive/histarchive.py /usr/local/lib/pft-histarchive/lib_hashverify.py | cut -c1-64'"
check "installed script + helper + lib = repo bytes on both hosts" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 3' | wc -l)" = 3 ] && echo 0 || echo 1)"
x "R 'd=\$(mktemp -d -p ~ histrecv.XXXXXX); printf x | sudo -n env STATE_DIR=\$d pft-histarchive serve receive fill-8042619-8042680.jsonl.gz.age; echo rc=\$?; sudo -n rm -rf \$d'"
check "sentry's receive accepts a fill segment name (scratch STATE_DIR)" "$(grep -q 'stored fill-8042619-8042680.jsonl.gz.age' <<<"$XOUT" && grep -qx 'rc=0' <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 4. validator: FILL_RPC, rulecheck lines, follower restart (loads 1.1.0), rules reload"
x "sudo -n grep -q '^FILL_RPC=' /etc/pft-histarchive.env || echo 'FILL_RPC=$PUB' | sudo -n tee -a /etc/pft-histarchive.env >/dev/null; sudo -n grep -c '^FILL_RPC=' /etc/pft-histarchive.env; sudo -n stat -c '%a %U' /etc/pft-histarchive.env"
check "conf has one FILL_RPC line, still 600 root" "$([ "$(head -1 <<<"$XOUT")" = 1 ] && grep -qx '600 root' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n grep -q '^textfile pft_histarchive_gaps.prom' /etc/pft-rulecheck.conf || sudo -n sed -i '/^textfile pft_histarchive_replica.prom/a textfile pft_histarchive_gaps.prom      15m   pft_histarchive_gap_check_timestamp_seconds' /etc/pft-rulecheck.conf; sudo -n grep -q '^require pft_histarchive_gaps.prom' /etc/pft-rulecheck.conf || sudo -n sed -i '/^require pft_histarchive_replica.prom/a require pft_histarchive_gaps.prom' /etc/pft-rulecheck.conf; sudo -n grep -n histarchive /etc/pft-rulecheck.conf"
check "validator rulecheck.conf has the 9 histarchive lines (2 new)" "$([ "$(grep -c histarchive <<<"$XOUT")" = 9 ] && grep -q 'textfile pft_histarchive_gaps.prom' <<<"$XOUT" && grep -q 'require pft_histarchive_gaps.prom' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive status | jq -c '.status | {last, gaps}'; t0=\$(date +%s); sudo -n systemctl restart pft-histarchive.service; sleep 15; systemctl is-active pft-histarchive.service; sudo -n journalctl -u pft-histarchive.service --since @\$t0 --no-pager -o cat | grep -E 'follow:|RESUME|GAP|START' | cut -c1-200"
check "follower restarted on 1.1.0 and resumed with no new gap" "$(grep -qx active <<<"$XOUT" && grep -q 'histarchive 1.1.0 follow' <<<"$XOUT" && grep -q 'RESUME at ledger' <<<"$XOUT" && ! grep -q ' GAP ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n stat -c '%a %U %n' $LIVE/.lock"
check "follower created the archive lock file (owned by pft-histarchive)" "$(grep -q '^644 pft-histarchive ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 40 && curl -s $PROM/api/v1/rules | jq -r '.data.groups[] | select(.name | test(\"histarchive\")) | .rules[] | [.name, .health, .state] | @tsv'"
check "4 histarchive rules loaded (incl. PFTHistarchiveGapFillable), health ok" "$([ "$(grep -c '	ok	' <<<"$XOUT")" = 4 ] && grep -q '^PFTHistarchiveGapFillable	ok' <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 5. FOUND: the open gap, its fillability (metric + alert), independent sequence check"
x "sudo -n pft-histarchive verify | tail -n 3"
check "FOUND: verify PASS with gaps 1 (62 ledgers) filled 0 (new code)" "$([ "$XRC" = 0 ] && grep -q 'gaps 1 (62 ledgers) filled 0 fails 0' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive gaps; grep -v '^#' $TF/pft_histarchive_gaps.prom"
check "FOUND: gaps lists $GAP OPEN, anchors ok, public RPC holds it -> FILLABLE; textfile open 1 fillable 1 source_up 1" "$(grep -q "^OPEN   $GAP (62) anchors ok source holds it -> FILLABLE" <<<"$XOUT" && grep -q 'pft_histarchive_gap_fillable{host="validator"} 1$' <<<"$XOUT" && grep -q 'pft_histarchive_gap_open{host="validator"} 1$' <<<"$XOUT" && grep -q 'pft_histarchive_gap_source_up{host="validator"} 1$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 75; prom_q '{__name__=~\"pft_histarchive_(gap_fillable|gap_open|gaps)\"}'; rule_state PFTHistarchiveGapFillable"
check "FOUND: Prometheus gap_fillable 1, gap_open 1, gaps 1; PFTHistarchiveGapFillable pending (for 15m; silenced)" "$(grep -q '^validator pft_histarchive_gap_fillable 1$' <<<"$XOUT" && grep -q '^validator pft_histarchive_gap_open 1$' <<<"$XOUT" && grep -q '^validator pft_histarchive_gaps 1$' <<<"$XOUT" && grep -q '^PFTHistarchiveGapFillable ok pending$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n python3 -I histarchive/tests/seqcheck.py $LIVE"
check "FOUND: independent seqcheck PASS, missing 62 = open-gap ledgers 62" "$([ "$XRC" = 0 ] && grep -q 'missing 62 open-gap ledgers 62 filled gaps 0' <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 6. FIX: fill-gap from the committed capture (dry run, then for real), then a duplicate fill"
x "sudo -n pft-histarchive fill-gap $GAP --staged $CAP --dry-run"
check "dry run: every check passed, nothing written" "$([ "$XRC" = 0 ] && grep -q 'DRY RUN: every check passed; nothing written' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n sha256sum $LIVE/MANIFEST.jsonl $LIVE/gaps.jsonl | cut -c1-64; sudo -n ls $LIVE/segments"
PRE="$XOUT"
x "sudo -n pft-histarchive fill-gap $GAP --staged $CAP"
check "fill: 62 ledgers checked, chain 8042618->8042681 unbroken, FILL written, verify after PASS gaps 0 filled 1" "$([ "$XRC" = 0 ] && grep -q 'checks: 62 ledgers header+hash+txroot OK, chain 8042618->8042681 unbroken (63 links' <<<"$XOUT" && grep -q "FILL $GAP count=62" <<<"$XOUT" && grep -q 'gaps 0 (0 ledgers) filled 1 fails 0' <<<"$XOUT" && grep -q "RESULT: PASS - fill-gap $GAP, verify rc 0" <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n tail -n 1 $LIVE/MANIFEST.jsonl | jq -c '{kind, day, first, last, count, txs, anchor_below, anchor_above, source, tool, gap: .gap.reason, sha256_gz, entry, prev_entry}'; sudo -n cat $LIVE/gapfills.jsonl; sudo -n cat $LIVE/gaps.jsonl; sudo -n stat -c '%a %U %n' $LIVE/segments/fill-$GAP.jsonl.gz $LIVE/gapfills.jsonl"
check "MANIFEST fill entry (staged, capture sha256, both anchors), one gapfills line, gaps.jsonl unchanged, files owned by pft-histarchive" "$(grep -q '"kind":"fill"' <<<"$XOUT" && grep -q "\"sha256\":\"$CAP_SHA\"" <<<"$XOUT" && grep -q '"anchor_below":{"h":"8278888DEFBCB472' <<<"$XOUT" && grep -q '"anchor_above":{"h":"F35D4801640E85FB' <<<"$XOUT" && [ "$(grep -c '"segment":"segments/fill-' <<<"$XOUT")" = 1 ] && [ "$(grep -c '"reason":"pruned' <<<"$XOUT")" = 1 ] && [ "$(grep -c '^644 pft-histarchive ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n sha256sum $LIVE/gaps.jsonl | cut -c1-64"
check "gaps.jsonl byte-identical to before the fill (append-only, never rewritten)" "$([ "$XOUT" = "$(sed -n 2p <<<"$PRE")" ] && echo 0 || echo 1)"
x "sudo -n sha256sum $LIVE/MANIFEST.jsonl $LIVE/gapfills.jsonl | cut -c1-64; sudo -n ls $LIVE/segments"
POST="$XOUT"
x "sudo -n pft-histarchive fill-gap $GAP --staged $CAP; sudo -n sha256sum $LIVE/MANIFEST.jsonl $LIVE/gapfills.jsonl | cut -c1-64; sudo -n ls $LIVE/segments"
check "duplicate fill REFUSED (rc 1), MANIFEST/gapfills/segments unchanged" "$(grep -q 'REFUSED: gap 8042619-8042680 is already filled' <<<"$XOUT" && grep -q 'RESULT: REFUSED - fill-gap rc 1' <<<"$XOUT" && [ "$(sed '/^20[0-9-]*T/d; /^pft-histarchive fill-gap/d; /^RESULT/d' <<<"$XOUT")" = "$POST" ] && echo 0 || echo 1)"
gate

echo; echo "== 7. VERIFIED: verify, seqcheck, metrics + alert, replica, restore, follower"
x "sudo -n pft-histarchive verify | tail -n 3"
check "verify PASS: gaps 0 (0 ledgers) filled 1, NOTE filled gap $GAP" "$([ "$XRC" = 0 ] && grep -q "NOTE filled gap $GAP (62 ledgers, verified in the chain)" <<<"$XOUT" && grep -q 'gaps 0 (0 ledgers) filled 1 fails 0' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n python3 -I histarchive/tests/seqcheck.py $LIVE"
check "independent seqcheck PASS: missing 0, filled gaps 1" "$([ "$XRC" = 0 ] && grep -q 'missing 0 open-gap ledgers 0 filled gaps 1' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive gaps; grep -v '^#' $TF/pft_histarchive_gaps.prom; grep -E '^pft_histarchive_(gaps|gaps_filled|verify_ok)\{' $TF/pft_histarchive.prom"
check "gaps: FILLED by staged; textfiles open 0 fillable 0, verify_ok 1 gaps 0 gaps_filled 1" "$(grep -q "^FILLED $GAP (62) by staged" <<<"$XOUT" && grep -q 'pft_histarchive_gap_fillable{host="validator"} 0$' <<<"$XOUT" && grep -q 'pft_histarchive_gap_open{host="validator"} 0$' <<<"$XOUT" && grep -q 'pft_histarchive_gaps{host="validator"} 0$' <<<"$XOUT" && grep -q 'pft_histarchive_gaps_filled{host="validator"} 1$' <<<"$XOUT" && grep -q 'pft_histarchive_verify_ok{host="validator"} 1$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive replicate"
check "replicate PASS: the fill segment encrypted and sent" "$([ "$XRC" = 0 ] && grep -q "sent fill-$GAP.jsonl.gz.age" <<<"$XOUT" && grep -q 'RESULT: PASS - replicate fails 0' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive verify-replica"
check "verify-replica PASS" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "R 'sudo -n pft-histarchive replica-check; sudo -n ls /var/lib/pft-histarchive/replica | grep -c fill-'"
check "sentry replica-check PASS and holds the fill ciphertext" "$([ "$XRC" = 0 ] && grep -q '^RESULT: PASS' <<<"$XOUT" && grep -qx 1 <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive restore-verify"
check "restore-verify from the sentry PASS: SAME fill-$GAP, restored copy gaps 0 filled 1" "$([ "$XRC" = 0 ] && grep -q "SAME fill-$GAP ledgers $GAP" <<<"$XOUT" && grep -q 'gaps 0 (0 ledgers) filled 1 fails 0' <<<"$XOUT" && ! grep -q 'not yet in gapfills' <<<"$XOUT" && grep -q 'RESULT: PASS - restore-verify fails 0' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 75; prom_q '{__name__=~\"pft_histarchive_(gap_fillable|gap_open|gaps|gaps_filled|replica_ok)\"}'; rule_state PFTHistarchiveGapFillable; rule_state PFTHistarchiveIntegrity"
check "Prometheus: gap_fillable 0, gap_open 0, gaps 0, gaps_filled 1, replica_ok 1; GapFillable + Integrity inactive" "$(grep -q '^validator pft_histarchive_gap_fillable 0$' <<<"$XOUT" && grep -q '^validator pft_histarchive_gap_open 0$' <<<"$XOUT" && grep -q '^validator pft_histarchive_gaps 0$' <<<"$XOUT" && grep -q '^validator pft_histarchive_gaps_filled 1$' <<<"$XOUT" && grep -q '^validator pft_histarchive_replica_ok 1$' <<<"$XOUT" && grep -q '^PFTHistarchiveGapFillable ok inactive$' <<<"$XOUT" && grep -q '^PFTHistarchiveIntegrity ok inactive$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-histarchive status | jq -c '.status | {last, lag, gaps}'; sleep 20; sudo -n pft-histarchive status | jq -c '.status | {last, lag, gaps}'"
check "follower advancing (last grows in 20 s), recorded gaps still 1 (no new gap)" "$([ "$(sed -n 2p <<<"$XOUT" | jq .last)" -gt "$(sed -n 1p <<<"$XOUT" | jq .last)" ] && [ "$(sed -n 2p <<<"$XOUT" | jq .gaps)" = 1 ] && echo 0 || echo 1)"
gate

echo; echo "== 8. scratch peer-RPC fill: deliberate 30-ledger gap in a copy, filled from the public testnet RPC"
SCR="$(mktemp -d -p "$HOME/.cache" histfill.XXXXXX)"
x "sudo -n cp -a $LIVE \$SCR/arch && sudo -n chown -R \$(id -u):\$(id -g) \$SCR/arch && du -sh \$SCR/arch | cut -f1"
L="$(sudo -n pft-histarchive status | jq .status.last)"; A=$((L - 300)); B=$((A + 29))
echo "scratch gap: $A-$B (follower last $L)"
x "python3 - \$SCR/arch $A $B <<'PYEOF'
import json, os, sys, time
d, a, b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
act = os.path.join(d, 'active'); cut = 0
for f in sorted(os.listdir(act)):
    p = os.path.join(act, f); keep = []
    for x in open(p, 'rb'):
        if x.strip() and a <= json.loads(x)['i'] <= b: cut += 1
        else: keep.append(x)
    open(p, 'wb').write(b''.join(keep))
with open(os.path.join(d, 'gaps.jsonl'), 'a') as fh:
    fh.write(json.dumps({'from': a, 'to': b, 'reason': 'scratch: deliberate gap for the peer-RPC fill drill', 'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}, sort_keys=True, separators=(',', ':')) + '\n')
print(f'cut {cut} ledgers {a}-{b} from active/, gap recorded')
PYEOF"
check "scratch copy: 30 ledgers cut, gap recorded" "$(grep -q "cut 30 ledgers $A-$B" <<<"$XOUT" && echo 0 || echo 1)"
x "python3 histarchive/histarchive.py verify --dir \$SCR/arch | tail -n 1; python3 histarchive/histarchive.py gaps --dir \$SCR/arch --rpc $PUB"
check "scratch: verify PASS gaps 1 (30 ledgers) filled 1; gaps: the new gap FILLABLE from the public RPC" "$(grep -q 'gaps 1 (30 ledgers) filled 1 fails 0' <<<"$XOUT" && grep -q "^OPEN   $A-$B (30) anchors ok source holds it -> FILLABLE" <<<"$XOUT" && echo 0 || echo 1)"
x "nice -n 15 python3 -u histarchive/histarchive.py fill-gap --dir \$SCR/arch --gap $A-$B --rpc $PUB --rate 2"
check "scratch peer-RPC fill: 30/30 answered, chain unbroken, FILL written" "$([ "$XRC" = 0 ] && grep -q 'source answered 30/30 ledgers' <<<"$XOUT" && grep -q "chain $((A - 1))->$((B + 1)) unbroken (31 links" <<<"$XOUT" && grep -q "FILL $A-$B count=30" <<<"$XOUT" && grep -q 'source=rpc' <<<"$XOUT" && echo 0 || echo 1)"
x "python3 histarchive/histarchive.py verify --dir \$SCR/arch | tail -n 3; python3 -I histarchive/tests/seqcheck.py \$SCR/arch; tail -n 1 \$SCR/arch/MANIFEST.jsonl | jq -c '{kind, first, last, count, source}'"
check "scratch: verify PASS gaps 0 filled 2; seqcheck PASS missing 0 filled 2; provenance rpc host only" "$(grep -q 'gaps 0 (0 ledgers) filled 2 fails 0' <<<"$XOUT" && grep -q 'missing 0 open-gap ledgers 0 filled gaps 2' <<<"$XOUT" && grep -q 'RESULT: PASS - fails 0' <<<"$XOUT" && grep -q '"rpc":"https://rpc.testnet.postfiat.org"' <<<"$XOUT" && echo 0 || echo 1)"
x "rm -rf \$SCR; test -e \$SCR && echo LEFT || echo scratch removed"; SCR=""

echo; echo "== 9. integrity (conf, rulecheck.conf), skew, rulecheck, aptrust, jobwatch"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -20"
x "sudo -n pft-integrity accept --reason '$TASK: histarchive $SHORT gap repair (FILL_RPC in pft-histarchive.env, rulecheck.conf gaps lines)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -20"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, histarchive CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +histarchive +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-histarchive-periodic.service; sudo -n systemctl start pft-rulecheck.service; sudo -n journalctl -u pft-rulecheck.service --since -1min --no-pager -o cat | grep -E '^RESULT |histarchive'"
check "pft-rulecheck RESULT OK (pft_histarchive_gaps.prom fresh and required)" "$(grep -q '^RESULT OK ' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-aptrust audit 2>&1 | grep -E 'histarchive|^RESULT' | cut -c1-200"
check "pft-aptrust PASS after the file change" "$(grep -q '^RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n systemctl start pft-jobwatch.service; grep -E '^pft_jobwatch_job_(failed|missed|disabled)\{.*histarchive' $TF/pft_jobwatch_validator.prom"
check "jobwatch: histarchive timer not failed, missed or disabled (periodic ran with the new code)" "$([ "$(grep -cE 'histarchive.* 0$' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"

echo; echo "== 10. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"'"
check "nothing but the pipeline watchdog pending or firing" "$([ "$(grep -vc PFTAlertPipelineWatchdog <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n docker exec postfiatd curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state; R \"sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\\\"method\\\":\\\"server_info\\\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state\""
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n find /var/lib/pft-histarchive -maxdepth 1 -name 'restore.*' | wc -l; systemctl list-units --all --no-legend 'run-u*' | wc -l"
check "no restore scratch left, no transient run-u units" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
if [ -n "$SIL" ] && [ "$FAILS" = 0 ]; then
  x "for id in $SIL $OLD_SIL; do curl -s -o /dev/null -w '%{http_code}\n' -X DELETE $AM/api/v2/silence/\$id; done"
  check "rollout silence(s) expired (nothing but the watchdog active)" "$([ "$(grep -vcx 200 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
fi
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "fill-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
