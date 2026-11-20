#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # jq programs and remote commands are single-quoted on purpose
# Recorded live matrix of specdrill (task_df1c7e56b837bacfb46c59c050c5c5cb) on the validator host. Built from
# ../../valwatch/drill/digest-install-run.sh (PASS, valwatch log 19/20). The live validator and the sentry keep
# running untouched; every cell is a throwaway node that pft-specdrill.sh creates and removes itself.
#   0. preflight (read-only): clean pushed HEAD, run copy = HEAD bytes, integrity PASS both hosts, both nodes full,
#      no labelled leftovers, Prometheus/AM up, nothing firing but the watchdog and the digest-only valwatch alerts,
#      only the allowed silence (SIL_OK), operator topics found, `pft-specdrill plan` guards ok except maint.
#   1. Alertmanager silences for exactly what the drill itself causes, host="validator" only (never the watchdog):
#      PFTKernelCritical pattern=~oom_cgroup|hung_task (OOM cells, 1 MB/s I/O cells), PFTKernelWarning
#      pattern=oom_invoked, PFTJobDisabled timer=pft-integrity.timer (paused per cell).
#   2. per axis: pft-maint window (both hosts, [MAINT] to a throwaway topic), `pft-specdrill matrix --axes A
#      --yes`, window end. Live safety is recorded per poll in every cell's samples.jsonl (live_state, live_lag).
#   3. after: pft-integrity timer active + failsafe unit gone, 0 labelled containers/volumes/networks, integrity
#      PASS both hosts, AppArmor/seccomp 0 denials, live node full, histarchive no new gap, every alert active at
#      any time during the run (Prometheus ALERTS) is the watchdog, a digest-only one or a silenced one; report.
#   4. restore: real pft-maint target back, drain (only watchdog/digest alerts active), silence expired, read back
#      the throwaway and every operator topic (0 messages on the operator topics).
#   AXES=cpu,io RUN=05 bash specdrill/drill/live-run.sh 2>&1 | tee LOG        (repo root, agent user, detached)
#   DRY=1 RUN=dry1 bash specdrill/drill/live-run.sh    one short cpu=2 cell (WINDOW_S=120) through every step
#   PREFLIGHT_ONLY=1 AXES=cpu RUN=x bash specdrill/drill/live-run.sh
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_df1c7e56
RUN="${RUN:?set RUN (run number)}"; DRY="${DRY:-0}"; AXES="${AXES:-cpu}"
SIL_OK="${SIL_OK:-}"
TT="pft-drill-specdrill-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
RD="$HOME/.cache/specdrill-run-$RUN"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@" </dev/null; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-specdrill
SWAPPED=0; MAINT=0; HAD=0; SILS=""
# alertname | extra matcher label=value(regex) : the only alerts the drill may cause, silenced on the validator
SILENCED="PFTKernelCritical|pattern=oom_cgroup|hung_task PFTKernelWarning|pattern=oom_invoked PFTJobDisabled|timer=pft-integrity.timer"
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
if [ "$DRY" = 1 ]; then
  CELLENV=(WINDOW_S=120 FULL_TIMEOUT_S=300); CELL_BUDGET=540; AXES=dry
else
  CELLENV=(); CELL_BUDGET=2220   # FULL_TIMEOUT_S 900 + WINDOW_S 1200 + slack 120 (pft-specdrill.sh cell_budget_s)
fi
ncells() { case "$1" in cpu) echo 4 ;; mem) echo 5 ;; io) echo 3 ;; dry) echo 1 ;; *) echo 0 ;; esac; }
ttl_of() { local t=$(( $(ncells "$1") * CELL_BUDGET + 600 )); [ "$t" -le 14400 ] || t=14400; echo "$t"; }
TOTAL=0; for a in ${AXES//,/ }; do TOTAL=$(( TOTAL + $(ttl_of "$a") + 120 )); done

maint_end() { if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi; }
restore() {
  maint_end
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
  [ -z "$SILS" ] || echo "silences $SILS left active until their end (expired only after a clean drain)"
}
trap 'restore; rm -f "$OPS"' EXIT
srv_state() { # both nodes' server_state, validator first (host RPC; the sentry has no host mapping -> its own curl shape)
  curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005/ | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
labelled() { sudo -n docker ps -aq --filter label=pft-specdrill; sudo -n docker volume ls -q --filter label=pft-specdrill; sudo -n docker network ls -q --filter label=pft-specdrill; }
active_alerts() { # "name state" of every Prometheus alert (pending included); query-error on failure (fails closed)
  local j; j="$(curl -s --max-time 10 "$PROM/api/v1/alerts")"
  if [ -n "$j" ] && jq -e '.data.alerts | type == "array"' >/dev/null 2>&1 <<<"$j"; then
    jq -r '.data.alerts[] | .labels.alertname as $n | "\($n) \(.state) \(.labels.notify // "-")"' <<<"$j"
  else echo query-error; fi
}
unexpected() { grep -vE '^PFTAlertPipelineWatchdog |^PFTValwatchValidator(Low|Late) .* digest$' | grep -c . ; }
gaps() { grep -h '^pft_histarchive_follow_gaps' "$TF"/pft_histarchive*.prom 2>/dev/null | awk '{print $NF}' | head -1; }

echo "specdrill live run $RUN - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO)) - axes $AXES dry=$DRY"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "rm -rf '$RD' && mkdir -p '$RD/bin' && cp specdrill/pft-specdrill.sh specdrill/specdrill.py '$RD/bin/' && chmod 755 '$RD' '$RD/bin' && sha256sum specdrill/pft-specdrill.sh specdrill/specdrill.py '$RD'/bin/* | cut -c1-64"
check "run copy of runner + helper = HEAD bytes (the repo may change while the run goes)" "$([ "$(sort <<<"$XOUT" | uniq -c | awk '$1 == 2' | wc -l)" = 2 ] && echo 0 || echo 1)"
x "shellcheck specdrill/pft-specdrill.sh specdrill/drill/*.sh && echo shellcheck clean"
check "shellcheck clean" "$XRC"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the run" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "labelled | wc -l"
check "no pft-specdrill labelled container/volume/network" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-maint status --json | jq -c '{window, remaining_sec, locks}'"
check "no pft-maint window open" "$(jq -e '.window == "none"' <<<"$XOUT" >/dev/null 2>&1 && echo 0 || echo 1)"
x "sudo -n env ${CELLENV[*]} bash '$RD/bin/pft-specdrill.sh' plan --axes ${AXES/dry/cpu}"
check "plan: every guard ok except maint (no window yet)" "$([ "$(grep -c '^FAIL ' <<<"$XOUT")" = 1 ] && grep -q '^FAIL maint: no active' <<<"$XOUT" && [ "$(grep -c '^ok ' <<<"$XOUT")" = 6 ] && echo 0 || echo 1)"
x "systemctl is-active pft-integrity.timer; systemctl list-units --all --no-legend 'specdrill-rearm-integrity*' | wc -l"
check "pft-integrity.timer active, no failsafe unit left" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "active 0 " ] && echo 0 || echo 1)"
G0="$(gaps)"; echo "histarchive follow_gaps before: ${G0:-?}"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s --max-time 10 $PROM/api/v1/alerts | jq -r .status; curl -s --max-time 10 $AM/api/v2/status | jq -r 'if (.uptime // \"\") != \"\" then \"up\" else \"down\" end'"
check "Prometheus and Alertmanager answer" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "success up " ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | .id[0:8]'"
check "active silences: none, or only the allowed one (SIL_OK=${SIL_OK:-none})" "$(grep -vxF "${SIL_OK:-none}" <<<"$XOUT" | grep -q . && echo 1 || echo 0)"
x "active_alerts | sort | uniq -c"
check "only the watchdog and the digest-only valwatch alerts active" "$([ "$(active_alerts | unexpected)" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. Alertmanager silences for what the drill itself causes (host=validator; never the watchdog), $((TOTAL / 60)) min + 30"
ends="$(date -u -d "+$(( TOTAL / 60 + 30 )) min" +%FT%TZ)"
for spec in $SILENCED; do
  an="${spec%%|*}"; lv="${spec#*|}"; ln="${lv%%=*}"; lval="${lv#*=}"
  SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK specdrill run $RUN $SHORT" --arg an "$an" --arg ln "$ln" --arg lv "$lval" \
    '{matchers: [{name: "alertname", value: $an, isRegex: false, isEqual: true}, {name: "host", value: "validator", isRegex: false, isEqual: true},
                 {name: $ln, value: $lv, isRegex: ($lv | test("[|]")), isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "specdrill-live-run", comment: $c}')"
  id="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
  echo "silence ${id:0:8}: alertname=$an host=validator $ln$([ "${lval//|/}" = "$lval" ] && echo "=" || echo "=~")$lval until $ends"
  check "silence for $an created" "$([ -n "$id" ] && echo 0 || echo 1)"
  [ -z "$id" ] || SILS="$SILS $id"
done
x "curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\" and .createdBy == \"specdrill-live-run\") | [.matchers[] | .name + (if .isRegex then \"=~\" else \"=\" end) + .value] | join(\" \")'"
check "3 drill silences active, none matches the pipeline watchdog" "$([ "$(grep -c . <<<"$XOUT")" = 3 ] && ! grep -q PFTAlertPipelineWatchdog <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 2. [MAINT] messages to a throwaway topic (real file kept as \$BK)"
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; else ORIG_SHA=absent; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
gate
mkdir -p "$RD/cells"
for a in ${AXES//,/ }; do
  ttl="$(ttl_of "$a")"
  echo; echo "== 2.$a window ${ttl}s (validator only), matrix axis $a"
  x "sudo -n pft-maint start --ttl $ttl --reason '$TASK specdrill run $RUN axis $a'"
  [ "$XRC" = 0 ] && MAINT=1
  check "pft-maint window open ($a)" "$XRC"
  gate
  t0="$(date -u +%s)"
  if [ "$a" = dry ]; then
    echo "\$ sudo -n env ${CELLENV[*]} bash \$RD/bin/pft-specdrill.sh run-cell --out \$RD/cells --axis cpu --cpus 2 --mem 2048"
    sudo -n env "${CELLENV[@]}" bash "$RD/bin/pft-specdrill.sh" run-cell --out "$RD/cells" --axis cpu --cpus 2 --mem 2048 2>&1 | red | sed -u 's/^/  /'
  else
    echo "\$ sudo -n bash \$RD/bin/pft-specdrill.sh matrix --out \$RD/cells --axes $a --yes"
    sudo -n bash "$RD/bin/pft-specdrill.sh" matrix --out "$RD/cells" --axes "$a" --yes 2>&1 | red | sed -u 's/^/  /'
  fi
  rc="${PIPESTATUS[0]}"; echo "  (exit $rc, $(( $(date -u +%s) - t0 ))s)"
  check "axis $a: runner exit 0" "$rc"
  maint_end
  x "systemctl is-active pft-integrity.timer; systemctl list-units --all --no-legend 'specdrill-rearm-integrity*' | wc -l; labelled | wc -l"
  check "axis $a: integrity timer re-armed, failsafe disarmed, 0 labelled resources" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "active 0 0 " ] && echo 0 || echo 1)"
  gate
done

echo; echo "== 3. after the matrix: cleanup, integrity, confinement, live node, report"
x "sudo -n chown -R '$ME:' '$RD/cells' && ls '$RD/cells' && for d in '$RD'/cells/*/; do jq -c '{cell, verdict, reasons, time_to_full_s, lag_p95, live_full_all, live_lag_max}' \$d/cell.json; done"
x "cat '$RD'/cells/*/samples.jsonl | jq -s '{polls: length, live_not_full: ([.[] | select(.live_state != \"full\")] | length), live_lag_max: ([.[].live_lag // 0] | max), live_lag_gt1: ([.[] | select((.live_lag // 0) > 1)] | length)}'"
check "live validator full at every poll of every cell, lag never above LIVE_LAG_MAX 3" "$(jq -e '.polls > 0 and .live_not_full == 0 and .live_lag_max <= 3' <<<"$XOUT" >/dev/null 2>&1 && echo 0 || echo 1)"
x "labelled | wc -l; sudo -n docker ps -a --format '{{.Names}}' | sort | tr '\n' ' '"
check "0 labelled containers/volumes/networks left" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E 'WARN|FAIL|RESULT' | cut -c1-160; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after the run (nothing to accept)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'"
check "AppArmor + seccomp audits PASS, 0 denials on the live container" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && grep -q ' 0 DENIED events' <<<"$XOUT" && echo 0 || echo 1)"
x "srv_state; sudo -n docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' postfiatd"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
RUN_S=$(( $(date -u +%s) - since + 60 ))
x "curl -s --max-time 20 $PROM/api/v1/query --data-urlencode 'query=count by (alertname, alertstate, host) (count_over_time(ALERTS[${RUN_S}s]))' | jq -r '.data.result[] | .metric | \"\\(.alertname) \\(.alertstate) \\(.host // \"-\")\"' | sort"
OUTSIDE="$(grep -vE '^(PFTAlertPipelineWatchdog|PFTValwatchValidator(Low|Late)) |^(PFTKernelCritical|PFTKernelWarning|PFTJobDisabled) (pending|firing) validator$' <<<"$XOUT" | grep -c .)"
check "every alert active at any time during the run (${RUN_S}s) is the watchdog, digest-only valwatch or a silenced drill alert" "$([ "$XRC" = 0 ] && [ "$OUTSIDE" = 0 ] && echo 0 || echo 1)" "$OUTSIDE outside"
G1="$(gaps)"; echo "histarchive follow_gaps after: ${G1:-?} (before ${G0:-?})"
check "no new histarchive follow gap (the live node never stopped)" "$([ -n "$G0" ] && [ "$G0" = "$G1" ] && echo 0 || echo 1)"
if [ "$DRY" != 1 ]; then
  x "rm -rf specdrill/data && mkdir -p specdrill/data && cp -r '$RD/cells' specdrill/data/cells && find specdrill/data/cells -name cell.json -delete && python3 -I specdrill/specdrill.py report specdrill/data/cells specdrill/data && cp specdrill/data/REPORT.md specdrill/REPORT.md && sha256sum specdrill/data/cells.json specdrill/data/cells.csv specdrill/REPORT.md"
  check "report built from the recorded cells" "$XRC"
fi

echo; echo "== 4. restore, drain, expire the silence, read back"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "for i in \$(seq 0 30 600); do n=\$(active_alerts | unexpected); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 30; done; echo \$n"
check "drained: only the watchdog and digest-only alerts active (pending included)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
if [ "$(tail -1 <<<"$XOUT")" = 0 ] && [ -n "$SILS" ]; then
  for id in $SILS; do
    x "curl -s -o /dev/null -w '%{http_code}' -X DELETE $AM/api/v2/silence/$id"
    check "silence ${id:0:8} expired" "$([ "$XOUT" = 200 ] && echo 0 || echo 1)"
  done
  SILS=""
fi
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r 'select(.event == \"message\") | .title'"
NAX=0; for a in ${AXES//,/ }; do NAX=$((NAX + 1)); done
check "the [MAINT] start/end messages reached the throwaway topic ($((2 * NAX)))" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = $((2 * NAX)) ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s after the expiry"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); m="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")')"
  # the hourly agent cycles keep reporting to the operator during a multi-hour run: their own messages carry the
  # "[pft-agent] " title prefix (/opt/pft-agent/notify) and are counted apart; anything else is a drill leak
  ag="$(jq -r '.title // ""' <<<"$m" | grep -c '^\[pft-agent\] ')"; n="$(jq -r '.title // ""' <<<"$m" | grep -vc '^\[pft-agent\] ')"
  [ -n "$m" ] || n=0
  echo "  operator #$i topic: $n alert/maint message(s), $ag agent-cycle message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received no alert or [MAINT] message during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "specdrill live run $RUN done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
