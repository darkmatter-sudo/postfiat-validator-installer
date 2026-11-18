#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host DEPLOY of the bounded histarchive verify (task_9fb56f105f2b404c135135b0e6ff456e), measured by
# pft-budget, through pft-fleet inside a pft-maint window. Built from ./upgrade-run.sh (logs/05).
# The daily full verify was OOM-killed at MemoryMax=512M (593 MiB on day 10); a 1G drop-in
# (pft-histarchive-periodic.service.d/50-memory.conf) has been the stop-gap since. This run:
#   0. preflight: HEAD pushed + clean, installed helper (both hosts) != HEAD, since the installed commit only
#      histarchive.py/README/tests changed, the stop-gap is in force (effective MemoryMax 1G), integrity PASS,
#      nodes full, sampler active on both hosts, nothing but the watchdog active.
#   1. BEFORE: the installed (old) helper, full verify + sealed-only verify, as transient pft-* units at
#      MemoryMax=1G (the sampler records their peaks).
#   2. silence + pft-maint window ([MAINT] to a throwaway topic).  3. pft-fleet sync histarchive; bytes = repo.
#   4. AFTER: the shipped helper, the same two verifies at MemoryMax=512M; sealed-only output cmp = BEFORE.
#   5. gate: AFTER full-verify peak_unrecl <= 256 MiB (2x headroom under 512M) and 0 OOM kills -> remove the stop-gap
#      drop-in, daemon-reload, effective MemoryMax 512M, integrity accept.
#   6. the REAL unit: drop verified-head so its next run verifies, start pft-histarchive-periodic.service at 512M;
#      verify textfile ok, the sampler's record for the unit (peak, oom 0, result success).
#   7. sentry: verify-replica (the peer's index + replica-check run the shipped helper there).
#  10. VERIFIED: pft-budget report rows (before/after/real), budget collect + pull.
#  11. integrity, skew.  12. restore, read back every operator topic (0 messages).
#   bash budget/drill/histarchive-run.sh 2>&1 | tee LOG    (repo root, agent user; run detached)
#   PREFLIGHT_ONLY=1 bash budget/drill/histarchive-run.sh
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_9fb56f10
TT="pft-drill-budget-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
HLIB=/usr/local/lib/pft-histarchive/histarchive.py
ARCH=/var/lib/pft-histarchive/archive
DROPIN=/etc/systemd/system/pft-histarchive-periodic.service.d/50-memory.conf
SAMPLES=/var/lib/pft-budget/samples.jsonl
INSTALLED_COMMIT=babb974524b8
MIB=1048576
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-budget
SWAPPED=0; MAINT=0; HAD=0
since="$(date -u +%s)"
OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
OUT="$(mktemp -d -p "$HOME/.cache")"; chmod 755 "$OUT"
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap 'restore; rm -rf "$OPS" "$OUT"' EXIT
srv_state() {
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
# alerts other than the watchdog, with whether AM suppresses them: "NAME STATE UNIT SUPPRESSED"
other_alerts() {
  local p a
  p="$(curl -s --max-time 10 "$PROM/api/v1/alerts")"
  if [ -z "$p" ] || ! jq -e 'type == "object"' <<<"$p" >/dev/null; then echo query-error; return; fi
  a="$(curl -s --max-time 10 "$AM/api/v2/alerts")"
  if [ -z "$a" ] || ! jq -e 'type == "array"' <<<"$a" >/dev/null; then echo query-error; return; fi
  jq -r --argjson am "$a" '.data.alerts[] | select(.labels.alertname != "PFTAlertPipelineWatchdog")
    | .labels.alertname as $n | (.labels.unit // "-") as $u
    | ([$am[] | select(.labels.alertname == $n and (.labels.unit // "-") == $u) | .status.state] | first // "none") as $s
    | "\($n) \(.state) \($u) \($s)"' <<<"$p"
}
# vrun NAME CAP ARGS...: the helper's verify as transient unit NAME (user pft-histarchive, MemoryMax CAP), stdout to $OUT/NAME.out
vrun() {
  local n="$1" cap="$2"; shift 2
  # shellcheck disable=SC2024  # stdout is written by the agent user into its own $OUT on purpose
  sudo -n systemd-run --quiet --wait --pipe --collect --unit "$n" -p User=pft-histarchive -p MemoryMax="$cap" \
    -p MemorySwapMax=0 -p Nice=10 /usr/bin/python3 -I "$HLIB" verify --dir "$ARCH" "$@" </dev/null >"$OUT/$n.out"
  local rc=$?; echo "unit $n cap $cap rc $rc out_sha256 $(sha256sum <"$OUT/$n.out" | cut -c1-64) $(tail -c 300 "$OUT/$n.out" | grep -o 'RESULT: [A-Z]*' | tail -1)"
  return $rc
}
# final sampler record of unit U (newest): "peak_unrecl_mib peak_mib oom_kills mem_max result"
rec() {
  local r i
  for i in $(seq 1 20); do
    r="$(sudo -n grep -F "\"unit\":\"$1\"" "$SAMPLES" | jq -c 'select(.kind == "final")' | tail -1)"
    [ -n "$r" ] && break; sleep 1
  done
  [ -n "$r" ] || { echo "no final record for $1"; return 1; }
  jq -r --argjson m "$MIB" '"\(.unit) peak_unrecl_mib \(.peak_unrecl_bytes / $m | . * 10 | floor / 10) peak_mib \(.peak_bytes / $m | . * 10 | floor / 10) oom_kills \(.oom_kills) mem_max \(.mem_max) result \(.result) samples \(.samples) runtime_s \(.runtime_sec)"' <<<"$r"
}
unrecl_bytes() { sudo -n grep -F "\"unit\":\"$1\"" "$SAMPLES" | jq -r 'select(.kind == "final") | .peak_unrecl_bytes' | tail -1; }
echo "histarchive bounded-verify deploy - $(date -u +%FT%TZ) - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum histarchive/histarchive.py | cut -c1-64; sudo -n sha256sum $HLIB | cut -c1-64; R 'sha256sum $HLIB | cut -c1-64'; git show $INSTALLED_COMMIT:histarchive/histarchive.py | sha256sum | cut -c1-64"
check "installed helper on both hosts = $INSTALLED_COMMIT bytes, != HEAD (deploy pending)" "$([ "$(sed -n 2p <<<"$XOUT")" = "$(sed -n 4p <<<"$XOUT")" ] && [ "$(sed -n 3p <<<"$XOUT")" = "$(sed -n 4p <<<"$XOUT")" ] && [ "$(sed -n 1p <<<"$XOUT")" != "$(sed -n 2p <<<"$XOUT")" ] && echo 0 || echo 1)"
x "git diff --name-only $INSTALLED_COMMIT $SHA -- histarchive | grep -vE '^histarchive/(logs|tests|drill)/'; git diff $INSTALLED_COMMIT $SHA -- fleet/manifest.tsv | grep -cE '^[-+]histarchive'"
check "since $INSTALLED_COMMIT only histarchive.py, README and ruff.toml (not installed) changed; 0 histarchive manifest rows changed" "$([ "$(grep -v '^$' <<<"$XOUT" | sort | tr '\n' ' ')" = "0 histarchive/README.md histarchive/histarchive.py histarchive/ruff.toml " ] && echo 0 || echo 1)"
x "cat $DROPIN; systemctl show -p MemoryMax --value pft-histarchive-periodic.service; grep -n '^MemoryMax=' histarchive/systemd/pft-histarchive-periodic.service; sudo -n sha256sum /etc/systemd/system/pft-histarchive-periodic.service | cut -c1-64; sha256sum histarchive/systemd/pft-histarchive-periodic.service | cut -c1-64"
check "stop-gap in force: drop-in MemoryMax=1G, effective 1073741824; installed unit = repo bytes (MemoryMax=512M)" "$(grep -qx 'MemoryMax=1G' <<<"$XOUT" && grep -qx 1073741824 <<<"$XOUT" && grep -q ':MemoryMax=512M$' <<<"$XOUT" && [ "$(tail -2 <<<"$XOUT" | sort -u | wc -l)" = 1 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl is-active pft-budget-sampler.service pft-histarchive.service; R 'systemctl is-active pft-budget-sampler.service'"
check "samplers active on both hosts, follower active" "$([ "$(grep -cx active <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "other_alerts; curl -s $AM/api/v2/silences | jq -r '.[] | select(.status.state == \"active\") | \"\(.createdBy) \(.endsAt)\"'"
check "alert queries answered" "$(grep -q query-error <<<"$XOUT" && echo 1 || echo 0)"
check "nothing but the watchdog active, no active silence" "$(grep -q . <<<"$XOUT" && echo 1 || echo 0)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. BEFORE: installed helper ($INSTALLED_COMMIT), MemoryMax=1G (the stop-gap cap)"
x "vrun pft-histarchive-verify-before.service 1G --json"
check "before: full verify exit 0" "$XRC"
x "vrun pft-histarchive-verify-before-sealed.service 1G --json --sealed-only"
check "before: sealed-only verify exit 0" "$XRC"
x "rec pft-histarchive-verify-before.service; rec pft-histarchive-verify-before-sealed.service"
check "sampler recorded both before runs, 0 OOM kills" "$([ "$XRC" = 0 ] && [ "$(grep -c 'oom_kills 0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "jq -c '{ok, segments, active, ledgers, first, last, txs, gaps, fails: (.fail | length)}' $OUT/pft-histarchive-verify-before.service.out $OUT/pft-histarchive-verify-before-sealed.service.out"
check "before: both verifies ok:true" "$([ "$(grep -c '"ok":true' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
gate

echo; echo "== 2. rollout silence + pft-maint window ([MAINT] to a throwaway topic)"
ends="$(date -u -d '+45 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK histarchive bounded-verify deploy $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTHistarchive.*|PFTBudget.*|PFTRuleDead|PFTTextfileStale|PFTRulecheck.*|PFTFleet.*|PFTAptrust.*|PFTJob.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "histarchive-deploy", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created until $ends (not the watchdog)" "$([ -n "$SIL" ] && echo 0 || echo 1)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK histarchive bounded-verify deploy'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window after ${w}s" "$?"
gate

echo; echo "== 3. pft-fleet sync histarchive"
x "sudo -n pft-fleet sync --addon histarchive --to $SHA --apply --reason '$TASK histarchive $SHORT bounded verify'"
check "histarchive sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
x "sha256sum histarchive/histarchive.py | cut -c1-64; sudo -n sha256sum $HLIB | cut -c1-64; R 'sha256sum $HLIB | cut -c1-64'"
check "installed helper = HEAD bytes on both hosts" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"
gate

echo; echo "== 4. AFTER: shipped helper ($SHORT), MemoryMax=512M (the unit's own cap)"
x "vrun pft-histarchive-verify-after.service 512M --json"
check "after: full verify exit 0" "$XRC"
x "vrun pft-histarchive-verify-after-sealed.service 512M --json --sealed-only"
check "after: sealed-only verify exit 0" "$XRC"
x "rec pft-histarchive-verify-after.service; rec pft-histarchive-verify-after-sealed.service"
check "sampler recorded both after runs, 0 OOM kills" "$([ "$XRC" = 0 ] && [ "$(grep -c 'oom_kills 0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "cmp $OUT/pft-histarchive-verify-before-sealed.service.out $OUT/pft-histarchive-verify-after-sealed.service.out && echo identical"
check "sealed-only verify --json byte-identical before/after" "$XRC"
x "jq -c '{ok, segments, active, ledgers, first, last, txs, gaps, fails: (.fail | length)}' $OUT/pft-histarchive-verify-after.service.out"
check "after: full verify ok:true" "$(grep -q '"ok":true' <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 5. gate: 2x headroom under 512M -> remove the 1G stop-gap"
B="$(unrecl_bytes pft-histarchive-verify-before.service)"; A="$(unrecl_bytes pft-histarchive-verify-after.service)"
echo "full verify peak_unrecl: before $((B / MIB)) MiB (cap 1G) -> after $((A / MIB)) MiB (cap 512M); headroom $(awk -v a="$A" 'BEGIN { printf "%.2f", 536870912 / a }')x"
check "after peak_unrecl <= 256 MiB (>= 2x headroom under 512M)" "$([ -n "$A" ] && [ "$A" -le 268435456 ] && echo 0 || echo 1)"
gate
x "sudo -n rm -f $DROPIN && sudo -n rmdir --ignore-fail-on-non-empty $(dirname "$DROPIN") && sudo -n systemctl daemon-reload && systemctl show -p MemoryMax --value pft-histarchive-periodic.service; ls $(dirname "$DROPIN") 2>&1 | head -2"
check "stop-gap removed: effective MemoryMax 536870912 (512M)" "$(grep -qx 536870912 <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E 'WARN|FAIL|RESULT' | head -5"
x "sudo -n pft-integrity accept --reason '$TASK: removed 1G stop-gap drop-in for pft-histarchive-periodic (bounded verify $SHORT, after peak <= 256 MiB)' | tail -1; sudo -n pft-integrity verify | tail -1"
check "integrity accepted the drop-in removal, PASS" "$(grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 6. the REAL unit at MemoryMax=512M: next periodic run verifies"
x "sudo -n rm -f /var/lib/pft-histarchive/verified-head && sudo -n systemctl start pft-histarchive-periodic.service; echo rc=\$?; systemctl show -p Result -p ExecMainStatus -p MemoryMax pft-histarchive-periodic.service"
check "pft-histarchive-periodic.service run exit 0, Result success" "$(grep -qx rc=0 <<<"$XOUT" && grep -qx Result=success <<<"$XOUT" && echo 0 || echo 1)"
x "rec pft-histarchive-periodic.service; grep -hE '^pft_histarchive_verify_(ok|failures|timestamp_seconds)' $TF/pft_histarchive.prom"
P="$(unrecl_bytes pft-histarchive-periodic.service)"
check "real run: sampler record at mem_max 536870912, oom 0, peak_unrecl <= 256 MiB, verify_ok 1" "$(grep -q 'oom_kills 0 mem_max 536870912 result success' <<<"$XOUT" && [ -n "$P" ] && [ "$P" -le 268435456 ] && grep -qE 'pft_histarchive_verify_ok\{.*\} 1$' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 7. sentry: the replica check runs the shipped helper there"
x "sudo -n pft-histarchive verify-replica | tail -3"
check "verify-replica exit 0" "$XRC"

echo; echo "== 10. VERIFIED: pft-budget report rows"
x "sudo -n systemctl start pft-budget-collect.service && R 'sudo -n systemctl start pft-budget-collect.service' && sudo -n systemctl start pft-budget-pull@sentry.service && echo collected"
check "budget collect on both hosts + pull exit 0" "$XRC"
x "sudo -n pft-budget report | grep -E -A2 '^validator +pft-histarchive'; sudo -n pft-budget report | grep '^RESULT'; R 'sudo -n pft-budget report' | grep '^RESULT'"
check "report: no FAIL verdict on either host" "$([ "$(grep -c '^RESULT: .* 0 FAIL,' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
check "report: pft-histarchive-periodic.service cap 512MiB, verdict OK" "$(grep -qE '^validator +pft-histarchive-periodic\.service .* 512MiB .* OK$' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 11. integrity, skew"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E 'histarchive|SUMMARY'"
check "pft-fleet skew: histarchive CURRENT on both hosts, nothing BEHIND" "$([ "$(grep -cE '^ *(validator|sentry) +histarchive +CURRENT' <<<"$XOUT")" = 2 ] && grep -q 'BEHIND=0 ' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 12. end window, restore, read back"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "for i in \$(seq 0 15 300); do n=\$(other_alerts | grep -c .); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; other_alerts"
check "nothing but the watchdog pending/firing" "$(grep -qE '^[A-Z]' <<<"$XOUT" && echo 1 || echo 0)"
x "curl -s --max-time 10 -X DELETE $AM/api/v2/silence/$SIL -o /dev/null -w '%{http_code}\n'"
check "rollout silence expired" "$(grep -qx 200 <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "histarchive-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
