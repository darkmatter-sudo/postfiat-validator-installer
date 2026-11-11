#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded fix-up after install run 06 (task_dd37a539fab2aacc4c0703ae0ceaa689): FOUND pft-aptrust keeps a copy of
# fleet/manifest.tsv as its offpkg allowlist, so the 6 new manifest rows left that copy BEHIND on both hosts (pft-fleet
# skew rc != 0) and `pft-aptrust audit` WARNs offpkg:/usr/local/bin/pft-peerwatch. FIX: pft-fleet sync --addon aptrust
# inside a pft-maint window (throwaway topic). VERIFIED: audit 0 warn / 0 fail and skew rc 0 on both hosts.
# Same framework as install-run.sh (redaction, checks, restore, keyescrow re-run, operator read-back).
# pft-maint's [MAINT] messages go to a throwaway topic; the real target is restored and compared, pft-keyescrow is
# re-run (it fingerprints that env file) and every operator topic is read back (must be 0 messages). The rollout
# silence names only the peerwatch/rulecheck/fleet/schedaudit/jobwatch/keyescrow alerts (never the pipeline watchdog)
# and is left to run out.
#   bash peerwatch/drill/aptrust-fixup.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
# KNOWN_PENDING: alert names already pending/firing before the run that the preflight accepts (each is printed).
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_dd37a539
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-peerwatch-fix-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-peerwatch-fixup
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
  R "rm -rf ~/pft-peerwatch-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
echo "peerwatch aptrust manifest-copy fix-up - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. FOUND (read-only)"
x "sudo -n pft-fleet skew | grep -vE ' CURRENT *$'"
check "skew shows aptrust BEHIND on both hosts (its manifest copy) and nothing else" "$([ "$(grep -cE '^ *(validator|sentry) +aptrust +BEHIND +/usr/local/lib/pft-aptrust/manifest.tsv' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^ *(validator|sentry) +[a-z]+ +(BEHIND|MODIFIED|MISSING|UNEXPECTED|DIVERGED)' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^RESULT'"
check "aptrust audit: the only WARN on each host is offpkg:/usr/local/bin/pft-peerwatch" "$([ "$(grep -c '^WARN  offpkg:/usr/local/bin/pft-peerwatch ' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }

echo; echo "== 1. silence (aptrust + fleet only; not the watchdog)"
ends="$(date -u -d '+40 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK aptrust manifest copy $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTAptrust.*|PFTFleet.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "peerwatch-fixup", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 20m --reason '$TASK aptrust manifest copy'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window after ${w}s" "$?"

echo; echo "== 3. FIX: pft-fleet sync --addon aptrust (writes the current manifest copy on both hosts, accepts it in pft-integrity)"
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust allowlist copy += peerwatch rows'"
check "aptrust sync exit 0" "$XRC"
x "sha256sum fleet/manifest.tsv | cut -c1-64; sudo -n sha256sum /usr/local/lib/pft-aptrust/manifest.tsv | cut -c1-64; R 'sha256sum /usr/local/lib/pft-aptrust/manifest.tsv | cut -c1-64'"
check "aptrust's manifest copy = repo fleet/manifest.tsv on both hosts" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"

echo; echo "== 4. VERIFIED: aptrust audit (CLI and the timer's unit run, textfile), skew, integrity"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^INFO  offpkg |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^INFO  offpkg |^RESULT'"
check "aptrust audit on both hosts: 0 warn, 0 fail; pft-peerwatch is a known add-on file" "$([ "$(grep -c ' 0 warn, 0 fail -> exit 0' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 0 ] && [ "$(grep -c '44 add-on file(s) in /usr/local/{bin,sbin} match the allowlist' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust.service; R 'sudo -n systemctl start pft-aptrust.service'; sudo -n systemctl start pft-aptrust-pull.service 2>/dev/null; grep -hE '^pft_aptrust_checks\{.*result=\"(warn|fail)\"' $TF/pft_aptrust_*.prom"
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
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Aptrust|Fleet|KeyEscrow|Integrity\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no aptrust/fleet/keyescrow/integrity alert pending or firing" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l"
check "no transient run-u services/timers (login-session run-user-N.mount units are not transient units)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "aptrust-fixup done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
