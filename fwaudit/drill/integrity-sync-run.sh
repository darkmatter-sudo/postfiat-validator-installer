#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host sync of the pft-integrity v6 fix (fw:ufw hashes the per-family UFW rule table + v6_rules) at the
# current HEAD (task_32d07e3a14bbfa7a29550f1d3c287263, fwaudit step 2 integration), through pft-fleet inside a
# pft-maint window. Built from ./install-run.sh (run 08 PASS 51/51). Changes NO firewall rule and no unit: it rewrites
# /usr/local/bin/pft-integrity on both hosts; pft-fleet's accept re-baselines with the new collector.
#   0. preflight: integrity PASS, nodes full, integrity BEHIND (only), HEAD tests pass, operator topics, alerts.
#   1. rollout silence (fleet/integrity/keyescrow only, never the watchdog).  2. pft-maint window, throwaway topic.
#   3. pft-fleet sync --addon integrity (sentry first, gated, accept).  4. VERIFIED: verify PASS both hosts and the
#      baseline now carries fw:ufw v6_rules (validator 2: dual-family 22+2559; sentry 1: 22 only, 2559 is IPv4-only
#      since fwaudit log 02).  5. skew.  6. restore + read-back (operator topics must get 0 messages).
#   bash fwaudit/drill/integrity-sync-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash fwaudit/drill/integrity-sync-run.sh  (step 0 only; changes nothing)
# KNOWN_PENDING: alert names already pending (long `for:`) before the run that the preflight accepts (each is printed).
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_32d07e3a
KNOWN_PENDING="${KNOWN_PENDING:-}"
TT="pft-drill-intsync-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-integrity-sync
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
srv_state() { # both nodes' server_state, validator first (same exec shape as install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
v6f() { # v6f -> "validator_v6_rules sentry_v6_rules" from the new baseline (root-only manifest; one field, no hashes)
  sudo -n awk -F'\t' '$1=="fw:ufw" && $2=="v6_rules" {print $3}' /var/lib/pft-integrity/manifest.tsv
  R "sudo -n awk -F'\t' '\$1==\"fw:ufw\" && \$2==\"v6_rules\" {print \$3}' /var/lib/pft-integrity/manifest.tsv"
}
echo "pft-integrity v6 sync - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum integrity/pft-integrity.sh integrity/tests/test-fw.sh fwaudit/drill/integrity-sync-run.sh; sha256sum /usr/local/bin/pft-integrity; R 'sha256sum /usr/local/bin/pft-integrity'"
x "TEST_TMPDIR=\$HOME/.cache bash integrity/tests/test-fw.sh | tail -1"
check "integrity fw unit tests pass at HEAD" "$XRC"
x "shellcheck integrity/pft-integrity.sh integrity/tests/test-fw.sh fwaudit/drill/integrity-sync-run.sh && echo clean"
check "shellcheck clean" "$XRC"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the sync" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -vE ' CURRENT( |\$)'"
check "skew: only integrity BEHIND, on both hosts" "$([ "$(grep -cE '^ *(validator|sentry) +integrity +BEHIND' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^ *(validator|sentry) +[a-z]+ +(BEHIND|MODIFIED|MISSING|UNEXPECTED|DIVERGED)' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "v6f | tr '\n' ' '; echo"
check "old baselines have no fw:ufw v6_rules field yet" "$([ -z "$(tr -d ' \n' <<<"$XOUT")" ] && echo 0 || echo 1)"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'; curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
echo "known pending before the run (accepted by the preflight): ${KNOWN_PENDING:-none}"
UNK="$(sed 1d <<<"$XOUT" | awk '{print $2}' | grep -vx PFTAlertPipelineWatchdog | while read -r a; do case " $KNOWN_PENDING " in *" $a "*) ;; *) echo "$a" ;; esac; done | wc -l)"
check "no active silence; only the pipeline watchdog (+ KNOWN_PENDING) pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$UNK" = 0 ] && echo 0 || echo 1)"
x "curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.state == \"firing\" and .labels.alertname != \"PFTAlertPipelineWatchdog\")] | length'"
check "nothing but the watchdog FIRING (KNOWN_PENDING may only be pending)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (fleet/integrity/keyescrow; not the watchdog)"
ends="$(date -u -d '+40 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK integrity v6 sync $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTFleet.*|PFTIntegrity.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "integrity-sync", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (fleet, integrity, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 30m --reason '$TASK integrity v6 sync'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || { echo "setup failed - stopping before any file is written"; exit 1; }

echo; echo "== 3. pft-fleet sync --addon integrity (gated per host, sentry first, accept with reason)"
x "sudo -n pft-fleet sync --addon integrity --to $SHA --apply --reason '$TASK integrity v6 per-family fw:ufw'"
check "integrity sync exit 0 (files written + integrity accepted by pft-fleet)" "$XRC"
[ "$FAILS" = 0 ] || { echo "sync failed - stopping (pft-fleet rolls back on its own gate failures)"; exit 1; }

echo; echo "== 4. VERIFIED: new collector live on both hosts"
x "sha256sum /usr/local/bin/pft-integrity; R 'sha256sum /usr/local/bin/pft-integrity'"
H="$(sha256sum integrity/pft-integrity.sh | cut -c1-64)"
check "installed pft-integrity == HEAD integrity/pft-integrity.sh on both hosts" "$([ "$(grep -c "^$H " <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts after the sync" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "v6f | tr '\n' ' '; echo"
check "baselines carry fw:ufw v6_rules: validator 2, sentry 1" "$([ "$(tr -s ' \n' ' ' <<<"$XOUT")" = "2 1 " ] && echo 0 || echo 1)"
x "sudo -n tail -n 1 /var/lib/pft-integrity/accept.log | cut -f1,5; R 'sudo -n tail -n 1 /var/lib/pft-integrity/accept.log | cut -f1,5'"

echo; echo "== 5. fleet skew"
x "sudo -n pft-fleet skew | tail -3"
check "pft-fleet skew exit 0, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$XRC" = 0 ] && grep -qE '^ *SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
echo; echo "== 6. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname | test(\"Fleet|Integrity|KeyEscrow|AppArmor|Seccomp\"))] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no fleet/integrity/keyescrow/confinement alert pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l"
check "no transient run-u services/timers" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "integrity-sync-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
