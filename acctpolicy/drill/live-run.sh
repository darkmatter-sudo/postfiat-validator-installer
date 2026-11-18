#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded two-host install + found -> fixed -> verified run of acctpolicy at the current HEAD
# (task_6a2e044a1006072ef343c005ba3765ff). Built from ../../budget/drill/install-run.sh (PASS, budget log 03).
# Restarts nothing: the node, sshd and every service keep running; only four policy files change.
#   0. preflight: clean pushed HEAD, integrity PASS, nodes full, not installed, manifest row, tools, self-test users,
#      operator topics, Prometheus + Alertmanager, alert gate, authwatch baseline.
#   1. rollout silence (fleet/aptrust/integrity/authwatch/keyescrow; never the pipeline watchdog).
#   2. pft-maint window, [MAINT] messages to a throwaway topic.   3. pft-fleet: fleet, acctpolicy, aptrust.
#   4. install.sh on both hosts.   5. FOUND: audit + plan on both hosts, sha256 of the four target files.
#   6. FIXED: apply --yes on both hosts.   7. VERIFIED: audit PASS 21/21 on both hosts; real access paths: the
#      sentry's real sshd (key login + sudo -n), local sudo -n, the sentry's self-test user sudo -n.
#   8. rollback drill: rollback -> the four files byte-identical to step 5 on both hosts; VERIFY_INJECT=selftest
#      apply -> exit 1 and byte-identical again; final apply -> audit PASS.
#   9. baselines: pft-integrity accept, schedaudit, aptrust 0/0, fleet skew, authwatch (no non-allowlisted login),
#      AppArmor/seccomp 0 denials.   10. restore + read back the throwaway and every operator topic (0 messages).
#   bash acctpolicy/drill/live-run.sh 2>&1 | tee LOG      (from the repo root, as the agent user)
#   PREFLIGHT_ONLY=1 bash acctpolicy/drill/live-run.sh    (step 0 only; changes nothing)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"; BRANCH="$(git rev-parse --abbrev-ref HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
TASK=task_6a2e044a
SU_V="$ME"; SU_S="${SENTRY_SELFTEST_USER:-ubuntu}"   # self-test users (NOPASSWD sudo) on validator / sentry
TT="pft-drill-acctpolicy-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TF=/var/lib/pft-exporter/textfile
TARGETS="/etc/pam.d/common-auth /etc/pam.d/su /etc/login.defs /etc/default/useradd"
read -ra TGT <<<"$TARGETS"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b$SU_S\b#<user2>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g; s#SHA256:[A-Za-z0-9+/]{43}#SHA256:<fingerprint>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a step failed - stopping before the next host change (restore runs)"; exit 1; }; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-acctpolicy
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
  R "rm -rf ~/pft-acctpolicy-$SHORT" || true
}
trap 'restore; rm -f "$OPS"' EXIT
srv_state() { # both nodes' server_state, validator first (same exec shape as budget/drill/install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
tsha() { sudo -n sha256sum "${TGT[@]}" | cut -c1-64; sudo -n stat -c '%a %U:%G' "${TGT[@]}"; }   # validator target files
rsha() { R "sha256sum $TARGETS | cut -c1-64; stat -c '%a %U:%G' $TARGETS"; }               # sentry target files
aw_unknown() { # non-allowlisted accepted SSH logins counted by authwatch so far (validator + pulled sentry copy)
  sudo -n systemctl start pft-authwatch.service; R 'sudo -n systemctl start pft-authwatch.service'
  sudo -n systemctl start pft-authwatch-pull.service 2>/dev/null
  grep -hE '^pft_authwatch_ssh_accepted_total\{' "$TF"/pft_authwatch_*.prom | grep -v 'key_class="allowlisted"' \
    | awk '{ s += $NF } END { print s + 0 }'
}
AUDIT_V='sudo -n pft-acctpolicy audit'
AUDIT_S="R 'sudo -n pft-acctpolicy audit'"
echo "acctpolicy two-host run - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo $BRANCH $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse "origin/$BRANCH" 2>/dev/null)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum acctpolicy/pft-acctpolicy.sh acctpolicy/install.sh acctpolicy/drill/live-run.sh fleet/manifest.tsv"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before the run" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /usr/local/bin/pft-acctpolicy 2>&1; sudo -n ls /var/lib/pft-acctpolicy 2>&1; R 'ls /usr/local/bin/pft-acctpolicy /var/lib/pft-acctpolicy 2>&1'"
check "not installed yet on either host" "$([ "$(grep -c 'No such file' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "grep -c '^acctpolicy ' fleet/manifest.tsv"
check "HEAD lists 1 acctpolicy manifest line" "$([ "$XOUT" = 1 ] && echo 0 || echo 1)"
x "for c in sshd ssh-keygen jq diff sha256sum; do command -v \$c || ls /usr/sbin/\$c; done | wc -l; R 'for c in sshd ssh-keygen jq diff sha256sum; do command -v \$c || ls /usr/sbin/\$c; done | wc -l'"
check "sshd ssh-keygen jq diff sha256sum on both hosts" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "5 5 " ] && echo 0 || echo 1)"
x "sudo -n true && echo v-sudo-ok; R \"sudo -u $SU_S sudo -n true && echo s-sudo-ok\"; R 'true' && echo s-ssh-ok"
check "self-test users have sudo -n (validator agent user, sentry $SU_S), real ssh to the sentry works" "$([ "$(grep -cE '^(v-sudo|s-sudo|s-ssh)-ok$' <<<"$XOUT")" = 3 ] && echo 0 || echo 1)"
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
UNK="$(sed 1d <<<"$XOUT" | awk '{print $2}' | grep -vxc PFTAlertPipelineWatchdog)"
check "no active silence; only the pipeline watchdog pending/firing in Prometheus" "$([ "$(head -1 <<<"$XOUT")" = 0 ] && [ "$UNK" = 0 ] && echo 0 || echo 1)"
x "aw_unknown"
AW0="$(tail -1 <<<"$XOUT")"
check "authwatch baseline read (non-allowlisted accepted logins so far: $AW0)" "$([[ "$AW0" =~ ^[0-9]+$ ]] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. rollout silence (fleet/aptrust see a new binary, integrity sees policy files, authwatch a new allowlist line; not the watchdog)"
ends="$(date -u -d '+50 min' +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK acctpolicy rollout $SHORT" \
  '{matchers: [{name: "alertname", value: "PFTFleet.*|PFTAptrust.*|PFTIntegrity.*|PFTAuth.*|PFTKeyEscrow.*", isRegex: true, isEqual: true}],
    startsAt: $s, endsAt: $e, createdBy: "acctpolicy-run", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence created (fleet, aptrust, integrity, authwatch, keyescrow; not the watchdog) until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"

echo; echo "== 2. pft-maint window, [MAINT] messages to a throwaway topic (real file kept as \$BK)"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"
x "sudo -n pft-maint start --ttl 40m --reason '$TASK acctpolicy install + fixes'"
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
gate

echo; echo "== 3. pft-fleet: manifest (fleet add-on), acctpolicy, then aptrust's allowlist copy"
x "sudo -n pft-fleet sync --addon fleet --to $SHA --apply --reason '$TASK acctpolicy manifest line'"
check "fleet manifest sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon acctpolicy --to $SHA --apply --reason '$TASK acctpolicy $SHORT first install'"
check "acctpolicy sync exit 0" "$XRC"
x "sudo -n pft-fleet sync --addon aptrust --to $SHA --apply --reason '$TASK aptrust allowlist copy += acctpolicy row'"
check "aptrust sync exit 0" "$XRC"
x "sha256sum acctpolicy/pft-acctpolicy.sh | cut -c1-64; sha256sum /usr/local/bin/pft-acctpolicy | cut -c1-64; R 'sha256sum /usr/local/bin/pft-acctpolicy | cut -c1-64'"
check "installed script = repo bytes on both hosts" "$([ "$(sort -u <<<"$XOUT" | wc -l)" = 1 ] && echo 0 || echo 1)"
gate

echo; echo "== 4. install.sh on both hosts (state dir, self-test key, authwatch allowlist entry, first audit)"
x "git archive $SHA acctpolicy | R 'rm -rf ~/pft-acctpolicy-$SHORT && mkdir -m 700 ~/pft-acctpolicy-$SHORT && tar -x -C ~/pft-acctpolicy-$SHORT'"
x "R 'sudo -n bash ~/pft-acctpolicy-$SHORT/acctpolicy/install.sh'"
check "sentry install: binary current, key created, allowlisted" "$(grep -q 'already current' <<<"$XOUT" && grep -q 'created the self-test key' <<<"$XOUT" && grep -q 'self-test key added' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n bash acctpolicy/install.sh"
check "validator install: binary current, key created, allowlisted" "$(grep -q 'already current' <<<"$XOUT" && grep -q 'created the self-test key' <<<"$XOUT" && grep -q 'self-test key added' <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 5. FOUND: audit + plan on both hosts (before any fix)"
x "$AUDIT_V"; V0="$XOUT"
check "validator audit before: exit 1, 0 FAIL" "$([ "$XRC" = 1 ] && grep -q 'RESULT: FINDINGS - 0 FAIL' <<<"$V0" && echo 0 || echo 1)"
x "$AUDIT_S"; S0="$XOUT"
check "sentry audit before: exit 1, 0 FAIL" "$([ "$XRC" = 1 ] && grep -q 'RESULT: FINDINGS - 0 FAIL' <<<"$S0" && echo 0 || echo 1)"
x "sudo -n pft-acctpolicy plan"
check "validator plan exit 0" "$XRC"
x "R 'sudo -n pft-acctpolicy plan'"
check "sentry plan exit 0" "$XRC"
x "tsha"; VS0="$XOUT"
x "rsha"; SS0="$XOUT"
gate

echo; echo "== 6. FIXED: apply --yes on both hosts (sentry first)"
x "R \"sudo -n SELFTEST_USER=$SU_S pft-acctpolicy apply --yes\""
check "sentry apply exit 0, self-test PASS" "$([ "$XRC" = 0 ] && grep -q 'self-test PASS' <<<"$XOUT" && echo 0 || echo 1)"
gate
x "R 'true' && echo s-ssh-ok"
check "real sshd on the sentry still takes the agent key after the sentry apply" "$(grep -qx s-ssh-ok <<<"$XOUT" && echo 0 || echo 1)"
gate
x "sudo -n SELFTEST_USER=$SU_V pft-acctpolicy apply --yes"
check "validator apply exit 0, self-test PASS" "$([ "$XRC" = 0 ] && grep -q 'self-test PASS' <<<"$XOUT" && echo 0 || echo 1)"
gate

echo; echo "== 7. VERIFIED: audit PASS on both hosts + real access paths"
x "$AUDIT_V"
check "validator audit after: exit 0, PASS 21 checks" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS - 21 checks' <<<"$XOUT" && echo 0 || echo 1)"
x "$AUDIT_S"
check "sentry audit after: exit 0, PASS 21 checks" "$([ "$XRC" = 0 ] && grep -q 'RESULT: PASS - 21 checks' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n true && echo v-sudo-ok; R \"sudo -u $SU_S sudo -n true && echo s-sudo-ok\"; R 'true' && echo s-ssh-ok; R 'sudo -n sshd -t && echo s-sshd-t-ok'; sudo -n sshd -t && echo v-sshd-t-ok"
check "after the fixes: sudo -n (both), real sentry sshd key login, sshd -t (both)" "$([ "$(grep -cE '^(v-sudo|s-sudo|s-ssh|s-sshd-t|v-sshd-t)-ok$' <<<"$XOUT")" = 5 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing after the fixes" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
gate

echo; echo "== 8. rollback drill: byte-identical restore, then an injected self-test failure, then the final apply"
x "R \"sudo -n SELFTEST_USER=$SU_S pft-acctpolicy rollback --yes\""
check "sentry rollback exit 0" "$XRC"
x "rsha"
check "sentry: the four files byte-identical to step 5 (sha256, mode, owner)" "$([ "$XOUT" = "$SS0" ] && echo 0 || echo 1)"
x "sudo -n SELFTEST_USER=$SU_V pft-acctpolicy rollback --yes"
check "validator rollback exit 0" "$XRC"
x "tsha"
check "validator: the four files byte-identical to step 5 (sha256, mode, owner)" "$([ "$XOUT" = "$VS0" ] && echo 0 || echo 1)"
x "R \"sudo -n SELFTEST_USER=$SU_S VERIFY_INJECT=selftest pft-acctpolicy apply --yes\""
check "sentry injected apply: exit 1, restored byte-identical" "$([ "$XRC" = 1 ] && grep -q 'restored byte-identical' <<<"$XOUT" && echo 0 || echo 1)"
x "rsha"
check "sentry: byte-identical to step 5 after the automatic restore" "$([ "$XOUT" = "$SS0" ] && echo 0 || echo 1)"
x "sudo -n SELFTEST_USER=$SU_V VERIFY_INJECT=selftest pft-acctpolicy apply --yes"
check "validator injected apply: exit 1, restored byte-identical" "$([ "$XRC" = 1 ] && grep -q 'restored byte-identical' <<<"$XOUT" && echo 0 || echo 1)"
x "tsha"
check "validator: byte-identical to step 5 after the automatic restore" "$([ "$XOUT" = "$VS0" ] && echo 0 || echo 1)"
gate
x "R \"sudo -n SELFTEST_USER=$SU_S pft-acctpolicy apply --yes\" | grep -E '^apply|selftest'"
check "sentry final apply exit 0" "$XRC"
x "sudo -n SELFTEST_USER=$SU_V pft-acctpolicy apply --yes | grep -E '^apply|selftest'"
check "validator final apply exit 0" "$XRC"
x "$AUDIT_V | tail -1; $AUDIT_S | tail -1"
check "final audit PASS 21 on both hosts" "$([ "$(grep -c 'RESULT: PASS - 21 checks' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
gate

echo; echo "== 9. baselines and side effects"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -30"
x "sudo -n pft-integrity accept --reason '$TASK: acctpolicy $SHORT installed + applied (pam.d common-auth/su, login.defs, default/useradd, binary, authwatch allowlist)' | tail -2"
x "R 'sudo -n pft-integrity verify' | grep -E '^(WARN|FAIL|RESULT)' | sed -E 's/ +sha256.*//' | cut -c1-140 | head -30"
x "R \"sudo -n pft-integrity accept --reason '$TASK: acctpolicy $SHORT installed + applied (pam.d common-auth/su, login.defs, default/useradd, binary, authwatch allowlist)'\" | tail -2"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts (baseline accepted)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-schedaudit audit | grep -E '^SUMMARY'; R 'sudo -n pft-schedaudit audit' | grep -E '^SUMMARY'"
check "schedaudit on both hosts: 0 unexpected, 0 new/removed (no timer or unit changed)" "$([ "$(grep -c '^SUMMARY .* unexpected_findings=0 new=0 removed=0 ' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-aptrust audit | grep -E '^(WARN|FAIL) |^RESULT'; R 'sudo -n pft-aptrust audit' | grep -E '^(WARN|FAIL) |^RESULT'"
check "aptrust audit on both hosts: 0 warn, 0 fail" "$([ "$(grep -c ' 0 warn, 0 fail -> exit 0' <<<"$XOUT")" = 2 ] && [ "$(grep -cE '^(WARN|FAIL) ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-aptrust.service; R 'sudo -n systemctl start pft-aptrust.service'; sudo -n systemctl start pft-aptrust-pull.service; grep -hE '^pft_aptrust_checks\{.*result=\"(warn|fail)\"' $TF/pft_aptrust_*.prom"
check "aptrust textfiles (validator + pulled sentry): warn 0, fail 0" "$([ "$(grep -c '} 0$' <<<"$XOUT")" = 4 ] && echo 0 || echo 1)"
x "sudo -n pft-fleet skew | grep -E 'acctpolicy|SUMMARY'"
check "pft-fleet skew: acctpolicy CURRENT on both hosts, nothing BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED" "$([ "$(grep -cE '^ *(validator|sentry) +acctpolicy +CURRENT' <<<"$XOUT")" = 2 ] && grep -qE 'SUMMARY CURRENT=[0-9]+ BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0$' <<<"$XOUT" && echo 0 || echo 1)"
x "aw_unknown"
check "authwatch: no new non-allowlisted accepted login (self-test logins never reached the journal; $AW0 before)" "$([ "$(tail -1 <<<"$XOUT")" = "$AW0" ] && echo 0 || echo 1)"
x "sudo -n journalctl --since @$since -o cat SYSLOG_IDENTIFIER=sshd | grep -c '^Accepted .* from 127.0.0.1 '; R \"journalctl --since @$since -o cat SYSLOG_IDENTIFIER=sshd | grep -c '^Accepted .* from 127.0.0.1 '\""
check "0 'Accepted ... from 127.0.0.1' sshd journal lines on both hosts" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts with 0 denials (nothing ran in the containers)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "ls /run | grep -c pft-acctpolicy; R 'ls /run | grep -c pft-acctpolicy'; pgrep -fc 'pft-acctpolicy\\.' ; R 'pgrep -fc \"pft-acctpolicy\\.\"'"
check "no throwaway sshd or temp dir left on either host" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 0 0 " ] && echo 0 || echo 1)"

echo; echo "== 10. end window, restore the real target, compare, keyescrow, read back the throwaway and every operator topic"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' $TF/pft_keyescrow.prom"
check "pft-keyescrow re-run after the ntfy.env restore: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "for i in \$(seq 0 15 150); do n=\$(curl -s $PROM/api/v1/alerts | jq -r '[.data.alerts[] | select(.labels.alertname != \"PFTAlertPipelineWatchdog\")] | length'); echo \"+\${i}s: \$n\"; [ \"\$n\" = 0 ] && break; sleep 15; done; echo \$n"
check "no alert but the pipeline watchdog pending or firing (silence left to run out)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "systemctl list-units --all --no-legend 'run-u*.service' 'run-u*.timer' | wc -l; R 'ls -d ~/pft-acctpolicy-* 2>/dev/null | wc -l'"
check "no transient run-u services/timers, no install copy left on the sentry" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "0 0 " ] && echo 0 || echo 1)"
echo "operator topic read-back waits 90 s (>= group_interval + 30 s after the last change)"; sleep 90
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
echo; echo "live-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
