#!/usr/bin/env bash
# install-run.sh: recorded two-host install of ../dnsaudit through ../fleet, sentry first, inside ONE pft-maint
# window whose [MAINT] notices go to a throwaway topic. Order matters (a rule loaded before its series exists reads
# DEAD to ../rulecheck): rulecheck lines -> pft-fleet sync fleet, aptrust, dnsaudit -> env file + first run through
# the sandboxed unit on each host (textfile written) -> validator pull drop-in + run (sentry copy pulled) -> timers
# -> Prometheus reload (PFTDNSAuditFinding loaded) -> rulecheck run clean -> schedaudit/integrity/skew/aptrust/
# jobwatch -> negative controls (.invalid, no textfile write) and audit PASS on both hosts -> postfiatd container ID
# and StartedAt unchanged on both hosts -> both operator topics (monitor + alert bridge) read back for 0 messages.
# Never touches postfiatd (no stop/restart/exec). Already-installed pieces are kept, so a re-run is read-mostly.
#   TO=<pushed sha> [PREFLIGHT_ONLY=1] bash dnsaudit/drill/install-run.sh 2>&1 | tee runlog     (validator)
set -uo pipefail
TO="${TO:?}"; REASON="task_fdeb1b1d3a29511fc05c433026b34d6a: pft-dnsaudit DNS dependency audit"
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-dnsaudit
TF=/var/lib/pft-exporter/textfile; RC_CONF=/etc/pft-rulecheck.conf
RC_LINE='textfile pft_dnsaudit_*.prom   45m  pft_dnsaudit_last_run_timestamp_seconds'
DROPIN=/etc/systemd/system/pft-dnsaudit.service.d/pull.conf
TT="pft-drill-dnsaudit-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
OPS="$(sudo -n sed -n 's/^NTFY_TOPIC=//p' /etc/postfiat-monitor.env | head -1)"
BRIDGE_URL="$(sed -n 's/^NTFY_URL=//p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null | tr -d '"' | head -1)"
BRT="${BRIDGE_URL##*/}"
since="$(date -u +%s)"; HAD=0; MADE=0; MSTART=0; FAILS=0
red() { sed -E "s#$TT#<throwaway-topic>#g; s#${OPS:-@@none@@}#<redacted>#g; s#${BRT:-@@none@@}#<redacted>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#/home/[a-z0-9_-]+#~#g; s#runuser -u [a-z0-9_-]+#runuser -u <operator>#g"; }
x() { echo "\$ $*" | red; XOUT="$( (eval "$*") 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
gate() { if [ "$1" = 0 ]; then echo "GATE PASS $2"; else echo "GATE FAIL $2"; FAILS=$((FAILS + 1)); fi; }
stop_if_failed() { [ "$FAILS" = 0 ] || { echo "RESULT: stopped after a failed gate ($1) -> FAIL"; exit 1; }; }
R() { ssh -o BatchMode=yes relay "$@" </dev/null; }   # sentry (root login)
restore() {
  [ "$MSTART" = 1 ] && sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MSTART=0
  if [ "$MADE" = 1 ]; then if [ "$HAD" = 1 ]; then sudo -n mv -f "$BK" "$NE"; else sudo -n rm -f "$NE"; fi; MADE=0
    sudo -n systemctl start pft-keyescrow.service; fi
}
trap restore EXIT
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 3
ids() { # "host id startedat" for both live node containers
  printf 'validator %s\n' "$(docker inspect -f '{{.Id}} {{.State.StartedAt}}' postfiatd)"
  printf 'sentry %s\n' "$(R "docker inspect -f '{{.Id}} {{.State.StartedAt}}' postfiatd-sentry")"
}
echo "dnsaudit install-run @$TO - $(date -u +%FT%TZ)"

# ---------- preflight (changes nothing) ----------
x "git cat-file -t $TO && git merge-base --is-ancestor $TO origin/main && echo ancestor-of-origin/main && [ \"\$(git rev-parse HEAD)\" = $TO ] && git status --short -- dnsaudit alerts fleet rulecheck | wc -l"
gate "$([ "$XRC" = 0 ] && [ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)" "TO is pushed, checked out and the tree is clean"
x "git show --stat --format='%H %s' $TO -- | tail -3; git show $TO:fleet/manifest.tsv | grep -c '^dnsaudit '; git show $TO:alerts/prometheus.yml | grep -c dnsaudit.rules.yml"
x "sudo -n pft-maint status | head -1"
grep -q 'no maintenance window' <<< "$XOUT"; gate $? "no pft-maint window open"
x "curl -s -m 10 http://127.0.0.1:9093/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
gate "$([ "$XOUT" = 0 ] && echo 0 || echo 1)" "no active Alertmanager silence"
x "curl -s -m 10 http://127.0.0.1:9090/api/v1/alerts | jq -e -r '.data.alerts[] | \"\\(.state) \\(.labels.alertname) \\(.labels.host // \"-\") notify=\\(.labels.notify // \"-\")\"'"
gate "$([ -n "$XOUT" ] && ! grep -v -E '^firing PFTAlertPipelineWatchdog |notify=digest$' <<< "$XOUT" | grep -q . && echo 0 || echo 1)" "Prometheus: only the watchdog and digest-only alerts active (query answered)"
x "ids"
PRE_IDS="$XOUT"
gate "$([ "$(grep -cE '^(validator|sentry) [0-9a-f]{64} 20[0-9-]+T' <<< "$PRE_IDS")" = 2 ] && echo 0 || echo 1)" "both postfiatd container IDs + StartedAt read"
x "curl -s -m 10 http://127.0.0.1:5005 -d '{\"method\":\"server_info\"}' | jq -r .result.info.server_state"
gate "$([ "$XOUT" = full ] || [ "$XOUT" = proposing ]; echo $?)" "validator server_state full"
x "sudo -n pft-integrity verify | tail -1; R 'pft-integrity verify | tail -1'"
gate "$([ "$(grep -c 'RESULT: PASS' <<< "$XOUT")" = 2 ] && echo 0 || echo 1)" "integrity PASS both hosts"
x "sudo -n pft-aptrust audit | grep -c '^WARN'; R 'pft-aptrust audit | grep -c ^WARN'"
PRE_APT="$XOUT"
x "sudo -n test -e /usr/local/bin/pft-dnsaudit && echo validator-installed; R 'test -e /usr/local/bin/pft-dnsaudit && echo sentry-installed'; ls $TF | grep -c dnsaudit"
x "sudo -n sed -n 's/^PULL_SSH=//p' /etc/pft-kmod.env | grep -c ."
gate "$([ "$XOUT" = 1 ] && echo 0 || echo 1)" "PULL_SSH available from /etc/pft-kmod.env (validator)"
x "sudo -n bash -c 'c=\"\$(sed -n \"s/^PULL_SSH=//p\" /etc/pft-kmod.env | tr -d \"\\\"\")\"; [ -n \"\$c\" ] && \$c true' && echo pull-ssh-ok"
gate "$([ "$XOUT" = pull-ssh-ok ] && echo 0 || echo 1)" "the pull's ssh command reaches the sentry as root"
stop_if_failed preflight
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "RESULT: preflight only, $FAILS gate(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"; exit "$FAILS"; }

# ---------- window ----------
sudo -n test -e "$NE" && HAD=1
{ [ "$HAD" = 0 ] || sudo -n cp -p "$NE" "$BK"; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' "$TT" | sudo -n tee "$NE" >/dev/null && sudo -n chmod 600 "$NE" && MADE=1
[ "$MADE" = 1 ] || exit 1
x "sudo -n pft-maint start --ttl 30m --reason 'pft-fleet sync dnsaudit (task_fdeb)'"; [ "$XRC" = 0 ] && MSTART=1 || exit 1
sleep 70
x "R 'pft-maint active && echo active'"
gate "$([ "$XOUT" = active ] && echo 0 || echo 1)" "window active on the sentry"; stop_if_failed window

# ---------- rulecheck lines first (a textfile without one reads UNCONFIGURED) ----------
x "sudo -n bash -c 'grep -qF \"pft_dnsaudit_*.prom\" $RC_CONF || printf \"%s\\n\" \"# pft-dnsaudit (15-minute audit; sentry copy pulled in the same run)\" \"$RC_LINE\" \"require pft_dnsaudit_validator.prom\" \"require pft_dnsaudit_sentry.prom\" >> $RC_CONF'; grep -n dnsaudit $RC_CONF"
R "grep -qF 'pft_dnsaudit_*.prom' $RC_CONF || printf '%s\n' '# pft-dnsaudit (15-minute audit)' '$RC_LINE' 'require pft_dnsaudit_sentry.prom' >> $RC_CONF" >/dev/null
x "R 'grep -n dnsaudit $RC_CONF'"
gate "$([ "$(grep -c 'pft_dnsaudit_\*.prom' <<< "$XOUT")" = 1 ] && echo 0 || echo 1)" "rulecheck lines on both hosts"

# ---------- files through ../fleet (fleet first: it reads its INSTALLED manifest; aptrust allowlist is a copy) ----------
for a in fleet aptrust dnsaudit; do
  x "sudo -n pft-fleet sync --addon $a --to $TO | tail -6"
  x "sudo -n pft-fleet sync --addon $a --to $TO --apply --reason '$REASON' | tail -8"; gate "$XRC" "fleet sync $a both hosts"
done
stop_if_failed "fleet sync"
x "sha256sum /usr/local/bin/pft-dnsaudit /etc/systemd/system/pft-dnsaudit.service /etc/systemd/system/pft-dnsaudit.timer; R 'sha256sum /usr/local/bin/pft-dnsaudit /etc/systemd/system/pft-dnsaudit.service /etc/systemd/system/pft-dnsaudit.timer'; git show $TO:dnsaudit/pft-dnsaudit.sh | sha256sum"
gate "$([ "$(grep -c "$(git show "$TO:dnsaudit/pft-dnsaudit.sh" | sha256sum | cut -c1-64)" <<< "$XOUT")" = 3 ] && echo 0 || echo 1)" "installed script = TO's bytes on both hosts"

# ---------- env + first run through the sandboxed unit, sentry first ----------
x "R 'test -e /etc/pft-dnsaudit.env || { install -m 600 /dev/null /etc/pft-dnsaudit.env && printf \"# pft-dnsaudit config (see pft-dnsaudit.env.example)\\nHOST_LABEL=sentry\\n\" > /etc/pft-dnsaudit.env; }; stat -c \"%a %U\" /etc/pft-dnsaudit.env; grep -c ^HOST_LABEL=sentry /etc/pft-dnsaudit.env'"
x "R 'systemctl start pft-dnsaudit.service; systemctl show -p Result --value pft-dnsaudit.service; grep -E \"^pft_dnsaudit_(up|checks)\" $TF/pft_dnsaudit_sentry.prom'"
gate "$(grep -q '^success$' <<< "$XOUT" && grep -q 'pft_dnsaudit_up{host="sentry"} 1' <<< "$XOUT" && echo 0 || echo 1)" "sentry: first run through the unit, textfile up 1"
x "sudo -n bash -c 'test -e /etc/pft-dnsaudit.env || { install -m 600 /dev/null /etc/pft-dnsaudit.env && { echo \"# pft-dnsaudit config (see pft-dnsaudit.env.example)\"; echo HOST_LABEL=validator; echo PEER_LABEL=sentry; grep \"^PULL_SSH=\" /etc/pft-kmod.env; } >> /etc/pft-dnsaudit.env; }; stat -c \"%a %U\" /etc/pft-dnsaudit.env; grep -cE \"^(HOST_LABEL=validator|PEER_LABEL=sentry|PULL_SSH=.+)\$\" /etc/pft-dnsaudit.env'"
x "sudo -n install -d -m 755 $(dirname "$DROPIN") && printf '[Service]\nEnvironment=PFT_DA_PULL=1\n' | sudo -n install -m 644 /dev/stdin $DROPIN && sudo -n systemctl daemon-reload && cat $DROPIN"
x "sudo -n systemctl start pft-dnsaudit.service; systemctl show -p Result --value pft-dnsaudit.service; grep -hE '^pft_dnsaudit_(up|checks)' $TF/pft_dnsaudit_validator.prom $TF/pft_dnsaudit_sentry.prom"
gate "$(grep -q '^success$' <<< "$XOUT" && grep -q 'pft_dnsaudit_up{host="validator"} 1' <<< "$XOUT" && grep -q 'pft_dnsaudit_up{host="sentry"} 1' <<< "$XOUT" && echo 0 || echo 1)" "validator: first run + pull through the unit, both textfiles up 1"
x "sudo -n journalctl --utc -u pft-dnsaudit.service -n 40 --no-pager | grep -cE 'Permission denied|Operation not permitted|cannot'"
gate "$([ "$XOUT" = 0 ] && echo 0 || echo 1)" "no sandbox denials in the unit's journal"
x "sudo -n systemctl enable --now pft-dnsaudit.timer 2>&1 | tail -1; R 'systemctl enable --now pft-dnsaudit.timer 2>&1 | tail -1'; systemctl is-active pft-dnsaudit.timer; R 'systemctl is-active pft-dnsaudit.timer'"
gate "$([ "$(grep -c '^active$' <<< "$XOUT")" = 2 ] && echo 0 || echo 1)" "timers active on both hosts"
stop_if_failed "first runs"

# ---------- Prometheus: only now that both hosts' series exist ----------
x "sudo -n docker kill -s HUP pft-prometheus >/dev/null && sleep 5 && curl -s -m 10 http://127.0.0.1:9090/api/v1/status/runtimeinfo | jq -r .data.reloadConfigSuccess && curl -s -m 10 http://127.0.0.1:9090/api/v1/rules | jq -r '.data.groups[] | select(.name == \"pft-dnsaudit\") | .rules[] | \"\\(.name) for=\\(.duration) notify=\\(.labels.notify) health=\\(.health)\"'"
gate "$(grep -q '^true$' <<< "$XOUT" && grep -q 'PFTDNSAuditFinding for=1800 notify=digest health=ok' <<< "$XOUT" && echo 0 || echo 1)" "Prometheus reloaded: PFTDNSAuditFinding loaded (30m, digest)"
sleep 40
x "curl -s -m 10 'http://127.0.0.1:9090/api/v1/query' --data-urlencode 'query=count by (host) (pft_dnsaudit_check_status)' | jq -r '.data.result[] | \"\\(.metric.host) \\(.value[1])\"'"
gate "$([ "$(grep -cE '^(validator|sentry) [0-9]+$' <<< "$XOUT")" = 2 ] && echo 0 || echo 1)" "both hosts' check series scraped"
x "sudo -n systemctl start pft-rulecheck.service; systemctl show -p Result --value pft-rulecheck.service; sudo -n pft-rulecheck check 2>&1 | grep -E 'dnsaudit|^RESULT'"
gate "$(grep -q '^success$' <<< "$XOUT" && grep -q 'LIVE .* DEAD 0 ERROR 0' <<< "$XOUT" && grep -q 'STALE 0 MISSING 0 LEFTOVER 0 UNCONFIGURED 0' <<< "$XOUT" && grep -qE '^LIVE +pft-dnsaudit/PFTDNSAuditFinding' <<< "$XOUT" && echo 0 || echo 1)" "rulecheck clean, PFTDNSAuditFinding LIVE (validator)"
x "R 'systemctl start pft-rulecheck.service; pft-rulecheck check 2>&1 | grep -E \"dnsaudit|^RESULT\"'"
gate "$(grep -q 'STALE 0 MISSING 0 LEFTOVER 0 UNCONFIGURED 0' <<< "$XOUT" && echo 0 || echo 1)" "rulecheck clean (sentry textfiles)"

restore
# ---------- baselines ----------
x "sudo -n pft-schedaudit audit | grep ^SUMMARY; R 'pft-schedaudit audit | grep ^SUMMARY'"
if [ "$(grep -c 'unexpected_findings=0 new=0 removed=0' <<< "$XOUT")" != 2 ]; then
  x "sudo -n pft-schedaudit accept --reason '$REASON' && sudo -n pft-schedaudit collect; R \"pft-schedaudit accept --reason 'task_fdeb pft-dnsaudit.timer' && pft-schedaudit collect\""
  x "sudo -n pft-schedaudit audit | grep ^SUMMARY; R 'pft-schedaudit audit | grep ^SUMMARY'"
fi
gate "$([ "$(grep -c 'unexpected_findings=0 new=0 removed=0' <<< "$XOUT")" = 2 ] && echo 0 || echo 1)" "schedaudit clean both hosts (no unexpected, new or removed entry)"
x "sudo -n pft-integrity verify | grep -E '^(WARN|FAIL)' | head; R 'pft-integrity verify | grep -E \"^(WARN|FAIL)\" | head'"
x "sudo -n pft-integrity accept --reason '$REASON: env file + pull drop-in + rulecheck lines' | tail -1; R \"pft-integrity accept --reason 'task_fdeb: pft-dnsaudit env file + rulecheck line' | tail -1\""
x "sudo -n pft-integrity verify | tail -1; R 'pft-integrity verify | tail -1'"
gate "$([ "$(grep -c 'RESULT: PASS' <<< "$XOUT")" = 2 ] && echo 0 || echo 1)" "integrity PASS both hosts"
x "sudo -n pft-fleet skew | grep -E ' (fleet|aptrust|dnsaudit) |DIVERGED|^SUMMARY'; echo skew_rc=\${PIPESTATUS[0]}"
gate "$(grep -q 'skew_rc=0' <<< "$XOUT" && echo 0 || echo 1)" "fleet skew rc 0"
x "sudo -n pft-aptrust audit | grep -E '^WARN|^RESULT' | grep -c dnsaudit; sudo -n pft-aptrust audit | grep -c '^WARN'; R 'pft-aptrust audit | grep -c ^WARN'"
gate "$([ "$(head -1 <<< "$XOUT")" = 0 ] && [ "$(tail -2 <<< "$XOUT")" = "$PRE_APT" ] && echo 0 || echo 1)" "aptrust: no WARN for dnsaudit files, WARN counts unchanged"
x "sudo -n pft-jobwatch collect >/dev/null && sudo -n pft-jobwatch inventory | grep dnsaudit; TEXT_BUDGET=999999 sudo -n pft-jobwatch collect --stdout | wc -c; R 'pft-jobwatch collect >/dev/null && pft-jobwatch inventory | grep dnsaudit'"
gate "$([ "$(grep -c 'pft-dnsaudit.timer.*900' <<< "$XOUT")" = 2 ] && echo 0 || echo 1)" "jobwatch: pft-dnsaudit.timer on both hosts, interval 900 s"
x "sudo -n pft-keyescrow inventory | tail -1"

# ---------- live results: audits PASS, negative controls never write ----------
for h in sentry validator; do
  if [ "$h" = sentry ]; then P=R; else P="sudo -n"; fi
  x "$P pft-dnsaudit audit; echo audit_rc=\$?"
  gate "$(grep -q '^audit_rc=0$' <<< "$XOUT" && grep -q '^RESULT: PASS' <<< "$XOUT" && echo 0 || echo 1)" "$h: live audit PASS"
  x "$P sha256sum $TF/pft_dnsaudit_$h.prom; $P pft-dnsaudit audit --name pft-control.invalid | grep -E '^FAIL|^RESULT'; echo control_rc=\${PIPESTATUS[0]}; $P pft-dnsaudit audit --textfile --name pft-control.invalid; echo textfile_control_rc=\$?; $P sha256sum $TF/pft_dnsaudit_$h.prom"
  gate "$(grep -q '^FAIL  resolve:pft-control.invalid' <<< "$XOUT" && grep -q '^control_rc=1$' <<< "$XOUT" && grep -q '^textfile_control_rc=3$' <<< "$XOUT" && [ "$(grep -cE '^[0-9a-f]{64} ' <<< "$XOUT")" = 2 ] && [ "$(grep -E '^[0-9a-f]{64} ' <<< "$XOUT" | cut -c1-64 | sort -u | wc -l)" = 1 ] && echo 0 || echo 1)" "$h: .invalid control FAILs (exit 1), --textfile control refused (exit 3), textfile byte-identical"
done
x "sudo -n pft-apparmor audit --since 3600 | tail -1; sudo -n pft-seccomp audit | tail -1; R 'pft-apparmor audit --since 3600 | tail -1; pft-seccomp audit | tail -1'"
gate "$([ "$(grep -c 'RESULT: PASS' <<< "$XOUT")" = 4 ] && echo 0 || echo 1)" "container AppArmor + seccomp: no denials (both hosts)"

# ---------- postfiatd untouched, operator topics quiet ----------
x "ids"
gate "$([ "$XOUT" = "$PRE_IDS" ] && echo 0 || echo 1)" "postfiatd container IDs + StartedAt unchanged (both hosts)"
x "curl -s -m 10 http://127.0.0.1:5005 -d '{\"method\":\"server_info\"}' | jq -r .result.info.server_state"
gate "$([ "$XOUT" = full ] || [ "$XOUT" = proposing ]; echo $?)" "validator server_state full"
sleep 30
x "curl -s -m 15 'https://ntfy.sh/$TT/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title'"
x "curl -s -m 15 'https://ntfy.sh/$OPS/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title' | wc -l"
gate "$([ -n "$OPS" ] && [ "$XOUT" = 0 ] && echo 0 || echo 1)" "operator monitor topic: 0 messages since the run started"
x "curl -s -m 15 '$BRIDGE_URL/json?poll=1&since=$since' | jq -r 'select(.event == \"message\") | .title' | wc -l"
gate "$([ -n "$BRT" ] && [ "$XOUT" = 0 ] && echo 0 || echo 1)" "operator alert-bridge topic: 0 messages since the run started"
echo "RESULT: $FAILS gate(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
