#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016  # remote commands are single-quoted on purpose (expand on the sentry)
# Recorded cross-host peer-port TLS audit (task_2b0012da8605a2058a617ebeaab70854), after drill/install-run.sh.
# Each host's installed pft-peertls audits its own peer port on loopback AND the other host's public peer port
# (`--target`, remote pace PACE_REMOTE 6 s, 21 handshakes per run), then `pft-peertls crosscheck` requires each remote
# view (protocols, TLS 1.2 classes, TLS 1.3 suites, renegotiation, certificate key + sha256) to equal the other host's
# own local view. Read-only towards the nodes; the only host change is one `remote` line per host in
# /etc/pft-peertls.targets (the weekly timer audits local targets only; not a pft-integrity item).
#   0. preflight: HEAD pushed, installed bytes = HEAD on both hosts, integrity PASS, nodes full, cluster link up,
#      targets = the one local line, both addresses derived from two owned sources each (never printed).
#   1. remote line on each host (root 0600), integrity still PASS.
#   2. reports: local + remote JSON on each host (--no-state: the weekly drift baseline is not touched), --public.
#   3. crosscheck both directions (PASS) + flip control (a host's remote view vs ITS OWN local view must FAIL).
#   4. offline: render every committed JSON and cmp with the live human report.  5. end gates.
# Outputs (redacted, no addresses): OUT/{validator,sentry}-{local,remote}.json + .txt, crosscheck*.txt.
#   OUT=peertls/logs/cross bash peertls/drill/crosshost-run.sh 2>&1 | tee LOG    (repo root, agent user)
#   PREFLIGHT_ONLY=1 bash peertls/drill/crosshost-run.sh
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
PROM=http://127.0.0.1:9090
ME="$(id -un)"; HN="$(hostname)"
OUT="${OUT:-peertls/logs/cross}"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "a check failed - stopping (FAILS=$FAILS)"; exit 1; }; }
srv_state() { # both nodes' server_state, validator first (same exec shape as install-run.sh)
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state
  R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005 | jq -r .result.info.server_state"
}
link_up() { # the sentry's node key is among the validator's peers (same exec shape as seccomp/drill/host-run.sh)
  local pk
  pk="$(R "sudo -n docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r .result.info.pubkey_node)"
  if [ -z "$pk" ] || [ "$pk" = null ]; then echo "no sentry pubkey"; return 1; fi
  sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"peers"}' http://127.0.0.1:5005 \
    | jq -r --arg k "$pk" '"peers \(.result.peers | length), sentry link \([.result.peers[] | select(.public_key == $k)] | length)"'
}
echo "peertls cross-host audit - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
git fetch -q origin
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 0. preflight (read-only)"
x "sha256sum peertls/pft-peertls.sh peertls/peertls_eval.py peertls/policy/* peertls/drill/crosshost-run.sh | cut -c1-64"
x "sudo -n sha256sum /usr/local/bin/pft-peertls /usr/local/lib/pft-peertls/peertls_eval.py /usr/local/lib/pft-peertls/policy/* | cut -c1-64; R 'sha256sum /usr/local/bin/pft-peertls /usr/local/lib/pft-peertls/peertls_eval.py /usr/local/lib/pft-peertls/policy/* | cut -c1-64'"
INST="$XOUT"
REPOH="$(sha256sum peertls/pft-peertls.sh peertls/peertls_eval.py peertls/policy/* | cut -c1-64)"
check "installed audit, grader and policies = HEAD bytes on both hosts" "$([ "$(head -4 <<<"$INST")" = "$REPOH" ] && [ "$(tail -4 <<<"$INST")" = "$REPOH" ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts before" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "link_up"
PEERS0="$(sed -n 's/^peers \([0-9]*\),.*/\1/p' <<<"$XOUT")"
check "cluster link up before (sentry key among the validator's peers)" "$(grep -q 'sentry link 1$' <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n grep -cvE '^[[:space:]]*(#|\$)' /etc/pft-peertls.targets; sudo -n grep -vE '^[[:space:]]*(#|\$)' /etc/pft-peertls.targets; R 'sudo -n grep -cvE \"^[[:space:]]*(#|\\\$)\" /etc/pft-peertls.targets; sudo -n grep -vE \"^[[:space:]]*(#|\\\$)\" /etc/pft-peertls.targets'"
check "targets: exactly the local loopback line on each host" "$([ "$(tr '\n' '|' <<<"$XOUT")" = "1|validator 127.0.0.1 2559 local postfiatd|1|sentry 127.0.0.1 2559 local postfiatd-sentry|" ] && echo 0 || echo 1)"
# addresses (never printed): sentry = the validator's [ips_fixed] entry AND the ssh alias; validator = the source the
# sentry sees on our ssh connection AND an address configured on this host's interfaces.
VCFG=/var/lib/docker/volumes/postfiatd_postfiatd-config/_data/postfiatd.cfg
S_FIX="$(sudo -n awk '/^\[ips_fixed\]/{f=1;next} /^\[/{f=0} f && $2 == 2559 {print $1}' "$VCFG")"
S_SSH="$(ssh -G relay | awk '$1 == "hostname" {print $2}')"
V_SEEN="$(R 'echo "${SSH_CONNECTION%% *}"')"
V_LOCAL="$(ip -4 -o addr show scope global | awk '{sub("/.*", "", $4); print $4}' | grep -cxF "$V_SEEN")"
isip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
check "sentry address: [ips_fixed] entry = ssh alias address (not printed)" "$(isip "$S_FIX" && [ "$S_FIX" = "$S_SSH" ] && echo 0 || echo 1)"
check "validator address: the sentry's view of our ssh source is configured on this host (not printed)" "$(isip "$V_SEEN" && [ "$V_LOCAL" = 1 ] && echo 0 || echo 1)"
x "sudo -n pft-peertls plan; R 'sudo -n pft-peertls plan'"
check "plans (local only): 21 handshakes per target, max 40, on both hosts" "$([ "$(grep -c '^total: 21 (max 40)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s --max-time 10 $PROM/api/v1/alerts | jq -r '.status, ([.data.alerts[] | select(.labels.alertname != \"PFTAlertPipelineWatchdog\")] | length)'"
check "Prometheus answers; nothing but the watchdog pending/firing" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "success 0 " ] && echo 0 || echo 1)"
gate
[ "${PREFLIGHT_ONLY:-0}" = 1 ] && { echo "PREFLIGHT_ONLY: stopping before any change ($FAILS failed)"; exit 0; }

echo; echo "== 1. one remote line per host (/etc/pft-peertls.targets stays root 0600)"
x "printf 'sentry %s 2559 remote\n' \"\$S_FIX\" | sudo -n tee -a /etc/pft-peertls.targets >/dev/null && sudo -n stat -c '%a %U' /etc/pft-peertls.targets && sudo -n awk '\$4 == \"remote\" {print \$1, \$3, \$4}' /etc/pft-peertls.targets"
check "validator: remote line 'sentry 2559 remote', 600 root" "$([ "$(tr '\n' '|' <<<"$XOUT")" = "600 root|sentry 2559 remote|" ] && echo 0 || echo 1)"
x "printf 'validator %s 2559 remote\n' \"\$V_SEEN\" | R 'sudo -n tee -a /etc/pft-peertls.targets >/dev/null && sudo -n stat -c \"%a %U\" /etc/pft-peertls.targets && sudo -n awk \"\\\$4 == \\\"remote\\\" {print \\\$1, \\\$3, \\\$4}\" /etc/pft-peertls.targets'"
check "sentry: remote line 'validator 2559 remote', 600 root" "$([ "$(tr '\n' '|' <<<"$XOUT")" = "600 root|validator 2559 remote|" ] && echo 0 || echo 1)"
x "sudo -n pft-peertls plan --target sentry; R 'sudo -n pft-peertls plan --target validator'"
check "remote plans: 21 handshakes, max 40, on both hosts" "$([ "$(grep -c '^total: 21 (max 40)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity still PASS on both hosts (the targets file is config, not an integrity item)" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
gate

echo; echo "== 2. reports: local + remote on each host (--no-state, --public), remote pace 6 s"
mkdir -p "$OUT"
TMPD="$(mktemp -d -p "$HOME/.cache")"; trap 'rm -rf "$TMPD"' EXIT
# shellcheck disable=SC2024  # the report is written to our own scratch file, sudo is only for the audit
run_report() { # WHERE(L|R) NAME [--target T] -> $TMPD/NAME.json + rc line
  local w="$1" n="$2"; shift 2
  if [ "$w" = L ]; then sudo -n pft-peertls audit --json --no-state --public "$@" > "$TMPD/$n.json"
  else R "sudo -n pft-peertls audit --json --no-state --public $*" > "$TMPD/$n.json"; fi
  echo "rc=$? bytes=$(wc -c < "$TMPD/$n.json") verdict=$(jq -r .verdict "$TMPD/$n.json" 2>/dev/null) handshakes=$(jq -r .handshakes "$TMPD/$n.json" 2>/dev/null)"
}
x "run_report L validator-local"
check "validator local: verdict PASS, 21 handshakes" "$(grep -q 'rc=0 .* verdict=PASS handshakes=21$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 30; run_report R sentry-local"
check "sentry local: verdict PASS, 21 handshakes" "$(grep -q 'rc=0 .* verdict=PASS handshakes=21$' <<<"$XOUT" && echo 0 || echo 1)"
x "sleep 30; s=\$(date +%s); run_report L validator-remote --target sentry; echo \"took \$((\$(date +%s) - s)) s\""
check "validator -> sentry remote: verdict PASS, 21 handshakes, >= 120 s (6 s pace)" "$(grep -q 'rc=0 .* verdict=PASS handshakes=21$' <<<"$XOUT" && [ "$(sed -n 's/^took \([0-9]*\) s$/\1/p' <<<"$XOUT")" -ge 120 ] && echo 0 || echo 1)"
x "sleep 30; s=\$(date +%s); run_report R sentry-remote --target validator; echo \"took \$((\$(date +%s) - s)) s\""
check "sentry -> validator remote: verdict PASS, 21 handshakes, >= 120 s (6 s pace)" "$(grep -q 'rc=0 .* verdict=PASS handshakes=21$' <<<"$XOUT" && [ "$(sed -n 's/^took \([0-9]*\) s$/\1/p' <<<"$XOUT")" -ge 120 ] && echo 0 || echo 1)"
x "grep -lE '([0-9]{1,3}\.){3}[0-9]{1,3}' \$TMPD/*.json | grep -v 127.0.0.1; grep -ohE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \$TMPD/*.json | sort -u | grep -vc '^127\.0\.0\.1\$'"
check "no address other than 127.0.0.1 in any report (publishable as is)" "$([ "$(tail -1 <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
gate
for n in validator-local sentry-local validator-remote sentry-remote; do
  cp "$TMPD/$n.json" "$OUT/$n.json"
  python3 peertls/peertls_eval.py render "$OUT/$n.json" > "$OUT/$n.txt"
done
x "for n in validator-local sentry-local validator-remote sentry-remote; do echo \"-- \$n\"; sed -n '/^target /,/^RESULT/p' $OUT/\$n.txt; done"
check "all four reports: RESULT PASS, no WARN/FAIL line" "$([ "$(grep -c '^RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -cE '\[(WARN|FAIL)\]' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"

echo; echo "== 3. crosscheck both directions + flip control"
x "python3 peertls/peertls_eval.py crosscheck $OUT/validator-remote.json $OUT/sentry-local.json | tee $OUT/crosscheck-validator-to-sentry.txt"
check "validator's remote view of the sentry = the sentry's own view (posture + cert sha256)" "$([ "$XRC" = 0 ] && [ "$(grep -c '^PASS ' <<<"$XOUT")" = 6 ] && [ "$(grep -c '^FAIL ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "python3 peertls/peertls_eval.py crosscheck $OUT/sentry-remote.json $OUT/validator-local.json | tee $OUT/crosscheck-sentry-to-validator.txt"
check "sentry's remote view of the validator = the validator's own view (posture + cert sha256)" "$([ "$XRC" = 0 ] && [ "$(grep -c '^PASS ' <<<"$XOUT")" = 6 ] && [ "$(grep -c '^FAIL ' <<<"$XOUT")" = 0 ] && echo 0 || echo 1)"
x "python3 peertls/peertls_eval.py crosscheck $OUT/validator-remote.json $OUT/validator-local.json | tee $OUT/crosscheck-flip-control.txt"
check "flip control: the sentry's certificate seen remotely != the validator's own -> crosscheck exit != 0 with a 'cert sha256' FAIL" "$([ "$XRC" != 0 ] && grep -q '^FAIL .* cert sha256: ' <<<"$XOUT" && echo 0 || echo 1)"

echo; echo "== 4. offline rebuild: render each committed JSON and cmp with the live human report"
for n in validator-local sentry-local validator-remote sentry-remote; do
  x "python3 peertls/peertls_eval.py render $OUT/$n.json > \$TMPD/$n.re.txt && cmp \$TMPD/$n.re.txt $OUT/$n.txt && sha256sum $OUT/$n.json $OUT/$n.txt | cut -c1-64"
  check "$n: rebuild from JSON is byte-identical (cmp exit 0)" "$XRC"
done

echo; echo "== 5. end gates"
x "link_up"
PEERS1="$(sed -n 's/^peers \([0-9]*\),.*/\1/p' <<<"$XOUT")"
check "cluster link still up; validator peers $PEERS1 (before $PEERS0, >= before - 2)" "$(grep -q 'sentry link 1$' <<<"$XOUT" && [ "${PEERS1:-0}" -ge $((${PEERS0:-0} - 2)) ] && echo 0 || echo 1)"
x "srv_state"
check "both nodes full or proposing at the end" "$([ "$(grep -cE '^(full|proposing)$' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-apparmor audit | grep -E 'denials|RESULT'; sudo -n pft-seccomp audit | grep -E 'RESULT'; R 'sudo -n pft-apparmor audit | grep -E \"denials|RESULT\"; sudo -n pft-seccomp audit | grep -E RESULT'"
check "AppArmor + seccomp audits PASS on both hosts with 0 denials" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 4 ] && [ "$(grep -c ' 0 DENIED events' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts at the end" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "curl -s --max-time 10 $PROM/api/v1/alerts | jq -r '.status, ([.data.alerts[] | select(.labels.alertname != \"PFTAlertPipelineWatchdog\")] | length)'"
check "Prometheus answers; nothing but the watchdog pending/firing at the end" "$([ "$(tr '\n' ' ' <<<"$XOUT")" = "success 0 " ] && echo 0 || echo 1)"
x "ls $OUT; sha256sum $OUT/* | cut -c1-64"
echo; echo "crosshost-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
