#!/usr/bin/env bash
# Offline tests for pft-peerexpose.sh: curl, sudo and docker are PATH stubs that answer from tests/fixtures/<case>/.
# No network, no docker, no root. Usage: bash tests/run-tests.sh [path/to/pft-peerexpose.sh]
# Conditions are single-quoted on purpose: check() evals them after run() has set RC and $OUT.
# shellcheck disable=SC2016,SC2034
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${1:-$HERE/../pft-peerexpose.sh}"
FIX="$HERE/fixtures"
STUBS="$(mktemp -d)"
trap 'rm -rf "$STUBS"' EXIT

cat > "$STUBS/curl" <<'EOF'
#!/usr/bin/env bash
# stub: -o FILE, -w FMT (only %{http_code}), last arg = URL (or admin RPC POST through docker exec)
#       Alertmanager POST /api/v2/silences -> a silence id. After a restart with the managed block in the running
#       config, answers come from $CASE_DIR/after/ (if present): the block "takes effect" only on restart.
out=""; url=""; data=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift ;; -d) data="$2"; shift ;; -w|-m|-X|-H|--max-time) shift ;; -*) ;; *) url="$1" ;; esac
  shift
done
echo "$url" >> "$STUB_LOG"
case "$url" in */api/v2/silences) echo "silence $data" >> "$STUB_LOG"; echo '{"silenceID":"sil-0123456789"}'; exit 0 ;; esac
d="$CASE_DIR"
if [ -d "$CASE_DIR/after" ] && grep -q "pft-peerexpose managed block" "$STUB_STATE/running.cfg" 2>/dev/null; then d="$CASE_DIR/after"; fi
path="/${url#*://*/}"
case "$path" in /crawl) ep=crawl ;; /vl/*) ep=vl ;; /health) ep=health ;; *) ep=none ;; esac
code="$(cat "$d/$ep.code" 2>/dev/null || echo 404)"
if [ "$code" = 000 ]; then printf '000'; exit 7; fi
if [ -n "$out" ]; then cat "$d/$ep.body" > "$out"; else cat "$d/$ep.body"; fi
printf '%s' "$code"
EOF
cat > "$STUBS/sudo" <<'EOF'
#!/usr/bin/env bash
[ "$1" = -n ] && shift
exec "$@"
EOF
cat > "$STUBS/docker" <<'EOF'
#!/usr/bin/env bash
# stub: docker exec [-i] CONTAINER cat CFG  -> $CFG_FILE (default: postfiatd.cfg of the case; missing = exit 1)
#       docker exec CONTAINER stat ...      -> 640
#       docker exec -i CONTAINER sh -c ...  -> stdin replaces $CFG_FILE (FAIL_WRITE=1: exit 1)
#       docker exec CONTAINER curl -d '{"method":"M"}' -> $SI_JSON / $PEERS_JSON / validators.json of the case
#       docker restart CONTAINER            -> copies $CFG_FILE to $STUB_STATE/running.cfg
echo "docker $*" >> "$STUB_LOG"
cfg="${CFG_FILE:-$CASE_DIR/postfiatd.cfg}"
if [ "$1" = restart ]; then cp "$cfg" "$STUB_STATE/running.cfg"; exit 0; fi
[ "$1" = exec ] || exit 0
shift; [ "$1" = -i ] && shift
shift
case "$1" in
  cat) cat "$cfg" 2>/dev/null ;;
  stat) echo 640 ;;
  sh) [ "${FAIL_WRITE:-0}" = 1 ] && exit 1; cat > "$cfg" ;;
  curl)
    m="$(printf '%s ' "$@" | grep -o '"method":"[a-z_]*"' | cut -d'"' -f4)"
    case "$m" in
      server_info) cat "${SI_JSON:-$CASE_DIR/server_info.json}" ;;
      peers) cat "${PEERS_JSON:-$CASE_DIR/peers.json}" ;;
      *) cat "$CASE_DIR/validators.json" ;;
    esac ;;
esac
EOF
cat > "$STUBS/pft-maint" <<'EOF'
#!/usr/bin/env bash
# stub: records the call; `lock list` prints $LOCKS_FILE or "no data-collection locks"
echo "pft-maint $*" >> "$STUB_LOG"
if [ "$1 $2" = "lock list" ]; then
  if [ -n "${LOCKS_FILE:-}" ]; then cat "$LOCKS_FILE"; else echo "no data-collection locks"; fi
fi
exit 0
EOF
cat > "$STUBS/ssh" <<'EOF'
#!/usr/bin/env bash
# stub: record the full ssh command line, then run the remote command string locally
echo "ssh $*" >> "$STUB_LOG"
eval "${*: -1}"
EOF
chmod +x "$STUBS"/*

PASS=0; FAIL=0
OUT="$STUBS/out"; export STUB_LOG="$STUBS/calls" STUB_STATE="$STUBS/state" POLL_SEC=0
mkdir -p "$STUB_STATE"

# run CASE ARGS... -> sets RC, output in $OUT
run() {
  local c="$1"; shift
  : > "$STUB_LOG"
  CASE_DIR="$FIX/$c" PATH="$STUBS:$PATH" bash "$SCRIPT" "$@" > "$OUT" 2>&1
  RC=$?
}
ok() { PASS=$((PASS + 1)); echo "PASS $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; sed 's/^/    | /' "$OUT"; }
# check NAME CONDITION (evaluated in a subshell, so an exit inside cannot abort the suite)
check() {
  local name="$1" cond="$2"
  if (eval "$cond") >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
# field FIELD -> "status count policy" from the last --json run
field() { jq -r --arg f "$1" '.fields[] | select(.field == $f) | "\(.status) \(.count) \(.policy)"' "$OUT"; }

# --- validator, fully open, 12 peers (two-digit count)
run open12 audit --role validator --json
check "open12 validator exit 1" '[ "$RC" -eq 1 ]'
check "open12 peer_ip disclosed n=12 VIOLATION" '[ "$(field crawl.overlay.peer_ip)" = "disclosed 12 VIOLATION" ]'
check "open12 peer_pubkey n=12" '[ "$(field crawl.overlay.peer_pubkey)" = "disclosed 12 VIOLATION" ]'
check "open12 pubkey_node VIOLATION" '[ "$(field crawl.server.pubkey_node)" = "disclosed 1 VIOLATION" ]'
check "open12 vl served VIOLATION" '[ "$(field vl.list)" = "disclosed 1 VIOLATION" ]'
check "open12 counts restricted ok" '[ "$(field crawl.counts)" = "restricted 0 ok" ]'
check "open12 health allowed" '[ "$(field health.details)" = "restricted 0 ok" ]'
check "open12 violations=11" '[ "$(jq .violations "$OUT")" = 11 ]'
check "open12 vl key taken from local admin RPC" 'grep -q "/vl/EDFAKEPUB$" "$STUB_LOG"'
check "open12 no address or key in output" '! grep -E "192\.0\.2|FAKEPEERKEY|FAKENODEKEY" "$OUT"'

# --- one peer (lower boundary of "disclosed")
run open1 audit --role validator --json
check "open1 peer_ip disclosed n=1" '[ "$(field crawl.overlay.peer_ip)" = "disclosed 1 VIOLATION" ]'

# --- same open node judged as a sentry: only overlay/counts are violations
run open12 audit --role sentry --json
check "open12 sentry exit 1" '[ "$RC" -eq 1 ]'
check "open12 sentry violations=4 (overlay only)" '[ "$(jq .violations "$OUT")" = 4 ]'
check "open12 sentry pubkey_node allowed" '[ "$(field crawl.server.pubkey_node)" = "disclosed 1 ok" ]'
check "open12 sentry vl allowed" '[ "$(field vl.list)" = "disclosed 1 ok" ]'

# --- hardened sentry: server + unl + vl public, no overlay
run sentry_hardened audit --role sentry --json
check "sentry_hardened exit 0" '[ "$RC" -eq 0 ]'
check "sentry_hardened peer_ip restricted" '[ "$(field crawl.overlay.peer_ip)" = "restricted 0 ok" ]'
run sentry_hardened audit --role validator --json
check "sentry_hardened as validator exit 1" '[ "$RC" -eq 1 ]'
run sentry_counts audit --role sentry --json
check "sentry counts disclosed = VIOLATION" '[ "$(field crawl.counts)" = "disclosed 1 VIOLATION" ] && [ "$RC" -eq 1 ]'

# --- hardened validator: /crawl 403, /vl 404
run restricted audit --role validator --json
check "restricted validator exit 0" '[ "$RC" -eq 0 ]'
check "restricted crawl.endpoint restricted (http 403)" '[ "$(field crawl.endpoint)" = "restricted 0 ok" ] && grep -q "http 403" "$OUT"'
check "restricted vl restricted" '[ "$(field vl.list)" = "restricted 0 ok" ]'
run restricted audit --role validator
check "restricted text output RESULT line" 'grep -q "^RESULT: 0 violation(s), 0 error(s)$" "$OUT"'

# --- errors
run unreachable audit --role validator --json
check "unreachable exit 2" '[ "$RC" -eq 2 ] && grep -q "unreachable" "$OUT"'
run crawl_nonjson audit --role validator
check "crawl 200 non-JSON exit 2" '[ "$RC" -eq 2 ] && grep -q "non-JSON" "$OUT"'

# --- /vl answering 200 without a blob is not a served list
run vl_no_blob audit --role validator --json
check "vl 200 without blob = restricted" '[ "$(field vl.list)" = "restricted 0 ok" ] && [ "$RC" -eq 0 ]'

# --- /health with details (unhealthy node) is reported but allowed for both roles
run health_details audit --role validator --json
check "health details disclosed, allowed" '[ "$(field health.details)" = "disclosed 2 ok" ] && [ "$RC" -eq 0 ]'

# --- key sources
run no_rpc_keys audit --role validator --json
check "no RPC keys -> dummy key probed" 'grep -q "/vl/ED0000" "$STUB_LOG"'
run open12 audit --role validator --vl-key EDGIVEN --url https://203.0.113.9:2559 --json
check "--vl-key and --url used, RPC not called" 'grep -q "^https://203.0.113.9:2559/vl/EDGIVEN$" "$STUB_LOG" && ! grep -q "^docker" "$STUB_LOG"'

# --- usage
run open12 audit
check "missing --role exit 3" '[ "$RC" -eq 3 ]'
run open12 audit --role relay
check "bad role exit 3" '[ "$RC" -eq 3 ]'

# --- render / effective / plan
R="$STUBS/rendered.cfg"
want_v="crawl=0 overlay=1 server=1 counts=0 unl=1 vl=0"
want_s="crawl=1 overlay=0 server=1 counts=0 unl=1 vl=1"
run cfg_stock plan --role validator
check "plan stock validator: CHANGE NEEDED, exit 0" '[ "$RC" -eq 0 ] && grep -q "^RESULT: CHANGE NEEDED" "$OUT"'
check "plan stock validator: effective now = defaults" 'grep -q "effective now:   crawl=1 overlay=1 server=1 counts=0 unl=1 vl=1$" "$OUT"'
check "plan stock validator: effective after = policy" 'grep -q "effective after: $want_v$" "$OUT"'
check "plan stock validator: validate OK" 'grep -q "validate: OK" "$OUT"'
check "plan output has no address" '! grep -q "192\.0\.2" "$OUT"'
run cfg_stock plan --role sentry
check "plan stock sentry: effective after = policy" 'grep -q "effective after: $want_s$" "$OUT" && [ "$RC" -eq 0 ]'
check "plan reads the cfg through docker exec" 'grep -q "^docker exec postfiatd cat /etc/postfiatd/postfiatd.cfg$" "$STUB_LOG"'

PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator < "$FIX/cfg_stock/postfiatd.cfg" > "$R"
check "render keeps every non-blank line outside the block" '[ "$(diff <(grep -v "^$" "$FIX/cfg_stock/postfiatd.cfg") <(grep -v "^$" "$R") | grep -c "^<")" = 0 ]'
check "render keeps the commented # [crawl] docs" '[ "$(grep -c "^#.*\[crawl\]" "$R")" = 2 ]'
check "render validator: one [crawl] with bare 0, [vl] enabled=0" '[ "$(grep -c "^\[crawl\]$" "$R")" = 1 ] && grep -A1 "^\[crawl\]$" "$R" | grep -qx 0 && grep -A1 "^\[vl\]$" "$R" | grep -qx "enabled=0"'
check "render is idempotent" 'PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator < "$R" | cmp -s - "$R"'
check "render sentry then validator = validator" 'PATH="$STUBS:$PATH" bash "$SCRIPT" render --role sentry < "$R" | PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator | cmp -s - "$R"'

# a cfg that is already rendered: plan says NO CHANGE (case dir built on the fly)
mkdir -p "$STUBS/cfg_done"; cp "$R" "$STUBS/cfg_done/postfiatd.cfg"
: > "$STUB_LOG"; CASE_DIR="$STUBS/cfg_done" PATH="$STUBS:$PATH" bash "$SCRIPT" plan --role validator > "$OUT" 2>&1; RC=$?
check "plan on rendered cfg: NO CHANGE" '[ "$RC" -eq 0 ] && grep -q "^RESULT: NO CHANGE" "$OUT"'
: > "$STUB_LOG"; CASE_DIR="$STUBS/cfg_done" PATH="$STUBS:$PATH" bash "$SCRIPT" plan --role sentry > "$OUT" 2>&1; RC=$?
check "plan validator-rendered cfg as sentry: CHANGE NEEDED" '[ "$RC" -eq 0 ] && grep -q "^RESULT: CHANGE NEEDED" "$OUT"'

# operator-made [Crawl]/[VL] sections (mixed case, mid-file) are replaced, not duplicated
run cfg_existing plan --role validator
check "existing sections: effective now parsed (counts = 1 with spaces)" 'grep -q "effective now:   crawl=1 overlay=1 server=1 counts=1 unl=1 vl=1$" "$OUT"'
check "existing sections: validate OK, after = policy" 'grep -q "validate: OK" "$OUT" && grep -q "effective after: $want_v$" "$OUT"'
check "existing sections: diff removes the old lines" 'grep -q "^    < counts = 1$" "$OUT"'
PATH="$STUBS:$PATH" bash "$SCRIPT" render --role sentry < "$FIX/cfg_existing/postfiatd.cfg" > "$R"
check "existing sections: exactly one [crawl] and one [vl] after render" '[ "$(grep -ciE "^\[crawl\]$" "$R")" = 1 ] && [ "$(grep -ciE "^\[vl\]$" "$R")" = 1 ]'
check "existing sections: [ips_fixed] kept" 'grep -A1 "^\[ips_fixed\]$" "$R" | grep -q "^192.0.2.20 2559$"'

run cfg_unreadable plan --role validator
check "plan with unreadable cfg exit 2" '[ "$RC" -eq 2 ] && grep -q "cannot read" "$OUT"'

# validate: positive (rendered stock) and one negative per rule, each asserting its own reason
V="$FIX/cfg_validate"
vrun() { PATH="$STUBS:$PATH" bash "$SCRIPT" validate "$@" > "$OUT" 2>&1; RC=$?; }
PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator < "$V/old.cfg" > "$R"
vrun --role validator --old "$V/old.cfg" --new "$R"
check "validate rendered cfg: exit 0, OK" '[ "$RC" -eq 0 ] && grep -q "^validate: OK" "$OUT"'
vrun --role validator --old "$V/old.cfg" --new "$V/extra-change.cfg"
check "validate rejects a change outside [crawl]/[vl]" '[ "$RC" -eq 1 ] && grep -q "lines outside \[crawl\]/\[vl\] would change" "$OUT"'
vrun --role validator --old "$V/old.cfg" --new "$V/two-crawl.cfg"
check "validate rejects two [crawl] sections" '[ "$RC" -eq 1 ] && grep -q "exactly one \[crawl\] section, found 2" "$OUT"'
vrun --role validator --old "$V/old.cfg" --new "$V/no-vl.cfg"
check "validate rejects a missing [vl] section" '[ "$RC" -eq 1 ] && grep -q "exactly one \[vl\] section, found 0" "$OUT"'
# postfiatd reads [vl] "enabled" (OverlayImpl.cpp setup_Overlay); "enable=0" is ignored and /vl stays on (live run -21)
vrun --role validator --old "$V/old.cfg" --new "$V/legacy-enable.cfg"
check "validate rejects [vl] enable=0 (ignored key, effective vl=1)" '[ "$RC" -eq 1 ] && grep -q "effective settings crawl=0 overlay=1 server=1 counts=0 unl=1 vl=1 != wanted" "$OUT"'
check "validate accepts [vl] enabled=0 (effective vl=0)" '[ "$(grep -c "^enabled=0$" "$R")" = 1 ] && PATH="$STUBS:$PATH" bash "$SCRIPT" validate --role validator --old "$V/old.cfg" --new "$R" | grep -q "^validate: OK"'
vrun --role sentry --old "$V/old.cfg" --new "$R"
check "validate rejects the validator block for a sentry" '[ "$RC" -eq 1 ] && grep -q "effective settings crawl=0 .* != wanted crawl=1 overlay=0" "$OUT"'
vrun --role validator --old "$V/old.cfg"
check "validate without --new exit 3" '[ "$RC" -eq 3 ]'

# remote target through ssh
run cfg_stock plan --role sentry --ssh relayhost --container postfiatd-sentry
check "plan --ssh uses ssh BatchMode + sudo -n docker exec" 'grep -q "^ssh -o BatchMode=yes -o ConnectTimeout=10 relayhost sudo -n docker exec postfiatd-sentry cat /etc/postfiatd/postfiatd.cfg" "$STUB_LOG" && [ "$RC" -eq 0 ]'

# ---------- apply / rollback (writes go to a per-test copy of the case cfg) ----------
LIVE="$STUBS/live.cfg"; ST="$STUBS/pestate"
# arun CASE ARGS... : fresh live cfg + state dir, then run with CFG_FILE/STATE_DIR set (extra env: VAR=x arun ...)
arun() {
  local c="$1"; shift
  cp "$FIX/$c/postfiatd.cfg" "$LIVE"; rm -rf "$ST" "$STUB_STATE/running.cfg"; : > "$STUB_LOG"
  CASE_DIR="$FIX/$c" CFG_FILE="$LIVE" STATE_DIR="$ST" PATH="$STUBS:$PATH" bash "$SCRIPT" "$@" > "$OUT" 2>&1
  RC=$?
}
# brun ARGS... : run against the CURRENT live cfg and state (no reset), answers from $STUBS/applied
brun() {
  cp "$LIVE" "$STUBS/applied/postfiatd.cfg"; : > "$STUB_LOG"
  CASE_DIR="$STUBS/applied" CFG_FILE="$LIVE" STATE_DIR="$ST" PATH="$STUBS:$PATH" bash "$SCRIPT" "$@" > "$OUT" 2>&1
  RC=$?
}
AV=apply_validator; ORIG="$FIX/$AV/postfiatd.cfg"
mkdir -p "$STUBS/applied"; cp -r "$FIX/$AV"/. "$STUBS/applied/"

arun $AV apply --role validator --gate-timeout 0
check "apply validator: exit 0, APPLIED" '[ "$RC" -eq 0 ] && grep -q "RESULT: APPLIED" "$OUT"'
check "apply validator: live cfg = rendered validator block" 'PATH="$STUBS:$PATH" bash "$SCRIPT" render --role validator < "$ORIG" | cmp -s - "$LIVE"'
check "apply validator: exactly one restart" '[ "$(grep -c "^docker restart postfiatd$" "$STUB_LOG")" = 1 ]'
check "apply validator: window opened before the write, closed after the restart" 'a=$(grep -n "^pft-maint start --ttl 600 " "$STUB_LOG" | cut -d: -f1); w=$(grep -n "^docker exec -i postfiatd sh -c" "$STUB_LOG" | head -1 | cut -d: -f1); r=$(grep -n "^docker restart" "$STUB_LOG" | cut -d: -f1); e=$(grep -n "^pft-maint end" "$STUB_LOG" | cut -d: -f1); [ -n "$a" ] && [ "$a" -lt "$w" ] && [ "$w" -lt "$r" ] && [ "$r" -lt "$e" ]'
check "apply validator: AM silence posted before the restart" 's=$(grep -n "^silence " "$STUB_LOG" | cut -d: -f1); r=$(grep -n "^docker restart" "$STUB_LOG" | cut -d: -f1); [ -n "$s" ] && [ "$s" -lt "$r" ] && grep -q "Alertmanager silence sil-0123" "$OUT"'
check "apply validator: silence matcher + comment" 'grep "^silence " "$STUB_LOG" | sed "s/^silence //" | jq -e ".matchers[0] == {name:\"alertname\",value:\".+\",isRegex:true,isEqual:true} and (.comment | test(\"pft-peerexpose .* validator local planned restart\"))"'
check "apply validator: fixed peer required by default and found (1/1), audit 0" 'grep -q "required_peers=1/1 audit_violations=0" "$OUT"'
check "apply validator: backup = original, 0600 in 0700 dirs, LATEST" 'b=$(cat "$ST/backups/local/LATEST"); cmp -s "$b" "$ORIG" && [ "$(stat -c %a "$b")" = 600 ] && [ "$(stat -c %a "$ST/backups/local")" = 700 ] && [ "$(stat -c %a "$ST")" = 700 ]'
check "apply validator: effective before -> after printed" 'grep -q "effective: crawl=1 overlay=1 server=1 counts=0 unl=1 vl=1 -> $want_v" "$OUT"'
check "apply validator: no peer address in output" '! grep -qE "192\.0\.2|198\.51\.100" "$OUT"'

# second apply on the applied cfg: NO CHANGE, no restart, no window
brun apply --role validator --gate-timeout 0
check "apply again: NO CHANGE, no restart, no window" '[ "$RC" -eq 0 ] && grep -q "RESULT: NO CHANGE" "$OUT" && ! grep -qE "^docker restart|^pft-maint start" "$STUB_LOG"'

# rollback after apply: restores the backup byte-identically, one restart, own window + silence
brun rollback --role validator --gate-timeout 0
check "rollback: exit 0, ROLLED BACK" '[ "$RC" -eq 0 ] && grep -q "RESULT: ROLLED BACK (backup restored" "$OUT"'
check "rollback: live cfg byte-identical to the original" 'cmp -s "$LIVE" "$ORIG"'
check "rollback: one restart inside a window, silence posted" '[ "$(grep -c "^docker restart" "$STUB_LOG")" = 1 ] && grep -q "^pft-maint start --ttl 600 " "$STUB_LOG" && grep -q "^pft-maint end" "$STUB_LOG" && grep -q "^silence " "$STUB_LOG"'
check "rollback: pre-rollback copy kept (0600)" 'p=$(ls "$ST"/backups/local/postfiatd.cfg.*.pre-rollback); [ "$(stat -c %a "$p")" = 600 ]'
brun rollback --role validator --gate-timeout 0
check "rollback twice: NO CHANGE, no restart" '[ "$RC" -eq 0 ] && grep -q "RESULT: NO CHANGE" "$OUT" && ! grep -q "^docker restart" "$STUB_LOG"'

# rollback refuses when lines outside [crawl]/[vl] changed since the backup
arun $AV apply --role validator --gate-timeout 0
printf '\n[extra_section]\n1\n' >> "$LIVE"; cp "$LIVE" "$STUBS/live.edited"
brun rollback --role validator --gate-timeout 0
check "rollback refuses outside-block drift (exit 4, nothing written)" '[ "$RC" -eq 4 ] && grep -q "lines outside \[crawl\]/\[vl\] changed" "$OUT" && cmp -s "$LIVE" "$STUBS/live.edited" && ! grep -q "^docker restart" "$STUB_LOG"'
arun $AV rollback --role validator
check "rollback without a backup: exit 2" '[ "$RC" -eq 2 ] && grep -q "no backup to roll back to" "$OUT"'

# automatic rollback: the block does not take effect (audit still finds violations after the restart)
arun apply_badgate apply --role validator --gate-timeout 0
check "badgate: exit 2, ROLLED BACK" '[ "$RC" -eq 2 ] && grep -q "RESULT: ROLLED BACK (apply failed its gate" "$OUT"'
check "badgate: audit violations seen in the gate" 'grep -q "audit_violations=11" "$OUT"'
check "badgate: live cfg restored byte-identical" 'cmp -s "$LIVE" "$FIX/apply_badgate/postfiatd.cfg"'
check "badgate: two restarts (apply + rollback), window closed once" '[ "$(grep -c "^docker restart" "$STUB_LOG")" = 2 ] && [ "$(grep -c "^pft-maint end" "$STUB_LOG")" = 1 ]'
# the validator's fixed peer (the sentry) is not connected: refused before anything is written
PEERS_JSON="$FIX/$AV/peers-nofixed.json" arun $AV apply --role validator --gate-timeout 0
check "fixed peer missing: refused before any write" '[ "$RC" -eq 4 ] && grep -q "required_peers=0/1" "$OUT" && cmp -s "$LIVE" "$ORIG" && ! grep -q "^pft-maint start" "$STUB_LOG"'
# write failure mid-apply -> rollback path; the restore write fails too -> exit 5
FAIL_WRITE=1 arun $AV apply --role validator --gate-timeout 0
check "write failure: ROLLBACK FAILED exit 5, window closed, no restart" '[ "$RC" -eq 5 ] && grep -q "writing /etc/postfiatd/postfiatd.cfg failed" "$OUT" && grep -q "^pft-maint end" "$STUB_LOG" && ! grep -q "^docker restart" "$STUB_LOG"'

# refusals: lock held, node not healthy, too few peers; dry run; AM=none
LOCKS_FILE="$FIX/$AV/locks-held" arun $AV apply --role validator --gate-timeout 0
check "lock held: exit 4, nothing written, no window" '[ "$RC" -eq 4 ] && grep -q "REFUSED: pft-maint data-collection lock held: resources-24h" "$OUT" && cmp -s "$LIVE" "$ORIG" && ! grep -qE "^pft-maint start|^docker restart" "$STUB_LOG"'
SI_JSON="$FIX/$AV/server_info-syncing.json" arun $AV apply --role validator --gate-timeout 0
check "node syncing: exit 4, nothing written" '[ "$RC" -eq 4 ] && grep -q "state=syncing" "$OUT" && grep -q "REFUSED: node is not healthy" "$OUT" && cmp -s "$LIVE" "$ORIG"'
arun $AV apply --role validator --min-peers 12 --gate-timeout 0
check "--min-peers 12 with 11 peers: refused" '[ "$RC" -eq 4 ] && grep -q "peers=11 " "$OUT"'
arun $AV apply --role validator --dry-run
check "dry run: diff shown, nothing written, no backup, no restart" '[ "$RC" -eq 0 ] && grep -q "RESULT: DRY RUN" "$OUT" && grep -q "^    > \[crawl\]$" "$OUT" && cmp -s "$LIVE" "$ORIG" && [ ! -e "$ST/backups" ] && ! grep -qE "^docker restart|^pft-maint start|^silence" "$STUB_LOG"'
AM=none arun $AV apply --role validator --gate-timeout 0
check "AM=none: applied without a silence" '[ "$RC" -eq 0 ] && grep -q "RESULT: APPLIED" "$OUT" && ! grep -q "^silence " "$STUB_LOG"'

# remote sentry: ssh target, --url for the audit gate, explicit --require-peer, backups per target label
arun apply_sentry apply --role sentry --ssh relayhost --container postfiatd-sentry --url https://203.0.113.9:2559 --require-peer 192.0.2.20 --gate-timeout 0
check "apply sentry remote: APPLIED, sentry block live" '[ "$RC" -eq 0 ] && grep -q "RESULT: APPLIED" "$OUT" && PATH="$STUBS:$PATH" bash "$SCRIPT" render --role sentry < "$FIX/apply_sentry/postfiatd.cfg" | cmp -s - "$LIVE"'
check "apply sentry remote: restart + write through ssh sudo -n" 'grep -q "^ssh -o BatchMode=yes -o ConnectTimeout=10 relayhost sudo -n docker restart postfiatd-sentry" "$STUB_LOG" && grep -q "relayhost sudo -n docker exec -i postfiatd-sentry sh -c" "$STUB_LOG"'
check "apply sentry remote: audit probed the given URL, required peer 1/1" 'grep -q "^https://203.0.113.9:2559/crawl$" "$STUB_LOG" && grep -q "required_peers=1/1" "$OUT"'
check "apply sentry remote: backup under the target label" '[ -s "$ST/backups/relayhost/LATEST" ]'
check "apply sentry remote: window + silence run locally (not via ssh)" 'grep -q "^pft-maint start" "$STUB_LOG" && ! grep -q "relayhost sudo -n pft-maint" "$STUB_LOG"'
# inbound peer behind docker-proxy: the sentry lists its validator as 172.17.0.1:PORT, so only the node key matches
SI=apply_sentry_inbound; VKEY="$(cat "$FIX/$SI/validator.key")"
arun $SI apply --role sentry --ssh relayhost --container postfiatd-sentry --url https://203.0.113.9:2559 --require-peer "$VKEY" --gate-timeout 0
check "inbound peer by node key: APPLIED, required peer 1/1, key not printed" '[ "$RC" -eq 0 ] && grep -q "RESULT: APPLIED" "$OUT" && grep -q "required_peers=1/1" "$OUT" && ! grep -qF "$VKEY" "$OUT"'
arun $SI apply --role sentry --ssh relayhost --container postfiatd-sentry --url https://203.0.113.9:2559 --require-peer 192.0.2.20 --gate-timeout 0
check "inbound peer by its real address: 0/1, refused before any write" '[ "$RC" -eq 4 ] && grep -q "required_peers=0/1" "$OUT" && cmp -s "$LIVE" "$FIX/$SI/postfiatd.cfg" && ! grep -q "^pft-maint start" "$STUB_LOG"'
arun $SI apply --role sentry --ssh relayhost --container postfiatd-sentry --url https://203.0.113.9:2559 --require-peer "${VKEY%?}x" --gate-timeout 0
check "unknown node key: 0/1, refused before any write" '[ "$RC" -eq 4 ] && grep -q "required_peers=0/1" "$OUT" && cmp -s "$LIVE" "$FIX/$SI/postfiatd.cfg"'
arun $SI apply --role sentry --ssh relayhost --container postfiatd-sentry --url https://203.0.113.9:2559 --require-peer "${VKEY:0:20}" --gate-timeout 0
check "key prefix is not a key (address match fails): 0/1, refused" '[ "$RC" -eq 4 ] && grep -q "required_peers=0/1" "$OUT"'
arun apply_sentry apply --role sentry --ssh relayhost --container postfiatd-sentry
check "remote apply without --url: exit 3" '[ "$RC" -eq 3 ] && grep -q "needs --url" "$OUT"'
arun $AV apply --role validator --gate-timeout 99999
check "--gate-timeout over the window limit: exit 3" '[ "$RC" -eq 3 ]'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
