#!/usr/bin/env bash
# Route/receiver assertion controls for drill/quiet-check.sh (task_62b5fc29b42bbe4e484a03a450c97616), read-only.
# Runs the quiet-check "loaded Alertmanager config" assertion lines VERBATIM, extracted from git:
#   OLD = quiet-check.sh lines 62-63 at 1f6ccc1 (used by run 03), on the live config -> must FAIL (run 03's reason);
#   NEW = quiet-check.sh lines 64-68 at PIN (used by run 04), on
#     live config                                                   -> must PASS
#     control A: the notify="digest" route sends to receiver bridge -> must FAIL (route not to digest)
#     control B: receiver digest gains a webhook_configs integration -> must FAIL (digest would page)
# The controls only edit an in-memory copy of the config text; Alertmanager itself is only read (GET /api/v2/status).
#   PIN=<sha> bash upstreamwatch/drill/quiet-controls.sh 2>&1 | tee LOG
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
OLD=1f6ccc19a5bb88219ae47e4d9623efc7a98f26ae
PIN="${PIN:-$(git rev-parse HEAD)}"
AM=http://127.0.0.1:9093
ME="$(id -un)"; HN="$(hostname)"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; /\b127\.0\.0\.1\b/!s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#/opt/pft-agent/[^[:space:]]*#<operator-agent-path>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
LAST=""
check() { LAST="$2"; if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; fi; }
FAILS=0
expect() { # $1 = case name, $2 = expected assertion result (0 pass / 1 fail)
  if [ "$LAST" = "$2" ]; then echo "EXPECT ok   $1: assertion result $LAST as expected"
  else echo "EXPECT FAIL $1: assertion result $LAST, expected $2"; FAILS=$((FAILS + 1)); fi; }

echo "quiet-controls start $(date -u +%FT%TZ) repo HEAD $(git rev-parse HEAD) PIN $PIN OLD $OLD"
OLDL="$(git show "$OLD:upstreamwatch/drill/quiet-check.sh" | sed -n '62,63p')"
NEWL="$(git show "$PIN:upstreamwatch/drill/quiet-check.sh" | sed -n '65,68p')"
echo "OLD lines 62-63 sha256 $(printf '%s\n' "$OLDL" | sha256sum | cut -c1-64)"; printf '%s\n' "$OLDL" | sed 's/^/  | /'
echo "NEW lines 65-68 sha256 $(printf '%s\n' "$NEWL" | sha256sum | cut -c1-64)"; printf '%s\n' "$NEWL" | sed 's/^/  | /'
LIVE="$(curl -s --max-time 10 "$AM/api/v2/status" | jq -r '.config.original')"
if [ -z "$LIVE" ] || ! grep -q '^receivers:' <<<"$LIVE"; then echo "Alertmanager config not readable"; exit 3; fi
echo "live config: $(grep -c . <<<"$LIVE") lines; sha256 $(printf '%s\n' "$LIVE" | sha256sum | cut -c1-64)"

echo; echo "== 1. OLD assertion (run 03) on the live config"
eval "$OLDL"
expect "old/live" 1

echo; echo "== 2. NEW assertion (run 04) on the live config"
export AMCONF="$LIVE"
eval "$NEWL"
expect "new/live" 0

echo; echo "== 3. control A: notify=\"digest\" route -> receiver bridge"
export AMCONF; AMCONF="$(awk '/^  - receiver: digest$/ {print "  - receiver: bridge"; n++; next} {print} END {exit n != 1}' <<<"$LIVE")" \
  || { echo "control A edit not applied exactly once"; exit 3; }
diff <(printf '%s\n' "$LIVE") <(printf '%s\n' "$AMCONF") | sed 's/^/  diff: /'
eval "$NEWL"
expect "new/controlA" 1

echo; echo "== 4. control B: receiver digest gains a webhook_configs integration"
export AMCONF; AMCONF="$(awk '{print} /^- name: digest$/ {print "  webhook_configs:"; print "  - url: <secret>"; n++} END {exit n != 1}' <<<"$LIVE")" \
  || { echo "control B edit not applied exactly once"; exit 3; }
diff <(printf '%s\n' "$LIVE") <(printf '%s\n' "$AMCONF") | sed 's/^/  diff: /'
eval "$NEWL"
expect "new/controlB" 1

echo; echo "quiet-controls done $(date -u +%FT%TZ): $FAILS expectation(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
