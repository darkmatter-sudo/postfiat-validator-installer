#!/usr/bin/env bash
# shellcheck disable=SC1091
# Recorded deploy of a vulnscan fix (1.1.0 stale-304 refetch, 1.2.0 stale 200 + cache-busting query; pft-fleet sync of the vulnscan add-on on both hosts, built from
# privesc/drill/fleet-run.sh). pft-maint [MAINT] start/end messages go to a throwaway topic.
#   bash vulnscan/drill/fleet-run.sh 2>&1 | tee LOG    (from the repo root, as the agent user)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"
ME="$(id -un)"
VER="$(sed -n 's/^VERSION=//p' vulnscan/pft-vulnscan.sh)"
TT="pft-drill-vulnscan-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-vulnscan
SWAPPED=0; MAINT=0
restore() {
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
trap restore EXIT
echo "vulnscan fleet sync - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
[ "$(git rev-parse origin/main)" = "$SHA" ] || { echo "HEAD is not pushed - stopping"; exit 3; }

echo; echo "== 1. point pft-maint at a throwaway topic (real file kept with mode/owner/mtime as \$BK)"
HAD=0; ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1
check "throwaway target installed" "$XRC"

echo; echo "== 2. window + sync of the vulnscan add-on ($VER)"
x "sudo -n pft-maint start --ttl 25m --reason \"vulnscan $VER fix deploy\""
[ "$XRC" = 0 ] && MAINT=1
check "pft-maint window open" "$XRC"
# the sentry gets the window through the watchdog channel (next tick, up to a few minutes); pft-fleet refuses a
# host without one (first run of this script: REFUSED sentry 22 s after start, nothing written)
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (via the watchdog channel) after ${w}s" "$?"
x "sudo -n pft-fleet sync --addon vulnscan --to $SHA --apply --reason \"vulnscan $VER: refetch fixes\""
check "fleet sync exit 0" "$XRC"
x "sudo -n pft-fleet skew"
check "pft-fleet skew exit 0, vulnscan CURRENT on both hosts" "$([ "$XRC" = 0 ] && [ "$(grep -cE '^ *(validator|sentry) +vulnscan +CURRENT' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"

echo; echo "== 3. end window, restore the real target, compare"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state ($NE: $([ "$HAD" = 1 ] && echo 'sha256 equal, not printed' || echo 'absent again'))" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n test ! -e \$BK && echo backup gone"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=10m\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | tail -1; R 'sudo -n pft-integrity verify | tail -1'"
check "pft-integrity PASS on both hosts" "$([ "$(grep -c 'RESULT: PASS' <<<"$XOUT")" = 2 ] && echo 0 || echo 1)"
echo; echo "fleet-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
