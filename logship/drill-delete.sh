#!/usr/bin/env bash
# shellcheck disable=SC2029,SC2016  # remote commands are built here on purpose; single-quoted $ expands on the remote side
# Delete-evidence drill for pft-logship: shows that removing a host's local journal file does not remove the
# evidence, because the peer already holds a copy. Run on the validator (the agent box); SENDER picks the host whose
# journal is "wiped": sentry (via `ssh relay`) or validator (local sudo).
#   1. sender: logger -t pft-logship-delete-drill "<id>"; wait until the RECEIVER's copy has it (<= 60 s)
#   2. sender: journalctl --rotate, find the archived system journal file that holds the marker
#   3. sender: move that file aside (simulated rm; the original is kept in a root-only dir), local query -> 0 entries
#   4. receiver: journalctl --directory=/var/log/journal/remote -t pft-logship-delete-drill -> the marker, intact
#   5. sender: move the file back, sha256 must equal the pre-move sha256, local query -> 1 entry again
# Only archived (already closed) files are moved, never the active one; nothing is deleted and journald is not
# restarted (FSS sealing is untouched: the file is restored byte-identical). Host names/addresses are not printed.
# Usage: bash logship/drill-delete.sh [sentry|validator]     Exit: 0 PASS, 1 FAIL, 3 setup error
set -uo pipefail
SENDER="${1:-sentry}"
TAG=pft-logship-delete-drill
ID="delete-$(date -u +%Y%m%dT%H%M%S)-$$"
local_sh() { sudo bash -c "$1"; }
relay_sh() { ssh relay "sudo bash -c $(printf '%q' "$1")"; }
case "$SENDER" in
  sentry) snd=relay_sh; rcv=local_sh; SN=sentry-host; RN=validator-host ;;
  validator) snd=local_sh; rcv=relay_sh; SN=validator-host; RN=sentry-host ;;
  *) echo "usage: $0 [sentry|validator]" >&2; exit 3 ;;
esac
rc=0
step() { printf '%s %s\n' "$(date -u +%T)" "$*"; }
check() { # LABEL GOT WANT
  if [ "$2" = "$3" ]; then step "  PASS $1: $2"; else step "  FAIL $1: got '$2', want '$3'"; rc=1; fi
}
count_local() { $snd "journalctl -t $TAG -o cat --no-pager | grep -cx 'drill $ID'"; }
count_peer() { $rcv "journalctl --directory=/var/log/journal/remote -t $TAG -o cat --no-pager | grep -cx 'drill $ID'"; }
echo "pft-logship delete-evidence drill - $(date -u +%FT%TZ) - sender $SN, receiver $RN - id $ID"
echo "sender OS: $($snd '. /etc/os-release; echo "$PRETTY_NAME"') | receiver OS: $($rcv '. /etc/os-release; echo "$PRETTY_NAME"')"
step "1. sender: logger -t $TAG 'drill $ID'"
$snd "logger -t $TAG 'drill $ID'"
n=0; for _ in $(seq 1 30); do n="$(count_peer)"; [ "$n" = 1 ] && break; sleep 2; done
check "receiver has the marker before the delete" "$n" 1
step "2. sender: journalctl --rotate; find the archived file with the marker"
$snd "journalctl --rotate" || rc=1
f="$($snd "for f in \$(ls -t /var/log/journal/*/system@*.journal | head -n 5); do
  journalctl --file \"\$f\" -t $TAG -o cat --no-pager 2>/dev/null | grep -qx 'drill $ID' && { echo \"\$f\"; break; }; done")"
[ -n "$f" ] || { step "  FAIL no archived file holds the marker"; echo "RESULT: FAIL -> exit 1"; exit 1; }
step "  marker is in archived file system@<...>.journal ($($snd "stat -c %s '$f'") bytes)"
sha0="$($snd "sha256sum '$f' | cut -d' ' -f1")"
check "local query finds the marker before the delete" "$(count_local)" 1
step "3. sender: move the file aside (simulated delete; kept in a root-only dir)"
$snd "install -d -m 700 /root/pft-logship-drill && mv '$f' /root/pft-logship-drill/" || rc=1
check "local query after the delete" "$(count_local)" 0
step "4. receiver: journalctl --directory=/var/log/journal/remote -t $TAG"
check "peer copy after the local delete" "$(count_peer)" 1
$rcv "journalctl --directory=/var/log/journal/remote -t $TAG -o json --no-pager | jq -c 'select(.MESSAGE == \"drill $ID\") | {time: ((.__REALTIME_TIMESTAMP | tonumber / 1e6 | floor | todate)), SYSLOG_IDENTIFIER, MESSAGE}'"
step "5. sender: restore the file"
$snd "mv '/root/pft-logship-drill/$(basename "$f")' '$f' && rmdir /root/pft-logship-drill" || rc=1
check "sha256 after restore equals before" "$($snd "sha256sum '$f' | cut -d' ' -f1")" "$sha0"
check "local query after the restore" "$(count_local)" 1
echo "RESULT: $([ "$rc" -eq 0 ] && echo PASS || echo FAIL) -> exit $rc"
exit "$rc"
