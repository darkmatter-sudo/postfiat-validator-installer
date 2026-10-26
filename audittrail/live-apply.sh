#!/usr/bin/env bash
# Live apply proof for pft-audittrail on one host (no postfiatd restart): before check (expected FAIL),
# install to SBIN, apply, after check (expected PASS), container uptime unchanged. The FSS verification key goes
# to KEY_OUT (root-only); the operator/agent moves it OFF this host right after and deletes it here.
# Usage: sudo bash live-apply.sh --label sentry-host|validator-host --key-out FILE [--container NAME]
# /etc/os-release is the host's; "A && B || C" lines are intended (echo never fails).
# shellcheck disable=SC1091,SC2015
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL=""; KEY_OUT=""; CONTAINER="${CONTAINER:-}"; SBIN="${SBIN:-/usr/local/sbin}"
while [ $# -gt 0 ]; do
  case "$1" in --label) LABEL="$2"; shift ;; --key-out) KEY_OUT="$2"; shift ;; --container) CONTAINER="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 3 ;; esac; shift
done
if [ -z "$LABEL" ] || [ -z "$KEY_OUT" ]; then echo "usage: $0 --label NAME --key-out FILE [--container NAME]" >&2; exit 3; fi
[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 3; }
[ -n "$CONTAINER" ] || for c in postfiatd postfiatd-sentry; do docker inspect "$c" >/dev/null 2>&1 && { CONTAINER="$c"; break; }; done
started() { docker inspect "$CONTAINER" --format '{{.State.StartedAt}} restarts={{.RestartCount}}'; }
echo "# OS: $(. /etc/os-release; echo "$PRETTY_NAME") | $(date -u +%FT%TZ) | $LABEL: pft-audittrail live apply | container $CONTAINER"
echo "script sha256: pft-audittrail.sh $(sha256sum "$HERE/pft-audittrail.sh" | cut -c1-64) | live-apply.sh $(sha256sum "$0" | cut -c1-64)"
S0="$(started)"; echo "container before: $S0"
echo; echo "== 1. BEFORE: check (expect FAIL: nothing applied)"
echo "\$ pft-audittrail check"; bash "$HERE/pft-audittrail.sh" check </dev/null; echo "exit $? (expect 1)"
echo "\$ journalctl --disk-usage; seal key present?"; journalctl --disk-usage </dev/null
ls "/var/log/journal/$(cat /etc/machine-id)/fss" >/dev/null 2>&1 && echo "FSS key: present" || echo "FSS key: absent"
echo; echo "== 2. install + apply"
install -m 0755 "$HERE/pft-audittrail.sh" "$SBIN/pft-audittrail" && echo "installed $SBIN/pft-audittrail"
echo "\$ pft-audittrail apply --yes --container $CONTAINER --key-out <root-only file, moved off-host after this run>"
"$SBIN/pft-audittrail" apply --yes --container "$CONTAINER" --key-out "$KEY_OUT" </dev/null; rc=$?; echo "apply exit $rc"
echo; echo "== 3. AFTER: check (expect PASS)"
echo "\$ pft-audittrail check"; "$SBIN/pft-audittrail" check </dev/null; crc=$?; echo "exit $crc (expect 0)"
echo "\$ auditctl -s | grep -E '^(enabled|lost|backlog_limit)'"; auditctl -s </dev/null | grep -E '^(enabled|lost|backlog_limit) '
echo "\$ auditctl -l | grep -c 'pft-'"; auditctl -l </dev/null | grep -c 'pft-'
S1="$(started)"; echo "container after: $S1 ($([ "$S0" = "$S1" ] && echo "unchanged: no node restart" || echo CHANGED))"
echo "live-apply done: apply exit $rc, check exit $crc"
