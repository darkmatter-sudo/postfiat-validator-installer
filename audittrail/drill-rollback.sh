#!/usr/bin/env bash
# Rollback-and-re-apply drill for pft-audittrail on one host (no postfiatd restart): rollback --dry-run (no
# change), rollback --yes, prove clean removal (0 pft-* rules loaded, rules files, drop-in, FSS key, state gone,
# auditing still on), re-apply (new FSS keys -> KEY_OUT, root-only, moved off-host afterwards), check PASS.
# Usage: sudo bash drill-rollback.sh --label sentry-host --key-out FILE [--container NAME]
# /etc/os-release is the host's. "A && B || C" lines are intended (echo never fails).
# shellcheck disable=SC1091,SC2015
set -uo pipefail
LABEL=""; KEY_OUT=""; CONTAINER="${CONTAINER:-}"; TOOL=/usr/local/sbin/pft-audittrail
while [ $# -gt 0 ]; do
  case "$1" in --label) LABEL="$2"; shift ;; --key-out) KEY_OUT="$2"; shift ;; --container) CONTAINER="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 3 ;; esac; shift
done
if [ -z "$LABEL" ] || [ -z "$KEY_OUT" ]; then echo "usage: $0 --label NAME --key-out FILE [--container NAME]" >&2; exit 3; fi
[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 3; }
[ -n "$CONTAINER" ] || for c in postfiatd postfiatd-sentry; do docker inspect "$c" >/dev/null 2>&1 && { CONTAINER="$c"; break; }; done
pass=0; fail=0
res() { if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "  -> PASS: $2"; else fail=$((fail + 1)); echo "  -> FAIL: $2"; fi; }
started() { docker inspect "$CONTAINER" --format '{{.State.StartedAt}} restarts={{.RestartCount}}'; }
FSS="/var/log/journal/$(cat /etc/machine-id)/fss"
files() { for f in /etc/audit/rules.d/pft-audittrail.rules /etc/audit/rules.d/zz-pft-audittrail-immutable.rules \
                   /etc/systemd/journald.conf.d/pft-audittrail.conf "$FSS" /var/lib/pft-audittrail; do
            printf '  %-58s %s\n' "$(sed -E 's#/[0-9a-f]{32}/#/<machine-id>/#' <<<"$f")" "$([ -e "$f" ] && echo present || echo absent)"; done; }
echo "# OS: $(. /etc/os-release; echo "$PRETTY_NAME") | $(date -u +%FT%TZ) | $LABEL: pft-audittrail rollback-and-re-apply drill | container $CONTAINER"
echo "script sha256: pft-audittrail $(sha256sum "$TOOL" | cut -c1-64) | drill-rollback.sh $(sha256sum "$0" | cut -c1-64)"
S0="$(started)"; echo "container before: $S0"
echo; echo "== 0. applied state"; "$TOOL" check </dev/null | tail -1; files
echo; echo "== 1. rollback --dry-run (expect no change)"
B="$(auditctl -l </dev/null | md5sum)"; "$TOOL" rollback --yes --dry-run </dev/null | sed -E 's#/[0-9a-f]{32}/#/<machine-id>/#'
[ "$B" = "$(auditctl -l </dev/null | md5sum)" ] && [ -e /etc/audit/rules.d/pft-audittrail.rules ]; res $? "dry-run changed nothing"
echo; echo "== 2. rollback --yes"
echo "\$ pft-audittrail rollback --yes"; "$TOOL" rollback --yes </dev/null; rc=$?; echo "exit $rc"; [ "$rc" = 0 ]; res $? "rollback exit 0"
n="$(auditctl -l </dev/null | grep -c 'pft-')"; echo "pft-* rules loaded: $n"; [ "$n" = 0 ]; res $? "no pft-* audit rules loaded"
files; ! files | grep -q present; res $? "rules files, journald drop-in, FSS key, state removed"
en="$(auditctl -s </dev/null | awk '$1=="enabled"{print $2}')"; echo "audit enabled=$en, auditd $(systemctl is-active auditd)"
[ "$en" = 1 ]; res $? "kernel auditing still enabled after the journald restart"
A="/var/log/journal/$(cat /etc/machine-id)/system.journal"
echo "\$ journalctl --header --file=<machine-id>/system.journal | grep -E '^(State|Compatible flags)'"
journalctl --header --file="$A" </dev/null 2>&1 | grep -E '^(State|Compatible flags)'
echo "\$ journalctl -u systemd-journald -n 3 -o cat (journald's own last messages)"; journalctl -u systemd-journald -n 3 -o cat </dev/null | sed -E 's#/[0-9a-f]{32}\)#/<machine-id>)#'
# journald always starts on /run and logs "Runtime Journal" until its flush; it is on /var when the LAST of those
# lines is "System Journal" (the old bug left "Runtime Journal" last: the sealed file could not be reopened)
on_var() { grep -E '^(Runtime|System) Journal' | tail -1 | grep -q '^System Journal'; }
[ -e "$A" ] && ! journalctl --header --file="$A" </dev/null 2>/dev/null | grep -qE '^Compatible flags:.*SEALED' \
  && journalctl -u systemd-journald -n 3 -o cat </dev/null | on_var
res $? "journald back on /var/log/journal with a fresh UNSEALED system.journal (no fallback to the volatile /run journal)"
echo "\$ pft-audittrail check (expect FAIL: not applied)"; "$TOOL" check </dev/null | grep -E 'not applied|RESULT'; c=${PIPESTATUS[0]}; [ "$c" = 1 ]; res $? "check exit 1 after rollback"
echo; echo "== 3. re-apply (new FSS keys)"
echo "\$ pft-audittrail apply --yes --container $CONTAINER --key-out <root-only file, moved off-host after this run>"
"$TOOL" apply --yes --container "$CONTAINER" --key-out "$KEY_OUT" </dev/null; rc=$?; echo "exit $rc"; [ "$rc" = 0 ]; res $? "re-apply exit 0"
echo "\$ pft-audittrail check"; "$TOOL" check </dev/null; c=$?; [ "$c" = 0 ]; res $? "check PASS after re-apply"
S1="$(started)"; echo "container after: $S1"; [ "$S0" = "$S1" ]; res $? "no node restart (StartedAt + RestartCount unchanged)"
echo; echo "drill-rollback: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
