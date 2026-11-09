#!/usr/bin/env bash
# Recorded live kmod drill on ONE host (run on that host, from a checkout of the pushed commit, as the agent user with
# sudo). The pft-maint window, the throwaway ntfy topic and the Alertmanager silence are the caller's job (see
# live-run.sh); this script refuses to apply/rollback without a window anyway (pft-kmod's own gate).
#   bash kmod/drill/host-run.sh apply|after-reboot|rollback-reapply LABEL 2>&1 | tee LOG
#  apply             audit before (found), dry-run controls, apply, audit after (fixed), refused loads (dccp, cramfs,
#                    SCTP autoload via socket()), allowed-module control (crc7 load + unload), node/network/egress
#                    unchanged
#  after-reboot      the rules persist: audit PASS, no deny module loaded, dccp still refused, node full
#  rollback-reapply  rollback (byte-identical), audit shows the modules loadable again, re-apply, audit PASS
# shellcheck disable=SC1091  # /etc/os-release is read at run time
set -uo pipefail
PHASE="${1:?apply|after-reboot|rollback-reapply}"; LABEL="${2:?host label}"
REPO="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
ME="$(id -un)"
K=/usr/local/bin/pft-kmod
CONF=/etc/modprobe.d/60-pft-kmod.conf
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$(hostname)#$LABEL-host#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; FAILS=$((FAILS + 1)); fi; }
is() { [ "$@" ] && echo 0 || echo 1; }
C="$(for c in postfiatd postfiatd-sentry; do [ "$(sudo -n docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && echo "$c"; done | head -1)"
node() { sudo -n docker exec "$C" postfiatd server_info 2>/dev/null | jq -r '"\(.result.info.server_state) \(.result.info.peers)"'; }
netsig() { # container networks (name, gateway, prefix; addresses redacted by red()) + published ports
  sudo -n docker inspect -f '{{range $n, $v := .NetworkSettings.Networks}}{{$n}} gw={{$v.Gateway}} ip={{$v.IPAddress}}/{{$v.IPPrefixLen}} {{end}}ports={{json .NetworkSettings.Ports}}' "$C"
}
egress() { curl -s -o /dev/null -m 15 -w '%{http_code}' https://api.github.com/zen; }
state_line() { echo "node(state peers)=$(node) | egress https=$(egress) | net=$(netsig | sha256sum | cut -c1-16)"; }
loaded_deny() { "$K" list | awk '{print $1}' | tr '-' '_' | grep -xF -f - <(awk '{print $1}' /proc/modules) || true; }

echo "kmod drill $PHASE - $(date -u +%FT%TZ) - $(. /etc/os-release; echo "$PRETTY_NAME") - host: $LABEL-host - kernel $(uname -r) - repo $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo tree) - container $C"
x "$K version"
S0="$(state_line)"; echo "before: $S0" | red
N0="$(netsig)"

case "$PHASE" in
apply)
  echo; echo "== 1. audit before (found)"
  x "sudo -n $K audit"; check "audit before: findings (exit 1)" "$(is "$XRC" = 1)"
  x "sudo -n $K audit --json | jq -c '[.checks[] | select(.status==\"FAIL\") | .check]'"
  echo; echo "== 2. dry-run controls before apply (nothing is loaded: modprobe -n only)"
  x "modprobe -n -v dccp"; check "before: dccp would load (insmod)" "$(is -n "$(grep '^insmod .*dccp' <<<"$XOUT")")"
  x "modprobe -n -v cramfs"; check "before: cramfs absent from this kernel's tree (modprobe -n fails)" "$(is "$XRC" != 0)"
  x "sudo -n $K apply --dry-run | tail -3"
  echo; echo "== 3. apply"
  x "sudo -n $K apply --yes | grep -v '^  [-+ ]'"; check "apply exit 0, verify ok" "$(is "$XRC" = 0 -a -n "$(grep 'verify ok' <<<"$XOUT")")"
  x "sha256sum $CONF; stat -c '%a %U:%G' $CONF; grep -c '^install .* /bin/false$' $CONF"
  echo; echo "== 4. audit after (fixed)"
  x "sudo -n $K audit"; check "audit after: PASS (exit 0), 20 enforced" "$(is "$XRC" = 0 -a -n "$(grep 'deny 20: 20 enforced' <<<"$XOUT")")"
  echo; echo "== 5. refused loads (real modprobe, real socket)"
  x "sudo -n modprobe -v dccp"; check "modprobe dccp refused (non-zero, 'install /bin/false')" "$(is "$XRC" != 0)"
  x "sudo -n modprobe -v cramfs"; check "modprobe cramfs refused" "$(is "$XRC" != 0)"
  x "python3 -I -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)'"
  check "SCTP socket() fails (autoload refused)" "$(is "$XRC" != 0 -a -n "$(grep -i 'Protocol not supported' <<<"$XOUT")")"
  x "grep -cE '^(dccp|sctp|cramfs) ' /proc/modules"; check "dccp/sctp/cramfs not loaded" "$(is "$(grep -cE '^(dccp|sctp|cramfs) ' /proc/modules)" = 0)"
  echo; echo "== 6. allowed-module control (crc7: library module, not on the list, no side effects)"
  x "grep -c '^crc7 ' /proc/modules"; PRE7="$XOUT"
  x "sudo -n modprobe -v crc7 && grep '^crc7 ' /proc/modules | cut -d' ' -f1"; check "crc7 loads" "$(is "$XRC" = 0 -a "$(grep -c '^crc7 ' /proc/modules)" = 1)"
  if [ "$PRE7" = 0 ]; then x "sudo -n modprobe -r -v crc7; grep -c '^crc7 ' /proc/modules"; check "crc7 unloaded again" "$(is "$(grep -c '^crc7 ' /proc/modules)" = 0)"; fi
  ;;
after-reboot)
  echo; echo "== 1. persistence after reboot"
  x "uptime -s; cat /proc/sys/kernel/random/boot_id | cut -c1-8"
  x "sha256sum $CONF"
  x "sudo -n $K audit"; check "audit after reboot: PASS, 20 enforced" "$(is "$XRC" = 0 -a -n "$(grep 'deny 20: 20 enforced' <<<"$XOUT")")"
  x "loaded_deny"; check "no deny-list module loaded after boot" "$(is -z "$(loaded_deny)")"
  x "sudo -n modprobe -v dccp"; check "modprobe dccp still refused" "$(is "$XRC" != 0)"
  ;;
rollback-reapply)
  echo; echo "== 1. rollback (byte-identical)"
  A="$(sha256sum < "$CONF" | cut -c1-64)"; B="$(sudo -n jq -r .sha_before /var/lib/pft-kmod/apply.json)"
  echo "before rollback: conf sha256 $A, recorded pre-apply sha256 $B"
  x "sudo -n $K rollback --yes"; check "rollback exit 0" "$(is "$XRC" = 0)"
  NOW="$( [ -f "$CONF" ] && sha256sum < "$CONF" | cut -c1-64 || echo absent)"
  check "conf back to the pre-apply state ($NOW)" "$(is "$NOW" = "$B")"
  x "sudo -n $K audit | tail -1"; check "audit after rollback: modules loadable again (exit 1)" "$(is "$XRC" = 1 -a -n "$(grep '13 loadable' <<<"$XOUT")")"
  x "modprobe -n -v dccp"; check "dccp would load again (dry run)" "$(is -n "$(grep '^insmod .*dccp' <<<"$XOUT")")"
  echo; echo "== 2. re-apply"
  x "sudo -n $K apply --yes | grep -v '^  [-+ ]'"; check "re-apply exit 0" "$(is "$XRC" = 0)"
  x "sha256sum $CONF"; check "re-applied file identical to the first apply" "$(is "$(sha256sum < "$CONF" | cut -c1-64)" = "$A")"
  x "sudo -n $K audit | tail -1"; check "audit after re-apply: PASS" "$(is "$XRC" = 0)"
  x "sudo -n modprobe -v dccp"; check "dccp refused again" "$(is "$XRC" != 0)"
  ;;
*) echo "unknown phase"; exit 3 ;;
esac

echo; echo "== node, network, egress unchanged"
S1="$(state_line)"; echo "after:  $S1" | red
st="$(node)"; check "server_state full, peers >= 1 ($st)" "$(is "${st%% *}" = full -a "${st##* }" -ge 1)"
check "container networks + published ports unchanged" "$(is "$(netsig)" = "$N0")"
check "host egress https 200" "$(is "$(egress)" = 200)"
x "sudo -n $K audit --textfile >/dev/null; grep -E '^pft_kmod_(up|deny_modules\{[^}]*enforced|required_blocked|autoload_ok)' /var/lib/pft-exporter/textfile/pft_kmod_$LABEL.prom"
echo; echo "kmod drill $PHASE done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
