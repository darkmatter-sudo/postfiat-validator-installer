#!/usr/bin/env bash
# Negative sandbox proofs: for several profiles, an action the profile must block is run in a transient unit with
# the profile's properties (probe.sh --expect-fail), and the same action is run with NO properties as a positive
# control (must succeed), so "blocked" cannot come from a broken command. Read-only apart from one probe file
# /etc/unitguard-probe.tmp that the unsandboxed control creates and removes. Network probes only open a TCP
# connection to this host's own ports: 127.0.0.1:5005 (admin RPC) and the docker0 address :2559 (peer port).
# Usage: sudo bash negative.sh DIR   (DIR holds profiles/ and drill/probe.sh)
set -uo pipefail
d="$1"; P="$d/drill/probe.sh"; pass=0; fail=0
run_mode() { # PROFILE MODE CMD...
  local prof="$1" mode="$2"; shift 2
  case "$mode" in
    block) bash "$P" "$d/profiles/$prof" --expect-fail -- "$@" ;;
    allow) bash "$P" "$d/profiles/$prof" -- "$@" ;;
    *) bash "$P" /dev/null -- "$@" ;;
  esac
}
step() { # NAME PROFILE MODE EXPECT -- CMD...   EXPECT: text the output must contain ("-" = none), so a negative
  local n="$1" prof="$2" mode="$3" want="$4" out rc; shift 5  # fails for the reason it claims
  echo "--- $n"
  out="$(run_mode "$prof" "$mode" "$@" 2>&1)"; rc=$?
  echo "$out"
  if [ "$rc" -eq 0 ] && { [ "$want" = - ] || grep -qF -- "$want" <<<"$out"; }; then pass=$((pass+1)); echo "STEP PASS $n"
  else fail=$((fail+1)); echo "STEP FAIL $n (rc $rc, wanted: $want)"; fi
}
W='touch /etc/unitguard-probe.tmp && rm -f /etc/unitguard-probe.tmp'
D="$(ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1)"
T="timeout 5 bash -c 'exec 3<>/dev/tcp/$D/2559'"
L="timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5005'"
H='ls /root/.profile'
step "control: /etc write without sandbox succeeds" none control - -- bash -c "$W"
step "logship-vacuum: /etc write blocked (ProtectSystem=strict)" pft-logship-vacuum.service.conf block "Read-only file system" -- bash -c "$W"
step "control: TCP to 127.0.0.1:5005 without sandbox succeeds" none control - -- bash -c "$L"
step "logship-vacuum: TCP to 127.0.0.1:5005 blocked (PrivateNetwork + AF_UNIX only)" pft-logship-vacuum.service.conf block "Address family not supported" -- bash -c "$L"
step "control: TCP to docker0:2559 without sandbox succeeds" none control - -- bash -c "$T"
step "exporter: TCP to 127.0.0.1:5005 allowed (same profile)" pft-exporter.service.conf allow - -- bash -c "$L"
step "exporter: TCP to non-loopback docker0:2559 dropped (IPAddressDeny=any drops silently: connect times out, exit 124; the unsandboxed control connects)" pft-exporter.service.conf block "probe exit 124" -- bash -c "$T"
step "exporter: /etc write blocked" pft-exporter.service.conf block "Read-only file system" -- bash -c "$W"
step "control: ls /root/.profile without sandbox succeeds" none control - -- bash -c "$H"
step "heartbeat: /root unreadable (ProtectHome=yes)" pft-heartbeat.service.conf block "Permission denied" -- bash -c "$H"
step "heartbeat: /etc write blocked" pft-heartbeat.service.conf block "Read-only file system" -- bash -c "$W"
step "integrity (docker class, keeps caps): /root is an empty mount (ProtectHome=yes)" pft-integrity.service.conf block "No such file or directory" -- bash -c "$H"
echo "NEGATIVE RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
