#!/usr/bin/env bash
# "cond && ok || bad" is intended: ok() always returns 0, so bad runs only when cond fails.
# shellcheck disable=SC2015,SC2016
# Integration test for pft-egress.sh against REAL iptables/iptables-restore, in three throwaway network
# namespaces (the host firewall, docker and the node are not touched):
#   egc ("container", eth0 172.17.0.2)  <->  egr ("host": docker0 / uplink, FORWARD -> DOCKER-USER with the
#   sentry's rate-limit rules)  <->  egx ("internet": 198.18.0.2 resolver + listeners, 198.18.0.3 non-resolver)
# docker exec is stubbed as `ip netns exec egc`, so `pft-egress probe` really connects from the container side.
# Needs root. Usage: sudo bash egress/tests/netns-test.sh
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 3; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PE="$HERE/../pft-egress.sh"; FX="$HERE/fixtures"
WORK="$(mktemp -d)"; pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }
ind() { sed 's/^/    /'; }
cleanup() { for n in egc egr egx; do ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del "$n" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
cleanup; WORK="$(mktemp -d)"

echo "netns-test - $(date -u +%FT%TZ) - $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) - $(iptables -V)"
for n in egc egr egx; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add eg-c0 type veth peer name eg-c1; ip link set eg-c0 netns egc; ip link set eg-c1 netns egr
ip link add eg-x0 type veth peer name eg-x1; ip link set eg-x0 netns egx; ip link set eg-x1 netns egr
ip -n egc link set eg-c0 name eth0; ip -n egr link set eg-c1 name docker0; ip -n egr link set eg-x1 name uplink
ip -n egx link set eg-x0 name eth0
ip -n egc addr add 172.17.0.2/16 dev eth0; ip -n egr addr add 172.17.0.1/16 dev docker0
ip -n egr addr add 198.18.0.1/24 dev uplink; ip -n egx addr add 198.18.0.2/24 dev eth0; ip -n egx addr add 198.18.0.3/24 dev eth0
for n in egc egr egx; do ip -n "$n" link set eth0 up 2>/dev/null; done
ip -n egr link set docker0 up; ip -n egr link set uplink up
ip -n egc route add default via 172.17.0.1; ip -n egx route add 172.17.0.0/16 via 198.18.0.1
ip netns exec egr sysctl -qw net.ipv4.ip_forward=1
R() { ip netns exec egr "$@"; }
R iptables -N DOCKER-USER
sed 1d "$FX/docker-user.rules" | sed 's/^-A DOCKER-USER //' | while read -r -a w; do R iptables -A DOCKER-USER "${w[@]}"; done
R iptables -A FORWARD -j DOCKER-USER
echo "egr filter table before apply:"; R iptables -S | ind
PRE="$(R iptables -S)"

# listeners: "internet" side on 53 80 443 2559 8080 51235; "container" side on 2559 (inbound peer)
LS='import socket,sys,threading
def srv(p):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",p)); s.listen(16)
    while True:
        c,_=s.accept(); c.sendall(b"hello\n"); c.close()
for p in sys.argv[1:]: threading.Thread(target=srv,args=(int(p),),daemon=True).start()
threading.Event().wait()'
ip netns exec egx python3 -c "$LS" 53 80 443 2559 8080 51235 & ip netns exec egc python3 -c "$LS" 2559 &
sleep 1

# stubs
cat > "$WORK/iptables" <<'EOF'
#!/usr/bin/env bash
exec ip netns exec egr iptables "$@"
EOF
cat > "$WORK/iptables-restore" <<'EOF'
#!/usr/bin/env bash
exec ip netns exec egr iptables-restore "$@"
EOF
cat > "$WORK/docker" <<EOF
#!/usr/bin/env bash
case "\$1 \$2" in
  "inspect "*) echo '[{"State":{"Running":true,"Pid":1},"HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2","GlobalIPv6Address":""}}}}]' ;;
  "network inspect") echo '[{"Id":"0123456789abcdef","Options":{"com.docker.network.bridge.name":"docker0"}}]' ;;
  "exec "*) case "\$*" in
      *"cat /etc/resolv.conf") echo "nameserver 198.18.0.2" ;;
      *"cat /etc/postfiatd/postfiatd.cfg") cat "$FX/postfiatd.cfg" ;;
      *"cat /etc/postfiatd/validators.txt") cat "$FX/validators.txt" ;;
      *) shift 2; exec ip netns exec egc "\$@" ;;
    esac ;;
esac
EOF
printf '#!/usr/bin/env bash\necho %s\n' "'{\"window\":\"active\",\"remaining_sec\":1800,\"locks\":[]}'" > "$WORK/pft-maint"
printf '#!/usr/bin/env bash\necho %s\n' "'{\"info\":{\"server_state\":\"full\",\"peers\":11}}'" > "$WORK/rpc"
printf '#!/usr/bin/env bash\ncase "$1" in is-enabled) echo enabled ;; esac\n' > "$WORK/systemctl"
printf '#!/usr/bin/env bash\ntrue\n' > "$WORK/journalctl"
printf '#!/usr/bin/env bash\ncat %s\n' "$FX/ss-established.txt" > "$WORK/ss"
chmod +x "$WORK"/*
date -u +%s > "$WORK/now"
export PFT_EGRESS_TEST=1 PFT_EGRESS_NOW_FILE="$WORK/now" PFT_EGRESS_IPT="$WORK/iptables" \
  PFT_EGRESS_IPT_RESTORE="$WORK/iptables-restore" PFT_EGRESS_DOCKER="$WORK/docker" PFT_EGRESS_MAINT="$WORK/pft-maint" \
  PFT_EGRESS_SYSTEMCTL="$WORK/systemctl" PFT_EGRESS_JOURNAL="$WORK/journalctl" PFT_EGRESS_RPC_CMD="$WORK/rpc" \
  PFT_EGRESS_SS_CMD="$WORK/ss" STATE_DIR="$WORK/state" UNIT_DIR="$WORK/units" CONTAINER=postfiatd-sentry DEADMAN_MIN=1
probe() { bash "$PE" probe --container postfiatd-sentry --target "$1" | sed 's/^probe [^ ]* //'; }
expect() { # TARGET CONNECTED|BLOCKED_OR_FAILED LABEL
  local o; o="$(probe "$1")"; echo "  $o"
  grep -q " $2 " <<<"$o" && ok "$3" || bad "$3"
}

echo; echo "# before apply"
expect 198.18.0.2:80 CONNECTED "before: container -> :80 connects (no policy)"
expect 198.18.0.3:53 CONNECTED "before: container -> non-resolver :53 connects"

echo; echo "# apply"
OUT="$(bash "$PE" apply --yes 2>&1)"; RC=$?; ind <<<"$OUT"
[ "$RC" = 0 ] && ok "apply exit 0 (dead-man 1 min on the fake clock: PASS)" || bad "apply rc $RC"
echo "egr DOCKER-USER + PFT-EGRESS after apply (real iptables -S):"; R iptables -S DOCKER-USER | ind; R iptables -S PFT-EGRESS | ind

echo; echo "# after apply"
expect 198.18.0.2:80 BLOCKED_OR_FAILED "after: :80 blocked"
expect 198.18.0.2:8080 BLOCKED_OR_FAILED "after: :8080 blocked"
expect 198.18.0.3:53 BLOCKED_OR_FAILED "after: :53 to a NON-resolver blocked"
expect 198.18.0.2:53 CONNECTED "after: :53/tcp to the resolver allowed"
expect 198.18.0.2:2559 CONNECTED "after: peer port 2559 allowed"
expect 198.18.0.2:51235 CONNECTED "after: [ips] peer port 51235 allowed"
expect 198.18.0.2:443 CONNECTED "after: validator-list 443 allowed"
o="$(ip netns exec egx timeout 5 bash -c 'exec 3<>/dev/tcp/172.17.0.2/2559; head -1 <&3')"
[ "$o" = hello ] && ok "after: INBOUND peer -> container:2559 works and the reply comes back (ESTABLISHED)" || bad "inbound ($o)"
echo "PFT-EGRESS counters:"; R iptables -L PFT-EGRESS -v -n -x | ind
OUT="$(bash "$PE" check 2>&1)"; RC=$?; ind <<<"$OUT"
[ "$RC" = 0 ] && grep -qE 'DROP counter: [1-9][0-9]* pkts' <<<"$OUT" && ok "check PASS, real DROP counter > 0" || bad "check rc $RC"
S1="$(R iptables -S)"
OUT="$(bash "$PE" apply --yes 2>&1)"; RC=$?; ind <<<"$OUT"
[ "$RC" = 0 ] && grep -q "no change" <<<"$OUT" && [ "$(R iptables -S)" = "$S1" ] && ok "apply again: no change, iptables -S identical" || bad "idempotent rc $RC"
R iptables -D FORWARD -j DOCKER-USER; R iptables -F DOCKER-USER; R iptables -A FORWARD -j DOCKER-USER
sed 1d "$FX/docker-user.rules" | sed 's/^-A DOCKER-USER //' | while read -r -a w; do R iptables -A DOCKER-USER "${w[@]}"; done
OUT="$(bash "$PE" reapply --container postfiatd-sentry 2>&1)"; RC=$?; ind <<<"$OUT"
[ "$RC" = 0 ] && [ "$(R iptables -S)" = "$S1" ] && ok "reapply after DOCKER-USER was flushed: firewall back to the applied state" || bad "reapply rc $RC"
expect 198.18.0.2:80 BLOCKED_OR_FAILED "after reapply: :80 blocked again"

echo; echo "# rollback"
OUT="$(bash "$PE" rollback --yes 2>&1)"; RC=$?; ind <<<"$OUT"
[ "$RC" = 0 ] && [ "$(R iptables -S)" = "$PRE" ] && ok "rollback: filter table identical to before apply" || { bad "rollback rc $RC"; diff <(echo "$PRE") <(R iptables -S) | ind; }
expect 198.18.0.2:80 CONNECTED "after rollback: :80 connects again"

echo
echo "netns tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
