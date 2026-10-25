#!/usr/bin/env bash
# "cond && ok || bad" is intended: ok() always returns 0, so bad runs only when cond fails.
# shellcheck disable=SC2015
# Offline test suite for pft-egress.sh - no root, no node, no docker, no real firewall. iptables and
# iptables-restore are a small stateful fake (fake_iptables.py); docker, pft-maint, systemctl, systemd-run,
# journalctl and server_info are stubs; ss output, resolv.conf, postfiatd.cfg, validators.txt and the existing
# DOCKER-USER rules are fixtures copied from the sentry (public IPs replaced by documentation ranges).
# The clock is fake (PFT_EGRESS_NOW_FILE): every dead-man poll sleep advances it.
# Usage: bash egress/tests/run-tests.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PE="$HERE/../pft-egress.sh"
FX="$HERE/fixtures"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }
ind() { sed 's/^/    /'; }

# --- stubs ---
cat > "$WORK/iptables" <<EOF
#!/usr/bin/env bash
exec python3 "$HERE/fake_iptables.py" iptables "\$@"
EOF
cat > "$WORK/iptables-restore" <<EOF
#!/usr/bin/env bash
exec python3 "$HERE/fake_iptables.py" iptables-restore "\$@"
EOF
cat > "$WORK/docker" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$STUB/docker.log"
case "$1 $2" in
  "inspect "*) cat "$STUB/inspect.json" ;;
  "network inspect") echo '[{"Id":"1e7f9b026db6ccee1ee1c280543b5793ba930d877423f0d627898be7db3091e2","Options":{"com.docker.network.bridge.name":"docker0"}}]' ;;
  "exec "*) case "$*" in
      *"cat /etc/resolv.conf") cat "$STUB/resolv.conf" ;;
      *"cat /etc/postfiatd/postfiatd.cfg") cat "$FX/postfiatd.cfg" ;;
      *"cat /etc/postfiatd/validators.txt") cat "$FX/validators.txt" ;;
      *"/dev/tcp/"*) exit "$(cat "$STUB/probe_rc")" ;;
      *) exit 1 ;;
    esac ;;
  *) exit 1 ;;
esac
EOF
cat > "$WORK/pft-maint" <<'EOF'
#!/usr/bin/env bash
cat "$STUB/maint.json"
EOF
cat > "$WORK/rpc" <<'EOF'
#!/usr/bin/env bash
# one answer per call from rpc.seq (first line consumed), rpc.default when the sequence is empty
if [ -s "$STUB/rpc.seq" ]; then head -1 "$STUB/rpc.seq"; sed -i 1d "$STUB/rpc.seq"; else cat "$STUB/rpc.default"; fi
EOF
cat > "$WORK/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$STUB/systemctl.log"
case "$1" in
  enable) echo enabled > "$STUB/timer" ;;
  disable) echo disabled > "$STUB/timer" ;;
  is-enabled) cat "$STUB/timer" 2>/dev/null || echo disabled ;;
esac
exit 0
EOF
cat > "$WORK/systemd-run" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$STUB/systemd-run.log"
EOF
cat > "$WORK/journalctl" <<'EOF'
#!/usr/bin/env bash
cat "$STUB/kern.log" 2>/dev/null
EOF
cat > "$WORK/ss" <<'EOF'
#!/usr/bin/env bash
cat "$FX/ss-established.txt"
EOF
chmod +x "$WORK"/*

full() { echo "{\"info\":{\"server_state\":\"$1\",\"peers\":$2}}"; }
inspect() { # MODE IP
  jq -n --arg m "$1" --arg ip "$2" '[{State:{Running:true,Pid:4242},HostConfig:{NetworkMode:$m},
     NetworkSettings:{Networks:{bridge:{IPAddress:$ip,GlobalIPv6Address:""}}}}]' > "$STUB/inspect.json"; }
maint() { # WINDOW REMAINING [LOCK]
  jq -n --arg w "$1" --argjson r "$2" --arg l "${3:-}" '{window:$w,remaining_sec:$r,locks:(if $l == "" then [] else [$l] end)}' > "$STUB/maint.json"; }
setup() { # fresh stub dir + firewall with the sentry's DOCKER-USER rules
  STUB="$(mktemp -d "$WORK/case.XXXX")"; export STUB FX
  jq -n --rawfile r "$FX/docker-user.rules" '{chains:{"DOCKER-USER":[$r | split("\n")[] | select(startswith("-A ")) | sub("^-A DOCKER-USER "; "")]}, drops:0}' > "$STUB/ipt.json"
  cp "$FX/resolv.conf" "$STUB/resolv.conf"
  inspect bridge 172.17.0.2; maint active 1800; full full 11 > "$STUB/rpc.default"; : > "$STUB/rpc.seq"; echo 0 > "$STUB/probe_rc"
  date -u -d 2026-10-25T05:00:00Z +%s > "$STUB/now"
  export FAKE_IPT_STATE="$STUB/ipt.json" PFT_EGRESS_TEST=1 PFT_EGRESS_NOW_FILE="$STUB/now" \
    PFT_EGRESS_IPT="$WORK/iptables" PFT_EGRESS_IPT_RESTORE="$WORK/iptables-restore" PFT_EGRESS_DOCKER="$WORK/docker" \
    PFT_EGRESS_MAINT="$WORK/pft-maint" PFT_EGRESS_SYSTEMCTL="$WORK/systemctl" PFT_EGRESS_SYSTEMD_RUN="$WORK/systemd-run" \
    PFT_EGRESS_JOURNAL="$WORK/journalctl" PFT_EGRESS_RPC_CMD="$WORK/rpc" PFT_EGRESS_SS_CMD="$WORK/ss" \
    STATE_DIR="$STUB/state" UNIT_DIR="$STUB/units" CONTAINER=postfiatd-sentry POLL_SEC=30 DEADMAN_MIN=10
}
run() { OUT="$(bash "$PE" "$@" 2>&1)"; RC=$?; }
ipt() { "$WORK/iptables" "$@"; }
du_sha() { ipt -S DOCKER-USER | sha256sum; }
njumps() { ipt -S DOCKER-USER | grep -c -- '-j PFT-EGRESS$'; }
jumppos() { ipt -S DOCKER-USER | grep -n -- '-j PFT-EGRESS$' | head -1 | cut -d: -f1; }

echo "# plan"
setup
run plan --json
[ "$RC" = 0 ] && [ "$(jq -c .policy.resolvers <<<"$OUT")" = '["192.0.2.53","192.0.2.54"]' ] \
  && ok "plan: resolvers from the container resolv.conf" || { bad "plan resolvers (rc $RC)"; ind <<<"$OUT"; }
[ "$(jq -c .policy.tcp_ports <<<"$OUT")" = '[443,2559,51235]' ] \
  && ok "plan: tcp ports = 2559 + [ips] port 51235 + outbound ss port 51235 + VL https 443" || bad "plan tcp ports $(jq -c .policy.tcp_ports <<<"$OUT")"
[ "$(jq -c '[.discover.inbound_conns, (.discover.established | length), .discover.outbound_ports]' <<<"$OUT")" = '[1,6,[2559,51235]]' ] \
  && ok "plan: ss parsing (6 established, 1 inbound on 2559, outbound remote ports 2559 51235)" || bad "plan ss $(jq -c .discover <<<"$OUT")"
[ "$(jq -r .discover.vl_sites[0] <<<"$OUT")" = https://postfiat.org/testnet_vl.json ] && ok "plan: validator_list_sites from validators.txt" || bad "plan vl"
run plan
grep -q -- '-A PFT-EGRESS -m limit --limit 6/min --limit-burst 10 -j LOG --log-prefix "pft-egress-drop: "' <<<"$OUT" \
  && grep -q -- '-A PFT-EGRESS -p tcp -m multiport --dports 443,2559,51235' <<<"$OUT" \
  && grep -q 'DOCKER-USER jump (position 1): -s 172.17.0.2/32 -i docker0 ! -o docker0' <<<"$OUT" \
  && ok "plan: prints restore input and jump" || { bad "plan text"; ind <<<"$OUT"; }
inspect host ""; run plan
[ "$RC" = 3 ] && grep -q "network mode 'host' is not supported" <<<"$OUT" && ok "plan: host network mode refused (exit 3)" || bad "host mode rc $RC"
inspect bridge 172.17.0.2; printf 'nameserver 127.0.0.11\n' > "$STUB/resolv.conf"; run plan --json
[ "$(jq -c .policy.resolvers <<<"$OUT")" = '[]' ] && jq -e '.policy.warnings | map(test("loopback")) | any' <<<"$OUT" >/dev/null \
  && ok "plan: embedded-DNS resolver warned and not allowlisted" || bad "embedded dns"

echo "# apply guards (each must leave DOCKER-USER untouched)"
guard() { # NAME EXPECT_GREP ARGS...
  local n="$1" g="$2"; shift 2; local before; before="$(du_sha)"
  run "$@"
  [ "$RC" = 4 ] && grep -q "$g" <<<"$OUT" && [ "$(du_sha)" = "$before" ] && ! ipt -S PFT-EGRESS >/dev/null 2>&1 \
    && ok "guard: $n -> exit 4, firewall unchanged" || { bad "guard $n (rc $RC)"; ind <<<"$OUT"; }
}
setup; guard "no --yes" "re-run with --yes" apply
setup; maint none 0; guard "no maintenance window" "no active pft-maint window" apply --yes
setup; maint active 600; guard "window shorter than dead-man + margin" "needs DEADMAN+MAINT_MARGIN=900s" apply --yes
setup; maint active 1800 "txflow-24h until X"; guard "data-collection lock" "data-collection lock" apply --yes
setup; full syncing 11 > "$STUB/rpc.default"; guard "node not full" "node is syncing" apply --yes
setup; full full 2 > "$STUB/rpc.default"; guard "peers below MIN_PEERS" "peers 2 < MIN_PEERS 3" apply --yes
setup; printf 'search .\n' > "$STUB/resolv.conf"; guard "no nameserver at all" "no nameserver in the container resolv.conf" apply --yes

echo "# dry run"
setup; before="$(du_sha)"; run apply --dry-run
[ "$RC" = 0 ] && [ "$(du_sha)" = "$before" ] && grep -q '^  + -A PFT-EGRESS -m comment --comment "pft-egress default deny" -j DROP$' <<<"$OUT" \
  && grep -q 'jump: + -I DOCKER-USER 1' <<<"$OUT" && [ ! -d "$STUB/state" ] \
  && ok "dry-run: diff printed, nothing changed" || { bad "dry-run rc $RC"; ind <<<"$OUT"; }

echo "# apply, idempotence, check"
setup; run apply --yes
[ "$RC" = 0 ] && [ "$(njumps)" = 1 ] && [ "$(jumppos)" = 2 ] && grep -q "dead-man: PASS" <<<"$OUT" \
  && ok "apply: chain loaded, one jump at DOCKER-USER 1, dead-man PASS after 10 min (fake clock)" || { bad "apply rc $RC"; ind <<<"$OUT"; }
[ "$(ipt -S PFT-EGRESS | grep -c '^-A')" = 8 ] && ipt -S PFT-EGRESS | tail -1 | grep -q -- '-j DROP$' \
  && ok "apply: 8 rules (replies, 2 resolvers x udp/tcp 53, peers+vl, LOG, DROP last)" || { bad "chain rules"; ipt -S PFT-EGRESS | ind; }
[ "$(ipt -S DOCKER-USER | sed 1,2d | sha256sum)" = "$(sed 1d "$FX/docker-user.rules" | sha256sum)" ] \
  && ok "apply: the existing DOCKER-USER rate-limit rules are kept, in order, after the jump" || bad "existing rules changed"
[ -f "$STUB/units/pft-egress-reapply@.service" ] && [ "$(cat "$STUB/timer")" = enabled ] && grep -q "reapply --container %i" "$STUB/units/pft-egress-reapply@.service" \
  && ok "apply: reapply service + timer written and enabled" || bad "units"
[ "$(jq -r .baseline_peers "$STUB/state/postfiatd-sentry.json")" = 11 ] && ok "apply: baseline peers 11 recorded" || bad "baseline"
s1="$(ipt -S | sha256sum)"; run apply --yes
[ "$RC" = 0 ] && grep -q "apply: no change" <<<"$OUT" && [ "$(ipt -S | sha256sum)" = "$s1" ] && [ "$(njumps)" = 1 ] \
  && ok "apply again: no change, firewall byte-identical" || { bad "idempotent rc $RC"; ind <<<"$OUT"; }
run check
[ "$RC" = 0 ] && grep -q "RESULT: PASS" <<<"$OUT" && ok "check: PASS after apply" || { bad "check rc $RC"; ind <<<"$OUT"; }
jq '.drops = 5' "$STUB/ipt.json" > "$STUB/t" && mv "$STUB/t" "$STUB/ipt.json"
printf '%s\n' 'Oct 25 05:01:00 host kernel: pft-egress-drop: IN=docker0 OUT=eth0 SRC=172.17.0.2 DST=203.0.113.99 PROTO=TCP SPT=40000 DPT=80' \
  'Oct 25 05:01:05 host kernel: pft-egress-drop: IN=docker0 OUT=eth0 SRC=172.17.0.2 DST=203.0.113.99 PROTO=TCP SPT=40002 DPT=80' > "$STUB/kern.log"
run check
grep -q "DROP counter: 5 pkts" <<<"$OUT" && grep -q "drop log lines in the last hour: 2; by DPT: DPT=80(2)" <<<"$OUT" \
  && ok "check: reports DROP counter and drop log lines by port" || { bad "check counters"; ind <<<"$OUT"; }
full full 9 > "$STUB/rpc.default"; run check
[ "$RC" = 1 ] && grep -q "\[FAIL\] peers 9 >= baseline 11" <<<"$OUT" && ok "check: FAIL when peers < baseline" || bad "check peers rc $RC"
full full 11 > "$STUB/rpc.default"

echo "# drift and reapply"
inspect bridge 172.17.0.3; run check
[ "$RC" = 1 ] && grep -q "\[FAIL\] container IP unchanged" <<<"$OUT" && ok "check: FAIL after container IP change" || bad "ip drift check"
run reapply --container postfiatd-sentry
[ "$RC" = 0 ] && [ "$(njumps)" = 1 ] && ipt -S DOCKER-USER | sed -n 2p | grep -q -- '-s 172.17.0.3/32' \
  && ok "reapply: stale jump replaced by one for the new IP at position 1" || { bad "reapply ip rc $RC"; ind <<<"$OUT"; ipt -S DOCKER-USER | ind; }
run check; [ "$RC" = 0 ] && ok "check: PASS after reapply" || { bad "check after reapply"; ind <<<"$OUT"; }
s1="$(ipt -S | sha256sum)"; run reapply --container postfiatd-sentry
[ "$RC" = 0 ] && [ -z "$OUT" ] && [ "$(ipt -S | sha256sum)" = "$s1" ] && ok "reapply: silent no-op without drift" || bad "reapply noop"
ipt -D DOCKER-USER -s 172.17.0.3/32 -i docker0 ! -o docker0 -m comment --comment pft-egress:postfiatd-sentry -j PFT-EGRESS
ipt -F PFT-EGRESS
run reapply --container postfiatd-sentry
[ "$RC" = 0 ] && [ "$(njumps)" = 1 ] && [ "$(ipt -S PFT-EGRESS | grep -c '^-A')" = 8 ] && grep -q "drift found" <<<"$OUT" \
  && ok "reapply: flushed chain + removed jump restored (boot / dockerd case)" || { bad "reapply restore rc $RC"; ind <<<"$OUT"; }
ipt -I DOCKER-USER 3 -s 172.17.0.3/32 -i docker0 ! -o docker0 -m comment --comment pft-egress:postfiatd-sentry -j PFT-EGRESS
run reapply --container postfiatd-sentry
[ "$(njumps)" = 1 ] && [ "$(jumppos)" = 2 ] && ok "reapply: duplicate jump further down removed" || { bad "dup jump"; ipt -S DOCKER-USER | ind; }

echo "# rollback"
run rollback
[ "$RC" = 4 ] && ok "rollback without --yes refused" || bad "rollback guard"
run rollback --yes
[ "$RC" = 0 ] && ! ipt -S PFT-EGRESS >/dev/null 2>&1 && [ "$(njumps)" = 0 ] && [ "$(cat "$STUB/timer")" = disabled ] \
  && [ "$(ipt -S DOCKER-USER | sha256sum)" = "$(sha256sum < "$FX/docker-user.rules")" ] \
  && ok "rollback: chain + jump gone, timer disabled, DOCKER-USER identical to the original" || { bad "rollback rc $RC"; ind <<<"$OUT"; }
run reapply --container postfiatd-sentry
[ "$RC" = 0 ] && ! ipt -S PFT-EGRESS >/dev/null 2>&1 && ok "reapply after rollback: does nothing (no state)" || bad "reapply after rollback"
run rollback --yes
[ "$RC" = 0 ] && ok "rollback twice: still clean, exit 0" || { bad "rollback twice rc $RC"; ind <<<"$OUT"; }

echo "# dead-man"
setup; printf '%s\n' "$(full full 11)" "$(full full 9)" "$(full full 8)" "$(full syncing 3)" > "$STUB/rpc.seq"
run apply --yes
[ "$RC" = 1 ] && grep -q "dead-man: TRIPPED" <<<"$OUT" && ! ipt -S PFT-EGRESS >/dev/null 2>&1 && [ "$(njumps)" = 0 ] \
  && ok "dead-man: 3 consecutive bad polls (peers 9, 8 < 10; syncing) -> rolled back, exit 1" || { bad "deadman trip rc $RC"; ind <<<"$OUT"; }
grep -q "rollback RESULT: PASS" <<<"$OUT" && ! grep -q "pft-egress-deadman" "$STUB/systemctl.log" \
  && ok "dead-man: rollback PASS and it does not try to stop its own unit" || bad "deadman self-stop"
setup; printf '%s\n' "$(full full 11)" "$(full full 8)" "$(full connected 11)" "$(full full 10)" "$(full full 7)" > "$STUB/rpc.seq"
run apply --yes
[ "$RC" = 0 ] && grep -q "dead-man: PASS" <<<"$OUT" && [ "$(njumps)" = 1 ] \
  && ok "dead-man: 2 bad polls then ok (and peers 10 = baseline-slack is ok) -> kept" || { bad "deadman transient rc $RC"; ind <<<"$OUT"; }
[ "$(grep -c 'dead-man poll' <<<"$OUT")" = 20 ] && ok "dead-man: 20 polls in 10 min at POLL_SEC=30 (fake clock)" || bad "poll count $(grep -c 'dead-man poll' <<<"$OUT")"
setup; FAKE_IPT_RESTORE_FAIL=1 run apply --yes
[ "$RC" = 1 ] && [ "$(njumps)" = 0 ] && ok "apply: iptables-restore failure -> rolled back, no jump" || { bad "restore fail rc $RC"; ind <<<"$OUT"; }

echo "# non-test mode starts the dead-man as a transient unit"
setup; PFT_EGRESS_TEST="" run apply --yes 2>&1
[ "$RC" = 3 ] && grep -q "needs root" <<<"$OUT" && ok "apply outside test mode needs root" || bad "root check rc $RC"

echo "# probe"
setup; echo 0 > "$STUB/probe_rc"; run probe --container postfiatd-sentry --target example.com:80
grep -q "postfiatd-sentry -> example.com:80 CONNECTED" <<<"$OUT" && ok "probe: connected" || bad "probe ok"
echo 1 > "$STUB/probe_rc"; run probe --container postfiatd-sentry --target example.com:80
grep -q "example.com:80 BLOCKED_OR_FAILED" <<<"$OUT" && grep -q "timeout 5 bash -c exec 3<>/dev/tcp/example.com/80" "$STUB/docker.log" \
  && ok "probe: blocked, runs inside the container with a 5 s timeout" || bad "probe blocked"

echo
echo "unit tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
