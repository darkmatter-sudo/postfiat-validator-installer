#!/usr/bin/env bash
# test-netns: exercise the guide's postfiat-docker-user.sh and read-only check with REAL iptables inside a
# throwaway network namespace (unshare --net), so no host rule is read or changed.
#   sudo bash tests/test-netns.sh EXTRACT_DIR      (EXTRACT_DIR = output of extract_dockeruser.py)
# Every case asserts the exit code AND the reason line; the fail controls must fail for the named reason.
# Exit 0 = every case PASS.
set -uo pipefail
if [ "${1:-}" != __ns ]; then
  [ "$(id -u)" = 0 ] || { echo "test-netns: run with sudo" >&2; exit 2; }
  if [ -z "${1:-}" ] || [ ! -f "$1/postfiat-docker-user.sh" ] || [ ! -f "$1/check.sh" ]; then
    echo "usage: sudo bash $0 EXTRACT_DIR" >&2; exit 2
  fi
  HOST_NETNS="$(readlink /proc/1/ns/net)" exec unshare --net bash "$0" __ns "$(cd "$1" && pwd)"
fi
X="$2"
[ "$(readlink /proc/self/ns/net)" != "$HOST_NETNS" ] || { echo "test-netns: still in the host netns, refusing" >&2; exit 2; }
echo "netns: private ($(readlink /proc/self/ns/net) != host)"
REAL_IPT="$(command -v iptables)"; echo "iptables: $("$REAL_IPT" --version)"
SCRIPT="$X/postfiat-docker-user.sh"
# the check block is `sudo sh -s <<'EOF' ... EOF`: run its body with sh, as the guide does (we are already root)
BODY="$X/check-body.sh"; sed -e '1d' -e '$d' "$X/check.sh" > "$BODY"
if [ "$(head -1 "$X/check.sh")" != "sudo sh -s <<'EOF'" ] || [ "$(tail -1 "$X/check.sh")" != EOF ]; then
  echo "test-netns: check block shape changed" >&2; exit 2
fi
echo "sha256 $(sha256sum "$SCRIPT" | cut -c1-64) postfiat-docker-user.sh"
echo "sha256 $(sha256sum "$BODY" | cut -c1-64) check body"
STUB="$(mktemp -d "$X/stub.XXXXXX")"; chmod 755 "$STUB"
cat > "$STUB/systemctl" <<'EOF'
#!/bin/sh
# stub: only `systemctl is-enabled --quiet postfiat-docker-user.service`; answer from STUB_ENABLED
[ "$1 $2 $3" = "is-enabled --quiet postfiat-docker-user.service" ] || { echo "stub systemctl: unexpected $*" >&2; exit 99; }
[ "${STUB_ENABLED:-1}" = 1 ]
EOF
cat > "$STUB/iptables" <<EOF
#!/bin/sh
# stub: real iptables, but fail when the first rule op equals STUB_FAIL_OP (e.g. -A or -D)
for a in "\$@"; do case "\$a" in -A|-D|-I|-N|-S) [ "\$a" = "\${STUB_FAIL_OP:-none}" ] && { echo "stub iptables: injected failure on \$a" >&2; exit 4; }; break ;; esac; done
exec "$REAL_IPT" "\$@"
EOF
chmod 755 "$STUB/systemctl" "$STUB/iptables"

PASS=0; FAILN=0
ok() { echo "PASS $*"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $*"; FAILN=$((FAILN + 1)); }
run_check() { CK_OUT="$(PATH="$STUB:$PATH" sh "$BODY" 2>&1)"; CK_RC=$?; echo "  check rc=$CK_RC: $CK_OUT"; }
run_script() { SC_OUT="$(PATH="$STUB:$PATH" sh "$SCRIPT" 2>&1)"; SC_RC=$?; echo "  script rc=$SC_RC${SC_OUT:+: $SC_OUT}"; }
expect_check() { # NAME RC REASON-SUBSTRING
  run_check
  if [ "$CK_RC" = "$2" ] && [[ "$CK_OUT" == *"$3"* ]]; then ok "$1 (check rc=$2, '$3')"; else bad "$1 (want rc=$2 '$3', got rc=$CK_RC '$CK_OUT')"; fi
}
rules() { "$REAL_IPT" -w -S DOCKER-USER 2>/dev/null; }
show() { echo "  rules:"; rules | sed 's/^/    /'; }
WANT_TAIL="-A DOCKER-USER -p tcp -m tcp --dport 2559 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-USER -p tcp -m tcp --dport 2559 -m connlimit --connlimit-above 50 --connlimit-mask 32 --connlimit-saddr -j DROP
-A DOCKER-USER -p tcp -m tcp --dport 2559 -m state --state NEW -m limit --limit 100/sec --limit-burst 50 -j ACCEPT
-A DOCKER-USER -p tcp -m tcp --dport 2559 -m state --state NEW -j DROP
-A DOCKER-USER -j RETURN"
old_guide() { # the guide's previous commands, verbatim
  "$REAL_IPT" -F DOCKER-USER 2>/dev/null || true
  "$REAL_IPT" -I DOCKER-USER -j RETURN
  "$REAL_IPT" -I DOCKER-USER -p tcp --dport 2559 -m state --state NEW -j DROP
  "$REAL_IPT" -I DOCKER-USER -p tcp --dport 2559 -m state --state NEW -m limit --limit 100/second --limit-burst 50 -j ACCEPT
  "$REAL_IPT" -I DOCKER-USER -p tcp --dport 2559 -m connlimit --connlimit-above 50 -j DROP
  "$REAL_IPT" -I DOCKER-USER -p tcp --dport 2559 -m state --state ESTABLISHED,RELATED -j ACCEPT
}

echo "== T01 no DOCKER-USER chain (fresh host before Docker): check must fail"
expect_check T01-no-chain 1 "FAIL: cannot read the DOCKER-USER chain"

echo "== T02 script on a fresh netns creates the chain and the exact rule set"
run_script; show
if [ "$SC_RC" = 0 ] && [ "$(rules | tail -n +2)" = "$WANT_TAIL" ]; then ok "T02-apply (exact 5 rules, RETURN last)"; else bad "T02-apply"; fi
expect_check T02-check 0 "OK: TCP 2559 DOCKER-USER limits present, RETURN last, unit enabled"

echo "== T03 idempotency: two more runs leave the chain byte-identical"
h0="$(rules | sha256sum | cut -c1-16)"; n0="$(rules | wc -l)"
run_script; h1="$(rules | sha256sum | cut -c1-16)"; n1="$(rules | wc -l)"
run_script; h2="$(rules | sha256sum | cut -c1-16)"; n2="$(rules | wc -l)"
echo "  lines $n0 $n1 $n2 sha $h0 $h1 $h2"
if [ "$h0" = "$h1" ] && [ "$h1" = "$h2" ] && [ "$n0" = 6 ] && [ "$n2" = 6 ]; then ok "T03-idempotent (6 lines incl. -N, sha unchanged x2)"; else bad "T03-idempotent"; fi

echo "== T04 other DOCKER-USER rules (incl. a quoted comment) are kept, in order, RETURN stays last"
"$REAL_IPT" -w -I DOCKER-USER 1 -s 192.0.2.10/32 -m comment --comment "operator rule one" -j DROP
"$REAL_IPT" -w -I DOCKER-USER 2 -p tcp --dport 8080 -j DROP
run_script; show
got="$(rules | tail -n +2)"
want4='-A DOCKER-USER -s 192.0.2.10/32 -m comment --comment "operator rule one" -j DROP
-A DOCKER-USER -p tcp -m tcp --dport 8080 -j DROP'$'\n'"$WANT_TAIL"
if [ "$SC_RC" = 0 ] && [ "$got" = "$want4" ]; then ok "T04-foreign-kept"; else bad "T04-foreign-kept"; fi
expect_check T04-check 0 "OK:"
"$REAL_IPT" -w -D DOCKER-USER -s 192.0.2.10/32 -m comment --comment "operator rule one" -j DROP
"$REAL_IPT" -w -D DOCKER-USER -p tcp --dport 8080 -j DROP

echo "== T05 host set up with the old guide commands twice (duplicates): script leaves one clean set"
old_guide
for c in "-I DOCKER-USER -j RETURN" "-I DOCKER-USER -p tcp --dport 2559 -m state --state NEW -j DROP"; do
  # shellcheck disable=SC2086
  "$REAL_IPT" -w $c
done
echo "  before: $(rules | wc -l) lines"; expect_check T05-dup-control 1 "FAIL: TCP 2559 rules missing, changed or out of order"
run_script
if [ "$SC_RC" = 0 ] && [ "$(rules | tail -n +2)" = "$WANT_TAIL" ]; then ok "T05-dedup"; else bad "T05-dedup"; fi
expect_check T05-check 0 "OK:"

echo "== T06 one rule lost (connlimit): check must fail"
"$REAL_IPT" -w -D DOCKER-USER -p tcp --dport 2559 -m connlimit --connlimit-above 50 -j DROP
expect_check T06-missing-rule 1 "FAIL: TCP 2559 rules missing, changed or out of order"
run_script; expect_check T06-repaired 0 "OK:"

echo "== T07 weakened limit (100/s -> 1000/s): check must fail, script restores"
"$REAL_IPT" -w -R DOCKER-USER 3 -p tcp --dport 2559 -m state --state NEW -m limit --limit 1000/second --limit-burst 50 -j ACCEPT
expect_check T07-changed-limit 1 "FAIL: TCP 2559 rules missing, changed or out of order"
run_script; expect_check T07-repaired 0 "OK:"

echo "== T08 RETURN inserted first (all 2559 rules dead): check must fail"
"$REAL_IPT" -w -I DOCKER-USER 1 -j RETURN
expect_check T08-return-first 1 "FAIL: RETURN must appear once, as the last rule"
run_script; expect_check T08-repaired 0 "OK:"

echo "== T09 a rule appended after RETURN: check must fail, script moves RETURN last again"
"$REAL_IPT" -w -A DOCKER-USER -p tcp --dport 8080 -j DROP
expect_check T09-rule-after-return 1 "FAIL: RETURN must appear once, as the last rule"
run_script; show; expect_check T09-repaired 0 "OK:"
"$REAL_IPT" -w -D DOCKER-USER -p tcp --dport 8080 -j DROP

echo "== T10 rules fine but the unit is not enabled: check must fail"
STUB_ENABLED=0 run_check
if [ "$CK_RC" = 1 ] && [[ "$CK_OUT" == *"FAIL: postfiat-docker-user.service is not enabled"* ]]; then ok "T10-unit-disabled"; else bad "T10-unit-disabled"; fi

echo "== T11 rules ordered differently (ESTABLISHED moved below DROP): check must fail"
"$REAL_IPT" -w -D DOCKER-USER -p tcp --dport 2559 -m state --state ESTABLISHED,RELATED -j ACCEPT
"$REAL_IPT" -w -I DOCKER-USER 4 -p tcp --dport 2559 -m state --state ESTABLISHED,RELATED -j ACCEPT
expect_check T11-order 1 "FAIL: TCP 2559 rules missing, changed or out of order"
run_script; expect_check T11-repaired 0 "OK:"

echo "== T12 fail-closed apply: an iptables -A error makes the script exit non-zero"
STUB_FAIL_OP=-A run_script
if [ "$SC_RC" != 0 ] && [[ "$SC_OUT" == *"injected failure on -A"* ]]; then ok "T12-append-error rc=$SC_RC"; else bad "T12-append-error"; fi
expect_check T12-state-is-flagged 1 "FAIL:"

echo "== T13 fail-closed apply: an iptables -D error inside the delete loop makes the script exit non-zero"
run_script >/dev/null
STUB_FAIL_OP=-D run_script
if [ "$SC_RC" != 0 ] && [[ "$SC_OUT" == *"injected failure on -D"* ]]; then ok "T13-delete-error rc=$SC_RC"; else bad "T13-delete-error"; fi
run_script; expect_check T13-repaired 0 "OK:"

echo "RESULT: $PASS passed, $FAILN failed"
[ "$FAILN" = 0 ]
