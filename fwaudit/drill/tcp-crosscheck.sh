#!/usr/bin/env bash
# fwaudit cross-host TCP validation, own two hosts only. Runs on the validator; the sentry is reached as `ssh relay`.
# For each direction (sentry -> validator, validator -> sentry) it asks the TARGET's installed pft-fwaudit for its
# graded exposure (`audit --json`), derives what the PROBER should be able to reach, and then makes one plain TCP
# connect from the prober to every candidate port on the target's public IPv4 and IPv6 address:
#   candidates = every reachable tcp entry of the audit + every non-loopback tcp listener of the target (ss)
#                + CONTROL_PORT (nothing listens there: must be blocked)
#   expected   reach   when the audit says open/limited, or sources and the prober's address is in one of them
#              blocked otherwise (no entry: filtered or nothing listening on that family)
#   observed   connected / refused / timeout (bash /dev/tcp under `timeout`); refused and timeout both count as blocked
# Every (direction, family, port) is one CHECK line; any mismatch is a FAIL. Controls that must hold: v4 tcp/22 is
# expected AND observed reachable in both directions (the probe can see an open port), CONTROL_PORT is expected AND
# observed blocked (the probe can see a closed one), and each prober has a global v4 and v6 address.
# Nothing is changed on either host. No address is printed: output names only direction, family and port, and the
# four host addresses are replaced by <redacted-ip> in everything written (plus a generic IPv4 pattern).
# Connections per target and port: one per family (2 to tcp/22, below fail2ban maxretry 5; each host is in the
# other's ignoreip anyway). Exit 0 all checks PASS, 1 any FAIL, 2 setup error.
# Comparator control: FWXC_FLIP=PORT inverts the expectation for that port (both families, both directions); such a
# run must end RESULT: FAIL with exit 1 (it proves a reach/blocked mismatch is reported, not just computed).
set -uo pipefail
CONTROL_PORT="${CONTROL_PORT:-9}"
FLIP="${FWXC_FLIP:-0}"
TO="${TO:-3}"
RELAY=(ssh -o BatchMode=yes relay)
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRATCH="$(mktemp -d -p "$HOME/.cache" fwxc.XXXXXX)" || exit 2
trap 'rm -rf "$SCRATCH"' EXIT
FAILS=0 CHECKS=0

# the probe, sent to whichever host connects: args TO fam,addr,port ... -> "fam port connected|refused|timeout"
cat > "$SCRATCH/probe.sh" <<'PROBE'
to="$1"; shift
for t in "$@"; do
  IFS=, read -r fam addr port <<<"$t"
  timeout "$to" bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$addr" "$port" 2>/dev/null
  rc=$?
  case "$rc" in 0) r=connected ;; 124) r=timeout ;; *) r=refused ;; esac
  echo "$fam $port $r"
done
PROBE

addrs() { # [remote] -> "V4 V6" (first global address of each family on the default-route interface)
  # shellcheck disable=SC2016 # expanded by the target shell
  local cmd='dev=$(ip -4 route show default | awk "{print \$5; exit}"); a4=$(ip -4 -o addr show dev "$dev" scope global | awk "{print \$4; exit}"); a6=$(ip -6 -o addr show dev "$dev" scope global | awk "{print \$4; exit}"); echo "${a4%/*} ${a6%/*}"'
  if [ "${1:-}" = remote ]; then "${RELAY[@]}" "$cmd" </dev/null; else bash -c "$cmd"; fi
}
read -r V4 V6 <<<"$(addrs)"
read -r S4 S6 <<<"$(addrs remote)"
for a in "$V4" "$V6" "$S4" "$S6"; do [ -n "$a" ] || { echo "SETUP: a host lacks a global v4 or v6 address"; exit 2; }; done

red() { sed -u -e "s/$V4/<redacted-ip>/g; s/$V6/<redacted-ip>/g; s/$S4/<redacted-ip>/g; s/$S6/<redacted-ip>/g" \
  -E -e 's/\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b/<redacted-ip>/g'; }

run_dir() { # NAME TARGET(local|remote) T4 T6 P4 P6 PROBER(local|remote)
  local name="$1" tgt="$2" t4="$3" t6="$4" p4="$5" p6="$6" prb="$7" aj ss rc
  echo "== direction $name"
  if [ "$tgt" = remote ]; then
    aj="$("${RELAY[@]}" sudo -n pft-fwaudit audit --json </dev/null)"; rc=$?
    ss="$("${RELAY[@]}" sudo -n ss -H -tln </dev/null)"
  else
    aj="$(sudo -n pft-fwaudit audit --json)"; rc=$?
    ss="$(sudo -n ss -H -tln)"
  fi
  echo "target audit: rc=$rc verdict=$(jq -r .verdict <<<"$aj" 2>/dev/null) exposure entries=$(jq '.exposure | length' <<<"$aj" 2>/dev/null)"
  if [ "$rc" -gt 2 ] || ! jq -e .exposure >/dev/null 2>&1 <<<"$aj"; then echo "SETUP: target audit failed"; FAILS=$((FAILS + 1)); return; fi
  printf '%s\n' "$aj" > "$SCRATCH/$name.audit.json"
  printf '%s\n' "$ss" > "$SCRATCH/$name.ss"
  # expected table: fam port expect why
  python3 -I - "$SCRATCH/$name.audit.json" "$SCRATCH/$name.ss" "$p4" "$p6" "$CONTROL_PORT" "$FLIP" > "$SCRATCH/$name.expect" <<'PY' || { echo "SETUP: expectation failed"; FAILS=$((FAILS + 1)); return; }
import ipaddress, json, sys
aud, ssf, p4, p6, ctl, flip = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
res = json.load(open(aud))
prober = {"v4": ipaddress.ip_address(p4), "v6": ipaddress.ip_address(p6)}
ports = {ctl}
exp = {}
for e in res["exposure"]:
    if e["proto"] == "tcp":
        exp[(e["family"], e["port"])] = e
        ports.add(e["port"])
for line in open(ssf):
    f = line.split()
    if len(f) < 4:
        continue
    addr, _, port = f[3].rpartition(":")
    addr = addr.split("%")[0].strip("[]")
    if addr != "*" and ipaddress.ip_address(addr).is_loopback:
        continue
    ports.add(int(port))
def expect(fam, port):
    e = exp.get((fam, port))
    if e is None:
        return "blocked", "no-exposure-entry"
    if e["state"] in ("open", "limited"):
        return "reach", e["state"]
    nets = [ipaddress.ip_network(s) for s in e["sources"]]
    if any(prober[fam] in n for n in nets if n.version == prober[fam].version):
        return "reach", "sources(prober-listed)"
    return "blocked", "sources(prober-not-listed)"
for fam in ("v4", "v6"):
    for port in sorted(ports):
        want, why = expect(fam, port)
        if port == flip:
            want, why = {"reach": "blocked", "blocked": "reach"}[want], why + ",FLIPPED-control"
        print(fam, port, want, why)
PY
  local args=() fam port want why
  while read -r fam port want why; do
    if [ "$fam" = v4 ]; then args+=("v4,$t4,$port"); else args+=("v6,$t6,$port"); fi
  done < "$SCRATCH/$name.expect"
  if [ "$prb" = remote ]; then
    "${RELAY[@]}" bash -s -- "$TO" "${args[@]}" < "$SCRATCH/probe.sh" > "$SCRATCH/$name.obs"
  else
    bash "$SCRATCH/probe.sh" "$TO" "${args[@]}" > "$SCRATCH/$name.obs"
  fi
  local ofam oport obs ok22=0 okctl=0 verdict
  while read -r fam port want why && read -r ofam oport obs <&3; do
    [ "$fam $port" = "$ofam $oport" ] || { echo "SETUP: probe output out of order"; FAILS=$((FAILS + 1)); return; }
    CHECKS=$((CHECKS + 1))
    if { [ "$want" = reach ] && [ "$obs" = connected ]; } || { [ "$want" = blocked ] && [ "$obs" != connected ]; }; then
      verdict=PASS
    else
      verdict=FAIL; FAILS=$((FAILS + 1))
    fi
    [ "$fam/$port/$want/$obs" = v4/22/reach/connected ] && ok22=1
    [ "$port" = "$CONTROL_PORT" ] && [ "$want" = blocked ] && [ "$obs" != connected ] && okctl=$((okctl + 1))
    printf 'CHECK %-20s %s tcp/%-5s expect %-7s (%s) observed %-9s %s\n' "$name" "$fam" "$port" "$want" "$why" "$obs" "$verdict"
  done < "$SCRATCH/$name.expect" 3< "$SCRATCH/$name.obs"
  [ "$(wc -l < "$SCRATCH/$name.expect")" = "$(wc -l < "$SCRATCH/$name.obs")" ] \
    || { echo "SETUP: $(wc -l < "$SCRATCH/$name.obs") probe lines for $(wc -l < "$SCRATCH/$name.expect") expectations"; FAILS=$((FAILS + 1)); }
  if [ "$ok22" = 1 ]; then echo "CONTROL $name open-port (v4 tcp/22 expected and observed reachable): PASS"
  else echo "CONTROL $name open-port (v4 tcp/22 expected and observed reachable): FAIL"; FAILS=$((FAILS + 1)); fi
  if [ "$okctl" = 2 ]; then echo "CONTROL $name closed-port (tcp/$CONTROL_PORT v4+v6 expected and observed blocked): PASS"
  else echo "CONTROL $name closed-port (tcp/$CONTROL_PORT v4+v6 expected and observed blocked): FAIL"; FAILS=$((FAILS + 1)); fi
}

main() {
  echo "fwaudit tcp-crosscheck $(date -u +%FT%TZ) script sha256 $(sha256sum "$HERE/tcp-crosscheck.sh" | cut -c1-64)"
  echo "pft-fwaudit: validator $(sudo -n pft-fwaudit version) / sentry $("${RELAY[@]}" sudo -n pft-fwaudit version </dev/null)"
  [ "$FLIP" = 0 ] || echo "COMPARATOR CONTROL RUN: expectation for tcp/$FLIP inverted, this run must FAIL"
  echo "addresses: validator v4 $V4 v6 $V6, sentry v4 $S4 v6 $S6 (redacted); CONTROL_PORT $CONTROL_PORT, connect timeout ${TO}s"
  run_dir sentry-to-validator local "$V4" "$V6" "$S4" "$S6" remote
  run_dir validator-to-sentry remote "$S4" "$S6" "$V4" "$V6" local
  if [ "$FAILS" = 0 ]; then echo "RESULT: PASS - $CHECKS checks, 0 mismatches, controls PASS"
  else echo "RESULT: FAIL - $FAILS failure(s) in $CHECKS checks"; fi
}
main > "$SCRATCH/out" 2>&1 # main runs in this shell (FAILS survives); the redacted copy is printed after
red < "$SCRATCH/out"
[ "$FAILS" = 0 ]
