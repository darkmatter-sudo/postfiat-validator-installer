#!/usr/bin/env bash
# Offline tests for pft-dnsaudit.sh, run once per host fixture set (tests/fixtures/validator and .../sentry: real
# captures from both hosts by capture.sh, addresses replaced by documentation addresses). Stubs: dig (stub_dig.py:
# real dig captures with the queried name swapped in), getent, ss, resolvectl, docker (inspect only) and nsenter;
# a fake /proc/<pid>/root and /etc under PFT_DA_ROOT. No root; nothing on the host changes, no network.
# The baseline is a host whose upstreams and paths all validate (every check PASS); every check then gets a control
# input that must make exactly that check WARN/FAIL with its specific reason.
#   bash dnsaudit/tests/run-tests.sh [SCRIPT]   (default ../pft-dnsaudit.sh)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; OUT/RC are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-dnsaudit.sh}"
T="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}")"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; [ -z "${DA_FAILFAST:-}" ] || exit 1; }   # FAILFAST: mutate.py
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }
run() { OUT="$(bash "$S" "$@" 2>&1)"; RC=$?; }
line() { grep -E "^$1 +$2 " <<<"$OUT"; }              # STATUS CHECK -> the audit line (rc 1 if absent)
has() { line "$1" "$2" | grep -qF -- "$3"; }           # STATUS CHECK TEXT
B="$T/bin"; mkdir -p "$B"
export DA_T="$T" PFT_DA_ROOT="$T/root" PFT_DA_CONF="$T/env" PFT_DA_NOW=4070908800 TEXTFILE_DIR="$T/tf"
export PFT_DA_DIG="$B/dig" PFT_DA_GETENT="$B/getent" PFT_DA_SS="$B/ss" PFT_DA_RESOLVECTL="$B/resolvectl"
export PFT_DA_DOCKER="$B/docker" PFT_DA_NSENTER="$B/nsenter" ACCEPT_FILE=/etc/pft-dnsaudit.accept
printf '#!/bin/sh\nexec python3 -I %s "$@"\n' "$HERE/stub_dig.py" > "$B/dig"
cat > "$B/getent" <<'EOF'
#!/bin/bash
[ "$1" = ahosts ] || exit 9
echo "$2" >> "$DA_T/getent.log"
grep -qxF "$2" "$DA_T/getent.fail" 2>/dev/null && exit 2
[ "$2" = dnssec-failed.org ] && [ ! -e "$DA_T/getent.bogus" ] && exit 2
case "$2" in *.invalid) exit 2 ;; esac
sed "s/postfiat\.org/$2/" "$DA_FIX/getent-postfiat.txt"
EOF
cat > "$B/ss" <<'EOF'
#!/bin/sh
case "$*" in "-H -lnu") cat "$DA_T/ss-lnu.txt" ;; "-H -lnt") cat "$DA_T/ss-lnt.txt" ;; *) exit 9 ;; esac
EOF
cat > "$B/resolvectl" <<'EOF'
#!/bin/sh
case "$*" in dns) cat "$DA_T/resolvectl-dns.txt" ;; status) cat "$DA_T/resolvectl-status.txt" ;; *) exit 9 ;; esac
EOF
# docker: inspect -f FORMAT NAME only (the script must never exec into the node container)
cat > "$B/docker" <<'EOF'
#!/bin/bash
echo "$*" >> "$DA_T/docker.log"
[ "$1 $2" = "inspect -f" ] || exit 9
[ -e "$DA_T/cname" ] && [ "$4" = "$(cat "$DA_T/cname")" ] || exit 1
case "$3" in '{{.State.Running}}') echo true ;; '{{.State.Pid}}') echo 4242 ;; '{{.Config.Image}}') cat "$DA_T/image" ;; *) exit 9 ;; esac
EOF
cat > "$B/nsenter" <<'EOF'
#!/bin/bash
[ "$1 $2 $3 $4" = "-t 4242 -n --" ] || { echo "bad nsenter args: $*" >&2; exit 9; }
shift 4; DA_NETNS=1 exec "$@"
EOF
chmod +x "$B"/*

reset() { # HOST: the live capture of HOST, with every path validating (the expected state after the fix)
  local h="$1" F="$HERE/fixtures/$1" C="$T/root/proc/4242/root"
  export DA_FIX="$F"
  rm -rf "$T/root" "$T/tf" "$T"/*.log "$T"/*.txt "$T/dig.rules" "$T/getent.fail" "$T/getent.bogus" "$T/cname"
  mkdir -p "$C/etc/postfiatd" "$T/root/etc/apt/sources.list.d" "$T/root/run/systemd/resolve" "$T/root/etc/pft-watchdog" "$T/tf"
  cp "$F/postfiatd.cfg" "$F/validators.txt" "$C/etc/postfiatd/"; cp "$F/container-resolv.conf" "$C/etc/resolv.conf"
  cp "$F/resolv.conf" "$T/root/run/systemd/resolve/stub-resolv.conf"
  ln -s "$(cat "$F/resolv.conf.target")" "$T/root/etc/resolv.conf"
  cp "$F/sources.list" "$T/root/etc/apt/"; [ -d "$F/sources.list.d" ] && cp "$F"/sources.list.d/* "$T/root/etc/apt/sources.list.d/"
  [ -f "$F/env/postfiat-monitor.env" ] && cp "$F/env/postfiat-monitor.env" "$T/root/etc/"
  [ -f "$F/env/ntfy.env" ] && cp "$F/env/ntfy.env" "$T/root/etc/pft-watchdog/"
  cp "$F/resolvectl-dns.txt" "$F/resolvectl-status.txt" "$F/ss-lnu.txt" "$F/ss-lnt.txt" "$T/"
  sed -E 's/^[^:]*:[[:space:]]*//' "$F/resolvectl-dns.txt" | tr ' ' '\n' | grep -E '^[0-9.]+$' > "$T/servers"
  awk '$1 == "nameserver" { print $2 }' "$F/container-resolv.conf" > "$T/cservers"
  cp "$F/image.txt" "$T/image"
  if [ "$h" = validator ]; then echo postfiatd > "$T/cname"; else echo postfiatd-sentry > "$T/cname"; fi
  printf 'HOST_LABEL=%s\n' "$h" > "$T/env"
}
rule() { echo "$*" >> "$T/dig.rules"; }   # NETNS SERVER NAME MODE KIND
CR="$T/root/proc/4242/root"

for H in validator sentry; do
  if [ "$H" = validator ]; then NN=8; NC=27; else NN=7; NC=26; fi
  echo "== fixtures: $H"
  reset "$H"; run audit
  check "$H baseline: exit 0, RESULT PASS, $NC checks, $NN critical names" \
    '[ "$RC" = 0 ] && grep -q "^RESULT: PASS - $NC checks: .* 0 warn, 0 fail; $NN critical names, 2 upstream resolvers, 0 accepted -> exit 0$" <<<"$OUT"'
  check "$H baseline: names from all five sources" \
    'has PASS source:vl postfiat.org && has PASS source:peer rpc.testnet.postfiat.org && has PASS source:ntfy ntfy.sh && has PASS source:apt security.ubuntu.com && has PASS source:registry registry-1.docker.io'
  check "$H baseline: signed names counted via a validating upstream (1: auth.docker.io)" \
    'has INFO dnssec:signed "1 of $NN critical names are DNSSEC-signed (AD via resolver 1): auth.docker.io"'
  check "$H output never prints a resolver address" '! grep -q "192\.0\.2\." <<<"$OUT"'
  check "$H never runs docker exec (inspect only)" '! grep -qv "^inspect -f " "$T/docker.log"'
  check "$H container-path queries go through nsenter (netns) to the container nameservers" \
    'grep -q "^1 $(head -1 "$T/cservers") rpc.testnet.postfiat.org " "$T/dig.log"'
  if [ "$H" = validator ]; then
    check "validator: trust-ad in the container resolv.conf -> container queries keep AD (no +noadflag)" \
      'grep -q "^1 127.0.0.11 dnssec-failed.org plain$" "$T/dig.log"'
    check "validator: embedded DNS with ExtServers -> PASS" 'has PASS embedded "Docker embedded DNS (127.0.0.11)"'
  else
    check "sentry: no trust-ad -> container queries sent like its glibc (+noadflag)" \
      'grep -q "^1 192.0.2.1 dnssec-failed.org noad$" "$T/dig.log"'
    check "sentry: 2 direct nameservers -> PASS" 'has PASS embedded "2 direct nameservers"'
  fi

  run audit --json
  check "$H --json: valid, result PASS, $NC checks" '[ "$RC" = 0 ] && jq -e --argjson n "$NC" ".result == \"PASS\" and (.checks | length) == \$n" <<<"$OUT" >/dev/null'

  # textfile
  reset "$H"; run audit --textfile; P="$T/tf/pft_dnsaudit_$H.prom"
  check "$H --textfile: writes pft_dnsaudit_$H.prom with up 1 and one status series per check" \
    '[ "$RC" = 0 ] && grep -qx "pft_dnsaudit_up{host=\"$H\"} 1" "$P" && [ "$(grep -c "^pft_dnsaudit_check_status{" "$P")" = "$NC" ]'
  check "$H textfile: counts and gauges" \
    'grep -qx "pft_dnsaudit_checks{host=\"$H\",status=\"fail\"} 0" "$P" && grep -qx "pft_dnsaudit_upstream_resolvers{host=\"$H\"} 2" "$P" && grep -qx "pft_dnsaudit_signed_names{host=\"$H\"} 1" "$P" && grep -qx "pft_dnsaudit_names{host=\"$H\",source=\"apt\"} $([ "$H" = validator ] && echo 3 || echo 2)" "$P"'
  check "$H textfile passes its own pull validation" 'bash "$S" validate "$P" "$H"'
  check "$H textfile has no address" '! grep -q "192\.0\.2\." "$P"'

  # negative control names (.invalid) never write the textfile
  sha0="$(sha256sum < "$P")"
  run audit --name pft-control.invalid
  check "$H control --name pft-control.invalid: exit 1, FAIL resolve with host path reason" \
    '[ "$RC" = 1 ] && has FAIL resolve:pft-control.invalid "host path: no address (extra)"'
  check "$H control run leaves the textfile byte-identical" '[ "$(sha256sum < "$P")" = "$sha0" ]'
  run audit --textfile --name pft-control.invalid
  check "$H --name with --textfile refused (exit 3), textfile unchanged" \
    '[ "$RC" = 3 ] && grep -q "never writes the textfile" <<<"$OUT" && [ "$(sha256sum < "$P")" = "$sha0" ]'
  run audit --name 'bad name!'
  check "$H --name rejects a non-DNS name (exit 3)" '[ "$RC" = 3 ]'

  # sources
  reset "$H"; sed -i '/validator_list_sites/,/^$/d' "$CR/etc/postfiatd/validators.txt" "$CR/etc/postfiatd/postfiatd.cfg"; run audit
  check "$H control source:vl: no [validator_list_sites] -> FAIL no name derived" '[ "$RC" = 1 ] && has FAIL source:vl "no name derived"'
  reset "$H"; sed -i 's/^rpc.testnet.postfiat.org/192.0.2.99/' "$CR/etc/postfiatd/postfiatd.cfg"; run audit
  check "$H control source:peer: IP-only [ips] -> INFO (no DNS dependency), not a finding" \
    'has INFO source:peer "IP literals only" && ! grep -q "resolve:rpc.testnet" <<<"$OUT"'
  reset "$H"; rm -f "$T/root/etc/postfiat-monitor.env" "$T/root/etc/pft-watchdog/ntfy.env"; run audit
  check "$H control source:ntfy: no ntfy env -> FAIL" '[ "$RC" = 1 ] && has FAIL source:ntfy "no name derived"'
  reset "$H"; : > "$T/root/etc/apt/sources.list"; rm -f "$T/root/etc/apt/sources.list.d/"*; run audit
  check "$H control source:apt: no sources -> FAIL" '[ "$RC" = 1 ] && has FAIL source:apt "no name derived"'
  reset "$H"; : > "$T/image"; run audit
  check "$H control source:registry: no image -> FAIL" '[ "$RC" = 1 ] && has FAIL source:registry "no name derived"'
  reset "$H"; echo "ghcr.io/postfiatorg/postfiatd:1.0.9" > "$T/image"; run audit
  check "$H registry host taken from a qualified image reference" 'has PASS source:registry "1 name(s): ghcr.io"'
  reset "$H"; rm -f "$T/cname"; run audit
  check "$H control: node container not running -> FAIL source:vl and embedded (rootfs unreadable)" \
    '[ "$RC" = 1 ] && has FAIL source:vl "not running" && has FAIL embedded "not running"'

  # resolution
  reset "$H"; echo ntfy.sh > "$T/getent.fail"; run audit
  check "$H control resolve: host path fails for ntfy.sh -> FAIL" '[ "$RC" = 1 ] && has FAIL resolve:ntfy.sh "host path: no address (ntfy)"'
  reset "$H"; rule 1 '*' rpc.testnet.postfiat.org '*' timeout; run audit
  check "$H control cresolve: container path times out -> FAIL TIMEOUT" '[ "$RC" = 1 ] && has FAIL cresolve:rpc.testnet.postfiat.org "container path: TIMEOUT"'
  reset "$H"; rule 1 '*' postfiat.org '*' nxdomain; run audit
  check "$H control cresolve: NXDOMAIN on the container path -> FAIL NXDOMAIN" 'has FAIL cresolve:postfiat.org "container path: NXDOMAIN"'

  # redundancy / upstreams
  reset "$H"; sed -i -E 's/^(Link 2 \(eth0\):) ([0-9.]+) [0-9.]+$/\1 \2/' "$T/resolvectl-dns.txt"; run audit
  check "$H control redundancy: 1 upstream -> WARN" '[ "$RC" = 1 ] && has WARN redundancy "1 upstream resolver: no redundancy"'
  reset "$H"; sed -i -E 's/^(Link 2 \(eth0\):).*$/\1/' "$T/resolvectl-dns.txt"; run audit
  check "$H control redundancy: no upstream -> FAIL" 'has FAIL redundancy "no upstream resolver"'
  reset "$H"; rule 0 192.0.2.2 '*' '*' timeout; run audit
  check "$H control upstream:2 unreachable -> FAIL upstream:2 + dnssec:upstream:2, resolver 1 still PASS" \
    '[ "$RC" = 1 ] && has FAIL upstream:2 "postfiat.org: TIMEOUT" && has FAIL dnssec:upstream:2 inconsistent && has PASS upstream:1 answers'
  reset "$H"; rule 0 192.0.2.1 ietf.org dnssec ok; rule 0 192.0.2.1 dnssec-failed.org dnssec ok; run audit
  check "$H control dnssec:upstream:1 non-validating -> FAIL does not validate; signed count via resolver 2" \
    '[ "$RC" = 1 ] && has FAIL dnssec:upstream:1 "does not validate: no AD on ietf.org, NOERROR for dnssec-failed.org" && has INFO dnssec:signed "(AD via resolver 2)"'
  reset "$H"; rule 0 192.0.2.1 ietf.org dnssec ok; run audit
  check "$H control dnssec:upstream:1 no AD on the signed control but SERVFAIL for bogus -> FAIL inconsistent" \
    '[ "$RC" = 1 ] && has FAIL dnssec:upstream:1 "inconsistent: ietf.org NOERROR/qr,rd,ra, dnssec-failed.org SERVFAIL"'
  reset "$H"; rule 0 192.0.2.1 dnssec-failed.org dnssec ok; run audit
  check "$H control dnssec:upstream:1 AD on the signed control but NOERROR for bogus -> FAIL inconsistent" \
    '[ "$RC" = 1 ] && has FAIL dnssec:upstream:1 "inconsistent: ietf.org NOERROR/qr,rd,ra,ad, dnssec-failed.org NOERROR"'
  reset "$H"; rule 0 '*' ietf.org dnssec ok; rule 0 '*' dnssec-failed.org dnssec ok; run audit
  check "$H control: no validating upstream -> signing status unknown" 'has INFO dnssec:signed "no validating upstream"'

  if [ "$H" = sentry ]; then
    reset "$H"; rule 1 192.0.2.1 '*' '*' timeout; run audit
    check "sentry: first container nameserver times out -> the second answers (cresolve + dnssec:container PASS)" \
      '[ "$RC" = 0 ] && has PASS cresolve:postfiat.org NOERROR && has PASS dnssec:container SERVFAIL && grep -q "^1 192.0.2.2 postfiat.org " "$T/dig.log"'
  fi

  # bogus control on the host and container paths
  reset "$H"; touch "$T/getent.bogus"; run audit
  check "$H control dnssec:stub: host path returns the bogus name -> FAIL" \
    '[ "$RC" = 1 ] && has FAIL dnssec:stub "host path returned an address for the DNSSEC-bogus control"'
  reset "$H"; rule 1 '*' dnssec-failed.org '*' ok; run audit
  check "$H control dnssec:container: container path returns the bogus name -> FAIL" \
    '[ "$RC" = 1 ] && has FAIL dnssec:container "container path: NOERROR for the DNSSEC-bogus control"'

  # LLMNR / mDNS
  reset "$H"; echo "UNCONN 0      0            0.0.0.0:5355       0.0.0.0:*" >> "$T/ss-lnu.txt"; run audit
  check "$H control llmnr: udp 5355 listener -> FAIL" '[ "$RC" = 1 ] && has FAIL llmnr "listener open on port 5355"'
  reset "$H"; echo "LISTEN 0      4096         0.0.0.0:5355       0.0.0.0:*" >> "$T/ss-lnt.txt"; run audit
  check "$H control llmnr: tcp 5355 listener -> FAIL" 'has FAIL llmnr "listener open on port 5355"'
  reset "$H"; sed -i '/^Global/,/^$/ s/-LLMNR/+LLMNR/' "$T/resolvectl-status.txt"; run audit
  check "$H control llmnr: resolved global LLMNR on -> WARN" '[ "$RC" = 1 ] && has WARN llmnr "global LLMNR is on"'
  reset "$H"; echo "UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*" >> "$T/ss-lnu.txt"; run audit
  check "$H control mdns: udp 5353 listener -> FAIL" '[ "$RC" = 1 ] && has FAIL mdns "listener open on udp 5353"'
  reset "$H"; echo "LISTEN 0      4096         0.0.0.0:5353       0.0.0.0:*" >> "$T/ss-lnt.txt"; run audit
  check "$H control mdns: a TCP 5353 socket is not mDNS -> PASS" 'has PASS mdns "no 5353 listener"'
  reset "$H"; sed -i '/^Global/,/^$/ s/-mDNS/+mDNS/' "$T/resolvectl-status.txt"; run audit
  check "$H control mdns: resolved global mDNS on -> WARN" 'has WARN mdns "global mDNS is on"'
  reset "$H"; sed -i '/^Global/,/^$/ s/Protocols:.*/Protocols: unknown/' "$T/resolvectl-status.txt"; run audit
  check "$H control llmnr/mdns: global setting unreadable -> WARN" 'has WARN llmnr unreadable && has WARN mdns unreadable'
  reset "$H"; sed -i '/^Global/,/^$/ {/Protocols:/d}' "$T/resolvectl-status.txt"; run audit
  check "$H control llmnr: no global Protocols line -> WARN unreadable (link lines with +LLMNR are not global)" \
    'has WARN llmnr "LLMNR setting unreadable" && has WARN mdns "mDNS setting unreadable"'

  # host stub
  reset "$H"; rm "$T/root/etc/resolv.conf"; printf 'nameserver 192.0.2.1\nnameserver 192.0.2.2\n' > "$T/root/etc/resolv.conf"; run audit
  check "$H control stub: static resolv.conf -> WARN (regular file, 2 nameservers)" \
    '[ "$RC" = 1 ] && has WARN stub "not resolved'"'"'s stub file (regular file, 2 nameserver(s))"'
  reset "$H"; printf 'search .\n' > "$T/root/run/systemd/resolve/stub-resolv.conf"; run audit
  check "$H control stub: no nameserver -> FAIL" 'has FAIL stub "has no nameserver"'
  reset "$H"; printf 'nameserver 127.0.0.53\nnameserver 192.0.2.9\n' > "$T/root/run/systemd/resolve/stub-resolv.conf"; run audit
  check "$H control stub: an extra nameserver next to 127.0.0.53 -> WARN" 'has WARN stub "2 nameserver(s)"'

  # container resolver configuration
  if [ "$H" = validator ]; then
    reset "$H"; sed -i '/^# ExtServers/d' "$CR/etc/resolv.conf"; run audit
    check "validator control embedded: no ExtServers record -> WARN" '[ "$RC" = 1 ] && has WARN embedded "without an ExtServers record"'
  else
    reset "$H"; sed -i '0,/^nameserver/{/^nameserver/d}' "$CR/etc/resolv.conf"; head -1 "$T/cservers" > "$T/c1"; tail -1 "$T/cservers" > "$T/cservers.new"; mv "$T/cservers.new" "$T/cservers"; run audit
    check "sentry control embedded: 1 direct nameserver -> WARN" '[ "$RC" = 1 ] && has WARN embedded "1 direct nameserver"'
  fi
  reset "$H"; sed -i '/^nameserver/d' "$CR/etc/resolv.conf"; run audit
  check "$H control embedded: no nameserver -> FAIL, container checks skipped" \
    '[ "$RC" = 1 ] && has FAIL embedded "has no nameserver" && ! grep -q "dnssec:container\|cresolve:" <<<"$OUT"'

  # operator acceptance (ACCEPT_FILE)
  mkdir -p "$T/root/etc"
  reset "$H"; touch "$T/getent.bogus"; printf 'dnssec:stub 2100-01-01 operator decision 2026-11-28\n' > "$T/root/etc/pft-dnsaudit.accept"; run audit --textfile
  check "$H accept: unexpired line -> INFO accepted, exit 0, pft_dnsaudit_accepted 1" \
    '[ "$RC" = 0 ] && has INFO dnssec:stub "accepted until 2100-01-01T00:00:00Z (operator decision 2026-11-28); was FAIL" && grep -qx "pft_dnsaudit_accepted{host=\"$H\"} 1" "$T/tf/pft_dnsaudit_$H.prom"'
  reset "$H"; touch "$T/getent.bogus"; printf 'dnssec:stub 2000-01-01 old\n' > "$T/root/etc/pft-dnsaudit.accept"; run audit
  check "$H accept: expired line ignored -> FAIL with expiry note" '[ "$RC" = 1 ] && has FAIL dnssec:stub "(acceptance 2000-01-01T00:00:00Z expired)"'
  reset "$H"; touch "$T/getent.bogus"; printf 'dnssec:container 2100-01-01 other check\n' > "$T/root/etc/pft-dnsaudit.accept"; run audit
  check "$H accept: a line for another check does not cover dnssec:stub" '[ "$RC" = 1 ] && has FAIL dnssec:stub "host path returned"'
  reset "$H"; printf 'dnssec:stub 2100-01-01 x\n' > "$T/root/etc/pft-dnsaudit.accept"; run audit
  check "$H accept: never touches a PASS check" '[ "$RC" = 0 ] && has PASS dnssec:stub refuses'
  reset "$H"; touch "$T/getent.bogus"; printf 'dnssec:stub 4070908800 ends exactly now\n' > "$T/root/etc/pft-dnsaudit.accept"; run audit
  check "$H accept: an acceptance ending exactly now (epoch form) is expired" '[ "$RC" = 1 ] && has FAIL dnssec:stub "(acceptance 2099-01-01T00:00:00Z expired)"'
done

# errors and config
reset validator
export PFT_DA_DIG="$T/no-such-dig"; run audit --textfile
check "dig missing: exit 2, textfile up 0 without findings series, no shell error" \
  '[ "$RC" = 2 ] && grep -qx "pft_dnsaudit_up{host=\"validator\"} 0" "$T/tf/pft_dnsaudit_validator.prom" && ! grep -q check_status "$T/tf/pft_dnsaudit_validator.prom" && [ "$OUT" = "pft-dnsaudit: dig, getent or resolvectl unavailable" ]'
export PFT_DA_DIG="$B/dig"
reset validator; export TEXTFILE_DIR="$T/no-such-dir"; run audit --textfile
check "textfile dir not writable: exit 2 (an error, not a finding)" '[ "$RC" = 2 ] && grep -q "cannot write" <<<"$OUT"'
export TEXTFILE_DIR="$T/tf"
reset validator; printf 'HOST_LABEL=Bad Label\n' > "$T/env"; run audit
check "bad HOST_LABEL: exit 3" '[ "$RC" = 3 ]'
reset validator; printf 'HOST_LABEL=validator\nDIG_TIMEOUT=0\n' > "$T/env"; run audit
check "bad DIG_TIMEOUT: exit 3" '[ "$RC" = 3 ]'
reset validator; printf 'HOST_LABEL=validator\nDNSSEC_BAD=-bad-\n' > "$T/env"; run audit
check "bad DNSSEC_BAD: exit 3" '[ "$RC" = 3 ]'
reset validator; printf 'HOST_LABEL=validator\nEXTRA_NAMES="extra.example.org"\n' > "$T/env"; run audit
check "EXTRA_NAMES adds a checked name" 'has PASS resolve:extra.example.org "(extra)"'
reset validator; printf 'HOST_LABEL=validator\nEXTRA_NAMES="ntfy.sh postfiat.org"\n' > "$T/env"; run names
check "names: a name in two sources is listed once, under its first source" \
  '[ "$(grep -c . <<<"$OUT")" = 8 ] && grep -qx "ntfy ntfy.sh" <<<"$OUT" && ! grep -q "^extra " <<<"$OUT"'
reset validator; printf 'NTFY_SERVER="https://ntfy.example.org:8443/base"\n' > "$T/root/etc/postfiat-monitor.env"; run names
check "names: URL host without scheme, port and path" 'grep -qx "ntfy ntfy.example.org" <<<"$OUT"'
reset validator; run names
check "names: SOURCE NAME lines, 8 unique" '[ "$RC" = 0 ] && [ "$(grep -c . <<<"$OUT")" = 8 ] && grep -qx "registry auth.docker.io" <<<"$OUT"'
run bogus-command
check "unknown command: exit 3" '[ "$RC" = 3 ]'

# pull / validate
reset validator; mkdir -p "$T/remote"
PS="$T/remote/pft_dnsaudit_sentry.prom"
printf 'pft_dnsaudit_up{host="sentry"} 1\npft_dnsaudit_last_run_timestamp_seconds{host="sentry"} 4070908800\npft_dnsaudit_check_status{host="sentry",check="stub"} 0\n' > "$PS"
printf 'HOST_LABEL=validator\nPEER_LABEL=sentry\nPULL_SSH=env\n' > "$T/env"
export REMOTE_DIR="$T/remote"; run pull
check "pull: copies a valid peer file" '[ "$RC" = 0 ] && cmp -s "$PS" "$T/tf/pft_dnsaudit_sentry.prom"'
printf 'pft_dnsaudit_up{host="validator"} 1\npft_dnsaudit_last_run_timestamp_seconds{host="validator"} 1\n' > "$PS"; run pull
check "pull: wrong host label -> exit 2, old copy kept" '[ "$RC" = 2 ] && grep -q "first label is not" <<<"$OUT" && grep -q "host=\"sentry\"" "$T/tf/pft_dnsaudit_sentry.prom"'
printf 'node_cpu_seconds_total{host="sentry"} 1\n' > "$PS"; run pull
check "pull: foreign metric -> exit 2" '[ "$RC" = 2 ] && grep -q "not a pft_dnsaudit_ sample" <<<"$OUT"'
printf 'pft_dnsaudit_check_status{host="sentry",check="stub"} 0\n' > "$PS"; run pull
check "pull: no up sample -> exit 2" '[ "$RC" = 2 ] && grep -q "no pft_dnsaudit_up sample" <<<"$OUT"'
printf 'pft_dnsaudit_up{host="sentry"} 1\npft_dnsaudit_last_run_timestamp_seconds{host="sentry"} 1\n' > "$PS"
head -c 40000 /dev/zero | tr '\0' '#' >> "$PS"; run pull
check "pull: oversize file -> exit 2" '[ "$RC" = 2 ] && grep -q "too big" <<<"$OUT"'
rm -f "$PS"; run pull
check "pull: fetch failure -> exit 1" '[ "$RC" = 1 ] && grep -q "fetch of pft_dnsaudit_sentry.prom failed" <<<"$OUT"'
printf 'HOST_LABEL=validator\nPEER_LABEL=sentry\n' > "$T/env"; run pull
check "pull: no PULL_SSH -> exit 3" '[ "$RC" = 3 ]'
check "pull leaves no temp files" '[ -z "$(find "$T/tf" -name ".pull-*")" ]'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
