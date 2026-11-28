#!/usr/bin/env bash
# Capture the live inputs pft-dnsaudit reads into a fixture directory for the offline tests (run as root on each
# host; read-only: resolvectl/ss/dig/getent and files read through the container's /proc/<pid>/root, no docker exec).
# Every routable IPv4/IPv6 address is replaced by a documentation address (192.0.2.N / 2001:db8::N, one mapping
# per run, consistent across files); loopback/docker-internal addresses are kept. ntfy topics and dig's local
# WHEN: timestamp become <redacted>.
#   sudo bash dnsaudit/tests/capture.sh OUTDIR [CONTAINER]
set -uo pipefail
OUT="${1:?usage: capture.sh OUTDIR [CONTAINER]}"; C="${2:-}"
if [ -z "$C" ]; then for c in postfiatd postfiatd-sentry; do [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && { C="$c"; break; }; done; fi
P="$(docker inspect -f '{{.State.Pid}}' "$C")"; CR="/proc/$P/root"
mkdir -p "$OUT/dig"
red() {
  python3 -I -c '
import re, sys
m = {}
def v4(x):
    a = x.group(0)
    if a.startswith(("127.", "0.", "255.")) or a in ("172.17.0.1",): return a
    return m.setdefault(a, "192.0.2.%d" % (len(m) + 1))
def v6(x):
    a = x.group(0)
    if a in ("::", "::1") or a.startswith(("fe80", "::ffff:127")): return a
    return m.setdefault(a, "2001:db8::%x" % (len(m) + 1))
t = sys.stdin.read()
t = re.sub(r"(?m)^;; WHEN: .*$", ";; WHEN: <redacted>", t)
t = re.sub(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", v4, t)
t = re.sub(r"(?<![0-9A-Za-z:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9A-Za-z:])", v6, t)
t = re.sub(r"(ntfy\.sh/)[A-Za-z0-9_-]{6,}", r"\1<redacted>", t)
t = re.sub(r"(NTFY_TOPIC=).*", r"\1<redacted>", t)
sys.stdout.write(t)'
}
# listeners: only DNS-relevant ports (53, LLMNR 5355, mDNS 5353) and the public 22/2559 are kept, so the fixtures
# never record a host's other (internal) ports
dnsports() { awk '{ n = split($4, a, ":"); if (a[n] ~ /^(22|53|2559|5353|5355)$/) print }'; }
# one redaction mapping for the whole capture: concatenate with separators, redact once, split again
{
  for f in resolvectl-dns resolvectl-status ss-lnu ss-lnt; do
    echo "@@@FILE $f.txt"
    case "$f" in
      resolvectl-dns) resolvectl dns ;; resolvectl-status) resolvectl status ;;
      ss-lnu) ss -H -lnu | dnsports ;; ss-lnt) ss -H -lnt | dnsports ;;
    esac
  done
  echo "@@@FILE container-resolv.conf"; cat "$CR/etc/resolv.conf"
  echo "@@@FILE resolv.conf"; cat /etc/resolv.conf
  echo "@@@FILE resolv.conf.target"; readlink /etc/resolv.conf
  echo "@@@FILE postfiatd.cfg"; awk '/^\[/ { p = ($1 ~ /^\[(ips|ips_fixed|validator_list_sites)\]$/) } p' "$CR/etc/postfiatd/postfiatd.cfg"
  echo "@@@FILE validators.txt"; cat "$CR/etc/postfiatd/validators.txt"
  echo "@@@FILE sources.list"; grep -E '^(deb|deb-src) ' /etc/apt/sources.list
  for f in /etc/apt/sources.list.d/*.list; do [ -f "$f" ] && { echo "@@@FILE sources.list.d/$(basename "$f")"; grep -E '^(deb|deb-src) ' "$f"; }; done
  for f in /etc/postfiat-monitor.env /etc/pft-watchdog/ntfy.env; do [ -f "$f" ] && { echo "@@@FILE env/$(basename "$f")"; grep -E '^NTFY_(SERVER|URL)=' "$f"; }; done
  echo "@@@FILE image.txt"; docker inspect -f '{{.Config.Image}}' "$C"
  i=0
  for s in $(resolvectl dns | sed -E 's/^[^:]*:[[:space:]]*//' | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | awk '!s[$0]++'); do
    i=$((i + 1))
    echo "@@@FILE dig/upstream$i-good-dnssec.txt"; dig +time=3 +tries=1 +dnssec "@$s" ietf.org A
    echo "@@@FILE dig/upstream$i-bad-dnssec.txt"; dig +time=3 +tries=1 +dnssec "@$s" dnssec-failed.org A
    echo "@@@FILE dig/upstream$i-postfiat.txt"; dig +time=3 +tries=1 "@$s" postfiat.org A
  done
  echo "@@@FILE dig/upstream1-nxdomain.txt"; dig +time=3 +tries=1 "@$s" pft-control.invalid A
  echo "@@@FILE dig/timeout.txt"; dig +time=1 +tries=1 @192.0.2.1 postfiat.org A
  echo "@@@FILE getent-postfiat.txt"; getent ahosts postfiat.org
} 2>&1 | red | awk -v d="$OUT" '/^@@@FILE / { f = d "/" $2; system("mkdir -p \"$(dirname " f ")\""); printf "" > f; next } { print >> f }'
find "$OUT" -type f | sort
