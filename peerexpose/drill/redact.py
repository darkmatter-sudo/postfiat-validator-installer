#!/usr/bin/env python3
"""Redaction for published peerexpose drill logs.

  redact.py filter  --literals FILE  < raw > published      replace secrets line by line (flushes every line)
  redact.py check   --literals FILE  LOG                     count what is left in LOG; exit 1 if anything is
  redact.py control --literals FILE                          positive control: build one synthetic line per literal
                                                             and per pattern kind, prove check finds each one
                                                             BEFORE filter and none AFTER; exit 1 otherwise

FILE holds one "kind<TAB>value" per line (kind: ip, key, topic, user). It is written by live-run.sh into a 0700
temp dir from values read on the hosts (host addresses, node pubkeys, throwaway topics) and is never printed.
Literals are replaced first (longest first), then patterns catch values nobody listed:
  IPv4 / IPv6 addresses (validated with ipaddress, boundaries required, loopback and unspecified kept),
  node public keys (n + 51 base58 chars), ED25519 publisher keys (ED + 64 hex).
Output never contains a matched value: check and control print kinds and counts only.
"""
import argparse
import ipaddress
import re
import sys

LABEL = {"ip": "<redacted-ip>", "key": "<redacted-key>", "topic": "<redacted>", "user": "<user>"}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NODE_KEY = re.compile(r"(?<![0-9A-Za-z])n[%s]{51}(?![0-9A-Za-z])" % B58)
ED_KEY = re.compile(r"(?<![0-9A-Za-z])ED[0-9A-Fa-f]{64}(?![0-9A-Za-z])")
V4 = re.compile(r"(?<![0-9A-Za-z.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z]|\.\d)")
# candidate IPv6: hex groups with at least two colons, no alnum/colon right before or after
V6 = re.compile(r"(?<![0-9A-Za-z:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:])")


def load_literals(path):
    out = []
    with open(path) as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if not ln or "\t" not in ln:
                continue
            kind, val = ln.split("\t", 1)
            if kind in LABEL and len(val) >= 3:
                out.append((kind, val))
    out.sort(key=lambda kv: -len(kv[1]))
    return out


def _ip_ok(s):
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified)


def _sub_ip(rx, line):
    return rx.sub(lambda m: LABEL["ip"] if _ip_ok(m.group(1)) else m.group(0), line)


def redact(line, literals):
    for kind, val in literals:
        line = line.replace(val, LABEL[kind])
    line = NODE_KEY.sub(LABEL["key"], line)
    line = ED_KEY.sub(LABEL["key"], line)
    line = _sub_ip(V4, line)
    line = _sub_ip(V6, line)
    return line


def findings(text, literals):
    """kind -> count of values still present in text (literal kinds plus pattern kinds)."""
    c = {}
    for kind, val in literals:
        n = text.count(val)
        if n:
            c["literal:" + kind] = c.get("literal:" + kind, 0) + n
    for name, rx in (("node_key", NODE_KEY), ("ed_key", ED_KEY)):
        n = len(rx.findall(text))
        if n:
            c[name] = n
    for name, rx in (("ipv4", V4), ("ipv6", V6)):
        n = sum(1 for m in rx.finditer(text) if _ip_ok(m.group(1)))
        if n:
            c[name] = n
    return c


def cmd_filter(lit):
    for ln in sys.stdin:
        sys.stdout.write(redact(ln, lit))
        sys.stdout.flush()
    return 0


def cmd_check(lit, log):
    with open(log, errors="replace") as f:
        text = f.read()
    c = findings(text, lit)
    kinds = sorted(set(k for k, _ in lit))
    print("redaction check: %d literal(s) (%s), %d line(s) scanned" % (len(lit), ",".join(kinds) or "none", text.count("\n")))
    if not c:
        print("REDACTION: CLEAN (0 literals, 0 pattern hits)")
        return 0
    for k in sorted(c):
        print("  LEFT %s: %d" % (k, c[k]))
    print("REDACTION: LEAK (%d)" % sum(c.values()))
    return 1


def cmd_control(lit):
    """Synthetic line per literal and per pattern kind: must be found before, gone after."""
    cases = [("literal:" + k, "control %s value=%s port=2559" % (k, v)) for k, v in lit]
    cases += [
        ("node_key", "control pubkey_node=n" + (B58 * 2)[:51]),
        ("ed_key", "control publisher=ED" + "A1" * 32),
        ("ipv4", "control peer 198.51.100.23:51235"),
        ("ipv6", "control peer [2001:db8::17]:2559"),
    ]
    ok = 0
    for want, line in cases:
        before = findings(line, lit)
        after = findings(redact(line, lit), lit)
        good = want in before and not after
        ok += good
        print("  %s control %-14s found before: %-3s left after: %s" % (
            "PASS" if good else "FAIL", want, "yes" if want in before else "NO", sum(after.values())))
    # negatives: things that look similar but must stay
    keep = ["build 1.0.9 ledger 7545048", "2026-10-28T03:07:55Z gate 03:07:55 ok", "ConsensusPhase::accepted", "admin 127.0.0.1:5005", "sha256 a8e2420c9b57c367"]
    for line in keep:
        same = redact(line, lit) == line
        ok += same
        print("  %s keep    %-30s unchanged: %s" % ("PASS" if same else "FAIL", line[:30], "yes" if same else "NO"))
    n = len(cases) + len(keep)
    print("REDACTION CONTROL: %s (%d/%d)" % ("PASS" if ok == n else "FAIL", ok, n))
    return 0 if ok == n else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["filter", "check", "control"])
    ap.add_argument("log", nargs="?")
    ap.add_argument("--literals", required=True)
    a = ap.parse_intermixed_args()
    lit = load_literals(a.literals)
    if a.cmd == "filter":
        return cmd_filter(lit)
    if a.cmd == "check":
        if not a.log:
            ap.error("check needs LOG")
        return cmd_check(lit, a.log)
    return cmd_control(lit)


if __name__ == "__main__":
    sys.exit(main())
