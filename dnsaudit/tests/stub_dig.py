#!/usr/bin/env python3
"""Stub dig for the pft-dnsaudit offline tests. Answers are real dig captures (tests/fixtures/HOST/dig/, recorded by
capture.sh) with the queried name swapped in, so the script's parser sees real dig output.

Env: DA_FIX (fixture dir of one host), DA_T (test state dir), DA_NETNS=1 when called through the nsenter stub.
Every call is appended to $DA_T/dig.log as "NETNS SERVER NAME MODE" (MODE: dnssec if +dnssec, noad if +noadflag,
else plain). Known servers: $DA_T/servers (host side) and $DA_T/cservers (container side); any other server
times out. $DA_T/dig.rules lines "NETNS SERVER NAME MODE KIND" (fields may be *) override the defaults, first match
wins. KIND: ad (signed answer, AD set), ok (NOERROR, no AD), servfail, nxdomain, timeout.
Defaults (a host whose upstreams validate): DNSSEC_BAD -> servfail on every path; ietf.org and auth.docker.io
with +dnssec -> ad; *.invalid -> nxdomain; anything else -> ok."""

import os
import sys

BAD = "dnssec-failed.org"
SIGNED = ("ietf.org", "auth.docker.io")


def read(path):
    with open(path) as fh:
        return fh.read()


def lines(path):
    try:
        return [x.split() for x in read(path).splitlines() if x.strip()]
    except FileNotFoundError:
        return []


def main(argv):
    fix, t = os.environ["DA_FIX"], os.environ["DA_T"]
    netns = "1" if os.environ.get("DA_NETNS") == "1" else "0"
    server, name, flags = "", "", set()
    for a in argv:
        if a.startswith("@"):
            server = a[1:]
        elif a.startswith("+"):
            flags.add(a.split("=")[0])
        elif a not in ("A", "AAAA") and not name:
            name = a
    mode = "dnssec" if "+dnssec" in flags else ("noad" if "+noadflag" in flags else "plain")
    with open(os.path.join(t, "dig.log"), "a") as fh:
        fh.write(f"{netns} {server} {name} {mode}\n")
    known = [x[0] for x in lines(os.path.join(t, "cservers" if netns == "1" else "servers"))]
    kind = None
    for r in lines(os.path.join(t, "dig.rules")):
        if len(r) == 5 and all(p in ("*", v) for p, v in zip(r[:4], (netns, server, name, mode))):
            kind = r[4]
            break
    if kind is None:
        if server not in known:
            kind = "timeout"
        elif name == BAD:
            kind = "servfail"
        elif name in SIGNED and mode == "dnssec":
            kind = "ad"
        elif name.endswith(".invalid"):
            kind = "nxdomain"
        else:
            kind = "ok"
    src, orig = {
        "ad": ("upstream1-good-dnssec.txt", "ietf.org"),
        "servfail": ("upstream1-bad-dnssec.txt", BAD),
        "ok": ("upstream1-postfiat.txt", "postfiat.org"),
        "nxdomain": ("upstream1-nxdomain.txt", "pft-control.invalid"),
        "timeout": ("timeout.txt", "postfiat.org"),
    }[kind]
    sys.stdout.write(read(os.path.join(fix, "dig", src)).replace(orig, name))
    return 9 if kind == "timeout" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
