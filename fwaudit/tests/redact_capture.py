#!/usr/bin/env python3
"""Turn a real pft-fwaudit capture bundle into a publishable fixture (one shared mapping over all inputs).

- every global IPv4 address -> 203.0.113.N (TEST-NET-3), every global IPv6 address -> 2001:db8::N, numbered in
  order of first appearance across all inputs, so the same host maps to the same fixture address in both files;
- link-local addresses with an interface id (EUI-64 carries the MAC) -> fe80::N; the fe80::/10 rule prefix stays;
- loopback, multicast, private (Docker bridge 172.16/12) and unspecified addresses are kept, they are the
  same on every Docker host and the audit reads them;
- hostnames given with --host are replaced by host-N.
Rule order, chains, ports, interface names and process names stay as captured.

Usage: redact_capture.py OUTDIR [--host NAME]... CAPTURE...   (writes OUTDIR/<same name>; prints only counts)
"""

import ipaddress
import os
import re
import sys

V4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
V6 = re.compile(r"(?<![0-9a-fA-F:])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![0-9a-fA-F:])")


def keep(ip):
    return ip.is_loopback or ip.is_multicast or ip.is_private or ip.is_unspecified


def main(argv):
    out, hosts, files = argv[0], [], []
    i = 1
    while i < len(argv):
        if argv[i] == "--host":
            hosts.append(argv[i + 1])
            i += 2
        else:
            files.append(argv[i])
            i += 1
    m4, m6, ml = {}, {}, {}

    def r4(m):
        s = m.group(1)
        try:
            ip = ipaddress.IPv4Address(s)
        except ValueError:
            return s
        if keep(ip) or s.startswith("255."):
            return s
        return m4.setdefault(s, f"203.0.113.{len(m4) + 1}")

    def r6(m):
        s = m.group(1)
        try:
            ip = ipaddress.IPv6Address(s)
        except ValueError:
            return s
        if ip.is_link_local:
            if ip.compressed == "fe80::":
                return s
            return ml.setdefault(ip.compressed, f"fe80::{len(ml) + 1:x}")
        if keep(ip) or s.lower().startswith("ffff:"):
            return s
        return m6.setdefault(ip.compressed, f"2001:db8::{len(m6) + 1:x}")

    for f in files:
        with open(f, encoding="utf-8") as fh:
            text = fh.read()
        text = V4.sub(r4, text)
        text = V6.sub(r6, text)
        for n, h in enumerate(hosts, 1):
            text = re.sub(re.escape(h), f"host-{n}", text)
        dst = os.path.join(out, os.path.basename(f))
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(f"redacted {len(files)} files: {len(m4)} IPv4, {len(m6)} IPv6, {len(ml)} link-local addresses mapped")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
