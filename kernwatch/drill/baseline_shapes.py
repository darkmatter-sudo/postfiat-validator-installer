#!/usr/bin/env python3
"""Group `journalctl -k -o json` records (stdin) by a redacted message shape, for the 24 h baseline investigation.

  journalctl -k --since S --until U -o json | python3 -I baseline_shapes.py [--top N]

The shape is the first 3 words of MESSAGE with interface names, hex runs and numbers replaced, so no address,
port, PID or raw kernel line is printed. Output: "count<TAB>shape" lines, most common first, then a total line.
"""

import argparse
import collections
import json
import re
import sys

IFACE = re.compile(r"\b(veth|br-|eth|ens|enp|docker)[0-9A-Za-z-]*")
HEX = re.compile(r"\b(?=[0-9A-Fa-f]*[A-Fa-f])[0-9A-Fa-f]{6,}\b")  # hex with a letter
NUM = re.compile(r"\d+")


def shape(msg):
    w = " ".join(msg.split()[:3])
    w = IFACE.sub(r"\1<if>", w)
    w = HEX.sub("<hex>", w)
    return NUM.sub("<n>", w)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=25)
    a = ap.parse_args()
    c = collections.Counter()
    bad = 0
    for line in sys.stdin:
        try:
            m = json.loads(line).get("MESSAGE")
        except (ValueError, AttributeError):
            bad += 1
            continue
        if isinstance(m, list):
            m = bytes(m).decode("utf-8", "replace")
        c[shape(m or "")] += 1
    for k, v in c.most_common(a.top):
        print(f"{v}\t{k}")
    print(f"{sum(c.values())}\ttotal records, {len(c)} shape(s), {bad} unparsable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
