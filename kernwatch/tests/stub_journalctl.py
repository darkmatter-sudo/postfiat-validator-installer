#!/usr/bin/env python3
"""Stub journalctl for the kernwatch tests: serves KW_JOURNAL (JSON lines, one record each) for the argument shapes
kernwatch_parse.py uses: -k -o json --no-pager -q [-b BOOT] [--after-cursor C] [--since @EPOCH|-Nmin] [--until ..] [-n N].
Error texts copied from journalctl 249 on Ubuntu 22.04: 'Failed to seek to cursor: Invalid argument' and
"Failed to add match 'X': Invalid argument" (unknown boot). KW_FAIL=1 fails every call; KW_CALLS appends argv;
KW_IGNORE_BOOT=1 ignores -b (other boots' records leak into the read)."""

import json
import os
import re
import sys
import time

args = sys.argv[1:]
if os.environ.get("KW_CALLS"):
    with open(os.environ["KW_CALLS"], "a") as f:
        f.write(" ".join(args) + "\n")
if os.environ.get("KW_FAIL"):
    print("Failed to open journal: Permission denied", file=sys.stderr)
    sys.exit(1)
recs = []
with open(os.environ["KW_JOURNAL"]) as f:
    for line in f:
        line = line.rstrip("\n")
        try:
            d = json.loads(line)
        except ValueError:
            d = None
        recs.append((line, d))


def opt(name):
    return args[args.index(name) + 1] if name in args else None


boot = opt("-b")
boots = []
for _, d in recs:
    b = d.get("_BOOT_ID") if isinstance(d, dict) else None
    if b and b not in boots:
        boots.append(b)
if boot is not None and boot != "0" and boot not in boots:
    print(f"Failed to add match '{boot}': Invalid argument", file=sys.stderr)
    sys.exit(1)
if boot == "0":
    boot = os.environ.get("KW_CUR_BOOT") or (boots[-1] if boots else None)
ignore = os.environ.get(
    "KW_IGNORE_BOOT"
)  # test: hand out other boots' records too (must be skipped)
sel = [
    (raw, d)
    for raw, d in recs
    if ignore or boot is None or not isinstance(d, dict) or d.get("_BOOT_ID") == boot
]
cur = opt("--after-cursor")
if cur is not None:
    idx = [
        i
        for i, (_, d) in enumerate(sel)
        if isinstance(d, dict) and d.get("__CURSOR") == cur
    ]
    if not idx:
        print("Failed to seek to cursor: Invalid argument", file=sys.stderr)
        sys.exit(1)
    sel = sel[idx[0] + 1 :]
since = opt("--since")
if since is not None:
    m = re.fullmatch(
        r"-(\d+)min", since
    )  # relative form, as passed by `report --since -15min`
    t = (
        int(time.time()) - int(m.group(1)) * 60 if m else int(since.lstrip("@"))
    ) * 1_000_000
    sel = [
        (r, d)
        for r, d in sel
        if not isinstance(d, dict) or int(d.get("__REALTIME_TIMESTAMP", "0") or 0) >= t
    ]
n = opt("-n")
if n is not None:
    sel = sel[-int(n) :]
try:
    for raw, _ in sel:
        sys.stdout.write(raw + "\n")
    sys.stdout.flush()
except BrokenPipeError:
    sys.exit(141)
