#!/usr/bin/env python3
"""Independent sequence check of a histarchive directory (stdlib only, imports nothing from histarchive.py
or lib_hashverify.py, so a bug shared by the tool and its own verify cannot hide here).

It reads every ledger line from segments/*.jsonl.gz (as listed in MANIFEST.jsonl, fill segments included)
and active/*.jsonl, then checks:
  - no ledger index appears twice;
  - the 4-byte header sequence equals the line's index;
  - sha512("LWR\\0" + header)[:32] equals the line's hash;
  - for every present pair (i, i+1): header bytes 12..44 of i+1 (parent hash) equal the hash of i;
  - the missing indexes between first and last are exactly the gaps.jsonl ranges that have no
    MANIFEST fill entry (and a filled range is fully present).
The transaction-tree root is NOT rebuilt here (that is histarchive verify's job, via lib_hashverify).
Exit 0 PASS, 1 FAIL. Usage: python3 seqcheck.py ARCHIVE_DIR
"""

import gzip
import hashlib
import json
import os
import sys


def lines_of(raw):
    return [json.loads(x) for x in raw.split(b"\n") if x.strip()]


def main(root):
    man = []
    if os.path.exists(os.path.join(root, "MANIFEST.jsonl")):
        with open(os.path.join(root, "MANIFEST.jsonl")) as fh:
            man = [json.loads(x) for x in fh if x.strip()]
    recs, fails = {}, []
    sources = [(e["segment"], True) for e in man]
    adir = os.path.join(root, "active")
    if os.path.isdir(adir):
        sources += [
            (f"active/{f}", False)
            for f in sorted(os.listdir(adir))
            if f.endswith(".jsonl")
        ]
    for rel, gz in sources:
        with open(os.path.join(root, rel), "rb") as fh:
            raw = fh.read()
        if (
            not gz and raw and not raw.endswith(b"\n")
        ):  # the follower is appending right now
            keep = raw.rfind(b"\n") + 1
            print(f"note: {rel}: in-flight last line ignored ({len(raw) - keep} bytes)")
            raw = raw[:keep]
        for r in lines_of(gzip.decompress(raw) if gz else raw):
            i = r["i"]
            if i in recs:
                fails.append(f"ledger {i}: appears twice ({recs[i][0]} and {rel})")
            recs[i] = (rel, r)
    for i, (rel, r) in recs.items():
        d = bytes.fromhex(r["d"])
        if int.from_bytes(d[:4], "big") != i:
            fails.append(f"ledger {i}: header sequence {int.from_bytes(d[:4], 'big')}")
        if hashlib.sha512(b"LWR\x00" + d).digest()[:32].hex().upper() != r["h"].upper():
            fails.append(f"ledger {i}: header hash mismatch")
    links = 0
    for i in sorted(recs):
        if i + 1 in recs:
            links += 1
            parent = bytes.fromhex(recs[i + 1][1]["d"])[12:44].hex().upper()
            if parent != recs[i][1]["h"].upper():
                fails.append(f"ledger {i + 1}: parent hash != hash of {i}")
    gaps = []
    if os.path.exists(os.path.join(root, "gaps.jsonl")):
        with open(os.path.join(root, "gaps.jsonl")) as fh:
            gaps = [
                (int(g["from"]), int(g["to"]))
                for g in map(json.loads, filter(str.strip, fh))
            ]
    filled = {(e["first"], e["last"]) for e in man if e.get("kind") == "fill"}
    want_missing = set()
    for a, b in gaps:
        if (a, b) not in filled:
            want_missing.update(range(a, b + 1))
    lo, hi = (min(recs), max(recs)) if recs else (0, -1)
    missing = {i for i in range(lo, hi + 1) if i not in recs}
    want_missing = {i for i in want_missing if lo <= i <= hi}
    for i in sorted(missing - want_missing)[:20]:
        fails.append(f"ledger {i}: missing and not inside an open recorded gap")
    for i in sorted(want_missing - missing)[:20]:
        fails.append(f"ledger {i}: present although inside an open (unfilled) gap")
    for a, b in sorted(filled):
        if any(i not in recs for i in range(a, b + 1)):
            fails.append(f"filled gap {a}-{b}: not every ledger present")
    for f in fails[:50]:
        print(f"FAIL {f}")
    print(
        f"seqcheck: ledgers {len(recs)} ({lo}-{hi}) sources {len(sources)} parent links {links} "
        f"missing {len(missing)} open-gap ledgers {len(want_missing)} filled gaps {len(filled)}"
    )
    print(f"RESULT: {'PASS' if not fails else 'FAIL'} - fails {len(fails)}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
