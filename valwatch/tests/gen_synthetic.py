#!/usr/bin/env python3
"""Tile a real capture into a synthetic retention directory for memory and equivalence runs.

    python3 -I tests/gen_synthetic.py CAPTURE.jsonl.gz OUTDIR HOURS

Copy k of the capture is shifted by k * span in receive time (`r`) and by k * (ledger span) in ledger index, and
every ledger hash is replaced per copy (sha256 of hash + k), so copies never share an (index, hash) pair. The
capture's U record is repeated in the first copy of every UTC hour (the collector rewrites it hourly, and readers
carry it in from at most CARRY_HOURS back); Q records repeat with every copy. Output: hourly
OUTDIR/valwatch-YYYYMMDDTHH.jsonl files, exactly as the collector names them. Deterministic: same input, same bytes.
"""

import gzip
import hashlib
import json
import os
import sys
import time


def main(src, out, hours):
    with gzip.open(src, "rt", encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh]
    rs = [r["r"] for r in recs]
    ii = [r["i"] for r in recs if r["t"] == "L"]
    span_ms = max(rs) - min(rs) + 1000
    span_i = max(ii) - min(ii) + 1
    copies = -(-hours * 3600 * 1000 // span_ms)
    os.makedirs(out, exist_ok=True)
    hashes, fhs = {}, {}
    try:
        for k in range(copies):
            for rec in recs:
                rec = dict(rec)
                rec["r"] += k * span_ms
                if k and rec["t"] == "U" and rec["r"] // 3600000 == (rec["r"] - span_ms) // 3600000:
                    continue
                if "i" in rec:
                    rec["i"] += k * span_i
                if "h" in rec and k:
                    key = (rec["h"], k)
                    if key not in hashes:
                        hashes[key] = hashlib.sha256(f"{rec['h']}{k}".encode()).hexdigest().upper()
                    rec["h"] = hashes[key]
                name = time.strftime("valwatch-%Y%m%dT%H.jsonl", time.gmtime(rec["r"] / 1000))
                if name not in fhs:
                    fhs[name] = open(os.path.join(out, name), "w", encoding="utf-8")  # noqa: SIM115
                fhs[name].write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
    finally:
        for f in fhs.values():
            f.close()
    print(f"copies {copies} files {len(fhs)} span_ms {span_ms} span_ledgers {span_i}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2], int(sys.argv[3])))
