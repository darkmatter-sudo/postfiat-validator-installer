#!/usr/bin/env python3
"""Seal memory probe: manifest fields of one day file computed the pre-fix way (read-all) or the streaming way.

Usage: python3 -I tests/seal_probe.py old|new DAY.jsonl HISTARCHIVE_DIR OUT_GZ   (prints the fields as JSON)
Run each mode under `/usr/bin/time -f %M` to compare peak RSS; the two outputs must be byte-identical.
"""

import gzip
import hashlib
import json
import sys

mode, day, repo, out_gz = sys.argv[1:5]
sys.path.insert(0, repo)
import histarchive as ha

# old = the field computation of the pre-fix _seal_day (read the whole day, parse every line)
if mode == "old":
    with open(day, "rb") as fh:
        raw = fh.read()
    lines = [json.loads(x) for x in raw.split(b"\n") if x.strip()]
    gz = gzip.compress(raw, compresslevel=9, mtime=0)
    with open(out_gz, "wb") as fh:
        fh.write(gz)
    out = {
        "count": len(lines),
        "first": lines[0]["i"],
        "last": lines[-1]["i"],
        "last_hash": lines[-1]["h"],
        "txs": sum(len(x.get("t", [])) for x in lines),
        "bytes_raw": len(raw),
        "bytes_gz": len(gz),
        "sha256_raw": hashlib.sha256(raw).hexdigest(),
        "sha256_gz": hashlib.sha256(gz).hexdigest(),
        "first_parent": ha.parse_header(bytes.fromhex(lines[0]["d"]))["parent_hash"],
    }
elif mode == "new":
    st = ha.gzip_day_stream(day, out_gz)
    keys = (
        "count",
        "first",
        "last",
        "last_hash",
        "txs",
        "bytes_raw",
        "bytes_gz",
        "sha256_raw",
        "sha256_gz",
    )
    out = {k: st[k] for k in keys}
    out["first_parent"] = ha.parse_header(bytes.fromhex(st["first_d"]))["parent_hash"]
else:
    sys.exit("mode must be old or new")
print(json.dumps(out, sort_keys=True))
