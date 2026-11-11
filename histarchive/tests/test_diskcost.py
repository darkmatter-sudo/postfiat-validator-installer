#!/usr/bin/env python3
"""Fixture tests for diskcost.py (stdlib unittest; hand-computed expected values).

Run: TMPDIR=$HOME/.cache python3 -m unittest -v tests/test_diskcost.py (from histarchive/)
"""

import contextlib
import gzip
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import diskcost as dc

T = 847600000  # ripple time


def header(seq, close):
    """118-byte header: seq, drops, parent, tx root, state root, parent close, close, resolution, flags."""
    b = seq.to_bytes(4, "big") + (10**17).to_bytes(8, "big") + bytes(96)
    b += (close - 3).to_bytes(4, "big") + close.to_bytes(4, "big") + bytes([10, 0])
    assert len(b) == 118
    return b.hex().upper()


def write_day(arc, day, first, closes, gz_bytes, raw_bytes):
    lines = "".join(
        json.dumps({"i": first + k, "h": "00" * 32, "d": header(first + k, c), "t": []})
        + "\n"
        for k, c in enumerate(closes)
    )
    seg = f"segments/{day}.jsonl.gz"
    with gzip.open(os.path.join(arc, seg), "wt") as f:
        f.write(lines)
    entry = {
        "day": day,
        "segment": seg,
        "count": len(closes),
        "first": first,
        "last": first + len(closes) - 1,
        "txs": 2,
        "bytes_gz": gz_bytes,
        "bytes_raw": raw_bytes,
    }
    with open(os.path.join(arc, "MANIFEST.jsonl"), "a") as f:
        f.write(json.dumps(entry) + "\n")


class DiskCost(unittest.TestCase):
    def setUp(self):
        base = os.environ.get("TEST_TMPDIR") or os.path.join(
            os.path.expanduser("~"), ".cache"
        )
        os.makedirs(base, exist_ok=True)
        self.d = tempfile.mkdtemp(prefix="ha-diskcost-", dir=base)
        self.arc = os.path.join(self.d, "archive")
        os.makedirs(os.path.join(self.arc, "segments"))
        os.makedirs(os.path.join(self.arc, "active"))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_close_time_reads_bytes_112_to_116(self):
        self.assertEqual(dc.close_time(header(5, T)), T + dc.RIPPLE_EPOCH)

    def test_two_days_totals_and_projection(self):
        # day A: 3 ledgers, closes T, T+3, T+9 (span 9, off-centre); day B: 5 ledgers, span 12
        write_day(self.arc, "2026-11-09", 100, [T, T + 3, T + 9], 800, 4000)
        write_day(
            self.arc,
            "2026-11-10",
            103,
            [T + 12, T + 15, T + 18, T + 21, T + 24],
            1200,
            5000,
        )
        with open(os.path.join(self.arc, "active", "2026-11-11.jsonl"), "w") as f:
            f.write("x" * 70)
        r = dc.measure(self.arc)
        a, b = r["archive"]["sealed_days"]
        self.assertEqual((a["close_span_s"], b["close_span_s"]), (9, 12))
        self.assertEqual((a["ratio"], b["ratio"]), (5.0, 4.17))
        t = r["archive"]["totals"]
        self.assertEqual(t["ledgers"], 8)
        self.assertEqual(t["gz_bytes_per_ledger"], 250.0)  # (800 + 1200) / 8
        self.assertEqual(t["raw_bytes_per_ledger"], 1125.0)  # 9000 / 8
        self.assertEqual(t["ledgers_per_s"], 0.2857)  # (8 - 2) intervals / 21 s
        self.assertEqual(
            t["projected_ledgers_per_day"], 24686
        )  # 6 / 21 * 86400 = 24685.71
        self.assertEqual(t["projected_gz_bytes_per_day"], 6171429)  # 24685.71 * 250
        self.assertEqual(t["projected_gz_bytes_365d"], 2252571429)
        self.assertEqual(r["archive"]["active_bytes"], 70)

    def test_nothing_sealed_exits_2(self):
        open(os.path.join(self.arc, "MANIFEST.jsonl"), "w").close()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = dc.main(["--dir", self.arc])
        self.assertEqual(rc, 2)
        self.assertIn("nothing to project", out.getvalue())

    def test_unreadable_manifest_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = dc.main(["--dir", os.path.join(self.d, "missing")])
        self.assertEqual(rc, 2)
        self.assertIn("cannot measure", err.getvalue())

    def test_replica_bytes(self):
        rep = os.path.join(self.d, "replica")
        os.makedirs(rep)
        for name, n in (("a.age", 11), ("REPLICA.json", 4)):
            with open(os.path.join(rep, name), "w") as f:
                f.write("y" * n)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = dc.main(["--replica", rep, "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(
            json.loads(out.getvalue()), {"replica_bytes": 15, "replica_files": 2}
        )


if __name__ == "__main__":
    unittest.main()
