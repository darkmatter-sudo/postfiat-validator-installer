#!/usr/bin/env python3
"""Tests for specdrill.py against hand-computed fixtures.

Run: python3 -m pytest -q specdrill/tests   (or python3 -m unittest discover specdrill/tests)
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SD = os.path.dirname(HERE)
sys.path.insert(0, SD)
import specdrill

HELPER = os.path.join(SD, "specdrill.py")

META = {
    "cell": "cpu-0.5",
    "axis": "cpu",
    "cpus": 0.5,
    "mem_mib": 2048,
    "io_bps": 0,
    "start": 1000,
    "full_deadline_s": 600,
    "window_s": 60,
    "end": 1100,
    "abort": None,
    "oom_killed": False,
    "restarts": 0,
    "peak_rss_bytes": 700 * 1024 * 1024,
}


def smp(t, state, seq=None, close=None, ref=None, peers=None, live_state="full", live_lag=0):
    return {
        "t": t,
        "state": state,
        "seq": seq,
        "close": close,
        "ref_seq": ref,
        "peers": peers,
        "live_state": live_state,
        "live_lag": live_lag,
    }


# Hand-computed: full at t=1030 -> time_to_full 30 s; window [1030, 1090] holds 5 samples with lags 1,0,2,0,3
# (sorted 0,0,1,2,3): nearest-rank p50 = 3rd = 1, p95 = ceil(4.75) = 5th = 3, max 3 -> 3 > LAG_P95_MAX 2 = FAIL.
# Distinct validated ledgers (100,5000) (102,5008) (105,5020) (106,5025): per-ledger intervals 4, 4, 5,
# mean 13/3, population stddev sqrt(2/9) = 0.471. Peers 8,9,9,10,10: min 8, p50 3rd = 9. t=1100 is outside.
SAMPLES = [
    smp(1000, "connected"),
    smp(1030, "full", 100, 5000, 101, 8),
    smp(1040, "full", 102, 5008, 102, 9),
    smp(1050, "full", 102, 5008, 104, 9),
    smp(1060, "full", 105, 5020, 105, 10),
    smp(1090, "full", 106, 5025, 109, 10, live_lag=1),
    smp(1100, "full", 120, 5090, 140, 1),
]


class TestMetrics(unittest.TestCase):
    def test_percentile_nearest_rank(self):
        self.assertEqual(specdrill.percentile([3, 0, 2, 0, 1], 50), 1)
        self.assertEqual(specdrill.percentile([3, 0, 2, 0, 1], 95), 3)
        self.assertEqual(specdrill.percentile([7], 95), 7)
        self.assertIsNone(specdrill.percentile([], 50))

    def test_summarize_hand_computed(self):
        c = specdrill.summarize(META, SAMPLES)
        self.assertEqual(c["time_to_full_s"], 30)
        self.assertEqual(c["window_samples"], 5)
        self.assertEqual((c["lag_p50"], c["lag_p95"], c["lag_max"]), (1, 3, 3))
        self.assertEqual(c["close_jitter_s"], 0.471)
        self.assertEqual((c["peers_min"], c["peers_p50"]), (8, 9))
        self.assertEqual(c["peak_rss_mib"], 700.0)
        self.assertEqual(c["verdict"], "FAIL")
        self.assertEqual(c["reasons"], ["lag_p95>2"])
        self.assertTrue(c["live_full_all"])
        self.assertEqual(c["live_lag_max"], 1)

    def test_lag_p95_at_limit_passes(self):
        s = [x if x["t"] != 1090 else smp(1090, "full", 106, 5025, 108, 10) for x in SAMPLES]  # lag 3 -> 2
        c = specdrill.summarize(META, s)
        self.assertEqual(c["lag_p95"], 2)
        self.assertEqual(c["verdict"], "PASS")

    def test_never_full_slow_full_oom_restart_abort(self):
        c = specdrill.summarize(META, [smp(1000, "connected"), smp(1500, "syncing")])
        self.assertEqual(c["reasons"], ["never_full"])
        c = specdrill.summarize(dict(META, full_deadline_s=20), SAMPLES)
        self.assertEqual(c["reasons"], ["slow_full"])
        c = specdrill.summarize(dict(META, oom_killed=True, restarts=2, abort="live_lag"), SAMPLES)
        self.assertEqual(c["reasons"][:3], ["aborted:live_lag", "oom_killed", "restarts=2"])
        self.assertEqual(c["verdict"], "FAIL")

    def test_single_restart_fails(self):
        c = specdrill.summarize(dict(META, restarts=1), SAMPLES)
        self.assertEqual((c["reasons"][0], c["verdict"]), ("restarts=1", "FAIL"))

    def test_full_without_ledger_samples(self):
        # full at 1030 but no sample in the window carries seq/ref_seq -> no lag data -> FAIL, not a vacuous PASS
        c = specdrill.summarize(META, [smp(1000, "connected"), smp(1030, "full", peers=8), smp(1040, "full", peers=8)])
        self.assertEqual((c["window_samples"], c["reasons"], c["verdict"]), (0, ["no_window_samples"], "FAIL"))

    def test_cell_ahead_of_reference_clamped(self):
        # the public reference answered one ledger behind the cell: lag -1 -> 0 (p50/max 0, not negative)
        s = [smp(1000, "connected"), smp(1030, "full", 101, 5000, 100, 8), smp(1040, "full", 102, 5004, 102, 8)]
        c = specdrill.summarize(META, s)
        self.assertEqual((c["lag_p50"], c["lag_max"], c["window_samples"]), (0, 0, 2))

    def test_jitter_needs_two_intervals(self):
        self.assertIsNone(specdrill.close_jitter([smp(1, "full", 1, 10), smp(2, "full", 2, 14)]))

    def test_live_not_full_recorded(self):
        s = SAMPLES[:-1] + [smp(1100, "full", 120, 5090, 140, 1, live_state="syncing")]
        self.assertFalse(specdrill.summarize(META, s)["live_full_all"])


def cell(name, axis, val, verdict):
    base = {"cpus": 2, "mem_mib": 2048, "io_bps": 0}
    base[specdrill.AXIS_FIELD[axis]] = val
    return dict(base, cell=name, axis=axis, verdict=verdict, reasons=[] if verdict == "PASS" else ["never_full"])


NULLS = dict.fromkeys(
    ("time_to_full_s", "lag_p50", "lag_p95", "lag_max", "close_jitter_s", "peers_min", "peak_rss_mib"), None
)
NULLS.update(live_full_all=True, live_lag_max=0)


class TestSpecs(unittest.TestCase):
    def test_min_and_safe(self):
        cells = [
            cell("c1", "cpu", 0.25, "FAIL"),
            cell("c2", "cpu", 0.5, "PASS"),
            cell("c3", "cpu", 1, "PASS"),
            cell("c4", "cpu", 2, "PASS"),
        ]
        s = specdrill.axis_spec(cells, "cpu")
        self.assertEqual((s["minimum"], s["safe"], s["failing"]), (0.5, 1, ["c1"]))
        self.assertTrue(s["bounded"])

    def test_no_failure_below_is_not_a_floor(self):
        cells = [cell("c2", "cpu", 0.5, "PASS"), cell("c3", "cpu", 1, "PASS"), cell("c4", "cpu", 2, "PASS")]
        s = specdrill.axis_spec(cells, "cpu")
        self.assertEqual((s["minimum"], s["safe"], s["failing"], s["bounded"]), (0.5, 1, [], False))
        rep = specdrill.render_report([dict(c, **NULLS) for c in cells], [s])
        self.assertIn("| cpu | <= 0.5 vCPU (`c2`, lowest tested: no failing cell below) | 1 vCPU (`c3`) | - |", rep)

    def test_pass_below_a_failure_not_trusted(self):
        cells = [
            cell("c1", "cpu", 0.25, "FAIL"),
            cell("c2", "cpu", 0.5, "PASS"),
            cell("c3", "cpu", 1, "FAIL"),
            cell("c4", "cpu", 2, "PASS"),
        ]
        s = specdrill.axis_spec(cells, "cpu")
        self.assertEqual((s["minimum"], s["safe"]), (2, 2))

    def test_none_passed_and_absent_axis(self):
        s = specdrill.axis_spec([cell("m1", "mem", 512, "FAIL")], "mem")
        self.assertIsNone(s["minimum"])
        self.assertIsNone(specdrill.axis_spec([], "io"))


class TestCli(unittest.TestCase):
    def write_cell(self, root, meta, samples):
        d = os.path.join(root, meta["cell"])
        os.makedirs(d)
        with open(os.path.join(d, "meta.json"), "w") as f:
            json.dump(meta, f)
        with open(os.path.join(d, "samples.jsonl"), "w") as f:
            f.write("".join(json.dumps(s) + "\n" for s in samples))
        return d

    def test_report_is_deterministic(self):
        with tempfile.TemporaryDirectory() as t:
            root = os.path.join(t, "cells")
            self.write_cell(root, META, SAMPLES)
            self.write_cell(root, dict(META, cell="cpu-1", cpus=1), SAMPLES[:-2] + [smp(1090, "full", 106, 5025, 106)])
            outs = []
            for n in ("a", "b"):
                r = subprocess.run(
                    [sys.executable, "-I", HELPER, "report", root, os.path.join(t, n)], capture_output=True, text=True
                )
                self.assertEqual(r.returncode, 0, r.stderr)
                outs.append({f: open(os.path.join(t, n, f)).read() for f in ("cells.json", "cells.csv", "REPORT.md")})
            self.assertEqual(outs[0], outs[1])
            rep = outs[0]["REPORT.md"]
            self.assertIn("| cpu | 1 vCPU (`cpu-1`) | 1 vCPU (`cpu-1`) | `cpu-0.5` (lag_p95>2) |", rep)
            self.assertIn("## Limits of this measurement", rep)
            self.assertEqual(outs[0]["cells.csv"].splitlines()[0], ",".join(specdrill.CSV_COLS))
            # cells in name order (cpu-0.5 < cpu-1), independent of directory listing order
            self.assertEqual([c["cell"] for c in json.loads(outs[0]["cells.json"])["cells"]], ["cpu-0.5", "cpu-1"])
            self.assertEqual([r.split(",")[0] for r in outs[0]["cells.csv"].splitlines()[1:]], ["cpu-0.5", "cpu-1"])

    def test_report_without_cells_exits_2(self):
        with tempfile.TemporaryDirectory() as t:
            r = subprocess.run(
                [sys.executable, "-I", HELPER, "report", t, os.path.join(t, "o")], capture_output=True, text=True
            )
            self.assertEqual(r.returncode, 2)
            self.assertFalse(os.path.exists(os.path.join(t, "o")))

    def test_live_gate(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "s.jsonl")

            def gate(rows, max_lag=3, polls=2):
                with open(p, "w") as f:
                    f.write("".join(json.dumps(r) + "\n" for r in rows))
                return subprocess.run(
                    [sys.executable, "-I", HELPER, "live-gate", p, str(max_lag), str(polls)],
                    capture_output=True,
                    text=True,
                ).returncode

            self.assertEqual(gate([smp(1, "full", live_lag=4)]), 0)  # fewer than POLLS samples
            self.assertEqual(gate([smp(1, "full", live_lag=4), smp(2, "full", live_lag=3)]), 0)  # 3 == max: ok
            self.assertEqual(gate([smp(1, "full", live_lag=4), smp(2, "full", live_lag=5)]), 1)
            self.assertEqual(gate([smp(1, "full", live_state="syncing"), smp(2, "full", live_lag=9)]), 1)
            self.assertEqual(gate([smp(1, "full", live_lag=0)], polls=0), 3)  # POLLS 0 would read the whole file

    def test_usage_exit_3(self):
        r = subprocess.run([sys.executable, "-I", HELPER], capture_output=True, text=True)
        self.assertEqual(r.returncode, 3)


if __name__ == "__main__":
    unittest.main()
