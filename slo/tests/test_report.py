"""Offline unit tests for pft_slo_report.py (no Prometheus needed).

Run: python3 -m unittest discover -s slo/tests -v
Real fixtures: tests/fixtures/real-2026-10-23/ are raw /api/v1/query_range responses recorded with
--record from the validator host's Prometheus (2026-10-23T19:00Z-21:00Z, step 60s).
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pft_slo_report as r

FIX = os.path.join(HERE, "fixtures")
REAL = ["--replay", os.path.join(FIX, "real-2026-10-23"), "--start", "2026-10-23T19:00:00Z",
        "--end", "2026-10-23T21:00:00Z", "--step", "60s"]
T0 = 1_800_000_000  # multiple of 60
INST = "node:9877"


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = r.main(argv)
    return rc, out.getvalue(), err.getvalue()


class FakeSource(r.Source):
    """Serves synthetic series: {metric_key: fn(t) -> value or None}; records every query."""

    def __init__(self, fns, objective=None):
        super().__init__("http://unused")
        self.fns, self.objective, self.log = fns, objective, []

    def query_range(self, query, start, end, step):
        self.log.append((query, start, end, step))
        if query == "pft:slo_objective:ratio":
            return [] if self.objective is None else [{"metric": {}, "values": [[end, str(self.objective)]]}]
        key = next(k for k, q in r.QUERIES.items() if q % "postfiat" == query)
        fn = self.fns.get(key)
        vals = [[t, str(fn(t))] for t in range(start, end + 1, step) if fn and fn(t) is not None]
        return [{"metric": {"instance": INST}, "values": vals}] if vals else []


def healthy(**over):
    base = {"up": lambda t: 1, "rpc": lambda t: 1, "state": lambda t: 4, "age": lambda t: 3,
            "maint": lambda t: 0, "uptime": lambda t: t - T0 + 5000}
    base.update(over)
    return base


def analyze(fns, minutes=60, spans=(), step=60):
    res = r.analyze(FakeSource(fns), "postfiat", T0, T0 + minutes * 60, step, list(spans))
    return res[0] if res else None


class RealFixtures(unittest.TestCase):
    def test_replay_matches_recorded_report(self):
        rc, out, _ = run(REAL)
        self.assertEqual(rc, 0)
        with open(os.path.join(FIX, "real-2026-10-23.md")) as f:
            self.assertEqual(out, f.read())

    def test_replay_with_maint_history_excludes_the_two_drill_windows(self):
        rc, out, _ = run(REAL + ["--maint-history", os.path.join(FIX, "maint-history.jsonl")])
        self.assertEqual(rc, 0)
        with open(os.path.join(FIX, "real-2026-10-23-maint.md")) as f:
            self.assertEqual(out, f.read())
        self.assertIn("| Maintenance excluded | 47m00s (2 windows) |", out)
        self.assertIn("### Bad intervals (1)", out)
        self.assertIn("node RPC down (1m00s); node restarted", out)


class Classification(unittest.TestCase):
    def test_steady_good(self):
        s = analyze(healthy())
        self.assertEqual(s["kinds"]["bad"], 0)
        self.assertEqual(s["kinds"]["good"], 61)
        self.assertEqual(s["intervals"], [])

    def test_rpc_outage_is_one_interval_with_restart(self):
        lo, hi = T0 + 600, T0 + 1200  # 10 bad steps
        s = analyze(healthy(rpc=lambda t: 0 if lo <= t < hi else 1,
                            state=lambda t: None if lo <= t < hi else 4,
                            age=lambda t: None if lo <= t < hi else 3,
                            uptime=lambda t: t - T0 + 5000 if t < lo else (None if t < hi else t - hi + 5)))
        self.assertEqual(len(s["intervals"]), 1)
        iv = s["intervals"][0]
        self.assertEqual((iv["start"], iv["seconds"]), (lo, 600))
        self.assertEqual(iv["causes"].most_common(1)[0][0], "node RPC down")
        self.assertTrue(iv["restart"])

    def test_cause_order_exporter_state_stale(self):
        cases = [({"up": lambda t: 0}, "exporter scrape failed"),
                 ({"state": lambda t: 2}, "server_state syncing"),
                 ({"state": lambda t: None}, "server_state unknown"),
                 ({"age": lambda t: 25}, "validated ledger stale"),
                 ({"age": lambda t: None}, "no validated ledger")]
        for over, cause in cases:
            with self.subTest(cause=cause):
                s = analyze(healthy(**over), minutes=5)
                self.assertEqual(s["kinds"]["bad"], 6)
                self.assertEqual(list(s["intervals"][0]["causes"]), [cause])
                self.assertFalse(s["intervals"][0]["restart"])

    def test_age_boundary_is_strictly_below_10s(self):
        self.assertEqual(analyze(healthy(age=lambda t: 9.9), minutes=1)["kinds"]["bad"], 0)
        self.assertEqual(analyze(healthy(age=lambda t: 10), minutes=1)["kinds"]["bad"], 2)

    def test_proposing_is_good(self):
        self.assertEqual(analyze(healthy(state=lambda t: 6), minutes=5)["kinds"]["bad"], 0)

    def test_maint_metric_excludes_outage(self):
        lo, hi = T0 + 600, T0 + 1200
        s = analyze(healthy(rpc=lambda t: 0 if lo <= t < hi else 1, maint=lambda t: 1 if lo <= t < hi else 0))
        self.assertEqual(s["kinds"]["bad"], 0)
        self.assertEqual(s["kinds"]["maint"], 10)
        self.assertEqual(s["maint"], [[lo, hi - 60]])

    def test_maint_history_span_excludes_outage_without_metric(self):
        lo, hi = T0 + 600, T0 + 1200
        s = analyze(healthy(rpc=lambda t: 0 if lo <= t < hi else 1, maint=lambda t: None), spans=[(lo, hi)])
        self.assertEqual((s["kinds"]["bad"], s["kinds"]["maint"]), (0, 10))

    def test_missing_prometheus_data_is_unmeasured_and_splits_intervals(self):
        gap = range(T0 + 600, T0 + 900)
        s = analyze(healthy(up=lambda t: None if t in gap else 1, rpc=lambda t: 0))
        self.assertEqual(s["kinds"]["nodata"], 5)
        self.assertEqual(len(s["intervals"]), 2)
        self.assertEqual(s["kinds"]["bad"], 56)

    def test_recording_rule_crosscheck_counts_disagreement(self):
        lo = T0 + 600
        fns = healthy(rpc=lambda t: 0 if t >= lo else 1,
                      rule_bad=lambda t: 1 if t >= lo + 120 else 0)  # rule lags two steps
        s = analyze(fns, minutes=20)
        self.assertEqual(s["rule_check"], (19, 2))


class Cli(unittest.TestCase):
    def test_only_range_queries_and_chunking(self):
        urls = []

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(url, timeout=None):
            urls.append(url)
            return Resp(json.dumps({"status": "success", "data": {"resultType": "matrix", "result": []}}).encode())

        with mock.patch.object(r.urllib.request, "urlopen", fake_urlopen):
            rc, _, err = run(["--start", str(T0), "--end", str(T0 + 3 * 86400), "--step", "15s"])
        self.assertEqual(rc, 1)  # no up{} data
        self.assertIn("no `up", err)
        self.assertTrue(urls)
        self.assertTrue(all(u.startswith("http://127.0.0.1:9090/api/v1/query_range?") for u in urls))
        # 3 days at 15s = 17281 points -> 2 chunks for each of the 7 series, + 1 objective lookup
        self.assertEqual(len(urls), 7 * 2 + 1)

    def test_chunks_cover_window_without_overlap(self):
        src = FakeSource(healthy())
        s = src.series(r.QUERIES["up"] % "postfiat", T0, T0 + 25000 * 15, 15)[INST]
        self.assertEqual(len(s), 25001)
        for q, a, b, step in src.log:
            self.assertLessEqual((b - a) // step + 1, r.MAX_POINTS)

    def test_objective_from_metric_then_default(self):
        res = r.analyze(FakeSource(healthy()), "postfiat", T0, T0 + 600, 60, [])
        md = r.render(res, T0, T0 + 600, 60, 0.999, "postfiat", "x", 50)
        self.assertIn("Objective: 99.900%", md)
        with mock.patch.object(r, "Source", lambda *a, **k: FakeSource(healthy(), objective=0.99)):
            rc, out, _ = run(["--start", str(T0), "--end", str(T0 + 600), "--step", "60s"])
        self.assertEqual(rc, 0)
        self.assertIn("Objective: 99.000%", out)
        with mock.patch.object(r, "Source", lambda *a, **k: FakeSource(healthy())):
            _, out, _ = run(["--start", str(T0), "--end", str(T0 + 600), "--step", "60s"])
        self.assertIn("Objective: 99.500%", out)

    def test_budget_math(self):
        lo = T0 + 60 * 50
        res = r.analyze(FakeSource(healthy(rpc=lambda t: 0 if lo <= t < lo + 120 else 1)),
                        "postfiat", T0, T0 + 199 * 60, 60, [])
        md = r.render(res, T0, T0 + 199 * 60, 60, 0.99, "postfiat", "x", 50)
        # 200 eligible steps, 2 bad -> SLI 99%, budget 1% of 200 min = 2 min, all consumed
        self.assertIn("| SLI (good / eligible) | 99.0000% |", md)
        self.assertIn("| Error budget for window | 2m00s |", md)
        self.assertIn("| Budget consumed | 100.0% |", md)

    def test_usage_errors_exit_2(self):
        for argv in (["--step", "15"], ["--start", "2026-10-23T21:00:00Z", "--end", "2026-10-23T19:00:00Z"],
                     ["--objective", "99.5"] + REAL[:2] + REAL[2:]):
            with self.subTest(argv=argv):
                self.assertEqual(run(argv)[0], 2)

    def test_record_then_replay_roundtrip(self):
        body = {"status": "success", "data": {"resultType": "matrix",
                                              "result": [{"metric": {"instance": INST}, "values": [[T0, "1"]]}]}}

        def fake_urlopen(url, timeout=None):
            return io.BytesIO(json.dumps(body).encode())

        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(r.urllib.request, "urlopen", fake_urlopen):
                live = r.Source("http://unused", record=d).query_range("up", T0, T0 + 60, 60)
            self.assertEqual(len(os.listdir(d)), 1)
            replayed = r.Source("http://unused", replay=d).query_range("up", T0, T0 + 60, 60)
        self.assertEqual(live, replayed)

    def test_real_fixture_shape(self):
        src = r.Source("http://unused", replay=os.path.join(FIX, "real-2026-10-23"))
        res = src.query_range(r.QUERIES["up"] % "postfiat", 1792782000, 1792789200, 60)
        self.assertEqual(res[0]["metric"]["instance"], "127.0.0.1:9877")
        self.assertEqual(len(res[0]["values"]), 121)

if __name__ == "__main__":
    unittest.main()
