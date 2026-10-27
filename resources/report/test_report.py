#!/usr/bin/env python3
"""Tests for report.py on synthetic history files. The base sample is a real line copied from the validator's
history file (2026-10-27), so a field rename in pft-resources.sh breaks these tests.
  python3 resources/report/test_report.py
"""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import report  # noqa: E402

REAL = ('{"ts":1793081492,"container":"postfiatd","id":"407cf9b6ffa6","restarts":0,"mem_current":852115456,'
        '"mem_max":2415919104,"oom_kill":0,"cpu_usec":22639668563,"nr_throttled":0,"pids":31,"pids_max":256,'
        '"fds":43,"fd_limit":1024,"psi_memory_some_avg60":0.00,"psi_cpu_some_avg60":2.75,"psi_io_some_avg60":0.06}')
T0 = 1793081492


def series(n, step=60, **over):
    """n samples 60 s apart; CPU grows 0.5 core; `over` maps field -> f(i) or constant."""
    base, out = json.loads(REAL), []
    for i in range(n):
        s = copy.deepcopy(base)
        s["ts"] = T0 + i * step
        s["cpu_usec"] = base["cpu_usec"] + i * step * 500000
        for k, v in over.items():
            s[k] = v(i) if callable(v) else v
        out.append(s)
    return out


class Base(unittest.TestCase):
    def run_report(self, samples, *args, raw_extra=()):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "h.jsonl")
            with open(p, "w") as f:
                for s in samples:
                    f.write(json.dumps(s) + "\n")
                for ln in raw_extra:
                    f.write(ln + "\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = report.main(list(args) + ["--json", "validator=" + p])
            return rc, (json.loads(out.getvalue())[0] if rc == 0 else None)

    def verdict(self, r, rule):
        return [x for x in r["recommend"] if x["rule"] == rule][0]["verdict"]


class TestReport(Base):
    def test_real_line_parses(self):
        rc, r = self.run_report([json.loads(REAL)])
        self.assertEqual(rc, 0)
        self.assertEqual(r["coverage"]["unparsed_lines"], 0)
        self.assertEqual(r["stats"]["fds"]["max"], 43)

    def test_steady_day(self):
        rc, r = self.run_report(series(1440))
        c = r["coverage"]
        self.assertEqual((c["samples"], c["expected"], c["pct"], c["gaps"]), (1440, 1440, 100.0, []))
        self.assertAlmostEqual(r["stats"]["cpu_cores"]["median"], 0.5)
        self.assertTrue(all(v["would_fire"] == 0 for v in r["replay"].values()))
        self.assertTrue(all(x["verdict"] == "keep default" for x in r["recommend"]), r["recommend"])
        self.assertIsNone(r["growth"]["hours_to_mem_limit"])

    def test_percentile_nearest_rank(self):
        v = list(range(1, 21))
        self.assertEqual((report.pct(v, 50), report.pct(v, 95), report.pct(v, 100)), (10, 19, 20))
        self.assertEqual(report.pct([7], 95), 7)
        self.assertEqual(report.pct(list(range(1, 11)), 95), 10)  # rank ceil(9.5) = 10, not 9

    def test_gap_counted(self):
        s = series(120)
        del s[50:60]
        rc, r = self.run_report(s, "--since", str(T0), "--until", str(T0 + 7200))
        c = r["coverage"]
        self.assertEqual((c["samples"], c["expected"], len(c["gaps"]), c["gaps"][0]["seconds"]), (110, 120, 1, 660))

    def test_extra_runs_do_not_inflate_coverage(self):
        s = series(60)
        extra = copy.deepcopy(s[30])
        extra["ts"] += 29  # a manual run between two timer runs
        rc, r = self.run_report(s + [extra], "--since", str(T0), "--until", str(T0 + 3600))
        c = r["coverage"]
        self.assertEqual((c["samples"], c["extra_runs"], c["expected"], c["pct"]), (61, 1, 60, 100.0))
        rc, r = self.run_report(s[:-6] + [extra], "--since", str(T0), "--until", str(T0 + 3600))
        self.assertEqual(r["coverage"]["pct"], 90.0)  # 54 on schedule of 60; the extra run does not fill a gap

    def test_restart_splits_cpu_and_counts(self):
        s = series(20)
        for i in range(10, 20):
            s[i]["id"], s[i]["restarts"], s[i]["cpu_usec"] = "aaaaaaaaaaaa", 1, 1000 + (i - 10) * 30000000
        rc, r = self.run_report(s)
        self.assertEqual(r["coverage"]["container_ids"], ["407cf9b6ffa6", "aaaaaaaaaaaa"])
        self.assertEqual(r["coverage"]["restarts_delta"], 1)
        self.assertGreaterEqual(r["stats"]["cpu_cores"]["min"], 0)
        self.assertEqual(r["stats"]["cpu_cores"]["n"], 18)  # the restart step is not a CPU sample

    def test_oom_kill_counter_resets_with_new_cgroup(self):
        s = series(20, oom_kill=lambda i: 2 if 5 <= i < 10 else 0)
        for i in range(10, 20):
            s[i]["id"] = "aaaaaaaaaaaa"  # new container = new cgroup, memory.events starts at 0 again
        rc, r = self.run_report(s)
        self.assertEqual(r["coverage"]["oom_kill_delta"], 2)

    def test_oom_kill_delta(self):
        rc, r = self.run_report(series(10, oom_kill=lambda i: 0 if i < 5 else 2))
        self.assertEqual(r["coverage"]["oom_kill_delta"], 2)

    def test_unparsed_lines_counted_not_skipped(self):
        bad = ["{not json", json.dumps({"ts": T0}), json.dumps(dict(json.loads(REAL), fds="43"))]
        rc, r = self.run_report(series(5), raw_extra=bad)
        self.assertEqual(r["coverage"]["unparsed_lines"], 3)

    def test_memory_near_limit_for_duration(self):
        mx = 2415919104
        hi = int(mx * 0.95)
        rc, r = self.run_report(series(60, mem_current=lambda i: hi if 10 <= i < 14 else 800000000))
        self.assertEqual(r["replay"]["PFTMemoryNearLimit"]["would_fire"], 0)  # 4 samples = 3 min < 5m
        rc, r = self.run_report(series(60, mem_current=lambda i: hi if 10 <= i < 20 else 800000000))
        self.assertEqual(r["replay"]["PFTMemoryNearLimit"]["would_fire"], 1)
        self.assertEqual(r["replay"]["PFTMemoryNearLimit"]["firing_seconds"], 240)  # fires at i=15, held to i=19
        self.assertTrue(self.verdict(r, "PFTMemoryNearLimit").startswith("REVIEW"))

    def test_gap_resets_for_timer(self):
        mx = 2415919104
        s = series(60, mem_current=lambda i: int(mx * 0.95) if 10 <= i < 18 else 800000000)
        del s[13:14]
        rc, r = self.run_report(s)
        self.assertEqual(r["replay"]["PFTMemoryNearLimit"]["would_fire"], 1)
        s = series(60, mem_current=lambda i: int(mx * 0.95) if 10 <= i < 18 else 800000000)
        del s[13:16]  # 240 s gap inside the high run -> timer resets, never 5 min continuous
        rc, r = self.run_report(s)
        self.assertEqual(r["replay"]["PFTMemoryNearLimit"]["would_fire"], 0)

    def test_close_to_threshold_without_firing_is_review(self):
        rc, r = self.run_report(series(60, mem_current=int(2415919104 * 0.80)))
        self.assertEqual(r["replay"]["PFTMemoryNearLimit"]["would_fire"], 0)
        self.assertTrue(self.verdict(r, "PFTMemoryNearLimit").startswith("REVIEW"))

    def test_fd_and_pids_and_psi(self):
        rc, r = self.run_report(series(30, fds=900, pids=250, psi_io_some_avg60=40.0, psi_memory_some_avg60=6.0))
        rp = r["replay"]
        self.assertEqual((rp["PFTFdNearLimit"]["would_fire"], rp["PFTPidsNearLimit"]["would_fire"],
                          rp["PFTIOPressure"]["would_fire"], rp["PFTMemoryPressure"]["would_fire"]), (1, 1, 1, 0))
        for rule in ("PFTFdNearLimit", "PFTPidsNearLimit", "PFTIOPressure", "PFTMemoryPressure"):
            self.assertTrue(self.verdict(r, rule).startswith("REVIEW"), rule)  # 6.0 > 10/2 for memory PSI

    def test_psi_spike_judged_by_max(self):
        rc, r = self.run_report(series(100, psi_memory_some_avg60=lambda i: 8.0 if i == 50 else 0.0))
        self.assertEqual(r["replay"]["PFTMemoryPressure"]["would_fire"], 0)
        self.assertTrue(self.verdict(r, "PFTMemoryPressure").startswith("REVIEW"))  # max 8 > 10/2, p95 is 0

    def test_growth_to_limit(self):
        mx = 2415919104
        step = 2 * 1048576  # +2 MiB/min = 120 MiB/h
        rc, r = self.run_report(series(240, mem_current=lambda i: int(mx * 0.6) + i * step))
        self.assertAlmostEqual(r["growth"]["mem_bytes_per_hour"] / 1048576.0, 120.0, places=3)
        last = int(mx * 0.6) + 239 * step
        self.assertAlmostEqual(r["growth"]["hours_to_mem_limit"], (mx - last) / (120.0 * 1048576), places=3)
        # 6h at 120 MiB/h = 720 MiB > remaining headroom from about 1h in -> fires once after the 30m hold
        self.assertEqual(r["replay"]["PFTMemoryGrowthToLimit"]["would_fire"], 1)
        self.assertTrue(self.verdict(r, "PFTMemoryGrowthToLimit").startswith("REVIEW"))

    def test_growth_below_half_does_not_fire(self):
        rc, r = self.run_report(series(120, mem_current=lambda i: 100000000 + i * 8 * 1048576))
        self.assertLess(r["stats"]["mem_pct_of_max"]["max"], 50)  # fast growth, but still below half of max
        self.assertEqual(r["replay"]["PFTMemoryGrowthToLimit"]["would_fire"], 0)

    def test_window_filter_and_empty(self):
        rc, r = self.run_report(series(100), "--since", str(T0 + 600), "--until", str(T0 + 1200))
        self.assertEqual((r["coverage"]["samples"], r["coverage"]["expected"]), (10, 10))
        rc, _ = self.run_report(series(10), "--since", str(T0 + 99999))
        self.assertEqual(rc, 2)

    def test_markdown_renders(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "h.jsonl")
            with open(p, "w") as f:
                f.write("\n".join(json.dumps(s) for s in series(30)) + "\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(report.main(["validator=" + p]), 0)
        md = out.getvalue()
        self.assertIn("## validator (container postfiatd)", md)
        self.assertIn("(0.50 h window)", md)
        self.assertIn("| PFTMemoryNearLimit | > 90% |", md)
        self.assertNotIn(d, md)

    def test_bad_args(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(report.main(["nolabel"]), 2)
            self.assertEqual(report.main(["x=/nonexistent/h.jsonl"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
