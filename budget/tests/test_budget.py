#!/usr/bin/env python3
"""Tests for pft-budget (budget.py + pft-budget.sh) against a fake cgroup v2 tree and stub systemctl / pft-maint.

Run: TMPDIR=$HOME/.cache python3 -m pytest -q budget/tests   (or python3 -m unittest discover budget/tests)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BUD = os.path.dirname(HERE)
sys.path.insert(0, BUD)
import budget

MIB = budget.MIB
SH = os.path.join(BUD, "pft-budget.sh")
HELPER = os.path.join(BUD, "budget.py")

# stub systemctl: `show U -p PROPS` -> STUB/show-U; `show U -p MemoryMax --value` -> MemoryMax of the newest drop-in
# under DROPIN_ROOT/U.d (else STUB/memmax-U, else infinity); `daemon-reload` -> rc STUB/reload-rc (0). Every call
# is appended to STUB/calls.
SYSTEMCTL_STUB = r"""#!/usr/bin/env python3
import os, sys
stub = os.environ["STUB"]
with open(os.path.join(stub, "calls"), "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
a = sys.argv[1:]
if a[:1] == ["daemon-reload"]:
    p = os.path.join(stub, "reload-rc")
    sys.exit(int(open(p).read()) if os.path.exists(p) else 0)
if a[:1] == ["show"] and a[2:] == ["-p", "MemoryMax", "--value"]:
    p = os.path.join(stub, "force-memmax-" + a[1])
    if os.path.exists(p):
        print(open(p).read().strip())
        sys.exit(0)
    d = os.path.join(os.environ["PFT_BUD_DROPIN_ROOT"], a[1] + ".d")
    val = None
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            for line in open(os.path.join(d, n)):
                if line.startswith("MemoryMax="):
                    val = line.split("=", 1)[1].strip()
    if val is None:
        p = os.path.join(stub, "memmax-" + a[1])
        val = open(p).read().strip() if os.path.exists(p) else "infinity"
    print(val)
    sys.exit(0)
if a[:1] == ["show"]:
    p = os.path.join(stub, "show-" + a[1])
    if os.path.exists(p):
        sys.stdout.write(open(p).read())
        sys.exit(0)
    sys.exit(1)
sys.exit(2)
"""
MAINT_STUB = """#!/bin/sh
echo "$*" >> "$STUB/maint-calls"
[ -f "$STUB/maint-active" ]
"""


def mkcg(
    root,
    unit,
    current=10 * MIB,
    anon=8 * MIB,
    file_=2 * MIB,
    cpu=1000,
    rbytes=(100,),
    wbytes=(50,),
    oom=0,
    mem_max="max",
    mem_high="max",
    inv="aaaa",
):
    d = os.path.join(root, unit)
    os.makedirs(d, exist_ok=True)
    files = {
        "memory.current": f"{current}\n",
        "memory.stat": f"anon {anon}\nfile {file_}\nkernel_stack 0\npagetables 4096\npercpu 0\nsock 0\nshmem 0\n"
        "slab_reclaimable 9999\nslab_unreclaimable 0\n",
        "cpu.stat": f"usage_usec {cpu}\nuser_usec 1\nsystem_usec 1\n",
        "io.stat": "".join(
            f"8:{i} rbytes={r} wbytes={w} rios=1 wios=1\n" for i, (r, w) in enumerate(zip(rbytes, wbytes))
        ),
        "memory.events": f"low 0\nhigh 0\nmax 0\noom 0\noom_kill {oom}\n",
        "memory.max": f"{mem_max}\n",
        "memory.high": f"{mem_high}\n",
        "inv": inv,  # read by the patched invocation_id below (xattrs need root)
    }
    for k, v in files.items():
        with open(os.path.join(d, k), "w") as f:
            f.write(v)
    return d


def rec(unit, t, peak, cap=512 * MIB, kind="final", inv=None, oom=0, result="success", host="validator", runtime=10):
    return {
        "v": 1, "kind": kind, "host": host, "unit": unit, "inv": inv or f"{unit}-{t}", "t_first": t - runtime,
        "t_last": t, "samples": 5, "from_start": True, "peak_bytes": peak + MIB, "peak_unrecl_bytes": peak,
        "cpu_sec": 1.0, "io_read_bytes": 1, "io_write_bytes": 2, "oom_kills": oom, "mem_max": cap, "mem_high": None,
        "result": result, "exit_status": 0, "runtime_sec": runtime,
    }  # fmt: skip


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="budget-test-")
        self.cg = os.path.join(self.tmp, "cg")
        self.data = os.path.join(self.tmp, "data")
        self.stub = os.path.join(self.tmp, "stub")
        self.dropins = os.path.join(self.tmp, "etc")
        self.textdir = os.path.join(self.tmp, "text")
        for d in (self.cg, self.data, self.stub, self.dropins, self.textdir):
            os.makedirs(d)
        self.systemctl = os.path.join(self.stub, "systemctl")
        self.maint = os.path.join(self.stub, "pft-maint")
        for path, body in ((self.systemctl, SYSTEMCTL_STUB), (self.maint, MAINT_STUB)):
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, 0o755)
        self.env = {
            "STUB": self.stub,
            "PFT_BUD_CGROUP_ROOT": self.cg,
            "PFT_BUD_DATA_DIR": self.data,
            "PFT_BUD_DROPIN_ROOT": self.dropins,
            "PFT_BUD_SYSTEMCTL": self.systemctl,
            "PFT_BUD_MAINT": self.maint,
            "PFT_BUD_HOST": "validator",
        }
        self.saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.conf = budget.load_conf("/nonexistent")
        self._inv = budget.invocation_id
        budget.invocation_id = lambda unit, p: open(os.path.join(p, "inv")).read()

    def tearDown(self):
        budget.invocation_id = self._inv
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp)

    def calls(self, name="calls"):
        p = os.path.join(self.stub, name)
        return open(p).read().splitlines() if os.path.exists(p) else []

    def records(self):
        p = os.path.join(self.data, "samples.jsonl")
        return [json.loads(x) for x in open(p)] if os.path.exists(p) else []

    def show(self, unit, inv, result="success", status=0, start=1_000_000, end=3_500_000):
        with open(os.path.join(self.stub, "show-" + unit), "w") as f:
            f.write(
                f"InvocationID={inv}\nResult={result}\nExecMainStatus={status}\n"
                f"ExecMainStartTimestampMonotonic={start}\nExecMainExitTimestampMonotonic={end}\n"
            )


class TestCgroup(Base):
    def test_scan_only_pft_services(self):
        for u in ("pft-a.service", "pft-b@x.service", "docker.service", "pft-c.scope", "postfiatd.service"):
            mkcg(self.cg, u)
        os.makedirs(os.path.join(self.cg, "pft-file.service.d"))
        open(os.path.join(self.cg, "pft-plain.service"), "w").close()  # a file, not a cgroup dir
        self.assertEqual(sorted(budget.scan(self.conf)), ["pft-a.service", "pft-b@x.service"])

    def test_read_cgroup_fields(self):
        d = mkcg(self.cg, "pft-a.service", current=50 * MIB, anon=30 * MIB, file_=20 * MIB, cpu=2_500_000,
                 rbytes=(100, 200), wbytes=(5, 7), oom=2, mem_max=str(512 * MIB))  # fmt: skip
        s = budget.read_cgroup(d)
        self.assertEqual(s["current"], 50 * MIB)
        self.assertEqual(s["unrecl"], 30 * MIB + 4096)  # anon + pagetables; file and slab_reclaimable excluded
        self.assertEqual((s["io_read"], s["io_write"]), (300, 12))
        self.assertEqual(s["cpu_usec"], 2_500_000)
        self.assertEqual(s["oom_kill"], 2)
        self.assertEqual(s["mem_max"], 512 * MIB)
        self.assertIsNone(s["mem_high"])

    def test_read_vanished_cgroup_is_none(self):
        d = mkcg(self.cg, "pft-a.service")
        os.remove(os.path.join(d, "memory.events"))
        self.assertIsNone(budget.read_cgroup(d))

    def test_missing_root_is_conf_error(self):
        os.environ["PFT_BUD_CGROUP_ROOT"] = os.path.join(self.tmp, "nope")
        with self.assertRaises(budget.ConfError):
            budget.scan(budget.load_conf("/nonexistent"))


class TestTracker(Base):
    def tracker(self, times):
        it = iter(times)
        return budget.Tracker(self.conf, clock=lambda: next(it))

    def test_lifecycle_peak_and_result(self):
        mkcg(self.cg, "pft-old.service", inv="old1")
        tr = self.tracker([100, 101, 102, 103, 104])
        self.assertEqual(tr.tick(), [])
        mkcg(self.cg, "pft-new.service", current=20 * MIB, anon=10 * MIB, inv="new1")
        tr.tick()
        mkcg(self.cg, "pft-new.service", current=90 * MIB, anon=70 * MIB, cpu=4_000_000, inv="new1")
        tr.tick()
        mkcg(self.cg, "pft-new.service", current=40 * MIB, anon=30 * MIB, cpu=5_000_000, oom=0, inv="new1")
        tr.tick()  # a lower sample after the peak must not replace it
        shutil.rmtree(os.path.join(self.cg, "pft-new.service"))
        self.show("pft-new.service", "new1", start=1_000_000, end=3_500_000)
        out = tr.tick()
        self.assertEqual(len(out), 1)
        r = out[0]
        self.assertEqual((r["kind"], r["unit"], r["inv"], r["host"]), ("final", "pft-new.service", "new1", "validator"))
        self.assertTrue(r["from_start"])
        self.assertEqual(r["peak_bytes"], 90 * MIB)
        self.assertEqual(r["peak_unrecl_bytes"], 70 * MIB + 4096)
        self.assertEqual(r["samples"], 3)
        self.assertEqual(r["cpu_sec"], 5.0)
        self.assertEqual((r["result"], r["exit_status"], r["runtime_sec"]), ("success", 0, 2.5))
        self.assertEqual(self.records(), out)
        tr2 = self.tracker([200])
        tr2.tick()
        self.assertFalse(tr2.open["pft-old.service"]["from_start"])  # running before the sampler: partial

    def test_result_of_other_invocation_is_ignored(self):
        tr = self.tracker([1, 2, 3])
        tr.tick()
        mkcg(self.cg, "pft-a.service", inv="run1")
        tr.tick()
        shutil.rmtree(os.path.join(self.cg, "pft-a.service"))
        self.show("pft-a.service", "run2", result="exit-code", status=1)
        r = tr.tick()[0]
        self.assertIsNone(r["result"])
        self.assertIsNone(r["exit_status"])
        self.assertEqual(r["runtime_sec"], 0.0)  # sampled span (one sample) when systemd's run is not ours

    def test_oom_kill_result_counts_as_oom(self):
        tr = self.tracker([1, 2, 3])
        tr.tick()
        mkcg(self.cg, "pft-a.service", inv="run1")
        tr.tick()
        shutil.rmtree(os.path.join(self.cg, "pft-a.service"))
        self.show("pft-a.service", "run1", result="oom-kill", status=9)
        r = tr.tick()[0]
        self.assertEqual((r["result"], r["oom_kills"]), ("oom-kill", 1))

    def test_new_invocation_while_present_finalizes_old(self):
        os.environ["PFT_BUD_INV_CHECK_SEC"] = "1"
        self.conf = budget.load_conf("/nonexistent")
        os.environ.pop("PFT_BUD_INV_CHECK_SEC")
        tr = self.tracker([1, 2, 3])
        tr.tick()
        mkcg(self.cg, "pft-a.service", current=30 * MIB, inv="run1")
        tr.tick()
        mkcg(self.cg, "pft-a.service", current=5 * MIB, inv="run2")
        out = tr.tick()
        self.assertEqual([(r["inv"], r["peak_bytes"]) for r in out], [("run1", 30 * MIB)])
        self.assertEqual(tr.open["pft-a.service"]["peak"], 5 * MIB)

    def test_running_checkpoint(self):
        os.environ["PFT_BUD_CHECKPOINT_SEC"] = "60"
        conf = budget.load_conf("/nonexistent")
        mkcg(self.cg, "pft-a.service", inv="long")
        it = iter([0, 30, 61, 90, 122])
        tr = budget.Tracker(conf, clock=lambda: next(it))
        kinds = [[r["kind"] for r in tr.tick()] for _ in range(5)]
        self.assertEqual(kinds, [[], [], ["running"], [], ["running"]])
        os.environ.pop("PFT_BUD_CHECKPOINT_SEC")

    def test_flush_writes_running(self):
        mkcg(self.cg, "pft-a.service", inv="x")
        tr = self.tracker([5])
        tr.tick()
        self.assertEqual([r["kind"] for r in tr.flush()], ["running"])


class TestJsonl(Base):
    def test_rotation_is_bounded(self):
        os.environ.update({"PFT_BUD_MAX_BYTES": "4096", "PFT_BUD_KEEP": "2"})
        conf = budget.load_conf("/nonexistent")
        for i in range(200):
            budget.append_record(conf, rec("pft-a.service", 1000 + i, MIB))
        names = sorted(os.listdir(self.data))
        self.assertEqual(names, ["samples.jsonl", "samples.jsonl.1", "samples.jsonl.2"])
        for n in names:
            self.assertLessEqual(os.path.getsize(os.path.join(self.data, n)), 4096)
        recs, bad = budget.load_records(budget.data_files(conf))
        self.assertEqual(bad, 0)
        self.assertEqual(max(r["t_last"] for r in recs), 1199)  # newest kept, oldest dropped
        self.assertGreater(min(r["t_last"] for r in recs), 1000)
        for k in ("PFT_BUD_MAX_BYTES", "PFT_BUD_KEEP"):
            os.environ.pop(k)

    def test_final_beats_running_and_torn_line(self):
        p = os.path.join(self.data, "x.jsonl")
        with open(p, "w") as f:
            f.write(json.dumps(rec("pft-a.service", 50, 5 * MIB, kind="final", inv="i")) + "\n")
            f.write(json.dumps(rec("pft-a.service", 90, 9 * MIB, kind="running", inv="i")) + "\n")
            f.write(json.dumps(rec("pft-b.service", 10, 1 * MIB, kind="running", inv="j")) + "\n")
            f.write(json.dumps(rec("pft-b.service", 20, 2 * MIB, kind="running", inv="j")) + "\n")
            f.write('{"kind": "final", "host": "validator", "unit": "pft-c.ser')
        recs, bad = budget.load_records([p])
        self.assertEqual(bad, 1)
        got = {r["unit"]: (r["kind"], r["peak_unrecl_bytes"]) for r in recs}
        self.assertEqual(got, {"pft-a.service": ("final", 5 * MIB), "pft-b.service": ("running", 2 * MIB)})


DAY = 86400.0
T0 = 1_795_000_000.0


class TestReport(Base):
    def rep(self, recs, t_now):
        p = os.path.join(self.data, "in.jsonl")
        with open(p, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        return budget.build_report(self.conf, t_now, [p])

    def one(self, recs, t_now=T0 + 3 * DAY):
        units = self.rep(recs, t_now)["units"]
        self.assertEqual(len(units), 1)
        return units[0]

    def test_ok_with_flat_peaks(self):
        u = self.one([rec("pft-a.service", T0 + i * DAY, 100 * MIB) for i in range(4)])
        self.assertEqual(u["verdict"], "OK")
        self.assertEqual(u["headroom"], 5.12)
        self.assertEqual((u["proj30"], u["proj90"]), (100 * MIB, 100 * MIB))

    def test_old_histarchive_under_stopgap_warns(self):
        # the real case: ~593 MiB peak of the old verify under the 1G stop-gap = 1.73x < 2x
        recs = [rec("pft-histarchive-periodic.service", T0 + i * DAY, 593 * MIB, cap=1024 * MIB) for i in range(3)]
        u = self.one(recs)
        self.assertEqual(u["verdict"], "WARN")
        self.assertIn("headroom 1.73x < 2x", u["reasons"][0])

    def test_bounded_histarchive_fits_512(self):
        recs = [rec("pft-histarchive-periodic.service", T0 + i * DAY, 251 * MIB, cap=512 * MIB) for i in range(3)]
        u = self.one(recs)
        self.assertEqual(u["verdict"], "OK")
        self.assertEqual(u["target"], 512 * MIB)  # 2 x 251 MiB = 502 MiB, rounded up to 64 MiB steps

    def test_peak_near_cap_fails(self):
        u = self.one([rec("pft-a.service", T0 + i * DAY, 470 * MIB) for i in range(3)])
        self.assertEqual(u["verdict"], "FAIL")
        self.assertTrue(any(">= 0.9 x cap" in r for r in u["reasons"]))

    def test_exactly_fail_fraction_fails(self):
        u = self.one([rec("pft-a.service", T0 + i * DAY, 900 * MIB, cap=1000 * MIB) for i in range(3)])
        self.assertEqual(u["verdict"], "FAIL")

    def test_just_below_fail_fraction_warns(self):
        u = self.one([rec("pft-a.service", T0 + i * DAY, 460 * MIB) for i in range(3)])  # 0.898 x 512
        self.assertEqual(u["verdict"], "WARN")

    def test_exactly_2x_headroom_is_ok(self):
        u = self.one([rec("pft-a.service", T0 + i * DAY, 256 * MIB) for i in range(3)])
        self.assertEqual(u["verdict"], "OK")

    def test_oom_fails_even_with_headroom(self):
        recs = [rec("pft-a.service", T0 + i * DAY, 10 * MIB) for i in range(2)]
        recs.append(rec("pft-a.service", T0 + 2 * DAY, 10 * MIB, oom=1, result="oom-kill"))
        u = self.one(recs)
        self.assertEqual((u["verdict"], u["oom_runs"], u["failed_runs"]), ("FAIL", 1, 1))

    def test_uncapped_recommendation(self):
        recs = [rec("pft-a.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(3)]
        u = self.one(recs)
        self.assertEqual(u["verdict"], "UNCAPPED")
        self.assertEqual(u["target"], 128 * MIB)  # max(2 x 40 = 80, 1.25 x proj90 40 = 50) -> 128 (64 MiB steps)

    def test_uncapped_with_oom_is_fail(self):
        u = self.one([rec("pft-a.service", T0 + i * DAY, 40 * MIB, cap=None, oom=i == 2) for i in range(3)])
        self.assertEqual(u["verdict"], "FAIL")

    def test_linear_projection_hand_computed(self):
        # 100, 130, 160 MiB on days 0, 3, 6, report on day 6: slope 10 MiB/day, 30 d -> 460, 90 d -> 1060 MiB
        recs = [rec("pft-a.service", T0 + 3 * i * DAY, (100 + 30 * i) * MIB, cap=2048 * MIB) for i in range(3)]
        u = self.one(recs, t_now=T0 + 6 * DAY)
        self.assertEqual(u["slope_per_day"], 10 * MIB)
        self.assertEqual(u["proj30"], 460 * MIB)
        self.assertEqual(u["proj90"], 1060 * MIB)
        self.assertEqual(u["verdict"], "OK")
        self.assertEqual(u["target"], 1344 * MIB)  # 1.25 x 1060 = 1325 MiB beats 2 x 160 MiB; 64 MiB steps

    def test_projection_30d_over_cap_fails(self):
        recs = [rec("pft-a.service", T0 + 3 * i * DAY, (100 + 30 * i) * MIB, cap=400 * MIB) for i in range(3)]
        u = self.one(recs, t_now=T0 + 6 * DAY)
        self.assertEqual(u["verdict"], "FAIL")
        self.assertTrue(any("30-day projection 460MiB >= cap 400MiB" in r for r in u["reasons"]))

    def test_projection_90d_over_cap_warns(self):
        recs = [rec("pft-a.service", T0 + 3 * i * DAY, (100 + 30 * i) * MIB, cap=1000 * MIB) for i in range(3)]
        u = self.one(recs, t_now=T0 + 6 * DAY)
        self.assertEqual(u["verdict"], "WARN")
        self.assertTrue(any("90-day projection" in r for r in u["reasons"]))

    def test_shrinking_peaks_do_not_project_down(self):
        recs = [rec("pft-a.service", T0 + 3 * i * DAY, (300 - 50 * i) * MIB) for i in range(3)]
        u = self.one(recs, t_now=T0 + 6 * DAY)
        self.assertEqual(u["slope_per_day"], 0)
        self.assertEqual(u["proj30"], 300 * MIB)

    def test_short_span_no_projection(self):
        # the live install case: 5 runs within 12 minutes, 0.2 -> 7 MiB; a fitted slope would project ~23 GiB
        recs = [
            rec("pft-a.service", T0 + i * 180, p * MIB // 10, cap=128 * MIB) for i, p in enumerate((2, 2, 16, 10, 70))
        ]
        u = self.one(recs, t_now=T0 + 720)
        self.assertEqual((u["proj30"], u["proj90"], u["verdict"]), (None, None, "OK"))
        self.assertIn("runs span 0.01 d < PROJ_MIN_SPAN_DAYS 3: no projection", u["reasons"][-1])
        recs = [rec("pft-a.service", T0 + i * DAY * 1.5, (100 + 10 * i) * MIB, cap=2048 * MIB) for i in range(3)]
        self.assertIsNotNone(self.one(recs, t_now=T0 + 3 * DAY)["proj30"])  # exactly 3 days: projected

    def test_too_few_runs_no_projection(self):
        # 4 days apart: only MIN_RUNS (not the span) stops the projection
        u = self.one([rec("pft-a.service", T0, 100 * MIB), rec("pft-a.service", T0 + 4 * DAY, 100 * MIB)], T0 + 4 * DAY)
        self.assertIsNone(u["proj30"])
        self.assertIn("only 2 run(s) < MIN_RUNS 3", u["reasons"][-1])

    def test_window_and_p50(self):
        recs = [rec("pft-a.service", T0 - 40 * DAY, 400 * MIB)]  # outside 30 d: ignored
        recs += [rec("pft-a.service", T0 + i, p * MIB) for i, p in enumerate((10, 30, 20, 50))]
        u = self.one(recs, t_now=T0 + 10)
        self.assertEqual(u["invocations"], 4)
        self.assertEqual(u["peak_unrecl_p50"], 25 * MIB)
        self.assertEqual(u["peak_unrecl_max"], 50 * MIB)

    def test_runtime_and_counts(self):
        recs = [rec("pft-a.service", T0 + i, MIB, runtime=r) for i, r in enumerate((3, 9, 5))]
        rep = self.rep(recs, T0 + 10)
        u = rep["units"][0]
        self.assertEqual((u["runtime_p50"], u["runtime_max"]), (5, 9))
        self.assertEqual(rep["counts"], {"OK": 1, "WARN": 0, "FAIL": 0, "UNCAPPED": 0})

    def test_hosts_are_separate(self):
        recs = [rec("pft-a.service", T0 + i, MIB, host=h) for i in range(3) for h in ("validator", "sentry")]
        rep = self.rep(recs, T0 + 10)
        self.assertEqual([(u["host"], u["invocations"]) for u in rep["units"]], [("sentry", 3), ("validator", 3)])

    def test_text_report_lines(self):
        recs = [rec("pft-a.service", T0 + i * DAY, 593 * MIB, cap=1024 * MIB) for i in range(3)]
        recs += [rec("pft-b.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(3)]
        text = budget.fmt_report(self.rep(recs, T0 + 3 * DAY))
        self.assertIn("RESULT: 0 OK, 1 WARN, 0 FAIL, 1 UNCAPPED", text)
        self.assertIn("recommend MemoryMax=128M", text)
        self.assertRegex(text, r"pft-a\.service +3 +593MiB +593MiB +594MiB +1024MiB +1\.73x")


class TestMetrics(Base):
    def test_metrics_labels_and_codes(self):
        recs = [rec("pft-a.service", T0 + i * DAY, 593 * MIB, cap=1024 * MIB) for i in range(3)]
        recs += [rec("pft-b.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(2)]
        p = os.path.join(self.data, "in.jsonl")
        with open(p, "w") as f:
            f.write("".join(json.dumps(r) + "\n" for r in recs))
        rep = budget.build_report(self.conf, T0 + 3 * DAY, [p])
        text = budget.fmt_metrics(rep, self.conf, 1234)
        lines = text.splitlines()
        self.assertIn('pft_budget_up{host="validator"} 1', lines)
        self.assertIn('pft_budget_sampler_heartbeat_timestamp_seconds{host="validator"} 1234', lines)
        self.assertIn('pft_budget_verdict{host="validator",unit="pft-a.service"} 1', lines)
        self.assertIn('pft_budget_verdict{host="validator",unit="pft-b.service"} 3', lines)
        self.assertIn(f'pft_budget_cap_bytes{{host="validator",unit="pft-a.service"}} {1024 * MIB}', lines)
        self.assertFalse(any(x.startswith('pft_budget_cap_bytes{host="validator",unit="pft-b') for x in lines))
        self.assertFalse(any(x.startswith("pft_budget_projected_30d_bytes") and "pft-b" in x for x in lines))
        for x in lines:
            if not x.startswith("#"):
                self.assertRegex(x, r'^pft_budget_[a-z0-9_]+\{host="validator"(,unit="[^"]+")?\} -?[0-9.]+$')


class TestPlanApply(Base):
    def report(self, recs, t_now=T0 + 3 * DAY):
        p = os.path.join(self.data, "in.jsonl")
        with open(p, "w") as f:
            f.write("".join(json.dumps(r) + "\n" for r in recs))
        self.datafile = p
        return budget.build_report(self.conf, t_now, [p])

    def mixed(self):
        recs = []
        for i in range(3):
            t = T0 + i * DAY
            recs += [
                rec("pft-warn.service", t, 300 * MIB, cap=512 * MIB),
                rec("pft-free.service", t, 40 * MIB, cap=None),
                rec("pft-big.service", t, 100 * MIB, cap=1024 * MIB),
                rec("postfiatd-x.service", t, 40 * MIB, cap=None),
                rec("pft-budget-sampler.service", t, 40 * MIB, cap=None),
                rec("pft-other-host.service", t, 40 * MIB, cap=None, host="sentry"),
            ]
        return recs

    def test_plan_actions_and_exclusions(self):
        plan = budget.build_plan(self.report(self.mixed()), self.conf)
        self.assertEqual(
            [(p["unit"], p["action"], p["to"]) for p in plan],
            [("pft-free.service", "set", 128 * MIB), ("pft-warn.service", "raise", 640 * MIB)],
        )
        plan = budget.build_plan(self.report(self.mixed()), self.conf, allow_lower=True)
        self.assertIn(("pft-big.service", "lower", 256 * MIB), [(p["unit"], p["action"], p["to"]) for p in plan])

    def test_never_set_on_few_runs(self):
        recs = [rec("pft-free.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(2)]
        self.assertEqual(budget.build_plan(self.report(recs), self.conf), [])

    def test_raise_even_on_one_run(self):
        recs = [rec("pft-warn.service", T0, 470 * MIB, cap=512 * MIB)]
        plan = budget.build_plan(self.report(recs), self.conf)
        self.assertEqual([(p["action"], p["to"]) for p in plan], [("raise", 960 * MIB)])

    def test_ok_unit_never_raised_by_rounding(self):
        recs = [rec("pft-ok.service", T0 + i * DAY, 50 * MIB, cap=100 * MIB) for i in range(3)]
        rep = self.report(recs)
        self.assertEqual((rep["units"][0]["verdict"], rep["units"][0]["target"]), ("OK", 128 * MIB))
        self.assertEqual(budget.build_plan(rep, self.conf), [])

    def test_never_lower_on_few_runs_or_oom(self):
        recs = [rec("pft-big.service", T0 + i * DAY, 100 * MIB, cap=1024 * MIB) for i in range(2)]
        self.assertEqual(budget.build_plan(self.report(recs), self.conf, allow_lower=True), [])
        recs = [rec("pft-big.service", T0 + i * DAY, 100 * MIB, cap=1024 * MIB, oom=i == 0) for i in range(3)]
        self.assertEqual(budget.build_plan(self.report(recs), self.conf, allow_lower=True), [])

    def run_main(self, *argv):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = budget.main(["--conf", "/nonexistent", *argv])
        return rc, out.getvalue(), err.getvalue()

    def dropin(self, unit):
        return os.path.join(self.dropins, unit + ".d", "60-pft-budget.conf")

    def test_apply_refused_without_window_writes_nothing(self):
        self.report(self.mixed())
        rc, _, err = self.run_main("apply", "--yes", "--now", str(T0 + 3 * DAY), "--data", self.datafile)
        self.assertEqual(rc, 4)
        self.assertIn("REFUSED: no active pft-maint window", err)
        self.assertEqual(os.listdir(self.dropins), [])
        self.assertEqual(self.calls(), [])  # no daemon-reload, no systemctl at all
        self.assertEqual(self.calls("maint-calls"), ["active"])
        self.assertFalse(os.path.exists(os.path.join(self.data, "applied")))

    def test_apply_dry_run_writes_nothing(self):
        open(os.path.join(self.stub, "maint-active"), "w").close()
        self.report(self.mixed())
        rc, out, _ = self.run_main("apply", "--now", str(T0 + 3 * DAY), "--data", self.datafile)
        self.assertEqual(rc, 0)
        self.assertIn("WOULD pft-free.service MemoryMax None -> 134217728", out)
        self.assertIn("dry run", out)
        self.assertEqual((os.listdir(self.dropins), self.calls(), self.calls("maint-calls")), ([], [], []))

    def test_apply_then_rollback(self):
        open(os.path.join(self.stub, "maint-active"), "w").close()
        self.report(self.mixed())
        os.makedirs(os.path.dirname(self.dropin("pft-warn.service")))
        with open(self.dropin("pft-warn.service"), "w") as f:
            f.write("[Service]\nMemoryMax=536870912\n")
        rc, out, _ = self.run_main("apply", "--yes", "--now", str(T0 + 3 * DAY), "--data", self.datafile)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK pft-free.service MemoryMax=134217728 (want 134217728)", out)
        self.assertIn("OK pft-warn.service MemoryMax=671088640 (want 671088640)", out)
        text = open(self.dropin("pft-free.service")).read()
        self.assertIn("[Service]\nMemoryMax=134217728\n", text)
        self.assertIn("measured unreclaimable peak 40MiB over 3 run(s)", text)
        self.assertEqual(oct(os.stat(self.dropin("pft-free.service")).st_mode & 0o777), "0o644")
        self.assertFalse(os.path.exists(os.path.join(self.dropins, "postfiatd-x.service.d")))
        self.assertFalse(os.path.exists(os.path.join(self.dropins, "pft-budget-sampler.service.d")))
        self.assertEqual(self.calls().count("daemon-reload"), 1)
        # rollback: the replaced file comes back, the new one goes away
        with open(os.path.join(self.stub, "memmax-pft-warn.service"), "w") as f:
            f.write("536870912\n")
        rc, out, _ = self.run_main("rollback", "--yes")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(self.dropin("pft-free.service")))
        self.assertEqual(open(self.dropin("pft-warn.service")).read(), "[Service]\nMemoryMax=536870912\n")
        self.assertIn("OK pft-free.service MemoryMax=infinity (want infinity)", out)
        self.assertIn("OK pft-warn.service MemoryMax=536870912 (want 536870912)", out)
        self.assertEqual(self.calls().count("daemon-reload"), 2)
        rc, _, err = self.run_main("rollback", "--yes")  # the record is marked rolled back
        self.assertEqual(rc, 4)
        self.assertIn("nothing to roll back", err)

    def test_apply_detects_cap_not_in_force(self):
        open(os.path.join(self.stub, "maint-active"), "w").close()
        with open(os.path.join(self.stub, "force-memmax-pft-free.service"), "w") as f:
            f.write("infinity\n")
        self.report([rec("pft-free.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(3)])
        rc, out, _ = self.run_main("apply", "--yes", "--now", str(T0 + 3 * DAY), "--data", self.datafile)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL pft-free.service MemoryMax=infinity (want 134217728)", out)

    def test_apply_reports_unapplied_cap(self):
        open(os.path.join(self.stub, "maint-active"), "w").close()
        with open(os.path.join(self.stub, "reload-rc"), "w") as f:
            f.write("1")
        self.report([rec("pft-free.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(3)])
        rc, _, _ = self.run_main("apply", "--yes", "--now", str(T0 + 3 * DAY), "--data", self.datafile)
        self.assertEqual(rc, 1)

    def test_rollback_refused_without_window(self):
        open(os.path.join(self.stub, "maint-active"), "w").close()
        self.report([rec("pft-free.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(3)])
        self.run_main("apply", "--yes", "--now", str(T0 + 3 * DAY), "--data", self.datafile)
        os.remove(os.path.join(self.stub, "maint-active"))
        n = len(self.calls())
        rc, _, err = self.run_main("rollback", "--yes")
        self.assertEqual(rc, 4)
        self.assertIn("no active pft-maint window", err)
        self.assertTrue(os.path.exists(self.dropin("pft-free.service")))
        self.assertEqual(len(self.calls()), n)

    def test_apply_refuses_excluded_unit_even_if_planned(self):
        open(os.path.join(self.stub, "maint-active"), "w").close()
        self.report([rec("pft-free.service", T0 + i * DAY, 40 * MIB, cap=None) for i in range(3)])
        orig = budget.build_plan
        budget.build_plan = lambda *a, **k: [{"unit": "docker.service", "action": "set", "from": None, "to": MIB,
                                              "peak": 1, "proj90": None, "runs": 3}]  # fmt: skip
        try:
            rc, _, err = self.run_main("apply", "--yes", "--now", str(T0 + 3 * DAY), "--data", self.datafile)
        finally:
            budget.build_plan = orig
        self.assertEqual(rc, 4)
        self.assertIn("docker.service is excluded", err)
        self.assertEqual((os.listdir(self.dropins), self.calls()), ([], []))


class TestConf(Base):
    def conf_file(self, text):
        p = os.path.join(self.tmp, "c.env")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_shell_keys_ignored_unknown_rejected(self):
        os.environ.pop("PFT_BUD_HOST")
        c = budget.load_conf(self.conf_file("# c\nHOST=sentry\nPULL_SSH=ssh x\nTEXT_MAX_BYTES=1\nINTERVAL=0.5\n"))
        self.assertEqual((c["HOST"], c["INTERVAL"]), ("sentry", 0.5))
        with self.assertRaises(budget.ConfError):
            budget.load_conf(self.conf_file("NOPE=1\n"))

    def test_bad_values(self):
        for k, v in (("HOST", "Pft Agent"), ("INTERVAL", "0"), ("KEEP", "1.5"), ("FAIL_FRACTION", "2"),
                     ("MAX_BYTES", "100"), ("WINDOW_DAYS", "x")):  # fmt: skip
            os.environ["PFT_BUD_" + k] = v
            with self.assertRaises(budget.ConfError, msg=k):
                budget.load_conf("/nonexistent")
            os.environ.pop("PFT_BUD_" + k)
        os.environ["PFT_BUD_HOST"] = "validator"

    def test_cli_rc(self):
        p = os.path.join(self.data, "in.jsonl")
        for peak, want in ((100, 0), (300, 2), (480, 1)):
            with open(p, "w") as f:
                f.write("".join(json.dumps(rec("pft-a.service", T0 + i, peak * MIB)) + "\n" for i in range(3)))
            r = subprocess.run([sys.executable, HELPER, "--conf", "/nonexistent", "report", "--now", str(T0 + 9),
                                "--data", p], capture_output=True, text=True, env=dict(os.environ))  # fmt: skip
            self.assertEqual(r.returncode, want, r.stdout + r.stderr)
        r = subprocess.run([sys.executable, HELPER, "--conf", self.conf_file("BAD\n"), "report"], capture_output=True,
                           text=True)  # fmt: skip
        self.assertEqual(r.returncode, 3)


class TestShell(Base):
    def sh(self, *args, extra=None):
        env = dict(os.environ, PFT_BUD_HELPER=HELPER, PFT_BUD_CONF="/nonexistent", PFT_BUD_TEXTFILE_DIR=self.textdir)
        env.update(extra or {})
        return subprocess.run(["bash", SH, *args], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)

    def seed(self, n=3, peak=100):
        with open(os.path.join(self.data, "samples.jsonl"), "w") as f:
            f.write("".join(json.dumps(rec("pft-a.service", T0 + i, peak * MIB)) + "\n" for i in range(n)))
        with open(os.path.join(self.data, "heartbeat"), "w") as f:
            f.write(f"{int(T0) + 5}\n")

    def test_collect_writes_validated_textfile(self):
        self.seed()
        r = self.sh("collect", extra={"PFT_BUD_NOW": str(T0 + 10)})
        self.assertEqual(r.returncode, 0, r.stderr)
        f = os.path.join(self.textdir, "pft_budget_validator.prom")
        text = open(f).read()
        self.assertIn('pft_budget_up{host="validator"} 1\n', text)
        self.assertIn('pft_budget_sampler_heartbeat_timestamp_seconds{host="validator"} 1795000005\n', text)
        self.assertIn('pft_budget_verdict{host="validator",unit="pft-a.service"} 0\n', text)
        self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"))
        self.assertEqual(self.sh("validate", f, "validator").returncode, 0)
        r = self.sh("validate", f, "sentry")
        self.assertEqual(r.returncode, 2)
        self.assertIn('first label is not host="sentry"', r.stdout)

    def test_collect_over_budget_is_up0(self):
        self.seed()
        r = self.sh("collect", extra={"PFT_BUD_NOW": str(T0 + 10), "PFT_BUD_TEXT_MAX_BYTES": "4096"})
        self.assertEqual(r.returncode, 0)  # the small report fits
        with open(os.path.join(self.data, "samples.jsonl"), "a") as f:
            for i in range(80):
                f.write(json.dumps(rec(f"pft-u{i}.service", T0 + 1, MIB)) + "\n")
        r = self.sh("collect", extra={"PFT_BUD_NOW": str(T0 + 10), "PFT_BUD_TEXT_MAX_BYTES": "4096"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("over TEXT_MAX_BYTES 4096: up 0", r.stderr)
        text = open(os.path.join(self.textdir, "pft_budget_validator.prom")).read()
        self.assertIn('pft_budget_up{host="validator"} 0\n', text)
        self.assertNotIn("pft_budget_verdict", text)

    def test_collect_helper_failure_is_up0(self):
        self.seed()
        r = self.sh("collect", extra={"PFT_BUD_INTERVAL": "0"})
        self.assertEqual(r.returncode, 1)
        text = open(os.path.join(self.textdir, "pft_budget_validator.prom")).read()
        self.assertEqual(text.splitlines()[-1], 'pft_budget_up{host="validator"} 0')

    def test_validate_rejects_foreign_and_malformed(self):
        p = os.path.join(self.tmp, "t.prom")
        for body, why in (
            ('node_x{host="validator"} 1\npft_budget_up{host="validator"} 1\n', "not a pft_budget_ sample"),
            ('pft_budget_up{host="validator"} one\n', "malformed sample"),
            ('pft_budget_verdict{host="validator",unit="a"} 1\n', "no pft_budget_up sample"),
            ("pft_budget_up 1\n", "not a pft_budget_ sample"),
        ):
            with open(p, "w") as f:
                f.write(body)
            r = self.sh("validate", p, "validator")
            self.assertEqual(r.returncode, 2, body)
            self.assertIn(why, r.stdout)

    def test_status(self):
        self.seed()
        r = self.sh("status", extra={"PFT_BUD_NOW": str(T0 + 65)})
        self.assertEqual(r.returncode, 0)
        self.assertIn("last scan 60s ago", r.stdout)
        r = self.sh("status", extra={"PFT_BUD_NOW": str(T0 + 306)})
        self.assertEqual(r.returncode, 4)
        self.assertIn("STALE, last scan 301s ago (> 300s)", r.stdout)
        os.remove(os.path.join(self.data, "heartbeat"))
        self.assertEqual(self.sh("status").returncode, 4)

    def test_report_passthrough_rc(self):
        self.seed(peak=480)
        r = self.sh("report", "--now", str(T0 + 10))
        self.assertEqual(r.returncode, 1)
        self.assertIn("RESULT: 0 OK, 0 WARN, 1 FAIL, 0 UNCAPPED", r.stdout)

    def test_pull(self):
        ssh = os.path.join(self.stub, "fake-ssh")
        with open(ssh, "w") as f:  # "$PULL_SSH cat -- REMOTE/FILE" -> cat of the local copy
            f.write('#!/bin/sh\n[ "$1" = cat ] && [ "$2" = -- ] || exit 9\nexec cat "$3"\n')
        os.chmod(ssh, 0o755)
        remote = os.path.join(self.tmp, "remote")
        os.makedirs(remote)
        good = 'pft_budget_up{host="sentry"} 1\npft_budget_verdict{host="sentry",unit="pft-a.service"} 0\n'
        with open(os.path.join(remote, "pft_budget_sentry.prom"), "w") as f:
            f.write(good)
        env = {"PFT_BUD_PULL_SSH": ssh, "PFT_BUD_REMOTE_DIR": remote}
        r = self.sh("pull", "--host", "sentry", extra=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(open(os.path.join(self.textdir, "pft_budget_sentry.prom")).read(), good)
        with open(os.path.join(remote, "pft_budget_sentry.prom"), "w") as f:
            f.write('pft_budget_up{host="validator"} 1\n')  # a file for the wrong host is refused, old one kept
        r = self.sh("pull", "--host", "sentry", extra=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn('validation failed: line 1: first label is not host="sentry"', r.stderr)
        self.assertEqual(open(os.path.join(self.textdir, "pft_budget_sentry.prom")).read(), good)
        self.assertEqual([n for n in os.listdir(self.textdir) if n.startswith(".")], [])
        r = self.sh("pull", extra=env)
        self.assertEqual(r.returncode, 3)
        self.assertIn("pull needs --host NAME", r.stderr)
        self.assertEqual(self.sh("pull", "--host", "Bad Host", extra=env).returncode, 3)

    def test_usage(self):
        self.assertEqual(self.sh("bogus").returncode, 3)
        self.assertEqual(self.sh("pull").returncode, 3)  # no --host
        self.assertEqual(self.sh("pull", "--host", "sentry").returncode, 3)  # no PULL_SSH (conf only)
        self.assertEqual(self.sh("version").stdout, "pft-budget 1\n")


class TestUnits(unittest.TestCase):
    def unit(self, name):
        return open(os.path.join(BUD, "systemd", name)).read()

    def test_sampler_unit_caps_itself(self):
        u = self.unit("pft-budget-sampler.service")
        self.assertIn("\nMemoryMax=64M\n", u)
        self.assertIn("\nCPUQuota=", u)
        self.assertIn("\nProtectSystem=strict\n", u)
        self.assertIn("\nReadWritePaths=/var/lib/pft-budget\n", u)
        self.assertIn("budget.py --conf /etc/pft-budget.env sample\n", u)

    def test_collect_unit(self):
        u = self.unit("pft-budget-collect.service")
        self.assertIn("ExecStart=/usr/local/bin/pft-budget collect", u)
        self.assertIn("\nMemoryMax=", u)


if __name__ == "__main__":
    unittest.main()
