#!/usr/bin/env python3
"""Offline tests for pft-internals (stdlib unittest). Fixtures: real admin `get_counts` / `server_info
{"counters": true}` captures of both hosts (2026-11-16, server_info reduced by redact_capture.py); variants are
derived from them in each test.

Run: python3 -I tests/test_internals.py   (scratch under $TEST_TMPDIR, default ~/.cache: /tmp is noexec here)
"""

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PARSER = os.path.join(ROOT, "internals_parse.py")
SCRIPT = os.path.join(ROOT, "pft-internals.sh")
FIX = os.path.join(HERE, "fixtures")
NOW = 1794805000
BASE = os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache")

REQUIRED_GC = (
    "AL_size",
    "treenode_cache_size",
    "treenode_track_size",
    "fullbelow_size",
    "AL_hit_rate",
    "ledger_hit_rate",
    "SLE_hit_rate",
    "dbKBTotal",
    "dbKBLedger",
    "dbKBTransaction",
    "node_reads_total",
    "node_reads_hit",
    "node_read_bytes",
    "node_writes",
    "node_written_bytes",
    "node_reads_duration_us",
    "read_queue",
    "read_threads_running",
    "read_threads_total",
    "read_request_bundle",
    "write_load",
    "historical_perminute",
    "CachedView::hit",
    "CachedView::miss",
)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


def samples(text):
    """{'metric{labels}': 'value'} of the non-comment lines."""
    out = {}
    for ln in text.splitlines():
        if ln and not ln.startswith("#"):
            k, v = ln.rsplit(" ", 1)
            out[k] = v
    return out


class Base(unittest.TestCase):
    def setUp(self):
        os.makedirs(BASE, exist_ok=True)
        self.d = tempfile.mkdtemp(prefix="pft-in-test.", dir=BASE)
        os.chmod(self.d, 0o755)
        self.state = os.path.join(self.d, "state.json")
        self.conf = os.path.join(self.d, "conf")
        self.write_conf("")
        self.gc = load("validator-get_counts.json")
        self.si = load("validator-server_info.json")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write_conf(self, text):
        with open(self.conf, "w", encoding="utf-8") as f:
            f.write(text)

    def dump(self, name, doc):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))
        return p

    def collect(self, gc=None, si=None, now=NOW, container="postfiatd", extra=()):
        gp = self.dump("gc.json", self.gc if gc is None else gc)
        sp = self.dump("si.json", self.si if si is None else si)
        args = [sys.executable, "-I", PARSER, "collect", "--counts", gp, "--server-info", sp, "--state", self.state]
        args += ["--container", container, "--conf", self.conf, "--now", str(now), *extra]
        return subprocess.run(args, check=False, capture_output=True, text=True, timeout=30)

    def ok(self, **kw):
        p = self.collect(**kw)
        self.assertEqual(p.returncode, 0, p.stderr)
        return samples(p.stdout), p

    def bad(self, reason, **kw):
        before = read(self.state) if os.path.exists(self.state) else None
        p = self.collect(**kw)
        self.assertEqual(p.returncode, 1, p.stdout[:200])
        self.assertEqual(p.stdout, "")
        self.assertRegex(p.stderr, reason)
        after = read(self.state) if os.path.exists(self.state) else None
        self.assertEqual(before, after, "state must not change on invalid input")
        return p


C = 'container="postfiatd"'


class TestFixtures(Base):
    def test_validator_values(self):
        s, _ = self.ok()
        self.assertEqual(s[f"pft_internals_nodestore_reads_total{{{C}}}"], "3055095")
        self.assertEqual(s[f"pft_internals_nodestore_read_hits_total{{{C}}}"], "2237360")
        self.assertEqual(s[f"pft_internals_nodestore_read_duration_seconds_total{{{C}}}"], "159.487549")
        self.assertEqual(s[f"pft_internals_node_uptime_seconds{{{C}}}"], "120077")
        self.assertEqual(s[f'pft_internals_db_bytes{{{C},db="total"}}'], str(2214 * 1024))
        self.assertEqual(s[f'pft_internals_cache_size{{{C},cache="treenode"}}'], "577")
        self.assertEqual(s[f'pft_internals_objects{{{C},type="STInteger<unsigned int>"}}'], "40591")
        self.assertEqual(s[f'pft_internals_job_queued_total{{{C},job_type="acceptLedger"}}'], "39657")
        self.assertEqual(s[f'pft_internals_job_queue_wait_seconds{{{C},job_type="acceptLedger"}}'], "55.401446")
        self.assertEqual(s[f'pft_internals_rpc_started_total{{{C},method="fee"}}'], "2001")
        self.assertEqual(s[f'pft_internals_load_job_peak_ms{{{C},job_type="peerCommand"}}'], "182")
        self.assertEqual(s[f"pft_internals_load_threads{{{C}}}"], "6")
        self.assertEqual(s[f"pft_internals_node_restarts_total{{{C}}}"], "0")
        self.assertNotIn(f'pft_internals_job_queued_total{{{C},job_type="total"}}', s, "total is not a job type")
        self.assertNotIn(f'pft_internals_rpc_started_total{{{C},method="total"}}', s)

    def test_hit_ratio_units_normalised(self):
        s, _ = self.ok()
        self.assertEqual(s[f'pft_internals_cache_hit_ratio{{{C},cache="accepted_ledger"}}'], "0.497759")  # 49.776 %
        self.assertEqual(s[f'pft_internals_cache_hit_ratio{{{C},cache="ledger"}}'], "0.340082")
        self.assertEqual(s[f'pft_internals_cache_hit_ratio{{{C},cache="SLE"}}'], "0.896608")  # already 0..1

    def test_omitted_load_fields_are_zero(self):
        s, _ = self.ok()  # acceptLedger has no per_second in the capture
        self.assertEqual(s[f'pft_internals_load_job_per_second{{{C},job_type="acceptLedger"}}'], "0")
        self.assertEqual(s[f'pft_internals_load_job_avg_ms{{{C},job_type="acceptLedger"}}'], "25")

    def test_job_waiting_running_derived(self):
        si = copy.deepcopy(self.si)
        si["result"]["info"]["counters"]["job_queue"]["batch"].update(queued="20", started="15", finished="12")
        s, _ = self.ok(si=si)
        self.assertEqual(s[f'pft_internals_job_waiting{{{C},job_type="batch"}}'], "5")

    def test_sentry_fixture(self):
        self.gc, self.si = load("sentry-get_counts.json"), load("sentry-server_info.json")
        s, _ = self.ok(container="postfiatd-sentry")
        self.assertTrue(all(k.split("{", 1)[1].startswith('container="postfiatd-sentry"') for k in s))
        self.assertIn('pft_internals_rpc_started_total{container="postfiatd-sentry",method="peers"}', s)

    def test_body_size_and_series_recorded(self):
        _, p = self.ok()
        st = json.loads(read(self.state))
        self.assertEqual(st["bytes"], len(p.stdout.encode()))
        self.assertEqual(st["series"], len(samples(p.stdout)))
        self.assertLess(st["bytes"], 40000)

    def test_every_sample_line_well_formed(self):
        _, p = self.ok()
        for ln in p.stdout.splitlines():
            if ln.startswith("#"):
                self.assertRegex(ln, r"^# (HELP|TYPE) pft_internals_[a-z0-9_]+ ")
            else:
                self.assertRegex(ln, r'^pft_internals_[a-z0-9_]+\{container="postfiatd"[^{}]*\} -?[0-9]+(\.[0-9]+)?$')


class TestValidation(Base):
    def test_every_required_get_counts_field(self):
        for k in REQUIRED_GC:
            with self.subTest(field=k):
                gc = copy.deepcopy(self.gc)
                del gc["result"][k]
                self.bad(rf"get_counts: missing {re.escape(k)}", gc=gc)

    def test_uint_types(self):
        for v, why in ((True, "boolean"), (-1, "negative"), (1.5, "not a non-negative integer"),
                       ("12a", "not a non-negative integer"), ("", "not a non-negative integer"),
                       (None, "not a non-negative integer"), ("1" * 21, "not a non-negative integer")):  # fmt: skip
            with self.subTest(v=v):
                gc = copy.deepcopy(self.gc)
                gc["result"]["node_reads_total"] = v
                self.bad(rf"get_counts.node_reads_total: {why}", gc=gc)

    def test_queued_duration_may_be_negative(self):
        # postfiatd 1.0.9 after a restart: writeAhead queued_duration_us -136 (sentry, 2026-11-24)
        name = next(k for k in self.si["result"]["info"]["counters"]["job_queue"] if k != "total")
        for v in (-136, "-136"):
            with self.subTest(v=v):
                si = copy.deepcopy(self.si)
                si["result"]["info"]["counters"]["job_queue"][name]["queued_duration_us"] = v
                s, _ = self.ok(si=si)
                self.assertEqual(s[f'pft_internals_job_queue_wait_seconds{{{C},job_type="{name}"}}'], "-0.000136")
        for f, v, why in (("running_duration_us", -1, "negative"), ("queued", -1, "negative"),
                          ("queued_duration_us", "-1x", "not an integer"), ("queued_duration_us", True, "boolean")):  # fmt: skip
            with self.subTest(f=f, v=v):
                si = copy.deepcopy(self.si)
                si["result"]["info"]["counters"]["job_queue"][name][f] = v
                self.bad(rf"job_queue.{name}.{f}: {why}", si=si)

    def test_uint_accepts_int_and_decimal_string(self):
        gc = copy.deepcopy(self.gc)
        gc["result"]["node_writes"] = 5
        gc["result"]["read_queue"] = "7"
        s, _ = self.ok(gc=gc)
        self.assertEqual(s[f"pft_internals_nodestore_writes_total{{{C}}}"], "5")
        self.assertEqual(s[f"pft_internals_nodestore_read_queue{{{C}}}"], "7")

    def test_hit_rate_ranges(self):
        for k, v, why in (("AL_hit_rate", 100.5, "outside 0..100"), ("SLE_hit_rate", 1.5, "outside 0..1"),
                          ("ledger_hit_rate", -0.1, "outside 0..100"), ("SLE_hit_rate", "0.5", "not a finite"),
                          ("AL_hit_rate", True, "not a finite")):  # fmt: skip
            with self.subTest(k=k, v=v):
                gc = copy.deepcopy(self.gc)
                gc["result"][k] = v
                self.bad(rf"get_counts.{k}: .*{why}", gc=gc)
        gc = copy.deepcopy(self.gc)
        p = self.dump("nan.json", json.dumps(gc).replace('"SLE_hit_rate": 0.8966077157837077', '"SLE_hit_rate": NaN'))
        self.assertIn("NaN", read(p))
        self.bad(r"SLE_hit_rate: not a finite", gc=read(p))

    def test_hit_rate_bounds_inclusive(self):
        gc = copy.deepcopy(self.gc)
        gc["result"].update(AL_hit_rate=100, SLE_hit_rate=0)
        s, _ = self.ok(gc=gc)
        self.assertEqual(s[f'pft_internals_cache_hit_ratio{{{C},cache="accepted_ledger"}}'], "1")
        self.assertEqual(s[f'pft_internals_cache_hit_ratio{{{C},cache="SLE"}}'], "0")

    def test_rpc_errors_and_garbage(self):
        self.bad(r"get_counts: not JSON", gc="<html>")
        self.bad(r"get_counts: rpc answer is not a success \(noPermission\)", gc={"result": {"status": "error", "error": "noPermission"}})  # fmt: skip
        self.bad(r"server_info: rpc answer is not a success \(no result\)", si=[1, 2])
        self.bad(r"server_info: not JSON", si="")

    def test_counters_param_missing(self):
        si = copy.deepcopy(self.si)
        del si["result"]["info"]["counters"]
        self.bad(r"missing counters", si=si)

    def test_server_info_structure(self):
        for path, why in ((("uptime",), "missing uptime"), (("load",), "missing load"),
                          (("load", "threads"), "missing threads"), (("load", "job_types"), "missing job_types"),
                          (("counters", "rpc"), "missing rpc"), (("counters", "job_queue"), "missing job_queue")):  # fmt: skip
            with self.subTest(path=path):
                si = copy.deepcopy(self.si)
                d = si["result"]["info"]
                for p in path[:-1]:
                    d = d[p]
                del d[path[-1]]
                self.bad(why, si=si)

    def test_job_field_missing_and_order(self):
        si = copy.deepcopy(self.si)
        del si["result"]["info"]["counters"]["job_queue"]["sweep"]["running_duration_us"]
        self.bad(r"job_queue.sweep: missing running_duration_us", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["counters"]["job_queue"]["sweep"].update(started="10", finished="11", queued="12")
        self.bad(r"job_queue.sweep: want finished <= started <= queued", si=si)
        si["result"]["info"]["counters"]["job_queue"]["sweep"].update(started="13", finished="11", queued="12")
        self.bad(r"job_queue.sweep: want finished <= started <= queued", si=si)

    def test_empty_sets_rejected(self):
        si = copy.deepcopy(self.si)
        si["result"]["info"]["counters"]["job_queue"] = {
            "total": si["result"]["info"]["counters"]["job_queue"]["total"]
        }
        self.bad(r"no job types", si=si)
        gc = copy.deepcopy(self.gc)
        gc["result"] = {k: v for k, v in gc["result"].items() if not k.startswith("ripple::")}
        self.bad(r"no ripple:: object counts", gc=gc)

    def test_label_injection_rejected(self):
        si = copy.deepcopy(self.si)
        si["result"]["info"]["counters"]["rpc"]['fee"} 1\nevil{x="'] = {
            "started": "1", "finished": "1", "errored": "0", "duration_us": "1"}  # fmt: skip
        self.bad(r"bad method name", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["counters"]["job_queue"]["bad-name"] = si["result"]["info"]["counters"]["job_queue"][
            "sweep"
        ]
        self.bad(r"bad job type name", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["load"]["job_types"].append({"job_type": 'x"y'})
        self.bad(r"bad job_type", si=si)
        gc = copy.deepcopy(self.gc)
        gc["result"]['ripple::Evil"}'] = 1
        self.bad(r"bad object type name", gc=gc)

    def test_method_names_strict(self):
        """Names without a newline that a loose pattern would pass: quote/brace, upper case, 33 chars."""
        for name in ('fee"}', "Fee", "f" * 33, "fee-x", "1fee"):
            with self.subTest(name=name):
                si = copy.deepcopy(self.si)
                si["result"]["info"]["counters"]["rpc"][name] = dict(si["result"]["info"]["counters"]["rpc"]["fee"])
                self.bad(r"bad method name", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["counters"]["rpc"]["f" * 32] = dict(si["result"]["info"]["counters"]["rpc"]["fee"])
        s, _ = self.ok(si=si)
        self.assertIn(f'pft_internals_rpc_started_total{{{C},method="{"f" * 32}"}}', s)

    def test_load_entries(self):
        si = copy.deepcopy(self.si)
        si["result"]["info"]["load"]["job_types"].append(dict(si["result"]["info"]["load"]["job_types"][0]))
        self.bad(r"load.job_types: duplicate clientConsensus", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["load"]["job_types"][0]["over_target"] = 1
        self.bad(r"over_target: not a boolean", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["load"]["job_types"][0]["peak_time"] = -3
        self.bad(r"load.clientConsensus.peak_time: negative", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["load"]["job_types"] = {"a": 1}
        self.bad(r"job_types: not a list", si=si)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["load"]["job_types"][0]["over_target"] = True
        s, _ = self.ok(si=si)
        self.assertEqual(s[f'pft_internals_load_job_over_target{{{C},job_type="clientConsensus"}}'], "1")
        self.assertEqual(s[f'pft_internals_load_job_over_target{{{C},job_type="clientRPC"}}'], "0")

    def test_bad_conf_is_usage_error(self):
        self.write_conf("MAX_RPC_METHODS=0\n")
        p = self.collect()
        self.assertEqual(p.returncode, 3)
        self.assertIn("MAX_RPC_METHODS", p.stderr)
        self.write_conf("MAX_BYTES=abc\n")
        self.assertEqual(self.collect().returncode, 3)


def many_methods(si, n, width=6):
    si = copy.deepcopy(si)
    rpc = si["result"]["info"]["counters"]["rpc"]
    rpc.clear()
    for i in range(n):
        rpc[f"m{i:0{width}d}"] = {"started": str(i + 1), "finished": str(i), "errored": "1", "duration_us": "1000000"}
    rpc["total"] = {"started": "0", "finished": "0", "errored": "0", "duration_us": "0"}
    return si


class TestCardinality(Base):
    def test_rpc_methods_capped_with_other(self):
        s, _ = self.ok(si=many_methods(self.si, 300))
        methods = {re.search(r'method="([^"]+)"', k).group(1) for k in s if k.startswith("pft_internals_rpc_started")}
        self.assertEqual(len(methods), 24)
        self.assertIn("other", methods)
        self.assertIn("m000000", methods)
        self.assertIn("m000022", methods)
        self.assertNotIn("m000023", methods)  # sorted: m000000..m000022 keep their label
        self.assertEqual(s[f'pft_internals_label_overflow{{{C},kind="method"}}'], "277")
        self.assertEqual(s[f'pft_internals_rpc_started_total{{{C},method="other"}}'], str(sum(range(24, 301))))
        self.assertEqual(s[f'pft_internals_rpc_errored_total{{{C},method="other"}}'], "277")
        self.assertEqual(s[f'pft_internals_rpc_duration_seconds_total{{{C},method="other"}}'], "277")

    def test_cap_exact_keeps_all(self):
        s, _ = self.ok(si=many_methods(self.si, 24))
        methods = {re.search(r'method="([^"]+)"', k).group(1) for k in s if k.startswith("pft_internals_rpc_started")}
        self.assertEqual(len(methods), 24)
        self.assertNotIn("other", methods)
        self.assertEqual(s[f'pft_internals_label_overflow{{{C},kind="method"}}'], "0")

    def test_cap_from_conf(self):
        self.write_conf("MAX_RPC_METHODS=5\nMAX_OBJECT_TYPES=3\nMAX_JOB_TYPES=4\n")
        s, _ = self.ok(si=many_methods(self.si, 10))
        self.assertEqual(sum(1 for k in s if k.startswith("pft_internals_rpc_started")), 5)
        self.assertEqual(sum(1 for k in s if k.startswith("pft_internals_objects")), 3)
        self.assertEqual(sum(1 for k in s if k.startswith("pft_internals_job_queued_total")), 4)
        self.assertEqual(sum(1 for k in s if k.startswith("pft_internals_load_job_peak_ms")), 4)
        objs = {k: int(v) for k, v in s.items() if k.startswith("pft_internals_objects")}
        total = sum(v for k, v in self.gc["result"].items() if k.startswith("ripple::"))
        self.assertEqual(sum(objs.values()), total, "folding keeps the object total")
        jq = self.si["result"]["info"]["counters"]["job_queue"]
        q = sum(int(v["queued"]) for k, v in jq.items() if k != "total")
        self.assertEqual(sum(int(v) for k, v in s.items() if k.startswith("pft_internals_job_queued_total")), q)
        peaks = [int(v) for k, v in s.items() if k.startswith(f'pft_internals_load_job_peak_ms{{{C},job_type="other"')]
        self.assertEqual(peaks, [182], "other takes the max peak, not the sum")

    def test_worst_case_fits_default_budget(self):
        """Every cap filled with maximum-length names still fits MAX_BYTES (61440) incl. the 1024 B header reserve."""
        si = copy.deepcopy(self.si)
        c = si["result"]["info"]["counters"]
        c["rpc"] = {("r" + f"{i:03d}" + "x" * 28): {"started": "9" * 19, "finished": "9" * 19, "errored": "9" * 19,
                    "duration_us": "9" * 19} for i in range(200)}  # fmt: skip
        c["job_queue"] = {("J" + f"{i:03d}" + "y" * 28): {f: "9" * 19 for f in ("queued", "started", "finished",
                          "queued_duration_us", "running_duration_us")} for i in range(200)}  # fmt: skip
        si["result"]["info"]["load"]["job_types"] = [
            {"job_type": "J" + f"{i:03d}" + "y" * 28, "per_second": 10**9, "peak_time": 10**9, "avg_time": 10**9,
             "in_progress": 10**9, "over_target": True} for i in range(200)]  # fmt: skip
        gc = copy.deepcopy(self.gc)
        for i in range(200):
            gc["result"]["ripple::" + f"T{i:03d}" + "z" * 44] = 10**12
        s, p = self.ok(gc=gc, si=si, extra=("--reserve", "1024"))
        size = len(p.stdout.encode())
        self.assertLessEqual(size + 1024, 61440, size)
        self.assertEqual(s[f'pft_internals_label_overflow{{{C},kind="method"}}'], "177")

    def test_over_budget_fails_closed(self):
        self.write_conf("MAX_RPC_METHODS=100\n")
        p = self.bad(
            r"over the 20000 B budget", si=many_methods(self.si, 200, width=30), extra=("--max-bytes", "20000")
        )
        self.assertFalse(os.path.exists(self.state))
        self.assertIn("MAX_BYTES", p.stderr)


class TestBudgetEdge(Base):
    def test_budget_boundary_and_reserve(self):
        _, p = self.ok()
        size = len(p.stdout.encode())
        os.unlink(self.state)
        self.ok(extra=("--max-bytes", str(size), "--reserve", "0"))  # exactly at the budget passes
        os.unlink(self.state)
        self.bad(r"over the", extra=("--max-bytes", str(size - 1), "--reserve", "0"))
        self.bad(r"\+ 1024 B header is over", extra=("--max-bytes", str(size + 1023), "--reserve", "1024"))
        self.ok(extra=("--max-bytes", str(size + 1024), "--reserve", "1024"))

    def test_parser_usage_exit_3(self):
        p = subprocess.run([sys.executable, "-I", PARSER], check=False, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 3)
        p = subprocess.run(
            [sys.executable, "-I", PARSER, "collect", "--counts", "x"], check=False, capture_output=True, text=True
        )
        self.assertEqual(p.returncode, 3)


class TestRestarts(Base):
    def bump(self, si, gc, up, scale):
        si, gc = copy.deepcopy(si), copy.deepcopy(gc)
        si["result"]["info"]["uptime"] = up
        for k in ("node_reads_total", "node_reads_hit", "node_writes"):
            gc["result"][k] = str(int(int(gc["result"][k]) * scale))
        return si, gc

    def test_normal_growth(self):
        self.ok()
        si, gc = self.bump(self.si, self.gc, 120137, 1.01)
        s, _ = self.ok(si=si, gc=gc, now=NOW + 60)
        self.assertEqual(s[f"pft_internals_node_restarts_total{{{C}}}"], "0")
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "0")

    def test_restart_counted_not_anomaly(self):
        self.ok()
        si, gc = self.bump(self.si, self.gc, 30, 0.001)
        s, p = self.ok(si=si, gc=gc, now=NOW + 60)
        self.assertEqual(s[f"pft_internals_node_restarts_total{{{C}}}"], "1")
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "0")
        self.assertEqual(s[f"pft_internals_nodestore_reads_total{{{C}}}"], "3055", "counters exported as the node says")
        self.assertEqual(p.stderr, "")
        self.assertEqual(json.loads(read(self.state))["last_restart"], NOW + 60)
        si2, gc2 = self.bump(si, gc, 90, 2)  # growth after the restart is normal again
        s, _ = self.ok(si=si2, gc=gc2, now=NOW + 120)
        self.assertEqual(s[f"pft_internals_node_restarts_total{{{C}}}"], "1")
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "0")

    def test_decrease_without_restart_is_anomaly(self):
        self.ok()
        si, gc = self.bump(self.si, self.gc, 120137, 0.5)
        s, p = self.ok(si=si, gc=gc, now=NOW + 60)
        self.assertEqual(s[f"pft_internals_node_restarts_total{{{C}}}"], "0")
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "1")
        self.assertIn("counters went down without a restart: ns.nodestore_read_hits_total", p.stderr)
        st = json.loads(read(self.state))
        self.assertEqual(st["last_anomaly"]["ts"], NOW + 60)
        self.assertIn("ns.nodestore_reads_total", st["last_anomaly"]["counters"])

    def test_single_rpc_counter_decrease_is_anomaly(self):
        self.ok()
        si = copy.deepcopy(self.si)
        si["result"]["info"]["uptime"] = 120100
        si["result"]["info"]["counters"]["rpc"]["fee"]["errored"] = "0"
        si["result"]["info"]["counters"]["rpc"]["fee"]["started"] = "2000"
        s, p = self.ok(si=si, now=NOW + 60)
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "1")
        self.assertIn("rpc.fee.started", p.stderr)

    def test_32bit_wrap_is_not_an_anomaly(self):
        """Real 2026-11-20 validator pair: node_read_bytes 4293619473 -> 10786189 with uptime up (2**32 wrap)."""
        gc = copy.deepcopy(self.gc)
        gc["result"]["node_read_bytes"] = "4293619473"
        self.ok(gc=gc)
        si = copy.deepcopy(self.si)
        si["result"]["info"]["uptime"] = 120107
        gc["result"]["node_read_bytes"] = "10786189"
        s, p = self.ok(si=si, gc=gc, now=NOW + 30)
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "0")
        self.assertEqual(s[f"pft_internals_nodestore_read_bytes_total{{{C}}}"], "10786189")
        self.assertIn("counters wrapped at 2^32 (not an anomaly): ns.nodestore_read_bytes_total", p.stderr)
        st = json.loads(read(self.state))
        self.assertEqual(st["last_wrap"], {"ts": NOW + 30, "counters": ["ns.nodestore_read_bytes_total"]})
        self.assertIsNone(st["last_anomaly"])

    def test_is_wrap_boundaries(self):
        sys.path.insert(0, ROOT)
        try:
            import internals_parse
        finally:
            sys.path.pop(0)
        cases = [
            (4293619473, 10786189, True),  # the live pair
            (2**32 - 1, 0, True),
            (2**32 - 1, 2**30 - 2, True),  # forward step 2**30 - 1, the largest accepted
            (2**32 - 1, 2**30 - 1, False),  # forward step 2**30
            (1000, 999, False),  # a small real decrease
            (3_000_000_000, 1_000_000_000, False),  # forward step 2.29e9, too large
            (2**32 + 5, 10, False),  # a counter already past 2**32 did not wrap at 2**32 (step mod 2**32 = 5)
            (5, 5, False),
        ]
        for old, new, wrap in cases:
            with self.subTest(old=old, new=new):
                self.assertIs(internals_parse.is_wrap(old, new), wrap)

    def test_queued_duration_decrease_is_not_an_anomaly(self):
        """Real 2026-11-16 validator pair: acceptLedger queued_duration_us 55548503 -> 55543016 with uptime up."""
        si = copy.deepcopy(self.si)
        si["result"]["info"]["counters"]["job_queue"]["acceptLedger"]["queued_duration_us"] = "55548503"
        self.ok(si=si)
        si["result"]["info"]["uptime"] = 120107
        si["result"]["info"]["counters"]["job_queue"]["acceptLedger"]["queued_duration_us"] = "55543016"
        s, p = self.ok(si=si, now=NOW + 30)
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "0")
        self.assertEqual(p.stderr, "")
        self.assertNotIn("job.acceptLedger.queued_duration_us", json.loads(read(self.state))["counters"])
        self.assertEqual(s[f'pft_internals_job_queue_wait_seconds{{{C},job_type="acceptLedger"}}'], "55.543016")
        self.assertIn("# TYPE pft_internals_job_queue_wait_seconds gauge", p.stdout)
        si["result"]["info"]["uptime"] = 120137  # running_duration_us is still a checked counter
        si["result"]["info"]["counters"]["job_queue"]["acceptLedger"]["running_duration_us"] = "1"
        s, p = self.ok(si=si, now=NOW + 60)
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "1")
        self.assertIn("job.acceptLedger.running_duration_us", p.stderr)

    def test_equal_uptime_same_counters_ok(self):
        self.ok()
        s, _ = self.ok(now=NOW + 60)
        self.assertEqual(s[f"pft_internals_counter_anomalies_total{{{C}}}"], "0")
        self.assertEqual(s[f"pft_internals_node_restarts_total{{{C}}}"], "0")

    def test_counts_persist_and_corrupt_state_rebaselines(self):
        self.ok()
        si, gc = self.bump(self.si, self.gc, 10, 0.1)
        self.ok(si=si, gc=gc, now=NOW + 60)
        with open(self.state, "w") as f:
            f.write("{broken")
        s, p = self.ok(now=NOW + 120)
        self.assertIn("re-baselining", p.stderr)
        self.assertEqual(s[f"pft_internals_node_restarts_total{{{C}}}"], "0")

    def test_invalid_sample_keeps_state(self):
        self.ok()
        gc = copy.deepcopy(self.gc)
        gc["result"]["node_writes"] = "x"
        self.bad(r"node_writes", gc=gc, now=NOW + 60)
        self.assertEqual(json.loads(read(self.state))["last_success"], NOW)


class TestStatus(Base):
    def status(self, now):
        a = [sys.executable, "-I", PARSER, "status", "--state", self.state, "--conf", self.conf, "--now", str(now)]
        return subprocess.run(a + ["--json"], check=False, capture_output=True, text=True, timeout=30)

    def test_status(self):
        p = self.status(NOW)
        self.assertEqual(p.returncode, 4)
        self.assertEqual(json.loads(p.stdout)["status"], "UNKNOWN")
        self.ok()
        p = self.status(NOW + 300)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["status"], "OK")
        p = self.status(NOW + 301)
        self.assertEqual(p.returncode, 4)
        self.assertEqual(json.loads(p.stdout)["status"], "STALE")


class ShellBase(Base):
    def setUp(self):
        super().setUp()
        self.tf = os.path.join(self.d, "tf")
        self.sd = os.path.join(self.d, "st")
        self.bin = os.path.join(self.d, "bin")
        for x in (self.tf, self.sd, self.bin):
            os.mkdir(x)
        self.calls = os.path.join(self.d, "calls")
        self.dump("gcf.json", self.gc)
        self.dump("sif.json", self.si)
        self.docker(0)

    def docker(self, rc, gc="gcf.json", si="sif.json"):
        p = os.path.join(self.bin, "docker")
        with open(p, "w") as f:
            f.write(
                "#!/usr/bin/env bash\n"
                f'printf "%s\\n" "$*" >> {self.calls}\n'
                "echo 'WARNING: Error loading config file: /root/.docker/config.json' >&2\n"
                f"[ {rc} = 0 ] || {{ echo 'Error: No such container' >&2; exit {rc}; }}\n"
                f'case "$*" in *get_counts*) cat {self.d}/{gc} ;; *server_info*) cat {self.d}/{si} ;; *) exit 9 ;; esac\n'
            )
        os.chmod(p, 0o755)

    def env(self, **kw):
        e = dict(os.environ, PFT_IN_CONF=os.path.join(self.d, "noconf"), PFT_IN_DOCKER=os.path.join(self.bin, "docker"),
                 PFT_IN_PARSER=PARSER, STATE_DIR=self.sd, TEXTFILE_DIR=self.tf, PFT_IN_NOW=str(NOW))  # fmt: skip
        e.update(kw)
        return e

    def sh(self, *args, **kw):
        return subprocess.run(
            ["bash", SCRIPT, *args], check=False, capture_output=True, text=True, env=self.env(**kw), timeout=60
        )

    def prom(self, name="postfiatd"):
        with open(os.path.join(self.tf, f"pft_internals_{name}.prom")) as f:
            return f.read()


class TestShell(ShellBase):
    def test_collect_ok_and_exec_shape(self):
        p = self.sh("collect")
        self.assertEqual(p.returncode, 0, p.stderr)
        s = samples(self.prom())
        self.assertEqual(s[f"pft_internals_up{{{C}}}"], "1")
        self.assertEqual(s[f"pft_internals_collect_timestamp_seconds{{{C}}}"], str(NOW))
        self.assertEqual(s[f"pft_internals_last_success_timestamp_seconds{{{C}}}"], str(NOW))
        self.assertEqual(s[f"pft_internals_nodestore_reads_total{{{C}}}"], "3055095")
        calls = read(self.calls).splitlines()
        self.assertEqual(
            calls,
            [
                (
                    "exec postfiatd curl -s --max-time 8 -H Content-Type: application/json -d "
                    '{"method":"get_counts","params":[{}]} http://127.0.0.1:5005/'
                ),
                (
                    "exec postfiatd curl -s --max-time 8 -H Content-Type: application/json -d "
                    '{"method":"server_info","params":[{"counters":true}]} http://127.0.0.1:5005/'
                ),
            ],
        )
        self.assertEqual(oct(os.stat(os.path.join(self.tf, "pft_internals_postfiatd.prom")).st_mode & 0o777), "0o644")
        v = self.sh("validate", os.path.join(self.tf, "pft_internals_postfiatd.prom"), "postfiatd")
        self.assertEqual(v.returncode, 0, v.stdout)
        self.assertEqual(os.listdir(self.sd), ["state-postfiatd.json"], "no scratch dir left behind")
        st = self.sh("status", "--json")
        self.assertEqual(st.returncode, 0, st.stderr)
        self.assertEqual(json.loads(st.stdout)["status"], "OK")
        self.assertEqual(self.sh("status", PFT_IN_NOW=str(NOW + 301)).returncode, 4)

    def test_docker_failure_up0_keeps_last_good(self):
        self.assertEqual(self.sh("collect").returncode, 0)
        good = self.prom()
        self.docker(1)
        p = self.sh("collect", PFT_IN_NOW=str(NOW + 60))
        self.assertEqual(p.returncode, 1)
        self.assertIn("get_counts via docker exec postfiatd failed: WARNING", p.stderr)
        self.assertIn("Error: No such container: up 0", p.stderr)
        s = samples(self.prom())
        self.assertEqual(
            s,
            {
                f"pft_internals_up{{{C}}}": "0",
                f"pft_internals_collect_timestamp_seconds{{{C}}}": str(NOW + 60),
                f"pft_internals_last_success_timestamp_seconds{{{C}}}": str(NOW),
            },
        )
        with open(os.path.join(self.sd, "last-good-postfiatd.prom")) as f:
            self.assertEqual(f.read(), good)
        self.assertEqual(self.sh("collect", PFT_IN_NOW=str(NOW + 120)).returncode, 1)  # a 2nd failure keeps it
        with open(os.path.join(self.sd, "last-good-postfiatd.prom")) as f:
            self.assertEqual(f.read(), good)

    def test_first_failure_last_success_zero(self):
        self.docker(1)
        self.assertEqual(self.sh("collect").returncode, 1)
        self.assertEqual(samples(self.prom())[f"pft_internals_last_success_timestamp_seconds{{{C}}}"], "0")
        self.assertFalse(os.path.exists(os.path.join(self.sd, "last-good-postfiatd.prom")))

    def test_server_info_failure_and_invalid_field(self):
        self.dump("bad.json", {"result": {"status": "error", "error": "noPermission"}})
        self.docker(0, si="bad.json")
        p = self.sh("collect")
        self.assertEqual(p.returncode, 1)
        self.assertIn("server_info: rpc answer is not a success (noPermission)", p.stderr)
        self.assertEqual(samples(self.prom())[f"pft_internals_up{{{C}}}"], "0")
        gc = copy.deepcopy(self.gc)
        gc["result"]["dbKBTotal"] = -5
        self.dump("badgc.json", gc)
        self.docker(0, gc="badgc.json")
        p = self.sh("collect")
        self.assertIn("get_counts.dbKBTotal: negative (-5)", p.stderr)
        self.assertEqual(len(samples(self.prom())), 3)

    def test_budget_from_conf(self):
        p = self.sh("collect", MAX_BYTES="8192")
        self.assertEqual(p.returncode, 1)
        self.assertRegex(p.stderr, r"over the 8192 B budget")
        self.assertEqual(samples(self.prom())[f"pft_internals_up{{{C}}}"], "0")
        for bad in ("100", "70000", "abc", "0"):
            with self.subTest(bad=bad):
                p = self.sh("collect", MAX_BYTES=bad)
                self.assertEqual(p.returncode, 3)
                self.assertIn("bad MAX_BYTES", p.stderr)

    def test_shell_hard_gate_with_oversized_body(self):
        stub = os.path.join(self.bin, "bigparser.py")
        with open(stub, "w", encoding="utf-8") as f:
            f.write(
                "import sys\n"
                "if sys.argv[1] == 'last-success':\n    print(5)\n    sys.exit(0)\n"
                "print('# HELP pft_internals_node_uptime_seconds x')\n"
                'for i in range(3000):\n    print(\'pft_internals_x{container="postfiatd",i="%05d"} 1\' % i)\n'
            )
        p = self.sh("collect", PFT_IN_PARSER=stub)
        self.assertEqual(p.returncode, 1)
        self.assertRegex(p.stderr, r"textfile \d+ B is over MAX_BYTES 61440: up 0")
        s = samples(self.prom())
        self.assertEqual(sorted(s), sorted([f"pft_internals_up{{{C}}}", f"pft_internals_collect_timestamp_seconds{{{C}}}",
                         f"pft_internals_last_success_timestamp_seconds{{{C}}}"]))  # fmt: skip
        self.assertEqual(s[f"pft_internals_up{{{C}}}"], "0")

    def test_stdout_writes_nothing(self):
        p = self.sh("collect", "--stdout")
        self.assertEqual(p.returncode, 0)
        self.assertIn(f"pft_internals_up{{{C}}} 1", p.stdout)
        self.assertEqual(os.listdir(self.tf), [])

    def test_usage_errors(self):
        self.assertEqual(self.sh("collect", "--container", "a b").returncode, 3)
        self.assertEqual(self.sh("collect", "--bogus").returncode, 3)
        self.assertEqual(self.sh("collect", RPC_TIMEOUT="0").returncode, 3)
        self.assertEqual(self.sh("nope").returncode, 3)
        self.assertFalse(os.path.exists(self.calls), "no docker call on a usage error")

    def test_root_owned_conf_only(self):
        conf = self.dump("conf.env", "CONTAINER=evil\n")
        p = self.sh("collect", "--stdout", PFT_IN_CONF=conf)  # owned by the test user: ignored
        self.assertIn(f"pft_internals_up{{{C}}} 1", p.stdout)


class TestValidatePull(ShellBase):
    def validate(self, text, name="postfiatd-sentry", **kw):
        p = self.dump("cand.prom", text)
        return self.sh("validate", p, name, **kw)

    def good(self, name="postfiatd-sentry"):
        self.gc, self.si = load("sentry-get_counts.json"), load("sentry-server_info.json")
        self.dump("gcf.json", self.gc)
        self.dump("sif.json", self.si)
        p = self.sh("collect", "--container", name, "--stdout")
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def test_validate(self):
        g = self.good()
        self.assertEqual(self.validate(g).returncode, 0)
        cases = (
            (g.replace('container="postfiatd-sentry"', 'container="postfiatd"', 1), "first label is not"),
            (g + 'node_exporter_x{container="postfiatd-sentry"} 1\n', "not a pft_internals_ sample"),
            (g + 'pft_internals_x{container="postfiatd-sentry"} 1 2\n', "malformed sample"),
            (g + 'pft_internals_x{container="postfiatd-sentry",a="}"} 1\n', "malformed sample"),
            ("\n".join(x for x in g.splitlines() if not x.startswith("pft_internals_up{")) + "\n", "no pft_internals_up"),
            ("\n".join(x for x in g.splitlines() if "collect_timestamp_seconds{" not in x) + "\n", "no pft_internals_collect"),
        )  # fmt: skip
        for text, why in cases:
            with self.subTest(why=why):
                p = self.validate(text)
                self.assertEqual(p.returncode, 2)
                self.assertIn(why, p.stdout)
        p = self.validate(g, MAX_BYTES="4096")
        self.assertEqual(p.returncode, 2)
        self.assertIn("too big", p.stdout)

    def pull_ssh(self, src):
        s = os.path.join(self.bin, "fakessh")
        with open(s, "w") as f:
            f.write(f'#!/usr/bin/env bash\n[ "$1" = cat ] && [ "$2" = -- ] || exit 7\ncat {src}/"$(basename "$3")"\n')
        os.chmod(s, 0o755)
        return s

    def test_pull(self):
        src = os.path.join(self.d, "remote")
        os.mkdir(src)
        with open(os.path.join(src, "pft_internals_postfiatd-sentry.prom"), "w") as f:
            f.write(self.good())
        ssh = self.pull_ssh(src)
        p = self.sh("pull", PULL_SSH=ssh)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.prom("postfiatd-sentry"), read(os.path.join(src, "pft_internals_postfiatd-sentry.prom")))
        with open(os.path.join(src, "pft_internals_postfiatd-sentry.prom"), "w") as f:
            f.write("garbage 1\n")
        p = self.sh("pull", PULL_SSH=ssh)
        self.assertEqual(p.returncode, 2)
        self.assertIn("validation failed", p.stderr)
        self.assertIn("pft_internals_up", self.prom("postfiatd-sentry"), "a bad fetch leaves the old file")
        self.assertEqual(sorted(os.listdir(self.tf)), ["pft_internals_postfiatd-sentry.prom"], "no temp files left")
        os.unlink(os.path.join(src, "pft_internals_postfiatd-sentry.prom"))
        self.assertEqual(self.sh("pull", PULL_SSH=ssh).returncode, 1)
        self.assertEqual(self.sh("pull").returncode, 3, "PULL_SSH unset")


REPORT = os.path.join(ROOT, "report_internals.py")


class TestReport(Base):
    def capture(self, values_by_container, query_override=None):
        sys.path.insert(0, ROOT)
        try:
            import report_internals as ri
        finally:
            sys.path.pop(0)
        cap = {"window": {"start": 1000, "end": 1000 + 60 * 19, "step": 60}, "queries": {}}
        for name, (q, _u, _d) in ri.QUERIES.items():
            res = []
            for cont, vals in values_by_container.items():
                res.append({"metric": {"container": cont}, "values": [[1000 + 60 * i, v] for i, v in enumerate(vals)]})
            cap["queries"][name] = {"query": q, "data": {"resultType": "matrix", "result": res}}
        if query_override:
            cap["queries"][query_override]["query"] = "something else"
        return self.dump("cap.json", json.dumps(cap, sort_keys=True))

    def build(self, cap, tag="a"):
        md, js = os.path.join(self.d, f"r{tag}.md"), os.path.join(self.d, f"r{tag}.json")
        p = subprocess.run(
            [sys.executable, "-I", REPORT, "build", cap, "--md", md, "--json", js],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return p, md, js

    def test_stats_nearest_rank_and_coverage(self):
        vals = [str(v) for v in range(20, 0, -1)]  # 20 samples 20..1, unsorted on purpose
        cap = self.capture({"postfiatd-sentry": vals[:19], "postfiatd": vals + ["NaN"]})
        p, md, js = self.build(cap)
        self.assertEqual(p.returncode, 0, p.stderr)
        rep = json.loads(read(js))
        self.assertEqual(rep["expected_samples"], 20)
        rows = [r for r in rep["rows"] if r["query"] == "nodestore_read_ms"]
        self.assertEqual([r["container"] for r in rows], ["postfiatd", "postfiatd-sentry"], "sorted by container")
        v = rows[0]
        self.assertEqual((v["samples"], v["coverage_pct"]), (20, 100.0), "NaN is not a sample")
        self.assertEqual((v["min"], v["p50"], v["p95"], v["max"]), (1.0, 10.0, 19.0, 20.0))
        s = rows[1]  # 20..2 (19 samples): p50 = rank 10 -> 11, p95 = rank ceil(18.05) = 19 -> 20
        self.assertEqual((s["samples"], s["coverage_pct"]), (19, 95.0))
        self.assertEqual((s["min"], s["p50"], s["p95"], s["max"]), (2.0, 11.0, 20.0, 20.0))
        text = read(md)
        self.assertIn("| nodestore_read_ms | postfiatd | ms | 20 | 100.00 | 1 | 10 | 19 | 20 |", text)
        self.assertIn("Window 1970-01-01T00:16:40Z .. 1970-01-01T00:35:40Z (0.32 h), step 60 s", text)
        with open(cap, "rb") as f:
            self.assertEqual(rep["capture_sha256"], hashlib.sha256(f.read()).hexdigest())

    def test_byte_identical_rebuild(self):
        cap = self.capture({"postfiatd": ["0.25", "0.3", "1234.5", "0"]})
        _, md1, js1 = self.build(cap, "a")
        _, md2, js2 = self.build(cap, "b")
        self.assertEqual(read(md1), read(md2))
        self.assertEqual(read(js1), read(js2))
        self.assertIn("| 4 | 20.00 | 0 | 0.25 | 1234 | 1234 |", read(md1))  # 1234.5 -> 1234 (half-even)

    def test_changed_query_refused(self):
        p, _, _ = self.build(self.capture({"postfiatd": ["1"]}, query_override="job_waiting_sum"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("capture has no answer for job_waiting_sum with the current query", p.stderr)

    def test_empty_series_row(self):
        p, _, js = self.build(self.capture({"postfiatd": ["NaN", "+Inf"]}))
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(read(js))["rows"][0]
        self.assertEqual(r["samples"], 0)
        self.assertNotIn("p50", r)


if __name__ == "__main__":
    unittest.main(verbosity=1)
