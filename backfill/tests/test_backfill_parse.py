#!/usr/bin/env python3
"""Unit tests for backfill_parse.py on the real fixtures (tests/fixtures/live, captured by drill/capture.sh) and on
hand-written server_info answers. Every expected count is computed by hand in the test from the window rule in the
parser's docstring: window = [validated - online_delete + 1, validated].

Run: python3 backfill/tests/test_backfill_parse.py   (stdlib only; temp files under TEST_TMPDIR or ~/.cache)
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import backfill_parse as bp

FX = os.path.join(HERE, "fixtures", "live")
TMPROOT = os.environ.get("TEST_TMPDIR") or os.path.join(
    os.path.expanduser("~"), ".cache"
)
CFG512 = "[node_db]\ntype=NuDB\npath=/var/lib/postfiatd/db/nudb\nonline_delete=512\nadvisory_delete=0\n"


def info(cl, seq, state="full"):
    return {
        "server_state": state,
        "complete_ledgers": cl,
        "validated_ledger": {"seq": seq},
    }


class Ranges(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(bp.parse_ranges("empty"), [])
        self.assertEqual(bp.parse_ranges("5"), [(5, 5)])
        self.assertEqual(bp.parse_ranges("1-3,5,7-9"), [(1, 3), (5, 5), (7, 9)])

    def test_rejects(self):
        for bad in (
            "",
            "1-",
            "a-3",
            "3-1",
            "1-3,2-5",
            "1-3,4-5",
            "5,1",
            "1-3, 5",
            "0-4",
            None,
        ):
            with self.subTest(bad=bad), self.assertRaises(bp.InputError):
                bp.parse_ranges(bad)


class Cfg(unittest.TestCase):
    def test_value(self):
        self.assertEqual(bp.online_delete(CFG512), 512)

    def test_other_section_and_comment_ignored(self):
        cfg = "[node_db]\n# online_delete=9\ntype=NuDB\n[other]\nonline_delete=7\n"
        self.assertIsNone(bp.online_delete(cfg))

    def test_zero_is_unset(self):
        self.assertIsNone(bp.online_delete("[node_db]\nonline_delete=0\n"))

    def test_bad_value(self):
        with self.assertRaises(bp.InputError):
            bp.online_delete("[node_db]\nonline_delete=lots\n")


class Accounting(unittest.TestCase):
    def test_complete(self):
        # window [1000-512+1, 1000] = [489, 1000], fully inside 100-1000
        a = bp.account(info("100-1000", 1000), 512)
        self.assertEqual(a["window"], [489, 1000])
        self.assertEqual(
            (a["held"], a["missing_interior"], a["missing_edge"], a["gaps"]),
            (512, 0, 0, []),
        )

    def test_interior_hole(self):
        # held 489-700 (212) + 711-1000 (290) = 502; hole 701-710 = 10
        a = bp.account(info("300-700,711-1000", 1000), 512)
        self.assertEqual(
            (a["held"], a["missing_interior"], a["missing_edge"]), (502, 10, 0)
        )
        self.assertEqual(
            a["gaps"], [{"kind": "interior", "lo": 701, "hi": 710, "size": 10}]
        )

    def test_edge_after_restart(self):
        # restart with ledger_history 256: held 745-1000 (256); edge 489-744 = 256
        a = bp.account(info("745-1000", 1000), 512)
        self.assertEqual(
            (a["held"], a["missing_interior"], a["missing_edge"]), (256, 0, 256)
        )

    def test_edge_and_interior_and_head(self):
        # held 600-650 (51), 660-990 (331) = 382; edge 489-599 = 111; interior 651-659 = 9 and 991-1000 = 10
        a = bp.account(info("600-650,660-990", 1000), 512)
        self.assertEqual(
            (a["held"], a["missing_edge"], a["missing_interior"]), (382, 111, 19)
        )
        self.assertEqual(a["held"] + a["missing_edge"] + a["missing_interior"], 512)

    def test_range_below_window_is_not_a_gap(self):
        # an old fragment below the window (rotation leftovers) does not count
        a = bp.account(info("10-20,489-1000", 1000), 512)
        self.assertEqual(
            (a["missing_interior"], a["missing_edge"], a["gaps"]), (0, 0, [])
        )

    def test_boundary_one_short(self):
        # starts at 490: exactly one edge ledger (489) missing
        a = bp.account(info("490-1000", 1000), 512)
        self.assertEqual(a["gaps"], [{"kind": "edge", "lo": 489, "hi": 489, "size": 1}])

    def test_empty_history(self):
        a = bp.account(info("empty", 1000), 512)
        self.assertEqual((a["held"], a["missing_edge"]), (0, 512))

    def test_no_online_delete(self):
        a = bp.account(info("1-3,9-10", 10), None)
        self.assertIsNone(a["window"])
        self.assertEqual(a["gaps"], [])

    def test_small_chain(self):
        # validated 100 < online_delete: window starts at ledger 1
        a = bp.account(info("50-100", 100), 512)
        self.assertEqual(a["window"], [1, 100])
        self.assertEqual(a["missing_edge"], 49)

    def test_no_validated(self):
        with self.assertRaises(bp.InputError):
            bp.account({"server_state": "connected", "complete_ledgers": "empty"}, 512)


class Plan(unittest.TestCase):
    def test_newest_first_interior_before_edge(self):
        a = bp.account(info("600-650,660-990", 1000), 512)
        p = bp.plan(a, 25)
        # interior gaps newest first: 1000..991 (10), 659..651 (9), then edge from 599 down: 599..594 (6)
        self.assertEqual(
            p,
            list(range(1000, 990, -1))
            + list(range(659, 650, -1))
            + list(range(599, 593, -1)),
        )

    def test_cap(self):
        a = bp.account(info("745-1000", 1000), 512)
        self.assertEqual(len(bp.plan(a, 7)), 7)
        self.assertEqual(bp.plan(a, 3), [744, 743, 742])

    def test_nothing(self):
        self.assertEqual(bp.plan(bp.account(info("1-1000", 1000), 512), 50), [])


class Cli(unittest.TestCase):
    def setUp(self):
        os.makedirs(TMPROOT, exist_ok=True)
        self.d = tempfile.mkdtemp(prefix="bf-py.", dir=TMPROOT)

    def tearDown(self):
        shutil.rmtree(self.d)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = bp.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def write(self, name, obj):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))
        return p

    def test_live_fixtures_both_hosts(self):
        for host in ("validator", "sentry"):
            with self.subTest(host=host):
                inf = os.path.join(FX, f"{host}-server_info.json")
                with open(inf, encoding="utf-8") as fh:
                    raw = json.load(fh)["result"]["info"]
                lo, hi = (int(x) for x in raw["complete_ledgers"].split("-"))
                seq = raw["validated_ledger"]["seq"]
                rc, out, err = self.run_cli(
                    "status",
                    "--info",
                    inf,
                    "--cfg",
                    os.path.join(FX, f"{host}-cfg.txt"),
                    "--node",
                    "n",
                    "--now",
                    "1",
                )
                self.assertEqual((rc, err), (0, ""))
                self.assertIn('pft_backfill_online_delete{node="n"} 512', out)
                self.assertIn(f'pft_backfill_validated_seq{{node="n"}} {seq}', out)
                # captured fixtures are one contiguous range reaching the validated seq and >= 512 long
                self.assertEqual(hi, seq)
                self.assertGreaterEqual(hi - lo + 1, 512)
                self.assertIn(
                    'pft_backfill_missing_ledgers{node="n",kind="interior"} 0', out
                )
                self.assertIn(
                    'pft_backfill_missing_ledgers{node="n",kind="edge"} 0', out
                )
                self.assertIn('pft_backfill_window_held_ledgers{node="n"} 512', out)

    def test_status_with_gaps(self):
        inf = self.write("i.json", {"result": {"info": info("600-650,660-990", 1000)}})
        cfg = self.write("c.txt", CFG512)
        rc, out, _ = self.run_cli(
            "status",
            "--info",
            inf,
            "--cfg",
            cfg,
            "--node",
            "postfiatd-sentry",
            "--now",
            "5",
        )
        self.assertEqual(rc, 0)
        for line in (
            'pft_backfill_missing_ledgers{node="postfiatd-sentry",kind="interior"} 19',
            'pft_backfill_missing_ledgers{node="postfiatd-sentry",kind="edge"} 111',
            'pft_backfill_gaps{node="postfiatd-sentry",kind="interior"} 2',
            'pft_backfill_gaps{node="postfiatd-sentry",kind="edge"} 1',
            'pft_backfill_gap_size{node="postfiatd-sentry",kind="edge",first="489",last="599"} 111',
            'pft_backfill_ranges{node="postfiatd-sentry"} 2',
            'pft_backfill_status_timestamp_seconds{node="postfiatd-sentry"} 5',
        ):
            self.assertIn(line + "\n", out)

    def test_gap_series_bounded(self):
        # 20 one-ledger holes: only MAX_GAP_SERIES gap_size series
        cl = ",".join(f"{s}-{s + 8}" for s in range(489, 669, 10)) + ",669-1000"
        inf = self.write("i.json", {"result": {"info": info(cl, 1000)}})
        rc, out, _ = self.run_cli(
            "status", "--info", inf, "--cfg", self.write("c.txt", CFG512), "--now", "1"
        )
        self.assertEqual(rc, 0)
        self.assertIn('pft_backfill_gaps{node="postfiatd",kind="interior"} 18', out)
        self.assertEqual(
            sum(1 for x in out.splitlines() if x.startswith("pft_backfill_gap_size{")),
            bp.MAX_GAP_SERIES,
        )

    def test_not_full(self):
        inf = self.write(
            "i.json", {"result": {"info": info("1-1000", 1000, state="syncing")}}
        )
        _rc, out, _ = self.run_cli(
            "status", "--info", inf, "--cfg", self.write("c.txt", CFG512), "--now", "1"
        )
        self.assertIn('pft_backfill_node_full{node="postfiatd"} 0', out)

    def test_plan_cli_and_cap_bounds(self):
        inf = self.write("i.json", {"result": {"info": info("745-1000", 1000)}})
        cfg = self.write("c.txt", CFG512)
        rc, out, _ = self.run_cli(
            "plan", "--info", inf, "--cfg", cfg, "--max-ledgers", "2"
        )
        self.assertEqual((rc, out), (0, "744\n743\n"))
        for bad in ("0", str(bp.MAX_PLAN + 1)):
            rc, out, err = self.run_cli(
                "plan", "--info", inf, "--cfg", cfg, "--max-ledgers", bad
            )
            self.assertEqual((rc, out), (1, ""))
            self.assertIn("--max-ledgers", err)

    def test_errors_are_one_line(self):
        cfg = self.write("c.txt", CFG512)
        cases = {
            "missing file": os.path.join(self.d, "nope.json"),
            "not json": self.write("a.json", "{"),
            "no info": self.write("b.json", {"result": {}}),
            "bad ranges": self.write("d.json", {"result": {"info": info("9-1", 10)}}),
        }
        for name, path in cases.items():
            with self.subTest(name=name):
                rc, out, err = self.run_cli(
                    "status", "--info", path, "--cfg", cfg, "--now", "1"
                )
                self.assertEqual((rc, out), (1, ""))
                self.assertEqual(len(err.strip().splitlines()), 1)
                self.assertTrue(err.startswith("backfill_parse: "))

    def test_bad_node_label(self):
        inf = self.write("i.json", {"result": {"info": info("1-1000", 1000)}})
        rc, _, err = self.run_cli(
            "status",
            "--info",
            inf,
            "--cfg",
            self.write("c.txt", CFG512),
            "--node",
            'x"}',
        )
        self.assertEqual(rc, 1)
        self.assertIn("bad node name", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
