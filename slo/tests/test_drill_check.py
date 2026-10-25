"""Offline tests for drill_check.py: the drill's pass/fail checker is tested before the one live run.

Run: python3 -m unittest discover -s slo/tests -v
Real fixtures: tests/fixtures/drill/query-*.json and alerts-none.json are raw /api/v1/query and /api/v1/alerts
responses from the validator host's Prometheus (2026-10-25); alerts-pending.json / alerts-firing.json come from
a throwaway prom/prometheus:v3.5.0 container (--network none) running an always-true PFTSLOFastBurn rule.
"""
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import drill_check as d

FIX = os.path.join(HERE, "fixtures", "drill")
T0 = 1_800_000_000
FAST = "PFTSLOFastBurn"


def fx(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


def capture():
    """A good timeline: B 8 min planned stop, 2 min gap, A 8 min down -> 1 min recover -> 6 min resolve."""
    s, t = [], T0

    def add(phase, n, **kw):
        nonlocal t
        for i in range(n):
            row = {"t": t, "phase": phase, "node": "full", "maint": 0, "bad": 0, "r5m": 0.0, "r1h": 0.0, "alerts": {}}
            row.update({k: (v(i) if callable(v) else v) for k, v in kw.items()})
            s.append(row)
            t += 15

    add("B", 32, maint=1, node="unreachable")
    add("gap", 8)
    a0 = t
    add("A-down", 32, bad=1, node="unreachable",
        alerts=lambda i: {FAST: "firing"} if i >= 26 else {FAST: "pending"} if i >= 18 else {})
    add("A-recover", 4, alerts={FAST: "firing", "PFTSLOSlowBurn": "pending"})
    add("A-resolve", 24, alerts=lambda i: {} if i >= 20 else {FAST: "firing"})
    fire_t = a0 + 26 * 15
    msgs = [{"time": T0 + 5, "title": "[MAINT] maintenance window open"},
            {"time": fire_t + 20, "title": "[FIRING] " + FAST},
            {"time": t - 30, "title": "[RESOLVED] " + FAST}]
    return s, msgs


def failed(samples, msgs):
    res, _ = d.check(samples, msgs)
    return {name for name, ok, _ in res if not ok}


class Sampler(unittest.TestCase):
    def test_build_sample_from_real_responses(self):
        v = {k: fx(f"query-{k}.json") for k in d.QUERIES}
        s = d.build_sample(T0 + 0.7, "B", "full", v, fx("alerts-none.json"))
        self.assertEqual(s, {"t": T0, "phase": "B", "node": "full", "maint": 0, "bad": 0,
                             "r5m": 0.0, "r1h": 0.0, "alerts": {}})

    def test_alert_states_from_real_responses(self):
        self.assertEqual(d.alerts_map(fx("alerts-pending.json")), {FAST: "pending", "PFTContainerRestarted": "firing"})
        self.assertEqual(d.alerts_map(fx("alerts-firing.json"))[FAST], "firing")

    def test_missing_series_is_none_not_zero(self):
        self.assertIsNone(d.vec_value(fx("query-empty.json")))
        v = {k: fx("query-empty.json") for k in d.QUERIES}
        s = d.build_sample(T0, "B", "unreachable", v, fx("alerts-none.json"))
        self.assertIsNone(s["maint"])
        self.assertIn("B: pft:sli_maint:bool == 1 in every sample", failed([s], []))

    def test_firing_wins_over_pending(self):
        p, f = fx("alerts-pending.json"), fx("alerts-firing.json")
        both = {"data": {"alerts": f["data"]["alerts"][:1] + p["data"]["alerts"][:1]}}
        self.assertEqual(d.alerts_map(both)[FAST], "firing")

    def test_ntfy_reduce_keeps_messages_drops_topic(self):
        raw = ['{"id":"a","time":5,"event":"open","topic":"secret"}',
               '{"id":"b","time":7,"event":"message","topic":"secret","title":"[FIRING] PFTSLOFastBurn","message":"x"}', ""]
        out = list(d.ntfy_reduce(raw))
        self.assertEqual(out, [{"time": 7, "title": "[FIRING] PFTSLOFastBurn"}])


class Checker(unittest.TestCase):
    def test_good_capture_passes(self):
        s, m = capture()
        self.assertEqual(failed(s, m), set())

    def test_maintenance_not_excluded_fails_b(self):
        s, m = capture()
        for row in s:
            if row["phase"] == "B":
                row.update(maint=0, bad=1)
        self.assertTrue({"B: pft:sli_maint:bool == 1 in every sample",
                         "B: pft:sli_bad:bool == 0 in every sample"} <= failed(s, m))

    def test_slo_alert_during_b_fails(self):
        s, m = capture()
        s[20]["alerts"] = {FAST: "pending"}
        self.assertEqual(failed(s, m), {"B: no PFTSLO* alert pending/firing"})

    def test_slo_message_during_b_fails(self):
        s, m = capture()
        m.append({"time": T0 + 200, "title": "[FIRING] PFTSLOSlowBurn"})
        self.assertEqual(failed(s, m), {"B: no PFTSLO* message on the topic"})

    def test_non_slo_alert_during_b_is_info_only(self):
        s, m = capture()
        s[3]["alerts"] = {"PFTNodeDown": "firing"}
        self.assertEqual(failed(s, m), set())
        _, info = d.check(s, m)
        self.assertIn("non-SLO alerts seen (silenced in Alertmanager): PFTNodeDown", info)

    def test_firing_without_pending_fails(self):
        s, m = capture()
        for row in s:
            if row["alerts"].get(FAST) == "pending":
                row["alerts"] = {}
        self.assertEqual(failed(s, m), {"A: FastBurn pending seen"})

    def test_no_bad_while_down_fails(self):
        s, m = capture()
        for row in s:
            row["bad"] = 0 if row["phase"] == "A-down" else row["bad"]
        self.assertEqual(failed(s, m), {"A: pft:sli_bad:bool == 1 while down"})

    def test_stale_firing_message_does_not_count(self):
        s, m = capture()
        fire = next(r["t"] for r in s if r["alerts"].get(FAST) == "firing")
        m[1]["time"] = fire - 61
        self.assertEqual(failed(s, m), {"A: [FIRING] PFTSLOFastBurn message delivered"})

    def test_resolved_title_is_not_firing(self):
        s, m = capture()
        del m[1]
        self.assertEqual(failed(s, m), {"A: [FIRING] PFTSLOFastBurn message delivered"})

    def test_not_resolved_fails(self):
        s, m = capture()
        s[-1]["alerts"] = {FAST: "firing"}
        self.assertEqual(failed(s, m), {"A: FastBurn resolved by the last sample"})

    def test_resolved_message_not_required(self):
        s, m = capture()
        del m[2]
        self.assertEqual(failed(s, m), set())

    def test_missing_drill_a_fails(self):
        s, m = capture()
        s = [r for r in s if r["phase"] in ("B", "gap")]
        self.assertIn("A: down samples recorded", failed(s, m))
        self.assertIn("A: FastBurn firing seen", failed(s, m))

    def test_failed_polls_excluded_but_limited(self):
        s, m = capture()
        s[5] = {"t": s[5]["t"], "phase": "B", "node": "full", "error": "timed out"}
        self.assertEqual(failed(s, m), set())
        s2 = copy.deepcopy(s)
        for i in range(0, len(s2), 5):
            s2[i] = {"t": s2[i]["t"], "phase": s2[i]["phase"], "node": "x", "error": "timed out"}
        self.assertIn("polls answered >= 90%", failed(s2, m))


def js(rows):
    return "".join(json.dumps(r) + "\n" for r in rows)


class Main(unittest.TestCase):
    def run_main(self, samples, msgs):
        with tempfile.TemporaryDirectory() as tmp:
            sp, mp = os.path.join(tmp, "s.jsonl"), os.path.join(tmp, "m.jsonl")
            with open(sp, "w", encoding="utf-8") as fh:
                fh.write(samples)
            with open(mp, "w", encoding="utf-8") as fh:
                fh.write(msgs)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = d.main(["drill_check.py", sp, mp])
            return rc, out.getvalue()

    def test_exit_codes(self):
        s, m = capture()
        rc, out = self.run_main(js(s), js(m))
        self.assertEqual(rc, 0)
        self.assertIn("RESULT: PASS", out)
        s[-1]["alerts"] = {FAST: "firing"}
        rc, out = self.run_main(js(s), js(m))
        self.assertEqual(rc, 1)
        self.assertIn("RESULT: FAIL", out)
        rc, _ = self.run_main("{not json\n", "")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
