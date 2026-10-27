#!/usr/bin/env python3
"""Tests for drill_verdict.py: a good synthetic run passes, and every way a run can go wrong fails the right check.
Message bodies are rendered from the real summaries in ../../alerts/resources.rules.yml, and the ntfy input goes
through ntfy_reduce() as raw ntfy.sh JSON lines, so a template change that breaks container matching fails here.
  python3 resources/drill/test_drill_verdict.py
"""
import copy
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import drill_verdict as dv  # noqa: E402

RULES = os.path.join(HERE, "..", "..", "alerts", "resources.rules.yml")


def summaries():
    out, name = {}, None
    with open(RULES) as f:
        for ln in f:
            m = re.match(r"\s*- alert: (\S+)", ln)
            if m:
                name = m.group(1)
            m = re.match(r'\s*summary: "(.*)"\s*$', ln)
            if m and name:
                out[name] = m.group(1)
    return out


SUM = summaries()
ALL = dv.LOAD_ALERTS + (dv.OOM_ALERT,)


def raw(t, status, alert, c):
    body = SUM[alert].replace("{{ $labels.container }}", c)
    return json.dumps({"id": "x%d" % t, "time": t, "expires": t + 43200, "event": "message", "topic": "t",
                       "title": "[%s] %s" % (status, alert), "message": body, "priority": 3,
                       "tags": ["rotating_light"]})


def good():
    samples, lines = [], ['{"id":"o","time":999,"event":"open","topic":"t"}']
    t = 1000

    def sample(phase, prom, up=1):
        nonlocal t
        samples.append({"t": t, "phase": phase, "nodes": {"validator": "full", "sentry": "full"},
                        "prom": {c: dict(prom) for c in dv.CONTAINERS if prom},
                        "am": {c: sorted(a for a, s in prom.items() if s == "firing") for c in dv.CONTAINERS if prom},
                        "real": [], "up": {c: up for c in dv.CONTAINERS}})
        t += 30
    for _ in range(3):
        sample("idle", {})
    for i in range(14):
        sample("load", {a: ("firing" if i >= 11 else "pending") for a in dv.LOAD_ALERTS})
    for c in dv.CONTAINERS:
        lines += [raw(t - 10, "FIRING", a, c) for a in dv.LOAD_ALERTS]
    for i in range(4):
        sample("oom", {dv.OOM_ALERT: "firing"} if i >= 2 else {a: "firing" for a in dv.LOAD_ALERTS})
    lines += [raw(t - 10, "FIRING", dv.OOM_ALERT, c) for c in dv.CONTAINERS]
    for i in range(24):
        sample("calm", {dv.OOM_ALERT: "firing"} if i < 22 else {})
        if i == 2:
            lines += [raw(t, "RESOLVED", a, c) for c in dv.CONTAINERS for a in dv.LOAD_ALERTS]
    lines += [raw(t, "RESOLVED", dv.OOM_ALERT, c) for c in dv.CONTAINERS]
    return samples, list(dv.ntfy_reduce(lines))


def run(samples, msgs):
    out = []
    ok = dv.verdict(samples, msgs, out=out.append)
    return ok, [ln[5:] for ln in out if ln.startswith("FAIL ")]


class T(unittest.TestCase):
    def test_templates_found(self):
        for a in ALL:
            self.assertIn("{{ $labels.container }}", SUM[a], a)

    def test_good_run_passes(self):
        ok, fails = run(*good())
        self.assertTrue(ok, fails)

    def test_ntfy_reduce_drops_topic_and_non_messages(self):
        r = list(dv.ntfy_reduce(['{"event":"open"}', "not json", raw(5, "FIRING", "PFTFdNearLimit", "a")]))
        self.assertEqual(len(r), 1)
        self.assertEqual(set(r[0]), {"time", "title", "message"})

    def assertFailsOnly(self, samples, msgs, *needles):
        ok, fails = run(samples, msgs)
        self.assertFalse(ok)
        for n in needles:
            self.assertTrue(any(n in f for f in fails), (n, fails))
        return fails

    def test_missing_resolved_for_one_container(self):
        s, m = good()
        m = [x for x in m if not (x["title"] == "[RESOLVED] PFTPidsNearLimit" and "pft-res-drill-s" in x["message"])]
        f = self.assertFailsOnly(s, m, "pft-res-drill-s [RESOLVED] PFTPidsNearLimit")
        self.assertEqual(len(f), 1, f)

    def test_oom_message_for_other_container_does_not_count(self):
        s, m = good()
        m = [x for x in m if not (x["title"].endswith(dv.OOM_ALERT) and "pft-res-drill-v" in x["message"])]
        self.assertFailsOnly(s, m, "pft-res-drill-v [FIRING] PFTContainerOOMKill",
                             "pft-res-drill-v [RESOLVED] PFTContainerOOMKill")

    def test_firing_message_before_phase_fails(self):
        s, m = good()
        m.append({"time": s[0]["t"], "title": "[FIRING] PFTFdNearLimit",
                  "message": SUM["PFTFdNearLimit"].replace("{{ $labels.container }}", "pft-res-drill-v")})
        self.assertFailsOnly(s, m, "pft-res-drill-v [FIRING] PFTFdNearLimit")

    def test_never_firing_in_prometheus(self):
        s, m = good()
        for x in s:
            x["prom"].get("pft-res-drill-v", {}).pop("PFTMemoryNearLimit", None)
        self.assertFailsOnly(s, m, "pft-res-drill-v PFTMemoryNearLimit firing in Prometheus")

    def test_node_not_full_once(self):
        s, m = good()
        s[10]["nodes"]["sentry"] = "syncing"
        self.assertFailsOnly(s, m, "server_state full in every sample")

    def test_node_missing_from_sample(self):
        s, m = good()
        del s[5]["nodes"]["validator"]
        self.assertFailsOnly(s, m, "server_state full in every sample")

    def test_real_container_alert(self):
        s, m = good()
        s[7]["real"] = ["PFTMemoryNearLimit"]
        self.assertFailsOnly(s, m, "real postfiatd containers")

    def test_alert_still_active_at_end(self):
        s, m = good()
        s[-1]["am"]["pft-res-drill-s"] = [dv.OOM_ALERT]
        self.assertFailsOnly(s, m, "last sample (calm)")

    def test_collector_down_once(self):
        s, m = good()
        s[-5]["up"]["pft-res-drill-v"] = 0
        self.assertFailsOnly(s, m, "collector up 1")

    def test_phase_missing(self):
        s, m = good()
        s = [x for x in s if x["phase"] != "idle"]
        self.assertFailsOnly(s, m, "phases idle")

    def test_empty_inputs_fail(self):
        ok, fails = run([], [])
        self.assertFalse(ok)
        self.assertGreater(len(fails), 10)

    def test_cli_exit_codes(self):
        import subprocess
        import tempfile
        s, m = good()
        with tempfile.TemporaryDirectory() as d:
            sp, mp = os.path.join(d, "s"), os.path.join(d, "m")
            for p, rows in ((sp, s), (mp, m)):
                with open(p, "w") as f:
                    f.write("".join(json.dumps(r) + "\n" for r in rows))
            r = subprocess.run([sys.executable, os.path.join(HERE, "drill_verdict.py"), sp, mp],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("DRILL PASS", r.stdout)
            with open(mp, "w") as f:
                f.write("".join(json.dumps(r) + "\n" for r in m[:-1]))
            r = subprocess.run([sys.executable, os.path.join(HERE, "drill_verdict.py"), sp, mp],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("DRILL FAIL", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
