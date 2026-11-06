#!/usr/bin/env python3
"""Offline tests for ntfy_bridge.py: one message per state change, bursts folded (python3 -m unittest)."""

import json
import os
import sys
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ntfy_bridge as nb


def alert(
    fp, status="firing", name="PFTJobFailed", host="sentry", sev="warning", summary=None
):
    return {
        "status": status,
        "fingerprint": fp,
        "labels": {"alertname": name, "host": host, "severity": sev},
        "annotations": {
            "summary": summary or f"{host}: job {fp} failed (1 run(s) in a row)"
        },
        "startsAt": "2026-11-06T17:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
    }


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


class DedupTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.d = nb.Dedup(self.clock)

    def test_first_sight_then_repeats_suppressed(self):
        a = alert("f1")
        self.assertEqual(len(self.d.changed([a])), 1)
        # Alertmanager re-sends the group (group change / repeat_interval): nothing new
        self.assertEqual(self.d.changed([a]), [])
        self.assertEqual(self.d.changed([a, alert("f2")]), [alert("f2")])

    def test_each_transition_sent_once(self):
        self.d.changed([alert("f1")])
        r = alert("f1", "resolved")
        self.assertEqual(self.d.changed([r]), [r])
        self.assertEqual(self.d.changed([r]), [])
        self.assertEqual(
            len(self.d.changed([alert("f1")])), 1
        )  # fires again: a new state change

    def test_resolved_forgotten_after_a_day_firing_kept(self):
        self.d.changed([alert("f1"), alert("f2")])
        self.d.changed([alert("f1", "resolved")])
        self.clock.t += nb.FORGET_S + 1
        self.d.changed([])
        self.assertNotIn("f1", self.d.sent)
        self.assertIn("f2", self.d.sent)
        self.assertEqual(self.d.changed([alert("f2")]), [])

    def test_no_fingerprint_uses_labels(self):
        a = alert("x")
        del a["fingerprint"]
        self.assertEqual(len(self.d.changed([a])), 1)
        self.assertEqual(self.d.changed([dict(a)]), [])


class MessagesTest(unittest.TestCase):
    def test_single_alert_keeps_old_format(self):
        self.assertEqual(
            nb.messages([alert("f1")]),
            [
                (
                    "[FIRING] PFTJobFailed",
                    "sentry: job f1 failed (1 run(s) in a row)",
                    "default",
                )
            ],
        )

    def test_burst_folds_into_one_message(self):
        burst = [alert(f"f{i}", "resolved") for i in range(27)]
        out = nb.messages(burst)
        self.assertEqual(len(out), 1)
        title, body, prio = out[0]
        self.assertEqual(title, "[RESOLVED] PFTJobFailed x27")
        self.assertEqual(prio, "low")
        self.assertEqual(len(body.splitlines()), nb.MAX_LINES + 1)
        self.assertTrue(body.endswith(f"... and {27 - nb.MAX_LINES} more"))

    def test_identical_summaries_listed_once(self):
        out = nb.messages([alert("a", summary="same"), alert("b", summary="same")])
        self.assertEqual(out, [("[FIRING] PFTJobFailed x2", "same", "default")])

    def test_split_by_status_and_name_critical_high(self):
        out = nb.messages(
            [
                alert("a"),
                alert("b", name="PFTNodeNotFull", sev="critical"),
                alert("c", "resolved"),
                alert("d"),
            ]
        )
        self.assertEqual(
            [(t, p) for t, _, p in out],
            [
                ("[FIRING] PFTJobFailed x2", "default"),
                ("[FIRING] PFTNodeNotFull", "high"),
                ("[RESOLVED] PFTJobFailed", "low"),
            ],
        )


class Sink(BaseHTTPRequestHandler):
    got: ClassVar[list] = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        Sink.got.append((self.headers.get("Title"), self.rfile.read(n).decode()))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


class EndToEndTest(unittest.TestCase):
    """Real HTTP: webhook -> bridge handler -> fake ntfy server on loopback (ephemeral ports)."""

    def setUp(self):
        Sink.got = []
        self.sink = HTTPServer(("127.0.0.1", 0), Sink)
        self.bridge = HTTPServer(("127.0.0.1", 0), nb.H)
        for s in (self.sink, self.bridge):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        self.old = (nb.NTFY_URL, nb.DEDUP, nb.log)
        nb.NTFY_URL = f"http://127.0.0.1:{self.sink.server_address[1]}/test"
        nb.DEDUP = nb.Dedup()
        nb.log = lambda m: None

    def tearDown(self):
        nb.NTFY_URL, nb.DEDUP, nb.log = self.old
        for s in (self.sink, self.bridge):
            s.shutdown()
            s.server_close()

    def post(self, alerts):
        data = json.dumps({"alerts": alerts}).encode()
        url = f"http://127.0.0.1:{self.bridge.server_address[1]}/alert"
        with urllib.request.urlopen(
            urllib.request.Request(url, data=data), timeout=5
        ) as r:
            self.assertEqual(r.status, 200)

    def test_incident_replay(self):
        # 17:06Z incident shape: 27 series of one alert, re-sent by group_interval, then resolved
        firing = [alert(f"f{i}") for i in range(27)]
        self.post(firing)
        self.post(firing)
        self.post([alert(f"f{i}", "resolved") for i in range(27)])
        self.assertEqual(
            [t for t, _ in Sink.got],
            ["[FIRING] PFTJobFailed x27", "[RESOLVED] PFTJobFailed x27"],
        )

    def test_bad_json_400(self):
        url = f"http://127.0.0.1:{self.bridge.server_address[1]}/alert"
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(urllib.request.Request(url, data=b"{"), timeout=5)
        self.assertEqual(e.exception.code, 400)
        self.assertEqual(Sink.got, [])


if __name__ == "__main__":
    unittest.main()
