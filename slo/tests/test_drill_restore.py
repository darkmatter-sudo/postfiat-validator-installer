"""Offline regression tests for the drill's restore step (drill_lib.sh), with curl stubbed as a shell function.

Run 2 (2026-10-26) expired the re-posted non-SLO silence because a just-recreated Prometheus answered /api/v1/alerts
with an empty list (it had not evaluated any rule yet); PFTContainerRestarted then reached the real topic.
These tests feed finish_silence exactly that answer (tests/fixtures/drill/alerts-none.json, a real response from the
validator host's Prometheus) and assert that no DELETE of the silence is ever sent.

Run: python3 -m unittest discover -s slo/tests -v
"""
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(os.path.dirname(HERE), "drill_lib.sh")
FIX = os.path.join(HERE, "fixtures", "drill")
SIL = "a48ecbdd-0000-4000-8000-000000000000"

# curl stub: logs every call (one line per call, args joined by spaces), saves the -d payload, and answers from
# $ALERTS (a file, or "fail" for an API error) for /api/v1/alerts and with a silence id for POST /api/v2/silences.
STUB = r"""
curl() {
  printf '%s\n' "$*" >> "$CALLS"
  local a prev=""
  for a in "$@"; do [ "$prev" = -d ] && printf '%s' "$a" > "$PAYLOAD"; prev="$a"; done
  case "$*" in
    *DELETE*) return 0 ;;
    */api/v1/alerts*) [ "$ALERTS" = fail ] && return 22; cat "$ALERTS" ;;
    */api/v2/silences*) echo '{"silenceID":"__SIL__"}' ;;
    *) return 22 ;;
  esac
}
""".replace("__SIL__", SIL)


def run(snippet, alerts):
    with tempfile.TemporaryDirectory() as tmp:
        calls, payload = os.path.join(tmp, "calls"), os.path.join(tmp, "payload")
        open(calls, "w").close()
        env = {"PATH": os.environ["PATH"], "CALLS": calls, "PAYLOAD": payload, "ALERTS": alerts,
               "AM": "http://127.0.0.1:9093", "PROM": "http://127.0.0.1:9090", "LIB": LIB}
        p = subprocess.run(["bash", "-c", 'set -euo pipefail; . "$LIB"\n' + STUB + snippet],
                           env=env, capture_output=True, text=True, timeout=30, check=False)
        with open(calls, encoding="utf-8") as fh:
            c = fh.read().splitlines()
        body = None
        if os.path.exists(payload):
            with open(payload, encoding="utf-8") as fh:
                body = json.load(fh)
        return p, c, body


class FinishSilence(unittest.TestCase):
    def assert_never_expired(self, calls):
        self.assertTrue(calls, "finish_silence made no curl call at all (stub not used?)")
        for c in calls:
            self.assertNotIn("DELETE", c, f"silence expired early: {c}")
            self.assertNotIn("/api/v2/silence/", c, f"silence expired early: {c}")

    def test_fresh_prometheus_empty_alert_list_keeps_silence(self):
        # the exact run-2 condition: recreated Prometheus, no rule evaluated yet -> {"alerts":[]}
        p, calls, _ = run(f'finish_silence "{SIL}"', os.path.join(FIX, "alerts-none.json"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_never_expired(calls)
        self.assertEqual(calls, ["-fsS http://127.0.0.1:9090/api/v1/alerts"])
        self.assertIn("non-SLO alerts pending/firing in Prometheus (informational, fresh instance): none", p.stdout)
        self.assertIn("Alertmanager silence a48ecbdd kept until its end time (60m; never expired early)", p.stdout)

    def test_prometheus_api_failure_keeps_silence(self):
        p, calls, _ = run(f'finish_silence "{SIL}"', "fail")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_never_expired(calls)
        self.assertIn("unknown (Prometheus API failed)", p.stdout)
        self.assertIn("kept until its end time", p.stdout)

    def test_no_silence_is_reported_not_deleted(self):
        p, calls, _ = run('finish_silence ""', os.path.join(FIX, "alerts-none.json"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_never_expired(calls)
        self.assertIn("no Alertmanager silence to keep", p.stdout)


class RestoreRepost(unittest.TestCase):
    def test_reposted_silence_covers_container_restarted_window(self):
        # restore() re-posts with `silence_nonslo 60 ...`; PFTContainerRestarted fires up to 15 min after the last
        # node start, and the playbook wants +10 min: the silence must last >= 25 min from the moment it is posted
        p, calls, body = run('silence_nonslo 60 "planned: SLO drill tail after restore (non-SLO alerts only)"',
                             os.path.join(FIX, "alerts-none.json"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), SIL)
        self.assertEqual(len(calls), 1)
        self.assertIn("-X POST", calls[0])
        self.assertIn("http://127.0.0.1:9093/api/v2/silences", calls[0])
        self.assertEqual(body["matchers"], [{"name": "alertname", "value": "PFTSLO.*", "isRegex": True,
                                             "isEqual": False}])
        start, end = (datetime.strptime(body[k], "%Y-%m-%dT%H:%M:%SZ") for k in ("startsAt", "endsAt"))
        minutes = (end - start).total_seconds() / 60
        self.assertGreaterEqual(minutes, 25)
        self.assertAlmostEqual(minutes, 60, delta=1)


if __name__ == "__main__":
    unittest.main()
