"""drill_stub.rewrite and drill_verdict.verdict on synthetic data (positive + negative cases).

Run: python3 -m unittest discover -s divergence/tests -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import drill_stub
import drill_verdict

H = "0123456789ABCDEF" * 4


def s(t, phase, stub, alert, real=0):
    return {"t": t, "phase": phase, "state": {"validator": real, "sentry": 0, "stub": stub}, "alert": alert}


GOOD = [s(100, "wrong", 0, "none"), s(160, "wrong", 1, "pending"), s(280, "wrong", 1, "firing"),
        s(300, "fixed", 1, "firing"), s(400, "fixed", 0, "none")]
MSGS = [{"time": 290, "title": "[FIRING] PFTLedgerDiverged"}, {"time": 420, "title": "[RESOLVED] PFTLedgerDiverged"}]


class Stub(unittest.TestCase):
    def test_wrong_changes_every_digit(self):
        w = drill_stub.wrong(H)
        self.assertEqual(len(w), 64)
        self.assertTrue(all(a != b for a, b in zip(w, H)))
        self.assertEqual(w[:4], "1234")

    def test_rewrite_only_ledger(self):
        led = json.dumps({"result": {"status": "success", "ledger_hash": H, "ledger": {"ledger_hash": H}}}).encode()
        out = json.loads(drill_stub.rewrite(b'{"method":"ledger"}', led))
        self.assertEqual(out["result"]["ledger"]["ledger_hash"], drill_stub.wrong(H))
        self.assertEqual(out["result"]["ledger_hash"], drill_stub.wrong(H))
        info = b'{"result":{"status":"success"}}'
        self.assertEqual(drill_stub.rewrite(b'{"method":"server_info"}', info), info)


class Verdict(unittest.TestCase):
    def v(self, samples, msgs):
        return drill_verdict.verdict(samples, msgs)

    def test_pass(self):
        self.assertTrue(self.v(GOOD, MSGS))

    def test_fail_without_resolved(self):
        self.assertFalse(self.v(GOOD, MSGS[:1]))

    def test_fail_on_stale_firing_message(self):
        self.assertFalse(self.v(GOOD, [{"time": 50, "title": "[FIRING] PFTLedgerDiverged"}, MSGS[1]]))

    def test_fail_if_never_firing(self):
        self.assertFalse(self.v([x if x["alert"] != "firing" else dict(x, alert="pending") for x in GOOD], MSGS))

    def test_fail_if_still_firing_at_end(self):
        self.assertFalse(self.v(GOOD[:-1], MSGS))

    def test_fail_if_real_source_moved(self):
        self.assertFalse(self.v(GOOD + [s(460, "fixed", 0, "none", real=2)], MSGS))

    def test_ntfy_reduce(self):
        lines = ['{"event":"open","topic":"x"}', '{"event":"message","time":5,"title":"t","topic":"x"}', "junk"]
        self.assertEqual(list(drill_verdict.ntfy_reduce(lines)), [{"time": 5, "title": "t"}])


if __name__ == "__main__":
    unittest.main()
