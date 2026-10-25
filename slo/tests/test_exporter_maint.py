"""pft_maint_active in ../exporter/pft_exporter.py mirrors `pft-maint active` flag validation.

Run: python3 -m unittest discover -s slo/tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "exporter"))
import pft_exporter as e

NOW = 1_800_000_000


def flag(d, mode=0o644, **over):
    j = {"v": 1, "id": "m1", "reason": "test", "host": "validator", "start": NOW - 60, "expiry": NOW + 600}
    j.update(over)
    p = os.path.join(d, "flag.json")
    with open(p, "w") as f:
        json.dump({k: v for k, v in j.items() if v is not None}, f)
    os.chmod(p, mode)
    return p


class MaintFlag(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def state(self, p, now=NOW):
        return e.maint_state(p, now=now, check_owner=False)

    def test_absent_is_inactive_not_malformed(self):
        self.assertEqual(self.state(os.path.join(self.d, "flag.json")), (0, 0))

    def test_valid_open_window_is_active(self):
        self.assertEqual(self.state(flag(self.d)), (1, 0))

    def test_expired_window_is_inactive(self):
        self.assertEqual(self.state(flag(self.d), now=NOW + 600), (0, 0))

    def test_malformed_flags_never_count_as_maintenance(self):
        cases = {"group-writable": {"mode": 0o664}, "missing reason": {"reason": None},
                 "ttl over 4h": {"expiry": NOW - 60 + 14401}, "expiry before start": {"expiry": NOW - 120},
                 "start in future": {"start": NOW + 120, "expiry": NOW + 600}, "v2": {"v": 2},
                 "bool start": {"start": True}}
        for name, over in cases.items():
            with self.subTest(name):
                self.assertEqual(self.state(flag(self.d, **over)), (0, 1))

    def test_symlink_and_garbage_are_malformed(self):
        real = flag(self.d)
        link = os.path.join(self.d, "link.json")
        os.symlink(real, link)
        self.assertEqual(self.state(link), (0, 1))
        with open(real, "w") as f:
            f.write("{not json")
        self.assertEqual(self.state(real), (0, 1))

    def test_owner_check_rejects_non_root_file(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        self.assertEqual(e.maint_state(flag(self.d), now=NOW, check_owner=True), (0, 1))

    def test_metric_lines(self):
        lines = "\n".join(e.maint_lines())
        self.assertIn("# TYPE pft_maint_active gauge", lines)
        self.assertRegex(lines, r"\npft_maint_active [01]\n")


if __name__ == "__main__":
    unittest.main()
