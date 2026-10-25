"""Textfile collector in ../exporter/pft_exporter.py (reads the .prom file pft-divergence writes).

Run: python3 -m unittest discover -s divergence/tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "exporter"))
import pft_exporter as e

GOOD = """# HELP pft_divergence_state x
# TYPE pft_divergence_state gauge
pft_divergence_state{source="validator"} 0
pft_divergence_state{source="sentry"} 1
pft_divergence_check_timestamp 1792934332
"""


def write(d, name, text, mode=0o644):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(text)
    os.chmod(p, mode)
    return p


class Textfile(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.d = self.t.name

    def tearDown(self):
        self.t.cleanup()

    def test_good_file_is_exported(self):
        write(self.d, "pft_divergence.prom", GOOD)
        out = e.textfile_lines(self.d)
        self.assertIn('pft_divergence_state{source="sentry"} 1', out)
        self.assertIn("pft_divergence_check_timestamp 1792934332", out)
        self.assertIn("pft_textfile_errors 0", out)
        self.assertTrue(any(ln.startswith('pft_textfile_mtime_seconds{file="pft_divergence.prom"} ') for ln in out))

    def test_missing_dir_is_not_an_error(self):
        out = e.textfile_lines(os.path.join(self.d, "nope"))
        self.assertIn("pft_textfile_errors 0", out)
        self.assertFalse(any(ln.startswith("pft_divergence") for ln in out))

    def test_malformed_file_skipped_whole(self):
        write(self.d, "bad.prom", GOOD + "this is not a sample\n")
        write(self.d, "ok.prom", "pft_other 3\n")
        out = e.textfile_lines(self.d)
        self.assertIn("pft_textfile_errors 1", out)
        self.assertNotIn('pft_divergence_state{source="sentry"} 1', out)
        self.assertIn("pft_other 3", out)

    def test_temp_and_non_prom_files_ignored(self):
        write(self.d, ".pft_divergence.AbC123", "pft_half_written 1\n")
        write(self.d, "notes.txt", "pft_txt 1\n")
        out = e.textfile_lines(self.d)
        self.assertNotIn("pft_half_written 1", out)
        self.assertNotIn("pft_txt 1", out)
        self.assertIn("pft_textfile_errors 0", out)

    def test_symlink_and_oversize_rejected(self):
        target = write(self.d, "real.txt", "pft_x 1\n")
        os.symlink(target, os.path.join(self.d, "link.prom"))
        write(self.d, "big.prom", "pft_y 1\n" * 10000)
        out = e.textfile_lines(self.d)
        self.assertIn("pft_textfile_errors 2", out)
        self.assertNotIn("pft_x 1", out)
        self.assertNotIn("pft_y 1", out)

    def test_render_includes_textfiles(self):
        write(self.d, "pft_divergence.prom", GOOD)
        old = e.TEXTFILE_DIR
        e.TEXTFILE_DIR = self.d
        try:
            text = e.render()   # RPC_URL may be unreachable here; textfile lines are added either way
        finally:
            e.TEXTFILE_DIR = old
        self.assertIn('pft_divergence_state{source="sentry"} 1\n', text)


if __name__ == "__main__":
    unittest.main()
