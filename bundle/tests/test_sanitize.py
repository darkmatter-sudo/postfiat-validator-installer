"""Unit tests for bundle/sanitize.py: one test class per redaction class plus fail-closed scans.
All secrets below are synthetic (random base58, wrong checksum); all addresses are documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)."""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import sanitize  # noqa: E402

FAKE_SEED = "sn3nxiW7v8KXzPzAqzyHXbSSKNuN9"      # s + 28 base58, synthetic
FAKE_ED_SEED = "sEdTM1uX8pu2do5XvTnutH6HsouMaM2"   # sEd + 28 base58, synthetic
TOKEN_BLOB = "eyJtYW5pZmVzdCI6IkpBQUFBQUZ4SWUwPSJ9"


def lits_file(d, rows):
    p = os.path.join(d, "lits")
    with open(p, "w") as f:
        f.writelines(f"{c}\t{v}\n" for c, v in rows)
    return p


def redactor(rows=()):
    with tempfile.TemporaryDirectory() as d:
        return sanitize.Redactor(sanitize.read_literals(lits_file(d, rows)))


def scan_classes(text, rows=()):
    with tempfile.TemporaryDirectory() as d:
        lits = sanitize.read_literals(lits_file(d, rows))
    return [c for _, c in sanitize.scan_text(text, lits)]


class Seed(unittest.TestCase):
    def test_seed_in_cfg_section_removed(self):
        r = redactor()
        out = r.text(f"[server]\nport_rpc\n\n[validation_seed]\n{FAKE_SEED}\n\n[ips]\nr.example 2559\n", is_cfg=True)
        self.assertNotIn(FAKE_SEED, out)
        self.assertIn("[validation_seed] section removed", out)
        self.assertIn("[ips]", out)
        self.assertEqual(scan_classes(out), [])

    def test_seed_patterns_detected(self):
        self.assertEqual(scan_classes(f"x {FAKE_SEED} y"), ["seed"])
        self.assertEqual(scan_classes(f"seed={FAKE_ED_SEED}"), ["seed"])

    def test_seed_inside_longer_base58_word_ignored(self):
        self.assertEqual(scan_classes("n9M4wJVRjcex1Di6Xhf6KohTMNxdnix88GAsEg3U6bDzSujwdyR9"), [])

    def test_known_doc_example_allowed(self):
        self.assertEqual(scan_classes("# example: shfArahZT9Q9ckTf3s1psJ7C7qzVN"), [])


class TokenBlock(unittest.TestCase):
    CFG = ("[validator_token]\n" + TOKEN_BLOB + "\nMORE+LINES/xyz==\n\n[port_rpc_admin_local]\nport = 5005\n"
           "admin = 127.0.0.1\nadmin_password = hunter2\n")

    def test_token_section_removed_and_values_redacted(self):
        r = redactor()
        out = r.text(self.CFG, is_cfg=True)
        self.assertNotIn(TOKEN_BLOB, out)
        self.assertNotIn("MORE+LINES", out)
        self.assertNotIn("hunter2", out)
        self.assertIn("admin_password = <redacted>", out)
        self.assertIn("admin = 127.0.0.1", out)
        self.assertEqual(scan_classes(out), [])
        self.assertEqual(r.counts["cfg_section"], 1)

    def test_token_block_outside_cfg_fails_scan(self):
        self.assertIn("validator_token_blob", scan_classes("log: " + TOKEN_BLOB))
        self.assertIn("secret_section", scan_classes("[validator_token]\nabc\n"))

    def test_other_token_classes(self):
        self.assertEqual(scan_classes("ghp_" + "a" * 36), ["github_token"])
        self.assertEqual(scan_classes("Authorization: Bearer tk_" + "a1" * 14 + "b"), ["ntfy_token"])
        self.assertEqual(scan_classes("-----BEGIN OPENSSH PRIVATE KEY-----"), ["private_key"])


class IPv4(unittest.TestCase):
    def test_public_tokenized_stably_private_kept(self):
        r = redactor()
        out = r.text("peer 203.0.113.7:2559 and 198.51.100.9, again 203.0.113.7; lan 10.0.0.5 lo 127.0.0.1 "
                     "any 0.0.0.0\n")
        self.assertEqual(out, "peer <ip-1>:2559 and <ip-2>, again <ip-1>; lan 10.0.0.5 lo 127.0.0.1 any 0.0.0.0\n")
        self.assertEqual(r.counts["ipv4"], 3)

    def test_tokens_stable_across_files(self):
        r = redactor()
        a = r.text("198.51.100.20\n")
        b = r.text("x 198.51.100.20 y 198.51.100.21\n")
        self.assertEqual((a, b), ("<ip-1>\n", "x <ip-1> y <ip-2>\n"))

    def test_not_an_address(self):
        r = redactor()
        for s in ("version 1.0.9", "999.1.1.1", "1.2.3.4.5", "v10.20.30.40x"):
            self.assertEqual(r.text(s), s)

    def test_own_private_ip_literal_is_tokenized(self):
        r = redactor([("ip", "10.1.2.3")])
        self.assertEqual(r.text("bind 10.1.2.3"), "bind <ip-1>")
        self.assertEqual(scan_classes("bind 10.1.2.3", [("ip", "10.1.2.3")]), ["literal_ip"])


class IPv6(unittest.TestCase):
    def test_global_tokenized_loopback_kept(self):
        r = redactor()
        out = r.text("[2001:db8:0:1::25]:51235 ::1 :: fe80::1c2:3ff:fe44:5566")
        self.assertEqual(out, "[<ip-1>]:51235 ::1 :: <ip-2>")
        self.assertEqual(r.counts["ipv6"], 2)

    def test_scope_names_and_times_untouched(self):
        r = redactor()
        line = ("2026-Oct-25 07:07:38.123 UTC LedgerConsensus:NFO ConsensusPhase::accepted "
                "Json::Value std::map Cafe::Face 12:34:56 aa:bb:cc:dd:ee:ff")
        self.assertEqual(r.text(line), line.replace("Cafe::Face", "<ip-1>"))
        # Known limit (README): a scope name made only of hex digits (Cafe::Face) is a valid IPv6 address
        # and is tokenized. That over-redacts; it never leaks.
        self.assertEqual(r.counts["ipv6"], 1)


class Hostname(unittest.TestCase):
    ROWS = [("host", "node-x1"), ("host", "node-x1.example.net"), ("host", "407cf9b6ffa6")]

    def test_fqdn_and_short_name(self):
        r = redactor(self.ROWS)
        out = r.text("Linux node-x1 5.15; fqdn NODE-X1.example.net; hostid 407cf9b6ffa6; node-x10 node-x1-old\n")
        self.assertNotIn("node-x1 ", out.lower())
        self.assertIn("node-x10 node-x1-old", out)       # whole-word only
        self.assertEqual(out.count("<host-"), 3)
        self.assertEqual(scan_classes(out, self.ROWS), [])

    def test_surviving_hostname_fails_scan(self):
        self.assertEqual(scan_classes("uname: node-x1", self.ROWS), ["literal_host"])


class Ntfy(unittest.TestCase):
    def test_ntfy_url_and_topic_literal(self):
        r = redactor([("topic", "my-secret-topic-123")])
        out = r.text("NTFY_URL=https://ntfy.sh/my-secret-topic-123\nposting to my-secret-topic-123\n"
                     "self-hosted https://push.ntfy.example.org:8443/alerts_9\n")
        self.assertEqual(out, "NTFY_URL=<ntfy-url>\nposting to <redacted-topic>\nself-hosted <ntfy-url>\n")
        self.assertEqual(scan_classes(out, [("topic", "my-secret-topic-123")]), [])

    def test_surviving_topic_fails_scan(self):
        self.assertEqual(scan_classes("x my-secret-topic-123", [("topic", "my-secret-topic-123")]),
                         ["literal_topic"])


class FailClosedCLI(unittest.TestCase):
    """End-to-end through the CLI: a planted fake seed in a non-cfg file must make scan exit 2."""

    def run_cli(self, *a):
        return subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(HERE), "sanitize.py"), *a],
                              capture_output=True, text=True)

    def test_planted_fake_seed_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            raw, out = os.path.join(d, "raw"), os.path.join(d, "out")
            os.makedirs(os.path.join(raw, "logs"))
            with open(os.path.join(raw, "postfiatd.cfg"), "w") as f:
                f.write(f"[validation_seed]\n{FAKE_SEED}\n")
            with open(os.path.join(raw, "logs", "debug.log"), "w") as f:
                f.write(f"line one\nwallet_propose returned {FAKE_ED_SEED}\n")
            self.assertEqual(self.run_cli("redact", raw, out).returncode, 0)
            res = self.run_cli("scan", out)
            self.assertEqual(res.returncode, 2)
            self.assertIn("HIT logs/debug.log:2 seed", res.stdout)
            self.assertNotIn(FAKE_ED_SEED, res.stdout + res.stderr)
            self.assertNotIn("postfiatd.cfg", res.stdout)   # the cfg seed was removed with its section

    def test_clean_bundle_passes(self):
        with tempfile.TemporaryDirectory() as d:
            raw, out = os.path.join(d, "raw"), os.path.join(d, "out")
            os.makedirs(raw)
            with open(os.path.join(raw, "peers.json"), "w") as f:
                f.write('{"address": "203.0.113.5:2559"}\n')
            self.assertEqual(self.run_cli("redact", raw, out).returncode, 0)
            res = self.run_cli("scan", out)
            self.assertEqual((res.returncode, res.stdout.strip()), (0, "scan: 0 hit(s)"))


if __name__ == "__main__":
    unittest.main()
