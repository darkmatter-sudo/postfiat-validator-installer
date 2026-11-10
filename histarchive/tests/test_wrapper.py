#!/usr/bin/env python3
"""Tests for pft-histarchive.sh: replicate / verify-replica / restore-verify / serve / periodic.

The "peer" is a second STATE_DIR on this host: PEER_SSH is `env STATE_DIR=<peer>` and the remote
command is `bash pft-histarchive.sh`, so every byte goes through the same serve verbs and stdin
pipes that ssh carries in production. Real age/age-keygen are used. No network, no root.
Run: TMPDIR=$HOME/.cache python3 -m unittest -v tests/test_wrapper.py (from histarchive/)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from test_histarchive import FakeNode, make_chain, rb, run, wb

import histarchive as ha

SH = os.path.join(os.path.dirname(HERE), "pft-histarchive.sh")


class Wrapper(unittest.TestCase):
    def setUp(self):
        base = os.environ.get("TEST_TMPDIR") or os.path.join(
            os.path.expanduser("~"), ".cache"
        )
        os.makedirs(base, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="pft-ha-wrap-", dir=base)
        self.state = os.path.join(self.tmp, "local")
        self.peer = os.path.join(self.tmp, "peer")
        self.tf = os.path.join(self.tmp, "textfile")
        for d in (self.state, self.peer, self.tf):
            os.makedirs(d)
        self.conf = os.path.join(self.tmp, "conf.env")
        wb(
            self.conf,
            f'HOST_LABEL=validator\nPEER_SSH="env STATE_DIR={self.peer} TEXTFILE_DIR={self.tmp}/none"\n'.encode(),
        )
        ha.RATE_CAP = 1e6
        ha._stop = False
        self.node = FakeNode(make_chain(1000, 40, step=3600))
        rc, out = run(
            [
                "follow",
                "--dir",
                os.path.join(self.state, "archive"),
                "--rpc",
                self.node.url,
                "--rate",
                "1000",
                "--start",
                "1000",
                "--stop-at",
                "1039",
                "--poll",
                "0.01",
            ]
        )
        self.assertEqual(rc, 0, out)

    def tearDown(self):
        self.node.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sh(self, *args, state=None, stdin=None, env=None):
        e = dict(
            os.environ,
            STATE_DIR=state or self.state,
            TEXTFILE_DIR=self.tf,
            PFT_HISTARCHIVE_CONF=self.conf,
            PFT_HISTARCHIVE_REMOTE=f"bash {SH}",
        )
        e.update(env or {})
        p = subprocess.run(  # noqa: PLW1510 - rc is asserted by every caller
            ["bash", SH, *args],
            env=e,
            input=stdin,
            capture_output=True,
            timeout=120,
            stdin=None if stdin is not None else subprocess.DEVNULL,
        )
        return p.returncode, (p.stdout + p.stderr).decode()

    def ready(self):
        rc, out = self.sh("keygen")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("AGE-SECRET-KEY", out)
        self.assertEqual(
            os.stat(os.path.join(self.state, "age.key")).st_mode & 0o777, 0o600
        )
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        return out

    def prom(self, name):
        return rb(os.path.join(self.tf, f"{name}.prom")).decode()

    def rep(self, name):
        return os.path.join(self.peer, "replica", name)

    def test_replicate_verify_restore_pass(self):
        out = self.ready()
        self.assertIn("outbox: 2 new segment(s) encrypted", out)
        self.assertIn("sent 2026-11-10.jsonl.gz.age", out)
        self.assertIn("RESULT: PASS - local files 3, peer files 3, fails 0", out)
        self.assertIn(
            'pft_histarchive_replica_ok{host="validator"} 1\n',
            self.prom("pft_histarchive_replica"),
        )
        names = sorted(os.listdir(os.path.join(self.peer, "replica")))
        self.assertEqual(len([n for n in names if n.endswith(".age")]), 3, names)
        # the peer holds only ciphertext
        self.assertFalse(
            rb(self.rep("2026-11-10.jsonl.gz.age")).startswith(b"\x1f\x8b")
        )
        rc, out = self.sh("verify-replica")
        self.assertEqual(rc, 0, out)
        rc, out = self.sh("restore-verify")
        self.assertEqual(rc, 0, out)
        self.assertIn("decrypted 2 segments", out)
        self.assertIn("RESULT: PASS - segments 2 active 0 ledgers", out)
        self.assertIn("SAME 2026-11-10", out)
        self.assertIn("is in the local MANIFEST chain", out)
        self.assertIn("RESULT: PASS - restore-verify fails 0", out)
        self.assertEqual(
            [d for d in os.listdir(self.state) if d.startswith("restore.")], []
        )

    def test_second_replicate_sends_nothing_new(self):
        self.ready()
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        self.assertIn("outbox: 0 new segment(s) encrypted", out)
        self.assertNotIn("sent 2026", out)

    def test_tampered_replica_detected_everywhere(self):
        self.ready()
        b = bytearray(rb(self.rep("2026-11-11.jsonl.gz.age")))
        b[len(b) // 2] ^= 1
        wb(self.rep("2026-11-11.jsonl.gz.age"), bytes(b))
        rc, out = self.sh("verify-replica")
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "FAIL 2026-11-11.jsonl.gz.age: peer sha256 differs from the local encrypted copy",
            out,
        )
        self.assertIn("FAIL peer replica-check rc 1", out)
        self.assertIn(
            'pft_histarchive_replica_ok{host="validator"} 0\n',
            self.prom("pft_histarchive_replica"),
        )
        rc, out = self.sh("replica-check", state=self.peer)
        self.assertEqual(rc, 1)
        self.assertIn(
            "FAIL 2026-11-11.jsonl.gz.age: sha256 differs from REPLICA.json", out
        )
        rc, out = self.sh("restore-verify")
        self.assertEqual(rc, 1)
        self.assertIn(
            "FAIL 2026-11-11.jsonl.gz.age: fetched copy sha256 differs from REPLICA.json",
            out,
        )

    def test_tamper_with_rewritten_peer_index_still_caught(self):
        """A peer that re-hashes its own REPLICA.json passes its local check, but not ours."""
        self.ready()
        b = bytearray(rb(self.rep("2026-11-11.jsonl.gz.age")))
        b[len(b) // 2] ^= 1
        wb(self.rep("2026-11-11.jsonl.gz.age"), bytes(b))
        d = json.loads(rb(self.rep("REPLICA.json")))
        d["files"]["2026-11-11.jsonl.gz.age"] = ha.sha256_file(
            self.rep("2026-11-11.jsonl.gz.age")
        )
        wb(self.rep("REPLICA.json"), json.dumps(d).encode())
        self.assertEqual(self.sh("replica-check", state=self.peer)[0], 0)
        rc, out = self.sh("verify-replica")
        self.assertEqual(rc, 1)
        fails = [x.strip() for x in out.splitlines() if x.strip().startswith("FAIL")]
        self.assertEqual(
            fails,
            [
                "FAIL 2026-11-11.jsonl.gz.age: peer sha256 differs from the local encrypted copy"
            ],
            out,
        )
        # restore trusts the peer's index, so the ciphertext must fail decryption (age is authenticated)
        rc, out = self.sh("restore-verify")
        self.assertEqual(rc, 1)
        self.assertIn(
            "FAIL 2026-11-11.jsonl.gz.age: does not decrypt with this host's identity",
            out,
        )

    def test_missing_and_extra_files_then_self_heal(self):
        self.ready()
        os.unlink(self.rep("2026-11-10.jsonl.gz.age"))
        wb(self.rep("2026-01-01.jsonl.gz.age"), b"x")
        rc, out = self.sh("verify-replica")
        self.assertEqual(rc, 1)
        self.assertIn("FAIL 2026-11-10.jsonl.gz.age: missing on the peer", out)
        self.assertIn(
            "FAIL 2026-01-01.jsonl.gz.age: on the peer but not in the local REPLICA.json",
            out,
        )
        os.unlink(self.rep("2026-01-01.jsonl.gz.age"))
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        self.assertIn("sent 2026-11-10.jsonl.gz.age", out)

    def test_stale_peer_head_detected(self):
        self.ready()
        stale = rb(self.rep("REPLICA.json"))
        # a new day is sealed locally and replicated; then the peer's index is rolled back
        self.node.validated = 1039
        chain = make_chain(1000, 70, step=3600)
        self.node.chain.update(chain)
        self.node.validated = 1069
        rc, out = run(
            [
                "follow",
                "--dir",
                os.path.join(self.state, "archive"),
                "--rpc",
                self.node.url,
                "--rate",
                "1000",
                "--stop-at",
                "1069",
                "--poll",
                "0.01",
            ]
        )
        self.assertEqual(rc, 0, out)
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        self.assertIn("outbox: 1 new segment(s) encrypted", out)
        wb(self.rep("REPLICA.json"), stale)
        rc, out = self.sh("verify-replica")
        self.assertEqual(rc, 1)
        self.assertIn("peer REPLICA.json head_entry", out)

    def test_wrong_identity_cannot_restore(self):
        self.ready()
        os.rename(
            os.path.join(self.state, "age.key"),
            os.path.join(self.state, "age.key.real"),
        )
        os.unlink(os.path.join(self.state, "age.pub"))
        self.assertEqual(self.sh("keygen")[0], 0)
        rc, out = self.sh("restore-verify")
        self.assertEqual(rc, 1)
        self.assertIn("does not decrypt with this host's identity", out)

    def test_restored_copy_differs_from_local(self):
        self.ready()
        ar = ha.Archive(os.path.join(self.state, "archive"))
        es = ar.manifest_entries()
        es[0]["sealed_utc"] = "2000-01-01T00:00:00Z"
        es[0]["entry"] = ha.entry_hash(es[0])
        wb(ar.manifest, "".join(ha.canon(e) + "\n" for e in es).encode())
        rc, out = self.sh("restore-verify")
        self.assertEqual(rc, 1)
        self.assertIn("DIFF 2026-11-10", out)
        self.assertIn("SAME 2026-11-11", out)
        self.assertIn("RESULT: FAIL - restore-verify fails 1", out)

    def test_restore_from_dir(self):
        self.ready()
        rc, out = self.sh(
            "restore-verify", "--from-dir", os.path.join(self.peer, "replica")
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("source: dir", out)

    def test_receive_refuses_bad_names(self):
        for name in (
            "../x.age",
            "a.age",
            "2026-11-10.jsonl.gz",
            "meta-zz.tar.age",
            "REPLICA.json/../x",
        ):
            rc, out = self.sh("serve", "receive", name, state=self.peer, stdin=b"x")
            self.assertEqual(rc, 3, (name, out))
            self.assertIn("refusing name", out)
        rc, out = self.sh("serve", "export", "../age.key", state=self.peer)
        self.assertEqual(rc, 3)
        rc, out = self.sh("serve", "rm", state=self.peer)
        self.assertEqual(rc, 3)
        self.assertIn("unknown verb", out)

    def test_old_metadata_generations_pruned_on_peer(self):
        self.ready()
        first = [
            n
            for n in os.listdir(os.path.join(self.peer, "replica"))
            if n.startswith("meta-")
        ]
        wb(
            os.path.join(self.state, "archive", "gaps.jsonl"),
            b'{"from":1,"to":2,"reason":"test","at":"2026-11-10T00:00:00Z"}\n',
        )
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        now = [
            n
            for n in os.listdir(os.path.join(self.peer, "replica"))
            if n.startswith("meta-")
        ]
        self.assertEqual(len(first), 1)
        self.assertEqual(len(now), 1)
        self.assertNotEqual(first, now)

    def test_nothing_sealed_exports_an_ok_empty_replica(self):
        ar = os.path.join(self.state, "archive")
        os.unlink(os.path.join(ar, "MANIFEST.jsonl"))
        for f in os.listdir(os.path.join(ar, "segments")):
            os.unlink(os.path.join(ar, "segments", f))
        self.assertEqual(self.sh("keygen")[0], 0)
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        self.assertIn("nothing sealed yet", out)
        self.assertIn(
            'pft_histarchive_replica_ok{host="validator"} 1\n',
            self.prom("pft_histarchive_replica"),
        )
        self.assertFalse(os.path.isdir(os.path.join(self.peer, "replica")))

    def test_replicate_needs_keygen(self):
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 2, out)
        self.assertIn("no age recipient (run keygen)", out)

    def test_keygen_never_replaces(self):
        self.assertEqual(self.sh("keygen")[0], 0)
        key = rb(os.path.join(self.state, "age.key"))
        rc, _out = self.sh("keygen")
        self.assertEqual(rc, 4)
        self.assertEqual(rb(os.path.join(self.state, "age.key")), key)

    def test_metrics_and_periodic(self):
        rc, out = self.sh("metrics")
        self.assertEqual(rc, 0, out)
        p = self.prom("pft_histarchive_follow")
        self.assertIn('pft_histarchive_follow_last_ledger{host="validator"} 1039\n', p)
        self.assertIn('pft_histarchive_lag_ledgers{host="validator"} 0\n', p)
        self.assertEqual(self.sh("keygen")[0], 0)
        rc, out = self.sh("periodic")
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULT: PASS - segments 2 active 1 ledgers 40", out)
        self.assertIn("RESULT: PASS - replicate fails 0", out)
        self.assertIn(
            'pft_histarchive_verify_ok{host="validator"} 1\n',
            self.prom("pft_histarchive"),
        )
        rc, out = self.sh("periodic")  # nothing due: metrics only
        self.assertEqual(rc, 0, out)
        self.assertNotIn("RESULT", out)

    def test_periodic_reports_verify_failure(self):
        self.assertEqual(self.sh("keygen")[0], 0)
        seg = os.path.join(self.state, "archive", "segments", "2026-11-10.jsonl.gz")
        b = bytearray(rb(seg))
        b[-8] ^= 0xFF
        wb(seg, bytes(b))
        rc, out = self.sh("periodic")
        self.assertEqual(rc, 1, out)
        self.assertIn(
            'pft_histarchive_verify_ok{host="validator"} 0\n',
            self.prom("pft_histarchive"),
        )
        self.assertIn("replicate skipped: the local archive did not verify", out)
        self.assertFalse(
            os.path.exists(os.path.join(self.tf, "pft_histarchive_replica.prom"))
        )
        self.assertFalse(os.path.isdir(os.path.join(self.peer, "replica")))


if __name__ == "__main__":
    unittest.main()
