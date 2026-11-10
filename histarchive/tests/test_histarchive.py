#!/usr/bin/env python3
"""Fixture tests for histarchive.py (stdlib unittest; no node, no network beyond 127.0.0.1).

A fake JSON-RPC server serves synthetic ledgers whose headers, hashes and tx-tree roots are
built with the same rules as postfiatd (lib_hashverify), so every check runs on real-shaped data.
Run: TMPDIR=$HOME/.cache python3 -m unittest -v tests/test_histarchive.py (from histarchive/)
"""

import contextlib
import gzip
import hashlib
import http.server
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import lib_hashverify as hv

import histarchive as ha

PINNED_LIB_SHA256 = "64ec1dacc49fcc955975a6c5f5ee85d657c9c7921dbe0ef15cd9b9411ef4e414"
DAY = 86400
# 2026-11-10T23:59:00Z in ripple time
T0 = 1794355140 - ha.RIPPLE_EPOCH


def make_chain(first, n, step=4, t0=T0 - 3600, tx_every=3):
    """Synthetic ledgers first..first+n-1: {seq: rpc-style answer}."""
    out, parent = {}, hashlib.sha256(b"genesis").hexdigest().upper()
    for k in range(n):
        seq = first + k
        txs = []
        if k % tx_every == 0:
            for j in range(1 + k % 4):
                blob = hashlib.sha256(f"tx{seq}-{j}".encode()).digest() * 3
                meta = hashlib.sha256(f"meta{seq}-{j}".encode()).digest() * 2
                txs.append({"tx_blob": blob.hex().upper(), "meta": meta.hex().upper()})
        root, _ = hv.tx_tree(txs) if txs else (hv.ZERO.hex().upper(), [])
        led = {
            "ledger_index": seq,
            "total_coins": 99999999967720066,
            "parent_hash": parent,
            "transaction_hash": root,
            "account_hash": hashlib.sha256(f"acct{seq}".encode()).hexdigest().upper(),
            "parent_close_time": t0 + (k - 1) * step,
            "close_time": t0 + k * step,
            "close_time_resolution": 10,
            "close_flags": 0,
        }
        d = hv.serialize_header(led)
        h = hv.sha512half(hv.PREFIX_LEDGER, d).hex().upper()
        out[seq] = {
            "ledger": {
                "closed": True,
                "ledger_data": d.hex().upper(),
                "transactions": txs,
            },
            "ledger_hash": h,
            "ledger_index": seq,
            "validated": True,
            "status": "success",
        }
        parent = h
    return out


class FakeNode:
    """Serves server_info + ledger(binary) from a chain; knobs for pruning and bad answers."""

    def __init__(self, chain):
        self.chain = chain
        self.validated = max(chain)
        self.oldest = min(chain)
        self.bad = {}  # seq -> function(answer) -> answer
        self.calls = []
        node = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                m, p = req["method"], req["params"][0]
                node.calls.append(m)
                if m == "server_info":
                    res = {
                        "status": "success",
                        "info": {
                            "build_version": "fake",
                            "server_state": "full",
                            "validated_ledger": {"seq": node.validated},
                            "complete_ledgers": f"{node.oldest}-{node.validated}",
                        },
                    }
                else:
                    seq = int(p["ledger_index"])
                    if (
                        seq < node.oldest
                        or seq > node.validated
                        or seq not in node.chain
                    ):
                        res = {"status": "error", "error": "lgrNotFound"}
                    else:
                        res = json.loads(json.dumps(node.chain[seq]))
                        if not p.get("binary"):
                            hdr = ha.parse_header(
                                bytes.fromhex(res["ledger"]["ledger_data"])
                            )
                            res["ledger"] = dict(
                                hdr,
                                ledger_hash=res["ledger_hash"],
                                transactions=[
                                    hv.tx_id(bytes.fromhex(t["tx_blob"])).hex().upper()
                                    for t in res["ledger"]["transactions"]
                                ],
                            )
                        if seq in node.bad:
                            res = node.bad[seq](res)
                body = json.dumps({"result": res}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def rb(path):
    with open(path, "rb") as fh:
        return fh.read()


def wb(path, data, mode="wb"):
    with open(path, mode) as fh:
        fh.write(data)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = ha.main(argv)
    return rc, out.getvalue() + err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        base = os.environ.get("TEST_TMPDIR") or os.path.join(
            os.path.expanduser("~"), ".cache"
        )
        os.makedirs(base, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="pft-ha-test-", dir=base)
        self.dir = os.path.join(self.tmp, "arch")
        self.node = None
        ha._stop = False
        ha.RATE_CAP = 1e6

    def tearDown(self):
        if self.node:
            self.node.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def serve(self, chain):
        self.node = FakeNode(chain)
        return self.node

    def follow(self, start=None, stop_at=None, extra=()):
        argv = [
            "follow",
            "--dir",
            self.dir,
            "--rpc",
            self.node.url,
            "--rate",
            "1000",
            "--poll",
            "0.01",
            "--retry-sleep",
            "0",
            "--retries",
            "2",
        ]
        if start is not None:
            argv += ["--start", str(start)]
        if stop_at is not None:
            argv += ["--stop-at", str(stop_at)]
        return run(argv + list(extra))

    def verify(self, *extra):
        return run(["verify", "--dir", self.dir, *extra])

    def build(self, n=40, first=1000, seal=True, **kw):
        self.serve(make_chain(first, n, **kw))
        rc, out = self.follow(first, first + n - 1)
        self.assertEqual(rc, 0, out)
        if seal:
            self.assertEqual(run(["seal", "--dir", self.dir, "--all"])[0], 0)
        return out

    def rewrite_segment(self, day, fn, fix_manifest=True):
        """Apply fn(list of records) to a sealed segment, re-gzip, and keep MANIFEST consistent."""
        ar = ha.Archive(self.dir)
        _gz, raw = ha.read_segment(ar.seg_path(day))
        recs = [json.loads(x) for x in raw.split(b"\n") if x.strip()]
        recs = fn(recs)
        raw = b"".join(ha.canon(r).encode() + b"\n" for r in recs)
        gz = gzip.compress(raw, mtime=0)
        with open(ar.seg_path(day), "wb") as fh:
            fh.write(gz)
        if fix_manifest:
            es = ar.manifest_entries()
            prev = None
            for e in es:
                if e["day"] == day:
                    e.update(
                        sha256_gz=hashlib.sha256(gz).hexdigest(),
                        sha256_raw=hashlib.sha256(raw).hexdigest(),
                        bytes_gz=len(gz),
                        bytes_raw=len(raw),
                        count=len(recs),
                        first=recs[0]["i"],
                        last=recs[-1]["i"],
                        last_hash=recs[-1]["h"],
                        first_parent=ha.parse_header(bytes.fromhex(recs[0]["d"]))[
                            "parent_hash"
                        ],
                    )
                e["prev_entry"] = prev
                e["entry"] = ha.entry_hash(e)
                prev = e["entry"]
            with open(ar.manifest, "w") as fh:
                fh.write("".join(ha.canon(e) + "\n" for e in es))


class TestLib(unittest.TestCase):
    def test_vendored_lib_is_the_pinned_hashverify_copy(self):
        self.assertEqual(
            ha.sha256_file(os.path.join(os.path.dirname(HERE), "lib_hashverify.py")),
            PINNED_LIB_SHA256,
        )

    def test_parse_header_roundtrip(self):
        ans = make_chain(5, 2)[6]
        hdr = ha.parse_header(bytes.fromhex(ans["ledger"]["ledger_data"]))
        self.assertEqual(hdr["ledger_index"], 6)
        self.assertEqual(
            hv.serialize_header(hdr).hex().upper(), ans["ledger"]["ledger_data"]
        )
        with self.assertRaises(ValueError):
            ha.parse_header(b"\x00" * 117)

    def test_day_of_uses_utc_ripple_epoch(self):
        self.assertEqual(ha.day_of(T0), "2026-11-10")
        self.assertEqual(ha.day_of(T0 + 60), "2026-11-11")

    def test_check_record_clean(self):
        rec = ha.record_from_rpc(make_chain(7, 1)[7])
        self.assertEqual(ha.check_record(rec)[1], [])

    def test_check_record_hash_only(self):
        rec = ha.record_from_rpc(make_chain(7, 1)[7])
        rec["h"] = "00" * 32
        probs = ha.check_record(rec)[1]
        self.assertEqual(len(probs), 1)
        self.assertTrue(probs[0].startswith("hash:"), probs)

    def test_check_record_txroot_only(self):
        rec = ha.record_from_rpc(make_chain(7, 1, tx_every=1)[7])
        rec["t"][0][1] = rec["t"][0][1][:-2] + (
            "00" if rec["t"][0][1][-2:] != "00" else "11"
        )
        probs = ha.check_record(rec)[1]
        self.assertEqual(len(probs), 1)
        self.assertTrue(probs[0].startswith("txroot:"), probs)

    def test_check_record_dropped_tx(self):
        rec = ha.record_from_rpc(make_chain(7, 1, tx_every=1)[7])
        rec["t"] = []
        self.assertTrue(any(p.startswith("txroot:") for p in ha.check_record(rec)[1]))

    def test_check_record_index_only(self):
        rec = ha.record_from_rpc(make_chain(7, 1)[7])
        rec["i"] = 8
        probs = ha.check_record(rec)[1]
        self.assertEqual(len(probs), 1)
        self.assertTrue(probs[0].startswith("header:"), probs)

    def test_unvalidated_answer_refused(self):
        ans = make_chain(7, 1)[7]
        ans["validated"] = False
        with self.assertRaises(LookupError):
            ha.record_from_rpc(ans)

    def test_rpc_refuses_write_methods(self):
        with self.assertRaises(ValueError):
            ha.Rpc("http://127.0.0.1:9/").call("submit")

    def test_drop_torn_tail(self):
        d = tempfile.mkdtemp(dir=os.path.join(os.path.expanduser("~"), ".cache"))
        try:
            p = os.path.join(d, "x.jsonl")
            with open(p, "wb") as fh:
                fh.write(b'{"i":1}\n{"i":2}\n{"i":3')
            self.assertEqual(ha.drop_torn_tail(p), 6)
            with open(p, "wb") as fh:
                fh.write(b'{"i":1}\n{"i":2,\n')
            self.assertEqual(ha.drop_torn_tail(p), 8)
            self.assertEqual(rb(p), b'{"i":1}\n')
            self.assertEqual(ha.drop_torn_tail(p), 0)
        finally:
            shutil.rmtree(d)


class TestFollow(Base):
    def test_follow_and_verify_pass(self):
        self.build(40, seal=False)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("ledgers 40 (1000-1039)", out)

    def test_day_roll_seals_with_chained_manifest(self):
        # step 4 s from 23:59:00 -> 15 ledgers on day 1, rest on day 2; second run adds day 3
        self.serve(make_chain(1000, 60, step=4, t0=T0))
        rc, out = self.follow(1000, 1050)
        self.assertEqual(rc, 0, out)
        self.assertIn("SEAL 2026-11-10 ledgers 1000-1014 count=15", out)
        es = ha.Archive(self.dir).manifest_entries()
        self.assertEqual([e["day"] for e in es], ["2026-11-10"])
        self.assertEqual(es[0]["prev_entry"], None)
        self.assertEqual(self.verify()[0], 0)

    def test_three_days_chain(self):
        chain = make_chain(1000, 40, step=3600)
        self.serve(chain)
        rc, out = self.follow(1000, 1039)
        self.assertEqual(rc, 0, out)
        es = ha.Archive(self.dir).manifest_entries()
        self.assertEqual(len(es), 2)
        self.assertEqual(es[1]["prev_entry"], es[0]["entry"])
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("segments 2 active 1 ledgers 40", out)

    def test_resume_continues_without_dup_or_gap(self):
        self.serve(make_chain(1000, 50))
        self.assertEqual(self.follow(1000, 1020)[0], 0)
        rc, out = self.follow(None, 1049)
        self.assertIn("RESUME at ledger 1021", out)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("ledgers 50 (1000-1049)", out)

    def test_torn_line_cut_on_resume(self):
        self.serve(make_chain(1000, 30))
        self.follow(1000, 1010)
        p = ha.Archive(self.dir).active_path("2026-11-10")
        good = rb(p)
        with open(p, "ab") as fh:
            fh.write(b'{"d":"0079')
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("last line is torn", out)
        rc, out = self.follow(None, 1029)
        self.assertIn(
            "RESUME cut torn last line of active/2026-11-10.jsonl (10 bytes)", out
        )
        self.assertIn("RESUME at ledger 1011", out)
        self.assertTrue(rb(p).startswith(good))
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("ledgers 30 (1000-1029)", out)

    def test_torn_line_ending_in_newline_cut(self):
        self.serve(make_chain(1000, 20))
        self.follow(1000, 1009)
        p = ha.Archive(self.dir).active_path("2026-11-10")
        with open(p, "ab") as fh:
            fh.write(b'{"i":1010,"h"\n')
        _rc, out = self.follow(None, 1019)
        self.assertIn("RESUME cut torn last line", out)
        self.assertEqual(self.verify()[0], 0)

    def test_crash_after_segment_rename_redoes_seal(self):
        self.serve(make_chain(1000, 30))
        self.follow(1000, 1009)
        ar = ha.Archive(self.dir)
        with open(ar.seg_path("2026-11-10"), "wb") as fh:
            fh.write(b"half")  # segment present, no MANIFEST entry, active still there
        with open(ar.seg_path("2026-11-09") + ".tmp", "wb") as fh:
            fh.write(b"tmp")
        rc, out = self.follow(None, 1029)
        self.assertIn("RESUME removed half-written 2026-11-09.jsonl.gz.tmp", out)
        self.assertIn("RESUME removed unrecorded segment 2026-11-10.jsonl.gz", out)
        self.assertEqual(run(["seal", "--dir", self.dir, "--all"])[0], 0)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)

    def test_crash_after_manifest_append_removes_active(self):
        self.serve(make_chain(1000, 30))
        self.follow(1000, 1009)
        ar = ha.Archive(self.dir)
        keep = rb(ar.active_path("2026-11-10"))
        ha.seal_day(ar, "2026-11-10")
        with open(ar.active_path("2026-11-10"), "wb") as fh:
            fh.write(keep)  # as if the unlink never happened
        _rc, out = self.follow(None, 1015)
        self.assertIn(
            "RESUME seal 2026-11-10: manifest entry and segment present, removed active copy",
            out,
        )
        self.assertIn("RESUME at ledger 1010", out)

    def test_pruned_while_down_records_gap(self):
        node = self.serve(make_chain(1000, 60))
        node.validated = 1019
        self.follow(1000, 1009)
        node.oldest, node.validated = 1030, 1059
        rc, out = self.follow(None, 1059)
        self.assertIn(
            "GAP ledgers 1010-1029 (20): pruned on the node before archiving (oldest 1030)",
            out,
        )
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("NOTE recorded gap 1010-1029", out)
        self.assertIn("gaps 1 (20 ledgers)", out)
        os.unlink(ha.Archive(self.dir).gaps)
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("missing ledgers 1010-1029 (no gaps.jsonl entry)", out)

    def test_bad_hash_at_ingest_becomes_gap(self):
        node = self.serve(make_chain(1000, 20))

        def corrupt(res):
            res["ledger_hash"] = "11" * 32
            return res

        node.bad[1005] = corrupt
        rc, out = self.follow(1000, 1019)
        self.assertIn("WARN ledger 1005 attempt 1/2", out)
        self.assertIn("GAP ledgers 1005-1005 (1): verification failed at ingest", out)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("ledgers 19", out)

    def test_wrong_parent_at_ingest_refused(self):
        chain = make_chain(1000, 20)
        other = make_chain(
            1010, 10, t0=T0 - 3599
        )  # a fork: valid ledgers on another parent
        chain.update(other)
        self.serve(chain)
        _rc, out = self.follow(1000, 1019)
        self.assertIn("chain: parent", out)
        self.assertIn("GAP ledgers 1010-1010 (1): verification failed at ingest", out)

    def test_until_in_the_past_stops_at_once(self):
        self.serve(make_chain(1000, 10))
        rc, out = self.follow(1000, 1009, ["--until", "2000-01-01T00:00:00Z"])
        self.assertEqual(rc, 0, out)
        self.assertIn("this run stops at 2000-01-01T00:00:00Z (--until)", out)
        self.assertIn("STOP (run time reached) last=999 archived_this_run=0", out)

    def test_signal_stops_after_current_ledger(self):
        self.serve(make_chain(1000, 10))
        ha._stop = True
        _rc, out = self.follow(1000, 1009)
        self.assertIn("STOP (signal) last=999 archived_this_run=0", out)


class TestVerify(Base):
    def test_broken_parent_link_in_segment(self):
        self.build(30)

        def relink(recs):
            # replace ledger 1010 with a valid ledger from another chain (own hash ok, parent wrong)
            alt = ha.record_from_rpc(make_chain(1010, 1, t0=T0 - 3598)[1010])
            recs[10] = alt
            return recs

        self.rewrite_segment("2026-11-10", relink)
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        fails = [x for x in out.splitlines() if x.startswith("FAIL")]
        self.assertTrue(any("ledger 1010: chain:" in f for f in fails), out)
        self.assertTrue(any("ledger 1011: chain:" in f for f in fails), out)
        self.assertFalse(any("sha256" in f for f in fails), out)

    def test_missing_ledger(self):
        self.build(30)
        self.rewrite_segment("2026-11-10", lambda r: r[:12] + r[13:])
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("missing ledgers 1012-1012 (no gaps.jsonl entry)", out)

    def test_duplicate_ledger(self):
        self.build(20)
        self.rewrite_segment("2026-11-10", lambda r: r[:6] + [r[5]] + r[6:])
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("ledger 1005: order: not after 1005", out)

    def test_tampered_segment_byte(self):
        self.build(30)
        p = ha.Archive(self.dir).seg_path("2026-11-10")
        b = bytearray(rb(p))
        b[len(b) // 2] ^= 0x01
        wb(p, bytes(b))
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertTrue(
            "not readable as gzip" in out or "sha256 of the file differs" in out, out
        )

    def test_bad_crc_with_intact_data(self):
        self.build(20)
        p = ha.Archive(self.dir).seg_path("2026-11-10")
        b = bytearray(rb(p))
        b[-8] ^= 0xFF  # CRC32 field only
        wb(p, bytes(b))
        _rc, out = self.verify()
        self.assertIn("not readable as gzip", out)

    def test_truncated_segment(self):
        self.build(20)
        p = ha.Archive(self.dir).seg_path("2026-11-10")
        b = rb(p)
        wb(p, b[: len(b) - 40])
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn("not readable as gzip", out)

    def test_tampered_tx_with_consistent_manifest(self):
        self.build(30, tx_every=1)

        def flip(recs):
            m = recs[7]["t"][0][1]
            recs[7]["t"][0][1] = m[:-2] + ("00" if m[-2:] != "00" else "11")
            return recs

        self.rewrite_segment("2026-11-10", flip)
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        fails = [x for x in out.splitlines() if x.startswith("FAIL")]
        self.assertEqual(len(fails), 1, out)
        self.assertIn("ledger 1007: txroot:", fails[0])

    def test_rehashed_header_breaks_chain(self):
        self.build(20)

        def rehash(recs):
            d = bytearray(bytes.fromhex(recs[4]["d"]))
            d[80] ^= 0x01  # account_hash byte
            recs[4]["d"] = bytes(d).hex().upper()
            recs[4]["h"] = hv.sha512half(hv.PREFIX_LEDGER, bytes(d)).hex().upper()
            return recs

        self.rewrite_segment("2026-11-10", rehash)
        _rc, out = self.verify()
        fails = [x for x in out.splitlines() if x.startswith("FAIL")]
        self.assertEqual(len(fails), 1, out)
        self.assertIn("ledger 1005: chain:", fails[0])

    def test_manifest_entry_edited(self):
        chain = make_chain(1000, 40, step=3600)
        self.serve(chain)
        self.follow(1000, 1039)
        ar = ha.Archive(self.dir)
        es = ar.manifest_entries()
        es[0]["txs"] += 1
        with open(ar.manifest, "w") as fh:
            fh.write("".join(ha.canon(e) + "\n" for e in es))
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn(
            "manifest entry 1 (2026-11-10): entry hash does not match its content", out
        )
        es[0]["entry"] = ha.entry_hash(es[0])
        with open(ar.manifest, "w") as fh:
            fh.write("".join(ha.canon(e) + "\n" for e in es))
        rc, out = self.verify()
        self.assertIn(
            "manifest entry 2 (2026-11-11): prev_entry does not link to entry 1", out
        )
        self.assertNotIn("entry hash does not match", out)

    def test_segment_removed_or_unlisted(self):
        chain = make_chain(1000, 40, step=3600)
        self.serve(chain)
        self.follow(1000, 1039)
        ar = ha.Archive(self.dir)
        shutil.copy(
            ar.seg_path("2026-11-10"), os.path.join(ar.segments, "2026-11-01.jsonl.gz")
        )
        rc, out = self.verify()
        self.assertEqual(rc, 1)
        self.assertIn(
            "segment segments/2026-11-01.jsonl.gz: not listed in MANIFEST", out
        )
        os.unlink(ar.seg_path("2026-11-11"))
        _rc, out = self.verify()
        self.assertIn("segment segments/2026-11-11.jsonl.gz: missing", out)

    def test_manifest_counts_checked(self):
        self.build(20)
        ar = ha.Archive(self.dir)
        es = ar.manifest_entries()
        es[0]["count"] = 19
        es[0]["entry"] = ha.entry_hash(es[0])
        with open(ar.manifest, "w") as fh:
            fh.write(ha.canon(es[0]) + "\n")
        _rc, out = self.verify()
        fails = [x for x in out.splitlines() if x.startswith("FAIL")]
        self.assertEqual(
            fails,
            [
                "FAIL segments/2026-11-10.jsonl.gz: first/last/count differ from MANIFEST"
            ],
            out,
        )

    def test_textfile_metrics(self):
        self.build(20, seal=False)
        tf = os.path.join(self.tmp, "ha.prom")
        self.assertEqual(self.verify("--textfile", tf)[0], 0)
        txt = rb(tf).decode()
        for want in (
            'pft_histarchive_verify_ok{host="validator"} 1',
            'pft_histarchive_ledgers{host="validator"} 20',
            'pft_histarchive_gaps{host="validator"} 0',
            'pft_histarchive_last_ledger{host="validator"} 1019',
        ):
            self.assertIn(want + "\n", txt)
        os.unlink(os.path.join(ha.Archive(self.dir).active_path("2026-11-10")))
        self.assertEqual(self.verify("--textfile", tf)[0], 0)
        self.assertIn('pft_histarchive_ledgers{host="validator"} 0\n', rb(tf).decode())


class TestReplicaAndCrosscheck(Base):
    def test_replica_check(self):
        d = os.path.join(self.tmp, "rep")
        os.makedirs(d)
        for n in ("a.age", "b.age"):
            wb(os.path.join(d, n), n.encode() * 10)
        rc, out = run(["cipher-index", "--dir", d])
        files = json.loads(out)
        wb(
            os.path.join(d, "REPLICA.json"),
            json.dumps({"files": files, "head_entry": "ab" * 32}).encode(),
        )
        self.assertEqual(run(["replica-check", "--dir", d])[0], 0)
        wb(os.path.join(d, "a.age"), b"x", "ab")
        wb(os.path.join(d, "c.age"), b"c")
        os.unlink(os.path.join(d, "b.age"))
        rc, out = run(["replica-check", "--dir", d])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL a.age: sha256 differs from REPLICA.json", out)
        self.assertIn("FAIL b.age: missing on replica", out)
        self.assertIn("FAIL c.age: not listed in REPLICA.json", out)

    def test_crosscheck_online_offline_negative(self):
        self.build(40, seal=True)
        rec = os.path.join(self.tmp, "xc.jsonl")
        rc, out = run(
            [
                "crosscheck",
                "--dir",
                self.dir,
                "--rpc",
                self.node.url,
                "--rate",
                "1000",
                "--sample",
                "10",
                "--record",
                rec,
            ]
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("10/10 MATCH", out)
        rc, out = run(
            ["crosscheck", "--dir", self.dir, "--offline", rec, "--sample", "10"]
        )
        self.assertEqual(rc, 0, out)
        rc, out = run(
            [
                "crosscheck",
                "--dir",
                self.dir,
                "--offline",
                rec,
                "--sample",
                "10",
                "--negative",
            ]
        )
        self.assertEqual(rc, 1)
        self.assertEqual(out.count("MISMATCH"), 10, out)
        self.assertIn("0/10 MATCH", out)

    def test_crosscheck_detects_differing_tx_ids(self):
        self.build(40, tx_every=1)

        def drop_tx(res):
            res["ledger"]["transactions"] = res["ledger"]["transactions"][1:]
            return res

        for s in range(1000, 1040):
            self.node.bad[s] = drop_tx
        rc, out = run(
            [
                "crosscheck",
                "--dir",
                self.dir,
                "--rpc",
                self.node.url,
                "--rate",
                "1000",
                "--sample",
                "5",
            ]
        )
        self.assertEqual(rc, 1)
        self.assertIn("ids differ", out)

    def test_crosscheck_retries_then_unchecked(self):
        self.build(20)
        self.node.oldest = 1000
        for s in range(1000, 1020):
            self.node.bad[s] = lambda res: {"status": "error", "error": "lgrNotFound"}
        rc, out = run(
            [
                "crosscheck",
                "--dir",
                self.dir,
                "--rpc",
                self.node.url,
                "--rate",
                "1000",
                "--sample",
                "1",
                "--retries",
                "1",
            ]
        )
        self.assertEqual(rc, 1)
        self.assertIn("RETRY", out)
        self.assertIn("UNCHECKED", out)


if __name__ == "__main__":
    unittest.main()
