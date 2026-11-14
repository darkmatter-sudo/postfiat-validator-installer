#!/usr/bin/env python3
"""Tests for verified gap repair: histarchive.py fill-gap / gaps, verify over fills, the wrapper's
fill-gap and the replica path for fill segments.

Every refused case asserts the specific FAIL reason AND that no byte of the archive changed
(snapshot of every file before vs after). Run (from histarchive/):
  TMPDIR=$HOME/.cache python3 -m unittest tests/test_fillgap.py
"""

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from test_histarchive import Base, make_chain, rb, run, wb

import histarchive as ha
import lib_hashverify as hv

SH = os.path.join(os.path.dirname(HERE), "pft-histarchive.sh")
GAP = "1010-1029"


def snapshot(root):
    """{relative path: sha256} of every file under root (the lock file is content-free and skipped)."""
    out = {}
    for d, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            if f != ".lock":
                out[os.path.relpath(p, root)] = hashlib.sha256(rb(p)).hexdigest()
    return out


def reheader(ans, **fields):
    """Copy of an RPC answer with header fields changed and the ledger hash recomputed (self-consistent)."""
    ans = json.loads(json.dumps(ans))
    hdr = ha.parse_header(bytes.fromhex(ans["ledger"]["ledger_data"]))
    hdr.update(fields)
    d = hv.serialize_header(hdr)
    ans["ledger"]["ledger_data"] = d.hex().upper()
    ans["ledger_hash"] = hv.sha512half(hv.PREFIX_LEDGER, d).hex().upper()
    return ans


class FillBase(Base):
    def make_gap(self, seal=False):
        """Archive 1000-1059 with the recorded gap 1010-1029 (node pruned while the follower was down)."""
        self.chain = make_chain(1000, 60)
        node = self.serve(self.chain)
        node.validated = 1019
        self.follow(1000, 1009)
        node.oldest, node.validated = 1030, 1059
        rc, out = self.follow(None, 1059)
        self.assertIn("GAP ledgers 1010-1029 (20)", out)
        if seal:
            self.assertEqual(run(["seal", "--dir", self.dir, "--all"])[0], 0)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("gaps 1 (20 ledgers) filled 0", out)

    def stage(self, lo=1009, hi=1030, edit=None, fmt="rpc", name="staged.jsonl"):
        """Write a staged capture of lo..hi; edit(seq, answer) -> answer | None (drop)."""
        lines = []
        for i in range(lo, hi + 1):
            ans = json.loads(json.dumps(self.chain[i]))
            if edit:
                ans = edit(i, ans)
            if ans is None:
                continue
            if fmt == "rpc":
                lines.append(json.dumps({"result": ans}))
            else:
                lines.append(ha.canon(ha.record_from_rpc(ans)))
        path = os.path.join(self.tmp, name)
        wb(path, ("\n".join(lines) + "\n").encode())
        return path

    def fill(self, *src, gap=GAP):
        return run(["fill-gap", "--dir", self.dir, "--gap", gap, *src])

    def refused(self, reason, *src, gap=GAP, rc_want=1):
        before = snapshot(self.dir)
        rc, out = self.fill(*src, gap=gap)
        fill_out = out
        self.assertEqual(rc, rc_want, out)
        self.assertIn(reason, out)
        if rc_want == 1:
            self.assertIn("nothing written", out)
        self.assertEqual(
            snapshot(self.dir), before, "a refused fill changed the archive"
        )
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("gaps 1 (20 ledgers) filled 0", out)
        return fill_out


class TestFillPass(FillBase):
    def check_filled(self, source_type):
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("gaps 0 (0 ledgers) filled 1 fails 0", out)
        self.assertIn(
            "NOTE filled gap 1010-1029 (20 ledgers, verified in the chain)", out
        )
        self.assertIn("ledgers 60 (1000-1059)", out)
        ar = ha.Archive(self.dir)
        e = ha.fill_entries(ar)[0]
        self.assertEqual((e["first"], e["last"], e["count"]), (1010, 1029, 20))
        self.assertEqual(
            e["anchor_below"], {"i": 1009, "h": self.chain[1009]["ledger_hash"]}
        )
        self.assertEqual(
            e["anchor_above"], {"i": 1030, "h": self.chain[1030]["ledger_hash"]}
        )
        self.assertEqual(e["last_hash"], self.chain[1029]["ledger_hash"])
        self.assertEqual(e["source"]["type"], source_type)
        self.assertEqual(e["entry"], ha.entry_hash(e))
        self.assertEqual(
            e["gap"]["reason"], "pruned on the node before archiving (oldest 1030)"
        )
        fills = ha.read_jsonl(ar.gapfills)
        self.assertEqual(len(fills), 1)
        self.assertEqual(
            (fills[0]["from"], fills[0]["to"], fills[0]["entry"]),
            (1010, 1029, e["entry"]),
        )
        # gaps.jsonl is append-only: the original gap line is untouched
        self.assertEqual(len(ha.read_jsonl(ar.gaps)), 1)
        return e

    def test_staged_fill_active_archive(self):
        self.make_gap(seal=False)
        rc, out = self.fill("--staged", self.stage())
        self.assertEqual(rc, 0, out)
        self.assertIn(
            "checks: 20 ledgers header+hash+txroot OK, chain 1009->1030 unbroken (21 links",
            out,
        )
        self.assertIn("source also held 2 ledger(s) outside the gap (1009..1030)", out)
        e = self.check_filled("staged")
        self.assertEqual(
            e["source"]["sha256"],
            hashlib.sha256(rb(os.path.join(self.tmp, "staged.jsonl"))).hexdigest(),
        )

    def test_staged_fill_sealed_archive_record_format(self):
        self.make_gap(seal=True)
        rc, out = self.fill("--staged", self.stage(1010, 1029, fmt="record"))
        self.assertEqual(rc, 0, out)
        self.check_filled("staged")

    def test_rpc_fill_from_peer(self):
        self.make_gap()
        self.node.oldest = 1000  # the peer still holds the range
        self.node.calls.clear()
        rc, out = self.fill("--rpc", self.node.url, "--rate", "1000")
        self.assertEqual(rc, 0, out)
        self.assertIn("source answered 20/20 ledgers in 21 requests", out)
        self.assertEqual(set(self.node.calls), {"server_info", "ledger"})
        e = self.check_filled("rpc")
        self.assertEqual(e["source"]["rpc"], "http://<local>")

    def test_dry_run_writes_nothing(self):
        self.make_gap()
        before = snapshot(self.dir)
        rc, out = self.fill("--staged", self.stage(), "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN: every check passed; nothing written", out)
        self.assertEqual(snapshot(self.dir), before)

    def test_follower_continues_and_seals_after_fill(self):
        self.make_gap()
        self.assertEqual(self.fill("--staged", self.stage())[0], 0)
        self.chain.update(
            make_chain(1000, 80)
        )  # same deterministic chain, 20 more ledgers
        self.node.chain = self.chain
        self.node.validated = 1079
        rc, out = self.follow(None, 1079)
        self.assertIn("RESUME at ledger 1060", out)
        self.assertEqual(run(["seal", "--dir", self.dir, "--all"])[0], 0)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("ledgers 80 (1000-1079)", out)
        self.assertIn("gaps 0 (0 ledgers) filled 1 fails 0", out)
        kinds = [e.get("kind", "day") for e in ha.Archive(self.dir).manifest_entries()]
        self.assertEqual(
            kinds[0], "fill"
        )  # the fill was committed before the day segments were sealed
        self.assertGreater(len(kinds), 1)


class TestFillRefused(FillBase):
    def setUp(self):
        super().setUp()
        self.make_gap()

    def test_tampered_header_byte(self):
        def edit(i, a):
            if i == 1015:
                d = bytearray.fromhex(a["ledger"]["ledger_data"])
                d[100] ^= 1  # account_hash byte; ledger_hash left as recorded
                a["ledger"]["ledger_data"] = d.hex().upper()
            return a

        self.refused(
            "FAIL ledger 1015: hash: recomputed", "--staged", self.stage(edit=edit)
        )

    def test_tampered_transaction(self):
        busy = next(
            i for i in range(1010, 1030) if self.chain[i]["ledger"]["transactions"]
        )

        def edit(i, a):
            if i == busy:
                t = a["ledger"]["transactions"][0]
                t["meta"] = t["meta"][:-2] + ("00" if t["meta"][-2:] != "00" else "11")
            return a

        self.refused(
            f"FAIL ledger {busy}: txroot: rebuilt", "--staged", self.stage(edit=edit)
        )

    def test_truncated_capture_missing_ledger(self):
        self.refused(
            "FAIL source lacks 1 ledger(s) of the gap, first 1029",
            "--staged",
            self.stage(1009, 1028),
        )

    def test_torn_last_line(self):
        p = self.stage(1009, 1029)  # the torn line is the gap's last ledger
        data = rb(p)
        wb(p, data[: len(data) - 200])
        out = self.refused("unreadable", "--staged", p)
        self.assertIn("FAIL source lacks 1 ledger(s) of the gap, first 1029", out)

    def test_swapped_ledgers(self):
        def edit(i, a):  # 1014 and 1015 exchange content, lines keep their order
            if i in (1014, 1015):
                o = json.loads(json.dumps(self.chain[2029 - i]))
                o["ledger_index"] = i
                return o
            return a

        out = self.refused(
            "FAIL ledger 1014: header: index 1015 != line index 1014",
            "--staged",
            self.stage(edit=edit),
        )
        self.assertIn("chain: parent", out)

    def test_foreign_chain_breaks_lower_anchor(self):
        other = make_chain(
            1000, 60, t0=12345
        )  # self-consistent ledgers of a different history

        def edit(i, a):
            return json.loads(json.dumps(other[i])) if 1010 <= i <= 1029 else a

        out = self.refused(
            "FAIL ledger 1010: chain: parent",
            "--staged",
            self.stage(1010, 1029, edit=edit),
        )
        self.assertIn("!= anchor ledger 1009", out)

    def test_upper_anchor_broken(self):
        def edit(
            i, a
        ):  # 1029 re-made with its correct parent but different content: valid by itself
            if i == 1029:
                return reheader(a, account_hash="AB" * 32)
            return a

        out = self.refused(
            "FAIL anchor: archived ledger 1030 parent",
            "--staged",
            self.stage(1010, 1029, edit=edit),
        )
        self.assertNotIn("FAIL ledger 1029", out)

    def test_staged_anchor_copy_differs(self):
        def edit(i, a):
            return reheader(a, account_hash="CD" * 32) if i == 1009 else a

        self.refused(
            "FAIL anchor: source copy of ledger 1009 differs from the archived one",
            "--staged",
            self.stage(edit=edit),
        )

    def test_duplicate_index_different_content(self):
        p = self.stage()
        wb(
            p,
            (
                json.dumps(
                    {"result": reheader(self.chain[1012], account_hash="EF" * 32)}
                )
                + "\n"
            ).encode(),
            "ab",
        )
        self.refused("ledger 1012 appears twice with different content", "--staged", p)

    def test_not_a_recorded_gap(self):
        self.refused(
            "REFUSED: 1011-1029 is not a recorded gap",
            "--staged",
            self.stage(),
            gap="1011-1029",
        )

    def test_missing_lower_anchor(self):
        ar = ha.Archive(self.dir)
        ha.append_line(
            ar.gaps,
            ha.canon(
                {
                    "from": 990,
                    "to": 999,
                    "reason": "test: before the archive",
                    "at": "x",
                }
            ),
        )
        chain = make_chain(990, 10)
        p = os.path.join(self.tmp, "early.jsonl")
        wb(
            p,
            "".join(
                json.dumps({"result": chain[i]}) + "\n" for i in range(990, 1000)
            ).encode(),
        )
        before = snapshot(self.dir)
        rc, out = self.fill("--staged", p, gap="990-999")
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "FAIL anchor: ledger 989 (below the gap) is not in the archive", out
        )
        self.assertEqual(snapshot(self.dir), before)

    def test_duplicate_fill_refused(self):
        p = self.stage()
        self.assertEqual(self.fill("--staged", p)[0], 0)
        before = snapshot(self.dir)
        rc, out = self.fill("--staged", p)
        self.assertEqual(rc, 1, out)
        self.assertIn("REFUSED: gap 1010-1029 is already filled", out)
        self.assertEqual(snapshot(self.dir), before)
        # refused before the source is even asked
        self.node.oldest = 1000
        self.node.calls.clear()
        rc, out = self.fill("--rpc", self.node.url, "--rate", "1000")
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.node.calls, [])
        self.assertEqual(snapshot(self.dir), before)

    def test_missing_upper_anchor(self):
        ar = ha.Archive(self.dir)
        ha.append_line(
            ar.gaps,
            ha.canon(
                {"from": 1060, "to": 1069, "reason": "test: at the tip", "at": "x"}
            ),
        )
        chain = make_chain(1000, 80)
        p = os.path.join(self.tmp, "tip.jsonl")
        wb(
            p,
            "".join(
                json.dumps({"result": chain[i]}) + "\n" for i in range(1060, 1070)
            ).encode(),
        )
        before = snapshot(self.dir)
        rc, out = self.fill("--staged", p, gap="1060-1069")
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "FAIL anchor: ledger 1070 (above the gap) is not in the archive", out
        )
        self.assertNotIn("FAIL ledger", out)
        self.assertEqual(snapshot(self.dir), before)

    def test_commit_rechecks_under_lock(self):
        # a fill that passed its checks must not be committed twice if another run filled the gap meanwhile
        p = self.stage()
        self.assertEqual(self.fill("--staged", p)[0], 0)
        ar = ha.Archive(self.dir)
        recs, _ = ha.staged_records(p)
        below, above = ha.anchors(ar, 1010, 1029)
        before = snapshot(self.dir)
        with self.assertRaises(ha.FillRefused):
            ha.commit_fill(ar, 1010, 1029, {}, recs, below, above, {"type": "staged"})
        self.assertEqual(snapshot(self.dir), before)

    def test_rpc_source_lacks_range(self):
        self.refused(
            "FAIL source does not hold 1010-1029",
            "--rpc",
            self.node.url,
            "--rate",
            "1000",
        )

    def test_rpc_unvalidated_answers(self):
        self.node.oldest = 1000
        self.node.bad[1020] = lambda r: dict(r, validated=False)
        out = self.refused(
            "FAIL ledger 1020: no answer from the source after 1 attempts",
            "--rpc",
            self.node.url,
            "--rate",
            "1000",
            "--retries",
            "1",
        )
        self.assertIn("ledger not validated", out)

    def test_archive_busy(self):
        p = self.stage()
        before = snapshot(self.dir)
        with ha.archive_lock(self.dir):
            rc, out = self.fill("--staged", p, "--lock-timeout", "0.3")
        self.assertEqual(rc, 2, out)
        self.assertIn("archive busy", out)
        self.assertEqual(snapshot(self.dir), before)


class TestFillCrashAndVerify(FillBase):
    def setUp(self):
        super().setUp()
        self.make_gap()
        self.staged = self.stage()

    def test_crash_before_manifest_append_is_redone(self):
        real = ha.append_line

        def boom(path, line):
            if path.endswith("MANIFEST.jsonl"):
                raise OSError("simulated crash")
            return real(path, line)

        ha.append_line = boom
        try:
            rc, out = self.fill("--staged", self.staged)
        finally:
            ha.append_line = real
        self.assertEqual(rc, 2, out)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "segment segments/fill-1010-1029.jsonl.gz: not listed in MANIFEST", out
        )
        rc, out = self.fill("--staged", self.staged)
        self.assertEqual(rc, 0, out)
        self.assertIn(
            "RESUME removed segments/fill-1010-1029.jsonl.gz (no MANIFEST entry; fill is redone)",
            out,
        )
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("filled 1 fails 0", out)

    def test_crash_before_gapfills_line_is_repaired(self):
        real = ha.append_line

        def boom(path, line):
            if path.endswith("gapfills.jsonl"):
                raise OSError("simulated crash")
            return real(path, line)

        ha.append_line = boom
        try:
            rc, out = self.fill("--staged", self.staged)
        finally:
            ha.append_line = real
        self.assertEqual(rc, 2, out)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("is in MANIFEST but not yet in gapfills.jsonl", out)
        rc, out = self.fill("--staged", self.staged)
        self.assertEqual(rc, 1, out)  # already filled ...
        self.assertIn(
            "RESUME gapfills.jsonl: added the missing line for fill 1010-1029", out
        )  # ... state repaired
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("not yet in gapfills.jsonl", out)

    def filled(self):
        rc, out = self.fill("--staged", self.staged)
        self.assertEqual(rc, 0, out)
        return ha.Archive(self.dir)

    def test_fill_segment_removed(self):
        ar = self.filled()
        os.unlink(os.path.join(self.dir, "segments", "fill-1010-1029.jsonl.gz"))
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("segment segments/fill-1010-1029.jsonl.gz: missing", out)
        self.assertTrue(ar)

    def test_fill_content_tampered_with_consistent_manifest(self):
        self.filled()

        def bad(recs):
            r = recs[5]
            d = bytearray.fromhex(r["d"])
            d[100] ^= 1
            r["d"] = d.hex().upper()
            r["h"] = (
                hv.sha512half(hv.PREFIX_LEDGER, bytes(d)).hex().upper()
            )  # self-consistent forgery
            return recs

        self.rewrite_segment("fill-1010-1029", bad)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "ledger 1016: chain: parent_hash does not equal ledger 1015's hash", out
        )

    def test_forged_gapfills_claim(self):
        ar = ha.Archive(self.dir)
        ha.append_line(
            ar.gapfills, ha.canon({"from": 1010, "to": 1029, "entry": "0" * 64})
        )
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "gapfills.jsonl line 1: fill 1010-1029 has no matching MANIFEST fill entry",
            out,
        )

    def test_fill_without_recorded_gap(self):
        ar = self.filled()
        os.unlink(ar.gaps)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("fill 1010-1029 does not match a recorded gap in gaps.jsonl", out)

    def test_fill_entry_appended_twice(self):
        ar = self.filled()
        es = ar.manifest_entries()
        dup = dict(es[-1], prev_entry=es[-1]["entry"])
        dup["entry"] = ha.entry_hash(dup)
        ha.append_line(ar.manifest, ha.canon(dup))
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("gap 1010-1029 filled twice", out)
        self.assertIn("order: not after", out)

    def test_short_fill_entry(self):
        # a fill entry (and segment) with the gap's first/last but a ledger missing in the middle
        ar = self.filled()
        self.rewrite_segment("fill-1010-1029", lambda recs: recs[:5] + recs[6:])
        e = ha.fill_entries(ar)[0]
        self.assertEqual((e["first"], e["last"], e["count"]), (1010, 1029, 19))
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("fill count does not cover the whole gap", out)
        self.assertNotIn("does not match a recorded gap", out)
        self.assertIn("missing ledgers 1015-1015 (no gaps.jsonl entry)", out)

    def test_end_of_fill_entry_moved(self):
        # the fill's records and entry end one ledger early: it no longer matches the recorded gap
        self.filled()
        self.rewrite_segment("fill-1010-1029", lambda recs: recs[:-1])
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("fill 1010-1028 does not match a recorded gap", out)
        self.assertIn(
            "fill 1010-1028: neighbour ledger(s) 1029 not in the archive", out
        )

    def forge_last_entry(self, **kw):
        ar = ha.Archive(self.dir)
        es = ar.manifest_entries()
        es[-1].update(kw)
        es[-1]["entry"] = ha.entry_hash(es[-1])
        wb(ar.manifest, "".join(ha.canon(e) + "\n" for e in es).encode())

    def test_manifest_anchor_field_forged(self):
        self.filled()
        self.forge_last_entry(anchor_below={"i": 1009, "h": "00" * 32})
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("anchor_below in MANIFEST differs from archived ledger 1009", out)

    def test_sealed_only_checks_fill_on_its_own_chain(self):
        self.filled()  # the gap and both neighbours are in active/ (the live shape)
        rc, out = self.verify("--sealed-only")
        self.assertEqual(rc, 0, out)
        self.assertIn("fill 1010-1029 checked on its own chain", out)
        self.assertIn("filled 1 fails 0", out)
        self.forge_last_entry(anchor_below={"i": 1009, "h": "00" * 32})
        rc, out = self.verify("--sealed-only")
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "ledger 1010: chain: parent_hash does not equal ledger 1009's hash", out
        )

    def test_fill_neighbour_missing_in_full_verify(self):
        ar = self.filled()
        p = ar.active_path(ar.active_days()[0])
        keep = [
            x for x in rb(p).split(b"\n") if x.strip() and json.loads(x)["i"] != 1030
        ]
        wb(p, b"\n".join(keep) + b"\n")
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "fill 1010-1029: neighbour ledger(s) 1030 not in the archive", out
        )

    def test_verify_waits_for_writer(self):
        self.filled()
        res = {}
        with ha.archive_lock(self.dir):
            t = threading.Thread(target=lambda: res.update(r=self.verify()))
            t.start()
            t.join(0.5)
            self.assertTrue(t.is_alive(), "verify did not wait for the exclusive lock")
        t.join(10)
        self.assertEqual(res["r"][0], 0, res["r"][1])

    def test_seal_waits_for_writer(self):
        fd = os.open(os.path.join(self.dir, ".lock"), os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX)
        t = threading.Thread(target=lambda: run(["seal", "--dir", self.dir, "--all"]))
        t.start()
        t.join(0.5)
        alive = t.is_alive()
        os.close(fd)
        t.join(10)
        self.assertTrue(alive, "seal did not wait for the archive lock")


class TestGaps(FillBase):
    def setUp(self):
        super().setUp()
        self.make_gap()
        self.tf = os.path.join(self.tmp, "gaps.prom")

    def gaps(self, *extra):
        return run(["gaps", "--dir", self.dir, "--textfile", self.tf, *extra])

    def metric(self, name):
        for ln in rb(self.tf).decode().splitlines():
            if ln.startswith(name + "{"):
                return int(ln.split()[-1])
        raise AssertionError(name)

    def test_fillable_when_source_holds_range(self):
        self.node.oldest = 1000
        rc, out = self.gaps("--rpc", self.node.url)
        self.assertEqual(rc, 0, out)
        self.assertIn(
            "OPEN   1010-1029 (20) anchors ok source holds it -> FILLABLE", out
        )
        self.assertEqual(
            (
                self.metric("pft_histarchive_gap_open"),
                self.metric("pft_histarchive_gap_fillable"),
            ),
            (1, 1),
        )
        self.assertEqual(self.metric("pft_histarchive_gap_source_up"), 1)

    def test_not_fillable_when_source_pruned(self):
        rc, out = self.gaps("--rpc", self.node.url)
        self.assertEqual(rc, 0, out)
        self.assertIn("source lacks it -> not fillable", out)
        self.assertEqual(
            (
                self.metric("pft_histarchive_gap_open"),
                self.metric("pft_histarchive_gap_fillable"),
            ),
            (1, 0),
        )

    def test_not_fillable_without_source(self):
        rc, out = self.gaps()
        self.assertEqual(rc, 0, out)
        self.assertIn("source not asked -> not fillable", out)
        self.assertEqual(self.metric("pft_histarchive_gap_fillable"), 0)

    def test_source_down(self):
        rc, out = self.gaps("--rpc", "http://127.0.0.1:9/")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.metric("pft_histarchive_gap_source_up"), 0)
        self.assertEqual(self.metric("pft_histarchive_gap_fillable"), 0)

    def test_after_fill_no_rpc_call(self):
        self.node.oldest = 1000
        self.assertEqual(self.fill("--staged", self.stage())[0], 0)
        self.node.calls.clear()
        rc, out = self.gaps("--rpc", self.node.url)
        self.assertEqual(rc, 0, out)
        self.assertIn("FILLED 1010-1029 (20) by staged", out)
        self.assertIn("RESULT: gaps 1 open 0 filled 1 fillable 0", out)
        self.assertEqual(self.node.calls, [])
        self.assertEqual(
            (
                self.metric("pft_histarchive_gap_open"),
                self.metric("pft_histarchive_gap_fillable"),
            ),
            (0, 0),
        )
        self.assertEqual(self.metric("pft_histarchive_gap_source_up"), 1)


class TestWrapperFill(FillBase):
    """The shell wrapper: fill-gap + verify + gaps textfiles, then replicate / restore-verify with the fill."""

    def setUp(self):
        super().setUp()
        self.state = os.path.join(self.tmp, "local")
        self.peer = os.path.join(self.tmp, "peer")
        self.tfd = os.path.join(self.tmp, "textfile")
        for d in (self.state, self.peer, self.tfd):
            os.makedirs(d)
        self.dir = os.path.join(self.state, "archive")
        self.make_gap(seal=True)
        self.conf = os.path.join(self.tmp, "conf.env")
        wb(
            self.conf,
            (
                f'HOST_LABEL=validator\nPEER_SSH="env STATE_DIR={self.peer} TEXTFILE_DIR={self.tmp}/none"\n'
                f"FILL_RPC={self.node.url}\n"
            ).encode(),
        )

    def sh(self, *args):
        e = dict(
            os.environ,
            STATE_DIR=self.state,
            TEXTFILE_DIR=self.tfd,
            PFT_HISTARCHIVE_CONF=self.conf,
            PFT_HISTARCHIVE_REMOTE=f"bash {SH}",
        )
        p = subprocess.run(
            ["bash", SH, *args],
            env=e,
            capture_output=True,
            check=False,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
        return p.returncode, (p.stdout + p.stderr).decode()

    def prom(self, name):
        return rb(os.path.join(self.tfd, f"{name}.prom")).decode()

    def test_fill_replicate_restore(self):
        self.node.oldest = 1000
        rc, out = self.sh("gaps")
        self.assertEqual(rc, 0, out)
        self.assertIn(
            'pft_histarchive_gap_fillable{host="validator"} 1',
            self.prom("pft_histarchive_gaps"),
        )
        self.assertEqual(self.sh("keygen")[0], 0)
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        rc, out = self.sh("fill-gap", GAP, "--staged", self.stage())
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULT: PASS - fill-gap 1010-1029, verify rc 0", out)
        self.assertIn("gaps 0 (0 ledgers) filled 1 fails 0", out)
        self.assertIn(
            'pft_histarchive_gaps{host="validator"} 0', self.prom("pft_histarchive")
        )
        self.assertIn(
            'pft_histarchive_gaps_filled{host="validator"} 1',
            self.prom("pft_histarchive"),
        )
        self.assertIn(
            'pft_histarchive_gap_fillable{host="validator"} 0',
            self.prom("pft_histarchive_gaps"),
        )
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        self.assertIn("outbox: 1 new segment(s) encrypted", out)
        self.assertIn("sent fill-1010-1029.jsonl.gz.age", out)
        self.assertIn("RESULT: PASS - replicate fails 0", out)
        rc, out = self.sh("restore-verify")
        self.assertEqual(rc, 0, out)
        self.assertIn("SAME fill-1010-1029 ledgers 1010-1029", out)
        self.assertIn("gaps 0 (0 ledgers) filled 1 fails 0", out)
        self.assertIn("RESULT: PASS - restore-verify fails 0", out)
        self.assertNotIn(
            "not yet in gapfills.jsonl", out
        )  # the replica's metadata carries gapfills.jsonl
        tars = [
            f
            for f in os.listdir(os.path.join(self.state, "outbox"))
            if f.startswith("meta-")
        ]
        self.assertEqual(len(tars), 1)

    def test_fill_in_active_day_replicate_restore(self):
        # the live shape: nothing sealed after the gap, so the restored (sealed-only) copy lacks the neighbours
        shutil.rmtree(self.dir)
        self.make_gap(seal=False)
        self.assertEqual(self.sh("keygen")[0], 0)
        rc, out = self.sh("fill-gap", GAP, "--staged", self.stage())
        self.assertEqual(rc, 0, out)
        rc, out = self.sh("replicate")
        self.assertEqual(rc, 0, out)
        self.assertIn("sent fill-1010-1029.jsonl.gz.age", out)
        rc, out = self.sh("restore-verify")
        self.assertEqual(rc, 0, out)
        self.assertIn("fill 1010-1029 checked on its own chain", out)
        self.assertIn("SAME fill-1010-1029 ledgers 1010-1029", out)
        self.assertIn("RESULT: PASS - restore-verify fails 0", out)

    def test_periodic_writes_gaps_textfile(self):
        self.node.oldest = 1000
        rc, out = self.sh("periodic")
        self.assertEqual(rc, 0, out)
        self.assertIn(
            'pft_histarchive_gap_fillable{host="validator"} 1',
            self.prom("pft_histarchive_gaps"),
        )
        self.assertIn(
            'pft_histarchive_gap_open{host="validator"} 1',
            self.prom("pft_histarchive_gaps"),
        )

    def test_wrapper_refusal_and_usage(self):
        rc, out = self.sh("fill-gap", GAP, "--staged", self.stage(1009, 1020))
        self.assertEqual(rc, 1, out)
        self.assertIn("RESULT: REFUSED - fill-gap rc 1 (nothing written)", out)
        rc, out = self.sh("fill-gap", "1010-x", "--staged", "y")
        self.assertEqual(rc, 3, out)
        rc, out = self.sh("fill-gap", GAP, "--staged", self.stage(), "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULT: DRY RUN PASS", out)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "gapfills.jsonl")))

    def test_receive_accepts_fill_names_only(self):
        for name, ok in (
            ("fill-1010-1029.jsonl.gz.age", True),
            ("fill-1010-1029.jsonl.gz.age.x", False),
            ("fill-../x.jsonl.gz.age", False),
            ("fill-1010.jsonl.gz.age", False),
        ):
            p = subprocess.run(
                ["bash", SH, "serve", "receive", name],
                input=b"x",
                capture_output=True,
                check=False,
                env=dict(
                    os.environ,
                    STATE_DIR=self.peer,
                    PFT_HISTARCHIVE_CONF=self.conf,
                    TEXTFILE_DIR=self.tfd,
                ),
                timeout=30,
            )
            self.assertEqual(p.returncode == 0, ok, (name, p.stderr))


if __name__ == "__main__":
    unittest.main()


class TestSeqcheck(FillBase):
    """tests/seqcheck.py, the independent checker: a PASS and a control that must FAIL for each check."""

    SEQ = os.path.join(HERE, "seqcheck.py")

    def seq(self):
        p = subprocess.run(
            [sys.executable, "-I", self.SEQ, self.dir],
            capture_output=True,
            check=False,
            timeout=60,
        )
        return p.returncode, (p.stdout + p.stderr).decode()

    def test_open_gap_pass_and_missing_without_gap_fails(self):
        self.make_gap()
        rc, out = self.seq()
        self.assertEqual(rc, 0, out)
        self.assertIn("missing 20 open-gap ledgers 20 filled gaps 0", out)
        os.unlink(ha.Archive(self.dir).gaps)
        rc, out = self.seq()
        self.assertEqual(rc, 1, out)
        self.assertIn(
            "FAIL ledger 1010: missing and not inside an open recorded gap", out
        )

    def test_filled_pass_and_controls(self):
        self.make_gap()
        self.assertEqual(self.fill("--staged", self.stage())[0], 0)
        rc, out = self.seq()
        self.assertEqual(rc, 0, out)
        self.assertIn("ledgers 60 (1000-1059)", out)
        self.assertIn("parent links 59 missing 0 open-gap ledgers 0 filled gaps 1", out)

        def forged(recs):
            r = recs[5]
            d = bytearray.fromhex(r["d"])
            d[100] ^= 1
            r["d"] = d.hex().upper()
            r["h"] = hv.sha512half(hv.PREFIX_LEDGER, bytes(d)).hex().upper()
            return recs

        self.rewrite_segment("fill-1010-1029", forged)
        rc, out = self.seq()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL ledger 1016: parent hash != hash of 1015", out)

    def test_hash_and_duplicate_controls(self):
        self.make_gap()
        self.assertEqual(self.fill("--staged", self.stage())[0], 0)
        ar = ha.Archive(self.dir)
        day = ar.active_days()[0]
        lines = rb(ar.active_path(day)).split(b"\n")
        first = json.loads(lines[0])
        first["h"] = "00" * 32
        wb(ar.active_path(day), lines[1] + b"\n", "ab")  # duplicate of ledger 1001
        wb(ar.active_path(day), (ha.canon(first) + "\n").encode(), "ab")
        rc, out = self.seq()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL ledger 1001: appears twice", out)
        self.assertIn("FAIL ledger 1000: header hash mismatch", out)

    def test_in_flight_line_ignored(self):
        self.make_gap()
        ar = ha.Archive(self.dir)
        wb(ar.active_path(ar.active_days()[0]), b'{"i": 1060, "h": "AB', "ab")
        rc, out = self.seq()
        self.assertEqual(rc, 0, out)
        self.assertIn("in-flight last line ignored (20 bytes)", out)
