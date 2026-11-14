#!/usr/bin/env python3
"""Offline re-derivation of the live gap repair of 8042619-8042680 from the committed capture.

Replays the 64 real `ledger` answers of logs/data/gap-8042619-8042680/ through a local stub
JSON-RPC node (tests/test_histarchive.FakeNode, no network): the follower archives 8042618, the
stub then "prunes" to 8042681 so the follower records the gap 8042619-8042680 exactly as the live
reboot did, and `fill-gap --staged` repairs it from the same capture file the live run used.
Prints verify before/after, seqcheck, and the fill segment sha256, which must equal the live
MANIFEST fill entry (logs/22-fill-live-resumed.log). Exit 0 only if every check holds.

Usage (from a checkout, with TMPDIR on an exec mount):
  python3 histarchive/drill/repro-real-gap.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HA = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HA, "tests"))
sys.path.insert(0, HA)
import histarchive as ha
from test_histarchive import FakeNode, run

GAP = "8042619-8042680"
CAPTURE = os.path.join(
    HA, "logs/data/gap-8042619-8042680/capture-8042618-8042681.jsonl"
)
CAPTURE_SHA = "3de3e996f83db302ca62b95eac33e0ac2ccb8f1a63463c5ebaf05bab38b96c0f"
LIVE_FILL_SHA = "e2c5dcfdd6ae159566b84e472d0b683ce46dadcec7234ad44d17a5eb60da6ea6"

fails = 0


def check(ok, what):
    global fails
    print(f"CHECK {'ok  ' if ok else 'FAIL'} {what}")
    fails += 0 if ok else 1


def step(name, rc_out):
    rc, out = rc_out
    print(f"$ histarchive.py {name}")
    print(out.rstrip())
    print(f"(exit {rc})")
    return rc, out


def main():
    with open(CAPTURE, "rb") as fh:
        raw = fh.read()
    check(
        hashlib.sha256(raw).hexdigest() == CAPTURE_SHA, f"capture sha256 {CAPTURE_SHA}"
    )
    chain = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        ans = json.loads(line)["result"]
        chain[int(ans["ledger_index"])] = ans
    check(
        sorted(chain) == list(range(8042618, 8042682)),
        f"capture holds 8042618-8042681 ({len(chain)} ledgers)",
    )

    tmp = tempfile.mkdtemp(prefix="pft-ha-repro-", dir=os.environ.get("TMPDIR") or None)
    arch = os.path.join(tmp, "arch")
    node = FakeNode(chain)
    ha.RATE_CAP = 1e6
    common = [
        "--dir",
        arch,
        "--rpc",
        node.url,
        "--rate",
        "1000",
        "--poll",
        "0.01",
        "--retry-sleep",
        "0",
        "--retries",
        "2",
    ]
    try:
        node.oldest = node.validated = 8042618
        step(
            "follow --start 8042618 --stop-at 8042618",
            run(["follow", *common, "--start", "8042618", "--stop-at", "8042618"]),
        )
        node.oldest, node.validated = 8042681, 8042681
        rc, out = step(
            "follow --stop-at 8042681 (stub pruned to 8042681)",
            run(["follow", *common, "--stop-at", "8042681"]),
        )
        check(
            f"GAP ledgers {GAP} (62)" in out,
            "follower recorded the gap 8042619-8042680 (62)",
        )
        rc, out = step("verify", run(["verify", "--dir", arch]))
        check(
            rc == 0 and "gaps 1 (62 ledgers) filled 0" in out,
            "verify before: gaps 1 (62 ledgers) filled 0",
        )
        rc, out = step(
            f"fill-gap --gap {GAP} --staged capture --dry-run",
            run(
                [
                    "fill-gap",
                    "--dir",
                    arch,
                    "--gap",
                    GAP,
                    "--staged",
                    CAPTURE,
                    "--dry-run",
                ]
            ),
        )
        seg = os.path.join(arch, "segments", f"fill-{GAP}.jsonl.gz")
        check(rc == 0 and not os.path.exists(seg), "dry run exit 0, nothing written")
        rc, out = step(
            f"fill-gap --gap {GAP} --staged capture",
            run(["fill-gap", "--dir", arch, "--gap", GAP, "--staged", CAPTURE]),
        )
        check(rc == 0, "fill-gap exit 0")
        rc, out = step("verify", run(["verify", "--dir", arch]))
        check(
            rc == 0 and "filled 1" in out and "gaps 0" in out,
            "verify after: gaps 0, filled 1",
        )
        with open(seg, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        print(f"fill segment sha256 {got}")
        check(
            got == LIVE_FILL_SHA,
            f"fill segment byte-identical to the live fill (sha256 {LIVE_FILL_SHA})",
        )
        with open(os.path.join(arch, "MANIFEST.jsonl")) as fh:
            ent = json.loads(fh.read().splitlines()[-1])
        live = {
            "kind": "fill",
            "first": 8042619,
            "last": 8042680,
            "count": 62,
            "txs": 22,
            "anchor_below": {
                "h": "8278888DEFBCB472CBAEC4AF3B0B3BAD3B358BB1C9F199095CF9322E2922673D",
                "i": 8042618,
            },
            "anchor_above": {
                "h": "F35D4801640E85FB2C36A794953891AD7E2ED4C55E7DBC707438EDE8B2719DB1",
                "i": 8042681,
            },
            "sha256_gz": LIVE_FILL_SHA,
        }
        print(
            "MANIFEST fill entry",
            json.dumps({k: ent.get(k) for k in live}, sort_keys=True),
        )
        check(
            all(ent.get(k) == v for k, v in live.items()),
            "MANIFEST fill fields (range, count, txs, both anchors, sha256_gz) equal the live entry",
        )
        rc, out = step(
            f"fill-gap --gap {GAP} --staged capture (again)",
            run(["fill-gap", "--dir", arch, "--gap", GAP, "--staged", CAPTURE]),
        )
        check(rc != 0, "duplicate fill refused")
        p = subprocess.run(
            [sys.executable, "-I", os.path.join(HA, "tests/seqcheck.py"), arch],
            capture_output=True,
            text=True,
            check=False,
        )
        print("$ python3 -I tests/seqcheck.py ARCHIVE")
        print((p.stdout + p.stderr).rstrip())
        print(f"(exit {p.returncode})")
        check(p.returncode == 0, "independent seqcheck PASS over the filled copy")
    finally:
        node.close()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"RESULT {'PASS' if fails == 0 else 'FAIL'} {fails} failed")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
