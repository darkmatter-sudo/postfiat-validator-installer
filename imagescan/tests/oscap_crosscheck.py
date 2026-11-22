#!/usr/bin/env python3
"""Cross-check imagescan_lib's OCI OVAL evaluator against OpenSCAP on the SAME feed and the SAME manifest.

Usage: oscap_crosscheck.py FEED.oval.xml.bz2 MANIFEST [--show-ids]

The Canonical OCI feeds test a file named "manifest" ("<package>[:arch] <version>" lines) in the working directory,
so `oscap oval eval` run in a directory holding only that file evaluates exactly what imagescan evaluates.
Prints per-result counts and the number of definitions where the two disagree; IDs only with --show-ids (the
true definitions of a live host or image are open findings and stay out of public logs). Exit 0 = full agreement.
"""
import bz2
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import imagescan_lib as L

R = "{http://oval.mitre.org/XMLSchema/oval-results-5}"


def main():
    feed, manifest = sys.argv[1], sys.argv[2]
    show = "--show-ids" in sys.argv[3:]
    lines = [x for x in open(manifest).read().splitlines() if x.strip()]
    mine = {f["id"] for f in L.eval_ubuntu(L.load_ubuntu_oval(feed), lines)}
    oval = L.load_ubuntu_oval(feed)
    usn_of = {d["id"]: d["usn"] for d in oval["defs"]}
    with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as d:
        shutil.copy(manifest, os.path.join(d, "manifest"))
        with bz2.open(feed) as s, open(os.path.join(d, "feed.xml"), "wb") as o:
            shutil.copyfileobj(s, o)
        r = subprocess.run(["oscap", "oval", "eval", "--results", "results.xml", "feed.xml"], cwd=d,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("oscap failed:", r.stderr[:300])
            return 2
        res = {}
        for _, el in ET.iterparse(os.path.join(d, "results.xml")):
            if el.tag == R + "definition":
                res[el.get("definition_id")] = el.get("result")
                el.clear()
    counts = {}
    for v in res.values():
        counts[v] = counts.get(v, 0) + 1
    theirs = {usn_of[k] for k, v in res.items() if v == "true"}
    bad = sorted(mine ^ theirs)
    print(f"manifest lines {len(lines)}; definitions {len(usn_of)}; oscap results "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"oscap true {len(theirs)}; imagescan affected {len(mine)}; disagreements {len(bad)}")
    if show:
        print("true:", " ".join(sorted(theirs)))
    if bad:
        print("DISAGREE:", " ".join(bad) if show else "(ids withheld; rerun with --show-ids)")
    unk = sum(v for k, v in counts.items() if k not in ("true", "false"))
    return 1 if bad or unk else 0


if __name__ == "__main__":
    sys.exit(main())
