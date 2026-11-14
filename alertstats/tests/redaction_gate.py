#!/usr/bin/env python3
"""Refuse to publish: exit 1 if any file under DIR (plain or .gz) holds a public IPv4 address or an ntfy topic
(alertstats_build.redact would change it), a home path, or a name listed in PFT_RED_NAMES (comma-separated: user,
host names; never printed). Prints one line per offending file with the kind of hit only.
Usage: PFT_RED_NAMES=user,host python3 -I alertstats/tests/redaction_gate.py DIR
"""

import gzip
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import alertstats_build as ab


def main(argv):
    if len(argv) != 2 or not Path(argv[1]).is_dir():
        print("usage: redaction_gate.py DIR", file=sys.stderr)
        return 3
    names = [n for n in os.environ.get("PFT_RED_NAMES", "").split(",") if len(n) >= 3]
    bad = 0
    files = sorted(p for p in Path(argv[1]).rglob("*") if p.is_file())
    for p in files:
        raw = p.read_bytes()
        text = (gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw).decode("utf-8", "replace")
        hits = []
        if ab.redact(text) != text:
            hits.append("public-ip-or-topic")
        if "/home/" in text:
            hits.append("home-path")
        if any(n in text for n in names):
            hits.append("user-or-host-name")
        if hits:
            bad += 1
            print(f"REFUSE {p.name}: {', '.join(hits)}")
    print(f"redaction gate: {len(files)} file(s), {bad} refused, {len(names)} name(s) checked")
    return 1 if bad or not files else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
