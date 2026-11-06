#!/usr/bin/env python3
"""Mutants for ntfy_bridge.py: each changes one exact text match in a temp copy and runs test_ntfy_bridge.py there.

CAUGHT = the suite fails; SURVIVED / NOT APPLIED (old text not found exactly once) fail the harness (exit 1).
Usage: python3 -u alerts/mutate_bridge.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("ntfy_bridge.py", "test_ntfy_bridge.py")
MUTANTS = [
    (
        "B01",
        "dedup off: repeats forwarded",
        "            if prev == st:\n                continue\n",
        "",
    ),
    (
        "B02",
        "dedup keyed on status only",
        "            fp = fingerprint(a)\n",
        "            fp = st\n",
    ),
    ("B03", "transition not remembered", "            self.sent[fp] = (st, now)\n", ""),
    (
        "B04",
        "no folding: key per alert",
        '        key = (a.get("status", "?"), lb.get("alertname", "?"))',
        '        key = (a.get("status", "?"), lb.get("alertname", "?"), fingerprint(a))',
    ),
    (
        "B05",
        "folded title without count",
        "        if len(items) > 1:\n",
        "        if False:\n",
    ),
    ("B06", "body not capped", "lines[:MAX_LINES]", "lines"),
    (
        "B07",
        "resolved not low priority",
        'prio = "low" if st == "resolved" else',
        'prio = "default" if st == "resolved" else',
    ),
    ("B08", "critical not high", '("high" if crit else "default")', '"default"'),
    (
        "B09",
        "forgetting drops firing alerts too",
        'if st == "resolved" and now - t > FORGET_S:',
        "if now - t > FORGET_S:",
    ),
    (
        "B10",
        "duplicate summaries listed twice",
        "            if s not in lines:\n",
        "            if True:\n",
    ),
    (
        "B11",
        "forward the whole webhook, not the changes",
        "messages(new)",
        "messages(alerts)",
    ),
]


def main():
    with open(os.path.join(HERE, "ntfy_bridge.py")) as f:
        src = f.read()
    bad = 0
    with tempfile.TemporaryDirectory() as d:
        for f in FILES:
            shutil.copy(os.path.join(HERE, f), d)
        ctl = subprocess.run(
            [sys.executable, "-m", "unittest", "test_ntfy_bridge"],
            cwd=d,
            capture_output=True,
            text=True,
            check=False,
        )
        print(f"control (unmutated): {'PASS' if ctl.returncode == 0 else 'FAIL'}")
        if ctl.returncode != 0:
            print(ctl.stderr[-2000:])
            return 1
        for mid, desc, old, new in MUTANTS:
            if src.count(old) != 1:
                print(f"{mid} NOT APPLIED  {desc}")
                bad += 1
                continue
            with open(os.path.join(d, "ntfy_bridge.py"), "w") as f:
                f.write(src.replace(old, new))
            r = subprocess.run(
                [sys.executable, "-m", "unittest", "test_ntfy_bridge"],
                cwd=d,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            st = (
                "CAUGHT"
                if r.returncode != 0 and ("FAIL" in r.stderr or "Error" in r.stderr)
                else "SURVIVED"
            )
            bad += st != "CAUGHT"
            print(f"{mid} {st:8} {desc}")
    print(
        f"RESULT: {len(MUTANTS) - bad}/{len(MUTANTS)} CAUGHT -> {'PASS' if bad == 0 else 'FAIL'}"
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
