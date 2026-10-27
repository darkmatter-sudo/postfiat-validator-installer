#!/usr/bin/env python3
"""Mutation control for test_report.py: each mutant puts one plausible bug into a temp copy of report.py and the
suite must FAIL on it (CAUGHT). Exit 0 only if every mutant applies cleanly and is caught.
  python3 resources/report/mutate_report.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

MUTANTS = (
    ("R1 percentile floor instead of nearest rank",
     "k = max(1, math.ceil(p / 100.0 * len(v)))", "k = max(1, int(p / 100.0 * len(v)))"),
    ("R2 gap does not reset the for: timer",
     "if prev is not None and s[\"ts\"] - prev[\"ts\"] > max_gap:\n            start, firing = None, False",
     "if False:\n            start, firing = None, False"),
    ("R3 restart (container id change) does not split segments",
     " or s[\"id\"] != cur[-1][\"id\"])", ")"),
    ("R4 unparsed lines dropped silently", "bad.append((no, str(e)))", "pass"),
    ("R5 growth rule loses the >50%-of-max guard",
     "and s[\"mem_current\"] / s[\"mem_max\"] > 0.5", "and True"),
    ("R6 ratio verdict ignores the 20-point headroom", "ok = s[\"max\"] <= default_pct - 20", "ok = s[\"max\"] <= default_pct"),
    ("R7 for: compare uses > (fires one sample late)", "elif s[\"ts\"] - start >= hold:", "elif s[\"ts\"] - start > hold:"),
    ("R8 non-numeric field accepted", "if k not in (\"container\", \"id\") and not isinstance", "if False and not isinstance"),
    ("R9 expected count from samples instead of window", "expected = int(round((t1 - t0) / interval))",
     "expected = len(samples)"),
    ("R10 PSI verdict compares p95 instead of max", "ok = s[\"max\"] * 2 <= default", "ok = s[\"p95\"] * 2 <= default"),
    ("R11 extra runs count as coverage", "min(on_schedule, expected)", "min(len(samples), expected)"),
)


def main():
    src = open(os.path.join(HERE, "report.py"), encoding="utf-8").read()
    caught = 0
    for name, old, new in MUTANTS:
        if src.count(old) != 1:
            print("MUTANT %s: pattern found %d times -> NOT APPLIED" % (name, src.count(old)))
            continue
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "report.py"), "w", encoding="utf-8") as f:
                f.write(src.replace(old, new))
            shutil.copy(os.path.join(HERE, "test_report.py"), d)
            p = subprocess.run([sys.executable, os.path.join(d, "test_report.py")], capture_output=True, text=True,
                               cwd=d)
        failed = [ln for ln in p.stderr.splitlines() if ln.startswith(("FAIL:", "ERROR:"))]
        ok = p.returncode != 0 and failed
        caught += bool(ok)
        print("MUTANT %s: %s (%s)" % (name, "CAUGHT" if ok else "SURVIVED", "; ".join(failed) or "suite passed"))
    print("RESULT: %d/%d mutants caught" % (caught, len(MUTANTS)))
    return 0 if caught == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
