#!/usr/bin/env python3
"""Mutation check for the pft-rulecheck test suite.

Each mutant is one exact text replacement in a temp copy of pft-rulecheck.sh or rulecheck_lib.py; the target text
must occur exactly once (else NOT APPLIED, which counts as a harness failure). tests/run-tests.sh then runs against
the mutated copies. A mutant is CAUGHT only if the suite printed its RESULT line with at least one FAIL line (an
aborted suite is not a catch). A control run on the unmodified copies must pass first.
  python3 -I tests/mutate.py          exit 0 = control passed and every mutant applied and was caught
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = {"sh": os.path.join(HERE, "..", "pft-rulecheck.sh"), "py": os.path.join(HERE, "..", "rulecheck_lib.py")}

MUTANTS = [
    ("M01", "py", "absent() context ignored: absent() arguments counted as live-required selectors",
     'elif prev and prev[0] == "ident" and prev[1].lower() in ABSENT_FUNCS:', "elif False:"),
    ("M02", "py", "by()/on()/without() label lists parsed as metric names",
     'pending_labels = nxt[1] == "("', "pending_labels = False"),
    ("M03", "py", "ALERTS/ALERTS_FOR_STATE not excluded (healthy-empty series reported dead)",
     "if s.absent or s.metric() in SYNTHETIC or s.metric() in conf.ignore_metrics:",
     "if s.absent or s.metric() in conf.ignore_metrics:"),
    ("M04", "py", "PARTIAL folded into DEAD (any dead selector = DEAD)",
     'elif len(row["dead"]) == len(counted):', 'elif row["dead"]:'),
    ("M05", "py", "Prometheus rule health 'err' ignored",
     'if r.get("health") == "err":', "if False:"),
    ("M06", "py", "content timestamp ignored (pulled copy judged by mtime only)",
     "worst = max(age, cage)", "worst = age"),
    ("M07", "py", "LEFTOVER temp files reported as FRESH",
     '"state": "LEFTOVER"', '"state": "FRESH"'),
    ("M08", "py", "required files never reported MISSING",
     "if n not in seen:", "if False:"),
    ("M09", "py", "check error reported as findings (exit 1 instead of 2)",
     "    if err:\n        rc = 2", "    if err:\n        rc = 1"),
    ("M10", "py", "selector cache off (every rule re-queries every selector)",
     "if t not in cache:", "if True:"),
    ("M11", "py", "last matching textfile line wins instead of the first",
     "rule = next((t for t in conf.textfiles if", "rule = next((t for t in reversed(conf.textfiles) if"),
    ("M12", "py", "ignore-rule not honoured",
     "if key in conf.ignore_rules:", "if False:"),
    ("M13", "py", "failed run still writes rule series (would read as 'all fine' / stale verdicts)",
     "None if err else rules, None if err else files, nsel", "rules, files, nsel"),
    ("M14", "py", "metric rule_dead only 1 for DEAD (PARTIAL/ERROR rules never alert)",
     'r["state"] in BAD_RULE))', 'r["state"] == "DEAD"))'),
    ("M15", "py", "symlinked .prom files followed",
     "if not os.path.isfile(p) or os.path.islink(p):", "if not os.path.isfile(p):"),
    ("M16", "py", "young in-flight temp files reported LEFTOVER",
     "if age > conf.leftover_age:", "if age >= 0:"),
    ("M17", "py", "duplicate selector within one rule counted twice",
     "if t in counted:\n                    continue", "if False:\n                    continue"),
    ("M18", "sh", "pull skips validation of the peer's file",
     'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then', "if false; then"),
    ("M19", "sh", "pull without timeout (a hanging ssh blocks the unit)",
     'if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat', "if ! $PULL_SSH cat"),
    ("M20", "sh", "unknown env keys accepted silently",
     '*) die "$ENVF: unknown key $k" ;;', "*) : ;;"),
    ("M21", "sh", "validate does not check the host label",
     "if (p[2] != h)", "if (0)"),
    ("M22", "sh", "check --lookback value not validated",
     '--lookback) [[ "${2:-}" =~ ^[1-9][0-9]*[smhd]$ ]] || die "bad --lookback"; LOOKBACK="$2"; shift ;;',
     '--lookback) LOOKBACK="$2"; shift ;;'),
]


def run_suite(sh, py):
    p = subprocess.run(["bash", os.path.join(HERE, "run-tests.sh"), sh, py], capture_output=True, text=True,
                       timeout=600)
    out = p.stdout + p.stderr
    fails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
    result = re.search(r"^RESULT: (\d+) passed, (\d+) failed$", out, re.M)
    return p.returncode, result, fails


def main():
    work = tempfile.mkdtemp(prefix="rc-mut.")
    try:
        orig = {k: open(v, encoding="utf-8").read() for k, v in SRC.items()}
        paths = {"sh": os.path.join(work, "pft-rulecheck.sh"), "py": os.path.join(work, "rulecheck_lib.py")}

        def write(k, text):
            with open(paths[k], "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(paths[k], 0o755)
        for k in orig:
            write(k, orig[k])
        rc, res, fails = run_suite(paths["sh"], paths["py"])
        ok = rc == 0 and res and res.group(2) == "0"
        print("CONTROL %s - unmodified copies: %s" % ("PASS" if ok else "FAIL", res.group(0) if res else "no RESULT"))
        if not ok:
            return 1
        caught = survived = napp = 0
        for mid, k, desc, old, new in MUTANTS:
            n = orig[k].count(old)
            if n != 1:
                napp += 1
                print("%s NOT APPLIED (%d matches) - %s: %s" % (mid, n, os.path.basename(SRC[k]), desc))
                continue
            write(k, orig[k].replace(old, new))
            rc, res, fails = run_suite(paths["sh"], paths["py"])
            write(k, orig[k])
            if res and fails and rc != 0:
                caught += 1
                print("%s CAUGHT - %s: %s :: %d failing, e.g. %s" % (mid, os.path.basename(SRC[k]), desc, len(fails),
                                                                     "; ".join(fails[:2])))
            else:
                survived += 1
                print("%s SURVIVED - %s: %s :: %s" % (mid, os.path.basename(SRC[k]), desc,
                                                       res.group(0) if res else "suite aborted, no RESULT"))
        print("MUTANTS %d: caught %d, survived %d, not applied %d" % (len(MUTANTS), caught, survived, napp))
        return 0 if caught == len(MUTANTS) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
