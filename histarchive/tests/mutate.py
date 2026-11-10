#!/usr/bin/env python3
"""Mutation harness for histarchive (stdlib only).

Each mutant replaces ONE exact text (must occur exactly once) in a private copy of the histarchive/ folder
(script, helper, vendored lib and tests side by side, so every relative lookup resolves inside the copy),
then runs the test modules named for it. Rules:
  - the UNMUTATED copy must pass first (baseline), from the same kind of location as the mutants;
  - a mutant is CAUGHT only if the suite ran (an "Ran N tests" line) and reported >= 1 FAIL/ERROR test;
    a crash before any test ran is BROKEN (a harness problem, not coverage);
  - a mutant whose text is not found exactly once is NOT APPLIED (harness failure, fix the table);
  - every suite runs in its own session with stdin from /dev/null and is killed as a process group on timeout
    (a hang counts as CAUGHT and is labelled TIMEOUT).
Exit 0 only if baseline passed and every mutant was CAUGHT.
Run (from histarchive/): nice -n 15 python3 tests/mutate.py [--jobs 3] [--only M01,S03]
"""

import argparse
import concurrent.futures
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY, SH = "histarchive.py", "pft-histarchive.sh"
UNIT, WRAP = "tests/test_histarchive.py", "tests/test_wrapper.py"
TIMEOUT = 300

MUTANTS = [
    # id, file, old text, new text, suites, what the mutant breaks
    (
        "M01",
        PY,
        'if got != str(rec.get("h", "")).upper():',
        "if False:",
        [UNIT],
        "ledger hash check skipped",
    ),
    (
        "M02",
        PY,
        'if root != hdr["transaction_hash"]:',
        "if False:",
        [UNIT],
        "tx-tree root check skipped",
    ),
    (
        "M03",
        PY,
        'if hdr["ledger_index"] != rec.get("i"):',
        "if False:",
        [UNIT],
        "header index check skipped",
    ),
    (
        "M04",
        PY,
        'elif hdr is not None and hdr["parent_hash"] != prev[1]:',
        "elif False:",
        [UNIT],
        "verify: broken parent link not reported",
    ),
    (
        "M05",
        PY,
        "if not any(a <= gap[0] and gap[1] <= b for a, b in gaps):",
        "if False:",
        [UNIT],
        "verify: missing ledgers accepted without a gaps.jsonl entry",
    ),
    (
        "M06",
        PY,
        "if i <= prev[0]:",
        "if i < prev[0]:",
        [UNIT],
        "verify: duplicate ledger accepted",
    ),
    (
        "M07",
        PY,
        'if hashlib.sha256(gz).hexdigest() != e["sha256_gz"]:',
        "if False:",
        [UNIT],
        "verify: segment file sha256 not compared",
    ),
    (
        "M08",
        PY,
        'if hashlib.sha256(raw).hexdigest() != e["sha256_raw"]:',
        "if False:",
        [UNIT],
        "verify: segment content sha256 not compared",
    ),
    (
        "M09",
        PY,
        'if e.get("entry") != entry_hash(e):',
        "if False:",
        [UNIT],
        "MANIFEST entry hash not checked",
    ),
    (
        "M10",
        PY,
        'if e.get("prev_entry") != (prev_entry["entry"] if prev_entry else None):',
        "if False:",
        [UNIT],
        "MANIFEST chain link not checked",
    ),
    (
        "M11",
        PY,
        'if f"segments/{f}" not in listed and f.endswith(".jsonl.gz"):',
        "if False:",
        [UNIT],
        "unlisted segment accepted",
    ),
    (
        "M12",
        PY,
        'if recs[-1].get("h") != e["last_hash"]:',
        "if False:",
        [UNIT],
        "MANIFEST last_hash not compared",
    ),
    (
        "M13",
        PY,
        'and hdr["parent_hash"] != e["first_parent"]',
        "and False",
        [UNIT],
        "MANIFEST first_parent not compared",
    ),
    (
        "M14",
        PY,
        'if raw and not raw.endswith(b"\\n"):',
        "if False:",
        [UNIT],
        "verify: torn last line accepted",
    ),
    (
        "M15",
        PY,
        "                keep = start\n",
        "                pass\n",
        [UNIT],
        "resume: torn line that ends in a newline is kept",
    ),
    (
        "M16",
        PY,
        'nxt = last + 1 if last is not None else state["start_seq"]',
        'nxt = last if last is not None else state["start_seq"]',
        [UNIT],
        "resume re-fetches the last ledger (duplicate)",
    ),
    (
        "M17",
        PY,
        "and prev_hash is not None\n",
        "and False\n",
        [UNIT],
        "ingest: parent chain not checked",
    ),
    (
        "M18",
        PY,
        'append_line(ar.gaps, canon({"from": a, "to": b, "reason": reason, "at": utcnow()}))',
        "pass",
        [UNIT],
        "gap ranges never recorded",
    ),
    (
        "M19",
        PY,
        "            if os.path.exists(src):\n",
        "            if False:\n",
        [UNIT],
        "resume: half-finished seal leaves the active copy",
    ),
    (
        "M20",
        PY,
        'same = ans["h"] == r["h"] and ans["ids"] == mine_ids',
        'same = ans["h"] == r["h"]',
        [UNIT],
        "crosscheck ignores tx ID differences",
    ),
    (
        "M21",
        PY,
        "elif sha256_file(p) != sha:",
        "elif False:",
        [UNIT, WRAP],
        "replica-check ignores altered files",
    ),
    (
        "M22",
        PY,
        'for name in sorted(have - set(want["files"])):',
        "for name in []:",
        [UNIT],
        "replica-check ignores extra files",
    ),
    (
        "M23",
        PY,
        "elif cipher[name] != sha:",
        "elif False:",
        [WRAP],
        "replica-compare ignores a peer sha256 mismatch",
    ),
    (
        "M24",
        PY,
        'if rep.get("head_entry") != want.get("head_entry"):',
        "if False:",
        [WRAP],
        "replica-compare ignores a stale peer index",
    ),
    (
        "M25",
        PY,
        'if got.get("check_rc") != 0:',
        "if False:",
        [WRAP],
        "replica-compare ignores the peer's own check",
    ),
    (
        "M26",
        PY,
        'ans = dict(ans, ids=ans["ids"] + ["NEG"])',
        "ans = dict(ans)",
        [UNIT],
        "negative crosscheck leaves tx IDs unaltered on odd picks",
    ),
    (
        "M27",
        PY,
        'ans = dict(ans, h=ans["h"][:-1] + ("0" if ans["h"][-1] != "0" else "1"))',
        "ans = dict(ans)",
        [UNIT],
        "negative crosscheck leaves the hash unaltered on even picks",
    ),
    (
        "S11",
        SH,
        '0 files)"; replica_prom 1; return 0',
        '0 files)"; return 0',
        [WRAP],
        "nothing sealed: no replica textfile (rulecheck would read MISSING)",
    ),
    (
        "S01",
        SH,
        '!= "$sha" ]; then',
        '= "never" ]; then',
        [WRAP],
        "restore: fetched copy sha256 not compared",
    ),
    (
        "S02",
        SH,
        '    esac || { echo "  FAIL $name: does not decrypt with this host\'s identity"; fails=$((fails + 1)); }',
        "    esac || true",
        [WRAP],
        "restore: decryption failure ignored",
    ),
    (
        "S03",
        SH,
        """[ "$name" = REPLICA.json ] || [[ "$name" =~ $NAME_RE ]] || die "receive: refusing name '$name'\"""",
        "true",
        [WRAP],
        "receive accepts any file name",
    ),
    (
        "S04",
        SH,
        """{ [ "$1" = REPLICA.json ] || [[ "$1" =~ $NAME_RE ]]; } || die "export: refusing name '$1'\"""",
        "true",
        [WRAP],
        "export serves any path",
    ),
    (
        "S05",
        SH,
        'if [ "$rc" = 1 ]; then echo "replicate skipped',
        'if false; then echo "replicate skipped',
        [WRAP],
        "periodic replicates an archive that failed verify",
    ),
    (
        "S06",
        SH,
        '[ -e "$IDF" ] && die',
        "false && die",
        [WRAP],
        "keygen replaces an existing identity",
    ),
    (
        "S07",
        SH,
        "sys.exit(1 if bad or not in_local else 0)",
        "sys.exit(0)",
        [WRAP],
        "restore: restored-vs-local differences ignored",
    ),
    (
        "S08",
        SH,
        '        os.unlink(os.path.join(sys.argv[1], f))\' "$REPLICA"',
        '        pass\' "$REPLICA"',
        [WRAP],
        "peer keeps every old metadata generation",
    ),
    (
        "S09",
        SH,
        '[ -f "$OUTBOX/$day.jsonl.gz.age" ] && continue',
        "true",
        [WRAP],
        "every replicate re-encrypts and re-sends every segment",
    ),
    (
        "S10",
        SH,
        'replica-compare --local "$OUTBOX/REPLICA.json" <<<"$idx" || ok=1',
        'replica-compare --local "$OUTBOX/REPLICA.json" <<<"$idx" || true',
        [WRAP],
        "replica mismatch reported as ok (rc and textfile)",
    ),
]


def copy_tree(dst):
    shutil.copytree(
        ROOT,
        dst,
        ignore=shutil.ignore_patterns(
            "logs", "__pycache__", ".ruff_cache", "*.pyc", "drill"
        ),
    )
    os.chmod(dst, 0o755)


def run_suites(d, suites, scratch):
    env = dict(os.environ, TMPDIR=scratch, TEST_TMPDIR=scratch)
    p = subprocess.Popen(
        [sys.executable, "-m", "unittest", *suites],
        cwd=d,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        out, _ = p.communicate(timeout=TIMEOUT)
        return p.returncode, out.decode(errors="replace"), False
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return -9, out.decode(errors="replace"), True


def failed_tests(out):
    return re.findall(r"^(?:FAIL|ERROR): (\w+)", out, re.MULTILINE)


def one(m, base):
    mid, fname, old, new, suites, desc = m
    work = tempfile.mkdtemp(prefix=f"pft-ha-mut-{mid}-", dir=base)
    try:
        d = os.path.join(work, "histarchive")
        copy_tree(d)
        scratch = os.path.join(work, "scratch")
        os.makedirs(scratch)
        if fname is not None:
            p = os.path.join(d, fname)
            with open(p) as fh:
                src = fh.read()
            if src.count(old) != 1:
                return mid, "NOT APPLIED", f"text found {src.count(old)} times", desc
            with open(p, "w") as fh:
                fh.write(src.replace(old, new))
        t0 = time.monotonic()
        rc, out, hung = run_suites(d, suites, scratch)
        el = time.monotonic() - t0
        ran = re.search(r"^Ran (\d+) tests?", out, re.MULTILINE)
        fails = failed_tests(out)
        if fname is None:
            ok = rc == 0 and ran and not fails
            return (
                mid,
                "PASS" if ok else "BASELINE FAIL",
                f"rc {rc}, {ran.group(0) if ran else 'no Ran line'}, {el:.0f}s",
                desc,
            )
        if hung:
            return mid, "CAUGHT", f"TIMEOUT after {TIMEOUT}s", desc
        if not ran:
            return (
                mid,
                "BROKEN",
                f"rc {rc}, suite did not run: {out.strip().splitlines()[-1:]}",
                desc,
            )
        if fails:
            return (
                mid,
                "CAUGHT",
                f"{len(fails)} failing: {', '.join(sorted(set(fails))[:4])}",
                desc,
            )
        return mid, "SURVIVED", f"rc {rc}, {ran.group(0)}, 0 failing", desc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--only", default=None)
    a = ap.parse_args()
    base = tempfile.mkdtemp(
        prefix="pft-ha-mutate-", dir=os.path.join(os.path.expanduser("~"), ".cache")
    )
    os.chmod(base, 0o755)
    try:
        print(
            f"histarchive mutation harness - {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
        )
        print(
            f"mutants: {len(MUTANTS)}, jobs {a.jobs}, per-suite timeout {TIMEOUT}s",
            flush=True,
        )
        _mid, verdict, why, _ = one(
            ("BASE", None, None, None, [UNIT, WRAP], "unmutated"), base
        )
        print(f"BASELINE {verdict} ({why})", flush=True)
        if verdict != "PASS":
            print("RESULT: FAIL - baseline does not pass; no mutant counted")
            return 1
        todo = [m for m in MUTANTS if not a.only or m[0] in a.only.split(",")]
        res = []
        with concurrent.futures.ThreadPoolExecutor(a.jobs) as ex:
            for r in ex.map(lambda m: one(m, base), todo):
                res.append(r)
                print(f"{r[0]} {r[1]:<11} {r[3]} [{r[2]}]", flush=True)
        caught = sum(r[1] == "CAUGHT" for r in res)
        bad = [r[0] for r in res if r[1] != "CAUGHT"]
        print(
            f"RESULT: {'PASS' if not bad else 'FAIL'} - {caught}/{len(res)} caught; not caught: {', '.join(bad) or 'none'}"
        )
        return 0 if not bad else 1
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
