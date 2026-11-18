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
FILL = "tests/test_fillgap.py"
TIMEOUT = 600  # the baseline runs all three suites in one process (~285 s unloaded)

MUTANTS = [
    (
        "V01",
        PY,
        '"parent": self.parent[32 * k : 32 * k + 32].hex().upper() if hdr else None,',
        '"parent": None,',
        [UNIT],
        "verify columns: parent hash not stored (chain unchecked)",
    ),
    (
        "V02",
        PY,
        "        if not fits:\n",
        "        if False:\n",
        [UNIT],
        "verify columns: odd records squeezed into the columns (problems/odd values lost)",
    ),
    (
        "V03",
        PY,
        '            not r["probs"]\n            and ',
        "            ",
        [UNIT],
        "verify columns: a record with problems counted as compact (problems lost)",
    ),
    (
        "V04",
        PY,
        "            if b.index(k) > after:",
        "            if False:",
        [UNIT, FILL],
        "verify: fill appended at the end instead of spliced at its gap",
    ),
    (
        "V05",
        PY,
        "    for b, lo, hi in reversed(views):\n        for k in range(hi - 1, lo - 1, -1):",
        "    for b, lo, hi in views:\n        for k in range(lo, hi):",
        [UNIT],
        "verify: neighbour lookup takes the first duplicate, not the last (dict semantics)",
    ),
    (
        "V06",
        PY,
        "return b.get(hi - 1 if last else lo)",
        "return b.get(lo)",
        [UNIT],
        "verify: last record of the stream read as its first",
    ),
    (
        "V07",
        PY,
        'if r0["hdr"] and r0["parent"] != e["first_parent"]:',
        'if r0["hdr"] is not None and r0["parent"] != e["first_parent"]:',
        [UNIT],
        "verify: first_parent compared for a header-less first record (extra FAIL, 8cdf339 regression)",
    ),
    (
        "V08",
        PY,
        'elif hdr and r["parent"] != prev[1]:',
        'elif hdr is not None and r["parent"] != prev[1]:',
        [UNIT],
        "verify: parent link checked for a header-less ledger (extra FAIL, 8cdf339 regression)",
    ),
    (
        "F25",
        PY,
        '                    None not in rng\n                    and (e.get(side) or {}).get("h") != _view_lookup(base, i)[1]',
        "                    False",
        [FILL],
        "verify: MANIFEST anchor fields not compared with the archive",
    ),
    (
        "F26",
        PY,
        "        if include_active:\n",
        "        if False:\n",
        [FILL],
        "verify: fill without neighbours accepted in a full verify",
    ),
    (
        "F27",
        PY,
        'prev = (r0.get("i", 0) - 1, anchor) if r0 is not None and anchor else None',
        "prev = None",
        [FILL],
        "verify: standalone fill not chained to its recorded anchor",
    ),
    (
        "F01",
        PY,
        "if below is None:",
        "if False:",
        [FILL],
        "fill: missing lower anchor accepted",
    ),
    (
        "F02",
        PY,
        "if above is None:",
        "if False:",
        [FILL],
        "fill: missing upper anchor accepted",
    ),
    (
        "F03",
        PY,
        'if hdr is not None and prev_h is not None and hdr["parent_hash"] != prev_h:',
        "if False:",
        [FILL],
        "fill: parent chain through the fill not checked",
    ),
    (
        "F04",
        PY,
        'if up["parent_hash"] != recs[b].get("h"):',
        "if False:",
        [FILL],
        "fill: upper anchor link not checked",
    ),
    (
        "F05",
        PY,
        'probs += [f"ledger {i}: {x}" for x in p]',
        "probs += []",
        [FILL],
        "fill: per-ledger header/hash/txroot problems dropped",
    ),
    (
        "F06",
        PY,
        "    if missing:\n",
        "    if False:\n",
        [FILL],
        "fill: source missing ledgers accepted",
    ),
    (
        "F07",
        PY,
        "if i in recs and anc is not None and recs[i] != anc:",
        "if False:",
        [FILL],
        "fill: staged anchor copy not compared",
    ),
    (
        "F08",
        PY,
        "if old is not None and old != rec:",
        "if False:",
        [FILL],
        "fill: conflicting duplicate staged ledger accepted",
    ),
    (
        "F09",
        PY,
        "if (lo, hi) not in open_gaps(ar):",
        "if False:",
        [FILL],
        "fill: already-filled gap re-fetched from the source",
    ),
    (
        "F10",
        PY,
        '            e.get("kind") == "fill" and (e["first"], e["last"]) == (a, b)\n            for e in entries\n',
        "            False\n            for e in entries\n",
        [FILL],
        "fill: no re-check under the lock (double commit)",
    ),
    (
        "F11",
        PY,
        "if (lo, hi) not in gaps:",
        "if False:",
        [FILL],
        "fill: range that is not a recorded gap accepted",
    ),
    (
        "F12",
        PY,
        'if rng not in gaps or (g.get("from"), g.get("to")) != rng:',
        "if False:",
        [FILL],
        "verify: fill without a matching recorded gap accepted",
    ),
    (
        "F13",
        PY,
        "if rng in filled:",
        "if False:",
        [FILL],
        "verify: gap filled twice accepted",
    ),
    (
        "F14",
        PY,
        'if e.get("count") != (rng[1] - rng[0] + 1 if None not in rng else None):',
        "if False:",
        [FILL],
        "verify: short fill accepted",
    ),
    (
        "F15",
        PY,
        'if fe is None or (fe["first"], fe["last"]) != (lf_.get("from"), lf_.get("to")):',
        "if False:",
        [FILL],
        "verify: forged gapfills.jsonl claim accepted",
    ),
    (
        "F16",
        PY,
        "open_gaps = [g for g in gaps if g not in filled]",
        "open_gaps = gaps",
        [FILL],
        "verify: filled gap still excuses missing ledgers",
    ),
    (
        "F17",
        PY,
        "with archive_lock(a.dir, exclusive=False):",
        "with contextlib.nullcontext():",
        [FILL],
        "verify: reads without the shared lock",
    ),
    (
        "F18",
        PY,
        "    with archive_lock(ar.root):\n        return _seal_day(ar, day, lf)",
        "    if True:\n        return _seal_day(ar, day, lf)",
        [FILL],
        "seal: no archive lock",
    ),
    (
        "F19",
        PY,
        "with archive_lock(ar.root, timeout=lock_timeout):\n        entries = ar.manifest_entries()",
        "with contextlib.nullcontext():\n        entries = ar.manifest_entries()",
        [FILL],
        "fill: commit without the archive lock",
    ),
    (
        "F20",
        PY,
        'for p in (seg + ".tmp", seg):',
        "for p in ():",
        [FILL],
        "fill: leftover unlisted fill segment not removed on redo",
    ),
    (
        "F21",
        PY,
        '            if e["entry"] not in logged:\n                append_line(',
        "            if False:\n                append_line(",
        [FILL],
        "fill: missing gapfills.jsonl line never repaired",
    ),
    (
        "F22",
        PY,
        "if not any(x <= a and b <= y for x, y in spans):",
        "if False:",
        [FILL],
        "fill: source range not checked before fetching",
    ),
    (
        "F23",
        PY,
        "fillable=bool(below and above and held),",
        "fillable=bool(below and above),",
        [FILL],
        "gaps: fillable ignores whether the source holds the range",
    ),
    (
        "F24",
        PY,
        "    if a.rpc and any(\n        g not in fills for g in ar.gap_ranges()\n    ):",
        "    if a.rpc:",
        [FILL],
        "gaps: asks the source although no gap is open",
    ),
    (
        "S12",
        SH,
        '[ -f "$ARCHIVE/gapfills.jsonl" ] && mf+=(gapfills.jsonl)',
        "true",
        [FILL],
        "replica metadata lacks gapfills.jsonl",
    ),
    (
        "S13",
        SH,
        "  cmd_verify | tail -n 3 | sed 's/^/  /'; rc=\"${PIPESTATUS[0]}\"",
        "  rc=0",
        [FILL],
        "fill-gap wrapper skips the post-fill verify",
    ),
    (
        "S14",
        SH,
        "  cmd_gaps > /dev/null || rc=2",
        "  true",
        [FILL],
        "periodic never refreshes the gaps textfile",
    ),
    (
        "S15",
        SH,
        "|fill-[0-9]{1,10}-[0-9]{1,10}\\.jsonl\\.gz",
        "",
        [FILL],
        "sentry refuses fill segment names (no replica of fills)",
    ),
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
        'elif hdr and r["parent"] != prev[1]:',
        "elif False:",
        [UNIT],
        "verify: broken parent link not reported",
    ),
    (
        "M05",
        PY,
        "if not any(a <= gap[0] and gap[1] <= b for a, b in open_gaps):",
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
        'if r1.get("h") != e["last_hash"]:',
        "if False:",
        [UNIT],
        "MANIFEST last_hash not compared",
    ),
    (
        "M13",
        PY,
        'if r0["hdr"] and r0["parent"] != e["first_parent"]:',
        "if False:",
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
            ("BASE", None, None, None, [UNIT, WRAP, FILL], "unmutated"), base
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
