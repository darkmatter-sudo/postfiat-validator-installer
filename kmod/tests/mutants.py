#!/usr/bin/env python3
"""Mutation harness for pft-kmod.sh: each mutant disables one safety guard or check; the offline suite
(run-tests.sh, KMOD_FAILFAST=1) must fail on it. Every mutant gets its own copy of the script AND its own
TEST_TMPDIR (lesson: parallel copies sharing scratch read each other's files). Prints one line per mutant
(CAUGHT + the first FAIL line, or SURVIVED) and "MUTANTS: caught N/M"; exit 0 only if all were caught.
   python3 -I kmod/tests/mutants.py [-j 4] [--only M14,M22]"""

import concurrent.futures as cf
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "pft-kmod.sh")
SUITE = os.path.join(HERE, "run-tests.sh")
# id, what it breaks, old text, new text, which occurrence (1-based)
MUTANTS = [
    (
        "M01",
        "apply without --yes",
        '[ "$yes" = 1 ] || refuse "apply writes',
        'true || refuse "apply writes',
        1,
    ),
    (
        "M02",
        "apply maintenance gate",
        'why="$(maint_gate)" || refuse "$why"',
        'why=""',
        1,
    ),
    (
        "M03",
        "rollback maintenance gate",
        'why="$(maint_gate)" || refuse "$why"',
        'why=""',
        2,
    ),
    ("M04", "window remaining time", '-lt "$MAINT_MIN"', "-lt 0", 1),
    ("M05", "maint data-collection locks", '"$nl" -gt 0', '"$nl" -gt 99', 1),
    (
        "M06",
        "last apply still in place",
        '[ -f "$STATE_DIR/apply.json" ] && refuse',
        "false && refuse",
        1,
    ),
    (
        "M07",
        "node healthy before apply",
        'node_ok "$ns0" || refuse',
        "true || refuse",
        1,
    ),
    ("M08", "autoload path guard", "autoload_ok || { echo", "true || { echo", 1),
    (
        "M09",
        "loaded deny module guard",
        'if is_loaded "$m"; then echo "deny-list',
        'if false; then echo "deny-list',
        1,
    ),
    (
        "M10",
        "builtin deny module guard",
        'if is_builtin "$m"; then echo "deny-list',
        'if false; then echo "deny-list',
        1,
    ),
    (
        "M11",
        "required-closure guard",
        'if grep -qx "$(norm "$m")" <<<"$cl"',
        "if false",
        1,
    ),
    (
        "M12",
        "loaded modules in the required set",
        "loaded; } | sort -u",
        "} | sort -u",
        1,
    ),
    (
        "M13",
        "required_blocked sees install rules",
        "grep -qE '^install ' <<<\"$out\"",
        "grep -qE '^install /never' <<<\"$out\"",
        1,
    ),
    (
        "M14",
        "verify: deny rules effective",
        'denied "$m" || fails=',
        "true || fails=",
        1,
    ),
    (
        "M15",
        "verify: required unblocked",
        '[ -z "$blk" ] || fails=',
        "true || fails=",
        1,
    ),
    (
        "M16",
        "verify: node still healthy",
        'node_ok "$ns1" || fails=',
        "true || fails=",
        1,
    ),
    (
        "M17",
        "restore keeps mode/mtime",
        'cp -p "$bk" "$CONF_FILE"',
        'cp "$bk" "$CONF_FILE"',
        1,
    ),
    (
        "M18",
        "rollback sha check",
        'if ! restore_conf "$pre"; then',
        'if ! restore_conf "$pre" && false; then',
        1,
    ),
    (
        "M19",
        "audit: loaded classification",
        'if is_loaded "$m"; then N_LOADED',
        "if false; then N_LOADED",
        1,
    ),
    (
        "M20",
        "audit: loadable vs absent",
        'elif in_tree "$m"; then',
        "elif false; then",
        1,
    ),
    ("M21", "validate: host label", "index(rest, pre) != 1", "0", 1),
    ("M22", "validate: size cap", '"$size" -le "$MAX_BYTES"', '"$size" -ge 0', 1),
    (
        "M23",
        "pull: invalid file kept out",
        'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then',
        "if false; then",
        1,
    ),
    (
        "M24",
        "up 0 on a failed audit",
        '[ "$tf" = 1 ] && write_textfile "$(metrics 0 "$t0")"',
        ":",
        1,
    ),
]


def mutate(src, old, new, nth):
    i = -1
    for _ in range(nth):
        i = src.find(old, i + 1)
        if i < 0:
            raise SystemExit(f"mutant anchor not found: {old!r} (occurrence {nth})")
    return src[:i] + new + src[i + len(old) :]


def read(path):
    with open(path) as fh:
        return fh.read()


def run(m):
    mid, what, old, new, nth = m
    src = read(SRC)
    with tempfile.TemporaryDirectory(
        dir=os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    ) as d:
        p = os.path.join(d, "pft-kmod.sh")
        with open(p, "w") as fh:
            fh.write(mutate(src, old, new, nth))
        os.chmod(p, 0o755)
        scratch = os.path.join(d, "scratch")
        os.mkdir(scratch)
        env = dict(os.environ, TEST_TMPDIR=scratch, KMOD_FAILFAST="1")
        r = subprocess.run(
            ["bash", SUITE, p],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=1800,
        )
        fails = [l for l in r.stdout.splitlines() if l.startswith("FAIL ")]
        if r.returncode != 0 and fails:
            return f"CAUGHT   {mid} {what:<38} by: {fails[0][5:]}", True
        return f"SURVIVED {mid} {what:<38} (suite rc {r.returncode})", False


if __name__ == "__main__":
    argv = sys.argv[1:]
    jobs = int(argv[argv.index("-j") + 1]) if "-j" in argv else 4
    only = (
        argv[argv.index("--only") + 1].split(",") if "--only" in argv else None
    )  # e.g. --only M14,M22
    src = read(SRC)
    for m in MUTANTS:
        mutate(src, m[2], m[3], m[4])  # every anchor must exist before anything runs
    with cf.ThreadPoolExecutor(jobs) as ex:
        res = list(ex.map(run, [m for m in MUTANTS if only is None or m[0] in only]))
    for line, _ in res:
        print(line, flush=True)
    n = sum(1 for _, c in res if c)
    print(f"MUTANTS: caught {n}/{len(res)}")
    sys.exit(0 if n == len(res) else 1)
