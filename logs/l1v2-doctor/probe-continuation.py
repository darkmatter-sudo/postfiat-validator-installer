#!/usr/bin/env python3
"""Show what scripts/test-validator-doctor-invocations extracts for a
backslash-continued doctor command, and what it would extract without joining.

usage: probe-continuation.py REPO_DIR
Read-only; imports the test script from REPO_DIR and runs nothing else.
"""

import importlib.machinery
import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
repo = Path(sys.argv[1]).resolve()
loader = importlib.machinery.SourceFileLoader(
    "t", str(repo / "scripts/test-validator-doctor-invocations")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
t = importlib.util.module_from_spec(spec)
loader.exec_module(t)
doctor = t.load_doctor()
shipped = t.shipped_units()
runbook = repo / "docs/runbooks/validator-doctor.md"
fixtures = [t.FIXTURES / name for name in t.FIXTURE_EXPECTATIONS]


def no_join(path):
    """Mutant: the same fence tracking, but every physical line is its own command."""
    found, fence = [], None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = t.FENCE_RE.match(line)
        if fence is None:
            if match:
                fence = match.group(1)
            continue
        marker = match.group(1) if match else ""
        if (
            marker[:1] == fence[0]
            and len(marker) >= len(fence)
            and line.strip() == marker
        ):
            fence = None
            continue
        found.append((number, line.rstrip()))
    return found


def show(label, extractor):
    print(f"== {label}: {runbook.relative_to(repo)} lines 23-28 ==")
    for number, text in extractor(runbook):
        if 23 <= number <= 28:
            print(f"  ({number}, {text!r})")
    original = t.fenced_commands
    t.fenced_commands = extractor
    failed = 0
    try:
        calls = [(n, a) for n, a in t.doctor_invocations(runbook) if 23 <= n <= 28]
        print(f"  doctor invocations found in lines 23-28: {len(calls)}")
        for number, argv in calls:
            print(f"  doctor argv from line {number}: {argv}")
            print(f"  problems: {t.check_invocation(doctor, argv, shipped) or 'none'}")
        for path in fixtures:
            count, found = t.check_files(doctor, [path], shipped)
            expected = t.FIXTURE_EXPECTATIONS[path.name]
            if expected is None:
                ok = count > 0 and not found
            else:
                ok = (
                    count > 0
                    and bool(found)
                    and all(expected in item for item in found)
                )
            failed += not ok
            print(
                f"  fixture {path.name}: invocations={count} expected={expected or 'pass'} -> {'ok' if ok else 'FAIL'}"
            )
        print(f"  fixture expectations failing: {failed} of {len(fixtures)}")
    finally:
        t.fenced_commands = original


show("joined (fenced_commands as shipped)", t.fenced_commands)
show("NOT joined (mutant)", no_join)
