#!/usr/bin/env python3
"""Mutation harness for pft-jobwatch: each mutant changes exactly one text match in ONE file of a full copy of the
module (pft-jobwatch.sh, jobwatch_lib.py) and runs tests/test_jobwatch.py against that copy (JW_DIR); rule mutants
(R*) change ../alerts/jobwatch.rules.yml in a copy and run `promtool test rules`.

A mutant is CAUGHT if its suite fails with a RESULT line and at least one FAIL line (promtool: exit != 0 with
"FAILED"), or hangs (process group SIGKILLed at --timeout). A failing suite without them is BROKEN. A mutant whose old
text does not match exactly once is NOT APPLIED. The unmutated control runs from a copy in the same place and must
pass first. Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan process fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u jobwatch/tests/mutate.py [--timeout SEC] [--jobs N] [--only M01,R01,...]
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
JW = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(JW), "alerts")
SUITE = os.path.join(HERE, "test_jobwatch.py")
FILES = ("pft-jobwatch.sh", "jobwatch_lib.py")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
L, S, R = "jobwatch_lib.py", "pft-jobwatch.sh", "jobwatch.rules.yml"

# (id, file, description, old text, new text)
MUTANTS = [
    # parsing
    ("M01", L, "span: '0' not special-cased", 'if s in ("0", ""):', 'if s in ("",):'),
    (
        "M02",
        L,
        "span: trailing junk accepted",
        "if pos == 0 or s[pos:].strip():",
        "if pos == 0:",
    ),
    (
        "M03",
        L,
        "ts: microseconds dropped",
        "frac = float(m.group(2)) if m.group(2) else 0.0",
        "frac = 0.0",
    ),
    (
        "M04",
        L,
        "ts: any zone accepted as UTC",
        r'(\.\d{1,6})? UTC$"',
        r'(\.\d{1,6})? \w+$"',
    ),
    (
        "M05",
        L,
        "parse_show: repeated keys overwrite",
        "cur.setdefault(k, []).append(v)",
        "cur[k] = [v]",
    ),
    # schedule
    (
        "M06",
        L,
        "monotonic: OnBootSec counted as repeating",
        'REPEATING = ("OnUnitActiveUSec", "OnUnitInactiveUSec")',
        'REPEATING = ("OnUnitActiveUSec", "OnUnitInactiveUSec", "OnBootUSec")',
    ),
    (
        "M07",
        L,
        "monotonic: largest interval used",
        "return kind, (min(mono) if mono else 0.0)",
        "return kind, (max(mono) if mono else 0.0)",
    ),
    (
        "M08",
        L,
        "calendar: learned interval keeps the largest gap",
        'gap < st["cal_interval"]',
        'gap > st["cal_interval"]',
    ),
    (
        "M09",
        L,
        "calendar: learned interval kept across a spec change",
        '        if prev.get("spec") == spec\n',
        "        if True\n",
    ),
    # enabled / disabled / present
    (
        "M10",
        L,
        "disabled: stopped timer counts as enabled",
        '        and one(timer, "ActiveState") == "active"\n',
        "",
    ),
    (
        "M11",
        L,
        "disabled: unit file state ignored",
        '        and one(timer, "UnitFileState") in ENABLED_STATES\n',
        "",
    ),
    ("M12", L, "disabled: static unit file counts as disabled", '    "static",\n', ""),
    (
        "M13",
        L,
        "removed: missing timer counts as present",
        'present = one(timer, "LoadState") == "loaded"',
        'present = one(timer, "LoadState") != "masked"',
    ),
    # failures
    (
        "M14",
        L,
        "failed: only ActiveState=failed counts",
        ' or result not in ("", "success")',
        "",
    ),
    (
        "M15",
        L,
        "failed: ActiveState=failed ignored",
        'one(service, "ActiveState") == "failed" or ',
        "",
    ),
    (
        "M16",
        L,
        "consecutive: same run counted again",
        'and run_key != st["seen_run"]',
        "and True",
    ),
    (
        "M17",
        L,
        "consecutive: success does not reset",
        'st["consecutive_failures"] = 0',
        "pass",
    ),
    (
        "M18",
        L,
        "consecutive: failure does not count",
        'st["consecutive_failures"] += 1',
        "pass",
    ),
    (
        "M19",
        L,
        "last success: not updated",
        'st["last_success"] = parse_ts(one(service, "ExecMainExitTimestamp")) or now',
        "pass",
    ),
    (
        "M20",
        L,
        "run key ignores result (start-limit-hit missed)",
        'run_key = f"{start_mono}:{result}:{exit_status}"',
        'run_key = f"{start_mono}"',
    ),
    ("M21", L, "running run counted as finished", "        and not running\n", ""),
    # missed
    ("M22", L, "missed: grace dropped", "        + MISS_GRACE\n", ""),
    (
        "M23",
        L,
        "missed: randomized delay counted once",
        "+ 2 * (parse_span(",
        "+ 1 * (parse_span(",
    ),
    (
        "M24",
        L,
        "missed: interval check never fires",
        "now - ref > interval_s + grace",
        "now - ref > 10 * interval_s + grace",
    ),
    (
        "M25",
        L,
        "missed: next-elapse check removed",
        "and next_rt and now - next_rt > grace",
        "and next_rt and False",
    ),
    (
        "M26",
        L,
        "missed: disabled jobs also missed",
        "if enabled and interval_s and ref and",
        "if interval_s and ref and",
    ),
    (
        "M27",
        L,
        "never run: ActiveEnterTimestamp not used as reference",
        'ref = last_trigger or parse_ts(one(timer, "ActiveEnterTimestamp"))',
        "ref = last_trigger",
    ),
    (
        "M28",
        L,
        "never_run: ignores service start",
        "never_run = not last_trigger and not started",
        "never_run = not last_trigger",
    ),
    # inventory / state
    (
        "M29",
        L,
        "inventory: state jobs not re-read (removed jobs vanish)",
        'names |= set(state["jobs"])',
        "pass",
    ),
    ("M30", L, "state written 0644", "os.chmod(tmp, 0o600)", "os.chmod(tmp, 0o644)"),
    (
        "M31",
        L,
        "render: job samples written when up 0",
        "    if not ok:\n        return",
        "    if False:\n        return",
    ),
    ("M32", L, "render: label value not escaped", ".replace('\"', '\\\\\"')", ""),
    # script
    (
        "S01",
        S,
        "collect: helper failure still publishes nothing",
        '  if [ "$rc" != 0 ] || [ -z "$text" ]; then',
        '  if [ -z "$text" ]; then',
    ),
    (
        "S02",
        S,
        "collect: failure exits 0",
        '  if [ "$rc" != 0 ]; then printf',
        "  if false; then printf",
    ),
    (
        "S03",
        S,
        "validate: host label not checked",
        "if (index(rest, pre) != 1)",
        "if (0)",
    ),
    (
        "S04",
        S,
        "validate: foreign metrics accepted",
        "if (match($0, /^pft_jobwatch_[a-z_]+\\{/) == 0)",
        "if (0)",
    ),
    (
        "S05",
        S,
        "validate: size not checked",
        '[ "$size" -le "$MAX_BYTES" ] ||',
        "true ||",
    ),
    (
        "S06",
        S,
        "validate: timestamp not required",
        "if (!ts) { print",
        "if (0) { print",
    ),
    ("S07", S, "pull: own host accepted", '[ "$name" != "$HOST_LABEL" ] ||', "true ||"),
    (
        "S08",
        S,
        "pull: invalid file installed",
        '  if ! why="$(validate "$tmp" "$name")"; then',
        "  if false; then",
    ),
    (
        "S09",
        S,
        "globs: any unit type accepted",
        ']+\\.timer$ ]] || die "bad JOB_GLOBS entry',
        ']+$ ]] || die "bad JOB_GLOBS entry',
    ),
    (
        "S10",
        S,
        "host label not validated",
        'valid_host "$HOST_LABEL" || die "bad HOST_LABEL"',
        "true",
    ),
    (
        "S11",
        S,
        "forget: any name accepted",
        r'[[ "$1" =~ ^[A-Za-z0-9:_.@-]+\.timer$ ]] || die "bad job name"',
        "true",
    ),
    # rules
    (
        "R01",
        R,
        "Failed: for 3m -> 0m (transient failure pages)",
        "        for: 3m\n",
        "",
    ),
    (
        "R02",
        R,
        "Failed: removed job still Failed",
        "          and on (host, timer) pft_jobwatch_job_present == 1\n",
        "",
    ),
    (
        "R03",
        R,
        "Missed: for 5m dropped",
        "        expr: pft_jobwatch_job_missed == 1\n        for: 5m\n",
        "        expr: pft_jobwatch_job_missed == 1\n",
    ),
    (
        "R04",
        R,
        "Disabled: for 5m -> 1m",
        "        expr: pft_jobwatch_job_disabled == 1\n        for: 5m\n",
        "        expr: pft_jobwatch_job_disabled == 1\n        for: 1m\n",
    ),
    (
        "R05",
        R,
        "Stale: up == 0 branch removed",
        "          or pft_jobwatch_up == 0\n",
        "",
    ),
    (
        "R06",
        R,
        "Stale: 600 s -> 1800 s",
        "time() - pft_jobwatch_collect_timestamp_seconds > 600",
        "time() - pft_jobwatch_collect_timestamp_seconds > 1800",
    ),
    (
        "R07",
        R,
        "Failed: value = failed flag, not consecutive count",
        "          pft_jobwatch_job_consecutive_failures\n          and on (host, timer) pft_jobwatch_job_failed == 1\n",
        "          pft_jobwatch_job_failed == 1\n",
    ),
]
MUTANTS += [
    (
        "M33",
        L,
        "label named job again (the scrape renames it)",
        'timer="{esc(j["job"])}"}} {fmt(j[key])}',
        'job="{esc(j["job"])}"}} {fmt(j[key])}',
    ),
    (
        "R08",
        R,
        "Failed: join on host only",
        "          and on (host, timer) pft_jobwatch_job_failed == 1\n",
        "          and on (host) pft_jobwatch_job_failed == 1\n",
    ),
]
EQUIVALENT = []


def run(cmd, timeout, env=None):
    """-> (PASS|FAIL|HANG, output). Own session; the whole process group is SIGKILLed on timeout."""
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return "HANG", ""
    return ("PASS" if p.returncode == 0 else "FAIL"), out


def make_copy(work, name, mutate=None):
    """Copy the module files (+ rules + rule tests) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, "alerts"))
    for f in FILES:
        shutil.copy2(os.path.join(JW, f), os.path.join(d, f))
    for f in ("jobwatch.rules.yml", "jobwatch.tests.yml"):
        shutil.copy2(os.path.join(ALERTS, f), os.path.join(d, "alerts", f))
    if mutate:
        f, old, new = mutate
        path = os.path.join(d, "alerts", f) if f == R else os.path.join(d, f)
        with open(path) as fh:
            src = fh.read()
        with open(path, "w") as fh:
            fh.write(src.replace(old, new, 1))
    return d


def suite(d, timeout):
    env = dict(os.environ, JW_DIR=d)
    return run([sys.executable, "-u", SUITE], timeout, env)


def promtool(d, timeout):
    return run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "promtool",
            "-v",
            f"{d}/alerts:/w:ro",
            "-w",
            "/w",
            PROMTOOL_IMAGE,
            "test",
            "rules",
            "jobwatch.tests.yml",
        ],
        timeout,
    )


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(JW, f)
    with open(src_path) as fh:
        n = fh.read().count(old)
    if n != 1:
        return mid, "NOT APPLIED", f"({n} matches in {f}) - {desc}"
    d = make_copy(work, mid, (f, old, new))
    st, out = promtool(d, timeout) if f == R else suite(d, timeout)
    shutil.rmtree(d)
    if st == "PASS":
        return mid, "SURVIVED", f"- {desc}"
    if st == "HANG":
        return mid, "CAUGHT", f"- {desc} [hung: timeout, process group killed]"
    if f == R:
        if "FAILED" not in out:
            return (
                mid,
                "BROKEN",
                f"- {desc} [promtool failed without FAILED: {out.strip()[-120:]}]",
            )
        names = sorted(
            {
                ln.strip()[len("name: ") :].rstrip(",")
                for ln in out.splitlines()
                if ln.strip().startswith("name: ")
            }
        )
        return mid, "CAUGHT", f"- {desc} [promtool FAILED: {'; '.join(names)[:200]}]"
    fails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
    done = any(ln.startswith("RESULT:") for ln in out.splitlines())
    if not fails or not done:
        last = out.strip().splitlines()[-1:] or [""]
        return (
            mid,
            "BROKEN",
            f"- {desc} [suite failed without a FAIL line or RESULT: {last[0][:120]}]",
        )
    return (
        mid,
        "CAUGHT",
        f"- {desc} [{len(fails)} failing: {'; '.join(x[:90] for x in fails[:2])}]",
    )


def main():
    a = sys.argv
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 300
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 2
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="pft-jw-mut.", dir=base)
    ids = [m[0] for m in MUTANTS]
    if len(ids) != len(set(ids)):
        print("RESULT: duplicate mutant ids")
        return 2
    ctl = make_copy(work, "CONTROL")
    st, out = suite(ctl, timeout)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(
        f"control suite (unmutated copy): {st} {last[-1] if last else ''}", flush=True
    )
    pst, pout = promtool(ctl, timeout)
    print(
        f"control promtool (unmutated copy): {pst} {pout.strip().splitlines()[-1] if pout.strip() else ''}",
        flush=True,
    )
    shutil.rmtree(ctl)
    if st != "PASS" or pst != "PASS":
        print("RESULT: control run failed, mutants not run")
        shutil.rmtree(work)
        return 2
    selected = [m for m in MUTANTS if only is None or m[0] in only]
    res = {}
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for mid, status, text in ex.map(lambda m: one(work, timeout, m), selected):
            res[mid] = status
            print(f"{mid} {status} {text}", flush=True)
    shutil.rmtree(work)
    c = sum(1 for s in res.values() if s == "CAUGHT")
    sv = sum(1 for s in res.values() if s == "SURVIVED")
    na = sum(1 for s in res.values() if s == "NOT APPLIED")
    br = sum(1 for s in res.values() if s == "BROKEN")
    orphans = subprocess.run(
        ["pgrep", "-fc", "pft-jw-mut\\."], capture_output=True, text=True, check=False
    ).stdout.strip()
    print(f"orphan check: {orphans or 0} process(es) still running from mutant copies")
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(
        f"RESULT: {c} caught, {sv} survived, {na} not applied, {br} broken of {len(selected)}{subset}"
        f" (+ {len(EQUIVALENT)} documented equivalent: {', '.join(EQUIVALENT)})"
    )
    return 0 if sv == 0 and na == 0 and br == 0 and (orphans or "0") == "0" else 1


if __name__ == "__main__":
    sys.exit(main())
