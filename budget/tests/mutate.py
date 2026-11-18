#!/usr/bin/env python3
"""Mutation harness for pft-budget. Each mutant changes exactly one text match in a COPY of the budget folder (helper
B*, shell S*, systemd unit U*) and runs that copy's tests/test_budget.py, or changes a copy of
../alerts/budget.rules.yml (R*) and runs `promtool test rules budget.tests.yml` on it.

CAUGHT: the suite printed its "Ran N tests" summary and at least one FAIL:/ERROR: test (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose report never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (BUDMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u budget/tests/mutate.py [--timeout SEC] [--jobs N] [--only B01,R01,...]
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BUD = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(BUD), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
B, S, R = "budget.py", "pft-budget.sh", "budget.rules.yml"
US = "systemd/pft-budget-sampler.service"
COPY = (B, S, "tests/test_budget.py", US, "systemd/pft-budget-collect.service")

# (id, file, description, old text, new text)
MUTANTS = [
    # ---- cgroup reading
    ("B01", B, "page cache counted as unreclaimable", '"anon", "shmem",', '"anon", "file", "shmem",'),
    ("B02", B, "anon not counted", '("anon", "shmem", "kernel_stack"', '("shmem", "kernel_stack"'),
    (
        "B03",
        B,
        "io read bytes ignored",
        'if k == "rbytes":\n                    io_r += int(v)',
        'if k == "rbytes":\n                    io_r += 0',
    ),
    ("B04", B, "io write bytes from rbytes", 'elif k == "wbytes":', 'elif k == "rbytes":'),
    (
        "B05",
        B,
        "memory.max 'max' read as 0",
        'return None if t == "max" else int(t)',
        'return 0 if t == "max" else int(t)',
    ),
    (
        "B06",
        B,
        "scan ignores the unit glob",
        'if fnmatch.fnmatchcase(n, conf["UNIT_GLOB"]) and UNIT_RE.match(n)',
        "if UNIT_RE.match(n)",
    ),
    (
        "B07",
        B,
        "scan accepts non-directories",
        "UNIT_RE.match(n) and os.path.isdir(os.path.join(root, n))",
        "UNIT_RE.match(n)",
    ),
    (
        "B08",
        B,
        "vanished cgroup raises",
        "    except FileNotFoundError:\n        return None",
        "    except FileNotFoundError:\n        raise",
    ),
    # ---- tracker
    ("B09", B, "pre-existing invocations marked complete", '"from_start": not self.first_scan', '"from_start": True'),
    ("B10", B, "peak is last sample", 'st["peak"] = max(st["peak"], s["current"])', 'st["peak"] = s["current"]'),
    (
        "B11",
        B,
        "unreclaimable peak is last sample",
        'st["peak_unrecl"] = max(st["peak_unrecl"], s["unrecl"])',
        'st["peak_unrecl"] = s["unrecl"]',
    ),
    ("B12", B, "no running checkpoints", 'if t - st["t_checkpoint"] >= self.conf["CHECKPOINT_SEC"]:', "if False:"),
    (
        "B13",
        B,
        "checkpoint one interval late",
        'if t - st["t_checkpoint"] >= self.conf["CHECKPOINT_SEC"]:',
        'if t - st["t_checkpoint"] > self.conf["CHECKPOINT_SEC"] + 1:',
    ),
    ("B14", B, "result of a later run attributed", 'if res.get("inv") != st["inv"]:', "if False:"),
    ("B15", B, "oom-kill result not counted", 'if res.get("result") == "oom-kill":', 'if res.get("result") == "oom":'),
    (
        "B16",
        B,
        "vanished units never finalized",
        "for unit in [u for u in self.open if u not in present]:",
        "for unit in []:",
    ),
    ("B17", B, "invocation change not detected", 'if st is not None and st["inv"] != s["inv"]:', "if False:"),
    ("B18", B, "invocation id never re-checked", 'or t - st["t_invcheck"] >= self.conf["INV_CHECK_SEC"]:', "or False:"),
    ("B19", B, "systemd runtime ignored", 'if rec["runtime_sec"] is None:', "if True:"),
    # ---- JSONL
    ("B20", B, "no rotation", 'if size and size + len(line) > conf["MAX_BYTES"]:', "if False:"),
    (
        "B21",
        B,
        "rotation keeps one file too many",
        'for i in range(conf["KEEP"], 0, -1):\n            src',
        'for i in range(conf["KEEP"] + 1, 0, -1):\n            src',
    ),
    (
        "B22",
        B,
        "running checkpoint beats final",
        '(r["kind"] == "final") > (old["kind"] == "final")',
        '(r["kind"] == "final") < (old["kind"] == "final")',
    ),
    (
        "B23",
        B,
        "older checkpoint wins",
        'r["kind"] == old["kind"] and r["t_last"] >= old["t_last"]',
        'r["kind"] == old["kind"] and r["t_last"] <= old["t_last"]',
    ),
    ("B24", B, "torn line not counted", "bad += 1  # a torn", "bad += 0  # a torn"),
    # ---- report
    ("B25", B, "window lower bound dropped", 'lo <= r["t_last"] <= t_now', 'r["t_last"] <= t_now'),
    ("B26", B, "OOM runs not counted from oom_kills", 'r.get("oom_kills", 0) > 0 or', ""),
    ("B27", B, "OOM does not fail", "if ooms:\n        fail.append", "if False:\n        fail.append"),
    (
        "B28",
        B,
        "fail fraction strict",
        'if max_peak >= conf["FAIL_FRACTION"] * cap:',
        'if max_peak > conf["FAIL_FRACTION"] * cap:',
    ),
    (
        "B29",
        B,
        "WARN at exactly 2x",
        'elif max_peak * conf["WARN_HEADROOM"] > cap:',
        'elif max_peak * conf["WARN_HEADROOM"] >= cap:',
    ),
    ("B30", B, "no headroom WARN", 'elif max_peak * conf["WARN_HEADROOM"] > cap:', "elif False:"),
    ("B31", B, "30-day projection ignored", 'if u["proj30"] is not None and u["proj30"] >= cap:', "if False:"),
    ("B32", B, "90-day projection ignored", 'elif u["proj90"] is not None and u["proj90"] >= cap:', "elif False:"),
    (
        "B33",
        B,
        "uncapped OOM stays UNCAPPED",
        'if cap is None and fail:\n        verdict = "FAIL"',
        'if False:\n        verdict = "FAIL"',
    ),
    ("B34", B, "projection on too few runs", 'if len(recs) >= conf["MIN_RUNS"]:', "if True:"),
    ("B63", B, "projection over a short span", 'and span_days >= conf["PROJ_MIN_SPAN_DAYS"]:', ":"),
    (
        "B64",
        B,
        "span bound strict",
        'and span_days >= conf["PROJ_MIN_SPAN_DAYS"]:',
        'and span_days > conf["PROJ_MIN_SPAN_DAYS"]:',
    ),
    ("B35", B, "negative growth lowers projection", "slope = max(0.0, slope)", "slope = slope"),
    ("B36", B, "projection from the mean time, not now", "base = my + slope * (t_now - mt) / 86400", "base = my"),
    (
        "B37",
        B,
        "projection ignores slope",
        'u["proj30"] = int(max(max_peak, base + slope * 30))',
        'u["proj30"] = int(max(max_peak, base))',
    ),
    ("B38", B, "target ignores projection", 'need = max(need, u["proj90"] * conf["PROJ_MARGIN"])', "need = need"),
    (
        "B39",
        B,
        "target not rounded up",
        "return math.ceil(x / (step * MIB)) * step * MIB",
        "return round(x / (step * MIB)) * step * MIB",
    ),
    (
        "B40",
        B,
        "report rc ignores FAIL",
        'return 1 if rep["counts"]["FAIL"] else 2',
        'return 2 if rep["counts"]["FAIL"] else 2',
    ),
    ("B41", B, "p50 is the lower middle", "return v[lo] + (v[hi] - v[lo]) * (k - lo)", "return v[lo]"),
    # ---- metrics
    ("B42", B, "host label missing on up", 'f"pft_budget_up{{{h}}} 1"', '"pft_budget_up 1"'),
    ("B43", B, "None values exported", "            if v is None:\n                continue", "            pass"),
    # ---- plan / apply / rollback guards
    (
        "B44",
        B,
        "plan ignores exclusions",
        'if u["host"] != host or excluded(u["unit"], conf):',
        'if u["host"] != host:',
    ),
    ("B45", B, "plan covers other hosts", 'if u["host"] != host or excluded', "if excluded"),
    (
        "B46",
        B,
        "uncapped set on few runs",
        "                continue  # never cap a unit on too few measured runs",
        "                pass",
    ),
    ("B47", B, "raise also for OK units", 'tgt > cap and u["verdict"] in ("WARN", "FAIL")', "tgt > cap"),
    (
        "B48",
        B,
        "lower without --allow-lower",
        "elif allow_lower and cap is not None and tgt < cap",
        "elif cap is not None and tgt < cap",
    ),
    (
        "B50",
        B,
        "lower on few runs",
        "                continue  # never lower a cap on too few measured runs",
        "                pass",
    ),
    (
        "B51",
        B,
        "apply without a window",
        '    if not maint_active():\n        print("REFUSED: no active pft-maint window (sudo',
        '    if False:\n        print("REFUSED: no active pft-maint window (sudo',
    ),
    (
        "B52",
        B,
        "apply writes excluded units",
        'if excluded(p["unit"], conf) or not UNIT_RE.match(p["unit"]):',
        'if not UNIT_RE.match(p["unit"]):',
    ),
    (
        "B53",
        B,
        "dry run writes",
        '    if not args.yes:\n        print("dry run: add --yes inside a pft-maint window to write',
        '    if False:\n        print("dry run: add --yes inside a pft-maint window to write',
    ),
    ("B54", B, "drop-in mode 0600", 'os.chmod(f + ".tmp", 0o644)', 'os.chmod(f + ".tmp", 0o600)'),
    ("B55", B, "apply check always OK", 'ok = got == str(p["to"])', "ok = True"),
    (
        "B56",
        B,
        "daemon-reload failure ignored",
        "bad = 0 if rc == 0 else 1\n    for p in plan:",
        "bad = 0\n    for p in plan:",
    ),
    (
        "B57",
        B,
        "rollback without a window",
        '    if not maint_active():\n        print("REFUSED: no active pft-maint window", file',
        '    if False:\n        print("REFUSED: no active pft-maint window", file',
    ),
    (
        "B58",
        B,
        "rollback keeps new drop-ins",
        'if u["previous"] is None:\n            if os.path.exists(u["path"]):\n                os.remove(u["path"])',
        'if u["previous"] is None:\n            if os.path.exists(u["path"]):\n                pass',
    ),
    (
        "B59",
        B,
        "rollback record reused",
        'os.replace(os.path.join(rec, done[-1]), os.path.join(rec, done[-1] + ".rolled-back"))',
        "pass",
    ),
    # ---- conf
    ("B60", B, "unknown conf keys accepted", "if not sep or k not in DEFAULTS:", "if not sep:"),
    (
        "B61",
        B,
        "FAIL_FRACTION > 1 accepted",
        'if not 0 < num["FAIL_FRACTION"] <= 1:',
        'if not 0 < num["FAIL_FRACTION"]:',
    ),
    ("B62", B, "free-form HOST accepted", 'if not re.match(r"^[a-z][a-z0-9-]{0,31}$", conf["HOST"]):', "if False:"),
    # ---- shell
    ("S01", S, "stale heartbeat reported ok", 'if [ "$age" -gt "$STALE_SEC" ]; then', 'if [ "$age" -gt 99999 ]; then'),
    ("S02", S, "oversized textfile written", 'if [ "$size" -gt "$TEXT_MAX_BYTES" ]; then', "if false; then"),
    ("S03", S, "validate skips host label", "if (index(rest, pre) != 1)", "if (0)"),
    ("S04", S, "validate needs no up sample", 'if (!up) { print "no pft_budget_up sample"; exit 1 }', ""),
    (
        "S05",
        S,
        "validate accepts malformed values",
        "if (rest !~ /^[^{}]*\\} -?[0-9]+",
        "if (0 && rest !~ /^[^{}]*\\} -?[0-9]+",
    ),
    (
        "S06",
        S,
        "helper failure keeps the report",
        '  if [ "$rc" != 0 ]; then\n    text="# HELP',
        '  if false; then\n    text="# HELP',
    ),
    ("S07", S, "collect rc 0 on failure", '  [ "$rc" = 0 ] || return 1\n}', "  return 0\n}"),
    ("S08", S, "pull without --host", 'valid_host "$name" || die "pull needs --host', 'true || die "pull needs --host'),
    # ---- units
    ("U01", US, "sampler uncapped", "\nMemoryMax=64M\n", "\n"),
    ("U02", US, "sampler writable /", "ProtectSystem=strict\n", "ProtectSystem=full\n"),
    # ---- alert rules
    (
        "R01",
        R,
        "cap rule at 0.95",
        ">= 0.9 * max by (host, unit) (pft_budget_cap_bytes)",
        ">= 0.95 * max by (host, unit) (pft_budget_cap_bytes)",
    ),
    (
        "R02",
        R,
        "projection rule dropped",
        "          or max by (host, unit) (pft_budget_projected_30d_bytes)\n          >= max by (host, unit) (pft_budget_cap_bytes)\n",
        "",
    ),
    ("R03", R, "cap rule for 10m", "        for: 30m\n", "        for: 10m\n"),
    ("R04", R, "stale ignores up 0", "max by (host) (pft_budget_up) == 0\n          or ", ""),
    (
        "R05",
        R,
        "heartbeat age 1200",
        "pft_budget_sampler_heartbeat_timestamp_seconds) > 900",
        "pft_budget_sampler_heartbeat_timestamp_seconds) > 1200",
    ),
    (
        "R06",
        R,
        "report age ignored",
        "\n          or max by (host) (time() - pft_budget_report_timestamp_seconds) > 1800",
        "",
    ),
    ("R07", R, "stale for 5m", "        for: 15m\n", "        for: 5m\n"),
    (
        "R08",
        R,
        "projection strict",
        "          or max by (host, unit) (pft_budget_projected_30d_bytes)\n          >= max",
        "          or max by (host, unit) (pft_budget_projected_30d_bytes)\n          > max",
    ),
]
HANG = (
    B,
    "def build_report(conf, t_now, files=None):\n",
    "def build_report(conf, t_now, files=None):\n    while True:\n        time.sleep(1)\n",
)


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
    """Copy the budget folder (+ rules, rule tests) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    for sub in ("tests", "systemd", "alerts"):
        os.makedirs(os.path.join(d, sub))
    for x in (d, os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in COPY:
        shutil.copy2(os.path.join(BUD, f), os.path.join(d, f))
    for f in (R, "budget.tests.yml"):
        shutil.copy2(os.path.join(ALERTS, f), os.path.join(d, "alerts", f))
        os.chmod(os.path.join(d, "alerts", f), 0o644)
    if mutate:
        f, old, new = mutate
        path = os.path.join(d, "alerts", f) if f == R else os.path.join(d, f)
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src.replace(old, new, 1))
    return d


def suite(d, timeout):
    tmp = os.path.join(d, "tmp")  # own temp base per copy
    os.makedirs(tmp, exist_ok=True)
    return run(
        [sys.executable, "-I", os.path.join(d, "tests", "test_budget.py")], timeout, dict(os.environ, TMPDIR=tmp)
    )


def promtool(d, timeout):
    cmd = ["sudo", "-n", "docker", "run", "--rm", "--network", "none", "--entrypoint", "promtool", "-v"]
    return run(cmd + [f"{d}/alerts:/w:ro", "-w", "/w", PROMTOOL_IMAGE, "test", "rules", "budget.tests.yml"], timeout)


def failing_tests(out):
    return [ln.split(" ", 1)[1].split(" ", 1)[0] for ln in out.splitlines() if ln.startswith(("FAIL: ", "ERROR: "))]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(BUD, f)
    with open(src_path, encoding="utf-8") as fh:
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
            return mid, "BROKEN", f"- {desc} [promtool failed without FAILED: {out.strip()[-120:]}]"
        names = sorted(
            {ln.strip()[len("name: ") :].rstrip(",") for ln in out.splitlines() if ln.strip().startswith("name: ")}
        )
        return mid, "CAUGHT", f"- {desc} [promtool FAILED: {'; '.join(names)[:220]}]"
    fails = failing_tests(out)
    if not fails or not re.search(r"^Ran \d+ tests? in ", out, re.MULTILINE):
        last = out.strip().splitlines()[-1:] or [""]
        return mid, "BROKEN", f"- {desc} [suite failed without a summary or a failing test: {last[0][:120]}]"
    return mid, "CAUGHT", f"- {desc} [{len(fails)} failing: {', '.join(fails[:4])}{' ...' if len(fails) > 4 else ''}]"


def main():
    a = sys.argv
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 120
    hang_timeout = int(a[a.index("--hang-timeout") + 1]) if "--hang-timeout" in a else 30
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 2
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="budmut.", dir=base)
    os.chmod(work, 0o755)
    ids = [m[0] for m in MUTANTS]
    if len(ids) != len(set(ids)):
        print("RESULT: duplicate mutant ids")
        return 2
    ctl = make_copy(work, "CONTROL")
    st, out = suite(ctl, timeout)
    summary = [ln for ln in out.splitlines() if ln.startswith(("Ran ", "OK", "FAILED"))]
    print(f"control baseline suite (unmutated copy): {st} {' / '.join(summary)}", flush=True)
    pst, pout = promtool(ctl, timeout)
    last = pout.strip().splitlines()[-1] if pout.strip() else ""
    print(f"control baseline promtool (unmutated copy): {pst} {last}", flush=True)
    shutil.rmtree(ctl)
    hang = make_copy(work, "HANGCTL", HANG)
    t0 = time.monotonic()
    hst, _ = suite(hang, hang_timeout)
    left = subprocess.run(["pgrep", "-af", re.escape(hang)], capture_output=True, text=True, check=False)
    left = left.stdout.splitlines()
    print(
        f"control timeout (report never returns, --hang-timeout {hang_timeout}): {hst} after "
        f"{time.monotonic() - t0:.0f} s, {len(left)} process(es) left",
        flush=True,
    )
    shutil.rmtree(hang)
    if st != "PASS" or pst != "PASS" or hst != "HANG" or left:
        print("RESULT: control run failed, mutants not run")
        shutil.rmtree(work)
        return 2
    selected = [m for m in MUTANTS if only is None or m[0] in only]
    res = {}
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for mid, status, text in ex.map(lambda m: one(work, timeout, m), selected):
            res[mid] = status
            print(f"{mid} {status} {text}", flush=True)
    if os.environ.get("BUDMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
        subprocess.Popen(
            ["bash", "-c", "sleep 60; true", os.path.join(work, "orphan-selftest")],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    hits = subprocess.run(["pgrep", "-af", re.escape(work)], capture_output=True, text=True, check=False)
    hits = hits.stdout.splitlines()
    shutil.rmtree(work)
    for h in hits:
        print(f"orphan: {h[:160]}")
    print(f"orphan check: {len(hits)} process(es) still running that name this run's scratch dir")
    c, sv, na, br = (sum(1 for s in res.values() if s == k) for k in ("CAUGHT", "SURVIVED", "NOT APPLIED", "BROKEN"))
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(f"RESULT: {c} caught, {sv} survived, {na} not applied, {br} broken of {len(selected)}{subset}")
    return 0 if sv == 0 and na == 0 and br == 0 and not hits else 1


if __name__ == "__main__":
    sys.exit(main())
