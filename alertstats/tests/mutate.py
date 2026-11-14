#!/usr/bin/env python3
"""Mutation harness for pft-alertstats. Each mutant changes exactly one text match in a COPY of the alertstats folder
(episode builder B*, silences/flaps/percentiles F*, hygiene/outputs H*, collect C*, shell S*) and runs that copy's
full pytest suite, or changes a copy of ../alerts/alertstats.rules.yml (R*) and runs
`promtool test rules alertstats.tests.yml` on it.

CAUGHT: pytest printed its "N failed ... in Xs" summary and at least one FAILED test line (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose helper never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (ASMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u alertstats/tests/mutate.py [--timeout SEC] [--jobs N] [--only B01,R01,...]
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
FW = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(FW), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
SKIP = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".ruff_cache", "logs", "*.pyc")

E, S, R = "alertstats_build.py", "pft-alertstats.sh", "alertstats.rules.yml"
RT = "alertstats.tests.yml"

# (id, file, description, old text, new text)
MUTANTS = [
    # ---- episode builder
    ("B01", E, "gap tolerance 1 step (every jitter splits)", "    tol = 1.5 * step\n", "    tol = 2.5 * step\n"),
    ("B02", E, "firing does not override pending at the same t", 'if st == "firing" or t not in d:', "if t not in d:"),
    ("B03", E, "real resolve treated as a data gap", "if not data_gap(gap_from, t):", "if False:"),
    ("B04", E, "data gap ignored (always a real resolve)", "if not data_gap(gap_from, t):", "if True:"),
    (
        "B05",
        E,
        "bridge without comparing activeAt",
        "elif fs.get(gap_from) is not None and fs.get(gap_from) == fs.get(t):",
        "elif True:",
    ),
    (
        "B06",
        E,
        "missing activeAt counts as the same",
        "elif fs.get(gap_from) is not None and fs.get(gap_from) == fs.get(t):",
        "elif fs.get(gap_from) == fs.get(t):",
    ),
    ("B07", E, "bridged gap seconds not subtracted", '                    cur["gap_s"] += t - gap_from - step\n', ""),
    ("B08", E, "split does not mark the earlier half", '                    cur["gap_split_after"] = True\n', ""),
    (
        "B09",
        E,
        "split does not mark the later half",
        "cur = new_episode(labels, t, start, step, gap_split_before=True)",
        "cur = new_episode(labels, t, start, step)",
    ),
    (
        "B10",
        E,
        "data gap = any overlap (far-away outage splits real resolves)",
        'return any(g["from"] - lb <= t0 + step and t1 <= g["to"] + lb for g in gaps)',
        'return any(g["from"] < t1 and g["to"] > t0 for g in gaps)',
    ),
    ("B11", E, "lookback widening dropped", '    lb = p.get("lookback", 300) + step\n', "    lb = 0\n"),
    (
        "B12",
        E,
        "lookback-filled outage not counted",
        'if e["start"] < g["from"] and g["to"] <= e["last"] and g["from"] not in e["sample_gaps"]:',
        "if False:",
    ),
    (
        "B13",
        E,
        "outage counted twice when already bridged by a sample gap",
        ' and g["from"] not in e["sample_gaps"]:',
        ":",
    ),
    ("B14", E, "firing_start overwritten by later firing samples", 'if st == "firing" and cur["firing_start"] is None:',
     'if st == "firing":'),
    ("B15", E, "truncated start not detected", '"truncated_start": t <= start + step / 2,', '"truncated_start": False,'),
    ("B16", E, "open episode not detected", 'e["open"] = e["last"] >= end - tol and not e["gap_split_after"]',
     'e["open"] = False'),
    ("B17", E, "end = last sample (one step short)", 'e["end"] = None if e["open"] else e["last"] + step',
     'e["end"] = None if e["open"] else e["last"]'),
    ("B18", E, "TTR for truncated episodes", ' and not e["truncated_start"]) else None', ") else None"),
    ("B19", E, "TTR across a split boundary", '        e["ttr_s"] = None  # boundary is a data gap, not a resolve\n',
     "        pass\n"),
    ("B20", E, "firing_s ignores gap seconds", 'e["firing_s"] = (stop - e["firing_start"] - e["gap_s"]) if fired else 0',
     'e["firing_s"] = (stop - e["firing_start"]) if fired else 0'),
    ("B21", E, "pending_s measured from firing start", '(e["firing_start"] if fired else stop) - e["start"]',
     '(stop if fired else stop) - e["start"]'),
    ("B22", E, "series key keeps alertstate (pending/firing split)", 'if k not in ("__name__", "alertstate")',
     'if k not in ("__name__",)'),
    ("B23", E, "prom gap threshold 1 step", '        if b - a > 1.5 * p["step"]:\n            gaps.append',
     '        if b - a > 2.5 * p["step"]:\n            gaps.append'),
    # ---- silences, flaps, percentiles
    ("F01", E, "regex not anchored", 'hit = re.fullmatch(m["value"], val) is not None', 'hit = re.search(m["value"], val) is not None'),
    ("F02", E, "negative matchers ignored", 'return hit if m.get("isEqual", True) else not hit', "return hit"),
    ("F03", E, "any matcher instead of all", 'if all(matcher_ok(m, labels) for m in s["matchers"]):',
     'if any(matcher_ok(m, labels) for m in s["matchers"]):'),
    ("F04", E, "overlapping silences double counted", "        if merged and a <= merged[-1][1]:", "        if False:"),
    ("F05", E, "notifiable ignores silences", 'e["notifiable"] = fired and e["silenced_s"] * 2 < max(e["firing_s"], 1)',
     'e["notifiable"] = fired'),
    ("F06", E, "pending-only episodes may flap", '        if e["notifiable"]:\n', "        if True:\n"),
    ("F07", E, "flap window inclusive of far firings", 'and e["start"] - prev["end"] < win:', "and True:"),
    ("F08", E, "split boundary counted as a flap", ' and not prev["gap_split_after"] and e["start"]', ' and e["start"]'),
    ("F09", E, "flapping ignores the recent window", 'starts = [e["start"] for e in eps if e["start"] >= recent_from]',
     'starts = [e["start"] for e in eps]'),
    ("F10", E, "flapping with FLAP_MIN-1 firings", "starts[i + fmin - 1] - starts[i] < win for i in range(len(starts) - fmin + 1)",
     "starts[i + fmin - 2] - starts[i] < win for i in range(len(starts) - fmin + 2)"),
    ("F11", E, "percentile off by one rank", "return s[max(0, math.ceil(q * len(s)) - 1)]", "return s[min(len(s) - 1, math.ceil(q * len(s)))]"),
    # ---- hygiene and outputs
    ("H01", E, "allow_no_for ignored", 'if r["duration"] == 0 and name not in allow:', 'if r["duration"] == 0:'),
    ("H02", E, "short_for boundary inclusive", 'elif 0 < r["duration"] < 2 * iv:', 'elif 0 < r["duration"] <= 2 * iv:'),
    ("H03", E, "any severity accepted", 'if r["labels"].get("severity") not in SEVERITIES:', "if False:"),
    ("H04", E, "always_firing threshold 80%", "firing.get(name, 0) >= 0.9 * window", "firing.get(name, 0) >= 0.8 * window"),
    ("H05", E, "no_rule check dropped", '        findings.append(("no_rule", name, "history only"))\n', "        pass\n"),
    ("H06", E, "duplicate rules not reported", "        if len(rules) > 1:", "        if len(rules) > 2:"),
    ("H07", E, "textfile label value not escaped", 'return str(v).replace("\\\\", "\\\\\\\\").replace(\'"\', \'\\\\"\')', "return str(v).replace('\"', '\"')"),
    ("H08", E, "textfile budget never enforced", "    if len(text.encode()) > TEXT_BUDGET:", "    if False:"),
    ("H09", E, "up 1 even when Prometheus failed", '{1 if r["sources"].get("prometheus") == "ok" else 0}', "{1}"),
    ("H10", E, "delivery errors counted as ok", 'x["ok" if d["result"].startswith("HTTP 2") else "error"] += 1', 'x["ok"] += 1'),
    ("H11", E, "deliveries reordered by kind", 'out.sort(key=lambda d: d["ts"])', 'out.sort(key=lambda d: (d["ts"], d["kind"]))'),
    # ---- collect
    ("C01", E, "chunks overlap by one point (duplicates)", "        t = chunk_end + step\n", "        t = chunk_end\n"),
    ("C02", E, "since cap not enforced", "    if since > MAX_SINCE:", "    if False:"),
    ("C03", E, "comments not redacted", '"comment": redact(s.get("comment", ""))[:120],', '"comment": s.get("comment", "")[:120],'),
    ("C04", E, "public IP regex misses addresses", '_IP4 = re.compile(r"\\b(?!(?:127|10|0)\\.)', '_IP4 = re.compile(r"\\b(?!(?:127|10|0|19)\\.)'),
    ("C05", E, "gzip with a timestamp (bundles not byte-identical)", 'mode="wb", fileobj=f, mtime=0)', 'mode="wb", fileobj=f)'),
    ("C06", E, "present_over_time window dropped (lookback hides outages)",
     '"up_query": f"count(present_over_time({a.up_selector}[{2 * step}s]))",', '"up_query": f"count({a.up_selector})",'),
    # ---- shell
    ("S01", S, "STEP not validated", '[[ "$STEP" =~ ^[1-9][0-9]*$ ]] || die', "true || die"),
    ("S02", S, "root check skipped", '[ "${PFT_AS_TEST:-0}" = 1 ] || [ "$(id -u)" = 0 ] || die', "true || die"),
    ("S03", S, "textfile not atomic (written in place)", 'mv -f "$t" "$TEXTFILE_DIR/pft_alertstats.prom"',
     'cp "$t" "$TEXTFILE_DIR/pft_alertstats.prom"'),
    ("S04", S, "up 0 textfile not written on capture failure",
     '    down_textfile "$TMP/t.prom"; write_textfile "$TMP/t.prom"\n', "    :\n"),
    ("S05", S, "deliveries read with docker exec", '"$DOCKER" logs --timestamps "$BRIDGE_CONTAINER"',
     '"$DOCKER" exec "$BRIDGE_CONTAINER" cat /proc/1/fd/1'),
    ("S06", S, "empty BRIDGE_CONTAINER still calls docker", '  [ -n "$BRIDGE_CONTAINER" ] || return 1\n', ""),
    ("S07", S, "capture failure returns 0", "    return 4\n  fi\n  for fmt in md json csv; do", "    return 0\n  fi\n  for fmt in md json csv; do"),
    # ---- rules
    ("R01", R, "for: dropped", "        for: 5m\n", "        for: 0m\n"),
    ("R02", R, "flapping alert label not relabelled", 'max by (host, flapping_alert) (', "max by (host) ("),
    ("R03", R, "report-error branch dropped", "          or\n          label_replace(label_replace(max by (host) (pft_alertstats_up) == 0",
     "          or\n          label_replace(label_replace(max by (host) (pft_alertstats_up) == 7"),
    ("R04", R, "flapping threshold > 1", ") == 1,\n", ") > 1,\n"),
]
HANG = (E, "def main(argv=None):\n", "def main(argv=None):\n    import time\n\n    while True:\n        time.sleep(1)\n")


def run(cmd, timeout, env=None, cwd=None):
    """-> (PASS|FAIL|HANG, output). Own session; the whole process group is SIGKILLed on timeout."""
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        env=env,
        cwd=cwd,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return "HANG", ""
    return ("PASS" if p.returncode == 0 else "FAIL"), out


def make_copy(work, name, mutate=None):
    """Copy the alertstats folder (+ rules, rule tests in alerts/) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    shutil.copytree(FW, d, ignore=SKIP)
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in (R, RT):
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
    tmp = os.path.join(d, "tmp")  # own temp base per copy (exec allowed, unlike /tmp)
    os.makedirs(tmp, exist_ok=True)
    return run(
        [sys.executable, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider", f"--basetemp={tmp}/pt", "tests"],
        timeout,
        dict(os.environ, TMPDIR=tmp, TEST_TMPDIR=tmp),
        cwd=d,
    )


def promtool(d, timeout):
    cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "promtool", "-v", f"{d}/alerts:/w:ro"]
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", RT], timeout)


SUMMARY = re.compile(r"^=*\s*(\d+ failed|\d+ error)[^\n]* in [0-9.]+s", re.MULTILINE)


def failing_tests(out):
    return [
        ln.split(" ", 1)[1].split(" ", 1)[0].split("::")[-1]
        for ln in out.splitlines()
        if ln.startswith(("FAILED ", "ERROR "))
    ]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(FW, f)
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
    if not fails or not SUMMARY.search(out):
        last = out.strip().splitlines()[-1:] or [""]
        return mid, "BROKEN", f"- {desc} [suite failed without a summary or a failing test: {last[0][:120]}]"
    return mid, "CAUGHT", f"- {desc} [{len(fails)} failing: {', '.join(fails[:4])}{' ...' if len(fails) > 4 else ''}]"


def main():
    a = sys.argv
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 400
    hang_timeout = int(a[a.index("--hang-timeout") + 1]) if "--hang-timeout" in a else 60
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 3
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="asmut.", dir=base)
    os.chmod(work, 0o755)
    ids = [m[0] for m in MUTANTS]
    if len(ids) != len(set(ids)):
        print("RESULT: duplicate mutant ids")
        return 2
    ctl = make_copy(work, "CONTROL")
    st, out = suite(ctl, timeout)
    summary = [ln.strip("= ") for ln in out.splitlines() if re.search(r"\d+ (passed|failed)", ln)]
    print(f"control baseline suite (unmutated copy): {st} {' / '.join(summary)}", flush=True)
    pst, pout = promtool(ctl, timeout)
    print(
        f"control baseline promtool (unmutated copy): {pst} {pout.strip().splitlines()[-1] if pout.strip() else ''}",
        flush=True,
    )
    shutil.rmtree(ctl)
    hang = make_copy(work, "HANGCTL", HANG)
    t0 = time.monotonic()
    hst, _ = suite(hang, hang_timeout)
    left = subprocess.run(
        ["pgrep", "-af", re.escape(hang)], capture_output=True, text=True, check=False
    ).stdout.splitlines()
    print(
        f"control timeout (helper never returns, --hang-timeout {hang_timeout}): {hst} after "
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
    if os.environ.get("ASMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
        subprocess.Popen(
            ["bash", "-c", "sleep 60; true", os.path.join(work, "orphan-selftest")],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    hits = subprocess.run(
        ["pgrep", "-af", re.escape(work)], capture_output=True, text=True, check=False
    ).stdout.splitlines()
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
