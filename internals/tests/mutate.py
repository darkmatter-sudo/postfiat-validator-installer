#!/usr/bin/env python3
"""Mutation harness for pft-internals. Each mutant changes exactly one text match in a COPY of the internals folder
(parser P*, shell S*/V*, report U*) and runs that copy's tests/test_internals.py, or changes a copy of
../alerts/internals.rules.yml (R*) and runs `promtool test rules internals.tests.yml` on it.

CAUGHT: the suite printed its "Ran N tests" summary and at least one FAIL:/ERROR: test (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose parser never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (INMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u internals/tests/mutate.py [--timeout SEC] [--jobs N] [--only P01,R01,...]
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
IN = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(IN), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
P, S, R, U = "internals_parse.py", "pft-internals.sh", "internals.rules.yml", "report_internals.py"
COPY = (P, S, U, "pft-internals.env.example", "tests/test_internals.py")

# (id, file, description, old text, new text)
MUTANTS = [
    (
        "P01",
        P,
        "bool accepted as a count",
        '    if isinstance(v, bool):\n        raise Invalid(f"{where}: boolean',
        '    if False:\n        raise Invalid(f"{where}: boolean',
    ),
    ("P02", P, "negative count accepted", "        if v < 0:\n", "        if False:\n"),
    (
        "P03",
        P,
        "decimal strings of any length",
        'UINT_RE = re.compile(r"^[0-9]{1,20}$")',
        'UINT_RE = re.compile(r"^[0-9]+$")',
    ),
    ("P04", P, "hit-rate range not checked", "    if not 0 <= v <= scale:\n", "    if False:\n"),
    ("P05", P, "NaN/inf hit rate accepted", " or not math.isfinite(v):", ":"),
    (
        "P06",
        P,
        "AL_hit_rate read as a fraction",
        '"AL_hit_rate": ("accepted_ledger", 100.0)',
        '"AL_hit_rate": ("accepted_ledger", 1.0)',
    ),
    ("P07", P, "SLE_hit_rate read as percent", '"SLE_hit_rate": ("SLE", 1.0)', '"SLE_hit_rate": ("SLE", 100.0)'),
    ("P08", P, "dbKB exported as KiB", ' f"get_counts.{k}") * 1024', ' f"get_counts.{k}")'),
    (
        "P09",
        P,
        "rpc status not checked",
        'if not isinstance(r, dict) or r.get("status") != "success":',
        "if not isinstance(r, dict):",
    ),
    (
        "P10",
        P,
        "object type names unchecked",
        'OBJ_RE = re.compile(r"^ripple::([A-Za-z][A-Za-z0-9_:<> ]{0,47})$")',
        'OBJ_RE = re.compile(r"^ripple::(.+)$")',
    ),
    (
        "P11",
        P,
        "RPC method names unchecked",
        'RPC_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")',
        'RPC_RE = re.compile(r"^.+$")',
    ),
    (
        "P12",
        P,
        "job type names unchecked",
        'JOB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")',
        'JOB_RE = re.compile(r"^.+$")',
    ),
    (
        "P13",
        P,
        "job_queue total exported as a job type",
        "            continue\n        if not JOB_RE.match(name):",
        "            pass\n        if not JOB_RE.match(name):",
    ),
    (
        "P14",
        P,
        "rpc total exported as a method",
        "            continue\n        if not RPC_RE.match(name):",
        "            pass\n        if not RPC_RE.match(name):",
    ),
    (
        "P15",
        P,
        "job counter order not checked",
        'if not jobs[name]["finished"] <= jobs[name]["started"] <= jobs[name]["queued"]:',
        "if False:",
    ),
    (
        "P16",
        P,
        "missing counters tolerated",
        'counters = need(info, "counters", "server_info.info (did the node get counters=true?)")',
        'counters = info.get("counters") or {"job_queue": {}, "rpc": {}}',
    ),
    ("P17", P, "duplicate load job_type accepted", "        if name in ljobs:\n", "        if False:\n"),
    ("P18", P, "non-bool over_target accepted", "        if not isinstance(ot, bool):\n", "        if False:\n"),
    (
        "P19",
        P,
        "omitted load field not 0",
        "if f in e else 0 for f in LOAD_FIELDS}",
        "if f in e else 1 for f in LOAD_FIELDS}",
    ),
    ("P20", P, "cap keeps one name too many", "    keep = set(names[: cap - 1])", "    keep = set(names[:cap])"),
    ("P21", P, "cap folds at exactly cap names", "    if len(names) <= cap:", "    if len(names) < cap:"),
    ("P22", P, "other sums peak times", 'if f in ("peak_time", "avg_time", "over_target") else', "if f in () else"),
    (
        "P23",
        P,
        "restart not detected",
        "    if uptime < pu:\n        return True, []",
        "    if False:\n        return True, []",
    ),
    (
        "P24",
        P,
        "anomaly never detected",
        "    dec = sorted(k for k, v in flat.items() if isinstance(pc.get(k), int) and v < pc[k])",
        "    dec = []",
    ),
    ("P25", P, "equal counter is an anomaly", "and v < pc[k])", "and v <= pc[k])"),
    (
        "P26",
        P,
        "restart count not persisted",
        '        "restarts": prev.get("restarts", 0) if isinstance(prev.get("restarts"), int) else 0,',
        '        "restarts": 0,',
    ),
    ("P27", P, "rpc counters not compared", '            flat[f"rpc.{name}.{f}"] = v[f]', "            pass"),
    ("P28", P, "budget not enforced", "    if size + a.reserve > budget:", "    if False:"),
    ("P29", P, "header reserve ignored", "    if size + a.reserve > budget:", "    if size > budget:"),
    ("P30", P, "budget exclusive", "    if size + a.reserve > budget:", "    if size + a.reserve >= budget:"),
    (
        "P31",
        P,
        "last-success ignores state",
        "    print(v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0)",
        "    print(0)",
    ),
    (
        "P32",
        P,
        "STALE at exactly STALE_SEC",
        'status = "STALE" if age > conf["STALE_SEC"] else "OK"',
        'status = "STALE" if age >= conf["STALE_SEC"] else "OK"',
    ),
    ("P33", P, "status always exit 0", '    return 0 if status == "OK" else 4', "    return 0"),
    ("P34", P, "conf ranges not checked", "if not v.isdigit() or not lo <= int(v) <= hi:", "if not v.isdigit():"),
    (
        "P35",
        P,
        "job_waiting = queued - finished",
        'v["queued"] - v["started"]) for k, v in sorted(jobs.items())',
        'v["queued"] - v["finished"]) for k, v in sorted(jobs.items())',
    ),
    (
        "P36",
        P,
        "read duration in ms",
        'num(ns["nodestore_read_duration_us"] / 1e6)',
        'num(ns["nodestore_read_duration_us"] / 1e3)',
    ),
    ("P37", P, "usage errors exit 2", "        die(message, 3)", "        die(message, 2)"),
    (
        "P38",
        P,
        "non-monotonic queued_duration_us compared again",
        "            if f not in NON_MONOTONIC:\n",
        "            if True:\n",
    ),
    (
        "P39",
        P,
        "queue wait typed as a counter",
        '"job_queue_wait_seconds",\n        "gauge",',
        '"job_queue_wait_seconds",\n        "counter",',
    ),
    ("S01", S, "curl without --max-time", 'curl -s --max-time "$RPC_TIMEOUT"', "curl -s"),
    ("S02", S, "server_info without counters", "rpc server_info '{\"counters\":true}'", "rpc server_info '{}'"),
    ("S03", S, "up always 1", 'pft_internals_up{$L} $([ -z "$err" ] && echo 1 || echo 0)', "pft_internals_up{$L} 1"),
    ("S04", S, "failed collect exits 0", '"$err" >&2; return 1; fi', '"$err" >&2; return 0; fi'),
    ("S05", S, "last good file not kept", 'cp -f "$TEXTFILE_DIR/$file" "$STATE_DIR/last-good-$CONTAINER.prom"', "true"),
    (
        "S06",
        S,
        "a failure file overwrites last-good",
        'grep -qx "pft_internals_up{$L} 1" "$TEXTFILE_DIR/$file"',
        "true",
    ),
    ("S07", S, "last success not carried", '  [[ "$last" =~ ^[0-9]+$ ]] || last=0', "  last=0"),
    ("S08", S, "final newline dropped", "    head+=\"$text\"$'\\n'", '    head+="$text"'),
    (
        "S09",
        S,
        "MAX_BYTES not checked",
        '  if ! [[ "$MAX_BYTES" =~ ^[1-9][0-9]{3,4}$ ]] || [ "$MAX_BYTES" -lt 4096 ] || [ "$MAX_BYTES" -gt 65000 ]; then',
        "  if false; then",
    ),
    ("S10", S, "MAX_BYTES upper bound off", ' || [ "$MAX_BYTES" -gt 65000 ]', ""),
    ("S11", S, "MAX_BYTES not passed to the parser", '--max-bytes "$MAX_BYTES" --reserve 1024', "--reserve 1024"),
    ("S12", S, "shell hard gate off", '    if [ "$size" -gt "$MAX_BYTES" ]; then', "    if false; then"),
    ("S13", S, "RPC_TIMEOUT not checked", '[[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad RPC_TIMEOUT"', "true"),
    ("S14", S, "collect scratch dir left behind", '  rm -rf "$work"\n', "  true\n"),
    (
        "S15",
        S,
        "non-root conf sourced",
        '[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"',
        '[ -f "$CONF" ] && . "$CONF"',
    ),
    ("S16", S, "docker stderr glued to the answer", '> "$3" 2>"$4"', '> "$3" 2>&1'),
    ("S17", S, "status --json dropped", "--json) json=(--json) ;;", "--json) ;;"),
    ("V01", S, "validate: size limit off", '[ "$size" -le "$MAX_BYTES" ] ||', "true ||"),
    ("V02", S, "validate: container label not checked", "if (index(rest, pre) != 1) { printf", "if (0) { printf"),
    ("V03", S, "validate: up not required", 'if (!up) { print "no pft_internals_up sample"; exit 1 }', ""),
    (
        "V04",
        S,
        "validate: timestamp not required",
        'if (!ts) { print "no pft_internals_collect_timestamp_seconds sample"; exit 1 }',
        "",
    ),
    (
        "V05",
        S,
        "validate: foreign metric accepted",
        "if (match($0, /^pft_internals_[a-z0-9_]+\\{/) == 0) {",
        "if (match($0, /^[a-z_]+\\{/) == 0) {",
    ),
    (
        "V06",
        S,
        "validate: malformed sample accepted",
        "if (rest !~ /^[^{}]*\\} -?[0-9]+(\\.[0-9]+)?([eE][-+]?[0-9]+)?$/)",
        "if (0)",
    ),
    ("V07", S, "pull: invalid file renamed in", '  if ! why="$(validate "$tmp" "$name")"; then', "  if false; then"),
    (
        "V08",
        S,
        "pull: fetch failure ignored",
        '    rm -f "$tmp"; die "fetch of pft_internals_$name.prom failed" 1',
        "    true",
    ),
    (
        "U01",
        U,
        "nearest rank rounds down",
        "sorted_vals[max(0, math.ceil(q * len(sorted_vals)) - 1)]",
        "sorted_vals[max(0, int(q * len(sorted_vals)) - 1)]",
    ),
    ("U02", U, "NaN counted as a sample", "                if math.isfinite(x):", "                if True:"),
    ("U03", U, "changed query accepted", 'if entry is None or entry.get("query") != q:', "if entry is None:"),
    (
        "U04",
        U,
        "expected samples off by one",
        '(w["end"] - w["start"]) // w["step"] + 1',
        '(w["end"] - w["start"]) // w["step"]',
    ),
    ("U05", U, "rows not sorted by container", 'key=lambda s: s["metric"].get("container", "")', "key=lambda s: 0"),
    (
        "U06",
        U,
        "capture hash not of the raw bytes",
        "hashlib.sha256(raw).hexdigest()",
        'hashlib.sha256(raw + b" ").hexdigest()',
    ),
    ("U07", U, "values not sorted", "            vals.sort()\n", "            pass\n"),
    ("R01", R, "slow: 50 ms", ") > 0.005", ") > 0.05"),
    ("R02", R, "slow: for 10m", "[10m]) > 0.5\n        for: 15m", "[10m]) > 0.5\n        for: 10m"),
    ("R03", R, "slow: read-rate guard off", "\n          and rate(pft_internals_nodestore_reads_total[10m]) > 0.5", ""),
    (
        "R04",
        R,
        "slow: 5m window",
        "rate(pft_internals_nodestore_read_duration_seconds_total[10m])",
        "rate(pft_internals_nodestore_read_duration_seconds_total[5m])",
    ),
    ("R05", R, "cache: 0.5 ratio", ")) < 0.4", ")) < 0.5"),
    ("R06", R, "cache: uptime guard off", "\n          and pft_internals_node_uptime_seconds > 1800", ""),
    (
        "R07",
        R,
        "cache: lookup-rate guard off",
        "\n          and sum without (result) (rate(pft_internals_cached_view_total[15m])) > 0.2",
        "",
    ),
    ("R08", R, "cache: for 20m", "        for: 30m\n", "        for: 20m\n"),
    ("R09", R, "backlog: >= 100", "(pft_internals_job_waiting) > 100", "(pft_internals_job_waiting) >= 100"),
    (
        "R10",
        R,
        "backlog: max instead of sum",
        "sum by (job, instance, container) (pft_internals_job_waiting)",
        "max by (job, instance, container) (pft_internals_job_waiting)",
    ),
    ("R11", R, "backlog: for 5m", "> 100\n        for: 10m", "> 100\n        for: 5m"),
    ("R12", R, "peak: >= 5000", "pft_internals_load_job_peak_ms > 5000", "pft_internals_load_job_peak_ms >= 5000"),
    ("R13", R, "peak: for 5m", "> 5000\n        for: 10m", "> 5000\n        for: 5m"),
    ("R14", R, "stale: up 0 ignored", "expr: pft_internals_up == 0 or (time()", "expr: (time()"),
    ("R15", R, "stale: 600 s", "_collect_timestamp_seconds > 300)", "_collect_timestamp_seconds > 600)"),
    ("R16", R, "stale: for 1m", "> 300)\n        for: 5m", "> 300)\n        for: 1m"),
    (
        "R17",
        R,
        "anomaly: changes() counts a state reset",
        "increase(pft_internals_counter_anomalies_total[30m])",
        "changes(pft_internals_counter_anomalies_total[30m])",
    ),
    ("R18", R, "anomaly: 10m window", "anomalies_total[30m]) > 0", "anomalies_total[10m]) > 0"),
]
HANG = (P, "def main():\n", "def main():\n    while True:\n        time.sleep(1)\n")


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
    """Copy the internals folder (+ fixtures, rules, rule tests) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, "tests"))
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "tests"), os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in COPY:
        shutil.copy2(os.path.join(IN, f), os.path.join(d, f))
    shutil.copytree(os.path.join(HERE, "fixtures"), os.path.join(d, "tests", "fixtures"))
    for f in (R, "internals.tests.yml"):
        shutil.copy2(os.path.join(ALERTS, f), os.path.join(d, "alerts", f))
        os.chmod(os.path.join(d, "alerts", f), 0o644)
    if mutate:
        f, old, new = mutate
        path = os.path.join(d, "alerts", f) if f == R else os.path.join(d, f)
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        if f == P and "time.sleep" in new:
            src = src.replace("import tempfile\n", "import tempfile\nimport time\n", 1)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src.replace(old, new, 1))
    return d


def suite(d, timeout):
    tmp = os.path.join(d, "tmp")  # own temp base per copy
    os.makedirs(tmp, exist_ok=True)
    return run(
        [sys.executable, "-I", os.path.join(d, "tests", "test_internals.py")],
        timeout,
        dict(os.environ, TEST_TMPDIR=tmp),
    )


def promtool(d, timeout):
    cmd = [
        "sudo",
        "-n",
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "promtool",
        "-v",
        f"{d}/alerts:/w:ro",
    ]
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", "internals.tests.yml"], timeout)


def failing_tests(out):
    return [ln.split(" ", 1)[1].split(" ", 1)[0] for ln in out.splitlines() if ln.startswith(("FAIL: ", "ERROR: "))]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(IN, f)
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
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 180
    hang_timeout = int(a[a.index("--hang-timeout") + 1]) if "--hang-timeout" in a else 60
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 2
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="inmut.", dir=base)
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
        f"control timeout (parser never returns, --hang-timeout {hang_timeout}): {hst} after {time.monotonic() - t0:.0f} s, {len(left)} process(es) left",
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
    if os.environ.get("INMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
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
