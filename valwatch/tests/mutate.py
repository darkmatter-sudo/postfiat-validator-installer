#!/usr/bin/env python3
"""Mutation harness for pft-valwatch. Each mutant changes exactly one text match in a COPY of the valwatch folder
(helper P*, wrapper S*) and runs that copy's full pytest suite, or changes a copy of ../alerts/valwatch.rules.yml
(R*) and runs `promtool test rules valwatch.tests.yml` on it (prom/prometheus:v3.5.0, already on the host, --network
none). Engine taken from ../peertls/tests/mutate.py.

CAUGHT: pytest printed its "N failed ... in Xs" summary and at least one FAILED test line (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose helper never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (VWMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
The suite takes ~20 s unloaded, so --timeout defaults to 300 s.
Usage: TEST_TMPDIR=~/.cache python3 -u valwatch/tests/mutate.py [--timeout SEC] [--jobs N] [--only P01,R01,...]
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
PT = os.path.dirname(HERE)  # the valwatch folder
ALERTS = os.path.join(os.path.dirname(PT), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
SKIP = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".ruff_cache", "logs", "drill", "*.pyc")

P, S, R = "valwatch.py", "pft-valwatch.sh", "valwatch.rules.yml"

# (id, file, description, old text, new text)
MUTANTS = [
    (
        "P01",
        P,
        "collect: any host allowed",
        "return ip.is_loopback or (ip.is_private and not ip.is_link_local)",
        "return True",
    ),
    ("P02", P, "collect: link-local host allowed", "(ip.is_private and not ip.is_link_local)", "ip.is_private"),
    (
        "P03",
        P,
        "UNL: first blob used, not the highest sequence",
        'if best is None or int(j["sequence"]) > int(best["sequence"]):',
        "if best is None:",
    ),
    (
        "P04",
        P,
        "UNL: key format not checked",
        'if not keys or not all(k.startswith("nH") for k in keys):',
        "if not keys:",
    ),
    (
        "P05",
        P,
        "UNL: empty validator list accepted",
        'if not keys or not all(k.startswith("nH") for k in keys):',
        'if not all(k.startswith("nH") for k in keys):',
    ),
    ("P06", P, "sink: no age pruning", "now_s - (hour + 3600) > self.retain_s", "False"),
    ("P07", P, "sink: no byte-cap pruning", "if total <= self.max_bytes or f == self.cur_name:", "if True:"),
    ("P08", P, "collect: partial validations stored as full", '"f": bool(msg.get("full")),', '"f": True,'),
    ("P09", P, "collect: refused subscribe ignored", 'if msg.get("status") != "success":', "if False:"),
    ("P10", P, "collect: no reconnect backoff", "backoff = min(backoff * 2, 60)", "backoff = 1"),
    ("P11", P, "load: line length cap not applied", "if len(line) > MAX_LINE:", "if False:"),
    ("P12", P, "load: non-UNL validations kept", 'if t == "V" and rec.get("k") not in unl_union:', "if False:"),
    (
        "P13",
        P,
        "load: far-older hour files opened",
        "if t_from is not None and hour + 3600 <= t_from - CARRY_HOURS * 3600:",
        "if False:",
    ),
    (
        "P14",
        P,
        "load: oldest U/Q carried in, not the newest",
        'if t in ("U", "Q") and r >= carry.get(t, {}).get("r", -1):',
        'if t in ("U", "Q") and t not in carry:',
    ),
    ("P15", P, "load: records after --to kept", "elif t_to is None or r < t_to * 1000:", "else:"),
    ("P16", P, "load: hour file not sorted", "        recs.sort(key=rec_order)\n", ""),
    (
        "P17",
        P,
        "pct: floor rank instead of nearest rank",
        "k = max(1, -(-p * len(s) // 100))",
        "k = max(1, p * len(s) // 100)",
    ),
    (
        "P18",
        P,
        "analyze: quorum 0 sample replaces the known quorum",
        'quorum = int(rec["q"]) or quorum',
        'quorum = int(rec["q"])',
    ),
    ("P19", P, "analyze: connects counted as reconnects", 'if rec.get("ev") == "disconnect":', "if True:"),
    (
        "P20",
        P,
        "analyze: ledgers graded without a quorum",
        "if unl is not None and quorum is not None:",
        "if unl is not None:",
    ),
    ("P21", P, "analyze: partial validations counted", 'elif t == "V" and rec.get("f"):', 'elif t == "V":'),
    (
        "P22",
        P,
        "analyze: latest duplicate validation wins",
        'vals.setdefault((int(rec["i"]), rec["h"]), {}).setdefault(rec["k"], rec["r"])',
        'vals.setdefault((int(rec["i"]), rec["h"]), {})[rec["k"]] = rec["r"]',
    ),
    (
        "P23",
        P,
        "analyze: no edge at the window start",
        "lo = first_ms + EDGE_MS if n else 0",
        "lo = first_ms if n else 0",
    ),
    ("P24", P, "analyze: no edge at the window end", "hi = last_ms - EDGE_MS if n else 0", "hi = last_ms if n else 0"),
    (
        "P25",
        P,
        "analyze: last L record per index wins",
        'ledgers.setdefault(idx, {"h": h, "r": r, "q": q, "keys": keys})',
        'ledgers[idx] = {"h": h, "r": r, "q": q, "keys": keys}',
    ),
    (
        "P26",
        P,
        "analyze: validations for any hash of the index count",
        'got = vals.get((idx, lg["h"]), {})',
        "got = {k: v for (i, _h), d in vals.items() if i == idx for k, v in d.items()}",
    ),
    (
        "P27",
        P,
        "analyze: non-UNL validators counted as trusted",
        'trusted = {k: r for k, r in got.items() if k in lg["keys"]}',
        "trusted = dict(got)",
    ),
    (
        "P28",
        P,
        "analyze: delay measured from the last validation",
        "first = min(trusted.values()) if trusted else None",
        "first = max(trusted.values()) if trusted else None",
    ),
    (
        "P29",
        P,
        "analyze: margin off by one",
        'margins[idx] = len(trusted) - lg["q"]',
        'margins[idx] = len(trusted) - lg["q"] + 1',
    ),
    (
        "P30",
        P,
        "flags: participation equal to the threshold flagged",
        "if part is not None and part < min_participation:",
        "if part is not None and part <= min_participation:",
    ),
    (
        "P31",
        P,
        "flags: p95 equal to the threshold flagged late",
        "if p95 is not None and p95 > warn_delay_ms:",
        "if p95 is not None and p95 >= warn_delay_ms:",
    ),
    ("P32", P, "flags: silent never set", 'if p["expected"] and not p["agreed"]:', "if False:"),
    ("P33", P, "margin: ledgers at the minimum counted below", "if v < min_margin)", "if v <= min_margin)"),
    ("P34", P, "report: exit 0 without graded ledgers", 'return 0 if rep["ledgers"] else 4', "return 0"),
    (
        "P35",
        P,
        "textfile: validator series not capped",
        'vals = list(rep["validators"].items())[:MAX_VALIDATORS]',
        'vals = list(rep["validators"].items())',
    ),
    ("P36", P, "textfile: up 1 without graded ledgers", 'ok = 1 if rep["ledgers"] else 0', "ok = 1"),
    (
        "P37",
        P,
        "compare: hash mismatches ignored",
        'hash_mismatch = [i for i in common if la[i]["h"] != lb[i]["h"]]',
        "hash_mismatch = []",
    ),
    (
        "P38",
        P,
        "compare: participation tolerance ignored",
        "ok = dp <= tol_part and (dd is None or dd <= tol_delay_ms)",
        "ok = dd is None or dd <= tol_delay_ms",
    ),
    (
        "P39",
        P,
        "compare: delay tolerance ignored",
        "ok = dp <= tol_part and (dd is None or dd <= tol_delay_ms)",
        "ok = dp <= tol_part",
    ),
    ("P40", P, "compare: UNL difference not reported", "if ea != eb or pa is None:", "if pa is None:"),
    (
        "P41",
        P,
        "compare: AGREE without common ledgers",
        "agree = bool(common) and not hash_mismatch",
        "agree = not hash_mismatch",
    ),
    ("P42", P, "compare: margin tolerance ignored", "and mmax <= tol_margin ", ""),
    (
        "S01",
        S,
        "endpoint: non-loopback publication used",
        r"^127\.0\.0\.1:([0-9]{1,5})$",
        "^[0-9.]+:([0-9]{1,5})$",
    ),
    ("S02", S, "endpoint: two publisher caches accepted", '[ "${#caches[@]}" = 1 ] ||', "true ||"),
    ("S03", S, "endpoint: missing db mount accepted", '[ -d "${src:-/nonexistent}" ] ||', "true ||"),
    ("S04", S, "textfile: MAX_BYTES not enforced", '[ "$size" -le "$MAX_BYTES" ] || err=', "true || err="),
    ("S05", S, "textfile: helper failure written as data", '[ "$rc" = 0 ] || err=', "true || err="),
    ("S06", S, "validate: first label not checked", "if (index(rest, pre) != 1)", "if (0)"),
    ("S07", S, "validate: missing up sample accepted", "if (!up) {", "if (0) {"),
    (
        "S08",
        S,
        "pull: fetched file renamed without validation",
        'if ! why="$(validate "$tmp" "$CONTAINER")"; then',
        "if false; then",
    ),
    ("S09", S, "conf: RETAIN_HOURS range not checked", 'in_range "$RETAIN_HOURS" 3 8760 ||', "true ||"),
    (
        "S10",
        S,
        "validate: size not checked",
        '[ "$size" -le "$MAX_BYTES" ] || { echo "too big',
        'true || { echo "too big',
    ),
    (
        "R01",
        R,
        "ValidatorLow threshold 0.8 -> 0.7",
        "expr: pft_valwatch_validator_participation_ratio < 0.8",
        "expr: pft_valwatch_validator_participation_ratio < 0.7",
    ),
    (
        "R02",
        R,
        "ValidatorLow fires while the node is not graded",
        "expr: pft_valwatch_validator_participation_ratio < 0.8 and on (job, instance, node) pft_valwatch_up == 1",
        "expr: pft_valwatch_validator_participation_ratio < 0.8",
    ),
    (
        "R03",
        R,
        "ValidatorLate threshold 3000 -> 3500",
        "expr: pft_valwatch_validator_delay_p95_ms > 3000",
        "expr: pft_valwatch_validator_delay_p95_ms > 3500",
    ),
    (
        "R04",
        R,
        "QuorumMarginLow threshold 2 -> 1",
        "pft_valwatch_quorum_margin_min < 2",
        "pft_valwatch_quorum_margin_min < 1",
    ),
    (
        "R05",
        R,
        "QuorumMarginCritical threshold 1 -> 0",
        "pft_valwatch_quorum_margin_p50 < 1",
        "pft_valwatch_quorum_margin_p50 < 0",
    ),
    ("R06", R, "Stale ignores up 0", "pft_valwatch_up == 0\n          or (time()", "(time()"),
    (
        "R07",
        R,
        "Stale textfile age 300 -> 3000",
        "pft_valwatch_collect_timestamp_seconds) > 300",
        "pft_valwatch_collect_timestamp_seconds) > 3000",
    ),
    (
        "R08",
        R,
        "Stale record age 300 -> 3000",
        "pft_valwatch_last_record_age_seconds > 300",
        "pft_valwatch_last_record_age_seconds > 3000",
    ),
    ("R09", R, "Reconnecting threshold 3 -> 4", "pft_valwatch_reconnects > 3", "pft_valwatch_reconnects > 4"),
    (
        "R10",
        R,
        "QuorumMarginCritical for 5m -> 1m",
        "pft_valwatch_up == 1\n        for: 5m",
        "pft_valwatch_up == 1\n        for: 1m",
    ),
    (
        "R11",
        R,
        "QuorumMarginLow for 10m -> 5m",
        "pft_valwatch_quorum_margin_min < 2 and on (job, instance, node) pft_valwatch_up == 1\n        for: 10m",
        "pft_valwatch_quorum_margin_min < 2 and on (job, instance, node) pft_valwatch_up == 1\n        for: 5m",
    ),
    ("R12", R, "QuorumMarginCritical severity critical -> warning", "severity: critical", "severity: warning"),
    # 2026-11-19 paging rule: other validators digest-only, our two nodes disagreeing pages
    (
        "R13",
        R,
        "ValidatorLow paged again (digest label dropped)",
        '          notify: digest\n        annotations:\n          summary: "UNL validator {{ $labels.validator }} is missing',
        '        annotations:\n          summary: "UNL validator {{ $labels.validator }} is missing',
    ),
    (
        "R14",
        R,
        "ValidatorLate paged again (digest label dropped)",
        '          notify: digest\n        annotations:\n          summary: "UNL validator {{ $labels.validator }} validations arrive',
        '        annotations:\n          summary: "UNL validator {{ $labels.validator }} validations arrive',
    ),
    ("R15", R, "HostsDisagree other-node floor 0.95 -> 0.9", ">= 0.95", ">= 0.9"),
    (
        "R16",
        R,
        "HostsDisagree without the other-node clause (pages on external outages)",
        "          and on (validator)\n          (pft_valwatch_validator_participation_ratio >= 0.95",
        "          or on (validator)\n          (pft_valwatch_validator_participation_ratio >= 0.95",
    ),
    (
        "R17",
        R,
        "HostsDisagree grades a blind other node",
        "(pft_valwatch_validator_participation_ratio >= 0.95 and on (job, instance, node) pft_valwatch_up == 1)",
        "(pft_valwatch_validator_participation_ratio >= 0.95)",
    ),
    ("R18", R, "HostsDisagreeLate other-node ceiling 2000 -> 2001", "<= 2000", "<= 2001"),
    (
        "R19",
        R,
        "HostsDisagreeLate threshold 3000 -> 3500",
        "(pft_valwatch_validator_delay_p95_ms > 3000 and on",
        "(pft_valwatch_validator_delay_p95_ms > 3500 and on",
    ),
]

HANG = (
    P,
    "def main(argv=None):\n",
    "def main(argv=None):\n    import time\n\n    while True:\n        time.sleep(1)\n",
)


def run(cmd, timeout, env=None, cwd=None, scope=None):
    """-> (PASS|FAIL|HANG, output). Own session; the whole process group is SIGKILLed on timeout, and so is every
    process that names `scope` (the copy's dir): the s_server fixtures run in their own sessions (their teardown
    killpg's them), so a hung suite would otherwise leave them behind."""
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
        if scope:
            left = subprocess.run(["pgrep", "-f", re.escape(scope)], capture_output=True, text=True, check=False)
            for pid in (int(x) for x in left.stdout.split()):
                if pid != os.getpid():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            time.sleep(1)
        return "HANG", ""
    return ("PASS" if p.returncode == 0 else "FAIL"), out


def make_copy(work, name, mutate=None):
    """Copy the valwatch folder (+ rules, rule tests in alerts/) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    shutil.copytree(PT, d, ignore=SKIP)
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in (R, "valwatch.tests.yml"):
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
        scope=d,
    )


def promtool(d, timeout):
    cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "promtool", "-v", f"{d}/alerts:/w:ro"]
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", "valwatch.tests.yml"], timeout)


SUMMARY = re.compile(r"^=*\s*(\d+ failed|\d+ error)[^\n]* in [0-9.]+s", re.MULTILINE)


def failing_tests(out):
    return [
        ln.split(" ", 1)[1].split(" ", 1)[0].split("::")[-1]
        for ln in out.splitlines()
        if ln.startswith(("FAILED ", "ERROR "))
    ]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(PT, f)
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
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 300
    hang_timeout = int(a[a.index("--hang-timeout") + 1]) if "--hang-timeout" in a else 60
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 6
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="vwmut.", dir=base)
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
    if os.environ.get("VWMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
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
