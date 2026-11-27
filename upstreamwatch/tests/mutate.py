#!/usr/bin/env python3
"""Mutation harness for upstreamwatch local_lagging + bounded heal (task: lagging feed detection and bounded vulnscan
healing). Each mutant changes exactly one text match in a COPY and runs that copy's checks:
  P* upstreamwatch_lib.py, S* pft-upstreamwatch.sh  -> the copy's full pytest suite (upstreamwatch/tests)
  R* ../alerts/upstreamwatch.rules.yml               -> `promtool test rules upstreamwatch.tests.yml vulnscan.tests.yml`
                                                        (prom/prometheus:v3.16.0, already on the host, --network none)
  V* ../vulnscan/pft-vulnscan.sh                     -> the copy's bash tests/run-tests.sh (stub curl/oscap + real oscap)
Engine taken from ../valwatch/tests/mutate.py.

CAUGHT: pytest printed its "N failed ... in Xs" summary and at least one FAILED test line (promtool: exit != 0 with
"FAILED"; run-tests.sh: exit != 0 with a RESULT line and at least one FAIL line), or it hung and its process group was
SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant whose old text does not match exactly once is
NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass pytest, promtool and run-tests.sh;
  timeout   a copy whose helper never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (UWMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
Usage: TEST_TMPDIR=$HOME/.cache python3 -u upstreamwatch/tests/mutate.py [--timeout SEC] [--jobs N] [--only P01,...]
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
PT = os.path.dirname(HERE)  # the upstreamwatch folder
REPO = os.path.dirname(PT)
ALERTS = os.path.join(REPO, "alerts")
VS = os.path.join(REPO, "vulnscan")
PROMTOOL_IMAGE = "prom/prometheus:v3.16.0"
SKIP = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".ruff_cache", "logs", "drill", "reports", "*.pyc")

P, S, R, V = "upstreamwatch_lib.py", "pft-upstreamwatch.sh", "upstreamwatch.rules.yml", "pft-vulnscan.sh"
RULE_FILES = ("upstreamwatch.rules.yml", "vulnscan.rules.yml", "upstreamwatch.tests.yml", "vulnscan.tests.yml")

# (id, file, description, old text, new text)
MUTANTS = [
    ("P01", P, "lag within grace reported ok (the old blind spot)", 'r["state"] = "local_lagging"', 'r["state"] = "ok"'),
    ("P02", P, "lag not clamped at 0 (future Last-Modified within skew)", "missed = max(0, up_date - up_content)",
     "missed = up_date - up_content"),
    ("P03", P, "lag left unknown when our copy is the latest", '    r["lag"] = 0\n    if r["content_age"] > quiet:',
     '    if r["content_age"] > quiet:'),
    ("P04", P, "grace boundary > -> >= (lag == grace pages)", 'if missed > int(cfg["stale_grace_hours"]) * 3600:',
     'if missed >= int(cfg["stale_grace_hours"]) * 3600:'),
    ("P05", P, "heal threshold <= -> < (lag == LAG_HEAL_HOURS heals)", 'if f.get("lag") is None or f["lag"] <= lag_max:',
     'if f.get("lag") is None or f["lag"] < lag_max:'),
    ("P06", P, "rate-limit boundary < -> <= (exactly HEAL_INTERVAL_HOURS still blocked)", "elif last and now - last < interval:",
     "elif last and now - last <= interval:"),
    ("P07", P, "no rate limit", "elif last and now - last < interval:", "elif False:"),
    ("P08", P, "maintenance guard removed", "        elif maint:\n", "        elif False:\n"),
    ("P09", P, "running-unit guard removed", "        elif running:\n", "        elif False:\n"),
    ("P10", P, "imagescan/reference feeds healed too",
     'if f.get("local") not in HEALABLE or f["state"] not in ("local_lagging", "local_stale"):',
     'if f["state"] not in ("local_lagging", "local_stale"):'),
    ("P11", P, "local_stale (lag beyond grace) not healed",
     'f["state"] not in ("local_lagging", "local_stale"):\n            continue', 'f["state"] != "local_lagging":\n            continue'),
    ("P12", P, "LAG_HEAL_HOURS=0 does not disable", "if lag_max == 0:", "if False:"),
    ("P13", P, "attempts not counted", 'e["attempts"] = int(e.get("attempts", 0)) + 1', 'e["attempts"] = 1'),
    ("P14", P, "every result moves the rate-limit clock", 'if result == "started":', "if True:"),
    ("P15", P, "obs copy of the heal state not updated", '        obs["heal"] = st\n', "        pass\n"),
    ("P16", P, "lag metric not exported",
     '        ("feed_lag_seconds", "lag", "how long upstream has had content our copy lacks (0 = our copy is the latest)"),\n', ""),
    ("P17", P, "heal result not one-hot", """f'{1 if v.get("last_result") == s else 0}'""", """f'{1 if v.get("last_result") else 0}'"""),
    ("P18", P, "heal state not collected into the observations", 'obs["heal"] = read_heal_state(cfg.get("heal_state", ""))',
     'obs["heal"] = {}'),
    ("P19", P, "unknown heal result accepted", "    if result not in HEAL_RESULTS:\n", "    if False:\n"),
    ("S01", S, "malformed/unknown maint state no longer blocks", '[ "$mrc" -eq 1 ] || maint=1', '[ "$mrc" -eq 0 ] && maint=1'),
    ("S02", S, "busy units ignored", '"$SYSTEMCTL" is-active --quiet "$u" && running=1', 'true'),
    ("S03", S, "heal lock not taken", "if ! flock -n 8; then", "if false; then"),
    ("S04", S, "start not persisted before the unit runs", "--result started \\\n      --note", "--result healed \\\n      --note"),
    ("S05", S, "no re-collect after the heal", '    ran=1\n    collect_obs "$1" "$2"\n', "    ran=1\n"),
    ("S06", S, "every heal reported healed", 'if [ "$lag" = 0 ]; then result=healed', "if true; then result=healed"),
    ("S07", S, "failed unit start treated as success", 'if [ "$hrc" -ne 0 ]; then', "if false; then"),
    ("S08", S, "--no-heal ignored", "--no-heal) doheal=0 ;;", "--no-heal) ;;"),
    ("S09", S, "LAG_HEAL_HOURS not validated", '[[ "$LAG_HEAL_HOURS" =~ ^[0-9]{1,4}$ ]] || die', "true || die"),
    ("S10", S, "HEAL_UNIT not validated", '[[ "$HEAL_UNIT" =~ ^[a-zA-Z0-9@_.-]+\\.service$ ]] || die "bad HEAL_UNIT"', "true"),
    ("S11", S, "heal journal not written", '> "$HEAL_JOURNAL.tmp" && mv -f "$HEAL_JOURNAL.tmp" "$HEAL_JOURNAL"', "> /dev/null"),
    ("S12", S, "heal started without a decision", 'if [ "$action" != heal ]; then heal_log', 'if false; then heal_log'),
    ("R01", R, "PFTUpstreamFeedLagging pages (notify digest dropped)",
     '        for: 3h\n        labels:\n          severity: info\n          notify: digest\n',
     '        for: 3h\n        labels:\n          severity: info\n'),
    ("R02", R, "PFTUpstreamFeedLagging for 3h -> 1h (fires inside the heal window)", 'state="local_lagging"} == 1\n        for: 3h',
     'state="local_lagging"} == 1\n        for: 1h'),
    ("R03", R, "PFTUpstreamFeedLagging selects local_stale", 'pft_upstreamwatch_feed_state{state="local_lagging"} == 1',
     'pft_upstreamwatch_feed_state{state="local_stale"} == 1'),
    ("V01", V, "scan --force-fetch ignored", "--force-fetch) force=force ;;", "--force-fetch) ;;"),
    ("V02", V, "forced GET without the cache-busting query", 'url="${url}pft-vulnscan-nocache=$(now)"', 'url="${url%[?&]}"'),
    ("V03", V, "cache lock never waited for", 'flock -w "$LOCK_WAIT" 7 ||', "true ||"),
    ("V04", V, "scan does not take the lock", '  lock\n  t0="$(now)"', '  t0="$(now)"'),
    ("V05", V, "fetch --force ignored", "--force) f=force ;;", "--force) ;;"),
    ("V06", V, "--no-fetch with --force-fetch accepted", '|| die "--no-fetch and --force-fetch exclude each other"', "|| true"),
    ("V07", V, "forced GET keeps the ETag", '    etag_args=(-H "Cache-Control: no-cache")\n',
     '    etag_args=(--etag-compare "$CACHE_DIR/feed.etag" -H "Cache-Control: no-cache")\n'),
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
    """Copy upstreamwatch (+ rules/rule tests in alerts/, vulnscan in vulnscan/) into work/name; mutate = (file, old,
    new) or None."""
    d = os.path.join(work, name)
    shutil.copytree(PT, d, ignore=SKIP)
    shutil.copytree(VS, os.path.join(d, "vulnscan"), ignore=SKIP)
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in RULE_FILES:
        shutil.copy2(os.path.join(ALERTS, f), os.path.join(d, "alerts", f))
        os.chmod(os.path.join(d, "alerts", f), 0o644)
    if mutate:
        f, old, new = mutate
        path = {R: os.path.join(d, "alerts", f), V: os.path.join(d, "vulnscan", f)}.get(f, os.path.join(d, f))
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
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", "upstreamwatch.tests.yml", "vulnscan.tests.yml"], timeout)


def vsuite(d, timeout):
    tmp = os.path.join(d, "tmp")
    os.makedirs(tmp, exist_ok=True)
    return run(["bash", os.path.join(d, "vulnscan", "tests", "run-tests.sh")], timeout,
               dict(os.environ, TMPDIR=tmp, TEST_TMPDIR=tmp), cwd=d, scope=d)


PROMQL_FAIL = re.compile(r'expr: "ALERTS\{alertname=\\"(\w+)\\"\}", time: (\w+),')
SUMMARY = re.compile(r"^=*\s*(\d+ failed|\d+ error)[^\n]* in [0-9.]+s", re.MULTILINE)


def failing_tests(out):
    return [
        ln.split(" ", 1)[1].split(" ", 1)[0].split("::")[-1]
        for ln in out.splitlines()
        if ln.startswith(("FAILED ", "ERROR "))
    ]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = {R: os.path.join(ALERTS, f), V: os.path.join(VS, f)}.get(f, os.path.join(PT, f))
    with open(src_path, encoding="utf-8") as fh:
        n = fh.read().count(old)
    if n != 1:
        return mid, "NOT APPLIED", f"({n} matches in {f}) - {desc}"
    d = make_copy(work, mid, (f, old, new))
    st, out = promtool(d, timeout) if f == R else (vsuite(d, timeout) if f == V else suite(d, timeout))
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
        # promql_expr_test failures carry no test name: name them by the queried ALERTS series and eval time
        exprs = PROMQL_FAIL.findall(out)
        if exprs:
            shown = ", ".join(f"{a}@{t}" for a, t in exprs[:3]) + (f" +{len(exprs) - 3} more" if len(exprs) > 3 else "")
            names = [f"ALERTS {shown}"] + names
        return mid, "CAUGHT", f"- {desc} [promtool FAILED: {'; '.join(names)[:220]}]"
    if f == V:
        vfails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
        if not vfails or "RESULT:" not in out:
            return mid, "BROKEN", f"- {desc} [run-tests.sh failed without RESULT/FAIL lines: {out.strip()[-120:]}]"
        return mid, "CAUGHT", f"- {desc} [{len(vfails)} FAIL: {'; '.join(vfails[:2])[:200]}]"
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
    work = tempfile.mkdtemp(prefix="uwmut.", dir=base)
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
    vst, vout = vsuite(ctl, timeout)
    print(f"control baseline run-tests.sh (unmutated vulnscan copy): {vst} {[ln for ln in vout.splitlines() if ln.startswith('RESULT')]}",
          flush=True)
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
    if st != "PASS" or pst != "PASS" or vst != "PASS" or hst != "HANG" or left:
        print("RESULT: control run failed, mutants not run")
        shutil.rmtree(work)
        return 2
    selected = [m for m in MUTANTS if only is None or m[0] in only]
    res = {}
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for mid, status, text in ex.map(lambda m: one(work, timeout, m), selected):
            res[mid] = status
            print(f"{mid} {status} {text}", flush=True)
    if os.environ.get("UWMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
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
