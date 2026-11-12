#!/usr/bin/env python3
"""Mutation harness for pft-selfheal. Each mutant changes exactly one text match in a COPY of the selfheal folder
(decider D*, shell S*) and runs that copy's pytest suite, or changes a copy of ../alerts/selfheal.rules.yml (R*) and
runs `promtool test rules selfheal.tests.yml` on it.

CAUGHT: pytest printed its "N failed ... in Xs" summary and at least one FAILED test line (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose decider never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (SHMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u selfheal/tests/mutate.py [--timeout SEC] [--jobs N] [--only D01,R01,...]
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
SH = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(SH), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
D, S, R = "selfheal_decide.py", "pft-selfheal.sh", "selfheal.rules.yml"
COPY = (D, S, "pft-selfheal.env.example", "ruff.toml", "tests/test_selfheal.py")

# (id, file, description, old text, new text)
MUTANTS = [
    ("D01", D, "default mode enforce", '"MODE": "dryrun",  # dryrun | enforce', '"MODE": "enforce",'),
    (
        "D02",
        D,
        "--dry-run does not force dryrun",
        'conf["MODE"] = "dryrun"\n    if conf["MODE"] not in',
        'pass\n    if conf["MODE"] not in',
    ),
    ("D03", D, "bad MODE accepted", 'if conf["MODE"] not in ("dryrun", "enforce"):', "if False:"),
    ("D04", D, "non-integer threshold accepted", "if not val.isdigit():", "if False:"),
    ("D05", D, "MAX_ACTIONS 0 accepted", 'if conf["MAX_ACTIONS"] < 1 or conf["RPC_FAILS"] < 1:', "if False:"),
    ("D06", D, "unknown state version accepted", 'if not isinstance(st, dict) or st.get("v") != 1:', "if False:"),
    ("D07", D, "rpc streak never counts", 'st["rpc_fail_streak"] += 1\n', 'st["rpc_fail_streak"] += 0\n'),
    ("D08", D, "rpc streak not reset on success", '    st["rpc_fail_streak"] = 0\n    seq =', "    seq ="),
    (
        "D09",
        D,
        "seq_since moves on every sample",
        'if isinstance(seq, int) and seq > 0 and seq != st["last_seq"]:',
        "if isinstance(seq, int) and seq > 0:",
    ),
    (
        "D10",
        D,
        "good state does not clear bad_state_since",
        '        st["bad_state_since"] = None\n    elif',
        "        pass\n    elif",
    ),
    ("D11", D, "zero peers never tracked", "if isinstance(peers, int) and peers == 0:", "if False:"),
    (
        "D12",
        D,
        "running but missing container not down",
        'if not c.get("exists") or not c.get("running"):',
        'if not c.get("exists"):',
    ),
    (
        "D13",
        D,
        "rpc failures fire one sample early",
        'if st["rpc_fail_streak"] >= conf["RPC_FAILS"]:',
        'if st["rpc_fail_streak"] >= conf["RPC_FAILS"] - 1:',
    ),
    (
        "D14",
        D,
        "failed sample judged by the other detectors",
        '        return None, "none", ""  # the other detectors only judge a sample that answered',
        "        pass",
    ),
    (
        "D15",
        D,
        "stale at STALE_SEC is not stale",
        'now - st["seq_since"] >= conf["STALE_SEC"]:',
        'now - st["seq_since"] > conf["STALE_SEC"]:',
    ),
    ("D16", D, "stuck_state detector off", 'if st["bad_state_since"] is not None and now', "if False and now"),
    ("D17", D, "zero_peers detector off", 'if st["zero_peers_since"] is not None and now', "if False and now"),
    ("D18", D, "stale_ledger detector off", 'if st["seq_since"] is not None and now', "if False and now"),
    (
        "D19",
        D,
        "missing reference treated as advancing",
        "        return True\n    ours =",
        "        return False\n    ours =",
    ),
    ("D20", D, "REF_LAG ignored", 'return ref <= ours + conf["REF_LAG"]', "return ref <= ours"),
    (
        "D21",
        D,
        "breaker does not suppress",
        '    if st["breaker"]["open"]:\n        return "breaker"',
        '    if False:\n        return "breaker"',
    ),
    ("D22", D, "maintenance window ignored", 'if g.get("maint_active"):', "if False:"),
    ("D23", D, "data lock ignored", 'if g.get("locks"):', "if False:"),
    (
        "D24",
        D,
        "grace also applies to container_down",
        'if detector != "container_down" and isinstance(started, int)',
        "if isinstance(started, int)",
    ),
    ("D25", D, "grace ignored", 'now - started < conf["GRACE_SEC"]:', "False:"),
    (
        "D26",
        D,
        "network-stall guard also on rpc_failures",
        'if detector in ("stale_ledger", "stuck_state") and network_stalled',
        'if detector in ("stale_ledger", "stuck_state", "rpc_failures") and network_stalled',
    ),
    (
        "D27",
        D,
        "network-stall guard off",
        'and network_stalled(st, obs, conf):\n        return "network_stall"',
        'and False:\n        return "network_stall"',
    ),
    ("D28", D, "backoff not doubled", "(2 ** max(len(recent) - 1, 0))", "1"),
    (
        "D29",
        D,
        "backoff not capped",
        'wait = min(conf["BACKOFF_SEC"] * (2 ** max(len(recent) - 1, 0)), conf["BACKOFF_MAX_SEC"])',
        'wait = conf["BACKOFF_SEC"] * (2 ** max(len(recent) - 1, 0))',
    ),
    ("D30", D, "budget allows K+1", 'if len(recent) >= conf["MAX_ACTIONS"]:', 'if len(recent) > conf["MAX_ACTIONS"]:'),
    (
        "D31",
        D,
        "budget does not open the breaker",
        '    if suppressed == "budget":\n        st["breaker"]',
        '    if False:\n        st["breaker"]',
    ),
    ("D32", D, "dryrun acts", 'if run and conf["MODE"] == "dryrun":', "if False:"),
    (
        "D33",
        D,
        "actions never expire",
        'st["actions"] = [t for t in st["actions"] if now - t < DAY]\n    update_tracking',
        "update_tracking",
    ),
    (
        "D34",
        D,
        "record does not reset tracking",
        '    st["last_action_ts"] = now\n    reset_tracking(st)',
        '    st["last_action_ts"] = now',
    ),
    (
        "D35",
        D,
        "reset keeps the 24h actions",
        '    st["actions"] = []\n    st["last_action_ts"] = None',
        '    st["last_action_ts"] = None',
    ),
    (
        "D36",
        D,
        "reset leaves the breaker open",
        'st["breaker"] = {"open": False, "since": None, "reason": ""}\n    st["actions"] = []',
        'st["actions"] = []',
    ),
    (
        "D37",
        D,
        "unsaveable state still acts",
        "        return 5\n    print(json.dumps(out",
        "        pass\n    print(json.dumps(out",
    ),
    ("S01", S, "restart without timeout", 'restart -t "$RESTART_TIMEOUT" "$CONTAINER"', 'restart "$CONTAINER"'),
    ("S02", S, "compose up recreates", "argv+=(up -d --no-recreate", "argv+=(up -d"),
    (
        "S03",
        S,
        "compose container started with docker start",
        'if [ -n "$project" ] && [ -n "$service" ] && [ -n "$files" ]; then',
        "if false; then",
    ),
    ("S04", S, "egress not reapplied", 'timeout 120 "${EGRESS[@]}" reapply --container "$CONTAINER"', "true"),
    ("S05", S, "unreadable lock state is no lock", "locks='[\"lock state unreadable\"]'", "locks='[]'"),
    (
        "S06",
        S,
        "maintenance window never seen",
        'if timeout 20 "${MAINT[@]}" active >/dev/null 2>&1; then maint=true',
        "if false; then maint=true",
    ),
    ("S07", S, "reference never queried", 'if ref="$(ref_seq)"; then ref_ok=true', "if false; then ref_ok=true"),
    ("S08", S, "empty rpc answer not refused", 'if [ -n "$o" ] && [ "${o:0:1}" = "{" ]; then', "if true; then"),
    ("S09", S, "rpc status not checked", 'select(.status == "success") | .info', ".info"),
    ("S10", S, "--dry-run ignored", 'd="$(SELFHEAL_FORCE_DRYRUN=1 python3', 'd="$(python3'),
    (
        "S11",
        S,
        "action failure exit 0",
        '[ "$arc" = 0 ] || { err="action exit $arc"; rc=1; }',
        '[ "$arc" = 0 ] || { err="action exit $arc"; }',
    ),
    ("S12", S, "healthy runs journaled", '[ "$verdict" = healthy ] || journal', "journal"),
    ("S13", S, "status: breaker exit 0", 'if jq -e .breaker_open <<< "$d" >/dev/null; then return 2; fi', ":"),
    ("S14", S, "status never stale", 'if [ "$age" -gt "$STALE_DECISION_SEC" ]; then', "if false; then"),
    ("S15", S, "reset without reason", '[ -n "$reason" ] || die "reset needs --reason"', "true"),
    ("S16", S, "pull: size not checked", '[ "$size" -le "$MAX_BYTES" ] ||', "true ||"),
    ("S17", S, "pull: foreign label accepted", "if (index(rest, pre) != 1) {", "if (0) {"),
    ("S18", S, "pull: missing up accepted", 'if (!up) { print "no pft_selfheal_up sample"; exit 1 }', ""),
    (
        "S19",
        S,
        "pull: rejected file still installed",
        '    rm -f "$tmp"; die "validation failed: $why" 2',
        '    mv -f "$tmp" "$TEXTFILE_DIR/pft_selfheal_$name.prom"; die "validation failed: $why" 2',
    ),
    ("S20", S, "state dir error not refused (up 1)", 'up=0 err="decider exit $rc"', 'err="decider exit $rc"'),
    (
        "R01",
        R,
        "breaker alert never matches",
        "expr: pft_selfheal_breaker_open == 1",
        "expr: pft_selfheal_breaker_open == 2",
    ),
    ("R02", R, "breaker alert for 3m", "== 1\n        for: 1m", "== 1\n        for: 3m"),
    (
        "R03",
        R,
        "breaker alert warning",
        "for: 1m\n        labels:\n          severity: critical",
        "for: 1m\n        labels:\n          severity: warning",
    ),
    ("R04", R, "stale: up 0 ignored", "expr: pft_selfheal_up == 0 or (time()", "expr: (time()"),
    (
        "R05",
        R,
        "stale: 10 min age",
        "pft_selfheal_run_timestamp_seconds > 300)",
        "pft_selfheal_run_timestamp_seconds > 600)",
    ),
    ("R06", R, "stale: for 1m", "> 300)\n        for: 5m", "> 300)\n        for: 1m"),
]
HANG = (D, "def main(argv):\n", "def main(argv):\n    while True:\n        time.sleep(1)\n")


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
    """Copy the selfheal folder (+ rules, rule tests) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, "tests"))
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "tests"), os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in COPY:
        shutil.copy2(os.path.join(SH, f), os.path.join(d, f))
    for f in (R, "selfheal.tests.yml"):
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
        [sys.executable, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider", "tests"],
        timeout,
        dict(os.environ, TEST_TMPDIR=tmp),
        cwd=d,
    )


def promtool(d, timeout):
    cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "promtool", "-v", f"{d}/alerts:/w:ro"]
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", "selfheal.tests.yml"], timeout)


SUMMARY = re.compile(r"^=*\s*(\d+ failed|\d+ error)[^\n]* in [0-9.]+s", re.MULTILINE)


def failing_tests(out):
    return [
        ln.split(" ", 1)[1].split(" ", 1)[0].split("::")[-1]
        for ln in out.splitlines()
        if ln.startswith(("FAILED ", "ERROR "))
    ]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(SH, f)
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
    work = tempfile.mkdtemp(prefix="shmut.", dir=base)
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
        f"control timeout (decider never returns, --hang-timeout {hang_timeout}): {hst} after "
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
    if os.environ.get("SHMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
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
