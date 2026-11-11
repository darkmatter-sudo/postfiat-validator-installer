#!/usr/bin/env python3
"""Mutation harness for pft-peerwatch. Each mutant changes exactly one text match in a COPY of the peerwatch folder
(parser P*, shell S*/V*) and runs that copy's tests/test_peerwatch.py, or changes a copy of
../alerts/peerwatch.rules.yml (R*) and runs `promtool test rules peerwatch.tests.yml` on it.

CAUGHT: the suite printed its "Ran N tests" summary and at least one FAIL:/ERROR: test (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose parser never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (PWMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u peerwatch/tests/mutate.py [--timeout SEC] [--jobs N] [--only P01,R01,...]
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
PW = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(PW), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
P, S, R, U = "peerwatch_parse.py", "pft-peerwatch.sh", "peerwatch.rules.yml", "summarize_peerwatch.py"
COPY = (P, S, U, "pft-peerwatch.env.example", "tests/test_peerwatch.py")

# (id, file, description, old text, new text)
MUTANTS = [
    (
        "P01",
        P,
        "version: rippled-/postfiatd- prefix not stripped",
        'for pre in ("rippled-", "postfiatd-", "xrpld-"):',
        "for pre in ():",
    ),
    (
        "P02",
        P,
        "nearest-rank rounds down",
        "k = max(1, -(-int(q * 100) * len(s) // 100))",
        "k = max(1, int(q * 100) * len(s) // 100)",
    ),
    ("P03", P, "complete_ledgers: lower bound read", 'hi = last.split("-")[-1]', 'hi = last.split("-")[0]'),
    ("P04", P, "rpc status not checked", ' or r.get("status") != "success":', ":"),
    (
        "P05",
        P,
        "entry without public_key not refused by name",
        'if not isinstance(p, dict) or not isinstance(p.get("public_key"), str) or not p["public_key"]:',
        "if not isinstance(p, dict):",
    ),
    (
        "P06",
        P,
        "latency type not checked",
        "if lat is not None and (not isinstance(lat, int) or isinstance(lat, bool) or lat < 0):",
        "if False:",
    ),
    (
        "P07",
        P,
        "peer without inbound field read as inbound",
        '"inbound": p.get("inbound") is True,',
        '"inbound": p.get("inbound") is not False,',
    ),
    ("P08", P, "duplicate public_key accepted", "if len(set(keys)) != len(keys):", "if False:"),
    ("P09", P, "missing server_state accepted", "if not isinstance(state, str):", "if False:"),
    (
        "P10",
        P,
        "below-grades: WARN at the threshold",
        'return "FAIL" if value < fail else "WARN" if value < warn else "PASS"',
        'return "FAIL" if value < fail else "WARN" if value <= warn else "PASS"',
    ),
    (
        "P11",
        P,
        "above-grades: WARN at the threshold",
        'return "FAIL" if value > fail else "WARN" if value > warn else "PASS"',
        'return "FAIL" if value > fail else "WARN" if value >= warn else "PASS"',
    ),
    (
        "P12",
        P,
        "gap never re-baselines",
        'gap = not prev or not isinstance(prev.get("ts"), int) or not 0 <= now - prev["ts"] <= conf["GAP_SEC"]',
        "gap = not prev",
    ),
    ("P13", P, "churn events never leave the window", 'if now - e[0] <= conf["CHURN_WINDOW_MIN"] * 60]', "if True]"),
    ("P14", P, "joins not recorded", 'events.append([now, "join", k])', "pass"),
    (
        "P15",
        P,
        "flapping needs 3 leaves",
        "flapping = sum(1 for k, c in left.items() if c >= 2)",
        "flapping = sum(1 for k, c in left.items() if c >= 3)",
    ),
    (
        "P16",
        P,
        "FLAP_WARN ignored",
        'if g == "PASS" and conf["FLAP_WARN"] and flapping >= conf["FLAP_WARN"]:',
        "if False:",
    ),
    ("P17", P, "latency graded on p50", 'grade(p95, conf["LAT_P95_WARN_MS"]', 'grade(p50, conf["LAT_P95_WARN_MS"]'),
    ("P18", P, "older/newer swapped", '"older" if v < own else "newer"', '"older" if v > own else "newer"'),
    (
        "P19",
        P,
        "outdated share counts newer peers",
        'outdated_pct = 100.0 * rel["older"] / n',
        'outdated_pct = 100.0 * rel["newer"] / n',
    ),
    (
        "P20",
        P,
        "direction graded on all peers",
        'grade(outbound, conf["MIN_OUTBOUND_WARN"]',
        'grade(n, conf["MIN_OUTBOUND_WARN"]',
    ),
    (
        "P21",
        P,
        "inbound (docker gateway) counted in diversity",
        'if p["inbound"] or ip is None or ip.is_loopback',
        "if ip is None or ip.is_loopback",
    ),
    (
        "P22",
        P,
        "private outbound counted by default",
        'if not ip.is_global and conf["COUNT_PRIVATE_OUTBOUND"] != "1":',
        "if False:",
    ),
    ("P23", P, "largest-/16 share rule off", ' or share > conf["PREFIX16_MAX_SHARE_WARN_PCT"]', ""),
    (
        "P24",
        P,
        "/24 computed as /16",
        'str(ipaddress.ip_network(f"{ip}/24", strict=False)),',
        'str(ipaddress.ip_network(f"{ip}/16", strict=False)),',
    ),
    (
        "P25",
        P,
        "peers ahead of us always agree",
        'agree += abs(lag) <= conf["MAX_LEDGER_LAG"]',
        'agree += lag <= conf["MAX_LEDGER_LAG"]',
    ),
    (
        "P26",
        P,
        "lag at MAX_LEDGER_LAG disagrees",
        'agree += abs(lag) <= conf["MAX_LEDGER_LAG"]',
        'agree += abs(lag) < conf["MAX_LEDGER_LAG"]',
    ),
    ("P27", P, "network_id mismatch ignored", "elif wrong_net:", "elif False:"),
    (
        "P28",
        P,
        "own node without validated ledger PASSes",
        'res["ledgers"] = ("WARN", f"own node has no validated ledger',
        'res["ledgers"] = ("PASS", f"own node has no validated ledger',
    ),
    ("P29", P, "cluster members not discovered", 'if not links and conf["FIXED_FROM_CLUSTER"] == "1":', "if False:"),
    ("P30", P, "FIXED_LINKS ignored", 'links = dict(conf["links"])', "links = {}"),
    (
        "P31",
        P,
        "link down graded PASS",
        'res["fixed"] = ("FAIL" if down else "PASS"',
        'res["fixed"] = ("PASS" if down else "PASS"',
    ),
    (
        "P32",
        P,
        "history not trimmed",
        'write_atomic(path, "\\n".join(lines[-keep:]) + "\\n")',
        'write_atomic(path, "\\n".join(lines) + "\\n")',
    ),
    ("P33", P, "status never STALE", 'if age > conf["STALE_SEC"]:', "if False:"),
    ("P34", P, "status STALE at exactly STALE_SEC", 'if age > conf["STALE_SEC"]:', 'if age >= conf["STALE_SEC"]:'),
    ("P35", P, "status exit code ignores the grades", "    return worst\n", "    return 0\n"),
    ("P36", P, "conf ranges not checked", "if not v.isdigit() or not lo <= int(v) <= hi:", "if not v.isdigit():"),
    (
        "P37",
        P,
        "inline conf comments kept",
        '                v = re.split(r"\\s#", v, maxsplit=1)[0]',
        "                pass",
    ),
    (
        "P38",
        P,
        "FIXED_LINKS item shape not checked",
        'if not sep or not tag.isidentifier() or not key.startswith("n") or not key.isalnum():',
        "if not sep:",
    ),
    ("P39", P, "non-object state trusted", "    if not isinstance(s, dict):\n", "    if False:\n"),
    ("P40", P, "local_full always 1", 'int(info["state"] in ("full", "validating", "proposing"))', "1"),
    ("P41", P, "usage errors exit 2", "        die(message, 3)", "        die(message, 2)"),
    (
        "P42",
        P,
        "state written before the answers are checked",
        '    peers, cluster = parse_peers(rpc_result(a.peers, "peers"))\n',
        '    write_atomic(a.state, "{}")\n    peers, cluster = parse_peers(rpc_result(a.peers, "peers"))\n',
    ),
    ("U01", U, "summary: gap threshold 300 s", 'if b["ts"] - a["ts"] > 90]', 'if b["ts"] - a["ts"] > 300]'),
    (
        "U02",
        U,
        "summary: link up counted as down",
        'd["down_samples"] += int(up == 0)',
        'd["down_samples"] += int(up == 1)',
    ),
    (
        "U03",
        U,
        "summary: --from/--to ignored",
        'if (lo is None or r["ts"] >= lo) and (hi is None or r["ts"] <= hi):',
        "if True:",
    ),
    (
        "U04",
        U,
        "summary: in-range churn window ignored",
        "if 0 <= ts - t <= window_s)",
        "if 0 <= ts - t)",
    ),
    ("U05", U, "summary: in-range churn window exclusive", "if 0 <= ts - t <= window_s)", "if 0 <= ts - t < window_s)"),
    (
        "U06",
        U,
        "summary: --churn-window-min ignored",
        "summarize(name, rows, bad, a.lo, a.hi, a.churn_window_min))",
        "summarize(name, rows, bad, a.lo, a.hi))",
    ),
    ("S01", S, "curl without --max-time", 'curl -s --max-time "$RPC_TIMEOUT"', "curl -s"),
    ("S02", S, "docker stderr glued to the answer", '> "$2" 2>"$3"', '> "$2" 2>&1'),
    ("S03", S, "up always 1", 'pft_peerwatch_up{$L} $([ -z "$err" ] && echo 1 || echo 0)', "pft_peerwatch_up{$L} 1"),
    ("S04", S, "failed collect exits 0", '"$err" >&2; return 1; fi', '"$err" >&2; return 0; fi'),
    (
        "S05",
        S,
        "server_info not fetched",
        'elif ! rpc server_info "$work/info.json" "$work/err"; then',
        "elif false; then",
    ),
    (
        "S06",
        S,
        "collect: container name not checked",
        'valid_name "$CONTAINER" || die "bad container name"\n  [[ "$RPC_TIMEOUT"',
        'true\n  [[ "$RPC_TIMEOUT"',
    ),
    (
        "S07",
        S,
        "status: container name not checked",
        'valid_name "$CONTAINER" || die "bad container name"\n  [ -r "$PARSER" ] || die "parser not found: $PARSER"\n  python3',
        'true\n  [ -r "$PARSER" ] || die "parser not found: $PARSER"\n  python3',
    ),
    ("S08", S, "RPC_TIMEOUT not checked", '[[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad RPC_TIMEOUT"', "true"),
    ("S09", S, "collect work dir left behind", '  rm -rf "$work"\n', "  true\n"),
    (
        "S10",
        S,
        "conf owner not checked",
        '[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"',
        '[ -f "$CONF" ] && . "$CONF"',
    ),
    ("S11", S, "status --json dropped", "--json) json=(--json) ;;", "--json) ;;"),
    (
        "S12",
        S,
        "parser failure ignored",
        '    if [ "$rc" != 0 ]; then err="$(head -c 200 "$work/err")"; err="${err:-parser failed (rc $rc)}"',
        '    if false; then err=""',
    ),
    ("V01", S, "validate: size limit off", '[ "$size" -le "$MAX_BYTES" ] ||', "true ||"),
    (
        "V02",
        S,
        "validate: foreign metric accepted",
        "if (match($0, /^pft_peerwatch_[a-z0-9_]+\\{/) == 0)",
        "if (match($0, /^[a-z0-9_]+\\{/) == 0)",
    ),
    ("V03", S, "validate: container label not checked", "if (index(rest, pre) != 1) { printf", "if (0) { printf"),
    (
        "V04",
        S,
        "validate: malformed value accepted",
        "if (rest !~ /^[^{}]*\\} -?[0-9]+(\\.[0-9]+)?([eE][-+]?[0-9]+)?$/)",
        "if (0)",
    ),
    ("V05", S, "validate: up not required", 'if (!up) { print "no pft_peerwatch_up sample"; exit 1 }', ""),
    (
        "V06",
        S,
        "validate: timestamp not required",
        'if (!ts) { print "no pft_peerwatch_collect_timestamp_seconds sample"; exit 1 }',
        "",
    ),
    (
        "V07",
        S,
        "pull: failed validation still renamed",
        'if ! why="$(validate "$tmp" "$name")"; then',
        'if ! why="$(validate "$tmp" "$name")" && false; then',
    ),
    (
        "V08",
        S,
        "pull: failed fetch not stopped",
        'rm -f "$tmp"; die "fetch of pft_peerwatch_$name.prom failed" 1',
        "true",
    ),
    (
        "V09",
        S,
        "pull: PULL_SSH unset not refused",
        '[ -n "$PULL_SSH" ] || die "PULL_SSH not set (see /etc/pft-peerwatch.env)"',
        "true",
    ),
    (
        "R01",
        R,
        "link alert: for 1m",
        "expr: pft_peerwatch_fixed_link_up == 0\n        for: 3m",
        "expr: pft_peerwatch_fixed_link_up == 0\n        for: 1m",
    ),
    (
        "R02",
        R,
        "link alert never matches",
        "expr: pft_peerwatch_fixed_link_up == 0",
        "expr: pft_peerwatch_fixed_link_up < 0",
    ),
    (
        "R03",
        R,
        "link alert severity warning",
        "        for: 3m\n        labels:\n          severity: critical",
        "        for: 3m\n        labels:\n          severity: warning",
    ),
    (
        "R04",
        R,
        "quality alert includes the fixed check",
        'expr: pft_peerwatch_check_status{check!="fixed"} == 2',
        "expr: pft_peerwatch_check_status == 2",
    ),
    (
        "R05",
        R,
        "quality alert fires on WARN",
        'expr: pft_peerwatch_check_status{check!="fixed"} == 2',
        'expr: pft_peerwatch_check_status{check!="fixed"} >= 1',
    ),
    ("R06", R, "quality alert for 10m", "== 2\n        for: 15m", "== 2\n        for: 10m"),
    ("R07", R, "stale: up 0 ignored", "expr: pft_peerwatch_up == 0 or (time()", "expr: (time()"),
    (
        "R08",
        R,
        "stale: 10 min age",
        "pft_peerwatch_collect_timestamp_seconds > 300)",
        "pft_peerwatch_collect_timestamp_seconds > 600)",
    ),
    ("R09", R, "stale: for 1m", "> 300)\n        for: 5m", "> 300)\n        for: 1m"),
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
    """Copy the peerwatch folder (+ fixtures, rules, rule tests) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, "tests"))
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "tests"), os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in COPY:
        shutil.copy2(os.path.join(PW, f), os.path.join(d, f))
    shutil.copytree(os.path.join(HERE, "fixtures"), os.path.join(d, "tests", "fixtures"))
    for f in (R, "peerwatch.tests.yml"):
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
        [sys.executable, "-I", os.path.join(d, "tests", "test_peerwatch.py")],
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
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", "peerwatch.tests.yml"], timeout)


def failing_tests(out):
    return [ln.split(" ", 1)[1].split(" ", 1)[0] for ln in out.splitlines() if ln.startswith(("FAIL: ", "ERROR: "))]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(PW, f)
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
    work = tempfile.mkdtemp(prefix="pwmut.", dir=base)
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
    if os.environ.get("PWMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
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
