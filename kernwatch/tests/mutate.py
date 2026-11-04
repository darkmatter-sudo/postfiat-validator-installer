#!/usr/bin/env python3
"""Mutation harness for pft-kernwatch: each mutant changes exactly one text match in ONE file of a full copy of the
module (pft-kernwatch.sh, kernwatch_parse.py, catalogue.tsv) and runs tests/test_kernwatch.py against that copy
(KW_DIR); rule mutants (R*) change ../alerts/kernwatch.rules.yml in a copy and run `promtool test rules`.

A mutant is CAUGHT if its suite fails with a RESULT line and at least one FAIL line (promtool: exit != 0 with
"FAILED"), or hangs (process group SIGKILLed at --timeout). A failing suite without them is BROKEN. A mutant whose old
text does not match exactly once is NOT APPLIED. The unmutated control runs from a copy in the same place and must
pass first. Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan process fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u kernwatch/tests/mutate.py [--timeout SEC] [--jobs N] [--only M01,R01,...]
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
KW = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(KW), "alerts")
SUITE = os.path.join(HERE, "test_kernwatch.py")
FILES = ("pft-kernwatch.sh", "kernwatch_parse.py", "catalogue.tsv")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
P, S, C, R = (
    "kernwatch_parse.py",
    "pft-kernwatch.sh",
    "catalogue.tsv",
    "kernwatch.rules.yml",
)

# (id, file, description, old text, new text)
MUTANTS = [
    # catalogue validation
    (
        "M01",
        P,
        "catalogue: 3-field lines accepted",
        "if len(parts) != 4:",
        "if len(parts) > 4:",
    ),
    ("M02", P, "catalogue: duplicate ids accepted", "or pid in seen:", "or False:"),
    (
        "M03",
        P,
        "catalogue: any severity accepted",
        "if sev not in SEVERITIES:",
        "if False:",
    ),
    (
        "M04",
        P,
        "catalogue: missing version accepted",
        "if version is None:",
        "if False:",
    ),
    # classification
    (
        "M05",
        P,
        "classify: last match wins instead of first",
        "for e in entries:",
        "for e in reversed(entries):",
    ),
    (
        "M06",
        C,
        "catalogue: OOM kill pattern loosened to any 'Killed process'",
        "^Out of memory: Killed process \\d+ \\(",
        "Killed process",
    ),
    (
        "M07",
        C,
        "catalogue: link_down exclusion of veth/docker/bridge dropped",
        "^(?!.*\\b(veth|docker\\d|br-)\\S*).*\\bLink is Down\\b",
        ".*\\bLink is Down\\b",
    ),
    (
        "M08",
        C,
        "catalogue: hung_task demoted to warn",
        "hung_task\tcrit",
        "hung_task\twarn",
    ),
    ("M09", C, "catalogue: martian promoted to warn", "martian\tinfo", "martian\twarn"),
    (
        "M10",
        C,
        "catalogue: clocksource fallback also matches tsc",
        "(hpet|acpi_pm|refined-jiffies|jiffies)\\b",
        "\\S+",
    ),
    # redaction
    ("M11", P, "redact: MAC addresses kept", 's = MAC_RE.sub("<mac>", s)', "pass"),
    (
        "M12",
        P,
        "redact: header byte dumps kept",
        's = BYTES_RE.sub("<bytes>", s)',
        "pass",
    ),
    ("M13", P, "redact: IPv4 kept", "s = IPV4_RE.sub(_v4, s)", "pass"),
    ("M14", P, "redact: IPv6 kept", "s = IPV6_CAND_RE.sub(_v6, s)", "pass"),
    ("M15", P, "redact: home paths kept", 's = HOME_RE.sub("<home>", s)', "pass"),
    (
        "M16",
        P,
        "redact: host name kept",
        's = re.sub(re.escape(name), "<host>", s, flags=re.IGNORECASE)',
        "pass",
    ),
    ("M17", P, "redact: long numbers kept", 's = NUM_RE.sub("<n>", s)', "pass"),
    # journal reading
    ("M18", P, "read: --max limit ignored", "if len(lines) >= limit:", "if False:"),
    (
        "M19",
        P,
        "read: journalctl failure ignored",
        "if not stopped and rc != 0:",
        "if False:",
    ),
    (
        "M20",
        P,
        "read: cursor error treated as a hard failure",
        '"seek to cursor" in msg',
        "False",
    ),
    (
        "M21",
        P,
        "parse: monotonic field not validated",
        "and mono.isdigit()",
        "and True",
    ),
    (
        "M22",
        P,
        "parse: byte-array MESSAGE not decoded",
        'm = bytes(m).decode("utf-8", "replace")',
        "pass",
    ),
    ("M23", P, "malformed: not counted", 'st["malformed_total"] += 1', "pass"),
    (
        "M24",
        P,
        "malformed: cursor not advanced past a malformed record with a cursor",
        "            if cur:\n",
        "            if False:\n",
    ),
    # cursor / rotation / boot
    (
        "M25",
        P,
        "rotation: monotonic guard dropped (double count)",
        'guard_mono is not None and rec["mono"] <= guard_mono',
        "False",
    ),
    ("M26", P, "rotation: reset not counted", 'st["cursor_resets_total"] += 1', "pass"),
    (
        "M27",
        P,
        "rotation: re-read from the boot start instead of --since",
        'base + ["--since", f"@{max(st[\'rt\'] - 1, 0)}"], budget',
        "base, budget",
    ),
    (
        "M28",
        P,
        "boot: records of another boot not skipped",
        'if rec["boot"] != boot or (',
        "if False or (",
    ),
    (
        "M29",
        P,
        "boot: old boot tail skipped",
        'run["truncated"] = read_boot(\n                        st, entries, st["boot"], run, budget, False\n                    )',
        "pass",
    ),
    (
        "M30",
        P,
        "boot: missing old boot is a hard failure",
        "except BootUnknown:",
        "except ZeroDivisionError:",
    ),
    ("M31", P, "boot: change not counted", 'st["boot_changes_total"] += 1', "pass"),
    (
        "M32",
        P,
        "boot: budget not reduced by the old boot's records",
        'budget -= run["records"] + run["malformed"] + run["skipped"]',
        "budget -= 0",
    ),
    # state
    ("M33", P, "seed: first run counts history", "if a.from_boot_start:", "if True:"),
    (
        "M34",
        P,
        "state: negative counters accepted",
        'or not all(isinstance(v, int) and v >= 0 for v in st["counters"].values())',
        "or False",
    ),
    (
        "M35",
        P,
        "state: invalid structure read as empty",
        'return None, "invalid state structure"',
        "return None, None",
    ),
    (
        "M36",
        P,
        "state: reset not counted",
        'st["state_resets_total"] = 1 if problem else 0',
        'st["state_resets_total"] = 0',
    ),
    ("M37", P, "state: not saved", "    save_state(a.state, st)\n", "    pass\n"),
    (
        "M38",
        P,
        "state: file mode not 0600",
        "os.chmod(tmp, 0o600)",
        "os.chmod(tmp, 0o644)",
    ),
    # metrics
    (
        "M40",
        P,
        "metrics: zero counters not exported",
        'st["counters"].get(pid, 0),',
        'st["counters"][pid],',
    ),
    (
        "M41",
        P,
        "metrics: backlog always 0",
        '[(L, 1 if run["truncated"] else 0)],',
        "[(L, 0)],",
    ),
    (
        "M42",
        P,
        "metrics: last-match keeps the oldest time",
        'max(st["last"].get(k, 0), ts)',
        'min(st["last"].get(k, ts), ts)',
    ),
    # report
    (
        "M43",
        P,
        "report: truncation hidden (rc 0)",
        "return 2 if stopped else 0",
        "return 0",
    ),
    (
        "M44",
        P,
        "report: severity order lost",
        'key=lambda r: (SEVERITIES.index(r["severity"]), order[r["pattern"]]),',
        'key=lambda r: r["pattern"],',
    ),
    # wrapper
    (
        "M45",
        S,
        "wrapper: HOST_LABEL not validated",
        'valid_host "$HOST_LABEL" || die "bad HOST_LABEL"',
        "true",
    ),
    (
        "M46",
        S,
        "wrapper: state dir mode not set",
        '{ mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR"; }',
        '{ mkdir -p "$STATE_DIR"; }',
    ),
    (
        "M47",
        S,
        "wrapper: no lock",
        'flock -n 9 || die "another collect is running" 1',
        "true",
    ),
    (
        "M48",
        S,
        "wrapper: helper timeout not turned into up 0",
        'if [ "$rc" = 124 ] || [ -z "$text" ]; then',
        'if [ -z "$text" ]; then',
    ),
    (
        "M49",
        S,
        "validate: size limit not enforced",
        '[ "$size" -le "$MAX_BYTES" ] ||',
        "true ||",
    ),
    (
        "M50",
        S,
        "validate: host label not enforced",
        "if (index(rest, pre) != 1)",
        "if (0)",
    ),
    (
        "M51",
        S,
        "validate: missing up sample accepted",
        'if (!up) { print "no pft_kernwatch_up sample"; exit 1 }',
        "",
    ),
    (
        "M52",
        S,
        "pull: refuses nothing for its own host",
        '[ "$name" != "$HOST_LABEL" ] ||',
        "true ||",
    ),
    (
        "M53",
        S,
        "pull: rejected file replaces the last good copy",
        'rm -f "$tmp"; die "validation failed: $why" 2',
        "true",
    ),
    # rules (promtool)
    (
        "R01",
        R,
        "rule: severity filter dropped from PFTKernelCritical (info fires)",
        'increase(pft_kernwatch_matches_total{severity="crit"}[15m])',
        "increase(pft_kernwatch_matches_total[15m])",
    ),
    (
        "R02",
        R,
        "rule: crit window 15m -> 60m (no resolve)",
        '{severity="crit"}[15m]',
        '{severity="crit"}[60m]',
    ),
    (
        "R03",
        R,
        "rule: per-pattern grouping lost",
        'sum by (host, class, pattern) (increase(pft_kernwatch_matches_total{severity="crit"}',
        'sum by (host) (increase(pft_kernwatch_matches_total{severity="crit"}',
    ),
    (
        "R04",
        R,
        "rule: warn severity filter swapped to crit",
        '{severity="warn"}[30m]',
        '{severity="crit"}[30m]',
    ),
    ("R05", R, "rule: stale ignores up 0", "or pft_kernwatch_up == 0\n", ""),
    ("R06", R, "rule: stale ignores backlog", "or pft_kernwatch_backlog == 1\n", ""),
    (
        "R07",
        R,
        "rule: stale threshold 600 -> 6000",
        "pft_kernwatch_collect_timestamp_seconds > 600",
        "pft_kernwatch_collect_timestamp_seconds > 6000",
    ),
    (
        "R08",
        R,
        "rule: crit uses delta-style raw value (counter reset fires)",
        '(increase(pft_kernwatch_matches_total{severity="crit"}[15m])) > 0',
        '(pft_kernwatch_matches_total{severity="crit"} - pft_kernwatch_matches_total{severity="crit"} offset 15m) != 0',
    ),
]
# documented equivalent mutants (no input can reach the difference):
#  M39 "if not up or st is None" -> "if st is None": collect() passes st=None on every failed read (up=False), so the
#      two conditions are true for exactly the same calls.
EQUIVALENT = ["M39"]


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
        shutil.copy2(os.path.join(KW, f), os.path.join(d, f))
    for f in ("kernwatch.rules.yml", "kernwatch.tests.yml"):
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
    env = dict(os.environ, KW_DIR=d)
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
            "kernwatch.tests.yml",
        ],
        timeout,
    )


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(KW, f)
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
    work = tempfile.mkdtemp(prefix="pft-kw-mut.", dir=base)
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
        ["pgrep", "-fc", "pft-kw-mut\\."], capture_output=True, text=True, check=False
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
