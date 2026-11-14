#!/usr/bin/env python3
"""Mutation harness for pft-peertls. Each mutant changes exactly one text match in a COPY of the peertls folder
(grader E*, collector S*, remediation F*) and runs that copy's full pytest suite, or changes a copy of
../alerts/peertls.rules.yml (R*) and runs `promtool test rules peertls.tests.yml` on it.

CAUGHT: pytest printed its "N failed ... in Xs" summary and at least one FAILED test line (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose grader never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (PTLSMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
The suite takes ~6 min unloaded (s_server fixtures, gate sleeps), so --timeout defaults to 900 s.
Usage: TEST_TMPDIR=~/.cache python3 -u peertls/tests/mutate.py [--timeout SEC] [--jobs N] [--only E01,R01,...]
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
PT = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(PT), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
SKIP = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".ruff_cache", "logs", "drill", "*.pyc")

E, S, F, R = "peertls_eval.py", "pft-peertls.sh", "pft-peertls-fix.sh", "peertls.rules.yml"

# (id, file, description, old text, new text)
MUTANTS = [
    # ---- grader: one mutant per check ----
    ("E01", E, "probe.reachable ignores failed probes", "bool(errs) or cert is None,", "cert is None,"),
    (
        "E02",
        E,
        "proto.*: forbidden protocol accepted passes",
        'bad = (rule == "forbid" and res == "accepted") or (rule == "require" and res != "accepted")',
        'bad = rule == "require" and res != "accepted"',
    ),
    (
        "E03",
        E,
        "proto.*: required protocol refused passes",
        'bad = (rule == "forbid" and res == "accepted") or (rule == "require" and res != "accepted")',
        'bad = rule == "forbid" and res == "accepted"',
    ),
    (
        "E04",
        E,
        "cipher.*: forbidden suite class accepted passes",
        'bad = (rule == "forbid" and r["result"] == "accepted") or (rule == "require" and r["result"] != "accepted")',
        'bad = rule == "require" and r["result"] != "accepted"',
    ),
    (
        "E05",
        E,
        "cipher.*: required suite class refused passes",
        'bad = (rule == "forbid" and r["result"] == "accepted") or (rule == "require" and r["result"] != "accepted")',
        'bad = rule == "forbid" and r["result"] == "accepted"',
    ),
    ("E06", E, "cipher.tls13_suites: no TLS 1.3 suite passes", 'rule13 == "require" and not acc13,', "False,"),
    ("E07", E, "kx.dh_bits: small DH group passes", 'b < pol["min_dh_bits"]', "b < 0"),
    ("E08", E, "cert.key: short key passes", 'cert["key_bits"] < need', 'cert["key_bits"] < 0'),
    (
        "E09",
        E,
        "cert.sig_hash: forbidden hash passes",
        'cert["sig_hash"] in pol["forbid_sig_hash"] or cert["sig_hash"] == "unknown",',
        'cert["sig_hash"] == "unknown",',
    ),
    ("E10", E, "cert.validity: expiring soon passes", 'left < pol["min_cert_days_left"]', "left < 0"),
    ("E11", E, "cert.validity: not-yet-valid passes", 'bad = now < cert["not_before"] or left', "bad = left"),
    ("E12", E, "hs.compression: compression passes", 'base["compression"] not in ("NONE", None),', "False,"),
    ("E13", E, "hs.secure_reneg: missing RFC 5746 passes", 'base["secure_reneg"] is False,', "False,"),
    ("E14", E, "hs.ems: no extended master secret passes", 'base["ems"] is False,', "False,"),
    (
        "E15",
        E,
        "hs.ticket_lifetime: long ticket passes",
        'lt is not None and lt > pol["max_ticket_lifetime"],',
        "False,",
    ),
    (
        "E16",
        E,
        "hs.client_reneg: accepted renegotiation passes",
        'rv == "accepted", f"client-initiated',
        'False, f"client-initiated',
    ),
    ("E17", E, "hs.fallback_scsv: missing SCSV passes", 'fb["fallback"] != "refused",', "False,"),
    (
        "E18",
        E,
        "drift.posture: changed posture passes",
        'bool(drift),\n            ("changed: "',
        'False,\n            ("changed: "',
    ),
    (
        "E19",
        E,
        "drift.cert: change without restart counted as restart",
        'restarted = t["started"] is not None and',
        'restarted = True or t["started"] is not None and',
    ),
    (
        "E20",
        E,
        "drift.cert: restart-explained change is WARN",
        "            if restarted:\n",
        "            if False:\n",
    ),
    # ---- grader: parsing, waivers, public view, verdict, policy, crosscheck ----
    (
        "E21",
        E,
        "alert-only answer not read as refused",
        'elif a or (m and m.group(2) == "(NONE)"):',
        'elif m and m.group(2) == "(NONE)":',
    ),
    (
        "E22",
        E,
        "fallback probe: any answer counts as refused",
        'r["fallback"] = "refused" if r["alert"] == "inappropriate_fallback" else r["result"]',
        'r["fallback"] = "refused"',
    ),
    (
        "E23",
        E,
        "renegotiation refusal not detected",
        'elif re.search(r"no renegotiation|alert", tail[1]):',
        "elif False:",
    ),
    ("E24", E, "expired waiver still applied", "(out if until > now else expired).append(w)", "out.append(w)"),
    ("E25", E, "waiver ignores its target", 'w["target"] in ("*", c["target"])', "True"),
    (
        "E26",
        E,
        "public view keeps waived checks",
        'r["checks"] = [c for c in r["checks"] if c["result"] != "WAIVED"]',
        'r["checks"] = list(r["checks"])',
    ),
    ("E27", E, "public view keeps waived probe answers", 't["probes"][pid] = {"result": "private"}', "pass"),
    (
        "E28",
        E,
        "verdict ignores FAIL/WARN",
        'worst = max([SEV.get(c["result"], 0) for c in checks] + [0])',
        "worst = 0",
    ),
    ("E29", E, "bundle over the handshake cap accepted", "if ended > MAX_HANDSHAKES:", "if False:"),
    ("E30", E, "bundle without end line accepted", "if ended is None:\n        raise", "if False:\n        raise"),
    ("E31", E, "bundle with a missing probe accepted", 'if pid != "cert" and pid not in t["probes"]:', "if False:"),
    (
        "E32",
        E,
        "unknown policy key accepted",
        "if key not in POLICY_KEYS:\n            raise",
        "if False:\n            raise",
    ),
    (
        "E33",
        E,
        "crosscheck: posture mismatch passes",
        'same = t["posture"].get(k) == own["posture"].get(k)',
        "same = True",
    ),
    ("E34", E, "crosscheck: certificate mismatch passes", "same = fa is not None and fa == fb", "same = True"),
    # ---- collector: scope guards, cap, pace, textfile ----
    ("S01", S, "local target need not be loopback", 'local) is_loopback "$addr" || die', "local) true || die"),
    ("S02", S, "remote target may be loopback", 'remote) is_loopback "$addr" && die', "remote) false && die"),
    ("S03", S, "non-peer port accepted", 'if [ "$port" != "$PEER_PORT" ] && !', "if false && !"),
    ("S04", S, "address need not be a literal IP", '[[ "$addr" =~ ^[0-9a-fA-F.:]+$ ]] ||', "true ||"),
    ("S05", S, "handshake cap not enforced", '[ "$total" -le "$MAX_HANDSHAKES" ]', "true"),
    (
        "S06",
        S,
        "remote targets audited without --target",
        'else [ "$scope" = local ] || continue; fi',
        "else true; fi",
    ),
    ("S07", S, "non-root run allowed", '[ -n "$TEST" ] || [ "$(id -u)" = 0 ] || die', "true || die"),
    ("S08", S, "textfile size cap not enforced", '[ "$size" -le "$MAX_BYTES" ] ||', "true ||"),
    # ---- remediation: refusals, window, gate, rollback ----
    ("F01", F, "apply without --yes allowed", '[ "$YES" = 1 ] || [ "$DRY" = 1 ] || die', "true || die"),
    ("F02", F, "apply outside a pft-maint window", '"$MAINT" active >/dev/null 2>&1 && {', "true && {"),
    ("F03", F, "several [port_peer] sections accepted", '[ "$n" = 1 ] || echo', "true || echo"),
    (
        "F04",
        F,
        "unmanaged ssl_ciphers line overwritten",
        'if [ "$k" != 0 ] && ! peer_section "$1" | grep -qxF "$MARK"; then',
        "if false; then",
    ),
    (
        "F05",
        F,
        "cipher string selecting nothing accepted",
        '"$OPENSSL" ciphers -tls1_2 "$CIPHERS" >/dev/null 2>&1 || echo',
        "true || echo",
    ),
    ("F06", F, "gate ignores the live TLS answer", 'if [ "$view" = "$want" ]; then', "if true; then"),
    (
        "F07",
        F,
        "gate ignores a changed node key",
        '[ "$st" = full ] && [ "$p" = "$pk" ] &&',
        '[ "$st" = full ] && true &&',
    ),
    ("F08", F, "gate ignores the peer count", '[ "$peers" -ge "$MIN_PEERS" ]', "true"),
    (
        "F09",
        F,
        "failed restart does not roll back",
        'if ! restart_node "$C" || ! health_gate',
        "if ! true || ! health_gate",
    ),
    ("F10", F, "integrity accepts other changed items", '[ -z "$other" ] ||', "true ||"),
    # ---- alert rule ----
    ("R01", R, "FAIL verdict does not alert", "(pft_peertls_verdict) == 2", "(pft_peertls_verdict) == 3"),
    ("R02", R, "audit error does not alert", "(pft_peertls_up) == 0", "(pft_peertls_up) == -1"),
    ("R03", R, "drift does not alert", "(pft_peertls_drift) > 0", "(pft_peertls_drift) > 1"),
    ("R04", R, "alert fires without its 5m hold", "        for: 5m\n", "        for: 0m\n"),
]

HANG = (E, "def main(argv):\n", "def main(argv):\n    import time\n\n    while True:\n        time.sleep(1)\n")


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
    """Copy the peertls folder (+ rules, rule tests in alerts/) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    shutil.copytree(PT, d, ignore=SKIP)
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in (R, "peertls.tests.yml"):
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
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", "peertls.tests.yml"], timeout)


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
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 900
    hang_timeout = int(a[a.index("--hang-timeout") + 1]) if "--hang-timeout" in a else 60
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 6
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="ptlsmut.", dir=base)
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
        f"control timeout (evaluator never returns, --hang-timeout {hang_timeout}): {hst} after "
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
    if os.environ.get("PTLSMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
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
