#!/usr/bin/env python3
"""Mutation harness for pft-schedaudit: each mutant changes exactly one text match in ONE file of a full copy of the
module (pft-schedaudit.sh, schedaudit_lib.py, plus ../integrity/pft-integrity.sh for the collect_sched hook) and runs
tests/test_schedaudit.py against that copy (SA_DIR, SA_INTEGRITY); rule mutants (R*) change
../alerts/schedaudit.rules.yml in a copy and run `promtool test rules`.

A mutant is CAUGHT if its suite fails with a RESULT line and at least one FAIL line (promtool: exit != 0 with
"FAILED"), or hangs (process group SIGKILLed at --timeout). A failing suite without them is BROKEN. A mutant whose old
text does not match exactly once is NOT APPLIED. The unmutated control runs from a copy in the same place and must
pass first. Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan process fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u schedaudit/tests/mutate.py [--timeout SEC] [--jobs N] [--only M01,R01,...]
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SA = os.path.dirname(HERE)
REPO = os.path.dirname(SA)
ALERTS = os.path.join(REPO, "alerts")
INTEG = os.path.join(REPO, "integrity", "pft-integrity.sh")
SUITE = os.path.join(HERE, "test_schedaudit.py")
FILES = ("pft-schedaudit.sh", "schedaudit_lib.py")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
L, S, R, I = (
    "schedaudit_lib.py",
    "pft-schedaudit.sh",
    "schedaudit.rules.yml",
    "pft-integrity.sh",
)

# (id, file, description, old text, new text)
MUTANTS = [
    (
        "M01",
        L,
        "commented cron lines dropped",
        'commented = s.startswith("#")\n        body = s.lstrip("#").strip() if commented else s',
        'commented = False\n        body = s.lstrip("#").strip() if commented else s',
    ),
    (
        "M02",
        L,
        "stock help line (unknown user) kept as a commented job",
        "if commented and system and user not in users:",
        "if False:",
    ),
    (
        "M03",
        L,
        "run-parts name rule ignored",
        '        if not RUN_PARTS_NAME.match(f):\n            state = "inert-name"',
        '        if False:\n            state = "inert-name"',
    ),
    (
        "M04",
        L,
        "non-executable run-parts file counted active",
        'state = "not-executable"',
        'state = "active"',
    ),
    (
        "M05",
        L,
        "undriven run-parts dir counted active",
        'state = "no-schedule"',
        'state = "active"',
    ),
    (
        "M06",
        L,
        "anacron does not drive run-parts dirs",
        "    out += anacron_entries(h)\n",
        "    pass\n",
    ),
    (
        "M07",
        L,
        "cron.d dotted names not inert",
        'e["enabled"], e["state"] = False, "inert-name"',
        "pass",
    ),
    (
        "M08",
        L,
        "at job state ignores the x bit",
        '"state": "queued" if st.st_mode & 0o100 else "done"',
        '"state": "queued"',
    ),
    ("M09", L, "template @.timer units listed", 'and not f[0].endswith("@.timer")', ""),
    (
        "M10",
        L,
        "next_elapse kept in the schedule (unstable id)",
        're.sub(r"\\s*;\\s*next_elapse=.*$", "", v.strip("{} "))',
        'v.strip("{} ")',
    ),
    (
        "M11",
        L,
        "masked timers read as disabled",
        'if loaded == "masked" or ufs == "masked":',
        "if False:",
    ),
    (
        "M12",
        L,
        "user-unit dirs not scanned",
        "        + timer_inventory(h)\n        + user_timer_inventory(h)\n",
        "        + timer_inventory(h)\n",
    ),
    (
        "M13",
        L,
        "spool crontabs not scanned",
        'for f in h.listdir("/var/spool/cron/crontabs"):',
        "for f in []:",
    ),
    (
        "M20",
        L,
        "group/world-writable bits not checked",
        "wr = st.st_mode & 0o022",
        "wr = 0",
    ),
    (
        "M21",
        L,
        "owner not checked",
        "            if st.st_uid != h.trusted:\n                fs.append(",
        "            if False:\n                fs.append(",
    ),
    (
        "M22",
        L,
        "sticky dirs not reported as writable_dir",
        "elif wr and sticky and not last and stat.S_ISDIR(st.st_mode):",
        "elif False:",
    ),
    (
        "M23",
        L,
        "user-tree paths not flagged",
        "if under_world_tmp(path) and not any(",
        "if False and not any(",
    ),
    ("M24", L, "md5 mismatch ignored", "if got != want:", "if False:"),
    ("M25", L, "obsolete conffiles kept", 'and "obsolete" not in f[2:]', ""),
    (
        "M26",
        L,
        "untracked never reported",
        "if not tracked(path) and not tracked(r) and not under_world_tmp(path):",
        "if False:",
    ),
    (
        "M27",
        L,
        "uid >= UID_MIN not a regular user",
        'info and info["uid"] >= uid_min and info["uid"] != 65534',
        "False",
    ),
    (
        "M28",
        L,
        "missing timer unit not reported",
        'if e.get("unit_load") in ("not-found", "masked", "error", "bad-setting"):',
        "if False:",
    ),
    (
        "M29",
        L,
        "missing ExecStart binary not reported",
        'fs.append(("timer_target", p, "ExecStart binary missing", False))',
        "pass",
    ),
    (
        "M30",
        L,
        "bare ExecStart names not resolved",
        '            for d in SYSTEMD_EXEC_PATH.split(":"):',
        "            for d in []:",
    ),
    (
        "M31",
        L,
        "user crontab ownership flagged",
        'if role == "file" and path.startswith("/var/spool/cron/crontabs/"):',
        "if False:",
    ),
    (
        "M32",
        L,
        "bare cron command not resolved through PATH",
        'if d.startswith("/") and h.lstat(c) is not None:',
        "if False:",
    ),
    (
        "M33",
        L,
        "inert entries audited",
        'e["state"] in ("inert-name", "done", "user-unit")',
        'e["state"] in ()',
    ),
    (
        "M34",
        L,
        "integrity hook ignored",
        "scope = set(scope_paths(h, entries)) if scope_hook else set()",
        "scope = set()",
    ),
    (
        "M40",
        L,
        "packaged /etc files dropped from scope",
        'and not p.startswith("/etc/")',
        "",
    ),
    (
        "M41",
        L,
        "user trees in scope",
        "                or p.startswith(SKIP_PREFIX)\n                or under_world_tmp(p)\n",
        "                or p.startswith(SKIP_PREFIX)\n",
    ),
    (
        "M42",
        L,
        "scheduling dirs not in scope",
        '            out.add(f"/etc/cron.{k}")',
        "            pass",
    ),
    (
        "M50",
        L,
        "allow line without reason accepted",
        "if len(f) < 4 or not f[3].strip():",
        "if len(f) < 3:",
    ),
    ("M51", L, "short reasons accepted", "if len(f[3].strip()) < 8:", "if False:"),
    (
        "M52",
        L,
        "allow path glob ignored",
        'and fnmatch.fnmatchcase(f["path"], r["path"])',
        "",
    ),
    (
        "M53",
        L,
        "wrong-typed state read as empty",
        'if not isinstance(d, dict) or not isinstance(d.get("expected"), dict):',
        "if False:",
    ),
    (
        "M54",
        L,
        "removed entries not reported",
        "return sorted(cur - exp), sorted(exp - cur)",
        "return sorted(cur - exp), []",
    ),
    ("M55", L, "no baseline is not unexpected", 'or not s["baseline"])', ")"),
    (
        "M56",
        L,
        "state file world-readable",
        "os.chmod(tmp, 0o600)",
        "os.chmod(tmp, 0o644)",
    ),
    (
        "M57",
        L,
        "accept reason length unchecked",
        "            if len(reason.strip()) < 8:",
        "            if False:",
    ),
    (
        "M60",
        L,
        "apply also removes the owner write bit",
        "new = old & ~0o022",
        "new = old & ~0o222",
    ),
    (
        "M61",
        L,
        "apply chmods files of other owners",
        "        if st.st_uid != h.trusted:\n            log.append(",
        "        if False:\n            log.append(",
    ),
    ("M62", L, "apply ignores --dry-run", "        if dry:\n", "        if False:\n"),
    (
        "M63",
        L,
        "apply touches non-fixable findings",
        'if f["check"] == "chain_writable" and f["fixable"] and not f["allowed"]:',
        'if not f["allowed"]:',
    ),
    ("S01", S, "findings make collect fail", '[ "$rc" = 1 ] && rc=0', ":"),
    ("S02", S, "size guard removed", '[ "${#text}" -gt "$TEXT_BUDGET" ]', "false"),
    (
        "S03",
        S,
        "conf owner not checked",
        '[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = "${PFT_SA_TRUSTED_UID:-0}" ] && . "$CONF"',
        '[ -f "$CONF" ] && . "$CONF"',
    ),
    (
        "S04",
        S,
        "hook detection always on",
        "grep -q '^collect_sched()' \"$INTEGRITY_BIN\"",
        "true",
    ),
    (
        "S06",
        S,
        "textfile mode not set",
        'if printf \'%s\' "$3" > "$tmp" && chmod 644 "$tmp" && mv',
        'if printf \'%s\' "$3" > "$tmp" && mv',
    ),
    (
        "I01",
        I,
        "scope failure silent",
        "then emit sched:scope status error; return 0; fi",
        "then return 0; fi",
    ),
    (
        "I02",
        I,
        "dirs hashed as files (no listing)",
        '    if [ -d "$p" ] && [ ! -L "$p" ]; then',
        "    if false; then",
    ),
    (
        "I03",
        I,
        "relative paths accepted",
        '    case "$p" in /*) ;; *) continue ;; esac',
        "    :",
    ),
    (
        "R01",
        R,
        "Unexpected: up guard removed",
        "          and on (host) pft_schedaudit_up == 1\n",
        "",
    ),
    (
        "R02",
        R,
        "Unexpected: unaccepted kind not alerted",
        'kind=~"new|removed|finding|unaccepted"',
        'kind=~"new|removed|finding"',
    ),
    ("R03", R, "Unexpected: no for (1-min blip pages)", "        for: 2m\n", ""),
    ("R04", R, "Stale: up 0 not stale", "          or pft_schedaudit_up == 0\n", "\n"),
    (
        "R05",
        R,
        "Stale: age threshold 1h",
        "pft_schedaudit_collect_timestamp_seconds > 900",
        "pft_schedaudit_collect_timestamp_seconds > 3600",
    ),
]
# S05 (dry-run writes apply.log) was removed with the redundant guard it targeted: only a real apply prints
# FIXED/FAILED lines, so the guard could not change any outcome (equivalent).
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
    """Copy the module files (+ pft-integrity.sh, rules + rule tests) into work/name; mutate = (file, old, new)."""
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, "alerts"))
    for f in FILES:
        shutil.copy2(os.path.join(SA, f), os.path.join(d, f))
    shutil.copy2(INTEG, os.path.join(d, I))
    for f in ("schedaudit.rules.yml", "schedaudit.tests.yml"):
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
    env = dict(os.environ, SA_DIR=d, SA_INTEGRITY=os.path.join(d, I))
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
            "schedaudit.tests.yml",
        ],
        timeout,
    )


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = {R: os.path.join(ALERTS, f), I: INTEG}.get(f, os.path.join(SA, f))
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
    work = tempfile.mkdtemp(prefix="pft-sa-mut.", dir=base)
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
        ["pgrep", "-fc", "pft-sa-mut\\."], capture_output=True, text=True, check=False
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
