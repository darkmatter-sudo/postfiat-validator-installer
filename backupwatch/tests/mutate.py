#!/usr/bin/env python3
"""Mutation harness for pft-backupwatch: each mutant changes exactly one text match in ONE file of a full copy of the
module (pft-backupwatch.sh, backupwatch_lib.py) and runs tests/test_backupwatch.py against that copy (BW_DIR); rule
mutants (R*) change ../alerts/backupwatch.rules.yml in a copy and run `promtool test rules`.

A mutant is CAUGHT if its suite fails with a RESULT line and at least one FAIL line (promtool: exit != 0 with
"FAILED"), or hangs (process group SIGKILLed at --timeout). A failing suite without them is BROKEN. A mutant whose old
text does not match exactly once is NOT APPLIED. The unmutated control runs from a copy in the same place and must
pass first. Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan process fails the harness (exit 1).
(Runner adapted from ../../jobwatch/tests/mutate.py; the work dir is named bwmut.*, not pft-bw-*, because the suite
asserts that no pft-bw-* scratch is left in the same temp base.)
Usage: TEST_TMPDIR=~/.cache python3 -u backupwatch/tests/mutate.py [--timeout SEC] [--jobs N] [--only M01,R01,...]
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BW = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(BW), "alerts")
SUITE = os.path.join(HERE, "test_backupwatch.py")
FILES = ("pft-backupwatch.sh", "backupwatch_lib.py")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
L, S, R = "backupwatch_lib.py", "pft-backupwatch.sh", "backupwatch.rules.yml"

# (id, file, description, old text, new text)
MUTANTS = [
    # check: fresh / size
    (
        "M01",
        L,
        "fresh: FAIL age boundary ignored",
        "if age > a.fail_age_h * 3600:",
        "if False:",
    ),
    (
        "M02",
        L,
        "fresh: WARN age uses FAIL threshold",
        "elif age > a.max_age_h * 3600:",
        "elif age > a.fail_age_h * 3600:",
    ),
    (
        "M03",
        L,
        "size: MIN_BYTES not enforced",
        "if size < a.min_bytes:",
        "if size < 0:",
    ),
    (
        "M04",
        L,
        "size: ratio upper bound dropped",
        "if a.size_lo <= ratio <= a.size_hi:",
        "if a.size_lo <= ratio:",
    ),
    # sidecar / manifest
    ("M05", L, "sidecar: mismatch accepted", "if want == sha256(blob):", "if want:"),
    (
        "M06",
        L,
        "manifest: bad member hash ignored",
        "p for p, h in listed.items() if p in members and sha256(members[p]) != h",
        "p for p, h in listed.items() if False",
    ),
    (
        "M07",
        L,
        "manifest: listed-but-absent ignored",
        "missing = sorted(p for p in listed if p not in members)",
        "missing = []",
    ),
    (
        "M08",
        L,
        "manifest: unlisted extra member ignored",
        'extra = sorted(p for p in members if p != "MANIFEST.sha256" and p not in listed)',
        "extra = []",
    ),
    (
        "M09",
        L,
        "archive: member outside STEM/ accepted",
        "if top != stem:",
        "if False:",
    ),
    # content
    (
        "M10",
        L,
        "content: COMPOSE_FILE members not required",
        'for f in compose_members(members.get("files/opt/postfiatd/.env"))',
        "for f in []",
    ),
    (
        "M11",
        L,
        "content: firewall tool error not flagged",
        'elif members[p].lstrip().startswith(b"ERROR"):',
        "elif False:",
    ),
    # drift
    (
        "M12",
        L,
        "drift: secrets not stripped before compare",
        'if rel == CFG_PREFIX + "postfiatd.cfg" and not secrets_included:',
        "if False:",
    ),
    (
        "M13",
        L,
        "drift: gone file reported as same",
        '            rows.append({"path": shown, "state": "gone"})',
        '            rows.append({"path": shown, "state": "same"})',
    ),
    # gpg
    (
        "M14",
        L,
        "gpg: empty PASSFILE accepted",
        "if not os.path.isfile(passfile) or os.path.getsize(passfile) == 0:",
        "if not os.path.isfile(passfile):",
    ),
    # offhost (check side)
    (
        "M15",
        L,
        "offhost: recorded ciphertext sha not compared",
        "if rec[name][0] != csha:",
        "if False:",
    ),
    ("M16", L, "offhost: peer verify result ignored", 'if v != "OK":', "if False:"),
    ("M17", L, "offhost: peer down not a FAIL", "if down:", "if False:"),
    # metrics
    (
        "M18",
        L,
        "metrics: drift grace boundary off by one",
        "overdue = 1 if since and a.now - since > a.drift_grace_h * 3600 else 0",
        "overdue = 1 if since and a.now - since >= a.drift_grace_h * 3600 else 0",
    ),
    (
        "M19",
        L,
        "metrics: drift since not kept between runs",
        "        if 0 < since <= now:\n            return since",
        "        if False:\n            return since",
    ),
    (
        "M20",
        L,
        "metrics: drift state never cleared",
        "    if not drifted:\n        try:\n            os.unlink(state_path)",
        "    if not drifted:\n        try:\n            os.path.exists(state_path)",
    ),
    (
        "M21",
        L,
        "metrics: invalid input still up 1",
        '        rows.append(("up", "1 if the check ran and produced a result.", (), 0))\n        sys.stdout.write(prom(a.host, rows))\n        return 1\n    rows.append(("up", "1 if the check ran and produced a result.", (), 1))\n    first',
        '        rows.append(("up", "1 if the check ran and produced a result.", (), 1))\n        sys.stdout.write(prom(a.host, rows))\n        return 1\n    rows.append(("up", "1 if the check ran and produced a result.", (), 1))\n    first',
    ),
    (
        "M22",
        L,
        "replica-metrics: any VERIFY OK counts",
        'ok = 1 if any(x == f"VERIFY {newest.group(1)} OK" for x in lines) else 0',
        'ok = 1 if any(x.endswith(" OK") for x in lines) else 0',
    ),
    (
        "M23",
        L,
        "replica-metrics: oldest replica used for age",
        "newest = max(reps, key=lambda m: m.group(2))",
        "newest = min(reps, key=lambda m: m.group(2))",
    ),
    (
        "M24",
        L,
        "metrics: host label not validated",
        "if not HOST_RE.match(a.host) or a.now <= 0:",
        "if a.now <= 0:",
    ),
    # CLI: replicate / serve
    (
        "S01",
        S,
        "replicate: archive not checked against its sidecar",
        '[ "$(sha < "$a")" = "$plain" ] || die "$n: archive does not match its sidecar; not replicated" 2',
        "true",
    ),
    (
        "S02",
        S,
        "receive: ciphertext sha not checked",
        'if [ "$got" != "$csha" ]; then rm -f "$tmp"; echo "RECEIVED $n $got SHA_MISMATCH"; return 2; fi',
        ":",
    ),
    (
        "S03",
        S,
        "receive: decrypt result not checked",
        'if [ "${PIPESTATUS[0]}" != 0 ] || [ "$dec" != "$plain" ]; then rm -f "$tmp"; echo "RECEIVED $n $got DECRYPT_MISMATCH"; return 2; fi',
        ":",
    ),
    (
        "S04",
        S,
        "receive: size cap not enforced",
        'if [ "$size" -gt "$REPLICA_MAX_BYTES" ]; then',
        "if false; then",
    ),
    (
        "S05",
        S,
        "receive: keep N + 1",
        'tail -n "+$((REPLICA_KEEP + 1))"',
        'tail -n "+$((REPLICA_KEEP + 2))"',
    ),
    (
        "S06",
        S,
        "verify: re-hash skipped",
        '[ "$(sha < "$REPLICA_DIR/$n.age")" = "$c" ] || { echo "VERIFY $n SHA_MISMATCH"; return 2; }',
        ":",
    ),
    (
        "S07",
        S,
        "replicate: record written without peer OK",
        'if [ "$rc" != 0 ] || ! grep -qx "RECEIVED $n $csha OK" <<<"$out"; then die "peer did not confirm $n (rc $rc)" 2; fi',
        ":",
    ),
    # CLI: collect / pull
    (
        "S08",
        S,
        "pull: foreign sample lines accepted",
        "$0 !~ /^pft_backupwatch_[a-z_]+\\{[^}]*\\} -?[0-9]+(\\.[0-9]+)?$/ { print",
        "0 { print",
    ),
    (
        "S09",
        S,
        "pull: host label not checked",
        "index($0, h) == 0 { print",
        "0 { print",
    ),
    (
        "S10",
        S,
        "pull: missing up sample accepted",
        '      if (!up) { print "no pft_backupwatch_up sample"; exit 1 }\n',
        "",
    ),
    (
        "S11",
        S,
        "pull: validation failure still installs the file",
        'if ! why="$(valid_prom "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi',
        'valid_prom "$tmp" "$PEER_LABEL" >/dev/null || true',
    ),
    (
        "S12",
        S,
        "collect: DRIFT_GRACE_H not passed to the helper",
        '--drift-grace-h "$DRIFT_GRACE_H"',
        "--drift-grace-h 30",
    ),
    (
        "S13",
        S,
        "collect: replica role skips verify of the newest",
        '[ -z "$n" ] || st+=$\'\\n\'"$(serve_verify "$n" 2>/dev/null)"',
        ":",
    ),
    ("S14", S, "collect: OFFHOST ignored", '[ "$OFFHOST" = 1 ] && off=(1)', ":"),
    (
        "S15",
        S,
        "pull: may overwrite own textfile",
        '[ "$PEER_LABEL" != "$HOST_LABEL" ] || die "refusing to pull over this host\'s own textfile ($PEER_LABEL)"',
        ":",
    ),
    # rules
    (
        "R01",
        R,
        "Stale: WARN (1) no longer fires",
        'expr: pft_backupwatch_check_state{check="fresh"} >= 1',
        'expr: pft_backupwatch_check_state{check="fresh"} >= 2',
    ),
    (
        "R02",
        R,
        "Broken: manifest dropped from the selector",
        'check=~"sidecar|manifest|content|size"',
        'check=~"sidecar|content|size"',
    ),
    (
        "R03",
        R,
        "Broken: WARN fires too",
        'check=~"sidecar|manifest|content|size"} == 2',
        'check=~"sidecar|manifest|content|size"} >= 1',
    ),
    (
        "R04",
        R,
        "Drift: for 15m -> 5m",
        "expr: pft_backupwatch_drift_overdue == 1\n        for: 15m",
        "expr: pft_backupwatch_drift_overdue == 1\n        for: 5m",
    ),
    (
        "R05",
        R,
        "NoOffhostCopy: sentry side dropped",
        "          or pft_backupwatch_replica_verify_ok == 0\n",
        "",
    ),
    (
        "R06",
        R,
        "Stale collector: up 0 dropped",
        "          or pft_backupwatch_up == 0\n",
        "",
    ),
    (
        "R07",
        R,
        "Stale collector: 45 min -> 60 min",
        "time() - pft_backupwatch_collect_timestamp_seconds > 2700",
        "time() - pft_backupwatch_collect_timestamp_seconds > 3600",
    ),
    (
        "R08",
        R,
        "Broken: severity critical -> warning",
        "        for: 15m\n        labels:\n          severity: critical",
        "        for: 15m\n        labels:\n          severity: warning",
    ),
    (
        "S16",
        S,
        "collect: textfile without its final newline",
        '"$text"$\'\\n\' || die "cannot write $TEXTFILE_DIR" 1',
        '"$text" || die "cannot write $TEXTFILE_DIR" 1',
    ),
    (
        "S17",
        S,
        "collect --stdout without its final newline",
        "then printf '%s\\n' \"$text\"",
        "then printf '%s' \"$text\"",
    ),
    (
        "M25",
        L,
        "gpg: empty PASSFILE accepted, variant 2",
        "or os.path.getsize(passfile) == 0",
        "or os.path.getsize(passfile) < 0",
    ),
]


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
        shutil.copy2(os.path.join(BW, f), os.path.join(d, f))
    for f in ("backupwatch.rules.yml", "backupwatch.tests.yml"):
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
    # own temp base per copy: the suite asserts no pft-bw-* scratch is left in it, so parallel copies must not share one
    tmp = os.path.join(d, "tmp")
    os.makedirs(tmp, exist_ok=True)
    env = dict(os.environ, BW_DIR=d, TEST_TMPDIR=tmp)
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
            "backupwatch.tests.yml",
        ],
        timeout,
    )


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(BW, f)
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
    work = tempfile.mkdtemp(prefix="bwmut.", dir=base)
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
        ["pgrep", "-fc", "bwmut\\."], capture_output=True, text=True, check=False
    ).stdout.strip()
    print(f"orphan check: {orphans or 0} process(es) still running from mutant copies")
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(
        f"RESULT: {c} caught, {sv} survived, {na} not applied, {br} broken of {len(selected)}{subset}"
    )
    return 0 if sv == 0 and na == 0 and br == 0 and (orphans or "0") == "0" else 1


if __name__ == "__main__":
    sys.exit(main())
