#!/usr/bin/env python3
"""Mutation harness for specdrill: each mutant breaks one guard, containment check, per-poll abort, teardown step,
command check (pft-specdrill.sh) or one metric/verdict/spec rule (specdrill.py). The stubbed suite must fail on
every one. Each mutant gets its own copy of the folder and its own TMPDIR; runner mutants run tests/test_runner.py,
helper mutants run both test files (the runner calls the helper for live-gate/summarize).

A mutant is CAUGHT only when pytest printed its RESULT line ("N failed") and at least one FAILED line; a suite that
times out is killed (process group + any process naming the copy) and reported HUNG (not caught). Each anchor must
occur exactly once in its file, checked before anything runs. Prints one line per mutant and "MUTANTS: caught N/M";
exit 0 only if the baseline passed and every mutant was caught.
   python3 specdrill/tests/mutants.py [-j 4] [--only R01,H05] [--timeout 900]"""

import concurrent.futures as cf
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SD = os.path.dirname(HERE)
SH = "pft-specdrill.sh"
PY = "specdrill.py"
# id, file, what it breaks, old text, new text
MUTANTS = [
    ("R01", SH, "need_root", '[ "$(id -u)" -eq 0 ] || [ -n "$TEST" ] || die 3 "run as root"', "true"),
    ("R02", SH, "lock: flock", 'flock -n 9 || refuse "lock:', 'true || refuse "lock:'),
    (
        "R03",
        SH,
        "maint: window active",
        '>/dev/null 2>&1 || { echo "FAIL maint: no active',
        '|| true || { echo "FAIL maint: no active',
    ),
    (
        "R04",
        SH,
        "maint: remaining >= budget",
        '[ "${rem:-0}" -ge "$need" ] 2>/dev/null',
        '[ "${rem:-0}" -ge 0 ] 2>/dev/null',
    ),
    ("R05", SH, "maint: boundary", '-ge "$need" ] 2>/dev/null', '-gt "$need" ] 2>/dev/null'),
    (
        "R06",
        SH,
        "budget: slack counted",
        "echo $(( FULL_TIMEOUT_S + WINDOW_S + SLACK_S ))",
        "echo $(( FULL_TIMEOUT_S + WINDOW_S ))",
    ),
    (
        "R07",
        SH,
        "live: unreadable",
        'li="$(live_info)" || { echo "FAIL live: live server_info unreadable"; return; }',
        'li="$(live_info)" || li="full 1"',
    ),
    (
        "R08",
        SH,
        "live: state full",
        '[ "$st" = full ] || { echo "FAIL live: live server_state',
        'true || { echo "FAIL live: live server_state',
    ),
    (
        "R09",
        SH,
        "live: reference unreadable",
        'ref="$(ref_seq)" || { echo "FAIL live: reference RPC unreadable"; return; }',
        'ref="$(ref_seq)" || ref="$seq"',
    ),
    (
        "R10",
        SH,
        "live: lag <= max",
        '[ "$lag" -le "$LIVE_LAG_MAX" ] || { echo "FAIL live: live lag',
        '[ "$lag" -le 999 ] || { echo "FAIL live: live lag',
    ),
    (
        "R11",
        SH,
        "live: lag boundary",
        '[ "$lag" -le "$LIVE_LAG_MAX" ] || { echo "FAIL live: live lag',
        '[ "$lag" -lt "$LIVE_LAG_MAX" ] || { echo "FAIL live: live lag',
    ),
    ("R12", SH, "integrity: verify rc", '[ "$rc" -eq 0 ] || { echo "FAIL integrity', 'true || { echo "FAIL integrity'),
    (
        "R13",
        SH,
        "integrity: service running",
        '"$SYSTEMCTL" is-active --quiet pft-integrity.service && {',
        "false && {",
    ),
    ("R14", SH, "headroom: subtract cell", '[ $(( a - $1 )) -ge "$HEADROOM_MIB" ]', '[ $(( a )) -ge "$HEADROOM_MIB" ]'),
    ("R15", SH, "headroom: boundary", '[ $(( a - $1 )) -ge "$HEADROOM_MIB" ]', '[ $(( a - $1 )) -gt "$HEADROOM_MIB" ]'),
    ("R16", SH, "disk: free >= min", '[ "$g" -ge "$DISK_MIN_GB" ]', "true"),
    (
        "R17",
        SH,
        "image: live container",
        '[ -n "$img" ] || { echo "FAIL image: live container',
        'true || { echo "FAIL image: live container',
    ),
    ("R18", SH, "image: present locally", '"$DOCKER" image inspect "$img" >/dev/null 2>&1 ||', "true ||"),
    ("R19", SH, "leftovers", '[ "$n" -eq 0 ] || { echo "FAIL leftovers', 'true || { echo "FAIL leftovers'),
    ("R20", SH, "preflight refuses on FAIL", '[ "${g%% *}" = ok ] || refuse', "true || refuse"),
    (
        "R21",
        SH,
        "failsafe: arm failure refuses",
        '|| refuse "integrity: failsafe re-arm unit could not be started"',
        "|| true",
    ),
    ("R22", SH, "failsafe: disarm on stop failure", '{ "$SYSTEMCTL" stop "$REARM_UNIT.service"; refuse', "{ refuse"),
    ("R23", SH, "failsafe: ttl", '"sleep $ttl && $SYSTEMCTL', '"sleep 60 && $SYSTEMCTL'),
    (
        "R24",
        SH,
        "teardown: re-arm timer",
        '"$SYSTEMCTL" start pft-integrity.timer && log "integrity timer re-armed"',
        'log "integrity timer re-armed"',
    ),
    ("R25", SH, "teardown: disarm failsafe", '"$SYSTEMCTL" stop "$REARM_UNIT.service" >/dev/null 2>&1\n', ":\n"),
    (
        "R58",
        SH,
        "teardown: failsafe before timer",
        '    "$SYSTEMCTL" stop "$REARM_UNIT.service" >/dev/null 2>&1\n    "$SYSTEMCTL" start pft-integrity.timer && log "integrity timer re-armed"\n',
        '    "$SYSTEMCTL" start pft-integrity.timer && log "integrity timer re-armed"\n    "$SYSTEMCTL" stop "$REARM_UNIT.service" >/dev/null 2>&1\n',
    ),
    ("R26", SH, "teardown: containers", '"$DOCKER" rm -fv "$id"', ":"),
    ("R59", SH, "teardown: anonymous volumes (rm -v)", '"$DOCKER" rm -fv "$id"', '"$DOCKER" rm -f "$id"'),
    ("R27", SH, "teardown: volumes", '"$DOCKER" volume rm -f "$id"', ":"),
    ("R28", SH, "teardown: networks", '"$DOCKER" network rm "$id"', ":"),
    ("R29", SH, "trap EXIT", "trap 'teardown' EXIT; ", ""),
    ("R30", SH, "trap INT TERM", "trap 'abort=signal; teardown; exit 130' INT TERM", ":"),
    ("R31", SH, "create: --pull never", "--pull never ", ""),
    ("R32", SH, "create: --cpus", '--cpus "$cpus" ', ""),
    ("R33", SH, "create: --memory-swap", ' --memory-swap "${mem}m")', ")"),
    ("R34", SH, "create: write-bps", ' --device-write-bps "$dev:$io")', ")"),
    ("R35", SH, "containment: enforced", '[ -z "$v" ] || refuse "containment: $v"', "true"),
    (
        "R36",
        SH,
        "containment: validator_token",
        "^\\[(validator_token|validation_seed|ips_fixed)\\]",
        "^\\[(validation_seed|ips_fixed)\\]",
    ),
    (
        "R37",
        SH,
        "containment: ips_fixed",
        "^\\[(validator_token|validation_seed|ips_fixed)\\]",
        "^\\[(validator_token|validation_seed)\\]",
    ),
    ("R38", SH, "containment: ports", "(.HostConfig.PortBindings // {} | length) == 0 and ", ""),
    ("R39", SH, "containment: privileged", " and (.HostConfig.Privileged | not)", ""),
    ("R40", SH, "containment: network", "\n    and .HostConfig.NetworkMode == $n'", "'"),
    (
        "R41",
        SH,
        "containment: exact own mount set",
        "'([.[0].Mounts[] | {Type, Name, Destination}] | sort) == ($p | map({Type: \"volume\"} + .) | sort)'",
        "'true'",
    ),
    ("R60", SH, "containment: mount type", 'map({Type: "volume"} + .)', "map({Type: .Type} + .)"),
    ("R61", SH, "containment: destination compared", "{Type, Name, Destination}] | sort", "{Type, Name}] | sort"),
    (
        "R62",
        SH,
        "volume plan: every declared path",
        "< <(printf '%s\\n/var/lib/postfiatd/db\\n' \"$paths\" | sort -u)",
        "< <(echo /var/lib/postfiatd/db)",
    ),
    ("R63", SH, "volume plan: always db", '"$paths" | sort -u)', '"$paths" | grep -v /db | sort -u)'),
    ("R64", SH, "volume plan: non-object fails", 'else error("not an object") end', "else keys end"),
    (
        "R65",
        SH,
        "volume plan: inspect failure fails",
        """'{{json .Config.Volumes}}' "$1" 2>/dev/null)" || return 1""",
        """'{{json .Config.Volumes}}' "$1" 2>/dev/null)" || true""",
    ),
    ("R66", SH, "volume plan: refuse empty", '[ -n "$plan" ] || refuse "volume plan', 'true || refuse "volume plan'),
    ("R67", SH, "volumes: mounted", '    args+=(-v "$vn:$vp")\n', "    :\n"),
    (
        "R68",
        SH,
        "volumes: labelled",
        '"$DOCKER" volume create --label "$LABEL=$id" "$vn"',
        '"$DOCKER" volume create "$vn"',
    ),
    ("R42", SH, "containment: unreadable cfg", '[ -n "$cfg" ] || { echo "cell config unreadable"; return; }', ":"),
    ("R43", SH, "abort: live gate", ">/dev/null || { abort=live_lag; break; }", ">/dev/null || true"),
    (
        "R44",
        SH,
        "abort: maint ended",
        '"$PFT_MAINT_BIN" active >/dev/null 2>&1 || { abort=maint_window_ended',
        "true || { abort=maint_window_ended",
    ),
    ("R45", SH, "abort: host mem low", '[ "$v" -lt $(( HEADROOM_MIB / 2 )) ]', '[ "$v" -lt 0 ]'),
    (
        "R46",
        SH,
        "abort: host mem boundary",
        '[ "$v" -lt $(( HEADROOM_MIB / 2 )) ]',
        '[ "$v" -le $(( HEADROOM_MIB / 2 )) ]',
    ),
    ("R47", SH, "loop: container stopped", '[ "${state%% *}" = true ] || { log', "true || { log"),
    (
        "R48",
        SH,
        "loop: never-full timeout",
        '[ $(( t - t0 )) -ge "$FULL_TIMEOUT_S" ]',
        "[ $(( t - t0 )) -ge $(( FULL_TIMEOUT_S * 2 )) ]",
    ),
    (
        "R49",
        SH,
        "loop: window end",
        '[ $(( t - full_t )) -ge "$WINDOW_S" ]',
        "[ $(( t - full_t )) -ge $(( WINDOW_S * 2 )) ]",
    ),
    ("R50", SH, "peak RSS = max", '[ "$v" -gt "$hwm" ] && hwm="$v"', 'hwm="$v"'),
    ("R51", SH, "oom: memory.events", "($oomk|tonumber) > 0", "false"),
    ("R52", SH, "oom: inspect flag", '($oom == "true" or ', "(false or "),
    ("R53", SH, "matrix: --yes", '[ "$YES" -eq 1 ] || die 3', "true || die 3"),
    (
        "R54",
        SH,
        "matrix: stop on refusal",
        '( run_cell "$OUT" "$a" "$c" "$m" "$i" ) || exit $?',
        '( run_cell "$OUT" "$a" "$c" "$m" "$i" ) || true',
    ),
    ("R55", SH, "matrix: unknown axis", '*) die 3 "unknown axis: $a" ;;', "*) ;;"),
    ("R56", SH, "run-cell: arg check", '! [[ "$MEM" =~ ^[0-9]+$ ]]', "false"),
    (
        "R57",
        SH,
        "refuse exit 4",
        'refuse() { echo "REFUSED: $*" >&2; exit 4; }',
        'refuse() { echo "REFUSED: $*" >&2; exit 1; }',
    ),
    ("H01", PY, "percentile: nearest rank", "math.ceil(p / 100.0 * len(s))", "round(p / 100.0 * len(s))"),
    ("H02", PY, "percentile: index", "return s[k - 1]", "return s[min(k, len(s) - 1)]"),
    (
        "H03",
        PY,
        "jitter: distinct ledgers",
        'if seen and s["seq"] <= seen[-1][0]:',
        'if seen and s["seq"] < seen[-1][0]:',
    ),
    ("H04", PY, "jitter: per-ledger step", "(c2 - c1) / (q2 - q1)", "(c2 - c1)"),
    ("H05", PY, "jitter: >= 2 intervals", "if len(iv) < 2:", "if len(iv) < 1:"),
    ("H06", PY, "jitter: population stddev", "/ len(iv)), 3)", "/ (len(iv) - 1)), 3)"),
    ("H07", PY, "window: upper bound", 'full_t <= s["t"] <= full_t + meta["window_s"]', 'full_t <= s["t"]'),
    (
        "H08",
        PY,
        "window: lower bound",
        'full_t <= s["t"] <= full_t + meta["window_s"]',
        's["t"] <= full_t + meta["window_s"]',
    ),
    ("H09", PY, "lag clamp >= 0", 'max(0, s["ref_seq"] - s["seq"])', 's["ref_seq"] - s["seq"]'),
    ("H10", PY, "verdict: abort", 'if meta.get("abort"):', "if False:"),
    ("H11", PY, "verdict: oom", 'if meta.get("oom_killed"):', "if False:"),
    ("H12", PY, "verdict: restarts", 'if meta.get("restarts", 0) > 0:', 'if meta.get("restarts", 0) > 1:'),
    ("H13", PY, "verdict: slow full", 'ttf > meta["full_deadline_s"]', 'ttf > meta["full_deadline_s"] * 2'),
    (
        "H14",
        PY,
        "verdict: lag p95",
        "elif percentile(lags, 95) > LAG_P95_MAX:",
        "elif percentile(lags, 50) > LAG_P95_MAX:",
    ),
    (
        "H15",
        PY,
        "verdict: lag boundary",
        "elif percentile(lags, 95) > LAG_P95_MAX:",
        "elif percentile(lags, 95) >= LAG_P95_MAX:",
    ),
    ("H16", PY, "verdict: no window samples", 'reasons.append("no_window_samples")', "pass"),
    (
        "H17",
        PY,
        "spec: pass below a failure",
        'if c["verdict"] != "PASS":\n            break',
        'if c["verdict"] != "PASS":\n            continue',
    ),
    ("H18", PY, "spec: safe = next step", "safe = above[0] if above else minimum", "safe = minimum"),
    (
        "H19",
        PY,
        "spec: failing list",
        '"failing": [r["cell"] for r in rows if r["verdict"] != "PASS"],',
        '"failing": [],',
    ),
    (
        "H20",
        PY,
        "peers_min",
        '"peers_min": min(peers) if peers else None',
        '"peers_min": max(peers) if peers else None',
    ),
    ("H21", PY, "live_full_all", 'all(s.get("live_state") == "full" for s in samples)', "True"),
    ("H22", PY, "live-gate: all polls bad", "len(bad) == polls:", "len(bad) >= 1:"),
    ("H23", PY, "live-gate: polls >= 1", "and int(argv[4]) >= 1:", ":"),
    ("H24", PY, "live-gate: lag boundary", '(x.get("live_lag") or 0) > max_lag', '(x.get("live_lag") or 0) >= max_lag'),
    ("H25", PY, "report: no cells exit 2", "        return 2\n", "        return 0\n"),
    (
        "H26",
        PY,
        "report: cell order",
        "for name in sorted(os.listdir(root)):",
        "for name in sorted(os.listdir(root), reverse=True):",
    ),
    ("H27", PY, "spec: bounded = failure below", '"bounded": rows[0][field] < minimum[field],', '"bounded": True,'),
    ("H28", PY, "report: open floor marked <=", 'low = "" if s["bounded"] else "<= "', 'low = ""'),
    ("H29", PY, "report: limits section", '"## Limits of this measurement",', '"",'),
]
FAILED = re.compile(r"^FAILED (\S+)", re.MULTILINE)
RESULT = re.compile(r"^=*\s*((?:\d+ \w+, )*\d+ \w+) in [0-9.]+s", re.MULTILINE)


def read(path):
    with open(path) as fh:
        return fh.read()


def check_anchors():
    bad = []
    for mid, f, _, old, _ in MUTANTS:
        n = read(os.path.join(SD, f)).count(old)
        if n != 1:
            bad.append(f"{mid}: anchor occurs {n}x in {f}: {old!r}")
    return bad


def procs_naming(path):
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                if path.encode() in fh.read():
                    out.append(int(pid))
        except OSError:
            pass
    return out


def kill_named(path):
    """SIGKILL every process whose command line names the copy (fixtures may survive the group kill)."""
    for pid in procs_naming(path):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def run(m, scratch_root, timeout):
    mid, f, what, old, new = m
    d = tempfile.mkdtemp(prefix=f"mut-{mid}-", dir=scratch_root)
    try:
        copy = os.path.join(d, "specdrill")
        shutil.copytree(SD, copy, ignore=shutil.ignore_patterns("__pycache__", ".ruff_cache", "logs", "data"))
        if f:
            p = os.path.join(copy, f)
            src = read(p)
            if src.count(old) != 1:
                return f"NOT APPLIED {mid} {what}", False
            with open(p, "w") as fh:
                fh.write(src.replace(old, new, 1))
        tmp = os.path.join(d, "tmp")
        os.mkdir(tmp)
        # helper mutants: the fast helper tests first (-x stops at the first failure), then the runner tests
        tests = ["tests/test_runner.py"] if f == SH else ["tests/test_specdrill.py", "tests/test_runner.py"]
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PFT_", "STUB_"))}
        env.update(TMPDIR=tmp, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.Popen(
            [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests],
            cwd=copy,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            kill_named(d)
            proc.communicate()
            return f"HUNG     {mid} {what:<34} (killed after {timeout}s)", False
        res = (RESULT.findall(out) or [None])[-1]  # the summary line is the last one with "in N.NNs"
        fails = FAILED.findall(out)
        if f is None:
            ok = proc.returncode == 0 and res is not None and not fails
            return (
                f"BASELINE {'ok  ' if ok else 'FAIL'} ({out.strip().splitlines()[-1] if out.strip() else 'no output'})",
                ok,
            )
        if proc.returncode != 0 and res and " failed" in res and fails:
            return f"CAUGHT   {mid} {what:<34} by: {fails[0]}", True
        return (
            f"SURVIVED {mid} {what:<34} (rc {proc.returncode}: {out.strip().splitlines()[-1] if out.strip() else '-'})",
            False,
        )
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    argv = sys.argv[1:]
    jobs = int(argv[argv.index("-j") + 1]) if "-j" in argv else 4
    timeout = int(argv[argv.index("--timeout") + 1]) if "--timeout" in argv else 900
    only = argv[argv.index("--only") + 1].split(",") if "--only" in argv else None
    bad = check_anchors()
    if bad:
        print("\n".join(bad))
        print("MUTANTS: anchor check failed - no mutant run")
        sys.exit(2)
    scratch_root = tempfile.mkdtemp(
        prefix="specdrill-mutants-", dir=os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    )
    base = run(("M00", None, "unmutated (baseline)", "", ""), scratch_root, timeout)
    print(base[0], flush=True)
    if not base[1]:
        print("MUTANTS: baseline suite fails - no mutant run")
        sys.exit(2)
    sel = [m for m in MUTANTS if only is None or m[0] in only]
    res = []
    with cf.ThreadPoolExecutor(jobs) as ex:
        futs = {ex.submit(run, m, scratch_root, timeout): m[0] for m in sel}
        for fut in cf.as_completed(futs):  # one line per mutant as soon as it finishes
            res.append(fut.result())
            print(res[-1][0], flush=True)
    left = procs_naming(scratch_root)
    shutil.rmtree(scratch_root, ignore_errors=True)
    n = sum(1 for _, c in res if c)
    print(f"orphans: {len(left)}")
    print(f"MUTANTS: caught {n}/{len(res)}")
    sys.exit(0 if n == len(res) and not left else 1)
