#!/usr/bin/env python3
"""Mutation harness for pft-coredump.sh: apply each mutant (exactly one textual match) to a copy of the tool, run
tests/run-tests.sh against it with a timeout, and count it CAUGHT only if the suite printed its RESULT line and at
least one FAIL line (or hung: the whole process group is killed and the mutant counts as caught). An unmutated
control run from the same location must pass first; a mutant whose text does not match exactly once is NOT APPLIED
and fails the harness. Every audit check CD01..CD13 has at least one mutant (CD10 is INFO-only: its mutant drops the
line). Usage: python3 -u tests/mutate.py [--timeout SEC] [--jobs N] [--only M01,M02]   (--only: dev subset, the RESULT
says so). Each mutant runs in its own copy; the suite makes its own private scratch dir, so --jobs copies do not share state.
Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts.
"""

import os
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "pft-coredump.sh")
SUITE = os.path.join(HERE, "run-tests.sh")

# (id, check, description, old text, new text)
MUTANTS = [
    (
        "M01",
        "CD01",
        "file pattern graded PASS",
        'file) add FAIL "CD01 pattern-live"',
        'file) add PASS "CD01 pattern-live"',
    ),
    (
        "M02",
        "CD01",
        "any pipe handler counted as safe",
        '*) echo "pipe:$prog" ;;\n          esac',
        "*) echo safe ;;\n          esac",
    ),
    (
        "M03",
        "CD01",
        "systemd-coredump safe whatever its storage",
        '*/systemd-coredump) [ "$CD05" = PASS ] && echo safe',
        "*/systemd-coredump) true && echo safe",
    ),
    (
        "M04",
        "CD02",
        "boot value read from the first file instead of the last",
        '[ "$k" = "$key" ] && out="$v	${f#"$R"}"',
        '[ "$k" = "$key" ] && [ -z "$out" ] && out="$v	${f#"$R"}"',
    ),
    (
        "M05",
        "CD02",
        "/usr/lib wins over /etc for the same name",
        "for d in /lib/sysctl.d /usr/lib/sysctl.d /usr/local/lib/sysctl.d /run/sysctl.d /etc/sysctl.d; do",
        "for d in /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d; do",
    ),
    (
        "M06",
        "CD02",
        "slash key form not normalized",
        'k="${k#-}"; k="${k//\\//.}"',
        'k="${k#-}"',
    ),
    (
        "M07",
        "CD02",
        "'-' (ignore-errors) key prefix not stripped",
        'k="${k#-}"; k="${k//\\//.}"',
        'k="${k//\\//.}"',
    ),
    (
        "M08",
        "CD02",
        "apport override ignored at boot",
        '  if apport_enabled; then\n    add FAIL "CD02 pattern-boot"',
        '  if false; then\n    add FAIL "CD02 pattern-boot"',
    ),
    (
        "M09",
        "CD02",
        "missing value treated as safe",
        '[ -n "$boot" ] || { bv=core; bf="kernel default"; }',
        '[ -n "$boot" ] || { bv="|/bin/false"; bf="kernel default"; }',
    ),
    (
        "M10",
        "CD03",
        "suid_dumpable 2 graded PASS",
        '|| add WARN "CD03 suid-dumpable"',
        '|| add PASS "CD03 suid-dumpable"',
    ),
    (
        "M11",
        "CD04",
        "apport default (no enabled=) taken as off",
        '[ "${e:-1}" != 0 ]',
        '[ "${e:-0}" != 0 ]',
    ),
    (
        "M12",
        "CD04",
        "enabled apport graded PASS",
        'elif apport_enabled; then add FAIL "CD04 apport"',
        'elif apport_enabled; then add PASS "CD04 apport"',
    ),
    (
        "M13",
        "CD05",
        "ProcessSizeMax not required",
        '[ "$st" = none ] && [ "$psm" = 0 ] && CD05=PASS',
        '[ "$st" = none ] && CD05=PASS',
    ),
    (
        "M14",
        "CD05",
        "first coredump drop-in wins",
        'tail -1)"; [ -n "$v" ] && last="$v"',
        'tail -1)"; [ -n "$v" ] && [ -z "$last" ] && last="$v"',
    ),
    (
        "M15",
        "CD06",
        "only PID 1 checked",
        '[ "$(cat "$R/proc/$p/cgroup" 2>/dev/null)" = "$cg" ] && echo "$p"',
        'false && echo "$p"',
    ),
    (
        "M16",
        "CD06",
        "processes of other cgroups counted",
        '[ "$(cat "$R/proc/$p/cgroup" 2>/dev/null)" = "$cg" ] && echo "$p"',
        '[ -n "$cg" ] && echo "$p"',
    ),
    (
        "M17",
        "CD06",
        "hard limit ignored",
        'elif ! limit_ok "$hard"; then warn=$((warn + 1)); fi',
        "fi",
    ),
    (
        "M18",
        "CD06",
        "soft limit > 0 graded WARN",
        'if [ "$bad" -gt 0 ]; then add FAIL "CD06 rlimit-live"',
        'if [ "$bad" -gt 0 ]; then add WARN "CD06 rlimit-live"',
    ),
    (
        "M19",
        "CD07",
        "anonymous-memory bits not tested",
        "[ $((16#$filt & 3)) -ne 0 ]",
        "[ $((16#$filt & 2)) -ne 0 ]",
    ),
    (
        "M20",
        "CD07",
        "dump-possible filter graded INFO",
        '    add WARN "CD07 dump-filter"',
        '    add INFO "CD07 dump-filter"',
    ),
    (
        "M21",
        "CD08",
        "pending re-create graded PASS",
        'elif [ "$CD09" = PASS ]; then add WARN "CD08 container-ulimit"',
        'elif [ "$CD09" = PASS ]; then add PASS "CD08 container-ulimit"',
    ),
    (
        "M22",
        "CD08",
        "running container ulimit never read",
        'select(.Name == "core") | "\\(.Soft):\\(.Hard)"] | first // "unset"',
        'select(.Name == "nofile") | "\\(.Soft):\\(.Hard)"] | first // "unset"',
    ),
    (
        "M23",
        "CD09",
        "compose overlay not required",
        '[ "$nxt" = 0:0 ] && CD09=PASS || CD09=FAIL',
        "CD09=PASS",
    ),
    (
        "M36",
        "CD09",
        "omitted compose zero fields read as null",
        '"\\(.soft // 0):\\(.hard // 0)"',
        '"\\(.soft):\\(.hard)"',
    ),
    (
        "M24",
        "CD09",
        "recreate tools not grepped",
        "grep -q 'HostConfig.Ulimits' \"$R$t\" || miss+=",
        "true || miss+=",
    ),
    (
        "M25",
        "CD10",
        "docker defaults line dropped",
        '  add INFO "CD10 docker-default"',
        '  true "CD10 docker-default"',
    ),
    (
        "M26",
        "CD11",
        "plain swap graded PASS",
        '|| add WARN "CD11 swap"',
        '|| add PASS "CD11 swap"',
    ),
    (
        "M27",
        "CD11",
        "dm-crypt swap counted as plain",
        'case "$s" in /dev/dm-*|/dev/mapper/*) ;; *)',
        'case "$s" in /dev/nonexistent) ;; *)',
    ),
    (
        "M28",
        "CD12",
        "hibernation with swap graded PASS",
        'else add WARN "CD12 hibernate"',
        'else add PASS "CD12 hibernate"',
    ),
    (
        "M29",
        "CD12",
        "AllowHibernation=no ignored",
        '[[ "$hd" == *"[disabled]"* ]] || [ "$ah" = no ]',
        '[[ "$hd" == *"[disabled]"* ]]',
    ),
    (
        "M30",
        "CD13",
        "*.crash files not counted",
        "-o -name '*.core' -o -name '*.crash' \\)",
        "-o -name '*.core' \\)",
    ),
    (
        "M31",
        "CD13",
        "core.* matches any suffix (core.txt)",
        "-name 'core.[0-9]*'",
        "-name 'core.*'",
    ),
    (
        "M32",
        "CD13",
        "depth limit removed",
        '-xdev -maxdepth "$SCAN_DEPTH" -type f',
        "-xdev -type f",
    ),
    (
        "M33",
        "CD13",
        "file names printed",
        '|| add FAIL "CD13 core-files" "$cnt core/crash file(s), $sz bytes (names withheld)"',
        '|| add FAIL "CD13 core-files" "$cnt core/crash file(s), $sz bytes $(find "$R/var/crash" -type f)"',
    ),
    (
        "M34",
        "exit",
        "WARN not counted in the exit code",
        'WARN) [ "$CODE" -lt 1 ] && CODE=1 ;;',
        "WARN) true ;;",
    ),
    (
        "M35",
        "exit",
        "missing container not an error",
        'i="$(inspect0 "$CONTAINER")"; [ -n "$i" ] || die "container $CONTAINER missing" 3',
        'i="$(inspect0 "$CONTAINER")"; [ -n "$i" ] || exit 0',
    ),
    # apply
    (
        "A01",
        "apply",
        "--yes not required",
        '[ "$YES" = 1 ] || { echo "apply: refused - needs --yes"; exit 4; }',
        "true",
    ),
    (
        "A02",
        "apply",
        "root not required",
        '[ "$UID_NOW" = 0 ] || { echo "apply: refused - root required"; return 4; }',
        "true",
    ),
    (
        "A03",
        "apply",
        "second apply allowed over an un-rolled-back one",
        'if [ -n "$p" ] && [ ! -e "$p/rolled_back" ]; then echo "apply: refused',
        'if false; then echo "apply: refused',
    ),
    (
        "A04",
        "apply",
        "--recreate without pft-maint",
        '"$MAINT" active >/dev/null 2>&1 || { echo "apply: refused - --recreate needs',
        'true || { echo "apply: refused - --recreate needs',
    ),
    (
        "A05",
        "apply",
        "--recreate on a node that is not full",
        'is_full "$(rpc_info)" || { echo "apply: refused - node not full"; return 4; }',
        "true",
    ),
    (
        "A06",
        "apply",
        "--recreate allowed on a compose container",
        '[ "$kind" = run ] || { echo "apply: refused - --recreate is only',
        'true || { echo "apply: refused - --recreate is only',
    ),
    (
        "A07",
        "apply",
        "live pattern not set",
        '&& set_pattern "$SAFE_PATTERN" && echo "  1.',
        '&& echo "  1.',
    ),
    (
        "A08",
        "apply",
        "prlimit result not verified",
        '--core=0:0 >/dev/null 2>&1 && [ "$(core_limit "$p")" = "0 0" ] && n=',
        "--core=0:0 >/dev/null 2>&1; n=",
    ),
    (
        "A09",
        "apply",
        "only soft limit lowered",
        '"$PRLIMIT" --pid "$p" --core=0:0',
        '"$PRLIMIT" --pid "$p" --core=0:unlimited',
    ),
    (
        "A10",
        "apply",
        "COMPOSE_FILE not extended",
        'case ":$out:" in *":$OVERLAY:"*) ;; *) out="$out:$OVERLAY" ;; esac',
        "true",
    ),
    (
        "A11",
        "apply",
        "other .env lines dropped",
        '{ grep -v \'^COMPOSE_FILE=\' "$eb" 2>/dev/null; echo "COMPOSE_FILE=$out"; }',
        '{ echo "COMPOSE_FILE=$out"; }',
    ),
    (
        "A12",
        "apply",
        ".env mode not kept",
        ' && chmod --reference="$eb" "$R$wd/.env.tmp" 2>/dev/null;',
        ";",
    ),
    (
        "A13",
        "apply",
        "compose config result ignored",
        '( cd "$R$wd" && "$DOCKER" compose config -q >/dev/null 2>&1 ) || { echo "  4. docker compose',
        'true || { echo "  4. docker compose',
    ),
    (
        "A14",
        "apply",
        "overlay sets soft only",
        "        soft: 0\\n        hard: 0\\n",
        "        soft: 0\\n",
    ),
    (
        "A15",
        "apply",
        "systemd-coredump drop-in without Storage=none",
        "[Coredump]\\nStorage=none\\nProcessSizeMax=0\\n",
        "[Coredump]\\nProcessSizeMax=0\\n",
    ),
    (
        "A16",
        "apply",
        "re-create without the ulimit",
        'recreate_run \'[{"Name":"core","Hard":0,"Soft":0}]\' apply',
        "recreate_run '[]' apply",
    ),
    (
        "A17",
        "apply",
        "run_args drops Ulimits",
        '    ($ul[] | "--ulimit=\\(.Name)=\\(.Soft):\\(.Hard)"),\n',
        "",
    ),
    (
        "A18",
        "apply",
        "run_args drops --read-only",
        '    (if .HostConfig.ReadonlyRootfs then "--read-only" else empty end),\n    (.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\\(.key)\\(if',
        '    (.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\\(.key)\\(if',
    ),
    (
        "A19",
        "apply",
        "gate ignores configuration changes",
        '[ "$(keep_sig "$i")" = "$4" ] || hard+=" configuration changed: $(sig_diff "$4" "$(keep_sig "$i")");"',
        "true",
    ),
    (
        "A20",
        "apply",
        "gate ignores Ulimits",
        '[ "$(ulimits_of "$i")" = "$3" ] || hard+=',
        "true || hard+=",
    ),
    (
        "A21",
        "apply",
        "gate failure not rolled back",
        '|| { echo "  4. re-create FAILED -> automatic rollback"; do_rollback auto; trap - INT TERM; return 1; }',
        "|| true",
    ),
    (
        "A22",
        "apply",
        "old container kept after PASS",
        '    drop_old\n    i="$(inspect0 "$CONTAINER")"; n=0',
        '    i="$(inspect0 "$CONTAINER")"; n=0',
    ),
    ("A23", "apply", "env values printed", "s/^(--env=[^=]*)=.*/\\1=<value>/; ", ""),
    (
        "A24",
        "apply",
        "previous container keeps its restart policy",
        ' && "$DOCKER" update --restart=no "$old" >/dev/null 2>&1 || { echo "  could not',
        ' || { echo "  could not',
    ),
    # rollback
    (
        "R01",
        "rollback",
        "drop-in not restored",
        'restore_file "$DROPIN" && restore_file "$CD_DROPIN" || {',
        'restore_file "$CD_DROPIN" || {',
    ),
    (
        "R02",
        "rollback",
        "absent file not removed (left in place)",
        'if grep -qxF -- "$1" "$SNAP/absent"; then rm -f -- "$R$1";',
        'if grep -qxF -- "$1" "$SNAP/absent"; then true;',
    ),
    (
        "R03",
        "rollback",
        "live pattern not restored",
        'set_pattern "$(cat "$SNAP/core_pattern")" && echo',
        "true && echo",
    ),
    (
        "R04",
        "rollback",
        "limits not restored",
        '"$PRLIMIT" --pid "$p" --core="$soft:$hard" >/dev/null 2>&1 && cur=',
        "true && cur=",
    ),
    (
        "R05",
        "rollback",
        "compose .env not restored",
        'restore_file "$wd/.env" && restore_file "$wd/$OVERLAY"',
        'restore_file "$wd/$OVERLAY"',
    ),
    (
        "R06",
        "rollback",
        "rolled_back marker not written",
        'date -u +%FT%TZ > "$SNAP/rolled_back"',
        "true",
    ),
    (
        "R07",
        "rollback",
        "auto rollback re-creates instead of restoring the old container",
        'if [ "$how" = auto ] && [ -e "$SNAP/old_container" ]; then restore_old || rc=5',
        "if false; then restore_old || rc=5",
    ),
    (
        "R08",
        "rollback",
        "re-create keeps the applied Ulimits",
        'recreate_run "$(ulimits_of "$(cat "$SNAP/inspect.json")")" restore',
        'recreate_run \'[{"Name":"core","Hard":0,"Soft":0}]\' restore',
    ),
    (
        "R09",
        "rollback",
        "restore_old keeps restart=no",
        '"$DOCKER" update --restart="$rp" "$CONTAINER"',
        '"$DOCKER" update --restart=no "$CONTAINER"',
    ),
    (
        "R10",
        "rollback",
        "snapshot dir world-readable",
        'chmod 700 "$STATE_DIR" "$SNAP"',
        'chmod 755 "$STATE_DIR" "$SNAP"',
    ),
]


# Equivalent mutants (no input can reach the difference), documented instead of counted. The former M07 (drop the
# '#'/';' comment skip in sysctl_boot) was one: a commented key keeps its '#'/';' and never equals the real key. It was
# replaced 2026-11-26 by the '-' prefix mutant above, so every listed mutant must be caught.
EQUIVALENT = []


def run_suite(tool, timeout):
    p = subprocess.Popen(
        ["bash", SUITE, tool],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return "HANG", ""
    return ("PASS" if p.returncode == 0 else "FAIL"), out


def main():
    timeout = 300
    if "--timeout" in sys.argv:
        timeout = int(sys.argv[sys.argv.index("--timeout") + 1])
    jobs = 1
    if "--jobs" in sys.argv:
        jobs = int(sys.argv[sys.argv.index("--jobs") + 1])
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))
    with open(TOOL) as f:
        src = f.read()
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="pft-cd-mut.", dir=base)
    # the control runs from the same scratch location as the mutants
    ctl = os.path.join(work, "control.sh")
    with open(ctl, "w") as f:
        f.write(src)
    st, out = run_suite(ctl, timeout)
    os.remove(ctl)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(
        f"control (unmutated, {work.split(os.sep)[-1]}): {st} {last[-1] if last else ''}"
    )
    if st != "PASS":
        print("RESULT: control run failed, mutants not run")
        return 2
    caught = survived = not_applied = 0
    selected = [m for m in MUTANTS if only is None or m[0] in only]

    def one(m):
        mid, chk, desc, old, new = m
        n = src.count(old)
        if n != 1:
            return "NOT APPLIED", f"{mid} [{chk}] NOT APPLIED ({n} matches) - {desc}"
        path = os.path.join(work, f"{mid}.sh")
        with open(path, "w") as f:
            f.write(src.replace(old, new, 1))
        st, out = run_suite(path, timeout)
        os.remove(path)
        fails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
        has_result = any(ln.startswith("RESULT:") for ln in out.splitlines())
        if st == "HANG":
            return (
                "CAUGHT",
                f"{mid} [{chk}] CAUGHT - {desc} [suite hung (timeout, process group killed)]",
            )
        if st == "FAIL" and has_result and fails:
            return (
                "CAUGHT",
                f"{mid} [{chk}] CAUGHT - {desc} [{len(fails)} failing: {'; '.join(fails[:2])}]",
            )
        why = (
            "suite passed"
            if st == "PASS"
            else "suite failed without RESULT/FAIL lines (crash?)"
        )
        return "SURVIVED", f"{mid} [{chk}] SURVIVED - {desc} [{why}]"

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for kind, line in ex.map(one, selected):  # map keeps the table order
            print(line, flush=True)
            caught += kind == "CAUGHT"
            survived += kind == "SURVIVED"
            not_applied += kind == "NOT APPLIED"
    os.rmdir(work)
    checks = sorted({m[1] for m in selected if m[1].startswith("CD")})
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(f"checks with mutants: {len(checks)} ({','.join(checks)})")
    print(
        f"RESULT: {caught} caught, {survived} survived, {not_applied} not applied of {len(selected)}{subset}"
        + (
            f" (+ {len(EQUIVALENT)} documented equivalent: {', '.join(EQUIVALENT)})"
            if EQUIVALENT
            else ""
        )
    )
    return 0 if survived == 0 and not_applied == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
