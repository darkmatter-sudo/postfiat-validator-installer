#!/usr/bin/env python3
"""Mutation harness for pft-dnsaudit.sh: each mutant disables one check, guard or parser step; the offline suite
(run-tests.sh, DA_FAILFAST=1) must fail on it. The unmutated script runs first through the same path (baseline must
pass). Every mutant gets its own copy of the script AND its own TEST_TMPDIR; each anchor must occur at the given
occurrence (NOT APPLIED = harness failure). Prints one line per mutant as it completes (CAUGHT + the first FAIL
line, or SURVIVED) and "MUTANTS: caught N/M"; exit 0 only if the baseline passed and all were caught.
   python3 -I dnsaudit/tests/mutate.py [-j 4] [--only M01,M07]"""

import concurrent.futures as cf
import os
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "pft-dnsaudit.sh")
SUITE = os.path.join(HERE, "run-tests.sh")
TIMEOUT = 900
# id, what it breaks, old text, new text, which occurrence (1-based)
MUTANTS = [
    (
        "M01",
        "ntfy/apt source without names",
        'grade FAIL "source:$s" "no name derived (files:',
        'row PASS "source:$s" "no name derived (files:',
        1,
    ),
    (
        "M02",
        "vl/registry source without names",
        'grade FAIL "source:$s" "no name derived from the container\'s',
        'row PASS "source:$s" "no name derived from the container\'s',
        1,
    ),
    (
        "M03",
        "container not running (sources)",
        'if [ -z "$CROOT" ]; then grade FAIL "source:$s"',
        'if [ -z "$CROOT" ]; then row PASS "source:$s"',
        1,
    ),
    ("M04", "IP literals are not peer names", 'is_ip "$h" || echo "$h"', 'echo "$h"', 1),
    (
        "M05",
        "qualified image registry host",
        'echo "${first%%:*}"',
        "printf '%s\\n' registry-1.docker.io auth.docker.io",
        1,
    ),
    (
        "M06",
        "host-path resolution",
        'if [ "${cnt:-0}" -gt 0 ]; then row PASS "resolve:$n"',
        'if true; then row PASS "resolve:$n"',
        1,
    ),
    (
        "M07",
        "container-path resolution",
        'if [ "$st" = NOERROR ]; then row PASS "cresolve:$n"',
        'if true; then row PASS "cresolve:$n"',
        1,
    ),
    ("M08", "glibc AD flag without trust-ad", '[ "$C_TRUSTAD" = 1 ] || CF=(+noadflag)', "CF=()", 1),
    ("M09", "trust-ad detection", '"$f" && C_TRUSTAD=1', '"$f"; C_TRUSTAD=0', 1),
    ("M10", "redundancy needs 2 resolvers", 'if [ "$N_UP" -ge 2 ]', 'if [ "$N_UP" -ge 1 ]', 1),
    (
        "M11",
        "no upstream resolver",
        'else grade FAIL redundancy "no upstream',
        'else row PASS redundancy "no upstream',
        1,
    ),
    (
        "M12",
        "upstream answers",
        'if [ "$st" = NOERROR ]; then row PASS "upstream:$i"',
        'if true; then row PASS "upstream:$i"',
        1,
    ),
    (
        "M13",
        "upstream DNSSEC: AD required",
        '[ "$st" = NOERROR ] && has_flag ad "$fl" && [ "$bad" = SERVFAIL ]',
        '[ "$st" = NOERROR ] && [ "$bad" = SERVFAIL ]',
        1,
    ),
    (
        "M14",
        "upstream DNSSEC: bogus must SERVFAIL",
        'has_flag ad "$fl" && [ "$bad" = SERVFAIL ]; then',
        'has_flag ad "$fl"; then',
        1,
    ),
    (
        "M15",
        "host path bogus control",
        'if [ "$(host_resolves "$DNSSEC_BAD")" -gt 0 ] 2>/dev/null; then',
        "if false; then",
        1,
    ),
    (
        "M16",
        "container path bogus control",
        'if [ "$st" = SERVFAIL ]; then row PASS dnssec:container',
        "if true; then row PASS dnssec:container",
        1,
    ),
    ("M17", "signed-name count", 'has_flag ad "$fl" && { N_SIGNED=', "true && { N_SIGNED=", 1),
    ("M18", "LLMNR listener", "if grep -Eq ':5355$' <<<\"$lis\"", "if false", 1),
    ("M19", "LLMNR global on", 'elif [[ "$glob" == *"+LLMNR"* ]]', "elif false", 1),
    ("M20", "mDNS is udp only", "if grep -Eq '^udp .*:5353$' <<<\"$lis\"", "if grep -Eq ':5353$' <<<\"$lis\"", 1),
    ("M21", "mDNS listener", "if grep -Eq '^udp .*:5353$' <<<\"$lis\"", "if false", 1),
    ("M22", "mDNS global on", 'elif [[ "$glob" == *"+mDNS"* ]]', "elif false", 1),
    ("M23", "global block ends at the first link", "/^Link / { g = 0 } ", "", 1),
    ("M24", "stub nameserver 127.0.0.53 only", ' && [ "$ns" = "127.0.0.53 " ]', "", 1),
    (
        "M25",
        "stub without nameserver",
        'elif [ -z "$ns" ]; then grade FAIL stub',
        "elif false; then grade FAIL stub",
        1,
    ),
    (
        "M26",
        "embedded DNS needs ExtServers",
        'if [ "$C_EXT" = 1 ]; then row PASS embedded',
        "if true; then row PASS embedded",
        1,
    ),
    (
        "M27",
        "container needs 2 direct nameservers",
        'elif [ "${#C_NS[@]}" -ge 2 ]; then row PASS embedded',
        'elif [ "${#C_NS[@]}" -ge 1 ]; then row PASS embedded',
        1,
    ),
    (
        "M28",
        "container without nameserver",
        'elif [ "${#C_NS[@]}" = 0 ]; then grade FAIL embedded',
        "elif false; then grade FAIL embedded",
        1,
    ),
    ("M29", "acceptance expiry boundary", 'if [ "$(now)" -lt "$e" ]', 'if [ "$(now)" -le "$e" ]', 1),
    ("M30", "acceptance names its check", '[ "$c" = "$1" ] || continue', "true", 1),
    (
        "M31",
        "expired acceptance is ignored",
        'printf \'EXPIRED %s\' "$(date -u -d "@$e" +%FT%TZ)"; return 2',
        'printf \'%s x\' "$(date -u -d "@$e" +%FT%TZ)"; return 0',
        1,
    ),
    ("M32", "--name never writes the textfile", '[ -n "$extra" ] && [ "$tf" = 1 ] && die', "false && die", 1),
    ("M33", "up 0 when tools are missing", '[ "$tf" = 1 ] && write_textfile "$(metrics 0 "$t0")"', "true", 1),
    ("M34", "no findings series when up 0", '[ "$1" = 1 ] || return 0', "true", 1),
    ("M35", "pull: host label", "if (index(rest, pre) != 1)", "if (0)", 1),
    (
        "M36",
        "pull: metric prefix",
        "if (match($0, /^pft_dnsaudit_[a-z_]+\\{/) == 0)",
        "if (match($0, /^[a-z_]+\\{/) == 0)",
        1,
    ),
    ("M37", "pull: size cap", '[ "$size" -le "$MAX_BYTES" ]', "true", 1),
    ("M38", "pull: up sample required", "if (!up) { print", "if (0) { print", 1),
    (
        "M39",
        "pull: invalid fetch keeps old copy",
        'rm -f "$tmp"; die "validation failed',
        'mv -f "$tmp" "$TEXTFILE_DIR/pft_dnsaudit_$PEER_LABEL.prom"; die "validation failed',
        1,
    ),
    (
        "M40",
        "resolver addresses never printed",
        'row PASS "upstream:$i" "answers',
        'row PASS "upstream:$i" "$a answers',
        1,
    ),
    ("M41", "names unique across sources", 'case "$seen" in *" $n "*) continue ;; esac', "", 1),
    ("M42", "URL port stripped", "s#:[0-9]+$##", "", 1),
    ("M43", "container queries in its netns", 'else out="$("$NSENTER" -t "$pid" -n -- "$DIG"', 'else out="$("$DIG"', 1),
    ("M44", "no status line = TIMEOUT", '"${st:-TIMEOUT}"', '"${st:-NOERROR}"', 1),
    ("M45", "next nameserver after a timeout", '[ "${a%% *}" = TIMEOUT ] || break', "break", 1),
    ("M46", "textfile write failure is an error", "|| rc=2; }", "; }", 1),
]


def mutate(src, old, new, nth):
    i = -1
    for _ in range(nth):
        i = src.find(old, i + 1)
        if i < 0:
            raise SystemExit(f"NOT APPLIED: anchor not found: {old!r} (occurrence {nth})")
    return src[:i] + new + src[i + len(old) :]


def read(path):
    with open(path) as fh:
        return fh.read()


def run(m):
    mid, what, old, new, nth = m
    src = read(SRC)
    with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))) as d:
        p = os.path.join(d, "pft-dnsaudit.sh")
        with open(p, "w") as fh:
            fh.write(src if mid == "BASE" else mutate(src, old, new, nth))
        os.chmod(p, 0o755)
        scratch = os.path.join(d, "scratch")
        os.mkdir(scratch)
        env = dict(os.environ, TEST_TMPDIR=scratch, DA_FAILFAST="" if mid == "BASE" else "1")
        pr = subprocess.Popen(
            ["bash", SUITE, p],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            start_new_session=True,
        )
        try:
            out, _ = pr.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(pr.pid, signal.SIGKILL)
            pr.communicate()
            return f"TIMEOUT  {mid} {what}", False
        fails = [x for x in out.splitlines() if x.startswith("FAIL ")]
        res = [x for x in out.splitlines() if x.startswith("RESULT: ")]
        if mid == "BASE":
            okb = pr.returncode == 0 and not fails and bool(res)
            return f"BASELINE {'PASS' if okb else 'FAIL'} {res[-1] if res else '(no RESULT line)'}", okb
        if pr.returncode != 0 and fails:
            return f"CAUGHT   {mid} {what:<40} by: {fails[0][5:]}", True
        return f"SURVIVED {mid} {what:<40} (suite rc {pr.returncode})", False


if __name__ == "__main__":
    argv = sys.argv[1:]
    jobs = int(argv[argv.index("-j") + 1]) if "-j" in argv else 4
    only = argv[argv.index("--only") + 1].split(",") if "--only" in argv else None
    src = read(SRC)
    for m in MUTANTS:
        if mutate(src, m[2], m[3], m[4]) == src:
            raise SystemExit(f"NOT APPLIED: {m[0]} changes nothing")
    line, okb = run(("BASE", "unmutated", "", "", 1))
    print(line, flush=True)
    if not okb:
        sys.exit(2)
    todo = [m for m in MUTANTS if only is None or m[0] in only]
    n = 0
    with cf.ThreadPoolExecutor(jobs) as ex:
        for fut in cf.as_completed([ex.submit(run, m) for m in todo]):
            line, c = fut.result()
            n += c
            print(line, flush=True)
    print(f"MUTANTS: caught {n}/{len(todo)}")
    sys.exit(0 if n == len(todo) else 1)
