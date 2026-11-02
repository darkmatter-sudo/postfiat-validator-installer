#!/usr/bin/env python3
"""Mutation harness for pft-apparmor.sh: apply each mutant (exactly one textual match) to a copy of the tool, run
tests/run-tests.sh against it with a timeout, and count it CAUGHT if the suite fails (or hangs: a hang is a
caught mutant, never a stuck harness). An unmutated control run must pass first; a mutant whose text does not
match exactly once is NOT APPLIED and fails the harness.
Usage: python3 -u tests/mutate.py [--timeout SEC]
Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "pft-apparmor.sh")
SUITE = os.path.join(HERE, "run-tests.sh")

# (id, description, old text, new text)
MUTANTS = [
    ("M01", "kernel check accepts any value", '[ "$en" = Y ] && add PASS kernel', '[ -n "$en$en" ] || [ -z "$en" ] && add PASS kernel'),
    ("M02", "docker-default graded PASS", 'docker-default) add FAIL container', 'docker-default) add PASS container'),
    ("M03", "complain mode graded PASS", 'complain) add WARN mode', 'complain) add PASS mode'),
    ("M04", "WARN not counted as a finding", "case \"$1\" in FAIL|WARN) FINDINGS", "case \"$1\" in FAIL) FINDINGS"),
    ("M05", "boot check skips the parse", 'elif ! "$PARSER" -Q -K "$f" >/dev/null 2>&1; then', 'elif false; then'),
    ("M06", "boot check skips apparmor.service", 'elif ! "$SYSTEMCTL" is-enabled apparmor.service >/dev/null 2>&1; then', 'elif false; then'),
    ("M07", "recreate: compose override not required", '[ "$found" = 1 ] && add PASS recreate', 'true && add PASS recreate'),
    ("M08", "cap_drop ALL not required", 'index("ALL") != null', 'true'),
    ("M09", "nnp :false accepted", 'test("^no-new-privileges(:true|=true)?$")', 'test("^no-new-privileges")'),
    ("M10", "denials: window ignored", "if (e < t + 0) next", "if (0) next"),
    ("M11", "denials: other profiles with the same prefix counted", 'index($0, "profile=\\"" p "\\"") || index($0, "profile=\\"" p "//")', 'index($0, "profile=\\"" p)'),
    ("M12", "denials: count shown but graded PASS", 'else add WARN denials', 'else add PASS denials'),
    ("M13", "denials: unreadable log graded PASS", 'then DENIED=0; add FAIL denials', 'then DENIED=0; add PASS denials'),
    ("M14", "prom: failing check exported as 1", '($1 == "PASS") }', '1 }'),
    ("M15", "prom: INFO exported", "$1 != \"INFO\" { printf", "1 { printf"),
    ("M16", "events: socket addresses kept", 'if (f != "") print "net\\t" f " " field("sock_type") "\\t-"; next', 'if (f != "") print "net\\t" f " " field("sock_type") " " field("faddr") $0 "\\t-"; next'),
    ("M17", "events: T0 ignored", 'if (substr($0, RSTART + 6, RLENGTH - 6) + 0 < t + 0) next', 'if (0) next'),
    ("M18", "events: DENIED lines dropped", 'index($0, "apparmor=\\"ALLOWED\\"") || index($0, "apparmor=\\"DENIED\\"") {', 'index($0, "apparmor=\\"ALLOWED\\"") {'),
    ("M19", "generate: tree rule without the directory itself", 'echo "$t{,**}"; return ;; "${t%/}")', 'echo "$t**"; return ;; "${t%/}")'),
    ("M20", "generate: /proc pid not normalized", "s#^/proc/[0-9]+/#@{PROC}/@{pid}/#;", ""),
    ("M21", "generate: overlap check disabled", '[ "$bad" = 0 ] || exit 4', 'true'),
    ("M22", "generate: write mask dropped for a/c/d", '[[ "$m" =~ [wacd] ]] && o+=w', '[[ "$m" == *w* ]] && o+=w'),
    ("M23", "generate: lock mask dropped", '[[ "$m" == *k* ]] && o+=k', 'true'),
    ("M24", "generate: --caps ignored", 'for k in $caps; do k="${k,,}"; CAP[${k#cap_}]=1; done', 'true'),
    ("M25", "generate: exec rule loses r for scripts", 'echo "  $k rix,"; else', 'echo "  $k ix,"; else'),
    ("M26", "generate: deny 'network raw' (blocks netlink, enforce probe 04)", 'audit deny network inet raw,', 'audit deny network raw,'),
    ("M27", "generate: ptrace read allow dropped", 'echo "  ptrace (read,readby) peer=$name,', 'echo "  # (read,readby) peer=$name,'),
    ("M28", "generate: EXTRA_EXEC ignored", 'for k in $EXTRA_EXEC; do EX[$k]=1; done', 'true'),
    ("M29", "generate: gshadow deny dropped", '"/etc/gshadow rwklx" ', ''),
    ("M30", "generate: /tmp exec deny dropped", '"/tmp/** x" ', ''),
    ("M31", "generate: unknown kind accepted", '*) die "unknown event kind', '*) true "unknown event kind'),
]

# Equivalent mutants (no input can reach the difference), documented instead of counted:
# M32 "overlap: {,**} probe not expanded" (probe="$p"): every AUDIT_DENY path is either exact (never matches a
# tree rule) or ends in "/**" (ERE ".*"), which matches the literal "{,**}" suffix as well as "x/y". Run 07
# (5f27eaf) reported it SURVIVED; re-check this note if a deny pattern with a single "*" or a mid-path "**" is added.
EQUIVALENT = ["M32"]


def run_suite(tool, timeout):
    try:
        r = subprocess.run(["bash", SUITE, tool], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "HANG", ""
    return ("PASS" if r.returncode == 0 else "FAIL"), r.stdout


def main():
    timeout = 300
    if "--timeout" in sys.argv:
        timeout = int(sys.argv[sys.argv.index("--timeout") + 1])
    src = open(TOOL).read()
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="pft-aa-mut.", dir=base)
    st, out = run_suite(TOOL, timeout)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(f"control (unmutated): {st} {last[-1] if last else ''}")
    if st != "PASS":
        print("RESULT: control run failed, mutants not run")
        return 2
    caught = survived = not_applied = 0
    for mid, desc, old, new in MUTANTS:
        n = src.count(old)
        if n != 1:
            print(f"{mid} NOT APPLIED ({n} matches) - {desc}")
            not_applied += 1
            continue
        path = os.path.join(work, f"{mid}.sh")
        with open(path, "w") as f:
            f.write(src.replace(old, new, 1))
        st, out = run_suite(path, timeout)
        fails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
        if st == "PASS":
            survived += 1
            print(f"{mid} SURVIVED - {desc}")
        else:
            caught += 1
            why = "suite hung (timeout)" if st == "HANG" else f"{len(fails)} failing: {'; '.join(fails[:2])}"
            print(f"{mid} CAUGHT - {desc} [{why}]")
        os.remove(path)
    os.rmdir(work)
    print(f"RESULT: {caught} caught, {survived} survived, {not_applied} not applied of {len(MUTANTS)}"
          f" (+ {len(EQUIVALENT)} documented equivalent: {', '.join(EQUIVALENT)})")
    return 0 if survived == 0 and not_applied == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
