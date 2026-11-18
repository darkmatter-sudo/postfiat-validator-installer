#!/usr/bin/env python3
"""Mutation harness for pft-acctpolicy.sh: each mutant breaks one check (one per check ID) or one apply/rollback
guard; the offline suite (run-tests.sh, AP_FAILFAST=1) must fail on every one. Every mutant gets its own copy of
the script AND its own TEST_TMPDIR. Prints one line per mutant (CAUGHT + the first FAIL line, or SURVIVED) and
"MUTANTS: caught N/M"; exit 0 only if all were caught.
   python3 -I acctpolicy/tests/mutants.py [-j 4] [--only M01,M22]"""

import concurrent.futures as cf
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "pft-acctpolicy.sh")
SUITE = os.path.join(HERE, "run-tests.sh")
# id, what it breaks, old text, new text, which occurrence (1-based)
MUTANTS = [
    ("M01", "acct.uid0", '"$n" = 0 ]; then add acct.uid0 PASS', '"$n" = "$n" ]; then add acct.uid0 PASS', 1),
    ("M02", "acct.dup-uid", "sort | uniq -d | wc -l)", "sort | uniq -u | head -0 | wc -l)", 1),
    ("M03", "acct.dup-name", "sort | uniq -d | sed 's/^/g:/'", "sort -u | uniq -d | sed 's/^/g:/'", 1),
    ("M04", "acct.shadowed: hash in passwd", '[ "$pw" = x ] || nox=', '[ -n "$pw" ] || nox=', 1),
    ("M05", "acct.shadowed: missing shadow entry", '[ -n "${SH[$u]+x}" ] || nos=', "true || nos=", 1),
    ("M06", "acct.empty-password", "empty) empty=$((empty + 1)) ;;", "empty) ;;", 1),
    ("M07", "acct.hash-scheme", '*) weak="$weak $k" ;;', "*) ;;", 1),
    ("M08", "hash_kind md5", "'$1$'*) echo md5 ;;", "'$1$'*) echo sha512 ;;", 1),
    (
        "M09",
        "acct.root-password: sshd password",
        '[ "$pa" = no ] && [ "$kbd" = no ] && [ "$prl" != yes ]; then\n         add acct.root-password',
        '[ "$kbd" = no ] && [ "$prl" != yes ]; then\n         add acct.root-password',
        1,
    ),
    (
        "M10",
        "acct.root-password: permitrootlogin",
        '[ "$prl" != yes ]; then\n         add acct.root-password',
        "true; then\n         add acct.root-password",
        1,
    ),
    ("M11", "acct.system-shell: locked", '[ "$k" = locked ] || good=0', "true || good=0", 1),
    ("M12", "acct.system-shell: restrict", '[[ "$line" =~ (^|,)restrict(,|[[:space:]]) ]] && ', "", 1),
    ("M13", "acct.file-modes: shadow", 'mode_ok "$f" 640', 'mode_ok "$f" 777', 1),
    ("M14", "acct.file-modes: owner", '[ "$o" = "$3" ] && ', "", 1),
    ("M15", "acct.home-modes", "& 8#027 )) = 0 ]", "& 8#002 )) = 0 ]", 1),
    ("M16", "pam.nullok: nullok_secure", "grep -qwE 'nullok|nullok_secure'", "grep -qwE 'nullok'", 1),
    ("M17", "pam.nullok: comments", "grep -vE '^[[:space:]]*(#|$)'", "grep -vE '^$'", 1),
    (
        "M18",
        "pam.permit: sufficient",
        '($2 == "sufficient" || $2 ~ /success=(done|[1-9])/)',
        "($2 ~ /success=(done|[1-9])/)",
        1,
    ),
    ("M19", "pam.permit: jump", '($2 == "sufficient" || $2 ~ /success=(done|[1-9])/)', '($2 == "sufficient")', 1),
    (
        "M20",
        "pam.faillock: N/A conditions",
        '[ "$pa" = no ] && [ "$kbd" = no ] && [ "$others" = 0 ]',
        '[ "$kbd" = no ]',
        1,
    ),
    ("M21", "pam.su-wheel: deny form", "$0 !~ /deny/ && ", "", 1),
    (
        "M22",
        "login.encrypt: weak equal",
        ' && [[ "$ph" =~ ^(yescrypt|sha512)$ ]]; then\n    add login.encrypt',
        "; then\n    add login.encrypt",
        1,
    ),
    ("M23", "login.pass-max: min", '&& [ "${mn:-0}" -ge "$PASS_MIN" ] 2>/dev/null', "", 1),
    ("M24", "login.pass-max: max", '[ "${mx:-99999}" -le "$PASS_MAX" ]', '[ "${mx:-99999}" -le 99999 ]', 1),
    ("M25", "login.umask", "& 8#022 )) = $(( 8#022 ))", "& 8#020 )) = $(( 8#020 ))", 1),
    ("M26", "useradd.inactive: upper", '&& [ "$ia" -le "$INACTIVE_DAYS" ]', "", 1),
    ("M27", "useradd.inactive: lower", '[ "${ia:--1}" -ge 1 ]', '[ "${ia:--1}" -ge 0 ]', 1),
    ("M28", "ctr.uid0", '"$n" = 0 ]; then add ctr.uid0 PASS', '"$n" = "$n" ]; then add ctr.uid0 PASS', 1),
    ("M29", "ctr.empty-password: shadow", 'empty="$(awk -F: \'$2 == ""\' "$root/etc/shadow" | wc -l)"', "empty=0", 1),
    ("M30", "ctr.empty-password: passwd", "[ $((nx + empty)) = 0 ]", "[ $((empty)) = 0 ]", 1),
    ("M31", "ctr.runtime: privileged", '[ "$priv" = false ] && ', "", 1),
    ("M32", "ctr.runtime: no-new-privileges", 'grep -q \'"no-new-privileges\' <<<"$sec" && ', "", 1),
    ("M33", "ctr.runtime: capdrop", ' && grep -qE \'"(CAP_)?ALL"\' <<<"$cd"', "", 1),
    ("M34", "ctr: missing container", 'if [ -z "$c" ]; then', "if false; then", 1),
    ("M35", "audit exit code", "grep -qE 'FAIL|WARN' && return 1", "grep -qE 'FAIL' && return 1", 1),
    ("M36", "plan: nullok precondition", "st_of acct.empty-password PASS && echo", "echo", 1),
    ("M37", "plan: su group precondition", 'getent_group "$SU_GROUP" && pam_lines', "pam_lines", 1),
    ("M38", "plan: pam_rootok precondition", 'pam_lines "$PAM_SU" | grep -q pam_rootok && echo', "echo", 1),
    (
        "M39",
        "fix: nullok removal",
        'gsub(/[ \\t]+nullok(_secure)?([ \\t]|$)/, " ", line)',
        'gsub(/[ \\t]+nullok_secure([ \\t]|$)/, " ", line)',
        1,
    ),
    ("M40", "fix: su-wheel marker on the PAM line", 'group=" g }', 'group=" g "  # pft-acctpolicy" }', 1),
    ("M41", "fix: passage min", "| set_key PASS_MIN_DAYS \"$PASS_MIN\" $'\\t'", "", 1),
    ("M42", "apply: --yes", '[ "${1:-}" = --yes ] || die "apply needs --yes', 'true || die "apply needs --yes', 1),
    ("M43", "apply: last apply in place", '[ ! -f "$STATE_DIR/apply.json" ] || die', "true || die", 1),
    ("M44", "apply: node healthy before", 'o="$(node_full)" || die', 'o="$(node_full)" || true', 1),
    ("M45", "node_full: peers", '[ "${pe:-0}" -ge "$MIN_PEERS" ]', "true", 1),
    ("M46", "node_full: state", '[ "$st" = full ] && ', "", 1),
    (
        "M47",
        "apply: self-test before change",
        'o="$(selftest)" || { rm -rf "$nd"; printf',
        'true || { rm -rf "$nd"; printf',
        1,
    ),
    ("M48", "selftest: sshd -t", 'if o="$("$SSHD" -t 2>&1)"; then', "if true; then", 1),
    ("M49", "selftest: root su", 'if [ "$o" = su-ok ]; then', "if true; then", 1),
    ("M50", "selftest: ssh", 'if o="$(ssh_selftest)"; then', 'if o="$(ssh_selftest)" || true; then', 1),
    (
        "M51",
        "selftest: inject",
        'echo "selftest: VERIFY_INJECT=selftest -> forced FAIL (restore drill)"; f=1;',
        "echo inject;",
        1,
    ),
    ("M52", "apply: self-test after change", 'if o="$(selftest post)"; then', "if true; then", 1),
    (
        "M53",
        "apply: restore on failure",
        'restore_from "$b" || { echo "apply $id: RESTORE MISMATCH"; return 5; }',
        ":",
        1,
    ),
    ("M54", "apply: keeps mode", 'chmod --reference="$f" "$f.pft-acctpolicy.tmp" && mv', "mv", 1),
    ("M55", "restore: mode", 'chmod "$m" "$f.pft-acctpolicy.tmp" && mv', "mv", 1),
    ("M56", "restore: sha check", 'if [ "$(sha "$f")" = "$s" ]; then', "if true; then", 1),
    (
        "M57",
        "rollback: --yes",
        '[ "${1:-}" = --yes ] || die "rollback needs --yes"',
        'true || die "rollback needs --yes"',
        1,
    ),
    ("M58", "rollback: nothing applied", '[ -f "$STATE_DIR/apply.json" ] || die "no apply', 'true || die "no apply', 1),
    ("M59", "rollback: mismatch exit", 'restore_from "$b" || return 5', 'restore_from "$b"', 1),
    ("M60", "rollback: clears apply.json", 'rm -f "$STATE_DIR/apply.json"', ":", 1),
    ("M61", "backup dir mode", 'chmod 700 "$STATE_DIR" "$STATE_DIR/backup" "$b"', "true", 1),
]


def mutate(src, old, new, nth):
    i = -1
    for _ in range(nth):
        i = src.find(old, i + 1)
        if i < 0:
            raise SystemExit(f"mutant anchor not found: {old!r} (occurrence {nth})")
    return src[:i] + new + src[i + len(old) :]


def read(path):
    with open(path) as fh:
        return fh.read()


def run(m):
    mid, what, old, new, nth = m
    src = read(SRC)
    with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))) as d:
        p = os.path.join(d, "pft-acctpolicy.sh")
        with open(p, "w") as fh:
            fh.write(mutate(src, old, new, nth))
        os.chmod(p, 0o755)
        scratch = os.path.join(d, "scratch")
        os.mkdir(scratch)
        env = dict(os.environ, TEST_TMPDIR=scratch, AP_FAILFAST="1")
        r = subprocess.run(
            ["bash", SUITE, p],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=1800,
        )
        fails = [l for l in r.stdout.splitlines() if l.startswith("FAIL ")]
        if r.returncode != 0 and fails:
            return f"CAUGHT   {mid} {what:<38} by: {fails[0][5:]}", True
        return f"SURVIVED {mid} {what:<38} (suite rc {r.returncode})", False


if __name__ == "__main__":
    argv = sys.argv[1:]
    jobs = int(argv[argv.index("-j") + 1]) if "-j" in argv else 4
    only = argv[argv.index("--only") + 1].split(",") if "--only" in argv else None  # e.g. --only M14,M22
    src = read(SRC)
    for m in MUTANTS:
        mutate(src, m[2], m[3], m[4])  # every anchor must exist before anything runs
    with cf.ThreadPoolExecutor(jobs) as ex:
        res = list(ex.map(run, [m for m in MUTANTS if only is None or m[0] in only]))
    for line, _ in res:
        print(line, flush=True)
    n = sum(1 for _, c in res if c)
    print(f"MUTANTS: caught {n}/{len(res)}")
    sys.exit(0 if n == len(res) else 1)
