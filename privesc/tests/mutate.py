#!/usr/bin/env python3
"""Mutation check for the pft-privesc test suites (tests/run-tests.sh + tests/test_owner.py).

Each mutant is one exact text replacement in a temp copy of pft-privesc.sh or privesc_classify.py; the target text
must occur exactly once (else NOT APPLIED, which counts as a harness failure). Both suites then run against the
mutated copies. A mutant is CAUGHT if a suite printed a FAIL line (run-tests.sh: RESULT line present; test_owner.py:
unittest FAIL/ERROR) or hung past the per-run timeout (lesson: a mutant that removes a loop exit hangs, not fails);
an aborted suite with no FAIL line is not a catch. The FAIL lines are printed so each description can be checked
against them. A control run on the unmodified copies must pass first.
  python3 tests/mutate.py          exit 0 = control passed and every mutant applied and was caught
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = {
    "sh": os.path.join(HERE, "..", "pft-privesc.sh"),
    "py": os.path.join(HERE, "..", "privesc_classify.py"),
}
TIMEOUT = 300

# (id, file, description, old, new)
MUTANTS = [
    (
        "M31",
        "py",
        "account hash not keyed by machine-id",
        '(self.salt + ":" + acct).encode()',
        "acct.encode()",
    ),
    (
        "M01",
        "py",
        "world-writable bit ignored",
        "if mode & 0o002 and not sticky_dir:",
        "if False:",
    ),
    (
        "M02",
        "py",
        "group-writable bit ignored",
        "if mode & 0o020 and st.st_gid not in ctx.root_uids and not sticky_dir:",
        "if False:",
    ),
    (
        "M03",
        "py",
        "sticky exemption also applied to the file itself (i > 0 dropped)",
        "mode & stat.S_ISVTX and i > 0",
        "mode & stat.S_ISVTX",
    ),
    (
        "M04",
        "py",
        "sticky dirs not exempted",
        "sticky_dir = stat.S_ISDIR(st.st_mode) and mode & stat.S_ISVTX and i > 0",
        "sticky_dir = False",
    ),
    (
        "M05",
        "py",
        "unpackaged SUID treated as packaged",
        "        if not pkg:\n            act = (",
        "        if False:\n            act = (",
    ),
    (
        "M06",
        "py",
        "dpkg --verify md5 changes ignored",
        "if path in md5 or (pkgpath and pkgpath in md5):",
        "if False:",
    ),
    (
        "M07",
        "py",
        "unneeded list ignored (pkexec -> REVIEW)",
        "        if path in unneeded:",
        "        if False:",
    ),
    (
        "M08",
        "py",
        "sudo's includedir reads names with a dot",
        'if not n.endswith("~") and "." not in n',
        'if not n.endswith("~")',
    ),
    (
        "M09",
        "py",
        "!env_reset not detected",
        'if re.search(r"!\\s*env_reset\\b", dtext):',
        "if False:",
    ),
    (
        "M10",
        "py",
        "NOPASSWD shell-escape check off",
        'if "NOPASSWD" in r["tags"] and os.path.basename(path) in SHELL_ESCAPE:',
        "if False:",
    ),
    (
        "M11",
        "py",
        "non-root units checked too (User= filter dropped)",
        'if u.get("User") not in ("", "root", "0", None):',
        "if False:",
    ),
    (
        "M12",
        "py",
        "relative PATH entries accepted",
        '            if not e.startswith("/"):',
        '            if e == "never":',
    ),
    (
        "M13",
        "py",
        "nologin service accounts graded like logins",
        'if shells.get(m, "") in NOLOGIN:',
        "if False:",
    ),
    (
        "M14",
        "py",
        "full-sudo members of root-equivalent groups graded FAIL",
        "elif m in sudo_users or mine & sudo_groups:",
        "elif False:",
    ),
    (
        "M15",
        "py",
        "runtime socket other-bits ignored",
        "        if mode & 0o007:",
        "        if False:",
    ),
    (
        "M16",
        "py",
        "container docker.sock mounts ignored",
        'r"/(docker|containerd)\\.sock$|/lxd/unix\\.socket$"',
        'r"^$"',
    ),
    (
        "M17",
        "py",
        "full-root rule detection off (agent in docker -> FAIL)",
        'if "ALL" not in expand(aliases, "Cmnd_Alias", [r["cmd"]]):',
        "if True:",
    ),
    (
        "M18",
        "py",
        "actions not deduplicated per (type, path)",
        "if action and (action[0], action[2]) not in {",
        "if action and () not in {",
    ),
    (
        "M19",
        "sh",
        "PROTECTED check by resolved path dropped (/bin/sudo slips through)",
        '[[ "$PROTECTED" == *" $path "* || "$PROTECTED" == *" $real "* ]]',
        '[[ "$PROTECTED" == *" $path "* ]]',
    ),
    (
        "M20",
        "sh",
        "visudo pre-check off",
        'visudo_ok || die "visudo -c fails before apply',
        'true || die "visudo -c fails before apply',
    ),
    (
        "M21",
        "sh",
        "agent sudo pre-check off",
        'agent_sudo_ok || die "AGENT_USER',
        'true || die "AGENT_USER',
    ),
    (
        "M22",
        "sh",
        "no agent/visudo check after a sudoers change",
        "if $sudoers_touched && ! { visudo_ok && agent_sudo_ok; }; then",
        "if false; then",
    ),
    (
        "M23",
        "sh",
        "undo does not verify stat",
        '[ "$now_st" = "$mode $uid $gid" ] ||',
        "true ||",
    ),
    (
        "M24",
        "sh",
        "undo does not verify content sha256",
        '[ "$(sha "$(P "$path")")" = "$sum" ] ||',
        "true ||",
    ),
    (
        "M25",
        "sh",
        "undo walks the manifest oldest-first",
        'done < <(tac "$f")',
        'done < <(cat "$f")',
    ),
    (
        "M26",
        "sh",
        "statoverride of a replaced override not removed first",
        '[ "$ov" != - ] && "$STATOVERRIDE" --remove "$pkgpath" > /dev/null 2>&1',
        "true",
    ),
    (
        "M27",
        "sh",
        "suid-remove via plain chmod (no statoverride)",
        '"$STATOVERRIDE" --update --add "$(stat -c %U "$(P "$path")")" "$(stat -c %G "$(P "$path")")" "$arg" "$pkgpath" > /dev/null',
        'chmod "$arg" "$(P "$path")"',
    ),
    (
        "M28",
        "sh",
        "failed run's entries left in the manifest after rollback",
        'grep -vxF -f "$t/run.tsv" "$BACKUP/manifest.tsv" > "$BACKUP/manifest.tsv.new"; mv -f "$BACKUP/manifest.tsv.new" "$BACKUP/manifest.tsv"',
        "true",
    ),
    (
        "M29",
        "sh",
        "validate accepts any metric name",
        "pft_privesc_[a-z_]+\\{host=",
        "[a-z_]+\\{host=",
    ),
    (
        "M30",
        "sh",
        "dry run changes files",
        'if $dry; then log "dry run: nothing changed"; rm -rf "$t"; return 0; fi',
        "true",
    ),
]


def run_suites(sh, py):
    fails, has_result = [], False
    try:
        p = subprocess.run(
            ["bash", os.path.join(HERE, "run-tests.sh"), sh, py],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        has_result = bool(
            re.search(r"^RESULT: \d+ passed, \d+ failed$", p.stdout, re.MULTILINE)
        )
        fails += [ln for ln in p.stdout.splitlines() if ln.startswith("FAIL ")]
    except subprocess.TimeoutExpired:
        return True, ["FAIL run-tests.sh hung (timeout)"]
    env = dict(os.environ, PRIVESC_LIB=os.path.dirname(py))
    try:
        q = subprocess.run(
            [sys.executable, os.path.join(HERE, "test_owner.py")],
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            env=env,
        )
        fails += [
            "FAIL test_owner: " + ln
            for ln in q.stderr.splitlines()
            if re.match(r"^(FAIL|ERROR): ", ln)
        ]
        has_result = has_result and bool(
            re.search(r"^Ran \d+ tests", q.stderr, re.MULTILINE)
        )
    except subprocess.TimeoutExpired:
        return True, fails + ["FAIL test_owner.py hung (timeout)"]
    return has_result, fails


def one(m):
    mid, which, desc, old, new = m
    d = tempfile.mkdtemp()
    try:
        paths = {}
        for k, src in SRC.items():
            paths[k] = os.path.join(d, os.path.basename(src))
            shutil.copy(src, paths[k])
        with open(paths[which]) as f:
            text = f.read()
        n = text.count(old)
        if n != 1:
            return mid, desc, f"NOT APPLIED (target found {n} times)", []
        with open(paths[which], "w") as f:
            f.write(text.replace(old, new))
        res, fails = run_suites(paths["sh"], paths["py"])
        if fails:
            return mid, desc, "CAUGHT", fails
        return mid, desc, "SURVIVED" if res else "SUITE ABORTED (not a catch)", fails
    finally:
        shutil.rmtree(d)


def main():
    res, fails = run_suites(SRC["sh"], SRC["py"])
    print(
        f"control (unmodified): {'RESULT lines present' if res else 'no RESULT line'}, {len(fails)} FAIL lines"
    )
    if not res or fails:
        print("control failed: fix the suite first")
        for ln in fails:
            print("  " + ln)
        return 1
    bad = 0
    with ThreadPoolExecutor(max_workers=4) as ex:
        for mid, desc, verdict, fl in ex.map(one, MUTANTS):
            print(f"{mid} {verdict}: {desc}")
            for ln in fl[:4]:
                print(f"      {ln}")
            if len(fl) > 4:
                print(f"      ... {len(fl) - 4} more FAIL lines")
            bad += verdict != "CAUGHT"
    print(f"RESULT: {len(MUTANTS) - bad}/{len(MUTANTS)} mutants caught")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
