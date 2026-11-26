#!/usr/bin/env python3
"""Mutation pass for ops/validator-host/systemd/install.sh (PR #269).

usage: mutants.py CLONE   (a checkout of the PR head; never modified)
Each mutant replaces one exact snippet once in a temporary copy of the clone,
shows the diff, runs the static part of scripts/test-validator-host-sandbox
and must make it exit non-zero. Exit 0 only if the unmutated baseline passes
and every mutant applies once and is caught.
"""
import difflib
import os
import shutil
import subprocess
import sys
import tempfile

TARGET = "ops/validator-host/systemd/install.sh"
MUTANTS = [
    ("restart always", 'if [ "$restart" -eq 1 ]; then', "if true; then"),
    ("dry-run executes", 'if [ "$dry" -eq 1 ]; then\n    echo "dry-run: $*"', 'if false; then\n    echo "dry-run: $*"'),
    ("no rollback on mismatch", "check_effective || rollback", "check_effective || true"),
    ("LoadState not checked", '[ "$load_state" = loaded ] ||', "true ||"),
    ("path in unit name allowed", "*/* | .* | *..*)", "*/nothing)"),
    ("drop-in mode 0666", 'install -m 0644 "$src"', 'install -m 0666 "$src"'),
    ("true shown as no", "true) echo yes ;;", "true) echo no ;;"),
    ("uninstall keeps file", 'run rm -f "$dest"', 'run true "$dest"'),
    ("no daemon-reload on install", 'run install -m 0644 "$src" "$dest"\nrun "$SYSTEMCTL" daemon-reload',
     'run install -m 0644 "$src" "$dest"\nrun true'),
    ("timer units allowed", "*.service) ;;\n  *) echo \"UNIT must end in .service", "*) ;;\n  *.never) echo \"UNIT must end in .service"),
]


def run_static(tree):
    env = dict(os.environ)
    env.pop("SANDBOX_NODE_BIN", None)
    p = subprocess.run([os.path.join(tree, "scripts/test-validator-host-sandbox")], env=env,
                       capture_output=True, text=True)
    fails = [line for line in p.stdout.splitlines() if line.startswith("FAIL")]
    result = [line for line in p.stdout.splitlines() if line.startswith("RESULT")]
    return p.returncode, fails, result[-1] if result else "no RESULT line"


def main():
    clone = os.path.abspath(sys.argv[1])
    base = os.environ.get("TMPDIR", "/tmp")
    ok = True
    rc, _, result = run_static(clone)
    print(f"baseline (unmutated): exit {rc} {result}")
    ok &= rc == 0
    for name, old, new in MUTANTS:
        tree = tempfile.mkdtemp(dir=base)
        try:
            shutil.copytree(clone, tree, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git"))
            path = os.path.join(tree, TARGET)
            src = open(path).read()
            count = src.count(old)
            print(f"\n== mutant: {name} (matches {count})")
            if count != 1:
                print("NOT APPLIED")
                ok = False
                continue
            mutated = src.replace(old, new, 1)
            open(path, "w").write(mutated)
            sys.stdout.writelines(difflib.unified_diff(src.splitlines(True), mutated.splitlines(True),
                                                       f"a/{TARGET}", f"b/{TARGET}", n=0))
            rc, fails, result = run_static(tree)
            for line in fails:
                print("  " + line)
            caught = rc != 0
            print(f"  exit {rc} {result} -> {'CAUGHT' if caught else 'SURVIVED'}")
            ok &= caught
        finally:
            shutil.rmtree(tree)
    print("\nRUN", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
