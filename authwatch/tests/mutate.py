#!/usr/bin/env python3
"""Mutation controls for authwatch: the collector (pft-authwatch.sh), the parser (authwatch_parse.py) and the alert
rules (alerts/authwatch.rules.yml). Same harness as ../../statewatch/tests/mutate.py.

Each mutant replaces one exact text that must occur EXACTLY ONCE in its target (else: NOT APPLIED, which counts as a
harness failure). The mutated copy is tested in a temp dir:
  sh / py  -> bash tests/run-tests.sh MUTATED_SH MUTATED_PY   CAUGHT = suite reached its RESULT line with >= 1 FAIL
  rules    -> promtool test rules authwatch.tests.yml          CAUGHT = promtool reported a FAILED test case (a rules
              file that no longer parses is BROKEN, not caught)
The FAIL lines / failing test names of every catch are printed. Control runs of the unmutated files must pass first.

Usage: python3 -u authwatch/tests/mutate.py      (needs docker for promtool; PROM_IMAGE, DOCKER as in alerts/)
Exit 0 only if every mutant was applied and caught.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AW = os.path.dirname(HERE)
ALERTS = os.path.join(AW, "..", "alerts")
SH = os.path.join(AW, "pft-authwatch.sh")
PY = os.path.join(AW, "authwatch_parse.py")
RULES = os.path.join(ALERTS, "authwatch.rules.yml")
TESTS = os.path.join(ALERTS, "authwatch.tests.yml")
PROM_IMAGE = os.environ.get("PROM_IMAGE", "prom/prometheus:v3.5.0")
DOCKER = os.environ.get("DOCKER", "sudo docker").split()

MUTANTS = [
    # --- collector (sh)
    ("S01", "sh", "saved cursor ignored (always -n 1)", 'if [ -n "$cur" ]; then', "if false; then"),
    ("S02", "sh", "journalctl errors ignored", 'if [ "$rc" -ne 0 ] && { [ "$rc" -eq 124 ] || [ -s "$err" ]; }; then',
     "if false; then"),
    ("S03", "sh", "no timeout around journalctl --after-cursor",
     'timeout "$JOURNAL_TIMEOUT" "$JOURNALCTL" "${q[@]}" --after-cursor', '"$JOURNALCTL" "${q[@]}" --after-cursor'),
    ("S04", "sh", "journal filter drops sudo", "SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sudo)", "SYSLOG_IDENTIFIER=sshd)"),
    ("S05", "sh", "validate: host label not checked", 'index($0, "{" h) == 0 {', "0 {"),
    ("S06", "sh", "pull: temp file kept after a validation failure", 'rm -f "$tmp"; die "validation failed: $why" 2',
     'die "validation failed: $why" 2'),
    ("S07", "sh", "--stdout works on the real state", '--state "$out/state.json"', '--state "$state"'),
    ("S08", "sh", "allowlist import does not dedupe",
     "awk -v fp=\"$fp\" '$1 == fp { found = 1 } END { exit !found }' \"$ALLOWLIST\" && continue", "false && continue"),
    ("S09", "sh", "pull: no timeout around ssh", 'timeout "$PULL_TIMEOUT" $PULL_SSH', "$PULL_SSH"),
    ("S10", "sh", "validate: up sample not required", "if (!up) {", "if (0) {"),
    # --- parser (py)
    ("P01", "py", "companion lines of an invalid user counted as aborted auth (double count)",
     "(?:Connection closed by|Connection reset by|Disconnected from) authenticating user",
     "(?:Connection closed by|Connection reset by|Disconnected from) (?:authenticating|invalid) user"),
    ("P02", "py", "allowlist ignored", '"allowlisted" if fp in allow else "unknown"', '"unknown"'),
    ("P03", "py", "cursor not advanced (re-run double counts)", 'st["cursor"] = e["__CURSOR"]', "pass"),
    ("P04", "py", "baseline run counts history", "    if a.baseline:", "    if False:"),
    ("P05", "py", "byte-array MESSAGE dropped", "if isinstance(msg, list):", "if False:"),
    ("P06", "py", "allowlisted logins move last_unknown_login", 'if label[1] != "allowlisted":', "if True:"),
    ("P07", "py", "algorithm negotiation failures counted as failed auth", 'if kind == "negotiate":', "if False:"),
    ("P08", "py", "write not atomic (temp file left behind)", "os.replace(tmp, path)",
     "open(path, \"w\").write(open(tmp).read())"),
    ("P09", "py", "sudo wrong-password lines counted as ok", 'return "sudo", "auth_failure" if m.group(1) else "ok"',
     'return "sudo", "ok"'),
    ("P10", "py", "password login classed allowlisted", '"other", "none")', '"other", "allowlisted")'),
    # --- rules
    ("R01", "rules", "unknown-key alert ignores keyless (password) logins", 'key_class!="allowlisted"',
     'key_class="unknown"'),
    ("R02", "rules", "burst threshold below the background peak", "[10m])) > 400", "[10m])) > 300"),
    ("R03", "rules", "burst per reason instead of summed",
     "sum by (instance, job, host) (increase(pft_authwatch_ssh_failed_total[10m])) > 400",
     "increase(pft_authwatch_ssh_failed_total[10m]) > 400"),
    ("R04", "rules", "stale after 10 min instead of 5", "pft_authwatch_collect_timestamp_seconds > 300",
     "pft_authwatch_collect_timestamp_seconds > 600"),
    ("R05", "rules", "stale without for: 2m", "        for: 2m\n", ""),
]


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def run_suite(sh, py):
    r = subprocess.run(["bash", os.path.join(HERE, "run-tests.sh"), sh, py], capture_output=True, text=True, timeout=900)
    out = r.stdout + r.stderr
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL ")]
    result = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    return r.returncode, fails, result


def run_promtool(rules_text, workdir):
    d = tempfile.mkdtemp(dir=workdir)
    os.chmod(d, 0o755)
    open(os.path.join(d, "authwatch.rules.yml"), "w").write(rules_text)
    shutil.copy(TESTS, os.path.join(d, "authwatch.tests.yml"))
    for f in os.listdir(d):
        os.chmod(os.path.join(d, f), 0o644)
    r = subprocess.run(DOCKER + ["run", "--rm", "-v", "%s:/w:ro" % d, "-w", "/w", "--entrypoint", "promtool", PROM_IMAGE,
                                 "test", "rules", "authwatch.tests.yml"], capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    names = re.findall(r"^\s+name: (.*),\s*$", out, re.M)
    shutil.rmtree(d)
    return r.returncode, out, names


def main():
    work = tempfile.mkdtemp()
    try:
        print("# pft-authwatch.sh sha256 %s" % sha(SH))
        print("# authwatch_parse.py sha256 %s" % sha(PY))
        print("# authwatch.rules.yml sha256 %s" % sha(RULES))
        print("# authwatch.tests.yml sha256 %s" % sha(TESTS))
        print("# run-tests.sh sha256 %s" % sha(os.path.join(HERE, "run-tests.sh")))
        rc, fails, result = run_suite(SH, PY)
        print("# control sh/py: %s rc %d" % (result[0] if result else "no RESULT", rc))
        if rc != 0 or fails:
            print("\n".join(fails))
            print("CONTROL FAILED - no mutant counted")
            return 1
        rc, out, names = run_promtool(open(RULES).read(), work)
        print("# control rules: promtool rc %d (%s)" % (rc, "SUCCESS" if "SUCCESS" in out and rc == 0 else "FAILED"))
        if rc != 0:
            print(out)
            print("CONTROL FAILED - no mutant counted")
            return 1
        caught = notapplied = broken = 0
        for mid, kind, what, old, new in MUTANTS:
            src = {"sh": SH, "py": PY, "rules": RULES}[kind]
            text = open(src).read()
            n = text.count(old)
            if n != 1:
                notapplied += 1
                print("%s NOT APPLIED (%d matches) - %s" % (mid, n, what))
                continue
            mtext = text.replace(old, new)
            if kind == "rules":
                rc, out, names = run_promtool(mtext, work)
                if rc != 0 and names:
                    caught += 1
                    print("%s CAUGHT - %s" % (mid, what))
                    for nm in names:
                        print("    failed: %s" % nm)
                elif rc != 0:
                    broken += 1
                    print("%s BROKEN (promtool error, no test ran) - %s\n%s" % (mid, what, out[-400:]))
                else:
                    print("%s SURVIVED - %s" % (mid, what))
                continue
            m = os.path.join(work, "%s.%s" % (mid, kind))
            open(m, "w").write(mtext)
            sh, py = (m, PY) if kind == "sh" else (SH, m)
            rc, fails, result = run_suite(sh, py)
            if result and fails:
                caught += 1
                print("%s CAUGHT %s - %s" % (mid, result[0], what))
                for f in fails:
                    print("    %s" % f)
            elif not result:
                broken += 1
                print("%s BROKEN (suite ended without RESULT, rc %d) - %s" % (mid, rc, what))
            else:
                print("%s SURVIVED %s - %s" % (mid, result[0], what))
        total = len(MUTANTS)
        print("MUTANTS: %d/%d caught, %d not applied, %d broken, %d survived"
              % (caught, total, notapplied, broken, total - caught - notapplied - broken))
        return 0 if caught == total else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
