#!/usr/bin/env python3
"""Mutation controls for statewatch: the collector (pft-statewatch.sh), the parser (statewatch_parse.py) and the
alert rules (alerts/statewatch.rules.yml).

Each mutant replaces one exact text that must occur EXACTLY ONCE in its target (else: NOT APPLIED, which counts as a
harness failure). The mutated copy is tested in a temp dir:
  sh / py  -> bash tests/run-tests.sh MUTATED_SH MUTATED_PY   CAUGHT = suite reached its RESULT line with >= 1 FAIL
  rules    -> promtool test rules statewatch.tests.yml         CAUGHT = promtool reported a FAILED test case (a rules
              file that no longer parses is BROKEN, not caught)
The FAIL lines / failing test names of every catch are printed, so each catch can be checked against what the mutant
claims to break. Control runs of the unmutated files must pass first, or nothing is counted.

Usage: python3 -u statewatch/tests/mutate.py      (needs docker for promtool; PROM_IMAGE, DOCKER as in alerts/)
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
SW = os.path.dirname(HERE)
ALERTS = os.path.join(SW, "..", "alerts")
SH = os.path.join(SW, "pft-statewatch.sh")
PY = os.path.join(SW, "statewatch_parse.py")
RULES = os.path.join(ALERTS, "statewatch.rules.yml")
TESTS = os.path.join(ALERTS, "statewatch.tests.yml")
PROM_IMAGE = os.environ.get("PROM_IMAGE", "prom/prometheus:v3.5.0")
DOCKER = os.environ.get("DOCKER", "sudo docker").split()

MUTANTS = [
    # --- collector (sh)
    ("S01", "sh", "docker stderr merged into the answer again (first sentry install bug)",
     'http://127.0.0.1:5005/ 2>"$errf")"; then', 'http://127.0.0.1:5005/ 2>&1)"; then'),
    ("S02", "sh", "up always 1", 'pft_statewatch_up{$L} $([ -z "$err" ] && echo 1 || echo 0)', "pft_statewatch_up{$L} 1"),
    ("S03", "sh", "write not atomic (copy, temp file left)", 'mv -f "$tmp" "$1/$2"', 'cp "$tmp" "$1/$2"'),
    ("S04", "sh", "failed collection exits 0", "\"$err\" >&2; return 1; fi", "\"$err\" >&2; return 0; fi"),
    ("S05", "sh", "no outer timeout around docker exec", 'timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec', '"${DOCKER[@]}" exec'),
    ("S06", "sh", "curl without --max-time", 'curl -s --max-time "$RPC_TIMEOUT"', "curl -s"),
    ("S07", "sh", "validate: first label not checked", "if (index(rest, pre) != 1)", "if (0)"),
    ("S08", "sh", "validate: any value accepted", r"\} -?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/", r"\} .*$/"),
    ("S09", "sh", "validate: up sample not required", "if (!up) {", "if (0) {"),
    ("S10", "sh", "validate: size limit dropped", '[ "$size" -le "$MAX_BYTES" ]', "true"),
    ("S11", "sh", "pull: temp file kept after a validation failure", 'rm -f "$tmp"; die "validation failed: $why" 2',
     'die "validation failed: $why" 2'),
    ("S12", "sh", "pull: no timeout around ssh", 'timeout "$PULL_TIMEOUT" $PULL_SSH', "$PULL_SSH"),
    ("S13", "sh", "textfile without final newline", "head+=\"$text\"$'\\n'", 'head+="$text"'),
    ("S14", "sh", "validate: foreign HELP/TYPE comments accepted", "/^# (HELP|TYPE) pft_statewatch_[a-z_]+ / { next }",
     "/^# / { next }"),
    # --- parser (py)
    ("P01", "py", "full_exits = raw full transitions (a restart/first sync counts as an exit)",
     'acct["full"][1] - (1 if in_full else 0)', 'acct["full"][1]'),
    ("P02", "py", "proposing not treated as mode full", 'FULL_STATES = ("full", "validating", "proposing")',
     'FULL_STATES = ("full", "validating")'),
    ("P03", "py", "JSON true accepted as a number", "if isinstance(v, bool):", "if False:"),
    ("P04", "py", "negative integers accepted", "if isinstance(v, int) and v >= 0:", "if isinstance(v, int):"),
    ("P05", "py", "accounting durations divided by 1e3, not 1e6", '"%.6f" % (p["acct"][m][0] / 1e6)',
     '"%.6f" % (p["acct"][m][0] / 1e3)'),
    ("P06", "py", "missing field read as 0", 'raise Bad("missing %s.%s" % (where, key))', "return 0"),
    ("P07", "py", "rpc status not checked", 'if res.get("status") != "success":', "if False:"),
    ("P08", "py", "unknown server_state accepted", "if state not in STATES:", "if False:"),
    ("P09", "py", "full with 0 full transitions accepted", 'if in_full and acct["full"][1] < 1:', "if False:"),
    ("P10", "py", "history write error kills the collection", "except OSError as e:", "except KeyError as e:"),
    ("P11", "py", "transitions exported from the duration field", 'p["acct"][m][1]) for m in MODES]',
     'p["acct"][m][0]) for m in MODES]'),
    ("P12", "py", "decimal strings with a sign/point accepted", 'INT_RE = re.compile(r"^[0-9]{1,20}$")',
     'INT_RE = re.compile(r"^[-0-9.e]{1,20}$")'),
    # --- rules
    ("R01", "rules", "flapping counts raw transitions (restart = 7 transitions)",
     "increase(pft_statewatch_full_exits_total[1h])) >= 3", "increase(pft_statewatch_state_transitions_total[1h])) >= 3"),
    ("R02", "rules", "brief-exit guard (every sample full) dropped", "[10m:1m]) == 1", "[10m:1m]) >= 0"),
    ("R03", "rules", "flapping threshold 2", "[1h])) >= 3", "[1h])) >= 2"),
    ("R04", "rules", "jq overflow on the raw counter (not reset-safe, fires on old drops)",
     "increase(pft_statewatch_jq_trans_overflow_total[15m]) > 0", "pft_statewatch_jq_trans_overflow_total > 0"),
    ("R05", "rules", "jq overflow with delta() (a reset hides new drops)",
     "increase(pft_statewatch_jq_trans_overflow_total[15m]) > 0", "delta(pft_statewatch_jq_trans_overflow_total[15m]) > 0"),
    ("R06", "rules", "io latency without for: 10m", "        for: 10m\n", ""),
    ("R07", "rules", "io latency >= 50", "pft_statewatch_io_latency_ms > 50", "pft_statewatch_io_latency_ms >= 50"),
    ("R08", "rules", "disconnect threshold 60", "[1h]) > 30", "[1h]) > 60"),
    ("R09", "rules", "disconnects with delta() (reset hides a burst)",
     "increase(pft_statewatch_peer_disconnects_total[1h])", "delta(pft_statewatch_peer_disconnects_total[1h])"),
    ("R10", "rules", "collector failing without for: 5m", "expr: pft_statewatch_up == 0\n        for: 5m",
     "expr: pft_statewatch_up == 0\n        for: 1m"),
    ("R11", "rules", "stale threshold 3000 s", "pft_statewatch_collect_timestamp_seconds > 300",
     "pft_statewatch_collect_timestamp_seconds > 3000"),
    ("R12", "rules", "brief exit checks only the current state (instant, no 10m subquery)",
     'min_over_time((sum by (instance, job, container) (pft_statewatch_server_state{state=~"full|validating|proposing"}))[10m:1m]) == 1',
     'sum by (instance, job, container) (pft_statewatch_server_state{state=~"full|validating|proposing"}) == 1'),
    ("R13", "rules", "brief-exit window 1m (exit gone before the next evaluation)",
     "increase(pft_statewatch_full_exits_total[10m])", "increase(pft_statewatch_full_exits_total[1m])"),
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
    open(os.path.join(d, "statewatch.rules.yml"), "w").write(rules_text)
    shutil.copy(TESTS, os.path.join(d, "statewatch.tests.yml"))
    for f in os.listdir(d):
        os.chmod(os.path.join(d, f), 0o644)
    r = subprocess.run(DOCKER + ["run", "--rm", "-v", "%s:/w:ro" % d, "-w", "/w", "--entrypoint", "promtool", PROM_IMAGE,
                                 "test", "rules", "statewatch.tests.yml"], capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    names = re.findall(r"^\s+name: (.*),\s*$", out, re.M)
    shutil.rmtree(d)
    return r.returncode, out, names


def main():
    work = tempfile.mkdtemp()
    try:
        print("# pft-statewatch.sh sha256 %s" % sha(SH))
        print("# statewatch_parse.py sha256 %s" % sha(PY))
        print("# statewatch.rules.yml sha256 %s" % sha(RULES))
        print("# statewatch.tests.yml sha256 %s" % sha(TESTS))
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
