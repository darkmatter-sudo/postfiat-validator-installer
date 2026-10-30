#!/usr/bin/env python3
"""Mutation check for the pft-sshcrypto test suite.

Each mutant is one exact text replacement in a temp copy of pft-sshcrypto.sh or sshcrypto_grade.py; the target text
must occur exactly once (else NOT APPLIED, which counts as a harness failure). tests/run-tests.sh then runs against
the mutated copies. A mutant is CAUGHT only if the suite printed its RESULT line with at least one FAIL line (an
aborted suite is not a catch); the FAIL lines are printed so each description can be checked against them. A control
run on the unmodified copies must pass first. Mutants run 4 at a time (each suite run takes about a minute).
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
    "sh": os.path.join(HERE, "..", "pft-sshcrypto.sh"),
    "py": os.path.join(HERE, "..", "sshcrypto_grade.py"),
}

MUTANTS = [
    (
        "M01",
        "py",
        "SHA-1 MAC rule dropped (hmac-sha1 falls to 'not in policy' WARN)",
        '    ("mac", "*sha1*", FAIL, "SHA-1"),\n',
        "",
    ),
    (
        "M02",
        "py",
        "CBC ciphers graded OK",
        '("cipher", "*-cbc*", FAIL, "CBC mode")',
        '("cipher", "*-cbc*", OK, "CBC mode")',
    ),
    (
        "M03",
        "py",
        "small DH group-exchange moduli ignored",
        "if moduli_min < 3071:",
        "if False:",
    ),
    ("M04", "py", "RSA 2048-3071 graded OK", "if bits < 3072:", "if bits < 1:"),
    (
        "M05",
        "py",
        "host key files graded even when no offered algorithm uses them",
        "offered = any(x.startswith(fam) for x in offered_hk) if fam else True",
        "offered = True",
    ),
    (
        "M06",
        "py",
        "any ECDSA key taken to serve every nistp curve (false probe mismatch on P-384/521)",
        'return ("ECDSA", int(alg[len("ecdsa-sha2-nistp") :])) in types',
        'return any(t == "ECDSA" for t, _ in types)',
    ),
    (
        "M07",
        "py",
        "host key certificates treated as available keys (cert chosen as positive control)",
        '    if "-cert-" in alg or alg.startswith("sk-"):',
        '    if alg.startswith("sk-"):',
    ),
    (
        "M08",
        "py",
        "probe outcome never compared with sshd -T",
        'ok = result == "skipped" or (expected == "offered") == (result == "negotiated")',
        "ok = True",
    ),
    (
        "M09",
        "py",
        "probe that could not run is not an audit error",
        'if result.startswith("error"):',
        "if False:",
    ),
    (
        "M10",
        "py",
        "probe mismatch does not make the result FAIL",
        "elif counts[FAIL] or mism:",
        "elif counts[FAIL]:",
    ),
    (
        "M11",
        "py",
        "failed audit still writes findings series (reads as 'all fine')",
        "    if up:\n",
        "    if True:\n",
    ),
    (
        "M12",
        "sh",
        "restart instead of reload",
        'if ! "$SYSTEMCTL" reload "$SSH_UNIT"; then',
        'if ! "$SYSTEMCTL" restart "$SSH_UNIT"; then',
    ),
    (
        "M13",
        "sh",
        "confirm always succeeds (token not checked)",
        """if [ "$(printf '%s' "$out" | tr -d '\\r' | tail -1)" = "$TOKEN" ]; then return 0; fi""",
        "return 0",
    ),
    (
        "M14",
        "sh",
        "failed confirmation stops the revert timer",
        'log "not committed: $TIMER.timer rolls back at',
        '"$SYSTEMCTL" stop "$TIMER.timer"; log "not committed: x',
    ),
    (
        "M15",
        "sh",
        "sshd -t failure leaves the drop-in in place",
        'restore_pre; die "sshd -t rejected the policy',
        'die "sshd -t rejected the policy',
    ),
    (
        "M16",
        "sh",
        "shadowed policy not detected",
        """if [ "$(printf '%s\\n' "$eff" | awk -v k="${d,,}" '$1==k{print $2; exit}')" != "$v" ]; then""",
        "if false; then",
    ),
    (
        "M17",
        "sh",
        "rollback does not compare the file manifest",
        'if [ "$m_now" != "$(cat "$PRE/manifest")" ]; then',
        "if false; then",
    ),
    (
        "M18",
        "sh",
        "rollback does not compare sshd -T",
        '[ "$e_now" = "$(cat "$PRE/effective.sha256")" ] || die',
        "true || die",
    ),
    (
        "M19",
        "sh",
        "snapshot retaken on every apply (rollback returns to the hardened state)",
        'if [ ! -d "$PRE" ]; then',
        'if true; then rm -rf "$PRE";',
    ),
    (
        "M20",
        "sh",
        "a drop-in that did not exist before is not removed on rollback",
        'if [ -f "$PRE/dropin.absent" ]; then rm -f "$DROPIN"; else',
        "if false; then :; else",
    ),
    (
        "M21",
        "sh",
        "restored file loses its mtime (cp without -p)",
        'else cp -p "$PRE/dropin" "$DROPIN"; fi',
        'else cp "$PRE/dropin" "$DROPIN"; fi',
    ),
    (
        "M22",
        "sh",
        "pull skips validation of the peer's file",
        'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then',
        "if false; then",
    ),
    (
        "M23",
        "sh",
        "pull without timeout",
        'if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat',
        "if ! $PULL_SSH cat",
    ),
    (
        "M24",
        "sh",
        "'no matching' read as negotiated",
        '*"no matching"*) echo rejected ;;',
        '*"no matching"*) echo negotiated ;;',
    ),
    (
        "M25",
        "sh",
        "MAC probes without a forced non-AEAD cipher (MAC never negotiated)",
        'extra=(-o "Ciphers=$nonaead")',
        "extra=()",
    ),
    (
        "M26",
        "sh",
        "unknown env keys accepted silently",
        """*) printf 'pft-sshcrypto: unknown key %s in %s\\n' "$k" "$CONF" >&2; exit 2 ;;""",
        "*) ;;",
    ),
    (
        "M27",
        "sh",
        "automatic revert also stops its own timer",
        '$auto || "$SYSTEMCTL" stop "$TIMER.timer" 2>/dev/null',
        '"$SYSTEMCTL" stop "$TIMER.timer" 2>/dev/null',
    ),
    (
        "M28",
        "sh",
        "apply while a revert is armed",
        'if "$SYSTEMCTL" is-active --quiet "$TIMER.timer" || [ -f "$STATE/pending" ]; then',
        "if false; then",
    ),
    (
        "M29",
        "sh",
        "post-reload audit not required for commit",
        """if [ "$rc" -eq 2 ] || grep -q 'MISMATCH' "$STATE/apply-audit.txt"; then""",
        "if false; then",
    ),
    (
        "M30",
        "sh",
        "--revert-after minimum not enforced",
        'if ! [[ "$after" =~ ^[0-9]+$ ]] || [ "$after" -lt 30 ]; then',
        "if false; then",
    ),
    (
        "M31",
        "sh",
        "reload runs in place of arming the revert timer (sshd changed with no revert armed)",
        'if ! "$SYSTEMD_RUN" --quiet --collect',
        'if ! "$SYSTEMCTL" reload "$SSH_UNIT" && ! "$SYSTEMD_RUN" --quiet --collect',
    ),
    (
        "M32",
        "sh",
        "non-crypto directives allowed in a policy",
        "grep -qvE '^[[:space:]]*(#|$|(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms)[[:space:]])' \"$policy\"",
        "false",
    ),
    (
        "M33",
        "sh",
        "confirm ssh at LogLevel ERROR (the failure reason is lost, as in live run 08)",
        "-o HostKeyAlias=pft-sshcrypto-loopback -o LogLevel=INFO",
        "-o HostKeyAlias=pft-sshcrypto-loopback -o LogLevel=ERROR",
    ),
    (
        "M34",
        "sh",
        "confirm ssh without -T (pty notice printed instead of the failure reason, as in live run 10)",
        'out="$(timeout 30 "$SSH" -T -F /dev/null',
        'out="$(timeout 30 "$SSH" -F /dev/null',
    ),
]


def run_suite(sh, py):
    p = subprocess.run(
        ["bash", os.path.join(HERE, "run-tests.sh"), sh, py],
        check=False,
        capture_output=True,
        text=True,
        timeout=900,
    )
    out = p.stdout
    res = re.search(r"^RESULT: (\d+) passed, (\d+) failed$", out, re.MULTILINE)
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL ")]
    return res, fails


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
        res, fails = run_suite(paths["sh"], paths["py"])
        if res and fails:
            return mid, desc, "CAUGHT", fails
        return mid, desc, "SURVIVED" if res else "SUITE ABORTED (not a catch)", fails
    finally:
        shutil.rmtree(d)


def main():
    res, fails = run_suite(SRC["sh"], SRC["py"])
    print(f"control (unmodified): {res.group(0) if res else 'no RESULT line'}")
    if not res or fails:
        print("control failed: fix the suite first")
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
