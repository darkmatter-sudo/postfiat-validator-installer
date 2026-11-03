#!/usr/bin/env python3
"""Mutation harness for pft-keyescrow.sh + keyescrow_tar.py: each mutant is one exact text replacement in one of the
two files (it must match exactly once, else NOT APPLIED, which counts as a harness failure). Both offline suites
(run-tests.sh: inventory, run-escrow-tests.sh: keygen/seal/escrow/verify/restore with the real age binary) run
against mutated copies; the mutant is KILLED if a suite fails with a FAIL line and a RESULT line. Mutants in
EQUIVALENT are reported, not counted (reason given).
Every suite run has a timeout and runs in its own session with stdin from /dev/null; on timeout the whole process
group is killed and the mutant counts as KILLED (a hang is a detected change). An unmutated control run must pass
first, or nothing is counted. After the run, no process from a mutant copy may be left (orphan check).
Usage: python3 tests/mutate.py [-j JOBS] [--timeout SEC] [IDS...]"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = {
    "sh": os.path.join(HERE, "..", "pft-keyescrow.sh"),
    "py": os.path.join(HERE, "..", "keyescrow_tar.py"),
}
SUITES = ("run-tests.sh", "run-escrow-tests.sh")
# /tmp is noexec on hosts hardened by ../mounts: keep mutated copies under the user cache dir
TBASE = os.environ.get("TEST_TMPDIR") or os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
)
PREFIX = "pft-keyescrow-mut-"

# id, file, what it breaks, old text, new text
MUTANTS = [
    # inventory integrity checks
    (
        "I1",
        "sh",
        "inventory: wrong mode accepted",
        'if [ "$((8#$have_m))" != "$((8#$mode))" ] ||',
        "if false ||",
    ),
    (
        "I2",
        "sh",
        "inventory: owner not checked",
        '[ "$owner" != "-" ] && [ "$have_o" != "$owner" ] && own=BAD',
        "true",
    ),
    (
        "I3",
        "sh",
        "inventory: group not checked",
        '[ "$group" != "-" ] && [ "$have_g" != "$group" ] && grp=BAD',
        "true",
    ),
    (
        "I4",
        "sh",
        "inventory: symlink / non-file accepted",
        'elif [ -L "$p" ] || [ ! -f "$p" ]; then',
        "elif false; then",
    ),
    (
        "I5",
        "sh",
        "inventory: missing required item read as optional",
        'if [ "$need" = opt ]; then st=absent',
        "if true; then st=absent",
    ),
    (
        "I6",
        "sh",
        "inventory: drift not detected",
        "else esc=drift; n_drift=$((n_drift + 1)); fi",
        "else esc=same; fi",
    ),
    (
        "I7",
        "sh",
        "inventory: never escrowed / new items exit 0",
        '[ $((n_drift + n_new)) -gt 0 ] || [ "$LAST" = 0 ] && SCAN_RC=1',
        "false && SCAN_RC=1",
    ),
    (
        "I8",
        "sh",
        "inventory: fingerprint not keyed",
        '{ cat "$FPF"; cat "$1"; } | sha256sum',
        'cat "$1" | sha256sum',
    ),
    (
        "I9",
        "sh",
        "inventory: unreadable item read as ok",
        'elif [ ! -r "$p" ]; then',
        "elif false; then",
    ),
    # keygen / set-peer
    (
        "K1",
        "sh",
        "keygen: replaces an existing identity",
        '[ -e "$IDF" ] && die "age identity already exists',
        'false && die "age identity already exists',
    ),
    (
        "K2",
        "sh",
        "set-peer: own recipient accepted",
        '[ -r "$AGEPUB" ] && [ "$(cat "$AGEPUB")" = "$1" ] && die',
        "false && die",
    ),
    (
        "K3",
        "sh",
        "set-peer: malformed recipient accepted",
        '[[ "${1:-}" =~ $AGE_RE ]] || die "set-peer: want',
        'true || die "set-peer: want',
    ),
    # seal refusals
    (
        "S1",
        "sh",
        "seal: inventory FAIL items do not refuse",
        'if [ "$SCAN_RC" = 2 ]; then',
        "if false; then",
    ),
    (
        "S2",
        "sh",
        "seal: missing/malformed PEER_RECIPIENT not refused",
        '[[ "$PEER_RECIPIENT" =~ $AGE_RE ]] || die "PEER_RECIPIENT not set',
        'true || die "PEER_RECIPIENT not set',
    ),
    (
        "S3",
        "sh",
        "seal: a failing pack/age pipe is committed",
        'if [ "$rc" != 0 ] || [ ! -s "$tmp" ]; then',
        "if false; then",
    ),
    (
        "S4",
        "sh",
        "seal: no fp_key not refused",
        '[ -s "$FPF" ] || die "no fp_key (run keygen)" 4',
        "true",
    ),
    # escrow bookkeeping
    (
        "E1",
        "sh",
        "escrow: recorded as escrowed without the peer's VERIFIED",
        'if [ "$rc" = 0 ] && grep -qx "VERIFIED from=$HOST_LABEL gen=$g items=[0-9]*" <<<"$out"; then',
        "if true; then",
    ),
    (
        "E2",
        "sh",
        "escrow: pulled generation acked without local verify",
        'if [ "$rc" = 0 ] && grep -qx "VERIFIED from=$PEER_LABEL gen=$g2 items=[0-9]*" <<<"$out"; then',
        "if true; then",
    ),
    (
        "E3",
        "sh",
        "escrow: a failed ack is not a failure",
        'grep -qx "ACKED gen=$g2 items=[0-9]*" <<<"$out" && [ "$rc" = 0 ] || {',
        "true || {",
    ),
    (
        "E4",
        "sh",
        "escrow: PEER_SSH unset not refused",
        '[ -n "$PEER_SSH" ] || die "PEER_SSH not set (see $CONF)" 4\n  echo "pft-keyescrow escrow',
        'true\n  echo "pft-keyescrow escrow',
    ),
    # held copies: receive / verify / prune
    (
        "V1",
        "sh",
        "verify: ciphertext sha256 not compared",
        'if [ -z "$want" ] || [ "$have" != "$want" ]; then',
        "if false; then",
    ),
    (
        "V2",
        "sh",
        "verify: in-memory check result ignored",
        '    rc=$?\n    [ "$rc" = 0 ] || rc=2',
        "    rc=0",
    ),
    (
        "V3",
        "sh",
        "receive: a generation that failed its check is kept (can displace good ones)",
        'if [ "$rc" != 0 ]; then # never let',
        "if false; then # never let",
    ),
    (
        "V4",
        "sh",
        "receive: KEEP ignored",
        'prune "$STORE/$from" "$KEEP"',
        'prune "$STORE/$from" 99',
    ),
    (
        "V5",
        "sh",
        "receive: the host's own label accepted",
        'valid_label "$from" && [ "$from" != "$HOST_LABEL" ] || die "receive: FROM',
        'valid_label "$from" || die "receive: FROM',
    ),
    (
        "V6",
        "sh",
        "serve: unknown verb not refused",
        'die "serve: unknown verb',
        'true "serve: unknown verb',
    ),
    (
        "V7",
        "sh",
        "ack: a generation never sealed is recorded",
        '[[ "$1" =~ $GEN_RE ]] && [ -f "$m" ] || die "no sealed generation',
        'true || die "no sealed generation',
    ),
    # restore refusals
    (
        "X1",
        "sh",
        "restore: no --yes needed",
        '[ "$yes" = 1 ] || [ "$dry" = 1 ] || die',
        "true || die",
    ),
    (
        "X2",
        "sh",
        "restore: no maintenance window needed",
        'if [ "$dry" = 0 ]; then maint_active >&2 || die',
        "if false; then maint_active >&2 || die",
    ),
    (
        "X3",
        "sh",
        "restore: an expired window accepted",
        '[ "$w" = active ] || {',
        '[ "$w" != none ] || {',
    ),
    (
        "X4",
        "sh",
        "restore: missing pft-maint read as an open window",
        '|| { echo "pft-maint not installed: cannot prove a maintenance window is open"; return 1; }',
        "|| return 0",
    ),
    (
        "X5",
        "sh",
        "restore: dry run writes",
        '$([ "$dry" = 1 ] && echo --dry-run) ); rc=$?',
        "); rc=$?",
    ),
    (
        "X6",
        "sh",
        "reseal: a held copy that fails its check is still sent",
        'verify_gen "$from" "$g" >&2 || die "reseal refused',
        'verify_gen "$from" "$g" >&2 || true "reseal refused',
    ),
    # helper: payload / envelope checks
    (
        "P1",
        "py",
        "check: item sha256 mismatch accepted",
        'elif hashlib.sha256(data).hexdigest() != want["sha256"]:',
        "elif False:",
    ),
    (
        "P2",
        "py",
        "check: extra member accepted",
        '                bad.append(f"member {m.name} not in MANIFEST or duplicated")\n                continue',
        "                continue",
    ),
    (
        "P3",
        "py",
        "apply: path outside this host's registry accepted",
        '        if allow.get(ident) != it["path"]:',
        "        if False:",
    ),
    (
        "P4",
        "py",
        "apply: payload for another host accepted",
        '    if man.get("host") != a.host:\n        die(f"payload is for host',
        '    if False:\n        die(f"payload is for host',
    ),
    (
        "P5",
        "py",
        "apply: setuid/setgid/sticky mode accepted",
        '            or int(it["mode"], 8) & 0o7000\n',
        "            or False\n",
    ),
    (
        "P6",
        "py",
        "apply: replaced file not backed up",
        "        if cur is not None and not same:",
        "        if False:",
    ),
    (
        "P7",
        "py",
        "apply: unknown item ignored",
        '            die(f"item {ident} is not in this generation")',
        "            continue",
    ),
    (
        "P8",
        "py",
        "receive: ciphertext sha256 not compared",
        '        if meta.get("cipher_sha256") != got["age"][2]:',
        "        if False:",
    ),
    (
        "P9",
        "py",
        "receive: a generation already held is overwritten",
        "        if os.path.exists(final_meta):",
        "        if False:",
    ),
    (
        "P10",
        "py",
        "receive: ciphertext size not compared",
        '        if meta.get("cipher_bytes") != str(got["age"][3]):',
        "        if False:",
    ),
    # evolving items (journald FSS key)
    (
        "F1",
        "sh",
        "evolving: never recognised (always drift)",
        'elif [[ " $EVOLVING " == *" $id "* ]]; then esc=evolving',
        "elif false; then esc=evolving",
    ),
    (
        "F2",
        "sh",
        "evolving: still counted as drift",
        "esc=evolving; n_evolving=$((n_evolving + 1))",
        "esc=evolving; n_drift=$((n_drift + 1))",
    ),
    (
        "F3",
        "sh",
        "evolving: substring match",
        '[[ " $EVOLVING " == *" $id "* ]]',
        '[[ " $EVOLVING " == *"$id"* ]]',
    ),
    (
        "F4",
        "sh",
        "evolving: no default",
        'EVOLVING="${EVOLVING:-journald:fss}"',
        'EVOLVING="${EVOLVING:-}"',
    ),
    # pull (peer textfiles copied here) and serve textfile
    (
        "U1",
        "sh",
        "pull: foreign lines accepted",
        '[ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }',
        "true",
    ),
    (
        "U2",
        "sh",
        "pull: node label not checked",
        """pft_keyescrow_[a-z_]+\\{node="'"$2"'"(,""",
        """pft_keyescrow_[a-z_]+\\{node="[a-z]+"(,""",
    ),
    (
        "U3",
        "sh",
        "pull: timestamp sample not required",
        """grep -qE '^'"$3"'\\{node="'"$2"'"\\} [0-9]+$' "$f" || { echo "no $3 sample"; return 1; }""",
        "true",
    ),
    (
        "U4",
        "sh",
        "pull: size limit dropped",
        '[ "$(stat -c %s "$f")" -le 65536 ] ||',
        "true ||",
    ),
    (
        "U5",
        "sh",
        "pull: rejected file installed anyway",
        'if ! why="$(validate_prom "$tmp" "$PEER_LABEL" "$ts")"; then rm -f "$tmp"; die "pulled $name rejected: $why" 2; fi',
        'why="$(validate_prom "$tmp" "$PEER_LABEL" "$ts")"',
    ),
    (
        "U6",
        "sh",
        "pull: failed remote read not detected",
        '[ "$rc" = 0 ] || { rm -f "$tmp"; die "pull of $name from $PEER_LABEL failed (rc $rc)" 1; }',
        "true",
    ),
    (
        "U7",
        "sh",
        "serve textfile: any name served",
        '[ $# = 1 ] && [[ "$1" =~ ^pft_keyescrow(_held)?$ ]] || die',
        "true || die",
    ),
    (
        "U8",
        "sh",
        "pull: runs without PEER_SSH",
        """  [ -n "$PEER_SSH" ] || die "PEER_SSH not set (see $CONF)" 4
  for name in pft_keyescrow:""",
        """  for name in pft_keyescrow:""",
    ),
    (
        "P11",
        "py",
        "pack: follows symlinks",
        "os.O_RDONLY | os.O_NOFOLLOW",
        "os.O_RDONLY",
    ),
]

EQUIVALENT = {
    "P11": "inventory refuses symlinks (I4) before pack is ever called, so no input reaches pack with a symlink; O_NOFOLLOW is defence in depth",
}


def suite(tool, helper, timeout):
    t0 = time.time()
    out_all, rcs = "", []
    try:
        for s in SUITES:
            env = dict(os.environ, PFT_KEYESCROW_HELPER=helper)
            p = subprocess.Popen(
                ["bash", os.path.join(HERE, s), tool],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                start_new_session=True,
            )
            try:
                stdout, _ = p.communicate(timeout=max(1, timeout - (time.time() - t0)))
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
                raise
            out_all += stdout
            rcs.append(p.returncode)
        return max(rcs), out_all, time.time() - t0
    except subprocess.TimeoutExpired:
        return None, out_all, time.time() - t0


def run(m, srcs, timeout):
    mid, which, desc, old, new = m
    n = srcs[which].count(old)
    if n != 1:
        return mid, desc, f"NOT APPLIED (matches {n})", 0.0
    os.makedirs(TBASE, exist_ok=True)
    d = tempfile.mkdtemp(prefix=f"{PREFIX}{mid}-", dir=TBASE)
    files = {
        "sh": os.path.join(d, "pft-keyescrow.sh"),
        "py": os.path.join(d, "keyescrow_tar.py"),
    }
    for k, path in files.items():
        with open(path, "w") as f:
            f.write(srcs[k].replace(old, new) if k == which else srcs[k])
    try:
        rc, out, secs = suite(files["sh"], files["py"], timeout)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if rc is None:
        return mid, desc, f"KILLED (timeout {timeout}s)", secs
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL ")]
    if rc == 0:
        return mid, desc, "SURVIVED", secs
    if not fails or "RESULT:" not in out:
        return (
            mid,
            desc,
            f"ERROR (rc={rc}, no FAIL/RESULT line: harness problem, not a catch)",
            secs,
        )
    return mid, desc, f"KILLED ({len(fails)} failed: {fails[0][5:70]})", secs


def orphans():
    ps = subprocess.run(
        ["ps", "-eo", "pid,args"], check=False, capture_output=True, text=True
    ).stdout
    return [ln for ln in ps.splitlines() if PREFIX in ln and "ps -eo" not in ln]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("ids", nargs="*")
    a = ap.parse_args()
    srcs = {}
    for k, path in SRC.items():
        with open(path) as f:
            srcs[k] = f.read()
    rc, out, secs = suite(
        os.path.abspath(SRC["sh"]), os.path.abspath(SRC["py"]), a.timeout
    )
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(
        f"CONTROL (unmutated) rc={rc} {' | '.join(last) if last else 'no RESULT line'} {secs:.0f}s",
        flush=True,
    )
    if rc != 0:
        print("RESULT: control run failed - no mutant counted")
        sys.exit(2)
    ms = [m for m in MUTANTS if not a.ids or m[0] in a.ids]
    bad = eq = 0
    with ThreadPoolExecutor(a.j) as ex:
        for mid, desc, verdict, secs in ex.map(lambda m: run(m, srcs, a.timeout), ms):
            if verdict == "SURVIVED" and mid in EQUIVALENT:
                verdict = "EQUIVALENT (documented)"
                desc += " - " + EQUIVALENT[mid]
                eq += 1
            print(f"{mid:4} {verdict:72.72} {secs:5.0f}s  {desc}", flush=True)
            bad += not verdict.startswith(("KILLED", "EQUIVALENT"))
    left = orphans()
    print(f"ORPHANS: {len(left)} process(es) from mutant copies left running")
    for ln in left:
        print(f"  {ln}")
    print(
        f"RESULT: {len(ms) - bad - eq} killed + {eq} documented equivalent of {len(ms)}, {bad} survived, not applied or errored"
    )
    sys.exit(1 if bad or left else 0)


if __name__ == "__main__":
    main()
