#!/usr/bin/env python3
"""Mutation harness for pft-mounts.sh: each mutant is one exact text replacement (it must match exactly once, else
NOT APPLIED, which counts as a harness failure). The offline suite (run-tests.sh) must FAIL on every mutant
except the ones listed in EQUIVALENT, where no input can reach the difference (reason given; reported, not counted).
Usage: python3 -I tests/mutate.py [-j JOBS] [--timeout SEC] [IDS...]"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "pft-mounts.sh")

# id, what it breaks, old text, new text
MUTANTS = [
    # gates
    ("G1", "gate: ignore a postfiatd restart (StartedAt)", '{ [ "$sa" = "$before" ] || [ "$mode" = rollback ]; }', 'true'),
    ("G2", "gate: accept any server_state", '[ "$st" = full ]', 'true'),
    ("G3", "gate: skip the peer-port check", 'grep -qE ":$PEER_PORT\\$"; then', 'true; then'),
    ("G4", "gate: ignore the ssh handshake", '[ "$sshok" = 1 ] \\', 'true \\'),
    ("G5", "gate: ignore failed oneshot units", '[ -n "$bad" ] || (( now', 'false || (( now'),
    ("G6", "gate: oneshot Result not checked", '[ "$("$SYSTEMCTL" show -p Result --value "$u" 2>/dev/null)" = success ]', 'true'),
    ("G7", "gate: ignore inactive daemons", '[ -z "$dbad" ] && [ "$sshok"', 'true && [ "$sshok"'),
    ("G8", "gate: ignore the injected miss", '{ [ "$INJECT" != health ] || [ "$mode" = rollback ]; }', 'true'),
    ("G9", "apply: no automatic rollback on a gate miss", 'echo "$(ts) apply: live step or health gate failed -> automatic rollback"\n    live_revert && restore_fstab "$b"', 'echo "$(ts) apply: live step or health gate failed -> automatic rollback"\n    true'),
    ("G10", "apply: findmnt --verify result ignored", 'if ! "$FINDMNT" --verify', 'if false && "$FINDMNT" --verify'),
    ("G11", "apply: refuse-on-conflict dropped", '[ -n "$cf" ] && { echo "REFUSE', 'false && { echo "REFUSE'),
    ("G12", "apply: idempotency check dropped", 'if cmp -s "$FSTAB" "$cand" && audit_quiet; then', 'if false; then'),
    ("G13", "rollback: sha256 compare dropped", '[ "$(sha "$b")" = "$(sha "$FSTAB")" ] ||', 'true ||'),
    ("G14", "rollback: live.state replayed in apply order", 'done < <(tac "$st")', 'done < "$st"'),
    ("G15", "rollback: rollback failure not reported (exit 5)", 'health_gate "$before" "$c" "$daemons" rollback || return 5\n    return 1', 'health_gate "$before" "$c" "$daemons" rollback || return 1\n    return 1'),
    ("W1", "apply: runs without a pft-maint window", '[ "$dry" = 1 ] || maint_window apply || return 4', 'true'),
    ("W2", "rollback: runs without a pft-maint window", '  maint_window rollback || return 4\n', ''),
    ("W3", "window check: exit status of pft-maint active ignored", '"$MAINT" active >/dev/null 2>&1 && {', '{ "$MAINT" active >/dev/null 2>&1; } ; {'),
    ("W4", "dry run: diff headers carry file times (local timezone)", 'diff -u --label /etc/fstab --label fstab.candidate "$FSTAB"', 'diff -u "$FSTAB"'),
    # live steps
    ("L1", "live: /proc remount drops its per-mount flags", '"remount,$po,hidepid=invisible', '"remount,hidepid=invisible'),
    ("L2", "live: /tmp never self-bound", 'else "$MOUNT" --bind "$t" "$t" || return 1; echo "created $t"', 'else echo "created $t"'),
    ("L3", "live: noexec missing on /tmp,/var/tmp", 'remount,bind,nodev,nosuid,noexec "$t"', 'remount,bind,nodev,nosuid "$t"'),
    ("L4", "live: container remount skipped", '"$NSENTER" -t "$pid" -m -- mount --options-mode ignore -o "remount,bind,$co,$DATA_OPTS" "$DATA_DEST" || return 1', 'true'),
    ("L5", "live: apt conf not written", 'printf \'// managed by pft-mounts', 'true || printf \'// managed by pft-mounts'),
    ("L6", "rollback: pre-existing apt conf not restored", 'cp -p "$BACKUP_DIR/aptconf.orig" "$APTCONF" &&', 'true &&'),
    ("L7", "rollback: apt conf left behind", 'elif rm -f "$APTCONF"; then', 'elif true; then'),
    # audit grading
    ("A1", "audit: duplicate fstab targets not warned", '[ "$n" -gt 1 ] && res WARN', 'false && res WARN'),
    ("A2", "audit: first duplicate wins instead of last", "fs_last() { awk -F'\\t' -v t=\"$2\" '$2 == t { l = $0 }", "fs_last() { awk -F'\\t' -v t=\"$2\" '$2 == t && l == \"\" { l = $0 }"),
    ("A3", "audit: commented fstab lines parsed", "awk '/^[ \\t]*(#|$)/ { next } NF >= 2 {", "awk '/^[ \\t]*$/ { next } NF >= 2 {"),
    ("A4", "audit: tmp.mount enablement ignored", '[ -f "$TMPUNIT" ] && [ -e "$TMPWANT" ]', '[ -f "$TMPUNIT" ]'),
    ("A5", "audit: hidepid=ptraceable counted as hiding", "hidepid=(invisible|2|noaccess|1)", "hidepid=(invisible|2|noaccess|1|ptraceable)"),
    ("A6", "audit: /dev/shm absent graded by covering mount", 'if [ -z "$top" ]; then\n      res FAIL "$cis.1"', 'if false; then\n      res FAIL "$cis.1"'),
    ("A7", "audit: dedicated data fs entry not consulted", '[ -z "$line" ] && [ "$(cut -f1 <<<"$cov")" != / ] && line=', 'false && line='),
    ("A8", "audit: live-only option graded PASS", 'elif [ -z "$p" ] || ! has_opt "$(cut -f2 <<<"$p")" "$n"; then res WARN', 'elif false; then res WARN'),
    ("A9", "audit: apt TempDir on a noexec mount accepted", 'elif has_opt "$(cut -f2 <<<"$am")" noexec; then res FAIL', 'elif false; then res FAIL'),
    ("A10", "audit: host path printed (no volume label)", "sed -E 's#^/var/lib/docker/volumes/([^/]+)/_data$#<docker-volume:\\1>#' <<<\"$1\"", 'cat <<<"$1"'),
    ("A11", "audit: \\040 not decoded in fstab", 't = $2; gsub(/\\\\040/, " ", t); s = $1', 't = $2; s = $1'),
    ("A12", "audit: reads its own (sandboxed) mount table", 'MOUNTINFO="$R/proc/1/mountinfo"', 'MOUNTINFO="$R/proc/self/mountinfo"'),
    # opt-in hidepid
    ("H1", "default: fstab gets the proc line without HIDEPID=1", '[ "$HIDEPID" = 1 ] && echo "proc /proc', 'echo "proc /proc'),
    ("H2", "default: /proc remounted without HIDEPID=1", 'if [ "$HIDEPID" = 1 ]; then\n    po=', 'if true; then\n    po='),
    ("H3", "default: group created without HIDEPID=1", 'if [ "$HIDEPID" = 1 ] && [ -z "$gid" ]; then', 'if [ -z "$gid" ]; then'),
    ("H4", "default: hidepid graded without HIDEPID=1", 'if [ "$HIDEPID" != 1 ]; then\n    res INFO', 'if false; then\n    res INFO'),
    # textfile / pull
    ("P1", "validate: foreign lines accepted", '[ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }', 'true'),
    ("P2", "pull: rejected file still installed", 'rm -f "$tmp"; die "pulled file rejected: $why" 2', 'mv -f "$tmp" "$TEXTFILE_DIR/pft_mounts_$PEER_LABEL.prom"; die "pulled file rejected: $why" 2'),
    ("P3", "prom: host label missing on findings", 'echo "pft_mounts_findings{host=\\"$h\\"} $FINDINGS"', 'echo "pft_mounts_findings $FINDINGS"'),
]

EQUIVALENT = {
    # restore_fstab runs `cp -p BACKUP FSTAB || return 1` right before the compare: once cp succeeded the bytes are
    # equal, so only a lying filesystem reaches the sha256 branch. Kept as a belt-and-braces check.
    "G13": "cp -p succeeded => bytes equal; no test input reaches the sha256 mismatch branch",
    # live.state records each target exactly once (created OR remount, never both), so undo steps touch disjoint
    # mounts and their order cannot change the result.
    "G14": "every live.state line names a different mount; undo order is unobservable",
}


def run(m, src, timeout):
    mid, desc, old, new = m
    n = src.count(old)
    if n != 1:
        return mid, desc, f"NOT APPLIED (matches {n})", 0.0
    d = tempfile.mkdtemp(prefix=f"mut-{mid}-")
    path = os.path.join(d, "pft-mounts.sh")
    with open(path, "w") as f:
        f.write(src.replace(old, new))
    t0 = time.time()
    try:
        p = subprocess.run(["bash", os.path.join(HERE, "run-tests.sh"), path], capture_output=True, text=True, timeout=timeout, check=False)
        fails = [ln for ln in p.stdout.splitlines() if ln.startswith("FAIL ")]
        verdict = f"KILLED ({len(fails)} failed: {fails[0][5:60] if fails else 'rc=' + str(p.returncode)})" if p.returncode != 0 else "SURVIVED"
    except subprocess.TimeoutExpired:
        verdict = f"KILLED (timeout {timeout}s)"
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return mid, desc, verdict, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("ids", nargs="*")
    a = ap.parse_args()
    with open(TOOL) as f:
        src = f.read()
    ms = [m for m in MUTANTS if not a.ids or m[0] in a.ids]
    bad = 0
    with ThreadPoolExecutor(a.j) as ex:
        for mid, desc, verdict, secs in ex.map(lambda m: run(m, src, a.timeout), ms):
            if verdict == "SURVIVED" and mid in EQUIVALENT:
                verdict = "EQUIVALENT (documented)"
                desc += " - " + EQUIVALENT[mid]
            print(f"{mid:4} {verdict:60.60} {secs:5.0f}s  {desc}", flush=True)
            bad += not verdict.startswith(("KILLED", "EQUIVALENT"))
    eq = sum(1 for m in ms if m[0] in EQUIVALENT)
    print(f"RESULT: {len(ms) - bad - eq} killed + {eq} documented equivalent of {len(ms)}, {bad} survived or not applied")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
