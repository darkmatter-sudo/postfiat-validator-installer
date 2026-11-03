#!/usr/bin/env python3
"""Mutation harness for pft-backfill.sh: each mutant is one exact text replacement (it must match exactly once, else
NOT APPLIED, which counts as a harness failure). Both offline suites (run-tests.sh: status/plan, run-repair-tests.sh:
repair/pull/validate) run against the mutated copy (SCRIPT=...); the mutant is KILLED if either suite fails with a
FAIL line and a RESULT line. Mutants in EQUIVALENT are reported, not counted (reason given).
Every suite run has a timeout; a hang counts as KILLED (a mutant that removes a loop exit hangs instead of failing).
An unmutated control run must pass first, or nothing is counted.
Usage: python3 tests/mutate.py [-j JOBS] [--timeout SEC] [IDS...]"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "pft-backfill.sh")
SUITES = ("run-tests.sh", "run-repair-tests.sh")
# /tmp is noexec on a host hardened by ../mounts: keep mutated copies beside the suites' own temp dirs
TBASE = os.environ.get("TEST_TMPDIR") or os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
)

# id, what it breaks, old text, new text
MUTANTS = [
    # refusals and caps
    (
        "R1",
        "repair: runs on a node that is not full",
        '  jq -e \'.server_state | IN("full","proposing","validating")\' >/dev/null <<<"$sum" \\\n    || die "refused: server_state',
        '  true \\\n    || die "refused: server_state',
    ),
    (
        "R2",
        "repair: runs inside a pft-maint window",
        '[ "$w" = none ] || { echo "pft-maint window is open',
        'true || { echo "pft-maint window is open',
    ),
    (
        "R3",
        "repair: pft-maint failure read as no window (fail open)",
        'j="$("$MAINT" status --json 2>/dev/null)" || { echo "pft-maint status --json failed"; return 1; }',
        'j="$("$MAINT" status --json 2>/dev/null)" || return 0',
    ),
    (
        "R4",
        "repair: missing pft-maint read as no window",
        '|| { echo "pft-maint not installed: cannot prove that no maintenance window is open"; return 1; }',
        "|| return 0",
    ),
    (
        "R5",
        "repair: concurrent runs allowed (lock ignored)",
        'flock -n 9 || die "another pft-backfill repair is running" 4',
        "flock -n 9 || true",
    ),
    (
        "R6",
        "repair: --apply by default (no dry run)",
        "local apply=0 max=16",
        "local apply=1 max=16",
    ),
    ("R7", "cap: --max-ledgers upper bound dropped", '[ "$max" -le 256 ]', "true"),
    ("R8", "cap: --interval 0 accepted", '[ "$INTERVAL" -ge 1 ] &&', "true &&"),
    ("R9", "cap: --wait upper bound dropped", '[ "$WAIT" -le 600 ]', "true"),
    (
        "R10",
        "cap: --max-runtime upper bound dropped",
        '[ "$runtime" -le 1800 ]',
        "true",
    ),
    (
        "R11",
        "runtime cap not checked while waiting",
        '    [ "$(now_s)" -ge "$RUN_END" ] && { R_RESULT=skipped;',
        "    false && { R_RESULT=skipped;",
    ),
    (
        "R12",
        "runtime cap not checked between ledgers",
        '    if [ "$(now_s)" -ge "$RUN_END" ]; then\n      C_skipped',
        "    if false; then\n      C_skipped",
    ),
    (
        "R13",
        "per-ledger wait never times out",
        '[ $(($(now_s) - start)) -ge "$WAIT" ] && {',
        "false && {",
    ),
    (
        "R14",
        "ledger_request re-sent on every poll (rate cap)",
        "if [ $((polls % 5)) = 0 ]; then",
        "if true; then",
    ),
    (
        "R15",
        "no pause between polls",
        '    "$SLEEP" "$INTERVAL"\n    polls=$((polls + 1))',
        "    polls=$((polls + 1))",
    ),
    # verification
    (
        "V1",
        "chain: mismatching arrived hash accepted",
        'elif [ "$R_EXPECT" = "$R_HASH" ]; then chain=ok',
        "elif true; then chain=ok",
    ),
    (
        "V2",
        "prev link: parent mismatch accepted",
        'if [ "${l% *}" = "$R_PARENT" ]; then prev=ok',
        "if true; then prev=ok",
    ),
    (
        "V3",
        "next link: parent mismatch accepted",
        'if [ "${l#* }" = "$R_HASH" ]; then next=ok',
        "if true; then next=ok",
    ),
    (
        "V4",
        "public: mismatch accepted",
        'if [ "$l" = "$R_HASH" ]; then pub=ok',
        "if true; then pub=ok",
    ),
    (
        "V5",
        "verified without any held-neighbour link",
        '[ "$chain" = ok ] && [ "$links" -ge 1 ] && return 0',
        '[ "$chain" = ok ] && return 0',
    ),
    (
        "V6",
        "verified without a validated-chain hash",
        '[ "$chain" = ok ] && [ "$links" -ge 1 ] && return 0',
        '[ "$links" -ge 1 ] && return 0',
    ),
    ("V7", "mismatch does not fail the ledger", '  [ "$bad" -gt 0 ] && return 2\n', ""),
    (
        "V8",
        "hash change between ledger_request calls ignored",
        'if [ -n "$R_EXPECT" ] && [ "$e" != "$R_EXPECT" ]; then',
        "if false; then",
    ),
    (
        "V9",
        "ledger_request errors ignored",
        '*) R_RESULT=failed; R_WHY="ledger_request: $err',
        '*) : R_RESULT=failed; R_WHY="ledger_request: $err',
    ),
    (
        "V10",
        "lgrNotFound acquiring hash (reference ledger) used as the expected hash",
        'e="$(jq -r \'if .result.error then empty else (.result.ledger.ledger_hash // .result.hash // empty) end\' <<<"$a")"',
        'e="$(jq -r \'(.result.ledger.ledger_hash // .result.hash // .result.acquiring.hash // empty)\' <<<"$a")"',
    ),
    (
        "V11",
        "public RPC not retried",
        'for i in 1 2 3; do\n    a="$("$CURL"',
        'for i in 1; do\n    a="$("$CURL"',
    ),
    (
        "V12",
        "public RPC check skipped",
        'elif l="$(public_hash "$s")"; then',
        "elif false; then",
    ),
    (
        "V13",
        "local ledger answer for another sequence accepted",
        "(.ledger.ledger_index | tostring) == $s",
        "true",
    ),
    # result accounting
    (
        "A1",
        "MISMATCH run exits 0",
        'if [ "$C_failed" -gt 0 ]; then rc=2;',
        "if false; then rc=2;",
    ),
    (
        "A2",
        "incomplete run reported PASS",
        'elif [ "$C_verified" = "$C_planned" ]; then rc=0;',
        "elif true; then rc=0;",
    ),
    (
        "A3",
        "timeouts not counted",
        "      timeout) C_timeout=$((C_timeout + 1)) ;;\n",
        "",
    ),
    (
        "A4",
        "repair textfile records exit 0 always",
        'repair_prom 0 "$rc" | write_prom',
        "repair_prom 0 0 | write_prom",
    ),
    (
        "A5",
        "repair textfile dry_run flag inverted",
        'repair_prom "$((1 - apply))" 0',
        'repair_prom "$apply" 0',
    ),
    # node access
    (
        "N1",
        "allowlist dropped",
        '[[ " $RPC_ALLOW " == *" $1 "* ]] || { echo "rpc $1: method not allowlisted"; return 1; }',
        "true",
    ),
    (
        "N2",
        "rpc: empty answer accepted",
        '[ -n "$out" ] || { echo "rpc $1: empty answer"; return 1; }',
        "true",
    ),
    (
        "N3",
        "cfg: whole postfiatd.cfg (with the seed) handed to the parser",
        '(s=="[node_db]") && !/^[[:space:]]*#/ && NF',
        "NF",
    ),
    # pull / validate
    (
        "P1",
        "pull: foreign metric lines accepted",
        '[ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }',
        "true",
    ),
    (
        "P2",
        "pull: missing timestamp sample accepted",
        '|| { echo "no $3 sample"; return 1; }',
        "|| true",
    ),
    (
        "P3",
        "pull: ssh failure read as 'no repair file yet'",
        'if [ "$rc" = 1 ] && [ "$name" = pft_backfill_repair ]; then',
        'if [ "$rc" != 0 ] && [ "$name" = pft_backfill_repair ] || [ "$rc" = 255 ]; then',
    ),
    (
        "P4",
        "pull: node label not checked",
        'pft_backfill_[a-z_]+\\{node="\'"$2"\'"(',
        'pft_backfill_[a-z_]+\\{node="[a-z]+"(',
    ),
]

EQUIVALENT = {
    # every rpc call site passes a literal allowlisted method; the guard defends future edits
    "N1": "no code path calls rpc() with a method outside the allowlist; the suite checks every method actually sent",
}


def suite(path, timeout):
    t0 = time.time()
    out_all, rcs = "", []
    try:
        for s in SUITES:
            env = dict(os.environ, SCRIPT=path)
            p = subprocess.run(
                ["bash", os.path.join(HERE, s)],
                capture_output=True,
                text=True,
                timeout=max(1, timeout - (time.time() - t0)),
                check=False,
                env=env,
            )
            out_all += p.stdout
            rcs.append(p.returncode)
        return max(rcs), out_all, time.time() - t0
    except subprocess.TimeoutExpired:
        return None, out_all, time.time() - t0


def run(m, src, timeout):
    mid, desc, old, new = m
    n = src.count(old)
    if n != 1:
        return mid, desc, f"NOT APPLIED (matches {n})", 0.0
    os.makedirs(TBASE, exist_ok=True)
    d = tempfile.mkdtemp(prefix=f"pft-backfill-mut-{mid}-", dir=TBASE)
    path = os.path.join(d, "pft-backfill.sh")
    with open(path, "w") as f:
        f.write(src.replace(old, new))
    # the mutated copy must find the real parser (it looks beside itself first)
    shutil.copy(os.path.join(HERE, "..", "backfill_parse.py"), d)
    try:
        rc, out, secs = suite(path, timeout)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("ids", nargs="*")
    a = ap.parse_args()
    with open(TOOL) as f:
        src = f.read()
    rc, out, secs = suite(os.path.abspath(TOOL), a.timeout)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(
        f"CONTROL (unmutated) rc={rc} {' | '.join(last) if last else 'no RESULT line'} {secs:.0f}s",
        flush=True,
    )
    if rc != 0:
        print("RESULT: control run failed - no mutant counted")
        sys.exit(2)
    ms = [m for m in MUTANTS if not a.ids or m[0] in a.ids]
    bad = 0
    with ThreadPoolExecutor(a.j) as ex:
        for mid, desc, verdict, secs in ex.map(lambda m: run(m, src, a.timeout), ms):
            if verdict == "SURVIVED" and mid in EQUIVALENT:
                verdict = "EQUIVALENT (documented)"
                desc += " - " + EQUIVALENT[mid]
            print(f"{mid:4} {verdict:72.72} {secs:5.0f}s  {desc}", flush=True)
            bad += not verdict.startswith(("KILLED", "EQUIVALENT"))
    eq = sum(1 for m in ms if m[0] in EQUIVALENT)
    print(
        f"RESULT: {len(ms) - bad - eq} killed + {eq} documented equivalent of {len(ms)}, {bad} survived, not applied or errored"
    )
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
