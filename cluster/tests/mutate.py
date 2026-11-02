#!/usr/bin/env python3
"""Mutation harness for pft-cluster.sh: each mutant is one exact text replacement (it must match exactly once, else
NOT APPLIED, which counts as a harness failure). The offline suite (run-tests.sh) must FAIL on every mutant except
the ones listed in EQUIVALENT, where no input can reach the difference (reason given; reported, not counted).
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
TOOL = os.path.join(HERE, "..", "pft-cluster.sh")
# /tmp is noexec on a host hardened by ../mounts; the mutated copy itself is run with `bash FILE`, but keep it beside
# the suite's own temp dirs
TBASE = os.environ.get("TEST_TMPDIR") or os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"))

# id, what it breaks, old text, new text
MUTANTS = [
    # health gate
    ("G1", "gate: restart not required (StartedAt)", '[ "$sa" != "$before" ] && [ -n "$sa" ] && [ "$st" = full ]', '[ "$st" = full ]'),
    ("G2", "gate: any server_state accepted", '[ "$st" = full ] && [ "$pk" = "$want" ]', 'true && [ "$pk" = "$want" ]'),
    ("G3", "gate: pubkey_node not compared", '[ "$pk" = "$want" ] && [ -z "$dbad" ]', 'true && [ -z "$dbad" ]'),
    ("G4", "gate: loaded member not required", '{ [ "$mem" = 1 ] && [ "$INJECT" != health ]; }', '{ [ "$INJECT" != health ]; }'),
    ("G5", "gate: injected miss ignored", '[ "$mem" = 1 ] && [ "$INJECT" != health ]', '[ "$mem" = 1 ]'),
    ("G6", "gate: --require-peer ignored", '{ [ "$need" != 1 ] || {', '{ true || {'),
    ("G7", "gate: report age bound dropped", '[[ "$age" =~ ^[0-9]+$ ]] && [ "$age" -le "$REPORT_MAX" ]; }; }; then', '[[ "$age" =~ ^[0-9]+$ ]]; }; }; then'),
    ("G8", "gate: stopped pft daemons ignored", '[ -z "$dbad" ] && [ "$sshok" = 1 ] \\', 'true && [ "$sshok" = 1 ] \\'),
    ("G9", "gate: ssh handshake ignored", '[ -z "$dbad" ] && [ "$sshok" = 1 ] \\', '[ -z "$dbad" ] && true \\'),
    ("G10", "gate: peer port not checked", '&& "$SS" -Hltn 2>/dev/null | awk \'{print $4}\' | grep -qE ":$PEER_PORT\\$" \\', '&& true \\'),
    ("G11", "apply: no automatic rollback on a gate miss", 'restore_cfg "$b" "$cfg" && restart_node "$c" && health_gate "$before" "$c" "$daemons" rollback "$prepub" 0 || return 5', 'true'),
    ("G12", "apply: failed rollback not reported (exit 5)", 'rollback "$prepub" 0 || return 5', 'rollback "$prepub" 0 || return 1'),
    ("G13", "restore: sha256 compare dropped", '[ "$(sha "$1")" = "$(sha "$2")" ] || { echo "$(ts) rollback: config sha256 mismatch', 'true || { echo "$(ts) rollback: config sha256 mismatch'),
    ("G14", "restore: original mode/owner not restored", 'chown "$u:$g" "$2" 2>/dev/null; chmod "$m" "$2" || return 1', 'true'),
    ("G15", "rollback: no restart after the restore", '  restart_node "$c" || return 5\n', ''),
    ("G16", "rollback gate: pre-apply key not expected", 'health_gate "$before" "$c" "$daemons" rollback "$want" 0 || return 5', 'health_gate "$before" "$c" "$daemons" rollback "$(server_field "$c" pubkey_node)" 0 || return 5'),
    # windows and refusals
    ("W1", "apply: runs without a pft-maint window", '  maint_window apply || return 4\n', ''),
    ("W2", "rollback: runs without a pft-maint window", '  maint_window rollback || return 4\n', ''),
    ("W3", "window check: exit status of pft-maint active ignored", '"$MAINT" active >/dev/null 2>&1 && {', '{ "$MAINT" active >/dev/null 2>&1; } ; {'),
    ("W4", "apply: --yes not required", '[ "$YES" = 1 ] || [ "$DRY" = 1 ] || die "apply', 'true || die "apply'),
    ("F1", "refuse: unmanaged [node_seed] accepted", '[ "$(section_unmanaged "$1" node_seed)" = 0 ] || echo', 'true || echo'),
    ("F2", "refuse: unmanaged [cluster_nodes] accepted", '[ "$(section_unmanaged "$1" cluster_nodes)" = 0 ] || echo', 'true || echo'),
    ("F3", "refuse: broken block markers accepted", '[ "$bc" = "0 0" ] || [ "$bc" = "1 1" ] || echo', 'true || echo'),
    ("F4", "refuse: own key as peer accepted", '[ "$(cat "$PUBF")" != "$PEER_PUBKEY" ] ||', 'true ||'),
    ("F5", "refuse: missing PEER_PUBKEY accepted", 'valid_pub "$PEER_PUBKEY" || { echo "$(ts) apply: REFUSED', 'true || { echo "$(ts) apply: REFUSED'),
    ("F6", "refuse: missing seed accepted", '[ -f "$SEEDF" ] && valid_seed_file "$SEEDF" && valid_pub "$(cat "$PUBF" 2>/dev/null)" \\\n    || { echo "$(ts) apply: REFUSED - no valid stored seed', 'true \\\n    || { echo "$(ts) apply: REFUSED - no valid stored seed'),
    ("F7", "base58: 0/O/I/l accepted in keys", "B58='[1-9A-HJ-NP-Za-km-z]'", "B58='[0-9A-Za-z]'"),
    # config writing
    ("C1", "apply: idempotency check dropped (restarts every time)", 'if cmp -s "$cfg" "$cand" && [ "$(mode_of "$cfg")" = 600 ]', 'if false && [ "$(mode_of "$cfg")" = 600 ]'),
    ("C2", "candidate: trailing blank lines kept (file grows on re-apply)", 'while (n > 0 && lines[n] ~ /^[ \\t\\r]*$/) n--; ', ''),
    ("C3", "candidate: old block not removed", '$0 == b { inb = 1; next } inb && $0 == e { inb = 0; next } inb { next }', '$0 == "never" { inb = 1 }'),
    ("C4", "parser: indented section headers missed", "awk -v n=\"$2\" -v b=\"$BEGIN_MARK\" -v e=\"$END_MARK\" '\n    $0 == b { inb = 1; next } $0 == e { inb = 0; next }\n    { sub(/^[ \\t]+/, \"\"); ", "awk -v n=\"$2\" -v b=\"$BEGIN_MARK\" -v e=\"$END_MARK\" '\n    $0 == b { inb = 1; next } $0 == e { inb = 0; next }\n    { "),
    ("C5", "parser: comment lines read as values", ' && substr($0, 1, 1) != "#" { print }', ' { print }'),
    # secret handling
    ("S1", "config installed with the old mode (0644 with the seed)", 'chown --reference="$cfg" "$cand" 2>/dev/null; chmod 600 "$cand"', 'chmod 644 "$cand"'),
    ("S2", "seed file left at the umask mode", '&& chmod 600 "$SEEDF" &&', '&&'),
    ("S3", "backup keeps the original 0644 mode", '(umask 077; cp -p "$cfg" "$b") && chmod 600 "$b" ||', '(umask 077; cp -p "$cfg" "$b") ||'),
    ("S4", "dry run prints the seed", 'then l="${BASH_REMATCH[1]}<seed: redacted>"; fi', 'then :; fi'),
    ("S5", "exposure: docker inspect not searched", '"$DOCKER" inspect "$c" 2>/dev/null | grep -qFf "$SEEDF" && bad+=', 'false && bad+='),
    ("S6", "exposure: process args not searched", '"$PS" -eo args 2>/dev/null | grep -qFf "$SEEDF" && bad+=', 'false && bad+='),
    ("S7", "exposure: container log not searched", '"$DOCKER" logs --tail "$LOG_TAIL" "$c" 2>&1 | grep -qFf "$SEEDF" && bad+=', 'false && bad+='),
    ("S8", "exposure: textfiles not searched", 'grep -qsFf "$SEEDF" "$TEXTFILE_DIR"/*.prom && bad+=', 'false && bad+='),
    ("S9", "fingerprints: full keys printed", 'echo "node:$({ cat "$FPF"; printf \'%s\' "$1"; } | sha256sum | cut -c1-12)"', 'echo "$1"'),
    # audit grading
    ("A1", "audit: seed storage modes not checked", '[ "$(mode_of "$STATE_DIR")" != 700 ] || [ "$(mode_of "$SEEDF")" != 600 ] ||', 'false ||'),
    ("A2", "audit: config seed not compared with the stored one", 'if [ -f "$SEEDF" ] && cmp -s "$seedline" "$SEEDF"; then', 'if [ -f "$SEEDF" ]; then'),
    ("A3", "audit: 0644 config with the seed graded PASS", 'elif [ "$(mode_of "$cfg")" = 600 ]; then res PASS cfg:mode', 'elif true; then res PASS cfg:mode'),
    ("A4", "audit: malformed [cluster_nodes] entries not counted", "$1 !~ /^n[1-9A-HJ-NP-Za-km-z]+$/ || length($1) < 51 || length($1) > 52 { c++ }", "0 { c++ }"),
    ("A5", "audit: connected peer without cluster flag graded PASS", 'elif any(.cluster == true) then "cluster"', 'elif true then "cluster"'),
    ("A6", "audit: report age bound dropped", '[[ "$e" =~ ^[0-9]+$ ]] && [ "$e" -le "$REPORT_MAX" ]; then res PASS live:reports', '[[ "$e" =~ ^[0-9]+$ ]]; then res PASS live:reports'),
    ("A7", "jq: empty answer (node down) read as true", '[ -n "${in//[[:space:]]/}" ] || return 1', 'true'),
    ("A8", "audit: duplicate [node_seed] sections accepted", 'elif [ "$n" != 1 ]; then res FAIL cfg:node_seed', 'elif false; then res FAIL cfg:node_seed'),
    # integrity, textfile, pull
    ("I1", "integrity: other changed items accepted too", "other=\"$(grep -vxE 'cfgvol:postfiatd\\.cfg' <<<\"$items\")\"", 'other=""'),
    ("P1", "validate: foreign lines accepted", '[ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }', 'true'),
    ("P2", "pull: rejected file still installed", 'rm -f "$tmp"; die "pulled file rejected: $why" 2', 'mv -f "$tmp" "$TEXTFILE_DIR/pft_cluster_$PEER_LABEL.prom"; die "pulled file rejected: $why" 2'),
    ("P3", "prom: host label missing on findings", 'echo "pft_cluster_findings{host=\\"$h\\"} $FINDINGS"', 'echo "pft_cluster_findings $FINDINGS"'),
]

EQUIVALENT = {
    # restore_cfg runs `cp -p BACKUP CFG || return 1` right before the compare: once cp succeeded the bytes are equal,
    # so only a lying filesystem reaches the sha256 branch. Kept as a belt-and-braces check.
    "G13": "cp -p succeeded => bytes equal; no test input reaches the sha256 mismatch branch",
}


def suite(path, timeout):
    t0 = time.time()
    try:
        p = subprocess.run(["bash", os.path.join(HERE, "run-tests.sh"), path], capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, time.time() - t0
    except subprocess.TimeoutExpired:
        return None, "", time.time() - t0


def run(m, src, timeout):
    mid, desc, old, new = m
    n = src.count(old)
    if n != 1:
        return mid, desc, f"NOT APPLIED (matches {n})", 0.0
    os.makedirs(TBASE, exist_ok=True)
    d = tempfile.mkdtemp(prefix=f"pft-cluster-mut-{mid}-", dir=TBASE)
    path = os.path.join(d, "pft-cluster.sh")
    with open(path, "w") as f:
        f.write(src.replace(old, new))
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
        return mid, desc, f"ERROR (rc={rc}, no FAIL/RESULT line: harness problem, not a catch)", secs
    return mid, desc, f"KILLED ({len(fails)} failed: {fails[0][5:70]})", secs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("ids", nargs="*")
    a = ap.parse_args()
    with open(TOOL) as f:
        src = f.read()
    rc, out, secs = suite(TOOL, a.timeout)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(f"CONTROL (unmutated) rc={rc} {last[-1] if last else 'no RESULT line'} {secs:.0f}s", flush=True)
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
    print(f"RESULT: {len(ms) - bad - eq} killed + {eq} documented equivalent of {len(ms)}, {bad} survived, not applied or errored")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
