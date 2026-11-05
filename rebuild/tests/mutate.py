#!/usr/bin/env python3
"""Mutation harness for rebuild/: each mutant changes exactly one text match in ONE file of a full copy of the
module (rebuild_lib.py, stack.list, pft-rebuild-drill.sh, bin/rb-*) and runs tests/test_rebuild.py against that copy (RB_DIR).

A mutant is CAUGHT if its suite fails with a RESULT line and at least one FAIL line, or hangs (process group
SIGKILLed at --timeout). A failing suite without them is BROKEN. A mutant whose old text does not match exactly once
is NOT APPLIED. The unmutated control runs from a copy in the same place and must pass first. Any SURVIVED /
NOT APPLIED / BROKEN mutant or an orphan process fails the harness (exit 1).
Usage: python3 -u rebuild/tests/mutate.py [--timeout SEC] [--only M01,M02,...]
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RB = os.path.dirname(HERE)
SUITE = os.path.join(HERE, "test_rebuild.py")
FILES = ("rebuild_lib.py", "stack.list", "pft-rebuild-drill.sh")
L, S, D = FILES
HELPERS = ("bin/rb-limit", "bin/rb-manifest", "bin/rb-fleet-conf", "bin/rb-restore")
BL, BM, BF = HELPERS[:3]

MUTANTS = [
    # stack.list parsing / ordering
    (
        "M01",
        L,
        "if last is not None and order <= last:",
        "if last is not None and order < last:",
    ),
    ("M02", L, "if a not in seen:", "if False:"),
    ("M03", L, 'if not steps and step != "base":', "if False:"),
    ("M04", L, "if step in seen:", "if False:"),
    ("M05", L, "if len(parts) < 4:", "if len(parts) < 3:"),
    ("M06", L, 'after = [] if after_s == "-" else after_s.split(",")', "after = []"),
    ("M07", L, "seen[step] = n", "pass"),
    ("M08", L, 'raise InputError("stack.list declares no steps")', "pass"),
    # preflight
    (
        "M11",
        L,
        'if str(cfg.get("security.privileged", "false")).lower() == "true":',
        "if False:",
    ),
    (
        "M12",
        L,
        'if str(cfg.get("security.nesting", "false")).lower() != "true":',
        "if False:",
    ),
    (
        "M13",
        L,
        'for key in ("limits.cpu", "limits.memory"):',
        'for key in ("limits.cpu",):',
    ),
    (
        "M14",
        L,
        'src == p.rstrip("-/") or src.startswith(p) for p in LIVE_PATH_PREFIXES',
        "False for p in ()",
    ),
    (
        "M15",
        L,
        'src = os.path.normpath(d.get("source") or "")',
        'src = d.get("source") or ""',
    ),
    ("M16", L, "LIVE_PORTS = {2559, 5005, 51235}", "LIVE_PORTS = {2559, 5005}"),
    ("M17", L, "return set(range(int(lo), int(hi or lo) + 1))", "return {int(lo)}"),
    (
        "M18",
        L,
        'if d.get("nictype", "bridged") != "bridged" and not d.get("network"):',
        "if False:",
    ),
    (
        "M19",
        L,
        'elif (d.get("network") or d.get("parent")) != bridge.get("name"):',
        "elif False:",
    ),
    (
        "M20",
        L,
        'elif typ in ("unix-char", "unix-block", "gpu", "usb", "pci", "infiniband"):',
        "elif False:",
    ),
    ("M21", L, ') not in ("none", ""):', ') == "never":'),
    (
        "M22",
        L,
        'if bridge.get("type") != "bridge" or not bridge.get("managed", False):',
        "if False:",
    ),
    ("M23", L, "if t in text:", "if False:"),
    ("M24", L, "ntfy URL {redact_url(m.group(0))}", "ntfy URL {m.group(0)}"),
    (
        "M25",
        L,
        'for m in re.finditer(r"https?://[^\\s\\"\']*ntfy[^\\s\\"\']*", text):',
        "for m in []:",
    ),
    ("M26", L, "return 4 if refusals else 0", "return 0"),
    # diff
    ("M31", L, 'VOLATILE_ATTRS = {"mtime"}', "VOLATILE_ATTRS = set()"),
    ("M32", L, 'cls, attrs = "EXTRA", ["*"]', 'cls, attrs = "MISSING", ["*"]'),
    ("M33", L, 'cls, attrs = "MISSING", ["*"]', 'cls, attrs = "EXTRA", ["*"]'),
    (
        "M34",
        L,
        "if a not in VOLATILE_ATTRS and lv.get(a) != sv.get(a)",
        "if a not in VOLATILE_ATTRS and a in lv and lv.get(a) != sv.get(a)",
    ),
    (
        "M35",
        L,
        'if r["class"] in ("MISSING", "DIFFERENT") and not r["exception"]:',
        'if r["class"] == "MISSING" and not r["exception"]:',
    ),
    (
        "M36",
        L,
        "if r is None:\n            return None",
        "if r is None:\n            continue",
    ),
    (
        "M37",
        L,
        "fnmatch.fnmatchcase(key, kg) and fnmatch.fnmatchcase(a, ag)",
        "fnmatch.fnmatchcase(key, kg)",
    ),
    (
        "M38",
        L,
        'items[f"unit-enabled:{u[\'unit\']}"] = {"enabled": u.get("enabled", "")}',
        'items[f"unit-enabled:{u[\'unit\']}"] = {"enabled": u.get("enabled", ""), "active": u.get("active", "")}',
    ),
    ("M39", L, 'if r["class"] == "REPRODUCED" and not show_reproduced:', "if False:"),
    ("M40", L, 'return 1 if s["open"] else 0', "return 0"),
    ("M41", L, "if len(args) != 2 or bool(lf) != bool(sf):", "if len(args) != 2:"),
    (
        "M42",
        L,
        'if len(parts) != 3:\n            raise InputError(f"manifest line {n}: expected KEY<TAB>ATTR<TAB>VALUE")',
        "if len(parts) != 3:\n            continue",
    ),
    # teardown
    (
        "M51",
        L,
        "return sorted(x for x in after.splitlines() if x.strip() and x not in b)",
        "return []",
    ),
    ("M52", L, "return 1 if left else 0", "return 0"),
    # shell teardown (against tests/stub_host.py)
    (
        "T01",
        D,
        'while "$IPT" -C $spec >/dev/null 2>&1; do "$IPT" -D $spec && echo "  removed jump: $spec"; done',
        'if "$IPT" -C $spec >/dev/null 2>&1; then "$IPT" -D $spec && echo "  removed jump: $spec"; fi',
    ),
    ("T02", D, 'if [ "${#left[@]}" -gt 0 ]; then', "if false; then"),
    (
        "T03",
        D,
        '"$LXC" image delete "$(cat "$STATE/image.fp")" 2>/dev/null && echo "  cached image deleted"; ',
        "",
    ),
    (
        "T04",
        D,
        "cmd_teardown; exit $(( $? == 0 ? 0 : 5 )) ;;",
        "cmd_teardown; exit 0 ;;",
    ),
    (
        "T05",
        D,
        '"$IPT" -S "$CHAIN_IN" >/dev/null 2>&1 && left+=("chain $CHAIN_IN")',
        ":",
    ),
    (
        "T06",
        D,
        'for c in "$CHAIN" "$CHAIN_IN"; do\n    if "$IPT" -S',
        'for c in "$CHAIN"; do\n    if "$IPT" -S',
    ),
    ("T07", D, 'else "$NFT" delete table inet lxd && rm -f', "else : && rm -f"),
    (
        "T08",
        D,
        'if [ -f "$STATE/nft-lxd.created" ] && "$NFT" list table inet lxd >/dev/null 2>&1; then',
        'if "$NFT" list table inet lxd >/dev/null 2>&1; then',
    ),
    (
        "T09",
        D,
        "if \"$NFT\" list table inet lxd | grep -q 'chain '; then",
        "if false; then",
    ),
    # run 08/09 additions: step-loop encoding, volume pool check, volume teardown
    ("M60", L, 'b = base64.b64encode(s["cmd"].encode()).decode()', 'b = s["cmd"]'),
    ("M61", L, 'if d.get("pool") != root_pool:', "if False:"),
    (
        "T10",
        D,
        '"$LXC" storage volume delete "$POOL" "$vn" && echo "  volume $vn deleted"',
        ":",
    ),
    # helpers
    (
        "H01",
        BL,
        'if [ "$virt" = lxc ] && grep -qE "$sig" "$out"; then',
        'if grep -qE "$sig" "$out"; then',
    ),
    # (dev pass log 10: "rc=${PIPESTATUS[0]}" -> "rc=$?" SURVIVED = equivalent under set -o pipefail; replaced)
    ("H02", BL, '"$@" 2>&1 | tee "$out"', '"$@" | tee "$out"'),
    ("H03", BL, 'exit "$rc"', "exit 0"),
    (
        "H04",
        BM,
        '  printf \'%s\\n\' "${timers[@]}" | grep -qxF "$b.timer" && continue\n',
        "",
    ),
    ("H05", BM, "  grep -q '^\\[Install\\]' \"${u#*:}\" || continue\n", ""),
    ("H06", BM, '  case "$b" in *@) continue ;; esac\n', ""),
    ("H07", BF, "grep -E '^host validator[[:space:]]'", "grep -E '^host '"),
    ("H08", BF, '-e "s|^REF=.*|REF=$ref|"', '-e "s|^REF=.*|REF=main|"'),
    ("H09", BF, 'if [ ! -e "$E/hosts.conf" ]; then', "if true; then"),
    # the declared stack itself
    ("S01", S, "50  backup        restore         rb-manifest backup\n", ""),
    ("S02", S, "340 baseline      integrity       pft-integrity baseline\n", ""),
    (
        "S03",
        S,
        "30  exporter      base            rb-manifest exporter",
        "95  exporter      base            rb-manifest exporter",
    ),
]


def run_suite(rbdir, timeout):
    env = dict(os.environ, RB_DIR=rbdir)
    p = subprocess.Popen(
        [sys.executable, "-u", SUITE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return "HANG", ""
    return p.returncode, out


def copy_module(base):
    d = os.path.join(base, "rebuild")
    os.makedirs(d)
    for f in FILES + HELPERS:  # the helper tests run bin/* from RB_DIR too
        os.makedirs(os.path.dirname(os.path.join(d, f)), exist_ok=True)
        shutil.copy2(os.path.join(RB, f), os.path.join(d, f))
    return d


def main(argv):
    timeout, only = 120, None
    if "--timeout" in argv:
        timeout = int(argv[argv.index("--timeout") + 1])
    if "--only" in argv:
        only = set(argv[argv.index("--only") + 1].split(","))
    base = tempfile.mkdtemp(
        prefix="rbmut-",
        dir=os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache"),
    )
    bad = 0
    try:
        ctl = copy_module(os.path.join(base, "control"))
        rc, out = run_suite(ctl, timeout)
        last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
        print(f"CONTROL rc={rc} {last[-1] if last else 'no RESULT line'}")
        if rc != 0:
            print(out)
            return 1
        counts = {}
        for mid, fname, old, new in MUTANTS:
            if only and mid not in only:
                continue
            d = copy_module(os.path.join(base, mid))
            path = os.path.join(d, fname)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            if text.count(old) != 1:
                verdict, detail = "NOT APPLIED", f"old text matches {text.count(old)}x"
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text.replace(old, new))
                rc, out = run_suite(d, timeout)
                fails = [
                    ln[5:].split(" -- ")[0]
                    for ln in out.splitlines()
                    if ln.startswith("FAIL ")
                ]
                has_result = any(ln.startswith("RESULT:") for ln in out.splitlines())
                if rc == "HANG":
                    verdict, detail = "CAUGHT", "hang (killed)"
                elif rc == 0:
                    verdict, detail = "SURVIVED", ""
                elif has_result and fails:
                    verdict, detail = "CAUGHT", f"{len(fails)} failing: {fails[0]}"
                else:
                    verdict, detail = (
                        "BROKEN",
                        (out.strip().splitlines() or ["no output"])[-1][:120],
                    )
            counts[verdict] = counts.get(verdict, 0) + 1
            if verdict != "CAUGHT":
                bad += 1
            print(f"{mid} {fname:<15} {verdict:<11} {detail}")
        orphans = subprocess.run(
            ["pgrep", "-f", "rbmut-"], capture_output=True, text=True, check=False
        ).stdout.split()
        orphans = [p for p in orphans if int(p) != os.getpid()]
        print(f"orphan processes: {len(orphans)}")
        summary = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        ok = bad == 0 and not orphans
        print(
            f"MUTANTS: {sum(counts.values())} run: {summary} -> {'PASS' if ok else 'FAIL'}"
        )
        return 0 if ok else 1
    finally:
        shutil.rmtree(base, True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
