#!/usr/bin/env python3
"""Mutation harness for upgradewatch: pft-upgradewatch.sh (S*), upgradewatch_parse.py (P*) and
../alerts/upgradewatch.rules.yml (R*). Each mutant is one exact text replacement that must match exactly once
(else NOT APPLIED, a harness failure). The tool is copied to a temp tree, mutated there, and its suites run on the copy:
  S*, P*: tests/test_upgradewatch_parse.py AND tests/run-tests.sh (KILLED if either fails with a failure line)
  R*:     promtool test rules upgradewatch.tests.yml (prom/prometheus:v3.5.0 in docker, read-only mount)
Every suite run has a timeout; a hang counts as KILLED. An unmutated control run of all three suites must pass first,
or nothing is counted.
Usage: python3 upgradewatch/tests/mutate.py [-j JOBS] [--timeout SEC] [IDS...]"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLDIR = os.path.normpath(os.path.join(HERE, ".."))
ALERTS = os.path.normpath(os.path.join(HERE, "..", "..", "alerts"))
TBASE = os.environ.get("TEST_TMPDIR") or os.path.expanduser(
    "~/.cache"
)  # /tmp is noexec here
PROM_IMAGE = "prom/prometheus:v3.5.0"
SH, PY, RULES = "pft-upgradewatch.sh", "upgradewatch_parse.py", "rules"

# id, target, what it breaks, old text, new text
MUTANTS = [
    # collector: RPC, config grep, foundation
    (
        "S1",
        SH,
        "Amendments read from the current (unvalidated) ledger",
        '"ledger_index":"validated"}]}',
        '"ledger_index":"current"}]}',
    ),
    (
        "S2",
        SH,
        "values written even when the collection failed (stale data)",
        '[ -z "$2" ] && head+="$3"',
        'head+="$3"',
    ),
    ("S3", SH, "up always 1", '$([ -z "$2" ] && echo 1 || echo 0)', "1"),
    (
        "S4",
        SH,
        "docker stderr merged into the RPC answer",
        '-d "$b" http://127.0.0.1:5005/ > "$2" 2> "$3"',
        '-d "$b" http://127.0.0.1:5005/ > "$2" 2>&1',
    ),
    (
        "S5",
        SH,
        "no timeout around the RPC docker exec",
        'timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" curl',
        '"${DOCKER[@]}" exec "$CONTAINER" curl',
    ),
    (
        "S6",
        SH,
        "no timeout around the config grep",
        'timeout "$((RPC_TIMEOUT + 5))" "${DOCKER[@]}" exec "$CONTAINER" grep',
        '"${DOCKER[@]}" exec "$CONTAINER" grep',
    ),
    (
        "S7",
        SH,
        "grep rc 1 (section absent) treated as a failure",
        '[ "$rc" = 0 ] || [ "$rc" = 1 ]',
        '[ "$rc" = 0 ]',
    ),
    (
        "S8",
        SH,
        "grep rc 2 (config unreadable) accepted",
        '[ "$rc" = 0 ] || [ "$rc" = 1 ]',
        '[ "$rc" -le 2 ]',
    ),
    (
        "S9",
        SH,
        "config filter widened to every line (secrets would leave the container)",
        "CFG_RE='^[[:space:]]*(\\[[^]]*\\]|[0-9]+[[:space:]]*(minutes|hours|days|weeks)([[:space:]].*)?)[[:space:]]*$'",
        "CFG_RE='.*'",
    ),
    (
        "S10",
        SH,
        "failed foundation answer still passed to the parser",
        'foundation "$d/foundation.json" && f="$d/foundation.json"',
        'foundation "$d/foundation.json"; f="$d/foundation.json"',
    ),
    (
        "S11",
        SH,
        "empty FOUNDATION_URL still asked",
        '[ -n "$FOUNDATION_URL" ] || return 1',
        ":",
    ),
    (
        "S12",
        SH,
        "empty foundation answer accepted",
        '"$FOUNDATION_URL" > "$1" 2>/dev/null && [ -s "$1" ]',
        '"$FOUNDATION_URL" > "$1" 2>/dev/null',
    ),
    (
        "S13",
        SH,
        "server_info answer not handed to the parser",
        '[ -z "$err" ] && mv "$d/server_info.json" "$d/info.json"',
        ":",
    ),
    # guards
    (
        "S14",
        SH,
        "replay may overwrite a real node's textfile",
        '[[ "$CONTAINER" == drill-* ]]',
        '[[ "$CONTAINER" == * ]]',
    ),
    (
        "S15",
        SH,
        "non-root-owned conf is sourced",
        '[ "$(stat -c %u "$CONF")" = 0 ]',
        "true",
    ),
    (
        "S16",
        SH,
        "RPC_TIMEOUT 0 / non-numeric accepted",
        '[[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]?$ ]]',
        '[[ "$RPC_TIMEOUT" =~ ^.*$ ]]',
    ),
    (
        "S17",
        SH,
        "NODE_CFG not checked",
        '[[ "$NODE_CFG" =~ ^/[A-Za-z0-9_./-]+$ ]]',
        '[[ "$NODE_CFG" =~ ^.*$ ]]',
    ),
    # textfile, validate, pull
    (
        "S18",
        SH,
        "atomic rename replaced by a copy (temp files left)",
        'chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"',
        'chmod 644 "$tmp" && cp "$tmp" "$1/$2"',
    ),
    (
        "S19",
        SH,
        "validate: first label not checked",
        "if (index(rest, pre) != 1)",
        "if (0)",
    ),
    (
        "S20",
        SH,
        "validate: size limit not enforced",
        '[ "$size" -le "$MAX_BYTES" ]',
        "true",
    ),
    ("S21", SH, "validate: up sample not required", "if (!up) {", "if (0) {"),
    ("S22", SH, "validate: timestamp sample not required", "if (!ts) {", "if (0) {"),
    (
        "S23",
        SH,
        "pull: pulled file not validated",
        'if ! why="$(validate "$tmp" "$name")"; then',
        "if false; then",
    ),
    (
        "S24",
        SH,
        "pull: temp file left after a failed fetch",
        'rm -f "$tmp"; die "fetch of',
        'die "fetch of',
    ),
    # parser: ETA derivation
    (
        "P1",
        PY,
        "Ripple epoch off by one second",
        "RIPPLE_EPOCH = 946684800",
        "RIPPLE_EPOCH = 946684801",
    ),
    (
        "P2",
        PY,
        "default majority time 1 week instead of 2",
        "DEFAULT_MAJORITY_SECONDS = 14 * 86400",
        "DEFAULT_MAJORITY_SECONDS = 7 * 86400",
    ),
    (
        "P3",
        PY,
        "minimum majority time 10 min instead of 15",
        "MIN_MAJORITY_SECONDS = 15 * 60",
        "MIN_MAJORITY_SECONDS = 10 * 60",
    ),
    ("P4", PY, "wrong week length", '"weeks": 604800}', '"weeks": 604000}'),
    (
        "P5",
        PY,
        "duration unit matched case-insensitively (the node is case-sensitive)",
        'DURATION_RE = re.compile(r"^\\s*(\\d+)\\s*(minutes|hours|days|weeks)\\s*(\\s+.*)?$")',
        'DURATION_RE = re.compile(r"^\\s*(\\d+)\\s*(minutes|hours|days|weeks)\\s*(\\s+.*)?$", re.I)',
    ),
    (
        "P6",
        PY,
        "two section lines: first one used instead of the default",
        "if len(values) != 1:",
        "if not values:",
    ),
    (
        "P7",
        PY,
        "comment lines read as values",
        'if not s or s.startswith("#"):',
        "if not s:",
    ),
    (
        "P8",
        PY,
        "an already enabled amendment counted as a majority",
        "        if h in enabled_set:\n            continue\n",
        "",
    ),
    (
        "P9",
        PY,
        "a known but unsupported amendment counted as supported",
        'supported = bool(f and f["supported"])',
        "supported = bool(f)",
    ),
    ("P10", PY, "majorities not sorted: not the earliest ETA", "    rows.sort()\n", ""),
    (
        "P11",
        PY,
        "majority time left out of the ETA",
        'eta = mm["CloseTime"] + RIPPLE_EPOCH + maj_secs',
        'eta = mm["CloseTime"] + RIPPLE_EPOCH',
    ),
    (
        "P12",
        PY,
        "node expected_date not converted from the Ripple epoch",
        'node_expected = d["expected_date"] + RIPPLE_EPOCH',
        'node_expected = d["expected_date"]',
    ),
    (
        "P13",
        PY,
        "ETA agreement tolerance 1 h",
        "ETA_AGREE_TOLERANCE = 1 ",
        "ETA_AGREE_TOLERANCE = 3600 ",
    ),
    (
        "P14",
        PY,
        "Amendments object from an unvalidated ledger accepted",
        'if amend.get("validated") is not True:',
        "if False:",
    ),
    (
        "P15",
        PY,
        "per-amendment series not capped",
        "for eta, lab, s in rows[:MAX_AMENDMENT_SERIES]",
        "for eta, lab, s in rows",
    ),
    (
        "P16",
        PY,
        "boolean CloseTime accepted",
        '            or isinstance(mm.get("CloseTime"), bool)\n',
        "",
    ),
    (
        "P17",
        PY,
        "enabled-but-unsupported count treats unknown hashes as supported",
        '.get("supported", False)',
        '.get("supported", True)',
    ),
    # parser: blocked flag, versions
    (
        "P18",
        PY,
        "warning 1002 alone does not mean blocked",
        'info.get("amendment_blocked") is True or WARN_AMENDMENT_BLOCKED in warn_ids',
        'info.get("amendment_blocked") is True',
    ),
    (
        "P19",
        PY,
        "amendment_blocked: false read as blocked",
        'info.get("amendment_blocked") is True or',
        'info.get("amendment_blocked") is not None or',
    ),
    (
        "P20",
        PY,
        "pre-release order rc/b swapped",
        '{"rc": 1, "b": 0, None: 2}',
        '{"rc": 0, "b": 1, None: 2}',
    ),
    (
        "P21",
        PY,
        "any prefix-version (rippled-2.x) compared as a postfiatd version",
        '"^(?:postfiatd-)?',
        '"^(?:[a-z]+-)?',
    ),
    (
        "P22",
        PY,
        "a peer on the same version counted as newer",
        "newer += k > bkey",
        "newer += k >= bkey",
    ),
    (
        "P23",
        PY,
        "same version as the foundation counted as behind",
        "version_key(fver) > bkey",
        "version_key(fver) >= bkey",
    ),
    (
        "P24",
        PY,
        "foundation build_version used without a version check",
        "if version_key(fv) is not None:",
        "if fv:",
    ),
    (
        "P25",
        PY,
        "peers without a parseable version not skipped",
        "        if k is None:\n            continue\n",
        "",
    ),
    # rules
    (
        "R1",
        RULES,
        "PFTAmendmentBlocked for 1m",
        "        for: 2m\n",
        "        for: 1m\n",
    ),
    (
        "R2",
        RULES,
        "majority count >= 0 fires on every node",
        '(pft_upgradewatch_majority_amendments{supported="no"}) > 0',
        '(pft_upgradewatch_majority_amendments{supported="no"}) >= 0',
    ),
    (
        "R3",
        RULES,
        "node warning 1001 path dropped",
        "\n          or pft_upgradewatch_unsupported_majority_warning == 1",
        "",
    ),
    ("R4", RULES, "activation window 48 h", "time() < 86400)", "time() < 172800)"),
    (
        "R5",
        RULES,
        "no 'an ETA exists' guard (ETA 0 = none would fire)",
        "\n          and pft_upgradewatch_unsupported_activation_eta_seconds > 0",
        "",
    ),
    (
        "R6",
        RULES,
        "peer path needs only 4 peers",
        "pft_upgradewatch_peers_versioned >= 5",
        "pft_upgradewatch_peers_versioned >= 4",
    ),
    (
        "R7",
        RULES,
        "peer path needs MORE than half",
        "pft_upgradewatch_peers_newer_ratio >= 0.5",
        "pft_upgradewatch_peers_newer_ratio > 0.5",
    ),
    ("R8", RULES, "version lag for 10m", "        for: 15m\n", "        for: 10m\n"),
    (
        "R9",
        RULES,
        "stale threshold 30 min",
        "_collect_timestamp_seconds > 900",
        "_collect_timestamp_seconds > 1800",
    ),
    (
        "R10",
        RULES,
        "up == 0 path dropped from the stale rule",
        " or pft_upgradewatch_up == 0",
        "",
    ),
]

EQUIVALENT = {}


def make_tree(d):
    shutil.copytree(
        TOOLDIR,
        os.path.join(d, "upgradewatch"),
        ignore=shutil.ignore_patterns("logs", "drill", "__pycache__", ".ruff_cache"),
    )
    os.makedirs(os.path.join(d, "alerts"))
    for f in ("upgradewatch.rules.yml", "upgradewatch.tests.yml"):
        shutil.copy(os.path.join(ALERTS, f), os.path.join(d, "alerts", f))


def target_path(d, target):
    if target == RULES:
        return os.path.join(d, "alerts", "upgradewatch.rules.yml")
    return os.path.join(d, "upgradewatch", target)


def run_cmd(cmd, timeout, cwd=None):
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd
        )
        return p.returncode, p.stdout + p.stderr, time.time() - t0
    except subprocess.TimeoutExpired:
        return None, "", time.time() - t0


def suites(d, target, timeout):
    """-> list of (suite, rc, failure lines, has_result_line)"""
    out = []
    if target in (SH, PY, None):
        rc, o, _ = run_cmd(
            [
                sys.executable,
                os.path.join(d, "upgradewatch", "tests", "test_upgradewatch_parse.py"),
            ],
            timeout,
        )
        fails = [ln for ln in o.splitlines() if ln.startswith(("FAIL:", "ERROR:"))]
        out.append(("py", rc, fails, "Ran " in o))
        rc, o, _ = run_cmd(
            ["bash", os.path.join(d, "upgradewatch", "tests", "run-tests.sh")], timeout
        )
        fails = [ln for ln in o.splitlines() if ln.startswith("FAIL ")]
        out.append(("sh", rc, fails, "RESULT:" in o))
    if target in (RULES, None):
        rc, o, _ = run_cmd(
            [
                "sudo",
                "docker",
                "run",
                "--rm",
                "-v",
                f"{os.path.join(d, 'alerts')}:/w:ro",
                "-w",
                "/w",
                "--entrypoint",
                "promtool",
                PROM_IMAGE,
                "test",
                "rules",
                "upgradewatch.tests.yml",
            ],
            timeout,
        )
        fails = [
            ln.strip() for ln in o.splitlines() if "FAILED" in ln or "alertname:" in ln
        ]
        out.append(("promtool", rc, fails, "SUCCESS" in o or "FAILED" in o))
    return out


def run(m, timeout):
    mid, target, desc, old, new = m
    os.makedirs(TBASE, exist_ok=True)
    d = tempfile.mkdtemp(prefix=f"uw-mut-{mid}-", dir=TBASE)
    t0 = time.time()
    try:
        make_tree(d)
        p = target_path(d, target)
        with open(p) as f:
            src = f.read()
        n = src.count(old)
        if n != 1:
            return mid, desc, f"NOT APPLIED (matches {n})", 0.0
        with open(p, "w") as f:
            f.write(src.replace(old, new))
        res = suites(d, target, timeout)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    secs = time.time() - t0
    if any(rc is None for _, rc, _, _ in res):
        return mid, desc, f"KILLED (timeout {timeout}s)", secs
    caught = [(s, fails) for s, rc, fails, ok in res if rc != 0 and fails and ok]
    if caught:
        s, fails = caught[0]
        return mid, desc, f"KILLED ({s}: {len(fails)} failed: {fails[0][:60]})", secs
    if all(rc == 0 for _, rc, _, _ in res):
        return mid, desc, "SURVIVED", secs
    return (
        mid,
        desc,
        "ERROR (non-zero rc without a failure line: harness problem, not a catch)",
        secs,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("ids", nargs="*")
    a = ap.parse_args()
    os.makedirs(TBASE, exist_ok=True)
    d = tempfile.mkdtemp(prefix="uw-mut-control-", dir=TBASE)
    try:
        make_tree(d)
        res = suites(d, None, a.timeout)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print(
        "CONTROL (unmutated): " + ", ".join(f"{s} rc={rc}" for s, rc, _, _ in res),
        flush=True,
    )
    if any(rc != 0 for _, rc, _, _ in res):
        print("RESULT: control run failed - no mutant counted")
        sys.exit(2)
    ms = [m for m in MUTANTS if not a.ids or m[0] in a.ids]
    bad = 0
    with ThreadPoolExecutor(a.j) as ex:
        for mid, desc, verdict, secs in ex.map(lambda m: run(m, a.timeout), ms):
            if verdict == "SURVIVED" and mid in EQUIVALENT:
                verdict = "EQUIVALENT (documented)"
                desc += " - " + EQUIVALENT[mid]
            print(f"{mid:4} {verdict:78.78} {secs:5.0f}s  {desc}", flush=True)
            bad += not verdict.startswith(("KILLED", "EQUIVALENT"))
    eq = sum(1 for m in ms if m[0] in EQUIVALENT)
    print(
        f"RESULT: {len(ms) - bad - eq} killed + {eq} documented equivalent of {len(ms)}, "
        f"{bad} survived, not applied or errored"
    )
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
