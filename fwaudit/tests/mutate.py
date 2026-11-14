#!/usr/bin/env python3
"""Mutation harness for pft-fwaudit. Each mutant changes exactly one text match in a COPY of the fwaudit folder
(evaluator E*, plan/ufwnum P*, shell S*) and runs that copy's full pytest suite, or changes a copy of
../alerts/fwaudit.rules.yml (R*) and runs `promtool test rules fwaudit.tests.yml` on it.

CAUGHT: pytest printed its "N failed ... in Xs" summary and at least one FAILED test line (promtool: exit != 0 with
"FAILED"), or it hung and its process group was SIGKILLed at --timeout. A failing run without those is BROKEN; a mutant
whose old text does not match exactly once is NOT APPLIED. Every CAUGHT line names the failing tests (the kill reason).
Controls, run before any mutant (the harness stops with exit 2 if one fails):
  baseline  the unmutated copy, in the same place as the mutants, must pass the suite and promtool;
  timeout   a copy whose evaluator never returns must be reported HANG within --hang-timeout and leave no process;
  orphan    at the end, no process may name this run's scratch dir (FWMUT_ORPHAN_SELFTEST=1 leaves one on purpose).
Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan fails the harness (exit 1).
Usage: TEST_TMPDIR=~/.cache python3 -u fwaudit/tests/mutate.py [--timeout SEC] [--jobs N] [--only E01,R01,...]
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(FW), "alerts")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
SKIP = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".ruff_cache", "logs", "drill", "*.pyc")

E, S, R = "fwaudit_eval.py", "pft-fwaudit.sh", "fwaudit.rules.yml"

# (id, file, description, old text, new text)
MUTANTS = [
    (
        "E01",
        E,
        "ss section not required",
        'for key in ("iptables", "ip6tables", "ufw", "ss"):',
        'for key in ("iptables", "ip6tables", "ufw"):',
    ),
    ("E02", E, "failed section accepted", "        if out[key][0] != 0:\n", "        if False:\n"),
    (
        "E03",
        E,
        "-i lo matches the uplink probe",
        'hit = not (val == "lo" or val.startswith(("docker", "br-", "veth")))',
        'hit = not val.startswith(("docker", "br-", "veth"))',
    ),
    ("E04", E, "ctstate ignores NEW", 'hit = "NEW" in val.split(",")', "hit = True"),
    (
        "E05",
        E,
        "unknown match treated as a full match",
        "            cond = True  # unknown match: may or may not match\n            continue",
        "            continue",
    ),
    (
        "E06",
        E,
        "limit modules not conditional",
        "            cond = True\n        elif m not in (",
        "            pass\n        elif m not in (",
    ),
    (
        "E07",
        E,
        "source-restricted rule is a full match",
        'if src is not None:\n        return ("src", src)',
        'if False:\n        return ("src", src)',
    ),
    (
        "E08",
        E,
        "conditional ACCEPT is open",
        'trail.append(r.raw)\n            if m == "cond":\n                limited = True\n                continue\n            return (',
        "trail.append(r.raw)\n            return (",
    ),
    (
        "E09",
        E,
        "rate-limited DROP closes the port",
        "                limited = True\n                trail.append(r.raw)\n                continue",
        "                return _settle(sources, limited, trail, closed=True)",
    ),
    ("E10", E, "ACCEPT chain policy is closed", '        if pol == "ACCEPT":\n', "        if False:\n"),
    (
        "E11",
        E,
        "closed sub-chain falls through",
        '            if st == "closed":\n                return _settle(sources, limited, trail, closed=True)',
        '            if st == "closed":\n                continue',
    ),
    (
        "E12",
        E,
        "sub-chain RETURN treated as closed",
        '            if st == "return":\n                continue',
        '            if st == "return":\n                return _settle(sources, limited, trail, closed=True)',
    ),
    ("E13", E, "udp sockets ignored", '(proto == "udp" and state != "UNCONN")', '(proto == "udp")'),
    ("E14", E, "dual-stack * listener only v4", '        return ["v4", "v6"]\n', '        return ["v4"]\n'),
    (
        "E15",
        E,
        "loopback listener counted",
        "    if ip.is_loopback:\n        return []",
        "    if False:\n        return []",
    ),
    (
        "E16",
        E,
        "docker-proxy with DNAT walked on INPUT",
        "continue  # reached through DNAT on the FORWARD path",
        "pass  # reached through DNAT on the FORWARD path",
    ),
    (
        "E17",
        E,
        "loopback DNAT walked as exposure",
        '                continue\n            p = Probe(fam, d["proto"], d["cport"]',
        '                pass\n            p = Probe(fam, d["proto"], d["cport"]',
    ),
    ("E18", E, "ufw inactive not reported", '    if not ufw["active"]:\n', "    if False:\n"),
    (
        "E19",
        E,
        "default allow accepted",
        'if ufw["default_in"] not in ("deny", "reject"):',
        'if ufw["default_in"] not in ("deny", "reject", "allow"):',
    ),
    (
        "E20",
        E,
        "undeclared exposure not reported",
        "        if not decl:\n            fnd(",
        "        if not decl:\n            continue\n            fnd(",
    ),
    (
        "E21",
        E,
        "source-too-broad ignores any-source reach",
        'if rec["state"] in ("open", "limited") or extra:',
        "if extra:",
    ),
    (
        "E22",
        E,
        "extra sources never computed",
        "                if not any(\n",
        "                if False and not any(\n",
    ),
    ("E23", E, "missing-limit off", 'if d["limit"] and rec["state"] == "open":', "if False:"),
    (
        "E24",
        E,
        "limited counts as missing limit",
        'if d["limit"] and rec["state"] == "open":',
        'if d["limit"] and rec["state"] in ("open", "limited"):',
    ),
    (
        "E25",
        E,
        "declared-unreachable off",
        "        if k not in exp:\n            fnd(",
        "        if False:\n            fnd(",
    ),
    (
        "E26",
        E,
        "stale-allow ignores Docker-published ports",
        "if (fam, proto, port) not in listening and (proto, port) not in published:",
        "if (fam, proto, port) not in listening:",
    ),
    (
        "E27",
        E,
        "stale-allow off",
        "if (fam, proto, port) not in listening and (proto, port) not in published:",
        "if False:",
    ),
    ("E28", E, "loopback DNAT guard accepts any target", 'r.target == "DROP"\n', 'r.target != "DROP"\n'),
    (
        "E29",
        E,
        "nft inet tables treated as iptables-nft",
        'own = fam in ("ip", "ip6") and name in IPT_NFT_TABLES',
        "own = name in IPT_NFT_TABLES",
    ),
    (
        "E30",
        E,
        "WARN overrides FAIL",
        'elif f["severity"] == "WARN" and verdict == "PASS":',
        'elif f["severity"] == "WARN":',
    ),
    (
        "E31",
        E,
        "INFO findings raise WARN",
        'elif f["severity"] == "WARN" and verdict == "PASS":',
        'elif f["severity"] in ("WARN", "INFO") and verdict == "PASS":',
    ),
    (
        "E32",
        E,
        "-d multicast/loopback matches",
        "            if net.is_multicast or net.is_loopback:\n                hit = False",
        "            if False:\n                hit = False",
    ),
    (
        "P01",
        E,
        "plan deletes ufw rules on a Docker path",
        'return bool(rec) and rec["paths"] == ["input"] and (f["proto"], f["port"]) in ufw_ports[f["family"]]',
        'return bool(rec) and (f["proto"], f["port"]) in ufw_ports[f["family"]]',
    ),
    (
        "P02",
        E,
        "plan acts without a ufw rule",
        'return bool(rec) and rec["paths"] == ["input"] and (f["proto"], f["port"]) in ufw_ports[f["family"]]',
        'return bool(rec) and rec["paths"] == ["input"]',
    ),
    ("P03", E, "deletes before adds", '"actions": adds + dels', '"actions": dels + adds'),
    ("P04", E, "ufwnum not family-scoped", 'if (family == "v6") != bool(v6) or action not in', "if action not in"),
    (
        "P05",
        E,
        "ufwnum ignores --keep",
        'action not in ("ALLOW", "LIMIT") or action == keep:',
        'action not in ("ALLOW", "LIMIT"):',
    ),
    (
        "P06",
        E,
        "ufwnum selects DENY rules",
        'action not in ("ALLOW", "LIMIT") or action == keep:',
        'action not in ("ALLOW", "LIMIT", "DENY") or action == keep:',
    ),
    (
        "P07",
        E,
        "ufwnum ignores --from-any",
        "        if from_any_only and net is not None:\n            continue\n",
        "",
    ),
    ("P08", E, "ufwnum ignores --except-from", "        if net and net in keepnets:\n            continue\n", ""),
    ("P09", E, "ufwnum lowest first", "return sorted(out, reverse=True)", "return sorted(out)"),
    (
        "P10",
        E,
        "missing-limit delete also removes the LIMIT",
        '"from_any_only": True, "keep": "LIMIT"',
        '"from_any_only": True',
    ),
    (
        "P11",
        E,
        "source-too-broad delete removes the declared sources",
        '"from_any_only": False, "except_from": nets',
        '"from_any_only": False',
    ),
    ("P12", E, "INFO findings listed as manual", 'elif SEVERITY[c] != "INFO":', "else:"),
    (
        "P13",
        E,
        "plan exit ignores manual items",
        'return 2 if pl["manual"] else (1 if pl["actions"] else 0)',
        'return 1 if pl["actions"] else 0',
    ),
    (
        "P14",
        E,
        "default deny never planned",
        'if c == "default-incoming-allow":',
        'if c == "default-incoming-allow-x":',
    ),
    (
        "S01",
        S,
        "apply without --yes",
        '[ "$YES" = 1 ] || die "apply changes the firewall',
        'true || die "apply changes the firewall',
    ),
    ("S02", S, "pending apply ignored", "= pending ]; then", "= pending-x ]; then"),
    ("S03", S, "maintenance gate ignored", 'case "$gate" in ok*) ;; *) die "REFUSED: ${gate#refuse }" 4 ;; esac', ":"),
    ("S04", S, "window time left not checked", 'elif [ "$rem" -lt "$1" ]; then', "elif false; then"),
    ("S05", S, "data-collection locks ignored", 'elif [ "$nl" -gt 0 ]; then', "elif false; then"),
    ("S06", S, "node not full accepted", 'is_full "$st" || die "REFUSED: node is $st, not full" 4', "true"),
    ("S07", S, "MIN_PEERS ignored", '[ "$pe" -ge "$MIN_PEERS" ] || die', "true || die"),
    ("S08", S, "SSH guard off", '[[ " $keep " == *" v4/tcp/22 "* ]] || die', "true || die"),
    ("S09", S, "no snapshot before change", 'snapshot || die "snapshot failed, nothing changed" 5', "true"),
    (
        "S10",
        S,
        "re-audit leftovers ignored",
        'if [ -n "$left" ]; then log "apply: re-audit still finds',
        'if false; then log "apply: re-audit still finds',
    ),
    (
        "S11",
        S,
        "lost declared exposure after apply ignored",
        'if [ "$(keep_check "$keep")" != ok ]; then log "apply: re-audit lost',
        'if false; then log "apply: re-audit lost',
    ),
    ("S12", S, "failed ufw action ignored", 'run_action "$a" || { log', 'run_action "$a" || true || { log'),
    (
        "S13",
        S,
        "dead-man trips one poll late",
        'if [ "$bad" -ge "$BAD_POLLS" ]; then',
        'if [ "$bad" -gt "$BAD_POLLS" ]; then',
    ),
    ("S14", S, "bad poll count never reset", 'then bad=0; log "dead-man poll', 'then log "dead-man poll'),
    ("S15", S, "PEER_SLACK ignored", "floor=$(( base - PEER_SLACK ))", "floor=$(( base ))"),
    (
        "S16",
        S,
        "dead-man ignores lost declared exposure",
        '[ "$pe" -ge "$floor" ] && [ "$kc" = ok ]; then',
        '[ "$pe" -ge "$floor" ]; then',
    ),
    (
        "S17",
        S,
        "dead-man ignores node state",
        'if is_full "$st" && [ "$pe" -ge "$floor" ]',
        'if [ "$pe" -ge "$floor" ]',
    ),
    (
        "S18",
        S,
        "rollback sha256 check skipped",
        'if [ "$(snap_sums)" != "$(cat "$STATE_DIR/snapshot/SHA256")" ]; then',
        "if false; then",
    ),
    (
        "S19",
        S,
        "rollback without ufw reload",
        '"$UFW" reload >/dev/null || { log "rollback: ufw reload failed"; rc=5; }',
        "true",
    ),
    ("S20", S, "dead-man unit never started", '"$SYSTEMD_RUN" --unit="$UNIT"', 'true --unit="$UNIT"'),
    (
        "S21",
        S,
        "--dry-run not honoured",
        'if [ "$dry" = 1 ]; then eval_cmd plan "$b"; prechecks "$aj"; echo "dry run - nothing changed"; return 0; fi',
        ":",
    ),
    ("S22", S, "audit error still writes up 1", 'if [ "$rc" -gt 2 ] || ! jq -e', "if ! jq -e"),
    (
        "S23",
        S,
        "findings by severity never match",
        "select(.severity == ($s | ascii_upcase))",
        "select(.severity == $s)",
    ),
    (
        "S24",
        S,
        "exposed state limited dropped",
        '["open", "limited", "sources"][] as $s',
        '["open", "sources"][] as $s',
    ),
    ("S25", S, "validate: foreign host label accepted", "if (index(rest, pre) != 1) {", "if (0) {"),
    ("S26", S, "validate: size not checked", '[ "$size" -le "$MAX_BYTES" ] ||', "true ||"),
    ("S27", S, "validate: missing up accepted", 'if (!up) { print "no pft_fwaudit_up sample"; exit 1 }', ""),
    ("S28", S, "pull over own textfile allowed", '[ "$PEER_LABEL" != "$HOST_LABEL" ] || die', "true || die"),
    (
        "S29",
        S,
        "pull: rejected file still installed",
        'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die',
        'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then mv -f "$tmp" "$TEXTFILE_DIR/pft_fwaudit_$PEER_LABEL.prom"; die',
    ),
    ("S30", S, "root check off", 'need_root() { [ -n "$TEST" ] ||', "need_root() { true ||"),
    (
        "S31",
        S,
        "failed capture still writes up 1",
        'if ! collect > "$b"; then write_textfile "$(metrics 0 "$t0")"; die "capture failed" 4; fi',
        'collect > "$b"',
    ),
    (
        "S32",
        S,
        "node source not checked before apply",
        'case "$src" in ok*) ;; *) die "REFUSED: ${src#refuse }" 4 ;; esac\n  read -r st pe',
        ":\n  read -r st pe",
    ),
    (
        "S33",
        S,
        "sentry role reads the validator container",
        "sentry) CONTAINER=postfiatd-sentry ;;",
        "sentry) CONTAINER=postfiatd ;;",
    ),
    ("S34", S, "configured CONTAINER ignored", 'if [ -z "$CONTAINER" ]; then case', "if true; then case"),
    (
        "S35",
        S,
        "missing container reported running",
        "  else echo \"refuse container '$CONTAINER' is not running",
        "  else echo \"ok container '$CONTAINER' is not running",
    ),
    (
        "S36",
        S,
        "RPC_URL source not honoured",
        'if [ -n "$RPC_URL" ]; then echo "ok RPC_URL',
        'if false; then echo "ok RPC_URL',
    ),
    (
        "S37",
        S,
        "dry run: node state not graded",
        'if is_full "$st" && [ "$pe" -ge "$MIN_PEERS" ]; then echo "pre-check node: ok',
        'if true; then echo "pre-check node: ok',
    ),
    (
        "S38",
        S,
        "dry run: pending apply not reported",
        '    pending) echo "pre-check earlier apply: refuse',
        '    pending-x) echo "pre-check earlier apply: refuse',
    ),
    (
        "S39",
        S,
        "dry run: ssh guard not reported",
        'if [[ "$k" == *" v4/tcp/22 "* ]]; then echo "pre-check ssh',
        'if true; then echo "pre-check ssh',
    ),
    ("R01", R, "for 1m", "for: 5m", "for: 1m"),
    ("R02", R, "audit error never matches", "(pft_fwaudit_up) == 0", "(pft_fwaudit_up) == 2"),
    (
        "R03",
        R,
        "WARN findings page",
        'pft_fwaudit_findings{severity="fail"}',
        'pft_fwaudit_findings{severity=~"fail|warn"}',
    ),
    ("R04", R, "zero FAIL findings page", '{severity="fail"}) > 0', '{severity="fail"}) >= 0'),
    ("R05", R, "severity warning", "severity: critical", "severity: warning"),
    (
        "R06",
        R,
        "not per host",
        'max by (host) (pft_fwaudit_findings{severity="fail"})',
        'max(pft_fwaudit_findings{severity="fail"})',
    ),
]
HANG = (E, "def main(argv):\n", "def main(argv):\n    import time\n\n    while True:\n        time.sleep(1)\n")


def run(cmd, timeout, env=None, cwd=None):
    """-> (PASS|FAIL|HANG, output). Own session; the whole process group is SIGKILLed on timeout."""
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        env=env,
        cwd=cwd,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return "HANG", ""
    return ("PASS" if p.returncode == 0 else "FAIL"), out


def make_copy(work, name, mutate=None):
    """Copy the fwaudit folder (+ rules, rule tests in alerts/) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    shutil.copytree(FW, d, ignore=SKIP)
    os.makedirs(os.path.join(d, "alerts"))
    for x in (d, os.path.join(d, "alerts")):
        os.chmod(x, 0o755)  # promtool runs as nobody in its container
    for f in (R, "fwaudit.tests.yml"):
        shutil.copy2(os.path.join(ALERTS, f), os.path.join(d, "alerts", f))
        os.chmod(os.path.join(d, "alerts", f), 0o644)
    if mutate:
        f, old, new = mutate
        path = os.path.join(d, "alerts", f) if f == R else os.path.join(d, f)
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src.replace(old, new, 1))
    return d


def suite(d, timeout):
    tmp = os.path.join(d, "tmp")  # own temp base per copy (exec allowed, unlike /tmp)
    os.makedirs(tmp, exist_ok=True)
    return run(
        [sys.executable, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider", f"--basetemp={tmp}/pt", "tests"],
        timeout,
        dict(os.environ, TMPDIR=tmp, TEST_TMPDIR=tmp),
        cwd=d,
    )


def promtool(d, timeout):
    cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "promtool", "-v", f"{d}/alerts:/w:ro"]
    return run(cmd + ["-w", "/w", PROMTOOL_IMAGE, "test", "rules", "fwaudit.tests.yml"], timeout)


SUMMARY = re.compile(r"^=*\s*(\d+ failed|\d+ error)[^\n]* in [0-9.]+s", re.MULTILINE)


def failing_tests(out):
    return [
        ln.split(" ", 1)[1].split(" ", 1)[0].split("::")[-1]
        for ln in out.splitlines()
        if ln.startswith(("FAILED ", "ERROR "))
    ]


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(FW, f)
    with open(src_path, encoding="utf-8") as fh:
        n = fh.read().count(old)
    if n != 1:
        return mid, "NOT APPLIED", f"({n} matches in {f}) - {desc}"
    d = make_copy(work, mid, (f, old, new))
    st, out = promtool(d, timeout) if f == R else suite(d, timeout)
    shutil.rmtree(d)
    if st == "PASS":
        return mid, "SURVIVED", f"- {desc}"
    if st == "HANG":
        return mid, "CAUGHT", f"- {desc} [hung: timeout, process group killed]"
    if f == R:
        if "FAILED" not in out:
            return mid, "BROKEN", f"- {desc} [promtool failed without FAILED: {out.strip()[-120:]}]"
        names = sorted(
            {ln.strip()[len("name: ") :].rstrip(",") for ln in out.splitlines() if ln.strip().startswith("name: ")}
        )
        return mid, "CAUGHT", f"- {desc} [promtool FAILED: {'; '.join(names)[:220]}]"
    fails = failing_tests(out)
    if not fails or not SUMMARY.search(out):
        last = out.strip().splitlines()[-1:] or [""]
        return mid, "BROKEN", f"- {desc} [suite failed without a summary or a failing test: {last[0][:120]}]"
    return mid, "CAUGHT", f"- {desc} [{len(fails)} failing: {', '.join(fails[:4])}{' ...' if len(fails) > 4 else ''}]"


def main():
    a = sys.argv
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 400
    hang_timeout = int(a[a.index("--hang-timeout") + 1]) if "--hang-timeout" in a else 60
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 3
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="fwmut.", dir=base)
    os.chmod(work, 0o755)
    ids = [m[0] for m in MUTANTS]
    if len(ids) != len(set(ids)):
        print("RESULT: duplicate mutant ids")
        return 2
    ctl = make_copy(work, "CONTROL")
    st, out = suite(ctl, timeout)
    summary = [ln.strip("= ") for ln in out.splitlines() if re.search(r"\d+ (passed|failed)", ln)]
    print(f"control baseline suite (unmutated copy): {st} {' / '.join(summary)}", flush=True)
    pst, pout = promtool(ctl, timeout)
    print(
        f"control baseline promtool (unmutated copy): {pst} {pout.strip().splitlines()[-1] if pout.strip() else ''}",
        flush=True,
    )
    shutil.rmtree(ctl)
    hang = make_copy(work, "HANGCTL", HANG)
    t0 = time.monotonic()
    hst, _ = suite(hang, hang_timeout)
    left = subprocess.run(
        ["pgrep", "-af", re.escape(hang)], capture_output=True, text=True, check=False
    ).stdout.splitlines()
    print(
        f"control timeout (evaluator never returns, --hang-timeout {hang_timeout}): {hst} after "
        f"{time.monotonic() - t0:.0f} s, {len(left)} process(es) left",
        flush=True,
    )
    shutil.rmtree(hang)
    if st != "PASS" or pst != "PASS" or hst != "HANG" or left:
        print("RESULT: control run failed, mutants not run")
        shutil.rmtree(work)
        return 2
    selected = [m for m in MUTANTS if only is None or m[0] in only]
    res = {}
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for mid, status, text in ex.map(lambda m: one(work, timeout, m), selected):
            res[mid] = status
            print(f"{mid} {status} {text}", flush=True)
    if os.environ.get("FWMUT_ORPHAN_SELFTEST") == "1":  # positive control for the orphan check
        subprocess.Popen(
            ["bash", "-c", "sleep 60; true", os.path.join(work, "orphan-selftest")],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    hits = subprocess.run(
        ["pgrep", "-af", re.escape(work)], capture_output=True, text=True, check=False
    ).stdout.splitlines()
    shutil.rmtree(work)
    for h in hits:
        print(f"orphan: {h[:160]}")
    print(f"orphan check: {len(hits)} process(es) still running that name this run's scratch dir")
    c, sv, na, br = (sum(1 for s in res.values() if s == k) for k in ("CAUGHT", "SURVIVED", "NOT APPLIED", "BROKEN"))
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(f"RESULT: {c} caught, {sv} survived, {na} not applied, {br} broken of {len(selected)}{subset}")
    return 0 if sv == 0 and na == 0 and br == 0 and not hits else 1


if __name__ == "__main__":
    sys.exit(main())
