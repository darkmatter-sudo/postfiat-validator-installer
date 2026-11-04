#!/usr/bin/env python3
"""Mutation harness for pft-seccomp.sh: apply each mutant (exactly one textual match) to a copy of the tool, run
tests/run-tests.sh against it with a timeout, and count it CAUGHT if the suite fails or hangs (a hang is a caught
mutant, never a stuck harness). An unmutated control run must pass first; a mutant whose text does not match exactly
once is NOT APPLIED and fails the harness. A failing suite counts as CAUGHT only with a RESULT line and at least one
FAIL line (else BROKEN, which fails the harness); the control runs from a copy next to the same helper files. Each suite runs in its own session and the whole process group is
SIGKILLed on timeout (subprocess's own timeout kills only the bash, and a hanging grandchild kept polling for 1.5 h
in backfill/); the run ends with an orphan check. Mutants run JOBS at a time (default 2) under nice 19.
Usage: python3 -u tests/mutate.py [--timeout SEC] [--jobs N] [--only M01,M02,...]   (--only: a dev subset)
Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts.
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "pft-seccomp.sh")
SUITE = os.path.join(HERE, "run-tests.sh")

# (id, description, old text, new text). Gates (audit grading, apply refusals, health gate) and rollback paths.
MUTANTS = [
    # audit grading
    (
        "M01",
        "kernel: errno logging not required",
        '[[ " $al " == *" errno "* ]] && add PASS logging',
        "true && add PASS logging",
    ),
    (
        "M02",
        "profile: check result ignored",
        'elif ! d="$(py check "$PROFILE_FILE" --table "$(table_file)")"; then',
        "elif false; then",
    ),
    (
        "M03",
        "container: Docker default graded PASS",
        "default) add FAIL container",
        "default) add PASS container",
    ),
    (
        "M04",
        "container: unconfined graded PASS",
        "unconfined) add FAIL container",
        "unconfined) add PASS container",
    ),
    (
        "M05",
        "container: drift graded PASS",
        '*) add FAIL container "$c stored seccomp profile',
        '*) add PASS container "$c stored seccomp profile',
    ),
    (
        "M06",
        "canonical compare replaced by raw file sha",
        'want="sha256:$(canon "$PROFILE_FILE")"; add PASS profile',
        'want="sha256:$(sha "$PROFILE_FILE")"; add PASS profile',
    ),
    (
        "M07",
        "filter: init mode not checked",
        '[ "${pm%% *}" = 2 ] && add PASS filter',
        "true && add PASS filter",
    ),
    (
        "M08",
        "recreate: compose override not required",
        '[ "$found" = 1 ] && add PASS recreate',
        "true && add PASS recreate",
    ),
    (
        "M09",
        "confine: cap_drop ALL not required",
        'index("ALL") != null\' <<<"$ins" >/dev/null \\\n      && add PASS confine:cap_drop',
        'true\' <<<"$ins" >/dev/null \\\n      && add PASS confine:cap_drop',
    ),
    (
        "M10",
        "WARN not counted as a finding",
        'case "$1" in FAIL|WARN) FINDINGS',
        'case "$1" in FAIL) FINDINGS',
    ),
    (
        "M11",
        "denials: errno filter dropped (LOG records counted)",
        '$1 == "errno" { n += $5',
        "1 { n += $5",
    ),
    (
        "M12",
        "denials: label filter dropped (throwaways counted)",
        'py audit --table "$(table_file)" --since "$1" --subj "$2" "${files[@]}"',
        'py audit --table "$(table_file)" --since "$1" "${files[@]}"',
    ),
    (
        "M13",
        "denials: count shown but graded PASS",
        "else add WARN denials",
        "else add PASS denials",
    ),
    (
        "M14",
        "denials: unreadable log graded PASS",
        "then DENIED=0; add FAIL denials",
        "then DENIED=0; add PASS denials",
    ),
    ("M15", "prom: failing check exported as 1", '($1 == "PASS") }', "1 }"),
    (
        "M16",
        "ack: malformed file accepted",
        'select(type == "object" and (.until | type) == "number" and (.reason | type) == "string") | .until',
        ".until // 0",
    ),
    (
        "M17",
        "ack: hides records after --until",
        "      eff=$((au + 1))",
        "      eff=$(now)",
    ),
    (
        "M18",
        "ack: future --until accepted",
        '[ "$u" -le "$(now)" ] || die "--until must be',
        'true || die "--until must be',
    ),
    (
        "M19",
        "validate: host label not enforced",
        'pft_seccomp_[a-z_]+\\{host="\'"$h"\'"(,',
        'pft_seccomp_[a-z_]+\\{host="[a-z-]+"(,',
    ),
    (
        "M20",
        "pull: rejected file replaces the last good copy",
        'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "pulled file rejected: $why" 2; fi',
        "true",
    ),
    # apply refusals
    (
        "M21",
        "apply: --yes not required",
        '[ "$YES" = 1 ] || { echo "$(ts) apply: REFUSED - apply re-creates',
        'true || { echo "$(ts) apply: REFUSED - apply re-creates',
    ),
    (
        "M22",
        "apply: no maintenance window required",
        'if [ "$w" != active ]; then echo "refuse no active',
        'if false; then echo "refuse no active',
    ),
    (
        "M23",
        "apply: window length not checked",
        'elif [ "$rem" -lt "$need" ]; then',
        "elif false; then",
    ),
    (
        "M24",
        "apply: data-collection locks ignored",
        'elif [ "$nl" -gt 0 ]; then echo "refuse $nl',
        'elif false; then echo "refuse $nl',
    ),
    (
        "M25",
        "apply: node full not required",
        'rs="$(rpc_state "$c")"; [ "$rs" = full ] ||',
        'rs="$(rpc_state "$c")"; true ||',
    ),
    (
        "M26",
        "apply: candidate check ignored",
        'd="$(py check "$src" --table "$(table_file)")" || {',
        'd="$(py check "$src" --table "$(table_file)")"; true || {',
    ),
    (
        "M27",
        "apply: AppArmor label not required",
        '[ -n "$(subj_of "$ins")" ] || { echo "$(ts) apply: REFUSED - $c has no AppArmor label',
        'true || { echo "$(ts) apply: REFUSED - $c has no AppArmor label',
    ),
    (
        "M28",
        "apply: last-apply-in-place check removed",
        '[ -f "$STATE_FILE" ] && [ "$(jq -r \'.rolled_back // false\' "$STATE_FILE" 2>/dev/null)" != true ] \\',
        "false \\",
    ),
    # health gate
    (
        "M29",
        "gate: stored profile not compared",
        '[ "$st" = "$want" ] || why+=',
        "true || why+=",
    ),
    (
        "M30",
        "gate: init filter mode not checked",
        '[ "${pm%% *}" = 2 ] || why+=" init Seccomp',
        'true || why+=" init Seccomp',
    ),
    (
        "M31",
        "gate: server_state not checked",
        '[ "$rs" = full ] || why+=" server_state',
        'true || why+=" server_state',
    ),
    (
        "M32",
        "gate: confine signature not compared",
        '[ -n "$ins" ] && [ "$(confine_sig "$ins")" = "$sig" ] || why+=',
        "true || why+=",
    ),
    (
        "M33",
        "gate: pft daemons not checked",
        'for u in $daemons; do [ "$("$SYSTEMCTL" is-active "$u" 2>/dev/null)" = active ] || why+=" $u inactive;"; done',
        "true",
    ),
    (
        "M34",
        "gate: denials since T0 ignored",
        'if [ "${d%%$\'\\t\'*}" != 0 ]; then echo "$(ts) apply: gate FAIL',
        'if false; then echo "$(ts) apply: gate FAIL',
    ),
    (
        "M35",
        "gate: injected failure ignored",
        '[ "$mode" = apply ] && [ "$INJECT" = health ] && why+=',
        "false && why+=",
    ),
    (
        "M36",
        "gate: add-ons' docker exec commands skipped",
        '  exercise_addons "$c"\n  lx "$DOCKER" exec "$c" ps -eo pid,comm\n}\n\n# Health gate',
        '  lx "$DOCKER" exec "$c" ps -eo pid,comm\n}\n\n# Health gate',
    ),
    (
        "M37",
        "confine sig: AppArmor label not part of it",
        '    apparmor: (.AppArmorProfile // ""),\n',
        "",
    ),
    (
        "M38",
        "run args: seccomp option not set",
        '(if $sc != "default" then "--security-opt=seccomp=\\($sc)" else empty end),\n    .Config.Image',
        "empty,\n    .Config.Image",
    ),
    (
        "M39",
        "run args: other security_opt dropped (nnp, apparmor)",
        '(.HostConfig.SecurityOpt // [] | map(select(startswith("seccomp") | not))[] | "--security-opt=\\(.)"),',
        "empty,",
    ),
    (
        "M40",
        "integrity: foreign items accepted",
        'other="$(grep -vxE "container:$1|compose:\\.env|compose:docker-compose\\.seccomp\\.yml" <<<"$items")"',
        'other=""',
    ),
    # rollback paths
    (
        "M41",
        "apply: gate failure does not roll back",
        'echo "$(ts) apply: gate failed -> automatic rollback"; do_rollback auto; local rc=$?',
        'echo "$(ts) apply: gate failed -> automatic rollback"; local rc=0',
    ),
    (
        "M42",
        "apply: failed docker run does not roll back",
        'echo "$(ts) apply: docker run failed -> automatic rollback"; do_rollback auto && return 1; return 5;',
        'echo "$(ts) apply: docker run failed -> automatic rollback"; return 1;',
    ),
    (
        "M43",
        "apply: failed compose up does not roll back",
        'echo "$(ts) apply: compose up failed -> automatic rollback"; do_rollback auto && return 1; return 5;',
        'echo "$(ts) apply: compose up failed -> automatic rollback"; return 1;',
    ),
    (
        "M44",
        "rollback: .env not restored (no prior override)",
        '        cp -p -- "$(jq -r .env_backup <<<"$s")" "$R$wd/.env" && rm -f',
        "        true && rm -f",
    ),
    (
        "M45",
        "rollback: prior override deleted instead of restored",
        'if [ -n "$ob" ]; then # an override existed',
        "if false; then # an override existed",
    ),
    (
        "M46",
        "rollback: previous profile file not restored",
        '  if [ -n "$pb" ] && [ -f "$pb" ]; then\n    cp -p "$pb" "$pf"',
        '  if false; then\n    cp -p "$pb" "$pf"',
    ),
    (
        "M47",
        "rollback: new profile file left behind",
        'if [ -z "$pb" ] && [ -f "$pf" ]; then rm -f "$pf";',
        'if false; then rm -f "$pf";',
    ),
    (
        "M48",
        "rollback: restart policy not restored",
        '"$DOCKER" update --restart="$(jq -r .restart <<<"$s")" "$c"',
        '"$DOCKER" update --restart=no "$c"',
    ),
    (
        "M49",
        "rollback: gate result ignored",
        'health_gate rollback "$c" "$before" "$pre" "$sig" "$daemons" 0 || return 5',
        'health_gate rollback "$c" "$before" "$pre" "$sig" "$daemons" 0 || true',
    ),
    (
        "M50",
        "rollback: gate wants the candidate, not the previous state",
        'health_gate rollback "$c" "$before" "$pre" "$sig"',
        'health_gate rollback "$c" "$before" "$(jq -r .want_state <<<"$s")" "$sig"',
    ),
    (
        "M51",
        "rollback: outside a maintenance window",
        'gate="$(maint_gate)"; case "$gate" in ok*) ;; *) echo "$(ts) rollback: REFUSED',
        'gate="ok"; case "$gate" in ok*) ;; *) echo "$(ts) rollback: REFUSED',
    ),
    (
        "M52",
        "apply: previous container keeps its restart policy",
        ' && "$DOCKER" update --restart=no "$old" >/dev/null',
        "",
    ),
    (
        "M53",
        "apply output: IPv4 not masked",
        "; s/([0-9]{1,3}\\.){3}[0-9]{1,3}/<redacted-ip>/g",
        "",
    ),
    (
        "M54",
        "lx: exit code swallowed",
        'rc=$?; echo "(exit $rc)"; return "$rc"; }',
        'rc=$?; echo "(exit $rc)"; return 0; }',
    ),
    # cpu weight / memory.low across compose re-creates
    (
        "M55",
        "apply: resources not restored after compose up",
        '    keep_resources "$c" "$sig" || { echo "$(ts) apply: resources not restored',
        '    true || { echo "$(ts) apply: resources not restored',
    ),
    (
        "M56",
        "rollback: resources not restored after compose up",
        'keep_resources "$c" "$sig" || { echo "$(ts) ROLLBACK FAILED: resources"',
        'true || { echo "$(ts) ROLLBACK FAILED: resources"',
    ),
    (
        "M57",
        "confine signature ignores cpu_shares",
        "cpu_shares: (.HostConfig.CpuShares // 0), memory_reservation",
        "memory_reservation",
    ),
    (
        "M58",
        "run args drop --cpu-shares",
        '(if (.HostConfig.CpuShares // 0) > 0 then "--cpu-shares=',
        '(if false then "--cpu-shares=',
    ),
    (
        "M59",
        "keep_resources: docker update failure ignored",
        '"$DOCKER" update "${a[@]}" "$1" >/dev/null || {',
        '"$DOCKER" update "${a[@]}" "$1" >/dev/null; true || {',
    ),
    (
        "M60",
        "apply: a failed automatic rollback exits 1 like a successful one",
        'echo "$(ts) apply: resources not restored -> automatic rollback"; do_rollback auto && return 1; return 5;',
        'echo "$(ts) apply: resources not restored -> automatic rollback"; do_rollback auto; return 1;',
    ),
]
# Equivalent mutants (no input can reach the difference) are documented here instead of counted.
EQUIVALENT = []


def run_suite(tool, timeout):
    """-> (PASS|FAIL|HANG, stdout). The suite gets its own session; on timeout the whole group is SIGKILLed."""
    p = subprocess.Popen(
        ["nice", "-n", "19", "bash", SUITE, tool],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return "HANG", ""
    return ("PASS" if p.returncode == 0 else "FAIL"), out


def one(work, timeout, src, m):
    mid, desc, old, new = m
    n = src.count(old)
    if n != 1:
        return mid, "NOT APPLIED", f"({n} matches) - {desc}"
    path = os.path.join(work, f"{mid}.sh")
    with open(path, "w") as f:
        f.write(src.replace(old, new, 1))
    st, out = run_suite(path, timeout)
    os.remove(path)
    if st == "PASS":
        return mid, "SURVIVED", f"- {desc}"
    if st == "HANG":
        return mid, "CAUGHT", f"- {desc} [suite hung (timeout, process group killed)]"
    fails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
    done = any(ln.startswith("RESULT:") for ln in out.splitlines())
    if not fails or not done:
        # a suite that died before its checks proves nothing about the mutant (log 04: every mutant copy lacked the
        # helper next to it, so the suite stopped at its first generate and all 54 read as caught)
        last = out.strip().splitlines()[-1:] or [""]
        return (
            mid,
            "BROKEN",
            f"- {desc} [suite failed without a FAIL line or RESULT: {last[0][:120]}]",
        )
    return mid, "CAUGHT", f"- {desc} [{len(fails)} failing: {'; '.join(fails[:2])}]"


def main():
    a = sys.argv
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 900
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 2
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    with open(TOOL) as f:
        src = f.read()
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="pft-sc-mut.", dir=base)
    # the tool finds its helper, margin and Docker reference profile next to itself: give every copy the same
    # neighbours, and run the control from a copy in the same place, so a broken copy setup fails the control
    tooldir = os.path.dirname(os.path.abspath(TOOL))
    for rel in (
        "pft_seccomp.py",
        "margin.tsv",
        os.path.join("ref", "docker-default-29.1.3.json"),
    ):
        os.makedirs(os.path.dirname(os.path.join(work, rel)), exist_ok=True)
        shutil.copy2(os.path.join(tooldir, rel), os.path.join(work, rel))
    ctl = os.path.join(work, "CONTROL.sh")
    with open(ctl, "w") as f:
        f.write(src)
    st, out = run_suite(ctl, timeout)
    os.remove(ctl)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(f"control (unmutated): {st} {last[-1] if last else ''}", flush=True)
    if st != "PASS":
        print("RESULT: control run failed, mutants not run")
        shutil.rmtree(work)
        return 2
    selected = [m for m in MUTANTS if only is None or m[0] in only]
    res = {}
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for mid, status, text in ex.map(lambda m: one(work, timeout, src, m), selected):
            res[mid] = status
            print(f"{mid} {status} {text}", flush=True)
    shutil.rmtree(work)
    c = sum(1 for s in res.values() if s == "CAUGHT")
    sv = sum(1 for s in res.values() if s == "SURVIVED")
    na = sum(1 for s in res.values() if s == "NOT APPLIED")
    br = sum(1 for s in res.values() if s == "BROKEN")
    orphans = subprocess.run(
        ["pgrep", "-fc", "pft-sc-mut\\."], capture_output=True, text=True, check=False
    ).stdout.strip()
    print(f"orphan check: {orphans or 0} process(es) still running from mutant copies")
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(
        f"RESULT: {c} caught, {sv} survived, {na} not applied, {br} broken of {len(selected)}{subset}"
        f" (+ {len(EQUIVALENT)} documented equivalent{': ' + ', '.join(EQUIVALENT) if EQUIVALENT else ''})"
    )
    return 0 if sv == 0 and na == 0 and br == 0 and (orphans or "0") == "0" else 1


if __name__ == "__main__":
    sys.exit(main())
