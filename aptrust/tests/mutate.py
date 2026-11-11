#!/usr/bin/env python3
"""Mutation harness for pft-aptrust: each mutant changes exactly one text match in a copy of pft-aptrust.sh and runs
tests/run-tests.sh against that copy (its SCRIPT argument); rule mutants (R*) change ../alerts/aptrust.rules.yml in a
copy and run `promtool test rules aptrust.tests.yml`.

A mutant is CAUGHT if its suite fails with a RESULT line and at least one FAIL line (promtool: exit != 0 with
"FAILED"), or hangs (process group SIGKILLed at --timeout). A failing suite without them is BROKEN. A mutant whose old
text does not match exactly once is NOT APPLIED. The unmutated control runs from a copy in the same place and must
pass first. Any SURVIVED / NOT APPLIED / BROKEN mutant or an orphan process fails the harness (exit 1).
(Runner adapted from ../../backupwatch/tests/mutate.py.)
Usage: TEST_TMPDIR=~/.cache python3 -u aptrust/tests/mutate.py [--timeout SEC] [--jobs N] [--only A01,R01,...]
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
AT = os.path.dirname(HERE)
ALERTS = os.path.join(os.path.dirname(AT), "alerts")
SUITE = os.path.join(HERE, "run-tests.sh")
PROMTOOL_IMAGE = "prom/prometheus:v3.5.0"
S, R = "pft-aptrust.sh", "aptrust.rules.yml"

# (id, file, description, old text, new text)
MUTANTS = [
    # sources
    (
        "A01",
        S,
        "src: trusted=yes ignored",
        'trusted) [ "$v" = yes ]',
        'trusted) [ "$v" = never ]',
    ),
    (
        "A02",
        S,
        "src: allow-insecure/weak/downgrade ignored",
        'allow-insecure|allow-weak|allow-downgrade-to-insecure) [ "$v" = yes ]',
        'allow-insecure|allow-weak|allow-downgrade-to-insecure) [ "$v" = never ]',
    ),
    (
        "A03",
        S,
        "src: option values not lower-cased",
        'v="${o#*=}"; v="${v,,}"',
        'v="${o#*=}"',
    ),
    (
        "A04",
        S,
        "src: signed-by naming a missing keyring accepted",
        '; else bad+="signed-by keyring $k missing; "; fi',
        "; fi",
    ),
    (
        "A05",
        S,
        "src: Ubuntu host matched as a substring of the URI",
        '[ "$h" = "$u" ] && return 0',
        '[[ "$1" == *"$u"* ]] && return 0',
    ),
    (
        "A06",
        S,
        "src: Ubuntu mirror suffix matched loosely",
        '[[ "$h" == *.archive.ubuntu.com ]]',
        '[[ "$h" == *archive.ubuntu.com* ]]',
    ),
    (
        "A07",
        S,
        "src: unsigned third-party http only WARN",
        'if [ -z "$sb" ] && [ "$scheme" != https ]; then row FAIL',
        'if [ -z "$sb" ] && [ "$scheme" != https ]; then row WARN',
    ),
    (
        "A08",
        S,
        "src: unsigned third-party https PASS",
        'elif [ -z "$sb" ]; then row WARN "src:$where"',
        'elif [ -z "$sb" ]; then row PASS "src:$where"',
    ),
    (
        "A09",
        S,
        "src: signed third-party over http PASS",
        'elif [ "$scheme" != https ]; then row WARN "src:$where"',
        'elif false; then row WARN "src:$where"',
    ),
    (
        "A10",
        S,
        "deb822: Enabled: no stanza graded",
        'if (have && en != "no")',
        "if (have)",
    ),
    (
        "A11",
        S,
        "deb822: Trusted: key not collected",
        'else if (k == "trusted" || k == "allow-insecure"',
        'else if (k == "allow-insecure"',
    ),
    (
        "A12",
        S,
        "src: no enabled source not a FAIL",
        '[ "$N_SRC" -gt 0 ] || row FAIL src',
        '[ "$N_SRC" -ge 0 ] || row FAIL src',
    ),
    # permissions / legacy / global
    (
        "A13",
        S,
        "perm: non-root owner accepted",
        'if [ "$uid" != 0 ]; then',
        "if false; then",
    ),
    (
        "A14",
        S,
        "perm: group-writable accepted (only world bit checked)",
        "if (( 8#$mode & 8#022 )); then",
        "if (( 8#$mode & 8#002 )); then",
    ),
    (
        "A15",
        S,
        "legacy: trusted.gpg with keys not a FAIL",
        'if [ -s "$R/etc/apt/trusted.gpg" ]; then row FAIL legacy',
        "if false; then row FAIL legacy",
    ),
    (
        "A16",
        S,
        "global: every trusted.gpg.d file treated as stock",
        'if p="$(pkg_stock "$f")"; then row INFO "global:$f"',
        'if p="$(pkg_stock "$f")" || true; then row INFO "global:$f"',
    ),
    (
        "A17",
        S,
        "global: dpkg -V modification ignored",
        "awk -v f=\"$1\" '$NF == f { bad = 1 } END { exit bad }'",
        "awk -v f=\"$1\" '$NF == f { bad = 1 } END { exit 0 }'",
    ),
    # keys
    (
        "A18",
        S,
        "key: RSA-2048 called weak (boundary)",
        '[ "$len" -lt 2048 ]',
        '[ "$len" -le 2048 ]',
    ),
    ("A19", S, "key: DSA not weak", "17) weak+=", "99) weak+="),
    (
        "A20",
        S,
        "key: expiry date ignored (only validity e/r)",
        'if [ "$val" = e ] || [ "$val" = r ] || { [ -n "$exp" ] && [ "$exp" -le "$t" ]; }; then',
        'if [ "$val" = e ] || [ "$val" = r ]; then',
    ),
    (
        "A21",
        S,
        "key: revoked key counted usable",
        '[ "$val" = e ] || [ "$val" = r ] ||',
        '[ "$val" = e ] ||',
    ),
    (
        "A22",
        S,
        "key: expiry warning window one day wider (boundary)",
        '[ $((exp - t)) -lt "$warn" ]',
        "[ $((exp - t)) -le $((warn + 86400)) ]",
    ),
    (
        "A23",
        S,
        "key: no usable key not a FAIL",
        'elif [ "$usable" = 0 ]; then row FAIL',
        "elif false; then row FAIL",
    ),
    (
        "A24",
        S,
        "key: unreadable keyring not reported as such",
        "if ! grep -q '^pub:' <<<\"$out\"; then row FAIL",
        "if false; then row FAIL",
    ),
    # apt options / pins
    (
        "A25",
        S,
        'aptconf: AllowInsecure... "true" not matched',
        'case "$v" in true|yes|1|on) row FAIL "aptconf:$k"',
        'case "$v" in yes|1|on) row FAIL "aptconf:$k"',
    ),
    (
        "A26",
        S,
        'aptconf: Verify-Peer/Host "false" not matched',
        'false|no|0|off) row FAIL "aptconf:$k" "$v: TLS',
        'no|0|off) row FAIL "aptconf:$k" "$v: TLS',
    ),
    (
        "A27",
        S,
        'aptconf: Check-Valid-Until "false" not matched',
        'false|no|0|off) row WARN "aptconf:$k"',
        'no|0|off) row WARN "aptconf:$k"',
    ),
    (
        "A28",
        S,
        "aptconf: failed apt-config dump silent",
        '|| { row WARN aptconf "apt-config dump failed"; return; }',
        "|| { return; }",
    ),
    (
        "A29",
        S,
        "pin: >= 1000 boundary moved",
        'elif [ "$prio" -ge 1000 ]; then',
        'elif [ "$prio" -gt 1001 ]; then',
    ),
    (
        "A30",
        S,
        "pin: third-party '*' pin threshold raised",
        'elif [ "$prio" -gt 500 ] && [ "$pkg" = "*" ]',
        'elif [ "$prio" -gt 600 ] && [ "$pkg" = "*" ]',
    ),
    (
        "A31",
        S,
        "pin: every preferences file treated as stock",
        'if [ -n "$stock" ]; then row INFO "pin:$f:$n"',
        'if true; then row INFO "pin:$f:$n"',
    ),
    # images / compose
    (
        "A32",
        S,
        "image: no RepoDigest always INFO",
        'if in_words "$repo" "$LOCAL_IMAGES"; then row INFO "image:$name"',
        'if true; then row INFO "image:$name"',
    ),
    (
        "A33",
        S,
        "image: :latest third-party not a WARN",
        'elif [ -z "$tag" ] || [ "$tag" = latest ]; then row WARN "image:$name"',
        'elif [ -z "$tag" ]; then row WARN "image:$name"',
    ),
    (
        "A34",
        S,
        "image: every registry image treated as official",
        'elif in_words "$repo" "$OFFICIAL_IMAGES"; then row INFO "image:$name"',
        'elif true; then row INFO "image:$name"',
    ),
    (
        "A35",
        S,
        "image: registry port read as a tag",
        'if [[ "${r##*/}" == *:* ]]; then echo "${r##*:}"',
        'if [[ "$r" == *:* ]]; then echo "${r##*:}"',
    ),
    (
        "A36",
        S,
        "compose: :latest not a WARN",
        'elif [ -z "$tag" ] || [ "$tag" = latest ]; then row WARN "compose:$f:$n"',
        'elif [ -z "$tag" ]; then row WARN "compose:$f:$n"',
    ),
    (
        "A37",
        S,
        "compose: ${VAR:-default} not resolved",
        'ref="$(unvar "${BASH_REMATCH[1]}")"',
        'ref="${BASH_REMATCH[1]}"',
    ),
    (
        "A50",
        S,
        "compose: project .env never read (working_dir label ignored)",
        'load_env "$R${wd:-/nonexistent}/.env"',
        "load_env /nonexistent/.env",
    ),
    (
        "A51",
        S,
        "compose: .env value ignored (always the default)",
        'then val="${CENV[$name]}"',
        "then :",
    ),
    (
        "A52",
        S,
        "compose: :- does not replace an empty value",
        '[[ "$op" != :-* ]]; }; then',
        "true; }; then",
    ),
    (
        "A53",
        S,
        "compose: .env quotes kept",
        'if [[ "$v" =~ ^\\"(.*)\\"$ ]] || [[ "$v" =~ ^\\\'(.*)\\\'$ ]]; then v="${BASH_REMATCH[1]}"; fi',
        "true",
    ),
    (
        "A54",
        S,
        "compose: unset ${VAR} without default becomes empty, not its name",
        'elif [ -z "$op" ]; then val="$name"; fi',
        "fi",
    ),
    (
        "A38",
        S,
        "compose: listed but unreadable file silent",
        '|| { row WARN "compose:$f" "listed by container $name but not readable"; continue; }',
        "|| { continue; }",
    ),
    (
        "A39",
        S,
        "image: docker ps failure silent",
        '|| { row WARN image "docker ps failed',
        '|| { row INFO image "docker ps failed',
    ),
    # off-package installs
    (
        "A40",
        S,
        "offpkg: unknown /usr/local file only INFO",
        'row WARN "offpkg:$p" "not from a package',
        'row INFO "offpkg:$p" "not from a package',
    ),
    (
        "A41",
        S,
        "offpkg: /usr/local/{bin,sbin} dir perms not checked",
        'perm_check "$d" || true',
        "true",
    ),
    (
        "A42",
        S,
        "offpkg: missing allowlist silent",
        '[ -r "$R$ALLOW_MANIFEST" ] || row WARN offpkg',
        '[ -r "$R$ALLOW_MANIFEST" ] || row INFO offpkg',
    ),
    (
        "A43",
        S,
        "pip: global package not a WARN",
        '[ -e "$m" ] && row WARN "pip:',
        '[ -e "$m" ] && row INFO "pip:',
    ),
    (
        "A44",
        S,
        "npm: global package not a WARN",
        '[ -e "$m" ] && row WARN "npm:',
        '[ -e "$m" ] && row INFO "npm:',
    ),
    (
        "A45",
        S,
        "dpkg-local: [installed,local] not matched",
        "grep -F '[installed,local]')",
        "grep -F '[installed,localx]')",
    ),
    # exit code / textfile
    (
        "A46",
        S,
        "exit: WARN-only audit exits 0",
        'rc=0; [ "$(count WARN)" -gt 0 ] || [ "$(count FAIL)" -gt 0 ] && rc=1',
        'rc=0; [ "$(count FAIL)" -gt 0 ] && rc=1',
    ),
    (
        "A47",
        S,
        "textfile: fail count always 0",
        'pft_aptrust_checks{$L,result="fail"} $(count FAIL)',
        'pft_aptrust_checks{$L,result="fail"} 0',
    ),
    (
        "A48",
        S,
        "textfile: no up 0 when the audit cannot run",
        '[ "$tf" = 1 ] && write_textfile "$(metrics 0 "$t0")"',
        "true",
    ),
    (
        "A49",
        S,
        "textfile: written 0600 (exporter cannot read)",
        'chmod 644 "$t"',
        'chmod 600 "$t"',
    ),
    # apply / rollback
    (
        "P01",
        S,
        "apply: no pft-maint window accepted",
        'if [ "$w" != active ]; then',
        "if false; then",
    ),
    (
        "P02",
        S,
        "apply: MAINT_MIN not enforced",
        'if [ "${rem%.*}" -lt "$MAINT_MIN" ]',
        'if [ "${rem%.*}" -lt 0 ]',
    ),
    (
        "P03",
        S,
        "apply: data-collection lock ignored",
        'if [ "$nl" -gt 0 ]; then',
        "if false; then",
    ),
    (
        "P04",
        S,
        "gate: apt-get update exit code ignored",
        '[ "$rc" = 0 ] || { echo "apt-get update exit $rc"; return 1; }',
        "true",
    ),
    (
        "P05",
        S,
        "gate: signature errors in apt-get update output ignored",
        "  if grep -qE '^(Err:|E:)|NO_PUBKEY|is not signed|signatures (were invalid|couldn.t be verified)|EXPKEYSIG|BADSIG' \"$1\"; then",
        "  if false; then",
    ),
    (
        "P06",
        S,
        "apply: refuses nothing when the pre-gate fails",
        'why="$(update_gate "$TMP/pre.log")" || { rm -rf "$TMP"; refuse "pre-apply gate: $why"; }',
        "true",
    ),
    (
        "P07",
        S,
        "apply: post-gate failure ignored",
        'why="$(update_gate "$TMP/post.log")" || fails+=" post-gate:[$why]"',
        'why="$(update_gate "$TMP/post.log")" || true',
    ),
    (
        "P08",
        S,
        "apply: lost index ignored",
        '[ -z "$lost" ] || fails+=" lost-index:',
        'true || fails+=" lost-index:',
    ),
    (
        "P09",
        S,
        "apply: VERIFY_INJECT ignored",
        '[ -n "$INJECT" ] && fails+=" injected:$INJECT"',
        "true",
    ),
    (
        "P10",
        S,
        "apply: no auto-restore on verify failure",
        '    restore "$bk" || rc=5',
        "    true || rc=5",
    ),
    (
        "P11",
        S,
        "plan: global keyring dropped though one of its keys signs nothing here",
        'if [ "$any" = 1 ] && [ "$all" = 1 ]; then printf \'drop',
        'if [ "$any" = 1 ]; then printf \'drop',
    ),
    (
        "P12",
        S,
        "plan: global keyring dropped while a source stays unsigned (manual)",
        '[ -s "$TMP/manual" ] && grep -q \'without Signed-By\\|no cached\\|verifies with no\' "$TMP/manual" && return 0',
        "true",
    ),
    (
        "P13",
        S,
        "apply: overwrites an existing target keyring",
        '[ -e "$R$p" ] && { rm -rf "$TMP"; refuse "$p already exists',
        'false && { rm -rf "$TMP"; refuse "$p already exists',
    ),
    (
        "P14",
        S,
        "apply: new keyring 0600",
        'base64 -d <<<"$ex" >"$R$d" && chmod 644 "$R$d"',
        'base64 -d <<<"$ex" >"$R$d" && chmod 600 "$R$d"',
    ),
    (
        "P15",
        S,
        "apply: exports every key, not only the signer",
        '--keyring "$R$g" --export "$e" 2>/dev/null',
        '--keyring "$R$g" --export 2>/dev/null',
    ),
    (
        "P16",
        S,
        "restore: sha256 mismatch not reported",
        '[ "$(sha "$R$p")" = "$want" ] || { echo "$(ts) RESTORE MISMATCH',
        'true || { echo "$(ts) RESTORE MISMATCH',
    ),
    (
        "P17",
        S,
        "rollback: created keyring not removed",
        'while IFS= read -r p; do [ -n "$p" ] && rm -f "$R$p"; done <"$bk/created"',
        "true",
    ),
    # rules
    (
        "R01",
        R,
        "rule: FAIL threshold > 1",
        'expr: pft_aptrust_checks{result="fail"} > 0',
        'expr: pft_aptrust_checks{result="fail"} > 1',
    ),
    ("R02", R, "rule: Untrusted for 5m -> 3m", "        for: 5m", "        for: 3m"),
    (
        "R03",
        R,
        "rule: stale age 26h -> 27h",
        "pft_aptrust_last_run_timestamp_seconds > 93600",
        "pft_aptrust_last_run_timestamp_seconds > 97200",
    ),
    (
        "R04",
        R,
        "rule: up 0 not stale",
        "          pft_aptrust_up == 0\n          or ",
        "          ",
    ),
    ("R05", R, "rule: Stale for 30m -> 20m", "        for: 30m", "        for: 20m"),
]
# pull / validate (the validator copies the sentry's textfile) and the default allowlist, 2026-11-11
MUTANTS += [
    (
        "V01",
        S,
        "validate: size limit off",
        '[ "$size" -le "$MAX_BYTES" ] ||',
        "true ||",
    ),
    (
        "V02",
        S,
        "validate: foreign metric accepted",
        'if (match($0, /^pft_aptrust_[a-z_]+\\{/) == 0) { printf "line %d: not a pft_aptrust_ sample\\n", NR; bad = 1; exit }',
        'if (match($0, /^[a-z_]+\\{/) == 0) { printf "line %d: not a pft_aptrust_ sample\\n", NR; bad = 1; exit }',
    ),
    (
        "V03",
        S,
        "validate: host label not checked",
        "if (index(rest, pre) != 1) { printf",
        "if (0) { printf",
    ),
    (
        "V04",
        S,
        "validate: trailing junk accepted",
        "if (rest !~ /^[^{}]*\\} -?[0-9]+(\\.[0-9]+)?$/)",
        "if (rest !~ /^[^{}]*\\} -?[0-9]+/)",
    ),
    (
        "V05",
        S,
        "validate: up not required",
        'if (!up) { print "no pft_aptrust_up sample"; exit 1 }',
        "",
    ),
    (
        "V06",
        S,
        "validate: last_run not required",
        'if (!ts) { print "no pft_aptrust_last_run_timestamp_seconds sample"; exit 1 }',
        "",
    ),
    (
        "V07",
        S,
        "pull: own label not refused",
        '[ "$PEER_LABEL" != "$HOST_LABEL" ] || die',
        "true || die",
    ),
    (
        "V08",
        S,
        "pull: no timeout",
        'if ! timeout "$PULL_TIMEOUT" $PULL_SSH',
        "if ! $PULL_SSH",
    ),
    (
        "V09",
        S,
        "pull: failed validation still renamed",
        'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi',
        'why="$(validate "$tmp" "$PEER_LABEL")" || true',
    ),
    (
        "V10",
        S,
        "pull: failed fetch not stopped",
        'rm -f "$tmp"; die "fetch of pft_aptrust_$PEER_LABEL.prom failed" 1',
        "true",
    ),
    (
        "V11",
        S,
        "pull: bad PULL_TIMEOUT accepted",
        '[[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die',
        "true || die",
    ),
    ("V12", S, "pull: copy keeps 0600 temp mode", 'chmod 644 "$tmp" && mv -f', "mv -f"),
    (
        "O01",
        S,
        "default allowlist drops the installer files",
        'OFFPKG_ALLOW="/usr/local/bin/pft-agent /usr/local/bin/postfiat-health /usr/local/sbin/postfiat-docker-user.sh"',
        'OFFPKG_ALLOW="/usr/local/bin/pft-agent"',
    ),
]


def run(cmd, timeout, env=None):
    """-> (PASS|FAIL|HANG, output). Own session; the whole process group is SIGKILLed on timeout."""
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return "HANG", ""
    return ("PASS" if p.returncode == 0 else "FAIL"), out


def make_copy(work, name, mutate=None):
    """Copy the script (+ rules + rule tests) into work/name; mutate = (file, old, new) or None."""
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, "alerts"))
    os.chmod(d, 0o755)
    os.chmod(
        os.path.join(d, "alerts"), 0o755
    )  # promtool runs as nobody in its container
    shutil.copy2(os.path.join(AT, S), os.path.join(d, S))
    for f in (R, "aptrust.tests.yml"):
        shutil.copy2(os.path.join(ALERTS, f), os.path.join(d, "alerts", f))
        os.chmod(os.path.join(d, "alerts", f), 0o644)
    if mutate:
        f, old, new = mutate
        path = os.path.join(d, "alerts", f) if f == R else os.path.join(d, f)
        with open(path) as fh:
            src = fh.read()
        with open(path, "w") as fh:
            fh.write(src.replace(old, new, 1))
    return d


def suite(d, timeout):
    tmp = os.path.join(d, "tmp")  # own temp base per copy
    os.makedirs(tmp, exist_ok=True)
    env = dict(os.environ, TEST_TMPDIR=tmp)
    return run(["bash", SUITE, os.path.join(d, S)], timeout, env)


def promtool(d, timeout):
    return run(
        [
            "sudo",
            "-n",
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "promtool",
            "-v",
            f"{d}/alerts:/w:ro",
            "-w",
            "/w",
            PROMTOOL_IMAGE,
            "test",
            "rules",
            "aptrust.tests.yml",
        ],
        timeout,
    )


def one(work, timeout, m):
    mid, f, desc, old, new = m
    src_path = os.path.join(ALERTS, f) if f == R else os.path.join(AT, f)
    with open(src_path) as fh:
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
            return (
                mid,
                "BROKEN",
                f"- {desc} [promtool failed without FAILED: {out.strip()[-120:]}]",
            )
        names = sorted(
            {
                ln.strip()[len("name: ") :].rstrip(",")
                for ln in out.splitlines()
                if ln.strip().startswith("name: ")
            }
        )
        return mid, "CAUGHT", f"- {desc} [promtool FAILED: {'; '.join(names)[:200]}]"
    fails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
    done = any(ln.startswith("RESULT:") for ln in out.splitlines())
    if not fails or not done:
        last = out.strip().splitlines()[-1:] or [""]
        return (
            mid,
            "BROKEN",
            f"- {desc} [suite failed without a FAIL line or RESULT: {last[0][:120]}]",
        )
    return (
        mid,
        "CAUGHT",
        f"- {desc} [{len(fails)} failing: {'; '.join(x[:90] for x in fails[:2])}]",
    )


def main():
    a = sys.argv
    timeout = int(a[a.index("--timeout") + 1]) if "--timeout" in a else 300
    jobs = int(a[a.index("--jobs") + 1]) if "--jobs" in a else 2
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="atmut.", dir=base)
    os.chmod(work, 0o755)
    ids = [m[0] for m in MUTANTS]
    if len(ids) != len(set(ids)):
        print("RESULT: duplicate mutant ids")
        return 2
    ctl = make_copy(work, "CONTROL")
    st, out = suite(ctl, timeout)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(
        f"control suite (unmutated copy): {st} {last[-1] if last else ''}", flush=True
    )
    pst, pout = promtool(ctl, timeout)
    print(
        f"control promtool (unmutated copy): {pst} {pout.strip().splitlines()[-1] if pout.strip() else ''}",
        flush=True,
    )
    shutil.rmtree(ctl)
    if st != "PASS" or pst != "PASS":
        print("RESULT: control run failed, mutants not run")
        shutil.rmtree(work)
        return 2
    selected = [m for m in MUTANTS if only is None or m[0] in only]
    res = {}
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for mid, status, text in ex.map(lambda m: one(work, timeout, m), selected):
            res[mid] = status
            print(f"{mid} {status} {text}", flush=True)
    shutil.rmtree(work)
    c = sum(1 for s in res.values() if s == "CAUGHT")
    sv = sum(1 for s in res.values() if s == "SURVIVED")
    na = sum(1 for s in res.values() if s == "NOT APPLIED")
    br = sum(1 for s in res.values() if s == "BROKEN")
    orphans = subprocess.run(
        ["pgrep", "-fc", "[a]tmut\\."], capture_output=True, text=True, check=False
    ).stdout.strip()
    print(f"orphan check: {orphans or 0} process(es) still running from mutant copies")
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(
        f"RESULT: {c} caught, {sv} survived, {na} not applied, {br} broken of {len(selected)}{subset}"
    )
    return 0 if sv == 0 and na == 0 and br == 0 and (orphans or "0") == "0" else 1


if __name__ == "__main__":
    sys.exit(main())
