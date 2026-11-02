#!/usr/bin/env python3
"""Mutation harness for pft-apparmor.sh and install.sh: apply each mutant (exactly one textual match) to a copy of the tool, run
tests/run-tests.sh against it with a timeout, and count it CAUGHT if the suite fails (or hangs: a hang is a
caught mutant, never a stuck harness). An unmutated control run must pass first; a mutant whose text does not
match exactly once is NOT APPLIED and fails the harness. Mutants with a 5th field "install" mutate install.sh; the
suite then runs the unmutated tool with PFT_AA_INSTALL pointing at the mutated copy.
Usage: python3 -u tests/mutate.py [--timeout SEC] [--only M01,I02,...]   (--only: a dev subset; the RESULT line says so)
Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "pft-apparmor.sh")
SUITE = os.path.join(HERE, "run-tests.sh")
INSTALL = os.path.join(HERE, "..", "install.sh")

# (id, description, old text, new text[, "install"])
MUTANTS = [
    ("M01", "kernel check accepts any value", '[ "$en" = Y ] && add PASS kernel', '[ -n "$en$en" ] || [ -z "$en" ] && add PASS kernel'),
    ("M02", "docker-default graded PASS", 'docker-default) add FAIL container', 'docker-default) add PASS container'),
    ("M03", "complain mode graded PASS", 'complain) add WARN mode', 'complain) add PASS mode'),
    ("M04", "WARN not counted as a finding", "case \"$1\" in FAIL|WARN) FINDINGS", "case \"$1\" in FAIL) FINDINGS"),
    ("M05", "boot check skips the parse", 'elif ! "$PARSER" -Q -K "$f" >/dev/null 2>&1; then', 'elif false; then'),
    ("M06", "boot check skips apparmor.service", 'elif ! "$SYSTEMCTL" is-enabled apparmor.service >/dev/null 2>&1; then', 'elif false; then'),
    ("M07", "recreate: compose override not required", '[ "$found" = 1 ] && add PASS recreate', 'true && add PASS recreate'),
    ("M08", "cap_drop ALL not required", 'index("ALL") != null', 'true'),
    ("M09", "nnp :false accepted", 'test("^no-new-privileges(:true|=true)?$")', 'test("^no-new-privileges")'),
    ("M10", "denials: window ignored", "if (e < t + 0) next", "if (0) next"),
    ("M11", "denials: other profiles with the same prefix counted", 'index($0, "profile=\\"" p "\\"") || index($0, "profile=\\"" p "//")', 'index($0, "profile=\\"" p)'),
    ("M12", "denials: count shown but graded PASS", 'else add WARN denials', 'else add PASS denials'),
    ("M13", "denials: unreadable log graded PASS", 'then DENIED=0; add FAIL denials', 'then DENIED=0; add PASS denials'),
    ("M14", "prom: failing check exported as 1", '($1 == "PASS") }', '1 }'),
    ("M15", "prom: INFO exported", "$1 != \"INFO\" { printf", "1 { printf"),
    ("M16", "events: socket addresses kept", 'if (f != "") print "net\\t" f " " field("sock_type") "\\t-"; next', 'if (f != "") print "net\\t" f " " field("sock_type") " " field("faddr") $0 "\\t-"; next'),
    ("M17", "events: T0 ignored", 'if (substr($0, RSTART + 6, RLENGTH - 6) + 0 < t + 0) next', 'if (0) next'),
    ("M18", "events: DENIED lines dropped", 'index($0, "apparmor=\\"ALLOWED\\"") || index($0, "apparmor=\\"DENIED\\"") {', 'index($0, "apparmor=\\"ALLOWED\\"") {'),
    ("M19", "generate: tree rule without the directory itself", 'echo "$t{,**}"; return ;; "${t%/}")', 'echo "$t**"; return ;; "${t%/}")'),
    ("M20", "generate: /proc pid not normalized", "s#^/proc/[0-9]+/#@{PROC}/@{pid}/#;", ""),
    ("M21", "generate: overlap check disabled", '[ "$bad" = 0 ] || exit 4', 'true'),
    ("M22", "generate: write mask dropped for a/c/d", '[[ "$m" =~ [wacd] ]] && o+=w', '[[ "$m" == *w* ]] && o+=w'),
    ("M23", "generate: lock mask dropped", '[[ "$m" == *k* ]] && o+=k', 'true'),
    ("M24", "generate: --caps ignored", 'for k in $caps; do k="${k,,}"; CAP[${k#cap_}]=1; done', 'true'),
    ("M25", "generate: exec rule loses r for scripts", 'echo "  $k rix,"; else', 'echo "  $k ix,"; else'),
    ("M26", "generate: deny 'network raw' (blocks netlink, enforce probe 04)", 'audit deny network inet raw,', 'audit deny network raw,'),
    ("M27", "generate: ptrace read allow dropped", 'echo "  ptrace (read,readby) peer=$name,', 'echo "  # (read,readby) peer=$name,'),
    ("M28", "generate: EXTRA_EXEC ignored", 'for k in $EXTRA_EXEC; do EX[$k]=1; done', 'true'),
    ("M29", "generate: gshadow deny dropped", '"/etc/gshadow rwklx" ', ''),
    ("M30", "generate: /tmp exec deny dropped", '"/tmp/** x" ', ''),
    ("M31", "generate: unknown kind accepted", '*) die "unknown event kind', '*) true "unknown event kind'),
    ("M33", "apply: no maintenance window required", 'if [ "$w" != active ]; then echo "refuse no active', 'if false; then echo "refuse no active'),
    ("M34", "apply: data-collection locks ignored", 'elif [ "$nl" -gt 0 ]; then echo "refuse $nl', 'elif false; then echo "refuse $nl'),
    ("M35", "apply: window length not checked", 'elif [ "$rem" -lt "$need" ]; then', 'elif false; then'),
    ("M36", "apply: --yes not required", '[ "$YES" = 1 ] || { echo "$(ts) apply: REFUSED - apply re-creates', 'true || { echo "$(ts) apply: REFUSED - apply re-creates'),
    ("M37", "apply: node full not required", 'st="$(rpc_state "$c")"; [ "$st" = full ] ||', 'st="$(rpc_state "$c")"; true ||'),
    ("M38", "apply: candidate compile result ignored", 'lx "$PARSER" -Q -K "$STATE_DIR/candidate" ||', 'lx "$PARSER" -Q -K "$STATE_DIR/candidate"; true ||'),
    ("M39", "gate: confine signature not compared", '[ -n "$ins" ] && [ "$(confine_sig "$ins")" = "$sig" ] || why+=', 'true || why+='),
    ("M40", "run args: --read-only dropped", '(if .HostConfig.ReadonlyRootfs then "--read-only" else empty end),', 'empty,'),
    ("M41", "run args: tmpfs dropped", '(.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\\(.key):\\(.value)"),', 'empty,'),
    ("M42", "run args: security_opt (no-new-privileges) dropped", '(.HostConfig.SecurityOpt // [] | map(select(startswith("apparmor") | not))[] | "--security-opt=\\(.)"),', 'empty,'),
    ("M43", "run args: profile not set", '"--security-opt=apparmor=\\($p)",', '"--security-opt=apparmor=docker-default",'),
    ("M44", "gate: container profile not checked", '[ "$prof" = "$wp" ] || why+=', 'true || why+='),
    ("M45", "gate: server_state not checked", '[ "$st" = full ] || why+=" server_state', 'true || why+=" server_state'),
    ("M46", "gate: DENIED records ignored", 'if [ "$wm" = enforce ] && [ "$dn" != 0 ]; then', 'if false; then'),
    ("M47", "gate: pft daemons not checked", 'for u in $daemons; do [ "$("$SYSTEMCTL" is-active "$u" 2>/dev/null)" = active ] || why+=" $u inactive;"; done', 'true'),
    ("M48", "integrity: foreign items accepted", 'other="$(grep -vxE "container:$1|compose:\\.env|compose:docker-compose\\.apparmor\\.yml" <<<"$items")"', 'other=""'),
    ("M49", "rollback: .env not restored", 'cp -p -- "$(jq -r .env_backup <<<"$s")" "$R$wd/.env" && rm -f', 'true && rm -f'),
    ("M50", "rollback: new profile not removed", 'if [ -f "$pf" ]; then "$PARSER" -R "$pf" >/dev/null 2>&1; rm -f "$pf"; fi', 'true'),
    ("M51", "rollback: restart policy not restored", '"$DOCKER" update --restart="$(jq -r .restart <<<"$s")" "$c"', '"$DOCKER" update --restart=no "$c"'),
    ("M52", "apply --complain: flag not added", 's/^(profile $PROFILE flags=\\()/\\1complain,/; ', ''),
    ("M53", "apply: already-applied check removed", '[ "$pre_prof" = "$PROFILE" ] \\', 'false \\'),
    ("M54", "apply output: IPv4 not masked", '; s/([0-9]{1,3}\\.){3}[0-9]{1,3}/<redacted-ip>/g', ''),
    ("M55", "apply output: env values not masked", 's/^(--env=[^=]*)=.*/\\1=<value>/; ', ''),
    ("M56", "lx: exit code swallowed (the bug the suite found)", 'rc=$?; echo "(exit $rc)"; return "$rc"; }', 'rc=$?; echo "(exit $rc)"; return 0; }'),
    ("M57", "apply: read-only root not required", "jq -e '.HostConfig.ReadonlyRootfs == true' <<<\"$ins\" >/dev/null \\", 'true \\'),
    ("M58", "rollback: gate result ignored", '"$(loaded_mode "$pp")" "$sig" "$daemons" 0 || return 5', '"$(loaded_mode "$pp")" "$sig" "$daemons" 0 || true'),
    ("M59", "apply: previous container keeps its restart policy", ' && "$DOCKER" update --restart=no "$old" >/dev/null', ''),
    ("M61", "gate: DENIED of other profiles with the same prefix counted", 'index($0, "profile=\\"" q "\\"") || index($0, "profile=\\"" q "//")', 'index($0, "profile=\\"" q)'),
    ("M60", "apply: gate failure does not roll back", 'echo "$(ts) apply: gate failed -> automatic rollback"; do_rollback auto; local rc=$?', 'echo "$(ts) apply: gate failed -> automatic rollback"; local rc=0'),
    # validate / pull
    ("M62", "validate: host label not enforced", 'pft_apparmor_[a-z_]+\\{host="\'"$h"\'"(,', 'pft_apparmor_[a-z_]+\\{host="[a-z-]+"(,'),
    ("M63", "validate: foreign lines accepted", '[ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }', 'true'),
    ("M64", "validate: size limit removed", '[ "$(stat -c %s "$f")" -le 65536 ] || { echo "larger than 65536 bytes"; return 1; }', 'true'),
    ("M65", "validate: last_run not required", "grep -qE '^pft_apparmor_last_run_timestamp_seconds\\{host=\"'\"$h\"'\"\\} [0-9]+$' \"$f\" || { echo \"no last_run sample\"; return 1; }", 'true'),
    ("M66", "pull: rejected file still replaces the last good copy", 'if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "pulled file rejected: $why" 2; fi', 'true'),
    ("M67", "pull: no timeout on the ssh", 'if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat', 'if ! $PULL_SSH cat'),
    ("M68", "pull: failed ssh leaves the temp file", '    rm -f "$tmp"; die "pull from $PEER_LABEL failed" 1', '    die "pull from $PEER_LABEL failed" 1'),
    ("M70", "cli: ARG from the environment used", 'ARG=""; ARG2=""; JSON=0;', 'ARG="${ARG:-}"; ARG2="${ARG2:-}"; JSON=0;'),
    # ack-denials
    ("M71", "audit: ack file ignored", '      eff=$((au + 1))', '      eff=$since'),
    ("M72", "audit: ack hides records after --until", '      eff=$((au + 1))', '      eff=$(now)'),
    ("M73", "audit: malformed ack file accepted", "select(type == \"object\" and .profile == $p and (.until | type) == \"number\" and (.reason | type) == \"string\") | .until", '.until // 0'),
    ("M74", "ack: future --until accepted", '[ "$u" -le "$(now)" ] || die "--until must be', 'true || die "--until must be'),
    ("M75", "ack: older --until accepted", '[ "$u" -gt "$prev" ] || die "already acknowledged up to $prev" 4', 'true'),
    ("M76", "ack: count includes records after --until", 'n=$(( ${a%%$\'\\t\'*} - ${b%%$\'\\t\'*} ))', 'n=${a%%$\'\\t\'*}'),
    ("M77", "ack: runs without --yes", '[ "$YES" = 1 ] || { echo "pft-apparmor: ack-denials hides', 'true || { echo "pft-apparmor: ack-denials hides'),
    ("M78", "ack: reason not checked", '[ -n "$why" ] && [ "${#why}" -le 200 ] && [[ "$why" != *[![:print:]]* ]] || die', 'true || die'),
    # install.sh
    ("I01", "install: failed first audit still enables the timer", 'log "ERROR: first audit failed"; "$JOURNALCTL" -u pft-apparmor.service -n 5 --no-pager --utc; exit 1', 'true', "install"),
    ("I02", "install: textfile not validated", '"$BIN" validate "$TEXTDIR/pft_apparmor_$host.prom" "$host" || { log "ERROR: textfile rejected"; exit 1; }', 'true', "install"),
    ("I03", "install: env file left world-readable", 'chmod 600 "$CONF"\nif [ -f "$RC_CONF" ]', 'if [ -f "$RC_CONF" ]', "install"),
    ("I04", "install: rulecheck line added twice", '[ -f "$RC_CONF" ] && ! grep -q \'pft_apparmor_\' "$RC_CONF"', '[ -f "$RC_CONF" ]', "install"),
    ("I05", "install: --host ignored", 'host="${label:-$(conf_get HOST_LABEL)}"', 'host="$(conf_get HOST_LABEL)"', "install"),
    ("I06", "uninstall: does not refuse while an apply is in place", "jq -e '.rolled_back != true' \"$f\" >/dev/null 2>&1 && { echo \"$f\"; return 0; }", 'true', "install"),
    ("I07", "install --pull: failed first pull still enables the timer", 'log "ERROR: first pull failed"; "$JOURNALCTL" -u pft-apparmor-pull.service -n 5 --no-pager --utc; exit 1', 'true', "install"),
    ("I08", "install --pull: runs without PULL_SSH", "&& grep -q '^PULL_SSH=' \"$CONF\"; }; then", '; }; then', "install"),
    ("I09", "install: label not validated", '[ -z "$label" ] || [[ "$label" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "bad host label" >&2; exit 3; }', 'true', "install"),
]

# Equivalent mutants (no input can reach the difference), documented instead of counted:
# M69 "pull: copied file not made world-readable" (drop `chmod 0644 "$tmp"` in do_pull): the script sets umask 022
# at the top, so the `> "$tmp"` redirect already creates the file 0644; the chmod only guards a future umask
# change. Dev run 2026-11-02 reported it SURVIVED.
# M32 "overlap: {,**} probe not expanded" (probe="$p"): every AUDIT_DENY path is either exact (never matches a
# tree rule) or ends in "/**" (ERE ".*"), which matches the literal "{,**}" suffix as well as "x/y". Run 07
# (5f27eaf) reported it SURVIVED; re-check this note if a deny pattern with a single "*" or a mid-path "**" is added.
EQUIVALENT = ["M32", "M69"]


def run_suite(tool, timeout, install=None):
    env = dict(os.environ)
    if install:
        env["PFT_AA_INSTALL"] = install
    try:
        r = subprocess.run(["bash", SUITE, tool], capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return "HANG", ""
    return ("PASS" if r.returncode == 0 else "FAIL"), r.stdout


def main():
    timeout = 300
    if "--timeout" in sys.argv:
        timeout = int(sys.argv[sys.argv.index("--timeout") + 1])
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))
    srcs = {"tool": open(TOOL).read(), "install": open(INSTALL).read()}
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="pft-aa-mut.", dir=base)
    st, out = run_suite(TOOL, timeout)
    last = [ln for ln in out.splitlines() if ln.startswith("RESULT:")]
    print(f"control (unmutated): {st} {last[-1] if last else ''}")
    if st != "PASS":
        print("RESULT: control run failed, mutants not run")
        return 2
    caught = survived = not_applied = 0
    selected = [m for m in MUTANTS if only is None or m[0] in only]
    for mid, desc, old, new, *tgt in selected:
        target = tgt[0] if tgt else "tool"
        src = srcs[target]
        n = src.count(old)
        if n != 1:
            print(f"{mid} NOT APPLIED ({n} matches) - {desc}")
            not_applied += 1
            continue
        path = os.path.join(work, f"{mid}.sh")
        with open(path, "w") as f:
            f.write(src.replace(old, new, 1))
        if target == "install":
            st, out = run_suite(TOOL, timeout, install=path)
        else:
            st, out = run_suite(path, timeout)
        fails = [ln[5:] for ln in out.splitlines() if ln.startswith("FAIL ")]
        if st == "PASS":
            survived += 1
            print(f"{mid} SURVIVED - {desc}")
        else:
            caught += 1
            why = "suite hung (timeout)" if st == "HANG" else f"{len(fails)} failing: {'; '.join(fails[:2])}"
            print(f"{mid} CAUGHT - {desc} [{why}]")
        os.remove(path)
    os.rmdir(work)
    subset = f" (--only subset of {len(MUTANTS)})" if only is not None else ""
    print(f"RESULT: {caught} caught, {survived} survived, {not_applied} not applied of {len(selected)}{subset}"
          f" (+ {len(EQUIVALENT)} documented equivalent: {', '.join(EQUIVALENT)})")
    return 0 if survived == 0 and not_applied == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
