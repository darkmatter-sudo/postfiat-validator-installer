#!/usr/bin/env python3
"""Mutation harness for pft-imagescan.sh and imagescan_lib.py: apply each mutant (exactly one textual match) to a
copy of the module, run the pytest suite against the copy with a timeout, and count it CAUGHT if the suite fails
(or hangs: a hang is a caught mutant, never a stuck harness). An unmutated control run must pass first; a mutant whose
text does not match exactly once is NOT APPLIED and fails the harness. The S0x "docker" mutants insert a forbidden
docker verb (pull / exec / run / create) and prove the docker stub catches it.
Usage: python3 -u tests/mutate.py [--timeout SEC] [--only S01,L02,...]   (--only: a dev subset; the RESULT line says so)
Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on the hardened hosts.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FILES = {"sh": "pft-imagescan.sh", "lib": "imagescan_lib.py"}

# (id, target, description, old text, new text)
MUTANTS = [
    ("S01", "sh", "docker pull before inspect",
     '    "$DOCKER" image inspect "$id" > "$w/inspect.json"',
     '    "$DOCKER" pull "$ref" >/dev/null 2>&1; "$DOCKER" image inspect "$id" > "$w/inspect.json"'),
    ("S02", "sh", "docker exec into each running container",
     '[ -n "$cid" ] || continue',
     '[ -n "$cid" ] || continue; "$DOCKER" exec "$cid" cat /etc/os-release >/dev/null 2>&1'),
    ("S03", "sh", "docker run of each image before save",
     'timeout "$SAVE_TIMEOUT" "$DOCKER" image save "$id"',
     '{ "$DOCKER" run --rm "$id" true >/dev/null 2>&1; timeout "$SAVE_TIMEOUT" "$DOCKER" image save "$id"; }'),
    ("S04", "sh", "docker create (no start) before save",
     'timeout "$SAVE_TIMEOUT" "$DOCKER" image save "$id"',
     '{ "$DOCKER" create "$id" >/dev/null 2>&1 || true; timeout "$SAVE_TIMEOUT" "$DOCKER" image save "$id"; }'),
    ("S05", "sh", "per-image-ID inventory cache ignored", 'if [ ! -s "$f" ] ||', 'if true ||'),
    ("S06", "sh", "scan error exported as up 1", 'base_metrics 0 "$t0"', 'base_metrics 1 "$t0"'),
    ("S07", "sh", "validate: foreign samples accepted",
     'if (match($0, /^pft_imagescan_[a-z_]+\\{/) == 0) {', 'if (0) {'),
    ("S08", "sh", "fetch: unverified download accepted",
     'if ! ts="$(check_feed "$kind" "$tmp/$file" "$lm")"; then', 'ts="$(now)"; if false; then'),
    ("S09", "sh", "scan error exits 0", "printf 'RESULT: ERROR - %s: up 0 -> exit 2\\n' \"$1\"\n    die \"$1\"",
     "printf 'RESULT: ERROR - %s: up 0 -> exit 2\\n' \"$1\"\n    exit 0"),
    ("L01", "lib", "feed sha256 pin ignored", 'if got != m["sha256"]:', "if False:"),
    ("L02", "lib", "feed fetch age ignored", "if age > max_age_days * 86400:", "if False:"),
    ("L03", "lib", "feed own-timestamp age ignored", "if now - ts > max_content_age_days * 86400:", "if False:"),
    ("L04", "lib", "own timestamp after fetch accepted", "if ts > fetched + 3600:", "if False:"),
    ("L05", "lib", "OVAL: installed == fixed counted vulnerable", "dpkg_cmp(v, want) < 0]", "dpkg_cmp(v, want) <= 0]"),
    ("L06", "lib", "OVAL: ESM-only fixes counted fixable", '"fixable": not esm,', '"fixable": True,'),
    ("L07", "lib", "Debian: installed == fixed counted vulnerable", "dpkg_cmp(v, fixed) >= 0:", "dpkg_cmp(v, fixed) > 0:"),
    ("L08", "lib", "Debian: open (no fix) counted fixable", "fixable = False\n", "fixable = True\n"),
    ("L09", "lib", "Go: fixed version counted vulnerable", 'if lo <= k < key(ev["fixed"]):', 'if lo <= k <= key(ev["fixed"]):'),
    ("L10", "lib", "Go: introduced bound ignored", 'if lo <= k < key(ev["fixed"]):', 'if k < key(ev["fixed"]):'),
    ("L11", "lib", "alert: accepted findings still alert", ' and c["accepted"] == "false")', ")"),
    ("L12", "lib", "alert: unfixable findings alert", 'c["fixable"] == "true" and ', ""),
    ("L13", "lib", "alert: medium findings alert", 'c["severity"] in ("critical", "high")',
     'c["severity"] in ("critical", "high", "medium")'),
    ("L14", "lib", "accept: image prefix ignored", "hexid.startswith(p) and f[\"id\"] == i", "f[\"id\"] == i"),
    ("L15", "lib", "accept: expiry ignored", "if until + 86400 <= now:", "if False:"),
    ("L16", "lib", "accept: 90-day limit ignored", "if until - now > 90 * 86400:", "if False:"),
    ("L17", "lib", "public render prints finding details", "        if not public:\n", "        if True:\n"),
    ("L18", "lib", "alert: images not in use alert", 'if im["in_use"]:\n            alert_n += n',
     'if True:\n            alert_n += n'),
    ("L19", "lib", "whiteouts ignored", 'if p in L["whiteouts"] or any(', "if False and any("),
    ("L20", "lib", "dpkg: tilde sorts like a letter", 'if c == "~":\n        return -1', 'if c == "~":\n        return 126'),
    ("L21", "lib", "missing layer silently skipped",
     '            raise Bad(f"layer {lp} listed in manifest.json but not readable from the stream")\n',
     "            continue\n"),
    ("L22", "lib", "drift: running image differs from tag not reported",
     'elif c["image_id"] != cur["image_id"]:', "elif False:"),
    ("L23", "lib", "drift: unscanned image not reported", "if cur is None:\n", "if cur is None and False:\n"),
    ("L24", "lib", "render: drift does not set exit 1", "rc = 1 if (alert_n or drift) else 0",
     "rc = 1 if alert_n else 0"),
    ("L25", "lib", "missing feed for an OS tolerated",
     '            raise Bad(f"no pinned feed {name} in feeds.json")\n', "            return {}\n"),
    ("L26", "lib", "feed age not clamped at 0 (fetched during this scan renders -1 h)",
     "age = max(0, now - fetched)", "age = now - fetched"),
    ("L27", "lib", "fetch time far after the scan time accepted (bad clock)",
     "if fetched > now + 3600:", "if fetched > now + 3600 and False:"),
    ("L28", "lib", "public rebuild: withheld image's container reported as unscanned drift",
     'if d["kind"] == "image_not_scanned" and d["ref"] in wh:', "if False:"),
    ("L29", "lib", "public rebuild: container running another image than the withheld tag hidden",
     "            if running.get(d[\"container\"]) == wh[d[\"ref\"]]:\n", "            if True:\n"),
]


def suite(tmp, timeout):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests"],
                           cwd=tmp, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    last = (r.stdout.strip().splitlines() or [""])[-1]
    return r.returncode, last


def copy_module(base):
    d = tempfile.mkdtemp(prefix="imagescan-mut-", dir=base)
    for f in FILES.values():
        shutil.copy2(os.path.join(ROOT, f), d)
    shutil.copytree(os.path.join(HERE), os.path.join(d, "tests"),
                    ignore=shutil.ignore_patterns("__pycache__", "mutate.py"))
    return d


def main():
    args = sys.argv[1:]
    timeout, only = 600, None
    while args:
        a = args.pop(0)
        if a == "--timeout":
            timeout = int(args.pop(0))
        elif a == "--only":
            only = set(args.pop(0).split(","))
        else:
            sys.exit(f"unknown argument {a}")
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    d = copy_module(base)
    try:
        rc, last = suite(d, timeout)
        print(f"CONTROL unmutated suite: rc={rc} {last}")
        if rc != 0:
            print("RESULT: FAIL - control run does not pass")
            return 1
    finally:
        shutil.rmtree(d)
    todo = [m for m in MUTANTS if only is None or m[0] in only]
    caught = applied_bad = 0
    for mid, target, desc, old, new in todo:
        src = open(os.path.join(ROOT, FILES[target])).read()
        n = src.count(old)
        if n != 1:
            print(f"{mid} NOT APPLIED ({n} matches) {target}: {desc}")
            applied_bad += 1
            continue
        d = copy_module(base)
        try:
            with open(os.path.join(d, FILES[target]), "w") as f:
                f.write(src.replace(old, new))
            rc, last = suite(d, timeout)
        finally:
            shutil.rmtree(d)
        ok = rc != 0
        caught += ok
        print(f"{mid} {'CAUGHT' if ok else 'SURVIVED'} rc={rc} {target}: {desc} | {last}")
    survived = len(todo) - applied_bad - caught
    subset = f" (subset --only {','.join(sorted(only))})" if only else ""
    verdict = "PASS" if survived == 0 and applied_bad == 0 else "FAIL"
    print(f"RESULT: {verdict} - {caught}/{len(todo)} mutants caught, {survived} survived, "
          f"{applied_bad} not applied{subset}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
