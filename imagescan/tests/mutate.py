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
FILES = {"sh": "pft-imagescan.sh", "lib": "imagescan_lib.py", "unit": "systemd/pft-imagescan-heal.service"}

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
    ("S10", "sh", "report: unmatched inventory glob passed as a literal path (every image withheld)",
     '  shopt -s nullglob; invs=("$b"/inv/*.json); shopt -u nullglob\n', '  invs=("$b"/inv/*.json)\n'),
    # fetch: upstream clock, one cache-busting conditional retry, outcomes, older-copy protection, textfile series
    ("F01", "sh", "fetch: never retries a behind copy",
     '[ $((ref - ts)) -le "$CONTENT_TOLERANCE_SECONDS" ]; then\n      outcome=fresh',
     'true; then\n      outcome=fresh'),
    ("F02", "sh", "fetch: tolerance boundary -le -> -lt",
     '[ $((ref - ts)) -le "$CONTENT_TOLERANCE_SECONDS" ]; then\n      outcome=fresh',
     '[ $((ref - ts)) -lt "$CONTENT_TOLERANCE_SECONDS" ]; then\n      outcome=fresh'),
    ("F03", "sh", "fetch: retry without the cache-busting query", 'ru="$url?pftcb=$t-$$"', 'ru="$url"'),
    ("F04", "sh", "fetch: retry without the conditional header", 'cond=(-H "If-None-Match: $etag")', "cond=()"),
    ("F05", "sh", "fetch: retry copy kept even when not newer", 'elif [ "$rts" -gt "$ts" ]; then', "elif true; then"),
    ("F06", "sh", "fetch: retry copy not verified",
     'if ! rts="$(check_feed "$kind" "$tmp/$file.retry" "$rlm")"; then', 'rts=$((ts + 1)); if false; then'),
    ("F07", "sh", "fetch: still behind after the retry reported retried_fresh",
     'elif [ -n "$ref" ]; then\n        outcome=still_behind', 'elif [ -n "$ref" ]; then\n        outcome=retried_fresh'),
    ("F08", "sh", "fetch: no upstream clock reported fresh", 'outcome=still_behind; note+="; no upstream clock',
     'outcome=fresh; note+="; no upstream clock'),
    ("F09", "sh", "fetch: older-copy protection removed (shell)",
     'if [[ "$old" =~ ^[0-9]+$ ]] && [ "$ts" -lt "$old" ]; then', "if false; then"),
    ("F10", "lib", "fetch: older-copy protection removed (feedmerge)",
     'if action == "replace" and old and int(e["timestamp_epoch"]) < int(old.get("timestamp_epoch", 0)):',
     "if False:"),
    ("F11", "lib", "feedmerge: unknown outcome accepted", 'if e["outcome"] not in OUTCOMES:', "if False:"),
    ("F12", "sh", "fetch: go clock = the zip's Last-Modified (moves on every rebuild)",
     'if [ "$1" = go-osv ]; then', "if false; then"),
    ("F13", "sh", "fetch: HEAD Last-Modified ignored (only the cached response's)",
     'if [ -n "$e1" ] && { [ -z "$e2" ] || [ "$e1" -ge "$e2" ]; }; then', "if false; then"),
    ("F14", "sh", "fetch textfile: old outcome series not stripped",
     "pft_imagescan_feed_(fetch_outcome|upstream_timestamp_seconds|outcome_timestamp_seconds)[{ ]",
     "pft_imagescan_feed_(fetch_outcomeX|upstream_timestamp_secondsX|outcome_timestamp_secondsX)[{ ]"),
    ("F15", "sh", "fetch textfile: written without validation",
     'if ! why="$(validate "$t" "$HOST_LABEL")"; then rm -f "$t"; echo "textfile: invalid ($why)"; return 1; fi',
     "true"),
    ("F16", "lib", "fetch metrics not one-hot", """f'{1 if v["outcome"] == o else 0}' for o in OUTCOMES]""",
     """f'{1}' for o in OUTCOMES]"""),
    ("F17", "sh", "scan textfile without the fetch-outcome series",
     '    python3 -I "$LIB" fetchmetrics --feeds "$CACHE_DIR/feeds/feeds.json" --host "$HOST_LABEL" >> "$w/m.prom"',
     '    true || python3 -I "$LIB" fetchmetrics --feeds "$CACHE_DIR/feeds/feeds.json" --host "$HOST_LABEL" >> "$w/m.prom"'),
    ("F18", "lib", "scan JSON drops the outcome fields", "\n                          + OUTCOME_KEYS if x in v}", " if x in v}"),
    ("U01", "unit", "heal unit runs a full scan (docker) instead of fetch",
     "ExecStart=/usr/local/bin/pft-imagescan fetch", "ExecStart=/usr/local/bin/pft-imagescan scan"),
    ("U02", "unit", "heal unit can reach the docker socket",
     "InaccessiblePaths=-/run/docker.sock -/var/run/docker.sock -/run/containerd\n", ""),
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
     'if d["kind"] == "image_not_scanned" and tag_ref(d["ref"]) in wh:', "if False:"),
    ("L29", "lib", "public rebuild: container running another image than the withheld tag hidden",
     "            if running.get(d[\"container\"]) == wh[tag_ref(d[\"ref\"])]:\n", "            if True:\n"),
    ("L30", "lib", "drift: digest-pinned container running an UNSCANNED image skipped",
     'if pinned and c["image_id"] in scanned_ids:', "if pinned:"),
    ("L31", "lib", "drift: digest-pinned ref not stripped to its tag",
     'return ref.split("@", 1)[0]', "return ref"),
    ("L32", "lib", "drift: digest-pinned container with a scanned image ID still reported",
     "        if pinned and c[\"image_id\"] in scanned_ids:\n            continue\n", ""),
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
        os.makedirs(os.path.dirname(os.path.join(d, f)), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, f), os.path.join(d, f))
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
