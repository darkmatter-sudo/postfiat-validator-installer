import os, shutil, subprocess, sys, tempfile
repo = sys.argv[1]
M = [
 ("fingerprint ignored", 'and fingerprint(live_path, state["fp_len"]) == state["fp"]', 'and True'),
 ("inode ignored", 'live_stat.st_ino == state["inode"]', 'True'),
 ("torn tail consumed when live", '                return offset\n            return line_start', '                return offset\n            return offset'),
 ("newer rotated skipped", 'segments = [(candidate, offset, True)] + [(path, 0, True) for path in newer]', 'segments = [(candidate, offset, True)]'),
 ("rotated read from 0", 'segments = [(candidate, offset, True)]', 'segments = [(candidate, 0, True)]'),
 ("pooled keys ignored", 'if counter.other > limit:', 'if False:'),
 ("limit off by one", 'status = "ok" if value <= limit else "breach"', 'status = "ok" if value < limit else "breach"'),
 ("state path not checked", 'if state["path"] != live_path:', 'if False:'),
 ("no lock", 'fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)', 'pass'),
 ("gap not a breach", '"name": "continuity",\n                "status": "breach"', '"name": "continuity",\n                "status": "ok"'),
 ("schema not checked", 'or record.get("schema") != EVENT_SCHEMA', ''),
 ("oversize counted as event", '        stats.bad["oversize"] += 1\n        if not complete', '        stats.events += 1\n        if not complete'),
 ("start-at-end mid-line", 'end = last_line_end(handle, os.fstat(handle.fileno()).st_size)', 'end = os.fstat(handle.fileno()).st_size'),
 ("error ratio min-events ignored", 'if stats.events < args.min_events:', 'if False:'),
 ("method filter ignored", 'if self.methods is not None and method not in self.methods:', 'if False:'),
]
src = open(os.path.join(repo, "scripts/rpc-events-report")).read()
def run(tag, text):
    d = tempfile.mkdtemp(dir=os.path.expanduser("~/.cache/rpcev-mut"))
    os.makedirs(d + "/scripts"); shutil.copytree(repo + "/ops", d + "/ops")
    open(d + "/scripts/rpc-events-report", "w").write(text)
    shutil.copy(repo + "/scripts/test-rpc-events-report", d + "/scripts/")
    env = dict(os.environ, TMPDIR=d)
    p = subprocess.run(["bash", d + "/scripts/test-rpc-events-report"], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=600)
    fails = [l for l in p.stdout.splitlines() if l.startswith("FAIL")]
    res = [l for l in p.stdout.splitlines() if l.startswith("RESULT")]
    shutil.rmtree(d)
    return p.returncode, res, fails
rc, res, fails = run("baseline", src)
print("baseline rc", rc, res); assert rc == 0
caught = 0
for name, old, new in M:
    n = src.count(old)
    if n != 1:
        print(f"NOT APPLIED ({n}) {name}"); continue
    rc, res, fails = run(name, src.replace(old, new))
    ok = rc != 0 and res and fails
    caught += bool(ok)
    print(("CAUGHT " if ok else "SURVIVED ") + name, res, fails[:2])
print(f"mutants {len(M)} caught {caught}")
