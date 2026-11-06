#!/usr/bin/env python3
"""Stub `systemctl` for the jobwatch tests: answers `show [--no-pager] [--timestamp=...] -p PROPS [--] NAME|GLOB...`
from JW_STUB_DIR/<unit>.show (captured `systemctl show` output). Unknown names answer LoadState=not-found like systemd;
a glob matches loaded fixture files only. Every call is appended to JW_STUB_LOG (the suite checks the stub, not the
real systemctl, answered, and that only `show` was ever run). JW_STUB_FAIL=1: exit 1 with an error, like a dead bus."""

import fnmatch
import os
import sys

d = os.environ["JW_STUB_DIR"]
with open(os.environ["JW_STUB_LOG"], "a") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\n")
if os.environ.get("JW_STUB_FAIL") == "1":
    print("Failed to connect to bus: No such file or directory", file=sys.stderr)
    sys.exit(1)
a = sys.argv[1:]
if not a or a[0] != "show":
    print(f"stub: refusing non-show verb {a[:1]}", file=sys.stderr)
    sys.exit(2)
props, names, i = None, [], 1
while i < len(a):
    if a[i] == "-p":
        props = a[i + 1].split(",")
        i += 2
        continue
    if a[i] in ("--", "--no-pager") or a[i].startswith("--timestamp="):
        i += 1
        continue
    names.append(a[i])
    i += 1
files = sorted(f[: -len(".show")] for f in os.listdir(d) if f.endswith(".show"))
units = []
for n in names:
    if any(c in n for c in "*?["):
        units += [f for f in files if fnmatch.fnmatchcase(f, n) and f not in units]
    else:
        units.append(n)
blocks = []
for u in units:
    p = os.path.join(d, u + ".show")
    if os.path.exists(p):
        with open(p) as fh:
            kv = [ln.rstrip("\n") for ln in fh if "=" in ln]
    else:
        kv = [
            f"Id={u}",
            "LoadState=not-found",
            "ActiveState=inactive",
            "UnitFileState=",
            "LastTriggerUSec=",
            "Unit=",
        ]
    if props:
        kv = [ln for ln in kv if ln.split("=", 1)[0] in props]
    blocks.append("\n".join(kv))
print("\n\n".join(blocks))
