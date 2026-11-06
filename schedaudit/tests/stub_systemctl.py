#!/usr/bin/env python3
"""Stub `systemctl` for the schedaudit tests. Answers only the three read-only verbs the helper uses:
  list-unit-files --type=timer ...   -> SA_STUB_DIR/unit-files.txt (captured `list-unit-files` lines)
  list-units --type=timer --all ...  -> SA_STUB_DIR/units.txt
  show [--no-pager] -p PROPS [--] NAME...  -> SA_STUB_DIR/<unit>.show (captured `systemctl show`), unknown names
                                       answer LoadState=not-found like systemd
Every call is appended to SA_STUB_LOG (the suite checks the stub answered, and that no other verb was ever run).
SA_STUB_FAIL=1: exit 1 with an error, like a dead bus."""

import os
import sys

d = os.environ["SA_STUB_DIR"]
with open(os.environ["SA_STUB_LOG"], "a") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\n")
if os.environ.get("SA_STUB_FAIL") == "1":
    print("Failed to connect to bus: No such file or directory", file=sys.stderr)
    sys.exit(1)
a = sys.argv[1:]
verb = a[0] if a else ""


def cat(name):
    p = os.path.join(d, name)
    if os.path.exists(p):
        with open(p) as fh:
            sys.stdout.write(fh.read())


if verb == "list-unit-files":
    cat("unit-files.txt")
    sys.exit(0)
if verb == "list-units":
    cat("units.txt")
    sys.exit(0)
if verb != "show":
    print(f"stub: refusing verb {verb!r}", file=sys.stderr)
    sys.exit(2)
props, names, i = None, [], 1
while i < len(a):
    if a[i] == "-p":
        props = a[i + 1].split(",")
        i += 2
        continue
    if a[i] in ("--", "--no-pager"):
        i += 1
        continue
    names.append(a[i])
    i += 1
blocks = []
for u in names:
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
            "Unit=",
        ]
    if props:
        kv = [ln for ln in kv if ln.split("=", 1)[0] in props]
    blocks.append("\n".join(kv))
print("\n\n".join(blocks))
