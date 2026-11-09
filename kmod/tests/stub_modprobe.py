#!/usr/bin/env python3
"""Stub modprobe for the kmod offline suite. Reads KMOD_T (test dir):
  KMOD_T/md/*.conf     modprobe.d (sorted by name, like modprobe)
  KMOD_T/tree          one line per module in the fake module tree: "name dep1 dep2 ..."
  KMOD_T/root/lib/modules/KREL/modules.builtin   built-in modules (kernel/.../name.ko)
Supports: -c (effective install/blacklist lines, names normalised to _) and --show-depends M (deps first, a
dependency or module with an install rule prints "install CMD", built-ins "builtin M"; rc 1 if M is unknown)."""

import glob
import os
import sys

T = os.environ["KMOD_T"]
norm = lambda s: s.replace("-", "_")


def config():
    rules = []
    for f in sorted(glob.glob(os.path.join(T, "md", "*.conf"))):
        with open(f) as fh:
            for line in fh:
                w = line.split()
                if len(w) >= 2 and w[0] in ("install", "blacklist"):
                    rules.append((w[0], norm(w[1]), " ".join(w[2:])))
    return rules


def installs():
    d = {}
    for kind, name, cmd in config():
        if kind == "install":
            d[name] = cmd
    return d


def tree():
    t = {}
    p = os.path.join(T, "tree")
    if os.path.exists(p):
        with open(p) as fh:
            for line in fh:
                w = line.split()
                if w:
                    t[norm(w[0])] = [norm(x) for x in w[1:]]
    return t


def builtin():
    krel = os.environ.get("PFT_KM_UNAME_R", "test")
    p = os.path.join(T, "root", "lib", "modules", krel, "modules.builtin")
    out = set()
    if os.path.exists(p):
        with open(p) as fh:
            for line in fh:
                out.add(norm(os.path.basename(line.strip())[:-3]))
    return out


def show(m, ins, t, b, seen, out):
    if m in seen:
        return
    seen.add(m)
    if m in ins:
        out.append(f"install {ins[m]} ")
        return
    if m in b:
        out.append(f"builtin {m}")
        return
    for d in t.get(m, []):
        show(d, ins, t, b, seen, out)
    out.append(f"insmod /lib/modules/test/kernel/{m}.ko ")


args = sys.argv[1:]
if args == ["-c"]:
    for kind, name, cmd in config():
        print((f"{kind} {name} {cmd}").rstrip())
    sys.exit(0)
if len(args) == 2 and args[0] == "--show-depends":
    m = norm(args[1])
    ins, t, b = installs(), tree(), builtin()
    if m not in ins and m not in t and m not in b:
        print(
            f"modprobe: FATAL: Module {m} not found in directory /lib/modules/test",
            file=sys.stderr,
        )
        sys.exit(1)
    out = []
    show(m, ins, t, b, set(), out)
    print("\n".join(out))
    sys.exit(0)
print(f"stub modprobe: unsupported args {args!r}", file=sys.stderr)
sys.exit(9)
