#!/usr/bin/env python3
"""Stub lxc + iptables + nft for the offline teardown tests. Called as `stub_host.py lxc ARGS...` or
`stub_host.py iptables ARGS...` (through two tiny wrapper scripts the test writes). State: one JSON file
(RB_STUB_STATE): {"instances": [], "networks": [], "pools": [], "images": [], "chains": {NAME: [rule, ...]}};
built-in chains FORWARD/INPUT hold rules as the text after the chain name ("-i pftrb0 -j PFT-REBUILD").
"nft": {"inet lxd": "chain ...rules or empty"}. Every call is appended to RB_STUB_CALLS. RB_STUB_FAIL=delete makes
`lxc delete` fail; RB_STUB_FAIL=X:CHAIN makes `iptables -X CHAIN` fail (exit 1)."""

import json
import os
import sys

state_path = os.environ["RB_STUB_STATE"]
with open(state_path, encoding="utf-8") as f:
    st = json.load(f)
with open(os.environ["RB_STUB_CALLS"], "a", encoding="utf-8") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")


def save():
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(st, fh)


def lxc(a):
    fail = os.environ.get("RB_STUB_FAIL", "")
    if a[:1] == ["info"] and len(a) == 2:
        return 0 if a[1] in st["instances"] else 1
    if a[:1] == ["delete"]:
        name = a[-1]
        if fail == "delete" or name not in st["instances"]:
            return 1
        st["instances"].remove(name)
        return 0
    if a[:2] == ["image", "delete"]:
        if a[2] not in st["images"]:
            return 1
        st["images"].remove(a[2])
        return 0
    for verb, key in (("network", "networks"), ("storage", "pools")):
        if a[:2] == [verb, "show"]:
            return 0 if a[2] in st[key] else 1
        if a[:2] == [verb, "delete"]:
            if a[2] not in st[key]:
                return 1
            st[key].remove(a[2])
            return 0
    print(f"stub lxc: unsupported {a}", file=sys.stderr)
    return 2


def nft(a):
    tables = st.setdefault("nft", {})
    if a[:2] == ["list", "table"] and len(a) == 4:
        key = f"{a[2]} {a[3]}"
        if key not in tables:
            return 1
        print(f"table {key} {{\n{tables[key]}}}")
        return 0
    if a[:2] == ["delete", "table"] and len(a) == 4:
        return 0 if tables.pop(f"{a[2]} {a[3]}", None) is not None else 1
    return 2


def ipt(a):
    ch = st["chains"]
    op, name, rest = a[0], (a[1] if len(a) > 1 else ""), " ".join(a[2:])
    if op == "-S":
        if name and name not in ch:
            return 1
        for c, rules in ch.items():
            if not name or c == name:
                for r in rules:
                    print(f"-A {c} {r}")
        return 0
    if op == "-N":
        if name in ch:
            return 1
        ch[name] = []
    elif op in ("-A", "-I"):
        if name not in ch:
            return 1
        if op == "-A":
            ch[name].append(rest)
        else:
            rule = " ".join(a[3:]) if a[2:3] and a[2].isdigit() else rest
            ch[name].insert(0, rule)
    elif op == "-C":
        return 0 if rest in ch.get(name, []) else 1
    elif op == "-D":
        if rest not in ch.get(name, []):
            return 1
        ch[name].remove(rest)
    elif op == "-F":
        if name not in ch:
            return 1
        ch[name] = []
    elif op == "-X":
        if os.environ.get("RB_STUB_FAIL") == f"X:{name}":
            return 1
        if (
            name not in ch
            or ch[name]
            or any(f"-j {name}" in r for rules in ch.values() for r in rules)
        ):
            return 1
        del ch[name]
    else:
        return 2
    return 0


rc = {"lxc": lxc, "iptables": ipt, "nft": nft}[sys.argv[1]](sys.argv[2:])
save()
sys.exit(rc)
