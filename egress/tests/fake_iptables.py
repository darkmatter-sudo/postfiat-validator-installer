#!/usr/bin/env python3
"""Minimal stateful iptables / iptables-restore stand-in for the pft-egress offline tests.

State lives in $FAKE_IPT_STATE (JSON: {"chains": {name: [rule, ...]}, "drops": int}). Rules are stored as the
text after "-A CHAIN "; -C/-D compare with double quotes removed (real iptables -S quotes comments).
Invoked as fake_iptables.py iptables ARGS... or fake_iptables.py iptables-restore --noflush (rules on stdin).
"""
import json
import os
import sys

STATE = os.environ["FAKE_IPT_STATE"]


def load():
    with open(STATE) as f:
        return json.load(f)


def save(s):
    with open(STATE, "w") as f:
        json.dump(s, f)


def norm(rule):
    return " ".join(rule.replace('"', "").split())


def fail(msg, code=1):
    print(f"iptables: {msg}", file=sys.stderr)
    sys.exit(code)


def iptables(args, s):
    op, chain, rest = args[0], (args[1] if len(args) > 1 else None), args[2:]
    ch = s["chains"]
    if op == "-S":
        names = [chain] if chain else list(ch)
        for n in names:
            if n not in ch:
                fail(f"chain '{n}' does not exist")
            print(f"-N {n}")
            for r in ch[n]:
                print(f"-A {n} {r}")
        return
    if op == "-N":
        if chain in ch:
            fail("chain already exists")
        ch[chain] = []
    elif op in ("-C", "-D", "-I", "-A", "-F", "-X", "-L") and chain not in ch:
        fail(f"chain '{chain}' does not exist")
    elif op == "-C":
        if norm(" ".join(rest)) not in [norm(r) for r in ch[chain]]:
            sys.exit(1)
        return
    elif op == "-D":
        rules = [norm(r) for r in ch[chain]]
        want = norm(" ".join(rest))
        if want not in rules:
            fail("bad rule (does a matching rule exist in that chain?)")
        del ch[chain][rules.index(want)]
    elif op == "-I":
        pos = 1
        if rest and rest[0].isdigit():
            pos, rest = int(rest[0]), rest[1:]
        ch[chain].insert(pos - 1, " ".join(rest))
    elif op == "-A":
        ch[chain].append(" ".join(rest))
    elif op == "-F":
        ch[chain] = []
    elif op == "-X":
        refs = [r for rs in ch.values() for r in rs if r.endswith(f"-j {chain}")]
        if refs or ch[chain]:
            fail("chain is in use / not empty")
        del ch[chain]
    elif op == "-L":
        print(f"Chain {chain} (1 references)")
        print("    pkts      bytes target     prot opt in     out     source               destination")
        for r in ch[chain]:
            tgt = r.split("-j ")[-1].split()[0]
            n = s.get("drops", 0) if tgt == "DROP" else 0
            print(f"{n:8d} {n * 60:10d} {tgt:10s} all  --  *      *       0.0.0.0/0            0.0.0.0/0")
        return
    else:
        fail(f"unsupported {op}", 2)
    save(s)


def restore(s):
    if os.environ.get("FAKE_IPT_RESTORE_FAIL"):
        fail("restore failed (injected)")
    for line in sys.stdin.read().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line in ("*filter", "COMMIT"):
            continue
        if line.startswith(":"):
            name = line[1:].split()[0]
            s["chains"][name] = []
        elif line.startswith("-F "):
            s["chains"][line.split()[1]] = []
        elif line.startswith("-A "):
            _, name, rule = line.split(" ", 2)
            s["chains"][name].append(rule)
        else:
            fail(f"restore: unsupported line {line}", 2)
    save(s)


if __name__ == "__main__":
    st = load()
    if sys.argv[1] == "iptables-restore":
        restore(st)
    else:
        iptables(sys.argv[2:], st)
