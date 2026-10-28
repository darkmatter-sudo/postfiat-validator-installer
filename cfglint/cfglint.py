#!/usr/bin/env python3
"""Lint a postfiatd.cfg against the registry of sections/keys the daemon actually reads.

Usage: cfglint.py --registry registry.json [--json] [--build-commit SHA] <cfg-file|->
Exit: 0 = no findings, 1 = findings (error or warn), 2 = usage/read/registry error.
Never prints config values (tokens and seeds live in this file); only line numbers, names and messages.
Parsing mirrors postfiatd: parseIniFile (Config.cpp) + Section::append (BasicConfig.cpp).
"""

import difflib
import json
import re
import sys

KEY_RE = re.compile(r"^\s*([a-zA-Z][_a-zA-Z0-9]*)\s*=\s*(.*\S+)\s*$")  # BasicConfig.cpp re1
EMPTY_RE = re.compile(r"^\s*([a-zA-Z][_a-zA-Z0-9]*)\s*=\s*$")


def strip_comment(val):
    """Section::append remove_comment: '#' starts a comment unless escaped with a backslash."""
    i = val.find("#")
    while i != -1:
        if i == 0:
            return ""
        if val[i - 1] == "\\":
            val = val[: i - 1] + val[i:]
            i = val.find("#", i)
            continue
        return val[:i].strip()
    return val


def parse(text):
    """Return [(section, lineno, line)] exactly as postfiatd groups them, plus section header lines."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    cur, out, headers = "", [], []
    for n, raw in enumerate(text.split("\n"), 1):
        s = raw.strip()
        if not s or s[0] == "#":
            continue
        if s[0] == "[" and s[-1] == "]":
            cur = s[1:-1]
            headers.append((cur, n))
            continue
        out.append((cur, n, s))
    return out, headers


def suggest(word, candidates):
    m = difflib.get_close_matches(word, sorted(candidates), n=1, cutoff=0.6)
    return m[0] if m else None


def lint(text, reg, build_commit=None):
    secs = reg["sections"]
    port = reg["port_section"]
    unread = {(u["section"], u["key"]): u["documented_at"] for u in reg["documented_unread"]}
    lines, headers = parse(text)
    findings = []

    def add(sev, code, line, section, msg, key=None, suggestion=None):
        f = {"severity": sev, "code": code, "line": line, "section": section, "message": msg}
        if key is not None:
            f["key"] = key
        if suggestion:
            f["suggestion"] = suggestion
        findings.append(f)

    if build_commit and build_commit != reg["source"]["commit"]:
        add(
            "warn",
            "registry-mismatch",
            0,
            "",
            "registry built from %s but the node runs %s; regenerate the registry"
            % (reg["source"]["commit"][:12], build_commit[:12]),
        )

    # port sections are whatever names [server] lists (ServerHandler.cpp setup_ServerHandler)
    ports = set()
    for sec, _, line in lines:
        if sec == "server" and not KEY_RE.match(strip_comment(line)):
            ports.add(strip_comment(line))

    def spec(name):
        if name in ports:
            return port
        return secs.get(name)

    seen = {}
    for name, n in headers:
        if name in seen:
            add(
                "warn",
                "duplicate-section",
                n,
                name,
                "section repeated (first at line %d); postfiatd merges the lines" % seen[name],
            )
        else:
            seen[name] = n
        if spec(name) is None:
            cands = set(secs) | ports
            add(
                "error",
                "unknown-section",
                n,
                name,
                "postfiatd never reads this section",
                suggestion=suggest(name, cands),
            )
    if any(sec == "" for sec, _, _ in lines):
        first = next(n for sec, n, _ in lines if sec == "")
        add("error", "no-section", first, "", "line before the first [section]; postfiatd ignores it")

    keyseen = {}
    for sec, n, raw in lines:
        sp = spec(sec)
        if sp is None or sec == "":
            continue
        line = strip_comment(raw)
        if not line:
            continue
        m = KEY_RE.match(line)
        if m is None:
            e = EMPTY_RE.match(line)
            if e and sp["kind"] != "values":
                add(
                    "error",
                    "empty-value",
                    n,
                    sec,
                    "`%s=` has no value; postfiatd does not set the key" % e.group(1),
                    key=e.group(1),
                )
            elif sp["kind"] == "keys":
                add("warn", "not-key-value", n, sec, "plain value in a key=value section; postfiatd ignores it")
            continue
        key = m.group(1)
        if sp["kind"] == "values":
            continue  # value-list sections (tokens, keys, URLs): a '=' inside a value is data, not a key
        prev = keyseen.get((sec, key))
        if prev:
            add("warn", "duplicate-key", n, sec, "key repeated (first at line %d); the last value wins" % prev, key=key)
        keyseen[(sec, key)] = n
        if key not in sp["keys"]:
            sug = suggest(key, sp["keys"])
            if (sec, key) in unread:
                msg = "documented (%s) but postfiatd never reads it" % unread[(sec, key)]
                add("error", "unread-documented-key", n, sec, msg, key=key, suggestion=sug)
            else:
                add(
                    "error",
                    "unknown-key",
                    n,
                    sec,
                    "postfiatd never reads this key in [%s]" % sec,
                    key=key,
                    suggestion=sug,
                )
    findings.sort(key=lambda f: (f["line"], f["code"]))
    return findings


def main(argv):
    args = argv[1:]
    as_json, reg_path, build, target = False, None, None, None
    try:
        while args:
            a = args.pop(0)
            if a == "--json":
                as_json = True
            elif a == "--registry":
                reg_path = args.pop(0)
            elif a == "--build-commit":
                build = args.pop(0)
            elif a.startswith("-") and a != "-":
                raise ValueError(a)
            else:
                if target is not None:
                    raise ValueError(a)
                target = a
        if not reg_path or target is None:
            raise ValueError("missing --registry or cfg")
    except (ValueError, IndexError) as e:
        print("usage: cfglint.py --registry FILE [--json] [--build-commit SHA] <cfg|-> (%s)" % e, file=sys.stderr)
        return 2
    try:
        reg = json.load(open(reg_path))
        if reg.get("schema") != "pft-cfglint-registry/1":
            raise ValueError("unexpected registry schema")
        text = sys.stdin.read() if target == "-" else open(target, encoding="utf-8").read()
    except (OSError, ValueError) as e:
        print("cfglint: %s" % e, file=sys.stderr)
        return 2
    if parse(text) == ([], []):
        print("cfglint: config has no sections or settings (empty or comments only)", file=sys.stderr)
        return 2
    findings = lint(text, reg, build)
    rc = 1 if any(f["severity"] in ("error", "warn") for f in findings) else 0
    if as_json:
        json.dump(
            {
                "registry_commit": reg["source"]["commit"],
                "build_commit": build,
                "findings": findings,
                "errors": sum(f["severity"] == "error" for f in findings),
                "warnings": sum(f["severity"] == "warn" for f in findings),
                "exit": rc,
            },
            sys.stdout,
            indent=1,
        )
        print()
    else:
        for f in findings:
            where = "[%s]%s" % (f["section"], (" " + f["key"]) if "key" in f else "")
            sug = ("  (did you mean `%s`?)" % f["suggestion"]) if f.get("suggestion") else ""
            print(
                "%-5s line %-4d %-22s %-28s %s%s"
                % (f["severity"].upper(), f["line"], f["code"], where, f["message"], sug)
            )
        print(
            "RESULT: %d error(s), %d warning(s) -> exit %d"
            % (sum(f["severity"] == "error" for f in findings), sum(f["severity"] == "warn" for f in findings), rc)
        )
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
