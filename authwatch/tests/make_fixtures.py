#!/usr/bin/env python3
"""Build tests/fixtures/journal-<host>.jsonl from REAL journal entries, redacted.

  journalctl -o json SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sudo --since -3d | \\
      python3 -I tests/make_fixtures.py --per-class 4 > tests/fixtures/journal-validator.jsonl

Keeps up to N entries per message shape (the shape = the message with names/numbers masked), in journal order,
and only the fields the parser reads. Redaction is deterministic and keeps each token's form:
  IPv4 -> 198.51.100.x / 203.0.113.x (RFC 5737), IPv6 -> 2001:db8::x, user names -> user01.., fingerprints ->
  SHA256:<43 chars> derived from a counter (a real key never maps to its own value), cursors -> synthetic,
  PWD=/COMMAND= of sudo lines -> PWD=/srv ; COMMAND=/usr/bin/true (also in "(command continued)" lines), ENV=... -> ENV=PFT_X=1.
  Ports and timestamps are kept.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import re
import sys

TOKEN = re.compile(r"[0-9A-Fa-f:.]*[.:][0-9A-Fa-f:.]*")
FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
# plain "by X" is not a user context ("Connection closed by <address>", "by remote host")
USER_CTX = re.compile(r"((?:[Ii]nvalid user|authenticating user|user|for|session opened for user|"
                      r"session closed for user) )([A-Za-z0-9_.@-]+)")
SUDO_HEAD = re.compile(r"^(\s*)([A-Za-z0-9_.-]+)( : )")
KEEP = {"root"}  # generic account names are kept as they are: they identify nobody
maps = {"ip": {}, "user": {}, "fp": {}}


def m(kind, v, fmt):
    d = maps[kind]
    if v not in d:
        d[v] = fmt(len(d) + 1)
    return d[v]


def is_ip(tok):
    try:
        ipaddress.ip_address(tok)
        return True
    except ValueError:
        return False


def ip(x):
    tok = x.group(0)
    core = tok.rstrip(".:")  # "port 22." / "address:" punctuation
    if not is_ip(core):
        return tok
    v4 = ipaddress.ip_address(core).version == 4
    return m("ip", core, lambda n: (f"198.51.100.{n}" if n < 255 else f"203.0.113.{n % 250}") if v4
             else f"2001:db8::{n:x}") + tok[len(core):]


def redact(msg):
    msg = FP.sub(lambda x: m("fp", x.group(0), lambda n: "SHA256:" + base64.b64encode(
        hashlib.sha256(f"fixture-key-{n}".encode()).digest()).decode().rstrip("=")), msg)
    msg = TOKEN.sub(ip, msg)

    def user(x):
        u = x.group(2)
        if u in KEEP or u in ("from", "user", "invalid", "authenticating") or u.startswith("(uid") or is_ip(u):
            return x.group(0)
        return x.group(1) + m("user", u, lambda n: f"user{n:02d}")
    msg = USER_CTX.sub(user, msg)
    msg = re.sub(r"\broot\(uid=\d+\)", "root(uid=0)", msg)
    msg = re.sub(r"\b([a-z][a-z0-9_-]*)\(uid=\d+\)", lambda x: m("user", x.group(1), lambda n: f"user{n:02d}") +
                 "(uid=1001)", msg)
    msg = re.sub(r"by \(uid=\d+\)", "by (uid=0)", msg)
    msg = SUDO_HEAD.sub(lambda x: x.group(1) + m("user", x.group(2), lambda n: f"user{n:02d}") + x.group(3), msg)
    msg = re.sub(r"ENV=.*?(?= ; COMMAND=)", "ENV=PFT_X=1", msg)
    msg = re.sub(r"PWD=\S+", "PWD=/srv", msg)
    msg = re.sub(r"COMMAND=.*$", "COMMAND=/usr/bin/true", msg)
    msg = re.sub(r"\(command continued\) .*$", "(command continued) /usr/bin/true", msg)
    msg = re.sub(r"TTY=\S+", "TTY=pts/0", msg)
    return re.sub(r"/home/[^/\s]+", "/home/user", msg)  # safety net for any path left


def shape(ident, msg):
    s = re.sub(r"\d+", "N", redact(msg))
    s = re.sub(r"user\d+|userN", "U", s)
    s = re.sub(r"Their offer: .*", "Their offer: X", s)
    return ident + "|" + s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=4)
    a = ap.parse_args()
    seen = {}
    n = 0
    for line in sys.stdin:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        ident, msg = e.get("SYSLOG_IDENTIFIER", ""), e.get("MESSAGE", "")
        if not isinstance(msg, str):
            continue
        k = shape(ident, msg)
        if seen.get(k, 0) >= a.per_class:
            continue
        seen[k] = seen.get(k, 0) + 1
        n += 1
        print(json.dumps({"__CURSOR": f"s=fixture;i={n:x};b=fixture;m={n:x};t={e.get('__REALTIME_TIMESTAMP', '0')};"
                                      f"x={n:x}",
                          "__REALTIME_TIMESTAMP": e.get("__REALTIME_TIMESTAMP", "0"),
                          "SYSLOG_IDENTIFIER": ident, "MESSAGE": redact(msg)}, sort_keys=True))
    print(f"{n} entries, {len(seen)} shapes", file=sys.stderr)


if __name__ == "__main__":
    main()
