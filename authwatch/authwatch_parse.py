#!/usr/bin/env python3
"""pft-authwatch parser: journald sshd/sudo entries -> privacy-safe counters (Python 3 stdlib only).

Reads `journalctl -o json` lines on stdin (SYSLOG_IDENTIFIER sshd or sudo), adds them to the counters kept in a
state file and writes a node_exporter textfile. Usernames, addresses and key fingerprints are never written to the
textfile or the state file; a fingerprint is only compared with the allowlist and then dropped.

  authwatch_parse.py collect --state F --allowlist F --textfile F --host NAME [--now T] [--baseline]
      stdin: journal entries after the state's cursor. Writes the state (new cursor + counters) and the textfile,
      each to a temp file renamed into place, so a run that dies half way changes nothing and the next run reads
      the same entries again from the old cursor (no double counting).
  authwatch_parse.py scan --window SECONDS
      stdin: journal entries (any range). Prints totals and the largest per-window failed-auth count (baseline).
  authwatch_parse.py classify
      stdin: one sshd/sudo MESSAGE per line, "IDENT<TAB>MESSAGE". Prints "CLASS<TAB>LABEL" (tests).
"""
import argparse
import json
import os
import re
import sys
import tempfile

VERSION = "1.0.0"
PREFIX = "pft_authwatch_"
FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")

# one counted event per connection attempt; companion lines of the same attempt are ignored on purpose
SSHD = [
    (re.compile(r"^Accepted (publickey|password|keyboard-interactive/pam|hostbased|gssapi-with-mic) for \S+ "
                r"from \S+ port \d+ ssh2(?:: \S+ (SHA256:\S+))?"), "accepted"),
    (re.compile(r"^Invalid user .* from \S+ port \d+$"), "invalid_user"),
    (re.compile(r"^Failed (password|publickey|keyboard-interactive/pam|none|hostbased) for "), "failed"),
    (re.compile(r"^error: maximum authentication attempts exceeded for "), "max_auth"),
    (re.compile(r"^(?:Connection closed by|Connection reset by|Disconnected from) authenticating user \S+ "
                r"\S+ port \d+ \[preauth\]$"), "preauth_abort"),
    (re.compile(r"^Unable to negotiate with \S+ port \d+: no matching (cipher|MAC|key exchange method|"
                r"host key type) found"), "negotiate"),
]
SUDO_CMD = re.compile(r"^\s*\S+ : (?:(\d+) incorrect password attempts? ; )?(?:TTY=\S+ ; )?PWD=.* ; USER=\S+ ; "
                      r"(?:.* ; )?COMMAND=")
SUDO_DENY = re.compile(r"^\s*\S+ : (?:user NOT in sudoers|command not allowed|user NOT authorized on host) ; ")
SUDO_NOPW = re.compile(r"^\s*\S+ : (?:(\d+) incorrect password attempts?|a password is required) ; ")
FAILED_REASONS = ("invalid_user", "failed_password", "failed_publickey", "failed_other", "max_auth",
                  "preauth_abort")
NEGOTIATE = ("cipher", "mac", "kex", "hostkey")
METHODS = ("publickey", "password", "other")
KEY_CLASSES = ("allowlisted", "unknown", "none")
SUDO_RESULTS = ("ok", "auth_failure", "denied")


def classify(ident, msg, allow):
    """-> (counter, label) or None. counter in accepted|failed|negotiate|sudo."""
    if ident == "sshd":
        for rx, kind in SSHD:
            m = rx.match(msg)
            if not m:
                continue
            if kind == "accepted":
                method = m.group(1)
                if method == "publickey":
                    fp = m.group(2) or ""
                    return "accepted", ("publickey", "allowlisted" if fp in allow else "unknown")
                return "accepted", ("password" if method == "password" else "other", "none")
            if kind == "failed":
                meth = m.group(1)
                return "failed", "failed_" + (meth if meth in ("password", "publickey") else "other")
            if kind == "negotiate":
                return "negotiate", {"cipher": "cipher", "MAC": "mac", "key exchange method": "kex",
                                     "host key type": "hostkey"}[m.group(1)]
            return "failed", kind
        return None
    if ident == "sudo":
        m = SUDO_CMD.match(msg)
        if m:
            return "sudo", "auth_failure" if m.group(1) else "ok"
        if SUDO_DENY.match(msg):
            return "sudo", "denied"
        if SUDO_NOPW.match(msg):
            return "sudo", "auth_failure"
    return None


def message(entry):
    msg = entry.get("MESSAGE", "")
    if isinstance(msg, list):  # journald sends non-UTF-8 messages as a byte array
        msg = bytes(b & 0xFF for b in msg if isinstance(b, int)).decode("utf-8", "replace")
    return msg if isinstance(msg, str) else ""


def read_allowlist(path):
    allow = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                tok = line.split("#", 1)[0].split()
                if tok and FP_RE.match(tok[0]):
                    allow.add(tok[0])
    except FileNotFoundError:
        pass
    return allow


def empty_state():
    return {
        "version": 1, "cursor": None, "entries_total": 0, "unmatched_total": 0,
        "accepted": {f"{m}|{k}": 0 for m in METHODS for k in KEY_CLASSES},
        "failed": {r: 0 for r in FAILED_REASONS},
        "negotiate": {r: 0 for r in NEGOTIATE},
        "sudo": {r: 0 for r in SUDO_RESULTS},
        "last_unknown_login_seconds": 0, "last_failed_seconds": 0, "last_entry_seconds": 0,
    }


def load_state(path):
    st = empty_state()
    try:
        with open(path, encoding="utf-8") as f:
            old = json.load(f)
    except FileNotFoundError:
        return st
    for k, v in old.items():
        if isinstance(st.get(k), dict) and isinstance(v, dict):
            st[k].update({kk: int(vv) for kk, vv in v.items() if kk in st[k]})
        elif k in st:
            st[k] = v
    return st


def apply(st, entries, allow):
    for e in entries:
        ident = e.get("SYSLOG_IDENTIFIER", "")
        try:
            ts = int(e.get("__REALTIME_TIMESTAMP", "0")) // 1_000_000
        except ValueError:
            ts = 0
        if e.get("__CURSOR"):
            st["cursor"] = e["__CURSOR"]
        st["entries_total"] += 1
        st["last_entry_seconds"] = max(st["last_entry_seconds"], ts)
        c = classify(ident, message(e), allow)
        if c is None:
            st["unmatched_total"] += 1
            continue
        counter, label = c
        if counter == "accepted":
            st["accepted"]["|".join(label)] += 1
            if label[1] != "allowlisted":
                st["last_unknown_login_seconds"] = max(st["last_unknown_login_seconds"], ts)
        elif counter == "failed":
            st["failed"][label] += 1
            st["last_failed_seconds"] = max(st["last_failed_seconds"], ts)
        else:
            st[counter][label] += 1
    return st


def read_entries(stream):
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e, dict):
            yield e


def render(st, host, now, allow_n):
    h = f'host="{host}"'
    out = []

    def metric(name, typ, help_, samples):
        out.append(f"# HELP {PREFIX}{name} {help_}")
        out.append(f"# TYPE {PREFIX}{name} {typ}")
        for labels, v in samples:
            out.append(f"{PREFIX}{name}{{{h}{labels}}} {v}")

    metric("up", "gauge", "1 if the last collection read the journal and wrote this file.", [("", 1)])
    metric("collect_timestamp_seconds", "gauge", "Unix time of the last collection.", [("", now)])
    metric("ssh_accepted_total", "counter", "Accepted SSH logins by method and key class (allowlist).",
           [(f',method="{m}",key_class="{k}"', st["accepted"][f"{m}|{k}"])
            for m in METHODS for k in KEY_CLASSES])
    metric("ssh_failed_total", "counter", "Failed SSH authentication attempts by reason (one per attempt).",
           [(f',reason="{r}"', st["failed"][r]) for r in FAILED_REASONS])
    metric("ssh_negotiation_failed_total", "counter", "Connections refused before authentication: no common "
           "algorithm.", [(f',kind="{r}"', st["negotiate"][r]) for r in NEGOTIATE])
    metric("sudo_total", "counter", "sudo invocations by result.", [(f',result="{r}"', st["sudo"][r])
                                                                    for r in SUDO_RESULTS])
    metric("journal_entries_total", "counter", "sshd/sudo journal entries read.", [("", st["entries_total"])])
    metric("journal_unmatched_total", "counter", "Entries read that are not counted (session/companion lines).",
           [("", st["unmatched_total"])])
    metric("last_unknown_login_timestamp_seconds", "gauge", "Unix time of the last login with a key that is not "
           "allowlisted, or without a key (0 = never).", [("", st["last_unknown_login_seconds"])])
    metric("last_failed_timestamp_seconds", "gauge", "Unix time of the last failed attempt (0 = never).",
           [("", st["last_failed_seconds"])])
    metric("allowlist_entries", "gauge", "Fingerprints in the allowlist.", [("", allow_n)])
    metric("info", "gauge", "Parser version.", [(f',version="{VERSION}"', 1)])
    return "\n".join(out) + "\n"


def atomic_write(path, text, mode):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".authwatch-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def main(argv):
    ap = argparse.ArgumentParser(prog="authwatch_parse.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--state", required=True)
    c.add_argument("--allowlist", required=True)
    c.add_argument("--textfile", required=True)
    c.add_argument("--host", required=True)
    c.add_argument("--now", type=int)
    c.add_argument("--baseline", action="store_true", help="first run: take the cursor, count nothing")
    s = sub.add_parser("scan")
    s.add_argument("--window", type=int, default=600)
    s.add_argument("--allowlist", default="/nonexistent")
    sub.add_parser("classify")
    a = ap.parse_args(argv)

    if a.cmd == "classify":
        allow = set()
        for line in sys.stdin:
            ident, _, msg = line.rstrip("\n").partition("\t")
            c = classify(ident, msg, allow)
            print("-\t-" if c is None else f"{c[0]}\t{'/'.join(c[1]) if isinstance(c[1], tuple) else c[1]}")
        return 0
    if a.cmd == "scan":
        allow = read_allowlist(a.allowlist)
        st = empty_state()
        buckets = {}
        for e in read_entries(sys.stdin):
            before = sum(st["failed"].values())
            apply(st, [e], allow)
            if sum(st["failed"].values()) > before:
                b = int(e.get("__REALTIME_TIMESTAMP", "0")) // 1_000_000 // a.window
                buckets[b] = buckets.get(b, 0) + 1
        st.pop("cursor")
        st["window_seconds"] = a.window
        st["windows_with_failures"] = len(buckets)
        st["max_failed_per_window"] = max(buckets.values(), default=0)
        st["p99_failed_per_window"] = sorted(buckets.values())[int(0.99 * (len(buckets) - 1))] if buckets else 0
        print(json.dumps(st, indent=1, sort_keys=True))
        return 0

    if not re.match(r"^[a-z][a-z0-9_-]*$", a.host):
        print("bad --host", file=sys.stderr)
        return 3
    allow = read_allowlist(a.allowlist)
    st = load_state(a.state)
    if a.baseline:
        for e in read_entries(sys.stdin):
            st["cursor"] = e.get("__CURSOR") or st["cursor"]
    else:
        st = apply(st, read_entries(sys.stdin), allow)
    now = a.now if a.now is not None else int(__import__("time").time())
    atomic_write(a.state, json.dumps(st, sort_keys=True) + "\n", 0o600)
    atomic_write(a.textfile, render(st, a.host, now, len(allow)), 0o644)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
