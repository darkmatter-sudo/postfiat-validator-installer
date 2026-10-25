#!/usr/bin/env python3
"""Sanitizer and fail-closed scanner for pft-bundle.

  sanitize.py redact IN_DIR OUT_DIR [--literals FILE]   copy IN_DIR to OUT_DIR with identities replaced
  sanitize.py scan DIR [--literals FILE]                exit 2 if any secret or identity survives

Redaction (applied to every file, in this order):
  postfiatd.cfg   [validator_token]/[validation_seed]/[validator_keys] sections dropped, comment lines dropped,
                  values of password/secret/seed/token/user keys -> <redacted>
  ntfy URLs       https://ntfy.<...>/<topic> -> <ntfy-url>; topic/URL literals from --literals -> <redacted-topic>
  hostnames       literals from --literals (case-insensitive, whole word) -> <host-N>
  IPv4 / IPv6     every address that is not loopback, unspecified or RFC 1918 -> <ip-N>
                  candidates are validated with the ipaddress module, so C++ names such as
                  ConsensusPhase::accepted and times such as 12:34:56 are left alone
N is stable within one bundle: the same address gets the same token in every file.

Scan (fail closed): XRPL seeds, validator token blobs, [validator_token]/[validation_seed] headers, PEM private
keys, GitHub/ntfy access tokens, and any --literals value that survived. Matched text is never printed, only
file:line and the class.

--literals FILE: lines "<class>\t<value>" with class host, ip or topic. The file is read, never copied.
"""
import argparse
import ipaddress
import json
import os
import re
import sys

B58 = "1-9A-HJ-NP-Za-km-z"
SECRET_PATTERNS = [
    ("seed", re.compile(rf"(?<![{B58}])s(?:Ed)?[{B58}]{{28}}(?![{B58}])")),
    ("validator_token_blob", re.compile(r"eyJtYW5pZmVzdCI6|eyJ2YWxpZGF0aW9uX3NlY3JldF9rZXki")),
    ("secret_keyword", re.compile(r"validation_secret_key|master_seed")),
    ("secret_section", re.compile(r"^\s*\[(validator_token|validation_seed|validator_keys)\]", re.M)),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}")),
    ("ntfy_token", re.compile(r"tk_[a-z0-9]{29}")),
]
# Public documentation example printed in the comments of the stock config (comments are dropped anyway).
KNOWN_EXAMPLES = {"shfArahZT9Q9ckTf3s1psJ7C7qzVN"}

CFG_SECRET_SECTIONS = {"validator_token", "validation_seed", "validator_keys"}
CFG_SECRET_KEY = re.compile(r"^(\s*[A-Za-z_]*(?:password|passphrase|secret|seed|token|user)[A-Za-z_]*\s*=\s*)(.+)$",
                            re.I)
NTFY_URL = re.compile(r"https?://(?:[A-Za-z0-9-]+\.)*ntfy[A-Za-z0-9.-]*(?::\d+)?/[A-Za-z0-9_-]+")
IPV4 = re.compile(r"(?<![0-9A-Za-z.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z]|\.\d)")
IPV6 = re.compile(r"(?<![0-9A-Za-z:.])((?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|\d{1,3}(?:\.\d{1,3}){3})?)"
                  r"(?![0-9A-Za-z:])")


def word_rx(value):
    return re.compile(r"(?<![A-Za-z0-9-])" + re.escape(value) + r"(?![A-Za-z0-9-])", re.I)


def read_literals(path):
    lits = {"host": [], "ip": [], "topic": []}
    if not path:
        return lits
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if "\t" not in line:
                continue
            cls, val = line.split("\t", 1)
            val = val.strip()
            if cls in lits and val and val not in lits[cls]:
                lits[cls].append(val)
    for cls in lits:  # longest first, so a FQDN is replaced before its short name
        lits[cls].sort(key=len, reverse=True)
    return lits


KEEP_V4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


def keep_ip(ip):
    """Loopback, unspecified and RFC 1918 (Docker bridges, LAN) stay readable; everything else is tokenized,
    including documentation, CGNAT and link-local ranges (IPv6 link-local embeds the MAC)."""
    if ip.is_loopback or ip.is_unspecified:
        return True
    return ip.version == 4 and any(ip in n for n in KEEP_V4)


class Redactor:
    def __init__(self, lits):
        self.lits = lits
        self.ip_tokens = {}
        self.host_tokens = {}
        self.counts = {"cfg_section": 0, "cfg_comment": 0, "cfg_value": 0, "ntfy_url": 0, "topic": 0,
                       "host": 0, "ipv4": 0, "ipv6": 0}
        self.host_rx = [(h, word_rx(h)) for h in lits["host"]]
        self.own_ips = set()
        for v in lits["ip"]:
            try:
                self.own_ips.add(ipaddress.ip_address(v))
            except ValueError:
                pass

    def ip_token(self, ip):
        if ip not in self.ip_tokens:
            self.ip_tokens[ip] = f"<ip-{len(self.ip_tokens) + 1}>"
        return self.ip_tokens[ip]

    def cfg(self, text):
        out, skip = [], False
        for line in text.splitlines(keepends=True):
            s = line.strip()
            m = re.match(r"^\[([A-Za-z0-9_]+)\]", s)
            if m:
                skip = m.group(1) in CFG_SECRET_SECTIONS
                if skip:
                    self.counts["cfg_section"] += 1
                    out.append(f"# [{m.group(1)}] section removed by pft-bundle\n")
                    continue
            if skip:
                continue
            if s.startswith("#"):
                self.counts["cfg_comment"] += 1
                continue
            m = CFG_SECRET_KEY.match(line.rstrip("\n"))
            if m:
                self.counts["cfg_value"] += 1
                line = m.group(1) + "<redacted>\n"
            out.append(line)
        return "".join(out)

    def _sub_ip(self, m, version):
        cand = m.group(1)
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            return m.group(0)
        if ip.version != version or (keep_ip(ip) and ip not in self.own_ips):
            return m.group(0)
        self.counts["ipv4" if version == 4 else "ipv6"] += 1
        return self.ip_token(ip)

    def text(self, text, is_cfg=False):
        if is_cfg:
            text = self.cfg(text)
        text, n = NTFY_URL.subn("<ntfy-url>", text)
        self.counts["ntfy_url"] += n
        for t in self.lits["topic"]:
            n = text.count(t)
            if n:
                text = text.replace(t, "<redacted-topic>")
                self.counts["topic"] += n
        for h, rx in self.host_rx:
            tok = self.host_tokens.setdefault(h.lower(), f"<host-{len(self.host_tokens) + 1}>")
            text, n = rx.subn(tok, text)
            self.counts["host"] += n
        text = IPV6.sub(lambda m: self._sub_ip(m, 6), text)
        text = IPV4.sub(lambda m: self._sub_ip(m, 4), text)
        return text


def iter_files(root):
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            yield p, os.path.relpath(p, root)


def redact(args):
    r = Redactor(read_literals(args.literals))
    for src, rel in iter_files(args.in_dir):
        dst = os.path.join(args.out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(src, encoding="utf-8", errors="replace") as f:
            data = f.read()
        with open(dst, "w", encoding="utf-8") as f:
            f.write(r.text(data, is_cfg=rel.endswith(".cfg")))
    summary = dict(r.counts, distinct_ips=len(r.ip_tokens), distinct_hosts=len(r.host_tokens))
    print(json.dumps({"redactions": summary}, sort_keys=True))
    return 0


def scan_text(text, lits):
    """Yield (line_no, class) for every surviving secret or identity. Never yields the value."""
    lit_rx = [("literal_host", word_rx(h)) for h in lits["host"]]
    lit_rx += [("literal_ip", re.compile(r"(?<![0-9A-Za-z.:])" + re.escape(i) + r"(?![0-9A-Za-z]|\.\d)"))
               for i in lits["ip"]]
    for no, line in enumerate(text.splitlines(), 1):
        for cls, rx in SECRET_PATTERNS:
            for m in rx.finditer(line):
                if m.group(0) not in KNOWN_EXAMPLES:
                    yield no, cls
                    break
        for t in lits["topic"]:
            if t in line:
                yield no, "literal_topic"
        for cls, rx in lit_rx:
            if rx.search(line):
                yield no, cls


def scan(args):
    lits = read_literals(args.literals)
    hits = 0
    for path, rel in iter_files(args.dir):
        with open(path, encoding="utf-8", errors="replace") as f:
            data = f.read()
        for no, cls in scan_text(data, lits):
            hits += 1
            print(f"HIT {rel}:{no} {cls}")
    print(f"scan: {hits} hit(s)")
    return 2 if hits else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("redact")
    r.add_argument("in_dir")
    r.add_argument("out_dir")
    r.add_argument("--literals")
    s = sub.add_parser("scan")
    s.add_argument("dir")
    s.add_argument("--literals")
    args = p.parse_args(argv)
    return redact(args) if args.cmd == "redact" else scan(args)


if __name__ == "__main__":
    sys.exit(main())
