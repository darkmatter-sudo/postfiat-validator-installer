#!/usr/bin/env python3
"""Zero-secret-leak check for a live pft-keyescrow host (run as root; prints ids and counts only, never bytes).

  leakcheck.py --tool /usr/local/bin/pft-keyescrow --conf /etc/pft-keyescrow.env --host validator|sentry \
               --scan DIR [--scan DIR ...] [--scan-file FILE ...]

Reads the built-in registry from the installed tool (the REG heredoc), resolves each item that applies to this host
(@MID@ = /etc/machine-id, @ALERTS@ / @VALKEYS@ from the conf), and takes up to 3 probes per present secret: 16-byte
windows at the start, middle and end of the file (the whole file if it is shorter). Every probe is searched in
every regular file under each --scan dir and in each --scan-file.
  control: the same search over the secret file itself must find every probe (proves the probes and the search work)
  leaks:   hits outside the secret's own file (must be 0)
Exit 0 = every control found, 0 leaks; 1 = a leak or a failed control; 3 = usage.
"""

import argparse
import os
import re
import sys
from pathlib import Path


def registry(tool):
    text = Path(tool).read_text(encoding="utf-8")
    m = re.search(r"^  cat <<'REG'\n(.*?)^REG$", text, re.DOTALL | re.MULTILINE)
    if not m:
        sys.exit("no REG block in the tool")
    for line in m.group(1).splitlines():
        f = line.split("\t")
        if len(f) >= 8:
            yield f[0], f[1], f[2]


def conf_get(conf, key):
    val = ""
    try:
        for line in Path(conf).read_text(encoding="utf-8").splitlines():
            if line.startswith(key + "="):
                val = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return val


def resolve(path, conf):
    mid = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    alerts = conf_get(conf, "ALERTS_NTFY_ENV")
    valkeys = conf_get(conf, "VALKEYS_DIR")
    if "@ALERTS@" in path and not alerts:
        return ""
    if "@VALKEYS@" in path and not valkeys:
        return ""
    return (
        path.replace("@MID@", mid)
        .replace("@ALERTS@", alerts)
        .replace("@VALKEYS@", valkeys)
    )


def probes(data):
    if len(data) <= 16:
        return [data] if data else []
    out = []
    for off in (0, (len(data) - 16) // 2, len(data) - 16):
        p = data[off : off + 16]
        if p not in out:
            out.append(p)
    return out


def files_under(dirs, extra):
    for d in dirs:
        for root, _dirs, names in os.walk(d):
            for n in names:
                p = os.path.join(root, n)
                if os.path.isfile(p) and not os.path.islink(p):
                    yield p
    for p in extra:
        if os.path.isfile(p):
            yield p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True)
    ap.add_argument("--conf", required=True)
    ap.add_argument("--host", required=True, choices=["validator", "sentry"])
    ap.add_argument("--scan", action="append", default=[])
    ap.add_argument("--scan-file", action="append", default=[])
    a = ap.parse_args()
    corpus = {}
    for p in files_under(a.scan, a.scan_file):
        try:
            corpus[p] = Path(p).read_bytes()
        except OSError as e:
            print(f"  cannot read a scanned file: {e.strerror}")
            return 1
    print(
        f"scanned files: {len(corpus)} ({sum(len(v) for v in corpus.values())} bytes)"
    )
    bad = checked = 0
    for item, hosts, tmpl in registry(a.tool):
        if hosts not in ("both", a.host):
            continue
        path = resolve(tmpl, a.conf)
        if not path or not os.path.isfile(path):
            print(f"  {item:18s} absent here (not checked)")
            continue
        data = Path(path).read_bytes()
        ps = probes(data)
        control = sum(1 for p in ps if p in data)
        leaks = sum(
            1 for f, body in corpus.items() if f != path for p in ps if p in body
        )
        checked += 1
        ok = control == len(ps) and ps and leaks == 0
        bad += 0 if ok else 1
        print(
            f"  {item:18s} probes {len(ps)}  control {control}/{len(ps)}  leaks {leaks}  {'ok' if ok else 'FAIL'}"
        )
    print(f"RESULT: {checked} secrets checked, {bad} failed -> exit {1 if bad else 0}")
    return 1 if bad or not checked else 0


if __name__ == "__main__":
    sys.exit(main())
