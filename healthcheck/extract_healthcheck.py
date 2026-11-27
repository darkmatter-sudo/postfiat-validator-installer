#!/usr/bin/env python3
"""Extract the "Continuous health check" subsection of a Post Fiat validator guide copy.

Usage: extract_healthcheck.py GUIDE OUTDIR
Writes into OUTDIR:
  section.txt                      the guide text from "### Continuous health check" up to "## 10."
  install.sh                       the first bash block (what the operator runs)
  postfiat-healthcheck             the script that install.sh writes with tee
  postfiat-healthcheck.service     the unit that install.sh writes with tee
  postfiat-healthcheck.timer       the timer that install.sh writes with tee
  visibility.sh                    the second bash block (run once, list timer, status, journal, --failed)
  alert.conf                       the ini block (optional OnFailure= drop-in)
  uninstall.sh                     the third bash block
Exit 1 if the subsection or any block is missing or appears more than once.
"""

import pathlib
import re
import sys

START = "### Continuous health check\n"
END = "## 10. Upgrade Procedure After Fresh Install\n"
FENCE = re.compile(r"^```(bash|ini)\n(.*?)^```\n", re.DOTALL | re.MULTILINE)
TEE = re.compile(r"^sudo tee (\S+) >/dev/null <<'EOF'\n(.*?)^EOF\n", re.DOTALL | re.MULTILINE)
FILES = {
    "/usr/local/bin/postfiat-healthcheck": "postfiat-healthcheck",
    "/etc/systemd/system/postfiat-healthcheck.service": "postfiat-healthcheck.service",
    "/etc/systemd/system/postfiat-healthcheck.timer": "postfiat-healthcheck.timer",
}


def die(msg):
    print(f"extract: {msg}", file=sys.stderr)
    sys.exit(1)


def main(argv):
    if len(argv) != 3:
        die("usage: extract_healthcheck.py GUIDE OUTDIR")
    text = pathlib.Path(argv[1]).read_text()
    if text.count(START) != 1 or text.count(END) != 1:
        die(f"{argv[1]}: subsection start/end markers must appear exactly once")
    a = text.index(START)
    b = text.index(END, a)
    section = text[a:b]
    blocks = FENCE.findall(section)
    kinds = [k for k, _ in blocks]
    if kinds != ["bash", "bash", "ini", "bash"]:
        die(f"{argv[1]}: expected blocks bash, bash, ini, bash; found {kinds}")
    files = dict(TEE.findall(blocks[0][1]))
    if sorted(files) != sorted(FILES):
        die(f"{argv[1]}: install block must tee exactly {sorted(FILES)}, found {sorted(files)}")
    out = pathlib.Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    parts = {"section.txt": section, "install.sh": blocks[0][1], "visibility.sh": blocks[1][1],
             "alert.conf": blocks[2][1], "uninstall.sh": blocks[3][1]}
    for path, name in FILES.items():
        parts[name] = files[path]
    for name, body in parts.items():
        (out / name).write_text(body)
        print(f"{name} {len(body.splitlines())} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
