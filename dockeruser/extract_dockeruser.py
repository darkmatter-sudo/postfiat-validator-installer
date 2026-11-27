#!/usr/bin/env python3
"""Extract the DOCKER-USER persistence section of a Post Fiat validator guide copy.

Usage: extract_dockeruser.py GUIDE OUTDIR
Writes into OUTDIR:
  section.txt                    the guide text from "Add Docker `DOCKER-USER`" up to "Expected security posture:"
  install.sh                     the first bash block of the section (what the operator runs)
  postfiat-docker-user.sh        the script that install.sh writes with tee
  postfiat-docker-user.service   the unit that install.sh writes with tee
  check.sh                       the second bash block (the read-only check)
Exit 1 if the section or any block is missing or appears more than once.
"""

import pathlib
import re
import sys

START = "Add Docker `DOCKER-USER` rate limits for peer traffic"
END = "Expected security posture:"
FENCE = re.compile(r"^```bash\n(.*?)^```\n", re.S | re.M)
TEE = re.compile(r"^sudo tee (\S+) >/dev/null <<'EOF'\n(.*?)^EOF\n", re.S | re.M)


def die(msg):
    print(f"extract: {msg}", file=sys.stderr)
    sys.exit(1)


def main(argv):
    if len(argv) != 3:
        die("usage: extract_dockeruser.py GUIDE OUTDIR")
    text = pathlib.Path(argv[1]).read_text()
    if text.count(START) != 1 or text.count(END) != 1:
        die(f"{argv[1]}: section start/end markers must appear exactly once")
    a = text.index(START)
    b = text.index(END, a)
    section = text[a:b]
    blocks = FENCE.findall(section)
    if len(blocks) != 2:
        die(f"{argv[1]}: expected 2 bash blocks in the section, found {len(blocks)}")
    files = dict(TEE.findall(blocks[0]))
    want = ["/usr/local/sbin/postfiat-docker-user.sh", "/etc/systemd/system/postfiat-docker-user.service"]
    if sorted(files) != sorted(want):
        die(f"{argv[1]}: install block must tee exactly {want}, found {sorted(files)}")
    out = pathlib.Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    (out / "section.txt").write_text(section)
    (out / "install.sh").write_text(blocks[0])
    (out / "postfiat-docker-user.sh").write_text(files[want[0]])
    (out / "postfiat-docker-user.service").write_text(files[want[1]])
    (out / "check.sh").write_text(blocks[1])
    for name in ("section.txt", "install.sh", "postfiat-docker-user.sh", "postfiat-docker-user.service", "check.sh"):
        print(f"{name} {len((out / name).read_text().splitlines())} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
