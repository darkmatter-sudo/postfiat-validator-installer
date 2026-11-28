#!/usr/bin/env python3
"""Extract the bash blocks a validator-domain re-run needs from a validator guide copy.

Usage: extract_domain.py OUTDIR GUIDE [GUIDE ...]
The first GUIDE is extracted; every further GUIDE must carry byte-identical sections 5-7 AND a byte-identical
Troubleshooting section (the guide ships three copies).
Writes into OUTDIR:
  section.txt          the guide text from "## 5. Generate Fresh Validator Keys" up to "## 8. "
  troubleshooting.txt  the guide text from "## Troubleshooting" up to "## Agent Safety Checklist"
  05-keys.sh           create_keys + copy of validator-keys.json to the host
  06a-domain.sh        export VALIDATOR_DOMAIN
  06b-setdomain.sh     set_domain from ./validator-keys.json -> set-domain-output.txt, validator-keys.domain.json
  06c-proof.sh         PUBLIC_KEY / ATTESTATION from set-domain-output.txt
  06d-token.sh         validator-token.block
  07a-inject.sh        postfiatd.cfg -> postfiatd.cfg.new with the token, copied in, docker compose restart
  07b-cleanup.sh       rm -rf /root/.ripple in the container
  T1-rerun.sh          (optional) re-run block of the "`domain` is empty" entry: set_domain from the newest key file
  T2-seqcheck.sh       (optional) read-only sequence-increase check of that entry
  blocks.txt           the section 5-7 block files in guide order
  rerun.txt            the re-run blocks of the entry in guide order (empty if the entry has none)
Prints one line per file (name, lines, sha256) and exits 1 if a section is missing or appears twice, the copies
differ, a non-bash block appears, a bash block matches no role or two roles, a required role is missing, or the
entry has exactly one of T1/T2.
"""

import hashlib
import pathlib
import re
import sys

START = "## 5. Generate Fresh Validator Keys\n"
END = "\n## 8. "
TS_START = "## Troubleshooting\n"
TS_END = "\n## Agent Safety Checklist\n"
ENTRY = "### `domain` is empty in `validator_info`\n"
FENCE = re.compile(r"^```(\w*)\n(.*?)^```\n", re.DOTALL | re.MULTILINE)
# (file name, a line the block must contain, required); 07c/07d are the token-modes blocks of another PR
ROLES = [
    ("05-keys.sh", "docker exec postfiatd validator-keys create_keys", True),
    ("06a-domain.sh", 'export VALIDATOR_DOMAIN="', True),
    (
        "06b-setdomain.sh",
        "docker cp ./validator-keys.json postfiatd:/root/.ripple/validator-keys.json",
        True,
    ),
    ("06c-proof.sh", 'PUBLIC_KEY="$(sed -n', True),
    ("06d-token.sh", "> ./validator-token.block", True),
    ("07a-inject.sh", "docker compose restart", True),
    ("07b-cleanup.sh", "docker exec postfiatd rm -rf /root/.ripple", True),
    ("07c-verify.sh", 'echo "token file modes OK"', False),
    ("07d-remove.sh", "rm -f ./postfiatd.cfg ./postfiatd.cfg.new", False),
]
TROLES = [
    ("T1-rerun.sh", 'docker cp "$KEYS" postfiatd:/root/.ripple/validator-keys.json'),
    ("T2-seqcheck.sh", 'echo "sequence increase OK"'),
]


def die(msg):
    print(f"extract: {msg}", file=sys.stderr)
    sys.exit(1)


def cut(text, path, start, end, what):
    if text.count(start) != 1:
        die(f"{path}: {what} start must appear exactly once")
    a = text.index(start)
    b = text.find(end, a)
    if b < 0 or text.count(end) != 1:
        die(f"{path}: {what} end must appear exactly once after its start")
    return text[a : b + 1]


def parts(path):
    text = pathlib.Path(path).read_text()
    sec = cut(text, path, START, END, "section 5")
    ts = cut(text, path, TS_START, TS_END, "Troubleshooting")
    return sec, ts


def blocks(body, roles, path, where):
    found, order = {}, []
    for kind, code in FENCE.findall(body):
        if kind != "bash":
            die(f"{path}: unexpected {kind or 'plain'} block in {where}")
        names = [r[0] for r in roles if r[1] in code]
        if len(names) != 1:
            die(
                f"{path}: a bash block in {where} matches roles {names}: {code.splitlines()[0]!r}"
            )
        if names[0] in found:
            die(f"{path}: two blocks for {names[0]}")
        found[names[0]] = code
        order.append(names[0])
    if order != [r[0] for r in roles if r[0] in found]:
        die(f"{path}: blocks out of order in {where}: {order}")
    return found, order


def main(argv):
    if len(argv) < 3:
        die("usage: extract_domain.py OUTDIR GUIDE [GUIDE ...]")
    out = pathlib.Path(argv[1])
    sec, ts = parts(argv[2])
    for other in argv[3:]:
        osec, ots = parts(other)
        if osec != sec:
            die(f"{other}: sections 5-7 differ from {argv[2]}")
        if ots != ts:
            die(f"{other}: Troubleshooting differs from {argv[2]}")
    found, order = blocks(sec, ROLES, argv[2], "sections 5-7")
    for name, _, required in ROLES:
        if required and name not in found:
            die(f"{argv[2]}: no block for {name}")
    a = (
        ts.index(ENTRY)
        if ts.count(ENTRY) == 1
        else die(f"{argv[2]}: entry {ENTRY.strip()!r} missing")
    )
    b = ts.find("\n### ", a + len(ENTRY))
    entry = ts[a : b + 1 if b >= 0 else len(ts)]
    tfound, torder = blocks(entry, TROLES, argv[2], "the domain entry")
    if len(torder) not in (0, 2):
        die(
            f"{argv[2]}: the domain entry has {torder}, expected none or both re-run blocks"
        )
    out.mkdir(parents=True, exist_ok=True)
    files = (
        [("section.txt", sec), ("troubleshooting.txt", ts)]
        + [(n, found[n]) for n in order]
        + [(n, tfound[n]) for n in torder]
        + [
            ("blocks.txt", "\n".join(order) + "\n"),
            ("rerun.txt", "".join(n + "\n" for n in torder)),
        ]
    )
    for name, body in files:
        (out / name).write_text(body)
        print(
            f"{name} {len(body.splitlines())} lines sha256 {hashlib.sha256(body.encode()).hexdigest()}"
        )
    print(f"copies with identical sections 5-7 and Troubleshooting: {len(argv) - 2}")


if __name__ == "__main__":
    main(sys.argv)
