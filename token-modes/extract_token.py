#!/usr/bin/env python3
"""Extract the fenced bash blocks of sections 5-7 (keys, domain + token, token injection) of a validator guide copy.

Usage: extract_token.py OUTDIR GUIDE [GUIDE ...]
The first GUIDE is extracted; every further GUIDE must carry byte-identical sections 5-7 (the guide ships three copies).
Writes into OUTDIR:
  section.txt      the guide text from "## 5. Generate Fresh Validator Keys" up to "## 8. "
  05-keys.sh       create_keys + copy of validator-keys.json to the host
  06a-domain.sh    export VALIDATOR_DOMAIN
  06b-setdomain.sh set_domain -> set-domain-output.txt, validator-keys.domain.json
  06c-proof.sh     PUBLIC_KEY / ATTESTATION from set-domain-output.txt
  06d-token.sh     validator-token.block
  07a-inject.sh    postfiatd.cfg -> postfiatd.cfg.new with the token, copied in, docker compose restart
  07b-cleanup.sh   rm -rf /root/.ripple in the container
  07c-verify.sh    mode/owner verifier (only in guide copies that have it)
  07d-remove.sh    removal of the two config copies (only in guide copies that have it)
  blocks.txt       the block files in guide order
Prints one line per file (name, lines, sha256) and exits 1 if a section is missing or appears twice, the copies
differ, a non-bash block appears, a bash block matches no role or two roles, or a required role is missing.
"""

import hashlib
import pathlib
import re
import sys

START = "## 5. Generate Fresh Validator Keys\n"
END = "\n## 8. "
FENCE = re.compile(r"^```(\w*)\n(.*?)^```\n", re.DOTALL | re.MULTILINE)
# (file name, a line the block must contain, required)
ROLES = [
    ("05-keys.sh", "docker exec postfiatd validator-keys create_keys", True),
    ("06a-domain.sh", 'export VALIDATOR_DOMAIN="', True),
    (
        "06b-setdomain.sh",
        'validator-keys set_domain "$VALIDATOR_DOMAIN" | tee ./set-domain-output.txt',
        True,
    ),
    ("06c-proof.sh", 'PUBLIC_KEY="$(sed -n', True),
    ("06d-token.sh", "> ./validator-token.block", True),
    ("07a-inject.sh", "docker compose restart", True),
    ("07b-cleanup.sh", "docker exec postfiatd rm -rf /root/.ripple", True),
    ("07c-verify.sh", 'echo "token file modes OK"', False),
    ("07d-remove.sh", "rm -f ./postfiatd.cfg ./postfiatd.cfg.new", False),
]


def die(msg):
    print(f"extract: {msg}", file=sys.stderr)
    sys.exit(1)


def sections(path):
    text = pathlib.Path(path).read_text()
    if text.count(START) != 1:
        die(f"{path}: section 5 start must appear exactly once")
    a = text.index(START)
    b = text.find(END, a)
    if b < 0 or text.count(END) != 1:
        die(f"{path}: section 8 heading must appear exactly once after section 5")
    return text[a : b + 1]


def main(argv):
    if len(argv) < 3:
        die("usage: extract_token.py OUTDIR GUIDE [GUIDE ...]")
    out = pathlib.Path(argv[1])
    sec = sections(argv[2])
    for other in argv[3:]:
        if sections(other) != sec:
            die(f"{other}: sections 5-7 differ from {argv[2]}")
    found = {}
    order = []
    for kind, body in FENCE.findall(sec):
        if kind != "bash":
            die(f"{argv[2]}: unexpected {kind or 'plain'} block in sections 5-7")
        names = [n for n, marker, _ in ROLES if marker in body]
        if len(names) != 1:
            die(
                f"{argv[2]}: a bash block matches roles {names}: {body.splitlines()[0]!r}"
            )
        if names[0] in found:
            die(f"{argv[2]}: two blocks for {names[0]}")
        found[names[0]] = body
        order.append(names[0])
    for name, _, required in ROLES:
        if required and name not in found:
            die(f"{argv[2]}: no block for {name}")
    if order != [n for n, _, _ in ROLES if n in found]:
        die(f"{argv[2]}: blocks out of order: {order}")
    out.mkdir(parents=True, exist_ok=True)
    parts = (
        [("section.txt", sec)]
        + [(n, found[n]) for n in order]
        + [("blocks.txt", "\n".join(order) + "\n")]
    )
    for name, body in parts:
        (out / name).write_text(body)
        print(
            f"{name} {len(body.splitlines())} lines sha256 {hashlib.sha256(body.encode()).hexdigest()}"
        )
    print(f"copies with identical sections 5-7: {len(argv) - 2}")


if __name__ == "__main__":
    main(sys.argv)
