#!/usr/bin/env python3
"""Extract the fenced bash blocks of section 10 (upgrade, rollback, return to the rolling tag) of a validator guide copy.

Usage: extract_rollback.py OUTDIR GUIDE [GUIDE ...]
The first GUIDE is extracted; every further GUIDE must carry a byte-identical section 10 (the guide ships three copies).
Writes into OUTDIR:
  section.txt      the guide text from "## 10. Upgrade Procedure After Fresh Install" up to the next "## " heading
  01-dircheck.sh   cd to the node directory, show the image: line
  02-record.sh     record image ID + first RepoDigest to pre-upgrade-<UTC>.txt
  03-upgrade.sh    docker compose pull + up -d
  04-workdir.sh    find the node directory from the container label
  05-verify.sh     server_info check
  06-rollback.sh   digest pin in docker-compose.override.yml (REC placeholder line as published)
  07-return.sh     remove the override, back to the rolling tag
Prints one line per file (name, lines, sha256) and exits 1 if the section is missing, appears more than once, differs
between copies, or does not hold exactly these seven bash blocks (checked by a marker line in each).
"""

import hashlib
import pathlib
import re
import sys

START = "## 10. Upgrade Procedure After Fresh Install\n"
FENCE = re.compile(r"^```(\w*)\n(.*?)^```\n", re.DOTALL | re.MULTILINE)
# (file name, a line the block must contain): fixes the block order, so a reordered or edited guide fails loudly
BLOCKS = [
    ("01-dircheck.sh", "grep 'image:' docker-compose.yml"),
    (
        "02-record.sh",
        'printf \'image_id=%s\\nrepo_digest=%s\\n\' "$IMAGE_ID" "$REPO_DIGEST" > "$REC"',
    ),
    ("03-upgrade.sh", "docker compose pull"),
    ("04-workdir.sh", "com.docker.compose.project.working_dir"),
    ("05-verify.sh", '"server_info"'),
    ("06-rollback.sh", "REC=pre-upgrade-YYYYMMDDTHHMMSSZ.txt"),
    ("07-return.sh", "rm docker-compose.override.yml"),
]


def die(msg):
    print(f"extract: {msg}", file=sys.stderr)
    sys.exit(1)


def section(path):
    text = pathlib.Path(path).read_text()
    if text.count(START) != 1:
        die(f"{path}: section start must appear exactly once")
    a = text.index(START)
    b = text.find("\n## ", a + len(START))
    if b < 0:
        die(f"{path}: no heading after section 10")
    return text[a : b + 1]


def main(argv):
    if len(argv) < 3:
        die("usage: extract_rollback.py OUTDIR GUIDE [GUIDE ...]")
    out = pathlib.Path(argv[1])
    sec = section(argv[2])
    for other in argv[3:]:
        if section(other) != sec:
            die(f"{other}: section 10 differs from {argv[2]}")
    blocks = FENCE.findall(sec)
    kinds = [k for k, _ in blocks]
    if kinds != ["bash"] * len(BLOCKS):
        die(f"{argv[2]}: expected {len(BLOCKS)} bash blocks, found {kinds}")
    out.mkdir(parents=True, exist_ok=True)
    parts = [("section.txt", sec)]
    for (name, marker), (_, body) in zip(BLOCKS, blocks):
        if marker not in body:
            die(f"{argv[2]}: block for {name} lacks {marker!r}")
        parts.append((name, body))
    for name, body in parts:
        (out / name).write_text(body)
        print(
            f"{name} {len(body.splitlines())} lines sha256 {hashlib.sha256(body.encode()).hexdigest()}"
        )
    print(f"copies with identical section 10: {len(argv) - 2}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
