#!/usr/bin/env python3
"""Tamper fixture for drill/tamper-run.sh: flip ONE byte (XOR 0x01) in the middle of an encrypted generation file.

    python3 -I - AGE_FILE [META_FILE] < flipbyte.py     (run as root on the holder; tamper-run.sh pipes it over ssh)

With META_FILE, the meta's cipher_sha256= line is rewritten to the tampered file's sha256 (atomic replace, mode and
owner kept), so the holder's sha256 check passes and only the in-memory age decrypt can catch the change.
Prints the offset, the file size and, with META_FILE, how many cipher_sha256 lines now carry the new hash. It never
prints byte values (the file is ciphertext, but nothing of it is needed in a log).
"""

import hashlib
import os
import sys


def main(argv):
    if len(argv) not in (2, 3):
        print("usage: flipbyte.py AGE_FILE [META_FILE]", file=sys.stderr)
        return 3
    path = argv[1]
    size = os.path.getsize(path)
    if size < 2:
        print("file too small", file=sys.stderr)
        return 2
    off = size // 2
    with open(path, "r+b") as f:
        f.seek(off)
        b = f.read(1)[0]
        f.seek(off)
        f.write(bytes([b ^ 1]))
        f.flush()
        os.fsync(f.fileno())
    print(f"flipped 1 byte at offset {off} of {size}")
    if len(argv) == 3:
        meta = argv[2]
        with open(path, "rb") as f:
            new = hashlib.sha256(f.read()).hexdigest()
        st = os.stat(meta)
        with open(meta) as f:
            lines = f.read().splitlines(keepends=True)
        line = f"cipher_sha256={new}\n"
        out = [line if ln.startswith("cipher_sha256=") else ln for ln in lines]
        tmp = meta + ".flip.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, st.st_mode & 0o7777)
        with os.fdopen(fd, "w") as f:
            f.writelines(out)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, meta)
        n = sum(1 for ln in out if ln == line)
        print(f"meta cipher_sha256 lines with the tampered file's sha256: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
