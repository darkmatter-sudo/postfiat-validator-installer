#!/usr/bin/env python3
"""Payload and envelope helper for pft-keyescrow (stdlib only). Never writes a secret to disk.

pack --host H --gen G      stdin: "id<TAB>path" lines. stdout: an uncompressed tar stream (meant to be piped
                           straight into `age -r PEER`): member MANIFEST (JSON: id, path, mode, uid, gid, size,
                           sha256 of every item) first, then items/0, items/1, ... with the file bytes.
check [--host H] [--gen G] stdin: a decrypted payload tar stream. Checks MANIFEST, then every item's size and
                           sha256, no missing/extra/duplicate members, no links or odd names. Prints one line per
                           item (no hashes) and a CHECK line. Nothing is written. Exit 0 all ok, 2 otherwise.
receive DEST               stdin: tar of exactly gen-G.meta + gen-G.age (one generation from the peer). Writes
                           both as 0600 temp files in DEST, checks the ciphertext sha256 and size against the
                           meta, then renames .age and finally .meta (the meta is the commit marker of a
                           generation). Prints RECEIVED gen=G. Exit 0 ok, 2 rejected (temp files removed).
"""

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import time

MAX_ITEM = 1 << 20  # a secret file larger than 1 MiB is not one of ours
MAX_CIPHER = 16 << 20
MAX_META = 64 << 10
GEN_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
HOST_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def die(msg, rc=2):
    print(f"keyescrow_tar: {msg}", file=sys.stderr)
    sys.exit(rc)


def read_items(stream):
    items = []
    for n, line in enumerate(stream.read().splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0] or not parts[1].startswith("/"):
            die(f"item list line {n}: want 'id<TAB>/abs/path'")
        items.append((parts[0], parts[1]))
    if not items:
        die("item list is empty")
    if len({i for i, _ in items}) != len(items):
        die("duplicate id in item list")
    return items


def cmd_pack(a):
    if not HOST_RE.match(a.host) or not GEN_RE.match(a.gen):
        die("bad --host or --gen", 3)
    items = read_items(sys.stdin)
    entries, blobs = [], []
    for ident, path in items:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                die(f"{ident}: not a regular file")
            if st.st_size > MAX_ITEM:
                die(f"{ident}: larger than {MAX_ITEM} bytes")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                data = fh.read(MAX_ITEM + 1)
        finally:
            os.close(fd)
        entries.append(
            {
                "id": ident,
                "path": path,
                "mode": f"{st.st_mode & 0o7777:o}",
                "uid": st.st_uid,
                "gid": st.st_gid,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        blobs.append(data)
    manifest = json.dumps(
        {"v": 1, "host": a.host, "gen": a.gen, "items": entries}, sort_keys=True
    ).encode()
    out = sys.stdout.buffer
    with tarfile.open(fileobj=out, mode="w|", format=tarfile.PAX_FORMAT) as tf:
        now = int(time.time())

        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime = len(data), 0o600, now
            tf.addfile(ti, io.BytesIO(data))

        add("MANIFEST", manifest)
        for i, data in enumerate(blobs):
            add(f"items/{i}", data)
    out.flush()
    print(f"PACKED host={a.host} gen={a.gen} items={len(entries)}", file=sys.stderr)


def cmd_check(a):
    bad, seen, results = [], set(), []
    try:
        tf = tarfile.open(fileobj=sys.stdin.buffer, mode="r|")  # noqa: SIM115 - closed below, die() exits
        first = tf.next()
        if first is None or first.name != "MANIFEST" or not first.isreg():
            die("payload does not start with MANIFEST")
        if first.size > MAX_META:
            die("MANIFEST too large")
        man = json.loads(tf.extractfile(first).read())
        if man.get("v") != 1 or not isinstance(man.get("items"), list):
            die("MANIFEST: unknown version or no items")
        if a.host and man.get("host") != a.host:
            bad.append(f"host is {man.get('host')!r}, want {a.host!r}")
        if a.gen and man.get("gen") != a.gen:
            bad.append(f"gen is {man.get('gen')!r}, want {a.gen!r}")
        items = man["items"]
        for m in tf:  # stream-mode iteration replays the members already read: skip MANIFEST itself
            if m is first:
                continue
            mm = re.fullmatch(r"items/([0-9]+)", m.name)
            if not mm or not m.isreg():
                bad.append(f"unexpected member {m.name!r}")
                continue
            i = int(mm.group(1))
            if i >= len(items) or i in seen:
                bad.append(f"member {m.name} not in MANIFEST or duplicated")
                continue
            seen.add(i)
            want = items[i]
            if m.size > MAX_ITEM:
                results.append((want["id"], "MISMATCH(size)"))
                continue
            data = tf.extractfile(m).read()
            if len(data) != want["size"]:
                results.append((want["id"], "MISMATCH(size)"))
            elif hashlib.sha256(data).hexdigest() != want["sha256"]:
                results.append((want["id"], "MISMATCH(sha256)"))
            else:
                results.append((want["id"], "ok"))
        tf.close()
    except (tarfile.TarError, OSError, ValueError, KeyError, EOFError) as e:
        die(f"payload unreadable: {type(e).__name__}: {e}")
    for i, want in enumerate(items):
        if i not in seen:
            results.append((want["id"], "MISSING"))
    for ident, res in results:
        print(f"  item {ident} {res}")
    for b in bad:
        print(f"  payload {b}")
    nok = sum(1 for _, r in results if r == "ok")
    nbad = len(results) - nok + len(bad)
    print(
        f"CHECK host={man.get('host')} gen={man.get('gen')} items={len(items)} ok={nok} bad={nbad}"
    )
    return 0 if nbad == 0 and nok == len(items) else 2


def parse_meta(data):
    meta = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if "=" in line and not line.startswith("fp\t"):
            k, v = line.split("=", 1)
            meta[k] = v
    return meta


def cmd_receive(a):
    dest = a.dest
    if not os.path.isdir(dest):
        die(f"no directory {dest}")
    got = {}
    tmps = []

    def cleanup():
        for p in tmps:
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    try:
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tf:
            for m in tf:
                mm = re.fullmatch(r"gen-([0-9]{8}T[0-9]{6}Z)\.(meta|age)", m.name)
                if not mm or not m.isreg() or mm.group(2) in got:
                    die(f"unexpected member {m.name!r}")
                kind = mm.group(2)
                limit = MAX_META if kind == "meta" else MAX_CIPHER
                if m.size > limit:
                    die(f"{m.name}: too large")
                tmp = os.path.join(dest, f".incoming-{m.name}.tmp")
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                tmps.append(tmp)
                h = hashlib.sha256()
                src = tf.extractfile(m)
                with os.fdopen(fd, "wb") as out:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
                        out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                got[kind] = (mm.group(1), tmp, h.hexdigest(), m.size)
        if set(got) != {"meta", "age"} or got["meta"][0] != got["age"][0]:
            die("want exactly gen-G.meta and gen-G.age of one generation")
        gen = got["age"][0]
        with open(got["meta"][1], "rb") as fh:
            meta = parse_meta(fh.read())
        if meta.get("gen") != gen:
            die(f"meta names gen {meta.get('gen')!r}, files are {gen}")
        if a.host and meta.get("host") != a.host:
            die(f"meta names host {meta.get('host')!r}, want {a.host!r}")
        if meta.get("cipher_sha256") != got["age"][2]:
            die("ciphertext sha256 differs from the meta")
        if meta.get("cipher_bytes") != str(got["age"][3]):
            die("ciphertext size differs from the meta")
        final_age = os.path.join(dest, f"gen-{gen}.age")
        final_meta = os.path.join(dest, f"gen-{gen}.meta")
        if os.path.exists(final_meta):
            die(f"generation {gen} already held")
        os.rename(got["age"][1], final_age)
        os.rename(got["meta"][1], final_meta)
        dfd = os.open(dest, os.O_RDONLY)
        os.fsync(dfd)
        os.close(dfd)
        tmps.clear()
        print(f"RECEIVED gen={gen} cipher_bytes={got['age'][3]} sha256 ok")
        return 0
    except SystemExit:
        cleanup()
        raise
    except (tarfile.TarError, OSError) as e:
        cleanup()
        die(f"receive failed: {type(e).__name__}: {e}")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    pk = sub.add_parser("pack")
    pk.add_argument("--host", required=True)
    pk.add_argument("--gen", required=True)
    ck = sub.add_parser("check")
    ck.add_argument("--host", default="")
    ck.add_argument("--gen", default="")
    rc = sub.add_parser("receive")
    rc.add_argument("dest")
    rc.add_argument("--host", default="")
    a = p.parse_args()
    if a.cmd == "pack":
        cmd_pack(a)
        return 0
    if a.cmd == "check":
        return cmd_check(a)
    return cmd_receive(a)


if __name__ == "__main__":
    sys.exit(main())
