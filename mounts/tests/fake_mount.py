#!/usr/bin/env python3
"""Fake mount/umount for the pft-mounts offline tests: edits a mountinfo FILE the way the kernel would.

  fake_mount.py MOUNTINFO mount [--options-mode ignore] --bind SRC DST
  fake_mount.py MOUNTINFO mount [--options-mode ignore] -o remount[,bind],OPTS TARGET
  fake_mount.py MOUNTINFO umount TARGET

Per-mount flags (field 6) are replaced by the flags given on a remount, as MS_REMOUNT does; a remount of a
target that is not a mount fails with exit 32 like mount(8). hidepid=/gid= go to the super options (proc).
Every call is appended to $FAKE_CALLS. FAKE_FAIL=<substring> makes a matching call fail (exit 32).
"""

import os
import sys

PER_MOUNT = {
    "rw",
    "ro",
    "nodev",
    "dev",
    "nosuid",
    "suid",
    "noexec",
    "exec",
    "relatime",
    "noatime",
    "strictatime",
    "nodiratime",
}


def log(args):
    calls = os.environ.get("FAKE_CALLS")
    if calls:
        with open(calls, "a") as f:
            f.write(" ".join(args) + "\n")


def read(path):
    with open(path) as f:
        return [line.rstrip("\n").split(" ") for line in f if line.strip()]


def write(path, rows):
    with open(path, "w") as f:
        f.writelines(" ".join(r) + "\n" for r in rows)


def top(rows, target):
    idx = [i for i, r in enumerate(rows) if r[4] == target]
    return idx[-1] if idx else None


def sep(r):
    return r.index("-", 6)


def main():
    path, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    log([cmd] + args)
    fail = os.environ.get("FAKE_FAIL")
    if fail and fail in " ".join([cmd] + args):
        print(f"{cmd}: injected failure", file=sys.stderr)
        return 32
    rows = read(path)
    if args[:2] == ["--options-mode", "ignore"]:
        args = args[2:]
    if cmd == "umount":
        i = top(rows, args[0])
        if i is None:
            print(f"umount: {args[0]}: not mounted.", file=sys.stderr)
            return 32
        del rows[i]
    elif args[0] == "--bind":
        src, dst = args[1], args[2]
        # source mount = deepest mount containing src
        best = max(
            (
                r
                for r in rows
                if r[4] == "/" or src == r[4] or src.startswith(r[4] + "/")
            ),
            key=lambda r: len(r[4]),
        )
        new = list(best)
        new[0] = str(max(int(r[0]) for r in rows) + 1)
        new[4] = dst
        rows.append(new)
    elif args[0] == "-o":
        opts, target = args[1].split(","), args[2]
        if opts[0] != "remount":
            return 2
        i = top(rows, target)
        if i is None:
            print(
                f"mount: {target}: mount point not mounted or bad option.",
                file=sys.stderr,
            )
            return 32
        r = rows[i]
        flags = [
            o for o in opts[1:] if o in PER_MOUNT and o not in ("dev", "suid", "exec")
        ]
        if "ro" not in flags and "rw" not in flags:
            flags.insert(0, "rw")
        atime = ("relatime", "noatime", "strictatime")
        if not any(
            o in atime for o in flags
        ):  # the kernel keeps the atime mode when none is given
            flags += [o for o in r[5].split(",") if o in atime]
        r[5] = ",".join(dict.fromkeys(flags))
        s = sep(r)
        # proc super options: given values replace old ones; hidepid=off and gid=0 are not shown (like the kernel)
        given = {
            o.split("=")[0]: o for o in opts[1:] if o.startswith(("hidepid=", "gid="))
        }
        sup = [o for o in r[s + 3].split(",") if o.split("=")[0] not in given]
        sup += [o for o in given.values() if o not in ("hidepid=off", "gid=0")]
        r[s + 3] = ",".join(sup)
    else:
        return 2
    write(path, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
