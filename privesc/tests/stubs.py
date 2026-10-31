#!/usr/bin/env python3
"""Stand-ins for the commands pft-privesc.sh runs, driven by files in $STUB (one dir per test case).

  dpkg -S PATH            $STUB/dpkg-owners.tsv  "PATH<TAB>PKG" (dpkg's own path, e.g. /bin/fusermount3)
  dpkg --verify PKG       $STUB/md5-changed.tsv  "PKG<TAB>PATH" -> "??5?????? PATH"
  dpkg-statoverride       $STUB/statoverride     "USER GROUP MODE PATH" lines; --list [PATH], --remove PATH,
                          [--update] --add U G MODE PATH (--update chmods $PFT_PE_ROOT/PATH like dpkg does)
  getcap FILE...          $STUB/caps.tsv         "FULLPATH<TAB>CAPS" ; setcap -r FILE / setcap CAPS FILE edit it
  systemctl show ...      $STUB/units.show       (printed as is)
  getent passwd|group     $STUB/passwd, $STUB/group
  docker ps -q / inspect  $STUB/docker-ps, $STUB/docker-inspect-<ID>
  visudo -c               exit $(cat $STUB/visudo.rc), default 0
  runuser -u U -- ...     exit $(cat $STUB/agent.rc), default 0; after $STUB/agent.flip-after calls: $STUB/agent.rc2
  chown U:G FILE          recorded only (tests run unprivileged); a real chown needs root
Every call is appended to $STUB/calls.log.
"""

import os
import sys

STUB = os.environ["STUB"]
ROOT = os.environ.get("PFT_PE_ROOT", "")


def f(name):
    return os.path.join(STUB, name)


def read(name, default=""):
    try:
        with open(f(name)) as fh:
            return fh.read()
    except OSError:
        return default


def write(name, text):
    with open(f(name), "w") as fh:
        fh.write(text)


def rows(name):
    return [ln.split("\t") for ln in read(name).splitlines() if ln.strip()]


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    with open(f("calls.log"), "a") as log:
        log.write(" ".join([cmd] + args) + "\n")
    if cmd == "dpkg":
        if args[0] == "-S":
            for p, pkg in rows("dpkg-owners.tsv"):
                if p == args[1]:
                    print(f"{pkg}: {p}")
                    return 0
            print(
                f"dpkg-query: no path found matching pattern {args[1]}", file=sys.stderr
            )
            return 1
        if args[0] == "--verify":
            for pkg, p in rows("md5-changed.tsv"):
                if pkg == args[1]:
                    print(f"??5??????   {p}")
            return 0
    if cmd == "dpkg-statoverride":
        lines = [ln for ln in read("statoverride").splitlines() if ln.strip()]
        if args[0] == "--list":
            for ln in lines:
                if len(args) == 1 or ln.split()[3] == args[1]:
                    print(ln)
            return (
                0
                if len(args) == 1 or any(ln.split()[3] == args[1] for ln in lines)
                else 1
            )
        if args[0] == "--remove":
            keep = [ln for ln in lines if ln.split()[3] != args[1]]
            if len(keep) == len(lines):
                print(
                    "dpkg-statoverride: warning: no override present", file=sys.stderr
                )
            write("statoverride", "".join(x + "\n" for x in keep))
            return 0
        update = args[0] == "--update"
        a = args[1:] if update else args
        if a[0] != "--add":
            return 2
        u, g, mode, p = a[1:5]
        if any(ln.split()[3] == p for ln in lines):
            print(
                f"dpkg-statoverride: error: an override for '{p}' already exists",
                file=sys.stderr,
            )
            return 2
        lines.append(f"{u} {g} {mode} {p}")
        write("statoverride", "".join(x + "\n" for x in lines))
        if update:
            os.chmod(ROOT + p, int(mode, 8))
        return 0
    if cmd == "getcap":
        caps = dict(rows("caps.tsv"))
        for p in args:
            if p in caps:
                print(f"{p} {caps[p]}")
        return 0
    if cmd == "setcap":
        caps = dict(rows("caps.tsv"))
        if args[0] == "-r":
            caps.pop(args[1], None)
        else:
            caps[args[1]] = args[0]
        write("caps.tsv", "".join(f"{k}\t{v}\n" for k, v in caps.items()))
        return 0
    if cmd == "systemctl":
        sys.stdout.write(read("units.show"))
        return 0
    if cmd == "getent":
        if not os.path.exists(f(args[0])):
            return 2
        sys.stdout.write(read(args[0]))
        return 0
    if cmd == "docker":
        if args[0] == "ps":
            sys.stdout.write(read("docker-ps"))
            return 0
        if args[0] == "inspect":
            sys.stdout.write(read("docker-inspect-" + args[-1]))
            return 0
    if cmd == "visudo":
        print("/etc/sudoers: parsed OK")
        return int(read("visudo.rc", "0").strip() or 0)
    if cmd == "runuser":
        n = int(read("agent.calls", "0") or 0) + 1
        write("agent.calls", str(n))
        flip = read("agent.flip-after").strip()
        if flip and n > int(flip):
            return int(read("agent.rc2", "1").strip())
        return int(read("agent.rc", "0").strip() or 0)
    if cmd == "chown":
        return 0
    print(f"stub: unknown call {cmd} {args}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
