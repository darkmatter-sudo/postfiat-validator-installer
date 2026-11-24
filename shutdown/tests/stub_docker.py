#!/usr/bin/env python3
"""Stateful `docker` stub for the pft-shutdown apply/rollback tests (no root, no Docker).

State in $STUB_D: containers/NAME.json (inspect .[0]), images.json {tag: {Id, Env}}, calls (log), seq (StartedAt
counter), knobs: fail_run / fail_compose_up (one-shot), run_drop_tmpfs / run_drop_stop_timeout (docker run loses
that flag: a lost setting), config_grace (the value `compose config` reports instead of the overlay's).
`compose` runs in the project dir: COMPOSE_FILE from .env; docker-compose.shutdown.yml's stop_grace_period is the
only overlay value it reads. `compose up` re-creates container postfiatd (live CpuShares dropped, as Docker does).
"""

import json
import os
import re
import sys

D = os.environ["STUB_D"]
C = os.path.join(D, "containers")


def path(n):
    return os.path.join(C, n + ".json")


def load(n):
    try:
        with open(path(n)) as f:
            return json.load(f)
    except OSError:
        return None


def save(n, c):
    with open(path(n), "w") as f:
        json.dump(c, f)


def read(p):
    with open(p) as f:
        return f.read()


def write(p, t):
    with open(p, "w") as f:
        f.write(t)


def knob(k):
    return os.path.exists(os.path.join(D, k))


def once(k):  # a one-shot failure knob: consumed when it fires
    if knob(k):
        os.remove(os.path.join(D, k))
        return True
    return False


def started():
    p = os.path.join(D, "seq")
    n = int(read(p)) + 1 if os.path.exists(p) else 1
    write(p, str(n))
    return f"2026-11-24T02:{n // 60:02d}:{n % 60:02d}Z"


def images():
    with open(os.path.join(D, "images.json")) as f:
        return json.load(f)


def compose_grace(wd):
    env = (
        read(os.path.join(wd, ".env"))
        if os.path.exists(os.path.join(wd, ".env"))
        else ""
    )
    m = re.search(r"^COMPOSE_FILE=(.*)$", env, re.MULTILINE)
    files = m.group(1).split(":") if m else ["docker-compose.yml"]
    g = None
    for fn in files:
        p = os.path.join(wd, fn)
        if not os.path.exists(p):
            return "missing", fn
        mm = re.search(r"stop_grace_period:\s*(\S+)", read(p))
        if mm:
            g = mm.group(1)
    return g, None


def do_run(args):
    hc = {
        "CapAdd": [],
        "CapDrop": [],
        "SecurityOpt": [],
        "Tmpfs": {},
        "PortBindings": {},
        "LogConfig": {"Config": {}},
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "NetworkMode": "default",
    }
    rest, name, mounts = [], None, []
    cfg = {"User": "", "Labels": {}, "Env": []}
    for a in args:
        if a == "-d" and not rest:
            continue
        if rest or not a.startswith("--"):
            rest.append(a)
            continue
        k, _, v = a[2:].partition("=")
        if k == "name":
            name = v
        elif k == "restart":
            hc["RestartPolicy"]["Name"] = v.split(":")[0]
        elif k == "stop-timeout":
            if not knob("run_drop_stop_timeout"):
                cfg["StopTimeout"] = int(v)
        elif k == "stop-signal":
            cfg["StopSignal"] = v
        elif k == "user":
            cfg["User"] = v
        elif k == "log-driver":
            hc["LogConfig"]["Type"] = v
        elif k == "log-opt":
            ok, _, ov = v.partition("=")
            hc["LogConfig"]["Config"][ok] = ov
        elif k == "network":
            hc["NetworkMode"] = v
        elif k == "publish":
            parts = v.split(":")
            ip, hp, cp = parts if len(parts) == 3 else [""] + parts
            hc["PortBindings"].setdefault(cp + "/tcp", []).append(
                {"HostIp": ip, "HostPort": hp}
            )
        elif k == "volume":
            parts = v.split(":")
            rw = not (len(parts) > 2 and parts[2] == "ro")
            if parts[0].startswith("/"):
                mounts.append(
                    {
                        "Type": "bind",
                        "Source": parts[0],
                        "Destination": parts[1],
                        "RW": rw,
                    }
                )
            else:
                mounts.append(
                    {
                        "Type": "volume",
                        "Name": parts[0],
                        "Destination": parts[1],
                        "RW": rw,
                    }
                )
        elif k == "env":
            cfg["Env"].append(v)
        elif k == "cap-drop":
            hc["CapDrop"].append(v)
        elif k == "cap-add":
            hc["CapAdd"].append(v)
        elif k == "read-only":
            hc["ReadonlyRootfs"] = True
        elif k == "tmpfs":
            tp, _, to = v.partition(":")
            if not knob("run_drop_tmpfs"):
                hc["Tmpfs"][tp] = to
        elif k in (
            "pids-limit",
            "memory",
            "memory-swap",
            "cpu-shares",
            "memory-reservation",
        ):
            hc[
                {
                    "pids-limit": "PidsLimit",
                    "memory": "Memory",
                    "memory-swap": "MemorySwap",
                    "cpu-shares": "CpuShares",
                    "memory-reservation": "MemoryReservation",
                }[k]
            ] = int(v)
        elif k == "security-opt":
            if v.startswith("seccomp="):  # Docker stores the profile inline
                v = "seccomp=" + json.dumps(
                    json.loads(read(os.environ["STUB_ROOT"] + v[8:])),
                    separators=(",", ":"),
                )
            hc["SecurityOpt"].append(v)
        else:
            sys.stderr.write(f"stub docker run: unknown flag {a}\n")
            return 125
    if name is None or load(name) is not None or once("fail_run"):
        return 125
    img = images()[rest[0]]
    cfg["Env"] = img.get("Env", []) + cfg["Env"]
    cfg["Image"], cfg["Cmd"] = rest[0], rest[1:]
    prof = "docker-default"
    for o in hc["SecurityOpt"]:
        if o.startswith("apparmor="):
            prof = o.split("=", 1)[1]
    save(
        name,
        {
            "Id": "id" + started(),
            "Name": "/" + name,
            "Image": img["Id"],
            "AppArmorProfile": prof,
            "Config": cfg,
            "HostConfig": hc,
            "Mounts": mounts,
            "State": {"Running": True, "StartedAt": started()},
        },
    )
    return 0


def main(a):
    with open(os.path.join(D, "calls"), "a") as f:
        f.write(" ".join(a) + "\n")
    if a[:1] == ["inspect"]:
        if a[1] == "-f":
            c = load(a[3])
            return (print(str(c["State"]["Running"]).lower()) or 0) if c else 1
        c = load(a[1])
        return (print(json.dumps([c])) or 0) if c else 1
    if a[:2] == ["image", "inspect"]:
        if a[2] == "-f":
            im = images().get(a[4])
            if not im:
                return 1
            print(im["Id"] if "Id" in a[3] else "<no value>")
            return 0
        im = images().get(a[2])
        return (
            (
                print(
                    json.dumps([{"Id": im["Id"], "Config": {"Env": im.get("Env", [])}}])
                )
                or 0
            )
            if im
            else 1
        )
    if a[0] == "stop":
        c = load(a[-1])
        if not c:
            return 1
        c["State"]["Running"] = False
        save(a[-1], c)
        return 0
    if a[0] == "start":
        c = load(a[1])
        if not c:
            return 1
        c["State"].update(Running=True, StartedAt=started())
        save(a[1], c)
        return 0
    if a[0] == "rename":
        c = load(a[1])
        if not c or load(a[2]):
            return 1
        c["Name"] = "/" + a[2]
        os.remove(path(a[1]))
        save(a[2], c)
        return 0
    if a[0] == "update":
        c = load(a[-1])
        if not c:
            return 1
        for o in a[1:-1]:
            k, _, v = o[2:].partition("=")
            if k == "restart":
                c["HostConfig"]["RestartPolicy"]["Name"] = v
            elif k == "cpu-shares":
                c["HostConfig"]["CpuShares"] = int(v)
            elif k == "memory-reservation":
                c["HostConfig"]["MemoryReservation"] = int(v)
        save(a[-1], c)
        return 0
    if a[0] == "rm":
        n = a[-1]
        c = load(n)
        if not c or (c["State"]["Running"] and "-f" not in a):
            return 1
        os.remove(path(n))
        return 0
    if a[0] == "run":
        return do_run(a[1:])
    if a[0] == "compose":
        wd = os.getcwd()
        g, miss = compose_grace(wd)
        if g == "missing":
            sys.stderr.write(f"stub compose: {miss} missing\n")
            return 1
        if a[1] == "config":
            if "-q" in a:
                return 0
            svc = {"image": "x"}
            if g:
                m = re.fullmatch(r"(\d+)s", g)
                svc["stop_grace_period"] = (
                    f"{int(m.group(1)) // 60}m{int(m.group(1)) % 60}s"
                    if m and int(m.group(1)) >= 60
                    else g
                )
            if knob(
                "config_grace"
            ):  # compose resolves another value than the overlay's (e.g. a later file)
                svc["stop_grace_period"] = read(os.path.join(D, "config_grace")).strip()
            print(json.dumps({"services": {"postfiatd": svc}}))
            return 0
        if a[1] == "up":
            if once("fail_compose_up"):
                return 1
            c = load("postfiatd")
            if g:
                c["Config"]["StopTimeout"] = int(re.fullmatch(r"(\d+)s", g).group(1))
            else:
                c["Config"].pop("StopTimeout", None)
            c["HostConfig"].pop("CpuShares", None)
            c["Id"] = "id" + started()
            c["State"].update(Running=True, StartedAt=started())
            labels = c["Config"]["Labels"]
            env = read(os.path.join(wd, ".env"))
            m = re.search(r"^COMPOSE_FILE=(.*)$", env, re.MULTILINE)
            labels["com.docker.compose.project.config_files"] = ",".join(
                os.path.join(labels["com.docker.compose.project.working_dir"], x)
                for x in m.group(1).split(":")
            )
            save("postfiatd", c)
            print(" Container postfiatd  Recreated")
            return 0
    sys.stderr.write(f"stub docker: unsupported {a}\n")
    return 1


sys.exit(main(sys.argv[1:]))
