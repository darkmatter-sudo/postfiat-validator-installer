#!/usr/bin/env python3
"""Stateful docker stub for the apply/rollback tests of pft-apparmor.sh.

State lives in $STUB_DIR: containers/<name>.json (one `docker inspect` object each), image.json (image Config),
compose_base.json (what `docker compose up` creates before the override files are applied), calls (log).
Knobs (files in $STUB_DIR): rpc_bad_profile (containers under this AppArmor profile answer server_state
"connected"), drop_on_recreate (HostConfig key removed from every container created by run/compose up),
profile_on_recreate (every created container reports this AppArmorProfile, as if the apparmor= option were ignored),
fail_run, fail_compose_up (one-shot), deny_on_exercise (run-parts appends a DENIED record to $AUDIT_LOG), deny_on_addon (the same for
exercise_addons' `du -sb`, as pft-retention sample was denied on the validator).
`docker run` builds the new container from its ARGUMENTS, so the tests check that apply's run args really
reproduce the old container (a lost flag shows up as a confine signature change).
"""
import json
import os
import sys

D = os.environ["STUB_DIR"]
CD = os.path.join(D, "containers")


def path(n):
    return os.path.join(CD, n + ".json")


def load(n):
    try:
        with open(path(n)) as f:
            return json.load(f)
    except OSError:
        return None


def save(n, c):
    with open(path(n), "w") as f:
        json.dump(c, f)


def knob(n):
    p = os.path.join(D, n)
    return open(p).read().strip() if os.path.exists(p) else None


def tick():
    p = os.path.join(D, "clock")
    t = int(knob("clock") or 0) + 1
    with open(p, "w") as f:
        f.write(str(t))
    return f"2026-11-02T10:{t // 60:02d}:{t % 60:02d}.000000000Z"


def after_create(c):
    k = knob("drop_on_recreate")
    if k:
        c["HostConfig"].pop(k, None)
    p = knob("profile_on_recreate")
    if p:
        c["AppArmorProfile"] = p
    c["State"] = {"Running": True, "StartedAt": tick()}
    return c


def image_cfg():
    with open(os.path.join(D, "image.json")) as f:
        return json.load(f)


def do_run(args):
    img = image_cfg()
    hc = {"CapAdd": [], "CapDrop": [], "SecurityOpt": [], "Tmpfs": {}, "PortBindings": {}, "LogConfig": {"Config": {}},
          "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "NetworkMode": "default"}
    cfg = {"Env": list(img.get("Env", [])), "Entrypoint": img.get("Entrypoint"), "User": "", "Labels": {}}
    mounts = []
    name = None
    rest = []
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
            ip, hp, cp = (parts if len(parts) == 3 else [""] + parts)
            hc["PortBindings"].setdefault(cp + "/tcp", []).append({"HostIp": ip, "HostPort": hp})
        elif k == "volume":
            parts = v.split(":")
            src, dst = parts[0], parts[1]
            rw = not (len(parts) > 2 and parts[2] == "ro")
            if src.startswith("/"):
                mounts.append({"Type": "bind", "Source": src, "Destination": dst, "RW": rw})
            else:
                mounts.append({"Type": "volume", "Name": src, "Source": f"/var/lib/docker/volumes/{src}/_data",
                               "Destination": dst, "RW": rw})
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
            hc["Tmpfs"][tp] = to
        elif k == "pids-limit":
            hc["PidsLimit"] = int(v)
        elif k == "memory":
            hc["Memory"] = int(v)
        elif k == "memory-swap":
            hc["MemorySwap"] = int(v)
        elif k == "security-opt":
            hc["SecurityOpt"].append(v)
        else:
            sys.stderr.write(f"stub docker run: unknown flag {a}\n")
            return 125
    if name is None or load(name) is not None:
        sys.stderr.write("stub docker run: name missing or in use\n")
        return 125
    if knob("fail_run") is not None:
        return 125
    cfg["Image"], cfg["Cmd"] = rest[0], rest[1:]
    prof = "docker-default"
    for o in hc["SecurityOpt"]:
        if o.startswith("apparmor="):
            prof = o.split("=", 1)[1]
    c = {"Name": "/" + name, "AppArmorProfile": prof, "Config": cfg, "HostConfig": hc, "Mounts": mounts}
    save(name, after_create(c))
    print("0123456789ab")
    return 0


def compose(args):
    if args[0] == "config":
        return 1 if knob("fail_compose_config") is not None else 0
    if args[0] != "up":
        return 0
    if knob("fail_compose_up") is not None:  # one-shot: the rollback's compose up works
        os.remove(os.path.join(D, "fail_compose_up"))
        print("Error response from daemon: stub compose up failure")
        return 1
    cwd = os.getcwd()
    files = []
    with open(os.path.join(cwd, ".env")) as f:
        for line in f:
            if line.startswith("COMPOSE_FILE="):
                files = line.strip().split("=", 1)[1].split(":")
    with open(os.path.join(D, "compose_base.json")) as f:
        c = json.load(f)
    c["AppArmorProfile"] = "docker-default"
    for fn in files:
        p = os.path.join(cwd, fn)
        if not os.path.exists(p):
            print(f"open {p}: no such file or directory")
            return 1
        with open(p) as f:
            for line in f:
                s = line.strip().strip("-").strip().strip('"')
                if s.startswith("apparmor="):
                    c["HostConfig"]["SecurityOpt"].append(s)
                    c["AppArmorProfile"] = s.split("=", 1)[1]
    c["Config"]["Labels"]["com.docker.compose.project.config_files"] = ",".join(
        os.path.join(c["Config"]["Labels"]["com.docker.compose.project.working_dir"], fn) for fn in files)
    name = c["Name"][1:]
    print(f" Container {name}  Recreated")
    save(name, after_create(c))
    return 0


def do_exec(args):
    c = load(args[0])
    if c is None or not c["State"]["Running"]:
        return 1
    cmd = " ".join(args[1:])
    for trig, kn, comm, name in (("run-parts", "deny_on_exercise", "run-parts", "/etc/cron.hourly/x"),
                                 ("du -sb", "deny_on_addon", "sh", "/usr/bin/du")):
        if trig in cmd and knob(kn) is not None:
            with open(os.environ["AUDIT_LOG"], "a") as f:
                now, prof = os.environ.get("PFT_AA_NOW", "0"), c["AppArmorProfile"]
                f.write(f'type=AVC msg=audit({now}.500:9): apparmor="DENIED" operation="open" profile="{prof}" '
                        f'name="{name}" pid=9 comm="{comm}" requested_mask="r" denied_mask="r" '
                        'fsuid=0 ouid=0\n')
    if "server_info" in cmd and "-w" not in args:
        st = "connected" if knob("rpc_bad_profile") == c["AppArmorProfile"] else "full"
        print(json.dumps({"result": {"info": {"server_state": st, "peers": 5}}}))
    elif "-w" in args:
        print("200")
    else:
        print("ok")
    return 0


def main(a):
    with open(os.path.join(D, "calls"), "a") as f:
        f.write("docker " + " ".join(a) + "\n")
    if a[0] == "inspect":
        c = load(a[-1])
        if c is None:
            print("[]")
            return 1
        print(json.dumps([c]))
        return 0
    if a[0] == "image":
        print(json.dumps([{"Config": image_cfg()}]))
        return 0
    if a[0] == "run":
        return do_run(a[1:])
    if a[0] == "compose":
        return compose(a[1:])
    if a[0] == "exec":
        return do_exec(a[1:])
    if a[0] == "stop":
        c = load(a[-1])
        if c is None:
            return 1
        c["State"]["Running"] = False
        save(a[-1], c)
        return 0
    if a[0] == "start":
        c = load(a[-1])
        if c is None:
            return 1
        c["State"] = {"Running": True, "StartedAt": tick()}
        save(a[-1], c)
        return 0
    if a[0] == "rename":
        c = load(a[1])
        if c is None or load(a[2]) is not None:
            return 1
        c["Name"] = "/" + a[2]
        os.remove(path(a[1]))
        save(a[2], c)
        return 0
    if a[0] == "update":
        c = load(a[-1])
        if c is None:
            return 1
        c["HostConfig"]["RestartPolicy"]["Name"] = a[1].split("=", 1)[1]
        save(a[-1], c)
        return 0
    if a[0] == "rm":
        if os.path.exists(path(a[-1])):
            os.remove(path(a[-1]))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
