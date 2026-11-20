#!/usr/bin/env python3
"""One stub for every external binary pft-specdrill.sh calls (docker, curl, systemctl, systemd-run, pft-maint,
pft-integrity); dispatched on argv[0]. Behaviour comes from $STUB_DIR/scenario.json and the fake clock
$NOW_FILE; every call is appended to $STUB_DIR/calls.log so tests can assert what was NOT called.

`docker create` mirrors real docker (shape from tests/fixtures/inspect-real.json, a real capture): every -v NAME:PATH
becomes a volume Mount, and every VOLUME path the image declares that no -v covers gets an ANONYMOUS volume
(64-hex name) that only `rm -v`/`rm -fv` removes; leaked ones stay in state["dangling"].

Timelines are lists of {"at": seconds since the first `docker start`, ...} entries; the last entry with at <= now
applies. Reference ledgers close every 4 s: ref seq = REF0 + (now - T0) // 4.
"""

import io
import json
import os
import sys
import tarfile
import time

D = os.environ["STUB_DIR"]
FIXTURE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "fixtures", "inspect-real.json")
REF0 = 8000000
T0 = 1_000_000  # the fake clock's start; tests write it to NOW_FILE


def load():
    with open(os.path.join(D, "scenario.json")) as f:
        return json.load(f)


def save_state(st):
    with open(os.path.join(D, "state.json"), "w") as f:
        json.dump(st, f)


def load_state():
    p = os.path.join(D, "state.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {"containers": {}, "volumes": [], "networks": [], "dangling": [], "started_at": None}


def fixture():
    with open(FIXTURE) as f:
        return json.load(f)


def mounts_for(vols, declared, anon_seed):
    """Mounts docker would report for `-v NAME:PATH` args on an image declaring `declared` paths (real key set)."""
    m, anon = [], []
    for v in vols:
        name, dest = v.split(":", 1)
        m.append(mount(name, dest))
    covered = {v.split(":", 1)[1] for v in vols}
    for i, dest in enumerate(sorted(set(declared) - covered)):
        name = f"{anon_seed:032x}{i:032x}"
        anon.append(name)
        m.append(mount(name, dest))
    return m, anon


def mount(name, dest):
    return {
        "Type": "volume",
        "Name": name,
        "Source": f"/var/lib/docker/volumes/{name}/_data",
        "Destination": dest,
        "Driver": "local",
        "Mode": "z",
        "RW": True,
        "Propagation": "",
    }


def now():
    with open(os.environ["NOW_FILE"]) as f:
        return int(f.read().strip())


def pick(timeline, rel, default):
    cur = default
    rel = 0 if rel is None else rel  # before `docker start` (the guards) the at=0 entries apply
    for e in timeline or []:
        if e["at"] <= rel:
            cur = {**cur, **e}
    return cur


def ref_seq():
    return REF0 + (now() - T0) // 4


def side_effects(sc, st):
    """Host files that change over time: MemAvailable and the cell process VmHWM."""
    rel = None if st["started_at"] is None else now() - st["started_at"]
    mem = pick(sc.get("meminfo"), rel, {"avail_mib": sc.get("avail_mib", 6000)})
    with open(os.environ["MEMINFO"], "w") as f:
        f.write(f"MemTotal:        8000000 kB\nMemAvailable:    {mem['avail_mib'] * 1024} kB\n")
    if st["started_at"] is not None:
        hwm = pick(sc.get("hwm"), rel, {"kb": 0})
        d = os.path.join(os.environ["PROC_ROOT"], "4242")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "status"), "w") as f:
            f.write(f"Name:\tpostfiatd\nVmHWM:\t  {hwm['kb']} kB\nVmRSS:\t  {hwm['kb']} kB\n")


def out(s, rc=0):
    sys.stdout.write(s)
    return rc


def docker(sc, st, a):
    labelled = "label=pft-specdrill" in " ".join(a)
    if a[:2] == ["ps", "-aq"] and labelled:
        return out(
            "".join(f"{n}\n" for n in st["containers"])
            + "".join(f"old{i}\n" for i in range(sc.get("leftover_containers", 0)))
        )
    if a[:2] == ["volume", "ls"] and labelled:
        return out("".join(f"{n}\n" for n in st["volumes"]))
    if a[:2] == ["network", "ls"] and labelled:
        return out("".join(f"{n}\n" for n in st["networks"]))
    if a[:2] == ["network", "create"]:
        st["networks"].append(a[-1])
        return out(a[-1] + "\n", sc.get("network_create_rc", 0))
    if a[:2] == ["volume", "create"]:
        st["volumes"].append(a[-1])
        return out(a[-1] + "\n")
    if a[:2] == ["network", "rm"]:
        st["networks"] = [n for n in st["networks"] if n != a[2]]
        return 0
    if a[:2] == ["volume", "rm"]:
        st["volumes"] = [n for n in st["volumes"] if n != a[-1]]
        return 0
    if a[:2] in (["rm", "-f"], ["rm", "-fv"]):
        if a[2].startswith("old"):
            sc["leftover_containers"] = max(0, sc.get("leftover_containers", 0) - 1)
            with open(os.path.join(D, "scenario.json"), "w") as f:
                json.dump(sc, f)
        c = st["containers"].pop(a[2], None)
        if c and a[1] == "-f":
            st["dangling"] += c["anon"]
        return 0
    if a[0] == "create":
        name = a[a.index("--name") + 1]
        net = a[a.index("--network") + 1]
        vols = [a[i + 1] for i, x in enumerate(a) if x == "-v"]
        declared = sc.get("image_volumes", fixture()["image_volumes"]) or {}
        mounts, anon = mounts_for(vols, declared, len(st["containers"]) + len(st["dangling"]) + 1)
        st["containers"][name] = {"net": net, "mounts": mounts, "anon": anon, "args": a}
        return out("cid\n")
    if a[0] == "start":
        st["started_at"] = now()
        return 0
    if a[:2] == ["image", "inspect"]:
        if not sc.get("image_present", True):
            return 1
        if "-f" in a and "Config.Volumes" in a[a.index("-f") + 1]:
            if sc.get("image_volumes_fail"):
                return 1
            return out(
                sc.get("image_volumes_raw", json.dumps(sc.get("image_volumes", fixture()["image_volumes"]))) + "\n"
            )
        return 0
    if a[0] == "cp":
        if sc.get("cp_fails"):
            return 1
        cfg = sc.get("cfg", "[server]\nport_rpc_admin_local\n[node_db]\ntype=NuDB\n").encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            ti = tarfile.TarInfo("postfiatd.cfg")
            ti.size = len(cfg)
            t.addfile(ti, io.BytesIO(cfg))
        sys.stdout.buffer.write(buf.getvalue())
        return 0
    if a[0] == "inspect":
        target = a[-1]
        if target == "postfiatd":
            return out("sha256:img\n") if sc.get("live_container", True) else 1
        c = st["containers"].get(target)
        if c is None:
            return 1
        rel = None if st["started_at"] is None else now() - st["started_at"]
        if a[1] == "-f" and "State.Running" in a[2]:
            r = pick(sc.get("running"), rel, {"running": True, "oom": False, "restarts": 0})
            pid = 4242 if r["running"] else 0
            return out(f"{str(r['running']).lower()} {str(r['oom']).lower()} {r['restarts']} {pid}\n")
        if a[1] == "-f" and ".Id" in a[2]:
            return out("cid\n")
        j = {
            "HostConfig": {"PortBindings": {}, "Privileged": False, "NetworkMode": c["net"]},
            "Mounts": c["mounts"][sc.get("inspect_drop_mount", 0) :],
        }
        for k, v in sc.get("inspect_override", {}).items():
            if k == "Mounts":
                j["Mounts"] = v
            else:
                j["HostConfig"][k] = v
        return out(json.dumps([j]) + "\n")
    if a[0] == "exec":
        rel = None if st["started_at"] is None else now() - st["started_at"]
        term = sc.get("term_at")
        if term is not None and rel is not None and rel >= term and not os.path.exists(os.path.join(D, "term.reached")):
            open(os.path.join(D, "term.reached"), "w").close()
            time.sleep(2)
        c = pick(sc.get("cell"), rel, {"state": "connected", "lag": 0, "peers": 5})
        pre = 'Loading: "/etc/postfiatd/postfiatd.cfg"\n2026-Nov-20 01:40:49 UTC HTTPClient:NFO Connecting to 127.0.0.1:5005\n\n'
        if "server_info" in a:
            return out(pre + json.dumps({"result": {"info": {"server_state": c["state"], "peers": c["peers"]}}}) + "\n")
        if "ledger" in a:
            seq = ref_seq() - c["lag"]
            return out(
                pre
                + json.dumps(
                    {"result": {"ledger": {"ledger_index": str(seq), "close_time": 848000000 + (seq - REF0) * 4}}}
                )
                + "\n"
            )
    return out("", 1)


def curl(sc, st, a):
    url = a[-1]
    body = json.loads(a[a.index("-d") + 1])
    rel = None if st["started_at"] is None else now() - st["started_at"]
    if url == "REF":
        if not sc.get("ref_ok", True):
            return 7
        return out(json.dumps({"result": {"ledger": {"ledger_index": str(ref_seq())}, "status": "success"}}))
    if url == "LIVE" and body["method"] == "server_info":
        lv = pick(sc.get("live"), rel, {"state": "full", "lag": 0})
        if lv.get("down"):
            return 7
        return out(
            json.dumps(
                {"result": {"info": {"server_state": lv["state"], "validated_ledger": {"seq": ref_seq() - lv["lag"]}}}}
            )
        )
    return 7


def systemctl(sc, st, a):
    if a[:2] == ["is-active", "--quiet"]:
        return 0 if sc.get("integrity_service_active") else 3
    if a[:2] == ["stop", "pft-integrity.timer"]:
        return sc.get("timer_stop_rc", 0)
    return 0


def maint(sc, st, a):
    rel = None if st["started_at"] is None else now() - st["started_at"]
    m = pick(sc.get("maint_timeline"), rel, sc.get("maint", {"active": True, "remaining": 99999}))
    if a[0] == "active":
        return 0 if m["active"] else 1
    if a[0] == "status":
        return out(
            json.dumps(
                {
                    "window": "active" if m["active"] else "none",
                    "remaining_sec": m["remaining"] if m["active"] else None,
                }
            )
            + "\n"
        )
    return 3


def main():
    name = os.path.basename(sys.argv[0])
    a = sys.argv[1:]
    with open(os.path.join(D, "calls.log"), "a") as f:
        f.write(name + " " + " ".join(a) + "\n")
    sc = load()
    st = load_state()
    side_effects(sc, st)
    if name == "docker":
        rc = docker(sc, st, a)
    elif name == "curl":
        rc = curl(sc, st, a)
    elif name == "systemctl":
        rc = systemctl(sc, st, a)
    elif name == "systemd-run":
        rc = sc.get("systemd_run_rc", 0)
    elif name == "pft-maint":
        rc = maint(sc, st, a)
    elif name == "pft-integrity":
        rc = sc.get("integrity_rc", 0)
        out("RESULT: PASS - 1 unchanged\n" if rc == 0 else "RESULT: WARN - 1 changed\n")
    else:
        rc = 127
    save_state(st)
    return rc


if __name__ == "__main__":
    sys.exit(main())
