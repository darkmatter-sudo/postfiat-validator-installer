#!/usr/bin/env python3
"""Stateful fake of `docker` and `curl` for the pft-monupgrade apply/rollback tests.

Invoked as `fake_stack.py docker ARGS...` or `fake_stack.py curl ARGS...` (two tiny wrappers in the test scratch
dir). State lives in $STUB_DIR/state.json; every call is appended to $STUB_DIR/calls. The Prometheus / Alertmanager
API answers are derived from the containers that are running right now (version = image tag, silences survive only
when the Alertmanager container mounts the ORIGINAL data volume), so the tests exercise the real re-create logic.

Knobs (env):
  STUB_READY_FAIL=<regex>    /-/ready fails while a running container's image matches
  STUB_RUN_FAIL=<regex>      `docker run` of a matching image fails
  STUB_RULES_DROP=<regex>    Prometheus on a matching image loses one rule
  STUB_RULE_ERR=<regex>      Prometheus on a matching image reports one rule with health "err"
  STUB_TARGET_DOWN=<regex>   Prometheus on a matching image reports the scrape target down
  STUB_NO_DELIVERY=1         Alertmanager accepts the test alert but nothing reaches the ntfy topic
  STUB_NO_RESOLVED=1         the test alert's [FIRING] is delivered, its [RESOLVED] is not
  STUB_WATCHDOG_SILENCED=1   the watchdog alert is silenced
  STUB_API_DOWN=1            every API call fails
  STUB_SILENCES_LOST=<regex> Alertmanager on a matching image reports no silences (state lost)
  STUB_DROP_SECOPT=<regex>   `docker run` of a matching image ignores --security-opt (configuration drift)
"""

import json
import os
import re
import sys
import time

SD = os.environ["STUB_DIR"]
STATE = os.path.join(SD, "state.json")


def load():
    with open(STATE) as f:
        return json.load(f)


def save(st):
    with open(STATE + ".tmp", "w") as f:
        json.dump(st, f, indent=1)
    os.replace(STATE + ".tmp", STATE)


def log_call(tool, args):
    with open(os.path.join(SD, "calls"), "a") as f:
        f.write(tool + " " + " ".join(args) + "\n")


def match(knob, image):
    rx = os.environ.get(knob, "")
    return bool(rx) and re.search(rx, image or "") is not None


def die(msg, rc=1):
    sys.stderr.write(msg + "\n")
    sys.exit(rc)


# --- docker -----------------------------------------------------------------------------------------------------


def inspect_obj(c):
    return {
        "Name": "/" + c["name"],
        "Image": c["image_id"],
        "Args": c["args"],
        "State": {"Running": c["running"], "StartedAt": c["started"]},
        "Config": {"Image": c["image"], "User": c["user"], "Entrypoint": c["entrypoint"], "Labels": {}},
        "HostConfig": {
            "RestartPolicy": {"Name": c["restart"], "MaximumRetryCount": 0},
            "NetworkMode": c["network"],
            "SecurityOpt": c["security"],
            "CapDrop": c["capdrop"],
            "CapAdd": None,
            "ReadonlyRootfs": c["readonly"],
            "Tmpfs": None,
            "LogConfig": c["log"],
            "Memory": 0,
            "NanoCpus": 0,
            "Privileged": False,
            "PortBindings": {},
        },
        "Mounts": c["mounts"],
    }


def template(fmt, c):
    t = {
        "{{.Config.Image}}": c["image"],
        "{{.Image}}": c["image_id"],
        "{{.State.Running}}": "true" if c["running"] else "false",
        "{{.HostConfig.RestartPolicy.Name}}": c["restart"],
        "{{.State.StartedAt}}": c["started"],
    }
    if fmt not in t:
        die("fake docker: unsupported template " + fmt, 99)
    return t[fmt]


def find_image(st, ref):
    """ref = id, repo@digest or repo:tag@digest -> image record."""
    for img in st["images"]:
        if ref == img["id"] or ref in img.get("tags", []):
            return img
        if "@" in ref:
            repo_tag, dig = ref.split("@", 1)
            repo = repo_tag.split(":")[0]
            if f"{repo}@{dig}" in img["repo_digests"]:
                return img
    return None


def docker(args):
    st = load()
    cs = st["containers"]
    cmd = args[0]
    if cmd == "inspect":
        fmt = None
        rest = args[1:]
        if rest[:1] == ["-f"]:
            fmt, rest = rest[1], rest[2:]
        out = []
        for n in rest:
            if n not in cs:
                die(f"Error: No such object: {n}")
            out.append(template(fmt, cs[n]) if fmt else inspect_obj(cs[n]))
        print("\n".join(out) if fmt else json.dumps(out))
        return
    if cmd == "image" and args[1] == "inspect":
        ref = args[-1]
        img = find_image(st, ref)
        if not img:
            die(f"Error: No such image: {ref}")
        if "-f" in args:
            print("\n".join(img["repo_digests"]))
        else:
            print(json.dumps([img]))
        return
    if cmd == "stop":
        cs[args[-1]]["running"] = False
    elif cmd == "start":
        c = cs[args[-1]]
        c["running"] = True
        c["started"] = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
    elif cmd == "rename":
        old, new = args[1], args[2]
        if new in cs:
            die(f"Error: name {new} in use")
        cs[new] = cs.pop(old)
        cs[new]["name"] = new
    elif cmd == "update":
        cs[args[-1]]["restart"] = args[1].split("=", 1)[1]
    elif cmd == "rm":
        n = args[-1]
        if n not in cs:
            die(f"Error: No such container: {n}")
        if "-v" in args:
            st.setdefault("volumes_removed", []).append(n)
        del cs[n]
    elif cmd == "run":
        run(st, args[1:])
    else:
        die("fake docker: unexpected " + " ".join(args), 99)
    save(st)


def run(st, a):
    c = {
        "user": "",
        "readonly": False,
        "security": [],
        "capdrop": [],
        "mounts": [],
        "running": True,
        "log": {"Type": "json-file", "Config": {}},
    }
    i = 0
    while a[i].startswith("-"):
        o = a[i]
        if o == "-d":
            i += 1
            continue
        v = a[i + 1]
        if o == "--name":
            c["name"] = v
        elif o == "--restart":
            c["restart"] = v
        elif o == "--network":
            c["network"] = v
        elif o == "--security-opt":
            c["security"].append(v)
        elif o == "--cap-drop":
            c["capdrop"].append(v)
        elif o == "--user":
            c["user"] = v
        elif o == "--log-driver":
            c["log"]["Type"] = v
        elif o == "--log-opt":
            k, val = v.split("=", 1)
            c["log"]["Config"][k] = val
        elif o == "--read-only":
            c["readonly"] = True
            i += 1
            continue
        elif o == "-v":
            src, dst, *mode = v.split(":")
            vol = not src.startswith("/")
            c["mounts"].append(
                {
                    "Type": "volume" if vol else "bind",
                    "Name": src if vol else None,
                    "Source": f"/var/lib/docker/volumes/{src}/_data" if vol else src,
                    "Destination": dst,
                    "RW": mode != ["ro"],
                }
            )
        else:
            die("fake docker run: unsupported option " + o, 99)
        i += 2
    image, c["args"] = a[i], a[i + 1 :]
    if c["log"]["Config"] == {} and os.environ.get("STUB_DAEMON_LOG_OPTS"):  # dockerd's daemon.json log-opts defaults
        c["log"]["Config"] = json.loads(os.environ["STUB_DAEMON_LOG_OPTS"])
    if match("STUB_DROP_SECOPT", image):
        c["security"] = []
    if match("STUB_RUN_FAIL", image):
        die("docker: Error response from daemon: stub run failure", 125)
    img = find_image(st, image)
    if not img:
        die("Unable to find image " + image, 125)
    if c["name"] in st["containers"]:
        die("Conflict. The container name is already in use", 125)
    c["image"], c["image_id"], c["entrypoint"] = image, img["id"], img["entrypoint"]
    c["started"] = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
    st["containers"][c["name"]] = c


# --- curl -------------------------------------------------------------------------------------------------------


def running(st, name):
    c = st["containers"].get(name)
    return c if c and c["running"] else None


def tag(c):
    m = re.search(r":v([0-9.]+)@", c["image"]) or re.search(r":v([0-9.]+)$", c["image"])
    return m.group(1) if m else "?"


def curl(args):
    st = load()
    data, method, url = None, "GET", None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-X",):
            method = args[i + 1]
            i += 2
        elif a in ("--data", "-H", "--max-time"):
            if a == "--data":
                data = args[i + 1]
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            url = a
            i += 1
    if os.environ.get("STUB_API_DOWN") == "1":
        die("curl: (7) Failed to connect", 7)
    prom, am = running(st, "pft-prometheus"), running(st, "pft-alertmanager")
    ntfy = os.environ.get("NTFY_TEST_URL", "-")
    if url.startswith(ntfy + "/json"):
        since = int(re.search(r"since=(\d+)", url).group(1))
        for m in st["ntfy"]:
            if m["time"] >= since:
                print(json.dumps(m))
        return
    path = re.sub(r"^http://127\.0\.0\.1:\d+", "", url)
    p_ok = prom and not match("STUB_READY_FAIL", prom["image"])
    a_ok = am and not match("STUB_READY_FAIL", am["image"])
    port = re.search(r":(\d+)/", url).group(1)
    if (port == "9090" and not p_ok) or (port == "9093" and not a_ok):
        die("curl: (7) Failed to connect", 7)
    if path == "/-/ready":
        print("ready")
    elif path == "/api/v1/status/buildinfo":
        print(json.dumps({"status": "success", "data": {"version": tag(prom)}}))
    elif path == "/api/v2/status":
        print(json.dumps({"versionInfo": {"version": tag(am)}, "uptime": "2026-11-24T00:00:00Z"}))
    elif path == "/api/v1/rules":
        rules = [{"name": "PFTA", "health": "ok"}, {"name": "PFTB", "health": "ok"}, {"name": "PFTC", "health": "ok"}]
        if match("STUB_RULES_DROP", prom["image"]):
            rules = rules[:2]
        if match("STUB_RULE_ERR", prom["image"]):
            rules[1]["health"] = "err"
        if os.environ.get("STUB_RULES_BIG") == "1":  # a real rule set: the body alone is > MAX_ARG_STRLEN (128 KiB)
            for r in rules:
                r["query"] = "x" * 100000
        print(json.dumps({"status": "success", "data": {"groups": [{"name": "g1", "rules": rules}]}}))
    elif path == "/api/v1/targets":
        h = "down" if match("STUB_TARGET_DOWN", prom["image"]) else "up"
        print(
            json.dumps(
                {
                    "data": {
                        "activeTargets": [
                            {"labels": {"job": "postfiat"}, "scrapeUrl": "http://127.0.0.1:9877/metrics", "health": h}
                        ]
                    }
                }
            )
        )
    elif path == "/api/v2/receivers":
        print(json.dumps([{"name": "bridge"}, {"name": "digest"}, {"name": "alertpath"}]))
    elif path == "/api/v2/silences":
        vols = [m["Name"] for m in am["mounts"] if m["Destination"] == "/alertmanager"]
        lost = vols != [st["am_volume"]] or match("STUB_SILENCES_LOST", am["image"])
        print(json.dumps([] if lost else st["silences"]))
    elif path.startswith("/api/v2/alerts") and method == "POST":
        for al in json.loads(data):
            name = al["labels"]["alertname"]
            st["posted"].append(al)
            firing = al["endsAt"] > time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            off = "STUB_NO_DELIVERY" if firing else "STUB_NO_RESOLVED"
            if os.environ.get("STUB_NO_DELIVERY") != "1" and os.environ.get(off) != "1":
                st["ntfy"].append(
                    {
                        "event": "message",
                        "time": int(time.time()),
                        "title": f"[{'FIRING' if firing else 'RESOLVED'}] {name}",
                        "message": al["annotations"]["summary"],
                    }
                )
        save(st)
        print("{}")
    elif path.startswith("/api/v2/alerts"):
        name = re.search(r"alertname%3D%22([A-Za-z]+)%22", path).group(1)
        if name == "PFTAlertPipelineWatchdog":
            sil = ["s-wd"] if os.environ.get("STUB_WATCHDOG_SILENCED") == "1" else []
            print(
                json.dumps(
                    [
                        {
                            "labels": {"alertname": name},
                            "status": {"state": "active", "silencedBy": sil, "inhibitedBy": []},
                        }
                    ]
                )
            )
        else:
            print(
                json.dumps(
                    [
                        {"labels": a["labels"], "status": {"state": "active", "silencedBy": [], "inhibitedBy": []}}
                        for a in st["posted"]
                        if a["labels"]["alertname"] == name
                    ]
                )
            )
    else:
        die("fake curl: unexpected " + method + " " + url, 99)


if __name__ == "__main__":
    tool, rest = sys.argv[1], sys.argv[2:]
    log_call(tool, rest)
    {"docker": docker, "curl": curl}[tool](rest)
