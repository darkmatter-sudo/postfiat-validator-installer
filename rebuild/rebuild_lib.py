#!/usr/bin/env python3
"""Helper for pft-rebuild-drill.sh (stdlib only).

Subcommands (all read-only; print to stdout, exit 0 ok / 1 finding / 3 usage or input error / 4 refused):
  stack   STACK_LIST [--json|--rows]        parse + validate rebuild/stack.list, print the ordered steps
          (--rows: ORDER<TAB>STEP<TAB>base64(CMD) per line, for the drill's step loop: no escaping of the command)
  preflight INSTANCE_JSON BRIDGE_JSON [--live-topic T ...] [--sandbox-file PATH ...]
                                            isolation refusals for the sandbox (lxc query output); exit 4 if any
  diff    LIVE_MANIFEST SANDBOX_MANIFEST [--live-fleet J] [--sandbox-fleet J] [--exceptions F] [--json]
                                            REPRODUCED / MISSING / EXTRA / DIFFERENT, exit 1 if any MISSING or
                                            DIFFERENT item has no documented exception
  teardown BEFORE AFTER                     host-state snapshots (one item per line) -> leftovers, exit 1 if any
"""

import base64
import fnmatch
import json
import os
import re
import sys

CLASSES = ("REPRODUCED", "MISSING", "EXTRA", "DIFFERENT")
# Attributes that differ on every install by design: file mtimes, image/container ids, and the per-host
# bytes pft-integrity records for generated files. Exceptions beyond these live in rebuild/exceptions.list.
VOLATILE_ATTRS = {"mtime"}
LIVE_PORTS = {2559, 5005, 51235}
# Host paths that belong to the live node or its add-ons; a sandbox disk device sourced from any of them shares
# live state and is refused.
LIVE_PATH_PREFIXES = (
    "/var/lib/docker",
    "/opt/postfiatd",
    "/etc/postfiatd",
    "/var/lib/pft-",
    "/etc/pft-",
    "/opt/pft-agent",
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/home",
    "/root",
)
STEP_RE = re.compile(r"^[a-z][a-z0-9-]*$")


class InputError(Exception):
    pass


# ---------- stack.list ----------
def parse_stack(text):
    """stack.list lines: ORDER STEP AFTER COMMAND...  ('#' comments, blank lines ignored).
    ORDER strictly increasing integers, STEP unique [a-z0-9-], AFTER '-' or comma list of EARLIER steps,
    the first step must be 'base' (the repo's install.sh)."""
    steps, seen, last = [], {}, None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4:
            raise InputError(f"line {n}: need ORDER STEP AFTER COMMAND")
        order_s, step, after_s, cmd = parts
        if not order_s.isdigit():
            raise InputError(f"line {n}: ORDER '{order_s}' is not an integer")
        order = int(order_s)
        if last is not None and order <= last:
            raise InputError(f"line {n}: ORDER {order} not greater than {last}")
        if not STEP_RE.match(step):
            raise InputError(f"line {n}: bad STEP name '{step}'")
        if step in seen:
            raise InputError(
                f"line {n}: duplicate STEP '{step}' (first on line {seen[step]})"
            )
        after = [] if after_s == "-" else after_s.split(",")
        for a in after:
            if a not in seen:
                raise InputError(
                    f"line {n}: STEP '{step}' runs after '{a}', which is not an earlier step"
                )
        if not steps and step != "base":
            raise InputError(
                f"line {n}: the first step must be 'base' (install.sh), got '{step}'"
            )
        seen[step] = n
        last = order
        steps.append(
            {"order": order, "step": step, "after": after, "cmd": cmd, "line": n}
        )
    if not steps:
        raise InputError("stack.list declares no steps")
    return steps


# ---------- preflight ----------
def _port_of(listen):
    # lxd proxy listen: "tcp:0.0.0.0:2559", "udp:[::]:5005", "tcp:127.0.0.1:5000-5010"
    m = re.match(r"^(tcp|udp|unix):(.*):([0-9]+(?:-[0-9]+)?)$", listen or "")
    if not m:
        return set()
    lo, _, hi = m.group(3).partition("-")
    return set(range(int(lo), int(hi or lo) + 1))


def preflight(instance, bridge, live_topics=(), sandbox_files=()):
    """instance: `lxc query /1.0/instances/NAME` JSON; bridge: `lxc query /1.0/networks/BRIDGE` JSON.
    sandbox_files: [(path, text)] the drill will push into the sandbox (env files, compose overrides).
    Returns a list of refusal strings (empty = isolated)."""
    refuse = []
    cfg = instance.get("expanded_config") or instance.get("config") or {}
    devs = instance.get("expanded_devices") or instance.get("devices") or {}
    if str(cfg.get("security.privileged", "false")).lower() == "true":
        refuse.append(
            "security.privileged=true: a privileged container is root on the host"
        )
    if str(cfg.get("security.nesting", "false")).lower() != "true":
        refuse.append(
            "security.nesting is not true: Docker cannot run inside the sandbox"
        )
    for key in ("limits.cpu", "limits.memory"):
        if not cfg.get(key):
            refuse.append(f"{key} unset: the sandbox must be resource-capped")
    root_pool = next(
        (
            d.get("pool")
            for d in devs.values()
            if d.get("type") == "disk" and d.get("path") == "/"
        ),
        None,
    )
    for name, d in sorted(devs.items()):
        typ = d.get("type")
        if typ == "disk" and d.get("path") != "/" and d.get("pool"):
            # a custom volume (Docker's data dirs: the idmapped rootfs cannot hold overlayfs layers, run 08) is
            # isolated only if it lives on the sandbox's own pool, which teardown deletes
            if d.get("pool") != root_pool:
                refuse.append(
                    f"device {name}: volume {d.get('source')} on pool {d.get('pool')}, not the sandbox pool {root_pool}"
                )
        elif typ == "disk" and d.get("path") != "/":
            src = os.path.normpath(d.get("source") or "")
            if src == "/" or any(
                src == p.rstrip("-/") or src.startswith(p) for p in LIVE_PATH_PREFIXES
            ):
                refuse.append(f"device {name}: disk source {src} is live host state")
        elif typ == "proxy":
            hit = _port_of(d.get("listen")) & LIVE_PORTS
            if hit:
                refuse.append(
                    f"device {name}: proxy listens on live port(s) {sorted(hit)}"
                )
        elif typ == "nic":
            if d.get("nictype", "bridged") != "bridged" and not d.get("network"):
                refuse.append(
                    f"device {name}: nictype {d.get('nictype')} bypasses the sandbox bridge"
                )
            elif (d.get("network") or d.get("parent")) != bridge.get("name"):
                refuse.append(
                    f"device {name}: nic not on sandbox bridge {bridge.get('name')}"
                )
        elif typ in ("unix-char", "unix-block", "gpu", "usb", "pci", "infiniband"):
            refuse.append(f"device {name}: host device passthrough ({typ})")
    bcfg = bridge.get("config") or {}
    if bridge.get("type") != "bridge" or not bridge.get("managed", False):
        refuse.append(f"network {bridge.get('name')}: not an LXD-managed bridge")
    elif bcfg.get("ipv4.nat", "false") != "true" or bcfg.get(
        "ipv6.address", "none"
    ) not in ("none", ""):
        refuse.append(
            f"network {bridge.get('name')}: must be NAT-only IPv4 (ipv4.nat=true, ipv6.address=none)"
        )
    topics = [t for t in live_topics if t and t != "<redacted>"]
    for path, text in sandbox_files:
        for t in topics:
            if t in text:
                refuse.append(f"sandbox file {path}: contains a live ntfy topic")
        for m in re.finditer(r"https?://[^\s\"']*ntfy[^\s\"']*", text):
            refuse.append(
                f"sandbox file {path}: ntfy URL {redact_url(m.group(0))} (sandbox must use the blackhole)"
            )
    return refuse


def redact_url(u):
    return re.sub(r"(https?://[^/]+/).+", r"\1<redacted>", u)


# ---------- diff ----------
def parse_manifest(text):
    """pft-integrity manifest.tsv -> {key: {attr: value}} (comment lines skipped)."""
    items = {}
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split("\t", 2)
        if len(parts) != 3:
            raise InputError(f"manifest line {n}: expected KEY<TAB>ATTR<TAB>VALUE")
        k, a, v = parts
        items.setdefault(k, {})[a] = v
    return items


def fleet_items(doc):
    """pft-fleet inventory --json (one host) -> {key: {attr: value}}: per add-on state, per file sha256,
    per unit enabled state (active is a moment in time and is not compared)."""
    items = {}
    for a in doc.get("addons", []):
        items[f"addon:{a['addon']}"] = {"state": a.get("state", "")}
    for f in doc.get("files", []):
        items[f"file:{f['path']}"] = {
            "sha256": f.get("sha256") or "",
            "state": f.get("state", ""),
            "addon": f.get("addon", ""),
        }
    for u in doc.get("units", []):
        items[f"unit-enabled:{u['unit']}"] = {"enabled": u.get("enabled", "")}
    return items


def parse_exceptions(text):
    """exceptions.list: KEY_GLOB ATTR_GLOB REASON...  -> [(key_glob, attr_glob, reason)]"""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            raise InputError(f"exceptions line {n}: need KEY_GLOB ATTR_GLOB REASON")
        out.append(tuple(parts))
    return out


def _exception(key, attrs, exceptions):
    """Reason if EVERY attr in attrs is covered by one exception for key ('*' = whole item), else None."""
    reasons = []
    for a in attrs:
        r = next(
            (
                why
                for kg, ag, why in exceptions
                if fnmatch.fnmatchcase(key, kg) and fnmatch.fnmatchcase(a, ag)
            ),
            None,
        )
        if r is None:
            return None
        reasons.append(r)
    return "; ".join(sorted(set(reasons))) if reasons else None


def classify(live, sandbox, exceptions=()):
    rows = []
    for key in sorted(set(live) | set(sandbox)):
        lv, sv = live.get(key), sandbox.get(key)
        if lv is None:
            cls, attrs = "EXTRA", ["*"]
        elif sv is None:
            cls, attrs = "MISSING", ["*"]
        else:
            attrs = sorted(
                a
                for a in set(lv) | set(sv)
                if a not in VOLATILE_ATTRS and lv.get(a) != sv.get(a)
            )
            cls = "DIFFERENT" if attrs else "REPRODUCED"
        exc = _exception(key, attrs, exceptions) if cls != "REPRODUCED" else None
        row = {
            "key": key,
            "class": cls,
            "attrs": attrs if cls == "DIFFERENT" else [],
            "exception": exc,
        }
        rows.append(row)
    _addon_state_follows_files(rows, live, sandbox)
    return rows


def _addon_state_follows_files(rows, live, sandbox):
    """pft-fleet grades an add-on by its worst file, so one excepted file (a cross-host pull unit) turns the whole
    add-on MISSING. An open addon:X row is excepted only if X has at least one non-REPRODUCED file row and EVERY
    such row is excepted; an add-on with no differing file, or with one open file, stays open."""
    by_key = {r["key"]: r for r in rows}
    for r in rows:
        if not r["key"].startswith("addon:") or r["class"] == "REPRODUCED" or r["exception"]:
            continue
        name = r["key"][len("addon:"):]
        files = [
            f
            for k, f in by_key.items()
            if k.startswith("file:")
            and f["class"] != "REPRODUCED"
            and name in ((live.get(k) or {}).get("addon"), (sandbox.get(k) or {}).get("addon"))
        ]
        if files and all(f["exception"] for f in files):
            r["exception"] = f"add-on state follows its files: all {len(files)} differing file(s) are excepted"


def summarize(rows):
    s = {c: 0 for c in CLASSES}
    open_ = 0
    for r in rows:
        s[r["class"]] += 1
        if r["class"] in ("MISSING", "DIFFERENT") and not r["exception"]:
            open_ += 1
    s["excepted"] = sum(1 for r in rows if r["exception"])
    s["open"] = open_
    return s


def render_table(rows, summary, show_reproduced=False):
    out = [f"{'CLASS':<11} {'ITEM':<60} DETAIL"]
    for r in rows:
        if r["class"] == "REPRODUCED" and not show_reproduced:
            continue
        detail = ",".join(r["attrs"])
        if r["exception"]:
            detail = (detail + " " if detail else "") + f"[exception: {r['exception']}]"
        out.append(f"{r['class']:<11} {r['key']:<60} {detail}".rstrip())
    out.append(
        "SUMMARY: "
        + " ".join(f"{c}={summary[c]}" for c in CLASSES)
        + f" excepted={summary['excepted']} open={summary['open']}"
    )
    return "\n".join(out)


# ---------- teardown ----------
def leftovers(before, after):
    b = {x for x in before.splitlines() if x.strip()}
    return sorted(x for x in after.splitlines() if x.strip() and x not in b)


# ---------- CLI ----------
def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _opt(args, name, multi=False):
    vals, rest, i = [], [], 0
    while i < len(args):
        if args[i] == name:
            if i + 1 >= len(args):
                raise InputError(f"{name} needs a value")
            vals.append(args[i + 1])
            i += 2
        else:
            rest.append(args[i])
            i += 1
    if multi:
        return vals, rest
    if len(vals) > 1:
        raise InputError(f"{name} given twice")
    return (vals[0] if vals else None), rest


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 3
    cmd, args = argv[0], argv[1:]
    js = "--json" in args
    rows = "--rows" in args
    args = [a for a in args if a not in ("--json", "--rows")]
    try:
        if cmd == "stack" and len(args) == 1:
            steps = parse_stack(_read(args[0]))
            if js:
                print(json.dumps(steps, indent=1))
            elif rows:
                # jq @tsv + `read -r` turned `\n` into `\\n` inside commands (run 08); base64 survives any byte
                for s in steps:
                    b = base64.b64encode(s["cmd"].encode()).decode()
                    print(f"{s['order']}\t{s['step']}\t{b}")
            else:
                for s in steps:
                    print(
                        f"{s['order']:>3} {s['step']:<14} after={','.join(s['after']) or '-':<20} {s['cmd']}"
                    )
            return 0
        if cmd == "preflight":
            topics, args = _opt(args, "--live-topic", multi=True)
            files, args = _opt(args, "--sandbox-file", multi=True)
            if len(args) != 2:
                raise InputError("preflight INSTANCE_JSON BRIDGE_JSON")
            inst, br = json.loads(_read(args[0])), json.loads(_read(args[1]))
            refusals = preflight(inst, br, topics, [(p, _read(p)) for p in files])
            for r in refusals:
                print(f"REFUSE {r}")
            print(
                f"PREFLIGHT: {'REFUSED' if refusals else 'ISOLATED'} ({len(refusals)} refusals)"
            )
            return 4 if refusals else 0
        if cmd == "diff":
            lf, args = _opt(args, "--live-fleet")
            sf, args = _opt(args, "--sandbox-fleet")
            ef, args = _opt(args, "--exceptions")
            if len(args) != 2 or bool(lf) != bool(sf):
                raise InputError(
                    "diff LIVE_MANIFEST SANDBOX_MANIFEST [--live-fleet J --sandbox-fleet J]"
                )
            live, sand = parse_manifest(_read(args[0])), parse_manifest(_read(args[1]))
            if lf:
                live.update(fleet_items(json.loads(_read(lf))))
                sand.update(fleet_items(json.loads(_read(sf))))
            exc = parse_exceptions(_read(ef)) if ef else []
            rows = classify(live, sand, exc)
            s = summarize(rows)
            if js:
                print(
                    json.dumps({"summary": s, "items": rows}, indent=1, sort_keys=True)
                )
            else:
                print(render_table(rows, s))
            return 1 if s["open"] else 0
        if cmd == "teardown" and len(args) == 2:
            left = leftovers(_read(args[0]), _read(args[1]))
            for x in left:
                print(f"LEFTOVER {x}")
            print(
                f"TEARDOWN: {'INCOMPLETE' if left else 'CLEAN'} ({len(left)} leftovers)"
            )
            return 1 if left else 0
    except (InputError, ValueError, KeyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    print(__doc__, file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
