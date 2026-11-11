#!/usr/bin/env python3
"""peerwatch_parse.py: peer-quality analysis behind pft-peerwatch (stdlib only).

collect: reads the node's `peers` and `server_info` admin RPC answers, the previous state file and the conf, then
  - writes the Prometheus textfile body (pft_peerwatch_* samples, first label container="NAME") to stdout,
  - writes STATE (last pubkey set, bounded churn events, check results) atomically,
  - appends one summary line to HISTORY and trims it to HISTORY_MAX lines (bounded history).
  Exit 0 ok, 1 bad input (non-JSON, rpc error, malformed field): nothing is written then.
status: reads STATE and prints the check table (or --json); exit 0 PASS, 1 WARN, 2 FAIL, 4 no state / stale.

Addresses and public keys never leave the state file (root-only dir): metrics carry counts, ratios and the
configured link TAG only.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile

LEVELS = {"PASS": 0, "WARN": 1, "FAIL": 2}
CHECKS = ("count", "churn", "latency", "versions", "direction", "diversity", "ledgers", "fixed")

# name -> (default, minimum, maximum)
NUMERIC = {
    "MIN_PEERS_WARN": (5, 0, 1000),
    "MIN_PEERS_FAIL": (1, 0, 1000),
    "CHURN_WINDOW_MIN": (60, 1, 1440),
    "CHURN_WARN": (20, 0, 100000),
    "CHURN_FAIL": (60, 0, 100000),
    "FLAP_WARN": (3, 0, 1000),
    "GAP_SEC": (180, 30, 86400),
    "LAT_P95_WARN_MS": (1000, 1, 600000),
    "LAT_P95_FAIL_MS": (3000, 1, 600000),
    "OUTDATED_WARN_PCT": (25, 0, 100),
    "OUTDATED_FAIL_PCT": (75, 0, 100),
    "MIN_OUTBOUND_WARN": (3, 0, 1000),
    "MIN_OUTBOUND_FAIL": (1, 0, 1000),
    "PREFIX16_MIN_WARN": (3, 0, 1000),
    "PREFIX16_MAX_SHARE_WARN_PCT": (50, 1, 100),
    "MAX_LEDGER_LAG": (8, 0, 100000),
    "AGREE_WARN_PCT": (70, 0, 100),
    "AGREE_FAIL_PCT": (30, 0, 100),
    "HISTORY_MAX": (1440, 10, 100000),
    "STALE_SEC": (300, 30, 86400),
}


def die(msg, rc=1):
    print("peerwatch_parse: " + msg, file=sys.stderr)
    sys.exit(rc)


def load_conf(path):
    """KEY=VALUE text (never executed). Unknown keys are ignored; bad numbers are an error."""
    conf = {k: v[0] for k, v in NUMERIC.items()}
    conf["FIXED_LINKS"] = ""
    conf["FIXED_FROM_CLUSTER"] = "1"
    conf["COUNT_PRIVATE_OUTBOUND"] = "0"
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = re.split(r"\s#", v, maxsplit=1)[0]  # inline comment after whitespace, as the shell reads it
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k in NUMERIC:
                    lo, hi = NUMERIC[k][1], NUMERIC[k][2]
                    if not v.isdigit() or not lo <= int(v) <= hi:
                        die(f"conf {k}={v!r}: want an integer {lo}..{hi}", 3)
                    conf[k] = int(v)
                elif k in ("FIXED_LINKS", "FIXED_FROM_CLUSTER", "COUNT_PRIVATE_OUTBOUND"):
                    conf[k] = v
    links = {}
    for item in conf["FIXED_LINKS"].split():
        tag, sep, key = item.partition("=")
        if not sep or not tag.isidentifier() or not key.startswith("n") or not key.isalnum():
            die(f"conf FIXED_LINKS item {item!r}: want TAG=NODE_PUBKEY", 3)
        links[tag] = key
    conf["links"] = links
    return conf


def version_tuple(v):
    v = str(v)
    for pre in ("rippled-", "postfiatd-", "xrpld-"):
        v = v.removeprefix(pre)
    core = v.split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def nearest_rank(values, q):
    s = sorted(values)
    k = max(1, -(-int(q * 100) * len(s) // 100))  # ceil(q * n), q in percent steps
    return s[k - 1]


def peer_ip(address):
    """'a.b.c.d:port' / '[v6]:port' / bare -> ip_address or None"""
    a = str(address)
    if a.startswith("["):
        a = a[1:].split("]", 1)[0]
    elif a.count(":") == 1:
        a = a.split(":", 1)[0]
    try:
        return ipaddress.ip_address(a)
    except ValueError:
        return None


def prefixes(ip):
    if ip.version == 4:
        return (
            str(ipaddress.ip_network(f"{ip}/16", strict=False)),
            str(ipaddress.ip_network(f"{ip}/24", strict=False)),
        )
    return (str(ipaddress.ip_network(f"{ip}/32", strict=False)), str(ipaddress.ip_network(f"{ip}/48", strict=False)))


def upper_ledger(cl):
    """complete_ledgers '7954421 - 7954933' or '1-5,7-9' -> highest seq, or None"""
    if not isinstance(cl, str) or not cl.strip() or cl.strip() == "empty":
        return None
    last = cl.replace(" ", "").split(",")[-1]
    hi = last.split("-")[-1]
    return int(hi) if hi.isdigit() else None


def rpc_result(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        die(f"{what}: not JSON ({e.__class__.__name__})")
    r = doc.get("result") if isinstance(doc, dict) else None
    if not isinstance(r, dict) or r.get("status") != "success":
        err = r.get("error") if isinstance(r, dict) else None
        die(f"{what}: rpc answer is not a success ({err or 'no result'})")
    return r


def parse_peers(r):
    peers = r.get("peers")
    if not isinstance(peers, list):
        die("peers: result.peers is not a list")
    out = []
    for i, p in enumerate(peers):
        if not isinstance(p, dict) or not isinstance(p.get("public_key"), str) or not p["public_key"]:
            die(f"peers: entry {i} has no public_key")
        lat = p.get("latency")
        if lat is not None and (not isinstance(lat, int) or isinstance(lat, bool) or lat < 0):
            die(f"peers: entry {i} latency {lat!r} is not a non-negative integer")
        out.append(
            {
                "key": p["public_key"],
                "inbound": p.get("inbound") is True,
                "latency": lat,
                "version": p.get("version"),
                "ledger": upper_ledger(p.get("complete_ledgers")),
                "network_id": p.get("network_id"),
                "ip": peer_ip(p.get("address", "")),
            }
        )
    keys = [p["key"] for p in out]
    if len(set(keys)) != len(keys):
        die("peers: duplicate public_key entries")
    cluster = r.get("cluster") if isinstance(r.get("cluster"), dict) else {}
    return out, cluster


def parse_info(r):
    info = r.get("info")
    if not isinstance(info, dict):
        die("server_info: result.info is not an object")
    vl = info.get("validated_ledger") or {}
    seq = vl.get("seq") if isinstance(vl, dict) else None
    state = info.get("server_state")
    if not isinstance(state, str):
        die("server_info: server_state missing")
    return {
        "state": state,
        "seq": seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
        "build": info.get("build_version"),
        "network_id": info.get("network_id"),
    }


def grade(value, warn, fail, below=False):
    if below:
        return "FAIL" if value < fail else "WARN" if value < warn else "PASS"
    return "FAIL" if value > fail else "WARN" if value > warn else "PASS"


def analyze(peers, cluster, info, prev, conf, now):
    res = {}
    n = len(peers)
    inbound = sum(1 for p in peers if p["inbound"])
    outbound = n - inbound
    m = {"peers_inbound": inbound, "peers_outbound": outbound}

    res["count"] = (grade(n, conf["MIN_PEERS_WARN"], conf["MIN_PEERS_FAIL"], below=True), f"{n} peers")

    # churn by public key: joins/leaves against the previous sample; a gap (collector or node down) re-baselines
    cur = {p["key"] for p in peers}
    events = [e for e in (prev.get("events") or []) if now - e[0] <= conf["CHURN_WINDOW_MIN"] * 60]
    prev_keys = set(prev.get("keys") or [])
    gap = not prev or not isinstance(prev.get("ts"), int) or not 0 <= now - prev["ts"] <= conf["GAP_SEC"]
    joins = leaves = 0
    if not gap:
        for k in sorted(cur - prev_keys):
            events.append([now, "join", k])
            joins += 1
        for k in sorted(prev_keys - cur):
            events.append([now, "leave", k])
            leaves += 1
    w_join = sum(1 for e in events if e[1] == "join")
    w_leave = sum(1 for e in events if e[1] == "leave")
    left = {}
    for e in events:
        if e[1] == "leave":
            left[e[2]] = left.get(e[2], 0) + 1
    flapping = sum(1 for k, c in left.items() if c >= 2)
    churn = w_join + w_leave
    g = grade(churn, conf["CHURN_WARN"], conf["CHURN_FAIL"])
    if g == "PASS" and conf["FLAP_WARN"] and flapping >= conf["FLAP_WARN"]:
        g = "WARN"
    res["churn"] = (
        g,
        (
            f"{churn} join/leave events in {conf['CHURN_WINDOW_MIN']}m ({w_join} joins, {w_leave} leaves, "
            f"{flapping} peers left twice or more){' [re-baselined: first sample or gap]' if gap else ''}"
        ),
    )
    m.update(churn_joins=w_join, churn_leaves=w_leave, churn_flapping_peers=flapping, churn_rebaselined=int(gap))

    lats = [p["latency"] for p in peers if p["latency"] is not None]
    if lats:
        p50, p95, mx = nearest_rank(lats, 0.50), nearest_rank(lats, 0.95), max(lats)
        res["latency"] = (
            grade(p95, conf["LAT_P95_WARN_MS"], conf["LAT_P95_FAIL_MS"]),
            f"p50 {p50} ms, p95 {p95} ms, max {mx} ms over {len(lats)} peers",
        )
        m.update(latency_p50_ms=p50, latency_p95_ms=p95, latency_max_ms=mx)
    else:
        res["latency"] = ("PASS", "no peer reports a latency")

    own = version_tuple(info["build"])
    rel = {"same": 0, "older": 0, "newer": 0, "unknown": 0}
    for p in peers:
        v = version_tuple(p["version"]) if p["version"] is not None else None
        rel["unknown" if v is None or own is None else "same" if v == own else "older" if v < own else "newer"] += 1
    m.update({f"version_{k}": v for k, v in rel.items()})
    outdated_pct = 100.0 * rel["older"] / n if n else 0.0
    res["versions"] = (
        grade(outdated_pct, conf["OUTDATED_WARN_PCT"], conf["OUTDATED_FAIL_PCT"]),
        f"{rel['older']}/{n} peers older than own {info['build']} ({outdated_pct:.0f} %), {rel['newer']} newer, {rel['unknown']} unknown",
    )

    res["direction"] = (
        grade(outbound, conf["MIN_OUTBOUND_WARN"], conf["MIN_OUTBOUND_FAIL"], below=True),
        f"{inbound} inbound, {outbound} outbound",
    )

    # outbound prefix diversity: inbound addresses behind docker-proxy are the bridge gateway, so only outbound count
    p16, p24, routable = {}, set(), 0
    for p in peers:
        ip = p["ip"]
        if p["inbound"] or ip is None or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        if not ip.is_global and conf["COUNT_PRIVATE_OUTBOUND"] != "1":
            continue
        routable += 1
        a, b = prefixes(ip)
        p16[a] = p16.get(a, 0) + 1
        p24.add(b)
    share = 100.0 * max(p16.values()) / routable if routable else 0.0
    m.update(
        outbound_prefix16=len(p16),
        outbound_prefix24=len(p24),
        outbound_prefix16_max_share=round(share / 100, 4),
        outbound_routable=routable,
    )
    g = "PASS"
    if routable and (len(p16) < conf["PREFIX16_MIN_WARN"] or share > conf["PREFIX16_MAX_SHARE_WARN_PCT"]):
        g = "WARN"
    res["diversity"] = (
        g,
        f"{routable} routable outbound peers in {len(p16)} /16 and {len(p24)} /24 prefixes, largest /16 holds {share:.0f} %",
    )

    # ledger agreement: a peer agrees when its newest complete ledger is within MAX_LEDGER_LAG of our validated seq
    wrong_net = sum(
        1
        for p in peers
        if p["network_id"] is not None
        and info["network_id"] is not None
        and str(p["network_id"]) != str(info["network_id"])
    )
    agree = 0
    lags = []
    if info["seq"] is not None:
        for p in peers:
            if p["ledger"] is not None:
                lag = info["seq"] - p["ledger"]
                lags.append(lag)
                agree += abs(lag) <= conf["MAX_LEDGER_LAG"]
    ratio = agree / n if n else 0.0
    m.update(ledger_agree_ratio=round(ratio, 4), network_mismatch_peers=wrong_net)
    if lags:
        m["ledger_lag_max"] = max(lags)
    if info["seq"] is None:
        res["ledgers"] = ("WARN", f"own node has no validated ledger (state {info['state']})")
    elif wrong_net:
        res["ledgers"] = ("FAIL", f"{wrong_net} peers on another network_id")
    else:
        res["ledgers"] = (
            grade(100 * ratio, conf["AGREE_WARN_PCT"], conf["AGREE_FAIL_PCT"], below=True),
            f"{agree}/{n} peers within {conf['MAX_LEDGER_LAG']} ledgers of own validated {info['seq']}",
        )

    links = dict(conf["links"])
    if not links and conf["FIXED_FROM_CLUSTER"] == "1":
        for k, v in sorted(cluster.items()):
            tag = v.get("tag") if isinstance(v, dict) else None
            if isinstance(tag, str) and tag.isidentifier():
                links[tag] = k
    link_up = {tag: int(key in cur) for tag, key in sorted(links.items())}
    down = [t for t, u in link_up.items() if not u]
    if not links:
        res["fixed"] = ("PASS", "no fixed links configured")
    else:
        res["fixed"] = ("FAIL" if down else "PASS", f"down: {', '.join(down)}" if down else f"up: {', '.join(link_up)}")
    m["links"] = link_up
    return res, m, events, joins, leaves, gap, links


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def metrics_text(name, res, m, info):
    c = f'container="{esc(name)}"'
    out = []

    def g(metric, help_, samples):
        out.append(f"# HELP pft_peerwatch_{metric} {help_}")
        out.append(f"# TYPE pft_peerwatch_{metric} gauge")
        for labels, val in samples:
            out.append(f"pft_peerwatch_{metric}{{{c}{labels}}} {val}")

    g(
        "peers",
        "connected peers by direction",
        [(',direction="inbound"', m["peers_inbound"]), (',direction="outbound"', m["peers_outbound"])],
    )
    g(
        "churn_events",
        "peer join/leave events (by public key) in the churn window",
        [(',kind="join"', m["churn_joins"]), (',kind="leave"', m["churn_leaves"])],
    )
    g("churn_flapping_peers", "peers that left twice or more in the churn window", [("", m["churn_flapping_peers"])])
    g(
        "churn_rebaselined",
        "1 if this sample re-baselined churn (first sample or gap since the previous one)",
        [("", m["churn_rebaselined"])],
    )
    if "latency_p50_ms" in m:
        g(
            "latency_ms",
            "peer latency reported by postfiatd (nearest-rank)",
            [
                (',quantile="0.5"', m["latency_p50_ms"]),
                (',quantile="0.95"', m["latency_p95_ms"]),
                (',quantile="1"', m["latency_max_ms"]),
            ],
        )
    g(
        "version_peers",
        "peers by build version relative to this node",
        [(f',relation="{k}"', m[f"version_{k}"]) for k in ("same", "older", "newer", "unknown")],
    )
    g(
        "outbound_prefixes",
        "distinct prefixes among routable outbound peers (IPv4 /16 and /24, IPv6 /32 and /48)",
        [(',len="16"', m["outbound_prefix16"]), (',len="24"', m["outbound_prefix24"])],
    )
    g(
        "outbound_prefix16_max_share",
        "share of routable outbound peers in the largest /16 (0..1)",
        [("", m["outbound_prefix16_max_share"])],
    )
    g(
        "ledger_agree_ratio",
        "share of peers whose newest complete ledger is within MAX_LEDGER_LAG of own validated ledger",
        [("", m["ledger_agree_ratio"])],
    )
    if "ledger_lag_max" in m:
        g(
            "ledger_lag_max",
            "largest (own validated seq - peer newest complete ledger) over all peers",
            [("", m["ledger_lag_max"])],
        )
    g("network_mismatch_peers", "peers reporting another network_id", [("", m["network_mismatch_peers"])])
    if m["links"]:
        g(
            "fixed_link_up",
            "1 if the fixed/cluster peer with this tag is connected (matched by public key)",
            [(f',link="{esc(t)}"', u) for t, u in m["links"].items()],
        )
    g(
        "local_full",
        "1 if own server_state is full, validating or proposing",
        [("", int(info["state"] in ("full", "validating", "proposing")))],
    )
    g(
        "check_status",
        "peerwatch check result: 0 PASS, 1 WARN, 2 FAIL",
        [(f',check="{k}"', LEVELS[res[k][0]]) for k in CHECKS],
    )
    g("status", "worst peerwatch check: 0 PASS, 1 WARN, 2 FAIL", [("", max(LEVELS[res[k][0]] for k in CHECKS))])
    return "\n".join(out) + "\n"


def write_atomic(path, text):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        print("peerwatch_parse: state file unreadable, re-baselining", file=sys.stderr)
        return {}
    if not isinstance(s, dict):
        print("peerwatch_parse: state file is not an object, re-baselining", file=sys.stderr)
        return {}
    return s


def append_history(path, line, keep):
    lines = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = [x for x in f.read().split("\n") if x.strip()]
    except FileNotFoundError:
        pass
    lines.append(line)
    write_atomic(path, "\n".join(lines[-keep:]) + "\n")


def cmd_collect(a):
    conf = load_conf(a.conf)
    peers, cluster = parse_peers(rpc_result(a.peers, "peers"))
    info = parse_info(rpc_result(a.server_info, "server_info"))
    prev = read_state(a.state)
    res, m, events, joins, leaves, gap, links = analyze(peers, cluster, info, prev, conf, a.now)
    sys.stdout.write(metrics_text(a.container, res, m, info))
    worst = max(LEVELS[res[k][0]] for k in CHECKS)
    state = {
        "ts": a.now,
        "container": a.container,
        "keys": sorted(p["key"] for p in peers),
        "events": events,
        "links": links,
        "checks": {k: list(res[k]) for k in CHECKS},
        "status": next(k for k, v in LEVELS.items() if v == worst),
    }
    write_atomic(a.state, json.dumps(state, sort_keys=True) + "\n")
    if a.history:
        summary = {
            "ts": a.now,
            "peers": len(peers),
            "joins": joins,
            "leaves": leaves,
            "gap": gap,
            "status": state["status"],
        }
        summary.update({k: v for k, v in m.items() if k != "links"})
        summary["links"] = m["links"]
        summary["checks"] = {k: res[k][0] for k in CHECKS}
        append_history(a.history, json.dumps(summary, sort_keys=True), conf["HISTORY_MAX"])


def cmd_status(a):
    conf = load_conf(a.conf)
    s = read_state(a.state)
    if not s or not isinstance(s.get("ts"), int) or not isinstance(s.get("checks"), dict):
        print(
            "UNKNOWN no peerwatch state yet" if not a.json else json.dumps({"status": "UNKNOWN", "reason": "no state"})
        )
        return 4
    age = a.now - s["ts"]
    if age > conf["STALE_SEC"]:
        reason = f"last sample is {age} s old (> {conf['STALE_SEC']} s)"
        print(json.dumps({"status": "STALE", "reason": reason, "ts": s["ts"]}) if a.json else f"STALE {reason}")
        return 4
    worst = max(LEVELS.get(v[0], 2) for v in s["checks"].values())
    if a.json:
        print(
            json.dumps(
                {
                    "status": s["status"],
                    "ts": s["ts"],
                    "age_sec": age,
                    "container": s.get("container"),
                    "checks": {k: {"result": v[0], "detail": v[1]} for k, v in s["checks"].items()},
                },
                sort_keys=True,
            )
        )
    else:
        print(f"pft-peerwatch {s.get('container')} sample age {age} s")
        for k in CHECKS:
            if k in s["checks"]:
                r, d = s["checks"][k]
                print(f"  [{r}] {k:<9} {d}")
        print(f"RESULT: {s['status']}")
    return worst


class Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors exit 3: argparse's default 2 would read as FAIL in status
        die(message, 3)


def main():
    ap = Parser()
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=Parser)
    c = sub.add_parser("collect")
    c.add_argument("--peers", required=True)
    c.add_argument("--server-info", required=True)
    c.add_argument("--state", required=True)
    c.add_argument("--history", default="")
    c.add_argument("--container", required=True)
    c.add_argument("--conf", default="")
    c.add_argument("--now", type=int, required=True)
    s = sub.add_parser("status")
    s.add_argument("--state", required=True)
    s.add_argument("--conf", default="")
    s.add_argument("--now", type=int, required=True)
    s.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.cmd == "collect":
        cmd_collect(a)
        return 0
    return cmd_status(a)


if __name__ == "__main__":
    sys.exit(main())
