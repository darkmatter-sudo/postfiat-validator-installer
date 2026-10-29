#!/usr/bin/env python3
"""statewatch_parse: turn one postfiatd admin `server_info` answer into pft_statewatch_* textfile metrics.

Usage: statewatch_parse.py --container NAME --now EPOCH [--history FILE] < server_info.json

Reads the JSON answer on stdin. Every field below is REQUIRED; if one is missing or malformed the helper prints
nothing on stdout, the reason on stderr and exits 1, so the caller writes `pft_statewatch_up 0` and no stale or
partial values. Exit 0 = the full metric text is on stdout (without the up/timestamp lines, the caller adds them).

  result.status == "success"
  info.server_state                    one of STATES (validating/proposing are mode FULL in state_accounting)
  info.server_state_duration_us        decimal string or integer
  info.state_accounting.<mode>.{duration_us,transitions}   for all five operating modes
  info.io_latency_ms, info.jq_trans_overflow, info.peer_disconnects, info.peer_disconnects_resources,
  info.uptime, info.peers

Derived counter: pft_statewatch_full_exits_total = full.transitions - (1 if the node is in mode FULL now else 0),
i.e. how often this process LEFT full. It only grows when the node drops out of full and is 0 again after a restart
(0 before the first full, 1 - 1 = 0 after it), so a restart is never counted as an exit (counter-reset safe).

--history FILE appends one compact JSON line per successful run (for report/report.py). Stdlib only.
"""
import argparse
import json
import re
import sys

MODES = ("disconnected", "connected", "syncing", "tracking", "full")
STATES = MODES + ("validating", "proposing")
FULL_STATES = ("full", "validating", "proposing")
INT_RE = re.compile(r"^[0-9]{1,20}$")


class Bad(Exception):
    pass


def num(obj, key, where):
    """Non-negative integer from an int or a decimal string (postfiatd sends 64-bit counters as strings)."""
    if not isinstance(obj, dict) or key not in obj:
        raise Bad("missing %s.%s" % (where, key))
    v = obj[key]
    if isinstance(v, bool):
        raise Bad("malformed %s.%s: %r" % (where, key, v))
    if isinstance(v, int) and v >= 0:
        return v
    if isinstance(v, str) and INT_RE.match(v):
        return int(v)
    raise Bad("malformed %s.%s: %r" % (where, key, str(v)[:40]))


def parse(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get("result"), dict):
        raise Bad("no result object")
    res = doc["result"]
    if res.get("status") != "success":
        raise Bad("status %r (error %r)" % (res.get("status"), res.get("error")))
    info = res.get("info")
    if not isinstance(info, dict):
        raise Bad("missing result.info")
    state = info.get("server_state")
    if state not in STATES:
        raise Bad("unknown server_state %r" % (str(state)[:40],))
    sa = info.get("state_accounting")
    if not isinstance(sa, dict):
        raise Bad("missing info.state_accounting")
    acct = {}
    for m in MODES:
        if not isinstance(sa.get(m), dict):
            raise Bad("missing state_accounting.%s" % m)
        acct[m] = (num(sa[m], "duration_us", "state_accounting." + m), num(sa[m], "transitions", "state_accounting." + m))
    out = {
        "state": state,
        "state_duration_us": num(info, "server_state_duration_us", "info"),
        "acct": acct,
        "io_latency_ms": num(info, "io_latency_ms", "info"),
        "jq_trans_overflow": num(info, "jq_trans_overflow", "info"),
        "peer_disconnects": num(info, "peer_disconnects", "info"),
        "peer_disconnects_resources": num(info, "peer_disconnects_resources", "info"),
        "uptime": num(info, "uptime", "info"),
        "peers": num(info, "peers", "info"),
    }
    in_full = state in FULL_STATES
    if in_full and acct["full"][1] < 1:
        raise Bad("server_state %s but state_accounting.full.transitions is 0" % state)
    out["full_exits"] = acct["full"][1] - (1 if in_full else 0)
    return out


def render(p, container):
    L = 'container="%s"' % container
    lines = []

    def metric(name, typ, helptext, samples):
        lines.append("# HELP %s %s" % (name, helptext))
        lines.append("# TYPE %s %s" % (name, typ))
        for labels, value in samples:
            lines.append("%s{%s%s} %s" % (name, L, labels, value))

    metric("pft_statewatch_server_state", "gauge", "1 for the current server_state, 0 for the others",
           [(',state="%s"' % s, 1 if s == p["state"] else 0) for s in STATES])
    metric("pft_statewatch_server_state_duration_seconds", "gauge", "Time in the current server_state",
           [("", "%.6f" % (p["state_duration_us"] / 1e6))])
    metric("pft_statewatch_state_duration_seconds_total", "counter",
           "state_accounting: total time in each operating mode since process start (resets on restart)",
           [(',state="%s"' % m, "%.6f" % (p["acct"][m][0] / 1e6)) for m in MODES])
    metric("pft_statewatch_state_transitions_total", "counter",
           "state_accounting: entries into each operating mode since process start (resets on restart)",
           [(',state="%s"' % m, p["acct"][m][1]) for m in MODES])
    metric("pft_statewatch_full_exits_total", "counter",
           "Times this process left mode full (full transitions minus 1 while full); 0 after a restart",
           [("", p["full_exits"])])
    metric("pft_statewatch_io_latency_ms", "gauge", "server_info io_latency_ms (job queue IO latency)",
           [("", p["io_latency_ms"])])
    metric("pft_statewatch_jq_trans_overflow_total", "counter",
           "server_info jq_trans_overflow: transactions dropped because the job queue was full",
           [("", p["jq_trans_overflow"])])
    metric("pft_statewatch_peer_disconnects_total", "counter", "server_info peer_disconnects",
           [("", p["peer_disconnects"])])
    metric("pft_statewatch_peer_disconnects_resources_total", "counter",
           "server_info peer_disconnects_resources (peers dropped for resource use)",
           [("", p["peer_disconnects_resources"])])
    metric("pft_statewatch_node_uptime_seconds", "gauge", "server_info uptime", [("", p["uptime"])])
    metric("pft_statewatch_peers", "gauge", "server_info peers", [("", p["peers"])])
    return "\n".join(lines) + "\n"


def history_line(p, container, now):
    return json.dumps({
        "ts": now, "container": container, "state": p["state"], "state_duration_us": p["state_duration_us"],
        "acct": {m: list(p["acct"][m]) for m in MODES}, "full_exits": p["full_exits"],
        "io_latency_ms": p["io_latency_ms"], "jq_trans_overflow": p["jq_trans_overflow"],
        "peer_disconnects": p["peer_disconnects"], "peer_disconnects_resources": p["peer_disconnects_resources"],
        "uptime": p["uptime"], "peers": p["peers"]}, separators=(",", ":"), sort_keys=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--container", required=True)
    ap.add_argument("--now", required=True, type=int)
    ap.add_argument("--history")
    a = ap.parse_args(argv)
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", a.container):
        print("statewatch_parse: bad container name", file=sys.stderr)
        return 3
    raw = sys.stdin.read(1 << 20)
    try:
        doc = json.loads(raw)
        p = parse(doc)
    except ValueError as e:  # json.JSONDecodeError is a ValueError
        print("statewatch_parse: not JSON (%d bytes): %s" % (len(raw), str(e)[:80]), file=sys.stderr)
        return 1
    except Bad as e:
        print("statewatch_parse: %s" % e, file=sys.stderr)
        return 1
    text = render(p, a.container)
    if a.history:  # the baseline history is best-effort: a full disk must not blind the alerts
        try:
            with open(a.history, "a", encoding="utf-8") as f:
                f.write(history_line(p, a.container, a.now) + "\n")
        except OSError as e:
            print("statewatch_parse: history not written: %s" % e, file=sys.stderr)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
