#!/usr/bin/env python3
"""internals_parse.py: postfiatd internal-health parser behind pft-internals (stdlib only).

collect: reads the node's admin `get_counts` and `server_info {"counters": true}` answers, the previous state file
  and the conf, then
  - validates every field it exports (fail closed: a missing, mistyped, negative or out-of-range field is an error),
  - writes the Prometheus textfile body (pft_internals_* samples, first label container="NAME") to stdout,
  - writes STATE (last uptime + cumulative counters, restart and anomaly counts, last success) atomically.
  Exit 0 ok, 1 bad input (non-JSON, rpc error, invalid field) or over the size budget: nothing is written then.
last-success: prints the last successful collect time from STATE (0 if none); used for the up 0 textfile.
status: reads STATE and prints a summary (or --json); exit 0 ok, 4 no state / stale.

Restart safety: the node's counters are cumulative since its start and are exported as *_total counters (rate()
and increase() handle the reset at a node restart). The parser also compares every counter with the previous
sample: a restart (uptime went down) adds 1 to pft_internals_node_restarts_total; a counter that went DOWN while
uptime went UP is not a restart and adds 1 to pft_internals_counter_anomalies_total.

Cardinality: job types, RPC methods and object types become label values only if they match a strict name
pattern, and at most MAX_JOB_TYPES / MAX_RPC_METHODS / MAX_OBJECT_TYPES distinct names (sorted) are kept; the rest
are summed into "other" and counted in pft_internals_label_overflow. The whole body must fit MAX_BYTES.
"""

import argparse
import json
import math
import os
import re
import sys
import tempfile

# name -> (default, minimum, maximum)
NUMERIC = {
    # defaults sized so that the worst case (every cap full, longest names, 19-digit values) fits MAX_BYTES with
    # the 1024 B header reserve (tests: test_worst_case_fits_default_budget); larger caps can hit the budget gate
    "MAX_JOB_TYPES": (28, 1, 100),
    "MAX_RPC_METHODS": (24, 1, 100),
    "MAX_OBJECT_TYPES": (32, 1, 100),
    "MAX_BYTES": (61440, 4096, 65000),
    "STALE_SEC": (300, 30, 86400),
}

UINT_RE = re.compile(r"^[0-9]{1,20}$")
JOB_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
RPC_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
OBJ_RE = re.compile(r"^ripple::([A-Za-z][A-Za-z0-9_:<> ]{0,47})$")

# get_counts gauges: field -> (metric, label)
GC_CACHE_SIZE = {
    "AL_size": "accepted_ledger",
    "treenode_cache_size": "treenode",
    "treenode_track_size": "treenode_track",
    "fullbelow_size": "fullbelow",
}
# hit rates: field -> (label, scale to a 0..1 ratio). AL_ and ledger_hit_rate are percent, SLE_hit_rate a fraction.
GC_HIT = {"AL_hit_rate": ("accepted_ledger", 100.0), "ledger_hit_rate": ("ledger", 100.0), "SLE_hit_rate": ("SLE", 1.0)}
GC_DB = {"dbKBTotal": "total", "dbKBLedger": "ledger", "dbKBTransaction": "transaction"}
GC_NODESTORE_COUNTERS = {
    "node_reads_total": "nodestore_reads_total",
    "node_reads_hit": "nodestore_read_hits_total",
    "node_read_bytes": "nodestore_read_bytes_total",
    "node_writes": "nodestore_writes_total",
    "node_written_bytes": "nodestore_written_bytes_total",
}
GC_GAUGES = {
    "read_queue": "nodestore_read_queue",
    "read_threads_running": "nodestore_read_threads_running",
    "read_threads_total": "nodestore_read_threads",
    "read_request_bundle": "nodestore_read_request_bundle",
    "write_load": "nodestore_write_load",
    "historical_perminute": "historical_fetches_per_minute",
}
JOB_FIELDS = ("queued", "started", "finished", "queued_duration_us", "running_duration_us")
RPC_FIELDS = ("started", "finished", "errored", "duration_us")
# postfiatd 1.0.9's job_queue queued_duration_us is NOT monotonic: on the validator it went down in 7 of 39
# 30-second intervals (by 3.5 ms to 313 ms, six job types; logs/03, logs/04). It is exported as a gauge
# and left out of the restart / anomaly comparison; every other job, RPC and NodeStore counter stays checked.
# It can also be NEGATIVE: on the sentry 23 min after a clean restart writeAhead read -136 (2026-11-24), which
# made every collect fail (PFTInternalsStale). NON_MONOTONIC fields accept a signed integer.
NON_MONOTONIC = {"queued_duration_us"}
SINT_RE = re.compile(r"^-?[0-9]{1,20}$")
LOAD_FIELDS = ("per_second", "peak_time", "avg_time", "in_progress")


class Invalid(Exception):
    pass


def die(msg, rc=1):
    print("internals_parse: " + msg, file=sys.stderr)
    sys.exit(rc)


def load_conf(path):
    """KEY=VALUE text (never executed). Unknown keys are ignored; bad numbers are an error."""
    conf = {k: v[0] for k, v in NUMERIC.items()}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = re.split(r"\s#", v, maxsplit=1)[0]
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k in NUMERIC:
                    lo, hi = NUMERIC[k][1], NUMERIC[k][2]
                    if not v.isdigit() or not lo <= int(v) <= hi:
                        die(f"conf {k}={v!r}: want an integer {lo}..{hi}", 3)
                    conf[k] = int(v)
    return conf


def uint(v, where):
    """A non-negative integer: JSON int (not bool) or a decimal string (the node sends 64-bit counters as strings)."""
    if isinstance(v, bool):
        raise Invalid(f"{where}: boolean where a count was expected")
    if isinstance(v, int):
        if v < 0:
            raise Invalid(f"{where}: negative ({v})")
        return v
    if isinstance(v, str) and UINT_RE.match(v):
        return int(v)
    raise Invalid(f"{where}: not a non-negative integer ({str(v)[:40]!r})")


def sint(v, where):
    """A signed integer (JSON int, not bool, or a decimal string): only for the NON_MONOTONIC job_queue gauge."""
    if isinstance(v, bool):
        raise Invalid(f"{where}: boolean where a number was expected")
    if isinstance(v, int):
        return v
    if isinstance(v, str) and SINT_RE.match(v):
        return int(v)
    raise Invalid(f"{where}: not an integer ({str(v)[:40]!r})")


def ratio(v, where, scale):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise Invalid(f"{where}: not a finite number ({str(v)[:40]!r})")
    if not 0 <= v <= scale:
        raise Invalid(f"{where}: {v} outside 0..{scale:g}")
    return v / scale


def need(d, key, where):
    if not isinstance(d, dict) or key not in d:
        raise Invalid(f"{where}: missing {key}")
    return d[key]


def rpc_result(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise Invalid(f"{what}: not JSON ({e.__class__.__name__})") from None
    r = doc.get("result") if isinstance(doc, dict) else None
    if not isinstance(r, dict) or r.get("status") != "success":
        err = r.get("error") if isinstance(r, dict) else None
        raise Invalid(f"{what}: rpc answer is not a success ({str(err or 'no result')[:60]})")
    return r


def capped(names, cap):
    """Sorted names; the first cap-1 keep their own label when there are more than cap, the rest go to "other"."""
    names = sorted(names)
    if len(names) <= cap:
        return set(names), 0
    keep = set(names[: cap - 1])
    return keep, len(names) - len(keep)


def parse_counts(r, conf):
    out = {"cache_size": {}, "hit": {}, "db": {}, "ns": {}, "gauge": {}, "objects": {}, "cv": {}}
    for k, lab in GC_CACHE_SIZE.items():
        out["cache_size"][lab] = uint(need(r, k, "get_counts"), f"get_counts.{k}")
    for k, (lab, scale) in GC_HIT.items():
        out["hit"][lab] = ratio(need(r, k, "get_counts"), f"get_counts.{k}", scale)
    for k, lab in GC_DB.items():
        out["db"][lab] = uint(need(r, k, "get_counts"), f"get_counts.{k}") * 1024
    for k, m in GC_NODESTORE_COUNTERS.items():
        out["ns"][m] = uint(need(r, k, "get_counts"), f"get_counts.{k}")
    out["ns"]["nodestore_read_duration_us"] = uint(
        need(r, "node_reads_duration_us", "get_counts"), "get_counts.node_reads_duration_us"
    )
    for k, m in GC_GAUGES.items():
        out["gauge"][m] = uint(need(r, k, "get_counts"), f"get_counts.{k}")
    out["cv"]["hit"] = uint(need(r, "CachedView::hit", "get_counts"), "get_counts.CachedView::hit")
    out["cv"]["miss"] = uint(need(r, "CachedView::miss", "get_counts"), "get_counts.CachedView::miss")
    objs = {}
    for k, v in r.items():
        if k.startswith("ripple::"):
            m = OBJ_RE.match(k)
            if not m:
                raise Invalid(f"get_counts: bad object type name {k[:80]!r}")
            objs[m.group(1)] = uint(v, f"get_counts.{k}")
    if not objs:
        raise Invalid("get_counts: no ripple:: object counts")
    keep, over = capped(objs, conf["MAX_OBJECT_TYPES"])
    for name, v in objs.items():
        lab = name if name in keep else "other"
        out["objects"][lab] = out["objects"].get(lab, 0) + v
    out["overflow_objects"] = over
    return out


def parse_info(r, conf):
    info = need(r, "info", "server_info")
    up = uint(need(info, "uptime", "server_info.info"), "server_info.info.uptime")
    counters = need(info, "counters", "server_info.info (did the node get counters=true?)")
    jq = need(counters, "job_queue", "server_info.counters")
    rpc = need(counters, "rpc", "server_info.counters")
    if not isinstance(jq, dict) or not isinstance(rpc, dict):
        raise Invalid("server_info.counters: job_queue/rpc are not objects")
    jobs = {}
    for name, v in jq.items():
        if name == "total":
            continue
        if not JOB_RE.match(name):
            raise Invalid(f"server_info.counters.job_queue: bad job type name {name[:60]!r}")
        jobs[name] = {
            f: (sint if f in NON_MONOTONIC else uint)(need(v, f, f"job_queue.{name}"), f"job_queue.{name}.{f}")
            for f in JOB_FIELDS
        }
        if not jobs[name]["finished"] <= jobs[name]["started"] <= jobs[name]["queued"]:
            raise Invalid(f"job_queue.{name}: want finished <= started <= queued")
    if not jobs:
        raise Invalid("server_info.counters.job_queue: no job types")
    methods = {}
    for name, v in rpc.items():
        if name == "total":
            continue
        if not RPC_RE.match(name):
            raise Invalid(f"server_info.counters.rpc: bad method name {name[:60]!r}")
        methods[name] = {f: uint(need(v, f, f"rpc.{name}"), f"rpc.{name}.{f}") for f in RPC_FIELDS}
    load = need(info, "load", "server_info.info")
    threads = uint(need(load, "threads", "server_info.load"), "server_info.load.threads")
    jt = need(load, "job_types", "server_info.load")
    if not isinstance(jt, list):
        raise Invalid("server_info.load.job_types: not a list")
    ljobs = {}
    for i, e in enumerate(jt):
        name = need(e, "job_type", f"load.job_types[{i}]")
        if not isinstance(name, str) or not JOB_RE.match(name):
            raise Invalid(f"load.job_types[{i}]: bad job_type {str(name)[:60]!r}")
        if name in ljobs:
            raise Invalid(f"load.job_types: duplicate {name}")
        # the node omits zero fields; over_target is a bool when present
        vals = {f: uint(e[f], f"load.{name}.{f}") if f in e else 0 for f in LOAD_FIELDS}
        ot = e.get("over_target", False)
        if not isinstance(ot, bool):
            raise Invalid(f"load.{name}.over_target: not a boolean")
        vals["over_target"] = int(ot)
        ljobs[name] = vals
    return {"uptime": up, "jobs": jobs, "methods": methods, "threads": threads, "load": ljobs}


def fold(d, cap, fields):
    """{name: {field: n}} -> same with names beyond the cap summed into "other"; returns (folded, overflow)."""
    keep, over = capped(d, cap)
    out = {}
    for name, v in d.items():
        lab = name if name in keep else "other"
        if lab not in out:
            out[lab] = dict.fromkeys(fields, 0)
        for f in fields:
            out[lab][f] = (
                max(out[lab][f], v[f]) if f in ("peak_time", "avg_time", "over_target") else out[lab][f] + v[f]
            )
    return out, over


def flat_counters(c, i):
    """Every cumulative counter by a stable key, for restart / anomaly detection."""
    flat = {f"ns.{k}": v for k, v in c["ns"].items()}
    flat["cv.hit"], flat["cv.miss"] = c["cv"]["hit"], c["cv"]["miss"]
    for name, v in i["jobs"].items():
        for f in JOB_FIELDS:
            if f not in NON_MONOTONIC:
                flat[f"job.{name}.{f}"] = v[f]
    for name, v in i["methods"].items():
        for f in RPC_FIELDS:
            flat[f"rpc.{name}.{f}"] = v[f]
    return flat


# postfiatd 1.0.9 node_read_bytes wraps at 2**32: on the validator it went 4293619473 -> 10786189 in one
# 30-second interval with uptime up (2026-11-20T12:23:40Z, README "32-bit wrap", logs/13). A decrease from below
# 2**32 whose forward step modulo 2**32 is small (< WRAP_MAX_STEP) is a wrap, not an anomaly.
WRAP = 2**32
WRAP_MAX_STEP = 2**30


def is_wrap(old, new):
    return 0 <= new < old < WRAP and (new - old) % WRAP < WRAP_MAX_STEP


def compare(prev, flat, uptime):
    """-> (restart, decreased counter names, wrapped counter names). A restart is uptime going down;
    counters may then start over."""
    pu = prev.get("uptime")
    pc = prev.get("counters")
    if not isinstance(pu, int) or not isinstance(pc, dict):
        return False, [], []
    if uptime < pu:
        return True, [], []
    down = sorted(k for k, v in flat.items() if isinstance(pc.get(k), int) and v < pc[k])
    wrapped = [k for k in down if is_wrap(pc[k], flat[k])]
    return False, [k for k in down if k not in wrapped], wrapped


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def metrics_text(name, c, i, jobs, methods, ljobs, over, st):
    base = f'container="{esc(name)}"'
    out = []

    def m(metric, typ, help_, samples):
        out.append(f"# HELP pft_internals_{metric} {help_}")
        out.append(f"# TYPE pft_internals_{metric} {typ}")
        for labels, val in samples:
            out.append(f"pft_internals_{metric}{{{base}{labels}}} {val}")

    def num(v):
        return f"{v:.6f}".rstrip("0").rstrip(".") if isinstance(v, float) else str(v)

    m("node_uptime_seconds", "gauge", "postfiatd uptime from server_info (a drop = node restart)", [("", i["uptime"])])
    m(
        "node_restarts_total",
        "counter",
        "node restarts seen by this collector (uptime went down between samples)",
        [("", st["restarts"])],
    )
    m(
        "counter_anomalies_total",
        "counter",
        "samples in which a node counter went down while uptime went up (not a restart)",
        [("", st["anomalies"])],
    )
    ns = c["ns"]
    for key, help_ in (
        ("nodestore_reads_total", "NodeStore reads (get_counts node_reads_total)"),
        ("nodestore_read_hits_total", "NodeStore reads answered from cache (node_reads_hit)"),
        ("nodestore_read_bytes_total", "NodeStore bytes read (node_read_bytes)"),
        ("nodestore_writes_total", "NodeStore writes (node_writes)"),
        ("nodestore_written_bytes_total", "NodeStore bytes written (node_written_bytes)"),
    ):
        m(key, "counter", help_, [("", ns[key])])
    m(
        "nodestore_read_duration_seconds_total",
        "counter",
        "time spent in NodeStore reads (node_reads_duration_us / 1e6)",
        [("", num(ns["nodestore_read_duration_us"] / 1e6))],
    )
    for key, val in sorted(c["gauge"].items()):
        m(key, "gauge", f"get_counts {key.replace('_', ' ')}", [("", val)])
    m(
        "cache_hit_ratio",
        "gauge",
        "cache hit ratio 0..1 (AL_hit_rate and ledger_hit_rate are percent, SLE_hit_rate a fraction)",
        [(f',cache="{k}"', num(v)) for k, v in sorted(c["hit"].items())],
    )
    m("cache_size", "gauge", "cache entries", [(f',cache="{k}"', v) for k, v in sorted(c["cache_size"].items())])
    m(
        "cached_view_total",
        "counter",
        "CachedView lookups by result",
        [(',result="hit"', c["cv"]["hit"]), (',result="miss"', c["cv"]["miss"])],
    )
    m(
        "db_bytes",
        "gauge",
        "SQLite database size (dbKB* x 1024)",
        [(f',db="{k}"', v) for k, v in sorted(c["db"].items())],
    )
    m(
        "objects",
        "gauge",
        "live object counts by type (ripple:: prefix dropped; capped, rest in type=other)",
        [(f',type="{esc(k)}"', v) for k, v in sorted(c["objects"].items())],
    )
    for f, help_ in (
        ("queued", "jobs queued"),
        ("started", "jobs started"),
        ("finished", "jobs finished"),
    ):
        m(
            f"job_{f}_total",
            "counter",
            help_ + " by job type",
            [(f',job_type="{k}"', v[f]) for k, v in sorted(jobs.items())],
        )
    m(
        "job_queue_wait_seconds",
        "gauge",
        "time jobs waited in the queue (s); not monotonic in postfiatd 1.0.9, use delta() not rate()",
        [(f',job_type="{k}"', num(v["queued_duration_us"] / 1e6)) for k, v in sorted(jobs.items())],
    )
    m(
        "job_run_seconds_total",
        "counter",
        "time jobs ran by job type (s)",
        [(f',job_type="{k}"', num(v["running_duration_us"] / 1e6)) for k, v in sorted(jobs.items())],
    )
    m(
        "job_waiting",
        "gauge",
        "jobs in the queue not yet started (queued - started)",
        [(f',job_type="{k}"', v["queued"] - v["started"]) for k, v in sorted(jobs.items())],
    )
    m("load_threads", "gauge", "job queue worker threads (server_info load.threads)", [("", i["threads"])])
    for f, metric, help_ in (
        ("per_second", "load_job_per_second", "jobs per second (load.job_types)"),
        ("peak_time", "load_job_peak_ms", "peak job time in ms over the node's recent window (load.job_types)"),
        ("avg_time", "load_job_avg_ms", "average job time in ms (load.job_types)"),
        ("in_progress", "load_job_in_progress", "jobs in progress (load.job_types)"),
        ("over_target", "load_job_over_target", "1 if the node reports the job type over its latency target"),
    ):
        m(metric, "gauge", help_, [(f',job_type="{k}"', v[f]) for k, v in sorted(ljobs.items())])
    for f, help_ in (
        ("started", "RPC calls started"),
        ("finished", "RPC calls finished"),
        ("errored", "RPC calls errored"),
    ):
        m(
            f"rpc_{f}_total",
            "counter",
            help_ + " by method",
            [(f',method="{k}"', v[f]) for k, v in sorted(methods.items())],
        )
    m(
        "rpc_duration_seconds_total",
        "counter",
        "time spent in RPC calls by method (s)",
        [(f',method="{k}"', num(v["duration_us"] / 1e6)) for k, v in sorted(methods.items())],
    )
    m(
        "label_overflow",
        "gauge",
        'distinct names folded into the "other" label because of the cardinality caps',
        [(f',kind="{k}"', v) for k, v in sorted(over.items())],
    )
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
        print("internals_parse: state file unreadable, re-baselining", file=sys.stderr)
        return {}
    if not isinstance(s, dict):
        print("internals_parse: state file is not an object, re-baselining", file=sys.stderr)
        return {}
    return s


def cmd_collect(a):
    conf = load_conf(a.conf)
    budget = a.max_bytes or conf["MAX_BYTES"]
    try:
        c = parse_counts(rpc_result(a.counts, "get_counts"), conf)
        i = parse_info(rpc_result(a.server_info, "server_info"), conf)
    except Invalid as e:
        die(str(e))
    jobs, ojobs = fold(i["jobs"], conf["MAX_JOB_TYPES"], JOB_FIELDS)
    methods, orpc = fold(i["methods"], conf["MAX_RPC_METHODS"], RPC_FIELDS)
    ljobs, oload = fold(i["load"], conf["MAX_JOB_TYPES"], LOAD_FIELDS + ("over_target",))
    over = {"job_type": ojobs, "load_job_type": oload, "method": orpc, "object_type": c["overflow_objects"]}
    prev = read_state(a.state)
    flat = flat_counters(c, i)
    restart, dec, wrapped = compare(prev, flat, i["uptime"])
    st = {
        "restarts": prev.get("restarts", 0) if isinstance(prev.get("restarts"), int) else 0,
        "anomalies": prev.get("anomalies", 0) if isinstance(prev.get("anomalies"), int) else 0,
    }
    st["restarts"] += int(restart)
    st["anomalies"] += int(bool(dec))
    text = metrics_text(a.container, c, i, jobs, methods, ljobs, over, st)
    size = len(text.encode("utf-8"))
    if size + a.reserve > budget:
        die(f"textfile body {size} B + {a.reserve} B header is over the {budget} B budget (MAX_BYTES)")
    if dec:
        print(f"internals_parse: counters went down without a restart: {', '.join(dec[:5])}", file=sys.stderr)
    if wrapped:
        print(f"internals_parse: counters wrapped at 2^32 (not an anomaly): {', '.join(wrapped[:5])}", file=sys.stderr)
    state = {
        "ts": a.now,
        "last_success": a.now,
        "container": a.container,
        "uptime": i["uptime"],
        "counters": flat,
        "restarts": st["restarts"],
        "anomalies": st["anomalies"],
        "last_restart": a.now if restart else prev.get("last_restart"),
        "last_anomaly": {"ts": a.now, "counters": dec[:20]} if dec else prev.get("last_anomaly"),
        "last_wrap": {"ts": a.now, "counters": wrapped[:20]} if wrapped else prev.get("last_wrap"),
        "bytes": size,
        "series": sum(1 for ln in text.split("\n") if ln and not ln.startswith("#")),
    }
    write_atomic(a.state, json.dumps(state, sort_keys=True) + "\n")
    sys.stdout.write(text)
    return 0


def cmd_last_success(a):
    s = read_state(a.state)
    v = s.get("last_success")
    print(v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0)
    return 0


def cmd_status(a):
    conf = load_conf(a.conf)
    s = read_state(a.state)
    if not s or not isinstance(s.get("ts"), int):
        print(
            "UNKNOWN no internals state yet" if not a.json else json.dumps({"status": "UNKNOWN", "reason": "no state"})
        )
        return 4
    age = a.now - s["ts"]
    status = "STALE" if age > conf["STALE_SEC"] else "OK"
    keys = ("container", "uptime", "restarts", "anomalies", "last_restart", "last_anomaly", "bytes", "series")
    doc = {"status": status, "ts": s["ts"], "age_sec": age}
    doc.update({k: s.get(k) for k in keys})
    if a.json:
        print(json.dumps(doc, sort_keys=True))
    else:
        print(f"pft-internals {s.get('container')} sample age {age} s")
        for k in keys[1:]:
            print(f"  {k:<13} {json.dumps(s.get(k))}")
        print(f"RESULT: {status}")
    return 0 if status == "OK" else 4


class Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors exit 3
        die(message, 3)


def main():
    ap = Parser()
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=Parser)
    c = sub.add_parser("collect")
    c.add_argument("--counts", required=True)
    c.add_argument("--server-info", required=True)
    c.add_argument("--state", required=True)
    c.add_argument("--container", required=True)
    c.add_argument("--conf", default="")
    c.add_argument("--now", type=int, required=True)
    c.add_argument("--max-bytes", type=int, default=0, help="override MAX_BYTES (tests)")
    c.add_argument("--reserve", type=int, default=512, help="bytes kept free for the shell's header lines")
    ls = sub.add_parser("last-success")
    ls.add_argument("--state", required=True)
    s = sub.add_parser("status")
    s.add_argument("--state", required=True)
    s.add_argument("--conf", default="")
    s.add_argument("--now", type=int, required=True)
    s.add_argument("--json", action="store_true")
    a = ap.parse_args()
    return {"collect": cmd_collect, "last-success": cmd_last_success, "status": cmd_status}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
