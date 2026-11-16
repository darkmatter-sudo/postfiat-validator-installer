#!/usr/bin/env python3
"""report_internals.py: two-host postfiatd internals report from Prometheus query_range (stdlib only).

capture --prom URL --start EPOCH --end EPOCH [--step 60] --out CAPTURE.json
    runs every query in QUERIES with /api/v1/query_range and stores the raw answers, the query strings and the
    window in CAPTURE.json (sorted keys). Read-only; retries transient errors 3 times and prints each retry.
build CAPTURE.json --md REPORT.md --json REPORT.json
    offline and deterministic: the same capture always gives byte-identical files (no clock, no environment).
    Per query and container: samples, coverage of the window, min / p50 / p95 / max (nearest rank).
"""

import argparse
import hashlib
import json
import math
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# name -> (PromQL, unit, description). Containers come from the `container` label of each answer.
QUERIES = {
    "up_min": ("min_over_time(pft_internals_up[1m])", "0/1", "collector up (1 = valid sample)"),
    "nodestore_read_ms": (
        (
            "1000 * rate(pft_internals_nodestore_read_duration_seconds_total[10m])"
            " / rate(pft_internals_nodestore_reads_total[10m])"
        ),
        "ms",
        "mean NodeStore read time over 10m (rule PFTInternalsNodeStoreSlow)",
    ),
    "nodestore_reads_per_s": ("rate(pft_internals_nodestore_reads_total[10m])", "1/s", "NodeStore reads per second"),
    "nodestore_hit_ratio": (
        "rate(pft_internals_nodestore_read_hits_total[15m]) / rate(pft_internals_nodestore_reads_total[15m])",
        "ratio",
        "NodeStore reads answered from cache over 15m (informational)",
    ),
    "cached_view_hit_ratio": (
        (
            'sum without (result) (rate(pft_internals_cached_view_total{result="hit"}[15m]))'
            " / sum without (result) (rate(pft_internals_cached_view_total[15m]))"
        ),
        "ratio",
        "CachedView lookups that hit over 15m (rule PFTInternalsCacheCollapse)",
    ),
    "nodestore_written_bytes_per_s": (
        "rate(pft_internals_nodestore_written_bytes_total[10m])",
        "B/s",
        "NodeStore bytes written per second",
    ),
    "sle_hit_ratio": ('pft_internals_cache_hit_ratio{cache="SLE"}', "ratio", "SLE cache hit ratio (node-reported)"),
    "treenode_cache_size": ('pft_internals_cache_size{cache="treenode"}', "entries", "tree node cache entries"),
    "db_total_bytes": ('pft_internals_db_bytes{db="total"}', "B", "SQLite databases, total"),
    "objects_total": ("sum by (container) (pft_internals_objects)", "objects", "live objects, all types"),
    "job_waiting_sum": (
        "sum by (container) (pft_internals_job_waiting)",
        "jobs",
        "jobs queued and not started (rule PFTInternalsJobBacklog)",
    ),
    "job_peak_ms_max": (
        "max by (container) (pft_internals_load_job_peak_ms)",
        "ms",
        "largest job-type peak time (rule PFTInternalsJobPeak)",
    ),
    "jobs_per_s": (
        "sum by (container) (rate(pft_internals_job_finished_total[10m]))",
        "1/s",
        "jobs finished per second, all types",
    ),
    "job_queue_wait_ms": (
        (
            "1000 * sum by (container) (clamp_min(delta(pft_internals_job_queue_wait_seconds[10m]), 0))"
            " / sum by (container) (rate(pft_internals_job_started_total[10m]))"
        ),
        "ms",
        "mean time a job waited in the queue (delta of the non-monotonic gauge, floored at 0)",
    ),
    "rpc_calls_per_s": (
        "sum by (container) (rate(pft_internals_rpc_started_total[10m]))",
        "1/s",
        "admin/public RPC calls per second",
    ),
    "rpc_errors_per_s": (
        "sum by (container) (rate(pft_internals_rpc_errored_total[10m]))",
        "1/s",
        "RPC calls that errored per second",
    ),
    "restarts_window": (
        "pft_internals_node_restarts_total - pft_internals_node_restarts_total offset 1m",
        "count",
        "node restarts seen per sample (non-zero = restart)",
    ),
    "anomalies_window": (
        "pft_internals_counter_anomalies_total - pft_internals_counter_anomalies_total offset 1m",
        "count",
        "counter anomalies per sample (rule PFTInternalsCounterAnomaly)",
    ),
}


def die(msg, rc=1):
    print("report_internals: " + msg, file=sys.stderr)
    sys.exit(rc)


def fetch(prom, query, start, end, step, tries=4):
    qs = urllib.parse.urlencode({"query": query, "start": start, "end": end, "step": step})
    url = f"{prom.rstrip('/')}/api/v1/query_range?{qs}"
    for n in range(1, tries + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                doc = json.loads(r.read().decode("utf-8"))
            if doc.get("status") != "success":
                raise ValueError(f"status {doc.get('status')}: {doc.get('error')}")
            return doc["data"]
        except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
            if n == tries:
                die(f"query failed after {tries} tries: {query[:60]}: {e}")
            print(f"retry {n}/{tries - 1} for {query[:60]}: {e}", file=sys.stderr)
            time.sleep(2 * n)
    return None


def cmd_capture(a):
    if not a.start < a.end or a.step < 1:
        die("want --start < --end and --step >= 1", 3)
    cap = {"window": {"start": a.start, "end": a.end, "step": a.step}, "queries": {}}
    for name, (q, _unit, _desc) in QUERIES.items():
        cap["queries"][name] = {"query": q, "data": fetch(a.prom, q, a.start, a.end, a.step)}
        n = sum(len(s.get("values", [])) for s in cap["queries"][name]["data"].get("result", []))
        print(f"{name}: {len(cap['queries'][name]['data'].get('result', []))} series, {n} samples")
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cap, f, sort_keys=True, separators=(",", ":"))
        f.write("\n")
    os.replace(tmp, a.out)
    print(f"wrote {a.out}")
    return 0


def nearest_rank(sorted_vals, q):
    return sorted_vals[max(0, math.ceil(q * len(sorted_vals)) - 1)]


def fmt(v):
    if v == 0:
        return "0"
    if abs(v) >= 1000:
        return f"{v:.0f}"
    return f"{v:.4g}"


def summarize(cap):
    w = cap["window"]
    expected = (w["end"] - w["start"]) // w["step"] + 1
    rows = []
    for name, (q, unit, desc) in QUERIES.items():
        entry = cap["queries"].get(name)
        if entry is None or entry.get("query") != q:
            die(
                f"capture has no answer for {name} with the current query (re-capture or check out the capture's commit)"
            )
        for s in sorted(entry["data"].get("result", []), key=lambda s: s["metric"].get("container", "")):
            vals = []
            for _t, v in s.get("values", []):
                x = float(v)
                if math.isfinite(x):
                    vals.append(x)
            vals.sort()
            row = {
                "query": name,
                "container": s["metric"].get("container", "-"),
                "unit": unit,
                "description": desc,
                "samples": len(vals),
                "coverage_pct": round(100.0 * len(vals) / expected, 2),
            }
            if vals:
                row.update(
                    min=vals[0], p50=nearest_rank(vals, 0.5), p95=nearest_rank(vals, 0.95), max=vals[-1]
                )  # fmt: skip
            rows.append(row)
    return {"window": w, "expected_samples": expected, "rows": rows}


def cmd_build(a):
    with open(a.capture, "rb") as f:
        raw = f.read()
    cap = json.loads(raw)
    rep = summarize(cap)
    rep["capture_sha256"] = hashlib.sha256(raw).hexdigest()
    w = rep["window"]
    t0 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(w["start"]))
    t1 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(w["end"]))
    md = [
        "# pft-internals two-host report",
        "",
        (
            f"Window {t0} .. {t1} ({(w['end'] - w['start']) / 3600:.2f} h), step {w['step']} s, "
            f"{rep['expected_samples']} expected samples per series."
        ),
        f"Built offline from the query capture (sha256 `{rep['capture_sha256']}`) by `report_internals.py build`;",
        "every query string is in the capture. Percentiles are nearest-rank over the finite samples.",
        "",
        "| query | container | unit | samples | coverage % | min | p50 | p95 | max |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rep["rows"]:
        vals = [fmt(r[k]) if k in r else "-" for k in ("min", "p50", "p95", "max")]
        md.append(
            f"| {r['query']} | {r['container']} | {r['unit']} | {r['samples']} | {r['coverage_pct']:.2f} | "
            + " | ".join(vals)
            + " |"
        )
    md += ["", "## Queries", ""]
    for name, (q, unit, desc) in QUERIES.items():
        md.append(f"- `{name}` ({unit}): {desc}. `{q}`")
    md.append("")
    with open(a.md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    with open(a.json, "w", encoding="utf-8") as f:
        json.dump(rep, f, sort_keys=True, indent=1)
        f.write("\n")
    print(f"wrote {a.md} and {a.json} ({len(rep['rows'])} rows)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--prom", required=True)
    c.add_argument("--start", type=int, required=True)
    c.add_argument("--end", type=int, required=True)
    c.add_argument("--step", type=int, default=60)
    c.add_argument("--out", required=True)
    b = sub.add_parser("build")
    b.add_argument("capture")
    b.add_argument("--md", required=True)
    b.add_argument("--json", required=True)
    a = ap.parse_args()
    return cmd_capture(a) if a.cmd == "capture" else cmd_build(a)


if __name__ == "__main__":
    sys.exit(main())
