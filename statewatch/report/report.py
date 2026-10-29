#!/usr/bin/env python3
"""report.py: baseline report from pft-statewatch history files (one JSON line per 1-minute collection).

Usage: python3 report.py [--threshold-io-ms 50] [--threshold-disc-per-h 30] [--json OUT.json] HISTORY.jsonl [...]

For each history file (one container) it prints a Markdown section with:
  coverage    samples, first/last time, gaps (> 90 s between collections), restarts (uptime went down)
  time share  per operating mode, from the increase of state_accounting duration_us between samples
  transitions per mode and per hour, full exits (pft_statewatch_full_exits_total) per hour
  io latency  distribution of io_latency_ms (min/p50/p90/p99/max, samples above the alert threshold)
  disconnects peer_disconnects increase per clock hour (max, mean), peer_disconnects_resources, jq overflow
  thresholds  each alert threshold next to the baseline value it is compared with
Counter increases are reset-aware: when postfiatd restarted between two samples (uptime went down) the new value of
every counter is the increase since the restart; otherwise a counter that went down counts its new value (Prometheus
increase() semantics). The uptime check is stricter than Prometheus, which cannot see a reset when a counter comes
back at its old value (after a start disconnected/connected are 2 again). Stdlib only; reads nothing but the files.
"""
import argparse
import json
import math
import sys
from datetime import datetime, timezone

MODES = ("disconnected", "connected", "syncing", "tracking", "full")
GAP_S = 90


def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                sys.exit("%s:%d: not JSON" % (path, n))
    rows.sort(key=lambda r: r["ts"])
    if len(rows) < 2:
        sys.exit("%s: need at least 2 samples" % path)
    return rows


def inc(prev, cur, restarted=False):
    """Reset-aware increase of a counter between two samples."""
    if restarted:
        return cur
    return cur - prev if cur >= prev else cur


def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    k = max(0, min(len(sorted_vals) - 1, int(math.ceil(q * len(sorted_vals))) - 1))  # nearest-rank
    return sorted_vals[k]


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def analyse(rows, io_thr, disc_thr):
    containers = sorted({r["container"] for r in rows})
    if len(containers) != 1:
        sys.exit("one container per history file, got %s" % containers)
    gaps, restarts = [], []
    dur = dict.fromkeys(MODES, 0)
    trans = dict.fromkeys(MODES, 0)
    full_exits = jq = disc = disc_res = 0
    hourly = {}
    for a, b in zip(rows[:-1], rows[1:], strict=True):
        if b["ts"] - a["ts"] > GAP_S:
            gaps.append((a["ts"], b["ts"]))
        rs = b["uptime"] < a["uptime"]
        if rs:
            restarts.append(b["ts"])
        for m in MODES:
            dur[m] += inc(a["acct"][m][0], b["acct"][m][0], rs)
            trans[m] += inc(a["acct"][m][1], b["acct"][m][1], rs)
        full_exits += inc(a["full_exits"], b["full_exits"], rs)
        jq += inc(a["jq_trans_overflow"], b["jq_trans_overflow"], rs)
        d = inc(a["peer_disconnects"], b["peer_disconnects"], rs)
        disc += d
        disc_res += inc(a["peer_disconnects_resources"], b["peer_disconnects_resources"], rs)
        hour = b["ts"] - b["ts"] % 3600
        hourly[hour] = hourly.get(hour, 0) + d
    span = rows[-1]["ts"] - rows[0]["ts"]
    hours = span / 3600.0
    # only full clock hours inside the window count for the hourly max/mean (partial edge hours would read low)
    first_full = rows[0]["ts"] if rows[0]["ts"] % 3600 == 0 else rows[0]["ts"] - rows[0]["ts"] % 3600 + 3600
    full_hours = {h: v for h, v in hourly.items() if h >= first_full and h + 3600 <= rows[-1]["ts"]}
    io = sorted(r["io_latency_ms"] for r in rows)
    total_dur = sum(dur.values()) or 1
    return {
        "container": containers[0], "samples": len(rows), "first": iso(rows[0]["ts"]), "last": iso(rows[-1]["ts"]),
        "span_h": round(hours, 3), "gaps": [(iso(x), iso(y), y - x) for x, y in gaps],
        "restarts": [iso(t) for t in restarts],
        "time_share_pct": {m: round(100.0 * dur[m] / total_dur, 4) for m in MODES},
        "time_s": {m: round(dur[m] / 1e6, 3) for m in MODES},
        "transitions": trans, "transitions_per_h": round(sum(trans.values()) / hours, 3) if hours else None,
        "full_exits": full_exits, "full_exits_per_h": round(full_exits / hours, 3) if hours else None,
        "io_latency_ms": {"min": io[0], "p50": pct(io, 0.5), "p90": pct(io, 0.9), "p99": pct(io, 0.99),
                          "max": io[-1], "above_threshold": sum(1 for v in io if v > io_thr),
                          "values": {str(v): io.count(v) for v in sorted(set(io))}},
        "jq_trans_overflow": jq, "peer_disconnects": disc, "peer_disconnects_resources": disc_res,
        "disconnects_per_h": round(disc / hours, 3) if hours else None,
        "disconnects_full_hours": {iso(h): v for h, v in sorted(full_hours.items())},
        "disconnects_hourly_max": max(full_hours.values()) if full_hours else None,
        "thresholds": {"io_latency_ms": io_thr, "disconnects_per_h": disc_thr, "flapping_exits_per_h": 3,
                       "jq_overflow_per_15m": 0},
    }


def markdown(s):
    o = ["### %s" % s["container"], ""]
    o.append("Window %s .. %s (%.2f h), %d samples, %d gaps > %d s, %d restarts."
             % (s["first"], s["last"], s["span_h"], s["samples"], len(s["gaps"]), GAP_S, len(s["restarts"])))
    for g in s["gaps"]:
        o.append("- gap %s .. %s (%d s)" % g)
    for r in s["restarts"]:
        o.append("- restart seen at %s" % r)
    o += ["", "| mode | time share | time (s) | transitions |", "|---|---:|---:|---:|"]
    for m in MODES:
        o.append("| %s | %.4f%% | %.3f | %d |" % (m, s["time_share_pct"][m], s["time_s"][m], s["transitions"][m]))
    io = s["io_latency_ms"]
    o += ["", "- transitions per hour (all modes): %s; full exits: %d (%s per hour)"
          % (s["transitions_per_h"], s["full_exits"], s["full_exits_per_h"]),
          "- io_latency_ms: min %s, p50 %s, p90 %s, p99 %s, max %s; samples above %s ms: %d; value counts %s"
          % (io["min"], io["p50"], io["p90"], io["p99"], io["max"], s["thresholds"]["io_latency_ms"],
             io["above_threshold"], json.dumps(io["values"])),
          "- peer_disconnects: +%d (%s per hour), max in one full clock hour: %s (over %d full clock hours, partial"
          " edge hours excluded); peer_disconnects_resources: +%d"
          % (s["peer_disconnects"], s["disconnects_per_h"], s["disconnects_hourly_max"],
             len(s["disconnects_full_hours"]), s["peer_disconnects_resources"]),
          "- jq_trans_overflow: +%d" % s["jq_trans_overflow"], ""]
    return "\n".join(o)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("history", nargs="+")
    ap.add_argument("--threshold-io-ms", type=float, default=50)
    ap.add_argument("--threshold-disc-per-h", type=float, default=30)
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    stats = [analyse(load(p), a.threshold_io_ms, a.threshold_disc_per_h) for p in a.history]
    for s in stats:
        sys.stdout.write(markdown(s) + "\n")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=1, sort_keys=True)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
