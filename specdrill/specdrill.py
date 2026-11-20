#!/usr/bin/env python3
"""specdrill helper: per-cell metrics, verdicts and the min/safe spec report for pft-specdrill.sh.

Stdlib only. Every output is a pure function of the committed inputs (cell meta + samples), so `report` run
offline in a fresh clone must rebuild the committed cells.json / cells.csv / REPORT.md byte for byte.

Inputs per cell directory CELL/ (written by pft-specdrill.sh run-cell):
  meta.json      {"cell", "axis", "cpus", "mem_mib", "io_bps", "start", "full_deadline_s", "window_s", "end",
                  "abort": null|"reason", "oom_killed": bool, "restarts": int, "peak_rss_bytes": int|null}
  samples.jsonl  one object per poll: {"t", "state", "seq", "close", "ref_seq", "peers", "live_state", "live_lag"}
                 seq/close = the throwaway node's validated ledger index / close time (unix s), ref_seq = the
                 reference (public RPC) validated index at the same poll, live_* = the live node's state and lag.

Usage: specdrill.py summarize CELL_DIR            -> CELL_DIR/cell.json (prints it)
       specdrill.py report CELLS_ROOT OUT_DIR      -> OUT_DIR/cells.json, cells.csv, REPORT.md
       specdrill.py live-gate SAMPLES.jsonl MAX_LAG POLLS   exit 1 if the last POLLS samples all breach
"""

import csv
import io
import itertools
import json
import math
import os
import sys

# A cell PASSES when the node reached full within full_deadline_s, never got OOM-killed or restarted, was not
# aborted, and its 20-minute lag p95 stayed at or below LAG_P95_MAX ledgers behind the reference.
LAG_P95_MAX = 2
MIB = 1024 * 1024
AXES = ("cpu", "mem", "io")
AXIS_FIELD = {"cpu": "cpus", "mem": "mem_mib", "io": "io_bps"}


def load_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def percentile(values, p):
    """Nearest-rank percentile (hand-computable): the ceil(p/100 * n)-th smallest value, n >= 1."""
    if not values:
        return None
    s = sorted(values)
    k = max(1, math.ceil(p / 100.0 * len(s)))
    return s[k - 1]


def close_jitter(samples):
    """Population stddev (s) of close-time intervals between consecutive DISTINCT validated ledgers seen by the
    cell, divided by the ledger-index step so a skipped poll does not count as one long interval."""
    seen = []
    for s in samples:
        if s.get("seq") is None or s.get("close") is None:
            continue
        if seen and s["seq"] <= seen[-1][0]:
            continue
        seen.append((s["seq"], s["close"]))
    iv = [(c2 - c1) / (q2 - q1) for (q1, c1), (q2, c2) in itertools.pairwise(seen)]
    if len(iv) < 2:
        return None
    m = sum(iv) / len(iv)
    return round(math.sqrt(sum((x - m) ** 2 for x in iv) / len(iv)), 3)


def summarize(meta, samples):
    start = meta["start"]
    full_t = next((s["t"] for s in samples if s.get("state") == "full"), None)
    ttf = None if full_t is None else full_t - start
    win = [s for s in samples if full_t is not None and full_t <= s["t"] <= full_t + meta["window_s"]]
    lags = [max(0, s["ref_seq"] - s["seq"]) for s in win if s.get("seq") is not None and s.get("ref_seq") is not None]
    peers = [s["peers"] for s in win if s.get("peers") is not None]
    reasons = []
    if meta.get("abort"):
        reasons.append("aborted:" + meta["abort"])
    if meta.get("oom_killed"):
        reasons.append("oom_killed")
    if meta.get("restarts", 0) > 0:
        reasons.append(f"restarts={meta['restarts']}")
    if ttf is None or ttf > meta["full_deadline_s"]:
        reasons.append("never_full" if ttf is None else "slow_full")
    elif not lags:
        reasons.append("no_window_samples")
    elif percentile(lags, 95) > LAG_P95_MAX:
        reasons.append(f"lag_p95>{LAG_P95_MAX}")
    rss = meta.get("peak_rss_bytes")
    return {
        "cell": meta["cell"],
        "axis": meta["axis"],
        "cpus": meta["cpus"],
        "mem_mib": meta["mem_mib"],
        "io_bps": meta["io_bps"],
        "time_to_full_s": ttf,
        "window_samples": len(lags),
        "lag_p50": percentile(lags, 50),
        "lag_p95": percentile(lags, 95),
        "lag_max": max(lags) if lags else None,
        "close_jitter_s": close_jitter(win),
        "peers_min": min(peers) if peers else None,
        "peers_p50": percentile(peers, 50),
        "oom_killed": bool(meta.get("oom_killed")),
        "restarts": meta.get("restarts", 0),
        "peak_rss_mib": None if rss is None else round(rss / MIB, 1),
        "live_full_all": all(s.get("live_state") == "full" for s in samples),
        "live_lag_max": max((s.get("live_lag") or 0) for s in samples) if samples else None,
        "verdict": "FAIL" if reasons else "PASS",
        "reasons": reasons,
    }


def cmd_summarize(cell_dir):
    with open(os.path.join(cell_dir, "meta.json")) as f:
        meta = json.load(f)
    cell = summarize(meta, load_jsonl(os.path.join(cell_dir, "samples.jsonl")))
    text = json.dumps(cell, indent=1, sort_keys=True) + "\n"
    with open(os.path.join(cell_dir, "cell.json"), "w") as f:
        f.write(text)
    sys.stdout.write(text)
    return 0


def axis_spec(cells, axis):
    """minimum = smallest passing value on the axis whose every larger tested value also passed (a pass below a
    failure is not trusted); safe = the next tested value above the minimum, else the minimum itself."""
    field = AXIS_FIELD[axis]
    rows = sorted((c for c in cells if c["axis"] == axis), key=lambda c: c[field])
    if not rows:
        return None
    minimum = None
    for c in reversed(rows):
        if c["verdict"] != "PASS":
            break
        minimum = c
    if minimum is None:
        return {"axis": axis, "minimum": None, "safe": None, "failing": [r["cell"] for r in rows]}
    above = [r for r in rows if r[field] > minimum[field]]
    safe = above[0] if above else minimum
    return {
        "axis": axis,
        "minimum": minimum[field],
        "minimum_cell": minimum["cell"],
        "safe": safe[field],
        "safe_cell": safe["cell"],
        "failing": [r["cell"] for r in rows if r["verdict"] != "PASS"],
    }


CSV_COLS = ("cell", "axis", "cpus", "mem_mib", "io_bps", "verdict", "reasons", "time_to_full_s", "window_samples",
            "lag_p50", "lag_p95", "lag_max", "close_jitter_s", "peers_min", "peers_p50", "oom_killed", "restarts",
            "peak_rss_mib", "live_full_all", "live_lag_max")


def fmt(v):
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        return ";".join(v) or "-"
    return str(v)


def fmt_io(bps):
    return "unlimited" if not bps else f"{bps / 1e6:g} MB/s"


def render_report(cells, specs):
    by = {c["cell"]: c for c in cells}
    out = ["# specdrill report: measured postfiatd 1.0.9 testnet node resource floors", "",
           "Generated by `specdrill.py report` from the committed per-cell data; rebuild offline to check.",
           (f"PASS = full within the cell deadline, no OOM kill or restart, not aborted, 20-min lag p95 <= {LAG_P95_MAX}"
           " ledgers."), "", "## Recommended specification", "",
           "| axis | minimum (measured) | safe | failing cells |", "|---|---|---|---|"]
    unit = {"cpu": lambda v: f"{v:g} vCPU", "mem": lambda v: f"{v} MiB", "io": fmt_io}
    for s in specs:
        if s["minimum"] is None:
            out.append(f"| {s['axis']} | none passed | - | {', '.join(s['failing'])} |")
            continue
        u = unit[s["axis"]]
        failing = ", ".join(f"`{f}` ({';'.join(by[f]['reasons'])})" for f in s["failing"]) or "-"
        out.append(f"| {s['axis']} | {u(s['minimum'])} (`{s['minimum_cell']}`) | {u(s['safe'])} (`{s['safe_cell']}`)"
                   f" | {failing} |")
    out += ["", "## Cells", "", ("| cell | cpus | mem MiB | io | verdict | time to full s | lag p50/p95/max | "
                                 "jitter s | peers min | peak RSS MiB | reasons |"), "|---|---|---|---|---|---|---|---|---|---|---|"]
    for c in cells:
        out.append(f"| {c['cell']} | {c['cpus']:g} | {c['mem_mib']} | {fmt_io(c['io_bps'])} | {c['verdict']}"
                   f" | {fmt(c['time_to_full_s'])} | {fmt(c['lag_p50'])}/{fmt(c['lag_p95'])}/{fmt(c['lag_max'])}"
                   f" | {fmt(c['close_jitter_s'])} | {fmt(c['peers_min'])} | {fmt(c['peak_rss_mib'])}"
                   f" | {fmt(c['reasons'])} |")
    live_ok = all(c["live_full_all"] for c in cells)
    live_max = max((c["live_lag_max"] or 0) for c in cells) if cells else None
    out += ["", "## Live node during the drill", "",
            f"live validator full at every poll: {fmt(live_ok)}; max live lag seen: {fmt(live_max)} ledgers.", ""]
    return "\n".join(out)


def cmd_report(root, out_dir):
    cells = []
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if os.path.isfile(os.path.join(d, "meta.json")):
            with open(os.path.join(d, "meta.json")) as f:
                meta = json.load(f)
            cells.append(summarize(meta, load_jsonl(os.path.join(d, "samples.jsonl"))))
    if not cells:
        sys.stderr.write(f"specdrill: no cells under {root}\n")
        return 2
    specs = [s for s in (axis_spec(cells, a) for a in AXES) if s]
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "cells.json"), "w") as f:
        f.write(json.dumps({"cells": cells, "specs": specs}, indent=1, sort_keys=True) + "\n")
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLS)
    for c in cells:
        w.writerow([fmt(c[k]) for k in CSV_COLS])
    with open(os.path.join(out_dir, "cells.csv"), "w") as f:
        f.write(buf.getvalue())
    with open(os.path.join(out_dir, "REPORT.md"), "w") as f:
        f.write(render_report(cells, specs))
    npass = sum(c["verdict"] == "PASS" for c in cells)
    print(f"report: {len(cells)} cells, {npass} PASS -> {out_dir}")
    return 0


def cmd_live_gate(path, max_lag, polls):
    """Abort signal for the runner: exit 1 when each of the last POLLS samples has the live node not full or its
    lag above MAX_LAG; exit 0 otherwise (including fewer than POLLS samples)."""
    s = load_jsonl(path)[-polls:]
    bad = [x for x in s if x.get("live_state") != "full" or (x.get("live_lag") or 0) > max_lag]
    if len(s) == polls and len(bad) == polls:
        print("live_lag")
        return 1
    return 0


def main(argv):
    if len(argv) == 3 and argv[1] == "summarize":
        return cmd_summarize(argv[2])
    if len(argv) == 4 and argv[1] == "report":
        return cmd_report(argv[2], argv[3])
    if len(argv) == 5 and argv[1] == "live-gate":
        return cmd_live_gate(argv[2], int(argv[3]), int(argv[4]))
    sys.stderr.write(__doc__)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
