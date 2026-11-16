#!/usr/bin/env python3
"""Threshold calibration for internals.rules.yml from 30-second admin samples (stdlib only).

reduce RAW.jsonl > data/calibration-validator.jsonl
    RAW lines are {"ts": EPOCH, "gc": <get_counts answer>, "si": <server_info counters=true answer>} (pretty JSON
    may span lines). Keeps only the fields the rules use, so no host id, key or port reaches the repo.
stats data/calibration-validator.jsonl
    windowed values the rules evaluate (5, 10, 15 min): mean NodeStore read ms, NodeStore hit ratio, CachedView hit
    ratio and lookups/s, plus max job backlog and max job peak.
reduce-jobq RAW.jsonl > data/calibration-validator-jobq.jsonl
    keeps only server_info uptime and the job_queue / rpc counters (all numeric).
monotonic data/calibration-validator-jobq.jsonl
    every job_queue / rpc counter that went DOWN between consecutive samples while uptime went up.
"""

import itertools
import json
import sys

GC = ("node_reads_total", "node_reads_hit", "node_reads_duration_us", "CachedView::hit", "CachedView::miss")


def raw_rows(path):
    with open(path, encoding="utf-8") as f:
        s = f.read()
    dec, i, rows = json.JSONDecoder(), 0, []
    while True:
        while i < len(s) and s[i].isspace():
            i += 1
        if i >= len(s):
            return rows
        o, i = dec.raw_decode(s, i)
        rows.append(o)


def reduce(path):
    for r in raw_rows(path):
        if not r.get("gc") or not r.get("si"):
            print(json.dumps({"ts": r["ts"], "missing": True}))
            continue
        g, info = r["gc"]["result"], r["si"]["result"]["info"]
        jq = info["counters"]["job_queue"]
        out = {
            "ts": r["ts"],
            "gc": {k: int(g[k]) for k in GC},
            "job_waiting": sum(int(v["queued"]) - int(v["started"]) for k, v in jq.items() if k != "total"),
            "job_peak_ms": max((e.get("peak_time", 0) for e in info["load"]["job_types"]), default=0),
        }
        print(json.dumps(out, sort_keys=True))


def reduce_jobq(path):
    for r in raw_rows(path):
        if not r.get("si"):
            continue
        info = r["si"]["result"]["info"]
        c = info["counters"]
        out = {
            "ts": r["ts"],
            "uptime": int(info["uptime"]),
            "job_queue": {k: {f: int(x) for f, x in v.items()} for k, v in c["job_queue"].items()},
            "rpc": {k: {f: int(x) for f, x in v.items()} for k, v in c["rpc"].items()},
        }
        print(json.dumps(out, sort_keys=True))


def monotonic(path):
    with open(path, encoding="utf-8") as f:
        rows = [json.loads(ln) for ln in f if ln.strip()]
    hits, intervals = [], set()
    for a, b in itertools.pairwise(rows):
        if b["uptime"] < a["uptime"]:
            continue  # restart
        for grp in ("job_queue", "rpc"):
            for name, v in b[grp].items():
                for fld, x in v.items():
                    old = a[grp].get(name, {}).get(fld)
                    if old is not None and x < old:
                        hits.append((b["ts"], grp, name, fld, old, x))
                        intervals.add(b["ts"])
    for ts, grp, name, fld, old, x in hits:
        print(f"{ts} {grp}.{name}.{fld} {old} -> {x} (-{old - x})")
    fields = sorted({f"{g}.*.{fl}" for _, g, _, fl, _, _ in hits})
    names = sorted({n for _, _, n, _, _, _ in hits})
    print(
        f"decreases {len(hits)} in {len(intervals)} of {len(rows) - 1} intervals; fields {fields}; {len(names)} names"
    )


def stats(path):
    with open(path, encoding="utf-8") as f:
        rows = [json.loads(ln) for ln in f if ln.strip()]
    rows = [r for r in rows if not r.get("missing")]
    print(f"samples {len(rows)}, {rows[0]['ts']} .. {rows[-1]['ts']} ({(rows[-1]['ts'] - rows[0]['ts']) / 60:.1f} min)")
    for w in (10, 20, 30):  # 30 s samples: 5, 10, 15 min windows
        ms, hr, cv, lk, rs = [], [], [], [], []
        for i in range(w, len(rows)):
            a, b = rows[i - w]["gc"], rows[i]["gc"]
            dt = rows[i]["ts"] - rows[i - w]["ts"]
            dr = b["node_reads_total"] - a["node_reads_total"]
            rs.append(dr / dt)
            ms.append((b["node_reads_duration_us"] - a["node_reads_duration_us"]) / dr / 1000)
            hr.append((b["node_reads_hit"] - a["node_reads_hit"]) / dr)
            h, m = b["CachedView::hit"] - a["CachedView::hit"], b["CachedView::miss"] - a["CachedView::miss"]
            cv.append(h / (h + m))
            lk.append((h + m) / dt)
        if ms:
            print(
                f"window {w // 2:>2} min: nodestore read ms {min(ms):.3f}..{max(ms):.3f}  reads/s {min(rs):.2f}..{max(rs):.2f}  "
                f"nodestore hit {min(hr):.3f}..{max(hr):.3f}  cachedview hit {min(cv):.3f}..{max(cv):.3f}  "
                f"cachedview lookups/s {min(lk):.2f}..{max(lk):.2f}"
            )
    print(
        f"job_waiting max {max(r['job_waiting'] for r in rows)}, job peak max {max(r['job_peak_ms'] for r in rows)} ms"
    )


if __name__ == "__main__":
    {"reduce": reduce, "stats": stats, "reduce-jobq": reduce_jobq, "monotonic": monotonic}[sys.argv[1]](sys.argv[2])
