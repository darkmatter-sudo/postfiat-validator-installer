#!/usr/bin/env python3
"""Median / p95 of |offset| and delay from offset_probe.py CSVs.

  offset_stats.py FILE.csv [FILE.csv ...]

Per file: samples ok/total, then per server and for the per-round median across
servers (the robust estimate of the local clock error). p95 = nearest-rank.
"""
import csv
import math
import statistics
import sys
from collections import defaultdict


def p95(xs):
    s = sorted(xs)
    return s[max(0, math.ceil(0.95 * len(s)) - 1)]


def main(paths):
    for p in paths:
        rows = list(csv.DictReader(open(p)))
        ok = [r for r in rows if r["ok"] == "1"]
        print("%s: %d rows, %d ok, %d failed, %s .. %s" % (
            p, len(rows), len(ok), len(rows) - len(ok),
            rows[0]["utc"] if rows else "-", rows[-1]["utc"] if rows else "-"))
        by_srv, by_round = defaultdict(list), defaultdict(list)
        for r in ok:
            by_srv[r["server"]].append((float(r["offset_ms"]), float(r["delay_ms"])))
            by_round[r["utc"][:16]].append(float(r["offset_ms"]))
        for srv, v in sorted(by_srv.items()):
            a = [abs(o) for o, _ in v]
            d = [x for _, x in v]
            print("  %-22s n=%-4d |offset| median %.3f ms p95 %.3f ms max %.3f ms | delay median %.3f ms" % (
                srv, len(v), statistics.median(a), p95(a), max(a), statistics.median(d)))
        rm = [abs(statistics.median(v)) for v in by_round.values()]
        if rm:
            print("  %-22s n=%-4d |offset| median %.3f ms p95 %.3f ms max %.3f ms" % (
                "round-median", len(rm), statistics.median(rm), p95(rm), max(rm)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
