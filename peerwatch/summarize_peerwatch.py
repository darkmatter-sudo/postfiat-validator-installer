#!/usr/bin/env python3
"""Summarize pft-peerwatch history files (history-<container>.jsonl) over a time window, as Markdown or JSON.

History lines carry counts, ratios and link tags only (no address or public key), so both the history and this
summary can be published. Per container: samples and coverage (expected one a minute), re-baselines, minutes per grade
of every check, joins/leaves, latency, version mix, outbound diversity, ledger agreement and fixed-link downtime.

The collector's churn gauge (churn_joins/churn_leaves) is a rolling CHURN_WINDOW_MIN window, so rows near --from can
carry events from before the range. The summary therefore also recomputes the same window from in-range joins/leaves
only (max_in_range_churn_window_events); --churn-window-min must match the collector's CHURN_WINDOW_MIN.

Usage: summarize_peerwatch.py [--from EPOCH] [--to EPOCH] [--churn-window-min N] [--json] history-postfiatd.jsonl [...]
"""

import argparse
import itertools
import json
import os
import statistics
import sys

CHECKS = ("count", "churn", "latency", "versions", "direction", "diversity", "ledgers", "fixed")


def load(path, lo, hi):
    rows, bad = [], 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if not isinstance(r, dict) or not isinstance(r.get("ts"), int):
                bad += 1
                continue
            if (lo is None or r["ts"] >= lo) and (hi is None or r["ts"] <= hi):
                rows.append(r)
    rows.sort(key=lambda r: r["ts"])
    return rows, bad


def q(values, p):
    s = sorted(values)
    return s[max(1, -(-p * len(s) // 100)) - 1] if s else None


def in_range_churn(rows, window_s):
    ev = [(r["ts"], r.get("joins", 0) + r.get("leaves", 0)) for r in rows]
    return max((sum(n for t, n in ev if 0 <= ts - t <= window_s) for ts, _ in ev), default=0)


def summarize(name, rows, bad, lo, hi, churn_window_min=60):
    out = {"container": name, "samples": len(rows), "unparsed_lines": bad}
    if not rows:
        return out
    t0, t1 = (lo if lo is not None else rows[0]["ts"]), (hi if hi is not None else rows[-1]["ts"])
    expected = (t1 - t0) // 60 + 1
    gaps = [b["ts"] - a["ts"] for a, b in itertools.pairwise(rows) if b["ts"] - a["ts"] > 90]
    out.update(
        first=rows[0]["ts"],
        last=rows[-1]["ts"],
        expected_samples=expected,
        coverage=round(len(rows) / expected, 4) if expected else None,
        gaps_over_90s=len(gaps),
        longest_gap_s=max(gaps) if gaps else 0,
        rebaselines=sum(1 for r in rows if r.get("gap")),
    )
    grades = {}
    for c in CHECKS:
        g = {"PASS": 0, "WARN": 0, "FAIL": 0}
        for r in rows:
            v = (r.get("checks") or {}).get(c)
            if v in g:
                g[v] += 1
        grades[c] = g
    out["check_samples"] = grades
    out["status_samples"] = {k: sum(1 for r in rows if r.get("status") == k) for k in ("PASS", "WARN", "FAIL")}
    out["joins"] = sum(r.get("joins", 0) for r in rows)
    out["leaves"] = sum(r.get("leaves", 0) for r in rows)
    out["max_in_range_churn_window_events"] = in_range_churn(rows, churn_window_min * 60)
    out["max_churn_window_events"] = max(r.get("churn_joins", 0) + r.get("churn_leaves", 0) for r in rows)
    out["max_flapping_peers"] = max(r.get("churn_flapping_peers", 0) for r in rows)
    peers = [r["peers"] for r in rows if isinstance(r.get("peers"), int)]
    out["peers_min_median_max"] = [min(peers), statistics.median(peers), max(peers)] if peers else None
    ob = [r["peers_outbound"] for r in rows if "peers_outbound" in r]
    out["outbound_min_median_max"] = [min(ob), statistics.median(ob), max(ob)] if ob else None
    p95 = [r["latency_p95_ms"] for r in rows if "latency_p95_ms" in r]
    p50 = [r["latency_p50_ms"] for r in rows if "latency_p50_ms" in r]
    out["latency_p50_median_ms"] = statistics.median(p50) if p50 else None
    out["latency_p95_median_max_ms"] = [statistics.median(p95), max(p95)] if p95 else None
    out["latency_p95_p99_of_samples_ms"] = q(p95, 99) if p95 else None
    older = [r.get("version_older", 0) for r in rows]
    out["version_older_min_max"] = [min(older), max(older)]
    out["version_newer_max"] = max(r.get("version_newer", 0) for r in rows)
    p16 = [r["outbound_prefix16"] for r in rows if "outbound_prefix16" in r]
    share = [r["outbound_prefix16_max_share"] for r in rows if "outbound_prefix16_max_share" in r]
    out["outbound_prefix16_min"] = min(p16) if p16 else None
    out["outbound_prefix16_max_share_max"] = max(share) if share else None
    agree = [r["ledger_agree_ratio"] for r in rows if "ledger_agree_ratio" in r]
    out["ledger_agree_min_median"] = [min(agree), statistics.median(agree)] if agree else None
    out["network_mismatch_max"] = max(r.get("network_mismatch_peers", 0) for r in rows)
    links = {}
    for r in rows:
        for tag, up in (r.get("links") or {}).items():
            d = links.setdefault(tag, {"samples": 0, "down_samples": 0})
            d["samples"] += 1
            d["down_samples"] += int(up == 0)
    out["links"] = links
    return out


def md(sums, lo, hi):
    lines = [
        f"# pft-peerwatch summary ({lo if lo is not None else 'start'} .. {hi if hi is not None else 'end'}, epoch seconds)",
        "",
    ]
    for s in sums:
        lines.append(f"## {s['container']}")
        lines.append("")
        if not s["samples"]:
            lines.append("no samples in the window")
            continue
        lines += [
            "| Item | Value |",
            "|------|-------|",
            f"| samples / expected (1 a minute) | {s['samples']} / {s['expected_samples']} ({100 * s['coverage']:.2f} %) |",
            f"| gaps > 90 s / longest | {s['gaps_over_90s']} / {s['longest_gap_s']} s |",
            f"| re-baselines (first sample or gap) | {s['rebaselines']} |",
            f"| unparsed history lines | {s['unparsed_lines']} |",
            f"| overall status samples PASS / WARN / FAIL | {s['status_samples']['PASS']} / {s['status_samples']['WARN']} / {s['status_samples']['FAIL']} |",
            f"| peers min / median / max | {' / '.join(str(x) for x in s['peers_min_median_max'])} |",
            f"| outbound min / median / max | {' / '.join(str(x) for x in s['outbound_min_median_max'])} |",
            f"| joins / leaves (by public key) | {s['joins']} / {s['leaves']} |",
            f"| max join+leave events in one churn window, in-range events only / max flapping peers | {s['max_in_range_churn_window_events']} / {s['max_flapping_peers']} |",
            f"| max collector churn gauge (rolling window, can include events before the range) | {s['max_churn_window_events']} |",
            f"| latency p50 (median of samples) | {s['latency_p50_median_ms']} ms |",
            f"| latency p95: median / max / p99 of samples | {s['latency_p95_median_max_ms'][0]} / {s['latency_p95_median_max_ms'][1]} / {s['latency_p95_p99_of_samples_ms']} ms |"
            if s["latency_p95_median_max_ms"]
            else "| latency | no samples |",
            f"| peers on an older build min / max; newer max | {s['version_older_min_max'][0]} / {s['version_older_min_max'][1]}; {s['version_newer_max']} |",
            f"| outbound distinct /16 min; largest /16 share max | {s['outbound_prefix16_min']}; {s['outbound_prefix16_max_share_max']} |",
            f"| ledger agreement min / median | {s['ledger_agree_min_median'][0]} / {s['ledger_agree_min_median'][1]} |",
            f"| peers on another network_id (max) | {s['network_mismatch_max']} |",
        ]
        for tag, d in sorted(s["links"].items()):
            lines.append(f"| fixed link `{tag}` down samples / samples | {d['down_samples']} / {d['samples']} |")
        lines += ["", "| Check | PASS | WARN | FAIL |", "|-------|------|------|------|"]
        for c in CHECKS:
            g = s["check_samples"][c]
            lines.append(f"| {c} | {g['PASS']} | {g['WARN']} | {g['FAIL']} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="lo", type=int)
    ap.add_argument("--to", dest="hi", type=int)
    ap.add_argument("--churn-window-min", type=int, default=60)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    sums = []
    for f in a.files:
        name = os.path.basename(f).removeprefix("history-").removesuffix(".jsonl")
        rows, bad = load(f, a.lo, a.hi)
        sums.append(summarize(name, rows, bad, a.lo, a.hi, a.churn_window_min))
    sys.stdout.write(json.dumps(sums, indent=1, sort_keys=True) + "\n" if a.json else md(sums, a.lo, a.hi))
    return 0


if __name__ == "__main__":
    sys.exit(main())
