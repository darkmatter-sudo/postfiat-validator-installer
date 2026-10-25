#!/usr/bin/env python3
"""pft-slo-report: Markdown availability/error-budget report for a Post Fiat node from Prometheus.

Reads the raw exporter series with /api/v1/query_range only (never instant queries) and applies the
same SLI as slo.rules.yml at every step:
  good = up == 1 AND pft_up == 1 AND server_state >= full AND validated ledger age < 10s
  maintenance (pft_maint_active == 1, or a window from --maint-history) is excluded from the budget
  steps where Prometheus has no `up` sample at all are "unmeasured" and excluded too (reported).
Because the raw series are used, the report covers all retained history, not only the time since
the recording rules were deployed. Where pft:sli_bad:bool exists, it is cross-checked step by step.

Usage:
  pft_slo_report.py [--prom URL] [--window 30d | --start ISO --end ISO] [--step 15s]
                    [--objective 0.995] [--job postfiat] [--maint-history FILE] [-o report.md]
                    [--record DIR | --replay DIR]
Exit: 0 report written, 1 no data in window, 2 usage/API error.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

STATES = ["disconnected", "connected", "syncing", "tracking", "full", "validating", "proposing"]
MAX_POINTS = 10000  # Prometheus refuses > 11000 points per series; stay below it
AGE_LIMIT = 10.0
DEFAULT_OBJECTIVE = 0.995


def parse_duration(s):
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if not s or s[-1] not in units or not s[:-1].isdigit() or int(s[:-1]) <= 0:
        raise ValueError(f"bad duration {s!r} (use e.g. 15s, 30m, 6h, 30d)")
    return int(s[:-1]) * units[s[-1]]


def parse_time(s):
    if s.isdigit():
        return int(s)
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human(sec):
    sec = round(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        m, sec = divmod(sec, 60)
        return f"{m}m{sec:02d}s"
    h, rem = divmod(sec, 3600)
    return f"{h}h{rem // 60:02d}m"


class Source:
    """Prometheus range-query client with optional record/replay of raw API responses."""

    def __init__(self, prom, record=None, replay=None, timeout=30):
        self.prom, self.record, self.replay, self.timeout = prom.rstrip("/"), record, replay, timeout
        self.calls = 0

    @staticmethod
    def key(query, start, end, step):
        return hashlib.sha256(f"{query}|{start}|{end}|{step}".encode()).hexdigest()[:16]

    def query_range(self, query, start, end, step):
        self.calls += 1
        k = self.key(query, start, end, step)
        if self.replay:
            with open(os.path.join(self.replay, k + ".json")) as f:
                body = json.load(f)["response"]
        else:
            qs = urllib.parse.urlencode({"query": query, "start": start, "end": end, "step": step})
            with urllib.request.urlopen(f"{self.prom}/api/v1/query_range?{qs}", timeout=self.timeout) as r:
                body = json.load(r)
            if self.record:
                os.makedirs(self.record, exist_ok=True)
                with open(os.path.join(self.record, k + ".json"), "w") as f:
                    json.dump({"query": query, "start": start, "end": end, "step": step, "response": body}, f,
                              sort_keys=True)
        if body.get("status") != "success":
            raise RuntimeError("Prometheus error for {}: {}".format(query, body.get("error", body)))
        return body["data"]["result"]

    def series(self, query, start, end, step):
        """{instance: {ts: float}} over [start, end], chunked under the per-query point limit."""
        out = {}
        t = start
        while t <= end:
            t_end = min(end, t + step * (MAX_POINTS - 1))
            for s in self.query_range(query, t, t_end, step):
                d = out.setdefault(s["metric"].get("instance", ""), {})
                for ts, v in s["values"]:
                    d[int(float(ts))] = float(v)
            t = t_end + step
        return out


def load_maint_history(path):
    """pft-maint history.jsonl -> [(start, end)] using ended_at when the window was closed early."""
    spans = []
    with open(path) as f:
        for line in f:
            try:
                j = json.loads(line)
                s, e = int(j["start"]), int(j.get("ended_at") or j["expiry"])
            except (ValueError, KeyError, TypeError):
                continue
            if e > s:
                spans.append((s, min(e, int(j["expiry"]))))
    return spans


def classify(t, comp, maint_spans):
    """-> (kind, cause) where kind in good|bad|maint|nodata."""
    up = comp["up"].get(t)
    if up is None:
        return "nodata", "no Prometheus data"
    if comp["maint"].get(t) == 1 or any(s <= t < e for s, e in maint_spans):
        return "maint", "pft-maint window"
    if up != 1:
        return "bad", "exporter scrape failed"
    if comp["rpc"].get(t) != 1:
        return "bad", "node RPC down"
    st = comp["state"].get(t)
    if st is None or st < 4:
        name = STATES[int(st)] if st is not None and 0 <= st < len(STATES) else "unknown"
        return "bad", f"server_state {name}"
    age = comp["age"].get(t)
    if age is None:
        return "bad", "no validated ledger"
    if age >= AGE_LIMIT:
        return "bad", "validated ledger stale"
    return "good", ""


QUERIES = {
    "up": 'max by (instance) (up{job="%s"})',
    "rpc": 'max by (instance) (pft_up{job="%s"})',
    "state": 'max by (instance) (pft_server_state{job="%s"})',
    "age": 'max by (instance) (pft_validated_ledger_age_seconds{job="%s"})',
    "maint": 'max by (instance) (pft_maint_active{job="%s"})',
    "uptime": 'max by (instance) (pft_uptime_seconds{job="%s"})',
    "rule_bad": 'max by (instance) (pft:sli_bad:bool{job="%s"})',
}


def analyze(src, job, start, end, step, maint_spans):
    data = {k: src.series(q % job, start, end, step) for k, q in QUERIES.items()}
    instances = sorted(data["up"])
    results = []
    for inst in instances:
        comp = {k: data[k].get(inst, {}) for k in data}
        steps = list(range(start, end + 1, step))
        rows = [(t,) + classify(t, comp, maint_spans) for t in steps]
        results.append(summarize(inst, rows, comp, step))
    return results


def summarize(inst, rows, comp, step):
    kinds = Counter(k for _, k, _ in rows)
    intervals, cur = [], None
    for t, kind, cause in rows:
        if kind == "bad":
            if cur and t - cur["end"] == step:
                cur["end"] = t
                cur["causes"][cause] += 1
            else:
                cur = {"start": t, "end": t, "causes": Counter([cause])}
                intervals.append(cur)
        else:  # good, maintenance and unmeasured steps all end a bad interval
            cur = None
    for iv in intervals:
        iv["seconds"] = iv["end"] - iv["start"] + step
        up_before = comp["uptime"].get(iv["start"] - step)
        ups_after = [comp["uptime"][t] for t in sorted(comp["uptime"]) if iv["end"] < t <= iv["end"] + 1800]
        iv["restart"] = bool(ups_after and up_before is not None and ups_after[0] < up_before)
    maint, cur = [], None
    for t, kind, _ in rows:
        if kind == "maint":
            if cur and t - cur[1] == step:
                cur[1] = t
            else:
                cur = [t, t]
                maint.append(cur)
        else:
            cur = None
    agree = disagree = 0
    for t, kind, _ in rows:
        rb = comp["rule_bad"].get(t)
        if rb is None or kind == "nodata":
            continue
        if (rb == 1) == (kind == "bad"):
            agree += 1
        else:
            disagree += 1
    measured = [t for t, kind, _ in rows if kind != "nodata"]
    return {"instance": inst, "kinds": kinds, "first": measured[0] if measured else None,
            "last": measured[-1] if measured else None, "intervals": intervals, "maint": maint,
            "rule_check": (agree, disagree), "step": step}


def render(results, start, end, step, objective, job, maint_source, max_intervals):
    out = ["# Post Fiat node availability SLO report", "",
           f"- Window: {iso(start)} -> {iso(end)} ({human(end - start)}), step {step}s, job `{job}`",
           f"- SLI: good = scrape up AND pft_up = 1 AND server_state >= full AND validated ledger age < {AGE_LIMIT:g}s",
           f"- Objective: {objective * 100:.3f}% (error budget {(1 - objective) * 100:.3f}% of eligible time)",
           f"- Maintenance source: {maint_source}",
           "- Source: Prometheus /api/v1/query_range only (pft-slo-report)", ""]
    for r in results:
        k, s = r["kinds"], step
        eligible = (k["good"] + k["bad"]) * s
        bad = k["bad"] * s
        budget = (1 - objective) * eligible
        sli = 100.0 * k["good"] / (k["good"] + k["bad"]) if eligible else float("nan")
        consumed = 100.0 * bad / budget if budget else float("nan")
        agree, disagree = r["rule_check"]
        out += ["## Instance `{}`".format(r["instance"]), "",
                "| Metric | Value |", "|---|---|",
                f"| SLI (good / eligible) | {sli:.4f}% |",
                f"| Objective met in window | {'yes' if sli >= objective * 100 else 'NO'} |",
                f"| Eligible time | {human(eligible)} |",
                f"| Bad time | {human(bad)} ({k['bad']} steps) |",
                f"| Error budget for window | {human(budget)} |",
                f"| Budget consumed | {consumed:.1f}% |",
                f"| Budget remaining | {100.0 - consumed:.1f}% |",
                f"| Maintenance excluded | {human(k['maint'] * s)} ({len(r['maint'])} window{'' if len(r['maint']) == 1 else 's'}) |",
                f"| Measured span | {iso(r['first'])} -> {iso(r['last'])} |" if r["first"] is not None
                else "| Measured span | none |",
                f"| Unmeasured (no Prometheus data) | {human(k['nodata'] * s)} |",
                "| Recording-rule cross-check (pft:sli_bad:bool) | "
                + (f"{agree} steps agree, {disagree} disagree" if agree + disagree else "rule not present") + " |",
                ""]
        ivs = sorted(r["intervals"], key=lambda i: i["start"])
        out += [f"### Bad intervals ({len(ivs)})", ""]
        if ivs:
            out += ["| Start (UTC) | End (UTC) | Duration | Likely cause |", "|---|---|---|---|"]
            shown = ivs if len(ivs) <= max_intervals else sorted(ivs, key=lambda i: -i["seconds"])[:max_intervals]
            for iv in sorted(shown, key=lambda i: i["start"]):
                cause = ", ".join(f"{c} ({human(n * s)})" for c, n in iv["causes"].most_common())
                if iv["restart"]:
                    cause += "; node restarted (pft_uptime_seconds reset)"
                out.append("| {} | {} | {} | {} |".format(iso(iv["start"]), iso(iv["end"] + s), human(iv["seconds"]),
                                                      cause))
            if len(ivs) > max_intervals:
                out.append("")
                out.append(f"({len(ivs) - max_intervals} shorter intervals omitted; --max-intervals)")
        else:
            out.append("None.")
        out += ["", f"### Maintenance windows excluded ({len(r['maint'])})", ""]
        if r["maint"]:
            out += ["| Start (UTC) | End (UTC) | Duration |", "|---|---|---|"]
            out += [f"| {iso(a)} | {iso(b + s)} | {human(b - a + s)} |" for a, b in r["maint"]]
        else:
            out.append("None.")
        out.append("")
    out += [(f"Step accounting: each step stands for {step}s; a bad interval ends at the last bad step + one step. "
            "A sampled SLI can miss sub-step blips."), ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--prom", default=os.environ.get("PROM_URL", "http://127.0.0.1:9090"))
    ap.add_argument("--job", default="postfiat")
    ap.add_argument("--window", default="30d")
    ap.add_argument("--start")
    ap.add_argument("--end")
    ap.add_argument("--step", default="15s")
    ap.add_argument("--objective", type=float, help="ratio, e.g. 0.995 (default: pft:slo_objective:ratio or 0.995)")
    ap.add_argument("--maint-history", help="pft-maint history.jsonl: also exclude windows before pft_maint_active")
    ap.add_argument("--max-intervals", type=int, default=50)
    ap.add_argument("-o", "--output")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--record", help="save every raw API response under DIR (test fixtures)")
    g.add_argument("--replay", help="read API responses from DIR instead of HTTP (offline)")
    a = ap.parse_args(argv)
    try:
        step = parse_duration(a.step)
        end = parse_time(a.end) if a.end else int(time.time()) // step * step
        start = parse_time(a.start) if a.start else end - parse_duration(a.window)
        if start >= end:
            raise ValueError("--start must be before --end")
        start -= start % step
        src = Source(a.prom, record=a.record, replay=a.replay)
        objective = a.objective
        if objective is None:
            obj = src.query_range("pft:slo_objective:ratio", end - 300, end, 60)
            objective = float(obj[0]["values"][-1][1]) if obj and obj[0]["values"] else DEFAULT_OBJECTIVE
        if not 0 < objective < 1:
            raise ValueError("objective must be a ratio between 0 and 1, e.g. 0.995")
        spans = load_maint_history(a.maint_history) if a.maint_history else []
        results = analyze(src, a.job, start, end, step, spans)
    except (ValueError, RuntimeError, OSError, KeyError) as e:
        print(f"pft-slo-report: {e}", file=sys.stderr)
        return 2
    if not results:
        print(f"pft-slo-report: no `up{{job=\"{a.job}\"}}` data in {iso(start)}..{iso(end)}", file=sys.stderr)
        return 1
    msrc = "pft_maint_active metric" + (f" + {len(spans)} window(s) from history file" if a.maint_history else "")
    md = render(results, start, end, step, objective, a.job, msrc, a.max_intervals)
    if a.output:
        with open(a.output, "w") as f:
            f.write(md)
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
