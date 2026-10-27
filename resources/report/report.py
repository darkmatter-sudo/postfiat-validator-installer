#!/usr/bin/env python3
"""24h baseline report for pft-resources history files (read-only, stdlib only).

  report.py [--since UNIX] [--until UNIX] [--interval 60] [--json] LABEL=HISTORY.jsonl [LABEL=HISTORY.jsonl ...]

HISTORY is the --history file pft-resources.sh appends one JSON object to per successful collection
(e.g. /var/lib/pft-resources/history-postfiatd.jsonl). For each host the report gives:
  - coverage: samples vs the expected count at --interval, gaps (> 2.5 intervals), unparsed lines, restarts
  - min / median / p95 / max of memory, fds, pids, CPU cores used, PSI avg60 (nearest-rank percentiles)
  - growth: least-squares slope of memory and fds per hour over the window, hours to the limit at that slope
  - replay: every threshold rule of ../../alerts/resources.rules.yml that the history can evaluate, run over the
    samples with its `for:` duration, and the number of times it would have fired
  - recommended thresholds: keep the rule default when the observed max leaves at least 2x headroom
    (or, for ratios of a limit, when the max is at least 20 points below it); otherwise flag it
Exit 0 on a report, 2 on bad input (no file, no samples in the window). Unparsed lines are counted and printed,
never skipped silently.
"""
import argparse
import json
import math
import sys
import time

FIELDS = ("ts", "container", "id", "mem_current", "mem_max", "oom_kill", "cpu_usec", "pids", "pids_max",
          "fds", "fd_limit", "psi_memory_some_avg60", "psi_cpu_some_avg60", "psi_io_some_avg60")

# (name, expression on one sample -> bool or None if not evaluable, for: seconds, rule default text)
RULES = (
    ("PFTMemoryNearLimit", lambda s: s["mem_current"] / s["mem_max"] > 0.90 if s["mem_max"] else None, 300,
     "memory.current / memory.max > 0.90 for 5m"),
    ("PFTFdNearLimit", lambda s: s["fds"] / s["fd_limit"] > 0.80 if s["fd_limit"] else None, 300,
     "fd_open / fd_limit_soft > 0.80 for 5m"),
    ("PFTPidsNearLimit", lambda s: s["pids"] / s["pids_max"] > 0.90 if s["pids_max"] else None, 300,
     "pids.current / pids.max > 0.90 for 5m"),
    ("PFTMemoryPressure", lambda s: s["psi_memory_some_avg60"] > 10.0, 600, "memory PSI some avg60 > 10% for 10m"),
    ("PFTIOPressure", lambda s: s["psi_io_some_avg60"] > 30.0, 900, "io PSI some avg60 > 30% for 15m"),
)


def pct(values, p):
    """Nearest-rank percentile (p in 0..100) of a non-empty list."""
    v = sorted(values)
    k = max(1, math.ceil(p / 100.0 * len(v)))
    return v[k - 1]


def stats(values):
    if not values:
        return None
    return {"n": len(values), "min": min(values), "median": pct(values, 50), "p95": pct(values, 95),
            "max": max(values)}


def slope_per_hour(points):
    """Least-squares slope of (t, y) in y-units per hour; None for < 2 points or zero time spread."""
    if len(points) < 2:
        return None
    n = len(points)
    mt = sum(t for t, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((t - mt) ** 2 for t, _ in points)
    if den == 0:
        return None
    return sum((t - mt) * (y - my) for t, y in points) / den * 3600.0


def load(path, since, until):
    samples, bad = [], []
    with open(path, encoding="utf-8") as f:
        for no, ln in enumerate(f, 1):
            if not ln.strip():
                continue
            try:
                s = json.loads(ln)
                if not isinstance(s, dict) or any(k not in s for k in FIELDS):
                    raise ValueError("missing field")
                for k in FIELDS:
                    if k not in ("container", "id") and not isinstance(s[k], (int, float)):
                        raise ValueError("non-numeric " + k)
            except ValueError as e:
                bad.append((no, str(e)))
                continue
            if (since is None or s["ts"] >= since) and (until is None or s["ts"] < until):
                samples.append(s)
    samples.sort(key=lambda s: s["ts"])
    return samples, bad


def segments(samples, max_gap):
    """Split into runs with no gap > max_gap and no container id change."""
    out, cur = [], []
    for s in samples:
        if cur and (s["ts"] - cur[-1]["ts"] > max_gap or s["id"] != cur[-1]["id"]):
            out.append(cur)
            cur = []
        cur.append(s)
    if cur:
        out.append(cur)
    return out


def replay(samples, cond, hold, max_gap):
    """Fire count + total firing seconds of `cond` held for `hold` s; a gap > max_gap resets the timer."""
    fires, firing_s, start, firing, prev = 0, 0, None, False, None
    for s in samples:
        if prev is not None and s["ts"] - prev["ts"] > max_gap:
            start, firing = None, False
        if cond(s):
            if start is None:
                start = s["ts"]
            if firing:
                firing_s += s["ts"] - prev["ts"]
            elif s["ts"] - start >= hold:
                fires, firing = fires + 1, True
        else:
            start, firing = None, False
        prev = s
    return fires, firing_s


def analyse(label, samples, bad, interval, since, until):
    max_gap = 2.5 * interval
    t0 = since if since is not None else samples[0]["ts"]
    t1 = until if until is not None else samples[-1]["ts"] + interval
    expected = int(round((t1 - t0) / interval))
    gaps = [(a["ts"], b["ts"] - a["ts"]) for a, b in zip(samples, samples[1:]) if b["ts"] - a["ts"] > max_gap]
    # runs closer than half an interval (manual runs, reinstall restarts) are extra, not coverage
    short = sum(1 for a, b in zip(samples, samples[1:]) if b["ts"] - a["ts"] < 0.5 * interval)
    on_schedule = len(samples) - short
    segs = segments(samples, max_gap)
    cores = []
    for seg in segs:
        for a, b in zip(seg, seg[1:]):
            d = b["cpu_usec"] - a["cpu_usec"]
            if d >= 0 and b["ts"] > a["ts"]:
                cores.append(d / 1e6 / (b["ts"] - a["ts"]))
    last = samples[-1]
    mem_slope = slope_per_hour([(s["ts"], s["mem_current"]) for s in samples])
    fd_slope = slope_per_hour([(s["ts"], s["fds"]) for s in samples])
    r = {
        "label": label, "container": last["container"],
        "window": {"since": t0, "until": t1, "hours": round((t1 - t0) / 3600.0, 2)},
        "coverage": {"samples": len(samples), "extra_runs": short, "expected": expected,
                     "pct": round(100.0 * min(on_schedule, expected) / expected, 2) if expected else None,
                     "gaps": [{"after": a, "seconds": d} for a, d in gaps], "unparsed_lines": len(bad),
                     "container_ids": sorted({s["id"] for s in samples}),
                     "restarts_delta": last["restarts"] - samples[0]["restarts"] if "restarts" in last else None,
                     "oom_kill_delta": sum(max(0, seg[-1]["oom_kill"] - seg[0]["oom_kill"]) for seg in segs)},
        "limits": {"mem_max": last["mem_max"], "fd_limit": last["fd_limit"], "pids_max": last["pids_max"]},
        "stats": {
            "mem_bytes": stats([s["mem_current"] for s in samples]),
            "mem_pct_of_max": stats([100.0 * s["mem_current"] / s["mem_max"] for s in samples if s["mem_max"]]),
            "fds": stats([s["fds"] for s in samples]),
            "fd_pct_of_limit": stats([100.0 * s["fds"] / s["fd_limit"] for s in samples if s["fd_limit"]]),
            "pids": stats([s["pids"] for s in samples]),
            "cpu_cores": stats(cores),
            "psi_memory_some_avg60": stats([s["psi_memory_some_avg60"] for s in samples]),
            "psi_cpu_some_avg60": stats([s["psi_cpu_some_avg60"] for s in samples]),
            "psi_io_some_avg60": stats([s["psi_io_some_avg60"] for s in samples]),
        },
        "growth": {"mem_bytes_per_hour": mem_slope, "fds_per_hour": fd_slope,
                   "hours_to_mem_limit": ((last["mem_max"] - last["mem_current"]) / mem_slope
                                          if mem_slope and mem_slope > 0 else None),
                   "hours_to_fd_limit": ((last["fd_limit"] - last["fds"]) / fd_slope
                                         if fd_slope and fd_slope > 0 and last["fd_limit"] else None)},
        "replay": {},
    }
    for name, cond, hold, text in RULES:
        fires, secs = replay(samples, cond, hold, max_gap)
        r["replay"][name] = {"rule": text, "would_fire": fires, "firing_seconds": secs}
    r["replay"]["PFTMemoryGrowthToLimit"] = replay_growth(samples, max_gap)
    r["recommend"] = recommend(r)
    return r


def replay_growth(samples, max_gap):
    """predict_linear(mem[1h], 6h) > mem_max and mem/mem_max > 0.5, for 30m; fit over the trailing hour."""
    def cond_at(i):
        s = samples[i]
        win = [(x["ts"], x["mem_current"]) for x in samples[: i + 1] if s["ts"] - x["ts"] <= 3600]
        k = slope_per_hour(win)
        if k is None or not s["mem_max"]:
            return False
        return s["mem_current"] + k * 6 > s["mem_max"] and s["mem_current"] / s["mem_max"] > 0.5
    flags = {id(s): cond_at(i) for i, s in enumerate(samples)}
    fires, secs = replay(samples, lambda s: flags[id(s)], 1800, max_gap)
    return {"rule": "predict_linear(memory[1h], 6h) > memory.max and memory > 50% of max, for 30m",
            "would_fire": fires, "firing_seconds": secs}


def recommend(r):
    st, out = r["stats"], []

    def ratio_rule(name, key, default_pct):
        s = st[key]
        if s is None:
            out.append({"rule": name, "default": default_pct, "verdict": "no data"})
            return
        ok = s["max"] <= default_pct - 20
        out.append({"rule": name, "default": "> %g%%" % default_pct, "observed_max": round(s["max"], 2),
                    "headroom_points": round(default_pct - s["max"], 2),
                    "verdict": "keep default" if ok else "REVIEW: observed max within 20 points of the threshold"})

    def psi_rule(name, key, default):
        s = st[key]
        if s is None:
            out.append({"rule": name, "default": default, "verdict": "no data"})
            return
        ok = s["max"] * 2 <= default
        out.append({"rule": name, "default": "> %g%%" % default, "observed_max": s["max"],
                    "observed_p95": s["p95"],
                    "verdict": "keep default" if ok else "REVIEW: observed max is more than half the threshold"})

    ratio_rule("PFTMemoryNearLimit", "mem_pct_of_max", 90)
    ratio_rule("PFTFdNearLimit", "fd_pct_of_limit", 80)
    pids = st["pids"]
    if pids and r["limits"]["pids_max"]:
        p = 100.0 * pids["max"] / r["limits"]["pids_max"]
        out.append({"rule": "PFTPidsNearLimit", "default": "> 90%", "observed_max": round(p, 2),
                    "headroom_points": round(90 - p, 2),
                    "verdict": "keep default" if p <= 70 else "REVIEW: observed max within 20 points of the threshold"})
    psi_rule("PFTMemoryPressure", "psi_memory_some_avg60", 10.0)
    psi_rule("PFTIOPressure", "psi_io_some_avg60", 30.0)
    g = r["growth"]["hours_to_mem_limit"]
    out.append({"rule": "PFTMemoryGrowthToLimit", "default": "6h horizon, 1h fit, >50% of max, for 30m",
                "window_slope_bytes_per_hour": r["growth"]["mem_bytes_per_hour"],
                "hours_to_limit_at_window_slope": g,
                "verdict": ("keep default" if g is None or g > 24 * 7
                            else "REVIEW: window slope reaches the limit within a week")})
    fired = [n for n, v in r["replay"].items() if v["would_fire"]]
    for o in out:
        if o["rule"] in fired and o["verdict"] == "keep default":
            o["verdict"] = "REVIEW: would have fired %d time(s) on this baseline" % r["replay"][o["rule"]]["would_fire"]
    return out


def utc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def mib(b):
    return "%.1f MiB" % (b / 1048576.0)


def fmt(v, kind):
    if v is None:
        return "n/a"
    if kind == "bytes":
        return mib(v)
    if kind == "pct":
        return "%.2f%%" % v
    if kind == "cores":
        return "%.3f" % v
    return "%g" % v


def markdown(reports, bad_by_label):
    hours = max(r["window"]["hours"] for r in reports)
    o = ["# pft-resources baseline report (%.2f h window)" % hours, ""]
    o.append("Generated by resources/report/report.py at %s from the pft-resources --history files." % utc(time.time()))
    o.append("Percentiles are nearest-rank. CPU cores = delta cpu.stat usage_usec / delta time between consecutive "
             "samples of the same container id with no gap. PSI values are the kernel's avg60 (percent).")
    o.append("")
    for r in reports:
        c, w = r["coverage"], r["window"]
        o += ["## %s (container %s)" % (r["label"], r["container"]), "",
              "- window: %s .. %s (%.2f h)" % (utc(w["since"]), utc(w["until"]), w["hours"]),
              "- samples: %d (%d extra runs < 0.5 interval apart), coverage %d expected -> %s%%, "
              "gaps > 2.5 intervals: %d, unparsed lines: %d"
              % (c["samples"], c["extra_runs"], c["expected"], c["pct"], len(c["gaps"]), c["unparsed_lines"]),
              "- container ids: %s, restarts in window: %s, new oom_kill events: %d"
              % (", ".join(c["container_ids"]), c["restarts_delta"], c["oom_kill_delta"]),
              "- limits (last sample): memory.max %s, fd soft limit %d, pids.max %d"
              % (mib(r["limits"]["mem_max"]), r["limits"]["fd_limit"], r["limits"]["pids_max"]), ""]
        for g in c["gaps"]:
            o.append("  - gap after %s: %d s" % (utc(g["after"]), g["seconds"]))
        for no, why in bad_by_label[r["label"]]:
            o.append("  - unparsed line %d: %s" % (no, why))
        o += ["| metric | min | median | p95 | max |", "|---|---|---|---|---|"]
        for key, kind in (("mem_bytes", "bytes"), ("mem_pct_of_max", "pct"), ("fds", "n"), ("fd_pct_of_limit", "pct"),
                          ("pids", "n"), ("cpu_cores", "cores"), ("psi_memory_some_avg60", "pct"),
                          ("psi_cpu_some_avg60", "pct"), ("psi_io_some_avg60", "pct")):
            s = r["stats"][key]
            if s is None:
                o.append("| %s | n/a | n/a | n/a | n/a |" % key)
            else:
                o.append("| %s | %s | %s | %s | %s |" % (key, fmt(s["min"], kind), fmt(s["median"], kind),
                                                          fmt(s["p95"], kind), fmt(s["max"], kind)))
        g = r["growth"]
        o += ["", "Growth (least squares over the window): memory %s/h, fds %s/h; hours to limit at that slope: "
              "memory %s, fds %s" % (
                  "n/a" if g["mem_bytes_per_hour"] is None else "%+.2f MiB" % (g["mem_bytes_per_hour"] / 1048576.0),
                  "n/a" if g["fds_per_hour"] is None else "%+.3f" % g["fds_per_hour"],
                  "not growing" if g["hours_to_mem_limit"] is None else "%.1f" % g["hours_to_mem_limit"],
                  "not growing" if g["hours_to_fd_limit"] is None else "%.1f" % g["hours_to_fd_limit"]), ""]
        o += ["Rule replay over these samples (would the rule have fired?):", "",
              "| rule | condition | would fire | firing seconds |", "|---|---|---|---|"]
        for n, v in r["replay"].items():
            o.append("| %s | %s | %d | %d |" % (n, v["rule"], v["would_fire"], v["firing_seconds"]))
        o += ["", "Recommended thresholds:", "", "| rule | default | observed | verdict |", "|---|---|---|---|"]
        for x in r["recommend"]:
            obs = []
            if "observed_max" in x:
                obs.append("max %s" % x["observed_max"])
            if "observed_p95" in x:
                obs.append("p95 %s" % x["observed_p95"])
            if "headroom_points" in x:
                obs.append("headroom %s points" % x["headroom_points"])
            if "hours_to_limit_at_window_slope" in x:
                h = x["hours_to_limit_at_window_slope"]
                obs.append("hours to limit %s" % ("n/a (not growing)" if h is None else "%.1f" % h))
            o.append("| %s | %s | %s | %s |" % (x["rule"], x["default"], ", ".join(obs) or "n/a", x["verdict"]))
        o.append("")
    o += ["Not evaluable from history (needs Prometheus): PFTCPUThrottled (history has nr_throttled but not "
          "nr_periods; use the Prometheus series), PFTContainerOOMKill (counted above as new oom_kill "
          "events), PFTResourcesCollectorFailing/Stale (history only has successful runs; see coverage gaps).", ""]
    return "\n".join(o)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--since", type=float)
    ap.add_argument("--until", type=float)
    ap.add_argument("--interval", type=float, default=60.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("files", nargs="+", metavar="LABEL=HISTORY.jsonl")
    a = ap.parse_args(argv)
    reports, bad_by_label = [], {}
    for spec in a.files:
        label, sep, path = spec.partition("=")
        if not sep or not label or not path:
            print("report.py: expected LABEL=PATH, got %r" % spec, file=sys.stderr)
            return 2
        try:
            samples, bad = load(path, a.since, a.until)
        except OSError as e:
            print("report.py: %s: %s" % (label, e), file=sys.stderr)
            return 2
        if not samples:
            print("report.py: %s: no samples in the window" % label, file=sys.stderr)
            return 2
        bad_by_label[label] = bad
        reports.append(analyse(label, samples, bad, a.interval, a.since, a.until))
    if a.json:
        print(json.dumps(reports, indent=1, sort_keys=True))
    else:
        print(markdown(reports, bad_by_label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
