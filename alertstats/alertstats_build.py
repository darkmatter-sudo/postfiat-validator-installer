#!/usr/bin/env python3
"""alertstats_build: observed alert behaviour from Prometheus ALERTS history (read-only, stdlib only).

Two halves, so a report can always be rebuilt without the hosts:
  collect  query Prometheus (query_range ALERTS / ALERTS_FOR_STATE / up, /api/v1/rules) and Alertmanager
           (/api/v2/silences), read ntfy-bridge delivery lines (stdin or --deliveries FILE), redact, and write ONE
           bundle JSON. Only HTTP GETs; nothing is sent, silenced or changed.
  report   read a bundle (--offline BUNDLE) and print md | json | csv | textfile. The report is a pure function of
           the bundle: the same bundle gives byte-identical output on any machine.

Episode model (per series = ALERTS labels minus alertstate):
  * samples come from query_range at STEP seconds; a sample at t means "active at t" (pending or firing).
  * consecutive samples more than 1.5*STEP apart are a GAP. If Prometheus itself has no `up` sample inside the gap
    (it was down / restarting) the gap is a DATA gap: when ALERTS_FOR_STATE shows the same activeAt on both sides the
    episode continued (gap_bridged), otherwise it is split and both halves carry gap_split (their boundary is not a
    real resolve, so it is never a flap). If `up` was scraped during the gap, the alert really went inactive and the
    next sample starts a new episode.
  * an episode with no firing sample is pending-only (a near miss: `for:` absorbed it).
  * TTR = end - firing_start for closed fired episodes; end = last sample + STEP (resolution: one STEP).
  * silenced seconds = overlap of [firing_start, end] with the union of silences whose matchers match the labels.
  * a FLAP is a fired, mostly-unsilenced episode that starts less than FLAP_WINDOW after the previous such episode
    of the same series ended (gap_split boundaries excluded). An alertname is FLAPPING when one of its series has
    >= FLAP_MIN such episodes starting within FLAP_WINDOW of each other, all inside the last FLAP_RECENT seconds.
  * percentiles: nearest rank (sorted values, index ceil(q*n)-1), so a reader can check them by hand.
"""

import argparse
import csv
import gzip
import io
import itertools
import json
import math
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BUNDLE_FORMAT = "pft-alertstats-bundle/1"
MAX_SINCE = 15 * 86400  # Prometheus retention on the validator
MAX_POINTS = 10000  # per series per query_range call (Prometheus refuses > 11000)
SEVERITIES = ("critical", "warning", "info", "none")
TEXT_BUDGET = 60000  # bytes; node_exporter-style textfile cap is 64 KiB
CHECKS = {
    # check id: (severity, meaning)
    "no_for": ("warn", "alerting rule without for: fires on the first evaluation"),
    "short_for": ("warn", "for: shorter than two evaluation intervals (does not absorb one bad sample)"),
    "bad_severity": ("warn", "severity label missing or not critical|warning|info|none"),
    "no_summary": ("warn", "summary annotation missing"),
    "no_description": ("info", "description annotation missing"),
    "unhealthy": ("warn", "rule health is not ok (evaluation error)"),
    "duplicate_name": ("info", "the same alertname is defined by more than one rule"),
    "always_firing": ("warn", "fired for >= 90% of the window (alert fatigue or a broken rule)"),
    "never_active": ("info", "never pending or firing in the window (untested in production)"),
    "no_rule": ("info", "episodes in the window but no loaded rule (renamed or removed)"),
}
_IP4 = re.compile(r"\b(?!(?:127|10|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}\b")
_NTFY = re.compile(r"(ntfy\.sh/)[A-Za-z0-9_-]+")
_DELIVERY = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z?\s+"
    r"(?:ntfy \[(?P<status>[A-Z]+)\] (?P<name>\S+)(?: x(?P<count>\d+))? -> (?P<result>HTTP \d+|ERROR \S+)"
    r"|webhook status=(?P<wstatus>\S+) alertname=(?P<wname>\S+))"
)
_LOG_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z?\s")


def die(msg, rc=3):
    print(f"alertstats: {msg}", file=sys.stderr)
    sys.exit(rc)


def redact(s):
    return _NTFY.sub(r"\1<redacted>", _IP4.sub("<redacted-ip>", s))


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()


def parse_duration(s):
    m = re.fullmatch(r"(\d+)([smhd]?)", s.strip())
    if not m:
        die(f"bad duration {s!r} (use 300, 300s, 5m, 2h, 7d)")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


# ---------------------------------------------------------------- collect


def http_json(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def query_range(prom, query, start, end, step, timeout):
    """Merged query_range result over chunks of at most MAX_POINTS steps: [{metric, values}] sorted by labels."""
    series = {}
    t = start
    while t <= end:
        chunk_end = min(end, t + (MAX_POINTS - 1) * step)
        q = urllib.parse.urlencode({"query": query, "start": t, "end": chunk_end, "step": step})
        doc = http_json(f"{prom}/api/v1/query_range?{q}", timeout)
        if doc.get("status") != "success":
            raise RuntimeError(f"query_range {query}: {doc.get('error', 'not success')}")
        for s in doc["data"]["result"]:
            key = json.dumps(s["metric"], sort_keys=True)
            series.setdefault(key, {"metric": s["metric"], "values": []})["values"].extend(s["values"])
        t = chunk_end + step
    out = []
    for key in sorted(series):
        s = series[key]
        seen, vals = set(), []
        for v in s["values"]:
            if v[0] not in seen:
                seen.add(v[0])
                vals.append(v)
        vals.sort(key=lambda v: v[0])
        out.append({"metric": s["metric"], "values": vals})
    return out


def trim_rules(groups):
    rules = []
    for g in groups:
        for r in g.get("rules", []):
            if r.get("type") != "alerting":
                continue
            rules.append(
                {
                    "group": g.get("name", ""),
                    "file": g.get("file", "").rsplit("/", 1)[-1],
                    "interval": g.get("interval", 0),
                    "name": r.get("name", ""),
                    "duration": r.get("duration", 0),
                    "labels": r.get("labels", {}),
                    "annotations": sorted(r.get("annotations", {})),
                    "health": r.get("health", ""),
                    "lastError": redact(r.get("lastError", "")),
                }
            )
    rules.sort(key=lambda r: (r["file"], r["group"], r["name"], json.dumps(r["labels"], sort_keys=True)))
    return rules


def trim_silences(sils):
    out = []
    for s in sils:
        out.append(
            {
                "id": s.get("id", ""),
                "startsAt": s.get("startsAt", ""),
                "endsAt": s.get("endsAt", ""),
                "comment": redact(s.get("comment", ""))[:120],
                "matchers": [
                    {k: m.get(k) for k in ("name", "value", "isRegex", "isEqual")} for m in s.get("matchers", [])
                ],
            }
        )
    out.sort(key=lambda s: (s["startsAt"], s["id"]))
    return out


def parse_deliveries(lines):
    """ntfy-bridge stdout lines (docker logs --timestamps) -> [{ts, kind, status, alertname, count, result}]."""
    out = []
    for line in lines:
        m = _DELIVERY.match(line.strip())
        if not m:
            continue
        ts = parse_iso(m.group("ts"))
        if m.group("name"):
            out.append(
                {
                    "ts": ts,
                    "kind": "ntfy",
                    "status": m.group("status").lower(),
                    "alertname": m.group("name"),
                    "count": int(m.group("count") or 1),
                    "result": m.group("result"),
                }
            )
        else:
            out.append(
                {
                    "ts": ts,
                    "kind": "webhook",
                    "status": m.group("wstatus"),
                    "alertname": m.group("wname"),
                    "count": 1,
                    "result": "",
                }
            )
    out.sort(key=lambda d: d["ts"])  # stable: same-second lines keep log order (webhook before its ntfy send)
    return out


def log_start(lines):
    """Timestamp of the first timestamped line (the bridge's `listening` line after a container start), else None.
    The delivery log covers [log_start, end] even when it holds no delivery at all."""
    for line in lines:
        m = _LOG_TS.match(line.strip())
        if m:
            return parse_iso(m.group(1))
    return None


def cmd_collect(a):
    since = parse_duration(a.since)
    if since > MAX_SINCE:
        die(f"--since {a.since} exceeds the {MAX_SINCE // 86400}d retention cap")
    step = a.step
    end = int(a.now) if a.now else int(datetime.now(timezone.utc).timestamp())
    end -= end % step
    start = end - since
    sources = {}
    bundle = {
        "format": BUNDLE_FORMAT,
        "params": {
            "start": start,
            "end": end,
            "step": step,
            "since_s": since,
            "flap_window": parse_duration(a.flap_window),
            "flap_min": a.flap_min,
            "flap_recent": parse_duration(a.flap_recent),
            "allow_no_for": sorted(x for x in a.allow_no_for.split(",") if x),
            "host": a.host,
            "lookback": 300,
            "up_query": f"count(present_over_time({a.up_selector}[{2 * step}s]))",
        },
    }
    try:
        bundle["alerts"] = query_range(a.prometheus, "ALERTS", start, end, step, a.timeout)
        bundle["for_state"] = query_range(a.prometheus, "ALERTS_FOR_STATE", start, end, step, a.timeout)
        # present_over_time over 2 steps, not plain `up`: the 5m lookback would hide outages shorter than 5 minutes
        up = query_range(a.prometheus, bundle["params"]["up_query"], start, end, step, a.timeout)
        bundle["up"] = [v[0] for s in up for v in s["values"]]
        rules = http_json(f"{a.prometheus}/api/v1/rules?type=alert", a.timeout)
        bundle["rules"] = trim_rules(rules["data"]["groups"])
        sources["prometheus"] = "ok"
    except Exception as e:  # noqa: BLE001 - reported in the bundle, exit 4
        sources["prometheus"] = f"error {type(e).__name__}: {redact(str(e))[:200]}"
    try:
        bundle["silences"] = trim_silences(http_json(f"{a.alertmanager}/api/v2/silences", a.timeout))
        sources["alertmanager"] = "ok"
    except Exception as e:  # noqa: BLE001
        bundle["silences"] = []
        sources["alertmanager"] = f"error {type(e).__name__}: {redact(str(e))[:200]}"
    if a.deliveries:
        with open(a.deliveries, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        parsed = parse_deliveries(lines)
        bundle["deliveries"] = [d for d in parsed if start <= d["ts"] <= end]
        bundle["delivery_log_from"] = log_start(lines)
        sources["bridge"] = "ok"
    else:
        bundle["deliveries"] = []
        bundle["delivery_log_from"] = None
        sources["bridge"] = "absent"
    bundle["sources"] = sources
    text = json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n"
    if a.out.endswith(".gz"):  # mtime=0 and no file name: the same bundle always gives the same bytes
        with open(a.out, "wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0) as g:
            g.write(text.encode())
    elif a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0 if sources["prometheus"] == "ok" else 4


# ---------------------------------------------------------------- analysis


def series_key(metric):
    return tuple(sorted((k, v) for k, v in metric.items() if k not in ("__name__", "alertstate")))


def matcher_ok(m, labels):
    val = labels.get(m["name"], "")
    if m.get("isRegex"):
        hit = re.fullmatch(m["value"], val) is not None
    else:
        hit = val == m["value"]
    return hit if m.get("isEqual", True) else not hit


def silence_intervals(silences, labels):
    iv = []
    for s in silences:
        if all(matcher_ok(m, labels) for m in s["matchers"]):
            a, b = parse_iso(s["startsAt"]), parse_iso(s["endsAt"])
            if b > a:
                iv.append((a, b))
    iv.sort()
    merged = []
    for a, b in iv:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def overlap(iv, a, b):
    return sum(max(0.0, min(b, y) - max(a, x)) for x, y in iv)


def nearest_rank(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    return s[max(0, math.ceil(q * len(s)) - 1)]


def prom_gaps(p, up):
    """Missing grid points of the Prometheus presence series as [{from, to (exclusive), seconds}]."""
    gaps = []
    edges = [p["start"] - p["step"], *sorted(up), p["end"] + p["step"]]
    for a, b in itertools.pairwise(edges):
        if b - a > 1.5 * p["step"]:
            gaps.append({"from": a + p["step"], "to": b, "seconds": b - a - p["step"]})
    return gaps


def build_episodes(bundle):
    p = bundle["params"]
    step, start, end = p["step"], p["start"], p["end"]
    tol = 1.5 * step
    gaps = prom_gaps(p, bundle.get("up", []))

    lb = p.get("lookback", 300) + step

    def data_gap(t0, t1):
        """True when the missing samples (t0, t1) of a series lie inside one Prometheus gap, widened by the query
        lookback on both sides (stale-free series stay visible up to 5m after the last sample before an outage)."""
        return any(g["from"] - lb <= t0 + step and t1 <= g["to"] + lb for g in gaps)

    states, active_at = {}, {}
    for s in bundle.get("alerts", []):
        k = series_key(s["metric"])
        st = s["metric"].get("alertstate", "")
        d = states.setdefault(k, {})
        for t, _v in s["values"]:
            if st == "firing" or t not in d:
                d[t] = st
    for s in bundle.get("for_state", []):
        k = series_key(s["metric"])
        d = active_at.setdefault(k, {})
        for t, v in s["values"]:
            d[t] = v
    silences = bundle.get("silences", [])
    episodes = []
    for k in sorted(states):
        labels = dict(k)
        sil = silence_intervals(silences, labels)
        fs = active_at.get(k, {})
        mine, cur = [], None
        for t in sorted(states[k]):
            st = states[k][t]
            if cur is None:
                cur = new_episode(labels, t, start, step)
            elif t - cur["last"] > tol:
                gap_from = cur["last"]
                if not data_gap(gap_from, t):
                    mine.append(cur)  # Prometheus was evaluating: a real resolve, then a new episode
                    cur = new_episode(labels, t, start, step)
                elif fs.get(gap_from) is not None and fs.get(gap_from) == fs.get(t):
                    cur["gap_bridged"] += 1  # same activeAt on both sides: restored across the outage
                    cur["gap_s"] += t - gap_from - step
                    cur["sample_gaps"] += [
                        g["from"] for g in gaps if g["from"] - lb <= gap_from + step and t <= g["to"] + lb
                    ]
                else:
                    cur["gap_split_after"] = True
                    mine.append(cur)
                    cur = new_episode(labels, t, start, step, gap_split_before=True)
            cur["last"] = t
            if st == "firing" and cur["firing_start"] is None:
                cur["firing_start"] = t
        mine.append(cur)
        for e in mine:
            for g in gaps:  # lookback (5m) fills a short outage: the episode spans it with no sample gap
                if e["start"] < g["from"] and g["to"] <= e["last"] and g["from"] not in e["sample_gaps"]:
                    e["gap_bridged"] += 1
                    e["gap_s"] += g["seconds"]
            finish_episode(e, end, step, tol, sil)
        episodes += mine
    episodes.sort(key=lambda e: (e["alertname"], e["start"], e["series"]))
    return episodes


def new_episode(labels, t, start, step, gap_split_before=False):
    return {
        "labels": labels,
        "alertname": labels.get("alertname", ""),
        "series": ",".join(f"{k}={v}" for k, v in sorted(labels.items()) if k != "alertname"),
        "start": t,
        "last": t,
        "firing_start": None,
        "truncated_start": t <= start + step / 2,
        "gap_split_before": gap_split_before,
        "gap_split_after": False,
        "gap_bridged": 0,
        "gap_s": 0,
        "sample_gaps": [],
    }


def finish_episode(e, end, step, tol, sil):
    e["open"] = e["last"] >= end - tol and not e["gap_split_after"]
    e["end"] = None if e["open"] else e["last"] + step
    stop = end if e["open"] else e["end"]
    fired = e["firing_start"] is not None
    e["kind"] = "fired" if fired else "pending_only"
    e["pending_s"] = (e["firing_start"] if fired else stop) - e["start"]
    e["firing_s"] = (stop - e["firing_start"] - e["gap_s"]) if fired else 0
    e["ttr_s"] = (e["end"] - e["firing_start"]) if (fired and not e["open"] and not e["truncated_start"]) else None
    if e["ttr_s"] is not None and (e["gap_split_after"] or e["gap_split_before"]):
        e["ttr_s"] = None  # boundary is a data gap, not a resolve
    e["silenced_s"] = overlap(sil, e["firing_start"], stop) if fired else 0
    e["notifiable"] = fired and e["silenced_s"] * 2 < max(e["firing_s"], 1)


def flap_stats(episodes, p):
    """Per alertname: flaps in the window, and flapping (bool) within the last flap_recent seconds."""
    win, fmin, recent_from = p["flap_window"], p["flap_min"], p["end"] - p["flap_recent"]
    by_series = {}
    for e in episodes:
        if e["notifiable"]:
            by_series.setdefault((e["alertname"], e["series"]), []).append(e)
    flaps, flapping = {}, {}
    for (name, _series), eps in sorted(by_series.items()):
        eps.sort(key=lambda e: e["start"])
        n = 0
        for prev, e in itertools.pairwise(eps):
            if prev["end"] is not None and not prev["gap_split_after"] and e["start"] - prev["end"] < win:
                n += 1
        flaps[name] = flaps.get(name, 0) + n
        starts = [e["start"] for e in eps if e["start"] >= recent_from]
        hit = any(starts[i + fmin - 1] - starts[i] < win for i in range(len(starts) - fmin + 1)) if fmin > 0 else False
        flapping[name] = flapping.get(name, False) or hit
    return flaps, flapping


def hygiene(bundle, episodes):
    p = bundle["params"]
    allow = set(p.get("allow_no_for", []))
    window = p["end"] - p["start"]
    findings = []
    names = {}
    for r in bundle.get("rules", []):
        names.setdefault(r["name"], []).append(r)
    firing = {}
    active = set()
    for e in episodes:
        active.add(e["alertname"])
        firing[e["alertname"]] = max(firing.get(e["alertname"], 0), e["firing_s"])
    for name in sorted(names):
        rules = names[name]
        if len(rules) > 1:
            findings.append(("duplicate_name", name, f"{len(rules)} rules"))
        for r in rules:
            where = f"{r['file']}:{r['group']}"
            iv = r.get("interval") or 0
            if r["duration"] == 0 and name not in allow:
                findings.append(("no_for", name, where))
            elif 0 < r["duration"] < 2 * iv:
                findings.append(("short_for", name, f"{where} for={r['duration']}s interval={iv}s"))
            if r["labels"].get("severity") not in SEVERITIES:
                findings.append(("bad_severity", name, f"{where} severity={r['labels'].get('severity', '-')}"))
            if "summary" not in r["annotations"]:
                findings.append(("no_summary", name, where))
            if "description" not in r["annotations"]:
                findings.append(("no_description", name, where))
            if r["health"] not in ("ok", "unknown"):
                findings.append(("unhealthy", name, f"{where} health={r['health']} {r['lastError'][:80]}"))
        if name not in active:
            findings.append(("never_active", name, "0 episodes"))
        elif name not in allow and firing.get(name, 0) >= 0.9 * window:
            findings.append(("always_firing", name, f"longest firing {firing[name]}s of {window}s"))
    for name in sorted(active - set(names)):
        findings.append(("no_rule", name, "history only"))
    findings = sorted(set(findings))
    return [{"check": c, "severity": CHECKS[c][0], "alertname": n, "detail": d} for c, n, d in findings]


def analyse(bundle):
    if bundle.get("format") != BUNDLE_FORMAT:
        die(f"not a {BUNDLE_FORMAT} bundle", 3)
    p = bundle["params"]
    eps = build_episodes(bundle)
    flaps, flapping = flap_stats(eps, p)
    rule_sev = {}
    for r in bundle.get("rules", []):
        rule_sev.setdefault(r["name"], r["labels"].get("severity", "-"))
        rule_sev[r["name"] + "/for"] = r["duration"]
    per = {}
    for e in eps:
        a = per.setdefault(
            e["alertname"],
            {
                "fired": 0,
                "pending_only": 0,
                "open": 0,
                "gap_split": 0,
                "ttr": [],
                "firing_s": 0,
                "silenced_s": 0,
                "pending_max_s": 0,
            },
        )
        a[e["kind"]] += 1
        a["open"] += 1 if e["open"] else 0
        a["gap_split"] += 1 if (e["gap_split_before"] or e["gap_split_after"]) else 0
        a["firing_s"] += e["firing_s"]
        a["silenced_s"] += e["silenced_s"]
        if e["kind"] == "pending_only" and not e["open"]:
            a["pending_max_s"] = max(a["pending_max_s"], e["pending_s"])
        if e["ttr_s"] is not None:
            a["ttr"].append(e["ttr_s"])
    alerts = []
    for name in sorted(per):
        a = per[name]
        alerts.append(
            {
                "alertname": name,
                "severity": rule_sev.get(name, "-"),
                "for_s": rule_sev.get(name + "/for"),
                "fired": a["fired"],
                "pending_only": a["pending_only"],
                "open": a["open"],
                "gap_split": a["gap_split"],
                "flaps": flaps.get(name, 0),
                "flapping": bool(flapping.get(name, False)),
                "ttr_n": len(a["ttr"]),
                "ttr_p50_s": nearest_rank(a["ttr"], 0.5),
                "ttr_p95_s": nearest_rank(a["ttr"], 0.95),
                "firing_s": a["firing_s"],
                "silenced_s": round(a["silenced_s"]),
                "pending_max_s": a["pending_max_s"],
            }
        )
    deliveries = bundle.get("deliveries", [])
    days = {}
    for d in deliveries:
        if d["kind"] != "ntfy":
            continue
        day = iso(d["ts"])[:10]
        x = days.setdefault(day, {"day": day, "ok": 0, "error": 0, "firing": 0, "resolved": 0})
        x["ok" if d["result"].startswith("HTTP 2") else "error"] += 1
        x[d["status"] if d["status"] in ("firing", "resolved") else "firing"] += 1
    gaps = prom_gaps(p, bundle.get("up", []))
    return {
        "params": p,
        "sources": bundle.get("sources", {}),
        "rules_total": len(bundle.get("rules", [])),
        "alertnames_total": len({r["name"] for r in bundle.get("rules", [])}),
        "episodes": eps,
        "alerts": alerts,
        "hygiene": hygiene(bundle, eps),
        "notifications": [days[k] for k in sorted(days)],
        "delivery_log_from": bundle.get("delivery_log_from"),
        "silences_in_bundle": len(bundle.get("silences", [])),
        "prometheus_gaps": gaps,
    }


# ---------------------------------------------------------------- output


def fmt_s(v):
    if v is None:
        return "-"
    v = int(v)
    if v >= 3600:
        return f"{v // 3600}h{v % 3600 // 60:02d}m"
    if v >= 60:
        return f"{v // 60}m{v % 60:02d}s"
    return f"{v}s"


def headline(r):
    eps = r["episodes"]
    return {
        "episodes": len(eps),
        "fired": sum(e["kind"] == "fired" for e in eps),
        "pending_only": sum(e["kind"] == "pending_only" for e in eps),
        "open": sum(e["open"] for e in eps),
        "gap_split": sum(e["gap_split_before"] or e["gap_split_after"] for e in eps),
        "flaps": sum(a["flaps"] for a in r["alerts"]),
        "flapping_alertnames": sum(a["flapping"] for a in r["alerts"]),
        "active_alertnames": len(r["alerts"]),
        "hygiene_warn": sum(h["severity"] == "warn" for h in r["hygiene"]),
        "hygiene_info": sum(h["severity"] == "info" for h in r["hygiene"]),
        "notifications": sum(d["ok"] + d["error"] for d in r["notifications"]),
        "prometheus_gap_s": sum(g["seconds"] for g in r["prometheus_gaps"]),
    }


def out_json(r):
    doc = dict(r)
    doc["headline"] = headline(r)
    doc["episodes"] = [
        {k: v for k, v in e.items() if k not in ("labels", "last", "sample_gaps")} for e in r["episodes"]
    ]
    return json.dumps(doc, sort_keys=True, indent=1) + "\n"


EP_COLS = [
    "alertname",
    "series",
    "kind",
    "start",
    "firing_start",
    "end",
    "open",
    "truncated_start",
    "gap_split_before",
    "gap_split_after",
    "gap_bridged",
    "pending_s",
    "firing_s",
    "ttr_s",
    "silenced_s",
    "notifiable",
]


def out_csv(r):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(EP_COLS)
    for e in r["episodes"]:
        row = []
        for c in EP_COLS:
            v = e[c]
            if c in ("start", "firing_start", "end"):
                v = iso(v) if v is not None else ""
            elif isinstance(v, bool):
                v = int(v)
            elif isinstance(v, float):
                v = round(v)
            row.append("" if v is None else v)
        w.writerow(row)
    return buf.getvalue()


def out_md(r):
    p, h = r["params"], headline(r)
    L = [
        f"# Alert behaviour report ({p['host']})",
        "",
        f"Window {iso(p['start'])} -> {iso(p['end'])} ({fmt_s(p['since_s'])}), step {p['step']}s. "
        f"Sources: " + ", ".join(f"{k} {v}" for k, v in sorted(r["sources"].items())) + ".",
        (
            f"Flap rule: >= {p['flap_min']} unsilenced fired episodes of one series starting within "
            f"{fmt_s(p['flap_window'])}, in the last {fmt_s(p['flap_recent'])}."
        ),
        "",
        "## Headline",
        "",
        "| metric | value |",
        "|---|---|",
    ]
    L += [f"| {k} | {v} |" for k, v in h.items()]
    L += [
        f"| alerting rules / alertnames | {r['rules_total']} / {r['alertnames_total']} |",
        "",
        "## Per alert",
        "",
        (
            "| alertname | sev | for | fired | pending-only | open | gap-split | flaps | flapping | TTR n | TTR p50 | "
            "TTR p95 | firing | silenced | max near-miss |"
        ),
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for a in r["alerts"]:
        L.append(
            f"| {a['alertname']} | {a['severity']} | {fmt_s(a['for_s'])} | {a['fired']} | {a['pending_only']} | "
            f"{a['open']} | {a['gap_split']} | {a['flaps']} | {'YES' if a['flapping'] else 'no'} | {a['ttr_n']} | "
            f"{fmt_s(a['ttr_p50_s'])} | {fmt_s(a['ttr_p95_s'])} | {fmt_s(a['firing_s'])} | "
            f"{fmt_s(a['silenced_s'])} | {fmt_s(a['pending_max_s']) if a['pending_only'] else '-'} |"
        )
    L += ["", "## Rule hygiene", ""]
    if r["hygiene"]:
        L += ["| check | severity | alertname | detail |", "|---|---|---|---|"]
        L += [f"| {x['check']} | {x['severity']} | {x['alertname']} | {x['detail']} |" for x in r["hygiene"]]
    else:
        L.append("No findings.")
    L += ["", "## Notifications (ntfy bridge deliveries)", ""]
    if r["delivery_log_from"] is None:
        L.append("No delivery log in the bundle.")
    else:
        L.append(f"Delivery log available from {iso(r['delivery_log_from'])} (bridge container start).")
        L += ["", "| day | ok | error | firing | resolved |", "|---|---|---|---|---|"]
        L += [
            f"| {d['day']} | {d['ok']} | {d['error']} | {d['firing']} | {d['resolved']} |" for d in r["notifications"]
        ]
    L += ["", "## Prometheus data gaps", ""]
    if r["prometheus_gaps"]:
        L += ["| from | to | seconds |", "|---|---|---|"]
        L += [f"| {iso(g['from'])} | {iso(g['to'])} | {g['seconds']} |" for g in r["prometheus_gaps"]]
    else:
        L.append("None.")
    return "\n".join(L) + "\n"


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def out_textfile(r, now):
    host = esc(r["params"]["host"])
    h = headline(r)
    L = [
        "# HELP pft_alertstats_up 1 = the report was built from a complete Prometheus capture.",
        "# TYPE pft_alertstats_up gauge",
        f'pft_alertstats_up{{host="{host}"}} {1 if r["sources"].get("prometheus") == "ok" else 0}',
        "# HELP pft_alertstats_last_run_timestamp_seconds When the report was built.",
        "# TYPE pft_alertstats_last_run_timestamp_seconds gauge",
        f'pft_alertstats_last_run_timestamp_seconds{{host="{host}"}} {int(now)}',
        "# HELP pft_alertstats_window_seconds Length of the analysed window.",
        "# TYPE pft_alertstats_window_seconds gauge",
        f'pft_alertstats_window_seconds{{host="{host}"}} {r["params"]["since_s"]}',
        "# HELP pft_alertstats_rules Alerting rules loaded in Prometheus.",
        "# TYPE pft_alertstats_rules gauge",
        f'pft_alertstats_rules{{host="{host}"}} {r["rules_total"]}',
        "# HELP pft_alertstats_prometheus_gap_seconds Seconds of the window with no Prometheus data.",
        "# TYPE pft_alertstats_prometheus_gap_seconds gauge",
        f'pft_alertstats_prometheus_gap_seconds{{host="{host}"}} {h["prometheus_gap_s"]}',
        "# HELP pft_alertstats_notifications ntfy deliveries in the window by result.",
        "# TYPE pft_alertstats_notifications gauge",
    ]
    ok = sum(d["ok"] for d in r["notifications"])
    err = sum(d["error"] for d in r["notifications"])
    L += [
        f'pft_alertstats_notifications{{host="{host}",result="ok"}} {ok}',
        f'pft_alertstats_notifications{{host="{host}",result="error"}} {err}',
    ]
    L += [
        "# HELP pft_alertstats_hygiene_findings Static rule-hygiene findings by check (0 when absent).",
        "# TYPE pft_alertstats_hygiene_findings gauge",
    ]
    for c in sorted(CHECKS):
        n = sum(x["check"] == c for x in r["hygiene"])
        L.append(f'pft_alertstats_hygiene_findings{{host="{host}",check="{c}",severity="{CHECKS[c][0]}"}} {n}')
    per = [
        ("flapping", "1 = the alertname is flapping (see the flap rule in the report).", lambda a: int(a["flapping"])),
        ("flaps", "Flaps of the alertname in the window.", lambda a: a["flaps"]),
        ("episodes_fired", "Fired episodes in the window.", lambda a: a["fired"]),
        ("episodes_pending_only", "Pending-only episodes (near misses) in the window.", lambda a: a["pending_only"]),
        ("ttr_p95_seconds", "95th percentile (nearest rank) time to resolve.", lambda a: a["ttr_p95_s"]),
        ("silenced_seconds", "Firing seconds covered by a matching silence.", lambda a: a["silenced_s"]),
    ]
    for name, help_, fn in per:
        L += [f"# HELP pft_alertstats_{name} {help_}", f"# TYPE pft_alertstats_{name} gauge"]
        for a in r["alerts"]:
            v = fn(a)
            if v is None:
                continue
            L.append(f'pft_alertstats_{name}{{host="{host}",alertname="{esc(a["alertname"])}"}} {v}')
    text = "\n".join(L) + "\n"
    if len(text.encode()) > TEXT_BUDGET:
        keep = [
            x
            for x in L
            if not x.startswith(
                ("pft_alertstats_flaps{", "pft_alertstats_episodes_", "pft_alertstats_ttr_", "pft_alertstats_silenced_")
            )
        ]
        text = "\n".join(keep) + "\n" + f'pft_alertstats_truncated{{host="{host}"}} 1\n'
    return text


def cmd_report(a):
    try:
        with open(a.offline, "rb") as f:
            raw = f.read()
        bundle = json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)
    except (OSError, ValueError) as e:
        die(f"cannot read bundle {a.offline}: {type(e).__name__}", 3)
    r = analyse(bundle)
    if a.format == "md":
        sys.stdout.write(out_md(r))
    elif a.format == "json":
        sys.stdout.write(out_json(r))
    elif a.format == "csv":
        sys.stdout.write(out_csv(r))
    else:
        sys.stdout.write(out_textfile(r, a.now if a.now else bundle["params"]["end"]))
    return 0 if r["sources"].get("prometheus") == "ok" else 4


def main(argv=None):
    ap = argparse.ArgumentParser(prog="alertstats_build.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--prometheus", default="http://127.0.0.1:9090")
    c.add_argument("--alertmanager", default="http://127.0.0.1:9093")
    c.add_argument("--since", default="7d")
    c.add_argument("--step", type=int, default=15)
    c.add_argument("--now", type=int, default=0)
    c.add_argument("--timeout", type=int, default=60)
    c.add_argument("--up-selector", default='up{job="postfiat"}')
    c.add_argument("--deliveries", default="")
    c.add_argument("--flap-window", default="1h")
    c.add_argument("--flap-min", type=int, default=3)
    c.add_argument("--flap-recent", default="24h")
    c.add_argument("--allow-no-for", default="PFTAlertPipelineWatchdog")
    c.add_argument("--host", default="validator")
    c.add_argument("--out", default="")
    r = sub.add_parser("report")
    r.add_argument("--offline", required=True)
    r.add_argument("--format", choices=("md", "json", "csv", "textfile"), default="md")
    r.add_argument("--now", type=int, default=0)
    a = ap.parse_args(argv)
    if a.cmd == "collect":
        if a.step <= 0 or a.flap_min < 2:
            die("--step must be > 0 and --flap-min >= 2")
        return cmd_collect(a)
    return cmd_report(a)


if __name__ == "__main__":
    sys.exit(main())
