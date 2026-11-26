#!/usr/bin/env python3
"""Cross-host skew measurement and old-vs-new replay of the valwatch disagreement rules.

The validator's Prometheus holds pft_valwatch_* for two nodes: the validator's own textfile and the sentry's, which
pft-valwatch-pull copies over afterwards. At one evaluation instant the two nodes' samples can describe different
minutes, so a change seen by BOTH nodes first shows on one node only. This tool:

  collect --prom URL --old-rules F --new-rules F --out DIR [--end EPOCH] [--step 15]
      read-only Prometheus HTTP API queries over the whole retained valwatch history (query_range, 1-day chunks, the
      rule evaluation step):
        skew.json      pft_valwatch_collect_timestamp_seconds{validator node} - {sentry node} at every step;
        replay.json    every step where the OLD and the NEW expression of PFTValwatchHostsDisagree / ...Late matched
                       (both read from the given rule files), per node and validator;
        context.json   both nodes' raw metric for every validator an old match names, +-15 min around each match.
      Files are written sorted with fixed float formatting, so a re-collect of the same range is byte-identical.
  analyze DIR [--out FILE]
      offline (no Prometheus): skew distribution, pending intervals per rule (consecutive matching steps), old-only /
      new-only intervals and an attribution of every old-only interval:
        skew  the other node crossed the same faulty threshold within max|skew| + 1 step of the interval and the
              interval is no longer than max|skew| + 1 step (both nodes saw it; one saw it first);
        real  otherwise (a genuine one-node difference the new rule no longer pends on: reported, never hidden).
      Exit 0 when every old-only interval is attributed `skew` and new-only is 0, 1 otherwise.
analyze is stdlib only (python3, no node, no Prometheus); collect also needs PyYAML to read the rule files.
"""

import argparse
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request

V, SN = "postfiatd", "postfiatd-sentry"
ALERTS = {
    # alert: (metric, faulty predicate on one sample)
    "PFTValwatchHostsDisagree": ("pft_valwatch_validator_participation_ratio", lambda x: x < 0.8),
    "PFTValwatchHostsDisagreeLate": ("pft_valwatch_validator_delay_p95_ms", lambda x: x > 3000),
}
SKEW_EXPR = (
    f'pft_valwatch_collect_timestamp_seconds{{node="{V}"}}'
    f' - on (job, instance) pft_valwatch_collect_timestamp_seconds{{node="{SN}"}}'
)
CONTEXT = 900  # s of raw metric kept around each old match


def query(prom, path, **params):
    url = prom.rstrip("/") + "/api/v1/" + path + "?" + urllib.parse.urlencode(params)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                doc = json.load(r)
            if doc.get("status") == "success":
                return doc["data"]
            raise RuntimeError(doc.get("error", "status != success"))
        except Exception as e:
            if attempt == 3:
                raise RuntimeError(f"{path} {params.get('query', '')[:80]}: {e}") from e
            print(f"retry {attempt + 1}: {path}: {e}", file=sys.stderr)
            time.sleep(2 * (attempt + 1))
    raise AssertionError


def qrange(prom, expr, start, end, step):
    """query_range over [start, end] in 1-day chunks -> {labels-json: {t: value}}."""
    out = {}
    t = start
    while t <= end:
        e = min(end, t + 86400 - step)
        for s in query(prom, "query_range", query=expr, start=t, end=e, step=step)["result"]:
            key = json.dumps({k: v for k, v in sorted(s["metric"].items()) if k != "__name__"}, sort_keys=True)
            out.setdefault(key, {}).update({int(float(ts)): float(v) for ts, v in s["values"]})
        t = e + step
    return out


def rule_exprs(path):
    import yaml  # collect only: analyze stays stdlib

    with open(path, encoding="utf-8") as f:
        rules = {r["alert"]: r for g in yaml.safe_load(f)["groups"] for r in g["rules"] if "alert" in r}
    return {a: " ".join(rules[a]["expr"].split()) for a in ALERTS}


def dump(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, indent=0, separators=(",", ":"))
        f.write("\n")


def collect(a):
    end = int(a.end or time.time()) // a.step * a.step
    first = query(a.prom, "query", query="min_over_time(timestamp(pft_valwatch_up)[15d:1m])", time=end)["result"]
    if not first:
        sys.exit("no pft_valwatch_up in retained history")
    start = (int(min(float(s["value"][1]) for s in first)) // a.step + 1) * a.step
    build = query(a.prom, "status/buildinfo")
    old, new = rule_exprs(a.old_rules), rule_exprs(a.new_rules)
    os.makedirs(a.out, exist_ok=True)
    print(f"range {start} .. {end} ({(end - start) / 86400:.2f} d), step {a.step} s, prometheus {build['version']}")
    skew = qrange(a.prom, SKEW_EXPR, start, end, a.step)
    if len(skew) != 1:
        sys.exit(f"skew expression returned {len(skew)} series, expected 1")
    pts = next(iter(skew.values()))
    dump(os.path.join(a.out, "skew.json"), {"expr": SKEW_EXPR, "points": [[t, pts[t]] for t in sorted(pts)]})
    replay, ctx_keys = {}, {}
    for alert in ALERTS:
        for side, exprs in (("old", old), ("new", new)):
            res = qrange(a.prom, exprs[alert], start, end, a.step)
            rows = []
            for key, vals in res.items():
                lab = json.loads(key)
                rows.append({"node": lab["node"], "validator": lab["validator"], "steps": sorted(vals)})
                if side == "old":
                    for t in vals:
                        ctx_keys.setdefault((alert, lab["validator"]), set()).add(t)
            replay.setdefault(alert, {})[side] = {
                "expr": exprs[alert],
                "series": sorted(rows, key=lambda r: (r["node"], r["validator"])),
            }
            print(f"{alert} {side}: {sum(len(r['steps']) for r in rows)} matching steps in {len(rows)} series")
    context = []
    for (alert, val), ts in sorted(ctx_keys.items()):
        metric = ALERTS[alert][0]
        lo, hi = min(ts) - CONTEXT, max(ts) + CONTEXT
        res = qrange(a.prom, f'{metric}{{validator="{val}"}}', lo, hi, a.step)
        for key, vals in sorted(res.items()):
            context.append(
                {
                    "alert": alert,
                    "node": json.loads(key)["node"],
                    "validator": val,
                    "points": [[t, vals[t]] for t in sorted(vals)],
                }
            )
    dump(os.path.join(a.out, "replay.json"), replay)
    dump(os.path.join(a.out, "context.json"), context)
    meta = {
        "start": start,
        "end": end,
        "step": a.step,
        "prometheus": build["version"],
        "old_rules_sha256": sha256(a.old_rules),
        "new_rules_sha256": sha256(a.new_rules),
    }
    dump(os.path.join(a.out, "meta.json"), meta)
    for f in sorted(os.listdir(a.out)):
        print(f"wrote {f} sha256 {sha256(os.path.join(a.out, f))}")


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load(d, name):
    p = os.path.join(d, name)
    opener = gzip.open if not os.path.exists(p) and os.path.exists(p + ".gz") else open
    with opener(p if opener is open else p + ".gz", "rt", encoding="utf-8") as f:
        return json.load(f)


def intervals(steps, step):
    """Sorted step times -> [(first, last)] of runs with no gap > step."""
    out = []
    for t in steps:
        if out and t - out[-1][1] <= step:
            out[-1][1] = t
        else:
            out.append([t, t])
    return [tuple(x) for x in out]


def pct(xs, q):
    s = sorted(xs)
    return s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))]


def utc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def attribute(alert, node, val, iv, context, max_skew, step):
    """-> (verdict, reason) for an old-only interval iv = (first, last) of (node, val)."""
    other = SN if node == V else V
    pred = ALERTS[alert][1]
    lo, hi = iv[0] - max_skew - step, iv[1] + max_skew + step
    pts = [
        p for c in context if c["alert"] == alert and c["node"] == other and c["validator"] == val for p in c["points"]
    ]
    near = [(t, x) for t, x in pts if lo <= t <= hi and pred(x)]
    dur = iv[1] - iv[0] + step
    if near and dur <= max_skew + step:
        t, x = min(near, key=lambda p: abs(p[0] - iv[0]))
        return (
            "skew",
            f"{other} crossed the same threshold at {utc(t)} ({x:g}, {t - iv[0]:+d} s); {dur} s <= {max_skew + step} s",
        )
    if not near:
        return "real", f"{other} never crossed the threshold within {utc(lo)} .. {utc(hi)}"
    return "real", f"{dur} s longer than max skew {max_skew} s + 1 step"


def analyze(a):
    meta, skew, replay, context = (load(a.dir, n) for n in ("meta.json", "skew.json", "replay.json", "context.json"))
    step = meta["step"]
    lines = [
        (
            f"range {utc(meta['start'])} .. {utc(meta['end'])} ({(meta['end'] - meta['start']) / 86400:.2f} d), step "
            f"{step} s, prometheus {meta['prometheus']}"
        ),
        f"old rules sha256 {meta['old_rules_sha256']}",
        f"new rules sha256 {meta['new_rules_sha256']}",
    ]
    xs = [v for _, v in skew["points"]]
    max_skew = int(max(abs(min(xs)), abs(max(xs))))
    lines.append(f"SKEW validator - sentry collect_timestamp (s): n={len(xs)}")
    lines.append(
        f"SKEW min {min(xs):g} p01 {pct(xs, 0.01):g} p50 {pct(xs, 0.5):g} p75 {pct(xs, 0.75):g} p90 {pct(xs, 0.9):g} p99 {pct(xs, 0.99):g} max {max(xs):g} max|skew| {max_skew}"
    )
    buckets = {}
    for x in xs:
        b = int(x // 15) * 15
        buckets[b] = buckets.get(b, 0) + 1
    for b in sorted(buckets):
        lines.append(f"SKEW_HIST [{b:+d}, {b + 15:+d}) s: {buckets[b]} ({100 * buckets[b] / len(xs):.2f}%)")
    lines.append(f"SKEW share of steps with |skew| > 15 s: {100 * sum(1 for x in xs if abs(x) > 15) / len(xs):.2f}%")
    # a [W] window on both sides absorbs a lag of up to W - 1 step (see ../alerts/valwatch.rules.yml)
    absorb = a.window - step
    out = [(t, v) for t, v in skew["points"] if abs(v) > absorb]
    lines.append(
        f"SKEW window {a.window} s absorbs |skew| <= {absorb} s: {len(xs) - len(out)}/{len(xs)} steps "
        f"({100 * (len(xs) - len(out)) / len(xs):.3f}%), outside: {len(out)}"
    )
    for t, v in out:
        lines.append(f"SKEW_OUTSIDE {utc(t)} {v:g} s")
    rest = [abs(v) for t, v in skew["points"] if abs(v) <= absorb]
    lines.append(f"SKEW max |skew| of the absorbed steps: {max(rest):g} s")
    bad = 0
    for alert in sorted(ALERTS):
        ivs = {}
        for side in ("old", "new"):
            for r in replay[alert][side]["series"]:
                for iv in intervals(r["steps"], step):
                    ivs.setdefault(side, []).append((r["node"], r["validator"], iv))
        old, new = ivs.get("old", []), ivs.get("new", [])

        def overlaps(x, pool):
            return any(n == x[0] and v == x[1] and i[0] <= x[2][1] and x[2][0] <= i[1] for n, v, i in pool)

        old_only = [x for x in old if not overlaps(x, new)]
        new_only = [x for x in new if not overlaps(x, old)]
        both = len(old) - len(old_only)
        lines.append(
            f"REPLAY {alert}: old {len(old)} pending intervals ({sum(i[1] - i[0] + step for *_, i in old)} s), new "
            f"{len(new)} ({sum(i[1] - i[0] + step for *_, i in new)} s), both {both}, old-only {len(old_only)}, "
            f"new-only {len(new_only)}"
        )
        for n, v, iv in sorted(old_only):
            verdict, why = attribute(alert, n, v, iv, context, max_skew, step)
            lines.append(
                f"OLD_ONLY {alert} node={n} validator={v} {utc(iv[0])} .. {utc(iv[1])} "
                f"({iv[1] - iv[0] + step} s): {verdict.upper()} - {why}"
            )
            bad += verdict != "skew"
        for n, v, iv in sorted(new_only):
            lines.append(f"NEW_ONLY {alert} node={n} validator={v} {utc(iv[0])} .. {utc(iv[1])}")
            bad += 1
    lines.append(
        f"RESULT: {'PASS' if bad == 0 else 'FAIL'} ({bad} old-only intervals not attributed to skew + new-only)"
    )
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    return 0 if bad == 0 else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--prom", default="http://127.0.0.1:9090")
    c.add_argument("--old-rules", required=True)
    c.add_argument("--new-rules", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--end", type=int)
    c.add_argument("--step", type=int, default=15)
    z = sub.add_parser("analyze")
    z.add_argument("dir")
    z.add_argument("--out")
    z.add_argument("--window", type=int, default=120, help="rule window in s (default 120 = [2m])")
    a = ap.parse_args(argv)
    if a.cmd == "collect":
        collect(a)
        return 0
    return analyze(a)


if __name__ == "__main__":
    sys.exit(main())
