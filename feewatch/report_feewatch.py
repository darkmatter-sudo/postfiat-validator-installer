#!/usr/bin/env python3
"""report_feewatch: 24h baseline report and independent crosscheck for pft-feewatch history files.

Usage:
  report_feewatch.py report --history FILE [FILE ...] [--start EPOCH] [--end EPOCH] [--threshold X]
                            --json OUT.json --md OUT.md
  report_feewatch.py crosscheck --history FILE [FILE ...] [--start EPOCH] [--end EPOCH] --rpc URL
                            [--sample N] [--seed S] [--max-lag S] [--negative] --json OUT.json
  report_feewatch.py crosscheck --offline OUT.json --history FILE [FILE ...]
  report_feewatch.py direct --history FILE --container NAME --fee FEE.json --info INFO.json --now EPOCH
                            [--max-age S] [--negative]

History files: one JSON line per successful collection, written by feewatch_parse.py --history (the unit passes
/var/lib/pft-feewatch/history-<container>.jsonl). Stdlib only, read-only.

report      per container: samples, coverage (minutes with a sample / minutes in the window, gaps > 2 min),
            distributions (min, p50, p95, p99, max, mean) of queue size and fill, open-ledger size vs expected,
            the escalation multiple, every load_factor source and the fee drops; minutes with escalation > 1,
            >= threshold, local > net; the observed values of base fee, max_queue_size, expected_ledger_size.
crosscheck  INDEPENDENT of the node that was sampled: for a seeded random sample of history lines, ask a different
            server (--rpc, e.g. the public Post Fiat RPC) for
              - ledger (ledger_current_index - 1): the last CLOSED ledger when the sample was taken. Its close
                time must not be after the sample time and at most --max-lag (default 30) s before it;
              - ledger_entry FeeSettings at that ledger: the base fee in drops (BaseFeeDrops, or BaseFee hex
                before the XRPFees amendment) must equal the recorded drops.base_fee.
            Every check prints OK or MISMATCH. --negative alters every recorded value first (ledger + 1000,
            base_fee + 1), so every check must MISMATCH: a control that the comparison can fail.
            --offline re-checks a recorded crosscheck JSON against the committed history with no RPC: the same
            sample is drawn again from (seed, history), every recorded answer is re-compared and the result must
            equal the recorded one.
direct      the values the public RPC cannot answer for the past (queue limit, expected ledger size, fee levels,
            load_factor) checked against the node itself: `fee` and `server_info` answers fetched by hand (not
            through pft-feewatch) are compared with the newest history line, which must be at most --max-age
            (default 90) s older; the open ledger may have advanced by at most age/2 + 2. --negative alters every
            recorded value, so every value check must MISMATCH.
"""

import argparse
import hashlib
import json
import random
import sys
import time
import urllib.request

FEE_SETTINGS = "4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651"  # keylet::fees(), space 'e'
RIPPLE_EPOCH = 946684800
SOURCES = ("total", "server", "local", "net", "cluster", "fee_escalation", "fee_queue")


def read_history(paths, start=None, end=None):
    rows, bad = [], 0
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for line in f:
                try:
                    d = json.loads(line)
                    ts = int(d["ts"])
                except (ValueError, KeyError, TypeError):
                    bad += 1
                    continue
                if (start is None or ts >= start) and (end is None or ts < end):
                    rows.append(d)
    rows.sort(key=lambda d: (d["container"], d["ts"]))
    return rows, bad


def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    i = min(len(sorted_vals) - 1, max(0, round(q * (len(sorted_vals) - 1))))
    return sorted_vals[i]


def dist(vals):
    v = sorted(x for x in vals if x is not None)
    if not v:
        return {"n": 0}
    return {
        "n": len(v),
        "min": v[0],
        "p50": pct(v, 0.5),
        "p95": pct(v, 0.95),
        "p99": pct(v, 0.99),
        "max": v[-1],
        "mean": round(sum(v) / len(v), 6),
    }


def counts(vals):
    out = {}
    for x in vals:
        out[str(x)] = out.get(str(x), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def summarize(rows, start, end, threshold):
    by = {}
    for d in rows:
        by.setdefault(d["container"], []).append(d)
    out = {}
    for c, rs in sorted(by.items()):
        t0 = start if start is not None else rs[0]["ts"]
        t1 = end if end is not None else rs[-1]["ts"] + 60
        minutes = max(1, (t1 - t0) // 60)
        mins_seen = len({(d["ts"] - t0) // 60 for d in rs})
        gaps = []
        prev = t0
        for d in rs:
            if d["ts"] - prev > 120:
                gaps.append({"from": prev, "to": d["ts"], "seconds": d["ts"] - prev})
            prev = d["ts"]
        if t1 - prev > 120:
            gaps.append({"from": prev, "to": t1, "seconds": t1 - prev})
        fill = [d["queue"] / d["max_queue"] for d in rs if d.get("max_queue")]
        src = {
            s: [(d["load_factor"] if s == "total" else d["sources"].get(s)) for d in rs]
            for s in SOURCES
        }
        local_gt_net = sum(
            1
            for d in rs
            if d["sources"].get("local") is not None
            and d["sources"].get("net") is not None
            and d["sources"]["local"] > d["sources"]["net"]
        )
        out[c] = {
            "window": {"start": t0, "end": t1, "minutes": minutes},
            "samples": len(rs),
            "coverage": round(mins_seen / minutes, 6),
            "gaps_over_2min": gaps,
            "admin_share": round(sum(1 for d in rs if d["admin"]) / len(rs), 6),
            "ledgers": {"first": rs[0]["ledger"], "last": rs[-1]["ledger"]},
            "queue_size": dist([d["queue"] for d in rs]),
            "queue_fill_ratio": dist(fill),
            "open_ledger_size": dist([d["cur_ledger"] for d in rs]),
            "open_ledger_over_expected_minutes": sum(
                1 for d in rs if d["cur_ledger"] > d["exp_ledger"]
            ),
            "escalation_multiple": dist([d["multiple"] for d in rs]),
            "escalated_minutes": sum(1 for d in rs if d["multiple"] > 1),
            "at_or_over_threshold_minutes": sum(
                1 for d in rs if d["multiple"] >= threshold
            ),
            "load_factor": {s: dist(v) for s, v in src.items()},
            "load_factor_above_1_minutes": {
                s: sum(1 for x in v if x is not None and x > 1) for s, v in src.items()
            },
            "local_over_net_minutes": local_gt_net,
            "fee_drops": {k: dist([d["drops"][k] for d in rs]) for k in rs[0]["drops"]},
            "observed": {
                "base_fee": counts(d["drops"]["base_fee"] for d in rs),
                "max_queue_size": counts(d["max_queue"] for d in rs),
                "expected_ledger_size": counts(d["exp_ledger"] for d in rs),
                "reference_level": counts(d["levels"]["reference_level"] for d in rs),
            },
        }
    return out


def fmt(x):
    if isinstance(x, float):
        return f"{x:.6g}"
    return str(x)


def markdown(rep):
    lines = [
        "# pft-feewatch baseline",
        "",
        (
            f"History rows used: {rep['rows']} (unparseable lines skipped: {rep['bad_lines']}). "
            f"Escalation threshold: {fmt(rep['threshold'])}."
        ),
        "",
    ]
    for c, s in rep["containers"].items():
        w = s["window"]
        lines += [
            f"## {c}",
            "",
            (
                f"- window {w['start']}..{w['end']} ({w['minutes']} min), samples {s['samples']}, "
                f"coverage {s['coverage']:.4f}, gaps > 2 min: {len(s['gaps_over_2min'])}, "
                f"admin answers {s['admin_share']:.4f}"
            ),
            f"- ledgers {s['ledgers']['first']}..{s['ledgers']['last']}",
            (
                f"- minutes with open ledger > expected: {s['open_ledger_over_expected_minutes']}; escalation > 1: "
                f"{s['escalated_minutes']}; >= threshold: {s['at_or_over_threshold_minutes']}; "
                f"local > net: {s['local_over_net_minutes']}"
            ),
            (
                f"- observed base fee {s['observed']['base_fee']}, max_queue_size {s['observed']['max_queue_size']}, "
                f"expected_ledger_size {s['observed']['expected_ledger_size']}"
            ),
            "",
            "| metric | n | min | p50 | p95 | p99 | max | mean |",
            "|---|---|---|---|---|---|---|---|",
        ]
        rowsrc = [
            ("queue size", s["queue_size"]),
            ("queue fill ratio", s["queue_fill_ratio"]),
            ("open ledger size", s["open_ledger_size"]),
            ("escalation multiple", s["escalation_multiple"]),
        ]
        rowsrc += [(f"load_factor {k}", v) for k, v in s["load_factor"].items()]
        rowsrc += [(f"drops {k}", v) for k, v in s["fee_drops"].items()]
        for name, d in rowsrc:
            if d["n"] == 0:
                lines.append(f"| {name} | 0 | | | | | | |")
            else:
                vals = " | ".join(
                    fmt(d[k]) for k in ("min", "p50", "p95", "p99", "max", "mean")
                )
                lines.append(f"| {name} | {d['n']} | {vals} |")
        lines.append("")
        above = {k: v for k, v in s["load_factor_above_1_minutes"].items() if v}
        lines.append(f"Minutes with a load_factor source above 1: {above or 'none'}")
        lines.append("")
    return "\n".join(lines)


def rpc(url, method, params):
    body = json.dumps({"method": method, "params": [params]}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read(1 << 22))["result"]


RETRY_DELAYS = (
    2,
    4,
    8,
)  # the public RPC sometimes answers lgrNotFound for a ledger it has, then succeeds


def rpc_retry(url, method, params, want, retries):
    """rpc() until the result has key `want`; every retry is printed and counted in retries[0]."""
    for n, delay in enumerate((*RETRY_DELAYS, None)):
        try:
            res = rpc(url, method, params)
            if want in res:
                return res
            why = res.get("error", f"no {want} in the answer")
        except (OSError, ValueError, KeyError) as e:
            why = f"{type(e).__name__}: {str(e)[:80]}"
        if delay is None:
            raise ValueError(
                f"{method} {params.get('ledger_index')}: {why} after {n + 1} tries"
            )
        retries[0] += 1
        print(
            f"RETRY    {method} ledger {params.get('ledger_index')}: {why}; again in {delay}s",
            flush=True,
        )
        time.sleep(delay)
    return None


def base_fee_of(node):
    if node.get("BaseFeeDrops") is not None:
        return int(node["BaseFeeDrops"])
    return int(node["BaseFee"], 16)


def draw(rows, n, seed):
    rng = random.Random(seed)
    idx = sorted(rng.sample(range(len(rows)), min(n, len(rows))))
    return [rows[i] for i in idx]


def compare(row, ans, max_lag, negative):
    ledger = row["ledger"] + (1000 if negative else 0)
    base = row["drops"]["base_fee"] + (1 if negative else 0)
    res = []
    if ans.get("error"):
        return [{"check": "rpc", "result": "MISMATCH", "detail": ans["error"]}]
    lag = row["ts"] - (ans["close_time"] + RIPPLE_EPOCH)
    ok = ans["ledger_index"] == ledger - 1 and 0 <= lag <= max_lag
    res.append(
        {
            "check": "closed ledger before the sample",
            "result": "OK" if ok else "MISMATCH",
            "detail": f"ledger {ans['ledger_index']} closed {lag}s before the sample (expected {ledger - 1}, 0..{max_lag}s)",
        }
    )
    ok = ans["base_fee"] == base
    res.append(
        {
            "check": "FeeSettings base fee",
            "result": "OK" if ok else "MISMATCH",
            "detail": f"FeeSettings {ans['base_fee']} drops vs recorded {base}",
        }
    )
    return res


def history_digest(rows):
    h = hashlib.sha256()
    for d in rows:
        h.update(json.dumps(d, sort_keys=True, separators=(",", ":")).encode())
    return h.hexdigest()


def crosscheck(a):
    rows, _ = read_history(a.history, a.start, a.end)
    if a.offline:
        with open(a.offline, encoding="utf-8") as f:
            rec = json.load(f)
        rows, _ = read_history(a.history, rec["start"], rec["end"])
        ok = history_digest(rows) == rec["history_sha256"]
        print(
            f"history sha256 {'matches' if ok else 'DIFFERS from'} the recorded one ({rec['history_sha256'][:16]})"
        )
        sample = draw(rows, rec["sample"], rec["seed"])
        same = [(s["container"], s["ts"]) for s in sample] == [
            (e["container"], e["ts"]) for e in rec["entries"]
        ]
        print(
            f"re-drawn sample ({len(sample)} rows, seed {rec['seed']}) {'equals' if same else 'DIFFERS from'} the recorded one"
        )
        fails = 0 if ok and same else 1
        for s, e in zip(sample, rec["entries"]):
            again = compare(s, e["answer"], rec["max_lag"], rec["negative"])
            if [r["result"] for r in again] != [r["result"] for r in e["checks"]]:
                fails += 1
                print(
                    f"DIFFERENT {e['container']} ts={e['ts']}: recorded {e['checks']} now {again}"
                )
        n_ok = sum(
            1 for e in rec["entries"] for r in e["checks"] if r["result"] == "OK"
        )
        n_all = sum(len(e["checks"]) for e in rec["entries"])
        print(
            f"offline: {len(rec['entries'])} entries re-compared, {n_ok}/{n_all} OK as recorded; differences: {fails}"
        )
        return 0 if fails == 0 else 1
    sample = draw(rows, a.sample, a.seed)
    entries = []
    retries = [0]
    for s in sample:
        try:
            led = rpc_retry(
                a.rpc, "ledger", {"ledger_index": s["ledger"] - 1}, "ledger", retries
            )["ledger"]
            fs = rpc_retry(
                a.rpc,
                "ledger_entry",
                {"index": FEE_SETTINGS, "ledger_index": s["ledger"] - 1},
                "node",
                retries,
            )["node"]
            ans = {
                "ledger_index": int(led["ledger_index"]),
                "close_time": int(led["close_time"]),
                "base_fee": base_fee_of(fs),
            }
        except (OSError, KeyError, ValueError) as e:
            ans = {"error": f"{type(e).__name__}: {str(e)[:80]}"}
        checks = compare(s, ans, a.max_lag, a.negative)
        entries.append(
            {
                "container": s["container"],
                "ts": s["ts"],
                "ledger": s["ledger"],
                "answer": ans,
                "checks": checks,
            }
        )
        for r in checks:
            print(
                f"{r['result']:<8} {s['container']} ts={s['ts']} ledger={s['ledger']}: {r['check']}: {r['detail']}"
            )
    n_ok = sum(1 for e in entries for r in e["checks"] if r["result"] == "OK")
    n_all = sum(len(e["checks"]) for e in entries)
    out = {
        "rpc": a.rpc,
        "start": a.start,
        "end": a.end,
        "seed": a.seed,
        "sample": a.sample,
        "max_lag": a.max_lag,
        "negative": a.negative,
        "history_rows": len(rows),
        "history_sha256": history_digest(rows),
        "ok": n_ok,
        "checks": n_all,
        "retries": retries[0],
        "entries": entries,
    }
    with open(a.json, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print(
        f"RESULT {n_ok}/{n_all} OK ({len(entries)} samples, {retries[0]} RPC retries"
        f"{', NEGATIVE control' if a.negative else ''})"
    )
    if a.negative:
        return 0 if n_ok == 0 else 1
    return 0 if n_ok == n_all and n_all > 0 else 1


def compare_direct(row, fee, info, now, max_age, negative):
    """Raw `fee` + `server_info` answers (fetched by hand, not through pft-feewatch) vs one history line."""
    f, i = fee["result"], info["result"]["info"]
    rec = {
        "ts": row["ts"],
        "base_fee": row["drops"]["base_fee"],
        "max_queue_size": row["max_queue"],
        "expected_ledger_size": row["exp_ledger"],
        "reference_level": row["levels"]["reference_level"],
        "minimum_level": row["levels"]["minimum_level"],
        "load_factor": row["load_factor"],
        "ledger": row["ledger"],
    }
    if negative:  # every recorded value altered: every check must MISMATCH
        rec = {
            k: (-1 if v is None else v + (1000 if k in ("ledger", "ts") else 1))
            for k, v in rec.items()
        }
    age = now - rec["ts"]
    got = {
        "base_fee": int(f["drops"]["base_fee"]),
        "max_queue_size": int(f["max_queue_size"]) if "max_queue_size" in f else None,
        "expected_ledger_size": int(f["expected_ledger_size"]),
        "reference_level": int(f["levels"]["reference_level"]),
        "minimum_level": int(f["levels"]["minimum_level"]),
        "load_factor": float(i["load_factor"]),
    }
    res = [
        {
            "check": "history line age",
            "result": "OK" if 0 <= age <= max_age else "MISMATCH",
            "detail": f"latest history line {age}s before the direct answer (0..{max_age}s)",
        }
    ]
    for k, v in got.items():
        res.append(
            {
                "check": k,
                "result": "OK" if v == rec[k] else "MISMATCH",
                "detail": f"direct {v} vs recorded {rec[k]}",
            }
        )
    # ledgers close every ~3-4 s: the open ledger may have moved on by at most age/2 + 2 ledgers
    led = int(f["ledger_current_index"])
    adv = led - rec["ledger"]
    res.append(
        {
            "check": "ledger_current_index",
            "result": "OK" if 0 <= adv <= age // 2 + 2 else "MISMATCH",
            "detail": f"direct {led}, recorded {rec['ledger']} (+{adv}, allowed 0..{age // 2 + 2})",
        }
    )
    return res


def direct(a):
    rows, _ = read_history(a.history)
    rows = [d for d in rows if d["container"] == a.container]
    if not rows:
        print(f"no history rows for {a.container}", file=sys.stderr)
        return 1
    with open(a.fee, encoding="utf-8") as f:
        fee = json.load(f)
    with open(a.info, encoding="utf-8") as f:
        info = json.load(f)
    row = max(rows, key=lambda d: d["ts"])
    checks = compare_direct(row, fee, info, a.now, a.max_age, a.negative)
    for r in checks:
        print(
            f"{r['result']:<8} {a.container} ts={row['ts']}: {r['check']}: {r['detail']}"
        )
    n_ok = sum(1 for r in checks if r["result"] == "OK")
    print(
        f"RESULT {n_ok}/{len(checks)} OK (direct RPC vs latest history line{', NEGATIVE control' if a.negative else ''})"
    )
    if a.negative:
        return 0 if n_ok == 0 else 1
    return 0 if n_ok == len(checks) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report")
    c = sub.add_parser("crosscheck")
    dr = sub.add_parser("direct")
    dr.add_argument("--history", nargs="+", required=True)
    dr.add_argument("--container", required=True)
    dr.add_argument("--fee", required=True)
    dr.add_argument("--info", required=True)
    dr.add_argument("--now", type=int, required=True)
    dr.add_argument("--max-age", type=int, default=90)
    dr.add_argument("--negative", action="store_true")
    for p in (r, c):
        p.add_argument("--history", nargs="+", required=True)
        p.add_argument("--start", type=int)
        p.add_argument("--end", type=int)
    r.add_argument("--threshold", type=float, default=4.0)
    r.add_argument("--json", required=True)
    r.add_argument("--md", required=True)
    c.add_argument("--rpc")
    c.add_argument("--sample", type=int, default=30)
    c.add_argument("--seed", type=int, default=1)
    c.add_argument("--max-lag", type=int, default=30)
    c.add_argument("--negative", action="store_true")
    c.add_argument("--json")
    c.add_argument("--offline")
    a = ap.parse_args(argv)
    if a.cmd == "direct":
        return direct(a)
    if a.cmd == "report":
        rows, bad = read_history(a.history, a.start, a.end)
        if not rows:
            print("report_feewatch: no history rows in the window", file=sys.stderr)
            return 1
        rep = {
            "rows": len(rows),
            "bad_lines": bad,
            "threshold": a.threshold,
            "containers": summarize(rows, a.start, a.end, a.threshold),
        }
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=1, sort_keys=True)
            f.write("\n")
        with open(a.md, "w", encoding="utf-8") as f:
            f.write(markdown(rep) + "\n")
        print(markdown(rep))
        return 0
    if not a.offline and not (a.rpc and a.json):
        ap.error("crosscheck needs --rpc and --json (or --offline)")
    return crosscheck(a)


if __name__ == "__main__":
    sys.exit(main())
