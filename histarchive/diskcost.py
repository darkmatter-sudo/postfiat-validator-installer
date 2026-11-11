#!/usr/bin/env python3
"""Measured disk cost of a pft-histarchive archive (read-only).

For every sealed day in MANIFEST.jsonl: ledgers, transactions, raw and gzip bytes (as recorded and as on disk), the
ledger close-time span read from the first and last header in the segment, and from that the observed ledger rate.
The projection to a full day / 30 days / a year uses the totals over all sealed days (bytes per ledger x ledgers
per second), so a partial first day is fine. Optional --replica DIR / --outbox DIR add the encrypted copies.

  python3 diskcost.py --dir /var/lib/pft-histarchive/archive [--outbox DIR] [--json]
  python3 diskcost.py --replica /var/lib/pft-histarchive/replica [--json]      (the peer: ciphertext only)
Exit: 0 ok | 2 nothing to measure / unreadable input | 3 usage
"""

import argparse
import gzip
import json
import os
import sys

RIPPLE_EPOCH = 946684800  # close times count seconds from 2000-01-01T00:00:00Z
CLOSE_OFF = (
    4 + 8 + 32 + 32 + 32 + 4
)  # seq, drops, parent, tx root, state root, parent close time


def close_time(header_hex):
    b = bytes.fromhex(header_hex)
    return int.from_bytes(b[CLOSE_OFF : CLOSE_OFF + 4], "big") + RIPPLE_EPOCH


def first_last(path):
    first = last = None
    with gzip.open(path, "rt") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            if first is None:
                first = rec
            last = rec
    return first, last


def dir_bytes(d):
    total = n = 0
    for root, _dirs, files in os.walk(d):
        for name in files:
            total += os.path.getsize(os.path.join(root, name))
            n += 1
    return total, n


def measure(archive, outbox=None):
    man = os.path.join(archive, "MANIFEST.jsonl")
    with open(man) as f:
        entries = [json.loads(x) for x in f if x.strip()]
    days = []
    for e in entries:
        seg = os.path.join(archive, e["segment"])
        a, z = first_last(seg)
        t0, t1 = close_time(a["d"]), close_time(z["d"])
        days.append(
            {
                "day": e["day"],
                "ledgers": e["count"],
                "first": e["first"],
                "last": e["last"],
                "txs": e.get("txs"),
                "bytes_raw": e["bytes_raw"],
                "bytes_gz": e["bytes_gz"],
                "bytes_gz_on_disk": os.path.getsize(seg),
                "close_span_s": t1 - t0,
                "ratio": round(e["bytes_raw"] / e["bytes_gz"], 2),
            }
        )
    out = {"archive": {"sealed_days": days}}
    if days:
        led = sum(d["ledgers"] for d in days)
        gz = sum(d["bytes_gz"] for d in days)
        raw = sum(d["bytes_raw"] for d in days)
        span = sum(d["close_span_s"] for d in days)
        rate = (
            (led - len(days)) / span if span > 0 else 0.0
        )  # intervals, not ledgers, per span
        per_day = rate * 86400
        out["archive"]["totals"] = {
            "ledgers": led,
            "bytes_raw": raw,
            "bytes_gz": gz,
            "gz_bytes_per_ledger": round(gz / led, 1),
            "raw_bytes_per_ledger": round(raw / led, 1),
            "ledgers_per_s": round(rate, 4),
            "projected_ledgers_per_day": round(per_day),
            "projected_gz_bytes_per_day": round(per_day * gz / led),
            "projected_gz_bytes_30d": round(30 * per_day * gz / led),
            "projected_gz_bytes_365d": round(365 * per_day * gz / led),
            "projected_active_raw_bytes_max": round(per_day * raw / led),
        }
    act = os.path.join(archive, "active")
    out["archive"]["active_bytes"], out["archive"]["active_files"] = (
        dir_bytes(act) if os.path.isdir(act) else (0, 0)
    )
    out["archive"]["total_bytes"], out["archive"]["total_files"] = dir_bytes(archive)
    if outbox:
        out["outbox_bytes"], out["outbox_files"] = dir_bytes(outbox)
    return out


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1000
    return str(n)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--dir", help="archive dir (MANIFEST.jsonl, segments/, active/)")
    p.add_argument(
        "--outbox", help="validator outbox (encrypted copies sent to the peer)"
    )
    p.add_argument("--replica", help="peer replica dir (ciphertext only)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if not a.dir and not a.replica:
        p.error("--dir or --replica is required")
    try:
        res = measure(a.dir, a.outbox) if a.dir else {}
        if a.replica:
            res["replica_bytes"], res["replica_files"] = dir_bytes(a.replica)
    except (OSError, ValueError, KeyError) as e:
        print(f"diskcost: cannot measure: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(res, sort_keys=True))
        return 0
    if a.dir:
        print("| sealed day | ledgers | close-time span | txs | raw | gzip | ratio |")
        print("|---|---|---|---|---|---|---|")
        for d in res["archive"]["sealed_days"]:
            print(
                f"| {d['day']} | {d['ledgers']} ({d['first']}-{d['last']}) | {d['close_span_s']} s | {d['txs']} "
                f"| {human(d['bytes_raw'])} | {human(d['bytes_gz'])} | {d['ratio']}x |"
            )
        t = res["archive"].get("totals")
        if not t:
            print("no sealed day yet: nothing to project")
            return 2
        print()
        print("| measure | value |")
        print("|---|---|")
        print(
            f"| gzip bytes per ledger | {t['gz_bytes_per_ledger']} B (raw {t['raw_bytes_per_ledger']} B) |"
        )
        print(
            f"| observed ledger rate | {t['ledgers_per_s']} /s = {t['projected_ledgers_per_day']} ledgers/day |"
        )
        print(
            f"| projected sealed archive | {human(t['projected_gz_bytes_per_day'])}/day, "
            f"{human(t['projected_gz_bytes_30d'])}/30 days, {human(t['projected_gz_bytes_365d'])}/year |"
        )
        print(
            f"| largest active (uncompressed) day | {human(t['projected_active_raw_bytes_max'])} |"
        )
        print(
            f"| archive dir now | {human(res['archive']['total_bytes'])} in {res['archive']['total_files']} files "
            f"(active {human(res['archive']['active_bytes'])}) |"
        )
        if a.outbox:
            print(
                f"| validator outbox (encrypted copies) | {human(res['outbox_bytes'])} in {res['outbox_files']} files |"
            )
    if a.replica:
        print(
            f"| sentry replica (ciphertext) | {human(res['replica_bytes'])} in {res['replica_files']} files |"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
