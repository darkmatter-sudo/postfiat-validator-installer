#!/usr/bin/env python3
"""Offline tests for report.py with a hand-built history (restart, gap, brief exit). Run: python3 test_report.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402

FAILS = []


def check(name, cond):
    print("%s %s" % ("PASS" if cond else "FAIL", name))
    if not cond:
        FAILS.append(name)


def row(ts, up, full_us, full_tr, tr_other=1, exits=0, io=1, disc=0, jq=0, state="full"):
    acct = {m: [0, tr_other] for m in report.MODES}
    acct["full"] = [full_us, full_tr]
    return {"ts": ts, "container": "c1", "state": state, "state_duration_us": full_us, "acct": acct,
            "full_exits": exits, "io_latency_ms": io, "jq_trans_overflow": jq, "peer_disconnects": disc,
            "peer_disconnects_resources": 0, "uptime": up, "peers": 10}


def main():
    t0 = 1800000000  # a clock-hour boundary (1800000000 % 3600 == 0)
    rows = []
    # 2 h in full, 1 sample/min; disconnects +1 every 10 min; io 1 ms, one 80 ms sample
    for i in range(121):
        rows.append(row(t0 + 60 * i, 1000 + 60 * i, (1000 + 60 * i) * 10**6, 1, disc=i // 10, io=80 if i == 50 else 1))
    # brief exit at minute 70: tracking for 5 s inside one minute, back in full (exits 1, full transitions 2)
    for i in range(70, 121):
        r = rows[i]
        r["full_exits"] = 1
        r["acct"]["full"][1] = 2
        r["acct"]["tracking"] = [5 * 10**6, 2]
        r["acct"]["full"][0] -= 5 * 10**6
    # 3-minute gap, then a restart: uptime and every counter back near 0
    rr = []
    for k in range(30):
        ts = t0 + 60 * 123 + 60 * k
        up = 30 + 60 * k
        r = row(ts, up, max(0, up - 40) * 10**6, 1, tr_other=1, disc=k // 15)
        r["acct"]["syncing"] = [40 * 10**6, 1]
        rr.append(r)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "h.jsonl")
        with open(p, "w") as f:
            for r in rows + rr:
                f.write(json.dumps(r) + "\n")
            f.write("\n")
        s = report.analyse(report.load(p), 50, 30)
        md = report.markdown(s)
    check("samples 151", s["samples"] == 151)
    check("one gap of 180 s", len(s["gaps"]) == 1 and s["gaps"][0][2] == 180)
    check("one restart", len(s["restarts"]) == 1)
    check("full exits counted once (restart is not an exit)", s["full_exits"] == 1)
    # transitions: tracking +1 and full +1 at the brief exit; after the restart the post-reset values count
    # (disconnected 1, connected 1, syncing 1, tracking 1, full 1) although disconnected/connected came back at their
    # old value 1 (no visible counter drop): the uptime drop marks the restart
    check("transitions reset-aware", s["transitions"] == {"disconnected": 1, "connected": 1, "syncing": 1,
                                                           "tracking": 2, "full": 2})
    check("tracking time 5 s", abs(s["time_s"]["tracking"] - 5.0) < 1e-6)
    check("syncing time 40 s (post-reset value)", abs(s["time_s"]["syncing"] - 40.0) < 1e-6)
    check("full share > 99%", s["time_share_pct"]["full"] > 99)
    check("io max 80, p50 1, 1 sample above 50", s["io_latency_ms"]["max"] == 80 and s["io_latency_ms"]["p50"] == 1
          and s["io_latency_ms"]["above_threshold"] == 1)
    # disconnects: 0..12 over the first 2 h (+12), then reset to 0 and 0..1 (+1 after the reset)
    check("disconnects reset-aware +13", s["peer_disconnects"] == 13)
    check("hourly max over full clock hours only (6 per hour)", s["disconnects_hourly_max"] == 6
          and len(s["disconnects_full_hours"]) == 2)
    check("markdown has the mode table", "| tracking |" in md and "restart seen at" in md)
    check("markdown names the full-hour count", "max in one full clock hour: 6 (over 2 full clock hours" in md)
    check("pct nearest-rank", report.pct([1, 2, 3, 4], 0.5) == 2 and report.pct([1, 2, 3, 4], 0.99) == 4)
    check("inc reset", report.inc(10, 3) == 3 and report.inc(3, 10) == 7 and report.inc(2, 2, True) == 2)
    print("RESULT: %d failed" % len(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
