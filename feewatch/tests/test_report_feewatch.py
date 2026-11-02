#!/usr/bin/env python3
"""Offline tests for report_feewatch.py: report, crosscheck (stub RPC server on 127.0.0.1), --offline, direct.

  python3 -u feewatch/tests/test_report_feewatch.py [REPORT_SCRIPT]
Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed. Stdlib only, nothing
outside a temp dir is read or written, no network beyond the loopback stub.
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = (
    sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "report_feewatch.py")
)
spec = importlib.util.spec_from_file_location("report_feewatch", SRC)
rf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rf)

passed = total = 0


def check(name, cond):
    global passed, total
    total += 1
    passed += bool(cond)
    print(f"{'PASS' if cond else 'FAIL'} {name}")


T0 = 1793492400  # window start (epoch, a whole minute)
CLOSE_LAG = 5  # the stub's ledger N-1 closed 5 s before the sample


def row(
    i,
    container="postfiatd",
    queue=0,
    multiple=1.0,
    local=1.0,
    net=1.0,
    base=10,
    max_queue=2000,
):
    return {
        "admin": True,
        "container": container,
        "cur_ledger": 3,
        "drops": {
            "base_fee": base,
            "median_fee": 5000,
            "minimum_fee": 10,
            "open_ledger_fee": 10,
        },
        "exp_ledger": 32,
        "ledger": 1000 + i * 17,
        "levels": {
            "median_level": 128000,
            "minimum_level": 256,
            "open_ledger_level": 256,
            "reference_level": 256,
        },
        "load_factor": 1.0,
        "max_queue": max_queue,
        "multiple": multiple,
        "queue": queue,
        "sources": {
            "cluster": 1.0,
            "fee_escalation": multiple,
            "fee_queue": 1.0,
            "local": local,
            "net": net,
            "server": 1.0,
        },
        "ts": T0 + i * 60 + 12,
    }


def rjson(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def wjson(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            rc = rf.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue()


tmp = tempfile.mkdtemp()
hist = os.path.join(tmp, "history.jsonl")

# --- report: 60 minutes, minute 30..33 missing (a 5-min gap), escalation in minutes 10-12, local > net in 20
rows = []
for i in range(60):
    if 30 <= i <= 33:
        continue
    kw = {}
    if 10 <= i <= 12:
        kw = {"queue": 500, "multiple": 5.0 if i == 11 else 2.0}
    if i == 20:
        kw = {"local": 3.0}
    rows.append(row(i, **kw))
rows.append(row(5, container="postfiatd-sentry"))
with open(hist, "w", encoding="utf-8") as f:
    f.writelines(json.dumps(d) + "\n" for d in rows)
    f.write("not json\n")
    f.write('{"no_ts": 1}\n')
J, M = os.path.join(tmp, "r.json"), os.path.join(tmp, "r.md")
rc, out = run(
    [
        "report",
        "--history",
        hist,
        "--start",
        str(T0),
        "--end",
        str(T0 + 3600),
        "--json",
        J,
        "--md",
        M,
    ]
)
rep = rjson(J)
v = rep["containers"]["postfiatd"]
check("report exit 0", rc == 0)
check("report counts 2 unparseable lines", rep["bad_lines"] == 2)
check("report rows = 57 (56 validator + 1 sentry)", rep["rows"] == 57)
check("validator samples 56", v["samples"] == 56)
check("validator coverage 56/60 (6 decimals)", v["coverage"] == round(56 / 60, 6))
check(
    "one gap > 2 min (minute 29 -> 34, 300 s)",
    [g["seconds"] for g in v["gaps_over_2min"]] == [300],
)
check("escalated minutes 3", v["escalated_minutes"] == 3)
check("at/over threshold 4.0 minutes 1", v["at_or_over_threshold_minutes"] == 1)
check(
    "escalation max 5.0, p50 1.0",
    v["escalation_multiple"]["max"] == 5.0 and v["escalation_multiple"]["p50"] == 1.0,
)
check("queue fill max 0.25", v["queue_fill_ratio"]["max"] == 0.25)
check("local > net minutes 1", v["local_over_net_minutes"] == 1)
check(
    "load_factor local above 1 minutes 1",
    v["load_factor_above_1_minutes"]["local"] == 1,
)
check(
    "sentry reported separately (1 sample, end gap)",
    rep["containers"]["postfiatd-sentry"]["samples"] == 1,
)
check(
    "markdown has both containers",
    "## postfiatd\n" in out and "## postfiatd-sentry" in out,
)
rc, _ = run(
    ["report", "--history", hist, "--start", str(T0 + 99999), "--json", J, "--md", M]
)
check("empty window -> exit 1", rc == 1)
check("window end is exclusive", rf.read_history([hist], T0, T0 + 12)[0] == [])


# --- crosscheck against a stub RPC that answers from the true rows (ledger N-1 closed CLOSE_LAG s before)
class Stub(BaseHTTPRequestHandler):
    truth: ClassVar[dict] = {}
    fail: ClassVar[set] = set()
    flaky: ClassVar[
        dict
    ] = {}  # ledger -> number of lgrNotFound answers before the real one

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        p = body["params"][0]
        idx = p["ledger_index"]
        if Stub.flaky.get(idx, 0) > 0:
            Stub.flaky[idx] -= 1
            res = {"error": "lgrNotFound", "status": "error"}
        elif idx in Stub.fail:
            res = {"error": "lgrNotFound", "status": "error"}
        elif body["method"] == "ledger":
            ts = Stub.truth[idx]
            res = {
                "ledger": {
                    "ledger_index": str(idx),
                    "close_time": ts - CLOSE_LAG - rf.RIPPLE_EPOCH,
                }
            }
        else:
            res = {"node": {"BaseFeeDrops": 10, "LedgerEntryType": "FeeSettings"}}
        data = json.dumps({"result": res}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


Stub.truth = {d["ledger"] - 1: d["ts"] for d in rows}
srv = HTTPServer(("127.0.0.1", 0), Stub)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{srv.server_port}/"
CX = os.path.join(tmp, "cx.json")
base = [
    "crosscheck",
    "--history",
    hist,
    "--start",
    str(T0),
    "--end",
    str(T0 + 3600),
    "--rpc",
    URL,
    "--sample",
    "10",
]
rc, out = run(base + ["--json", CX])
cx = rjson(CX)
check("crosscheck exit 0, 20/20 OK", rc == 0 and cx["ok"] == 20 and cx["checks"] == 20)
check(
    "crosscheck prints RESULT 20/20 OK",
    "RESULT 20/20 OK (10 samples, 0 RPC retries)" in out,
)
rc, out = run(["crosscheck", "--offline", CX, "--history", hist])
check(
    "offline re-check exit 0, 0 differences",
    rc == 0 and "differences: 0" in out and "history sha256 matches" in out,
)

CN = os.path.join(tmp, "cn.json")
rc, out = run(base + ["--negative", "--json", CN])
cn = rjson(CN)
check("negative: exit 0 and 0/20 OK", rc == 0 and cn["ok"] == 0 and cn["checks"] == 20)
check("negative: every line MISMATCH", out.count("MISMATCH") == 20)
rc, out = run(["crosscheck", "--offline", CN, "--history", hist])
check(
    "offline re-check of the negative run exit 0",
    rc == 0 and "0/20 OK as recorded" in out,
)

# a wrong base fee in history (11 at one sampled ledger) must MISMATCH
bad = copy.deepcopy(rows)
for d in bad:
    if (
        d["ts"] == cx["entries"][0]["ts"]
        and d["container"] == cx["entries"][0]["container"]
    ):
        d["drops"]["base_fee"] = 11
hist2 = os.path.join(tmp, "history2.jsonl")
with open(hist2, "w", encoding="utf-8") as f:
    f.write("".join(json.dumps(d) + "\n" for d in bad))
C2 = os.path.join(tmp, "c2.json")
rc, out = run(
    [
        "crosscheck",
        "--history",
        hist2,
        "--start",
        str(T0),
        "--end",
        str(T0 + 3600),
        "--rpc",
        URL,
        "--sample",
        "10",
        "--json",
        C2,
    ]
)
check("wrong base fee: exit 1, exactly 19/20 OK", rc == 1 and "RESULT 19/20 OK" in out)
check(
    "wrong base fee: the FeeSettings check names 11",
    "FeeSettings 10 drops vs recorded 11" in out,
)
rc, out = run(["crosscheck", "--offline", CX, "--history", hist2])
check(
    "offline: altered history -> exit 1, sha256 DIFFERS",
    rc == 1 and "DIFFERS from the recorded" in out,
)

# lag outside 0..max_lag and an RPC error must MISMATCH
rc, out = run(base + ["--max-lag", "4", "--json", C2])
check(
    "close lag 5 s > --max-lag 4 -> exit 1, 10/20 OK",
    rc == 1 and "RESULT 10/20 OK" in out,
)
rf.RETRY_DELAYS = (0, 0, 0)  # no real sleeps in the suite
Stub.flaky = {cx["entries"][1]["ledger"] - 1: 2}
rc, out = run([*base, "--json", C2])
c2 = rjson(C2)
check(
    "transient lgrNotFound x2: exit 0, 20/20 OK, 2 retries printed and recorded",
    rc == 0
    and c2["ok"] == 20
    and c2["retries"] == 2
    and out.count("RETRY    ledger") == 2,
)
Stub.fail = {cx["entries"][0]["ledger"] - 1}
rc, out = run(base + ["--json", C2])
check(
    "RPC error on one sample -> exit 1, MISMATCH rpc",
    rc == 1
    and ": rpc: " in out
    and "RESULT 18/19 OK (10 samples, 3 RPC retries)" in out,
)
Stub.fail = set()
srv.shutdown()
srv.server_close()  # closed listening socket: connection refused at once
rc, out = run(base + ["--json", C2])
check("RPC down -> exit 1, 0 OK", rc == 1 and "RESULT 0/10 OK" in out)

# a tampered recorded answer must show as DIFFERENT offline
t = rjson(CX)
t["entries"][3]["answer"]["base_fee"] = 12
CT = os.path.join(tmp, "ct.json")
wjson(CT, t)
rc, out = run(["crosscheck", "--offline", CT, "--history", hist])
check(
    "offline: tampered recorded answer -> exit 1, DIFFERENT",
    rc == 1 and "DIFFERENT" in out,
)

# --- direct: raw answers from the fixtures vs the newest history line
fx = os.path.join(HERE, "fixtures")
fee = rjson(os.path.join(fx, "validator_fee.json"))
info = rjson(os.path.join(fx, "validator_server_info.json"))
last = row(59)
last["ledger"] = int(fee["result"]["ledger_current_index"]) - 3
hist3 = os.path.join(tmp, "history3.jsonl")
with open(hist3, "w", encoding="utf-8") as f:
    f.write(
        json.dumps(row(58))
        + "\n"
        + json.dumps(last)
        + "\n"
        + json.dumps(row(59, container="other"))
        + "\n"
        + json.dumps(
            {**last, "ts": last["ts"] + 61, "ledger": 1}
        )  # after --now: ignored
        + "\n"
    )
FEE, INFO = os.path.join(tmp, "fee.json"), os.path.join(tmp, "info.json")


def direct(fee_doc, now, extra=()):
    wjson(FEE, fee_doc)
    wjson(INFO, info)
    return run(
        [
            "direct",
            "--history",
            hist3,
            "--container",
            "postfiatd",
            "--fee",
            FEE,
            "--info",
            INFO,
            "--now",
            str(now),
            *extra,
        ]
    )


rc, out = direct(fee, last["ts"] + 20)
check(
    "direct: exit 0, 8/8 OK against the newest line",
    rc == 0 and "RESULT 8/8 OK" in out and f"ts={last['ts']}" in out,
)
rc, out = direct(fee, last["ts"] + 20, ["--negative"])
check("direct --negative: exit 0, 0/8 OK", rc == 0 and "RESULT 0/8 OK" in out)
rc, out = direct(fee, last["ts"] + 200)
check(
    "direct: history line too old -> exit 1",
    rc == 1 and "MISMATCH postfiatd" in out and "history line age" in out,
)
f2 = copy.deepcopy(fee)
f2["result"]["expected_ledger_size"] = "33"
rc, out = direct(f2, last["ts"] + 20)
check(
    "direct: expected_ledger_size differs -> exit 1, 7/8",
    rc == 1 and "RESULT 7/8 OK" in out,
)
f2 = copy.deepcopy(fee)
f2["result"]["ledger_current_index"] = last["ledger"] - 1
rc, out = direct(f2, last["ts"] + 20)
check(
    "direct: open ledger went backwards -> exit 1",
    rc == 1 and "MISMATCH postfiatd" in out,
)
f2 = copy.deepcopy(fee)
del f2["result"]["max_queue_size"]
rc, out = direct(f2, last["ts"] + 20)
check(
    "direct: queue limit absent vs recorded 2000 -> exit 1",
    rc == 1 and "max_queue_size: direct None" in out,
)
rc, out = run(
    [
        "direct",
        "--history",
        hist3,
        "--container",
        "nope",
        "--fee",
        FEE,
        "--info",
        INFO,
        "--now",
        "1",
    ]
)
check("direct: unknown container -> exit 1", rc == 1)

print(f"RESULT: {passed}/{total} passed")
sys.exit(0 if passed == total else 1)
