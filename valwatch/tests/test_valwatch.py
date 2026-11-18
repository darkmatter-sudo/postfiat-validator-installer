"""Tests for valwatch.py and pft-valwatch.sh. Fixtures: real 240 s captures from the validator and the sentry
(2026-11-18T18:24:57Z, runlog 1) and the validator's publisher-list cache file (public, signed list)."""

import base64
import gzip
import itertools
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import valwatch

FX = HERE / "fixtures"
SCRIPT = ROOT / "pft-valwatch.sh"
HELPER = ROOT / "valwatch.py"


def fixture_recs(host):
    with gzip.open(FX / host / "valwatch-20261118T18.jsonl.gz", "rt", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def write_dir(path, recs):
    path.mkdir(parents=True, exist_ok=True)
    by_file = {}
    for r in recs:
        by_file.setdefault(time.strftime("valwatch-%Y%m%dT%H.jsonl", time.gmtime(r["r"] / 1000)), []).append(r)
    for name, rs in by_file.items():
        (path / name).write_text("".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in rs))
    return path


def analyze(recs, **kw):
    return valwatch.analyze(sorted(recs, key=lambda x: (x["r"], x["t"], x.get("i", 0), x.get("k", ""))), **kw)


def unl_keys(recs):
    return next(r for r in recs if r["t"] == "U")["keys"]


@pytest.fixture(scope="module")
def vrecs():
    return fixture_recs("validator")


@pytest.fixture(scope="module")
def srecs():
    return fixture_recs("sentry")


# ------------------------------------------------------------------ UNL / keys
def test_unl_cache_decodes_to_master_keys_seen_in_stream(vrecs):
    u = valwatch.read_unl(FX / "unl-cache.json")
    assert u["seq"] == 30 and len(u["keys"]) == 25 and u["pub"] == "ED3F1E0DA736FCF9"
    streamed = {r["k"] for r in vrecs if r["t"] == "V"}
    assert set(u["keys"]) <= streamed  # every UNL key (hex -> base58 nH...) is a master_key in the live stream


def test_node_public_b58_rejects_wrong_length():
    with pytest.raises(ValueError, match="33 bytes"):
        valwatch.node_public_b58("ED" + "00" * 31)


def test_read_unl_picks_highest_sequence(tmp_path):
    d = json.loads((FX / "unl-cache.json").read_text())
    blob = json.loads(base64.b64decode(d["blobs_v2"][0]["blob"]))
    older = dict(blob, sequence=29, validators=blob["validators"][:3])
    d["blobs_v2"] = [{"blob": base64.b64encode(json.dumps(older).encode()).decode()}, d["blobs_v2"][0]]
    p = tmp_path / "cache.X"
    p.write_text(json.dumps(d))
    u = valwatch.read_unl(p)
    assert u["seq"] == 30 and len(u["keys"]) == 25


def test_read_unl_refuses_empty(tmp_path):
    p = tmp_path / "cache.X"
    p.write_text(json.dumps({"blobs_v2": []}))
    with pytest.raises(ValueError, match="no blob"):
        valwatch.read_unl(p)


# ------------------------------------------------------------------ host restriction
@pytest.mark.parametrize("host", ["127.0.0.1", "172.17.0.2", "10.1.2.3", "192.168.5.6", "::1"])
def test_allowed_hosts(host):
    assert valwatch.allowed_host(host)


@pytest.mark.parametrize("host", ["8.8.8.8", "169.254.1.1", "rpc.example.org", "", "0.0.0.0x"])
def test_refused_hosts(host):
    assert not valwatch.allowed_host(host)


def test_collect_refuses_public_host_before_connecting(tmp_path):
    p = subprocess.run(
        [
            sys.executable,
            "-I",
            str(HELPER),
            "collect",
            "--host",
            "8.8.8.8",
            "--out",
            str(tmp_path / "o"),
            "--unl-cache",
            str(FX / "unl-cache.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert p.returncode == 3 and "refusing" in p.stderr
    assert not (tmp_path / "o").exists()  # nothing written, no connection attempted


# ------------------------------------------------------------------ grading on real captures
def test_fixture_baseline_is_clean(vrecs):
    rep = analyze(vrecs)
    assert rep["ledgers"] == 76 and rep["missing_ledgers"] == 0 and rep["unl"]["size"] == 25
    assert rep["quorum_last"] == 17
    assert rep["quorum_margin"] == {"min": 8, "p5": 8, "p50": 8, "ledgers_below_min": 0, "below_min_first": []}
    assert all(not v["flags"] for v in rep["validators"].values())


def test_silent_validator_is_flagged(vrecs):
    k = unl_keys(vrecs)[3]
    rep = analyze([r for r in vrecs if not (r["t"] == "V" and r["k"] == k)])
    v = rep["validators"][k]
    assert v["agreed"] == 0 and v["expected"] == 76 and v["participation"] == 0.0
    assert v["flags"] == ["low_participation", "silent"]
    assert rep["quorum_margin"]["min"] == 7  # 24 agreeing - 17


def test_partial_participation_threshold(vrecs):
    k = unl_keys(vrecs)[5]
    ledgers = sorted({r["i"] for r in vrecs if r["t"] == "L"})
    drop = set(ledgers[::8])  # every 8th ledger: graded ledgers lose ~1/8
    rep = analyze([r for r in vrecs if not (r["t"] == "V" and r["k"] == k and r["i"] in drop)])
    v = rep["validators"][k]
    assert v["expected"] == 76 and v["agreed"] == 76 - len(drop & set(rep_ledgers(rep, vrecs)))
    assert v["participation"] < 0.9 and "low_participation" in v["flags"] and "silent" not in v["flags"]
    others = [x for kk, x in rep["validators"].items() if kk != k]
    assert all(not x["flags"] for x in others)


def rep_ledgers(rep, recs):
    return [
        i for i in sorted({r["i"] for r in recs if r["t"] == "L"}) if rep["first_ledger"] <= i <= rep["last_ledger"]
    ]


def test_wrong_hash_validation_does_not_count(vrecs):
    k = unl_keys(vrecs)[0]
    recs = [dict(r, h="00" * 32) if r["t"] == "V" and r["k"] == k else r for r in vrecs]
    v = analyze(recs)["validators"][k]
    assert v["agreed"] == 0 and "silent" in v["flags"]


def test_partial_validations_do_not_count(vrecs):
    k = unl_keys(vrecs)[0]
    recs = [dict(r, f=False) if r["t"] == "V" and r["k"] == k else r for r in vrecs]
    assert analyze(recs)["validators"][k]["agreed"] == 0


def test_late_validator_flagged_with_exact_delay(vrecs):
    k = unl_keys(vrecs)[7]
    base = analyze(vrecs)["validators"][k]
    recs = [dict(r, r=r["r"] + 3500) if r["t"] == "V" and r["k"] == k else r for r in vrecs]
    v = analyze(recs)["validators"][k]
    assert "late" in v["flags"] and v["agreed"] == base["agreed"]
    assert v["delay_ms_p95"] > 3000


def test_late_threshold_boundary(vrecs):
    k = unl_keys(vrecs)[7]
    rep = analyze(vrecs)
    p95 = rep["validators"][k]["delay_ms_p95"]
    assert "late" not in analyze(vrecs, warn_delay_ms=p95)["validators"][k]["flags"]
    assert "late" in analyze(vrecs, warn_delay_ms=p95 - 1)["validators"][k]["flags"]


def test_quorum_margin_below_threshold_exact(vrecs):
    keys = unl_keys(vrecs)
    target = sorted({r["i"] for r in vrecs if r["t"] == "L"})[30]
    gone = set(keys[:7])  # 25 - 7 = 18 agreeing on one ledger -> margin 1
    recs = [r for r in vrecs if not (r["t"] == "V" and r["i"] == target and r["k"] in gone)]
    rep = analyze(recs)
    assert rep["quorum_margin"]["min"] == 1
    assert rep["quorum_margin"]["ledgers_below_min"] == 1 and rep["quorum_margin"]["below_min_first"] == [target]
    rep0 = analyze(recs, min_margin=1)
    assert rep0["quorum_margin"]["ledgers_below_min"] == 0  # boundary: margin 1 is not below 1


def test_quorum_change_uses_latest_sample(vrecs):
    recs = [dict(r, q=20) if r["t"] == "Q" else r for r in vrecs]
    assert analyze(recs)["quorum_margin"]["min"] == 5


def test_no_unl_or_quorum_grades_nothing(vrecs):
    assert analyze([r for r in vrecs if r["t"] != "U"])["ledgers"] == 0
    assert analyze([r for r in vrecs if r["t"] != "Q"])["ledgers"] == 0


def test_edge_ledgers_not_graded(vrecs):
    rep = analyze(vrecs)
    t0 = min(r["r"] for r in vrecs)
    t1 = max(r["r"] for r in vrecs)
    graded = [r for r in vrecs if r["t"] == "L" and rep["first_ledger"] <= r["i"] <= rep["last_ledger"]]
    assert min(r["r"] for r in graded) >= t0 + valwatch.EDGE_MS
    assert max(r["r"] for r in graded) <= t1 - valwatch.EDGE_MS
    every = [r for r in vrecs if r["t"] == "L"]
    assert len(every) > len(graded)  # control: the edges did hold ledgers


def test_missing_ledger_counted(vrecs):
    ls = sorted({r["i"] for r in vrecs if r["t"] == "L"})
    gap = ls[40]
    rep = analyze([r for r in vrecs if not (r["t"] == "L" and r["i"] == gap)])
    assert rep["missing_ledgers"] == 1 and rep["ledgers"] == 75


def test_recovery_window(tmp_path, vrecs):
    """Validator silent for the first half, back for the second: full window low, second-half window clean."""
    k = unl_keys(vrecs)[2]
    ls = sorted({r["i"] for r in vrecs if r["t"] == "L"})
    mid = ls[len(ls) // 2]
    recs = [r for r in vrecs if not (r["t"] == "V" and r["k"] == k and r["i"] < mid)]
    d = write_dir(tmp_path / "d", recs)
    mid_r = next(r["r"] for r in recs if r["t"] == "L" and r["i"] == mid)
    carried, a, bad = valwatch.load(d)
    full = valwatch.analyze(a, bad, carried=carried)["validators"][k]
    carried, b, bad = valwatch.load(d, t_from=mid_r // 1000 - 6)
    late = valwatch.analyze(b, bad, carried=carried)["validators"][k]
    assert "low_participation" in full["flags"]
    assert late["flags"] == [] and late["participation"] == 1.0


def test_load_carries_unl_and_quorum_into_window(tmp_path, vrecs):
    d = write_dir(tmp_path / "d", vrecs)
    t_from = (max(r["r"] for r in vrecs) // 1000) - 60
    carried, recs, _ = valwatch.load(d, t_from=t_from)
    assert [c["t"] for c in carried] == ["U", "Q"]
    assert not any(r["t"] == "U" for r in recs)  # the only U record is older than the window
    assert valwatch.analyze(recs, carried=carried)["ledgers"] > 0
    assert valwatch.analyze(recs)["ledgers"] == 0  # control: without carry-in nothing can be graded


def test_torn_and_oversized_lines_counted(tmp_path, vrecs):
    d = write_dir(tmp_path / "d", vrecs)
    f = max(d.iterdir())
    with open(f, "a", encoding="utf-8") as fh:
        fh.write('{"t":"V","i":1,"r":17\n' + "x" * (valwatch.MAX_LINE + 1) + "\n")
    _, recs, bad = valwatch.load(d)
    keys = set(unl_keys(vrecs))
    assert bad == 2 and len(recs) == sum(1 for r in vrecs if r["t"] != "V" or r["k"] in keys)


def test_load_drops_non_unl_validations_and_skips_far_files(tmp_path, vrecs):
    d = write_dir(tmp_path / "d", vrecs)
    keys = set(unl_keys(vrecs))
    _, recs, _ = valwatch.load(d)
    nv = sum(1 for r in vrecs if r["t"] == "V" and r["k"] not in keys)
    assert nv > 1000 and not any(r["t"] == "V" and r["k"] not in keys for r in recs)  # control: there were some
    (d / "valwatch-20261101T00.jsonl").write_text("not json\n")  # far older than any window: never opened
    (d / "valwatch-notanhour.jsonl").write_text("not json\n")
    t_from = min(r["r"] for r in vrecs) // 1000
    assert valwatch.load(d, t_from=t_from)[2] == 0
    assert valwatch.load(d)[2] == 1  # control: an unbounded load does read the old file
    sink = valwatch.Sink(str(d), retain_hours=24, max_dir_bytes=10**9)
    sink.write({"t": "C", "ev": "connect", "why": "", "r": max(r["r"] for r in vrecs)})
    assert "valwatch-notanhour.jsonl" in os.listdir(d) and "valwatch-20261101T00.jsonl" not in os.listdir(d)


# ------------------------------------------------------------------ report CLI: deterministic, offline
def run_helper(*args, timeout=60):
    return subprocess.run(
        [sys.executable, "-I", str(HELPER), *args], check=False, capture_output=True, text=True, timeout=timeout
    )


def test_report_byte_identical_and_offline(tmp_path, vrecs):
    d = write_dir(tmp_path / "d", vrecs)
    outs = [run_helper("report", "--dir", str(d), *m).stdout for m in ([], [], ["--json"], ["--json"])]
    assert outs[0] == outs[1] and outs[2] == outs[3] and "RESULT: OK" in outs[0]
    shutil.copytree(d, tmp_path / "copy")
    assert run_helper("report", "--dir", str(tmp_path / "copy"), "--json").stdout == outs[2]


def test_report_exit_4_without_graded_ledgers(tmp_path, vrecs):
    d = write_dir(tmp_path / "d", [r for r in vrecs if r["t"] != "U"])
    assert run_helper("report", "--dir", str(d)).returncode == 4


# ------------------------------------------------------------------ compare
def detail(recs):
    return analyze(recs, detail=True)


def test_compare_real_hosts_agree(vrecs, srecs):
    res = valwatch.compare(detail(vrecs), detail(srecs), 0.02, 1000, 1)
    assert res["result"] == "AGREE" and res["common_ledgers"] == 76 and res["hash_mismatch"] == []
    assert res["margin_absdiff_max"] == 0 and res["validators_outside"] == []


def test_compare_hash_mismatch_disagrees(vrecs, srecs):
    a, b = detail(vrecs), detail(srecs)
    i = sorted(a["ledger_detail"], key=int)[10]
    b["ledger_detail"][i]["h"] = "FF" * 32
    res = valwatch.compare(a, b, 0.02, 1000, 1)
    assert res["result"] == "DISAGREE" and res["hash_mismatch"] == [int(i)]


def test_compare_participation_outside_tolerance(vrecs, srecs):
    k = unl_keys(srecs)[4]
    ls = sorted({r["i"] for r in srecs if r["t"] == "L"})
    drop = set(ls[10:20])
    b = detail([r for r in srecs if not (r["t"] == "V" and r["k"] == k and r["i"] in drop)])
    res = valwatch.compare(detail(vrecs), b, 0.02, 1000, 3)
    assert res["result"] == "DISAGREE" and res["validators_outside"] == [k]
    assert valwatch.compare(detail(vrecs), b, 0.2, 1000, 10)["result"] == "AGREE"  # within a wider tolerance


def test_compare_unl_differs(vrecs, srecs):
    k = unl_keys(srecs)[0]
    b = detail([dict(r, keys=[x for x in r["keys"] if x != k]) if r["t"] == "U" else r for r in srecs])
    res = valwatch.compare(detail(vrecs), b, 0.02, 1000, 1)
    assert res["result"] == "DISAGREE"
    assert {"validator": k, "expected_a": 76, "expected_b": 0, "status": "unl_differs"} in res["validators"]


def test_compare_needs_detail(vrecs):
    with pytest.raises(ValueError, match="--detail"):
        valwatch.compare(analyze(vrecs), analyze(vrecs), 0.02, 1000, 1)


def test_compare_no_common_ledgers_disagrees(vrecs):
    a = detail(vrecs)
    b = json.loads(json.dumps(a))
    b["ledger_detail"] = {str(int(k) + 1000): v for k, v in b["ledger_detail"].items()}
    assert valwatch.compare(a, b, 0.02, 1000, 1)["result"] == "DISAGREE"


# ------------------------------------------------------------------ textfile
def test_textfile_values_and_cap(tmp_path, vrecs):
    d = write_dir(tmp_path / "d", vrecs)
    now = max(r["r"] for r in vrecs) // 1000
    p = run_helper("textfile", "--dir", str(d), "--name", "postfiatd", "--now", str(now))
    assert p.returncode == 0
    assert 'pft_valwatch_up{node="postfiatd"} 1' in p.stdout
    assert 'pft_valwatch_quorum_margin_min{node="postfiatd"} 8' in p.stdout
    assert p.stdout.count("pft_valwatch_validator_participation_ratio{") == 25
    assert len(p.stdout.encode()) < 61440


def test_textfile_caps_validator_series(tmp_path, vrecs):
    extra = [f"nHfake{i:046d}" for i in range(60)]
    recs = [dict(r, keys=sorted(r["keys"] + extra)) if r["t"] == "U" else r for r in vrecs]
    d = write_dir(tmp_path / "d", recs)
    now = max(r["r"] for r in vrecs) // 1000
    out = run_helper("textfile", "--dir", str(d), "--name", "postfiatd", "--now", str(now)).stdout
    assert out.count("pft_valwatch_validator_participation_ratio{") == valwatch.MAX_VALIDATORS
    assert 'pft_valwatch_validators_truncated{node="postfiatd"} 1' in out


def test_textfile_stale_window_is_down(tmp_path, vrecs):
    d = write_dir(tmp_path / "d", vrecs)
    now = max(r["r"] for r in vrecs) // 1000 + 3600
    p = run_helper("textfile", "--dir", str(d), "--name", "postfiatd", "--now", str(now))
    assert p.returncode == 1 and 'pft_valwatch_up{node="postfiatd"} 0' in p.stdout


# ------------------------------------------------------------------ collector against a local ws:// stub
class StubNode(threading.Thread):
    """Plain-ws server that replays fixture messages; drops the first connection after N messages."""

    def __init__(self, msgs, drop_after):
        super().__init__(daemon=True)
        self.msgs, self.drop_after = msgs, drop_after
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.connections, self.commands = 0, []

    def run(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            self.connections += 1
            try:
                self.serve(c, self.drop_after if self.connections == 1 else len(self.msgs))
            except OSError:
                pass
            finally:
                c.close()

    @staticmethod
    def frame(data):
        n = len(data)
        if n < 126:
            return bytes([0x81, n]) + data
        if n < 65536:
            return bytes([0x81, 126]) + n.to_bytes(2, "big") + data
        return bytes([0x81, 127]) + n.to_bytes(8, "big") + data

    def recv_cmd(self, c, buf):
        while len(buf) < 2:
            buf += c.recv(4096)
        n = buf[1] & 0x7F
        off = 2
        if n == 126:
            n, off = int.from_bytes(buf[2:4], "big"), 4
        while len(buf) < off + 4 + n:
            buf += c.recv(4096)
        mask = buf[off : off + 4]
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(buf[off + 4 : off + 4 + n]))
        self.commands.append(json.loads(payload)["command"])
        return json.loads(payload), buf[off + 4 + n :]

    def serve(self, c, limit):
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += c.recv(4096)
        c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        buf = buf.split(b"\r\n\r\n", 1)[1]
        for _ in range(2):  # server_info + subscribe
            cmd, buf = self.recv_cmd(c, buf)
            if cmd["command"] == "server_info":
                res = {
                    "id": cmd["id"],
                    "result": {"info": {"validation_quorum": 17, "server_state": "full"}},
                    "status": "success",
                    "type": "response",
                }
            else:
                res = {"id": cmd["id"], "result": {}, "status": "success", "type": "response"}
            c.sendall(self.frame(json.dumps(res).encode()))
        for m in self.msgs[:limit]:
            c.sendall(self.frame(json.dumps(m).encode()))
        if limit < len(self.msgs):
            return  # drop the connection
        time.sleep(30)


def stub_msgs(vrecs):
    out = []
    for r in vrecs:
        if r["t"] == "L":
            out.append({"type": "ledgerClosed", "ledger_index": r["i"], "ledger_hash": r["h"], "ledger_time": r["lt"]})
        elif r["t"] == "V":
            out.append(
                {
                    "type": "validationReceived",
                    "ledger_index": str(r["i"]),
                    "ledger_hash": r["h"],
                    "master_key": r["k"],
                    "validation_public_key": "n9x",
                    "full": r["f"],
                    "data": "AA" * 50,
                    "signature": "BB" * 30,
                }
            )
    return out[:600]


def test_collect_records_and_reconnects(tmp_path, vrecs):
    stub = StubNode(stub_msgs(vrecs), drop_after=100)
    stub.start()
    out = tmp_path / "out"
    p = run_helper(
        "collect",
        "--plain",
        "--host",
        "127.0.0.1",
        "--port",
        str(stub.port),
        "--out",
        str(out),
        "--unl-cache",
        str(FX / "unl-cache.json"),
        "--duration",
        "6",
        timeout=30,
    )
    stub.srv.close()
    assert p.returncode == 0, p.stderr
    _, recs, bad = valwatch.load(out)
    evs = [r["ev"] for r in recs if r["t"] == "C"]
    assert evs[:3] == ["connect", "disconnect", "connect"] and stub.connections == 2
    msgs = stub_msgs(vrecs)
    keys = set(unl_keys(vrecs))
    want_v = sum(1 for m in msgs[:100] + msgs if m["type"] == "validationReceived" and m["master_key"] in keys)
    assert bad == 0 and sum(1 for r in recs if r["t"] == "V") == want_v
    assert set(stub.commands) == {"server_info", "subscribe"}  # read-only: nothing else is ever sent
    assert not any("data" in r or "signature" in r for r in recs)
    assert any(r["t"] == "U" and len(r["keys"]) == 25 for r in recs)


def test_collect_backoff_on_refused_port(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens
    out = tmp_path / "out"
    p = run_helper(
        "collect",
        "--plain",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--out",
        str(out),
        "--unl-cache",
        str(FX / "unl-cache.json"),
        "--duration",
        "6",
        timeout=30,
    )
    assert p.returncode == 0
    _, recs, _ = valwatch.load(out)
    tries = [r["r"] for r in recs if r["t"] == "C" and r["ev"] == "disconnect"]
    gaps = [b - a for a, b in itertools.pairwise(tries)]
    assert 2 <= len(tries) <= 4  # 1 + 2 + 4 s backoff inside 6 s, not a busy loop
    assert all(g2 >= g1 for g1, g2 in itertools.pairwise(gaps))


# ------------------------------------------------------------------ retention
def test_sink_prunes_by_age_and_bytes(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    now = 1795026000
    for h in range(10):
        name = time.strftime("valwatch-%Y%m%dT%H.jsonl", time.gmtime(now - (h + 1) * 3600))
        (out / name).write_text("x" * 1000 + "\n")
    sink = valwatch.Sink(str(out), retain_hours=4, max_dir_bytes=10**9)
    sink.write({"t": "C", "ev": "connect", "why": "", "r": now * 1000})
    names = sorted(os.listdir(out))
    assert len(names) == 5  # current hour + the 4 hours whose end is within 4 h
    sink2 = valwatch.Sink(str(out), retain_hours=48, max_dir_bytes=2500)
    sink2.write({"t": "C", "ev": "connect", "why": "", "r": (now + 3600) * 1000})
    total = sum(os.path.getsize(out / n) for n in os.listdir(out))
    assert total <= 2500 and sink2.cur_name in os.listdir(out)


# ------------------------------------------------------------------ shell wrapper
def sh(args, env_extra, timeout=60):
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/tmp"),
        "PFT_VW_CONF": "/nonexistent",
        "PFT_VW_HELPER": str(HELPER),
        **env_extra,
    }
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


def docker_stub(tmp_path, port_out, ip, mount_src):
    log = tmp_path / "docker.log"
    stub = tmp_path / "docker"
    stub.write_text(f"""#!/bin/bash
echo "$*" >> {log}
case "$1" in
  port) printf '%b' {json.dumps(port_out)} ;;
  inspect) case "$3" in *NetworkSettings*) echo {ip} ;; *Mounts*) echo {mount_src} ;; esac ;;
  *) echo "unexpected docker $1" >&2; exit 99 ;;
esac
""")
    stub.chmod(0o755)
    return stub, log


@pytest.mark.parametrize(
    ("port_out", "want"),
    [
        ("127.0.0.1:6005\n", "--host 127.0.0.1 --port 6005"),
        ("", "--host 172.17.0.2 --port 6005"),
        ("0.0.0.0:16005\n127.0.0.1:16006\n", "--host 127.0.0.1 --port 16006"),
    ],
    ids=["published-loopback", "bridge-only", "second-line-loopback"],
)
def test_run_resolves_endpoint_without_exec(tmp_path, port_out, want):
    vol = tmp_path / "vol"
    vol.mkdir()
    shutil.copy(FX / "unl-cache.json", vol / "cache.ED3F")
    stub, log = docker_stub(tmp_path, port_out, "172.17.0.2", vol)
    execstub = tmp_path / "execstub"
    execstub.write_text('#!/bin/bash\necho "ARGV $*"\n')
    execstub.chmod(0o755)
    p = sh(
        ["run", "--container", "postfiatd"],
        {"PFT_VW_DOCKER": str(stub), "PFT_VW_EXEC": str(execstub), "DATA_DIR": str(tmp_path / "data")},
    )
    assert p.returncode == 0, p.stderr
    assert want in p.stdout and f"--unl-cache {vol}/cache.ED3F" in p.stdout
    calls = log.read_text().splitlines()
    assert all(c.split()[0] in ("port", "inspect") for c in calls) and not any("exec" in c for c in calls)


def test_run_refuses_two_publisher_caches(tmp_path):
    vol = tmp_path / "vol"
    vol.mkdir()
    for n in ("cache.A", "cache.B"):
        shutil.copy(FX / "unl-cache.json", vol / n)
    stub, _ = docker_stub(tmp_path, "127.0.0.1:6005\n", "172.17.0.2", vol)
    p = sh(["run"], {"PFT_VW_DOCKER": str(stub), "PFT_VW_EXEC": "/bin/false", "DATA_DIR": str(tmp_path / "d")})
    assert p.returncode == 1 and "2 publisher caches" in p.stderr


def test_run_refuses_missing_mount(tmp_path):
    stub, _ = docker_stub(tmp_path, "127.0.0.1:6005\n", "172.17.0.2", "")
    p = sh(["run"], {"PFT_VW_DOCKER": str(stub), "PFT_VW_EXEC": "/bin/false", "DATA_DIR": str(tmp_path / "d")})
    assert p.returncode == 1 and "no volume mounted" in p.stderr


@pytest.mark.parametrize(
    ("key", "val"),
    [
        ("WS_PORT", "0"),
        ("RETAIN_HOURS", "2"),
        ("WINDOW_SEC", "60"),
        ("MIN_PARTICIPATION", "1.5"),
        ("MAX_BYTES", "70000"),
        ("RUN_DURATION", "x"),
    ],
    ids=["port0", "retain2", "window60", "part1.5", "maxbytes70000", "durationx"],
)
def test_bad_conf_refused(tmp_path, key, val):
    p = sh(["textfile"], {key: val, "DATA_DIR": str(tmp_path)})
    assert p.returncode == 3 and f"bad {key}" in p.stderr


def test_textfile_wrapper_writes_and_validates(tmp_path, vrecs):
    write_dir(tmp_path / "data" / "postfiatd", vrecs)
    text = tmp_path / "text"
    text.mkdir()
    now = str(max(r["r"] for r in vrecs) // 1000)
    p = sh(
        ["textfile", "--container", "postfiatd"],
        {"DATA_DIR": str(tmp_path / "data"), "TEXTFILE_DIR": str(text), "PFT_VW_NOW": now},
    )
    assert p.returncode == 0, p.stderr
    f = text / "pft_valwatch_postfiatd.prom"
    assert sh(["validate", str(f), "postfiatd"], {}).returncode == 0
    assert sh(["validate", str(f), "postfiatd-sentry"], {}).returncode == 2  # control: wrong node label


def test_textfile_wrapper_up0_without_data(tmp_path):
    text = tmp_path / "text"
    text.mkdir()
    p = sh(
        ["textfile", "--container", "postfiatd"],
        {"DATA_DIR": str(tmp_path / "none"), "TEXTFILE_DIR": str(text), "PFT_VW_NOW": "1795026000"},
    )
    assert p.returncode == 1
    body = (text / "pft_valwatch_postfiatd.prom").read_text()
    assert 'pft_valwatch_up{node="postfiatd"} 0' in body and "collect_timestamp_seconds" in body


def test_textfile_wrapper_over_max_bytes_is_up0(tmp_path, vrecs):
    write_dir(tmp_path / "data" / "postfiatd", vrecs)
    text = tmp_path / "text"
    text.mkdir()
    now = str(max(r["r"] for r in vrecs) // 1000)
    p = sh(
        ["textfile", "--container", "postfiatd"],
        {"DATA_DIR": str(tmp_path / "data"), "TEXTFILE_DIR": str(text), "PFT_VW_NOW": now, "MAX_BYTES": "4096"},
    )
    assert p.returncode == 1 and "over MAX_BYTES" in p.stderr
    assert 'pft_valwatch_up{node="postfiatd"} 0' in (text / "pft_valwatch_postfiatd.prom").read_text()


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ('pft_valwatch_up{node="postfiatd"} 1\n', "no pft_valwatch_collect_timestamp_seconds"),
        ('pft_other{node="postfiatd"} 1\n', "not a pft_valwatch_ sample"),
        ('pft_valwatch_up{node="postfiatd"} one\n', "malformed sample"),
    ],
    ids=["no-ts", "foreign-metric", "malformed"],
)
def test_validate_rejects(tmp_path, body, why):
    f = tmp_path / "x.prom"
    f.write_text(body)
    p = sh(["validate", str(f), "postfiatd"], {})
    assert p.returncode == 2 and why in p.stdout


def test_pull_validates_before_rename(tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    (remote / "pft_valwatch_postfiatd-sentry.prom").write_text('pft_valwatch_up{node="postfiatd"} 1\n')
    text = tmp_path / "text"
    text.mkdir()
    p = sh(["pull"], {"PULL_SSH": "env", "REMOTE_DIR": str(remote), "TEXTFILE_DIR": str(text)})
    assert p.returncode == 2 and "validation failed" in p.stderr and os.listdir(text) == []
    (remote / "pft_valwatch_postfiatd-sentry.prom").write_text(
        'pft_valwatch_up{node="postfiatd-sentry"} 1\npft_valwatch_collect_timestamp_seconds{node="postfiatd-sentry"} 5\n'
    )
    assert sh(["pull"], {"PULL_SSH": "env", "REMOTE_DIR": str(remote), "TEXTFILE_DIR": str(text)}).returncode == 0
    assert os.listdir(text) == ["pft_valwatch_postfiatd-sentry.prom"]
