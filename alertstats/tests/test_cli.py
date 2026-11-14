"""collect against a stub Prometheus/Alertmanager (replaying a real capture) and pft-alertstats.sh end to end.

The stub serves query_range, /api/v1/rules and /api/v2/silences from fixtures/real-reboot.json and records every
request, so the tests can assert that collect only ever sends GETs and that the round trip
capture -> stub -> collect -> report reproduces the committed golden report byte for byte.
"""

import gzip
import json
import os
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import alertstats_build as ab

FIX = HERE / "fixtures"
SRC = json.loads((FIX / "real-reboot.json").read_text())
P = SRC["params"]


def api_rules(rules):
    groups = {}
    for r in rules:
        g = groups.setdefault(
            (r["file"], r["group"]),
            {"name": r["group"], "file": "/etc/pft-alerts/" + r["file"], "interval": r["interval"], "rules": []},
        )
        g["rules"].append(
            {
                "type": "alerting",
                "name": r["name"],
                "duration": r["duration"],
                "labels": r["labels"],
                "annotations": {k: "x" for k in r["annotations"]},
                "health": r["health"],
                "lastError": r["lastError"],
            }
        )
    return {"status": "success", "data": {"groups": list(groups.values())}}


class Stub:
    def __init__(self, src, fail_prom=False, extra_silence=None):
        self.src, self.fail_prom, self.requests = src, fail_prom, []
        self.silences = [dict(s, createdBy="someone", status={"state": "expired"}) for s in src["silences"]]
        if extra_silence:
            self.silences.append(extra_silence)
        stub = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                stub.requests.append(("GET", self.path))
                u = urllib.parse.urlparse(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                if u.path.startswith("/api/v1/") and stub.fail_prom:
                    return self.reply(503, {"status": "error", "error": "stub down"})
                if u.path == "/api/v1/query_range":
                    return self.reply(200, stub.query_range(q))
                if u.path == "/api/v1/rules":
                    return self.reply(200, api_rules(stub.src["rules"]))
                if u.path == "/api/v2/silences":
                    return self.reply(200, stub.silences)
                return self.reply(404, {})

            def do_POST(self):
                stub.requests.append(("POST", self.path))
                self.reply(405, {})

            do_PUT = do_DELETE = do_POST

            def reply(self, code, doc):
                body = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def query_range(self, q):
        t0, t1, step = float(q["start"]), float(q["end"]), int(q["step"])
        pts = int((t1 - t0) // step) + 1
        if pts > 11000:
            return {"status": "error", "error": "exceeded maximum resolution of 11,000 points per timeseries"}
        if q["query"] == "ALERTS":
            series = self.src["alerts"]
        elif q["query"] == "ALERTS_FOR_STATE":
            series = self.src["for_state"]
        elif q["query"].startswith("count(present_over_time("):
            series = [{"metric": {}, "values": [[t, "1"] for t in self.src["up"]]}]
        else:
            return {"status": "error", "error": f"unexpected query {q['query']}"}
        out = []
        for s in series:
            v = [x for x in s["values"] if t0 <= x[0] <= t1]
            if v:
                out.append({"metric": s["metric"], "values": v})
        return {"status": "success", "data": {"resultType": "matrix", "result": out}}

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def stub():
    s = Stub(SRC)
    yield s
    s.close()


def collect_args(url, out, *extra):
    return [
        "collect",
        "--prometheus",
        url,
        "--alertmanager",
        url,
        "--now",
        str(P["end"]),
        "--since",
        "1h",
        "--out",
        str(out),
        *extra,
    ]


def test_round_trip_reproduces_golden_report(stub, tmp_path, monkeypatch):
    monkeypatch.setattr(ab, "MAX_POINTS", 50)  # 241 points per series -> 5 chunks, merged without duplicates
    out = tmp_path / "b.json"
    assert ab.main(collect_args(stub.url, out)) == 0
    b = json.loads(out.read_text())
    assert b["alerts"] == SRC["alerts"] and b["for_state"] == SRC["for_state"] and b["up"] == SRC["up"]
    assert b["silences"] == SRC["silences"] and b["rules"] == SRC["rules"]
    assert sum(1 for m, p in stub.requests if p.startswith("/api/v1/query_range")) == 15  # 3 queries x 5 chunks
    r = subprocess.run(
        [sys.executable, "-I", str(ROOT / "alertstats_build.py"), "report", "--offline", str(out)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert r.stdout == (FIX / "real-reboot.expected.md").read_text()


def test_collect_sends_only_gets(stub, tmp_path):
    ab.main(collect_args(stub.url, tmp_path / "b.json"))
    assert stub.requests and {m for m, _ in stub.requests} == {"GET"}


def test_collect_gz_is_byte_identical(stub, tmp_path):
    ab.main(collect_args(stub.url, tmp_path / "a.json.gz"))
    ab.main(collect_args(stub.url, tmp_path / "b.json.gz"))
    a, b = (tmp_path / "a.json.gz").read_bytes(), (tmp_path / "b.json.gz").read_bytes()
    assert a == b and json.loads(gzip.decompress(a))["format"] == ab.BUNDLE_FORMAT
    assert a[4:8] == b"\x00\x00\x00\x00" and a[3] & 0x08 == 0  # gzip MTIME 0 and no FNAME: same bytes any day


def test_collect_redacts_silence_comment_and_drops_created_by(tmp_path):
    s = Stub(
        SRC,
        extra_silence={
            "id": "z",
            "startsAt": "2026-11-12T16:00:00Z",
            "endsAt": "2026-11-12T16:10:00Z",
            "createdBy": "operator-name",
            "comment": "peer 198.51.100.9 topic ntfy.sh/secret1",
            "matchers": [],
            "status": {"state": "expired"},
        },
    )
    try:
        ab.main(collect_args(s.url, tmp_path / "b.json"))
    finally:
        s.close()
    text = (tmp_path / "b.json").read_text()
    assert "198.51.100.9" not in text and "secret1" not in text and "operator-name" not in text
    assert "peer <redacted-ip> topic ntfy.sh/<redacted>" in text


def test_collect_since_cap_and_bad_args(stub, tmp_path):
    with pytest.raises(SystemExit) as e:
        ab.main(["collect", "--prometheus", stub.url, "--since", "16d", "--out", str(tmp_path / "b.json")])
    assert e.value.code == 3
    assert stub.requests == []  # refused before any query
    with pytest.raises(SystemExit) as e:
        ab.main(["collect", "--prometheus", stub.url, "--flap-min", "1", "--out", str(tmp_path / "b.json")])
    assert e.value.code == 3


def test_collect_prometheus_down_exit_4(tmp_path):
    s = Stub(SRC, fail_prom=True)
    try:
        rc = ab.main(collect_args(s.url, tmp_path / "b.json"))
    finally:
        s.close()
    b = json.loads((tmp_path / "b.json").read_text())
    assert rc == 4 and b["sources"]["prometheus"].startswith("error") and b["sources"]["alertmanager"] == "ok"


# ---------------------------------------------------------------- pft-alertstats.sh


def sh(tmp_path, url, *args, **env):
    calls = tmp_path / "docker-calls"
    e = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", ""),
        "PFT_AS_TEST": "1",
        "PFT_AS_CONF": str(tmp_path / "absent.env"),
        "PFT_AS_BUILD": str(ROOT / "alertstats_build.py"),
        "PFT_AS_DOCKER": str(HERE / "stubs" / "docker"),
        "PFT_AS_NOW": str(P["end"]),
        "STUB_CALLS": str(calls),
        "STUB_BRIDGE_LOG": str(FIX / "bridge-sample.log"),
        "PROM_URL": url,
        "AM_URL": url,
        "SINCE": "1h",
        "STATE_DIR": str(tmp_path / "state"),
        "TEXTFILE_DIR": str(tmp_path / "text"),
        "TMPDIR": os.environ.get("TMPDIR", str(tmp_path)),
    }
    e.update(env)
    (tmp_path / "text").mkdir(exist_ok=True)
    r = subprocess.run(
        ["bash", str(ROOT / "pft-alertstats.sh"), *args],
        capture_output=True,
        text=True,
        env=e,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    return r, (calls.read_text().splitlines() if calls.exists() else [])


def test_sh_run_writes_bundle_reports_textfile(stub, tmp_path):
    r, calls = sh(tmp_path, stub.url, "run")
    assert r.returncode == 0, r.stderr
    assert calls == ["logs --timestamps pft-alert-bridge"]  # the only docker call: no exec, no ps, no restart
    stamp = "20261112T170000Z"
    b = tmp_path / "state" / "bundles" / f"alertstats-{stamp}.json.gz"
    assert b.exists()
    for fmt in ("md", "json", "csv"):
        assert (tmp_path / "state" / "reports" / f"alertstats-{stamp}.{fmt}").stat().st_size > 0
    t = (tmp_path / "text" / "pft_alertstats.prom").read_text()
    assert 'pft_alertstats_up{host="validator"} 1' in t
    assert f'pft_alertstats_last_run_timestamp_seconds{{host="validator"}} {P["end"]}' in t
    assert 'pft_alertstats_notifications{host="validator",result="ok"} 2' in t
    assert oct((tmp_path / "text" / "pft_alertstats.prom").stat().st_mode & 0o777) == "0o644"
    assert not list((tmp_path / "text").glob(".pft_alertstats.*"))  # no temp file left
    assert {m for m, _ in stub.requests} == {"GET"}
    md = (tmp_path / "state" / "reports" / f"alertstats-{stamp}.md").read_text()
    off, _ = sh(tmp_path, stub.url, "report", "--offline", str(b))
    assert off.stdout == md  # live run and offline rebuild are the same bytes


def test_sh_run_prometheus_down_writes_up_zero(tmp_path):
    s = Stub(SRC, fail_prom=True)
    try:
        r, _ = sh(tmp_path, s.url, "run")
    finally:
        s.close()
    assert r.returncode == 4 and "wrote up 0" in r.stderr
    t = (tmp_path / "text" / "pft_alertstats.prom").read_text()
    assert 'pft_alertstats_up{host="validator"} 0' in t and "pft_alertstats_flapping" not in t


def test_sh_no_bridge_container_still_reports(stub, tmp_path):
    r, calls = sh(tmp_path, stub.url, "run", BRIDGE_CONTAINER="")
    assert r.returncode == 0 and calls == []
    r, calls = sh(tmp_path, stub.url, "run", STUB_CONTAINER="other")
    assert r.returncode == 0 and calls == ["logs --timestamps pft-alert-bridge"]
    assert "bridge absent" in next((tmp_path / "state" / "reports").glob("*.md")).read_text()


@pytest.mark.parametrize(
    ("env", "msg"),
    [
        ({"STEP": "0"}, "STEP must be a positive integer"),
        ({"FLAP_MIN": "1"}, "FLAP_MIN must be >= 2"),
        ({"KEEP_DAYS": "x"}, "KEEP_DAYS must be a positive integer"),
        ({"HOST_LABEL": 'a"b'}, "HOST_LABEL has characters"),
        ({"PFT_AS_BUILD": "/nonexistent"}, "not readable"),
    ],
)
def test_sh_config_refused(stub, tmp_path, env, msg):
    r, calls = sh(tmp_path, stub.url, "run", **env)
    assert r.returncode == 3 and msg in r.stderr
    assert stub.requests == [] and calls == []


def test_sh_needs_root_without_test_hook(stub, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    r, _ = sh(tmp_path, stub.url, "run", PFT_AS_TEST="0")
    assert r.returncode == 3 and "run as root" in r.stderr and stub.requests == []


def test_sh_collect_to_stdout_and_usage(stub, tmp_path):
    r, _ = sh(tmp_path, stub.url, "collect", "--since", "1h")
    assert r.returncode == 0 and json.loads(r.stdout)["format"] == ab.BUNDLE_FORMAT
    r, _ = sh(tmp_path, stub.url, "collect", "--bogus")
    assert r.returncode == 3
    r, _ = sh(tmp_path, stub.url, "nope")
    assert r.returncode == 3 and "Usage" in r.stderr
    r, _ = sh(tmp_path, stub.url, "version")
    assert r.stdout.strip() == "pft-alertstats 1"
