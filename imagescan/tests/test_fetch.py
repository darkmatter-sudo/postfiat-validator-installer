"""Tests for `pft-imagescan fetch`: upstream-clock comparison, ONE cache-busting conditional retry, outcomes
(fresh / retried_fresh / still_behind), truncated downloads, older-copy protection and the fetch-outcome textfile
series (run: cd imagescan && python3 -m pytest -q tests).

The origin is a local stdlib HTTP server that behaves like the stale CDN seen on 2026-11-27: a plain GET returns
the cached (stale) copy, a GET with a fresh cache-busting query reaches the origin's current copy, a conditional GET
whose If-None-Match names the cached copy may be answered 304, and HEAD reports the origin's Last-Modified. Real
curl talks to it, so the shell's request headers and query are what is checked.
"""
import bz2
import hashlib
import io
import json
import os
import subprocess
import threading
import zipfile
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT = ROOT / "pft-imagescan.sh"
LIB = ROOT / "imagescan_lib.py"
UNIT = ROOT / "systemd" / "pft-imagescan-heal.service"
T = 1795700000  # 2026-11-26T13:33:20Z, the content clock of the "fresh" copies
H = 3600
TOL = 3600      # CONTENT_TOLERANCE_SECONDS in these tests
NOBLE = "/oval/oci.com.ubuntu.noble.usn.oval.xml.bz2"
TRACKER = "/tracker/data/json"
GOZIP, GOIDX = "/go/vulndb.zip", "/go/index/db.json"


def hdate(e):
    return formatdate(e, usegmt=True)


def iso(e):
    return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def oval(e):
    return bz2.compress(f'<?xml version="1.0"?>\n<oval_definitions><generator><oval:timestamp>{iso(e)}'
                        f'</oval:timestamp></generator>{"<d/>" * 2000}</oval_definitions>'.encode())


def tracker():
    return json.dumps({f"pkg{i}": {} for i in range(1200)}).encode()


def gozip(e):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("index/db.json", json.dumps({"modified": iso(e) + "Z"}))
        z.writestr("ID/GO-0000-0001.json", "{}")
    return b.getvalue()


class Origin:
    """path -> {"cached": (body, lm, etag), "origin": (body, lm, etag), "head_lm": epoch|None, "on_304": bool,
    "status": int (plain GET), "retry_status": int}. Every request is logged (method, path, query, headers)."""

    def __init__(self):
        self.routes, self.log = {}, []
        me = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                u = urlsplit(self.path)
                me.log.append({"method": self.command, "path": u.path, "query": u.query,
                               "headers": {k.lower(): v for k, v in self.headers.items()}})
                r = me.routes.get(u.path)
                if r is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                busted = "pftcb=" in u.query
                body, lm, etag = r["origin"] if busted else r["cached"]
                status = r.get("retry_status", 200) if busted else r.get("status", 200)
                if self.command == "HEAD":
                    lm = r.get("head_lm", lm)
                    self.send_response(200)
                    if lm is not None:
                        self.send_header("Last-Modified", hdate(lm))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if busted and r.get("on_304") and self.headers.get("If-None-Match") == r["cached"][2]:
                    status, body = 304, b""
                self.send_response(status)
                if status == 200:
                    if lm is not None:
                        self.send_header("Last-Modified", hdate(lm))
                    if etag:
                        self.send_header("ETag", etag)
                else:
                    body = b""
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_HEAD = _serve

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def gets(self, path):
        return [r for r in self.log if r["method"] == "GET" and r["path"] == path]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def origin():
    o = Origin()
    yield o
    o.close()


def noble(o, cached_e, origin_e=None, head_e=None, **kw):
    origin_e = cached_e if origin_e is None else origin_e
    o.routes[NOBLE] = {"cached": (oval(cached_e), cached_e + 19, '"c-noble"'),
                       "origin": (oval(origin_e), origin_e + 19, '"o-noble"'),
                       "head_lm": head_e if head_e is not None else origin_e + 19, **kw}


@pytest.fixture
def fenv(tmp_path, origin):
    cache, tf = tmp_path / "cache", tmp_path / "tf"
    tf.mkdir()
    conf = tmp_path / "conf.env"
    conf.write_text(f"HOST_LABEL=validator\nCACHE_DIR={cache}\nTEXTFILE_DIR={tf}\nFEEDS=ubuntu-noble\n"
                    f"CONTENT_TOLERANCE_SECONDS={TOL}\nFETCH_TIMEOUT=20\n")
    env = dict(os.environ, PFT_IS_CONF=str(conf), PFT_IS_LIB=str(LIB), PFT_IS_UBUNTU_BASE=origin.base + "/oval",
               PFT_IS_DEBIAN_URL=origin.base + TRACKER, PFT_IS_GO_BASE=origin.base + "/go", PFT_IS_NOW=str(T + 10 * H))
    env.pop("PFT_IS_CURL", None)
    return {"env": env, "cache": cache, "tf": tf, "conf": conf, "o": origin}


def fetch(fe):
    return subprocess.run(["bash", str(SCRIPT), "fetch"], env=fe["env"], capture_output=True, text=True, timeout=120)


def meta(fe):
    return json.loads((fe["cache"] / "feeds" / "feeds.json").read_text())["feeds"]


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------------ outcomes

def test_fresh_first_copy_no_retry(fenv):
    noble(fenv["o"], T)
    r = fetch(fenv)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ubuntu-noble: fresh (own timestamp 2026-11-26T13:33:20Z)" in r.stdout
    m = meta(fenv)["ubuntu-noble"]
    assert m["outcome"] == "fresh" and m["upstream_clock"] == "head_last_modified" and m["upstream_epoch"] == T + 19
    assert m["timestamp_epoch"] == T and m["sha256"] == sha(oval(T))
    assert len(fenv["o"].gets(NOBLE)) == 1 and not any(g["query"] for g in fenv["o"].gets(NOBLE))
    heads = [x for x in fenv["o"].log if x["method"] == "HEAD"]
    assert len(heads) == 1 and heads[0]["headers"]["cache-control"] == "no-cache"


def test_tolerance_boundary(fenv):
    noble(fenv["o"], T, head_e=T + TOL)          # exactly the tolerance: fresh, no retry
    assert "ubuntu-noble: fresh" in fetch(fenv).stdout and len(fenv["o"].gets(NOBLE)) == 1
    noble(fenv["o"], T, head_e=T + TOL + 1)      # one second more: behind -> one retry
    r = fetch(fenv)
    assert "ubuntu-noble: still_behind" in r.stdout and len(fenv["o"].gets(NOBLE)) == 3


def test_stale_then_fresh_retry_keeps_the_fresh_copy(fenv):
    noble(fenv["o"], T - 30 * H, origin_e=T)
    r = fetch(fenv)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ubuntu-noble: retried_fresh (own timestamp 2026-11-26T13:33:20Z)" in r.stdout
    g = fenv["o"].gets(NOBLE)
    assert len(g) == 2 and g[0]["query"] == "" and g[1]["query"].startswith("pftcb=")
    h = g[1]["headers"]
    assert h["cache-control"] == "no-cache" and h["pragma"] == "no-cache" and h["if-none-match"] == '"c-noble"'
    m = meta(fenv)["ubuntu-noble"]
    assert m["outcome"] == "retried_fresh" and m["timestamp_epoch"] == T and m["sha256"] == sha(oval(T))
    assert (fenv["cache"] / "feeds" / m["file"]).read_bytes() == oval(T)
    assert "retry copy is newer, kept" in m["outcome_note"]


def test_retry_still_behind_keeps_first_copy(fenv):
    noble(fenv["o"], T - 30 * H, origin_e=T - 30 * H, head_e=T)  # the cache-busted GET reaches the same old copy
    r = fetch(fenv)
    assert r.returncode == 0 and "ubuntu-noble: still_behind" in r.stdout
    m = meta(fenv)["ubuntu-noble"]
    assert m["outcome"] == "still_behind" and m["timestamp_epoch"] == T - 30 * H
    assert "retry copy is not newer" in m["outcome_note"] and f"{30 * H} s behind head_last_modified" in m["outcome_note"]
    assert len(fenv["o"].gets(NOBLE)) == 2  # exactly one retry, never more


def test_retry_304_is_still_behind(fenv):
    noble(fenv["o"], T - 30 * H, origin_e=T, head_e=T, on_304=True)
    r = fetch(fenv)
    assert "ubuntu-noble: still_behind" in r.stdout
    m = meta(fenv)["ubuntu-noble"]
    assert "retry HTTP 304" in m["outcome_note"] and m["timestamp_epoch"] == T - 30 * H


def test_retry_without_etag_uses_if_modified_since(fenv):
    noble(fenv["o"], T - 30 * H, origin_e=T)
    r = fenv["o"].routes[NOBLE]
    r["cached"] = (r["cached"][0], r["cached"][1], "")
    fetch(fenv)
    h = fenv["o"].gets(NOBLE)[1]["headers"]
    assert "if-none-match" not in h and h["if-modified-since"] == hdate(T - 30 * H + 19)


# ------------------------------------------------------------------ truncated downloads

def test_truncated_first_download_refused_without_retry(fenv):
    noble(fenv["o"], T)
    good = fenv["o"].routes[NOBLE]["cached"]
    fenv["o"].routes[NOBLE]["cached"] = (good[0][: len(good[0]) // 2], good[1], good[2])
    r = fetch(fenv)
    assert r.returncode == 1 and "ubuntu-noble: REFUSED" in r.stdout
    assert not (fenv["cache"] / "feeds" / "feeds.json").exists()
    assert len(fenv["o"].gets(NOBLE)) == 1


def test_truncated_retry_copy_refused_first_kept(fenv):
    noble(fenv["o"], T - 30 * H, origin_e=T)
    fresh = fenv["o"].routes[NOBLE]["origin"]
    fenv["o"].routes[NOBLE]["origin"] = (fresh[0][:100], fresh[1], fresh[2])
    r = fetch(fenv)
    assert r.returncode == 0 and "ubuntu-noble: still_behind" in r.stdout
    m = meta(fenv)["ubuntu-noble"]
    assert "retry copy refused" in m["outcome_note"] and m["sha256"] == sha(oval(T - 30 * H))


def test_failed_download_keeps_previous_entry(fenv):
    noble(fenv["o"], T)
    assert fetch(fenv).returncode == 0
    before = (fenv["cache"] / "feeds" / "feeds.json").read_text()
    fenv["o"].routes[NOBLE]["status"] = 503
    r = fetch(fenv)
    assert r.returncode == 1 and "ubuntu-noble: FAILED (HTTP 503" in r.stdout
    assert (fenv["cache"] / "feeds" / "feeds.json").read_text() == before


# ------------------------------------------------------------------ older-copy protection

def test_download_older_than_installed_never_replaces_it(fenv):
    noble(fenv["o"], T)
    assert fetch(fenv).returncode == 0
    m0 = meta(fenv)["ubuntu-noble"]
    noble(fenv["o"], T - 30 * H, origin_e=T - 30 * H, head_e=T)  # a cache now serves an even older copy
    fenv["env"]["PFT_IS_NOW"] = str(T + 20 * H)
    r = fetch(fenv)
    assert r.returncode == 0 and "older than the installed copy, kept installed" in r.stdout
    m = meta(fenv)["ubuntu-noble"]
    assert m["outcome"] == "still_behind" and "installed copy kept" in m["outcome_note"]
    for k in ("sha256", "timestamp_epoch", "fetched_epoch", "file"):
        assert m[k] == m0[k], k
    assert (fenv["cache"] / "feeds" / m["file"]).read_bytes() == oval(T)


def test_feed_merge_second_guard(tmp_path):
    import imagescan_lib as L
    fdir, tmp = tmp_path / "feeds", tmp_path / "tmp"
    fdir.mkdir()
    tmp.mkdir()
    (fdir / "f.bz2").write_bytes(b"new")
    (tmp / "f.bz2").write_bytes(b"old")
    (fdir / "feeds.json").write_text(json.dumps({"feeds": {"ubuntu-noble": {
        "kind": "ubuntu-oval", "file": "f.bz2", "sha256": sha(b"new"), "timestamp_epoch": T, "fetched_epoch": T,
        "url": "u"}}}))
    e = {"name": "ubuntu-noble", "kind": "ubuntu-oval", "file": "f.bz2", "sha256": sha(b"old"),
         "timestamp_epoch": T - H, "fetched_epoch": T + H, "url": "u", "outcome": "fresh", "upstream_epoch": T - H,
         "upstream_clock": "head_last_modified", "outcome_note": "x", "outcome_epoch": T + H, "action": "replace"}
    m = L.feed_merge(str(fdir), str(tmp), [json.dumps(e)])["feeds"]["ubuntu-noble"]
    assert m["sha256"] == sha(b"new") and m["outcome"] == "still_behind" and (fdir / "f.bz2").read_bytes() == b"new"
    with pytest.raises(L.Bad):
        L.feed_merge(str(fdir), str(tmp), [json.dumps({**e, "outcome": "maybe"})])
    with pytest.raises(L.Bad):
        L.feed_merge(str(fdir), str(tmp), [json.dumps({**e, "name": "go", "action": "keep"})])


# ------------------------------------------------------------------ debian / go clocks

def test_debian_head_clock_and_retry(fenv):
    fenv["conf"].write_text(fenv["conf"].read_text().replace("FEEDS=ubuntu-noble", "FEEDS=debian"))
    body = tracker()
    fenv["o"].routes[TRACKER] = {"cached": (body, T - 10 * H, '"c-deb"'), "origin": (body, T, '"o-deb"'), "head_lm": T}
    r = fetch(fenv)
    assert r.returncode == 0 and "debian: retried_fresh" in r.stdout, r.stdout + r.stderr
    m = meta(fenv)["debian"]
    assert m["timestamp_epoch"] == T and m["upstream_clock"] == "head_last_modified"


def test_go_index_clock(fenv):
    fenv["conf"].write_text(fenv["conf"].read_text().replace("FEEDS=ubuntu-noble", "FEEDS=go"))
    # the zip's own Last-Modified is NEWER than its content (rebuilt daily): it must not count as the clock
    fenv["o"].routes[GOZIP] = {"cached": (gozip(T - 30 * H), T + 5 * H, '"c-go"'), "origin": (gozip(T), T + 5 * H, '"o-go"')}
    fenv["o"].routes[GOIDX] = {"cached": (json.dumps({"modified": iso(T) + "Z"}).encode(), None, ""),
                               "origin": (b"", None, "")}
    r = fetch(fenv)
    assert r.returncode == 0 and "go: retried_fresh" in r.stdout, r.stdout + r.stderr
    m = meta(fenv)["go"]
    assert m["upstream_clock"] == "index_modified" and m["upstream_epoch"] == T and m["timestamp_epoch"] == T


def test_no_upstream_clock_is_not_fresh(fenv):
    fenv["conf"].write_text(fenv["conf"].read_text().replace("FEEDS=ubuntu-noble", "FEEDS=go"))
    fenv["o"].routes[GOZIP] = {"cached": (gozip(T), T, '"c-go"'), "origin": (gozip(T), T, '"o-go"')}
    r = fetch(fenv)  # no index/db.json route: 404
    assert r.returncode == 0 and "go: still_behind" in r.stdout
    m = meta(fenv)["go"]
    assert "no upstream clock readable (not proven fresh)" in m["outcome_note"] and m["upstream_epoch"] == 0
    assert len(fenv["o"].gets(GOZIP)) == 2  # it did retry once


# ------------------------------------------------------------------ textfile series

SCAN_LINES = ('# HELP pft_imagescan_up x\n# TYPE pft_imagescan_up gauge\npft_imagescan_up{host="validator"} 1\n'
              'pft_imagescan_last_run_timestamp_seconds{host="validator"} 1795600000\n'
              'pft_imagescan_feed_fetched_timestamp_seconds{host="validator",feed="ubuntu-noble"} 1795600000\n')


def test_fetch_rewrites_only_outcome_series(fenv):
    prom = fenv["tf"] / "pft_imagescan_validator.prom"
    prom.write_text(SCAN_LINES)
    noble(fenv["o"], T - 30 * H, origin_e=T)
    assert fetch(fenv).returncode == 0
    noble(fenv["o"], T)
    r = fetch(fenv)
    assert r.returncode == 0 and "textfile: fetch outcome series updated" in r.stdout
    text = prom.read_text()
    assert text.startswith(SCAN_LINES)  # scan series untouched, in order
    rows = [ln for ln in text.splitlines() if ln.startswith("pft_imagescan_feed_fetch_outcome{")]
    assert rows == ['pft_imagescan_feed_fetch_outcome{host="validator",feed="ubuntu-noble",outcome="fresh"} 1',
                    'pft_imagescan_feed_fetch_outcome{host="validator",feed="ubuntu-noble",outcome="retried_fresh"} 0',
                    'pft_imagescan_feed_fetch_outcome{host="validator",feed="ubuntu-noble",outcome="still_behind"} 0']
    assert text.count("# TYPE pft_imagescan_feed_fetch_outcome gauge") == 1
    assert f'pft_imagescan_feed_upstream_timestamp_seconds{{host="validator",feed="ubuntu-noble"}} {T + 19}' in text
    assert prom.stat().st_mode & 0o777 == 0o644
    v = subprocess.run(["bash", str(SCRIPT), "validate", str(prom), "validator"], env=fenv["env"],
                       capture_output=True, text=True)
    assert v.returncode == 0, v.stdout


def test_fetch_without_textfile_writes_none(fenv):
    noble(fenv["o"], T)
    r = fetch(fenv)
    assert r.returncode == 0 and "absent (written by the first scan)" in r.stdout
    assert list(fenv["tf"].iterdir()) == []


# ------------------------------------------------------------------ heal unit

def test_heal_unit_is_fetch_only_sandboxed_and_untimed():
    u = UNIT.read_text()
    lines = [ln for ln in u.splitlines() if ln and not ln.startswith("#")]
    assert "ExecStart=/usr/local/bin/pft-imagescan fetch" in lines
    assert [ln for ln in lines if ln.startswith("ExecStart")] == ["ExecStart=/usr/local/bin/pft-imagescan fetch"]
    ina = next(ln for ln in lines if ln.startswith("InaccessiblePaths="))
    assert "/run/docker.sock" in ina and "/var/run/docker.sock" in ina
    for k in ("ProtectSystem=strict", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "PrivateTmp=yes",
              "MemoryMax=768M", "ReadWritePaths=/var/lib/pft-exporter/textfile", "CacheDirectory=pft-imagescan"):
        assert k in lines, k
    assert "[Install]" not in u and not any(ln.startswith("SuccessExitStatus") for ln in lines)
    assert not (ROOT / "systemd" / "pft-imagescan-heal.timer").exists()


def test_fetch_refuses_to_rewrite_an_invalid_textfile(fenv):
    prom = fenv["tf"] / "pft_imagescan_validator.prom"
    bad = SCAN_LINES + 'pft_other{host="validator"} 1\n'
    prom.write_text(bad)
    noble(fenv["o"], T)
    r = fetch(fenv)
    assert r.returncode == 1 and "textfile: invalid (line" in r.stdout
    assert prom.read_text() == bad and [p.name for p in fenv["tf"].iterdir()] == [prom.name]
    assert meta(fenv)["ubuntu-noble"]["outcome"] == "fresh"  # the feed itself was still refreshed


def test_scan_textfile_carries_outcome_series(tmp_path):
    import shutil
    import tempfile

    import test_imagescan as ti
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))  # stubs must be executable (/tmp noexec)
    os.makedirs(base, exist_ok=True)
    sd = Path(tempfile.mkdtemp(prefix="imagescan-stub-", dir=base))
    try:
        _scan_outcome(tmp_path, sd, ti)
    finally:
        shutil.rmtree(sd)


def _scan_outcome(tmp_path, sd, ti):
    env, tf, cache = ti.shell_env(tmp_path, [("go:1", "2" * 64, ti.go_only_image())], sd)
    p = cache / "feeds" / "feeds.json"
    m = json.loads(p.read_text())
    m["feeds"]["go"].update(outcome="retried_fresh", upstream_epoch=ti.NOW - 7000, upstream_clock="index_modified",
                            outcome_note="n", outcome_epoch=ti.NOW - 60)
    p.write_text(json.dumps(m))
    r = subprocess.run(["bash", str(SCRIPT), "scan", "--no-fetch"], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    prom = (tf / "pft_imagescan_validator.prom").read_text()
    assert 'pft_imagescan_feed_fetch_outcome{host="validator",feed="go",outcome="retried_fresh"} 1' in prom
    assert 'feed="debian",outcome=' not in prom  # entries from before outcomes existed export none
    scan = json.loads((cache / "last-scan.json").read_text())
    assert scan["feeds"]["go"]["outcome"] == "retried_fresh" and "outcome" not in scan["feeds"]["debian"]
