"""Tests for upstreamwatch (run: cd upstreamwatch && TMPDIR=$HOME/.cache python3 -m pytest -q tests).

Fixture servers are real HTTP servers on 127.0.0.1 (ThreadingHTTPServer); the live capture
tests/fixtures/obs-live-validator-20261123.json holds the real upstream headers of 2026-11-23T01:43Z.
"""

import bz2
import copy
import io
import json
import os
import socket
import subprocess
import sys
import threading
import zipfile
from datetime import datetime, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import upstreamwatch_lib as uw

LIVE = json.loads((HERE / "fixtures" / "obs-live-validator-20261123.json").read_text())
SCRIPT = ROOT / "pft-upstreamwatch.sh"
LIB = ROOT / "upstreamwatch_lib.py"
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
H = 3600


def hdate(epoch):
    return format_datetime(datetime.fromtimestamp(epoch, tz=timezone.utc), usegmt=True)


# ------------------------------------------------------------------------------------------------ fixture server


class Server:
    """routes: path -> list of (status, headers, body); the last entry repeats. Records every request."""

    def __init__(self):
        self.routes, self.log = {}, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body_in = self.rfile.read(n) if n else b""
                outer.log.append({"method": self.command, "path": self.path, "headers": dict(self.headers),
                                  "body": body_in.decode()})
                key = self.path.split("?")[0]
                seq = outer.routes.get(key) or outer.routes.get(self.path) or [(404, {}, b"")]
                idx = sum(1 for r in outer.log if r["path"].split("?")[0] == key) - 1
                status, headers, body = seq[min(idx, len(seq) - 1)]
                if callable(body):
                    body = body(self)
                body = body.encode() if isinstance(body, str) else body
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                if "Content-Length" not in headers:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = do_POST = _serve

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def srv():
    s = Server()
    yield s
    s.close()


def dead_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here any more
    return f"http://127.0.0.1:{port}"


def cfg(**kw):
    c = uw.load_cfg("")
    c.update({"backoff_seconds": 0.0, "http_timeout": 5, **kw})
    return c


# ------------------------------------------------------------------------------------------------ local fixtures

OVAL = b'<?xml version="1.0"?>\n<oval_definitions><generator><oval:timestamp>{ts}</oval:timestamp></generator>'


def oval_bytes(epoch, pad=200000):
    ts = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S").encode()
    return bz2.compress(OVAL.replace(b"{ts}", ts) + b"<d/>" * pad + b"</oval_definitions>")


def write_vulnscan(d, content_epoch, fetched, etag='"e1"', data=None):
    d.mkdir(parents=True, exist_ok=True)
    data = data if data is not None else oval_bytes(content_epoch)
    (d / "feed.xml.bz2").write_bytes(data)
    import hashlib

    sha = hashlib.sha256(data).hexdigest()
    (d / "feed.meta").write_text(f"sha256={sha}\nfetched_at={fetched}\nlast_checked={fetched}\nurl=x\n")
    (d / "feed.etag").write_text(etag + "\n")
    return sha


def go_zip(modified):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("index/db.json", json.dumps({"modified": modified}))
        z.writestr("ID/GO-2026-0001.json", "{}" * 2000)
    return b.getvalue()


def write_imagescan(d, entries):
    """entries: name -> (file, kind, bytes, content_epoch, fetched)"""
    import hashlib

    (d / "feeds").mkdir(parents=True, exist_ok=True)
    feeds = {}
    for name, (fname, kind, data, ts, fetched) in entries.items():
        (d / "feeds" / fname).write_bytes(data)
        feeds[name] = {"file": fname, "kind": kind, "sha256": hashlib.sha256(data).hexdigest(),
                       "timestamp_epoch": ts, "fetched_epoch": fetched, "url": "x"}
    (d / "feeds" / "feeds.json").write_text(json.dumps({"feeds": feeds}))


# ------------------------------------------------------------------------------------------------ obs builders

NOW = 1795398000  # 2026-11-23T01:40:00Z


def feed_obs(name="usn-host", local="vulnscan", status=200, date=NOW, lm=NOW - 2 * H, etag='"new"',
             content_epoch=NOW - 2 * H, fetched=NOW - H, local_etag='"old"', local_error="", attempts=None,
             content=None, kind="ubuntu-oval"):
    up_h = {}
    if date is not None:
        up_h["date"] = hdate(date)
    if lm is not None:
        up_h["last-modified"] = hdate(lm)
    if etag:
        up_h["etag"] = etag
    f = {"name": name, "kind": kind, "url": "https://example.invalid/" + name, "local": local, "content_url": "",
         "local_obs": {"source": local, "error": local_error, "etag": local_etag, "fetched_epoch": fetched,
                       "checked_epoch": fetched, "content_epoch": content_epoch},
         "upstream": {"status": status, "headers": up_h, "attempts": attempts or [status], "error": "",
                      "conditional": True}}
    if not local:
        f["local_obs"] = {"source": "", "error": ""}
    if content is not None:
        f["content_url"] = "https://example.invalid/index/db.json"
        f["upstream"]["content"] = content
    return f


def ev(f, now=NOW, **kw):
    return uw.evaluate_feed(f, now, cfg(**kw))


# ================================================================================================ real capture


def test_live_capture_reclassifies_quiet_usn_feeds():
    res = uw.evaluate(LIVE)
    st = {f["name"]: f["state"] for f in res["feeds"]}
    assert st == {"usn-host": "upstream_quiet", "ubuntu-jammy": "upstream_quiet", "ubuntu-noble": "upstream_quiet",
                  "debian": "ok", "go": "upstream_quiet", "debian-oval-bookworm": "ok"}
    usn = res["feeds"][0]
    assert "304" in usn["reason"]
    assert res["release"]["state"] == "current"
    assert res["release"]["digest_state"] == "current" and res["release"]["version_state"] == "current"
    assert res["counts"]["local_stale"] == 0 and res["counts"]["fetch_failing"] == 0


def test_live_capture_render_is_byte_identical_offline(tmp_path):
    p = tmp_path / "obs.json"
    p.write_text(json.dumps(LIVE))
    for fmt in ("text", "json", "prom"):
        a = subprocess.run([sys.executable, "-I", str(LIB), "render", "--obs", str(p), "--format", fmt],
                           capture_output=True, check=True).stdout
        assert a == uw.render(copy.deepcopy(LIVE), fmt).encode()
        assert a == subprocess.run([sys.executable, "-I", str(LIB), "render", "--obs", str(p), "--format", fmt],
                                   capture_output=True, check=True).stdout


# ================================================================================================ feed states


def test_ok_when_latest_and_young():
    r = ev(feed_obs())
    assert r["state"] == "ok" and r["content_age"] == 2 * H


def test_upstream_quiet_when_latest_but_old():
    r = ev(feed_obs(lm=NOW - 80 * H, content_epoch=NOW - 80 * H - 20))
    assert r["state"] == "upstream_quiet", r
    assert "has not published" in r["reason"]


def test_quiet_boundary_is_exclusive():
    assert ev(feed_obs(lm=NOW - 72 * H, content_epoch=NOW - 72 * H))["state"] == "ok"
    assert ev(feed_obs(lm=NOW - 72 * H - 1, content_epoch=NOW - 72 * H - 1))["state"] == "upstream_quiet"


def test_local_stale_when_upstream_newer_beyond_grace():
    r = ev(feed_obs(lm=NOW - 40 * H, content_epoch=NOW - 100 * H))
    assert r["state"] == "local_stale", r
    assert "newer than ours" in r["reason"] and r["upstream_newer"] == 60 * H


def test_upstream_newer_within_grace_is_local_lagging():
    # was "ok" before local_lagging existed (the 2026-11-24 / 11-27 blind spot)
    r = ev(feed_obs(lm=NOW - 20 * H, content_epoch=NOW - 100 * H))
    assert r["state"] == "local_lagging" and "within grace" in r["reason"] and r["lag"] == 20 * H


def test_tolerance_absorbs_publish_lag():
    # Canonical's Last-Modified is seconds-to-minutes after the feed's own <oval:timestamp>
    r = ev(feed_obs(lm=NOW - 80 * H, content_epoch=NOW - 80 * H - 5 * H))
    assert r["state"] == "upstream_quiet"
    r = ev(feed_obs(lm=NOW - 80 * H, content_epoch=NOW - 80 * H - 7 * H))
    assert r["state"] == "local_stale"


def test_304_means_latest():
    r = ev(feed_obs(status=304, lm=NOW - 75 * H, content_epoch=NOW - 75 * H - 60, etag=""))
    assert r["state"] == "upstream_quiet" and "304" in r["reason"]
    r = ev(feed_obs(status=304, lm=None, content_epoch=NOW - 200 * H, etag=""))
    assert r["state"] == "upstream_quiet" and "304" in r["reason"]


def test_304_with_newer_last_modified_is_not_trusted():
    # a cache revalidating our old ETag while its Last-Modified says upstream is 125 h newer
    r = ev(feed_obs(status=304, lm=NOW - 75 * H, content_epoch=NOW - 200 * H, etag=""))
    assert r["state"] == "local_stale" and "newer than ours" in r["reason"]
    r = ev(feed_obs(status=200, lm=NOW - 75 * H, content_epoch=NOW - 200 * H, etag='"s"', local_etag='"s"'))
    assert r["state"] == "local_stale"


def test_control_200_with_other_etag_and_newer_lm_is_stale():
    r = ev(feed_obs(status=200, lm=NOW - 75 * H, content_epoch=NOW - 200 * H, etag='"other"'))
    assert r["state"] == "local_stale"


def test_same_etag_means_latest():
    r = ev(feed_obs(status=200, lm=NOW - 75 * H, content_epoch=NOW - 75 * H, etag='"same"', local_etag='"same"'))
    assert r["state"] == "upstream_quiet" and "ETag equals" in r["reason"]


def test_fetch_failing_wins_over_everything_upstream():
    r = ev(feed_obs(fetched=NOW - 51 * H))
    assert r["state"] == "fetch_failing" and "51.0 h" in r["reason"]
    r = ev(feed_obs(fetched=NOW - 51 * H, status=0, date=None, lm=None))
    assert r["state"] == "fetch_failing"


def test_fetch_age_boundary():
    assert ev(feed_obs(fetched=NOW - 50 * H))["state"] == "ok"
    assert ev(feed_obs(fetched=NOW - 50 * H - 1))["state"] == "fetch_failing"


def test_unreachable_dead_and_5xx_and_429():
    for st in (0, 503, 429, 404):
        r = ev(feed_obs(status=st, date=None if st == 0 else NOW, lm=None))
        assert r["state"] == "unreachable", (st, r)
        assert "upstream not usable" in r["reason"]


def test_unreachable_never_hides_local_corruption():
    r = ev(feed_obs(status=0, date=None, lm=None, local_error="ValueError: feed sha256 differs"))
    assert r["state"] == "local_stale" and "sha256" in r["reason"]


def test_missing_last_modified_is_unreachable():
    r = ev(feed_obs(lm=None))
    assert r["state"] == "unreachable" and "Last-Modified" in r["reason"]


def test_clock_skew_local_clock_ahead_uses_upstream_date():
    # local clock 2 days ahead: ages are taken on upstream's Date, so a young feed stays ok, skew is reported
    f = feed_obs(lm=NOW - 2 * H, content_epoch=NOW - 2 * H, fetched=NOW + 47 * H)
    r = ev(f, now=NOW + 48 * H)
    assert r["state"] == "ok" and r["content_age"] == 2 * H and r["skew"] == 48 * H


def test_clock_skew_local_clock_behind():
    r = ev(feed_obs(lm=NOW - 80 * H, content_epoch=NOW - 80 * H, fetched=NOW - 30 * H), now=NOW - 24 * H)
    assert r["state"] == "upstream_quiet" and r["skew"] == -24 * H


def test_future_last_modified_is_refused():
    r = ev(feed_obs(lm=NOW + 2 * H))
    assert r["state"] == "unreachable" and "future" in r["reason"]


def test_reference_feed_upstream_only():
    assert ev(feed_obs(name="debian-oval-bookworm", local="", lm=NOW - 5 * H, kind="debian-oval"))["state"] == "ok"
    r = ev(feed_obs(name="debian-oval-bookworm", local="", lm=NOW - 90 * H, kind="debian-oval"))
    assert r["state"] == "upstream_quiet" and r["fetch_age"] is None


def test_go_content_clock_from_index():
    body = json.dumps({"modified": "2026-11-11T02:51:11Z"})
    c = {"status": 200, "body": body, "attempts": [200], "error": "", "headers": {}}
    ts = int(datetime(2026, 11, 11, 2, 51, 11, tzinfo=timezone.utc).timestamp())
    # zip Last-Modified is fresh every day; the content clock (index modified) is what counts
    r = ev(feed_obs(name="go", local="imagescan", lm=NOW - H, content_epoch=ts, content=c, kind="go-osv"))
    assert r["state"] == "upstream_quiet"
    newer = dict(c, body=json.dumps({"modified": "2026-11-21T00:00:00Z"}))
    r = ev(feed_obs(name="go", local="imagescan", lm=NOW - H, content_epoch=ts, content=newer, kind="go-osv"))
    assert r["state"] == "local_stale"
    broken = dict(c, body="not json")
    r = ev(feed_obs(name="go", local="imagescan", lm=NOW - H, content_epoch=ts, content=broken, kind="go-osv"))
    assert r["state"] == "unreachable" and "content clock" in r["reason"]


def test_unknown_feed_name():
    obs = copy.deepcopy(LIVE)
    obs["feeds"].append({"name": "bogus", "error": "unknown feed 'bogus'"})
    assert uw.evaluate(obs)["feeds"][-1]["state"] == "unreachable"
    with pytest.raises(ValueError):
        uw.feed_def("bogus", cfg())


# ================================================================================================ local readers


def test_local_vulnscan_reads_timestamp_and_etag(tmp_path):
    write_vulnscan(tmp_path, NOW - 3 * H, NOW - H)
    o = uw.local_vulnscan(str(tmp_path), "ubuntu-oval")
    assert o["error"] == "" and o["content_epoch"] == NOW - 3 * H and o["etag"] == '"e1"'


def test_truncated_vulnscan_feed_hash_mismatch(tmp_path):
    write_vulnscan(tmp_path, NOW - 3 * H, NOW - H)
    p = tmp_path / "feed.xml.bz2"
    p.write_bytes(p.read_bytes()[: len(p.read_bytes()) // 2])
    o = uw.local_vulnscan(str(tmp_path), "ubuntu-oval")
    assert "sha256 differs" in o["error"]


def test_truncated_vulnscan_feed_with_matching_hash_fails_format(tmp_path):
    data = oval_bytes(NOW - 3 * H)
    write_vulnscan(tmp_path, NOW - 3 * H, NOW - H, data=data[: len(data) - 40])  # meta re-hashed: only format catches
    o = uw.local_vulnscan(str(tmp_path), "ubuntu-oval")
    assert o["error"].startswith("EOFError"), o


def test_missing_vulnscan_cache(tmp_path):
    o = uw.local_vulnscan(str(tmp_path / "nope"), "ubuntu-oval")
    assert o["error"].startswith("FileNotFoundError")


def test_local_imagescan_all_kinds_and_truncation(tmp_path):
    good = {
        "ubuntu-jammy": ("j.bz2", "ubuntu-oval", oval_bytes(NOW - 5 * H), NOW - 5 * H, NOW - H),
        "go": ("vulndb.zip", "go-osv", go_zip("2026-11-11T02:51:11Z"), NOW - 9 * H, NOW - H),
        "debian": ("d.json", "debian-tracker", b'{"pkg": {}}\n', NOW - 2 * H, NOW - H),
    }
    write_imagescan(tmp_path, good)
    for name, (_, kind, *_r) in good.items():
        assert uw.local_imagescan(str(tmp_path), name, kind)["error"] == "", name
    for name, (fname, kind, data, ts, fe) in good.items():
        bad = dict(good)
        bad[name] = (fname, kind, data[: len(data) - 7], ts, fe)  # recorded hash matches the truncated bytes
        write_imagescan(tmp_path, bad)
        err = uw.local_imagescan(str(tmp_path), name, kind)["error"]
        assert err, name
    assert "KeyError" in uw.local_imagescan(str(tmp_path), "ubuntu-noble", "ubuntu-oval")["error"]


# ================================================================================================ HTTP


def test_http_retries_with_backoff_then_gives_up(srv):
    srv.routes["/f"] = [(503, {}, b"")]
    waits = []
    r = uw.http("HEAD", srv.base + "/f", {}, cfg(retries=3, backoff_seconds=1.0), sleep=waits.append)
    assert r["attempts"] == [503, 503, 503] and waits == [1.0, 2.0]


def test_http_429_honours_retry_after_then_succeeds(srv):
    srv.routes["/f"] = [(429, {"Retry-After": "7"}, b""), (200, {"Last-Modified": hdate(NOW)}, b"")]
    waits = []
    r = uw.http("HEAD", srv.base + "/f", {}, cfg(retries=3, backoff_seconds=1.0), sleep=waits.append)
    assert r["attempts"] == [429, 200] and waits == [7.0] and r["status"] == 200


def test_http_no_retry_on_404(srv):
    srv.routes["/f"] = [(404, {}, b"")]
    r = uw.http("HEAD", srv.base + "/f", {}, cfg(retries=3), sleep=lambda s: None)
    assert r["attempts"] == [404]


def test_http_dead_endpoint():
    waits = []
    r = uw.http("HEAD", dead_url() + "/f", {}, cfg(retries=2, backoff_seconds=0.5), sleep=waits.append)
    assert r["status"] == 0 and r["attempts"] == [0, 0] and waits == [0.5] and "URLError" in r["error"]


def test_probe_sends_conditional_head(srv):
    srv.routes["/f"] = [(304, {"ETag": '"e1"', "Date": hdate(NOW)}, b"")]
    d = {"url": srv.base + "/f", "content_url": ""}
    up = uw.probe_feed(d, {"etag": '"e1"'}, cfg())
    assert up["status"] == 304 and up["conditional"]
    req = srv.log[-1]
    assert req["method"] == "HEAD" and req["headers"]["If-None-Match"] == '"e1"'
    uw.probe_feed(d, {"etag": ""}, cfg())
    assert "If-None-Match" not in srv.log[-1]["headers"]


# ================================================================================================ release watch


def rel_server(srv, manifest_seq, token_seq=None, version="1.0.9"):
    srv.routes["/v2/agtipft/postfiatd/manifests/testnet-light-latest"] = manifest_seq
    srv.routes["/token"] = token_seq or [(200, {}, json.dumps({"token": "t0k"}))]
    srv.routes["/rpc"] = [(200, {}, json.dumps({"result": {"info": {"build_version": version}}}))]


def challenge(srv):
    return {"WWW-Authenticate": f'Bearer realm="{srv.base}/token",service="reg",scope="repository:agtipft/postfiatd:pull"'}


def test_registry_401_then_token_then_digest(srv):
    rel_server(srv, [(401, challenge(srv), b""), (200, {"Docker-Content-Digest": DIGEST}, b"")])
    o = uw.registry_digest(srv.base, "agtipft/postfiatd", "testnet-light-latest", cfg())
    assert [s["what"] for s in o["steps"]] == ["manifest", "token", "manifest"]
    assert o["steps"][-1]["headers"]["docker-content-digest"] == DIGEST
    tok = next(r for r in srv.log if r["path"].startswith("/token"))
    assert "scope=repository%3Aagtipft%2Fpostfiatd%3Apull" in tok["path"]
    last = [r for r in srv.log if r["path"].startswith("/v2/")][-1]
    assert last["method"] == "HEAD" and last["headers"]["Authorization"] == "Bearer t0k"
    assert "application/vnd.oci.image.index.v1+json" in last["headers"]["Accept"]


def test_registry_token_401_is_unknown(srv):
    rel_server(srv, [(401, challenge(srv), b"")], token_seq=[(401, {}, b"")])
    o = uw.registry_digest(srv.base, "agtipft/postfiatd", "testnet-light-latest", cfg())
    assert o["steps"][-1]["what"] == "token" and o["steps"][-1]["status"] == 401


def test_registry_realm_must_be_https(srv):
    rel_server(srv, [(401, {"WWW-Authenticate": 'Bearer realm="http://evil.invalid/token"'}, b"")])
    o = uw.registry_digest(srv.base, "agtipft/postfiatd", "testnet-light-latest", cfg())
    assert o["steps"][-1]["error"] == "no usable Bearer realm"


def test_registry_429_retried(srv):
    rel_server(srv, [(429, {}, b"")])
    o = uw.registry_digest(srv.base, "agtipft/postfiatd", "testnet-light-latest", cfg(retries=3), sleep=lambda s: None)
    assert o["steps"][-1]["attempts"] == [429, 429, 429]


def release_obs(srv=None, repo_digests=None, steps=None, found="1.0.9", running="1.0.9", mtime=NOW - 60):
    return {"container": "postfiatd", "error": "", "ref": "agtipft/postfiatd:testnet-light-latest",
            "image_id": DIGEST, "registry": "registry-1.docker.io", "repo": "agtipft/postfiatd",
            "tag": "testnet-light-latest",
            "repo_digests": repo_digests if repo_digests is not None else [f"agtipft/postfiatd@{DIGEST}"],
            "registry_obs": {"steps": steps if steps is not None else [
                {"what": "manifest", "status": 200, "attempts": [200], "error": "",
                 "headers": {"docker-content-digest": DIGEST}}]},
            "foundation": {"version": found, "attempts": [200], "error": "" if found else "URLError: x"},
            "running_build": {"version": running, "mtime": mtime, "error": ""}}


def er(rel):
    return uw.evaluate_release(rel, NOW, cfg())


def test_release_current():
    r = er(release_obs())
    assert r["state"] == "current" and r["digest_state"] == "current" and r["version_state"] == "current"


def test_release_behind_on_digest():
    steps = [{"what": "manifest", "status": 200, "attempts": [200], "error": "",
              "headers": {"docker-content-digest": OTHER}}]
    r = er(release_obs(steps=steps))
    assert r["state"] == "behind" and r["digest_state"] == "behind" and r["version_state"] == "current"


def test_release_behind_on_version_numeric_compare():
    r = er(release_obs(found="1.0.10", running="1.0.9"))
    assert r["version_state"] == "behind" and r["state"] == "behind"
    assert er(release_obs(found="1.0.9", running="1.0.10"))["version_state"] == "current"


def test_release_unknown_cases():
    assert er(release_obs(steps=[{"what": "token", "status": 401, "attempts": [401], "error": "HTTP 401",
                                  "headers": {}}]))["digest_state"] == "unknown"
    assert er(release_obs(repo_digests=[]))["digest_state"] == "unknown"
    assert er(release_obs(found=""))["version_state"] == "unknown"
    assert er(release_obs(mtime=NOW - 2 * H))["version_state"] == "unknown"
    bad = {"what": "manifest", "status": 200, "attempts": [200], "error": "", "headers": {"docker-content-digest": "x"}}
    assert er(release_obs(steps=[bad]))["digest_state"] == "unknown"
    assert er({"container": "c", "error": "RuntimeError: docker", "foundation": {}, "running_build": {}})["state"] == \
        "unknown"


def test_parse_ref():
    assert uw.parse_ref("agtipft/postfiatd:testnet-light-latest") == (
        "registry-1.docker.io", "agtipft/postfiatd", "testnet-light-latest")
    assert uw.parse_ref("prom/prometheus") == ("registry-1.docker.io", "prom/prometheus", "latest")
    assert uw.parse_ref("busybox:1") == ("registry-1.docker.io", "library/busybox", "1")
    assert uw.parse_ref("ghcr.io/o/r:v2") == ("ghcr.io", "o/r", "v2")
    assert uw.parse_ref("localhost:5000/r") == ("localhost:5000", "r", "latest")
    with pytest.raises(ValueError):
        uw.parse_ref("agtipft/postfiatd@" + DIGEST)


def test_running_build_reader(tmp_path):
    p = tmp_path / "u.prom"
    p.write_text('# HELP x\npft_upgradewatch_build_info{container="postfiatd",version="1.0.9"} 1\n')
    assert uw.running_build({"build_textfile": str(p)})["version"] == "1.0.9"
    p.write_text("pft_upgradewatch_up 1\n")
    assert uw.running_build({"build_textfile": str(p)})["error"]
    assert "FileNotFoundError" in uw.running_build({"build_textfile": str(tmp_path / "no")})["error"]


# ================================================================================================ rendering


def test_prom_one_hot_and_validates(tmp_path):
    txt = uw.render(copy.deepcopy(LIVE), "prom")
    for name in ("usn-host", "go", "debian-oval-bookworm"):
        rows = [ln for ln in txt.splitlines() if ln.startswith(f'pft_upstreamwatch_feed_state{{host="validator",feed="{name}"')]
        assert len(rows) == 6 and sum(int(r.rsplit(" ", 1)[1]) for r in rows) == 1
    assert 'pft_upstreamwatch_release_state{host="validator",container="postfiatd",state="current"} 1' in txt
    p = tmp_path / "t.prom"
    p.write_text(txt)
    assert uw.validate(str(p), "validator") == ""
    assert "first label" in uw.validate(str(p), "sentry")
    assert len(txt.encode()) < 32768
    p.write_text(txt + "garbage line\n")
    assert "malformed" in uw.validate(str(p), "validator")
    p.write_text(uw.prom_down("validator", NOW))
    assert uw.validate(str(p), "validator") == ""
    p.write_text('pft_upstreamwatch_up{host="validator"} 1\n')
    assert "last_run" in uw.validate(str(p), "validator")


def test_text_marks_paged_states():
    obs = copy.deepcopy(LIVE)
    assert "-> PAGE" not in uw.render(obs, "text")
    obs["feeds"][0]["local_obs"]["fetched_epoch"] = obs["collected_epoch"] - 60 * H
    obs["feeds"][0]["local_obs"]["checked_epoch"] = obs["collected_epoch"] - 60 * H
    t = uw.render(obs, "text")
    assert "fetch_failing=1" in t and "-> PAGE" in t


def test_label_escaping():
    assert uw.label('a"b\\c\nd') == 'a\\"b\\\\c d'


def test_config_validation(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"nope": 1}))
    with pytest.raises(ValueError):
        uw.load_cfg(str(p))
    p.write_text(json.dumps({"retries": 0}))
    with pytest.raises(ValueError):
        uw.load_cfg(str(p))


def test_evaluate_refuses_other_schema():
    with pytest.raises(ValueError):
        uw.evaluate({"schema": "x"})


# ================================================================================================ shell level

DOCKER_STUB = r"""#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(" ".join(a) + "\n")
if a[:3] == ["inspect", "--type", "container"]:
    print(json.dumps([{"Config": {"Image": "agtipft/postfiatd:testnet-light-latest"}, "Image": os.environ["STUB_ID"]}]))
elif a[:2] == ["image", "inspect"]:
    print(json.dumps([{"RepoDigests": ["agtipft/postfiatd@" + os.environ["STUB_DIGEST"]]}]))
else:
    sys.stderr.write("docker stub: refused " + " ".join(a) + "\n")
    sys.exit(99)
"""


@pytest.fixture
def env(tmp_path, srv):
    stub = tmp_path / "docker"
    stub.write_text(DOCKER_STUB)
    stub.chmod(0o755)
    vs, isc, tf, data = tmp_path / "vs", tmp_path / "is", tmp_path / "tf", tmp_path / "data"
    tf.mkdir()
    now = NOW
    write_vulnscan(vs, now - 80 * H - 10, now - 20 * H, etag='"usn"')
    write_imagescan(isc, {"ubuntu-jammy": ("j.bz2", "ubuntu-oval", oval_bytes(now - 80 * H), now - 80 * H, now - H)})
    (tf / "pft_upgradewatch_postfiatd.prom").write_text(
        'pft_upgradewatch_build_info{container="postfiatd",version="1.0.9"} 1\n')
    os.utime(tf / "pft_upgradewatch_postfiatd.prom", (now - 60, now - 60))
    srv.routes["/oval/com.ubuntu.jammy.usn.oval.xml.bz2"] = [
        (304, {"ETag": '"usn"', "Date": hdate(now), "Last-Modified": hdate(now - 80 * H)}, b"")]
    srv.routes["/oval/oci.com.ubuntu.jammy.usn.oval.xml.bz2"] = [
        (200, {"ETag": '"j"', "Date": hdate(now), "Last-Modified": hdate(now - 80 * H + 30)}, b"")]
    rel_server(srv, [(401, challenge(srv), b""), (200, {"Docker-Content-Digest": DIGEST}, b"")])
    conf = tmp_path / "conf"
    conf.write_text("\n".join([
        "FEEDS=usn-host ubuntu-jammy", f"VULNSCAN_CACHE={vs}", f"IMAGESCAN_CACHE={isc}", f"DATA_DIR={data}",
        f"TEXTFILE_DIR={tf}", f"FOUNDATION_RPC={srv.base}/rpc", f"REGISTRY_URL={srv.base}", "BACKOFF_SECONDS=0",
        "RETRIES=2", "HTTP_TIMEOUT=5", f"PROM_URL={srv.base}/prom", f"NTFY_ENV={tmp_path / 'ntfy.env'}",
    ]) + "\n")
    e = dict(os.environ, PFT_UW_CONF=str(conf), PFT_UW_LIB=str(LIB), PFT_UW_DOCKER=str(stub),
             PFT_UW_NOW=str(now), PFT_UW_UBUNTU_BASE=srv.base + "/oval", STUB_LOG=str(tmp_path / "docker.log"),
             STUB_ID=DIGEST, STUB_DIGEST=DIGEST)
    return {"env": e, "tf": tf, "data": data, "tmp": tmp_path, "srv": srv, "conf": conf, "vs": vs}


def sh(env, *args):
    return subprocess.run(["bash", str(SCRIPT), *args], env=env["env"], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=120)


def test_shell_run_quiet_feeds_exit0_and_docker_only_inspects(env):
    p = sh(env, "run")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "upstream_quiet=2" in p.stdout and "release=current" in p.stdout and "-> PAGE" not in p.stdout
    calls = (env["tmp"] / "docker.log").read_text().splitlines()
    assert calls == ["inspect --type container postfiatd", f"image inspect {DIGEST}"]
    assert not any(c.split()[0] in ("pull", "exec", "run", "create", "start") for c in calls)
    prom = (env["tf"] / "pft_upstreamwatch_validator.prom").read_text()
    assert 'feed="usn-host",state="upstream_quiet"} 1' in prom
    assert (env["tf"] / "pft_upstreamwatch_validator.prom").stat().st_mode & 0o777 == 0o644
    # offline re-render of the saved observations is byte-identical to the run's report
    r = sh(env, "report", "--obs", str(env["data"] / "last-obs.json"))
    assert r.stdout == p.stdout
    j = sh(env, "report", "--obs", str(env["data"] / "last-obs.json"), "--format", "json")
    assert j.stdout == (env["data"] / "last-report.json").read_text()


def test_shell_run_local_stale_exits_1(env):
    # truncate the host feed: only a local fault can explain it, so it pages
    p = env["vs"] / "feed.xml.bz2"
    p.write_bytes(p.read_bytes()[:100])
    r = sh(env, "run")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "local_stale=1" in r.stdout and "-> PAGE" in r.stdout
    prom = (env["tf"] / "pft_upstreamwatch_validator.prom").read_text()
    assert 'feed="usn-host",state="local_stale"} 1' in prom


def test_shell_run_dead_upstreams_unreachable_not_paged(env):
    env["env"]["PFT_UW_UBUNTU_BASE"] = dead_url() + "/oval"
    r = sh(env, "run")
    assert r.returncode == 0 and "unreachable=2" in r.stdout


def test_shell_collect_error_writes_up0(env):
    env["env"]["PFT_UW_LIB"] = str(LIB)
    env["conf"].write_text(env["conf"].read_text() + "QUIET_AGE_HOURS=0\n")
    r = sh(env, "run")
    assert r.returncode == 2 and "QUIET_AGE_HOURS" in r.stderr


def test_shell_lib_failure_writes_up0(env, tmp_path):
    bad = tmp_path / "bad_lib.py"
    bad.write_text(LIB.read_text().replace('if a.cmd == "collect":', 'if a.cmd == "collect":\n            raise OSError("boom")'))
    env["env"]["PFT_UW_LIB"] = str(bad)
    r = sh(env, "run")
    assert r.returncode == 2 and "collect failed" in r.stdout
    assert 'pft_upstreamwatch_up{host="validator"} 0' in (env["tf"] / "pft_upstreamwatch_validator.prom").read_text()


def test_shell_unknown_conf_key(env):
    env["conf"].write_text(env["conf"].read_text() + "EVIL=1\n")
    r = sh(env, "run")
    assert r.returncode == 2 and "unknown key" in r.stderr


def test_shell_validate(env):
    sh(env, "run")
    f = env["tf"] / "pft_upstreamwatch_validator.prom"
    assert sh(env, "validate", str(f), "validator").returncode == 0
    r = sh(env, "validate", str(f), "sentry")
    assert r.returncode == 2 and "first label" in r.stdout


def test_shell_pull_validates_peer_file(env):
    remote = env["tmp"] / "remote"
    remote.mkdir()
    (remote / "pft_upstreamwatch_sentry.prom").write_text(uw.prom_down("sentry", NOW))
    env["conf"].write_text(env["conf"].read_text() + f"REMOTE_DIR={remote}\nPULL_SSH=env\n")
    r = sh(env, "pull")
    assert r.returncode == 0, r.stderr
    assert (env["tf"] / "pft_upstreamwatch_sentry.prom").read_text() == uw.prom_down("sentry", NOW)
    (remote / "pft_upstreamwatch_sentry.prom").write_text(uw.prom_down("validator", NOW))
    r = sh(env, "pull")
    assert r.returncode == 2 and "validation failed" in r.stderr
    assert not list(env["tf"].glob(".pull-*"))


def prom_answer(results):
    return json.dumps({"status": "success", "data": {"resultType": "vector", "result": results}})


def test_digest_sends_once_a_day_low_priority(env):
    srv = env["srv"]
    srv.routes["/prom/api/v1/query"] = [(200, {}, prom_answer([
        {"metric": {"alertname": "PFTUpstreamFeedQuiet", "host": "validator", "feed": "usn-host"}, "value": [0, "600"]},
        {"metric": {"alertname": "PFTUpstreamReleaseAvailable", "host": "sentry"}, "value": [0, "30"]}]))]
    srv.routes["/ntfy/throwaway"] = [(200, {}, b"{}")]
    (env["tmp"] / "ntfy.env").write_text(f"NTFY_SERVER={srv.base}/ntfy\nNTFY_TOPIC=throwaway\n")
    r = sh(env, "digest")
    assert r.returncode == 0 and "digest: sent" in r.stdout, r.stderr
    sent = [x for x in srv.log if x["path"] == "/ntfy/throwaway"]
    assert len(sent) == 1 and sent[0]["headers"]["Priority"] == "low"
    assert "FeedQuiet usn-host on validator: 600 min" in sent[0]["body"]
    assert "ReleaseAvailable postfiatd on sentry: 30 min" in sent[0]["body"]
    r = sh(env, "digest")
    assert "already sent" in r.stdout and len([x for x in srv.log if x["path"] == "/ntfy/throwaway"]) == 1


def test_digest_nothing_to_send(env):
    env["srv"].routes["/prom/api/v1/query"] = [(200, {}, prom_answer([]))]
    r = sh(env, "digest")
    assert r.returncode == 0 and "nothing to send" in r.stdout
    assert not [x for x in env["srv"].log if x["path"].startswith("/ntfy")]


def test_digest_dead_prometheus_fails_closed(env):
    env["conf"].write_text(env["conf"].read_text() + f"PROM_URL={dead_url()}\n")
    r = sh(env, "digest")
    assert r.returncode == 1 and "Prometheus query failed" in r.stderr


def test_digest_empty_prometheus_answer_fails_closed(env):
    env["srv"].routes["/prom/api/v1/query"] = [(200, {}, b"")]
    r = sh(env, "digest")
    assert r.returncode == 1 and "unexpected Prometheus answer" in r.stderr


# ================================================================================================ local_lagging + lag


def test_live_capture_20261127_is_local_lagging():
    # real headers of 2026-11-27T14:43Z: our USN copy 26 Nov 08:55Z, upstream Last-Modified 26 Nov 16:51Z
    obs = json.loads((HERE / "fixtures" / "obs-live-validator-20261127.json").read_text())
    res = uw.evaluate(obs)
    usn = next(f for f in res["feeds"] if f["name"] == "usn-host")
    assert usn["state"] == "local_lagging" and usn["lag"] == 1795790608 - 1795711901
    assert res["counts"]["local_lagging"] >= 1 and res["counts"]["local_stale"] == 0
    assert "-> PAGE" not in uw.render(obs, "text")


def test_lag_boundaries_at_grace():
    g = 30 * H
    r = ev(feed_obs(lm=NOW - g, content_epoch=NOW - 100 * H))
    assert r["state"] == "local_lagging" and r["lag"] == g
    r = ev(feed_obs(lm=NOW - g - 1, content_epoch=NOW - 100 * H))
    assert r["state"] == "local_stale" and r["lag"] == g + 1
    r = ev(feed_obs(lm=NOW, content_epoch=NOW - 10 * H))
    assert r["state"] == "local_lagging" and r["lag"] == 0
    r = ev(feed_obs(lm=NOW - 3 * H, content_epoch=NOW - 10 * H), stale_grace_hours=2)
    assert r["state"] == "local_stale"


def test_lag_zero_when_latest_on_every_path():
    assert ev(feed_obs())["lag"] == 0  # content clock within tolerance
    assert ev(feed_obs(status=304, lm=None, content_epoch=NOW - 2 * H))["lag"] == 0
    assert ev(feed_obs(etag='"same"', local_etag='"same"'))["lag"] == 0
    q = ev(feed_obs(lm=NOW - 80 * H, content_epoch=NOW - 80 * H))
    assert q["state"] == "upstream_quiet" and q["lag"] == 0


def test_lag_none_when_unknown():
    assert ev(feed_obs(status=503, attempts=[503, 503]))["lag"] is None
    assert ev(feed_obs(fetched=NOW - 51 * H))["lag"] is None
    assert ev(feed_obs(local_error="OSError: gone"))["lag"] is None


def test_lag_future_last_modified_within_skew_is_zero():
    r = ev(feed_obs(lm=NOW + 200, content_epoch=NOW - 10 * H))
    assert r["state"] == "local_lagging" and r["lag"] == 0


def test_lag_tolerance_edge():
    tol = 21600
    assert ev(feed_obs(lm=NOW - H, content_epoch=NOW - H - tol))["state"] == "ok"
    r = ev(feed_obs(lm=NOW - H, content_epoch=NOW - H - tol - 1))
    assert r["state"] == "local_lagging" and r["lag"] == H


def test_prom_and_text_carry_lag():
    obs = copy.deepcopy(LIVE)
    obs["feeds"][0] = feed_obs(lm=NOW - 5 * H, content_epoch=NOW - 30 * H)
    obs["collected_epoch"] = NOW
    txt = uw.render(obs, "prom")
    assert 'pft_upstreamwatch_feed_lag_seconds{host="validator",feed="usn-host"} 18000' in txt
    assert 'pft_upstreamwatch_feed_state{host="validator",feed="usn-host",state="local_lagging"} 1' in txt
    t = uw.render(obs, "text")
    row = next(ln for ln in t.splitlines() if ln.startswith("usn-host"))
    assert "local_lagging" in row and " 5.0 h  " in row and "-> PAGE" not in t
    j = json.loads(uw.render(obs, "json"))
    assert j["feeds"][0]["lag"] == 18000 and j["counts"]["local_lagging"] == 1


# ================================================================================================ heal plan (pure)


def lag_res(lag, state=None, local="vulnscan", name="usn-host", heal=None):
    st = state or ("local_lagging" if lag <= 30 * H else "local_stale")
    return {"feeds": [{"name": name, "local": local, "state": st, "lag": lag}], "heal": heal or {}}


def plan(res, now=NOW, maint=False, busy=(), **kw):
    return uw.heal_plan(res, now, cfg(**kw), maint, set(busy))


def multi_res(feeds, heal=None):
    """feeds: [(name, local, lag)] -> evaluate()-shaped result (state from the lag, as lag_res)."""
    return {"feeds": [{"name": n, "local": loc, "lag": lag, "state": "local_lagging" if lag <= 30 * H else "local_stale"}
                      for n, loc, lag in feeds], "heal": heal or {}}


def test_heal_plan_lag_threshold():
    assert plan(lag_res(2 * H)) == []  # exactly LAG_HEAL_HOURS: not yet
    d = plan(lag_res(2 * H + 1))
    assert len(d) == 1 and d[0]["action"] == "heal" and d[0]["feed"] == "usn-host" and "LAG_HEAL_HOURS 2 h" in d[0]["reason"]
    assert plan(lag_res(3 * H), lag_heal_hours=4) == []
    assert plan(lag_res(40 * H))[0]["action"] == "heal"  # local_stale (beyond grace) is healed too


def test_heal_plan_only_healable_fetchers_and_lagging_states():
    d = plan(lag_res(5 * H, local="imagescan", name="ubuntu-jammy"))
    assert [(x["fetcher"], x["feed"], x["feeds"], x["action"]) for x in d] == [
        ("imagescan", "imagescan", ["ubuntu-jammy"], "heal")]
    assert plan(lag_res(5 * H, local="")) == []  # reference feed (debian-oval-*): no local copy, nothing to heal
    assert plan(lag_res(5 * H, local="other")) == []
    for st in ("ok", "upstream_quiet", "fetch_failing", "unreachable"):
        assert plan(lag_res(5 * H, state=st)) == []
    assert plan({"feeds": [{"name": "usn-host", "local": "vulnscan", "state": "local_stale", "lag": None}], "heal": {}}) == []


def test_heal_plan_rate_limit_boundary():
    last = {"usn-host": {"last_attempt_epoch": NOW - 6 * H + 1, "attempts": 1}}
    d = plan(lag_res(5 * H, heal=last))
    assert d[0]["action"] == "skip" and d[0]["reason"].startswith("rate_limited")
    last["usn-host"]["last_attempt_epoch"] = NOW - 6 * H
    assert plan(lag_res(5 * H, heal=last))[0]["action"] == "heal"
    last["usn-host"]["last_attempt_epoch"] = NOW - 2 * H
    assert plan(lag_res(5 * H, heal=last), heal_interval_hours=1)[0]["action"] == "heal"
    # another feed's attempt does not rate-limit this one
    assert plan(lag_res(5 * H, heal={"other": {"last_attempt_epoch": NOW}}))[0]["action"] == "heal"


def test_heal_plan_guards_and_order():
    assert plan(lag_res(5 * H), maint=True)[0]["reason"].startswith("maint_window")
    assert plan(lag_res(5 * H), busy={"vulnscan"})[0]["reason"].startswith("vulnscan_running")
    assert plan(lag_res(5 * H), maint=True, busy={"vulnscan"})[0]["reason"].startswith("maint_window")
    recent = {"usn-host": {"last_attempt_epoch": NOW - H}}
    assert plan(lag_res(5 * H, heal=recent), maint=True)[0]["reason"].startswith("rate_limited")
    d = plan(lag_res(5 * H), lag_heal_hours=0)
    assert d[0]["action"] == "skip" and d[0]["reason"].startswith("disabled")
    assert all(x["action"] == "skip" for x in plan(lag_res(5 * H), maint=True, busy={"vulnscan"}))


def test_heal_plan_one_decision_per_fetcher():
    res = multi_res([("usn-host", "vulnscan", 5 * H), ("ubuntu-jammy", "imagescan", 3 * H),
                     ("ubuntu-noble", "imagescan", 40 * H), ("debian", "imagescan", H), ("go", "imagescan", 0)])
    d = plan(res)
    assert [(x["fetcher"], x["feed"], x["action"]) for x in d] == [("imagescan", "imagescan", "heal"),
                                                                   ("vulnscan", "usn-host", "heal")]
    im = d[0]
    # debian (lag 1 h <= LAG_HEAL_HOURS) and go (lag 0) are not part of the decision; lag = max, state = worst
    assert im["feeds"] == ["ubuntu-jammy", "ubuntu-noble"] and im["lag"] == 40 * H and im["state"] == "local_stale"
    assert im["reason"].startswith("ubuntu-jammy, ubuntu-noble: lag 40.0 h > LAG_HEAL_HOURS 2 h")


def test_heal_plan_cooldown_is_per_fetcher():
    feeds = [("usn-host", "vulnscan", 5 * H), ("ubuntu-jammy", "imagescan", 5 * H)]
    d = plan(multi_res(feeds, heal={"imagescan": {"last_attempt_epoch": NOW - H}}))
    assert [(x["fetcher"], x["action"], x["reason"].split(":")[0]) for x in d] == [
        ("imagescan", "skip", "rate_limited"), ("vulnscan", "heal", "usn-host")]
    d = plan(multi_res(feeds, heal={"usn-host": {"last_attempt_epoch": NOW - H}}))
    assert [(x["fetcher"], x["action"]) for x in d] == [("imagescan", "heal"), ("vulnscan", "skip")]
    # a per-FEED key is not the imagescan cooldown (the unit refreshes every imagescan feed at once)
    d = plan(multi_res(feeds, heal={"ubuntu-jammy": {"last_attempt_epoch": NOW - H}}))
    assert [x["action"] for x in d] == ["heal", "heal"]
    # boundary: exactly HEAL_INTERVAL_HOURS after the last imagescan start heals again
    d = plan(multi_res(feeds[1:], heal={"imagescan": {"last_attempt_epoch": NOW - 6 * H}}))
    assert d[0]["action"] == "heal"
    d = plan(multi_res(feeds[1:], heal={"imagescan": {"last_attempt_epoch": NOW - 6 * H + 1}}))
    assert d[0]["action"] == "skip" and "last imagescan attempt" in d[0]["reason"]


def test_heal_plan_busy_is_per_fetcher():
    feeds = [("usn-host", "vulnscan", 5 * H), ("ubuntu-jammy", "imagescan", 5 * H)]
    d = plan(multi_res(feeds), busy={"imagescan"})
    assert [(x["fetcher"], x["action"], x["reason"].split(":")[0]) for x in d] == [
        ("imagescan", "skip", "imagescan_running"), ("vulnscan", "heal", "usn-host")]
    d = plan(multi_res(feeds), busy={"vulnscan"})
    assert [(x["fetcher"], x["action"]) for x in d] == [("imagescan", "heal"), ("vulnscan", "skip")]
    d = plan(multi_res(feeds), maint=True)
    assert [x["reason"].split(":")[0] for x in d] == ["maint_window", "maint_window"]
    d = plan(multi_res(feeds), lag_heal_hours=0)
    assert [(x["action"], x["reason"].split(" ")[0]) for x in d] == [("skip", "disabled"), ("skip", "disabled")]


def test_heal_plan_cli_busy_validation(tmp_path):
    o = tmp_path / "obs.json"
    o.write_text(json.dumps(LIVE))
    r = subprocess.run([sys.executable, "-I", str(LIB), "heal-plan", "--obs", str(o), "--now", str(NOW), "--maint", "0",
                        "--busy", "vulnscan,bogus"], capture_output=True, text=True)
    assert r.returncode == 2 and "unknown fetchers ['bogus']" in r.stderr
    r = subprocess.run([sys.executable, "-I", str(LIB), "heal-plan", "--obs", str(o), "--now", str(NOW), "--maint", "0",
                        "--busy", ""], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_heal_record_persists_attempts_and_results(tmp_path):
    p = str(tmp_path / "heal.json")
    e = uw.heal_record(p, "usn-host", NOW, "started", 0, "lag 5 h")
    assert e["attempts"] == 1 and e["last_attempt_epoch"] == NOW and e["last_result"] == "started"
    e = uw.heal_record(p, "usn-host", NOW + 120, "healed", 0, "lag 0")
    assert e["attempts"] == 1 and e["last_attempt_epoch"] == NOW and e["last_result_epoch"] == NOW + 120
    e = uw.heal_record(p, "usn-host", NOW + 7 * H, "started", 0)
    assert e["attempts"] == 2 and e["last_attempt_epoch"] == NOW + 7 * H
    assert json.loads(Path(p).read_text())["usn-host"]["attempts"] == 2
    with pytest.raises(ValueError):
        uw.heal_record(p, "usn-host", NOW, "bogus", 0)
    Path(p).write_text("[1]")
    with pytest.raises(ValueError):
        uw.read_heal_state(p)
    assert uw.read_heal_state(str(tmp_path / "absent.json")) == {} and uw.read_heal_state("") == {}


def test_heal_record_updates_obs_copy(tmp_path):
    o = tmp_path / "obs.json"
    o.write_text(json.dumps(LIVE))
    uw.heal_record(str(tmp_path / "h.json"), "usn-host", NOW, "started", 0, obs_path=str(o))
    uw.heal_record(str(tmp_path / "h.json"), "usn-host", NOW + 60, "still_lagging", 0, "lag 5 h", obs_path=str(o))
    obs = json.loads(o.read_text())
    assert obs["heal"]["usn-host"]["last_result"] == "still_lagging"
    prom = uw.render(obs, "prom")
    assert 'pft_upstreamwatch_heal_attempts{host="validator",feed="usn-host"} 1' in prom
    assert f'pft_upstreamwatch_heal_last_attempt_timestamp_seconds{{host="validator",feed="usn-host"}} {NOW}' in prom
    rows = [ln for ln in prom.splitlines() if ln.startswith("pft_upstreamwatch_heal_last_result")]
    assert len(rows) == 4 and [r for r in rows if r.endswith(" 1")] == [
        'pft_upstreamwatch_heal_last_result{host="validator",feed="usn-host",result="still_lagging"} 1']
    p = tmp_path / "t.prom"
    p.write_text(prom)
    assert uw.validate(str(p), "validator") == ""
    assert "heal usn-host: attempts 1" in uw.render(obs, "text") and "still_lagging" in uw.render(obs, "text")


def test_no_heal_metrics_without_state():
    assert "pft_upstreamwatch_heal_" not in uw.render(copy.deepcopy(LIVE), "prom")


def test_load_cfg_heal_keys():
    assert uw.load_cfg("")["lag_heal_hours"] == 2 and uw.load_cfg("")["heal_interval_hours"] == 6


# ================================================================================================ heal (shell level)

SYSTEMCTL_STUB = r"""#!/usr/bin/env python3
import os, shutil, sys
a = sys.argv[1:]
with open(os.environ["SC_LOG"], "a") as f:
    f.write(" ".join(a) + "\n")
if a[:2] == ["is-active", "--quiet"]:
    sys.exit(0 if a[2] in os.environ.get("SC_ACTIVE", "").split() else 3)
if a[0] == "start" and a[1] == "pft-imagescan-heal.service":
    src = os.environ.get("SC_IS_SRC", "")
    if src:  # what pft-imagescan fetch would leave behind: the origin's feeds + feeds.json
        shutil.copytree(os.path.join(src, "feeds"), os.path.join(os.environ["SC_IS"], "feeds"), dirs_exist_ok=True)
    sys.exit(int(os.environ.get("SC_START_RC", "0")))
if a[0] == "start":
    src = os.environ.get("SC_HEAL_SRC", "")
    if src:  # what pft-vulnscan scan --force-fetch would leave behind: the origin's newer feed
        for n in ("feed.xml.bz2", "feed.meta", "feed.etag"):
            shutil.copy(os.path.join(src, n), os.path.join(os.environ["SC_VS"], n))
    sys.exit(int(os.environ.get("SC_START_RC", "0")))
sys.exit(64)
"""


@pytest.fixture
def henv(env):
    """usn-host lagging 5 h: upstream published NOW-5h (ETag "new"), our copy is from NOW-30h (ETag "usn")."""
    t, now = env["tmp"], NOW
    write_vulnscan(env["vs"], now - 30 * H, now - 3 * H, etag='"usn"')
    write_vulnscan(t / "origin", now - 5 * H, now, etag='"new"')
    env["srv"].routes["/oval/com.ubuntu.jammy.usn.oval.xml.bz2"] = [
        (200, {"ETag": '"new"', "Date": hdate(now), "Last-Modified": hdate(now - 5 * H)}, b"")]
    stub = t / "systemctl"
    stub.write_text(SYSTEMCTL_STUB)
    stub.chmod(0o755)
    maint = t / "maint"
    maint.write_text("#!/bin/sh\nexit ${MAINT_RC:-1}\n")
    maint.chmod(0o755)
    env["conf"].write_text(env["conf"].read_text() + f"MAINT_CMD={maint}\n")
    env["env"].update(PFT_UW_SYSTEMCTL=str(stub), SC_LOG=str(t / "sc.log"), SC_VS=str(env["vs"]),
                      SC_HEAL_SRC=str(t / "origin"))
    return env


def sc_calls(env):
    p = env["tmp"] / "sc.log"
    return p.read_text().splitlines() if p.exists() else []


def journal(env):
    p = env["data"] / "heal.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_shell_heal_heals_once_and_returns_to_ok(henv):
    r = sh(henv, "run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert sc_calls(henv) == ["is-active --quiet pft-vulnscan.service", "is-active --quiet pft-vulnscan-heal.service",
                              "is-active --quiet pft-imagescan.service", "is-active --quiet pft-imagescan-heal.service",
                              "start pft-vulnscan-heal.service"]
    assert [e["event"] for e in journal(henv)] == ["start", "healed"]
    assert "heal: usn-host healed - lag 0 after the refetch (usn-host=0) (rc 0)" in r.stdout
    row = next(ln for ln in r.stdout.splitlines() if ln.startswith("usn-host"))
    assert " ok " in row and "upstream ETag equals ours" in row
    prom = (henv["tf"] / "pft_upstreamwatch_validator.prom").read_text()
    assert 'feed="usn-host",state="ok"} 1' in prom and 'pft_upstreamwatch_feed_lag_seconds{host="validator",feed="usn-host"} 0' in prom
    assert 'pft_upstreamwatch_heal_last_result{host="validator",feed="usn-host",result="healed"} 1' in prom
    assert 'pft_upstreamwatch_heal_attempts{host="validator",feed="usn-host"} 1' in prom
    st = json.loads((henv["data"] / "heal-state.json").read_text())["usn-host"]
    assert st["attempts"] == 1 and st["last_attempt_epoch"] == NOW and st["last_result"] == "healed"
    # offline re-render of the final observations equals the run's report (heal line included)
    rep = sh(henv, "report", "--obs", str(henv["data"] / "last-obs.json"))
    assert rep.stdout in r.stdout and "heal usn-host: attempts 1" in rep.stdout
    # the next run: nothing to heal, no new start, journal unchanged
    r2 = sh(henv, "run")
    assert r2.returncode == 0 and sc_calls(henv).count("start pft-vulnscan-heal.service") == 1
    assert len(journal(henv)) == 2


def test_shell_heal_control_without_heal_stays_lagging(henv):
    r = sh(henv, "run", "--no-heal")
    assert r.returncode == 0 and sc_calls(henv) == [] and journal(henv) == []
    row = next(ln for ln in r.stdout.splitlines() if ln.startswith("usn-host"))
    assert "local_lagging" in row and "5.0 h" in row
    prom = (henv["tf"] / "pft_upstreamwatch_validator.prom").read_text()
    assert 'pft_upstreamwatch_feed_lag_seconds{host="validator",feed="usn-host"} 18000' in prom


def test_shell_heal_still_lagging_then_rate_limited_then_retried(henv):
    henv["env"]["SC_HEAL_SRC"] = ""  # the refetch gets the old copy again (cache still old)
    r = sh(henv, "run")
    assert r.returncode == 0 and "heal: usn-host still_lagging" in r.stdout
    assert 'result="still_lagging"} 1' in (henv["tf"] / "pft_upstreamwatch_validator.prom").read_text()
    henv["env"]["PFT_UW_NOW"] = str(NOW + 6 * H - 1)
    r = sh(henv, "run")
    assert "heal: usn-host skip - rate_limited" in r.stdout
    assert sc_calls(henv).count("start pft-vulnscan-heal.service") == 1
    henv["env"]["PFT_UW_NOW"] = str(NOW + 6 * H)
    henv["env"]["SC_HEAL_SRC"] = str(henv["tmp"] / "origin")
    r = sh(henv, "run")
    assert "heal: usn-host healed" in r.stdout and sc_calls(henv).count("start pft-vulnscan-heal.service") == 2
    assert [e["event"] for e in journal(henv)] == ["start", "still_lagging", "skip", "start", "healed"]
    assert json.loads((henv["data"] / "heal-state.json").read_text())["usn-host"]["attempts"] == 2


def test_shell_heal_maint_window_blocks(henv):
    for rc in ("0", "2", "127"):
        henv["env"]["MAINT_RC"] = rc
        r = sh(henv, "run")
        assert "heal: usn-host skip - maint_window" in r.stdout, rc
    assert "start pft-vulnscan-heal.service" not in sc_calls(henv)
    assert 'state="local_lagging"} 1' in (henv["tf"] / "pft_upstreamwatch_validator.prom").read_text()


def test_shell_heal_busy_unit_blocks(henv):
    for u in ("pft-vulnscan.service", "pft-vulnscan-heal.service"):
        henv["env"]["SC_ACTIVE"] = u
        r = sh(henv, "run")
        assert "heal: usn-host skip - vulnscan_running" in r.stdout
    assert "start pft-vulnscan-heal.service" not in sc_calls(henv)


def test_shell_heal_lock_held_blocks(henv):
    henv["data"].mkdir(exist_ok=True)
    holder = subprocess.Popen(["flock", str(henv["data"] / "heal.lock"), "sleep", "20"])
    try:
        import time

        time.sleep(0.5)
        r = sh(henv, "run")
    finally:
        holder.kill()
        holder.wait()
    assert "heal: usn-host skip - locked" in r.stdout and "start pft-vulnscan-heal.service" not in sc_calls(henv)
    assert not (henv["data"] / "heal-state.json").exists()


def test_shell_heal_unit_failure_recorded(henv):
    henv["env"]["SC_START_RC"] = "1"
    henv["env"]["SC_HEAL_SRC"] = ""
    r = sh(henv, "run")
    assert r.returncode == 0 and "heal: usn-host failed - systemctl start pft-vulnscan-heal.service failed" in r.stdout
    assert journal(henv)[-1]["event"] == "failed" and journal(henv)[-1]["rc"] == 1
    assert 'result="failed"} 1' in (henv["tf"] / "pft_upstreamwatch_validator.prom").read_text()


def test_shell_heal_disabled_and_bad_config(henv):
    base = henv["conf"].read_text()
    henv["conf"].write_text(base + "LAG_HEAL_HOURS=0\n")
    r = sh(henv, "run")
    assert "heal: usn-host skip - disabled" in r.stdout and "start pft-vulnscan-heal.service" not in sc_calls(henv)
    for bad in ("LAG_HEAL_HOURS=x", "HEAL_INTERVAL_HOURS=0", "HEAL_TIMEOUT=-1", "HEAL_UNIT=evil;rm.service"):
        henv["conf"].write_text(base + bad + "\n")
        r = sh(henv, "run")
        assert r.returncode == 2 and bad.split("=")[0] in r.stderr, bad


def test_shell_heal_below_threshold_no_decision(henv):
    henv["srv"].routes["/oval/com.ubuntu.jammy.usn.oval.xml.bz2"] = [
        (200, {"ETag": '"new"', "Date": hdate(NOW), "Last-Modified": hdate(NOW - 2 * H)}, b"")]
    r = sh(henv, "run")
    assert r.returncode == 0 and "heal:" not in r.stdout and journal(henv) == []
    assert not any(c.startswith("start") for c in sc_calls(henv))


# ------------------------------------------------------------------------------------------------ imagescan heal


@pytest.fixture
def ihenv(henv):
    """ubuntu-jammy + ubuntu-noble (../imagescan) lag 5 h: upstream published NOW-5h, our copies are from NOW-30h.
    usn-host is upstream_quiet (304, the env default) and never part of these heals."""
    t, now = henv["tmp"], NOW
    write_vulnscan(henv["vs"], now - 80 * H - 10, now - 20 * H, etag='"usn"')
    henv["srv"].routes["/oval/com.ubuntu.jammy.usn.oval.xml.bz2"] = [
        (304, {"ETag": '"usn"', "Date": hdate(now), "Last-Modified": hdate(now - 80 * H)}, b"")]
    old = {n: (f"{n}.bz2", "ubuntu-oval", oval_bytes(now - 30 * H), now - 30 * H, now - H)
           for n in ("ubuntu-jammy", "ubuntu-noble")}
    write_imagescan(t / "is", old)
    write_imagescan(t / "isorigin", {n: (f"{n}.bz2", "ubuntu-oval", oval_bytes(now - 5 * H), now - 5 * H, now)
                                     for n in ("ubuntu-jammy", "ubuntu-noble")})
    for c in ("jammy", "noble"):
        henv["srv"].routes[f"/oval/oci.com.ubuntu.{c}.usn.oval.xml.bz2"] = [
            (200, {"ETag": f'"{c}"', "Date": hdate(now), "Last-Modified": hdate(now - 5 * H)}, b"")]
    henv["conf"].write_text(henv["conf"].read_text().replace("FEEDS=usn-host ubuntu-jammy\n",
                                                             "FEEDS=usn-host ubuntu-jammy ubuntu-noble\n"))
    henv["env"].update(SC_HEAL_SRC="", SC_IS=str(t / "is"), SC_IS_SRC=str(t / "isorigin"))
    henv["is"] = t / "is"
    return henv


def test_shell_imagescan_heal_once_for_all_its_feeds(ihenv):
    r = sh(ihenv, "run")
    assert r.returncode == 0, r.stdout + r.stderr
    starts = [c for c in sc_calls(ihenv) if c.startswith("start")]
    assert starts == ["start pft-imagescan-heal.service"]  # ONE start for both lagging feeds, vulnscan untouched
    assert [(e["feed"], e["event"]) for e in journal(ihenv)] == [("imagescan", "start"), ("imagescan", "healed")]
    assert "heal: imagescan start - ubuntu-jammy, ubuntu-noble: lag 5.0 h > LAG_HEAL_HOURS 2 h" in r.stdout
    assert "heal: imagescan healed - lag 0 after the refetch (ubuntu-jammy=0 ubuntu-noble=0) (rc 0)" in r.stdout
    for n in ("ubuntu-jammy", "ubuntu-noble"):
        row = next(ln for ln in r.stdout.splitlines() if ln.startswith(n))
        assert " ok " in row, row
    prom = (ihenv["tf"] / "pft_upstreamwatch_validator.prom").read_text()
    assert 'pft_upstreamwatch_heal_last_result{host="validator",feed="imagescan",result="healed"} 1' in prom
    assert 'pft_upstreamwatch_heal_attempts{host="validator",feed="imagescan"} 1' in prom
    assert 'feed="usn-host",state="upstream_quiet"} 1' in prom
    st = json.loads((ihenv["data"] / "heal-state.json").read_text())
    assert list(st) == ["imagescan"] and st["imagescan"]["attempts"] == 1
    r2 = sh(ihenv, "run")
    assert r2.returncode == 0 and sc_calls(ihenv).count("start pft-imagescan-heal.service") == 1
    assert len(journal(ihenv)) == 2


def test_shell_imagescan_partial_heal_is_still_lagging_then_cooldown(ihenv):
    # the refetch fixes jammy only (noble: the cache served the old copy again): not healed while noble still lags
    write_imagescan(ihenv["tmp"] / "isorigin", {
        "ubuntu-jammy": ("ubuntu-jammy.bz2", "ubuntu-oval", oval_bytes(NOW - 5 * H), NOW - 5 * H, NOW),
        "ubuntu-noble": ("ubuntu-noble.bz2", "ubuntu-oval", oval_bytes(NOW - 30 * H), NOW - 30 * H, NOW)})
    r = sh(ihenv, "run")
    assert "heal: imagescan still_lagging - lag after the refetch: ubuntu-jammy=0 ubuntu-noble=18000 s" in r.stdout
    assert 'feed="imagescan",result="still_lagging"} 1' in (ihenv["tf"] / "pft_upstreamwatch_validator.prom").read_text()
    ihenv["env"]["PFT_UW_NOW"] = str(NOW + 6 * H - 1)
    r = sh(ihenv, "run")
    assert "heal: imagescan skip - rate_limited: last imagescan attempt" in r.stdout
    assert sc_calls(ihenv).count("start pft-imagescan-heal.service") == 1
    ihenv["env"]["PFT_UW_NOW"] = str(NOW + 6 * H)
    r = sh(ihenv, "run")
    assert sc_calls(ihenv).count("start pft-imagescan-heal.service") == 2
    assert [e["event"] for e in journal(ihenv)] == ["start", "still_lagging", "skip", "start", "still_lagging"]


def test_shell_imagescan_heal_guards(ihenv):
    for u in ("pft-imagescan.service", "pft-imagescan-heal.service"):
        ihenv["env"]["SC_ACTIVE"] = u
        r = sh(ihenv, "run")
        assert "heal: imagescan skip - imagescan_running" in r.stdout, u
    ihenv["env"]["SC_ACTIVE"] = "pft-vulnscan.service"  # a busy vulnscan does not block the imagescan heal
    ihenv["env"]["MAINT_RC"] = "0"
    r = sh(ihenv, "run")
    assert "heal: imagescan skip - maint_window" in r.stdout
    assert "start pft-imagescan-heal.service" not in sc_calls(ihenv)
    ihenv["env"]["MAINT_RC"] = "1"
    r = sh(ihenv, "run")
    assert "heal: imagescan healed" in r.stdout


def test_shell_imagescan_heal_lock_held_blocks(ihenv):
    ihenv["data"].mkdir(exist_ok=True)
    holder = subprocess.Popen(["flock", str(ihenv["data"] / "heal.lock"), "sleep", "20"])
    try:
        import time

        time.sleep(0.5)
        r = sh(ihenv, "run")
    finally:
        holder.kill()
        holder.wait()
    assert "heal: imagescan skip - locked" in r.stdout and "start pft-imagescan-heal.service" not in sc_calls(ihenv)
    assert not (ihenv["data"] / "heal-state.json").exists()


def test_shell_imagescan_heal_unit_failure_recorded(ihenv):
    ihenv["env"].update(SC_START_RC="1", SC_IS_SRC="")
    r = sh(ihenv, "run")
    assert "heal: imagescan failed - systemctl start pft-imagescan-heal.service failed" in r.stdout
    assert journal(ihenv)[-1]["event"] == "failed" and journal(ihenv)[-1]["rc"] == 1


def test_shell_imagescan_heal_unit_validated(ihenv):
    base = ihenv["conf"].read_text()
    ihenv["conf"].write_text(base + "IMAGESCAN_HEAL_UNIT=evil;rm.service\n")
    r = sh(ihenv, "run")
    assert r.returncode == 2 and "IMAGESCAN_HEAL_UNIT" in r.stderr
    ihenv["conf"].write_text(base + "IMAGESCAN_HEAL_UNIT=pft-other-heal.service\n")
    r = sh(ihenv, "run")
    assert "start pft-other-heal.service" in sc_calls(ihenv)
