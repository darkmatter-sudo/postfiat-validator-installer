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


def test_upstream_newer_within_grace_is_ok():
    r = ev(feed_obs(lm=NOW - 20 * H, content_epoch=NOW - 100 * H))
    assert r["state"] == "ok" and "within grace" in r["reason"]


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
        assert len(rows) == 5 and sum(int(r.rsplit(" ", 1)[1]) for r in rows) == 1
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
