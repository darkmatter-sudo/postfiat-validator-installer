#!/usr/bin/env python3
"""upstreamwatch: two-clock freshness of the vulnerability feeds and a read-only postfiatd release watch.

Stdlib only. Called by pft-upstreamwatch.sh:

  collect --config CONF.json --out OBS.json      gather raw observations (local feed metadata, upstream HEAD
                                                 headers, registry digest, foundation build_version, docker inspect)
  render  --obs OBS.json --format text|json|prom evaluate + render; pure function of OBS.json (offline re-render)
  validate FILE HOST                             check a textfile before it is served

Observations hold only raw facts (headers, epochs, hashes). Every state is derived by evaluate(), so a committed
OBS.json re-renders byte-identically anywhere (no network, no docker, no clock).

Feed states (one per feed):
  ok              local copy is the latest upstream content and it is younger than QUIET_AGE_HOURS
  upstream_quiet  local copy is the latest upstream content, but upstream itself has not published for
                  QUIET_AGE_HOURS (nothing is wrong locally; never paged, daily digest only)
  local_stale     upstream has published newer content more than STALE_GRACE_HOURS ago and the local copy still
                  lacks it, or the local copy is missing/truncated/corrupt (sha256 or format check fails)
  fetch_failing   the local fetcher has not completed a download/revalidation for FETCH_MAX_AGE_HOURS
  unreachable     upstream could not be asked (network error, 5xx/429 after retries, unusable headers) and the
                  local fetcher is not (yet) overdue; a persisting outage turns into fetch_failing
"""

import argparse
import bz2
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

SCHEMA = "upstreamwatch/1"
STATES = ("ok", "upstream_quiet", "local_stale", "fetch_failing", "unreachable")
RELEASE_STATES = ("current", "behind", "unknown")
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
)
UA = "pft-upstreamwatch/1.0 (+https://github.com/darkmatter-sudo/postfiat-validator-installer)"
OVAL_TS = re.compile(rb"<(?:oval:)?timestamp>(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

DEFAULTS = {
    "host": "validator",
    "feeds": "usn-host ubuntu-jammy ubuntu-noble debian go debian-oval-bookworm",
    "vulnscan_cache": "/var/cache/pft-vulnscan",
    "imagescan_cache": "/var/cache/pft-imagescan",
    "ubuntu_base": "https://security-metadata.canonical.com/oval",
    "debian_tracker_url": "https://security-tracker.debian.org/tracker/data/json",
    "debian_oval_base": "https://www.debian.org/security/oval",
    "go_base": "https://vuln.go.dev",
    "quiet_age_hours": 72,
    "stale_grace_hours": 30,
    "fetch_max_age_hours": 50,
    "content_tolerance_seconds": 21600,
    "skew_max_seconds": 300,
    "retries": 3,
    "backoff_seconds": 2.0,
    "http_timeout": 20,
    "container": "postfiatd",
    "registry_url": "",
    "foundation_rpc": "https://rpc.testnet.postfiat.org/",
    "build_textfile": "/var/lib/pft-exporter/textfile/pft_upgradewatch_postfiatd.prom",
    "build_max_age_seconds": 3600,
    "docker": "docker",
}


# ----------------------------------------------------------------------------------------------------------------
# feed definitions


def feed_def(name, cfg):
    """NAME -> {kind, url, local, content_url}; ValueError for an unknown name."""
    if name == "usn-host":
        return {"kind": "ubuntu-oval", "local": "vulnscan", "content_url": "",
                "url": cfg["ubuntu_base"] + "/com.ubuntu.jammy.usn.oval.xml.bz2"}
    m = re.fullmatch(r"ubuntu-([a-z]+)", name)
    if m:
        return {"kind": "ubuntu-oval", "local": "imagescan", "content_url": "",
                "url": f"{cfg['ubuntu_base']}/oci.com.ubuntu.{m.group(1)}.usn.oval.xml.bz2"}
    if name == "debian":
        return {"kind": "debian-tracker", "local": "imagescan", "content_url": "", "url": cfg["debian_tracker_url"]}
    if name == "go":
        return {"kind": "go-osv", "local": "imagescan", "url": cfg["go_base"] + "/vulndb.zip",
                "content_url": cfg["go_base"] + "/index/db.json"}
    m = re.fullmatch(r"debian-oval-([a-z]+)", name)
    if m:
        return {"kind": "debian-oval", "local": "", "content_url": "",
                "url": f"{cfg['debian_oval_base']}/oval-definitions-{m.group(1)}.xml.bz2"}
    raise ValueError(f"unknown feed {name!r}")


# ----------------------------------------------------------------------------------------------------------------
# local observations (read-only)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def oval_timestamp(path):
    """<oval:timestamp> of a .bz2 OVAL feed (first 256 KiB of the stream), as UTC epoch."""
    with bz2.open(path, "rb") as f:
        head = f.read(1 << 18)
    m = OVAL_TS.search(head)
    if not m:
        raise ValueError("no <timestamp> in the first 256 KiB")
    return int(datetime.strptime(m.group(1).decode(), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())


def format_check(kind, path):
    """Cheap structural check that catches truncation independent of the recorded hash."""
    if kind == "ubuntu-oval":
        oval_timestamp(path)
        with bz2.open(path, "rb") as f:  # the end-of-stream marker is only reached if the file is complete
            while f.read(1 << 20):
                pass
    elif kind == "go-osv":
        with zipfile.ZipFile(path) as z:
            json.loads(z.read("index/db.json"))
    elif kind == "debian-tracker":
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            f.seek(max(0, end - 64))
            if not f.read().rstrip().endswith(b"}"):
                raise ValueError("JSON does not end with '}' (truncated)")


def local_vulnscan(cache, kind):
    meta_p = os.path.join(cache, "feed.meta")
    feed_p = os.path.join(cache, "feed.xml.bz2")
    obs = {"source": "vulnscan", "error": ""}
    try:
        meta = {}
        with open(meta_p, encoding="utf-8") as f:
            for line in f:
                k, sep, v = line.strip().partition("=")
                if sep:
                    meta[k] = v
        obs["fetched_epoch"] = int(meta["fetched_at"])
        obs["checked_epoch"] = int(meta.get("last_checked", meta["fetched_at"]))
        obs["recorded_sha256"] = meta["sha256"]
        try:
            with open(os.path.join(cache, "feed.etag"), encoding="utf-8") as f:
                obs["etag"] = f.read().strip()
        except FileNotFoundError:
            obs["etag"] = ""
        obs["sha256"] = sha256_file(feed_p)
        if obs["sha256"] != obs["recorded_sha256"]:
            raise ValueError("feed sha256 differs from feed.meta (truncated or replaced)")
        format_check(kind, feed_p)
        obs["content_epoch"] = oval_timestamp(feed_p)
    except (OSError, KeyError, ValueError, EOFError) as e:
        obs["error"] = f"{type(e).__name__}: {e}"
    return obs


def local_imagescan(cache, name, kind):
    obs = {"source": "imagescan", "error": "", "etag": ""}
    try:
        with open(os.path.join(cache, "feeds", "feeds.json"), encoding="utf-8") as f:
            ent = json.load(f)["feeds"][name]
        obs["fetched_epoch"] = int(ent["fetched_epoch"])
        obs["checked_epoch"] = obs["fetched_epoch"]
        obs["content_epoch"] = int(ent["timestamp_epoch"])
        obs["recorded_sha256"] = ent["sha256"]
        path = os.path.join(cache, "feeds", ent["file"])
        obs["sha256"] = sha256_file(path)
        if obs["sha256"] != obs["recorded_sha256"]:
            raise ValueError("feed sha256 differs from feeds.json (truncated or replaced)")
        format_check(kind, path)
    except (OSError, KeyError, ValueError, TypeError, EOFError, zipfile.BadZipFile) as e:
        obs["error"] = f"{type(e).__name__}: {e}"
    return obs


# ----------------------------------------------------------------------------------------------------------------
# HTTP (urllib; every request is a HEAD or a small GET, retried with backoff)


def http(method, url, headers, cfg, sleep=time.sleep):
    """-> {status, headers{lower: value}, body (<= 64 KiB, GET only), attempts, error}; retries 5xx/429/network."""
    attempts = []
    retries = max(1, int(cfg["retries"]))
    out = {"status": 0, "headers": {}, "body": "", "error": ""}
    for i in range(retries):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": UA, **headers})
        wait = float(cfg["backoff_seconds"]) * (2**i)
        try:
            with urllib.request.urlopen(req, timeout=float(cfg["http_timeout"])) as r:
                out = {"status": r.status, "headers": {k.lower(): v for k, v in r.headers.items()},
                       "body": r.read(65536).decode("utf-8", "replace") if method == "GET" else "", "error": ""}
        except urllib.error.HTTPError as e:
            out = {"status": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                   "body": "", "error": f"HTTP {e.code}"}
            if e.code == 429:
                ra = out["headers"].get("retry-after", "")
                if ra.isdigit():
                    wait = min(30.0, float(ra))
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            out = {"status": 0, "headers": {}, "body": "", "error": f"{type(e).__name__}: {reason}"}
        attempts.append(out["status"])
        retry = out["status"] == 0 or out["status"] == 429 or out["status"] >= 500
        if not retry or i == retries - 1:
            break
        sleep(wait)
    out["attempts"] = attempts
    return out


def keep_headers(h):
    return {k: h[k] for k in ("date", "last-modified", "etag", "content-length", "retry-after",
                              "www-authenticate", "docker-content-digest", "content-type") if k in h}


def probe_feed(d, local, cfg, sleep=time.sleep):
    hdrs = {"Cache-Control": "no-cache"}
    if local.get("etag"):
        hdrs["If-None-Match"] = local["etag"]
    r = http("HEAD", d["url"], hdrs, cfg, sleep)
    up = {"status": r["status"], "headers": keep_headers(r["headers"]), "attempts": r["attempts"], "error": r["error"],
          "conditional": bool(local.get("etag"))}
    if d["content_url"]:
        c = http("GET", d["content_url"], {"Cache-Control": "no-cache"}, cfg, sleep)
        up["content"] = {"status": c["status"], "body": c["body"][:4096], "attempts": c["attempts"],
                         "error": c["error"], "headers": keep_headers(c["headers"])}
    return up


# ----------------------------------------------------------------------------------------------------------------
# release watch (read-only: docker inspect / image inspect, registry HEAD, foundation server_info, upgradewatch file)


def docker_json(cfg, *args):
    p = subprocess.run([cfg["docker"], *args], capture_output=True, text=True, timeout=30, check=False)
    if p.returncode != 0:
        raise RuntimeError(f"docker {args[0]} rc {p.returncode}: {p.stderr.strip()[:160]}")
    return json.loads(p.stdout)


def parse_ref(ref):
    """'agtipft/postfiatd:tag' -> (registry, repo, tag); docker hub defaults; digests refused."""
    if "@" in ref:
        raise ValueError("image is pinned by digest; nothing to watch")
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "registry-1.docker.io", ref
    tag = "latest"
    if ":" in path.rsplit("/", 1)[-1]:
        path, tag = path.rsplit(":", 1)
    if registry == "registry-1.docker.io" and "/" not in path:
        path = "library/" + path
    return registry, path, tag or "latest"


def parse_bearer(h):
    if not h.lower().startswith("bearer "):
        return {}
    return dict(re.findall(r'(\w+)="([^"]*)"', h[7:]))


def registry_digest(base, repo, tag, cfg, sleep=time.sleep):
    url = f"{base}/v2/{repo}/manifests/{tag}"
    obs = {"url": url, "steps": []}
    r = http("HEAD", url, {"Accept": MANIFEST_ACCEPT}, cfg, sleep)
    obs["steps"].append({"what": "manifest", "status": r["status"], "attempts": r["attempts"], "error": r["error"],
                         "headers": keep_headers(r["headers"])})
    if r["status"] == 401:
        ch = parse_bearer(r["headers"].get("www-authenticate", ""))
        realm = ch.get("realm", "")
        if not realm.startswith(("https://", "http://127.0.0.1")):
            obs["steps"].append({"what": "token", "status": 0, "attempts": [], "error": "no usable Bearer realm",
                                 "headers": {}})
            return obs
        q = urllib.parse.urlencode({k: ch[k] for k in ("service", "scope") if k in ch})
        t = http("GET", f"{realm}?{q}", {}, cfg, sleep)
        tok = ""
        try:
            tok = json.loads(t["body"]).get("token", "") if t["status"] == 200 else ""
        except ValueError:
            pass
        obs["steps"].append({"what": "token", "status": t["status"], "attempts": t["attempts"],
                             "error": t["error"] or ("" if tok else "no token in answer"), "headers": {}})
        if not tok:
            return obs
        r = http("HEAD", url, {"Accept": MANIFEST_ACCEPT, "Authorization": f"Bearer {tok}"}, cfg, sleep)
        obs["steps"].append({"what": "manifest", "status": r["status"], "attempts": r["attempts"],
                             "error": r["error"], "headers": keep_headers(r["headers"])})
    return obs


def foundation_version(cfg, sleep=time.sleep):
    req_body = json.dumps({"method": "server_info", "params": [{}]}).encode()
    attempts = []
    for i in range(max(1, int(cfg["retries"]))):
        req = urllib.request.Request(cfg["foundation_rpc"], data=req_body, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=float(cfg["http_timeout"])) as r:
                v = json.loads(r.read(1 << 20))["result"]["info"]["build_version"]
                attempts.append(r.status)
                return {"version": str(v), "attempts": attempts, "error": ""}
        except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as e:
            attempts.append(getattr(e, "code", 0))
            err = f"{type(e).__name__}: {getattr(e, 'reason', e)}"
        if i < int(cfg["retries"]) - 1:
            sleep(float(cfg["backoff_seconds"]) * (2**i))
    return {"version": "", "attempts": attempts, "error": err}


def running_build(cfg):
    """this node's build_version from ../upgradewatch's textfile (file read, no exec), with the file's mtime."""
    p = cfg["build_textfile"]
    try:
        st = os.stat(p)
        with open(p, encoding="utf-8") as f:
            for line in f:
                m = re.match(r'pft_upgradewatch_build_info\{[^}]*version="([^"]+)"[^}]*\} 1$', line.strip())
                if m:
                    return {"version": m.group(1), "mtime": int(st.st_mtime), "error": ""}
        return {"version": "", "mtime": int(st.st_mtime), "error": "no pft_upgradewatch_build_info sample"}
    except OSError as e:
        return {"version": "", "mtime": 0, "error": f"{type(e).__name__}: {e}"}


def collect_release(cfg, sleep=time.sleep):
    rel = {"container": cfg["container"], "error": ""}
    try:
        c = docker_json(cfg, "inspect", "--type", "container", cfg["container"])[0]
        rel["ref"] = c["Config"]["Image"]
        rel["image_id"] = c["Image"]
        img = docker_json(cfg, "image", "inspect", c["Image"])[0]
        rel["repo_digests"] = sorted(img.get("RepoDigests") or [])
        registry, repo, tag = parse_ref(rel["ref"])
        rel.update({"registry": registry, "repo": repo, "tag": tag})
        base = cfg["registry_url"] or f"https://{registry}"
        rel["registry_obs"] = registry_digest(base.rstrip("/"), repo, tag, cfg, sleep)
    except (RuntimeError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError, OSError) as e:
        rel["error"] = f"{type(e).__name__}: {e}"
    rel["foundation"] = foundation_version(cfg, sleep)
    rel["running_build"] = running_build(cfg)
    return rel


def collect(cfg, now=None, sleep=time.sleep):
    obs = {"schema": SCHEMA, "host": cfg["host"], "collected_epoch": int(now if now is not None else time.time()),
           "config": {k: cfg[k] for k in sorted(DEFAULTS) if k != "docker"}, "feeds": []}
    for name in cfg["feeds"].split():
        try:
            d = feed_def(name, cfg)
        except ValueError as e:
            obs["feeds"].append({"name": name, "error": str(e)})
            continue
        if d["local"] == "vulnscan":
            local = local_vulnscan(cfg["vulnscan_cache"], d["kind"])
        elif d["local"] == "imagescan":
            local = local_imagescan(cfg["imagescan_cache"], name, d["kind"])
        else:
            local = {"source": "", "error": ""}
        obs["feeds"].append({"name": name, **d, "local_obs": local, "upstream": probe_feed(d, local, cfg, sleep)})
    obs["release"] = collect_release(cfg, sleep)
    obs["finished_epoch"] = int(time.time()) if now is None else obs["collected_epoch"]
    return obs


# ----------------------------------------------------------------------------------------------------------------
# evaluation (pure)


def http_epoch(v):
    try:
        dt = parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None or dt.tzinfo is None:
        return None
    return int(dt.timestamp())


def go_modified(body):
    try:
        v = json.loads(body)["modified"]
        return int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp())
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def hours(s):
    return f"{s / 3600:.1f} h"


def evaluate_feed(f, now, cfg):
    """-> dict with state, reason and the clocks behind it."""
    r = {"name": f["name"], "kind": f.get("kind", ""), "url": f.get("url", ""), "state": "unreachable",
         "reason": "", "fetch_age": None, "content_age": None, "upstream_age": None, "upstream_newer": None,
         "skew": None, "attempts": 0, "local": f.get("local", "")}
    if f.get("error"):
        r["reason"] = f["error"]
        return r
    tol, quiet = int(cfg["content_tolerance_seconds"]), int(cfg["quiet_age_hours"]) * 3600
    up, loc = f["upstream"], f["local_obs"]
    r["attempts"] = len(up.get("attempts", [])) + len(up.get("content", {}).get("attempts", []))
    # upstream clocks: ages are measured on upstream's own Date header, so a skewed local clock cannot shift them
    up_date = http_epoch(up["headers"].get("date", ""))
    up_lm = http_epoch(up["headers"].get("last-modified", ""))
    reachable = up["status"] in (200, 304) and up_date is not None
    bad = ""
    if reachable:
        r["skew"] = now - up_date
        if up["status"] == 200 and up_lm is None:
            bad = "upstream answered without a usable Last-Modified"
        elif up_lm is not None and up_lm > up_date + int(cfg["skew_max_seconds"]):
            bad = "upstream Last-Modified lies in the future of its own Date header"
    up_content = up_lm
    if reachable and not bad and f.get("content_url"):
        c = up.get("content", {})
        up_content = go_modified(c.get("body", "")) if c.get("status") == 200 else None
        if up_content is None:
            bad = f"content clock {f['content_url']} unusable ({c.get('error') or 'no modified field'})"
    clock = up_date if up_date is not None else now
    if f["local"]:
        if loc.get("error"):
            r["state"], r["reason"] = "local_stale", f"local copy unusable: {loc['error']}"
            return r
        last_ok = max(loc["fetched_epoch"], loc.get("checked_epoch", 0))
        r["fetch_age"] = now - last_ok
        r["content_age"] = clock - loc["content_epoch"]
        if r["fetch_age"] > int(cfg["fetch_max_age_hours"]) * 3600:
            r["state"] = "fetch_failing"
            r["reason"] = (f"{loc['source']} has not downloaded or revalidated this feed for {hours(r['fetch_age'])} "
                           f"(> {cfg['fetch_max_age_hours']} h)")
            return r
    if not reachable or bad:
        why = bad or up.get("error") or f"HTTP {up['status']}"
        r["state"], r["reason"] = "unreachable", f"upstream not usable: {why} (attempts {up.get('attempts')})"
        return r
    if up_lm is not None:
        r["upstream_age"] = up_date - up_lm
    if not f["local"]:  # reference feed: upstream clock only
        age = up_date - up_content
        r["content_age"] = age
        if age > quiet:
            r["state"], r["reason"] = "upstream_quiet", f"upstream last published {hours(age)} ago (no local copy)"
        else:
            r["state"], r["reason"] = "ok", f"upstream last published {hours(age)} ago (no local copy)"
        return r
    # a 304 / equal ETag proves "latest" only if its Last-Modified (when sent) is not newer than our copy: a content
    # cache can revalidate an old copy against our old ETag (the ../vulnscan 304stale case)
    lm_newer = up_content is not None and up_content - loc["content_epoch"] > tol
    if up["status"] == 304 and not lm_newer:
        latest, how = True, "upstream answered 304 to our ETag"
    elif loc.get("etag") and up["headers"].get("etag") == loc["etag"] and not lm_newer:
        latest, how = True, "upstream ETag equals ours"
    else:
        newer = up_content - loc["content_epoch"]
        r["upstream_newer"] = newer
        latest = newer <= tol
        how = (f"upstream content clock is {hours(max(newer, 0))} after ours (tolerance {hours(tol)})"
               if latest else f"upstream content is {hours(newer)} newer than ours")
    if not latest:
        missed = up_date - up_content
        if missed > int(cfg["stale_grace_hours"]) * 3600:
            r["state"] = "local_stale"
            r["reason"] = f"{how}; upstream published it {hours(missed)} ago (> grace {cfg['stale_grace_hours']} h)"
        else:
            r["state"] = "ok"
            r["reason"] = f"{how}; published {hours(missed)} ago, within grace {cfg['stale_grace_hours']} h"
        return r
    if r["content_age"] > quiet:
        r["state"] = "upstream_quiet"
        r["reason"] = f"local copy is upstream's latest ({how}); upstream has not published for {hours(r['content_age'])}"
    else:
        r["state"] = "ok"
        r["reason"] = f"local copy is upstream's latest ({how}); content {hours(r['content_age'])} old"
    return r


def version_tuple(v):
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else None


def evaluate_release(rel, now, cfg):
    out = {"container": rel.get("container", ""), "ref": rel.get("ref", ""), "image_id": rel.get("image_id", ""),
           "running_digest": "", "registry_digest": "", "digest_state": "unknown", "digest_reason": "",
           "running_version": "", "foundation_version": "", "version_state": "unknown", "version_reason": "",
           "state": "unknown"}
    if rel.get("error"):
        out["digest_reason"] = rel["error"]
    else:
        prefix = rel["repo"].removeprefix("library/") if rel["registry"] == "registry-1.docker.io" else (
            f"{rel['registry']}/{rel['repo']}")
        mine = [d.split("@", 1)[1] for d in rel["repo_digests"] if d.split("@", 1)[0] in (prefix, rel["repo"])]
        out["running_digest"] = mine[0] if len(mine) == 1 else ""
        last = rel["registry_obs"]["steps"][-1]
        reg = last["headers"].get("docker-content-digest", "") if last["what"] == "manifest" else ""
        if last["what"] == "manifest" and last["status"] == 200 and DIGEST_RE.match(reg):
            out["registry_digest"] = reg
        if not out["running_digest"]:
            out["digest_reason"] = f"{len(mine)} repo digests for {prefix} on the running image (need exactly 1)"
        elif not out["registry_digest"]:
            st = [f"{s['what']} {s['status'] or s['error']}" for s in rel["registry_obs"]["steps"]]
            out["digest_reason"] = "registry digest not read: " + ", ".join(st)
        elif out["registry_digest"] == out["running_digest"]:
            out["digest_state"], out["digest_reason"] = "current", f"{rel['tag']} digest equals the running image's"
        else:
            out["digest_state"], out["digest_reason"] = "behind", f"{rel['tag']} now points at a different manifest"
    rb, fd = rel.get("running_build", {}), rel.get("foundation", {})
    out["running_version"], out["foundation_version"] = rb.get("version", ""), fd.get("version", "")
    rv, fv = version_tuple(out["running_version"]), version_tuple(out["foundation_version"])
    if rb.get("error") or rv is None:
        out["version_reason"] = f"running build unknown: {rb.get('error') or 'unparsable'}"
    elif now - rb.get("mtime", 0) > int(cfg["build_max_age_seconds"]):
        out["version_reason"] = f"running build file is {hours(now - rb['mtime'])} old"
    elif fd.get("error") or fv is None:
        out["version_reason"] = f"foundation build_version unknown: {fd.get('error') or 'unparsable'}"
    elif fv > rv:
        out["version_state"] = "behind"
        out["version_reason"] = f"foundation runs {out['foundation_version']}, this node {out['running_version']}"
    else:
        out["version_state"] = "current"
        out["version_reason"] = f"this node {out['running_version']} >= foundation {out['foundation_version']}"
    states = {out["digest_state"], out["version_state"]}
    out["state"] = "behind" if "behind" in states else ("current" if states == {"current"} else "unknown")
    return out


def evaluate(obs):
    if obs.get("schema") != SCHEMA:
        raise ValueError(f"not an {SCHEMA} observation file")
    cfg = {**DEFAULTS, **obs["config"]}
    now = obs["collected_epoch"]
    feeds = [evaluate_feed(f, now, cfg) for f in obs["feeds"]]
    return {"schema": SCHEMA, "host": obs["host"], "generated_epoch": now, "feeds": feeds,
            "release": evaluate_release(obs["release"], now, cfg),
            "counts": {s: sum(1 for f in feeds if f["state"] == s) for s in STATES}}


# ----------------------------------------------------------------------------------------------------------------
# rendering


def iso(e):
    return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_text(res):
    L = [f"pft-upstreamwatch - host {res['host']} - {iso(res['generated_epoch'])}", "",
         f"{'FEED':<22} {'STATE':<15} {'FETCH AGE':>10} {'CONTENT AGE':>12}  REASON"]
    for f in res["feeds"]:
        fa = hours(f["fetch_age"]) if f["fetch_age"] is not None else "-"
        ca = hours(f["content_age"]) if f["content_age"] is not None else "-"
        L.append(f"{f['name']:<22} {f['state']:<15} {fa:>10} {ca:>12}  {f['reason']}")
    rel = res["release"]
    L += ["", f"release ({rel['container']}, {rel['ref'] or '?'}): {rel['state']}",
          f"  digest  {rel['digest_state']:<8} running {rel['running_digest'] or '?'}",
          f"                   registry {rel['registry_digest'] or '?'}  ({rel['digest_reason']})",
          f"  version {rel['version_state']:<8} ({rel['version_reason']})", ""]
    c = res["counts"]
    paged = c["local_stale"] + c["fetch_failing"]
    L.append("RESULT: " + " ".join(f"{s}={c[s]}" for s in STATES) + f" release={rel['state']}"
             + (" -> PAGE (local_stale/fetch_failing)" if paged else ""))
    return "\n".join(L) + "\n"


def label(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render_prom(res):
    h = f'host="{label(res["host"])}"'
    L = [
        "# HELP pft_upstreamwatch_up 1 if the last pft-upstreamwatch run completed",
        "# TYPE pft_upstreamwatch_up gauge",
        f"pft_upstreamwatch_up{{{h}}} 1",
        "# HELP pft_upstreamwatch_last_run_timestamp_seconds when the observations were collected",
        "# TYPE pft_upstreamwatch_last_run_timestamp_seconds gauge",
        f"pft_upstreamwatch_last_run_timestamp_seconds{{{h}}} {res['generated_epoch']}",
        ("# HELP pft_upstreamwatch_feed_state 1 for the feed's current state (ok upstream_quiet local_stale "
         "fetch_failing unreachable)"),
        "# TYPE pft_upstreamwatch_feed_state gauge",
    ]
    for f in res["feeds"]:
        for s in STATES:
            L.append(f'pft_upstreamwatch_feed_state{{{h},feed="{label(f["name"])}",state="{s}"}} '
                     f'{1 if f["state"] == s else 0}')
    for metric, key, help_ in (
        ("feed_fetch_age_seconds", "fetch_age", "seconds since the local fetcher last downloaded/revalidated"),
        ("feed_content_age_seconds", "content_age", "age of the newest content we hold (upstream Date clock)"),
        ("feed_upstream_age_seconds", "upstream_age", "upstream Date minus upstream Last-Modified"),
        ("feed_upstream_newer_seconds", "upstream_newer", "upstream content clock minus ours"),
        ("feed_clock_skew_seconds", "skew", "local clock minus upstream Date header"),
        ("feed_probe_attempts", "attempts", "HTTP attempts this run (HEAD + content GET, retries included)"),
    ):
        L += [f"# HELP pft_upstreamwatch_{metric} {help_}", f"# TYPE pft_upstreamwatch_{metric} gauge"]
        for f in res["feeds"]:
            if f[key] is not None:
                L.append(f'pft_upstreamwatch_{metric}{{{h},feed="{label(f["name"])}"}} {f[key]}')
    rel = res["release"]
    c = f'{h},container="{label(rel["container"])}"'
    L += ["# HELP pft_upstreamwatch_release_state 1 for the release watch state (current behind unknown)",
          "# TYPE pft_upstreamwatch_release_state gauge"]
    L += [f'pft_upstreamwatch_release_state{{{c},state="{s}"}} {1 if rel["state"] == s else 0}'
          for s in RELEASE_STATES]
    L += [("# HELP pft_upstreamwatch_release_check 1 for each check's state (digest: registry tag vs running image; "
           "version: foundation build_version vs this node)"), "# TYPE pft_upstreamwatch_release_check gauge"]
    for chk in ("digest", "version"):
        L += [f'pft_upstreamwatch_release_check{{{c},check="{chk}",state="{s}"}} '
              f'{1 if rel[chk + "_state"] == s else 0}' for s in RELEASE_STATES]
    L += ["# HELP pft_upstreamwatch_release_info running and foundation build_version",
          "# TYPE pft_upstreamwatch_release_info gauge",
          (f'pft_upstreamwatch_release_info{{{c},running="{label(rel["running_version"])}",'
           f'foundation="{label(rel["foundation_version"])}"}} 1')]
    return "\n".join(L) + "\n"


def render(obs, fmt):
    res = evaluate(obs)
    if fmt == "json":
        return json.dumps(res, indent=2, sort_keys=True) + "\n"
    if fmt == "prom":
        return render_prom(res)
    return render_text(res)


def prom_down(host, now):
    h = f'host="{label(host)}"'
    return (f"# HELP pft_upstreamwatch_up 1 if the last pft-upstreamwatch run completed\n"
            f"# TYPE pft_upstreamwatch_up gauge\npft_upstreamwatch_up{{{h}}} 0\n"
            f"# HELP pft_upstreamwatch_last_run_timestamp_seconds when the observations were collected\n"
            f"# TYPE pft_upstreamwatch_last_run_timestamp_seconds gauge\n"
            f"pft_upstreamwatch_last_run_timestamp_seconds{{{h}}} {now}\n")


# ----------------------------------------------------------------------------------------------------------------
# textfile validation


def validate(path, host):
    want = f'host="{host}"'
    up = ts = False
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    if not lines:
        return "empty file"
    for n, line in enumerate(lines, 1):
        if line.startswith("#"):
            continue
        m = re.fullmatch(r"(pft_upstreamwatch_[a-z_]+)\{([^{}]*)\} (-?[0-9]+(?:\.[0-9]+)?)", line)
        if not m:
            return f"line {n}: malformed sample"
        if not m.group(2).startswith(want):
            return f"line {n}: first label is not {want}"
        up |= m.group(1) == "pft_upstreamwatch_up"
        ts |= m.group(1) == "pft_upstreamwatch_last_run_timestamp_seconds"
    if not up:
        return "no pft_upstreamwatch_up sample"
    if not ts:
        return "no pft_upstreamwatch_last_run_timestamp_seconds sample"
    return ""


# ----------------------------------------------------------------------------------------------------------------


def load_cfg(path):
    cfg = dict(DEFAULTS)
    if path:
        with open(path, encoding="utf-8") as f:
            given = json.load(f)
        unknown = set(given) - set(DEFAULTS)
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        cfg.update(given)
    for k in ("quiet_age_hours", "stale_grace_hours", "fetch_max_age_hours", "content_tolerance_seconds",
              "skew_max_seconds", "retries", "http_timeout", "build_max_age_seconds"):
        cfg[k] = int(cfg[k])
        if cfg[k] < (1 if k != "skew_max_seconds" else 0):
            raise ValueError(f"{k} must be positive")
    cfg["backoff_seconds"] = float(cfg["backoff_seconds"])
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(prog="upstreamwatch_lib.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--config", default="")
    c.add_argument("--out", required=True)
    c.add_argument("--now", type=int)
    r = sub.add_parser("render")
    r.add_argument("--obs", required=True)
    r.add_argument("--format", choices=("text", "json", "prom"), default="text")
    d = sub.add_parser("down")
    d.add_argument("host")
    d.add_argument("--now", type=int, required=True)
    v = sub.add_parser("validate")
    v.add_argument("file")
    v.add_argument("host")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "collect":
            obs = collect(load_cfg(a.config), now=a.now)
            tmp = a.out + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(obs, f, indent=1, sort_keys=True)
                f.write("\n")
            os.replace(tmp, a.out)
            return 0
        if a.cmd == "render":
            with open(a.obs, encoding="utf-8") as f:
                sys.stdout.write(render(json.load(f), a.format))
            return 0
        if a.cmd == "down":
            sys.stdout.write(prom_down(a.host, a.now))
            return 0
        why = validate(a.file, a.host)
        if why:
            print(why)
            return 2
        return 0
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"upstreamwatch_lib: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

