#!/usr/bin/env python3
"""imagescan_lib: offline vulnerability + provenance audit of Docker IMAGES (stdlib only).

Subcommands (all print JSON on stdout; errors: one line on stderr, exit 2):
  extract --ref REF --image-id ID [--inspect FILE] < `docker image save` tar stream
        Reads the image's layers in order (whiteouts and opaque dirs applied) WITHOUT running the image:
        os-release, dpkg status (+ status.d), apk installed db, and every executable ELF file that carries Go build
        info (Go version, main module, deps, build settings, sha256). Output = one inventory object.
  scan --inventory FILE... --feeds DIR --now EPOCH [--max-age-days N]
        Matches inventories against the pinned offline feeds in DIR (feeds.json lists file, sha256, kind, feed
        timestamp). Refuses (exit 2) a feed whose sha256 differs from feeds.json, a feed older than N days by its own
        timestamp, an inventory whose OS has no feed (unless the OS is listed as unscanned-by-design), and any
        version that cannot be compared.
  render --scan FILE [--public]           text report; --public drops package/CVE detail for findings in images
                                          marked private (unremediated upstream images), keeping only counts and
                                          the sha256 commitment of the private findings list.
  metrics --scan FILE --host LABEL [--prev FILE]   Prometheus textfile body.
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

GO_MAGIC = b"\xff Go buildinf:"
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unrated")
MIN_EXEC_SIZE = 256 * 1024          # smaller ELF files cannot be Go binaries with build info
TRAILER = 1 << 20                   # bytes kept after the Go magic (version + modinfo are inline since Go 1.18)


class Bad(Exception):
    pass


def die(msg):
    print(f"imagescan: {msg}", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------- versions
def _dpkg_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_cmp_part(a, b):
    while a or b:
        na = re.match(r"^[^0-9]*", a).group(0)
        nb = re.match(r"^[^0-9]*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        for i in range(max(len(na), len(nb))):
            ca = _dpkg_order(na[i]) if i < len(na) else 0
            cb = _dpkg_order(nb[i]) if i < len(nb) else 0
            if ca != cb:
                return -1 if ca < cb else 1
        da = re.match(r"^[0-9]*", a).group(0)
        db = re.match(r"^[0-9]*", b).group(0)
        a, b = a[len(da):], b[len(db):]
        ia, ib = int(da or 0), int(db or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


DPKG_RE = re.compile(r"^(?:(\d+):)?([0-9][A-Za-z0-9.+~:-]*?)(?:-([A-Za-z0-9.+~]+))?$")


def dpkg_split(v):
    m = DPKG_RE.match(v.strip())
    if not m:
        raise Bad(f"not a Debian version: {v!r}")
    return int(m.group(1) or 0), m.group(2), m.group(3) or ""


def dpkg_cmp(a, b):
    """Debian policy 5.6.12 version comparison: -1, 0, 1."""
    ea, ua, ra = dpkg_split(a)
    eb, ub, rb = dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_cmp_part(ua, ub) or _dpkg_cmp_part(ra, rb)


SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def semver_key(v):
    m = SEMVER_RE.match(v)
    if not m:
        raise Bad(f"not a semantic version: {v!r}")
    pre = m.group(4)
    # a release sorts after every prerelease of the same version; prerelease identifiers: numeric < alphanumeric
    prek = (1,) if pre is None else (0,) + tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) + (prek,)


def go_to_semver(gov):
    """go1.24.4 -> v1.24.4, go1.22 -> v1.22.0, go1.21rc2 -> v1.21.0-rc.2 (vuln.go.dev convention)."""
    m = re.match(r"^go(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta)(\d+))?", gov)
    if not m:
        raise Bad(f"not a Go version: {gov!r}")
    s = f"v{m.group(1)}.{m.group(2)}.{m.group(3) or 0}"
    if m.group(4):
        s += f"-{m.group(4)}.{m.group(5)}"
    return s


# ---------------------------------------------------------------- extract
def _norm(name):
    name = name.lstrip("./") if name.startswith("./") else name.lstrip("/")
    return os.path.normpath(name) if name else ""


WANTED = ("etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed")


def _wanted(path):
    return path in WANTED or path.startswith("var/lib/dpkg/status.d/")


def go_buildinfo(buf):
    """Parse inline Go build info (Go >= 1.18) starting at GO_MAGIC. -> (goversion, modinfo) or raises Bad."""
    if len(buf) < 32 or not buf.startswith(GO_MAGIC):
        raise Bad("truncated Go build info header")
    flags = buf[15]
    if not flags & 0x2:
        raise Bad("pre-Go-1.18 build info (pointer format) not supported")
    pos = 32
    out = []
    for _ in range(2):
        n, shift = 0, 0
        while True:
            if pos >= len(buf):
                raise Bad("truncated Go build info varint")
            b = buf[pos]
            pos += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        if pos + n > len(buf):
            raise Bad("truncated Go build info string")
        out.append(buf[pos:pos + n].decode("utf-8", "replace"))
        pos += n
    ver, mod = out
    if len(mod) >= 33 and mod[-17] == "\n":
        mod = mod[16:-16]
    return ver, mod


def parse_modinfo(mod):
    info = {"path": "", "main": None, "deps": [], "settings": {}}
    last = None
    for line in mod.splitlines():
        parts = line.split("\t")
        if parts[0] == "path" and len(parts) > 1:
            info["path"] = parts[1]
        elif parts[0] == "mod" and len(parts) > 2:
            info["main"] = {"path": parts[1], "version": parts[2]}
        elif parts[0] == "dep" and len(parts) > 2:
            last = {"path": parts[1], "version": parts[2]}
            info["deps"].append(last)
        elif parts[0] == "=>" and len(parts) > 2 and last is not None:
            last["replaced_by"] = {"path": parts[1], "version": parts[2]}
        elif parts[0] == "build" and len(parts) > 1 and "=" in parts[1]:
            k, v = parts[1].split("=", 1)
            info["settings"][k] = v
    return info


def scan_member(f, size):
    """Stream one layer file: sha256 + Go build info if present. -> dict or None (not ELF)."""
    h = hashlib.sha256()
    head = f.read(4)
    h.update(head)
    if head != b"\x7fELF":
        return None
    tail, found, total = b"", None, 4
    while True:
        chunk = f.read(1 << 20)
        if not chunk:
            break
        total += len(chunk)
        h.update(chunk)
        if found is not None:
            if len(found) < TRAILER:
                found += chunk[:TRAILER - len(found)]
            continue
        data = tail + chunk
        i = data.find(GO_MAGIC)
        if i >= 0:
            found = data[i:i + TRAILER]
        else:
            tail = data[-(len(GO_MAGIC) - 1):]
    if total != size:
        raise Bad(f"short read in layer member ({total} of {size} bytes)")
    res = {"sha256": h.hexdigest(), "size": size, "go": None}
    if found is not None:
        try:
            ver, mod = go_buildinfo(found)
            res["go"] = {"version": ver, **parse_modinfo(mod)}
        except Bad as e:
            res["go"] = {"error": str(e)}
    return res


def read_layer(fobj):
    """-> {'entries': {path: entry}, 'whiteouts': set, 'opaque': set}; entry: ('file', bytes|dict) | ('link', tgt)."""
    entries, whiteouts, opaque = {}, set(), set()
    # tarfile's "r|*" autodetection misreads a gzip layer nested in a stream; pick the mode from the magic bytes
    head = fobj.peek(6)[:6] if hasattr(fobj, "peek") else b""
    if head[:4] == b"\x28\xb5\x2f\xfd":
        raise Bad("zstd-compressed layer: not readable with the Python stdlib")
    mode = "r|gz" if head[:2] == b"\x1f\x8b" else "r|bz2" if head[:3] == b"BZh" else "r|xz" if head[:6] == b"\xfd7zXZ\x00" else "r|"
    with tarfile.open(fileobj=fobj, mode=mode) as lt:
        for m in lt:
            p = _norm(m.name)
            if not p or p == ".":
                continue
            base, d = os.path.basename(p), os.path.dirname(p)
            if base == ".wh..wh..opq":
                opaque.add(d)
                continue
            if base.startswith(".wh."):
                whiteouts.add(os.path.join(d, base[4:]))
                continue
            if m.issym():
                entries[p] = ("link", m.linkname)
            elif m.islnk():
                entries[p] = ("hard", _norm(m.linkname))
            elif m.isreg():
                if _wanted(p):
                    entries[p] = ("file", lt.extractfile(m).read())
                elif m.mode & 0o111 and m.size >= MIN_EXEC_SIZE:
                    r = scan_member(lt.extractfile(m), m.size)
                    entries[p] = ("exec", r) if r else ("other", None)
                else:
                    entries[p] = ("other", None)
            elif m.isdir():
                entries[p] = ("dir", None)
    return {"entries": entries, "whiteouts": whiteouts, "opaque": opaque}


EMPTY_LAYER = {"entries": {}, "whiteouts": set(), "opaque": set()}


def _empty_layer(data):
    """The canonical empty layer (gzip of 1024 zero bytes, or a bare empty tar): tarfile rejects it."""
    import gzip
    try:
        raw = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
    except (OSError, EOFError):
        return False
    return len(raw) <= 10240 and not raw.strip(b"\0")


def read_save_stream(stream):
    """docker image save (OCI layout or legacy) -> (layers in order [layer dicts], config dict)."""
    blobs, manifest, index, oci_blobs = {}, None, None, {}
    with tarfile.open(fileobj=stream, mode="r|") as t:
        for m in t:
            p = _norm(m.name)
            if not m.isreg():
                continue
            f = t.extractfile(m)
            if p == "manifest.json":
                manifest = json.loads(f.read())
            elif p == "index.json":
                index = json.loads(f.read())
            elif m.size < 4 * 1024 * 1024 and (p.endswith(".json") or p.startswith("blobs/")):
                data = f.read()
                try:
                    oci_blobs[p] = json.loads(data)
                except ValueError:
                    blobs[p] = read_layer(io.BufferedReader(io.BytesIO(data))) if not _empty_layer(data) else EMPTY_LAYER
            elif p.startswith("blobs/") or p.endswith("/layer.tar"):
                # large non-layer blobs exist (in-toto/SBOM attestations, 15 MB in rust:1.95.0-bookworm): only
                # compressed streams and ustar archives are layers; a layer we skip wrongly fails the manifest check
                head = f.peek(512)[:512]
                if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00" \
                        or head[:4] == b"\x28\xb5\x2f\xfd" or head[257:262] == b"ustar":
                    blobs[p] = read_layer(f)
    del index
    if not manifest or len(manifest) != 1:
        raise Bad("save stream has no single-image manifest.json")
    man = manifest[0]
    layers = []
    for lp in man.get("Layers", []):
        lp = _norm(lp)
        if lp not in blobs:
            raise Bad(f"layer {lp} listed in manifest.json but not readable from the stream")
        layers.append(blobs[lp])
    cfg = oci_blobs.get(_norm(man.get("Config", "")), {})
    return layers, cfg


def _ancestors(path):
    d = os.path.dirname(path)
    while d:
        yield d
        d = os.path.dirname(d)


def merged(layers):
    """Visible view: path -> entry from the highest layer, honouring later whiteouts/opaque dirs."""
    view = {}
    for i, L in enumerate(layers):
        for p in list(view):
            if p in L["whiteouts"] or any(a in L["whiteouts"] or a in L["opaque"] for a in _ancestors(p)):
                del view[p]
        for p, e in L["entries"].items():
            view[p] = e
    return view


def resolve(view, path, depth=0):
    e = view.get(path)
    if e is None or depth > 16:
        return None
    if e[0] == "link":
        tgt = e[1]
        tgt = _norm(tgt) if tgt.startswith("/") else os.path.normpath(os.path.join(os.path.dirname(path), tgt))
        return resolve(view, tgt, depth + 1)
    if e[0] == "hard":
        return resolve(view, e[1], depth + 1)
    return e


def parse_os_release(data):
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def parse_dpkg_status(data):
    pkgs = []
    for para in data.decode("utf-8", "replace").split("\n\n"):
        f = {}
        for line in para.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            k, v = line.split(":", 1)
            f[k] = v.strip()
        if not f.get("Package") or "installed" not in f.get("Status", "").split():
            continue
        if f.get("Status", "").split()[-1] != "installed":
            continue
        src, srcver = f.get("Source", f["Package"]), f.get("Version", "")
        m = re.match(r"^(\S+)\s+\((.+)\)$", src)
        if m:
            src, srcver = m.group(1), m.group(2)
        pkgs.append({"name": f["Package"], "arch": f.get("Architecture", ""), "version": f.get("Version", ""),
                     "source": src, "source_version": srcver})
    return sorted(pkgs, key=lambda p: (p["name"], p["arch"]))


def parse_apk(data):
    pkgs, cur = [], {}
    for line in data.decode("utf-8", "replace").splitlines() + [""]:
        if not line:
            if cur.get("P"):
                pkgs.append({"name": cur["P"], "version": cur.get("V", ""), "origin": cur.get("o", cur["P"])})
            cur = {}
        elif len(line) > 2 and line[1] == ":":
            cur[line[0]] = line[2:]
    return sorted(pkgs, key=lambda p: p["name"])


def build_inventory(layers, cfg, ref, image_id, inspect):
    view = merged(layers)
    inv = {"ref": ref, "image_id": image_id, "layers": len(layers), "os": {}, "dpkg": [], "apk": [],
           "go_binaries": [], "elf_without_go": 0, "provenance": {}}
    osr = resolve(view, "etc/os-release") or resolve(view, "usr/lib/os-release")
    if osr and osr[0] == "file":
        o = parse_os_release(osr[1])
        inv["os"] = {k: o.get(k, "") for k in ("ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME")}
    st = resolve(view, "var/lib/dpkg/status")
    pk = parse_dpkg_status(st[1]) if st and st[0] == "file" else []
    for p, e in sorted(view.items()):
        if p.startswith("var/lib/dpkg/status.d/") and e[0] == "file":
            pk += parse_dpkg_status(e[1])
    inv["dpkg"] = sorted(pk, key=lambda p: (p["name"], p["arch"]))
    apk = resolve(view, "lib/apk/db/installed")
    inv["apk"] = parse_apk(apk[1]) if apk and apk[0] == "file" else []
    for p, e in sorted(view.items()):
        if e[0] != "exec":
            continue
        if e[1]["go"] is None:
            inv["elf_without_go"] += 1
            continue
        g = e[1]["go"]
        inv["go_binaries"].append({"path": "/" + p, "sha256": e[1]["sha256"], "size": e[1]["size"],
                                   "go_version": g.get("version", ""), "module_path": g.get("path", ""),
                                   "main": g.get("main"), "deps": g.get("deps", []), "settings": g.get("settings", {}),
                                   "error": g.get("error", "")})
    c = cfg.get("config", {}) if isinstance(cfg, dict) else {}
    labels = c.get("Labels") or {}
    insp = inspect or {}
    inv["provenance"] = {
        "repo_digests": sorted(insp.get("RepoDigests") or []),
        "created": cfg.get("created", insp.get("Created", "")) if isinstance(cfg, dict) else "",
        "source": labels.get("org.opencontainers.image.source", ""),
        "revision": labels.get("org.opencontainers.image.revision", ""),
        "version_label": labels.get("org.opencontainers.image.version", ""),
        "diff_ids": (cfg.get("rootfs") or {}).get("diff_ids", []) if isinstance(cfg, dict) else [],
    }
    return inv


# ---------------------------------------------------------------- feeds
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_feeds(fdir, now, max_age_days, max_content_age_days=30):
    try:
        with open(os.path.join(fdir, "feeds.json")) as f:
            meta = json.load(f)
    except (OSError, ValueError) as e:
        raise Bad(f"feeds.json unreadable: {e}")
    feeds = {}
    for name, m in sorted(meta.get("feeds", {}).items()):
        path = os.path.join(fdir, m["file"])
        try:
            got = sha256_file(path)
        except OSError as e:
            raise Bad(f"feed {name}: {e}")
        if got != m["sha256"]:
            raise Bad(f"feed {name}: sha256 {got} != pinned {m['sha256']} (feed changed behind our back)")
        ts, fetched = m.get("timestamp_epoch"), m.get("fetched_epoch")
        if not isinstance(ts, int) or not isinstance(fetched, int):
            raise Bad(f"feed {name}: no feed timestamp / fetch time in feeds.json")
        # two clocks: when we last downloaded it from the origin (a cache-busted GET is the origin's current copy),
        # and the feed's own content timestamp, which only moves when the publisher changes an entry (vuln.go.dev
        # went 11 days without a change in 2026-11). A mirror serving an ancient file trips the second.
        # the scan clock is read before this run's fetch, so a feed fetched in the same run is a few seconds
        # after `now`: count that as 0 h (floor division made it "-1 h ago"); more than an hour ahead is a bad clock
        if fetched > now + 3600:
            raise Bad(f"feed {name}: fetch time is after the scan time (clock or feeds.json wrong)")
        age = max(0, now - fetched)
        if age > max_age_days * 86400:
            raise Bad(f"feed {name} is stale: fetched {age // 3600} h ago (> {max_age_days} d)")
        if now - ts > max_content_age_days * 86400:
            raise Bad(f"feed {name} is stale: own timestamp {(now - ts) // 86400} d old (> {max_content_age_days} d)")
        if ts > fetched + 3600:
            raise Bad(f"feed {name}: own timestamp is after its fetch time (clock or feeds.json wrong)")
        feeds[name] = {**m, "path": path, "age_seconds": age}
    return feeds


OUTCOMES = ("fresh", "retried_fresh", "still_behind")
OUTCOME_KEYS = ("outcome", "upstream_epoch", "upstream_clock", "outcome_note", "outcome_epoch")
ENTRY_KEYS = ("kind", "file", "sha256", "timestamp_epoch", "fetched_epoch", "url")


def feed_merge(fdir, tmp, lines):
    """Merge fetch results (one JSON object per line) into fdir/feeds.json, atomically.

    action "replace": move tmp/<file> into fdir, then the whole entry is replaced. action "keep" (the download is
    older than the installed copy): file and entry stay; only the outcome fields change. A replace whose content
    timestamp is older than the installed entry is refused here as well (second guard behind the shell's)."""
    p = os.path.join(fdir, "feeds.json")
    try:
        with open(p) as f:
            meta = json.load(f)
    except (OSError, ValueError):
        meta = {"feeds": {}}
    meta.setdefault("feeds", {})
    for line in lines:
        if not line.strip():
            continue
        e = json.loads(line)
        if e["outcome"] not in OUTCOMES:
            raise Bad(f"feed {e['name']}: unknown outcome {e['outcome']}")
        old = meta["feeds"].get(e["name"])
        action = e["action"]
        if action == "replace" and old and int(e["timestamp_epoch"]) < int(old.get("timestamp_epoch", 0)):
            action = "keep"
            e["outcome"] = "still_behind"
            e["outcome_note"] += "; download older than the installed copy, installed copy kept"
        if action == "replace":
            os.replace(os.path.join(tmp, e["file"]), os.path.join(fdir, e["file"]))
            meta["feeds"][e["name"]] = {k: e[k] for k in ENTRY_KEYS + OUTCOME_KEYS}
        elif action == "keep" and old:
            old.update({k: e[k] for k in OUTCOME_KEYS})
        else:
            raise Bad(f"feed {e['name']}: action {action} without an installed copy")
    with open(p + ".tmp", "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
    os.replace(p + ".tmp", p)
    return meta


def fetch_metrics(meta, host):
    """Fetch-outcome series from feeds.json (entries written before outcomes existed have none)."""
    h = esc(host)
    feeds = sorted((k, v) for k, v in meta.get("feeds", {}).items() if v.get("outcome") in OUTCOMES)
    L = [("# HELP pft_imagescan_feed_fetch_outcome 1 for the last fetch's outcome per feed (fresh retried_fresh "
          "still_behind)."), "# TYPE pft_imagescan_feed_fetch_outcome gauge"]
    for k, v in feeds:
        L += [f'pft_imagescan_feed_fetch_outcome{{host="{h}",feed="{esc(k)}",outcome="{o}"}} '
              f'{1 if v["outcome"] == o else 0}' for o in OUTCOMES]
    L += [("# HELP pft_imagescan_feed_upstream_timestamp_seconds Upstream content clock seen by the last fetch "
           "(0 = unreadable)."), "# TYPE pft_imagescan_feed_upstream_timestamp_seconds gauge"]
    L += [f'pft_imagescan_feed_upstream_timestamp_seconds{{host="{h}",feed="{esc(k)}"}} {int(v["upstream_epoch"])}'
          for k, v in feeds]
    L += ["# HELP pft_imagescan_feed_outcome_timestamp_seconds When the last fetch outcome was recorded.",
          "# TYPE pft_imagescan_feed_outcome_timestamp_seconds gauge"]
    L += [f'pft_imagescan_feed_outcome_timestamp_seconds{{host="{h}",feed="{esc(k)}"}} {int(v["outcome_epoch"])}'
          for k, v in feeds]
    return "\n".join(L) + "\n"


def feed_timestamp(kind, path):
    """The feed's OWN timestamp (not the file mtime) as UTC epoch."""
    if kind == "ubuntu-oval":
        import bz2
        with bz2.open(path, "rb") as f:
            head = f.read(8192).decode("utf-8", "replace")
        m = re.search(r"<oval:timestamp>(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", head)
        if not m:
            raise Bad(f"{path}: no <oval:timestamp>")
        return int(datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    if kind == "go-osv":
        with zipfile.ZipFile(path) as z:
            db = json.loads(z.read("index/db.json"))
        return int(datetime.strptime(db["modified"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    if kind == "debian-tracker":
        # the tracker JSON carries no timestamp of its own; fetch records the HTTP Last-Modified in feeds.json
        raise Bad("debian-tracker timestamp comes from Last-Modified (recorded by fetch)")
    raise Bad(f"unknown feed kind {kind}")


# Ubuntu OCI OVAL: textfilecontent54 tests on a "manifest" file of "name version" lines
OD = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
IND = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#independent}"
POCKET_RE = re.compile(r"^(?P<src>\S+) source package in (?P<pocket>\S+),")


def load_ubuntu_oval(path):
    import bz2
    defs, tests, objs, states, vars_ = [], {}, {}, {}, {}
    with bz2.open(path, "rb") as f:
        for _, el in ET.iterparse(f, events=("end",)):
            t = el.tag
            if t == OD + "definition":
                md = el.find(OD + "metadata")
                title = md.findtext(OD + "title", "")
                sev = (md.findtext(f"{OD}advisory/{OD}severity", "") or "unrated").lower()
                cves = [r.get("ref_id") for r in md.findall(OD + "reference") if r.get("source") == "CVE"]
                usn = next((r.get("ref_id") for r in md.findall(OD + "reference") if r.get("source") == "USN"), title)
                defs.append({"id": el.get("id"), "usn": usn, "severity": sev, "cves": cves,
                             "criteria": _crit(el.find(OD + "criteria"))})
                el.clear()
            elif t == IND + "textfilecontent54_test":
                o, s = el.find(IND + "object"), el.find(IND + "state")
                tests[el.get("id")] = {"obj": o.get("object_ref") if o is not None else None,
                                       "state": s.get("state_ref") if s is not None else None,
                                       "check": el.get("check", "all"),
                                       "existence": el.get("check_existence", "at_least_one_exists")}
                el.clear()
            elif t == IND + "textfilecontent54_object":
                pat = el.find(IND + "pattern")
                if el.findtext(IND + "filename") != "manifest" or pat is None:
                    raise Bad(f"OVAL object {el.get('id')} is not a manifest pattern object")
                objs[el.get("id")] = pat.get("var_ref") or ("=" + (pat.text or ""))
                el.clear()
            elif t == IND + "textfilecontent54_state":
                sub = el.find(IND + "subexpression")
                states[el.get("id")] = None if sub is None else (sub.get("operation"), sub.get("datatype"),
                                                                 (sub.text or "").strip())
                el.clear()
            elif t == OD + "constant_variable":
                vars_[el.get("id")] = [v.text or "" for v in el.findall(OD + "value")]
                el.clear()
    if not defs:
        raise Bad(f"{path}: no OVAL definitions")
    return {"defs": defs, "tests": tests, "objs": objs, "states": states, "vars": vars_}


def _crit(el):
    if el is None:
        return None
    node = {"op": el.get("operator", "AND"), "neg": el.get("negate") == "true", "items": []}
    for c in el:
        if c.tag == OD + "criteria":
            node["items"].append(_crit(c))
        elif c.tag == OD + "criterion":
            node["items"].append({"test": c.get("test_ref"), "neg": c.get("negate") == "true",
                                  "comment": c.get("comment", "")})
        elif c.tag == OD + "extend_definition":
            raise Bad("extend_definition not supported in OCI feed")
    return node


def eval_ubuntu(oval, manifest_lines):
    """-> list of findings. A finding = definition true; packages = the matched lines whose version < fixed."""
    compiled = {}
    findings = []

    def pats(oid):
        ref = oval["objs"][oid]
        if oid not in compiled:
            srcs = [ref[1:]] if ref.startswith("=") else oval["vars"].get(ref)
            if srcs is None:
                raise Bad(f"OVAL variable {ref} missing")
            compiled[oid] = [re.compile(p) for p in srcs]
        return compiled[oid]

    def test(tid, hits):
        t = oval["tests"].get(tid)
        if t is None:
            raise Bad(f"OVAL test {tid} missing")
        items = []
        for rx in pats(t["obj"]):
            for line in manifest_lines:
                m = rx.match(line)
                if m:
                    items.append((line.split()[0].split(":")[0], m.group(1)))
        if not items:
            return False
        st = oval["states"].get(t["state"]) if t["state"] else None
        if st is None:
            return True
        op, dt, want = st
        if dt != "debian_evr_string" or op not in ("less than",):
            raise Bad(f"unsupported OVAL state {op}/{dt}")
        ok = [(n, v) for n, v in items if dpkg_cmp(v, want) < 0]
        res = bool(ok) if t["check"] in ("at least one", "any") else len(ok) == len(items)
        if res:
            hits.extend({"binary": n, "installed": v, "fixed": want} for n, v in ok)
        return res

    def ev(node, hits):
        if "test" in node:
            r = test(node["test"], hits)
            if r:
                pm = POCKET_RE.match(node["comment"])
                for h in hits:
                    h.setdefault("pocket", pm.group("pocket") if pm else "")
                    h.setdefault("source", pm.group("src") if pm else "")
            return r != node["neg"]
        rs = [ev(i, hits) for i in node["items"]]
        r = all(rs) if node["op"] == "AND" else any(rs)
        return r != node["neg"]

    for d in oval["defs"]:
        hits = []
        if d["criteria"] and ev(d["criteria"], hits) and hits:
            esm = all("esm" in h["pocket"] for h in hits)
            findings.append({"source": "ubuntu", "id": d["usn"], "severity": d["severity"], "cves": d["cves"],
                             "fixable": not esm, "fix": "esm" if esm else "archive", "packages": hits})
    return findings


DEB_URGENCY = {"high": "high", "medium": "medium", "low": "low", "unimportant": "negligible"}


def eval_debian(tracker, codename, dpkg):
    by_src = {}
    for p in dpkg:
        by_src.setdefault(p["source"], set()).add(p["source_version"])
    findings = []
    for src in sorted(by_src):
        for cve, info in sorted((tracker.get(src) or {}).items()):
            rel = (info.get("releases") or {}).get(codename)
            if not rel:
                continue
            status, fixed = rel.get("status"), rel.get("fixed_version")
            sev = DEB_URGENCY.get((rel.get("urgency") or "").rstrip("*"), "unrated")
            for v in sorted(by_src[src]):
                if status == "resolved":
                    if not fixed or fixed == "0" or dpkg_cmp(v, fixed) >= 0:
                        continue
                    fixable = True
                elif status == "open":
                    fixable = False
                else:
                    continue
                if sev == "negligible" and not fixable:
                    continue
                findings.append({"source": "debian", "id": cve, "severity": sev, "cves": [cve], "fixable": fixable,
                                 "fix": "archive" if fixable else "none",
                                 "packages": [{"source": src, "installed": v, "fixed": fixed if fixable else ""}]})
    return findings


def load_go_osv(path):
    entries = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if not (n.startswith("ID/") and n.endswith(".json")):
                continue
            e = json.loads(z.read(n))
            if e.get("withdrawn"):
                continue
            for a in e.get("affected", []):
                mod = a.get("package", {}).get("name")
                if mod:
                    entries.setdefault(mod, []).append((e["id"], e.get("aliases", []), a.get("ranges", [])))
    return entries


def _in_ranges(v, ranges):
    """OSV SEMVER ranges (introduced/fixed event pairs) -> (affected, fixed version of the matching range or '')."""
    k = semver_key(v)

    def key(x):
        return (0, 0, 0, (0,)) if x == "0" else semver_key("v" + x.lstrip("v"))

    for r in ranges:
        if r.get("type") != "SEMVER":
            continue
        lo = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                lo = key(ev["introduced"])
            elif "fixed" in ev and lo is not None:
                if lo <= k < key(ev["fixed"]):
                    return True, ev["fixed"]
                lo = None
        if lo is not None and lo <= k:
            return True, ""
    return False, ""


def eval_go(osv, gb):
    findings = []
    mods = [("stdlib", go_to_semver(gb["go_version"]))]
    for d in gb.get("deps", []):
        eff = d.get("replaced_by") or d
        if eff.get("version", "").startswith("v"):
            mods.append((eff["path"], eff["version"]))
    # the main module is not matched: release builds record "(devel)" or a v0.0.0 pseudo-version that would fall in
    # every "introduced: 0" range (govulncheck skips it too). README "Limits" says so.
    for mod, ver in mods:
        for vid, aliases, ranges in osv.get(mod, []):
            try:
                hit, fixed = _in_ranges(ver, ranges)
            except Bad:
                raise Bad(f"{gb['path']}: cannot compare {mod} {ver} with {vid}")
            if hit:
                findings.append({"source": "go", "id": vid, "severity": "unrated",
                                 "cves": sorted(a for a in aliases if a.startswith("CVE-")),
                                 "fixable": bool(fixed), "fix": "rebuild" if fixed else "none",
                                 "packages": [{"binary": gb["path"], "module": mod, "installed": ver,
                                               "fixed": fixed}]})
    return findings


# ---------------------------------------------------------------- scan
def scanner_for(inv):
    o = inv.get("os") or {}
    if o.get("ID") == "ubuntu" and inv["dpkg"]:
        return "ubuntu-oval:" + o.get("VERSION_CODENAME", "")
    if o.get("ID") == "debian" and inv["dpkg"]:
        return "debian-tracker:" + o.get("VERSION_CODENAME", "")
    if inv["apk"]:
        return "none:apk-inventory-only"
    if not o and not inv["dpkg"]:
        return "none:no-package-db"
    return "none:unsupported-os"


def provenance_flags(inv):
    p, flags = inv["provenance"], []
    if not p["repo_digests"]:
        flags.append("no_registry_digest")
    if not p["source"]:
        flags.append("no_source_label")
    for g in inv["go_binaries"]:
        if g["error"]:
            flags.append("go_buildinfo_unreadable")
        elif g["settings"].get("vcs.modified") == "true" or "+dirty" in (g.get("main") or {}).get("version", ""):
            flags.append("go_dirty_vcs")
    return sorted(set(flags))


def count(findings):
    c = {}
    for f in findings:
        k = (f["source"], f["severity"], "true" if f["fixable"] else "false", "true" if f.get("accepted") else "false")
        c[k] = c.get(k, 0) + 1
    return [{"source": k[0], "severity": k[1], "fixable": k[2], "accepted": k[3], "n": n} for k, n in sorted(c.items())]


def alerting(im):
    """Fixable high/critical findings that are not accepted (the alert input)."""
    return sum(c["n"] for c in im["counts"]
               if c["severity"] in ("critical", "high") and c["fixable"] == "true" and c["accepted"] == "false")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


ACCEPT_RE = re.compile(r"^(?P<img>[0-9a-f]{12,64})\s+(?P<id>\S+)\s+(?P<until>\d{4}-\d\d-\d\d)\s+(?P<why>\S.*)$")


def load_accept(path, now):
    """-> (entries [(img_prefix, finding_id)], expired count). Malformed lines or > 90 days ahead are refused."""
    entries, expired = [], 0
    if not path:
        return entries, expired
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = ACCEPT_RE.match(line)
            if not m:
                raise Bad(f"{path}:{n}: expected 'IMAGE_ID_PREFIX(>=12 hex) FINDING_ID YYYY-MM-DD reason'")
            until = int(datetime.strptime(m.group("until"), "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp())
            if until - now > 90 * 86400:
                raise Bad(f"{path}:{n}: acceptance more than 90 days ahead")
            if until + 86400 <= now:
                expired += 1
                continue
            entries.append((m.group("img"), m.group("id")))
    return entries, expired


def do_scan(inv_paths, containers_path, feeds_dir, now, max_age_days, max_content_age_days=30, accept_path=None):
    feeds = load_feeds(feeds_dir, now, max_age_days, max_content_age_days)
    accepted, expired = load_accept(accept_path, now)
    invs = []
    for p in inv_paths:
        with open(p) as f:
            invs.append(json.load(f))
    loaded = {}

    def feed(name, loader):
        if name not in feeds:
            raise Bad(f"no pinned feed {name} in feeds.json")
        if name not in loaded:
            loaded[name] = loader(feeds[name]["path"])
        return loaded[name]

    deb_rels = {scanner_for(i).partition(":")[2] for i in invs if scanner_for(i).startswith("debian-tracker:")}
    images = []
    for inv in sorted(invs, key=lambda i: i["ref"]):
        sc = scanner_for(inv)
        kind, _, rel = sc.partition(":")
        if kind == "ubuntu-oval":
            lines = [f"{p['name']}:{p['arch']} {p['version']}" if p["arch"] not in ("", "all") else
                     f"{p['name']} {p['version']}" for p in inv["dpkg"]]
            findings = eval_ubuntu(feed(f"ubuntu-{rel}", load_ubuntu_oval), lines)
        elif kind == "debian-tracker":
            def jload(path):
                # keep only what eval_debian reads, for the releases the scanned images use: the 92 MB tracker JSON
                # costs ~540 MB RSS when loaded whole
                def hook(pairs):
                    d = dict(pairs)
                    if "status" in d:                       # one release of one CVE
                        return {k: d[k] for k in ("status", "fixed_version", "urgency") if k in d}
                    if "releases" in d:                     # one CVE
                        return {"releases": {r: v for r, v in d["releases"].items() if r in deb_rels}}
                    return d
                with open(path, "rb") as f:
                    return json.load(f, object_pairs_hook=hook)
            findings = eval_debian(feed("debian", jload), rel, inv["dpkg"])
        else:
            findings = []
        go_osv = None
        for gb in inv["go_binaries"]:
            if gb["error"]:
                continue
            go_osv = go_osv or feed("go", load_go_osv)
            findings += eval_go(go_osv, gb)
        hexid = inv["image_id"].removeprefix("sha256:")
        for f in findings:
            f["accepted"] = any(hexid.startswith(p) and f["id"] == i for p, i in accepted)
        findings.sort(key=lambda f: (f["source"], f["id"], canon(f["packages"])))
        images.append({"ref": inv["ref"], "image_id": inv["image_id"], "os": inv["os"].get("PRETTY_NAME", ""),
                       "scanner": sc, "packages": len(inv["dpkg"]) + len(inv["apk"]),
                       "go_binaries": [{"path": g["path"], "go_version": g["go_version"], "sha256": g["sha256"],
                                        "vcs_revision": g["settings"].get("vcs.revision", ""),
                                        "deps": len(g["deps"])} for g in inv["go_binaries"]],
                       "provenance": inv["provenance"], "provenance_flags": provenance_flags(inv),
                       "findings": findings, "counts": count(findings),
                       "findings_sha256": hashlib.sha256(canon(findings)).hexdigest()})
    containers = []
    if containers_path:
        with open(containers_path) as f:
            containers = json.load(f)
    running = {c["image_id"] for c in containers}
    for im in images:
        im["in_use"] = im["image_id"] in running
    by_ref = {i["ref"]: i for i in images}
    scanned_ids = {i["image_id"] for i in images}
    drift = []
    for c in sorted(containers, key=lambda c: c["name"]):
        # a digest-pinned container (Config.Image repo:tag@sha256:...) is looked up by its tag; it runs exactly the
        # digest it was pinned to, so a scanned image ID is not drift even when the tag now names another image
        pinned = "@" in c["ref"]
        if pinned and c["image_id"] in scanned_ids:
            continue
        cur = by_ref.get(tag_ref(c["ref"]))
        if cur is None:
            drift.append({"container": c["name"], "ref": c["ref"], "kind": "image_not_scanned"})
        elif c["image_id"] != cur["image_id"]:
            drift.append({"container": c["name"], "ref": c["ref"], "kind": "running_image_differs_from_tag",
                          "running": c["image_id"], "tag": cur["image_id"]})
    return {"generated_at": now, "max_feed_age_days": max_age_days, "accept_expired": expired,
            "feeds": {k: {x: v[x] for x in ("file", "sha256", "url", "timestamp_epoch", "fetched_epoch", "age_seconds")
                          + OUTCOME_KEYS if x in v} for k, v in feeds.items()},
            "containers": containers, "drift": drift, "images": images}


def severity_rank(s):
    return SEVERITIES.index(s) if s in SEVERITIES else len(SEVERITIES)


def withhold(scan, pattern):
    """Summaries (no findings, no inventory) of the images whose ref matches pattern, for a public bundle."""
    rx = re.compile(pattern)
    keep = ("ref", "image_id", "os", "scanner", "packages", "counts", "findings_sha256", "in_use")
    return [{k: im[k] for k in keep} for im in scan["images"] if rx.search(im["ref"])]


def tag_ref(ref):
    """repo:tag@sha256:... -> repo:tag (the key `docker image ls` lists the image under)."""
    return ref.split("@", 1)[0]


def public_drift(scan, withheld):
    """Drift as seen on the host. A bundle rebuilt without a withheld image's inventory sees that image's containers
    as image_not_scanned; the withheld summary (taken from the host's full scan) says which image the tag named, so
    a container running exactly it is not drift and one running anything else is running_image_differs_from_tag."""
    wh = {w["ref"]: w["image_id"] for w in (withheld or [])}
    running = {c["name"]: c["image_id"] for c in scan["containers"]}
    out = []
    for d in scan["drift"]:
        if d["kind"] == "image_not_scanned" and tag_ref(d["ref"]) in wh:
            if running.get(d["container"]) == wh[tag_ref(d["ref"])]:
                continue
            d = {"container": d["container"], "ref": d["ref"], "kind": "running_image_differs_from_tag",
                 "running": running.get(d["container"], ""), "tag": wh[tag_ref(d["ref"])]}
        out.append(d)
    return out


def render(scan, public, before=None, withheld=None):
    gen = datetime.fromtimestamp(scan["generated_at"], timezone.utc)
    out = [f"pft-imagescan report - generated {gen:%Y-%m-%dT%H:%M:%SZ}"
           + ("  [PUBLIC: open-finding details withheld, counts + sha256 commitment only]" if public else "")]
    for k, f in sorted(scan["feeds"].items()):
        ts = datetime.fromtimestamp(f["timestamp_epoch"], timezone.utc)
        out.append(f"feed {k:<13} own {ts:%Y-%m-%dT%H:%MZ}  fetched {f['age_seconds'] // 3600:>3} h ago  "
                   f"sha256 {f['sha256']}")
    for c in scan["containers"]:
        out.append(f"container {c['name']:<18} {c['ref']}  {c['image_id'][:19]}")
    drift = public_drift(scan, withheld)
    for d in drift:
        extra = f" (running {d['running'][:19]}, tag {d['tag'][:19]})" if "running" in d else ""
        out.append(f"DRIFT {d['container']}: {d['kind']}{extra}")
    if scan.get("accept_expired"):
        out.append(f"ACCEPT: {scan['accept_expired']} expired acceptance line(s) ignored")
    prev = {i["ref"]: i for i in (before or {}).get("images", [])}
    images = [dict(im, withheld=False) for im in scan["images"]]
    images += [dict(im, withheld=True, findings=[], go_binaries=[], provenance=None, provenance_flags=[])
               for im in (withheld or [])]
    total, alert_n = 0, 0
    for im in sorted(images, key=lambda i: i["ref"]):
        out.append("")
        out.append(f"IMAGE {im['ref']}  {im['image_id'][:19]}  in_use={'yes' if im['in_use'] else 'no'}  "
                   f"os={im['os'] or '-'}  scanner={im['scanner']}  packages={im['packages']}"
                   + ("  [WITHHELD: unremediated upstream image, inventory not published]" if im["withheld"] else
                      f"  go_binaries={len(im['go_binaries'])}"))
        for g in im["go_binaries"]:
            out.append(f"  go {g['path']}  {g['go_version']}  deps={g['deps']}  vcs={g['vcs_revision'][:12] or '-'}"
                       f"  sha256={g['sha256'][:16]}")
        if im["provenance"] is not None:
            out.append(f"  provenance: digests={len(im['provenance']['repo_digests'])} "
                       f"source={im['provenance']['source'] or '-'} flags={','.join(im['provenance_flags']) or 'none'}")
        for c in im["counts"]:
            out.append(f"  count {c['source']:<7} {c['severity']:<10} fixable={c['fixable']:<5} "
                       f"accepted={c['accepted']:<5} {c['n']}")
            total += c["n"]
        if not im["counts"]:
            out.append("  count none")
        n = alerting(im)
        if im["in_use"]:
            alert_n += n
        out.append(f"  fixable high/critical not accepted: {n}{'' if im['in_use'] else ' (image not in use: no alert)'}")
        out.append(f"  findings_sha256 {im['findings_sha256']}")
        if im["ref"] in prev and not im["withheld"]:
            now_ids = {(f["source"], f["id"]) for f in im["findings"]}
            gone = sorted({(f["source"], f["id"], f["severity"]) for f in prev[im["ref"]]["findings"]
                           if (f["source"], f["id"]) not in now_ids})
            out.append(f"  fixed since the before-scan ({prev[im['ref']]['image_id'][:19]} -> {im['image_id'][:19]}): "
                       f"{len(gone)} of {len(prev[im['ref']]['findings'])}")
            out += [f"    FIXED {s} {i} {sev}" for s, i, sev in gone]
        if not public:
            for f in sorted(im["findings"], key=lambda f: (severity_rank(f["severity"]), f["id"])):
                pk = ", ".join(f"{p.get('binary') or p.get('source')}{'/' + p['module'] if 'module' in p else ''} "
                               f"{p['installed']} -> {p['fixed'] or 'no fix'}" for p in f["packages"][:4])
                more = f" (+{len(f['packages']) - 4})" if len(f["packages"]) > 4 else ""
                acc = " ACCEPTED" if f.get("accepted") else ""
                out.append(f"  {f['severity']:<10} {f['fix']:<7} {f['id']:<18} {pk}{more}{acc}")
    rc = 1 if (alert_n or drift) else 0
    out.append("")
    out.append(f"RESULT: {len(images)} images ({sum(1 for i in images if i['in_use'])} in use), {total} findings, "
               f"{alert_n} fixable high/critical in in-use images (not accepted), {len(drift)} drift -> exit {rc}")
    return "\n".join(out) + "\n", rc


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def metrics(scan, host):
    h = esc(host)
    L = ["# HELP pft_imagescan_findings Image findings by source, severity, fixable, accepted (offline feeds).",
         "# TYPE pft_imagescan_findings gauge"]
    for im in scan["images"]:
        for c in im["counts"]:
            L.append(f'pft_imagescan_findings{{host="{h}",image="{esc(im["ref"])}",source="{c["source"]}",'
                     f'severity="{c["severity"]}",fixable="{c["fixable"]}",accepted="{c["accepted"]}"}} {c["n"]}')
    L += ["# HELP pft_imagescan_fixable_high_critical Fixable high/critical findings per image, accepted ones excluded.",
          "# TYPE pft_imagescan_fixable_high_critical gauge"]
    for im in scan["images"]:
        L.append(f'pft_imagescan_fixable_high_critical{{host="{h}",image="{esc(im["ref"])}",'
                 f'in_use="{"true" if im["in_use"] else "false"}"}} {alerting(im)}')
    L += ["# HELP pft_imagescan_image_info Scanned image (scanner none:* = inventory only, no package feed).",
          "# TYPE pft_imagescan_image_info gauge"]
    for im in scan["images"]:
        L.append(f'pft_imagescan_image_info{{host="{h}",image="{esc(im["ref"])}",image_id="{im["image_id"][:19]}",'
                 f'scanner="{esc(im["scanner"])}",in_use="{"true" if im["in_use"] else "false"}"}} 1')
    L += ["# HELP pft_imagescan_provenance_flag Provenance flag raised for an image.",
          "# TYPE pft_imagescan_provenance_flag gauge"]
    for im in scan["images"]:
        for fl in im["provenance_flags"]:
            L.append(f'pft_imagescan_provenance_flag{{host="{h}",image="{esc(im["ref"])}",flag="{fl}"}} 1')
    L += ["# HELP pft_imagescan_drift Containers whose running image differs from the scanned tag (or unscanned).",
          "# TYPE pft_imagescan_drift gauge", f'pft_imagescan_drift{{host="{h}"}} {len(scan["drift"])}',
          "# HELP pft_imagescan_accept_expired Expired lines in the accept file (ignored).",
          "# TYPE pft_imagescan_accept_expired gauge",
          f'pft_imagescan_accept_expired{{host="{h}"}} {scan.get("accept_expired", 0)}',
          "# HELP pft_imagescan_feed_timestamp_seconds The feed's own timestamp.",
          "# TYPE pft_imagescan_feed_timestamp_seconds gauge"]
    for k, f in sorted(scan["feeds"].items()):
        L.append(f'pft_imagescan_feed_timestamp_seconds{{host="{h}",feed="{k}"}} {f["timestamp_epoch"]}')
    L += ["# HELP pft_imagescan_feed_fetched_timestamp_seconds When the pinned feed was downloaded from its origin.",
          "# TYPE pft_imagescan_feed_fetched_timestamp_seconds gauge"]
    for k, f in sorted(scan["feeds"].items()):
        L.append(f'pft_imagescan_feed_fetched_timestamp_seconds{{host="{h}",feed="{k}"}} {f["fetched_epoch"]}')
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="imagescan_lib")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("--ref", required=True)
    e.add_argument("--image-id", required=True)
    e.add_argument("--inspect")
    t = sub.add_parser("feedts")
    t.add_argument("kind")
    t.add_argument("path")
    s = sub.add_parser("scan")
    s.add_argument("--inventory", nargs="*", default=[])  # none: every image of the host is withheld
    s.add_argument("--containers")
    s.add_argument("--feeds", required=True)
    s.add_argument("--now", type=int, required=True)
    s.add_argument("--max-age-days", type=int, default=7)
    s.add_argument("--max-content-age-days", type=int, default=30)
    s.add_argument("--accept")
    r = sub.add_parser("render")
    r.add_argument("--scan", required=True)
    r.add_argument("--public", action="store_true")
    r.add_argument("--before")
    r.add_argument("--withheld")
    w = sub.add_parser("withhold")
    w.add_argument("--scan", required=True)
    w.add_argument("--ref", required=True, help="regex on the image ref")
    fm = sub.add_parser("feedmerge")
    fm.add_argument("fdir")
    fm.add_argument("tmp")
    fx = sub.add_parser("fetchmetrics")
    fx.add_argument("--feeds", required=True)
    fx.add_argument("--host", required=True)
    m = sub.add_parser("metrics")
    m.add_argument("--scan", required=True)
    m.add_argument("--host", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "extract":
            insp = None
            if a.inspect:
                with open(a.inspect) as f:
                    insp = json.load(f)
                insp = insp[0] if isinstance(insp, list) else insp
            layers, cfg = read_save_stream(sys.stdin.buffer)
            inv = build_inventory(layers, cfg, a.ref, a.image_id, insp)
            json.dump(inv, sys.stdout, sort_keys=True, indent=1)
            print()
        elif a.cmd == "feedts":
            print(feed_timestamp(a.kind, a.path))
        elif a.cmd == "scan":
            json.dump(do_scan(a.inventory, a.containers, a.feeds, a.now, a.max_age_days, a.max_content_age_days,
                              a.accept), sys.stdout, sort_keys=True, indent=1)
            print()
        elif a.cmd == "render":
            with open(a.scan) as f:
                sc = json.load(f)
            before = withheld = None
            if a.before:
                with open(a.before) as f:
                    before = json.load(f)
            if a.withheld:
                with open(a.withheld) as f:
                    withheld = json.load(f)
            text, rc = render(sc, a.public, before, withheld)
            sys.stdout.write(text)
            return rc
        elif a.cmd == "withhold":
            with open(a.scan) as f:
                json.dump(withhold(json.load(f), a.ref), sys.stdout, sort_keys=True, indent=1)
            print()
        elif a.cmd == "feedmerge":
            feed_merge(a.fdir, a.tmp, sys.stdin.read().splitlines())
        elif a.cmd == "fetchmetrics":
            with open(a.feeds) as f:
                sys.stdout.write(fetch_metrics(json.load(f), a.host))
        elif a.cmd == "metrics":
            with open(a.scan) as f:
                sys.stdout.write(metrics(json.load(f), a.host))
    except (Bad, tarfile.TarError, zipfile.BadZipFile, ET.ParseError, OSError, ValueError, KeyError) as ex:
        die(f"{a.cmd}: {ex}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
