"""Tests for imagescan_lib.py and pft-imagescan.sh (run: cd imagescan && python3 -m pytest -q tests).

Images are synthetic OCI-layout `docker image save` streams built here (gzip layers, whiteouts, opaque dirs,
symlinked os-release, a non-layer attestation blob, the canonical empty layer) around real Go build-info bytes
(fixtures/amtool.buildinfo). Feeds use Canonical OCI OVAL / Debian tracker / OSV structure with made-up IDs.
The shell tests run pft-imagescan.sh against a docker stub that records every call and fails on any verb other
than ps / inspect / image ls / image inspect / image save.
"""
import bz2
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import imagescan_lib as L

SCRIPT = ROOT / "pft-imagescan.sh"
LIB = ROOT / "imagescan_lib.py"
NOW = 1795400000  # 2026-11-23T02:13:20Z
BUILDINFO = (HERE / "fixtures" / "amtool.buildinfo").read_bytes()


# ------------------------------------------------------------------ builders
def tar_bytes(members, gz=True):
    """members: list of (name, kind, data/target, mode). kind: file|dir|sym."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name, kind, data, mode in members:
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = data
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gz else raw


def go_elf(pad=300 * 1024):
    return b"\x7fELF" + b"\0" * pad + BUILDINFO + b"\0" * 1024


def status(pkgs):
    out = []
    for name, ver, src, arch, st in pkgs:
        p = f"Package: {name}\nStatus: {st}\nArchitecture: {arch}\nVersion: {ver}\n"
        if src:
            p += f"Source: {src}\n"
        p += "Description: x\n multi-line\n"
        out.append(p)
    return "\n".join(out).encode()


def save_stream(layers, extra_blobs=(), labels=None):
    """OCI layout + manifest.json, as docker 29 (containerd store) writes it."""
    files, layer_paths = {}, []
    for lb in layers:
        d = hashlib.sha256(lb).hexdigest()
        files[f"blobs/sha256/{d}"] = lb
        layer_paths.append(f"blobs/sha256/{d}")
    for b in extra_blobs:
        files[f"blobs/sha256/{hashlib.sha256(b).hexdigest()}"] = b
    cfg = json.dumps({"created": "2026-11-01T00:00:00Z", "config": {"Labels": labels or {}},
                      "rootfs": {"diff_ids": ["sha256:" + "0" * 64] * len(layers)}}).encode()
    cd = hashlib.sha256(cfg).hexdigest()
    files[f"blobs/sha256/{cd}"] = cfg
    files["index.json"] = b'{"schemaVersion":2,"manifests":[]}'
    files["oci-layout"] = b'{"imageLayoutVersion": "1.0.0"}'
    files["manifest.json"] = json.dumps([{"Config": f"blobs/sha256/{cd}", "RepoTags": ["x:y"],
                                          "Layers": layer_paths}]).encode()
    order = sorted(k for k in files if k.startswith("blobs/")) + ["index.json", "manifest.json", "oci-layout"]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for k in order:
            ti = tarfile.TarInfo(k)
            ti.size = len(files[k])
            t.addfile(ti, io.BytesIO(files[k]))
    return buf.getvalue()


DEB_PKGS = [
    ("zlib1g", "1:1.3.dfsg+really1.3.1-1+b1", "zlib (1:1.3.dfsg+really1.3.1-1)", "amd64", "install ok installed"),
    ("libc6", "2.41-12+deb13u4", "glibc", "amd64", "install ok installed"),
    ("tar", "1.35+dfsg-3.1", "", "amd64", "install ok installed"),
    ("oldpkg", "1.0-1", "", "amd64", "deinstall ok config-files"),
]


def debian_image():
    osr = b'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'
    l1 = tar_bytes([("etc", "dir", None, 0o755), ("etc/os-release", "sym", "../usr/lib/os-release", 0o777),
                    ("usr/lib/os-release", "file", osr, 0o644), ("var/lib/dpkg/status", "file", status(DEB_PKGS), 0o644),
                    ("usr/local/bin/tool", "file", go_elf(), 0o755)])
    # layer 2: a Go binary that is later deleted by a whiteout, and a dir made opaque
    l2 = tar_bytes([("opt/gone/bin", "file", go_elf(), 0o755), ("srv/app/old", "file", go_elf(), 0o755)])
    l3 = tar_bytes([("opt/.wh.gone", "file", b"", 0o644), ("srv/app/.wh..wh..opq", "file", b"", 0o644),
                    ("srv/app/new.txt", "file", b"x", 0o644)])
    empty = gzip.compress(b"\0" * 1024, mtime=0)
    attestation = b'{"_type": "https://in-toto.io/Statement/v0.1"}' + b" " * (5 * 1024 * 1024)
    return save_stream([l1, l2, l3, empty], extra_blobs=[attestation],
                       labels={"org.opencontainers.image.source": "https://example.invalid/src"})


UB_PKGS = [
    ("libfoo1", "1.2-3ubuntu0.1", "foo", "amd64", "install ok installed"),   # < fixed 1.2-3ubuntu0.2 -> affected
    ("libbar1", "2.0-1ubuntu0.5", "bar", "amd64", "install ok installed"),   # == fixed -> not affected
    ("jsthing", "1.0-1", "jsthing", "all", "install ok installed"),           # esm only
]


def ubuntu_image():
    osr = b'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
    l1 = tar_bytes([("etc/os-release", "file", osr, 0o644), ("var/lib/dpkg/status", "file", status(UB_PKGS), 0o644)])
    return save_stream([l1])


def go_only_image():
    l1 = tar_bytes([("bin/amtool", "file", go_elf(), 0o755), ("bin/small", "file", b"\x7fELF" + b"\0" * 10, 0o755)])
    return save_stream([l1])


def extract(stream, ref="x:y", image_id="sha256:" + "a" * 64):
    layers, cfg = L.read_save_stream(io.BytesIO(stream))
    return L.build_inventory(layers, cfg, ref, image_id, {"RepoDigests": ["x@sha256:" + "b" * 64]})


OVAL = """<?xml version="1.0"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
 xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
 xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">
 <generator><oval:timestamp>{ts}</oval:timestamp></generator>
 <definitions>
  <definition id="oval:t:def:1" class="patch" version="1"><metadata><title>USN-0000-1 -- foo</title>
   <reference source="USN" ref_id="USN-0000-1"/><reference source="CVE" ref_id="CVE-0000-0001"/>
   <advisory><severity>High</severity></advisory></metadata>
   <criteria><criterion test_ref="oval:t:tst:1" comment="foo source package in noble, is affected and has been fixed (note: '1.2-3ubuntu0.2')."/></criteria></definition>
  <definition id="oval:t:def:2" class="patch" version="1"><metadata><title>USN-0000-2 -- bar</title>
   <reference source="USN" ref_id="USN-0000-2"/><advisory><severity>Critical</severity></advisory></metadata>
   <criteria><criterion test_ref="oval:t:tst:2" comment="bar source package in noble, is affected and has been fixed (note: '2.0-1ubuntu0.5')."/></criteria></definition>
  <definition id="oval:t:def:3" class="patch" version="1"><metadata><title>USN-0000-3 -- jsthing</title>
   <reference source="USN" ref_id="USN-0000-3"/><advisory><severity>Medium</severity></advisory></metadata>
   <criteria operator="OR"><criterion test_ref="oval:t:tst:3" comment="jsthing source package in esm-apps/noble, is affected and has been fixed (note: '1.0-1ubuntu0.1~esm1')."/>
   <criterion test_ref="oval:t:tst:4" comment="nothere source package in noble, is affected and has been fixed (note: '9')."/></criteria></definition>
 </definitions>
 <tests>
  <ind-def:textfilecontent54_test id="oval:t:tst:1" check="at least one" check_existence="at_least_one_exists"><ind-def:object object_ref="oval:t:obj:1"/><ind-def:state state_ref="oval:t:ste:1"/></ind-def:textfilecontent54_test>
  <ind-def:textfilecontent54_test id="oval:t:tst:2" check="at least one" check_existence="at_least_one_exists"><ind-def:object object_ref="oval:t:obj:2"/><ind-def:state state_ref="oval:t:ste:2"/></ind-def:textfilecontent54_test>
  <ind-def:textfilecontent54_test id="oval:t:tst:3" check="at least one" check_existence="at_least_one_exists"><ind-def:object object_ref="oval:t:obj:3"/><ind-def:state state_ref="oval:t:ste:3"/></ind-def:textfilecontent54_test>
  <ind-def:textfilecontent54_test id="oval:t:tst:4" check="at least one" check_existence="at_least_one_exists"><ind-def:object object_ref="oval:t:obj:4"/><ind-def:state state_ref="oval:t:ste:4"/></ind-def:textfilecontent54_test>
 </tests>
 <objects>
  <ind-def:textfilecontent54_object id="oval:t:obj:1"><ind-def:path>.</ind-def:path><ind-def:filename>manifest</ind-def:filename><ind-def:pattern operation="pattern match" datatype="string" var_ref="oval:t:var:1"/><ind-def:instance datatype="int">1</ind-def:instance></ind-def:textfilecontent54_object>
  <ind-def:textfilecontent54_object id="oval:t:obj:2"><ind-def:path>.</ind-def:path><ind-def:filename>manifest</ind-def:filename><ind-def:pattern operation="pattern match" datatype="string" var_ref="oval:t:var:2"/><ind-def:instance datatype="int">1</ind-def:instance></ind-def:textfilecontent54_object>
  <ind-def:textfilecontent54_object id="oval:t:obj:3"><ind-def:path>.</ind-def:path><ind-def:filename>manifest</ind-def:filename><ind-def:pattern operation="pattern match" datatype="string" var_ref="oval:t:var:3"/><ind-def:instance datatype="int">1</ind-def:instance></ind-def:textfilecontent54_object>
  <ind-def:textfilecontent54_object id="oval:t:obj:4"><ind-def:path>.</ind-def:path><ind-def:filename>manifest</ind-def:filename><ind-def:pattern operation="pattern match" datatype="string" var_ref="oval:t:var:4"/><ind-def:instance datatype="int">1</ind-def:instance></ind-def:textfilecontent54_object>
 </objects>
 <states>
  <ind-def:textfilecontent54_state id="oval:t:ste:1"><ind-def:subexpression datatype="debian_evr_string" operation="less than">1.2-3ubuntu0.2</ind-def:subexpression></ind-def:textfilecontent54_state>
  <ind-def:textfilecontent54_state id="oval:t:ste:2"><ind-def:subexpression datatype="debian_evr_string" operation="less than">2.0-1ubuntu0.5</ind-def:subexpression></ind-def:textfilecontent54_state>
  <ind-def:textfilecontent54_state id="oval:t:ste:3"><ind-def:subexpression datatype="debian_evr_string" operation="less than">1.0-1ubuntu0.1~esm1</ind-def:subexpression></ind-def:textfilecontent54_state>
  <ind-def:textfilecontent54_state id="oval:t:ste:4"><ind-def:subexpression datatype="debian_evr_string" operation="less than">9</ind-def:subexpression></ind-def:textfilecontent54_state>
 </states>
 <variables>
  <constant_variable id="oval:t:var:1" datatype="string"><value>^libfoo1(?::\\w+|)\\s+(.*)$</value></constant_variable>
  <constant_variable id="oval:t:var:2" datatype="string"><value>^libbar1(?::\\w+|)\\s+(.*)$</value></constant_variable>
  <constant_variable id="oval:t:var:3" datatype="string"><value>^jsthing(?::\\w+|)\\s+(.*)$</value></constant_variable>
  <constant_variable id="oval:t:var:4" datatype="string"><value>^nothere(?::\\w+|)\\s+(.*)$</value></constant_variable>
 </variables>
</oval_definitions>
"""

TRACKER = {
    "zlib": {
        "CVE-0000-1001": {"releases": {"trixie": {"status": "resolved", "urgency": "high",
                                                  "fixed_version": "1:1.3.dfsg+really1.3.1-1+deb13u1"}}},
        "CVE-0000-1002": {"releases": {"trixie": {"status": "resolved", "urgency": "medium",
                                                  "fixed_version": "1:1.3.dfsg+really1.3.1-1"}}},  # == installed src
        "CVE-0000-1003": {"releases": {"trixie": {"status": "resolved", "urgency": "low", "fixed_version": "0"}}},
        "CVE-0000-1004": {"releases": {"bookworm": {"status": "open", "urgency": "high"}}},  # other release
    },
    "glibc": {"CVE-0000-2001": {"releases": {"trixie": {"status": "open", "urgency": "not yet assigned"}}},
              "CVE-0000-2002": {"releases": {"trixie": {"status": "open", "urgency": "unimportant"}}}},
    "tar": {"CVE-0000-3001": {"releases": {"trixie": {"status": "undetermined", "urgency": "high"}}}},
}
TRACKER.update({f"filler{i}": {} for i in range(1001)})  # fetch refuses a tracker with < 1000 source packages

GO_ENTRIES = [
    {"id": "GO-0000-0001", "aliases": ["CVE-0000-5001"], "affected": [
        {"package": {"name": "golang.org/x/net"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "0.33.0"}]}]}]},                          # amtool has v0.33.0: not hit
    {"id": "GO-0000-0002", "aliases": [], "affected": [
        {"package": {"name": "golang.org/x/net"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "0.34.0"}]}]}]},                          # hit, fixed 0.34.0
    {"id": "GO-0000-0003", "aliases": [], "affected": [
        {"package": {"name": "stdlib"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "1.22.12"}, {"introduced": "1.23.0-0"}, {"fixed": "1.23.7"}]}]}]},
    {"id": "GO-0000-0004", "aliases": ["CVE-0000-5004"], "affected": [
        {"package": {"name": "stdlib"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "1.22.13"}, {"introduced": "1.23.0-0"}, {"fixed": "1.23.8"}]}]}]},
    {"id": "GO-0000-0005", "withdrawn": "2026-01-01T00:00:00Z", "affected": [
        {"package": {"name": "stdlib"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
    {"id": "GO-0000-0006", "aliases": [], "affected": [
        {"package": {"name": "github.com/prometheus/alertmanager"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}]}]}]},                                               # main module: never matched
    {"id": "GO-0000-0007", "aliases": [], "affected": [
        {"package": {"name": "golang.org/x/net"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0.40.0"}, {"fixed": "0.41.0"}]}]}]},                     # introduced after v0.33.0
]


def write_feeds(d, fetched=NOW - 3600, own=NOW - 7200, oval_ts="2026-11-23T00:13:20"):
    d.mkdir(parents=True, exist_ok=True)
    (d / "oci.com.ubuntu.noble.usn.oval.xml.bz2").write_bytes(bz2.compress(OVAL.format(ts=oval_ts).encode()))
    (d / "debian-tracker.json").write_text(json.dumps(TRACKER))
    with zipfile.ZipFile(d / "vulndb.zip", "w") as z:
        z.writestr("index/db.json", json.dumps({"modified": "2026-11-22T00:00:00Z"}))
        for e in GO_ENTRIES:
            z.writestr(f"ID/{e['id']}.json", json.dumps(e))
    meta = {"feeds": {}}
    for name, kind, file in (("ubuntu-noble", "ubuntu-oval", "oci.com.ubuntu.noble.usn.oval.xml.bz2"),
                             ("debian", "debian-tracker", "debian-tracker.json"), ("go", "go-osv", "vulndb.zip")):
        meta["feeds"][name] = {"kind": kind, "file": file, "url": "https://example.invalid/" + file,
                               "sha256": hashlib.sha256((d / file).read_bytes()).hexdigest(),
                               "timestamp_epoch": own, "fetched_epoch": fetched}
    (d / "feeds.json").write_text(json.dumps(meta))
    return d


# ------------------------------------------------------------------ versions
@pytest.mark.parametrize("a,b,want", [
    ("1.0", "1.0", 0), ("1.0-1", "1.0-2", -1), ("1:0.9", "2.0", 1), ("1.0~rc1", "1.0", -1), ("1.0~~", "1.0~", -1),
    ("1.0+really0.9", "1.0", 1), ("2.41-12+deb13u4", "2.41-12+deb13u5", -1), ("1.0a", "1.0+", -1),
    ("1:1.3.dfsg+really1.3.1-1", "1:1.3.dfsg+really1.3.1-1+deb13u1", -1), ("1.10", "1.9", 1), ("0:1.0", "1.0", 0),
    ("1.0-1ubuntu0.1~esm1", "1.0-1ubuntu0.1", -1), ("1.0-1ubuntu0.1~esm1", "1.0-1", 1),
])
def test_dpkg_cmp(a, b, want):
    assert L.dpkg_cmp(a, b) == want
    assert L.dpkg_cmp(b, a) == -want


def test_dpkg_bad_version():
    with pytest.raises(L.Bad):
        L.dpkg_cmp("not a version!", "1.0")


@pytest.mark.parametrize("a,b", [("v1.0.0-rc.1", "v1.0.0"), ("v1.0.0-alpha", "v1.0.0-alpha.1"),
                                 ("v1.0.0-alpha.1", "v1.0.0-alpha.beta"), ("v1.0.0-2", "v1.0.0-10"),
                                 ("v0.0.0-20250714113842-8be3a9560fbd", "v0.1.0"), ("v1.2.3", "v1.10.0")])
def test_semver_order(a, b):
    assert L.semver_key(a) < L.semver_key(b)


def test_go_version_mapping():
    assert L.go_to_semver("go1.23.7") == "v1.23.7"
    assert L.go_to_semver("go1.22") == "v1.22.0"
    assert L.go_to_semver("go1.21rc2") == "v1.21.0-rc.2"
    assert L.go_to_semver("go1.24.5 X:boringcrypto") == "v1.24.5"
    with pytest.raises(L.Bad):
        L.go_to_semver("devel +abc")


# ------------------------------------------------------------------ extraction
def test_extract_debian_layers_whiteouts_symlink():
    inv = extract(debian_image())
    assert inv["os"]["VERSION_CODENAME"] == "trixie"  # via the etc/os-release -> ../usr/lib/os-release symlink
    names = [p["name"] for p in inv["dpkg"]]
    assert names == ["libc6", "tar", "zlib1g"]       # config-files-only package excluded
    z = next(p for p in inv["dpkg"] if p["name"] == "zlib1g")
    assert (z["source"], z["source_version"]) == ("zlib", "1:1.3.dfsg+really1.3.1-1")  # binNMU source version
    paths = [g["path"] for g in inv["go_binaries"]]
    assert paths == ["/usr/local/bin/tool"]           # /opt/gone (whiteout) and /srv/app/old (opaque) are gone
    assert inv["go_binaries"][0]["go_version"] == "go1.23.7"
    assert inv["provenance"]["source"] == "https://example.invalid/src"


def test_extract_real_buildinfo_bytes():
    inv = extract(go_only_image())
    (g,) = inv["go_binaries"]
    assert g["module_path"] == "github.com/prometheus/alertmanager/cmd/amtool"
    assert g["main"]["path"] == "github.com/prometheus/alertmanager"
    deps = {d["path"]: d["version"] for d in g["deps"]}
    assert deps["golang.org/x/net"] == "v0.33.0"
    assert g["settings"]["vcs.revision"].startswith("b2099eaa")
    assert g["sha256"] == hashlib.sha256(go_elf()).hexdigest()
    assert inv["elf_without_go"] == 0                 # bin/small is below MIN_EXEC_SIZE: not even read


def test_buildinfo_split_across_chunks():
    # put the magic across the 1 MiB read boundary of scan_member
    data = b"\x7fELF" + b"\0" * ((1 << 20) - 6) + BUILDINFO + b"\0" * 64
    r = L.scan_member(io.BytesIO(data), len(data))
    assert r["go"]["version"] == "go1.23.7"


def test_old_buildinfo_format_reported_not_guessed():
    old = bytearray(BUILDINFO)
    old[15] = 0  # flags without the inline-strings bit (Go < 1.18 pointer format)
    data = b"\x7fELF" + b"\0" * 1000 + bytes(old)
    r = L.scan_member(io.BytesIO(data), len(data))
    assert "pre-Go-1.18" in r["go"]["error"]


def test_missing_layer_refused():
    s = bytearray(save_stream([tar_bytes([("a", "file", b"x", 0o644)])]))
    buf = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(bytes(s))) as src, tarfile.open(fileobj=buf, mode="w") as dst:
        for m in src:
            data = src.extractfile(m).read() if m.isreg() else b""
            if data[:2] == b"\x1f\x8b":
                continue  # drop the layer blob
            dst.addfile(m, io.BytesIO(data))
    with pytest.raises(L.Bad, match="not readable"):
        L.read_save_stream(io.BytesIO(buf.getvalue()))


# ------------------------------------------------------------------ matching
def scan_all(tmp_path, invs, containers=None, **kw):
    feeds = write_feeds(tmp_path / "feeds")
    paths = []
    for i, inv in enumerate(invs):
        p = tmp_path / f"inv{i}.json"
        p.write_text(json.dumps(inv))
        paths.append(str(p))
    cp = None
    if containers is not None:
        cp = tmp_path / "containers.json"
        cp.write_text(json.dumps(containers))
    return L.do_scan(paths, cp and str(cp), str(feeds), NOW, 7, **kw)


def test_ubuntu_oval_edges(tmp_path):
    sc = scan_all(tmp_path, [extract(ubuntu_image())])
    f = {x["id"]: x for x in sc["images"][0]["findings"]}
    assert set(f) == {"USN-0000-1", "USN-0000-3"}     # USN-0000-2: installed == fixed -> not affected
    assert f["USN-0000-1"]["fixable"] and f["USN-0000-1"]["severity"] == "high"
    assert f["USN-0000-1"]["packages"] == [{"binary": "libfoo1", "installed": "1.2-3ubuntu0.1",
                                            "fixed": "1.2-3ubuntu0.2", "pocket": "noble", "source": "foo"}]
    assert not f["USN-0000-3"]["fixable"] and f["USN-0000-3"]["fix"] == "esm"


def test_debian_tracker_edges(tmp_path):
    sc = scan_all(tmp_path, [extract(debian_image())])
    f = {x["id"]: x for x in sc["images"][0]["findings"] if x["source"] == "debian"}
    # 1001 fixed later -> fixable high; 1002 fixed == installed; 1003 "0" = never affected; 1004 other release;
    # 2001 open, unrated, not fixable; 2002 open + unimportant -> dropped; 3001 undetermined -> not reported
    assert set(f) == {"CVE-0000-1001", "CVE-0000-2001"}
    assert f["CVE-0000-1001"]["fixable"] and f["CVE-0000-1001"]["severity"] == "high"
    assert not f["CVE-0000-2001"]["fixable"] and f["CVE-0000-2001"]["severity"] == "unrated"


def test_go_osv_edges(tmp_path):
    sc = scan_all(tmp_path, [extract(go_only_image())])
    f = {(x["id"], x["packages"][0]["module"]) for x in sc["images"][0]["findings"]}
    # 0001 fixed at exactly the dep version, 0003 fixed at exactly go1.23.7, 0005 withdrawn, 0006 main module,
    # 0007 introduced after the dep version
    assert f == {("GO-0000-0002", "golang.org/x/net"), ("GO-0000-0004", "stdlib")}
    g = next(x for x in sc["images"][0]["findings"] if x["id"] == "GO-0000-0004")
    assert g["packages"][0]["fixed"] == "1.23.8" and g["cves"] == ["CVE-0000-5004"] and g["severity"] == "unrated"


def test_accept_and_in_use(tmp_path):
    inv = extract(ubuntu_image(), image_id="sha256:" + "c" * 64)
    acc = tmp_path / "accept"
    acc.write_text("# comment\n" + "c" * 12 + " USN-0000-1 2026-12-01 upstream image, operator informed\n"
                   + "c" * 12 + " USN-0000-3 2026-11-01 expired line\n")
    sc = scan_all(tmp_path, [inv], containers=[{"name": "n", "ref": "x:y", "image_id": "sha256:" + "c" * 64}],
                  accept_path=str(acc))
    im = sc["images"][0]
    assert im["in_use"] and sc["accept_expired"] == 1 and L.alerting(im) == 0
    text, rc = L.render(sc, public=False)
    assert rc == 0 and "ACCEPTED" in text
    acc.write_text("c" * 12 + " USN-0000-1 2027-06-01 too far ahead\n")
    with pytest.raises(L.Bad, match="90 days"):
        scan_all(tmp_path, [inv], accept_path=str(acc))
    acc.write_text("ccc USN-0000-1 2026-12-01 short prefix\n")
    with pytest.raises(L.Bad, match="expected"):
        scan_all(tmp_path, [inv], accept_path=str(acc))


def test_alert_input_counts_only_fixable_high_critical_not_accepted():
    def im(sev, fixable, accepted, n=1):
        return {"counts": [{"source": "ubuntu", "severity": sev, "fixable": fixable, "accepted": accepted, "n": n}]}
    assert L.alerting(im("high", "true", "false", 2)) == 2
    assert L.alerting(im("critical", "true", "false")) == 1
    assert L.alerting(im("medium", "true", "false")) == 0
    assert L.alerting(im("high", "false", "false")) == 0
    assert L.alerting(im("critical", "true", "true")) == 0


def test_accept_line_for_another_image_does_not_suppress(tmp_path):
    inv = extract(ubuntu_image(), image_id="sha256:" + "c" * 64)
    acc = tmp_path / "accept"
    acc.write_text("d" * 12 + " USN-0000-1 2026-12-01 accepted for a different image\n")
    sc = scan_all(tmp_path, [inv], accept_path=str(acc))
    assert L.alerting(sc["images"][0]) == 1
    assert not any(f["accepted"] for f in sc["images"][0]["findings"])


def test_image_not_in_use_does_not_alert(tmp_path):
    inv = extract(ubuntu_image(), image_id="sha256:" + "c" * 64)
    sc = scan_all(tmp_path, [inv], containers=[])
    text, rc = L.render(sc, public=False)
    assert rc == 0 and "fixable high/critical not accepted: 1 (image not in use: no alert)" in text
    sc = scan_all(tmp_path, [inv], containers=[{"name": "n", "ref": "x:y", "image_id": "sha256:" + "c" * 64}])
    assert L.render(sc, public=False)[1] == 1


def test_drift_and_unscanned(tmp_path):
    inv = extract(go_only_image(), ref="prom/x:1", image_id="sha256:" + "d" * 64)
    sc = scan_all(tmp_path, [inv], containers=[
        {"name": "a", "ref": "prom/x:1", "image_id": "sha256:" + "e" * 64},
        {"name": "b", "ref": "other:1", "image_id": "sha256:" + "f" * 64}])
    kinds = {d["container"]: d["kind"] for d in sc["drift"]}
    assert kinds == {"a": "running_image_differs_from_tag", "b": "image_not_scanned"}
    assert L.render(sc, public=False)[1] == 1


def test_public_render_withholds_details(tmp_path):
    inv = extract(ubuntu_image(), ref="up/stream:1", image_id="sha256:" + "c" * 64)
    sc = scan_all(tmp_path, [inv], containers=[{"name": "n", "ref": "up/stream:1", "image_id": "sha256:" + "c" * 64}])
    full, _ = L.render(sc, public=False)
    pub, rc = L.render(sc, public=True)
    assert "USN-0000-1" in full and "libfoo1" in full
    assert "USN-0000-1" not in pub and "libfoo1" not in pub and sc["images"][0]["findings_sha256"] in pub
    wh = L.withhold(sc, r"^up/")
    sc2 = dict(sc, images=[], containers=sc["containers"])
    pub2, rc2 = L.render(sc2, public=True, withheld=wh)
    assert "WITHHELD" in pub2 and "libfoo1" not in pub2 and rc2 == rc == 1


def test_before_after_fixed_listing(tmp_path):
    inv = extract(debian_image(), ref="local:1")
    before = scan_all(tmp_path, [inv])
    fixed_pkgs = [list(p) for p in DEB_PKGS]
    fixed_pkgs[0][1], fixed_pkgs[0][2] = "1:1.3.dfsg+really1.3.1-1+deb13u1", ""
    osr = b"ID=debian\nVERSION_CODENAME=trixie\n"
    after_img = save_stream([tar_bytes([("etc/os-release", "file", osr, 0o644),
                                        ("var/lib/dpkg/status", "file", status([tuple(p) for p in fixed_pkgs]), 0o644)])])
    after = scan_all(tmp_path, [extract(after_img, ref="local:1", image_id="sha256:" + "9" * 64)])
    text, _ = L.render(after, public=True, before=before)
    assert "FIXED debian CVE-0000-1001 high" in text and "CVE-0000-2001" not in text


# ------------------------------------------------------------------ feeds
@pytest.mark.parametrize("kw,msg", [
    ({"fetched": NOW - 8 * 86400, "own": NOW - 8 * 86400}, "fetched 192 h ago"),
    ({"own": NOW - 31 * 86400}, "own timestamp 31 d old"),
    ({"own": NOW, "fetched": NOW - 7200}, "after its fetch time"),
    ({"own": NOW - 86400, "fetched": NOW + 3601}, "fetch time is after the scan time"),
])
def test_stale_feeds_refused(tmp_path, kw, msg):
    write_feeds(tmp_path / "f", **kw)
    with pytest.raises(L.Bad, match=msg):
        L.load_feeds(str(tmp_path / "f"), NOW, 7)


@pytest.mark.parametrize("ahead", [1, 30, 3600], ids=["ahead-1s", "ahead-30s", "ahead-1h"])
def test_feed_fetched_during_this_scan_is_0h(tmp_path, ahead):
    # the scan clock is read before the fetch: a feed fetched seconds later must render "0 h ago", never "-1 h ago"
    write_feeds(tmp_path / "f", own=NOW - 86400, fetched=NOW + ahead)
    feeds = L.load_feeds(str(tmp_path / "f"), NOW, 7)
    assert all(f["age_seconds"] == 0 for f in feeds.values())
    sc = {"generated_at": NOW, "feeds": feeds, "containers": [], "images": [], "drift": [], "accept_expired": 0}
    text, _ = L.render(sc, public=True)
    assert "fetched   0 h ago" in text and "-1 h ago" not in text


def test_feed_hash_mismatch_refused(tmp_path):
    d = write_feeds(tmp_path / "f")
    with open(d / "vulndb.zip", "ab") as f:
        f.write(b"x")
    with pytest.raises(L.Bad, match="sha256"):
        L.load_feeds(str(d), NOW, 7)


def test_missing_feed_for_os_refused(tmp_path):
    d = write_feeds(tmp_path / "f")
    meta = json.loads((d / "feeds.json").read_text())
    del meta["feeds"]["debian"]
    (d / "feeds.json").write_text(json.dumps(meta))
    p = tmp_path / "inv.json"
    p.write_text(json.dumps(extract(debian_image())))
    with pytest.raises(L.Bad, match="no pinned feed debian"):
        L.do_scan([str(p)], None, str(d), NOW, 7)


def test_feed_timestamps(tmp_path):
    d = write_feeds(tmp_path / "f")
    assert L.feed_timestamp("ubuntu-oval", str(d / "oci.com.ubuntu.noble.usn.oval.xml.bz2")) == NOW - 7200
    assert L.feed_timestamp("go-osv", str(d / "vulndb.zip")) == 1795305600


# ------------------------------------------------------------------ shell + docker stub
STUB = r"""#!/usr/bin/env bash
# docker stub: records argv, serves fixture data, fails on any verb outside the read-only allowlist
printf '%s\n' "$*" >> "$STUB_LOG"
D="$STUB_DIR"
case "$1 ${2:-}" in
  "ps --no-trunc") cat "$D/ps" ;;
  "inspect --format") id="$4"; cat "$D/c-$id" ;;
  "image ls") cat "$D/images" ;;
  "image inspect") echo '[{"RepoDigests": []}]' ;;
  "image save") cat "$D/save-${3#sha256:}" ;;
  *) echo "STUB: forbidden docker call: $*" >&2; exit 99 ;;
esac
"""


@pytest.fixture
def exec_dir(tmp_path):
    """Stubs must be executable: /tmp is noexec on the hardened hosts, so they go under TEST_TMPDIR (~/.cache)."""
    import shutil
    import tempfile
    base = os.environ.get("TEST_TMPDIR", os.path.expanduser("~/.cache"))
    os.makedirs(base, exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="imagescan-stub-", dir=base))
    yield d
    shutil.rmtree(d)


def shell_env(tmp_path, images, sd):
    """images: [(ref, hexid, stream)]; every image is run by one container. sd: executable stub dir."""
    (sd / "docker").write_text(STUB)
    (sd / "docker").chmod(0o755)
    ps, imgs = [], []
    for i, (ref, hexid, stream) in enumerate(images):
        (sd / f"save-{hexid}").write_bytes(stream)
        cid = f"c{i}"
        ps.append(cid)
        (sd / f"c-{cid}").write_text(f"/ctr{i}\t{ref}\tsha256:{hexid}\n")
        imgs.append(f"{ref}\tsha256:{hexid}")
    (sd / "ps").write_text("\n".join(ps) + "\n")
    (sd / "images").write_text("\n".join(imgs) + "\n")
    cache = tmp_path / "cache"
    write_feeds(cache / "feeds")
    tf = tmp_path / "textfile"
    tf.mkdir()
    conf = tmp_path / "conf.env"
    conf.write_text(f"HOST_LABEL=validator\nCACHE_DIR={cache}\nTEXTFILE_DIR={tf}\nACCEPT_FILE={tmp_path}/none\n")
    env = dict(os.environ, PFT_IS_DOCKER=str(sd / "docker"), PFT_IS_LIB=str(LIB), PFT_IS_CONF=str(conf),
               PFT_IS_NOW=str(NOW), STUB_LOG=str(tmp_path / "docker.log"), STUB_DIR=str(sd),
               PFT_IS_CURL="/bin/false")
    return env, tf, cache


def run(args, env):
    return subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True, timeout=120)


def test_shell_scan_only_readonly_docker_calls_and_cache(tmp_path, exec_dir):
    imgs = [("deb:1", "1" * 64, debian_image()), ("go:1", "2" * 64, go_only_image()), ("ub:1", "3" * 64, ubuntu_image())]
    env, tf, _cache = shell_env(tmp_path, imgs, exec_dir)
    r = run(["scan", "--no-fetch"], env)
    assert r.returncode == 1, r.stdout + r.stderr  # ub:1 has an in-use fixable high (USN-0000-1)
    assert "RESULT: 3 images (3 in use)" in r.stdout
    calls = (tmp_path / "docker.log").read_text().splitlines()
    verbs = {" ".join(c.split()[:2]) for c in calls}
    assert verbs <= {"ps --no-trunc", "inspect --format", "image ls", "image inspect", "image save"}, verbs
    assert sum(c.startswith("image save") for c in calls) == 3
    prom = (tf / "pft_imagescan_validator.prom").read_text()
    assert 'pft_imagescan_up{host="validator"} 1' in prom
    assert 'pft_imagescan_fixable_high_critical{host="validator",image="ub:1",in_use="true"} 1' in prom
    v = run(["validate", str(tf / "pft_imagescan_validator.prom"), "validator"], env)
    assert v.returncode == 0, v.stdout
    # second run: inventories come from the per-image-ID cache, no image is saved again
    (tmp_path / "docker.log").write_text("")
    r2 = run(["scan", "--no-fetch"], env)
    assert r2.returncode == 1
    assert not [c for c in (tmp_path / "docker.log").read_text().splitlines() if c.startswith("image save")]


def test_shell_scan_error_sets_up_0(tmp_path, exec_dir):
    env, tf, cache = shell_env(tmp_path, [("deb:1", "1" * 64, debian_image())], exec_dir)
    meta = json.loads((cache / "feeds" / "feeds.json").read_text())
    for f in meta["feeds"].values():
        f["fetched_epoch"] = NOW - 9 * 86400
        f["timestamp_epoch"] = NOW - 9 * 86400
    (cache / "feeds" / "feeds.json").write_text(json.dumps(meta))
    r = run(["scan", "--no-fetch"], env)
    assert r.returncode == 2 and "stale" in r.stdout
    assert 'pft_imagescan_up{host="validator"} 0' in (tf / "pft_imagescan_validator.prom").read_text()


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write a 0555 directory")
def test_shell_scan_unwritable_cache_named(tmp_path, exec_dir):
    env, tf, cache = shell_env(tmp_path, [("deb:1", "1" * 64, debian_image())], exec_dir)
    (cache / "inv").mkdir()
    (cache / "inv").chmod(0o555)
    try:
        r = run(["scan", "--no-fetch"], env)
    finally:
        (cache / "inv").chmod(0o755)
    assert r.returncode == 2 and "is not writable" in r.stdout, r.stdout
    assert 'pft_imagescan_up{host="validator"} 0' in (tf / "pft_imagescan_validator.prom").read_text()


def test_shell_bundle_report_reproduces(tmp_path, exec_dir):
    env, _tf, cache = shell_env(tmp_path, [("go:1", "2" * 64, go_only_image())], exec_dir)
    b = tmp_path / "bundle"
    r = run(["scan", "--no-fetch", "--bundle", str(b)], env)
    assert r.returncode == 0, r.stdout + r.stderr
    for f in ("vulndb.zip", "debian-tracker.json", "oci.com.ubuntu.noble.usn.oval.xml.bz2"):
        (b / "feeds" / f).write_bytes((cache / "feeds" / f).read_bytes())
    env2 = dict(env, PFT_IS_DOCKER="/nonexistent")  # report never needs docker
    a = run(["report", "--bundle", str(b), "--public"], env2)
    c = run(["report", "--bundle", str(b), "--public"], env2)
    assert a.returncode == 0 and a.stdout == c.stdout and "GO-0000-0004" not in a.stdout


def test_validate_rejects_foreign_samples(tmp_path, exec_dir):
    env, _tf, _ = shell_env(tmp_path, [("go:1", "2" * 64, go_only_image())], exec_dir)
    bad = tmp_path / "bad.prom"
    bad.write_text('pft_imagescan_up{host="sentry"} 1\npft_other{host="sentry"} 1\n')
    r = run(["validate", str(bad), "sentry"], env)
    assert r.returncode == 2 and "not a pft_imagescan_ sample" in r.stdout


def test_fetch_refuses_bad_download(tmp_path, exec_dir):
    env, _tf, cache = shell_env(tmp_path, [("go:1", "2" * 64, go_only_image())], exec_dir)
    curl = exec_dir / "curl"
    # a "200" whose body is a truncated bzip2 stream must not replace the pinned feed
    curl.write_text("#!/usr/bin/env bash\nout=''; hdr=''\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) out=\"$2\"; shift;; "
                    "-D) hdr=\"$2\"; shift;; esac; shift; done\nprintf 'BZh91AY&SY' > \"$out\"; : > \"$hdr\"; printf 200\n")
    curl.chmod(0o755)
    conf = Path(env["PFT_IS_CONF"])
    conf.write_text(conf.read_text() + "FEEDS=ubuntu-noble\n")
    before = (cache / "feeds" / "feeds.json").read_text()
    r = run(["fetch"], dict(env, PFT_IS_CURL=str(curl)))
    assert r.returncode == 1 and "REFUSED" in r.stdout
    assert (cache / "feeds" / "feeds.json").read_text() == before
