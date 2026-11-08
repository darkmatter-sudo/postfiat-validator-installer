#!/usr/bin/env python3
"""Offline tests for backupwatch_lib.py check: synthetic pft-backup archives with the exact layout pft-backup.sh
writes (NAME/files/..., NAME/firewall/..., META.txt, MANIFEST.sha256, sidecar NAME.tar.gz.sha256).

Run: TEST_TMPDIR=~/.cache python3 -u backupwatch/tests/test_backupwatch.py   (stdlib + gpg; /tmp is noexec on the
hosts, so the temp dir defaults to ~/.cache). Prints one PASS/FAIL line per check and 'RESULT: PASS|FAIL (n checks)'.
BW_DIR points the suite at a mutant copy (tests/mutate.py).
"""

import calendar
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BW = os.environ.get("BW_DIR") or os.path.dirname(HERE)
HELPER = os.path.join(BW, "backupwatch_lib.py")
SCRIPT = os.path.join(BW, "pft-backupwatch.sh")
TMP_BASE = os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache")
NOW = calendar.timegm(time.strptime("20261108T120000Z", "%Y%m%dT%H%M%SZ"))

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(
        f"{'PASS' if cond else 'FAIL'} {name}{'' if cond else ' :: ' + str(detail)[:400]}",
        flush=True,
    )


CFG = (
    "[server]\nport_peer\n\n[node_seed]\nsSECRETSEEDxxxxxxxxxxxxxxxxx\n\n[peer_private]\n1\n"
    "\n[validators_file]\nvalidators.txt\n"
)
ENV = "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml\n"


def strip(text):
    out, skip = [], False
    for line in text.splitlines(keepends=True):
        if line.startswith("["):
            skip = line.startswith("[node_seed]")
        if not skip:
            out.append(line)
    return "".join(out)


def live_tree(root):
    """A fake host: ROOT/opt/postfiatd, ROOT/etc/systemd/system, and a config volume dir ROOT/cfgvol."""
    files = {
        "opt/postfiatd/docker-compose.yml": "services: {}\n",
        "opt/postfiatd/docker-compose.override.yml": "services: {}\n",
        "opt/postfiatd/docker-compose.confine.yml": "services: {}\n",
        "opt/postfiatd/.env": ENV,
        "etc/systemd/system/pft-exporter.service": "[Service]\n",
        "cfgvol/postfiatd.cfg": CFG,
        "cfgvol/validators.txt": "[validators]\n",
    }
    for rel, body in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(body)


def members_for(root, *, drop=(), extra=None, firewall_error=False, pad=6000):
    m = {
        "files/etc/postfiatd/postfiatd.cfg": strip(CFG).encode(),
        "files/etc/postfiatd/validators.txt": b"[validators]\n",
        "files/opt/postfiatd/docker-compose.yml": b"services: {}\n",
        "files/opt/postfiatd/docker-compose.override.yml": b"services: {}\n",
        "files/opt/postfiatd/docker-compose.confine.yml": b"services: {}\n",
        "files/opt/postfiatd/.env": ENV.encode(),
        "files/etc/systemd/system/pft-exporter.service": b"[Service]\n",
        "files/units-enabled.txt": b"pft-exporter.service enabled\n",
        "firewall/user.rules": b"*filter\n"
        + os.urandom(pad).hex().encode(),  # incompressible: realistic size
        "firewall/ufw-status.txt": b"ERROR: Couldn't determine iptables version\n"
        if firewall_error
        else b"Status: active\n",
        "firewall/docker-user.rules": b"-N DOCKER-USER\n",
        "META.txt": b"created_utc=x\nsecrets_included=0\n",
    }
    for d in drop:
        m.pop(d, None)
    return m


def write_archive(
    d, ts, members, *, manifest_skip=(), manifest_extra=(), tamper=None, gpg_pass=None
):
    """pft-backup layout. manifest_skip: members left out of the manifest (= unlisted extra file);
    tamper: member whose bytes change AFTER the manifest is computed."""
    name = f"pft-backup-{ts}"
    lines = [
        f"{hashlib.sha256(b).hexdigest()}  {p}"
        for p, b in sorted(members.items())
        if p not in manifest_skip
    ]
    lines += [f"{'0' * 64}  {p}" for p in manifest_extra]
    body = dict(members)
    body["MANIFEST.sha256"] = ("\n".join(lines) + "\n").encode()
    if tamper:
        body[tamper] = body[tamper] + b"x"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for p, b in sorted(body.items()):
            ti = tarfile.TarInfo(f"{name}/{p}")
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
    data = buf.getvalue()
    out = os.path.join(d, f"{name}.tar.gz")
    with open(out, "wb") as fh:
        fh.write(data)
    if gpg_pass is not None:
        home = tempfile.mkdtemp(dir=TMP_BASE)
        pf = os.path.join(home, "pass")
        with open(pf, "w") as fh:
            fh.write(gpg_pass)
        subprocess.run(
            [
                "gpg",
                "--homedir",
                home,
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--passphrase-file",
                pf,
                "-o",
                out + ".gpg",
                out,
            ],
            check=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
        )
        shutil.rmtree(home)
        os.remove(out)
        out += ".gpg"
    with open(out, "rb") as fh:
        h = hashlib.sha256(fh.read()).hexdigest()
    with open(out + ".sha256", "w") as fh:
        fh.write(f"{h}  {os.path.basename(out)}\n")
    return out


def run(bdir, root, *extra, now=NOW):
    cmd = [
        sys.executable,
        HELPER,
        "check",
        "--dir",
        bdir,
        "--now",
        str(now),
        "--root",
        root,
        "--cfg-dir",
        os.path.join(root, "cfgvol"),
        "--scratch",
        TMP_BASE,
        *extra,
    ]
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    try:
        j = json.loads(p.stdout)
    except ValueError:
        j = {"checks": [], "_raw": p.stdout + p.stderr}
    return p.returncode, j


def state(j, name):
    for c in j.get("checks", []):
        if c["name"] == name:
            return c["state"], c["detail"]
    return None, ""


class Case:
    def __init__(self, label):
        self.label = label
        self.base = tempfile.mkdtemp(prefix="bwtest.", dir=TMP_BASE)
        self.bdir = os.path.join(self.base, "backups")
        self.root = os.path.join(self.base, "root")
        os.makedirs(self.bdir)
        live_tree(self.root)

    def done(self):
        shutil.rmtree(self.base, ignore_errors=True)


def case(label, fn):
    c = Case(label)
    try:
        fn(c)
    except Exception as e:  # noqa: BLE001 (a crash in a case is a failure, never a skip)
        check(f"{label}: no exception", False, repr(e))
    finally:
        c.done()


def t_fresh(c):
    write_archive(c.bdir, "20261107T023000Z", members_for(c.root))
    write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    rc, j = run(c.bdir, c.root)
    check("fresh: rc 0", rc == 0, j)
    check("fresh: worst OK", j.get("worst") == "OK", j)
    for n in ("fresh", "size", "sidecar", "manifest", "content", "drift"):
        check(f"fresh: {n} OK", state(j, n)[0] == "OK", state(j, n))
    check(
        "fresh: newest archive picked",
        j.get("archive") == "pft-backup-20261108T023000Z.tar.gz",
        j.get("archive"),
    )
    check(
        "fresh: secret section never in output",
        "SECRETSEED" not in json.dumps(j),
        "leak",
    )
    check(
        "fresh: drift rows all same",
        j["drift"] and all(r["state"] == "same" for r in j["drift"]),
        j["drift"],
    )
    check(
        "fresh: units-enabled.txt not drift-checked",
        all("units-enabled" not in r["path"] for r in j["drift"]),
        "",
    )


def t_old(c):
    write_archive(c.bdir, "20261107T060000Z", members_for(c.root))  # 30 h before NOW
    rc, j = run(c.bdir, c.root)
    check("old 30h: rc 1", rc == 1, j)
    check("old 30h: fresh WARN", state(j, "fresh")[0] == "WARN", state(j, "fresh"))
    rc, j = run(c.bdir, c.root, now=NOW + 24 * 3600)  # 54 h
    check("old 54h: rc 2", rc == 2, j)
    check("old 54h: fresh FAIL", state(j, "fresh")[0] == "FAIL", state(j, "fresh"))
    rc, j = run(c.bdir, c.root, now=NOW - 4 * 3600 - 1)  # 25 h 59 min 59 s
    check("boundary 26h-1s: fresh OK", state(j, "fresh")[0] == "OK", state(j, "fresh"))
    rc, j = run(c.bdir, c.root, now=NOW - 4 * 3600 + 1)  # 26 h + 1 s
    check(
        "boundary 26h+1s: fresh WARN", state(j, "fresh")[0] == "WARN", state(j, "fresh")
    )


def t_missing(c):
    rc, j = run(c.bdir, c.root)
    check("no archive: rc 2", rc == 2, j)
    check(
        "no archive: fresh FAIL 'no archive'",
        state(j, "fresh") == ("FAIL", "no archive"),
        state(j, "fresh"),
    )
    with open(os.path.join(c.bdir, "pft-backup-junk.tar.gz"), "w") as fh:
        fh.write("x")
    rc, j = run(c.bdir, c.root)
    check(
        "only foreign names: still no archive",
        state(j, "fresh") == ("FAIL", "no archive"),
        state(j, "fresh"),
    )
    rc, j = run(os.path.join(c.base, "nope"), c.root)
    check(
        "dir missing: rc 2 + unreadable",
        rc == 2 and "unreadable" in state(j, "fresh")[1],
        j,
    )


def t_corrupt(c):
    p = write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    with open(p, "r+b") as fh:
        fh.seek(os.path.getsize(p) // 2)
        b = fh.read(1)
        fh.seek(-1, 1)
        fh.write(bytes([b[0] ^ 0xFF]))
    rc, j = run(c.bdir, c.root)
    check("byte flip: rc 2", rc == 2, j)
    check(
        "byte flip: sidecar FAIL mismatch",
        state(j, "sidecar") == ("FAIL", "sha256 mismatch"),
        state(j, "sidecar"),
    )
    check(
        "byte flip: manifest FAIL",
        state(j, "manifest")[0] == "FAIL",
        state(j, "manifest"),
    )
    # regenerated sidecar: only the archive itself can tell
    with open(p, "rb") as fh:
        h = hashlib.sha256(fh.read()).hexdigest()
    with open(p + ".sha256", "w") as fh:
        fh.write(f"{h}  x\n")
    rc, j = run(c.bdir, c.root)
    check(
        "byte flip + new sidecar: sidecar OK",
        state(j, "sidecar")[0] == "OK",
        state(j, "sidecar"),
    )
    check(
        "byte flip + new sidecar: manifest FAIL corrupt",
        state(j, "manifest")[0] == "FAIL",
        state(j, "manifest"),
    )


def t_truncated(c):
    write_archive(c.bdir, "20261107T023000Z", members_for(c.root))
    p = write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    with open(p, "r+b") as fh:
        fh.truncate(os.path.getsize(p) // 3)
    _rc, j = run(c.bdir, c.root)
    check(
        "truncated: size FAIL (< MIN_BYTES)",
        state(j, "size")[0] == "FAIL",
        state(j, "size"),
    )
    check(
        "truncated: manifest FAIL",
        state(j, "manifest")[0] == "FAIL",
        state(j, "manifest"),
    )


def t_size_ratio(c):
    write_archive(c.bdir, "20261107T023000Z", members_for(c.root, pad=6000))
    write_archive(c.bdir, "20261108T023000Z", members_for(c.root, pad=20000))
    rc, j = run(c.bdir, c.root)
    check(
        "size 3x previous: size WARN", state(j, "size")[0] == "WARN", state(j, "size")
    )
    check("size 3x previous: rc 1", rc == 1, j)


def t_sidecar_missing(c):
    p = write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    os.remove(p + ".sha256")
    _rc, j = run(c.bdir, c.root)
    check(
        "no sidecar: sidecar FAIL",
        state(j, "sidecar")[0] == "FAIL",
        state(j, "sidecar"),
    )
    check(
        "no sidecar: manifest still checked OK",
        state(j, "manifest")[0] == "OK",
        state(j, "manifest"),
    )


def t_extra(c):
    m = members_for(c.root)
    m["files/etc/cron.d/evil"] = b"* * * * * root sh\n"
    write_archive(
        c.bdir, "20261108T023000Z", m, manifest_skip=("files/etc/cron.d/evil",)
    )
    _rc, j = run(c.bdir, c.root)
    st, d = state(j, "manifest")
    check("extra unlisted member: manifest FAIL", st == "FAIL", (st, d))
    check(
        "extra unlisted member: names it",
        "unlisted member: files/etc/cron.d/evil" in d,
        d,
    )
    check(
        "extra unlisted member: sidecar OK (the archive is what was written)",
        state(j, "sidecar")[0] == "OK",
        j,
    )


def t_listed_absent_and_tamper(c):
    write_archive(
        c.bdir,
        "20261108T023000Z",
        members_for(c.root),
        manifest_extra=("files/etc/gone.conf",),
    )
    _rc, j = run(c.bdir, c.root)
    check(
        "listed but absent: names it",
        "listed but absent: files/etc/gone.conf" in state(j, "manifest")[1],
        j,
    )
    c2 = os.path.join(c.base, "b2")
    os.makedirs(c2)
    write_archive(
        c2, "20261108T023000Z", members_for(c.root), tamper="files/opt/postfiatd/.env"
    )
    _rc, j = run(c2, c.root)
    check(
        "member edited after manifest: mismatch named",
        "sha256 mismatch: files/opt/postfiatd/.env" in state(j, "manifest")[1],
        state(j, "manifest"),
    )


def t_content(c):
    write_archive(
        c.bdir,
        "20261108T023000Z",
        members_for(c.root, drop=("files/opt/postfiatd/docker-compose.confine.yml",)),
    )
    rc, j = run(c.bdir, c.root)
    st, d = state(j, "content")
    check(
        "COMPOSE_FILE member missing: content FAIL",
        st == "FAIL" and "docker-compose.confine.yml" in d,
        (st, d),
    )
    check(
        "COMPOSE_FILE member missing: manifest OK (consistent archive)",
        state(j, "manifest")[0] == "OK",
        j,
    )
    c2 = os.path.join(c.base, "b2")
    os.makedirs(c2)
    write_archive(
        c2,
        "20261108T023000Z",
        members_for(c.root, drop=("files/etc/postfiatd/postfiatd.cfg",)),
    )
    rc, j = run(c2, c.root)
    check(
        "postfiatd.cfg missing: content FAIL",
        state(j, "content")[0] == "FAIL",
        state(j, "content"),
    )
    c3 = os.path.join(c.base, "b3")
    os.makedirs(c3)
    write_archive(
        c3,
        "20261108T023000Z",
        members_for(c.root, drop=("firewall/docker-user.rules",), firewall_error=True),
    )
    rc, j = run(c3, c.root)
    st, d = state(j, "content")
    check("firewall reference incomplete: content WARN", st == "WARN", (st, d))
    check(
        "firewall: names missing docker-user.rules", "docker-user.rules missing" in d, d
    )
    check(
        "firewall: names tool error in ufw-status",
        "ufw-status.txt holds a tool error" in d,
        d,
    )
    check("firewall reference incomplete: rc 1", rc == 1, j)


def t_drift(c):
    write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    with open(
        os.path.join(c.root, "opt/postfiatd/docker-compose.override.yml"), "a"
    ) as fh:
        fh.write("# edited\n")
    os.remove(os.path.join(c.root, "etc/systemd/system/pft-exporter.service"))
    rc, j = run(c.bdir, c.root)
    st, d = state(j, "drift")
    check("drift: WARN", st == "WARN", (st, d))
    check(
        "drift: changed file named",
        "/opt/postfiatd/docker-compose.override.yml changed" in d,
        d,
    )
    check(
        "drift: gone file named",
        "/etc/systemd/system/pft-exporter.service gone" in d,
        d,
    )
    check("drift: rc 1", rc == 1, j)
    rows = {r["path"]: r["state"] for r in j["drift"]}
    check(
        "drift: cfg (secret section stripped on the live side) is same",
        rows.get("/etc/postfiatd/postfiatd.cfg") == "same",
        rows,
    )


def t_cfg_drift(c):
    write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    with open(os.path.join(c.root, "cfgvol/postfiatd.cfg"), "a") as fh:
        fh.write("\n[ips_fixed]\npeer.example 2559\n")
    _rc, j = run(c.bdir, c.root)
    check(
        "cfg drift: postfiatd.cfg changed",
        "/etc/postfiatd/postfiatd.cfg changed" in state(j, "drift")[1],
        j,
    )
    # a secret-only change is NOT drift (the archive never holds secrets by default)
    c2 = Case("cfg2")
    try:
        write_archive(c2.bdir, "20261108T023000Z", members_for(c2.root))
        p = os.path.join(c2.root, "cfgvol/postfiatd.cfg")
        with open(p) as fh:
            s = fh.read()
        with open(p, "w") as fh:
            fh.write(
                s.replace("sSECRETSEEDxxxxxxxxxxxxxxxxx", "sOTHERSEEDyyyyyyyyyyyyyyyyy")
            )
        _rc, j = run(c2.bdir, c2.root)
        check(
            "secret-only cfg change: drift OK",
            state(j, "drift")[0] == "OK",
            state(j, "drift"),
        )
    finally:
        c2.done()
    _rc, j = run(c.bdir, c.root, "--cfg-dir", "")
    rows = {r["path"]: r["state"] for r in j["drift"]}
    check(
        "no cfg dir: cfg files unchecked (WARN), not same",
        rows.get("/etc/postfiatd/postfiatd.cfg") == "unchecked"
        and state(j, "drift")[0] == "WARN",
        rows,
    )


def t_gpg(c):
    pf = os.path.join(c.base, "pass")
    with open(pf, "w") as fh:
        fh.write("correct horse")
    write_archive(
        c.bdir, "20261108T023000Z", members_for(c.root), gpg_pass="correct horse"
    )
    rc, j = run(c.bdir, c.root, "--passfile", pf)
    check("gpg right passphrase: manifest OK", state(j, "manifest")[0] == "OK", j)
    check("gpg right passphrase: rc 0", rc == 0, j)
    bad = os.path.join(c.base, "badpass")
    with open(bad, "w") as fh:
        fh.write("wrong horse")
    rc, j = run(c.bdir, c.root, "--passfile", bad)
    check("gpg wrong passphrase: rc 2", rc == 2, j)
    check(
        "gpg wrong passphrase: manifest FAIL 'wrong passphrase'",
        "wrong passphrase" in state(j, "manifest")[1],
        j,
    )
    check("gpg wrong passphrase: sidecar still OK", state(j, "sidecar")[0] == "OK", j)
    rc, j = run(c.bdir, c.root)
    check(
        "gpg no passfile: manifest FAIL named",
        "no PASSFILE" in state(j, "manifest")[1],
        j,
    )
    left = [n for n in os.listdir(TMP_BASE) if n.startswith("pft-bw-gpg.")]
    check("gpg scratch home removed", not left, left)


def t_usage(c):
    p = subprocess.run(
        [sys.executable, HELPER, "check", "--dir", c.bdir],
        capture_output=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    check("usage: missing --now -> rc 3", p.returncode == 3, p.returncode)
    rc, _j = run(c.bdir, c.root, "--max-age-h", "60", "--fail-age-h", "50")
    check("usage: fail-age < max-age -> rc 3", rc == 3, rc)


def wrap(c, *args, env=None, docker_src=None):
    """Run pft-backupwatch.sh with a stub docker that answers inspect with DOCKER_SRC (or fails)."""
    stub = os.path.join(c.base, "docker")
    with open(stub, "w") as fh:
        if docker_src is None:
            fh.write("#!/bin/sh\necho 'Error: No such object' >&2\nexit 1\n")
        else:
            fh.write(
                f"#!/bin/sh\n[ \"$1\" = inspect ] || exit 9\necho '{docker_src}'\n"
            )
    os.chmod(stub, 0o755)
    e = dict(os.environ)
    e.update(
        PFT_BW_HELPER=HELPER,
        PFT_BW_NOW=str(NOW),
        PFT_BW_DOCKER=stub,
        PFT_BW_ROOT=c.root,
        PFT_BW_CONF=os.path.join(c.base, "no.conf"),
        BACKUP_DIR=c.bdir,
        SCRATCH=TMP_BASE,
    )
    e.update(env or {})
    p = subprocess.run(
        ["bash", SCRIPT, *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=e,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr


def t_wrapper(c):
    write_archive(c.bdir, "20261107T023000Z", members_for(c.root))
    write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    cfg = os.path.join(c.root, "cfgvol")
    # stub self-check: the stub, not a real docker, answered (lesson: stubs in a noexec dir fall through)
    rc, out, err = wrap(c, "check", docker_src=cfg)
    check("wrapper: rc 0 on a clean archive", rc == 0, (rc, out, err))
    check("wrapper: RESULT: OK line", "RESULT: OK - 0 finding(s)" in out, out)
    check(
        "wrapper: one line per check (6)",
        sum(1 for x in out.splitlines() if x.startswith("  [")) == 6,
        out,
    )
    check(
        "wrapper: stub docker answered (drift compared the cfg volume)",
        "[OK  ] drift" in out,
        out,
    )
    rc, out, err = wrap(c, "check", "--json", docker_src=cfg)
    try:
        j = json.loads(out)
    except ValueError:
        j = {}
    check(
        "wrapper --json: helper JSON passed through, worst OK",
        j.get("worst") == "OK" and rc == 0,
        (rc, out),
    )
    rc, out, err = wrap(c, "check", docker_src=None)
    check(
        "wrapper: docker inspect fails -> cfg files unchecked -> WARN rc 1",
        rc == 1 and "unchecked" in out,
        (rc, out),
    )
    rc, out, err = wrap(
        c, "check", docker_src=cfg, env={"PFT_BW_NOW": str(NOW + 30 * 3600)}
    )
    check(
        "wrapper: 39 h old -> rc 1 + fresh WARN",
        rc == 1 and "[WARN] fresh" in out,
        (rc, out),
    )
    rc, out, err = wrap(
        c, "check", docker_src=cfg, env={"PFT_BW_NOW": str(NOW + 60 * 3600)}
    )
    check(
        "wrapper: 69 h old -> rc 2 + RESULT: FAIL",
        rc == 2 and "RESULT: FAIL" in out,
        (rc, out),
    )
    conf = os.path.join(c.base, "user.conf")
    with open(conf, "w") as fh:
        fh.write("MAX_AGE_H=1\n")
    rc, out, err = wrap(c, "check", docker_src=cfg, env={"PFT_BW_CONF": conf})
    check(
        "wrapper: a conf not owned by root is not sourced",
        rc == 0 and "[OK  ] fresh" in out,
        (rc, out),
    )
    rc, out, err = wrap(c, "check", docker_src=cfg, env={"MAX_AGE_H": "x"})
    check(
        "wrapper: bad MAX_AGE_H -> rc 3",
        rc == 3 and "must be integers" in err,
        (rc, err),
    )
    rc, out, err = wrap(c, "check", docker_src=cfg, env={"SIZE_HI": "two"})
    check("wrapper: bad SIZE_HI -> rc 3", rc == 3, (rc, err))
    rc, out, err = wrap(
        c,
        "check",
        docker_src=cfg,
        env={"PFT_BW_HELPER": os.path.join(c.base, "nope.py")},
    )
    check(
        "wrapper: missing helper -> rc 3",
        rc == 3 and "helper missing" in err,
        (rc, err),
    )
    rc, out, err = wrap(c, "check", "--bogus", docker_src=cfg)
    check("wrapper: unknown check argument -> rc 3", rc == 3, (rc, err))
    rc, out, err = wrap(c, "frobnicate", docker_src=cfg)
    check("wrapper: unknown command -> rc 3", rc == 3, (rc, err))
    rc, out, err = wrap(c, "version", docker_src=cfg)
    check("wrapper: version", rc == 0 and out.startswith("pft-backupwatch "), out)


def main():
    os.makedirs(TMP_BASE, exist_ok=True)
    for label, fn in [
        ("fresh", t_fresh),
        ("old", t_old),
        ("missing", t_missing),
        ("corrupt", t_corrupt),
        ("truncated", t_truncated),
        ("size", t_size_ratio),
        ("sidecar", t_sidecar_missing),
        ("extra", t_extra),
        ("absent", t_listed_absent_and_tamper),
        ("content", t_content),
        ("drift", t_drift),
        ("cfgdrift", t_cfg_drift),
        ("gpg", t_gpg),
        ("usage", t_usage),
        ("wrapper", t_wrapper),
    ]:
        case(label, fn)
    ok = all(results)
    print(
        f"RESULT: {'PASS' if ok else 'FAIL'} ({len(results)} checks, {results.count(False)} failed)"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
