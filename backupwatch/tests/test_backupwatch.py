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


def t_outside_stem(c):
    """A member outside NAME/ (path traversal or a foreign archive) makes the archive unreadable, whatever else it holds."""
    a = write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    with open(a, "rb") as fh:
        data = fh.read()
    buf = io.BytesIO()
    with (
        tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as src,
        tarfile.open(fileobj=buf, mode="w:gz") as dst,
    ):
        for m in src:
            dst.addfile(m, src.extractfile(m) if m.isfile() else None)
        ti = tarfile.TarInfo("other/etc/cron.d/x")
        ti.size = 2
        dst.addfile(ti, io.BytesIO(b"x\n"))
    with open(a, "wb") as fh:
        fh.write(buf.getvalue())
    with open(a + ".sha256", "w") as fh:
        fh.write(
            f"{hashlib.sha256(buf.getvalue()).hexdigest()}  {os.path.basename(a)}\n"
        )
    rc, j = run(c.bdir, c.root)
    st, detail = state(j, "manifest")
    check(
        "member outside NAME/: manifest FAIL naming it, rc 2",
        rc == 2
        and st == "FAIL"
        and "outside" in detail
        and "other/etc/cron.d/x" in detail,
        (rc, j),
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
            # answers only the exact inspect the wrapper must send (container + the /etc/postfiatd mount)
            fh.write(
                '#!/bin/sh\n[ "$1" = inspect ] && [ "$2" = postfiatd ] || exit 9\n'
                'case "$4" in *\'.Destination "/etc/postfiatd"\'*) ;; *) exit 8 ;; esac\n'
                f"echo '{docker_src}'\n"
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


def readf(path):
    try:
        with open(path) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def agekey(path):
    subprocess.run(
        ["age-keygen", "-o", path],
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    p = subprocess.run(
        ["age-keygen", "-y", path],
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return p.stdout.strip()


def peer_setup(c, keep=3, max_bytes=None):
    """A fake sentry: PEER_SSH = peer.sh, which runs this same script's `serve` with the peer's own env."""
    pdir = os.path.join(c.base, "peer")
    os.makedirs(pdir)
    rcpt = agekey(os.path.join(pdir, "age.key"))
    sh = os.path.join(c.base, "peer.sh")
    extra = f" REPLICA_MAX_BYTES={max_bytes}" if max_bytes else ""
    with open(sh, "w") as fh:
        fh.write(
            "#!/bin/sh\n"
            f'echo "$*" >> "{c.base}/peer-calls"\n'
            f'[ -e "{c.base}/peer-down" ] && exit 255\n'
            '[ "$1" = pft-backupwatch ] || exit 9\nshift\n'
            f"exec env PFT_BW_CONF=/nonexistent REPLICA_DIR={pdir}/replicas REPLICA_IDENTITY={pdir}/age.key "
            f'REPLICA_KEEP={keep}{extra} bash {SCRIPT} "$@"\n'
        )
    os.chmod(sh, 0o755)
    return rcpt, sh, os.path.join(pdir, "replicas")


def t_replica(c):
    rcpt, sh, rdir = peer_setup(c)
    state = os.path.join(c.base, "state")
    cfg = os.path.join(c.root, "cfgvol")
    env = {"PEER_SSH": sh, "REPLICA_RECIPIENT": rcpt, "STATE_DIR": state}
    write_archive(c.bdir, "20261107T023000Z", members_for(c.root))
    a = write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    n = os.path.basename(a)
    rc, out, err = wrap(c, "replicate", env=env, docker_src=cfg)
    check(
        "replicate: rc 0 + REPLICATED",
        rc == 0 and f"REPLICATED {n} " in out,
        (rc, out, err),
    )
    check(
        "replicate: peer confirmed OK",
        f"peer: RECEIVED {n} " in out and " OK" in out,
        out,
    )
    stored = os.path.join(rdir, n + ".age")
    check(
        "replicate: ciphertext + meta stored on the peer",
        os.path.isfile(stored) and os.path.isfile(stored + ".meta"),
        rdir,
    )
    with open(stored, "rb") as fh:
        head = fh.read(22)
    check(
        "replicate: peer holds age ciphertext, not the tar.gz",
        head.startswith(b"age-encryption.org/v1"),
        head,
    )
    check(
        "replicate: replica dir is 0700",
        os.path.isdir(rdir) and (os.stat(rdir).st_mode & 0o777) == 0o700,
        oct(os.stat(rdir).st_mode),
    )
    with open(os.path.join(state, "replica.tsv")) as fh:
        rec = fh.read().split("\n")[0].split("\t")
    with open(stored, "rb") as fh:
        csha = hashlib.sha256(fh.read()).hexdigest()
    with open(a + ".sha256") as fh:
        plain = fh.read().split()[0]
    check(
        "replicate: local record = name, peer ciphertext sha256, sidecar sha256",
        rec[:3] == [n, csha, plain],
        rec,
    )
    left = [x for x in os.listdir(TMP_BASE) if x.startswith("pft-bw-")]
    check("replicate: no scratch left (ciphertext removed)", not left, left)
    check(
        "replicate: no partial file left on the peer",
        not [x for x in os.listdir(rdir) if x.startswith(".in.")],
        os.listdir(rdir),
    )

    rc, out, err = wrap(c, "check", "--offhost", env=env, docker_src=cfg)
    check(
        "check --offhost: rc 0 + offhost OK",
        rc == 0 and "[OK  ] offhost" in out,
        (rc, out, err),
    )
    rc, out, err = wrap(c, "check", env=dict(env, OFFHOST="1"), docker_src=cfg)
    check("OFFHOST=1 in conf/env = --offhost", "offhost" in out and rc == 0, (rc, out))
    rc, out, err = wrap(c, "check", env=env, docker_src=cfg)
    check(
        "check without --offhost: no offhost line, peer not called for it",
        "offhost" not in out,
        out,
    )

    # a newer local archive that is not replicated yet -> WARN
    write_archive(c.bdir, "20261108T090000Z", members_for(c.root))
    rc, out, err = wrap(c, "check", "--offhost", env=env, docker_src=cfg)
    check(
        "newer archive not replicated: offhost WARN",
        rc == 1 and "[WARN] offhost" in out and n[:-7] in out,
        (rc, out),
    )
    # replicate twice more -> keep 3 on the peer, oldest pruned
    rc, out, err = wrap(c, "replicate", env=env, docker_src=cfg)
    write_archive(c.bdir, "20261108T100000Z", members_for(c.root))
    rc2, _out2, _err2 = wrap(c, "replicate", env=env, docker_src=cfg)
    write_archive(c.bdir, "20261108T110000Z", members_for(c.root))
    rc3, out3, _err3 = wrap(c, "replicate", env=env, docker_src=cfg)
    ages = sorted(x for x in os.listdir(rdir) if x.endswith(".age"))
    check(
        "prune: REPLICA_KEEP=3 -> 3 replicas kept",
        len(ages) == 3 and rc == rc2 == rc3 == 0,
        (ages, out3),
    )
    check(
        "prune: the oldest was pruned (PRUNED line, meta gone)",
        f"PRUNED {n}" in out3 and not os.path.exists(stored + ".meta"),
        out3,
    )

    newest = max(ages)
    path = os.path.join(rdir, newest)
    with open(path, "r+b") as fh:
        fh.seek(200)
        b = fh.read(1)
        fh.seek(200)
        fh.write(bytes([b[0] ^ 1]))
    rc, out, err = wrap(c, "check", "--offhost", env=env, docker_src=cfg)
    check(
        "tampered replica on the peer: offhost FAIL SHA_MISMATCH",
        rc == 2 and "[FAIL] offhost" in out and "SHA_MISMATCH" in out,
        (rc, out),
    )
    # tamper the meta too (an attacker on the peer re-hashes): the local record still disagrees
    meta = path + ".meta"
    with open(path, "rb") as fh:
        newsha = hashlib.sha256(fh.read()).hexdigest()
    with open(meta) as fh:
        m = fh.read()
    with open(meta, "w") as fh:
        fh.write(
            "\n".join(
                f"cipher_sha256={newsha}" if x.startswith("cipher_sha256=") else x
                for x in m.split("\n")
            )
        )
    rc, out, err = wrap(c, "check", "--offhost", env=env, docker_src=cfg)
    check(
        "tampered replica + re-hashed meta: FAIL vs the local record",
        rc == 2 and "differs from the one recorded" in out,
        (rc, out),
    )
    os.rename(
        os.path.join(state, "replica.tsv"), os.path.join(state, "replica.tsv.bak")
    )
    rc, out, err = wrap(c, "check", "--offhost", env=env, docker_src=cfg)
    check(
        "no local replica record: offhost FAIL",
        rc == 2 and "not recorded locally" in out,
        (rc, out),
    )
    os.rename(
        os.path.join(state, "replica.tsv.bak"), os.path.join(state, "replica.tsv")
    )

    open(os.path.join(c.base, "peer-down"), "w").close()
    rc, out, err = wrap(c, "check", "--offhost", env=env, docker_src=cfg)
    check(
        "peer down (ssh rc 255): offhost FAIL unreachable",
        rc == 2 and "peer unreachable (PEER_DOWN 255)" in out,
        (rc, out),
    )
    rc, out, err = wrap(c, "replicate", env=env, docker_src=cfg)
    check(
        "peer down: replicate rc 2, not recorded",
        rc == 2 and "did not confirm" in err,
        (rc, out, err),
    )
    os.remove(os.path.join(c.base, "peer-down"))


def t_replica_refusals(c):
    rcpt, sh, rdir = peer_setup(c, max_bytes=100000)
    other = agekey(os.path.join(c.base, "other.key"))
    state = os.path.join(c.base, "state")
    cfg = os.path.join(c.root, "cfgvol")
    env = {"PEER_SSH": sh, "REPLICA_RECIPIENT": other, "STATE_DIR": state}
    a = write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    n = os.path.basename(a)
    rc, out, err = wrap(c, "replicate", env=env, docker_src=cfg)
    check(
        "wrong recipient: peer cannot decrypt -> DECRYPT_MISMATCH, rc 2",
        rc == 2 and "DECRYPT_MISMATCH" in out,
        (rc, out, err),
    )
    check(
        "wrong recipient: nothing stored, no partial file",
        not os.path.isdir(rdir) or not os.listdir(rdir),
        os.listdir(rdir) if os.path.isdir(rdir) else "",
    )
    check(
        "wrong recipient: nothing recorded locally",
        not os.path.exists(os.path.join(state, "replica.tsv")),
        "recorded",
    )
    env["REPLICA_RECIPIENT"] = rcpt
    with open(a + ".sha256", "w") as fh:
        fh.write("0" * 64 + "  x\n")
    calls = os.path.join(c.base, "peer-calls")
    before = readf(calls)
    rc, out, err = wrap(c, "replicate", env=env, docker_src=cfg)
    after = readf(calls)
    check(
        "archive != sidecar: replicate refused rc 2 before any peer call",
        rc == 2 and "does not match its sidecar" in err and before == after,
        (rc, err),
    )
    with open(a, "rb") as fh:
        good = hashlib.sha256(fh.read()).hexdigest()
    with open(a + ".sha256", "w") as fh:
        fh.write(f"{good}  {n}\n")
    rc, out, err = wrap(
        c, "replicate", env=dict(env, REPLICA_RECIPIENT="age1short"), docker_src=cfg
    )
    check(
        "malformed recipient: rc 3", rc == 3 and "REPLICA_RECIPIENT" in err, (rc, err)
    )
    rc, out, err = wrap(c, "replicate", env=dict(env, PEER_SSH=""), docker_src=cfg)
    check("no PEER_SSH: rc 3", rc == 3 and "PEER_SSH" in err, (rc, err))

    def serve(*args, data=b""):
        e = dict(
            os.environ,
            PFT_BW_CONF="/nonexistent",
            REPLICA_DIR=rdir,
            REPLICA_IDENTITY=os.path.join(c.base, "peer", "age.key"),
            REPLICA_MAX_BYTES="100000",
        )
        p = subprocess.run(
            ["bash", SCRIPT, "serve", *args],
            input=data,
            capture_output=True,
            timeout=60,
            env=e,
            check=False,
        )
        return p.returncode, p.stdout.decode(), p.stderr.decode()

    rc, out, err = serve("receive", n, good, "f" * 64, data=b"not the ciphertext")
    check(
        "serve receive: forged CIPHER_SHA -> SHA_MISMATCH rc 2",
        rc == 2 and "SHA_MISMATCH" in out,
        (rc, out, err),
    )
    rc, out, err = serve("receive", n, good, "f" * 64, data=os.urandom(100001))
    check(
        "serve receive: over REPLICA_MAX_BYTES -> TOO_BIG rc 2",
        rc == 2 and "TOO_BIG" in out,
        (rc, out, err),
    )
    check(
        "serve receive refusals: nothing stored",
        not [x for x in os.listdir(rdir) if not x.startswith("x")],
        os.listdir(rdir),
    )
    rc, out, err = serve("receive", "../../etc/x.tar.gz", good, good)
    check(
        "serve receive: name outside the pft-backup pattern -> rc 3", rc == 3, (rc, err)
    )
    rc, out, err = serve("verify", "pft-backup-20990101T000000Z.tar.gz")
    check(
        "serve verify: missing replica -> MISSING rc 2",
        rc == 2 and "MISSING" in out,
        (rc, out),
    )
    rc, out, err = serve("status")
    check(
        "serve status: empty store -> END only",
        rc == 0 and out.strip() == "END",
        (rc, out),
    )
    rc, out, err = serve("shell", "id")
    check("serve: unknown verb -> rc 3", rc == 3, (rc, err))


def prom_samples(text):
    """{'name{labels}': value} for every sample line."""
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            k, v = line.rsplit(" ", 1)
            out[k] = float(v)
    return out


def helper(args, stdin):
    p = subprocess.run(
        [sys.executable, HELPER, *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return p.returncode, p.stdout, p.stderr


def t_metrics(c):
    ds = os.path.join(c.base, "drift.since")
    j = {
        "archive": "pft-backup-20261108T023000Z.tar.gz",
        "age_s": 34200,
        "bytes": 9000,
        "checks": [
            {"name": "fresh", "state": "OK", "detail": ""},
            {"name": "manifest", "state": "FAIL", "detail": ""},
            {"name": "drift", "state": "WARN", "detail": ""},
        ],
        "drift": [
            {"path": "/a", "state": "changed"},
            {"path": "/b", "state": "same"},
            {"path": "/c", "state": "gone"},
        ],
        "worst": "FAIL",
    }
    base = [
        "metrics",
        "--host",
        "validator",
        "--drift-state",
        ds,
        "--drift-grace-h",
        "30",
    ]
    rc, out, err = helper(base + ["--now", str(NOW)], json.dumps(j))
    m = prom_samples(out)
    check(
        "metrics: rc 0, up 1, collect timestamp = now",
        rc == 0
        and m.get('pft_backupwatch_up{host="validator"}') == 1
        and m.get('pft_backupwatch_collect_timestamp_seconds{host="validator"}') == NOW,
        (rc, out, err),
    )
    check(
        "metrics: check_state 0/2/1 per check, only checks that ran",
        m.get('pft_backupwatch_check_state{host="validator",check="fresh"}') == 0
        and m.get('pft_backupwatch_check_state{host="validator",check="manifest"}') == 2
        and m.get('pft_backupwatch_check_state{host="validator",check="drift"}') == 1
        and not any("offhost" in k for k in m),
        out,
    )
    check(
        "metrics: archive age + bytes",
        m.get('pft_backupwatch_archive_age_seconds{host="validator"}') == 34200
        and m.get('pft_backupwatch_archive_bytes{host="validator"}') == 9000,
        out,
    )
    check(
        "metrics: drift_files counts changed + gone, not same",
        m.get('pft_backupwatch_drift_files{host="validator"}') == 2,
        out,
    )
    check(
        "metrics: first drift -> since = now, not overdue, state file written",
        m.get('pft_backupwatch_drift_since_timestamp_seconds{host="validator"}') == NOW
        and m.get('pft_backupwatch_drift_overdue{host="validator"}') == 0
        and readf(ds).strip() == str(NOW),
        (out, readf(ds)),
    )
    rc, out, _ = helper(base + ["--now", str(NOW + 30 * 3600)], json.dumps(j))
    m = prom_samples(out)
    check(
        "metrics: drift exactly DRIFT_GRACE_H old -> not overdue, since kept",
        m.get('pft_backupwatch_drift_overdue{host="validator"}') == 0
        and m.get('pft_backupwatch_drift_since_timestamp_seconds{host="validator"}')
        == NOW,
        out,
    )
    rc, out, _ = helper(base + ["--now", str(NOW + 30 * 3600 + 1)], json.dumps(j))
    m = prom_samples(out)
    check(
        "metrics: drift older than DRIFT_GRACE_H -> overdue 1",
        m.get('pft_backupwatch_drift_overdue{host="validator"}') == 1,
        out,
    )
    j2 = dict(j, checks=[{"name": "drift", "state": "OK", "detail": ""}], drift=[])
    rc, out, _ = helper(base + ["--now", str(NOW + 31 * 3600)], json.dumps(j2))
    m = prom_samples(out)
    check(
        "metrics: drift OK again -> since 0, overdue 0, state file removed",
        m.get('pft_backupwatch_drift_since_timestamp_seconds{host="validator"}') == 0
        and m.get('pft_backupwatch_drift_overdue{host="validator"}') == 0
        and not os.path.exists(ds),
        out,
    )
    with open(ds, "w") as fh:
        fh.write(f"{NOW + 99999}\n")
    rc, out, _ = helper(base + ["--now", str(NOW)], json.dumps(j))
    m = prom_samples(out)
    check(
        "metrics: a future/garbled since is reset to now",
        m.get('pft_backupwatch_drift_since_timestamp_seconds{host="validator"}') == NOW,
        out,
    )
    rc, out, _ = helper(
        base + ["--now", str(NOW), "--drift-grace-h", "0"], json.dumps(j)
    )
    rc, out, _ = helper(
        base + ["--now", str(NOW + 1), "--drift-grace-h", "0"], json.dumps(j)
    )
    check(
        "metrics: DRIFT_GRACE_H 0 -> overdue one second after first seen",
        prom_samples(out).get('pft_backupwatch_drift_overdue{host="validator"}') == 1,
        out,
    )
    j3 = {
        "archive": None,
        "age_s": None,
        "bytes": None,
        "checks": [{"name": "fresh", "state": "FAIL", "detail": "no archive"}],
        "drift": [],
        "worst": "FAIL",
    }
    rc, out, _ = helper(base + ["--now", str(NOW)], json.dumps(j3))
    m = prom_samples(out)
    check(
        "metrics: no archive -> age/bytes -1, fresh 2, up 1",
        m.get('pft_backupwatch_archive_age_seconds{host="validator"}') == -1
        and m.get('pft_backupwatch_archive_bytes{host="validator"}') == -1
        and m.get('pft_backupwatch_check_state{host="validator",check="fresh"}') == 2
        and m.get('pft_backupwatch_up{host="validator"}') == 1,
        out,
    )
    for bad in ("", "not json", '{"checks": [{"name": "fresh", "state": "MAYBE"}]}'):
        rc, out, _ = helper(base + ["--now", str(NOW)], bad)
        m = prom_samples(out)
        check(
            f"metrics: input {bad[:12]!r} -> up 0 + timestamp, rc 1, no check_state",
            rc == 1
            and m.get('pft_backupwatch_up{host="validator"}') == 0
            and 'pft_backupwatch_collect_timestamp_seconds{host="validator"}' in m
            and not any("check_state" in k for k in m),
            (rc, out),
        )
    rc, out, err = helper(["metrics", "--host", 'x"}', "--now", str(NOW)], "{}")
    check("metrics: label-breaking host -> rc 3", rc == 3 and not out, (rc, out))
    rc, out, err = helper(
        ["metrics", "--host", "validator", "--now", str(NOW), "--drift-grace-h", "-1"],
        "{}",
    )
    check("metrics: negative drift grace -> rc 3", rc == 3, (rc, err))
    # replica role
    sha = "a" * 64
    st = "\n".join(
        [
            f"REPLICA pft-backup-20261107T023000Z.tar.gz {sha} {sha} {NOW - 90000}",
            f"REPLICA pft-backup-20261108T023000Z.tar.gz {sha} {sha} {NOW - 3000}",
            "END",
            "VERIFY pft-backup-20261108T023000Z.tar.gz OK",
        ]
    )
    rc, out, _ = helper(["replica-metrics", "--host", "sentry", "--now", str(NOW)], st)
    m = prom_samples(out)
    check(
        "replica-metrics: up 1, 2 replicas, newest age from its name, verify ok 1",
        rc == 0
        and m.get('pft_backupwatch_up{host="sentry"}') == 1
        and m.get('pft_backupwatch_replicas{host="sentry"}') == 2
        and m.get('pft_backupwatch_replica_newest_age_seconds{host="sentry"}')
        == NOW - calendar.timegm(time.strptime("20261108T023000Z", "%Y%m%dT%H%M%SZ"))
        and m.get('pft_backupwatch_replica_verify_ok{host="sentry"}') == 1,
        out,
    )
    rc, out, _ = helper(
        ["replica-metrics", "--host", "sentry", "--now", str(NOW)],
        st.replace("tar.gz OK", "tar.gz DECRYPT_FAIL"),
    )
    check(
        "replica-metrics: newest does not verify -> verify ok 0",
        prom_samples(out).get('pft_backupwatch_replica_verify_ok{host="sentry"}') == 0,
        out,
    )
    rc, out, _ = helper(
        ["replica-metrics", "--host", "sentry", "--now", str(NOW)],
        st.replace("VERIFY pft-backup-20261108", "VERIFY pft-backup-20261107"),
    )
    check(
        "replica-metrics: an OK for an older replica does not count",
        prom_samples(out).get('pft_backupwatch_replica_verify_ok{host="sentry"}') == 0,
        out,
    )
    rc, out, _ = helper(
        ["replica-metrics", "--host", "sentry", "--now", str(NOW)], "END\n"
    )
    m = prom_samples(out)
    check(
        "replica-metrics: empty store -> 0 replicas, age -1, verify 0",
        m.get('pft_backupwatch_replicas{host="sentry"}') == 0
        and m.get('pft_backupwatch_replica_newest_age_seconds{host="sentry"}') == -1
        and m.get('pft_backupwatch_replica_verify_ok{host="sentry"}') == 0,
        out,
    )
    rc, out, _ = helper(
        ["replica-metrics", "--host", "sentry", "--now", str(NOW)],
        st.replace("END", "x"),
    )
    check(
        "replica-metrics: no END (status failed) -> up 0, rc 1",
        rc == 1 and prom_samples(out).get('pft_backupwatch_up{host="sentry"}') == 0,
        (rc, out),
    )


def t_collect(c):
    write_archive(c.bdir, "20261107T023000Z", members_for(c.root))
    write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    cfg = os.path.join(c.root, "cfgvol")
    tdir = os.path.join(c.base, "textfile")
    os.makedirs(tdir)
    state = os.path.join(c.base, "state")
    env = {"TEXTFILE_DIR": tdir, "STATE_DIR": state}
    rc, out, err = wrap(c, "collect", env=env, docker_src=cfg)
    f = os.path.join(tdir, "pft_backupwatch_validator.prom")
    m = prom_samples(readf(f))
    check(
        "collect: rc 0, textfile written with up 1 and 6 check states all 0",
        rc == 0
        and m.get('pft_backupwatch_up{host="validator"}') == 1
        and sum(1 for k, v in m.items() if "check_state" in k and v == 0) == 6,
        (rc, out, err, readf(f)),
    )
    check(
        "collect: textfile 0644, no temp file left",
        os.path.isfile(f)
        and (os.stat(f).st_mode & 0o777) == 0o644
        and os.listdir(tdir) == ["pft_backupwatch_validator.prom"],
        os.listdir(tdir),
    )
    with open(
        os.path.join(c.root, "opt/postfiatd/docker-compose.override.yml"), "a"
    ) as fh:
        fh.write("# drill\n")
    rc, out, err = wrap(
        c, "collect", "--stdout", env=dict(env, DRIFT_GRACE_H="0"), docker_src=cfg
    )
    m = prom_samples(out)
    check(
        "collect --stdout: live edit -> drift 1, drift_files 1, since = now, stdout only",
        m.get('pft_backupwatch_check_state{host="validator",check="drift"}') == 1
        and m.get('pft_backupwatch_drift_files{host="validator"}') == 1
        and m.get('pft_backupwatch_drift_since_timestamp_seconds{host="validator"}')
        == NOW
        and prom_samples(readf(f)).get(
            'pft_backupwatch_check_state{host="validator",check="drift"}'
        )
        == 0,
        (out, err),
    )
    rc, out, err = wrap(
        c,
        "collect",
        "--stdout",
        env=dict(env, DRIFT_GRACE_H="0", PFT_BW_NOW=str(NOW + 60)),
        docker_src=cfg,
    )
    check(
        "collect: DRIFT_GRACE_H from conf reaches the helper (overdue at grace 0)",
        prom_samples(out).get('pft_backupwatch_drift_overdue{host="validator"}') == 1,
        out,
    )
    rc, out, err = wrap(
        c,
        "collect",
        "--stdout",
        env=dict(env, PFT_BW_NOW=str(NOW + 60)),
        docker_src=cfg,
    )
    check(
        "collect: default DRIFT_GRACE_H 30 -> not overdue after 1 min",
        prom_samples(out).get('pft_backupwatch_drift_overdue{host="validator"}') == 0,
        out,
    )
    rc, out, err = wrap(
        c,
        "collect",
        env=dict(env, PFT_BW_HELPER=os.path.join(c.base, "no-helper.py")),
        docker_src=cfg,
    )
    check(
        "collect: helper missing -> rc 3, old textfile kept",
        rc == 3
        and prom_samples(readf(f)).get('pft_backupwatch_up{host="validator"}') == 1,
        (rc, err),
    )
    rc, out, err = wrap(
        c, "collect", "--stdout", env=dict(env, MAX_AGE_H="x"), docker_src=cfg
    )
    m = prom_samples(out)
    check(
        "collect: check cannot run (bad conf) -> up 0 sample, rc 1",
        rc == 1 and m.get('pft_backupwatch_up{host="validator"}') == 0,
        (rc, out, err),
    )
    for k, v in (("HOST_LABEL", 'v"x'), ("DRIFT_GRACE_H", "-1"), ("ROLE", "both")):
        rc, out, err = wrap(
            c, "collect", "--stdout", env=dict(env, **{k: v}), docker_src=cfg
        )
        check(f"collect: bad {k} -> rc 3", rc == 3 and not out, (rc, out, err))


def t_collect_pull(c):
    rcpt, sh, rdir = peer_setup(c)
    cfg = os.path.join(c.root, "cfgvol")
    state = os.path.join(c.base, "state")
    vt = os.path.join(c.base, "textfile")
    st = os.path.join(c.base, "sentry-textfile")
    os.makedirs(vt)
    os.makedirs(st)
    a = write_archive(c.bdir, "20261108T023000Z", members_for(c.root))
    n = os.path.basename(a)
    env = {
        "PEER_SSH": sh,
        "REPLICA_RECIPIENT": rcpt,
        "STATE_DIR": state,
        "TEXTFILE_DIR": vt,
    }
    rc, out, err = wrap(c, "replicate", env=env, docker_src=cfg)
    check("collect/pull: replicate first rc 0", rc == 0, (rc, out, err))
    peer = {
        "ROLE": "replica",
        "HOST_LABEL": "sentry",
        "REPLICA_DIR": rdir,
        "REPLICA_IDENTITY": os.path.join(c.base, "peer", "age.key"),
        "TEXTFILE_DIR": st,
    }
    rc, out, err = wrap(c, "collect", env=peer)
    m = prom_samples(readf(os.path.join(st, "pft_backupwatch_sentry.prom")))
    check(
        "collect ROLE=replica: 1 replica, newest verifies, up 1",
        rc == 0
        and m.get('pft_backupwatch_replicas{host="sentry"}') == 1
        and m.get('pft_backupwatch_replica_verify_ok{host="sentry"}') == 1
        and m.get('pft_backupwatch_up{host="sentry"}') == 1,
        (rc, out, err, m),
    )
    rc, out, err = wrap(c, "collect", env=dict(env, OFFHOST="1"), docker_src=cfg)
    m = prom_samples(readf(os.path.join(vt, "pft_backupwatch_validator.prom")))
    check(
        "collect OFFHOST=1: offhost check_state 0 via the peer",
        rc == 0
        and m.get('pft_backupwatch_check_state{host="validator",check="offhost"}') == 0,
        (rc, err, m),
    )
    # the fake peer's `serve metrics` must read the sentry textfile dir: give the peer script that env
    with open(sh) as fh:
        body = fh.read()
    with open(sh, "w") as fh:
        fh.write(
            body.replace("exec env ", f"exec env HOST_LABEL=sentry TEXTFILE_DIR={st} ")
        )
    rc, out, err = wrap(c, "pull", env=env)
    pf = os.path.join(vt, "pft_backupwatch_sentry.prom")
    check(
        "pull: rc 0, sentry textfile copied byte-identical, 0644",
        rc == 0
        and readf(pf) == readf(os.path.join(st, "pft_backupwatch_sentry.prom"))
        and (os.stat(pf).st_mode & 0o777) == 0o644,
        (rc, err),
    )
    check(
        "pull: only `serve metrics` ran on the peer for the pull",
        readf(os.path.join(c.base, "peer-calls")).strip().splitlines()[-1]
        == "pft-backupwatch serve metrics",
        readf(os.path.join(c.base, "peer-calls")),
    )
    good = readf(pf)
    sentry_prom = os.path.join(st, "pft_backupwatch_sentry.prom")
    for label, text in (
        ("a foreign metric", good + 'node_load1{host="sentry"} 1\n'),
        ("the wrong host label", good.replace('host="sentry"', 'host="validator"')),
        (
            "no up sample",
            "\n".join(x for x in good.splitlines() if "pft_backupwatch_up{" not in x)
            + "\n",
        ),
        (
            "no timestamp sample",
            "\n".join(x for x in good.splitlines() if "collect_timestamp" not in x)
            + "\n",
        ),
    ):
        with open(sentry_prom, "w") as fh:
            fh.write(text)
        rc, out, err = wrap(c, "pull", env=env)
        check(
            f"pull: {label} -> rc 2, validator copy unchanged, no temp left",
            rc == 2
            and readf(pf) == good
            and sorted(os.listdir(vt))
            == ["pft_backupwatch_sentry.prom", "pft_backupwatch_validator.prom"],
            (rc, err, os.listdir(vt)),
        )
    open(os.path.join(c.base, "peer-down"), "w").close()
    rc, out, err = wrap(c, "pull", env=env)
    check(
        "pull: SSH down -> rc 1, copy unchanged (goes stale -> PFTBackupwatchStale)",
        rc == 1 and readf(pf) == good,
        (rc, err),
    )
    rc, out, err = wrap(c, "collect", env=dict(env, OFFHOST="1"), docker_src=cfg)
    m = prom_samples(readf(os.path.join(vt, "pft_backupwatch_validator.prom")))
    check(
        "collect OFFHOST=1 with SSH down -> offhost FAIL (2), rc 0",
        m.get('pft_backupwatch_check_state{host="validator",check="offhost"}') == 2,
        (rc, err, m),
    )
    os.remove(os.path.join(c.base, "peer-down"))
    rc, out, err = wrap(c, "pull", env=dict(env, PEER_LABEL="validator"))
    check("pull: PEER_LABEL = own HOST_LABEL -> rc 3", rc == 3, (rc, err))
    rc, out, err = wrap(c, "pull", env=dict(env, PEER_SSH=""))
    check("pull: no PEER_SSH -> rc 3", rc == 3, (rc, err))
    os.remove(os.path.join(rdir, n + ".age"))
    rc, out, err = wrap(c, "collect", env=peer)
    m = prom_samples(readf(os.path.join(st, "pft_backupwatch_sentry.prom")))
    check(
        "collect ROLE=replica: replica removed -> 0 replicas, verify 0",
        m.get('pft_backupwatch_replicas{host="sentry"}') == 0
        and m.get('pft_backupwatch_replica_verify_ok{host="sentry"}') == 0,
        m,
    )


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
        ("outside", t_outside_stem),
        ("absent", t_listed_absent_and_tamper),
        ("content", t_content),
        ("drift", t_drift),
        ("cfgdrift", t_cfg_drift),
        ("gpg", t_gpg),
        ("usage", t_usage),
        ("wrapper", t_wrapper),
        ("replica", t_replica),
        ("refusals", t_replica_refusals),
        ("metrics", t_metrics),
        ("collect", t_collect),
        ("collectpull", t_collect_pull),
    ]:
        case(label, fn)
    ok = all(results)
    print(
        f"RESULT: {'PASS' if ok else 'FAIL'} ({len(results)} checks, {results.count(False)} failed)"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
