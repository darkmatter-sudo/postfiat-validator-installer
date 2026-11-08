#!/usr/bin/env python3
"""backupwatch_lib: stdlib helper for pft-backupwatch.sh (read-only backup checks).

Usage (called by pft-backupwatch.sh; every path comes from its conf):
  backupwatch_lib.py check --dir DIR --now EPOCH [--passfile F] [--cfg-dir D] [--root R]
                           [--max-age-h H] [--fail-age-h H] [--min-bytes B] [--size-lo X] [--size-hi X]
                           [--scratch DIR] [--gpg BIN]
      prints one JSON object: archive, age_s, bytes, checks[{name,state,detail}], drift[...], worst
      exit 0 OK | 1 WARN | 2 FAIL | 3 usage

Archives are read into memory and opened as tar streams; nothing is extracted. A gpg archive is decrypted by
`gpg --decrypt` to a pipe; gpg's home dir is a fresh dir under --scratch (a tmpfs, /dev/shm by default), removed
before the check returns.
"""

import argparse
import calendar
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib

NAME_RE = re.compile(r"^pft-backup-(\d{8}T\d{6}Z)\.tar\.gz(\.gpg)?$")
SECRET_SECTIONS = ("validator_token", "validation_seed", "node_seed")
CFG_PREFIX = "files/etc/postfiatd/"
REQUIRED = (
    "files/etc/postfiatd/postfiatd.cfg",
    "files/etc/postfiatd/validators.txt",
    "files/opt/postfiatd/docker-compose.yml",
    "files/opt/postfiatd/.env",
)
REFERENCE = (
    "firewall/user.rules",
    "firewall/ufw-status.txt",
    "firewall/docker-user.rules",
)
NO_DRIFT = (
    "files/units-enabled.txt",
)  # derived from systemctl at backup time, not a file on the host
RANK = {"OK": 0, "WARN": 1, "FAIL": 2}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def list_archives(d):
    """[(ts, name)] oldest first; only names pft-backup.sh writes."""
    out = []
    for n in os.listdir(d):
        m = NAME_RE.match(n)
        if m and os.path.isfile(os.path.join(d, n)):
            out.append((m.group(1), n))
    return sorted(out)


def ts_epoch(ts):
    return calendar.timegm(time.strptime(ts, "%Y%m%dT%H%M%SZ"))


def strip_secrets(text):
    """Same rule as pft-backup.sh's awk: drop each secret section from its header to the next [section]."""
    out, skip = [], False
    hdr = re.compile(r"^\[(" + "|".join(SECRET_SECTIONS) + r")\]")
    for line in text.splitlines(keepends=True):
        if line.startswith("["):
            skip = bool(hdr.match(line))
        if not skip:
            out.append(line)
    return "".join(out)


def decrypt_gpg(path, passfile, scratch, gpg="gpg"):
    """(bytes, None) or (None, reason). gpg home lives in a removed scratch dir."""
    if not passfile:
        return None, "gpg archive but no PASSFILE configured"
    if not os.path.isfile(passfile) or os.path.getsize(passfile) == 0:
        return None, "PASSFILE missing or empty"
    home = tempfile.mkdtemp(prefix="pft-bw-gpg.", dir=scratch)
    try:
        os.chmod(home, 0o700)
        p = subprocess.run(
            [
                gpg,
                "--homedir",
                home,
                "--batch",
                "--quiet",
                "--pinentry-mode",
                "loopback",
                "--passphrase-file",
                passfile,
                "--decrypt",
                path,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"gpg failed to run: {type(e).__name__}"
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace")
        why = (
            "wrong passphrase"
            if "Bad session key" in err or "decryption failed" in err
            else "gpg error"
        )
        return None, f"{why} (gpg rc {p.returncode})"
    return p.stdout, None


def read_members(data, stem):
    """({relpath: bytes}, None) or (None, reason). Every regular file must sit under STEM/."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")  # noqa: SIM115 (closed in finally)
    except (tarfile.TarError, OSError, EOFError) as e:
        return None, f"not a readable tar.gz ({type(e).__name__})"
    members = {}
    try:
        for m in tf:
            top, _, rel = m.name.partition("/")
            if top != stem:
                return None, f"member outside {stem}/: {m.name[:80]}"
            if m.isdir():
                continue
            if not m.isfile():
                return None, f"non-regular member: {m.name[:80]}"
            members[rel] = tf.extractfile(m).read()
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        return None, f"archive truncated or corrupt ({type(e).__name__})"
    finally:
        tf.close()
    return members, None


def check_manifest(members):
    """(state, detail)."""
    raw = members.get("MANIFEST.sha256")
    if raw is None:
        return "FAIL", "MANIFEST.sha256 missing"
    listed = {}
    for line in raw.decode(errors="replace").splitlines():
        m = re.match(r"^([0-9a-f]{64})  (.+)$", line)
        if not m:
            return "FAIL", "malformed manifest line"
        listed[m.group(2)] = m.group(1)
    bad = sorted(
        p for p, h in listed.items() if p in members and sha256(members[p]) != h
    )
    missing = sorted(p for p in listed if p not in members)
    extra = sorted(p for p in members if p != "MANIFEST.sha256" and p not in listed)
    if bad or missing or extra:
        parts = []
        if bad:
            parts.append(f"sha256 mismatch: {', '.join(bad)}")
        if missing:
            parts.append(f"listed but absent: {', '.join(missing)}")
        if extra:
            parts.append(f"unlisted member: {', '.join(extra)}")
        return "FAIL", "; ".join(parts)
    return "OK", f"{len(listed)} members match"


def compose_members(env_bytes):
    m = None
    for line in (env_bytes or b"").decode(errors="replace").splitlines():
        if line.startswith("COMPOSE_FILE="):
            m = line[len("COMPOSE_FILE=") :]
    if not m:
        return []
    return [f for f in m.strip().strip("\"'").split(":") if f]


def check_content(members):
    req = list(REQUIRED) + [
        f"files/opt/postfiatd/{f}"
        for f in compose_members(members.get("files/opt/postfiatd/.env"))
    ]
    missing = [p for p in dict.fromkeys(req) if p not in members]
    if missing:
        return "FAIL", f"required member missing: {', '.join(missing)}"
    warn = []
    for p in REFERENCE:
        if p not in members:
            warn.append(f"{p} missing")
        elif members[p].lstrip().startswith(b"ERROR"):
            warn.append(f"{p} holds a tool error")
    if warn:
        return "WARN", "reference member: " + "; ".join(warn)
    return (
        "OK",
        f"{len(set(req))} required + {len(REFERENCE)} reference members present",
    )


def live_path(rel, root, cfg_dir):
    if rel.startswith(CFG_PREFIX):
        return os.path.join(cfg_dir, rel[len(CFG_PREFIX) :]) if cfg_dir else None
    return os.path.join(root, rel[len("files/") :])


def check_drift(members, root, cfg_dir, secrets_included):
    """(state, detail, [ {path, state} ]): changed | gone | unchecked (no cfg dir)."""
    rows = []
    for rel in sorted(members):
        if not rel.startswith("files/") or rel in NO_DRIFT:
            continue
        lp = live_path(rel, root, cfg_dir)
        shown = "/" + rel[len("files/") :]
        if lp is None:
            rows.append({"path": shown, "state": "unchecked"})
            continue
        try:
            with open(lp, "rb") as fh:
                live = fh.read()
        except FileNotFoundError:
            rows.append({"path": shown, "state": "gone"})
            continue
        except OSError:
            rows.append({"path": shown, "state": "unreadable"})
            continue
        if rel == CFG_PREFIX + "postfiatd.cfg" and not secrets_included:
            live = strip_secrets(live.decode(errors="surrogateescape")).encode(
                errors="surrogateescape"
            )
        rows.append(
            {"path": shown, "state": "same" if live == members[rel] else "changed"}
        )
    odd = [r for r in rows if r["state"] != "same"]
    if not odd:
        return "OK", f"{len(rows)} files equal the live host", rows
    return "WARN", "; ".join(f"{r['path']} {r['state']}" for r in odd), rows


def secrets_flag(members):
    for line in members.get("META.txt", b"").decode(errors="replace").splitlines():
        if line.startswith("secrets_included="):
            return line.split("=", 1)[1].strip() == "1"
    return False


def cmd_check(a):
    res = {"archive": None, "age_s": None, "bytes": None, "checks": [], "drift": []}

    def add(name, state, detail):
        res["checks"].append({"name": name, "state": state, "detail": detail})

    try:
        arch = list_archives(a.dir)
    except OSError as e:
        add("fresh", "FAIL", f"backup dir unreadable ({type(e).__name__})")
        return finish(res)
    if not arch:
        add("fresh", "FAIL", "no archive")
        return finish(res)
    ts, name = arch[-1]
    path = os.path.join(a.dir, name)
    size = os.path.getsize(path)
    age = a.now - ts_epoch(ts)
    res.update(archive=name, age_s=age, bytes=size)

    if age > a.fail_age_h * 3600:
        add("fresh", "FAIL", f"newest {age // 3600} h old > {a.fail_age_h} h")
    elif age > a.max_age_h * 3600:
        add("fresh", "WARN", f"newest {age // 3600} h old > {a.max_age_h} h")
    else:
        add("fresh", "OK", f"newest {age // 60} min old")

    if size < a.min_bytes:
        add("size", "FAIL", f"{size} B < {a.min_bytes} B")
    elif len(arch) > 1:
        prev = os.path.getsize(os.path.join(a.dir, arch[-2][1]))
        ratio = size / prev if prev else float("inf")
        if a.size_lo <= ratio <= a.size_hi:
            add("size", "OK", f"{size} B, {ratio:.2f}x previous")
        else:
            add(
                "size",
                "WARN",
                f"{size} B, {ratio:.2f}x previous (allowed {a.size_lo}..{a.size_hi})",
            )
    else:
        add("size", "OK", f"{size} B (no previous archive)")

    with open(path, "rb") as fh:
        blob = fh.read()
    side = path + ".sha256"
    try:
        with open(side) as fh:
            want = fh.read().split()[0]
        if want == sha256(blob):
            add("sidecar", "OK", "sha256 matches")
        else:
            add("sidecar", "FAIL", "sha256 mismatch")
    except (OSError, IndexError):
        add("sidecar", "FAIL", "sidecar missing or empty")

    stem = (
        name[: -len(".tar.gz.gpg")]
        if name.endswith(".gpg")
        else name[: -len(".tar.gz")]
    )
    if name.endswith(".gpg"):
        data, why = decrypt_gpg(path, a.passfile, a.scratch, a.gpg)
    else:
        data, why = blob, None
    members = None
    if data is not None:
        members, why = read_members(data, stem)
    if members is None:
        add("manifest", "FAIL", why)
        add("content", "FAIL", "archive not readable")
        add("drift", "FAIL", "archive not readable")
        return finish(res)
    add("manifest", *check_manifest(members))
    add("content", *check_content(members))
    st, detail, rows = check_drift(members, a.root, a.cfg_dir, secrets_flag(members))
    add("drift", st, detail)
    res["drift"] = rows
    return finish(res)


def finish(res):
    worst = max((RANK[c["state"]] for c in res["checks"]), default=2)
    res["worst"] = next(k for k, v in RANK.items() if v == worst)
    print(json.dumps(res, sort_keys=True))
    return worst


def main(argv):
    ap = argparse.ArgumentParser(prog="backupwatch_lib.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--dir", required=True)
    c.add_argument("--now", type=int, required=True)
    c.add_argument("--passfile", default="")
    c.add_argument("--cfg-dir", default="")
    c.add_argument("--root", default="/")
    c.add_argument("--max-age-h", type=int, default=26)
    c.add_argument("--fail-age-h", type=int, default=50)
    c.add_argument("--min-bytes", type=int, default=4096)
    c.add_argument("--size-lo", type=float, default=0.5)
    c.add_argument("--size-hi", type=float, default=2.0)
    c.add_argument("--scratch", default="/dev/shm")
    c.add_argument("--gpg", default="gpg")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 3
    if (
        a.fail_age_h < a.max_age_h
        or a.min_bytes < 0
        or not 0 < a.size_lo <= 1 <= a.size_hi
    ):
        print("backupwatch_lib: inconsistent thresholds", file=sys.stderr)
        return 3
    return cmd_check(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
