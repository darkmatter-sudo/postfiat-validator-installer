#!/usr/bin/env python3
"""backupwatch_lib: stdlib helper for pft-backupwatch.sh (read-only backup checks).

Usage (called by pft-backupwatch.sh; every path comes from its conf):
  backupwatch_lib.py check --dir DIR --now EPOCH [--passfile F] [--cfg-dir D] [--root R]
                           [--max-age-h H] [--fail-age-h H] [--min-bytes B] [--size-lo X] [--size-hi X]
                           [--scratch DIR] [--gpg BIN]
      prints one JSON object: archive, age_s, bytes, checks[{name,state,detail}], drift[...], worst
      exit 0 OK | 1 WARN | 2 FAIL | 3 usage
  backupwatch_lib.py render < CHECK_JSON      the table pft-backupwatch check prints
  backupwatch_lib.py metrics --host H --now EPOCH [--drift-state F] [--drift-grace-h H] < CHECK_JSON
      pft_backupwatch_* textfile for the archive host (empty/invalid input -> up 0, exit 1)
  backupwatch_lib.py replica-metrics --host H --now EPOCH < SERVE_STATUS_AND_VERIFY
      pft_backupwatch_* textfile for the replica host (no END line -> up 0, exit 1)

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


def check_offhost(report_path, state_path, name, plain):
    """(state, detail) from the peer report (PEER_DOWN rc | REPLICA name csha plain received... | VERIFY name state)
    and the local replica record (name csha plain epoch per line, newest last)."""
    try:
        with open(report_path) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return "FAIL", "no peer report"
    down = [x for x in lines if x.startswith("PEER_DOWN")]
    if down:
        return "FAIL", f"peer unreachable ({down[0]})"
    if not name:
        return "FAIL", "no local archive to compare"
    reps, verify = {}, {}
    for x in lines:
        f = x.split()
        if len(f) >= 4 and f[0] == "REPLICA":
            reps[f[1].removesuffix(".age")] = (f[2], f[3])
        elif len(f) == 3 and f[0] == "VERIFY":
            verify[f[1]] = f[2]
    if not reps:
        return "FAIL", "no replica on the peer"
    rec = {}
    try:
        with open(state_path) as fh:
            for line in fh:
                f = line.rstrip("\n").split("\t")
                if len(f) == 4:
                    rec[f[0]] = (f[1], f[2])
    except OSError:
        pass
    if name not in reps:
        newest = max(reps)
        return "WARN", f"newest archive not replicated; newest replica {newest}"
    csha, rplain = reps[name]
    if name not in rec:
        return (
            "FAIL",
            "replica not recorded locally (state file missing or replicated elsewhere)",
        )
    if rec[name][0] != csha:
        return (
            "FAIL",
            "replica ciphertext sha256 differs from the one recorded at replication",
        )
    if rplain != plain or rec[name][1] != plain:
        return "FAIL", "replica plaintext sha256 differs from the archive sidecar"
    v = verify.get(name)
    if v != "OK":
        return "FAIL", f"peer verify: {v or 'no answer'}"
    return (
        "OK",
        f"peer holds {name}: ciphertext sha256 = recorded, decrypts to the sidecar sha256 ({len(reps)} replica(s))",
    )


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
        offhost(a, res, add, "")
        return finish(res)
    if not arch:
        add("fresh", "FAIL", "no archive")
        offhost(a, res, add, "")
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
        res["sidecar_sha256"] = want
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
        offhost(a, res, add, name)
        return finish(res)
    add("manifest", *check_manifest(members))
    add("content", *check_content(members))
    st, detail, rows = check_drift(members, a.root, a.cfg_dir, secrets_flag(members))
    add("drift", st, detail)
    res["drift"] = rows
    offhost(a, res, add, name)
    return finish(res)


def offhost(a, res, add, name):
    if a.offhost:
        add(
            "offhost",
            *check_offhost(
                a.offhost, a.replica_state, name, res.get("sidecar_sha256", "")
            ),
        )


def finish(res):
    worst = max((RANK[c["state"]] for c in res["checks"]), default=2)
    res["worst"] = next(k for k, v in RANK.items() if v == worst)
    print(json.dumps(res, sort_keys=True))
    return worst


CHECKS = ("fresh", "size", "sidecar", "manifest", "content", "drift", "offhost")
HOST_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
REPLICA_LINE = re.compile(
    r"^REPLICA (pft-backup-(\d{8}T\d{6}Z)\.tar\.gz(?:\.gpg)?) [0-9a-f]{64} [0-9a-f]{64} (\d+)$"
)


def drift_since(state_path, drifted, now):
    """First time the drift check was seen non-OK (epoch), kept in state_path; 0 and removed once it is OK again."""
    if not drifted:
        try:
            os.unlink(state_path)
        except FileNotFoundError:
            pass
        return 0
    try:
        with open(state_path) as fh:
            since = int(fh.read().split()[0])
        if 0 < since <= now:
            return since
    except (OSError, ValueError, IndexError):
        pass
    tmp = state_path + ".new"
    with open(tmp, "w") as fh:
        fh.write(f"{now}\n")
    os.replace(tmp, state_path)
    return now


def prom(host, rows):
    out = []
    for name, help_, labels, value in rows:
        if help_:
            out.append(f"# HELP pft_backupwatch_{name} {help_}")
            out.append(f"# TYPE pft_backupwatch_{name} gauge")
        lab = ",".join(f'{k}="{v}"' for k, v in (("host", host),) + labels)
        out.append(f"pft_backupwatch_{name}{{{lab}}} {value}")
    return "\n".join(out) + "\n"


def cmd_metrics(a, text):
    """Archive-host textfile from check's JSON on stdin (empty/invalid stdin -> up 0)."""
    try:
        j = json.loads(text)
        states = {c["name"]: RANK[c["state"]] for c in j["checks"]}
    except (ValueError, KeyError, TypeError):
        j, states = None, None
    rows = [
        (
            "collect_timestamp_seconds",
            "Last pft-backupwatch collect (epoch).",
            (),
            a.now,
        )
    ]
    if states is None:
        rows.append(("up", "1 if the check ran and produced a result.", (), 0))
        sys.stdout.write(prom(a.host, rows))
        return 1
    rows.append(("up", "1 if the check ran and produced a result.", (), 1))
    first = True
    for name in CHECKS:
        if name in states:
            rows.append(
                (
                    "check_state",
                    "Per check: 0 OK, 1 WARN, 2 FAIL." if first else "",
                    (("check", name),),
                    states[name],
                )
            )
            first = False
    rows.append(
        (
            "archive_age_seconds",
            "Age of the newest archive (-1: none).",
            (),
            j.get("age_s") if j.get("age_s") is not None else -1,
        )
    )
    rows.append(
        (
            "archive_bytes",
            "Size of the newest archive (-1: none).",
            (),
            j.get("bytes") if j.get("bytes") is not None else -1,
        )
    )
    drifted = states.get("drift", 0) != 0
    since = drift_since(a.drift_state, drifted, a.now) if a.drift_state else 0
    rows.append(
        (
            "drift_files",
            "Archived config files that differ from the live host.",
            (),
            sum(1 for r in j.get("drift", []) if r.get("state") != "same"),
        )
    )
    rows.append(
        (
            "drift_since_timestamp_seconds",
            "First collect that saw drift (0: none).",
            (),
            since,
        )
    )
    overdue = 1 if since and a.now - since > a.drift_grace_h * 3600 else 0
    rows.append(
        (
            "drift_overdue",
            "1 if drift outlived DRIFT_GRACE_H (no backup picked the change up).",
            (),
            overdue,
        )
    )
    sys.stdout.write(prom(a.host, rows))
    return 0


def cmd_replica_metrics(a, text):
    """Replica-host textfile from `serve status` (+ one VERIFY line for the newest) on stdin."""
    lines = text.splitlines()
    rows = [
        (
            "collect_timestamp_seconds",
            "Last pft-backupwatch collect (epoch).",
            (),
            a.now,
        )
    ]
    if "END" not in lines:
        rows.append(("up", "1 if the check ran and produced a result.", (), 0))
        sys.stdout.write(prom(a.host, rows))
        return 1
    reps = [m for m in (REPLICA_LINE.match(x) for x in lines) if m]
    rows.append(("up", "1 if the check ran and produced a result.", (), 1))
    rows.append(("replicas", "Encrypted replicas held for the peer.", (), len(reps)))
    if reps:
        newest = max(reps, key=lambda m: m.group(2))
        age = a.now - ts_epoch(newest.group(2))
        ok = 1 if any(x == f"VERIFY {newest.group(1)} OK" for x in lines) else 0
    else:
        age, ok = -1, 0
    rows.append(
        (
            "replica_newest_age_seconds",
            "Archive age of the newest replica (-1: none).",
            (),
            age,
        )
    )
    rows.append(
        (
            "replica_verify_ok",
            "1 if the newest replica re-hashes and decrypts to its recorded sha256.",
            (),
            ok,
        )
    )
    sys.stdout.write(prom(a.host, rows))
    return 0


def cmd_render(text):
    """Table for a terminal: one line per check + RESULT, from check's JSON on stdin."""
    try:
        j = json.loads(text)
    except ValueError:
        return 3
    print(
        f"pft-backupwatch check | archive {j.get('archive') or '-'} | age_s {j.get('age_s')} | bytes {j.get('bytes')}"
    )
    for c in j["checks"]:
        print(f"  [{c['state']:<4}] {c['name']:<9} {c['detail']}")
    n = sum(c["state"] != "OK" for c in j["checks"])
    print(f"RESULT: {j['worst']} - {n} finding(s)")
    return 0


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
    c.add_argument(
        "--offhost",
        default="",
        help="peer report file (pft-backupwatch.sh offhost_report)",
    )
    c.add_argument("--replica-state", default="/var/lib/pft-backupwatch/replica.tsv")
    sub.add_parser("render")
    for nm in ("metrics", "replica-metrics"):
        m = sub.add_parser(nm)
        m.add_argument("--host", required=True)
        m.add_argument("--now", type=int, required=True)
        if nm == "metrics":
            m.add_argument("--drift-state", default="")
            m.add_argument("--drift-grace-h", type=int, default=30)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 3
    if a.cmd == "render":
        return cmd_render(sys.stdin.read())
    if a.cmd in ("metrics", "replica-metrics"):
        if not HOST_RE.match(a.host) or a.now <= 0:
            print("backupwatch_lib: bad --host/--now", file=sys.stderr)
            return 3
        if a.cmd == "metrics":
            if a.drift_grace_h < 0:
                print("backupwatch_lib: bad --drift-grace-h", file=sys.stderr)
                return 3
            return cmd_metrics(a, sys.stdin.read())
        return cmd_replica_metrics(a, sys.stdin.read())
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
