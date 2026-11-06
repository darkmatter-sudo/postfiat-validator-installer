#!/usr/bin/env python3
"""schedaudit_lib: inventory and audit of every scheduled-execution entry point on a Post Fiat validator or sentry
host (Ubuntu 22.04): /etc/crontab, /etc/cron.d, user crontab spools, run-parts dirs (/etc/cron.{hourly,daily,weekly,
monthly}), /etc/anacrontab, at spools and every systemd timer (system + user unit dirs), including disabled timers,
commented-out cron lines and run-parts files that run-parts would skip. Read-only except `apply` (chmod go-w only)
and `accept` (writes the state file). Python 3 stdlib only.

Usage: schedaudit_lib.py inventory [--format tsv|json] [COMMON]
       schedaudit_lib.py audit     [--format tsv|json] [COMMON]   exit 0 clean, 1 unexpected entries/findings
       schedaudit_lib.py prom --host NAME [COMMON]                 textfile metrics on stdout (exit as audit)
       schedaudit_lib.py apply [--dry-run] [COMMON]                chmod go-w on fixable path-chain findings
       schedaudit_lib.py accept --reason TEXT [COMMON]             record the current entry set as expected
       schedaudit_lib.py scope [COMMON]                            files pft-integrity should track (one per line)
COMMON: --root DIR (/)  --state FILE  --allow FILE  --systemctl CMD  --trusted-uid N (0)  --now EPOCH
Exit codes: 0 ok, 1 findings / unexpected entries, 2 collection failed, 3 usage or config error.
"""

import fnmatch
import hashlib
import json
import os
import pwd
import re
import shlex
import stat
import subprocess
import sys
import time

VERSION = 1
CRON_DIRS = ("hourly", "daily", "weekly", "monthly")
CRON_DEFAULT_PATH = (
    "/usr/bin:/bin"  # cron(8) on Debian/Ubuntu when the crontab sets no PATH
)
RUN_PARTS_NAME = re.compile(
    r"^[A-Za-z0-9_-]+$"
)  # run-parts --lsbsysinit off: other names are skipped
SPECIAL = {
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@midnight",
    "@hourly",
}
FIELD = re.compile(r"^[0-9A-Za-z*/,-]+$")
ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
ABS_PATH = re.compile(r"(?<![\w.$/-])(/[A-Za-z0-9_.+@%:-]+(?:/[A-Za-z0-9_.+@%:-]+)*)")
SKIP_PREFIX = ("/proc/", "/sys/", "/dev/")
WORLD_TMP = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/shm",
    "/run/user",
    "/home",
    "/var/crash",
    "/run/lock",
)
UNIT_RE = re.compile(r"^[A-Za-z0-9:_.\\@-]+\.timer$")
TIMER_PROPS = "Id,Unit,LoadState,ActiveState,UnitFileState,FragmentPath,DropInPaths,TimersCalendar,TimersMonotonic"
SERVICE_PROPS = "Id,LoadState,UnitFileState,FragmentPath,DropInPaths,User,ExecStart,WorkingDirectory"
SYSTEM_UNIT_DIRS = (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
)
USER_UNIT_DIRS = ("/etc/systemd/user", "/usr/lib/systemd/user")
CHECKS = {
    # check: severity, meaning
    "chain_writable": (
        "crit",
        "a path the job runs/reads, or one of its parent dirs, is writable by non-root",
    ),
    "chain_owner": (
        "crit",
        "a path the job runs/reads, or one of its parent dirs, is not owned by root",
    ),
    "writable_dir": (
        "crit",
        "the job runs a path inside a directory any user can write (tmp/home)",
    ),
    "pkg_modified": (
        "warn",
        "a packaged file differs from the dpkg md5sum / conffile hash",
    ),
    "untracked": ("warn", "an unpackaged file that pft-integrity does not track"),
    "nonsystem_user": (
        "warn",
        "the job runs as a regular (login) user, not root/system",
    ),
    "timer_target": (
        "crit",
        "a timer whose unit is missing/masked or whose ExecStart binary is missing",
    ),
}


class ConfigError(Exception):
    pass


# ---------------------------------------------------------------- filesystem view (all paths are host-logical)
class Host:
    def __init__(self, root="/", trusted_uid=0, systemctl="systemctl", now=None):
        self.root = os.path.abspath(root)
        self.trusted = trusted_uid
        self.systemctl_cmd = systemctl.split()
        self.now = int(now if now is not None else time.time())
        self._users = None
        self._dpkg = None

    def real(self, p):
        return p if self.root == "/" else self.root + p

    def lstat(self, p):
        try:
            return os.lstat(self.real(p))
        except OSError:
            return None

    def read(self, p):
        try:
            with open(self.real(p), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def listdir(self, p):
        try:
            return sorted(os.listdir(self.real(p)))
        except OSError:
            return []

    def resolve(self, p, depth=0):
        """Host-logical realpath (symlinks resolved inside the root) or None if a component is missing."""
        parts, cur = [x for x in p.split("/") if x], ""
        for i, part in enumerate(parts):
            nxt = cur + "/" + part
            st = self.lstat(nxt)
            if st is None:
                return None
            if stat.S_ISLNK(st.st_mode):
                if depth > 20:
                    return None
                tgt = os.readlink(self.real(nxt))
                base = tgt if tgt.startswith("/") else (cur or "") + "/" + tgt
                rest = "/".join(parts[i + 1 :])
                return self.resolve(
                    os.path.normpath(base + ("/" + rest if rest else "")), depth + 1
                )
            cur = nxt
        return cur or "/"

    # users
    def users(self):
        if self._users is None:
            self._users = {}
            for ln in (
                (self.read("/etc/passwd") or b"")
                .decode("utf-8", "replace")
                .splitlines()
            ):
                f = ln.split(":")
                if len(f) >= 7 and f[2].isdigit():
                    self._users[f[0]] = {"uid": int(f[2]), "shell": f[6]}
        return self._users

    def uid_min(self):
        for ln in (
            (self.read("/etc/login.defs") or b"")
            .decode("utf-8", "replace")
            .splitlines()
        ):
            m = re.match(r"^\s*UID_MIN\s+(\d+)", ln)
            if m:
                return int(m.group(1))
        return 1000

    # dpkg
    def dpkg(self):
        """-> (path -> package, path -> md5) from /var/lib/dpkg/info/*.list, *.md5sums and the status Conffiles."""
        if self._dpkg is not None:
            return self._dpkg
        owner, md5 = {}, {}
        info = "/var/lib/dpkg/info"
        for f in self.listdir(info):
            pkg = f.rsplit(".", 1)[0].split(":")[0]
            if f.endswith(".list"):
                for ln in (
                    (self.read(f"{info}/{f}") or b"")
                    .decode("utf-8", "replace")
                    .splitlines()
                ):
                    if ln.startswith("/"):
                        owner.setdefault(ln, pkg)
            elif f.endswith(".md5sums"):
                for ln in (
                    (self.read(f"{info}/{f}") or b"")
                    .decode("utf-8", "replace")
                    .splitlines()
                ):
                    h, _, path = ln.partition("  ")
                    if len(h) == 32 and path:
                        md5["/" + path] = h
        in_conf = False
        for ln in (
            (self.read("/var/lib/dpkg/status") or b"")
            .decode("utf-8", "replace")
            .splitlines()
        ):
            if ln.startswith("Conffiles:"):
                in_conf = True
                continue
            if in_conf and ln.startswith(" /"):
                f = ln.split()
                if len(f) >= 2 and len(f[1]) == 32 and "obsolete" not in f[2:]:
                    md5[f[0]] = f[1]
                continue
            in_conf = False
        self._dpkg = (owner, md5)
        return self._dpkg

    def systemctl(self, args):
        env = dict(
            os.environ, TZ="UTC", LC_ALL="C", SYSTEMD_PAGER="cat", SYSTEMD_COLORS="0"
        )
        p = subprocess.run(
            self.systemctl_cmd + args,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        if p.returncode != 0:
            raise RuntimeError(
                f"systemctl {args[0]} failed (rc {p.returncode}): {p.stderr.strip()[:200]}"
            )
        return p.stdout


def pkg_verified(h, p):
    """Package name if p is a packaged regular file whose content matches dpkg's md5 (md5sums or Conffiles), else
    None. Such files are identified by package, not content: an unattended-upgrades update of a packaged
    cron.daily script or timer unit must not look like a new scheduled entry (a non-package edit fails the md5,
    keeps the content id and is a pkg_modified finding)."""
    owner, md5 = h.dpkg()
    r = h.resolve(p) or p
    cands = usr_merge_variants(p) + usr_merge_variants(r)
    pkg = next((owner[c] for c in cands if c in owner), None)
    want = next((md5[c] for c in cands if c in md5), None)
    st = h.lstat(r)
    if not pkg or not want or st is None or not stat.S_ISREG(st.st_mode):
        return None
    return pkg if hashlib.md5(h.read(r) or b"").hexdigest() == want else None


def usr_merge_variants(p):
    out = [p]
    for a, b in (
        ("/bin/", "/usr/bin/"),
        ("/sbin/", "/usr/sbin/"),
        ("/lib/", "/usr/lib/"),
    ):
        if p.startswith(a):
            out.append(b + p[len(a) :])
        elif p.startswith(b):
            out.append(a + p[len(b) :])
    return out


# ---------------------------------------------------------------- cron parsing
def eid(source, name, text):
    return (
        f"{source}/{name}@"
        + hashlib.sha256(" ".join(text.split()).encode()).hexdigest()[:10]
    )


def parse_cron_line(s, system):
    """-> (schedule, user, command) or None. system=True: crontab with a user field (/etc/crontab, cron.d)."""
    f = s.split()
    if not f:
        return None
    if f[0] in SPECIAL:
        sched, rest = f[0], f[1:]
    elif len(f) >= 6 and all(FIELD.match(x) for x in f[:5]):
        sched, rest = " ".join(f[:5]), f[5:]
    else:
        return None
    if system:
        if len(rest) < 2:
            return None
        user, cmd_words = rest[0], rest[1:]
    else:
        if not rest:
            return None
        user, cmd_words = None, rest
    # keep the command text as written (after the schedule/user fields)
    cmd = s.strip()
    for w in f[: len(f) - len(cmd_words)]:
        cmd = cmd[len(w) :].lstrip() if cmd.startswith(w) else cmd
    return sched, user, cmd


def crontab_entries(h, path, source, name, system, spool_user=None):
    out, env_path = [], CRON_DEFAULT_PATH
    raw = h.read(path)
    if raw is None:
        return out
    users = h.users()
    for n, ln in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        s = ln.strip()
        if not s:
            continue
        commented = s.startswith("#")
        body = s.lstrip("#").strip() if commented else s
        if not commented and ENV_LINE.match(s):
            k, _, v = s.partition("=")
            if k.strip() == "PATH":
                env_path = v.strip().strip("\"'")
            continue
        p = parse_cron_line(body, system)
        if p is None:
            continue
        sched, user, cmd = p
        user = user if system else spool_user
        if commented and system and user not in users:
            continue  # the stock "m h dom mon dow user command" help text, not a disabled job
        out.append(
            {
                "id": eid(source, name, body),
                "source": source,
                "file": path,
                "line": n,
                "schedule": sched,
                "user": user or "",
                "command": cmd,
                "enabled": not commented,
                "state": "commented" if commented else "active",
                "path_env": env_path,
            }
        )
    return out


def run_parts_entries(h, d, cron_active):
    out = []
    for f in h.listdir(d):
        p = f"{d}/{f}"
        st = h.lstat(p)
        if st is None or stat.S_ISDIR(st.st_mode):
            continue
        tgt = h.resolve(p)
        tst = h.lstat(tgt) if tgt else None
        if not RUN_PARTS_NAME.match(f):
            state = "inert-name"  # run-parts skips names with dots (.placeholder, x.dpkg-old)
        elif tst is None or not (tst.st_mode & 0o111):
            state = "not-executable"
        elif not cron_active:
            state = "no-schedule"
        else:
            state = "active"
        pkg = pkg_verified(h, p)
        sha = hashlib.sha256(
            f"pkg:{pkg}".encode() if pkg else (h.read(p) or b"")
        ).hexdigest()
        out.append(
            {
                "id": f"run-parts/{d.rsplit('/', 1)[1]}/{f}@{sha[:10]}",
                "source": "run-parts",
                "file": p,
                "line": 0,
                "schedule": d.rsplit(".", 1)[1],
                "user": "root",
                "command": p,
                "enabled": state == "active",
                "state": state,
                "path_env": CRON_DEFAULT_PATH,
            }
        )
    return out


def cron_inventory(h):
    out = []
    out += crontab_entries(h, "/etc/crontab", "crontab", "etc", True)
    for f in h.listdir("/etc/cron.d"):
        p = f"/etc/cron.d/{f}"
        st = h.lstat(p)
        if st is None or not stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
            continue
        ents = crontab_entries(h, p, "cron.d", f, True)
        if not RUN_PARTS_NAME.match(
            f
        ):  # cron(8) skips cron.d names with dots, like run-parts
            for e in ents:
                e["enabled"], e["state"] = False, "inert-name"
        out += ents
    for f in h.listdir("/var/spool/cron/crontabs"):
        out += crontab_entries(
            h, f"/var/spool/cron/crontabs/{f}", "spool", f, False, spool_user=f
        )
    out += anacron_entries(h)
    # which run-parts dirs are driven by an active line (crontab or anacron)
    drivers = " ".join(e["command"] for e in out if e["enabled"])
    for k in CRON_DIRS:
        d = f"/etc/cron.{k}"
        out += run_parts_entries(h, d, d in drivers)
    return out


def anacron_entries(h):
    out = []
    raw = h.read("/etc/anacrontab")
    if raw is None:
        return out
    for n, ln in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        s = ln.strip()
        if not s or ENV_LINE.match(s):
            continue
        commented = s.startswith("#")
        body = s.lstrip("#").strip()
        f = body.split(None, 3)
        if (
            len(f) < 4
            or not (f[0].isdigit() or f[0].startswith("@"))
            or not f[1].isdigit()
        ):
            continue
        out.append(
            {
                "id": eid("anacrontab", "etc", body),
                "source": "anacrontab",
                "file": "/etc/anacrontab",
                "line": n,
                "schedule": f"period {f[0]} delay {f[1]} job {f[2]}",
                "user": "root",
                "command": f[3],
                "enabled": not commented,
                "state": "commented" if commented else "active",
                "path_env": CRON_DEFAULT_PATH,
            }
        )
    return out


def at_inventory(h):
    out = []
    for d in ("/var/spool/cron/atjobs", "/var/spool/at"):
        for f in h.listdir(d):
            p = f"{d}/{f}"
            st = h.lstat(p)
            if st is None or not stat.S_ISREG(st.st_mode) or f.startswith("."):
                continue
            try:
                user = (
                    pwd.getpwuid(st.st_uid).pw_name if h.root == "/" else str(st.st_uid)
                )
            except KeyError:
                user = str(st.st_uid)
            sha = hashlib.sha256(h.read(p) or b"").hexdigest()
            out.append(
                {
                    "id": f"at/{f}@{sha[:10]}",
                    "source": "at",
                    "file": p,
                    "line": 0,
                    "schedule": "at-queue",
                    "user": user,
                    "command": p,
                    "enabled": bool(
                        st.st_mode & 0o100
                    ),  # atd runs only executable job files
                    "state": "queued" if st.st_mode & 0o100 else "done",
                    "path_env": CRON_DEFAULT_PATH,
                }
            )
    return out


# ---------------------------------------------------------------- systemd timers
def parse_show(text):
    blocks, cur = [], {}
    for ln in text.splitlines():
        if not ln.strip():
            if cur:
                blocks.append(cur)
            cur = {}
            continue
        k, sep, v = ln.partition("=")
        if sep:
            cur.setdefault(k, []).append(v)
    if cur:
        blocks.append(cur)
    return blocks


def one(b, k, default=""):
    v = b.get(k)
    return v[-1] if v else default


SYSTEMD_EXEC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"  # systemd 249 search path


def exec_paths(h, execstart):
    """systemctl show ExecStart= '{ path=/x ; argv[]=/x a b ; ... }' (possibly several) -> list of paths.
    systemd 249 prints a bare name (path=sh) as written and resolves it at start time: do the same here."""
    out = []
    for p in re.findall(r"\bpath=([^ ;]+)", execstart):
        if not p.startswith("/"):
            for d in SYSTEMD_EXEC_PATH.split(":"):
                if h.lstat(f"{d}/{p}") is not None:
                    p = f"{d}/{p}"
                    break
        out.append(p)
    return out


def timer_inventory(h):
    names = set()
    for ln in h.systemctl(
        ["list-unit-files", "--type=timer", "--no-legend", "--no-pager", "--plain"]
    ).splitlines():
        f = ln.split()
        if f and UNIT_RE.match(f[0]) and not f[0].endswith("@.timer"):
            names.add(f[0])
    for ln in h.systemctl(
        ["list-units", "--type=timer", "--all", "--no-legend", "--no-pager", "--plain"]
    ).splitlines():
        f = ln.split()
        if f and UNIT_RE.match(f[0]):
            names.add(f[0])
    names = sorted(names)
    out = []
    if not names:
        return out
    timers = parse_show(
        h.systemctl(["show", "--no-pager", "-p", TIMER_PROPS, "--"] + names)
    )
    svc = sorted({one(t, "Unit") for t in timers} - {""})
    services = {}
    if svc:
        services = {
            one(b, "Id"): b
            for b in parse_show(
                h.systemctl(["show", "--no-pager", "-p", SERVICE_PROPS, "--"] + svc)
            )
        }
    for t in timers:
        name = one(t, "Id")
        unit = one(t, "Unit")
        s = services.get(unit, {})
        sched = "; ".join(
            re.sub(r"\s*;\s*next_elapse=.*$", "", v.strip("{} "))
            for v in t.get("TimersCalendar", []) + t.get("TimersMonotonic", [])
        )
        ufs = one(t, "UnitFileState")
        loaded = one(t, "LoadState")
        active = one(t, "ActiveState")
        if loaded == "masked" or ufs == "masked":
            state = "masked"
        elif active == "active":
            state = "active"
        elif ufs in ("disabled", "indirect", ""):
            state = "disabled"
        else:
            state = "inactive"
        execs = exec_paths(h, one(s, "ExecStart"))
        files = [x for x in [one(t, "FragmentPath"), one(s, "FragmentPath")] if x]
        for b in (t, s):
            files += [x for x in one(b, "DropInPaths").split() if x]
        desc = f"{unit} -> " + " ".join(execs) if unit else "(no unit)"
        frags = [x for x in [one(t, "FragmentPath"), one(s, "FragmentPath")] if x]
        pkgs = [pkg_verified(h, x) for x in frags]
        if len(frags) == 2 and all(pkgs) and len(files) == 2:
            # both unit files packaged + md5-verified, no drop-ins: identified by package (see pkg_verified)
            fp = hashlib.sha256(
                "\n".join([name, unit, "pkg:" + ",".join(pkgs)]).encode()
            ).hexdigest()
        else:
            fp = hashlib.sha256(
                "\n".join(
                    [
                        sched,
                        unit,
                        one(s, "ExecStart").split(" ; ignore_errors")[0],
                        one(s, "User"),
                    ]
                    + files
                ).encode()
            ).hexdigest()
        out.append(
            {
                "id": f"timer/{name}@{fp[:10]}",
                "source": "timer",
                "file": one(t, "FragmentPath"),
                "line": 0,
                "schedule": sched,
                "user": one(s, "User") or "root",
                "command": desc,
                "enabled": state == "active",
                "state": state,
                "path_env": "",
                "unit": unit,
                "unit_load": one(s, "LoadState") or "not-found",
                "unit_file_state": one(s, "UnitFileState"),
                "execs": execs,
                "unit_files": files,
                "workdir": one(s, "WorkingDirectory"),
            }
        )
    return out


def user_timer_inventory(h):
    """Timer unit FILES in systemd user-unit dirs (system-wide and per-user); listed, not resolved."""
    out = []
    dirs = list(USER_UNIT_DIRS)
    for ln in (h.read("/etc/passwd") or b"").decode("utf-8", "replace").splitlines():
        f = ln.split(":")
        if len(f) >= 7 and f[5].startswith("/") and f[5] != "/":
            dirs.append(f"{f[5]}/.config/systemd/user")
    for d in dirs:
        for f in h.listdir(d):
            p = f"{d}/{f}"
            if not f.endswith(".timer") or h.lstat(p) is None:
                continue
            sha = hashlib.sha256(h.read(p) or b"").hexdigest()
            st = h.lstat(p)
            out.append(
                {
                    "id": f"user-timer/{f}@{sha[:10]}",
                    "source": "user-timer",
                    "file": p,
                    "line": 0,
                    "schedule": "user-manager",
                    "user": "" if d in USER_UNIT_DIRS else str(st.st_uid),
                    "command": p,
                    "enabled": False,
                    "state": "user-unit",
                    "path_env": "",
                }
            )
    return out


def inventory(h):
    return (
        cron_inventory(h)
        + at_inventory(h)
        + timer_inventory(h)
        + user_timer_inventory(h)
    )


# ---------------------------------------------------------------- checks
def command_paths(h, e):
    """Absolute paths a cron command names, plus its first word resolved through the crontab's PATH."""
    cmd = e["command"]
    paths = [m for m in ABS_PATH.findall(cmd) if not m.startswith(SKIP_PREFIX)]
    try:
        words = shlex.split(cmd, comments=False, posix=True)
    except ValueError:
        words = cmd.split()
    while words and ENV_LINE.match(words[0]):
        words = words[1:]
    if (
        words
        and not words[0].startswith("/")
        and re.match(r"^[A-Za-z0-9_.+-]+$", words[0])
        and words[0]
        not in (
            "test",
            "cd",
            "[",
            "true",
            "false",
            "exec",
            "echo",
            "if",
            "then",
            "fi",
            "for",
            "do",
        )
    ):
        for d in (e.get("path_env") or CRON_DEFAULT_PATH).split(":"):
            c = f"{d.rstrip('/')}/{words[0]}"
            if d.startswith("/") and h.lstat(c) is not None:
                paths.append(c)
                break
    seen, out = set(), []
    for p in paths:
        p = os.path.normpath(p)
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def entry_paths(h, e):
    """-> list of (path, role). role: 'file' (the definition), 'exec', 'ref' (named in the command), 'unit'."""
    out = []
    if e["file"]:
        out.append((e["file"], "file"))
    if e["source"] == "timer":
        out += [(p, "unit") for p in e.get("unit_files", []) if p != e["file"]]
        out += [(p, "exec") for p in e.get("execs", [])]
        if e.get("workdir") and e["workdir"].startswith("/"):
            out.append((e["workdir"].lstrip("!-"), "ref"))
    elif e["source"] in ("crontab", "cron.d", "spool", "anacrontab"):
        out += [(p, "ref") for p in command_paths(h, e)]
    return out


def under_world_tmp(p):
    return any(p == d or p.startswith(d + "/") for d in WORLD_TMP)


def chain_findings(h, path, role):
    """Path-chain walk (every component from / to the file, symlink targets included) -> findings."""
    fs = []
    if role == "file" and path.startswith("/var/spool/cron/crontabs/"):
        # user crontabs are owned by their user by design (crontab(1)); only the dir chain matters
        path_chain_end = "/var/spool/cron/crontabs"
    else:
        path_chain_end = path
    targets = [path_chain_end]
    r = h.resolve(path_chain_end)
    if r and r != path_chain_end:
        targets.append(r)
    for tgt in targets:
        parts = [x for x in tgt.split("/") if x]
        cur = ""
        for i in range(len(parts) + 1):
            cur = "/" + "/".join(parts[:i])
            st = h.lstat(cur)
            if st is None:
                break
            if stat.S_ISLNK(st.st_mode):
                continue  # link mode bits are meaningless; the link target is walked separately
            last = cur == tgt
            sticky = bool(st.st_mode & stat.S_ISVTX)
            if st.st_uid != h.trusted:
                fs.append(
                    (
                        "chain_owner",
                        cur,
                        f"owner uid {st.st_uid} (want {h.trusted})",
                        False,
                    )
                )
            wr = st.st_mode & 0o022
            if wr and not (sticky and stat.S_ISDIR(st.st_mode) and not last):
                fs.append(
                    (
                        "chain_writable",
                        cur,
                        f"mode {stat.S_IMODE(st.st_mode):04o}",
                        True,
                    )
                )
            elif wr and sticky and not last and stat.S_ISDIR(st.st_mode):
                fs.append(
                    (
                        "writable_dir",
                        cur,
                        f"sticky world-writable dir {stat.S_IMODE(st.st_mode):04o}",
                        False,
                    )
                )
    if under_world_tmp(path) and not any(f[0] == "writable_dir" for f in fs):
        fs.append(("writable_dir", path, "inside a user-writable tree", False))
    return fs


def pkg_findings(h, path, tracked):
    owner, md5 = h.dpkg()
    r = h.resolve(path) or path
    cands = []
    for p in (path, r):
        cands += usr_merge_variants(p)
    pkg = next((owner[c] for c in cands if c in owner), None)
    st = h.lstat(r)
    if st is None or not stat.S_ISREG(st.st_mode):
        return [], pkg
    if pkg:
        want = next((md5[c] for c in cands if c in md5), None)
        if want:
            got = hashlib.md5(h.read(r) or b"").hexdigest()  # dpkg's own md5sums format
            if got != want:
                return [
                    (
                        "pkg_modified",
                        path,
                        f"package {pkg}: md5 differs from dpkg",
                        False,
                    )
                ], pkg
        return [], pkg
    if not tracked(path) and not tracked(r) and not under_world_tmp(path):
        # (under /tmp or /home the writable_dir finding already covers it; pft-integrity never tracks user trees)
        return [
            (
                "untracked",
                path,
                "not in any package and not tracked by pft-integrity",
                False,
            )
        ], None
    return [], None


def integrity_tracked_builtin(p):
    """Paths pft-integrity's built-in item list covers (see ../integrity/pft-integrity.sh build_items)."""
    n = os.path.basename(p)
    d = os.path.dirname(p)
    if d == "/usr/local/bin":
        return True
    if d == "/etc/systemd/system" and re.match(
        r"^(pft-|postfiat-).*\.(service|timer)$", n
    ):
        return True
    return bool(
        re.match(r"^/etc/systemd/system/(pft-|postfiat-)[^/]*\.d$", d)
        and n.endswith(".conf")
    )


def audit(h, entries, scope_hook):
    """Attach findings to entries. scope_hook: pft-integrity tracks `scope` output -> unpackaged entry files count
    as tracked."""
    scope = set(scope_paths(h, entries)) if scope_hook else set()

    def tracked(p):
        return integrity_tracked_builtin(p) or p in scope

    uid_min = h.uid_min()
    users = h.users()
    for e in entries:
        fs = []
        if (
            e["state"] in ("inert-name", "done", "user-unit")
            and e["source"] != "user-timer"
        ):
            e["findings"] = []
            e["paths"] = []
            continue
        paths = entry_paths(h, e)
        e["paths"] = [p for p, _ in paths]
        for p, role in paths:
            if h.lstat(p) is None:
                if role in ("exec",) and e["source"] == "timer":
                    fs.append(("timer_target", p, "ExecStart binary missing", False))
                elif role == "ref" and h.lstat(os.path.dirname(p)) is not None:
                    fs += chain_findings(h, os.path.dirname(p), "ref")
                continue
            fs += chain_findings(h, p, role)
            if role in ("file", "exec", "unit") or (role == "ref" and _is_file(h, p)):
                pf, _ = pkg_findings(h, p, tracked)
                if role == "file" and p.startswith("/var/spool/"):
                    pf = []  # spool files are never packaged; the spool entry itself is the finding below
                fs += pf
        u = e.get("user") or ""
        info = users.get(u)
        if e["source"] == "spool" or (
            info and info["uid"] >= uid_min and info["uid"] != 65534
        ):
            fs.append(
                (
                    "nonsystem_user",
                    e["file"],
                    f"runs as a regular user (uid >= {uid_min})",
                    False,
                )
            )
        if e["source"] == "timer":
            if e.get("unit_load") in ("not-found", "masked", "error", "bad-setting"):
                fs.append(
                    (
                        "timer_target",
                        e["file"] or e["id"],
                        f"unit {e.get('unit') or '-'} {e.get('unit_load')}",
                        False,
                    )
                )
            elif e["state"] == "active" and not e.get("execs"):
                fs.append(
                    (
                        "timer_target",
                        e["file"] or e["id"],
                        f"unit {e.get('unit')} has no ExecStart",
                        False,
                    )
                )
        # one finding per (check, path)
        seen, uniq = set(), []
        for c, p, d, fix in fs:
            if (c, p) not in seen:
                seen.add((c, p))
                uniq.append(
                    {
                        "check": c,
                        "severity": CHECKS[c][0],
                        "path": p,
                        "detail": d,
                        "fixable": fix,
                    }
                )
        e["findings"] = uniq
    return entries


def _is_file(h, p):
    st = h.lstat(h.resolve(p) or p)
    return st is not None and stat.S_ISREG(st.st_mode)


def scope_paths(h, entries):
    """Files pft-integrity should track: the definition file, unit files and every unpackaged regular file each
    scheduled entry runs or names that pft-integrity's built-in list does not cover, plus the scheduling dirs (a NEW
    file there must change an item too)."""
    owner, _ = h.dpkg()
    out = set()
    for e in entries:
        for p, _role in entry_paths(h, e):
            if (
                not p
                or integrity_tracked_builtin(p)
                or p.startswith(SKIP_PREFIX)
                or under_world_tmp(p)
            ):
                continue
            r = h.resolve(p)
            if r is None:
                continue
            st = h.lstat(r)
            if st is None or not stat.S_ISREG(st.st_mode):
                continue
            if any(
                c in owner for c in usr_merge_variants(p) + usr_merge_variants(r)
            ) and not p.startswith("/etc/"):
                continue  # packaged binaries are dpkg-verified; packaged /etc files can be edited, so track them
            out.add(p)
    for k in CRON_DIRS:
        if h.lstat(f"/etc/cron.{k}") is not None:
            out.add(f"/etc/cron.{k}")
    for d in (
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/var/spool/cron/atjobs",
        "/etc/anacrontab",
    ):
        if h.lstat(d) is not None:
            out.add(d)
    return sorted(out)


# ---------------------------------------------------------------- allowlist + state
def load_allow(h_path):
    """Allowlist lines: CHECK ENTRY_GLOB PATH_GLOB REASON...  (CHECK may be '*' only together with a reason).
    A missing reason is a config error: every exception must say why."""
    rules = []
    if not h_path or not os.path.exists(h_path):
        return rules
    with open(h_path) as fh:
        for n, ln in enumerate(fh, 1):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            f = s.split(None, 3)
            if len(f) < 4 or not f[3].strip():
                raise ConfigError(
                    f"allowlist line {n}: need CHECK ENTRY_GLOB PATH_GLOB REASON"
                )
            if f[0] != "*" and f[0] not in CHECKS:
                raise ConfigError(f"allowlist line {n}: unknown check {f[0]}")
            if len(f[3].strip()) < 8:
                raise ConfigError(f"allowlist line {n}: reason too short")
            rules.append(
                {
                    "check": f[0],
                    "entry": f[1],
                    "path": f[2],
                    "reason": f[3].strip(),
                    "line": n,
                    "used": 0,
                }
            )
    return rules


def apply_allow(entries, rules):
    for e in entries:
        for f in e["findings"]:
            f["allowed"] = ""
            for r in rules:
                if (
                    (r["check"] == "*" or r["check"] == f["check"])
                    and fnmatch.fnmatchcase(e["id"], r["entry"])
                    and fnmatch.fnmatchcase(f["path"], r["path"])
                ):
                    f["allowed"] = r["reason"]
                    r["used"] += 1
                    break
    return entries


def load_state(path):
    if not path or not os.path.exists(path):
        return {"version": VERSION, "expected": {}, "accepted_at": 0, "reason": ""}
    with open(path) as fh:
        d = json.load(fh)
    if not isinstance(d, dict) or not isinstance(d.get("expected"), dict):
        raise ConfigError("state file is not a schedaudit state")
    return d


def save_state(path, d):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as fh:
        json.dump(d, fh, sort_keys=True, indent=1)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def drift(entries, state):
    """-> (new ids, removed ids). Only entries that can run (enabled) or are disabled/commented count: a changed line
    gets a new id, so 'changed' shows up as one new + one removed."""
    cur = {e["id"] for e in entries}
    exp = set(state["expected"])
    if not state.get("accepted_at"):
        return (
            [],
            [],
        )  # no baseline yet: everything is unknown, reported by the unaccepted metric instead
    return sorted(cur - exp), sorted(exp - cur)


# ---------------------------------------------------------------- output
def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def summarize(entries, state, rules):
    new, removed = drift(entries, state)
    fnd = [(e, f) for e in entries for f in e["findings"]]
    unallowed = [(e, f) for e, f in fnd if not f["allowed"]]
    return {
        "entries": len(entries),
        "enabled": sum(1 for e in entries if e["enabled"]),
        "new": new,
        "removed": removed,
        "findings": len(fnd),
        "unallowed": unallowed,
        "allowed": len(fnd) - len(unallowed),
        "unused_allow": [r for r in rules if not r["used"]],
        "baseline": bool(state.get("accepted_at")),
    }


def render_prom(host, entries, state, rules, now, ok=True, err=""):
    h = esc(host)
    out = [
        "# HELP pft_schedaudit_up 1 if the last audit could read every scheduling source.",
        "# TYPE pft_schedaudit_up gauge",
        f'pft_schedaudit_up{{host="{h}"}} {1 if ok else 0}',
        "# HELP pft_schedaudit_collect_timestamp_seconds Unix time of the last audit run.",
        "# TYPE pft_schedaudit_collect_timestamp_seconds gauge",
        f'pft_schedaudit_collect_timestamp_seconds{{host="{h}"}} {int(now)}',
    ]
    if not ok:
        return "\n".join(out) + "\n"
    s = summarize(entries, state, rules)
    out += [
        "# HELP pft_schedaudit_entries Scheduled entries by source and state.",
        "# TYPE pft_schedaudit_entries gauge",
    ]
    cnt = {}
    for e in entries:
        cnt[(e["source"], e["state"])] = cnt.get((e["source"], e["state"]), 0) + 1
    for (src, st), n in sorted(cnt.items()):
        out.append(
            f'pft_schedaudit_entries{{host="{h}",source="{esc(src)}",state="{esc(st)}"}} {n}'
        )
    out += [
        "# HELP pft_schedaudit_findings Findings by check and severity (allowed=1: covered by an allowlist reason).",
        "# TYPE pft_schedaudit_findings gauge",
    ]
    fc = {(c, CHECKS[c][0], a): 0 for c in CHECKS for a in ("0", "1")}
    for e in entries:
        for f in e["findings"]:
            k = (f["check"], f["severity"], "1" if f["allowed"] else "0")
            fc[k] += 1
    for (c, sev, a), n in sorted(fc.items()):
        out.append(
            f'pft_schedaudit_findings{{host="{h}",check="{c}",severity="{sev}",allowed="{a}"}} {n}'
        )
    out += [
        "# HELP pft_schedaudit_unexpected Entries/findings nobody accepted: kind=new|removed (vs the accepted set), "
        + "finding (not allowlisted), unaccepted (1 = no baseline yet).",
        "# TYPE pft_schedaudit_unexpected gauge",
        f'pft_schedaudit_unexpected{{host="{h}",kind="new"}} {len(s["new"])}',
        f'pft_schedaudit_unexpected{{host="{h}",kind="removed"}} {len(s["removed"])}',
        f'pft_schedaudit_unexpected{{host="{h}",kind="finding"}} {len(s["unallowed"])}',
        f'pft_schedaudit_unexpected{{host="{h}",kind="unaccepted"}} {0 if s["baseline"] else 1}',
        "# HELP pft_schedaudit_allowlist_unused Allowlist lines that matched no finding (stale exceptions).",
        "# TYPE pft_schedaudit_allowlist_unused gauge",
        f'pft_schedaudit_allowlist_unused{{host="{h}"}} {len(s["unused_allow"])}',
        "# HELP pft_schedaudit_accepted_timestamp_seconds Unix time of the last `accept` (0 = never).",
        "# TYPE pft_schedaudit_accepted_timestamp_seconds gauge",
        f'pft_schedaudit_accepted_timestamp_seconds{{host="{h}"}} {int(state.get("accepted_at") or 0)}',
    ]
    return "\n".join(out) + "\n"


def tsv_inventory(entries):
    rows = ["id\tsource\tstate\tuser\tschedule\tfile:line\tcommand"]
    for e in entries:
        rows.append(
            "\t".join(
                [
                    e["id"],
                    e["source"],
                    e["state"],
                    e["user"] or "-",
                    e["schedule"] or "-",
                    f"{e['file'] or '-'}:{e['line']}",
                    e["command"].replace("\t", " ") or "-",
                ]
            )
        )
    return "\n".join(rows) + "\n"


def tsv_audit(entries, state, rules):
    s = summarize(entries, state, rules)
    rows = []
    for e in entries:
        for f in e["findings"]:
            tag = "ALLOWED" if f["allowed"] else f["severity"].upper()
            rows.append(
                f"{tag}\t{f['check']}\t{e['id']}\t{f['path']}\t{f['detail']}"
                + (f"\t# {f['allowed']}" if f["allowed"] else "")
            )
    for i in s["new"]:
        rows.append(f"NEW\t-\t{i}\t-\tnot in the accepted entry set")
    for i in s["removed"]:
        rows.append(f"REMOVED\t-\t{i}\t-\taccepted entry is gone")
    for r in s["unused_allow"]:
        rows.append(
            f"INFO\tallowlist\tline {r['line']}\t-\tunused: {r['check']} {r['entry']} {r['path']}"
        )
    rows.append(
        f"SUMMARY entries={s['entries']} enabled={s['enabled']} findings={s['findings']} allowed={s['allowed']}"
        f" unexpected_findings={len(s['unallowed'])} new={len(s['new'])} removed={len(s['removed'])}"
        f" baseline={'yes' if s['baseline'] else 'no'} unused_allow={len(s['unused_allow'])}"
    )
    return "\n".join(rows) + "\n", s


def is_unexpected(s):
    return bool(s["unallowed"] or s["new"] or s["removed"] or not s["baseline"])


# ---------------------------------------------------------------- apply (permissions only)
def plan_fixes(entries):
    """chmod go-w for chain_writable findings on paths owned by the trusted uid; nothing else is ever changed."""
    plan = {}
    for e in entries:
        for f in e["findings"]:
            if f["check"] == "chain_writable" and f["fixable"] and not f["allowed"]:
                plan[f["path"]] = e["id"]
    return sorted(plan)


def do_fixes(h, paths, dry):
    log = []
    for p in paths:
        st = h.lstat(p)
        if st is None or stat.S_ISLNK(st.st_mode):
            log.append(f"SKIP\t{p}\tgone or symlink")
            continue
        if st.st_uid != h.trusted:
            log.append(f"SKIP\t{p}\towner uid {st.st_uid}: not a permissions-only fix")
            continue
        old = stat.S_IMODE(st.st_mode)
        new = old & ~0o022
        if dry:
            log.append(f"PLAN\t{p}\t{old:04o} -> {new:04o}")
            continue
        os.chmod(h.real(p), new)
        got = stat.S_IMODE(os.lstat(h.real(p)).st_mode)
        log.append(
            f"{'FIXED' if got == new else 'FAILED'}\t{p}\t{old:04o} -> {got:04o}"
        )
    return log


# ---------------------------------------------------------------- main
def arg(argv, flag, default=None):
    if flag in argv:
        i = argv.index(flag)
        if i + 1 >= len(argv):
            raise ConfigError(f"{flag} needs a value")
        return argv[i + 1]
    return default


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__, file=sys.stderr)
        return 3
    cmd, rest = argv[0], argv[1:]
    try:
        tu = arg(rest, "--trusted-uid", "0")
        now = arg(rest, "--now")
        if not tu.isdigit() or (now is not None and not now.isdigit()):
            raise ConfigError("bad --trusted-uid/--now")
        h = Host(
            arg(rest, "--root", "/"),
            int(tu),
            arg(rest, "--systemctl", "systemctl"),
            int(now) if now else None,
        )
        state_path = arg(rest, "--state")
        rules = load_allow(arg(rest, "--allow"))
        state = load_state(state_path)
        fmt = arg(rest, "--format", "tsv")
        if fmt not in ("tsv", "json"):
            raise ConfigError("bad --format")
        if cmd not in ("inventory", "audit", "prom", "apply", "accept", "scope"):
            raise ConfigError(f"unknown command {cmd}")
        hook = "--integrity-hook" in rest
        try:
            entries = inventory(h)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as ex:
            if cmd == "prom":
                print(
                    render_prom(
                        arg(rest, "--host", "validator"),
                        [],
                        state,
                        rules,
                        h.now,
                        ok=False,
                    ),
                    end="",
                )
            print(f"schedaudit: collection failed: {ex}", file=sys.stderr)
            return 2
        if cmd == "inventory":
            print(
                json.dumps(entries, indent=1, sort_keys=True)
                if fmt == "json"
                else tsv_inventory(entries),
                end="\n" if fmt == "json" else "",
            )
            return 0
        if cmd == "scope":
            print("\n".join(scope_paths(h, entries)))
            return 0
        apply_allow(audit(h, entries, hook), rules)
        if cmd == "accept":
            reason = arg(rest, "--reason", "")
            if len(reason.strip()) < 8:
                raise ConfigError("accept needs --reason (8+ chars)")
            if not state_path:
                raise ConfigError("accept needs --state")
            old = set(state["expected"])
            state = {
                "version": VERSION,
                "expected": {
                    e["id"]: {
                        "source": e["source"],
                        "file": e["file"],
                        "state": e["state"],
                    }
                    for e in entries
                },
                "accepted_at": h.now,
                "reason": reason.strip(),
            }
            save_state(state_path, state)
            cur = set(state["expected"])
            print(
                f"accepted {len(cur)} entries (+{len(cur - old)} -{len(old - cur)}): {reason.strip()}"
            )
            return 0
        if cmd == "apply":
            plan = plan_fixes(entries)
            for ln in do_fixes(h, plan, "--dry-run" in rest):
                print(ln)
            if "--dry-run" in rest:
                return 0
            entries2 = apply_allow(audit(h, inventory(h), hook), rules)
            left = [p for p in plan_fixes(entries2)]
            print(f"RESULT apply: planned={len(plan)} remaining_fixable={len(left)}")
            return 0 if not left else 1
        if cmd == "prom":
            text = render_prom(
                arg(rest, "--host", "validator"), entries, state, rules, h.now
            )
            print(text, end="")
            return 1 if is_unexpected(summarize(entries, state, rules)) else 0
        # audit
        text, s = tsv_audit(entries, state, rules)
        if fmt == "json":
            print(
                json.dumps(
                    {
                        "entries": entries,
                        "new": s["new"],
                        "removed": s["removed"],
                        "summary": {
                            k: (len(v) if isinstance(v, list) else v)
                            for k, v in s.items()
                        },
                    },
                    indent=1,
                    sort_keys=True,
                )
            )
        else:
            print(text, end="")
        return 1 if is_unexpected(s) else 0
    except ConfigError as ex:
        print(f"schedaudit: {ex}", file=sys.stderr)
        return 3
    except (json.JSONDecodeError, ValueError) as ex:
        print(f"schedaudit: bad state/allowlist: {ex}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
