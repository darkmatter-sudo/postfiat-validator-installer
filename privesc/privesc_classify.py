#!/usr/bin/env python3
"""Classify local privilege-escalation paths on a Post Fiat validator/sentry host (Ubuntu 22.04).

Called by pft-privesc.sh, which collects the facts that need external commands (find, dpkg, getcap, systemctl,
getent, docker, visudo) into FACTS_DIR. This script runs nothing; it reads FACTS_DIR plus files under --root and
stat()s paths itself.

  privesc_classify.py grade --facts DIR [--root PREFIX] [--host L] [--now EPOCH] [--json] [--metrics FILE]
                            [--actions FILE] [--show-names] [--unneeded-suid P:P..] [--remove-suid P:P..]
                            [--cap-allow P:P..] [--rooteq-groups G,G..] [--root-uid N]
  privesc_classify.py ids     check ID table (markdown, used in README.md)

Facts (TSV, "-" for an empty field; lesson: `IFS=$'\\t' read` collapses empty fields, so none are empty):
  suid.tsv     PATH MODE(octal) UID GID PKG PKGPATH        PKG/PKGPATH "-" = no dpkg owner
  md5.tsv      PATH                                       files `dpkg --verify` reports with a changed md5sum
  override.tsv USER GROUP MODE PATH                       `dpkg-statoverride --list`
  caps.tsv     PATH CAPS PKG
  units.show   raw `systemctl show --all -p Id,User,FragmentPath,DropInPaths,Exec... '*'` blocks
  passwd.tsv   NAME UID GID SHELL                              group.tsv  NAME GID MEMBERS(comma)
  mounts.tsv   CONTAINER SOURCE                           one line per bind mount of a running container
  visudo.txt   line 1 "rc=N", then visudo -c output
Exit: 0 no WARN/FAIL; 1 at least one WARN or FAIL; 2 collection error (errors.tsv non-empty or facts missing).
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys

PASS, INFO, WARN, FAIL = "PASS", "INFO", "WARN", "FAIL"
AREAS = ("suid", "sudoers", "exec", "path", "rooteq")

# SUID/SGID binaries a headless validator needs (dpkg-owned, unmodified, root-owned, not writable -> PASS)
KEEP_SUID = {
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chage",
    "/usr/bin/expiry",
    "/usr/bin/crontab",
    "/usr/bin/ssh-agent",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/x86_64-linux-gnu/utempter/utempter",
}
# dpkg-owned SUID binaries with no use on a headless node (WARN; apply removes the bit through dpkg-statoverride)
UNNEEDED_SUID = [
    "/usr/bin/pkexec",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/fusermount3",
    "/usr/lib/openssh/ssh-keysign",
]
# never changed by apply, whatever a finding says
PROTECTED = {"/usr/bin/sudo", "/usr/bin/su", "/usr/sbin/unix_chkpwd", "/usr/bin/passwd"}
CAP_ALLOW = ["/usr/bin/ping", "/usr/bin/mtr-packet", "/usr/lib/snapd/snap-confine"]
# dpkg-owned files whose capabilities have no use on a headless node (WARN; apply: setcap -r, undo restores)
UNNEEDED_CAPS = ["/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"]
ROOTEQ_GROUPS = ["docker", "lxd", "disk"]
RUNTIME_SOCKETS = [
    "/run/containerd/containerd.sock",
    "/var/snap/lxd/common/lxd/unix.socket",
    "/run/docker.sock",
    "/var/run/docker.sock",
]
CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]
SCRIPT_EXT = (".sh", ".py", ".pl", ".rb", ".bash")
NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")
SYSTEMD_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# NOPASSWD commands that can spawn a shell or write any file (short GTFOBins subset)
SHELL_ESCAPE = {
    "vi",
    "vim",
    "nano",
    "ed",
    "less",
    "more",
    "man",
    "find",
    "awk",
    "gawk",
    "mawk",
    "sed",
    "perl",
    "python",
    "python3",
    "ruby",
    "lua",
    "bash",
    "sh",
    "dash",
    "zsh",
    "env",
    "tee",
    "cp",
    "mv",
    "tar",
    "zip",
    "unzip",
    "git",
    "docker",
    "journalctl",
    "systemctl",
    "nmap",
    "rsync",
    "scp",
    "ssh",
    "dd",
    "chmod",
    "chown",
    "install",
    "apt",
    "apt-get",
    "dpkg",
    "pip",
    "pip3",
    "crontab",
    "su",
    "sudoedit",
    "vipw",
    "visudo",
    "openssl",
    "socat",
    "nc",
    "curl",
    "wget",
    "node",
    "php",
    "make",
    "script",
    "expect",
    "busybox",
    "xargs",
    "nsenter",
    "unshare",
}
DANGEROUS_ENV = (
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5LIB",
    "PERL5OPT",
    "BASH_ENV",
    "ENV",
    "RUBYLIB",
    "NODE_OPTIONS",
)

# check ID -> (area, summary); `ids` prints this table
IDS = {
    "PE-SUID-OK": (
        "suid",
        "dpkg-owned, unmodified, root-owned, not writable, needed (PASS)",
    ),
    "PE-SUID-UNNEEDED": (
        "suid",
        "dpkg-owned SUID/SGID with no use on a headless node (WARN; apply: statoverride)",
    ),
    "PE-SUID-REMOVED": (
        "suid",
        "unneeded bit already removed by a dpkg-statoverride (PASS)",
    ),
    "PE-SUID-REVIEW": (
        "suid",
        "dpkg-owned SUID/SGID not on the keep or unneeded list (WARN, review)",
    ),
    "PE-SUID-UNPKG": (
        "suid",
        "SUID/SGID file no package owns (FAIL; apply strips it only if in REMOVE_SUID)",
    ),
    "PE-SUID-MODIFIED": (
        "suid",
        "dpkg --verify: md5sum differs from the package (FAIL)",
    ),
    "PE-SUID-WRITABLE": (
        "suid",
        "SUID/SGID file or a parent dir writable by non-root (FAIL; apply: chmod go-w)",
    ),
    "PE-SUID-OWNER": (
        "suid",
        "SUID/SGID file not owned by root (FAIL; apply: chown root, only if dpkg-owned)",
    ),
    "PE-CAP-OK": (
        "suid",
        "file capabilities on an allowlisted dpkg-owned binary (PASS)",
    ),
    "PE-CAP-UNNEEDED": (
        "suid",
        "file capabilities with no use on a headless node (WARN; apply: setcap -r)",
    ),
    "PE-CAP-REVIEW": (
        "suid",
        "file capabilities on another dpkg-owned binary (WARN, review)",
    ),
    "PE-CAP-UNPKG": ("suid", "file capabilities on a file no package owns (FAIL)"),
    "PE-SUDO-SYNTAX": ("sudoers", "visudo -c fails (FAIL)"),
    "PE-SUDO-PERM": (
        "sudoers",
        "sudoers file not root:root or group/world-writable (FAIL; apply: chown + chmod 0440)",
    ),
    "PE-SUDO-CMD-WRITABLE": (
        "sudoers",
        "a sudo rule names a command whose path is writable by non-root (FAIL)",
    ),
    "PE-SUDO-CMD-RELATIVE": ("sudoers", "a sudo rule names a relative command (FAIL)"),
    "PE-SUDO-SHELLESC": (
        "sudoers",
        "NOPASSWD rule for a command that can spawn a shell (WARN)",
    ),
    "PE-SUDO-WILDCARD": (
        "sudoers",
        "rule with a * wildcard in command arguments (WARN)",
    ),
    "PE-SUDO-ENV": (
        "sudoers",
        "env_keep/setenv lets a loader/interpreter variable through, or !env_reset (FAIL)",
    ),
    "PE-SUDO-DEFAULTS": ("sudoers", "Defaults secure_path / use_pty missing (WARN)"),
    "PE-SUDO-ADMIN": (
        "sudoers",
        "full-root rule (ALL commands); names hashed unless --show-names (INFO)",
    ),
    "PE-SUDO-OK": (
        "sudoers",
        "visudo OK, every file root:root and not writable (PASS)",
    ),
    "PE-EXEC-UNIT": (
        "exec",
        "root unit runs a file (or a script argument) writable by non-root (FAIL; apply: chmod go-w)",
    ),
    "PE-EXEC-UNITFILE": (
        "exec",
        "unit file or drop-in of a root unit writable by non-root (FAIL; apply: chmod go-w)",
    ),
    "PE-EXEC-CRON": (
        "exec",
        "cron file, cron script or a command it runs writable by non-root (FAIL; apply: chmod go-w)",
    ),
    "PE-EXEC-OK": ("exec", "every root unit and cron exec chain checked clean (PASS)"),
    "PE-PATH-REL": ("path", "empty or relative entry in a root PATH (FAIL)"),
    "PE-PATH-DIR": (
        "path",
        "root PATH directory (or a parent) writable by non-root (FAIL; apply: chmod go-w)",
    ),
    "PE-PATH-FILE": (
        "path",
        "file in a root PATH directory writable by non-root (FAIL; apply: chmod go-w)",
    ),
    "PE-PATH-OK": ("path", "every root PATH entry and its files checked clean (PASS)"),
    "PE-ROOTEQ-GROUP": (
        "rooteq",
        "member of docker/lxd/disk without a full sudo rule = hidden root (FAIL)",
    ),
    "PE-ROOTEQ-ADMIN": (
        "rooteq",
        "member of a root-equivalent group who already has full sudo (INFO)",
    ),
    "PE-ROOTEQ-SERVICE": (
        "rooteq",
        "no-login service account in a root-equivalent group, e.g. the lxd daemon user (INFO)",
    ),
    "PE-ROOTEQ-SOCK": (
        "rooteq",
        "containerd/lxd/docker runtime socket readable or writable by others (FAIL; apply: chmod o-rwx)",
    ),
    "PE-ROOTEQ-MOUNT": (
        "rooteq",
        "running container bind-mounts a runtime socket or the host root (FAIL)",
    ),
    "PE-ROOTEQ-OK": ("rooteq", "no hidden root-equivalent access (PASS)"),
}


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


class Ctx:
    def __init__(self, a):
        self.root = a.root.rstrip("/")
        self.root_uids = {0} if a.root_uid is None else {0, a.root_uid}
        self.show_names = a.show_names
        self.findings = []
        self.seen = set()
        try:
            self.salt = read_text(self.p("/etc/machine-id")).strip()
        except OSError:
            self.salt = ""
        self.actions = []
        self.errors = []
        self.facts = a.facts

    def p(self, path):  # host path -> path under the test root
        return self.root + path if self.root else path

    def name(self, acct):
        if self.show_names:
            return acct
        # keyed by this host's machine-id: a bare sha256 of a short account name is reversed by guessing
        return (
            "acct-" + hashlib.sha256((self.salt + ":" + acct).encode()).hexdigest()[:8]
        )

    def shown(self, path):  # /home/<name>/... -> /home/acct-xxxx/...
        m = re.match(r"^/home/([^/]+)(/.*)?$", path)
        if m and not self.show_names:
            return "/home/" + self.name(m.group(1)) + (m.group(2) or "")
        return path

    def add(self, cid, grade, subject, detail, hint="-", action=None):
        key = (cid, subject, detail)
        if key in self.seen:  # ExecStart and ExecStartPre often name the same file
            return
        self.seen.add(key)
        self.findings.append(
            {
                "id": cid,
                "area": IDS[cid][0],
                "grade": grade,
                "subject": self.shown(subject),
                "detail": detail,
                "hint": hint,
            }
        )
        # one change per (type, path): a world-writable file can be named by a unit, a cron line and PATH
        if action and (action[0], action[2]) not in {
            (x[1], x[3]) for x in self.actions
        }:
            self.actions.append((cid,) + action)

    def tsv(self, name, ncols, required=True):
        path = os.path.join(self.facts, name)
        if not os.path.exists(path):
            if required:
                self.errors.append(f"facts file {name} missing")
            return []
        rows = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line:
                    continue
                cols = line.split("\t")
                if len(cols) != ncols:
                    self.errors.append(f"{name}:{n}: {len(cols)} fields, want {ncols}")
                    continue
                rows.append(["" if c == "-" else c for c in cols])
        return rows


def chain_issue(ctx, path, final_only=False):
    """First reason PATH (or a parent dir) can be changed by a non-root user, as (element, reason, fix_mode)."""
    host = os.path.normpath(path)
    if not host.startswith("/"):
        return path, "not an absolute path", None
    elems = [host]
    if not final_only:
        d = os.path.dirname(host)
        while True:
            elems.append(d)
            if d in ("/", ""):
                break
            d = os.path.dirname(d)
    for i, e in enumerate(elems):
        try:
            st = os.lstat(ctx.p(e))
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            # a symlink's own mode is ignored; its target is checked separately by the callers that resolve
            if st.st_uid not in ctx.root_uids:
                return e, f"symlink owned by uid {st.st_uid}", None
            continue
        mode = stat.S_IMODE(st.st_mode)
        sticky_dir = stat.S_ISDIR(st.st_mode) and mode & stat.S_ISVTX and i > 0
        if st.st_uid not in ctx.root_uids:
            return e, f"owned by uid {st.st_uid}", None
        if mode & 0o002 and not sticky_dir:
            return e, f"world-writable (mode {mode:04o})", mode & ~0o022
        if mode & 0o020 and st.st_gid not in ctx.root_uids and not sticky_dir:
            return (
                e,
                f"group-writable by gid {st.st_gid} (mode {mode:04o})",
                mode & ~0o022,
            )
    return None


def resolve(ctx, path):  # follow symlinks inside the test root
    real = os.path.realpath(ctx.p(path))
    if ctx.root and real.startswith(ctx.root + "/"):
        real = real[len(ctx.root) :]
    return real


def exec_chain(ctx, path):
    """chain_issue for PATH and, if it is a symlink, its resolved target."""
    r = chain_issue(ctx, path)
    if r:
        return r
    real = resolve(ctx, path)
    if real != os.path.normpath(path):
        return chain_issue(ctx, real)
    return None


def chmod_action(ctx, element, fix_mode):
    if fix_mode is None:
        return None
    return ("chmod", f"{fix_mode:04o}", element)


# ---------------------------------------------------------------- area 1: SUID/SGID + file capabilities
def check_suid(ctx, a):
    unneeded = a.unneeded_suid.split(":") if a.unneeded_suid else UNNEEDED_SUID
    remove = set(a.remove_suid.split(":")) if a.remove_suid else set()
    md5 = {r[0] for r in ctx.tsv("md5.tsv", 1)}
    overrides = {r[3]: r for r in ctx.tsv("override.tsv", 4)}
    seen = set()
    for path, mode_s, uid_s, gid_s, pkg, pkgpath in ctx.tsv("suid.tsv", 6):
        seen.add(path)
        mode = int(mode_s, 8)
        bits = (
            ("SUID" if mode & 0o4000 else "")
            + ("+" if mode & 0o4000 and mode & 0o2000 else "")
            + ("SGID" if mode & 0o2000 else "")
        )
        desc = f"{bits} mode {mode:04o}"
        if path in PROTECTED and not pkg:
            ctx.add(
                "PE-SUID-UNPKG",
                FAIL,
                path,
                f"{desc}, no dpkg owner for a protected binary",
                "apt-get install --reinstall the owning package; investigate",
            )
            continue
        w = chain_issue(ctx, path)
        if w:
            act = None if w[0] in PROTECTED else chmod_action(ctx, w[0], w[2])
            ctx.add(
                "PE-SUID-WRITABLE",
                FAIL,
                path,
                f"{desc}; {ctx.shown(w[0])} {w[1]}",
                "chmod go-w on it",
                act,
            )
            continue
        if int(uid_s) not in ctx.root_uids:
            act = ("chown", "0:" + gid_s, path) if pkg else None
            ctx.add(
                "PE-SUID-OWNER",
                FAIL,
                path,
                f"{desc}, owned by uid {uid_s}",
                "chown root (dpkg-owned only)",
                act,
            )
            continue
        if not pkg:
            act = (
                ("suid-remove", f"{mode & ~0o6000:04o}", path, "-")
                if path in remove
                else None
            )
            ctx.add(
                "PE-SUID-UNPKG",
                FAIL,
                path,
                f"{desc}, not owned by any package",
                "remove it, or list it in REMOVE_SUID for apply to strip the bit",
                act,
            )
            continue
        if path in md5 or (pkgpath and pkgpath in md5):
            ctx.add(
                "PE-SUID-MODIFIED",
                FAIL,
                path,
                f"{desc}, dpkg --verify: md5sum differs from package {pkg}",
                f"apt-get install --reinstall {pkg}; investigate",
            )
            continue
        if path in unneeded:
            ctx.add(
                "PE-SUID-UNNEEDED",
                WARN,
                path,
                f"{desc} ({pkg}), not needed on a headless node",
                "sudo pft-privesc apply (dpkg-statoverride, survives upgrades)",
                ("suid-remove", f"{mode & ~0o6000:04o}", path, pkgpath or path),
            )
        elif path in KEEP_SUID:
            ctx.add("PE-SUID-OK", PASS, path, f"{desc} ({pkg})")
        else:
            ctx.add(
                "PE-SUID-REVIEW",
                WARN,
                path,
                f"{desc} ({pkg}), not on the keep or unneeded list",
                "decide: add to UNNEEDED_SUID (apply removes it) or accept",
            )
    for path in unneeded:
        if path in seen:
            continue
        ov = overrides.get(path) or overrides.get(
            re.sub(r"^/usr/(bin|sbin|lib)/", r"/\1/", path)
        )
        if ov and not int(ov[2], 8) & 0o6000:
            ctx.add(
                "PE-SUID-REMOVED",
                PASS,
                path,
                f"bit removed by dpkg-statoverride (mode {ov[2]})",
            )
    allow = a.cap_allow.split(":") if a.cap_allow else CAP_ALLOW
    for path, caps, pkg in ctx.tsv("caps.tsv", 3):
        if not pkg:
            ctx.add(
                "PE-CAP-UNPKG",
                FAIL,
                path,
                f"capabilities {caps}, not owned by any package",
                "setcap -r it, or remove the file",
            )
        elif path in allow:
            ctx.add("PE-CAP-OK", PASS, path, f"{caps} ({pkg})")
        elif path in UNNEEDED_CAPS:
            ctx.add(
                "PE-CAP-UNNEEDED",
                WARN,
                path,
                f"{caps} ({pkg}), not needed on a headless node",
                "sudo pft-privesc apply (setcap -r; a package upgrade restores it, the audit then WARNs again)",
                ("cap-remove", caps, path),
            )
        else:
            ctx.add(
                "PE-CAP-REVIEW",
                WARN,
                path,
                f"{caps} ({pkg}), not on the capability allowlist",
                "setcap -r if unused (reverted by package upgrades), or add to CAP_ALLOW",
            )


# ---------------------------------------------------------------- area 2: sudoers
def sudoers_files(ctx):
    """[/etc/sudoers, included files...] in sudo's order (#include/@include, #includedir/@includedir)."""
    out, todo, seen = [], ["/etc/sudoers"], set()
    while todo:
        f = todo.pop(0)
        if f in seen or not os.path.isfile(ctx.p(f)):
            continue
        seen.add(f)
        out.append(f)
        with open(ctx.p(f), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"^\s*[#@]include(dir)?\s+(\S+)", line)
                if not m:
                    continue
                if m.group(1):
                    d = m.group(2)
                    try:
                        names = sorted(os.listdir(ctx.p(d)))
                    except OSError:
                        continue
                    # sudo skips names that end in ~ or contain a dot
                    todo += [
                        os.path.join(d, n)
                        for n in names
                        if not n.endswith("~") and "." not in n
                    ]
                else:
                    todo.append(m.group(2))
    return out


def logical_lines(text):
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        s = buf.strip()
        buf = ""
        if s and not (s.startswith("#") and not re.match(r"^#include", s)):
            yield s


def split_top(s, sep=","):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def parse_sudoers(ctx, files):
    aliases = {"User_Alias": {}, "Cmnd_Alias": {}, "Runas_Alias": {}, "Host_Alias": {}}
    defaults, rules = [], []
    for f in files:
        try:
            text = read_text(ctx.p(f))
        except OSError as e:
            ctx.errors.append(f"cannot read {f}: {e.strerror}")
            continue
        for line in logical_lines(text):
            if re.match(r"^[#@]include", line):
                continue
            m = re.match(
                r"^(User_Alias|Cmnd_Alias|Cmd_Alias|Runas_Alias|Host_Alias)\s+(.*)$",
                line,
            )
            if m:
                kind = "Cmnd_Alias" if m.group(1) == "Cmd_Alias" else m.group(1)
                for part in m.group(2).split(":"):
                    if "=" in part:
                        n, v = part.split("=", 1)
                        aliases[kind][n.strip()] = split_top(v)
                continue
            if re.match(r"^Defaults([@:!>]\S*)?\s", line):
                defaults.append((f, line.split(None, 1)[1]))
                continue
            m = re.match(r"^(\S+(?:\s*,\s*\S+)*)\s+(.*)$", line)
            if not m:
                continue
            who = [w.strip() for w in m.group(1).split(",")]
            # one Host=Cmnds spec per line here: ':' also separates tags (NOPASSWD:) and runas (ALL:ALL), and
            # multi-spec lines ("h1=c1 : h2=c2") are not used on these hosts; a later spec is read as commands
            for spec in [m.group(2)]:
                if "=" not in spec:
                    continue
                cmds = spec.split("=", 1)[1].strip()
                runas = ""
                rm = re.match(r"^\(([^)]*)\)\s*(.*)$", cmds)
                if rm:
                    runas, cmds = rm.group(1), rm.group(2)
                tags = set()
                for c in split_top(cmds):
                    while True:
                        tm = re.match(r"^([A-Z_]+):\s*(.*)$", c)
                        if not tm:
                            break
                        tags.add(tm.group(1))
                        c = tm.group(2)
                    rules.append(
                        {
                            "file": f,
                            "who": who,
                            "runas": runas,
                            "tags": set(tags),
                            "cmd": c.strip(),
                        }
                    )
    return aliases, defaults, rules


def expand(aliases, kind, items, depth=0):
    out = []
    for it in items:
        neg = it.startswith("!")
        name = it.lstrip("!").strip()
        if depth < 8 and name in aliases[kind]:
            out += expand(aliases, kind, aliases[kind][name], depth + 1)
        elif not neg:
            out.append(name)
    return out


def admins(ctx, aliases, rules):
    """(users, groups) that have a rule granting ALL commands as root."""
    users, groups = set(), set()
    for r in rules:
        if "ALL" not in expand(aliases, "Cmnd_Alias", [r["cmd"]]):
            continue
        for w in expand(aliases, "User_Alias", r["who"]):
            if w.startswith("%"):
                groups.add(w[1:])
            elif w not in ("ALL", "root"):
                users.add(w)
    return users, groups


def check_sudoers(ctx):
    vis = os.path.join(ctx.facts, "visudo.txt")
    files = sudoers_files(ctx)
    if not files:
        ctx.errors.append("no /etc/sudoers")
        return set(), set()
    bad = 0
    try:
        lines = read_text(vis).splitlines()
    except OSError:
        lines = []
        ctx.errors.append("facts file visudo.txt missing")
    if lines and lines[0] != "rc=0":
        bad += 1
        msg = next((x for x in lines[1:] if "parsed OK" not in x), lines[0])
        ctx.add(
            "PE-SUDO-SYNTAX",
            FAIL,
            "/etc/sudoers",
            f"visudo -c failed: {msg[:160]}",
            "sudo visudo -c; fix the file",
        )
    for f in files:
        st = os.lstat(ctx.p(f))
        mode = stat.S_IMODE(st.st_mode)
        if (
            st.st_uid not in ctx.root_uids
            or st.st_gid not in ctx.root_uids
            or mode & 0o022
        ):
            bad += 1
            ctx.add(
                "PE-SUDO-PERM",
                FAIL,
                f,
                f"owner {st.st_uid}:{st.st_gid} mode {mode:04o}",
                "chown root:root; chmod 0440",
                ("sudoers-fix", "0440", f),
            )
        else:
            w = chain_issue(ctx, os.path.dirname(f))
            if w:
                bad += 1
                ctx.add(
                    "PE-SUDO-PERM",
                    FAIL,
                    f,
                    f"{ctx.shown(w[0])} {w[1]}",
                    "chmod go-w on it",
                    chmod_action(ctx, w[0], w[2]),
                )
    aliases, defaults, rules = parse_sudoers(ctx, files)
    dtext = " ".join(d for _, d in defaults)
    if re.search(r"!\s*env_reset\b", dtext):
        bad += 1
        ctx.add(
            "PE-SUDO-ENV",
            FAIL,
            "Defaults",
            "!env_reset: the caller's environment reaches root",
            "remove !env_reset",
        )
    for var in DANGEROUS_ENV:
        if re.search(r"env_keep\s*\+?=.*\b" + var + r"\b", dtext):
            bad += 1
            ctx.add(
                "PE-SUDO-ENV",
                FAIL,
                "Defaults",
                f"env_keep keeps {var}",
                f"remove {var} from env_keep",
            )
    for name in ("secure_path", "use_pty"):
        if not re.search(r"(^|[\s,])" + name + r"\b", dtext):
            ctx.add(
                "PE-SUDO-DEFAULTS",
                WARN,
                "Defaults",
                f"{name} not set",
                f"add 'Defaults {name}...' via visudo",
            )
    for r in rules:
        for cmd in expand(aliases, "Cmnd_Alias", [r["cmd"]]):
            if cmd in ("ALL", "sudoedit") or cmd.startswith("sudoedit "):
                continue
            path = cmd.split()[0]
            who = ",".join(
                w if w.startswith("%") or w == "ALL" else ctx.name(w)
                for w in expand(aliases, "User_Alias", r["who"])
            )
            if not path.startswith("/"):
                bad += 1
                ctx.add(
                    "PE-SUDO-CMD-RELATIVE",
                    FAIL,
                    r["file"],
                    f"{who}: relative command {path}",
                    "use an absolute path",
                )
                continue
            w = exec_chain(ctx, path)
            if w:
                bad += 1
                ctx.add(
                    "PE-SUDO-CMD-WRITABLE",
                    FAIL,
                    r["file"],
                    f"{who}: {ctx.shown(path)}: {ctx.shown(w[0])} {w[1]}",
                    "chmod go-w / chown root the command and its parents",
                    chmod_action(ctx, w[0], w[2]),
                )
            if "NOPASSWD" in r["tags"] and os.path.basename(path) in SHELL_ESCAPE:
                ctx.add(
                    "PE-SUDO-SHELLESC",
                    WARN,
                    r["file"],
                    f"{who}: NOPASSWD {os.path.basename(path)} can spawn a shell",
                    "require a password, or wrap the exact task in a root-owned script",
                )
            parts = cmd.split(None, 1)
            if len(parts) > 1 and "*" in parts[1]:
                ctx.add(
                    "PE-SUDO-WILDCARD",
                    WARN,
                    r["file"],
                    f"{who}: wildcard arguments in {os.path.basename(path)}",
                    "list the exact arguments",
                )
    users, groups = admins(ctx, aliases, rules)
    for u in sorted(users):
        ctx.add(
            "PE-SUDO-ADMIN",
            INFO,
            "sudoers",
            f"full-root rule for account {ctx.name(u)}",
        )
    for g in sorted(groups):
        ctx.add("PE-SUDO-ADMIN", INFO, "sudoers", f"full-root rule for group %{g}")
    if bad == 0:
        ctx.add(
            "PE-SUDO-OK",
            PASS,
            "sudoers",
            f"visudo OK, {len(files)} file(s) root:root and not writable, "
            f"{len(rules)} rule(s) parsed",
        )
    return users, groups


# ---------------------------------------------------------------- area 3: units + cron
def parse_units(ctx):
    path = os.path.join(ctx.facts, "units.show")
    try:
        text = read_text(path)
    except OSError:
        ctx.errors.append("facts file units.show missing")
        return []
    units = []
    for block in text.split("\n\n"):
        u = {"exec": [], "args": []}
        for line in block.splitlines():
            k, _, v = line.partition("=")
            if k in ("Id", "User", "FragmentPath"):
                u[k] = v
            elif k == "DropInPaths":
                u["dropins"] = v.split()
            elif k.startswith("Exec") and v:
                u["exec"] += re.findall(r"path=([^ ;]+)", v)
                for argv in re.findall(r"argv\[\]=([^;]*)", v):
                    u["args"] += [t for t in argv.split()[1:] if t.startswith("/")]
        if u.get("Id"):
            units.append(u)
    return units


def check_exec(ctx):
    bad = checked = 0
    for u in parse_units(ctx):
        if u.get("User") not in ("", "root", "0", None):
            continue
        for p in u["exec"]:
            if not p.startswith("/"):
                # bare name: systemd resolves it in its fixed search path at start time
                found = [
                    d + "/" + p
                    for d in SYSTEMD_PATH.split(":")
                    if os.path.isfile(ctx.p(d + "/" + p))
                ]
                if not found:
                    continue
                p = found[0]
            checked += 1
            w = exec_chain(ctx, p)
            if w:
                bad += 1
                ctx.add(
                    "PE-EXEC-UNIT",
                    FAIL,
                    u["Id"],
                    f"runs {ctx.shown(p)}: {ctx.shown(w[0])} {w[1]}",
                    "chmod go-w (or chown root) it",
                    chmod_action(ctx, w[0], w[2]),
                )
        for p in u["args"]:
            # only script arguments (an interpreter's program), not data/log files a unit names
            if not os.path.isfile(ctx.p(p)) or not (
                os.access(ctx.p(p), os.X_OK) or p.endswith(SCRIPT_EXT)
            ):
                continue
            checked += 1
            w = exec_chain(ctx, p)
            if w:
                bad += 1
                ctx.add(
                    "PE-EXEC-UNIT",
                    FAIL,
                    u["Id"],
                    f"argument {ctx.shown(p)}: {ctx.shown(w[0])} {w[1]}",
                    "chmod go-w (or chown root) it",
                    chmod_action(ctx, w[0], w[2]),
                )
        for p in ([u["FragmentPath"]] if u.get("FragmentPath") else []) + u.get(
            "dropins", []
        ):
            checked += 1
            w = chain_issue(ctx, p)
            if w:
                bad += 1
                ctx.add(
                    "PE-EXEC-UNITFILE",
                    FAIL,
                    u["Id"],
                    f"{ctx.shown(p)}: {ctx.shown(w[0])} {w[1]}",
                    "chmod go-w it",
                    chmod_action(ctx, w[0], w[2]),
                )
    cron_files = ["/etc/crontab", "/etc/anacrontab"]
    for d in CRON_DIRS + ["/var/spool/cron/crontabs"]:
        try:
            cron_files += [os.path.join(d, n) for n in sorted(os.listdir(ctx.p(d)))]
        except OSError:
            pass
    for f in cron_files:
        if not os.path.isfile(ctx.p(f)):
            continue
        checked += 1
        w = exec_chain(ctx, f)
        if w:
            bad += 1
            ctx.add(
                "PE-EXEC-CRON",
                FAIL,
                f,
                f"{ctx.shown(w[0])} {w[1]}",
                "chmod go-w it",
                chmod_action(ctx, w[0], w[2]),
            )
            continue
        if not (
            f.startswith(("/etc/cron.d/", "/var/spool/cron/"))
            or f in ("/etc/crontab", "/etc/anacrontab")
        ):
            continue  # run-parts script: the file itself is the command
        try:
            text = read_text(ctx.p(f))
        except OSError:
            continue
        for line in logical_lines(text):
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
                continue
            for tok in re.findall(r"(?:^|[\s;&|(])(/[^\s;&|()<>'\"]+)", line):
                if os.path.isfile(ctx.p(tok)) and (
                    os.access(ctx.p(tok), os.X_OK) or tok.endswith(SCRIPT_EXT)
                ):
                    checked += 1
                    w = exec_chain(ctx, tok)
                    if w:
                        bad += 1
                        ctx.add(
                            "PE-EXEC-CRON",
                            FAIL,
                            f,
                            f"runs {ctx.shown(tok)}: {ctx.shown(w[0])} {w[1]}",
                            "chmod go-w it",
                            chmod_action(ctx, w[0], w[2]),
                        )
    if bad == 0:
        ctx.add(
            "PE-EXEC-OK",
            PASS,
            "units+cron",
            f"{checked} exec/unit/cron paths of root units and cron checked",
        )


# ---------------------------------------------------------------- area 4: root PATH
def root_paths(ctx, files):
    out = [("systemd", SYSTEMD_PATH)]
    for f in files:
        try:
            text = read_text(ctx.p(f))
        except OSError:
            continue
        for m in re.finditer(r'secure_path\s*=\s*"?([^"\s,]*)"?', text):
            out.append(("sudo secure_path", m.group(1)))
    try:
        for line in read_text(ctx.p("/etc/environment")).splitlines():
            m = re.match(r'^\s*PATH\s*=\s*"?([^"\n]*)"?', line)
            if m:
                out.append(("/etc/environment", m.group(1)))
    except OSError:
        pass
    return out


def check_path(ctx, files):
    bad = 0
    dirs = []
    for src, value in root_paths(ctx, files):
        for e in value.split(":"):
            if not e.startswith("/"):
                bad += 1
                ctx.add(
                    "PE-PATH-REL",
                    FAIL,
                    src,
                    f"PATH entry {e!r} is empty or relative (root runs ./x)",
                    "remove it from PATH",
                )
            elif e not in dirs and resolve(ctx, e) not in [
                resolve(ctx, x) for x in dirs
            ]:
                dirs.append(
                    e
                )  # /bin and /usr/bin are one dir with usrmerge: check it once
    nfiles = 0
    for d in dirs:
        target = d if os.path.exists(ctx.p(d)) else os.path.dirname(d)
        w = exec_chain(ctx, target)
        if w:
            bad += 1
            ctx.add(
                "PE-PATH-DIR",
                FAIL,
                d,
                f"{ctx.shown(w[0])} {w[1]}",
                "chmod go-w it",
                chmod_action(ctx, w[0], w[2]),
            )
            continue
        if not os.path.isdir(ctx.p(d)):
            continue
        for n in sorted(os.listdir(ctx.p(d))):
            f = os.path.join(d, n)
            nfiles += 1
            w = chain_issue(ctx, f, final_only=True)
            if w is None and os.path.islink(ctx.p(f)):
                w = exec_chain(ctx, resolve(ctx, f))
            if w:
                bad += 1
                ctx.add(
                    "PE-PATH-FILE",
                    FAIL,
                    f,
                    f"{ctx.shown(w[0])} {w[1]}",
                    "chmod go-w (or chown root) it",
                    chmod_action(ctx, w[0], w[2]),
                )
    if bad == 0:
        ctx.add(
            "PE-PATH-OK",
            PASS,
            "PATH",
            f"{len(dirs)} PATH dirs, {nfiles} entries checked",
        )


# ---------------------------------------------------------------- area 5: root-equivalent access
def check_rooteq(ctx, a, sudo_users, sudo_groups):
    bad = 0
    groups = {
        r[0]: (r[1], [m for m in r[2].split(",") if m]) for r in ctx.tsv("group.tsv", 3)
    }
    passwd = ctx.tsv("passwd.tsv", 4)
    shells = {r[0]: r[3] for r in passwd}
    gid_names = {}
    for name, (gid, members) in groups.items():
        gid_names.setdefault(gid, []).append(name)
    for gname in a.rooteq_groups.split(",") if a.rooteq_groups else ROOTEQ_GROUPS:
        if gname not in groups:
            continue
        gid, members = groups[gname]
        members = set(members) | {n for n, _, g, _ in passwd if g == gid}
        for m in sorted(members):
            if m == "root":
                continue
            mine = {g for g, (_, mem) in groups.items() if m in mem}
            mine |= {
                gn for n, _, g, _ in passwd if n == m for gn in gid_names.get(g, [])
            }
            if shells.get(m, "") in NOLOGIN:
                ctx.add(
                    "PE-ROOTEQ-SERVICE",
                    INFO,
                    gname,
                    f"service account {ctx.name(m)} (no login shell) is in {gname}",
                )
            elif m in sudo_users or mine & sudo_groups:
                ctx.add(
                    "PE-ROOTEQ-ADMIN",
                    INFO,
                    gname,
                    f"account {ctx.name(m)} is in {gname} and already has full sudo",
                )
            else:
                bad += 1
                ctx.add(
                    "PE-ROOTEQ-GROUP",
                    FAIL,
                    gname,
                    f"account {ctx.name(m)} is in {gname} (root-equivalent) "
                    "without a full sudo rule",
                    f"gpasswd -d <account> {gname}",
                )
    for s in RUNTIME_SOCKETS:
        try:
            st = os.stat(ctx.p(s))
        except OSError:
            continue
        mode = stat.S_IMODE(st.st_mode)
        if s.endswith("docker.sock"):
            continue  # mode/group of docker.sock: audit/ docker.socket (not repeated here)
        if mode & 0o007:
            bad += 1
            ctx.add(
                "PE-ROOTEQ-SOCK",
                FAIL,
                s,
                f"mode {mode:04o}: any local user can drive the runtime as root",
                "chmod o-rwx",
                ("chmod", f"{mode & ~0o007:04o}", s),
            )
    for cname, src in ctx.tsv("mounts.tsv", 2, required=False):
        if (
            src == "/"
            or re.search(r"/(docker|containerd)\.sock$|/lxd/unix\.socket$", src)
            or src in ("/run", "/var/run")
        ):
            bad += 1
            ctx.add(
                "PE-ROOTEQ-MOUNT",
                FAIL,
                cname,
                f"bind-mounts {src} (root on the host from inside the container)",
                "remove the mount (recreate the container)",
            )
    if bad == 0:
        ctx.add(
            "PE-ROOTEQ-OK",
            PASS,
            "rooteq",
            "no hidden root-equivalent group member, runtime socket or mount",
        )


# ---------------------------------------------------------------- output
def counts(findings):
    c = {(ar, g): 0 for ar in AREAS for g in (PASS, INFO, WARN, FAIL)}
    for f in findings:
        c[(f["area"], f["grade"])] += 1
    return c


def write_metrics(path, ctx, host, now, ok):
    c = counts(ctx.findings)
    lines = [
        "# HELP pft_privesc_up 1 if the last pft-privesc audit collected every fact.",
        "# TYPE pft_privesc_up gauge",
        f'pft_privesc_up{{host="{host}"}} {1 if ok else 0}',
        "# HELP pft_privesc_last_run_timestamp_seconds Unix time of the last pft-privesc audit.",
        "# TYPE pft_privesc_last_run_timestamp_seconds gauge",
        f'pft_privesc_last_run_timestamp_seconds{{host="{host}"}} {now}',
        "# HELP pft_privesc_findings Findings of the last audit by area and grade.",
        "# TYPE pft_privesc_findings gauge",
    ]
    for ar in AREAS:
        for g in (PASS, INFO, WARN, FAIL):
            lines.append(
                f'pft_privesc_findings{{host="{host}",area="{ar}",grade="{g.lower()}"}} {c[(ar, g)]}'
            )
    lines += [
        "# HELP pft_privesc_fixable Findings that `pft-privesc apply` would fix.",
        "# TYPE pft_privesc_fixable gauge",
        f'pft_privesc_fixable{{host="{host}"}} {len(ctx.actions)}',
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def grade(a):
    ctx = Ctx(a)
    for name in ("errors.tsv",):
        p = os.path.join(a.facts, name)
        if os.path.exists(p):
            ctx.errors += [x.strip() for x in read_text(p).splitlines() if x.strip()]
    files = sudoers_files(ctx)
    check_suid(ctx, a)
    users, groups = check_sudoers(ctx)
    check_exec(ctx)
    check_path(ctx, files)
    check_rooteq(ctx, a, users, groups)
    ok = not ctx.errors
    c = counts(ctx.findings)
    nfail = sum(v for (ar, g), v in c.items() if g == FAIL)
    nwarn = sum(v for (ar, g), v in c.items() if g == WARN)
    rc = 2 if not ok else (1 if nfail or nwarn else 0)
    verdict = "ERROR" if rc == 2 else (FAIL if nfail else (WARN if nwarn else PASS))
    if a.actions:
        with open(a.actions, "w") as f:
            f.writelines("\t".join(act) + "\n" for act in ctx.actions)
    if a.metrics:
        write_metrics(a.metrics, ctx, a.host, a.now, ok)
    if a.json:
        print(
            json.dumps(
                {
                    "host": a.host,
                    "result": verdict,
                    "exit": rc,
                    "fail": nfail,
                    "warn": nwarn,
                    "fixable": len(ctx.actions),
                    "errors": ctx.errors,
                    "findings": ctx.findings,
                },
                indent=1,
            )
        )
    else:
        for f in ctx.findings:
            hint = "" if f["hint"] == "-" else f"  -> {f['hint']}"
            print(f"{f['grade']:<4} {f['id']:<20} {f['subject']}: {f['detail']}{hint}")
        for e in ctx.errors:
            print(f"ERROR {e}")
        print(
            f"RESULT: {verdict} - {nfail} fail, {nwarn} warn, {len(ctx.actions)} fixable by apply, "
            f"{len(ctx.errors)} errors -> exit {rc}"
        )
    return rc


def ids_table():
    print("| ID | area | meaning |\n|---|---|---|")
    for k, (ar, s) in IDS.items():
        print(f"| `{k}` | {ar} | {s} |")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grade")
    g.add_argument("--facts", required=True)
    g.add_argument("--root", default="")
    g.add_argument("--host", default="validator")
    g.add_argument("--now", type=int, default=0)
    g.add_argument("--json", action="store_true")
    g.add_argument("--metrics")
    g.add_argument("--actions")
    g.add_argument("--show-names", action="store_true")
    g.add_argument("--unneeded-suid", default="")
    g.add_argument("--remove-suid", default="")
    g.add_argument("--cap-allow", default="")
    g.add_argument("--rooteq-groups", default="")
    g.add_argument(
        "--root-uid", type=int, default=None, help="tests: treat this uid as root too"
    )
    sub.add_parser("ids")
    a = ap.parse_args()
    if a.cmd == "ids":
        return ids_table()
    return grade(a)


if __name__ == "__main__":
    sys.exit(main())
