#!/usr/bin/env python3
"""Offline tests for pft-kernwatch (kernwatch_parse.py + pft-kernwatch.sh) against a stub journalctl.

Run: TEST_TMPDIR=~/.cache python3 -u kernwatch/tests/test_kernwatch.py   (stdlib only; /tmp is noexec on the hosts,
so the temp dir defaults to ~/.cache). Prints one PASS/FAIL line per check and 'RESULT: PASS|FAIL (n checks)'.
"""

import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KW = os.environ.get("KW_DIR") or os.path.dirname(
    HERE
)  # KW_DIR: a mutant copy (tests/mutate.py)
HELPER = os.path.join(KW, "kernwatch_parse.py")
SCRIPT = os.path.join(KW, "pft-kernwatch.sh")
CAT = os.path.join(KW, "catalogue.tsv")
STUB = os.path.join(HERE, "stub_journalctl.py")
FIX = os.path.join(HERE, "fixtures")
TMP_BASE = os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache")
BOOT_A = "a" * 32
BOOT_B = "b" * 32
T0 = 1_762_000_000

sys.path.insert(0, KW)
import kernwatch_parse as kp

results = []
CRIT = [
    "oom_global",
    "oom_cgroup",
    "hung_task",
    "soft_lockup",
    "hard_lockup",
    "rcu_stall",
    "kernel_panic",
    "kernel_bug",
    "kernel_oops",
    "io_error",
    "buffer_io",
    "ext4_error",
    "fs_readonly",
    "jbd2_abort",
    "xfs_shutdown",
    "btrfs_error",
    "mce_error",
    "edac_ue",
    "conntrack_full",
]
WARN = [
    "conntrack_expect",
    "syn_flood",
    "tcp_mem",
    "tcp_orphans",
    "alloc_fail",
    "oom_invoked",
    "mce_logged",
    "edac_ce",
    "io_timeout",
    "ext4_warning",
    "link_down",
    "clock_unstable",
    "clock_fallback",
    "audit_backlog",
    "audit_lost",
    "audit_queue",
    "audit_ratelimit",
    "segfault",
    "trap",
]
INFO = ["martian", "martian_header"]


def rd(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(
        f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ' :: ' + str(detail)[:300]}"
    )


def rec(boot, i, msg, rt=None):
    return {
        "__CURSOR": f"s=1;i={i};b={boot}",
        "MESSAGE": msg,
        "PRIORITY": "4",
        "_BOOT_ID": boot,
        "__REALTIME_TIMESTAMP": str((rt if rt is not None else T0 + i) * 1_000_000),
        "__MONOTONIC_TIMESTAMP": str(1_000_000 + i * 1000),
        "_TRANSPORT": "kernel",
    }


def load_tsv(name):
    out = []
    with open(os.path.join(FIX, name)) as f:
        for line in f:
            pid, msg = line.rstrip("\n").split("\t", 1)
            out.append((pid, msg))
    return out


class Env:
    def __init__(self):
        self.d = tempfile.mkdtemp(prefix="kw-test.", dir=TMP_BASE)
        # tests that raise before done() (mutants) leak no dirs
        atexit.register(shutil.rmtree, self.d, True)
        self.journal = os.path.join(self.d, "journal.jsonl")
        self.state = os.path.join(self.d, "state.json")
        self.bootf = os.path.join(self.d, "boot_id")
        self.calls = os.path.join(self.d, "calls")
        self.set_boot(BOOT_A)
        self.write([])

    def set_boot(self, b):
        with open(self.bootf, "w") as f:
            f.write(f"{b[:8]}-{b[8:12]}-{b[12:16]}-{b[16:20]}-{b[20:]}\n")
        self.cur_boot = b

    def write(self, recs, raw_lines=()):
        with open(self.journal, "w") as f:
            f.writelines(
                (r if isinstance(r, str) else json.dumps(r)) + "\n" for r in recs
            )
            f.writelines(r + "\n" for r in raw_lines)

    def env(self, **extra):
        e = dict(os.environ)
        e.update(
            PFT_KW_JOURNALCTL=f"{sys.executable} {STUB}",
            PFT_KW_BOOT_ID_FILE=self.bootf,
            KW_JOURNAL=self.journal,
            KW_CALLS=self.calls,
            KW_CUR_BOOT=self.cur_boot,
        )
        e.update(extra)
        return e

    def collect(self, *args, **extra):
        p = subprocess.run(
            [
                sys.executable,
                "-I",
                HELPER,
                "collect",
                "--catalogue",
                CAT,
                "--state",
                self.state,
                "--host",
                "validator",
                "--now",
                str(T0 + 99999),
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self.env(**extra),
            stdin=subprocess.DEVNULL,
            timeout=60,
        )
        return p.returncode, p.stdout, p.stderr

    def report(self, *args, **extra):
        p = subprocess.run(
            [sys.executable, "-I", HELPER, "report", "--catalogue", CAT, *args],
            check=False,
            capture_output=True,
            text=True,
            env=self.env(**extra),
            stdin=subprocess.DEVNULL,
            timeout=60,
        )
        return p.returncode, p.stdout, p.stderr

    def st(self):
        with open(self.state) as f:
            return json.load(f)

    def done(self):
        shutil.rmtree(self.d, ignore_errors=True)


def metric(text, name, **labels):
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        lab = dict(re.findall(r'(\w+)="([^"]*)"', line[: line.rindex("}")]))
        if all(lab.get(k) == v for k, v in labels.items()):
            return float(line.rsplit(" ", 1)[1])
    return None


def t_catalogue():
    version, _sha, entries = kp.load_catalogue(CAT)
    check(
        "catalogue loads", version >= 1 and len(entries) >= 30, (version, len(entries))
    )
    pos = load_tsv("positive.tsv")
    ids = {e[0] for e in entries}
    covered = {pid for pid, _ in pos}
    check(
        "every catalogue pattern has a positive fixture",
        ids == covered,
        sorted(ids ^ covered),
    )
    bad = [
        (pid, msg, (kp.classify(entries, msg) or ("none",))[0])
        for pid, msg in pos
        if (kp.classify(entries, msg) or ("none",))[0] != pid
    ]
    check(f"{len(pos)} positive fixtures classify to their pattern", not bad, bad)
    near = load_tsv("near_miss.tsv")
    hit = [
        (msg, kp.classify(entries, msg)[0])
        for _, msg in near
        if kp.classify(entries, msg)
    ]
    check(f"{len(near)} near-miss fixtures match nothing", not hit, hit)
    both = "Kernel panic - not syncing: watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [x:1]"
    hit = kp.classify(entries, both)
    check(
        "first matching pattern wins (soft_lockup is listed before kernel_panic)",
        hit is not None and hit[0] == "soft_lockup",
        hit and hit[0],
    )
    sev = {e[0]: e[1] for e in entries}
    pinned = (
        {p: "crit" for p in CRIT}
        | {p: "warn" for p in WARN}
        | {p: "info" for p in INFO}
    )
    check(
        "every pattern's severity matches the pinned table (catalogue changes need a test change)",
        sev == pinned,
        {
            k: (sev.get(k), pinned.get(k))
            for k in set(sev) | set(pinned)
            if sev.get(k) != pinned.get(k)
        },
    )
    classes = {e[2] for e in entries}
    want = {
        "io",
        "fs",
        "hung",
        "lockup",
        "oom",
        "conntrack",
        "synflood",
        "link",
        "clocksource",
        "mce",
        "audit",
    }
    check(
        "catalogue covers every requested class",
        want <= classes,
        sorted(want - classes),
    )


def t_catalogue_negative():
    d = tempfile.mkdtemp(prefix="kw-cat.", dir=TMP_BASE)
    good = rd(CAT)
    cases = {
        "dup id": (good + "oom_global\tcrit\toom\tx\n", "duplicate id"),
        "bad severity": (good + "zz\tbad\toom\tx\n", "bad severity"),
        "bad regex": (good + "zz\tcrit\toom\t(\n", "does not compile"),
        "3 fields": (good + "zz\tcrit\toom\n", "want 4 tab-separated"),
        "no version": (good.replace("# version\t1\n", ""), "no '# version"),
        "bad class": (good + "zz\tcrit\tBad Class\tx\n", "bad class"),
    }
    for name, (body, want) in cases.items():
        p = os.path.join(d, "c.tsv")
        with open(p, "w") as f:
            f.write(body)
        r = subprocess.run(
            [sys.executable, "-I", HELPER, "check-catalogue", "--catalogue", p],
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        check(
            f"catalogue refused: {name} (rc 3 + reason)",
            r.returncode == 3 and want in r.stderr,
            (r.returncode, r.stderr),
        )
    r = subprocess.run(
        [sys.executable, "-I", HELPER, "check-catalogue", "--catalogue", CAT],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    check(
        "catalogue accepted: shipped file (rc 0)",
        r.returncode == 0 and "patterns" in r.stdout,
        r.stderr,
    )
    shutil.rmtree(d)


def t_redaction():
    host = os.uname().nodename
    raw = [
        f"IPv4: martian source 203.0.113.7 from 198.51.100.9, on dev eth0 host {host}",
        "ll header: 00000000: de 7c 0c 8a 88 61 5e da 55 a5 3b 19 08 00",
        "eth0: Link is Down mac 96:00:03:aa:bb:cc v6 2001:db8::1 fe80::1%eth0 /home/someuser/x /root/y",
        "Out of memory: Killed process 1234567 (python3) UID:1000 at 0xffffa1b2c3d4",
    ]
    out = [kp.redact(m, [host]) for m in raw]
    joined = "\n".join(out)
    for leak in (
        "203.0.113.7",
        "198.51.100.9",
        "96:00:03",
        "2001:db8",
        "fe80::1",
        "someuser",
        "/root",
        "de 7c 0c",
        "1234567",
        "ffffa1b2",
        host,
    ):
        check(
            f"redact removes {leak if leak != host else '<hostname>'}",
            leak not in joined,
            joined,
        )
        check(
            f"redact control: raw input has {leak if leak != host else '<hostname>'}",
            leak in "\n".join(raw),
        )
    check(
        "redact keeps the shape (ConsensusPhase::accepted style text survives)",
        kp.redact("ConsensusPhase::accepted eth0") == "ConsensusPhase::accepted eth0",
        kp.redact("ConsensusPhase::accepted eth0"),
    )
    check("redact truncates", len(kp.redact("x" * 500)) <= kp.EXCERPT_MAX + 3)


def t_seed_and_count():
    e = Env()
    pos = load_tsv("positive.tsv")
    e.write([rec(BOOT_A, i, m) for i, (_, m) in enumerate(pos[:3])])
    rc, out, err = e.collect()
    st = e.st()
    check(
        "first run seeds at the newest record (rc 0, nothing counted)",
        rc == 0
        and st["cursor"] == f"s=1;i=2;b={BOOT_A}"
        and sum(st["counters"].values()) == 0
        and metric(out, "pft_kernwatch_matches_total", pattern="oom_global") == 0,
        (rc, err, st),
    )
    check(
        "seed run: up 1 + seeded timestamp",
        metric(out, "pft_kernwatch_up") == 1
        and metric(out, "pft_kernwatch_seeded_timestamp_seconds") == T0 + 99999,
        out[:200],
    )
    new = [rec(BOOT_A, 3 + i, m) for i, (_, m) in enumerate(pos[3:8])]
    e.write([rec(BOOT_A, i, m) for i, (_, m) in enumerate(pos[:3])] + new)
    rc, out, err = e.collect()
    want = [pid for pid, _ in pos[3:8]]
    got = {
        pid: int(metric(out, "pft_kernwatch_matches_total", pattern=pid))
        for pid in want
    }
    check(
        "second run counts only records after the cursor",
        rc == 0
        and all(v == want.count(k) for k, v in got.items())
        and metric(out, "pft_kernwatch_matches_total", pattern="oom_global") == 0
        and metric(out, "pft_kernwatch_records_total") == 5,
        (rc, err, got),
    )
    check(
        "last-match time per class is the kernel record time",
        metric(
            out,
            "pft_kernwatch_last_match_timestamp_seconds",
            **{"class": "lockup", "severity": "crit"},
        )
        == T0 + 5,
        out,
    )
    rc, out, err = e.collect()
    check(
        "third run with no new records adds nothing",
        rc == 0
        and metric(out, "pft_kernwatch_records_total") == 5
        and metric(out, "pft_kernwatch_run_records") == 0,
        (rc, err),
    )
    calls = rd(e.calls)
    check(
        "collect asks journalctl for kernel records only (-k) of one boot (-b)",
        all(" -k " in f" {c} " and " -b " in f" {c} " for c in calls.splitlines()),
        calls,
    )
    check(
        "state file is 0600",
        oct(os.stat(e.state).st_mode & 0o777) == "0o600",
        oct(os.stat(e.state).st_mode),
    )
    e.done()


def t_from_boot_start_and_backlog():
    pos = load_tsv("positive.tsv")
    recs = [rec(BOOT_A, i, m) for i, (_, m) in enumerate(pos)]
    one = Env()
    one.write(recs)
    rc, out_one, err = one.collect("--from-boot-start")
    check(
        "--from-boot-start counts the whole boot",
        rc == 0 and metric(out_one, "pft_kernwatch_records_total") == len(pos),
        (rc, err),
    )
    many = Env()
    many.write(recs)
    rc, out, _ = many.collect("--from-boot-start", "--max", "7")
    check(
        "--max 7: backlog 1 and 7 records read",
        metric(out, "pft_kernwatch_backlog") == 1
        and metric(out, "pft_kernwatch_records_total") == 7,
        out[-400:],
    )
    runs = 1
    while metric(out, "pft_kernwatch_backlog") == 1 and runs < 20:
        rc, out, _ = many.collect("--max", "7")
        runs += 1
    same = all(
        metric(out, "pft_kernwatch_matches_total", pattern=pid)
        == metric(out_one, "pft_kernwatch_matches_total", pattern=pid)
        for pid, _ in pos
    )
    check(
        f"bounded resume ({runs} runs of 7) ends with the same counters as one run, backlog 0",
        same
        and metric(out, "pft_kernwatch_backlog") == 0
        and metric(out, "pft_kernwatch_records_total") == len(pos),
        out[-400:],
    )
    one.done()
    many.done()


def t_cursor_reset():
    e = Env()
    recs = [rec(BOOT_A, i, "free (1): drop_caches: 3") for i in range(10)]
    e.write(recs)
    e.collect("--from-boot-start")
    # journald rotated/vacuumed: the oldest 6 records are gone, so the cursor (i=9) is still there - make it vanish
    rot = recs[6:9] + [
        rec(BOOT_A, 10, "Out of memory: Killed process 5 (x) total-vm:1kB"),
        rec(BOOT_A, 11, "INFO: task kworker/0:1:99 blocked for more than 120 seconds."),
    ]
    e.write(rot)
    rc, out, err = e.collect()
    check(
        "unknown cursor: cursor_resets_total 1, rc 0",
        rc == 0 and metric(out, "pft_kernwatch_cursor_resets_total") == 1,
        (rc, err, out[-300:]),
    )
    check(
        "unknown cursor: only records after the saved monotonic time are counted (no double count)",
        metric(out, "pft_kernwatch_records_total") == 12
        and metric(out, "pft_kernwatch_matches_total", pattern="oom_global") == 1
        and metric(out, "pft_kernwatch_matches_total", pattern="hung_task") == 1,
        out[-600:],
    )
    calls = rd(e.calls).splitlines()
    check(
        "unknown cursor: re-read uses --since one second before the last record",
        any(f"--since @{T0 + 9 - 1}" in c for c in calls),
        calls,
    )
    e.done()


def t_boot_change():
    e = Env()
    a = [rec(BOOT_A, i, "free (1): drop_caches: 3") for i in range(3)]
    e.write(a)
    e.collect()
    tail = [
        rec(BOOT_A, 3, "watchdog: BUG: soft lockup - CPU#0 stuck for 23s! [x:1]"),
        rec(BOOT_A, 4, "Kernel panic - not syncing: softlockup: hung tasks"),
    ]
    b = [
        rec(BOOT_B, 100 + i, m)
        for i, m in enumerate(["Linux version 5.15.0", "eth0: Link is Down"])
    ]
    e.write(a + tail + b)
    e.set_boot(BOOT_B)
    rc, out, err = e.collect()
    check(
        "boot change: old boot tail after the cursor is counted (lockup + panic before the reboot)",
        rc == 0
        and metric(out, "pft_kernwatch_matches_total", pattern="soft_lockup") == 1
        and metric(out, "pft_kernwatch_matches_total", pattern="kernel_panic") == 1,
        (rc, err, out[-500:]),
    )
    check(
        "boot change: new boot read from its start, boot_changes_total 1",
        metric(out, "pft_kernwatch_matches_total", pattern="link_down") == 1
        and metric(out, "pft_kernwatch_boot_changes_total") == 1
        and e.st()["boot"] == BOOT_B,
        out[-500:],
    )
    rc, out, _ = e.collect()
    check(
        "boot change: next run stays on the new boot (no recount)",
        metric(out, "pft_kernwatch_records_total") == 4
        and metric(out, "pft_kernwatch_boot_changes_total") == 1,
        out[-400:],
    )
    # old boot vacuumed away entirely
    g = Env()
    g.write(a)
    g.collect()
    g.write([rec(BOOT_B, 100, "eth0: Link is Down")])
    g.set_boot(BOOT_B)
    rc, out, err = g.collect("--events-json", os.path.join(g.d, "ev.json"))
    ev = json.loads(rd(os.path.join(g.d, "ev.json")))
    check(
        "boot change with the old boot gone: old_boot_missing, new boot still read",
        rc == 0
        and ev["old_boot_missing"]
        and metric(out, "pft_kernwatch_matches_total", pattern="link_down") == 1,
        (rc, err, ev),
    )
    e.done()
    g.done()


def t_other_boot_and_budget():
    e = Env()
    e.write(
        [
            rec(BOOT_A, 0, "x"),
            rec(BOOT_B, 1, "Out of memory: Killed process 9 (y) total-vm:1kB"),
            rec(BOOT_A, 2, "eth0: Link is Down"),
        ]
    )
    rc, out, err = e.collect("--from-boot-start", KW_IGNORE_BOOT="1")
    check(
        "a record of another boot in this boot's read is skipped, not counted",
        rc == 0
        and metric(out, "pft_kernwatch_matches_total", pattern="oom_global") == 0
        and metric(out, "pft_kernwatch_matches_total", pattern="link_down") == 1
        and metric(out, "pft_kernwatch_records_total") == 2,
        (rc, err, out[-400:]),
    )
    g = Env()
    a = [rec(BOOT_A, 0, "x")]
    g.write(a)
    g.collect()
    tail = [rec(BOOT_A, 1, "x"), rec(BOOT_A, 2, "x")]
    b = [rec(BOOT_B, 10 + i, "eth0: Link is Down") for i in range(3)]
    g.write(a + tail + b)
    g.set_boot(BOOT_B)
    rc, out, err = g.collect("--max", "3")
    check(
        "boot change: old boot tail + new boot together stay within --max (2 + 1 = 3, backlog 1)",
        rc == 0
        and metric(out, "pft_kernwatch_records_total") == 3
        and metric(out, "pft_kernwatch_backlog") == 1,
        (rc, err, out[-500:]),
    )
    rc, out, _ = g.collect("--max", "3")
    check(
        "boot change: next run finishes the new boot (5 records, link_down 3, backlog 0)",
        metric(out, "pft_kernwatch_records_total") == 5
        and metric(out, "pft_kernwatch_matches_total", pattern="link_down") == 3
        and metric(out, "pft_kernwatch_backlog") == 0,
        out[-500:],
    )
    e.done()
    g.done()


def t_malformed():
    e = Env()
    e.write([rec(BOOT_A, 0, "x")])
    e.collect()
    binmsg = rec(BOOT_A, 3, "")
    binmsg["MESSAGE"] = list(b"Out of memory: Killed process 7 (p\xff) total-vm:1kB")
    nofield = rec(BOOT_A, 2, "Kernel panic - not syncing: x")
    del nofield["__REALTIME_TIMESTAMP"]
    badmono = rec(BOOT_A, 5, "Kernel panic - not syncing: y")
    badmono["__MONOTONIC_TIMESTAMP"] = "x"
    tailbad = rec(BOOT_A, 6, "z")
    del tailbad["MESSAGE"]
    e.write(
        [
            rec(BOOT_A, 0, "x"),
            "{not json",
            json.dumps(nofield),
            json.dumps(binmsg),
            "[1,2]",
            rec(BOOT_A, 4, "eth0: Link is Down"),
            json.dumps(badmono),
            json.dumps(tailbad),
        ]
    )
    rc, out, err = e.collect()
    check(
        "malformed: 5 bad records counted (incl. non-numeric monotonic time), run continues (rc 0)",
        rc == 0 and metric(out, "pft_kernwatch_malformed_total") == 5,
        (rc, err, out[-400:]),
    )
    check(
        "malformed: record missing a field is NOT classified (no panic counted)",
        metric(out, "pft_kernwatch_matches_total", pattern="kernel_panic") == 0,
    )
    check(
        "malformed: cursor moves past a malformed record that has a cursor (no re-read next run)",
        e.st()["cursor"] == f"s=1;i=6;b={BOOT_A}",
        e.st()["cursor"],
    )
    check(
        "byte-array MESSAGE is decoded and classified",
        metric(out, "pft_kernwatch_matches_total", pattern="oom_global") == 1
        and metric(out, "pft_kernwatch_matches_total", pattern="link_down") == 1,
        out[-400:],
    )
    e.done()


def t_state_problems():
    for name, body in (
        ("garbage", "{not json"),
        ("list", "[]"),
        ("wrong version", None),
        ("negative counter", None),
    ):
        e = Env()
        e.write([rec(BOOT_A, 0, "x"), rec(BOOT_A, 1, "eth0: Link is Down")])
        if body is None:
            st = kp.new_state(BOOT_A)
            if name == "wrong version":
                st["version"] = 99
            else:
                st["counters"] = {"oom_global": -1}
            body = json.dumps(st)
        with open(e.state, "w") as f:
            f.write(body)
        rc, out, err = e.collect()
        check(
            f"state {name}: replaced (state_resets_total 1, re-seeded, rc 0)",
            rc == 0
            and metric(out, "pft_kernwatch_state_resets_total") == 1
            and e.st()["cursor"] == f"s=1;i=1;b={BOOT_A}"
            and metric(out, "pft_kernwatch_up") == 1,
            (rc, err),
        )
        e.done()


def t_journal_failure():
    e = Env()
    e.write([rec(BOOT_A, 0, "x")])
    e.collect()
    before = rd(e.state, "rb")
    rc, out, err = e.collect(KW_FAIL="1")
    check(
        "journalctl failure: rc 1, up 0, no counters exported",
        rc == 1 and metric(out, "pft_kernwatch_up") == 0 and "matches_total" not in out,
        (rc, out, err),
    )
    check("journalctl failure: state file untouched", rd(e.state, "rb") == before)
    check("journalctl failure: reason on stderr", "Permission denied" in err, err)
    e.done()


def t_report():
    e = Env()
    host = os.uname().nodename
    pos = load_tsv("positive.tsv")
    recs = [rec(BOOT_A, i, m) for i, (_, m) in enumerate(pos)]
    recs.append(rec(BOOT_A, 500, f"eth1: Link is Down on {host} from 203.0.113.50"))
    e.write(recs)
    rc, out, err = e.report("--format", "json")
    j = json.loads(out) if rc == 0 else {}
    rows = {r["pattern"]: r for r in j.get("matches", [])}
    check(
        "report json: every pattern counted",
        rc == 0 and len(rows) == len({p for p, _ in pos}),
        (rc, err),
    )
    check(
        "report json: link_down count 3 (two fixtures + one extra)",
        rows.get("link_down", {}).get("count") == 3,
        rows.get("link_down"),
    )
    check(
        "report json: severities ordered crit, warn, info",
        [r["severity"] for r in j["matches"]]
        == sorted([r["severity"] for r in j["matches"]], key=kp.SEVERITIES.index),
    )
    check(
        "report: no IP, MAC bytes or host name in the output",
        not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)
        and host not in out
        and "de 7c 0c" not in out,
        out,
    )
    check(
        "report: UTC timestamps",
        rows["oom_global"]["first"].endswith("Z"),
        rows["oom_global"],
    )
    rc, out, _ = e.report("--format", "tsv", "--max", "5")
    check(
        "report truncated at --max: rc 2 and 'truncated True' in the header",
        rc == 2 and "truncated\tTrue" in out,
        (rc, out[:300]),
    )
    rc, _, err = e.report("--boot", "x; rm -rf /")
    check("report refuses a bad --boot (rc 3)", rc == 3, (rc, err))
    e.done()


def t_report_relative_since():
    # kernwatch drill run 06: `report --since -15min` died in argparse ("expected one argument", rc 2)
    e = Env()
    try:
        now = int(time.time())
        e.write(
            [
                rec(BOOT_A, 1, "Out of memory: Killed process 1 (old) total-vm:0kB"),
                rec(BOOT_A, 2, "segfault at 0 ip 0 sp 0 error 4", rt=now - 60),
            ]
        )
        for form in (("--since", "-15min"), ("--since=-15min",)):
            open(e.calls, "w").close()
            rc, out, err = e.report(*form, "--format", "json")
            rows = (
                {r["pattern"]: r for r in json.loads(out).get("matches", [])}
                if rc == 0
                else {}
            )
            check(
                f"report {' '.join(form)}: rc 0, only the recent segfault counted",
                rc == 0
                and set(rows) == {"segfault"}
                and rows["segfault"]["count"] == 1,
                (rc, err, sorted(rows)),
            )
            check(
                f"report {' '.join(form)}: journalctl gets --since -15min",
                "--since -15min" in rd(e.calls),
                rd(e.calls),
            )
        rc, _, err = e.report("--until", "-1min", "--format", "tsv")
        check(
            "report --until -1min: accepted (not an argparse error)", rc == 0, (rc, err)
        )
    finally:
        e.done()


def sh(e, *args, conf=None, **extra):
    env = e.env(PFT_KW_HELPER=HELPER, PFT_KW_CONF=conf or "/nonexistent", **extra)
    return subprocess.run(
        ["bash", SCRIPT, *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )


def t_wrapper():
    e = Env()
    e.write(
        [rec(BOOT_A, i, m) for i, (_, m) in enumerate(load_tsv("positive.tsv")[:4])]
    )
    tdir = os.path.join(e.d, "textfile")
    os.mkdir(tdir)
    base = {
        "STATE_DIR": os.path.join(e.d, "st"),
        "CATALOGUE": CAT,
        "PFT_KW_NOW": str(T0),
    }
    r = sh(e, "collect", "--textfile-dir", tdir, "--from-boot-start", **base)
    prom = os.path.join(tdir, "pft_kernwatch_validator.prom")
    body = rd(prom) if os.path.exists(prom) else ""
    check(
        "wrapper collect writes pft_kernwatch_validator.prom (rc 0, up 1)",
        r.returncode == 0 and metric(body, "pft_kernwatch_up") == 1,
        (r.returncode, r.stderr),
    )
    check(
        "wrapper output ends with a newline and has no temp files left",
        body.endswith("\n") and not [f for f in os.listdir(tdir) if f.startswith(".")],
        os.listdir(tdir),
    )
    v = sh(e, "validate", prom, "validator")
    check("validate accepts the collected file", v.returncode == 0, v.stdout)
    v = sh(e, "validate", prom, "sentry")
    check(
        "validate refuses another host's label (rc 2)",
        v.returncode == 2 and "first label" in v.stdout,
        v.stdout,
    )
    bad = os.path.join(e.d, "bad.prom")
    with open(bad, "w") as f:
        f.write(body + 'node_load1{host="validator"} 1\n')
    v = sh(e, "validate", bad, "validator")
    check(
        "validate refuses a foreign metric (rc 2)",
        v.returncode == 2 and "not a pft_kernwatch_" in v.stdout,
        v.stdout,
    )
    with open(bad, "w") as f:
        f.write('pft_kernwatch_matches_total{host="validator"} 1\n')
    v = sh(e, "validate", bad, "validator")
    check(
        "validate refuses a file without pft_kernwatch_up (rc 2)",
        v.returncode == 2 and "no pft_kernwatch_up" in v.stdout,
        v.stdout,
    )
    r = sh(e, "collect", "--stdout", **base, KW_FAIL="1")
    check(
        "wrapper collect on journal failure: rc 1, up 0 on stdout",
        r.returncode == 1 and metric(r.stdout, "pft_kernwatch_up") == 0,
        (r.returncode, r.stdout, r.stderr),
    )
    r = sh(e, "collect", "--stdout", **dict(base, HOST_LABEL="My-Host"))
    check(
        "wrapper refuses a bad HOST_LABEL (rc 3)",
        r.returncode == 3 and "HOST_LABEL" in r.stderr,
        r.stderr,
    )
    stub_helper = os.path.join(e.d, "slow.py")
    with open(stub_helper, "w") as f:
        # prints a partial textfile line first: a hung helper's partial output must never be published
        f.write(
            "import time\nprint('pft_kernwatch_up{host=\"validator\"} 1', flush=True)\ntime.sleep(30)\n"
        )
    r = subprocess.run(
        ["bash", SCRIPT, "collect", "--stdout"],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=e.env(
            PFT_KW_HELPER=stub_helper,
            PFT_KW_CONF="/nonexistent",
            RUN_TIMEOUT="2",
            **base,
        ),
        timeout=60,
    )
    check(
        "wrapper: a hanging helper is stopped at RUN_TIMEOUT -> up 0, rc 1",
        r.returncode == 1
        and metric(r.stdout, "pft_kernwatch_up") == 0
        and "timed out" in r.stderr,
        (r.returncode, r.stderr),
    )
    # pull: the 'remote' is a local dir served by a cat-like PULL_SSH
    remote = os.path.join(e.d, "remote")
    os.mkdir(remote)
    r = sh(
        e,
        "collect",
        "--textfile-dir",
        remote,
        **dict(base, HOST_LABEL="sentry", STATE_DIR=os.path.join(e.d, "st2")),
    )
    r = sh(
        e,
        "pull",
        "--host",
        "sentry",
        **dict(base, TEXTFILE_DIR=tdir, REMOTE_DIR=remote, PULL_SSH="env"),
    )
    check(
        "pull copies + validates the sentry file",
        r.returncode == 0
        and os.path.exists(os.path.join(tdir, "pft_kernwatch_sentry.prom")),
        (r.returncode, r.stderr),
    )
    with open(os.path.join(remote, "pft_kernwatch_sentry.prom"), "w") as f:
        f.write('pft_kernwatch_up{host="validator"} 1\n')
    before = rd(os.path.join(tdir, "pft_kernwatch_sentry.prom"))
    r = sh(
        e,
        "pull",
        "--host",
        "sentry",
        **dict(base, TEXTFILE_DIR=tdir, REMOTE_DIR=remote, PULL_SSH="env"),
    )
    check(
        "pull refuses a bad file and keeps the last good copy (rc 2)",
        r.returncode == 2
        and rd(os.path.join(tdir, "pft_kernwatch_sentry.prom")) == before,
        (r.returncode, r.stderr),
    )
    r = sh(
        e,
        "pull",
        "--host",
        "validator",
        **dict(base, TEXTFILE_DIR=tdir, REMOTE_DIR=remote, PULL_SSH="env"),
    )
    check(
        "pull refuses to overwrite this host's own file (rc 3)",
        r.returncode == 3,
        (r.returncode, r.stderr),
    )
    big = os.path.join(e.d, "big.prom")
    with open(big, "w") as f:
        f.write(body)
        f.write('pft_kernwatch_records_total{host="validator"} 1\n' * 3000)
    v = sh(e, "validate", big, "validator")
    check(
        "validate refuses a file over MAX_BYTES (rc 2)",
        v.returncode == 2 and "too big" in v.stdout,
        v.stdout,
    )
    v = sh(e, "validate", big, "validator", MAX_BYTES="10000000")
    check(
        "validate control: the same big file passes with a larger MAX_BYTES",
        v.returncode == 0,
        v.stdout,
    )
    sdir = os.path.join(e.d, "st")
    check(
        "state dir is 0700",
        oct(os.stat(sdir).st_mode & 0o777) == "0o700",
        oct(os.stat(sdir).st_mode),
    )
    holder = subprocess.Popen(
        ["flock", os.path.join(sdir, "lock"), "sleep", "20"],
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        for _ in range(50):
            busy = subprocess.run(
                ["flock", "-n", os.path.join(sdir, "lock"), "true"],
                check=False,
                stdin=subprocess.DEVNULL,
            )
            if busy.returncode != 0:
                break
            subprocess.run(["sleep", "0.1"], check=False)
        r = sh(e, "collect", "--stdout", **base)
        check(
            "a second collect while one holds the lock exits 1 without touching state",
            r.returncode == 1 and "another collect is running" in r.stderr,
            (r.returncode, r.stderr),
        )
    finally:
        os.killpg(holder.pid, 9)
        holder.wait()
    r = sh(e, "collect", "--stdout", **base)
    check(
        "collect works again once the lock is free",
        r.returncode == 0,
        (r.returncode, r.stderr),
    )
    e.done()


def main():
    os.makedirs(TMP_BASE, exist_ok=True)
    for t in (
        t_catalogue,
        t_catalogue_negative,
        t_redaction,
        t_seed_and_count,
        t_from_boot_start_and_backlog,
        t_cursor_reset,
        t_boot_change,
        t_other_boot_and_budget,
        t_malformed,
        t_state_problems,
        t_journal_failure,
        t_report,
        t_report_relative_since,
        t_wrapper,
    ):
        print(f"== {t.__name__}")
        try:
            t()
        except Exception as ex:  # noqa: BLE001 - a crashing test is a failure, never a silent pass
            check(f"{t.__name__} raised", False, f"{ex.__class__.__name__}: {ex}")
    n = len(results)
    print(
        f"RESULT: {'PASS' if all(results) and n else 'FAIL'} ({n} checks, {results.count(False)} failing)"
    )
    return 0 if all(results) and n else 1


if __name__ == "__main__":
    sys.exit(main())
