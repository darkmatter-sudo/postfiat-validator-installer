#!/usr/bin/env python3
"""Unit tests for pft_seccomp.py (stdlib unittest). Fixtures are tiny hand-written Docker profiles, tables and audit
lines, so every expected value below is computed by hand. Run: python3 -I tests/test_pft_seccomp.py"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import pft_seccomp as ps

TABLE = os.path.join(
    HERE, "fixtures", "syscall-table.tsv"
)  # libseccomp x86_64 table (`pft_seccomp.py table`)
# A miniature Docker default: plain allows, a cap-gated allow, an arg-filtered socket rule, clone3 -> ENOSYS.
DOCKER = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "syscalls": [
        {
            "names": ["read", "write", "mmap", "pread64", "exit_group"],
            "action": "SCMP_ACT_ALLOW",
        },
        {
            "names": ["ptrace"],
            "action": "SCMP_ACT_ALLOW",
            "includes": {"caps": ["CAP_SYS_PTRACE"]},
        },
        {
            "names": ["mount"],
            "action": "SCMP_ACT_ALLOW",
            "includes": {"caps": ["CAP_SYS_ADMIN"]},
        },
        {
            "names": ["socket"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 0, "value": 40, "op": "SCMP_CMP_NE"}],
        },
        {
            "names": ["clone3"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 38,
            "excludes": {"caps": ["CAP_SYS_ADMIN"]},
        },
    ],
}


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=os.environ.get("TEST_TMPDIR") or None)
        self.table = TABLE
        self.docker = self.w("docker.json", json.dumps(DOCKER))

    def w(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def helper(self, *args):
        return subprocess.run(
            [sys.executable, "-I", os.path.join(HERE, "..", "pft_seccomp.py"), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def gen_args(self, census, events="", margin=""):
        a = [
            "--docker",
            self.docker,
            "--table",
            self.table,
            "--census",
            self.w("census.json", json.dumps(census)),
        ]
        if events:
            a += ["--events", self.w("events.tsv", events)]
        if margin:
            a += ["--margin", self.w("margin.tsv", margin)]
        return a


class TestAllowed(Base):
    def test_caps_gate_rules(self):
        al = ps.docker_allowed(DOCKER, ps.caps_set("CAP_SETGID,CAP_SETUID"), "5.15")
        self.assertEqual(
            sorted(al), ["exit_group", "mmap", "pread64", "read", "socket", "write"]
        )
        self.assertEqual(al["socket"], "args")
        al2 = ps.docker_allowed(DOCKER, ps.caps_set("CAP_SYS_PTRACE"), "5.15")
        self.assertIn("ptrace", al2)
        self.assertNotIn("mount", al2)


class TestPlanGenerate(Base):
    def test_rows_keep_remove_deny(self):
        r = self.helper(
            "diff",
            *self.gen_args(
                {"read": 5, "socket": 2, "ptrace": 1},
                "log\tmmap\tx\t/x\t1\n",
                "exit_group\tprocess exit\n",
            ),
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = {
            ln.split("\t")[0]: ln.split("\t")[1:]
            for ln in r.stdout.splitlines()
            if not ln.startswith("#")
        }
        self.assertEqual(rows["read"], ["allow", "allow", "census 5"])
        self.assertEqual(rows["socket"], ["allow(args)", "allow(args)", "census 2"])
        self.assertEqual(
            rows["mmap"],
            ["allow", "allow", "SCMP_ACT_LOG record (missed by the census)"],
        )
        self.assertEqual(rows["exit_group"], ["allow", "allow", "margin: process exit"])
        self.assertEqual(rows["write"], ["allow", "deny", "never observed"])
        self.assertEqual(rows["pread64"], ["allow", "deny", "never observed"])
        self.assertEqual(
            rows["ptrace"],
            ["deny", "deny", "observed, denied by Docker default too: stays denied"],
        )
        self.assertIn(
            "allows 6 x86_64 syscalls for these caps; profile keeps 4, removes 2",
            r.stdout.splitlines()[-1],
        )

    def test_generate_profile_shape(self):
        r = self.helper(
            "generate",
            *self.gen_args(
                {"read": 5, "socket": 2, "ptrace": 1}, margin="exit_group\tx\n"
            ),
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        p = json.loads(r.stdout)
        self.assertEqual(p["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertEqual(p["flags"], ["SECCOMP_FILTER_FLAG_LOG"])
        self.assertEqual(p["architectures"], ["SCMP_ARCH_X86_64"])
        self.assertEqual(
            p["syscalls"][0],
            {"names": ["exit_group", "read"], "action": "SCMP_ACT_ALLOW"},
        )
        self.assertEqual(p["syscalls"][1]["names"], ["socket"])
        self.assertEqual(p["syscalls"][1]["args"], DOCKER["syscalls"][3]["args"])
        self.assertEqual(
            p["syscalls"][2],
            {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38},
        )
        allowed = {
            n
            for r_ in p["syscalls"]
            if r_["action"] == "SCMP_ACT_ALLOW"
            for n in r_["names"]
        }
        self.assertNotIn(
            "ptrace", allowed
        )  # observed but Docker denies it for these caps: never widened

    def test_deterministic(self):
        a = self.gen_args({"read": 5, "write": 1})
        self.assertEqual(
            self.helper("generate", *a).stdout, self.helper("generate", *a).stdout
        )

    def test_margin_cannot_widen_docker(self):
        r = self.helper("generate", *self.gen_args({"read": 1}, margin="mount\tno\n"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("would widen it", r.stderr)

    def test_margin_needs_reason(self):
        r = self.helper("generate", *self.gen_args({"read": 1}, margin="write\n"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("want 'name<TAB>reason'", r.stderr)

    def test_unknown_census_name(self):
        r = self.helper("generate", *self.gen_args({"pread": 1}))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not in the syscall table: pread", r.stderr)

    def test_learnprofile_logs_unknown_denies_rest(self):
        r = self.helper(
            "learnprofile",
            "--docker",
            self.docker,
            "--table",
            self.table,
            "--census",
            self.w("c.json", '{"read": 3}'),
        )
        p = json.loads(r.stdout)
        self.assertEqual(p["defaultAction"], "SCMP_ACT_LOG")
        self.assertEqual(p["syscalls"][0]["names"], ["read"])
        errno_rules = [x for x in p["syscalls"] if x["action"] == "SCMP_ACT_ERRNO"]
        self.assertEqual(
            errno_rules[0],
            {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38},
        )
        # Docker-denied for these caps and not explicitly listed: EPERM (as under Docker's default), never LOG
        names = set(errno_rules[1]["names"])
        self.assertTrue({"clone", "mount", "personality", "ptrace"} <= names)
        self.assertFalse({"read", "write", "socket", "clone3"} & names)
        by_nr, _ = ps.load_table(self.table)
        # every table name but the 6 allowed and clone3 (its own ENOSYS rule)
        self.assertEqual(len(names), len(by_nr) - 6 - 1)


class TestAudit(Base):
    def line(self, t, code, subj, nr, comm='"du"', arch="c000003e"):
        return (
            f"type=SECCOMP msg=audit({t}.100:1): auid=4294967295 uid=0 subj={subj} (enforce) pid=7 comm={comm} "
            f'exe="/usr/bin/du" sig=0 arch={arch} syscall={nr} compat=0 ip=0x1 code={code}\n'
        )

    def test_parse_filters(self):
        by_nr, _ = ps.load_table(self.table)
        log = self.w(
            "audit.log",
            self.line(100, "0x50000", "pft-postfiatd", 165)
            + self.line(101, "0x50000", "pft-postfiatd", 165)
            + self.line(102, "0x7ffc0000", "pft-postfiatd", 0)
            + self.line(103, "0x50000", "docker-default", 101)
            + self.line(50, "0x50000", "pft-postfiatd", 101)
            + self.line(104, "0x50000", "pft-postfiatd", 7, arch="40000003")
            + self.line(
                105,
                "0x50000",
                "pft-postfiatd",
                17,
                comm="6462207072656665746368202331",
            )
            + 'type=AVC msg=audit(106.1:2): apparmor="DENIED" subj=pft-postfiatd (enforce)\n',
        )
        ev = ps.parse_audit([log], by_nr, 100, "pft-postfiatd")
        self.assertEqual(
            ev,
            {
                ("errno", "mount", "du", "/usr/bin/du"): 2,
                ("log", "read", "du", "/usr/bin/du"): 1,
                ("errno", "arch40000003:7", "du", "/usr/bin/du"): 1,
                ("errno", "pread64", "db prefetch #1", "/usr/bin/du"): 1,
            },
        )
        self.assertEqual(sum(ps.parse_audit([log], by_nr, 0, "").values()), 7)


class TestCanonCheck(Base):
    def test_canon_is_compact_in_file_order(self):
        p = self.w("p.json", '{\n  "b": 1,\n  "a": ["x", "y"]\n}\n')
        self.assertEqual(
            ps.canon_sha(p), hashlib.sha256(b'{"b":1,"a":["x","y"]}').hexdigest()
        )

    def test_check(self):
        good = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "flags": ["SECCOMP_FILTER_FLAG_LOG"],
            "syscalls": [{"names": ["read"] * 1, "action": "SCMP_ACT_ALLOW"}],
        }
        r = self.helper(
            "check", self.w("g.json", json.dumps(good)), "--table", self.table
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("only 1 allowed syscalls (truncated profile?)", r.stdout)
        bad = dict(
            good,
            defaultAction="SCMP_ACT_ALLOW",
            flags=[],
            syscalls=[{"names": ["pread"], "action": "SCMP_ACT_LOG"}],
        )
        r = self.helper(
            "check", self.w("b.json", json.dumps(bad)), "--table", self.table
        )
        self.assertEqual(r.returncode, 1)
        for want in (
            "defaultAction must be SCMP_ACT_ERRNO",
            "SECCOMP_FILTER_FLAG_LOG",
            "unknown syscall names: pread",
            "only SCMP_ACT_ALLOW",
        ):
            self.assertIn(want, r.stdout)
        r = self.helper("check", self.w("n.json", "{"), "--table", self.table)
        self.assertEqual(r.returncode, 1)
        self.assertIn("not readable JSON", r.stdout)


class TestCensus(Base):
    def test_cgroup_selection(self):
        by_nr, _ = ps.load_table(self.table)
        raw = self.w(
            "c.raw",
            "Attaching 2 probes...\n@[11, 0]: 5\n@[11, 17]: 2\n@[12, 0]: 3\n@[99, 165]: 9\n@[11, 999]: 1\n",
        )
        out = ps.parse_census([raw], by_nr, {11, 12})
        self.assertEqual(out.get("read"), 8)
        self.assertEqual(out.get("pread64"), 2)
        self.assertNotIn("mount", out)


class TestShippedProfile(unittest.TestCase):
    # Syscalls of in-container jobs that no learn run saw. pselect6: the image's cron.daily runs
    # `run-parts --report`, which died "select: Operation not permitted" daily without it (2026-11-06).
    NEEDED = ("pselect6",)
    PROFILE = os.environ.get(
        "SC_SHIPPED_PROFILE", os.path.join(HERE, "..", "profile", "pft-postfiatd.json")
    )

    def test_shipped_profile_allows_job_syscalls(self):
        with open(self.PROFILE) as f:
            prof = json.load(f)
        allowed = {
            n
            for s in prof["syscalls"]
            if s["action"] == "SCMP_ACT_ALLOW" and not s.get("args")
            for n in s["names"]
        }
        with open(os.path.join(HERE, "..", "margin.tsv")) as f:
            margin = dict(
                line.rstrip("\n").split("\t", 1)
                for line in f
                if line.strip() and not line.startswith("#")
            )
        for name in self.NEEDED:
            self.assertIn(name, allowed, f"{name} not allowed by the shipped profile")
            self.assertTrue(
                margin.get(name, "").strip(), f"{name} has no margin reason"
            )


if __name__ == "__main__":
    unittest.main(verbosity=1)
