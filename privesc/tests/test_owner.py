#!/usr/bin/env python3
"""Owner-based checks of privesc_classify.py (files owned by a non-root uid), which run-tests.sh cannot build
without root. A fake root is made in a temp dir (its files belong to the test user, treated as root via --root-uid)
and os.lstat/os.stat are patched to report uid 4242 for the paths listed in OWNED.
  python3 tests/test_owner.py          exit 0 = every case passed
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ.get("PRIVESC_LIB", os.path.join(HERE, "..")))
import privesc_classify as pc

ME = os.getuid()


class Owner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.facts = os.path.join(self.root, "facts")
        os.makedirs(self.facts)
        self.mk("/usr/bin/sudo", 0o4755)
        self.mk("/usr/local/bin/tool", 0o755)
        self.mk(
            "/etc/sudoers",
            0o440,
            "Defaults env_reset\nDefaults secure_path=/usr/bin\nDefaults use_pty\n"
            "root ALL=(ALL:ALL) ALL\nops ALL=(root) /usr/local/bin/tool\n",
        )
        self.mk("/etc/crontab", 0o644, "")
        self.mk("/lib/systemd/system/tool.service", 0o644, "")
        self.fact("suid.tsv", "/usr/bin/sudo\t4755\t0\t0\tsudo\t/usr/bin/sudo\n")
        for n in ("md5.tsv", "override.tsv", "caps.tsv", "mounts.tsv", "errors.tsv"):
            self.fact(n, "")
        self.fact(
            "units.show",
            "Id=tool.service\nUser=\nFragmentPath=/lib/systemd/system/tool.service\n"
            "DropInPaths=\nExecStart={ path=/usr/local/bin/tool ; argv[]=/usr/local/bin/tool ; }\n",
        )
        self.fact("passwd.tsv", "root\t0\t0\t/bin/bash\n")
        self.fact("group.tsv", "docker\t120\t-\n")
        self.fact("visudo.txt", "rc=0\nparsed OK\n")
        self.owned = set()
        self.gid_owned = set()
        real_lstat, real_stat = os.lstat, os.stat

        def fake(fn):
            def f(path, *a, **k):
                st = fn(path, *a, **k)
                rel = str(path)[len(self.root) :]
                if rel in self.owned or rel in self.gid_owned:
                    lst = list(st)
                    lst[4 if rel in self.owned else 5] = 4242  # st_uid / st_gid
                    return os.stat_result(lst)
                return st

            return f

        self.patches = [(os, "lstat", real_lstat), (os, "stat", real_stat)]
        os.lstat, os.stat = fake(real_lstat), fake(real_stat)

    def tearDown(self):
        for mod, name, fn in self.patches:
            setattr(mod, name, fn)
        self.tmp.cleanup()

    def mk(self, path, mode, text="x\n"):
        p = self.root + path
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        os.chmod(p, mode)

    def fact(self, name, text):
        with open(os.path.join(self.facts, name), "w") as f:
            f.write(text)

    def run_grade(self, *extra):
        argv = [
            "grade",
            "--facts",
            self.facts,
            "--root",
            self.root,
            "--root-uid",
            str(ME),
            "--actions",
            os.path.join(self.facts, "actions"),
        ] + list(extra)
        sys.argv = ["privesc_classify.py"] + argv
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = pc.main()
        with open(os.path.join(self.facts, "actions")) as f:
            actions = f.read()
        return rc, out.getvalue(), actions

    def test_suid_owned_by_other_uid(self):
        self.fact("suid.tsv", "/usr/bin/sudo\t4755\t4242\t0\tsudo\t/usr/bin/sudo\n")
        rc, out, act = self.run_grade()
        self.assertIn("FAIL PE-SUID-OWNER", out)
        self.assertIn("/usr/bin/sudo: SUID mode 4755, owned by uid 4242", out)
        self.assertIn(
            "PE-SUID-OWNER\tchown\t0:0\t/usr/bin/sudo", act
        )  # apply then skips it (PROTECTED)
        self.assertEqual(rc, 1)

    def test_unpackaged_suid_owned_by_other_uid_not_chowned(self):
        self.fact("suid.tsv", "/usr/local/bin/tool\t4755\t4242\t0\t-\t-\n")
        _rc, out, act = self.run_grade()
        self.assertIn("FAIL PE-SUID-OWNER", out)
        self.assertNotIn("chown", act)

    def test_sudoers_owned_by_other_uid(self):
        self.owned.add("/etc/sudoers")
        _rc, out, act = self.run_grade()
        self.assertIn("FAIL PE-SUDO-PERM", out)
        self.assertIn("sudoers-fix\t0440\t/etc/sudoers", act)

    def test_sudo_command_owned_by_other_uid(self):
        self.owned.add("/usr/local/bin/tool")
        _rc, out, _act = self.run_grade()
        self.assertRegex(
            out,
            r"FAIL PE-SUDO-CMD-WRITABLE +/etc/sudoers: acct-[0-9a-f]{8}: /usr/local/bin/tool: "
            r"/usr/local/bin/tool owned by uid 4242",
        )

    def test_unit_exec_parent_owned_by_other_uid(self):
        self.owned.add("/usr/local/bin")
        _rc, out, act = self.run_grade()
        self.assertRegex(
            out,
            r"FAIL PE-EXEC-UNIT +tool.service: runs /usr/local/bin/tool: /usr/local/bin owned by uid 4242",
        )
        self.assertNotIn(
            "PE-EXEC-UNIT\tchmod", act
        )  # owner problems are report-only (no chown of dirs)

    def test_group_writable_by_non_root_group(self):
        os.chmod(self.root + "/usr/local/bin/tool", 0o775)
        self.gid_owned.add("/usr/local/bin/tool")
        _rc, out, act = self.run_grade()
        self.assertRegex(
            out,
            r"FAIL PE-EXEC-UNIT +tool.service: runs /usr/local/bin/tool: /usr/local/bin/tool "
            r"group-writable by gid 4242 \(mode 0775\)",
        )
        self.assertIn(
            "\tchmod\t0755\t/usr/local/bin/tool", act
        )  # one action (the sudo rule names it first)

    def test_group_writable_by_root_group_is_fine(self):
        os.chmod(
            self.root + "/usr/local/bin/tool", 0o775
        )  # gid = the test user's group, treated as root
        _rc, out, _act = self.run_grade()
        self.assertNotIn("group-writable", out)

    def test_clean_tree_passes_owner_checks(self):
        _rc, out, _act = self.run_grade()
        self.assertNotIn("owned by uid", out)
        self.assertIn("PASS PE-EXEC-OK", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
