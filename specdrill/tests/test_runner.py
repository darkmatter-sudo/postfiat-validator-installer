#!/usr/bin/env python3
"""Stubbed tests for pft-specdrill.sh: every guard refuses with its own reason and creates nothing, every abort
path tears the cell down and re-arms pft-integrity, and the happy path records a cell. All external binaries are
tests/stub.py (see its docstring); the clock is fake (NOW_FILE), so a 20-minute window runs in seconds.

Run: python3 -m pytest -q specdrill/tests   (or python3 -m unittest discover specdrill/tests)
"""

import fcntl
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SD = os.path.dirname(HERE)
RUNNER = os.path.join(SD, "pft-specdrill.sh")
STUB = os.path.join(HERE, "stub.py")
T0 = 1_000_000
BINS = ("docker", "curl", "systemctl", "systemd-run", "pft-maint", "pft-integrity")
CREATE_CALLS = (
    "docker network create",
    "docker volume create",
    "docker create",
    "docker start",
    "systemctl stop pft-integrity.timer",
    "systemd-run",
)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="specdrill-test-", dir=os.environ.get("TMPDIR"))
        self.bin = os.path.join(self.d, "bin")
        os.makedirs(self.bin)
        for b in BINS:
            os.symlink(STUB, os.path.join(self.bin, b))
        self.out = os.path.join(self.d, "out")
        with open(os.path.join(self.d, "now"), "w") as f:
            f.write(str(T0))
        self.scenario({})

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def scenario(self, sc):
        with open(os.path.join(self.d, "scenario.json"), "w") as f:
            json.dump(sc, f)

    def env(self, **kw):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("PFT_", "STUB_"))}
        e.update(
            {
                "PATH": self.bin + ":" + os.environ["PATH"],
                "STUB_DIR": self.d,
                "NOW_FILE": os.path.join(self.d, "now"),
                "PFT_SPECDRILL_TEST": "1",
                "PFT_MAINT_BIN": "pft-maint",
                "PFT_INTEGRITY_BIN": "pft-integrity",
                "MEMINFO": os.path.join(self.d, "meminfo"),
                "PROC_ROOT": os.path.join(self.d, "proc"),
                "CGROUP_ROOT": os.path.join(self.d, "cg"),
                "LOCK": os.path.join(self.d, "lock"),
                "REF_RPC": "REF",
                "LIVE_RPC": "LIVE",
                "DF_PATH": "/",
                "DISK_MIN_GB": "1",
                "IO_DEV": "/dev/stubdisk",
                "POLL_SEC": "10",
                "WINDOW_S": "60",
                "FULL_TIMEOUT_S": "120",
                "FULL_DEADLINE_S": "100",
            }
        )
        e.update(kw)
        return e

    def run_sd(self, *args, env=None, **kw):
        return subprocess.run(
            ["bash", RUNNER, *args],
            env=env or self.env(**kw),
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )

    def cell(self, *extra, **kw):
        return self.run_sd("run-cell", "--out", self.out, "--axis", "cpu", "--cpus", "1", "--mem", "2048", *extra, **kw)

    def calls(self):
        p = os.path.join(self.d, "calls.log")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def assert_nothing_created(self):
        bad = [c for c in self.calls() if c.startswith(CREATE_CALLS)]
        self.assertEqual(bad, [], "guard refusal must not create or pause anything")

    def assert_refused(self, r, reason):
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("REFUSED: " + reason, r.stderr)

    def assert_torn_down(self):
        st = json.load(open(os.path.join(self.d, "state.json")))
        self.assertEqual((st["containers"], st["volumes"], st["networks"]), ({}, [], []))
        c = self.calls()
        stops = [i for i, x in enumerate(c) if x == "systemctl stop pft-integrity.timer"]
        starts = [i for i, x in enumerate(c) if x == "systemctl start pft-integrity.timer"]
        self.assertTrue(stops and starts and starts[-1] > stops[-1], "integrity timer must be re-armed after the pause")
        disarm = [i for i, x in enumerate(c) if x == "systemctl stop specdrill-rearm-integrity.service"]
        self.assertTrue(disarm, "the failsafe unit must be stopped")
        self.assertLess(disarm[-1], starts[-1], "failsafe stopped before the timer is re-armed (no verify sees it)")

    def meta(self, cell="cpu-c1-m2048-io0"):
        return json.load(open(os.path.join(self.out, cell, "meta.json")))

    def celljson(self, cell="cpu-c1-m2048-io0"):
        return json.load(open(os.path.join(self.out, cell, "cell.json")))


class TestGuards(Base):
    def test_not_root_refused(self):
        r = self.run_sd(
            "run-cell", "--out", self.out, "--axis", "cpu", "--cpus", "1", "--mem", "2048", PFT_SPECDRILL_TEST=""
        )
        if os.geteuid() == 0:
            self.skipTest("running as root")
        self.assertEqual(r.returncode, 3)
        self.assertIn("run as root", r.stderr)
        self.assertEqual(self.calls(), [])

    def test_lock_held(self):
        with open(os.path.join(self.d, "lock"), "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = self.cell()
        self.assert_refused(r, "lock: another pft-specdrill run holds")
        self.assertEqual(self.calls(), [])

    def test_no_maint_window(self):
        self.scenario({"maint": {"active": False, "remaining": 0}})
        self.assert_refused(self.cell(), "maint: no active pft-maint window")
        self.assert_nothing_created()

    def test_maint_window_too_short(self):
        # budget = FULL_TIMEOUT_S 120 + WINDOW_S 60 + slack 120 = 300 s
        self.scenario({"maint": {"active": True, "remaining": 299}})
        self.assert_refused(self.cell(), "maint: window has 299s left, cell needs 300s")
        self.assert_nothing_created()

    def test_maint_window_exact_budget_passes(self):
        self.scenario({"maint": {"active": True, "remaining": 300}, "cell": [{"at": 0, "state": "full", "lag": 0}]})
        r = self.cell()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok maint: active, 300s left >= 300s", r.stdout)

    def test_live_not_full(self):
        self.scenario({"live": [{"at": 0, "state": "syncing", "lag": 0}]})
        self.assert_refused(self.cell(), "live: live server_state=syncing")
        self.assert_nothing_created()

    def test_live_lag_over_max(self):
        self.scenario({"live": [{"at": 0, "state": "full", "lag": 4}]})
        self.assert_refused(self.cell(), "live: live lag 4 > 3")
        self.assert_nothing_created()

    def test_live_lag_at_max_passes(self):
        self.scenario({"live": [{"at": 0, "state": "full", "lag": 3}], "cell": [{"at": 0, "state": "full", "lag": 0}]})
        r = self.cell()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok live: full, lag 3 <= 3", r.stdout)

    def test_live_unreadable(self):
        self.scenario({"live": [{"at": 0, "down": True}]})
        self.assert_refused(self.cell(), "live: live server_info unreadable")
        self.assert_nothing_created()

    def test_reference_unreadable(self):
        self.scenario({"ref_ok": False})
        self.assert_refused(self.cell(), "live: reference RPC unreadable")
        self.assert_nothing_created()

    def test_integrity_not_pass(self):
        self.scenario({"integrity_rc": 1})
        self.assert_refused(self.cell(), "integrity: verify rc=1 (RESULT: WARN - 1 changed)")
        self.assert_nothing_created()

    def test_integrity_service_running(self):
        self.scenario({"integrity_service_active": True})
        self.assert_refused(self.cell(), "integrity: pft-integrity.service is running now")
        self.assert_nothing_created()

    def test_headroom_short(self):
        self.scenario({"avail_mib": 3583})  # 3583 - 2048 = 1535 < 1536
        self.assert_refused(self.cell(), "headroom: MemAvailable 3583 MiB - cell 2048 MiB < 1536 MiB")
        self.assert_nothing_created()

    def test_headroom_exact_passes(self):
        self.scenario({"avail_mib": 3584, "cell": [{"at": 0, "state": "full", "lag": 0}]})
        r = self.cell()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok headroom: 3584 MiB - 2048 MiB >= 1536 MiB", r.stdout)

    def test_disk_short(self):
        self.assert_refused(self.cell(DISK_MIN_GB="999999"), "disk:")
        self.assertIn("GB free < 999999 GB", self.cell(DISK_MIN_GB="999999").stderr)
        self.assert_nothing_created()

    def test_live_container_missing(self):
        self.scenario({"live_container": False})
        self.assert_refused(self.cell(), "image: live container postfiatd not found")
        self.assert_nothing_created()

    def test_image_not_local(self):
        self.scenario({"image_present": False})
        self.assert_refused(self.cell(), "image: sha256:img not present locally")
        self.assert_nothing_created()

    def test_leftovers_present(self):
        self.scenario({"leftover_containers": 2})
        self.assert_refused(self.cell(), "leftovers: 2 labelled resources from an earlier run (run cleanup)")
        self.assert_nothing_created()

    def test_failsafe_arm_failure(self):
        self.scenario({"systemd_run_rc": 1})
        self.assert_refused(self.cell(), "integrity: failsafe re-arm unit could not be started")
        c = self.calls()
        self.assertNotIn("systemctl stop pft-integrity.timer", c)
        self.assertFalse([x for x in c if x.startswith(("docker network create", "docker create"))])

    def test_timer_stop_failure_disarms_failsafe(self):
        self.scenario({"timer_stop_rc": 1})
        self.assert_refused(self.cell(), "integrity: timer stop failed")
        self.assertIn("systemctl stop specdrill-rearm-integrity.service", self.calls())
        self.assertFalse([x for x in self.calls() if x.startswith(("docker network create", "docker create"))])


class TestContainment(Base):
    def assert_never_started(self):
        self.assertFalse([x for x in self.calls() if x.startswith("docker start")])
        self.assert_torn_down()

    def test_validator_token_in_cfg(self):
        self.scenario({"cfg": "[server]\n[validator_token]\neyJ...\n"})
        self.assert_refused(self.cell(), "containment: cell config has a validator/fixed-peer stanza")
        self.assert_never_started()

    def test_ips_fixed_in_cfg(self):
        self.scenario({"cfg": "[ips_fixed]\n10.0.0.1 2559\n"})
        self.assert_refused(self.cell(), "containment: cell config has a validator/fixed-peer stanza")
        self.assert_never_started()

    def test_published_port(self):
        self.scenario({"inspect_override": {"PortBindings": {"2559/tcp": [{"HostPort": "2559"}]}}})
        self.assert_refused(self.cell(), "containment: container publishes ports")
        self.assert_never_started()

    def test_extra_mount(self):
        self.scenario({"inspect_override": {"Mounts": [{"Type": "bind", "Name": ""}, {"Type": "volume", "Name": "x"}]}})
        self.assert_refused(self.cell(), "containment: container publishes ports, mounts more than its volume")
        self.assert_never_started()

    def test_privileged(self):
        self.scenario({"inspect_override": {"Privileged": True}})
        self.assert_refused(self.cell(), "containment:")
        self.assert_never_started()

    def test_live_network(self):
        self.scenario({"inspect_override": {"NetworkMode": "postfiatd_default"}})
        self.assert_refused(self.cell(), "containment:")
        self.assert_never_started()


class TestCell(Base):
    def test_happy_path(self):
        self.scenario(
            {
                "cell": [
                    {"at": 0, "state": "connected", "lag": 0, "peers": 2},
                    {"at": 30, "state": "full", "lag": 1, "peers": 8},
                ],
                "hwm": [{"at": 0, "kb": 100000}, {"at": 40, "kb": 640000}, {"at": 70, "kb": 630000}],
            }
        )
        r = self.cell()
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.celljson()
        self.assertEqual(c["verdict"], "PASS", c)
        self.assertEqual(c["time_to_full_s"], 30)
        # window [30, 90] polled every 10 s = 7 samples, lag 1 each
        self.assertEqual((c["window_samples"], c["lag_p50"], c["lag_p95"], c["lag_max"]), (7, 1, 1, 1))
        self.assertEqual(c["peers_min"], 8)
        self.assertEqual(c["peak_rss_mib"], 625.0)  # max VmHWM 640000 kB
        self.assertEqual(self.meta()["abort"], None)
        self.assert_torn_down()
        create = next(x for x in self.calls() if x.startswith("docker create"))
        for frag in (
            "--pull never",
            "--restart no",
            "--cpus 1",
            "--memory 2048m",
            "--memory-swap 2048m",
            "--network pft-specdrill-",
            "-v pft-specdrill-",
        ):
            self.assertIn(frag, create)
        self.assertNotIn(" -p ", create)
        self.assertNotIn("--device-write-bps", create)
        self.assertTrue(create.endswith(" sha256:img"))
        arm = next(x for x in self.calls() if x.startswith("systemd-run"))
        self.assertEqual(
            arm,
            "systemd-run --collect --unit specdrill-rearm-integrity /bin/sh -c "
            "sleep 600 && systemctl start pft-integrity.timer",
        )  # budget 300 + 300

    def test_io_cell_device_limits(self):
        self.scenario({"cell": [{"at": 0, "state": "full", "lag": 0}]})
        r = self.run_sd(
            "run-cell", "--out", self.out, "--axis", "io", "--cpus", "2", "--mem", "2048", "--io", "4000000"
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        create = next(x for x in self.calls() if x.startswith("docker create"))
        self.assertIn("--device-read-bps /dev/stubdisk:4000000 --device-write-bps /dev/stubdisk:4000000", create)

    def test_never_full(self):
        self.scenario({"cell": [{"at": 0, "state": "syncing", "lag": 0}]})
        r = self.cell()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("cell never full within 120s", r.stdout)
        c = self.celljson()
        self.assertEqual((c["verdict"], c["reasons"]), ("FAIL", ["never_full"]))
        self.assert_torn_down()

    def test_slow_full(self):
        self.scenario({"cell": [{"at": 0, "state": "syncing", "lag": 0}, {"at": 110, "state": "full", "lag": 0}]})
        self.cell()
        self.assertEqual(self.celljson()["reasons"], ["slow_full"])  # 110 > FULL_DEADLINE_S 100

    def test_oom_kill(self):
        self.scenario(
            {
                "cell": [{"at": 0, "state": "full", "lag": 0}],
                "running": [{"at": 20, "running": False, "oom": True, "restarts": 0}],
            }
        )
        r = self.cell()
        self.assertIn("cell container stopped (false true 0 0)", r.stdout)
        c = self.celljson()
        self.assertTrue(c["oom_killed"])
        self.assertIn("oom_killed", c["reasons"])
        self.assertEqual(c["verdict"], "FAIL")
        self.assert_torn_down()

    def test_live_lag_abort_after_two_polls(self):
        self.scenario(
            {
                "cell": [{"at": 0, "state": "full", "lag": 0}],
                "live": [{"at": 0, "state": "full", "lag": 0}, {"at": 20, "state": "full", "lag": 5}],
            }
        )
        r = self.cell()
        self.assertIn("cell ABORTED: live_lag", r.stdout)
        m = self.meta()
        self.assertEqual(m["abort"], "live_lag")
        samples = [json.loads(x) for x in open(os.path.join(self.out, "cpu-c1-m2048-io0", "samples.jsonl"))]
        self.assertEqual([s["live_lag"] for s in samples], [0, 0, 5, 5])  # aborted at the 2nd breaching poll
        self.assertEqual(self.celljson()["reasons"][0], "aborted:live_lag")
        self.assert_torn_down()

    def test_single_live_lag_poll_does_not_abort(self):
        self.scenario(
            {
                "cell": [{"at": 0, "state": "full", "lag": 0}],
                "live": [
                    {"at": 0, "state": "full", "lag": 0},
                    {"at": 20, "state": "full", "lag": 5},
                    {"at": 30, "state": "full", "lag": 0},
                ],
            }
        )
        r = self.cell()
        self.assertNotIn("ABORTED", r.stdout)
        self.assertEqual(self.meta()["abort"], None)

    def test_live_down_mid_cell_aborts(self):
        self.scenario(
            {
                "cell": [{"at": 0, "state": "full", "lag": 0}],
                "live": [{"at": 0, "state": "full", "lag": 0}, {"at": 30, "down": True}],
            }
        )
        self.cell()
        self.assertEqual(self.meta()["abort"], "live_lag")
        self.assert_torn_down()

    def test_maint_window_ends_mid_cell(self):
        self.scenario(
            {
                "cell": [{"at": 0, "state": "full", "lag": 0}],
                "maint_timeline": [{"at": 40, "active": False, "remaining": 0}],
            }
        )
        r = self.cell()
        self.assertIn("cell ABORTED: maint_window_ended", r.stdout)
        self.assertEqual(self.meta()["abort"], "maint_window_ended")
        self.assert_torn_down()

    def test_host_memory_low_mid_cell(self):
        # HEADROOM_MIB 1536 -> abort below 768 MiB available
        self.scenario(
            {
                "cell": [{"at": 0, "state": "full", "lag": 0}],
                "meminfo": [{"at": 0, "avail_mib": 6000}, {"at": 30, "avail_mib": 767}],
            }
        )
        self.cell()
        self.assertEqual(self.meta()["abort"], "host_mem_low")
        self.assert_torn_down()

    def test_host_memory_at_floor_no_abort(self):
        self.scenario(
            {
                "cell": [{"at": 0, "state": "full", "lag": 0}],
                "meminfo": [{"at": 0, "avail_mib": 6000}, {"at": 30, "avail_mib": 768}],
            }
        )
        self.cell()
        self.assertEqual(self.meta()["abort"], None)

    def test_sigterm_mid_cell_tears_down(self):
        self.scenario({"cell": [{"at": 0, "state": "full", "lag": 0}], "term_at": 20})
        p = subprocess.Popen(
            ["bash", RUNNER, "run-cell", "--out", self.out, "--axis", "cpu", "--cpus", "1", "--mem", "2048"],
            env=self.env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.time() + 30
        while not os.path.exists(os.path.join(self.d, "term.reached")) and time.time() < deadline:
            time.sleep(0.05)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 130, out + err)
        self.assertFalse(os.path.exists(os.path.join(self.out, "cpu-c1-m2048-io0", "meta.json")))
        self.assert_torn_down()


class TestCommands(Base):
    def test_matrix_needs_yes(self):
        r = self.run_sd("matrix", "--out", self.out, "--axes", "cpu")
        self.assertEqual(r.returncode, 3)
        self.assertIn("add --yes", r.stderr)
        self.assertEqual(self.calls(), [])

    def test_matrix_unknown_axis(self):
        r = self.run_sd("matrix", "--out", self.out, "--axes", "gpu", "--yes")
        self.assertEqual(r.returncode, 3)
        self.assert_nothing_created()

    def test_matrix_runs_every_cell_of_axis(self):
        self.scenario({"cell": [{"at": 0, "state": "full", "lag": 0}]})
        r = self.run_sd("matrix", "--out", self.out, "--axes", "io", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            sorted(os.listdir(self.out)), ["io-c2-m2048-io1000000", "io-c2-m2048-io16000000", "io-c2-m2048-io4000000"]
        )

    def test_matrix_stops_on_refusal(self):
        self.scenario({"maint": {"active": False, "remaining": 0}})
        r = self.run_sd("matrix", "--out", self.out, "--axes", "cpu", "--yes")
        self.assertEqual(r.returncode, 4)
        self.assertEqual(r.stderr.count("REFUSED"), 1)
        self.assert_nothing_created()

    def test_bad_cell_args(self):
        r = self.run_sd("run-cell", "--out", self.out, "--axis", "cpu", "--cpus", "1.2.3", "--mem", "2048")
        self.assertEqual(r.returncode, 3)
        self.assertEqual(self.calls(), [])

    def test_cleanup_removes_leftovers(self):
        self.scenario({"leftover_containers": 2})
        r = self.run_sd("cleanup")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("teardown: leftovers=0", r.stdout)
        self.assertIn("docker rm -f old0", self.calls())
        self.assertNotIn("systemctl start pft-integrity.timer", self.calls())

    def test_plan_makes_no_changes(self):
        r = self.run_sd("plan", "--axes", "cpu,mem,io")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("\ncell ") + r.stdout.startswith("cell "), 12)
        for g in ("maint", "live", "integrity", "headroom", "disk", "image", "leftovers"):
            self.assertIn(f"ok {g}:", r.stdout)
        self.assert_nothing_created()


if __name__ == "__main__":
    unittest.main()
