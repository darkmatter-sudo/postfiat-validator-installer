"""Shell-level tests for `pft-fwaudit plan/apply/rollback/watch` with stubbed ufw, capture, RPC, pft-maint and
systemd (tests/stubs). The capture stub serves the real pre-fix sentry capture until the ufw stub has changed
anything, then the post-fix capture, so the re-audit and dead-man run the real evaluator on real data.

Every guard has a test asserting the change was NOT made: the stub call log has no mutating ufw call and
user.rules is unchanged.
"""

import hashlib
import json
import os
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STUBS = os.path.join(HERE, "stubs")
FIX = os.path.join(HERE, "fixtures")
SCRIPT = os.path.join(ROOT, "pft-fwaudit.sh")

# `ufw status numbered` of the sentry capture before the fix (fixture addresses)
SENTRY_RULES = [
    ["22/tcp", "ALLOW", "Anywhere"],
    ["2559/tcp", "LIMIT", "Anywhere"],
    ["19532/tcp", "ALLOW", "203.0.113.7"],
    ["22/tcp (v6)", "ALLOW", "Anywhere (v6)"],
    ["2559/tcp (v6)", "LIMIT", "Anywhere (v6)"],
]
FULL = {"result": {"status": "success", "info": {"server_state": "full", "peers": 10}}}
WINDOW = {"window": "active", "remaining_sec": 1800, "locks": []}
MUTATING = ("ufw --force delete", "ufw allow", "ufw limit", "ufw default")


def fixture_text(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


class Env:
    def __init__(self, tmp):
        self.d = str(tmp)
        self.ufw = os.path.join(self.d, "ufw")
        self.state = os.path.join(self.d, "state")
        os.makedirs(self.ufw)
        for name, body in (("user.rules", "# user.rules\n"), ("user6.rules", "# user6.rules\n")):
            self.write_in(self.ufw, name, body)
        self.write("default-ufw", "DEFAULT_INPUT_POLICY=DROP\n")
        self.write("rules.json", json.dumps(SENTRY_RULES))
        self.write("bundle_before", fixture_text("sentry.bundle"))
        self.write("bundle_after", fixture_text("sentry-postfix.bundle"))
        self.write("rpc.json", json.dumps(FULL))
        self.write("maint.json", json.dumps(WINDOW))
        self.write("now", "1800000000")
        self.write("calls.log", "")

    def write_in(self, d, name, body):
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)

    def write(self, name, body):
        self.write_in(self.d, name, body)

    def read(self, name):
        p = os.path.join(self.d, name)
        if not os.path.exists(p):
            return ""
        with open(p, encoding="utf-8") as fh:
            return fh.read()

    def sha(self):
        out = []
        for p in (os.path.join(self.ufw, "user.rules"), os.path.join(self.ufw, "user6.rules"), self.p("default-ufw")):
            with open(p, "rb") as fh:
                out.append(hashlib.sha256(fh.read()).hexdigest())
        return out

    def p(self, name):
        return os.path.join(self.d, name)

    def run(self, *args, **extra):
        env = dict(os.environ)
        env.update(
            {
                "PFT_FWA_CONF": self.p("no-such.env"),
                "PFT_FWA_TEST": "1",
                "PFT_FWA_EVAL": os.path.join(ROOT, "fwaudit_eval.py"),
                "PFT_FWA_COLLECT": os.path.join(STUBS, "collect"),
                "PFT_FWA_UFW": os.path.join(STUBS, "ufw"),
                "PFT_FWA_MAINT": os.path.join(STUBS, "maint"),
                "PFT_FWA_SYSTEMCTL": os.path.join(STUBS, "systemctl"),
                "PFT_FWA_SYSTEMD_RUN": os.path.join(STUBS, "systemd-run"),
                "PFT_FWA_RPC_CMD": os.path.join(STUBS, "rpc"),
                "PFT_FWA_NOW_FILE": self.p("now"),
                "FWA_STUB_DIR": self.d,
                "ROLE": "sentry",
                "POLICY_DIR": os.path.join(ROOT, "policy"),
                "PEERS": os.path.join(FIX, "sentry.peers"),
                "STATE_DIR": self.state,
                "UFW_DIR": self.ufw,
                "UFW_DEFAULT": self.p("default-ufw"),
                "DEADMAN_MIN": "2",
                "POLL_SEC": "30",
            }
        )
        env.update(extra)
        r = subprocess.run(
            ["bash", SCRIPT, *args],
            check=False,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
        return r.returncode, r.stdout + r.stderr

    def mutations(self):
        return [c for c in self.read("calls.log").splitlines() if c.startswith(MUTATING)]

    def state_json(self):
        with open(os.path.join(self.state, "state.json"), encoding="utf-8") as fh:
            return json.load(fh)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def assert_untouched(e, before):
    assert e.mutations() == []
    assert e.sha() == before


# ------------------------------------------------------------- stub self-check
def test_stubs_answer(env):
    out = subprocess.run(
        [os.path.join(STUBS, "ufw"), "status", "numbered"],
        env={**os.environ, "FWA_STUB_DIR": env.d, "UFW_DIR": env.ufw},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "[ 5] 2559/tcp (v6)" in out
    assert env.read("calls.log") == "ufw status numbered\n"


# ------------------------------------------------------------- plan
def test_plan_lists_the_v6_delete(env):
    rc, out = env.run("plan")
    assert rc == 1, out
    assert "ACTION delete tcp/2559 v6 (stale-allow)" in out
    assert env.mutations() == []


def test_plan_nothing_to_do_after_fix(env):
    env.write("bundle_before", fixture_text("sentry-postfix.bundle"))
    rc, out = env.run("plan")
    assert rc == 0 and "PLAN: 0 action(s), 0 manual item(s) (audit PASS)" in out


# ------------------------------------------------------------- guards (nothing changed)
def test_dry_run_changes_nothing(env):
    before = env.sha()
    rc, out = env.run("apply", "--dry-run")
    assert rc == 0 and "dry run - nothing changed" in out
    assert_untouched(env, before)
    assert not os.path.exists(os.path.join(env.state, "snapshot"))


def test_apply_needs_yes(env):
    before = env.sha()
    rc, out = env.run("apply")
    assert rc == 4 and "re-run with --yes" in out
    assert_untouched(env, before)


@pytest.mark.parametrize(
    "maint, reason",
    [
        ({"window": "none", "remaining_sec": None, "locks": []}, "no active pft-maint window"),
        ({"window": "active", "remaining_sec": 200, "locks": []}, "window has 200s left"),
        ({"window": "active", "remaining_sec": 1800, "locks": ["backfill"]}, "1 pft-maint data-collection lock"),
    ],
)
def test_maint_gate_refuses(env, maint, reason):
    env.write("maint.json", json.dumps(maint))
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 4 and "REFUSED" in out and reason in out, out
    assert_untouched(env, before)


@pytest.mark.parametrize(
    "info, reason",
    [
        ({"server_state": "syncing", "peers": 10}, "node is syncing, not full"),
        ({"server_state": "full", "peers": 2}, "peers 2 < MIN_PEERS 3"),
    ],
)
def test_node_health_refuses(env, info, reason):
    env.write("rpc.json", json.dumps({"result": {"status": "success", "info": info}}))
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 4 and reason in out, out
    assert_untouched(env, before)


def test_rpc_unanswered_refuses(env):
    env.write("rpc.json", "")
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 4 and "node is down, not full" in out
    assert env.mutations() == []


def test_pending_apply_refuses(env):
    os.makedirs(env.state)
    with open(os.path.join(env.state, "state.json"), "w", encoding="utf-8") as fh:
        json.dump({"result": "pending"}, fh)
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 4 and "still pending its dead-man" in out
    assert_untouched(env, before)


def test_no_ssh_exposure_refuses(env):
    t = fixture_text("sentry.bundle")
    lines = [ln for ln in t.splitlines() if not (ln.startswith("tcp") and ":22 " in ln and "sshd" in ln)]
    assert len(lines) < len(t.splitlines())
    env.write("bundle_before", "\n".join(lines) + "\n")
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 4 and "SSH (v4/tcp/22) is not a reachable declared exposure" in out, out
    assert_untouched(env, before)


def test_no_actions_is_no_change(env):
    env.write("bundle_before", fixture_text("sentry-postfix.bundle"))
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 0 and "apply: no change" in out
    assert env.mutations() == []
    assert not os.path.exists(os.path.join(env.state, "snapshot"))


# ------------------------------------------------------------- happy path
def test_apply_deletes_only_the_v6_rule_and_dead_man_keeps_it(env):
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 0, out
    assert env.mutations() == ["ufw --force delete 5"]
    assert json.loads(env.read("rules.json")) == SENTRY_RULES[:4]
    assert "every planned finding gone, declared exposure intact" in out
    assert out.count("dead-man poll: full peers 10 declared ok") == 4
    assert "dead-man: PASS" in out
    st = env.state_json()
    assert st["result"] == "kept" and st["baseline_peers"] == 10
    assert st["keep"] == ["v4/tcp/19532", "v4/tcp/22", "v4/tcp/2559", "v6/tcp/22"]
    assert env.sha() != before  # kept: not restored
    with open(os.path.join(env.state, "snapshot", "SHA256"), encoding="utf-8") as fh:
        assert fh.read().split() == before


def test_apply_starts_the_dead_man_as_a_transient_unit(env):
    rc, out = env.run("apply", "--yes")
    assert rc == 0, out
    runs = [c for c in env.read("calls.log").splitlines() if c.startswith("systemd-run")]
    assert len(runs) == 1 and "--unit=fwaudit-deadman --collect" in runs[0] and runs[0].endswith("pft-fwaudit.sh watch")
    assert env.state_json()["result"] == "pending"
    rc, out = env.run("apply", "--yes")  # nothing left to change: no second snapshot, no second unit
    assert rc == 0 and "apply: no change" in out
    assert len([c for c in env.read("calls.log").splitlines() if c.startswith("systemd-run")]) == 1
    rc, out = env.run("watch")  # what the unit runs
    assert rc == 0 and "dead-man: PASS" in out and env.state_json()["result"] == "kept"


def test_non_root_refused_without_test_hook(env):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    rc, out = env.run("apply", "--yes", PFT_FWA_TEST="")
    assert rc == 3 and "must run as root" in out
    assert env.mutations() == []


# ------------------------------------------------------------- rollbacks
def test_dead_man_trips_on_node_down_and_restores(env):
    env.write("rpc_after.json", json.dumps({"result": {"status": "success", "info": {"server_state": "connected"}}}))
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 1, out
    assert "BAD (3/3)" in out and "dead-man: TRIPPED - rolling back" in out
    assert "rollback RESULT: PASS" in out
    assert env.sha() == before
    assert "ufw reload" in env.read("calls.log")
    assert env.state_json()["result"] == "rolled-back"


def test_dead_man_trips_on_peer_drop(env):
    env.write(
        "rpc_after.json", json.dumps({"result": {"status": "success", "info": {"server_state": "full", "peers": 8}}})
    )
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 1 and "peers 8" in out and "TRIPPED" in out
    assert env.sha() == before


def test_dead_man_control_peer_slack_tolerates_one(env):
    env.write(
        "rpc_after.json", json.dumps({"result": {"status": "success", "info": {"server_state": "full", "peers": 9}}})
    )
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 0 and "TRIPPED" not in out


def test_dead_man_trips_when_ssh_exposure_disappears(env):
    before = env.sha()
    t = fixture_text("sentry-postfix.bundle")
    env.write("bundle_after", "\n".join(ln for ln in t.splitlines() if not (":22 " in ln and "sshd" in ln)) + "\n")
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 1, out
    assert "re-audit lost a declared exposure" in out and "v4/tcp/22" in out
    assert env.sha() == before


def test_reaudit_still_finding_rolls_back(env):
    env.write("bundle_after", fixture_text("sentry.bundle"))  # the change "did not take"
    before = env.sha()
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 1 and "re-audit still finds: stale-allow:v6/tcp/2559" in out, out
    assert env.sha() == before
    assert "dead-man" not in out.replace("its dead-man", "")


def test_failed_ufw_command_rolls_back(env):
    env.write("fail-delete", "1")
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 1 and "apply: action failed" in out and "rollback RESULT: PASS" in out
    assert env.state_json()["result"] == "rolled-back"


def test_manual_rollback_after_kept_apply(env):
    before = env.sha()
    assert env.run("apply", "--yes", "--foreground")[0] == 0
    assert env.sha() != before
    rc, out = env.run("rollback")
    assert rc == 4 and "--yes" in out
    rc, out = env.run("rollback", "--yes")
    assert rc == 0 and "rollback RESULT: PASS" in out
    assert env.sha() == before


def test_rollback_without_snapshot_fails(env):
    rc, out = env.run("rollback", "--yes")
    assert rc == 5 and "no snapshot" in out
    assert env.mutations() == []


# ------------------------------------------------------------- other plan classes end to end
def test_source_too_broad_adds_source_then_deletes_the_broad_rule(env):
    rules = [
        ["22/tcp", "ALLOW", "Anywhere"],
        ["19532/tcp", "ALLOW", "Anywhere"],
        ["22/tcp (v6)", "ALLOW", "Anywhere (v6)"],
    ]
    env.write("rules.json", json.dumps(rules))
    t = fixture_text("sentry-postfix.bundle")
    a = "-A ufw-user-input -s 203.0.113.7/32 -p tcp -m tcp --dport 19532"
    assert a in t
    env.write("bundle_before", t.replace(a, "-A ufw-user-input -p tcp -m tcp --dport 19532", 1))
    rc, out = env.run("apply", "--yes", "--foreground")
    assert rc == 0, out
    assert env.mutations() == [
        "ufw allow proto tcp from 203.0.113.7/32 to any port 19532 comment pft-fwaudit",
        "ufw --force delete 2",
    ]
    assert ["19532/tcp", "ALLOW", "203.0.113.7"] in json.loads(env.read("rules.json"))
