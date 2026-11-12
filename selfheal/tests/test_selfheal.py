"""Offline tests for selfheal/: the decision core (every detector, guard, backoff and breaker path) and
pft-selfheal.sh against stubbed docker / reference curl / pft-maint / pft-egress (no real container is touched).

Run: cd selfheal && python3 -m pytest -q tests
Stubs live under $TEST_TMPDIR or ~/.cache (/tmp is noexec on the hosts)."""

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT = ROOT / "pft-selfheal.sh"
DECIDER = ROOT / "selfheal_decide.py"

spec = importlib.util.spec_from_file_location("selfheal_decide", DECIDER)
sd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sd)

T0 = 1_800_000_000
GOOD = {"ok": True, "server_state": "full", "validated_seq": 1000, "peers": 10}
FAIL = {"ok": False, "server_state": None, "validated_seq": None, "peers": None}


def obs(now, rpc=None, running=True, exists=True, started=T0 - 3600, maint=False, locks=None, ref=None, ref_ok=None):
    return {
        "now": now,
        "container": {"exists": exists, "running": running and exists, "started_at": started},
        "rpc": dict(GOOD if rpc is None else rpc),
        "guards": {
            "maint_active": maint,
            "locks": locks or [],
            "reference_seq": ref,
            "reference_ok": (ref is not None) if ref_ok is None else ref_ok,
        },
    }


class Core:
    """Drives selfheal_decide.decide() in-process through files, as the shell does."""

    def __init__(self, tmp, **conf):
        self.state = tmp / "state.json"
        self.conf = tmp / "selfheal.env"
        conf.setdefault("MODE", "enforce")
        self.conf.write_text("".join(f"{k}={v}\n" for k, v in conf.items()))

    def decide(self, o, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(o)))
        rc = sd.decide(str(self.state), str(self.conf))
        out = capsys.readouterr().out.strip()
        return rc, (json.loads(out) if out else None)

    def record(self, now, capsys, rc=0):
        sd.record(str(self.state), "restart", rc, now)
        capsys.readouterr()

    def st(self):
        return json.loads(self.state.read_text())


@pytest.fixture
def core(tmp_path):
    return lambda **conf: Core(tmp_path, **conf)


# ---------------------------------------------------------------- detectors


def test_healthy(core, monkeypatch, capsys):
    c = core()
    rc, d = c.decide(obs(T0), monkeypatch, capsys)
    assert rc == 0 and d["verdict"] == "healthy" and d["detector"] is None and d["action"] == "none"


@pytest.mark.parametrize("exists", [True, False])
def test_container_down_up(core, monkeypatch, capsys, exists):
    c = core()
    _, d = c.decide(obs(T0, running=False, exists=exists, rpc=FAIL), monkeypatch, capsys)
    assert (d["verdict"], d["detector"], d["action"]) == ("act", "container_down", "up")
    assert d["detail"] == ("container not running" if exists else "container missing")


def test_container_down_ignores_grace(core, monkeypatch, capsys):
    c = core()
    _, d = c.decide(obs(T0, running=False, started=T0 - 10, rpc=FAIL), monkeypatch, capsys)
    assert d["verdict"] == "act" and d["suppressed_by"] is None


def test_rpc_failures_need_k_consecutive(core, monkeypatch, capsys):
    c = core(RPC_FAILS=3)
    verdicts = [c.decide(obs(T0 + 60 * i, rpc=FAIL), monkeypatch, capsys)[1]["verdict"] for i in range(3)]
    assert verdicts == ["healthy", "healthy", "act"]


def test_rpc_streak_resets_on_success(core, monkeypatch, capsys):
    c = core(RPC_FAILS=3)
    for i, r in enumerate([FAIL, FAIL, GOOD, FAIL, FAIL]):
        _, d = c.decide(obs(T0 + 60 * i, rpc=dict(r, validated_seq=1000 + i) if r["ok"] else r), monkeypatch, capsys)
    assert d["verdict"] == "healthy" and d["rpc_fail_streak"] == 2


def test_stale_ledger(core, monkeypatch, capsys):
    c = core(STALE_SEC=300)
    c.decide(obs(T0), monkeypatch, capsys)
    _, d = c.decide(obs(T0 + 299, ref=2000), monkeypatch, capsys)
    assert d["verdict"] == "healthy"
    _, d = c.decide(obs(T0 + 300, ref=2000), monkeypatch, capsys)
    assert (d["verdict"], d["detector"], d["action"]) == ("act", "stale_ledger", "restart")
    assert d["detail"] == "validated ledger 1000 unchanged for 300s"


def test_advancing_ledger_is_not_stale(core, monkeypatch, capsys):
    c = core(STALE_SEC=300)
    for i in range(10):
        _, d = c.decide(obs(T0 + 60 * i, rpc=dict(GOOD, validated_seq=1000 + i), ref=5000), monkeypatch, capsys)
    assert d["verdict"] == "healthy"


def test_stuck_state(core, monkeypatch, capsys):
    c = core(STUCK_SEC=600, STALE_SEC=99999)
    bad = dict(GOOD, server_state="connected")
    for i, t in enumerate([0, 300, 599]):
        _, d = c.decide(obs(T0 + t, rpc=dict(bad, validated_seq=1000 + i), ref=5000), monkeypatch, capsys)
        assert d["verdict"] == "healthy"
    _, d = c.decide(obs(T0 + 600, rpc=dict(bad, validated_seq=1010), ref=5000), monkeypatch, capsys)
    assert (d["detector"], d["verdict"]) == ("stuck_state", "act")
    assert d["detail"] == "server_state connected for 600s"


@pytest.mark.parametrize("state", ["full", "proposing", "validating"])
def test_good_states_never_stuck(core, monkeypatch, capsys, state):
    c = core(STUCK_SEC=60, STALE_SEC=99999)
    for i in range(5):
        _, d = c.decide(
            obs(T0 + 60 * i, rpc=dict(GOOD, server_state=state, validated_seq=1000 + i)), monkeypatch, capsys
        )
    assert d["verdict"] == "healthy"


def test_zero_peers(core, monkeypatch, capsys):
    c = core(ZERO_PEERS_SEC=600)
    zp = dict(GOOD, peers=0)
    _, d = c.decide(obs(T0, rpc=dict(zp, validated_seq=1)), monkeypatch, capsys)
    _, d = c.decide(obs(T0 + 599, rpc=dict(zp, validated_seq=2)), monkeypatch, capsys)
    assert d["verdict"] == "healthy"
    _, d = c.decide(obs(T0 + 600, rpc=dict(zp, validated_seq=3)), monkeypatch, capsys)
    assert (d["detector"], d["detail"]) == ("zero_peers", "0 peers for 600s")


def test_zero_peers_resets_with_one_peer(core, monkeypatch, capsys):
    c = core(ZERO_PEERS_SEC=600)
    for i, p in enumerate([0, 0, 1, 0]):
        _, d = c.decide(obs(T0 + 300 * i, rpc=dict(GOOD, peers=p, validated_seq=1 + i)), monkeypatch, capsys)
    assert d["verdict"] == "healthy" and c.st()["zero_peers_since"] == T0 + 900


# ---------------------------------------------------------------- guards


def test_dryrun_mode_would_act(core, monkeypatch, capsys):
    c = core(MODE="dryrun")
    _, d = c.decide(obs(T0, running=False, rpc=FAIL), monkeypatch, capsys)
    assert d["verdict"] == "would_act" and d["mode"] == "dryrun"


def test_force_dryrun_env_overrides_enforce(core, monkeypatch, capsys):
    c = core(MODE="enforce")
    monkeypatch.setenv("SELFHEAL_FORCE_DRYRUN", "1")
    _, d = c.decide(obs(T0, running=False, rpc=FAIL), monkeypatch, capsys)
    assert d["verdict"] == "would_act"


def test_maintenance_guard(core, monkeypatch, capsys):
    c = core()
    _, d = c.decide(obs(T0, running=False, rpc=FAIL, maint=True), monkeypatch, capsys)
    assert (d["verdict"], d["suppressed_by"]) == ("suppressed", "maintenance")


def test_lock_guard(core, monkeypatch, capsys):
    c = core()
    _, d = c.decide(obs(T0, running=False, rpc=FAIL, locks=["histarchive until x"]), monkeypatch, capsys)
    assert d["suppressed_by"] == "lock"


def test_grace_guard_and_its_end(core, monkeypatch, capsys):
    c = core(RPC_FAILS=1, GRACE_SEC=900)
    _, d = c.decide(obs(T0, rpc=FAIL, started=T0 - 899), monkeypatch, capsys)
    assert d["suppressed_by"] == "grace"
    _, d = c.decide(obs(T0 + 1, rpc=FAIL, started=T0 - 899), monkeypatch, capsys)
    assert d["verdict"] == "act"


@pytest.mark.parametrize(
    "ref,ref_ok,expect",
    [(None, False, "network_stall"), (1005, True, "network_stall"), (1006, True, None), (2000, False, "network_stall")],
)
def test_network_stall_guard(core, monkeypatch, capsys, ref, ref_ok, expect):
    c = core(STALE_SEC=300, REF_LAG=5)
    c.decide(obs(T0), monkeypatch, capsys)
    _, d = c.decide(obs(T0 + 300, ref=ref, ref_ok=ref_ok), monkeypatch, capsys)
    assert d["detector"] == "stale_ledger" and d["suppressed_by"] == expect
    assert d["verdict"] == ("act" if expect is None else "suppressed")


def test_network_stall_does_not_guard_container_down(core, monkeypatch, capsys):
    c = core()
    _, d = c.decide(obs(T0, running=False, rpc=FAIL, ref=None, ref_ok=False), monkeypatch, capsys)
    assert d["verdict"] == "act"


def test_guard_order_breaker_first(core, monkeypatch, capsys):
    c = core()
    c.decide(obs(T0), monkeypatch, capsys)
    st = c.st()
    st["breaker"] = {"open": True, "since": T0, "reason": "x"}
    c.state.write_text(json.dumps(st))
    _, d = c.decide(obs(T0 + 60, running=False, rpc=FAIL, maint=True, locks=["a"]), monkeypatch, capsys)
    assert d["suppressed_by"] == "breaker"


# ---------------------------------------------------------------- backoff, budget, breaker


def test_backoff_doubles_per_action(core, monkeypatch, capsys):
    c = core(BACKOFF_SEC=600, BACKOFF_MAX_SEC=7200, MAX_ACTIONS=10)
    down = {"running": False, "rpc": FAIL}
    _, d = c.decide(obs(T0, **down), monkeypatch, capsys)
    assert d["verdict"] == "act"
    c.record(T0, capsys)
    _, d = c.decide(obs(T0 + 599, **down), monkeypatch, capsys)
    assert d["suppressed_by"] == "backoff"
    _, d = c.decide(obs(T0 + 600, **down), monkeypatch, capsys)
    assert d["verdict"] == "act"
    c.record(T0 + 600, capsys)
    _, d = c.decide(obs(T0 + 600 + 1199, **down), monkeypatch, capsys)
    assert d["suppressed_by"] == "backoff"  # 2 actions in 24 h -> 1200 s
    _, d = c.decide(obs(T0 + 600 + 1200, **down), monkeypatch, capsys)
    assert d["verdict"] == "act"


def test_backoff_capped(core, monkeypatch, capsys):
    c = core(BACKOFF_SEC=600, BACKOFF_MAX_SEC=1000, MAX_ACTIONS=10)
    for i in range(4):
        c.record(T0 + i, capsys)
    _, d = c.decide(obs(T0 + 3 + 1000, running=False, rpc=FAIL), monkeypatch, capsys)
    assert d["verdict"] == "act"


def test_budget_opens_breaker_after_k(core, monkeypatch, capsys):
    c = core(MAX_ACTIONS=3, BACKOFF_SEC=60, BACKOFF_MAX_SEC=60)
    down = {"running": False, "rpc": FAIL}
    t, acted = T0, 0
    for _ in range(3):
        _, d = c.decide(obs(t, **down), monkeypatch, capsys)
        assert d["verdict"] == "act"
        c.record(t, capsys)
        acted += 1
        t += 61
    _, d = c.decide(obs(t, **down), monkeypatch, capsys)
    assert acted == 3 and d["suppressed_by"] == "budget" and d["breaker_open"]
    assert d["breaker_reason"] == "container_down after 3 actions/24h"
    _, d = c.decide(obs(t + 86400, **down), monkeypatch, capsys)
    assert d["suppressed_by"] == "breaker"  # stays open after the 24 h window, only reset closes it
    _, d = c.decide(obs(t + 86460), monkeypatch, capsys)
    assert d["verdict"] == "healthy" and d["breaker_open"]


def test_reset_closes_breaker(core, monkeypatch, capsys):
    c = core(MAX_ACTIONS=1, BACKOFF_SEC=60, BACKOFF_MAX_SEC=60)
    c.record(T0, capsys)
    _, d = c.decide(obs(T0 + 61, running=False, rpc=FAIL), monkeypatch, capsys)
    assert d["breaker_open"]
    sd.reset(str(c.state), "operator fixed egress", T0 + 100)
    out = json.loads(capsys.readouterr().out)
    assert out["was_open"] and out["reason"] == "operator fixed egress"
    _, d = c.decide(obs(T0 + 120, running=False, rpc=FAIL), monkeypatch, capsys)
    assert d["verdict"] == "act" and not d["breaker_open"] and d["actions_24h"] == 0


def test_actions_older_than_24h_expire(core, monkeypatch, capsys):
    c = core(MAX_ACTIONS=1, BACKOFF_SEC=60, BACKOFF_MAX_SEC=60)
    c.record(T0, capsys)
    _, d = c.decide(obs(T0 + 86400, running=False, rpc=FAIL), monkeypatch, capsys)
    assert d["verdict"] == "act" and d["actions_24h"] == 0


def test_record_resets_tracking(core, monkeypatch, capsys):
    c = core(RPC_FAILS=5)
    for i in range(3):
        c.decide(obs(T0 + i, rpc=FAIL), monkeypatch, capsys)
    c.record(T0 + 10, capsys)
    st = c.st()
    assert st["rpc_fail_streak"] == 0 and st["actions"] == [T0 + 10] and st["last_action_ts"] == T0 + 10


# ---------------------------------------------------------------- conf and state errors


@pytest.mark.parametrize("line", ["MODE=yolo", "MAX_ACTIONS=0", "RPC_FAILS=x", "STALE_SEC=-1"])
def test_bad_conf_exit_3(tmp_path, monkeypatch, capsys, line):
    (tmp_path / "c.env").write_text(line + "\n")
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(obs(T0))))
    assert sd.decide(str(tmp_path / "s.json"), str(tmp_path / "c.env")) == 3
    assert not (tmp_path / "s.json").exists()


@pytest.mark.parametrize("body", ["{not json", '{"v": 2}', "[]"])
def test_unreadable_state_refuses(tmp_path, monkeypatch, capsys, body):
    (tmp_path / "s.json").write_text(body)
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(obs(T0, running=False, rpc=FAIL))))
    assert sd.decide(str(tmp_path / "s.json"), None) == 5
    assert capsys.readouterr().out == ""
    assert (tmp_path / "s.json").read_text() == body


def test_bad_observation_exit_3(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("{}"))
    assert sd.decide(str(tmp_path / "s.json"), None) == 3


def test_default_mode_is_dryrun(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(obs(T0, running=False, rpc=FAIL))))
    assert sd.decide(str(tmp_path / "s.json"), None) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "would_act"


# ---------------------------------------------------------------- pft-selfheal.sh with stubs

STUB_DOCKER = r"""#!/usr/bin/env bash
# stub docker: behaviour from files in $STUB
echo "docker $*" >> "$STUB/calls"
case "$1" in
  inspect)
    [ -e "$STUB/missing" ] && { echo "Error: No such object" >&2; exit 1; }
    case "$3" in
      *State.Running*) echo "$(cat "$STUB/running") $(cat "$STUB/started")" ;;
      *compose.project*) cat "$STUB/labels" 2>/dev/null || echo "|||" ;;
    esac ;;
  exec)
    [ -e "$STUB/rpc_fail" ] && exit 7
    cat "$STUB/rpc" ;;
  restart|start|compose)
    exit "$(cat "$STUB/act_rc" 2>/dev/null || echo 0)" ;;
  *) exit 99 ;;
esac
"""
STUB_CURL = r"""#!/usr/bin/env bash
echo "curl $*" >> "$STUB/calls"
[ -e "$STUB/ref" ] || exit 6
cat "$STUB/ref"
"""
STUB_MAINT = r"""#!/usr/bin/env bash
echo "maint $*" >> "$STUB/calls"
case "$1" in
  active) [ -e "$STUB/maint" ] ;;
  lock) [ -e "$STUB/lock_fail" ] && exit 3; cat "$STUB/locks" 2>/dev/null || echo "no data-collection locks" ;;
esac
"""
STUB_EGRESS = r"""#!/usr/bin/env bash
echo "egress $*" >> "$STUB/calls"
exit "$(cat "$STUB/egress_rc" 2>/dev/null || echo 0)"
"""


def server_info(state="full", seq=1000, peers=10):
    return json.dumps(
        {
            "result": {
                "status": "success",
                "info": {"server_state": state, "validated_ledger": {"seq": seq}, "peers": peers},
            }
        }
    )


class Sh:
    def __init__(self, base, **conf):
        self.base = base
        self.stub = base / "stub"
        self.state = base / "state"
        self.text = base / "text"
        for d in (self.stub, self.state, self.text):
            d.mkdir()
        for name, body in (
            ("docker", STUB_DOCKER),
            ("curl", STUB_CURL),
            ("maint", STUB_MAINT),
            ("egress", STUB_EGRESS),
        ):
            p = base / f"{name}.sh"
            p.write_text(body)
            p.chmod(0o755)
        conf.setdefault("MODE", "enforce")
        lines = [f"STATE_DIR={self.state}", f"TEXTFILE_DIR={self.text}", "CONTAINER=postfiatd-sentry"]
        lines += [f"{k}={v}" for k, v in conf.items()]
        self.conf = base / "selfheal.env"
        self.conf.write_text("\n".join(lines) + "\n")
        self.set(running="true", started="2026-01-01T00:00:00.123Z", rpc=server_info())

    def set(self, **kv):
        for k, v in kv.items():
            p = self.stub / k
            if v is None:
                p.unlink(missing_ok=True)
            else:
                p.write_text(str(v) + "\n")

    def run(self, *args, now=T0):
        env = {
            "PATH": os.environ["PATH"],
            "STUB": str(self.stub),
            "PFT_SH_CONF": str(self.conf),
            "PFT_SH_DOCKER": str(self.base / "docker.sh"),
            "PFT_SH_CURL": str(self.base / "curl.sh"),
            "PFT_SH_MAINT": str(self.base / "maint.sh"),
            "PFT_SH_EGRESS": str(self.base / "egress.sh"),
            "PFT_SH_DECIDER": str(DECIDER),
            "PFT_SH_NOW": str(now),
            "PFT_SH_TEST": "1",
        }
        (self.stub / "calls").write_text("")
        p = subprocess.run(
            ["bash", str(SCRIPT), *args],
            check=False,
            env=env,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=60,
        )
        return p

    def calls(self):
        return (self.stub / "calls").read_text().splitlines()

    def journal(self):
        p = self.state / "journal-postfiatd-sentry.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def prom(self):
        return (self.text / "pft_selfheal_postfiatd-sentry.prom").read_text()


@pytest.fixture
def sh():
    root = Path(os.environ.get("TEST_TMPDIR") or Path.home() / ".cache")
    root.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="selfheal-test.", dir=root))
    os.chmod(base, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    made = []

    def make(**conf):
        d = base / f"s{len(made)}"
        d.mkdir()
        made.append(Sh(d, **conf))
        return made[-1]

    yield make
    shutil.rmtree(base)


def test_stub_self_check(sh):
    s = sh()
    p = s.run("run")
    assert p.returncode == 0, p.stderr
    assert any(c.startswith("docker exec postfiatd-sentry curl") for c in s.calls()), "stub docker did not answer"
    assert '"verdict": "healthy"' in p.stderr or '"verdict":"healthy"' in p.stderr


def test_sh_healthy_no_action_no_journal(sh):
    s = sh()
    p = s.run("run")
    assert p.returncode == 0
    assert not [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]
    assert s.journal() == []
    prom = s.prom()
    assert 'pft_selfheal_up{container="postfiatd-sentry"} 1' in prom
    assert 'pft_selfheal_verdict{container="postfiatd-sentry",verdict="healthy"} 1' in prom
    assert 'pft_selfheal_enforce{container="postfiatd-sentry"} 1' in prom
    assert 'pft_selfheal_breaker_open{container="postfiatd-sentry"} 0' in prom
    assert not any(c.startswith("curl") for c in s.calls()), "reference queried for a healthy advancing sample"
    assert s.run("status").returncode == 0


def test_sh_stopped_docker_run_container_started_once(sh):
    s = sh()
    s.set(running="false")
    p = s.run("run")
    assert p.returncode == 0, p.stderr
    acts = [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]
    assert acts == ["docker start postfiatd-sentry"]
    assert "egress reapply --container postfiatd-sentry" in s.calls()
    ev = [j["event"] for j in s.journal()]
    assert ev == ["decision", "action", "result"]
    assert s.journal()[2]["rc"] == 0 and s.journal()[2]["egress_rc"] == 0
    assert 'pft_selfheal_actions_total{container="postfiatd-sentry"} 1' in s.prom()
    assert 'pft_selfheal_actions_24h{container="postfiatd-sentry"} 1' in s.prom()


def test_sh_compose_container_up_no_recreate(sh):
    s = sh()
    s.set(labels="postfiatd|postfiatd|/opt/p/a.yml,/opt/p/b.yml|/opt/p")
    assert s.run("run").returncode == 0  # healthy run caches the compose identity
    s.set(missing="1")
    p = s.run("run", now=T0 + 60)
    assert p.returncode == 0, p.stderr
    acts = [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]
    assert acts == [
        (
            "docker compose --project-name postfiatd --project-directory /opt/p -f /opt/p/a.yml -f /opt/p/b.yml "
            "up -d --no-recreate postfiatd"
        )
    ]


def test_sh_rpc_failures_restart(sh):
    s = sh(RPC_FAILS=2, GRACE_SEC=0)
    s.set(rpc_fail="1")
    assert s.run("run").returncode == 0
    assert s.journal() == []
    p = s.run("run", now=T0 + 60)
    acts = [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]
    assert p.returncode == 0 and acts == ["docker restart -t 60 postfiatd-sentry"]


def test_sh_stale_queries_reference_and_guards_network_stall(sh):
    s = sh(STALE_SEC=120, GRACE_SEC=0)
    s.run("run")
    s.set(ref=server_info(seq=1003))
    p = s.run("run", now=T0 + 60)
    assert any(c.startswith("curl") for c in s.calls()), "unchanged seq must query the reference"
    p = s.run("run", now=T0 + 120)
    d = json.loads(p.stderr.strip().splitlines()[-1])
    assert (d["detector"], d["suppressed_by"]) == ("stale_ledger", "network_stall")
    assert not [c for c in s.calls() if c.split()[1] == "restart"]
    s.set(ref=server_info(seq=1100))
    p = s.run("run", now=T0 + 180)
    assert [c for c in s.calls() if c.split()[1] == "restart"], p.stderr


def test_sh_reference_unreachable_is_a_stall(sh):
    s = sh(STALE_SEC=60, GRACE_SEC=0)
    s.run("run")
    p = s.run("run", now=T0 + 60)
    d = json.loads(p.stderr.strip().splitlines()[-1])
    assert d["suppressed_by"] == "network_stall"


def test_sh_maintenance_window_zero_actions(sh):
    s = sh()
    s.set(running="false", maint="1")
    for i in range(5):
        p = s.run("run", now=T0 + 60 * i)
        assert p.returncode == 0
        assert not [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]
    assert {j["suppressed_by"] for j in s.journal()} == {"maintenance"}
    assert s.run("status").returncode == 1


def test_sh_lock_and_unreadable_lock_state(sh):
    s = sh()
    s.set(running="false", locks="peerwatch-24h until 2026-11-12T13:50:29Z")
    p = s.run("run")
    assert json.loads(p.stderr.strip().splitlines()[-1])["suppressed_by"] == "lock"
    s.set(locks=None, lock_fail="1")
    p = s.run("run", now=T0 + 60)
    assert json.loads(p.stderr.strip().splitlines()[-1])["suppressed_by"] == "lock"


def test_sh_dry_run_flag_never_acts(sh):
    s = sh()
    s.set(running="false")
    p = s.run("run", "--dry-run")
    assert p.returncode == 0
    assert json.loads(p.stderr.strip().splitlines()[-1])["verdict"] == "would_act"
    assert not [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]
    assert 'pft_selfheal_enforce{container="postfiatd-sentry"} 0' in s.prom()


def test_sh_action_failure_exit_1_and_recorded(sh):
    s = sh()
    s.set(running="false", act_rc=1)
    p = s.run("run")
    assert p.returncode == 1
    assert s.journal()[-1]["rc"] == 1
    assert json.loads((s.state / "state-postfiatd-sentry.json").read_text())["actions"] == [T0]


def test_sh_unfixable_fault_opens_breaker_after_k_then_reset(sh):
    s = sh(MAX_ACTIONS=2, BACKOFF_SEC=60, BACKOFF_MAX_SEC=60, ZERO_PEERS_SEC=60, GRACE_SEC=0)
    s.set(rpc=server_info(peers=0, seq=1))
    t, restarts = T0, 0
    for i in range(12):
        s.set(rpc=server_info(peers=0, seq=1 + i))
        s.run("run", now=t)
        restarts += len([c for c in s.calls() if c.split()[1] == "restart"])
        t += 61
    assert restarts == 2
    assert s.run("status", now=t - 61).returncode == 2
    assert 'pft_selfheal_breaker_open{container="postfiatd-sentry"} 1' in s.prom()
    assert s.run("reset", now=t).returncode == 3  # --reason is required
    p = s.run("reset", "--reason", "egress fault removed", now=t)
    assert p.returncode == 0 and json.loads(p.stdout)["was_open"]
    assert s.journal()[-1]["event"] == "reset"
    s.set(rpc=server_info(peers=10, seq=500))
    s.run("run", now=t + 1)
    assert 'pft_selfheal_breaker_open{container="postfiatd-sentry"} 0' in s.prom()
    assert s.run("status", now=t + 1).returncode == 0


def test_sh_status_stale_and_missing(sh):
    s = sh()
    assert s.run("status").returncode == 4
    s.run("run")
    assert s.run("status", now=T0 + 301).returncode == 4
    p = s.run("status", "--json", now=T0 + 5)
    assert p.returncode == 0 and json.loads(p.stdout)["age_sec"] == 5


def test_sh_bad_state_refuses_and_up_0(sh):
    s = sh()
    s.set(running="false")
    (s.state / "state-postfiatd-sentry.json").write_text("{broken")
    p = s.run("run")
    assert p.returncode == 5
    assert not [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]
    assert 'pft_selfheal_up{container="postfiatd-sentry"} 0' in s.prom()
    assert "pft_selfheal_breaker_open" not in s.prom()


def test_sh_bad_conf_exit_3(sh):
    s = sh(MODE="yolo")
    s.set(running="false")
    assert s.run("run").returncode == 3
    assert not [c for c in s.calls() if c.split()[1] in ("restart", "start", "compose")]


@pytest.mark.parametrize("args", [["run", "--container", "../x"], ["run", "--bogus"], ["nope"]])
def test_sh_usage_exit_3(sh, args):
    s = sh()
    assert s.run(*args).returncode == 3


def test_sh_empty_rpc_answer_counts_as_failure(sh):
    s = sh(RPC_FAILS=1, GRACE_SEC=0)
    s.set(rpc="")
    p = s.run("run")
    assert p.returncode == 0, p.stderr
    d = json.loads(p.stderr.strip().splitlines()[-1])
    assert (d["detector"], d["verdict"]) == ("rpc_failures", "act")


def test_sh_never_execs_anything_but_server_info(sh):
    s = sh(RPC_FAILS=1, GRACE_SEC=0)
    s.set(rpc_fail="1")
    s.run("run")
    s.set(rpc_fail=None, running="false")
    s.run("run", now=T0 + 7200)
    execs = [c for c in Path(s.stub / "calls").read_text().splitlines() if c.startswith("docker exec")]
    assert all('"method":"server_info"' in c for c in execs)
