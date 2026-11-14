"""pft-peertls-fix tests: the real script against a fake container (tests/fixnode/docker) whose peer port is a real
`openssl s_server` that restarts with the ssl_ciphers of the config the fix installed. Every refusal asserts that
nothing changed (config bytes, no `restart` in the docker call log); every gate failure asserts the rollback.

Run from the peertls folder: TMPDIR=$HOME/.cache python3 -m pytest -q tests
"""

import os
import subprocess
from pathlib import Path

import pytest

from test_peertls import free_port, make_cert, sh

REPO = Path(__file__).resolve().parents[1]
FIX = REPO / "pft-peertls-fix.sh"
STUB = REPO / "tests" / "fixnode" / "docker"
MARK = "# pft-peertls-fix: managed line (inbound peer TLS 1.2 suites; see peertls/README.md)"
LINE = "ssl_ciphers = ECDHE+AESGCM:ECDHE+CHACHA20"
PUB = "n9KfixtureNodeKey000000000000000000000000000000000"
CFG = """[server]
port_rpc_admin_local
port_peer

[port_rpc_admin_local]
port = 5005
ip = 127.0.0.1
admin = 127.0.0.1
protocol = http

[port_peer]
port = 2559
ip = 0.0.0.0
protocol = peer

[node_seed]
sFixtureSeedNotARealOne000000

[network_id]
2025
"""
APPLIED = "GOOD=ECDHE-RSA-AES256-GCM-SHA384 AES256-GCM-SHA384=NONE DHE-RSA-AES256-SHA256=NONE"
WEAK = (
    "GOOD=ECDHE-RSA-AES256-GCM-SHA384 AES256-GCM-SHA384=AES256-GCM-SHA384 DHE-RSA-AES256-SHA256=DHE-RSA-AES256-SHA256"
)


class Node:
    def __init__(self, tmp, cfg=CFG):
        self.tmp = tmp
        self.state = tmp / "state"
        self.vol = tmp / "vol" / "_data"
        self.bin = tmp / "bin"
        for d in (self.state, self.vol, self.bin):
            d.mkdir(parents=True)
        self.cfg = self.vol / "postfiatd.cfg"
        self.cfg.write_text(cfg)
        self.cfg.chmod(0o600)
        self.port = free_port()
        self.conf = tmp / "pft-peertls.env"
        self.conf.write_text(f"BACKUP_DIR={tmp / 'backup'}\nPEER_PORT={self.port}\nHEALTH_BUDGET=20\nPOLL_SEC=1\n")
        k, c = make_cert(tmp)
        os.rename(k, self.state / "key.pem")
        os.rename(c, self.state / "cert.pem")
        for f, v in (("name", "postfiatd"), ("vol", str(self.vol)), ("pubkey", PUB), ("peers", "3")):
            (self.state / f).write_text(v)
        self.stub("pft-maint", 'case "$1" in active) [ -e "$FX_STATE/maint" ];; *) exit 3;; esac')
        self.stub(
            "pft-integrity",
            'echo "$*" >> "$FX_STATE/integrity.log"; '
            '[ "$1" = verify ] && { [ -e "$FX_STATE/integrity_other" ] && echo "  [WARN] bin:/usr/local/bin/x"; '
            'echo "  [WARN] cfgvol:postfiatd.cfg sha256 changed"; }; exit 0',
        )
        self.stub("ss", f'echo "LISTEN 0 4096 0.0.0.0:{self.port} 0.0.0.0:*"')
        self.maint(True)
        self.docker("start-fixture")
        (self.state / "calls.log").write_text("")

    def stub(self, name, body):
        p = self.bin / name
        p.write_text("#!/usr/bin/env bash\n" + body + "\n")
        p.chmod(0o755)

    def maint(self, on):
        f = self.state / "maint"
        if on:
            f.write_text("")
        elif f.exists():
            f.unlink()

    def flag(self, name, value=""):
        (self.state / name).write_text(value)

    def env(self):
        e = dict(os.environ)
        e.update(
            FX_STATE=str(self.state),
            FX_PORT=str(self.port),
            PFT_PTLS_CONF=str(self.conf),
            PFT_PTLSF_ROOT="/",
            PFT_PTLSF_DOCKER=str(STUB),
            PFT_PTLSF_MAINT=str(self.bin / "pft-maint"),
            PFT_PTLSF_INTEGRITY=str(self.bin / "pft-integrity"),
            PFT_PTLSF_SS=str(self.bin / "ss"),
        )
        e.pop("PFT_PTLSF_RPC", None)
        return e

    def docker(self, *args):
        return subprocess.run([str(STUB), *args], env=self.env(), check=False, capture_output=True, text=True)

    def run(self, *args):
        return sh("bash", str(FIX), *args, env=self.env(), timeout=180)

    def calls(self):
        return (self.state / "calls.log").read_text().splitlines()

    def restarts(self):
        return [c for c in self.calls() if c.startswith("restart")]

    def view(self):
        out = []
        for s in ("ECDHE-RSA-AES256-GCM-SHA384", "AES256-GCM-SHA384", "DHE-RSA-AES256-SHA256"):
            r = sh(
                "openssl",
                "s_client",
                "-connect",
                f"127.0.0.1:{self.port}",
                "-tls1_2",
                "-cipher",
                f"{s}@SECLEVEL=0",
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            neg = [ln.split()[-1] for ln in r.stdout.splitlines() if ln.startswith("New, ")]
            out.append(neg[0] if neg and neg[0] != "(NONE)" else "NONE")
        return out

    def close(self):
        try:
            os.killpg(int((self.state / "pgid").read_text()), 15)
        except (OSError, ValueError):
            pass


@pytest.fixture
def node(tmp_path):
    n = Node(tmp_path)
    yield n
    n.close()


def node_with(tmp_path, cfg):
    return Node(tmp_path, cfg)


def test_fixture_self_check(node):
    """the fake node answers like the real finding before any fix: static RSA and CBC-SHA2 accepted"""
    assert node.view() == ["ECDHE-RSA-AES256-GCM-SHA384", "AES256-GCM-SHA384", "DHE-RSA-AES256-SHA256"]
    r = node.docker("exec", "postfiatd", "sh", "-c", "curl -s other")
    assert r.returncode == 1  # the stub refuses any exec shape but the fix's RPC call


def test_plan_is_read_only_and_shows_only_port_peer_lines(node):
    before = node.cfg.read_bytes()
    r = node.run("plan")
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"+{MARK}" in r.stdout and f"+{LINE}" in r.stdout
    assert "sFixture" not in r.stdout  # no other config line (seed) is printed
    assert node.cfg.read_bytes() == before and node.restarts() == []


def test_dry_run_changes_nothing(node):
    before = node.cfg.read_bytes()
    r = node.run("apply", "--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "dry run" in r.stdout and f"pre-apply TLS {WEAK}" in r.stdout
    assert node.cfg.read_bytes() == before and node.restarts() == []
    assert not (node.tmp / "backup").exists()  # dry run creates nothing on the host


def test_apply_without_yes_is_refused(node):
    before = node.cfg.read_bytes()
    r = node.run("apply")
    assert r.returncode == 4 and "pass --yes" in r.stderr
    assert node.cfg.read_bytes() == before and node.calls() == []


def test_apply_outside_maint_window_is_refused(node):
    node.maint(False)
    before = node.cfg.read_bytes()
    r = node.run("apply", "--yes")
    assert r.returncode == 4 and "no active pft-maint window" in r.stdout
    assert node.cfg.read_bytes() == before and node.restarts() == []
    assert not (node.tmp / "backup").exists()


def test_apply_fixes_and_gates_on_live_tls(node):
    before = node.cfg.read_text()
    r = node.run("apply", "--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "health: PASS" in r.stdout and f"TLS {APPLIED}" in r.stdout and "apply: done" in r.stdout
    after = node.cfg.read_text()
    # exactly the two managed lines, right after the [port_peer] header; nothing else touched
    assert after == before.replace("[port_peer]\n", f"[port_peer]\n{MARK}\n{LINE}\n")
    assert oct(node.cfg.stat().st_mode & 0o777) == "0o600"
    assert len(node.restarts()) == 1
    assert node.view() == ["ECDHE-RSA-AES256-GCM-SHA384", "NONE", "NONE"]
    backups = sorted(p.name for p in (node.tmp / "backup").iterdir())
    assert len(backups) == 3 and backups[0].startswith("postfiatd.cfg.")  # cfg + .meta + .tls
    b = node.tmp / "backup" / backups[0]
    assert b.read_text() == before and oct(b.stat().st_mode & 0o777) == "0o600"
    assert (node.tmp / "backup" / (backups[0] + ".tls")).read_text().strip() == WEAK
    assert "accept --reason pft-peertls-fix apply" in (node.state / "integrity.log").read_text()


def test_second_apply_is_a_no_op(node):
    assert node.run("apply", "--yes").returncode == 0
    once = node.cfg.read_bytes()
    r = node.run("apply", "--yes")
    assert r.returncode == 0 and "already applied" in r.stdout
    assert node.cfg.read_bytes() == once and len(node.restarts()) == 1


def test_plan_after_apply_reports_nothing_to_change(node):
    """an applied host: plan prints no diff and no restart line (fix-run 07 printed an empty diff + 'then: docker restart')"""
    assert node.run("apply", "--yes").returncode == 0
    once = node.cfg.read_bytes()
    r = node.run("plan")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "already applied (managed line present): nothing to change, no restart" in r.stdout
    assert "diff:" not in r.stdout and "then: docker restart" not in r.stdout
    assert node.cfg.read_bytes() == once and len(node.restarts()) == 1


def test_gate_fails_when_node_ignores_the_line_and_rolls_back(node):
    node.flag("ignore_cfg")  # the build would not honour ssl_ciphers: weak suites still answered after restart
    before = node.cfg.read_bytes()
    r = node.run("apply", "--yes")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "health: FAIL" in r.stdout and f"TLS {WEAK}" in r.stdout and "automatic rollback" in r.stdout
    assert "rollback: health: PASS" in r.stdout
    assert node.cfg.read_bytes() == before and len(node.restarts()) == 2


def test_gate_fails_on_changed_node_key(node):
    node.flag("pubkey_after_restart", "n9KotherKey00000000000000000000000000000000000000")
    before = node.cfg.read_bytes()
    r = node.run("apply", "--yes")
    assert "health: FAIL" in r.stdout and "pubkey_node CHANGED" in r.stdout
    assert r.returncode == 5  # the rollback gate also sees the changed key: a human must look
    assert node.cfg.read_bytes() == before


def test_gate_fails_on_too_few_peers(node):
    node.conf.write_text(node.conf.read_text() + "MIN_PEERS=5\n")
    before = node.cfg.read_bytes()
    r = node.run("apply", "--yes")
    assert "health: FAIL" in r.stdout and "peers=3" in r.stdout
    assert r.returncode == 5 and node.cfg.read_bytes() == before


def test_failed_restart_restores_config(node):
    node.flag("fail_restart")
    before = node.cfg.read_bytes()
    r = node.run("apply", "--yes")
    assert "docker restart postfiatd FAILED" in r.stdout and "automatic rollback" in r.stdout
    assert r.returncode == 5 and node.cfg.read_bytes() == before


def test_integrity_not_accepted_when_other_items_changed(node):
    node.flag("integrity_other")
    r = node.run("apply", "--yes")
    assert r.returncode == 0 and "integrity: NOT accepted" in r.stdout and "bin:/usr/local/bin/x" in r.stdout
    assert "accept" not in (node.state / "integrity.log").read_text().replace("verify", "")


def test_rollback_command_restores_backup_and_old_tls(node):
    before = node.cfg.read_bytes()
    assert node.run("apply", "--yes").returncode == 0
    r = node.run("rollback", "--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "rollback: health: PASS" in r.stdout and f"TLS {WEAK}" in r.stdout
    assert node.cfg.read_bytes() == before and len(node.restarts()) == 2


def test_rollback_outside_window_is_refused(node):
    assert node.run("apply", "--yes").returncode == 0
    node.maint(False)
    applied = node.cfg.read_bytes()
    r = node.run("rollback", "--yes")
    assert r.returncode == 4 and node.cfg.read_bytes() == applied and len(node.restarts()) == 1


@pytest.mark.parametrize(
    "edit, why",
    [
        (lambda c: c.replace("protocol = peer\n", "protocol = peer\nssl_ciphers = ALL\n"), "unmanaged ssl_ciphers"),
        (lambda c: c + "\n[port_peer]\nport = 2560\n", "has 2 [port_peer] sections"),
        (lambda c: c.replace("port_rpc_admin_local\nport_peer\n", "port_rpc_admin_local\n"), "does not list port_peer"),
    ],
)
def test_config_refusals_change_nothing(tmp_path, edit, why):
    n = Node(tmp_path, edit(CFG))
    try:
        before = n.cfg.read_bytes()
        r = n.run("apply", "--yes")
        assert r.returncode == 4 and why in r.stdout, r.stdout
        assert n.cfg.read_bytes() == before and n.restarts() == []
    finally:
        n.close()


def test_cipher_string_selecting_nothing_is_refused(node):
    node.conf.write_text(node.conf.read_text() + "CIPHERS=NOSUCHSUITE\n")
    before = node.cfg.read_bytes()
    r = node.run("apply", "--yes")
    assert r.returncode == 4 and "selects no TLS 1.2 suite" in r.stdout
    assert node.cfg.read_bytes() == before and node.restarts() == []


def test_cipher_string_with_newline_is_refused(node):
    node.conf.write_text(node.conf.read_text() + 'CIPHERS="ECDHE+AESGCM\\n[x]"\n')
    r = node.run("apply", "--yes")
    assert r.returncode == 3 and "bad CIPHERS" in r.stderr and node.calls() == []
