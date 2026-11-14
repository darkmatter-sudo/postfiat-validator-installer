"""redaction_gate.py: the install run publishes a real bundle + reports only if this gate exits 0.

Each kind of hit has a control that must be refused (with that reason), next to a clean file that must pass.
"""

import gzip
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
GATE = HERE / "redaction_gate.py"
CLEAN = '{"alertname": "PFTNodeDown", "instance": "127.0.0.1:9100", "note": "<redacted-ip> ntfy.sh/<redacted>"}\n'


def gate(d, names=""):
    env = dict(os.environ, PFT_RED_NAMES=names)
    return subprocess.run(
        [sys.executable, "-I", str(GATE), str(d)], check=False, capture_output=True, text=True, env=env
    )


def test_clean_dir_passes(tmp_path):
    (tmp_path / "a.json").write_text(CLEAN)
    (tmp_path / "b.json.gz").write_bytes(gzip.compress(CLEAN.encode()))
    r = gate(tmp_path, "someuser,somehost")
    assert r.returncode == 0, r.stdout
    assert "2 file(s), 0 refused, 2 name(s) checked" in r.stdout


@pytest.mark.parametrize(
    "text, reason",
    [
        ("peer 8.8.4.4 connected\n", "public-ip-or-topic"),
        ("sent to https://ntfy.sh/pft-real-topic-123\n", "public-ip-or-topic"),
        ("path /home/someone/work\n", "home-path"),
        ("ran on somehost\n", "user-or-host-name"),
    ],
)
def test_each_hit_is_refused_with_its_reason(tmp_path, text, reason):
    (tmp_path / "clean.md").write_text(CLEAN)
    (tmp_path / "bad.md").write_text(CLEAN + text)
    r = gate(tmp_path, "someuser,somehost")
    assert r.returncode == 1, r.stdout
    assert f"REFUSE bad.md: {reason}" in r.stdout
    assert "REFUSE clean.md" not in r.stdout
    assert "pft-real-topic-123" not in r.stdout and "somehost" not in r.stdout


def test_hit_inside_gzip_is_refused(tmp_path):
    (tmp_path / "b.json.gz").write_bytes(gzip.compress((CLEAN + "from 8.8.4.4\n").encode()))
    r = gate(tmp_path)
    assert r.returncode == 1 and "REFUSE b.json.gz: public-ip-or-topic" in r.stdout


def test_empty_dir_and_bad_usage_refused(tmp_path):
    assert gate(tmp_path).returncode == 1
    assert gate(tmp_path / "missing").returncode == 3
