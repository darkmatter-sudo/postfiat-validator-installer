"""Shell-level tests for `pft-fwaudit audit --textfile`, `validate` and `pull`.

The audit runs the real evaluator on the redacted real captures (tests/fixtures); every metric is checked against the
evaluator's own --json for the same bundle. Every error path asserts what was (not) written: up 0 with only the up and
timestamp samples, no file at all, or the previous pulled copy left byte-identical.
"""

import json
import os
import re
import subprocess

import pytest
from test_fwaudit import in_section, insert_before, listen, load, section_bounds

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
SCRIPT = os.path.join(ROOT, "pft-fwaudit.sh")
EVAL = os.path.join(ROOT, "fwaudit_eval.py")
NOW = 1800000000
CLASSES = 10
SAMPLE = re.compile(r"^(pft_fwaudit_[a-z_]+)\{([^}]*)\} (-?[0-9]+)$")


def run(tmp, *args, role="validator", **extra):
    env = dict(os.environ)
    now = os.path.join(str(tmp), "now")
    with open(now, "w", encoding="utf-8") as fh:
        fh.write(str(NOW))
    env.update(
        {
            "PFT_FWA_CONF": os.path.join(str(tmp), "no-such.env"),
            "PFT_FWA_TEST": "1",
            "PFT_FWA_EVAL": EVAL,
            "PFT_FWA_NOW_FILE": now,
            "ROLE": role,
            "POLICY_DIR": os.path.join(ROOT, "policy"),
            "PEERS": os.path.join(FIX, f"{role}.peers"),
            "TEXTFILE_DIR": tdir(tmp),
        }
    )
    env.update(extra)
    r = subprocess.run(
        ["bash", SCRIPT, *args],
        check=False,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    return r.returncode, r.stdout, r.stderr


def tdir(tmp):
    d = os.path.join(str(tmp), "textfile")
    os.makedirs(d, exist_ok=True)
    return d


def samples(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("# "):
                continue
            m = SAMPLE.match(line)
            assert m, f"malformed sample: {line}"
            out[(m.group(1), m.group(2))] = int(m.group(3))
    return out


def evaluator_json(bundle, role):
    r = subprocess.run(
        [
            "python3",
            "-I",
            EVAL,
            "audit",
            bundle,
            os.path.join(ROOT, "policy", f"{role}.policy"),
            "--peers",
            os.path.join(FIX, f"{role}.peers"),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return json.loads(r.stdout)


def leftovers(tmp):
    return [n for n in os.listdir(tdir(tmp)) if n.startswith(".")]


@pytest.mark.parametrize(
    "role,bundle,rc,verdict",
    [
        ("validator", "validator.bundle", 0, 0),
        ("sentry", "sentry.bundle", 1, 1),
        ("sentry", "sentry-postfix.bundle", 0, 0),
    ],
)
def test_textfile_matches_evaluator_json(tmp_path, role, bundle, rc, verdict):
    b = os.path.join(FIX, bundle)
    got, out, err = run(tmp_path, "audit", "--textfile", "--bundle", b, role=role)
    assert got == rc, err
    assert out.rstrip().endswith("RESULT: " + ["PASS", "WARN", "FAIL"][verdict])  # human output still printed
    s = samples(os.path.join(tdir(tmp_path), f"pft_fwaudit_{role}.prom"))
    h = f'host="{role}"'
    assert s[("pft_fwaudit_up", h)] == 1
    assert s[("pft_fwaudit_last_run_timestamp_seconds", h)] == NOW
    assert s[("pft_fwaudit_verdict", h)] == verdict
    j = evaluator_json(b, role)
    for sev in ("fail", "warn", "info"):
        want = sum(1 for f in j["findings"] if f["severity"] == sev.upper())
        assert s[("pft_fwaudit_findings", f'{h},severity="{sev}"')] == want
    cls = {k[1]: v for k, v in s.items() if k[0] == "pft_fwaudit_finding_class"}
    assert len(cls) == CLASSES
    for f in j["findings"]:
        key = f'{h},class="{f["class"]}",severity="{f["severity"].lower()}"'
        assert cls[key] == sum(1 for g in j["findings"] if g["class"] == f["class"])
    assert sum(cls.values()) == len(j["findings"])
    exp = {k[1]: v for k, v in s.items() if k[0] == "pft_fwaudit_exposed"}
    assert len(exp) == 6
    assert sum(exp.values()) == sum(1 for e in j["exposure"] if e["state"] != "closed")
    assert all(k[1].startswith(h) for k in s)  # first label is always host (validate/pull rely on it)
    assert leftovers(tmp_path) == []


def test_sentry_prefix_capture_counts_its_stale_allow(tmp_path):
    run(tmp_path, "audit", "--textfile", "--bundle", os.path.join(FIX, "sentry.bundle"), role="sentry")
    s = samples(os.path.join(tdir(tmp_path), "pft_fwaudit_sentry.prom"))
    h = 'host="sentry"'
    assert s[("pft_fwaudit_finding_class", f'{h},class="stale-allow",severity="warn"')] == 1
    assert s[("pft_fwaudit_findings", f'{h},severity="warn"')] == 1
    assert s[("pft_fwaudit_findings", f'{h},severity="fail"')] == 0
    # control: the same counters are 0 after the fix
    run(tmp_path, "audit", "--textfile", "--bundle", os.path.join(FIX, "sentry-postfix.bundle"), role="sentry")
    s = samples(os.path.join(tdir(tmp_path), "pft_fwaudit_sentry.prom"))
    assert s[("pft_fwaudit_finding_class", f'{h},class="stale-allow",severity="warn"')] == 0
    assert s[("pft_fwaudit_findings", f'{h},severity="warn"')] == 0


def test_fail_finding_is_counted_and_exits_2(tmp_path):
    # an undeclared listener on 0.0.0.0:8080 plus a UFW allow for it on the INPUT path (as test_fwaudit does)
    text = in_section(load("validator"), "ss -H", lambda t: t + listen(8080) + "\n")
    text = insert_before(
        text,
        "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
        "-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT",
    )
    b = tmp_path / "fail.bundle"
    b.write_text(text, encoding="utf-8")
    j = evaluator_json(str(b), "validator")
    assert j["verdict"] == "FAIL" and any(f["class"] == "undeclared-exposure" for f in j["findings"])
    rc, _, err = run(tmp_path, "audit", "--textfile", "--bundle", str(b))
    assert rc == 2, err
    s = samples(os.path.join(tdir(tmp_path), "pft_fwaudit_validator.prom"))
    assert s[("pft_fwaudit_verdict", 'host="validator"')] == 2
    assert s[("pft_fwaudit_findings", 'host="validator",severity="fail"')] >= 1
    assert s[("pft_fwaudit_finding_class", 'host="validator",class="undeclared-exposure",severity="fail"')] >= 1


def only_up_zero(tmp, role="validator"):
    s = samples(os.path.join(tdir(tmp), f"pft_fwaudit_{role}.prom"))
    h = f'host="{role}"'
    assert s == {("pft_fwaudit_up", h): 0, ("pft_fwaudit_last_run_timestamp_seconds", h): NOW}
    assert leftovers(tmp) == []


def test_incomplete_bundle_writes_up_0_exit_4(tmp_path):
    text = load("validator")
    start, end = section_bounds(text, "ss -H")
    b = tmp_path / "cut.bundle"
    b.write_text(text[:start] + text[text.index("\n", end) + 1 :], encoding="utf-8")  # ss section removed
    rc, _, err = run(tmp_path, "audit", "--textfile", "--bundle", str(b))
    assert rc == 4 and "up 0" in err
    only_up_zero(tmp_path)


def test_missing_policy_writes_up_0_exit_3(tmp_path):
    rc, _, err = run(
        tmp_path,
        "audit",
        "--textfile",
        "--bundle",
        os.path.join(FIX, "validator.bundle"),
        POLICY_DIR=str(tmp_path / "nopolicy"),
    )
    assert rc == 3 and "no policy" in err
    only_up_zero(tmp_path)


def test_failed_capture_writes_up_0_exit_4(tmp_path):
    stub = tmp_path / "collect-fails"
    stub.write_text("#!/bin/sh\necho partial\nexit 1\n", encoding="utf-8")
    stub.chmod(0o755)
    rc, _, err = run(tmp_path, "audit", "--textfile", PFT_FWA_COLLECT=str(stub))
    assert rc == 4 and "capture failed" in err
    only_up_zero(tmp_path)


def test_control_live_capture_path_writes_up_1(tmp_path):
    stub = tmp_path / "collect-ok"
    stub.write_text(f"#!/bin/sh\nexec cat {os.path.join(FIX, 'validator.bundle')}\n", encoding="utf-8")
    stub.chmod(0o755)
    rc, _, err = run(tmp_path, "audit", "--textfile", PFT_FWA_COLLECT=str(stub))
    assert rc == 0, err
    assert (
        samples(os.path.join(tdir(tmp_path), "pft_fwaudit_validator.prom"))[("pft_fwaudit_up", 'host="validator"')] == 1
    )


def test_unwritable_textfile_dir_exit_4_no_file(tmp_path):
    rc, _, err = run(
        tmp_path,
        "audit",
        "--textfile",
        "--bundle",
        os.path.join(FIX, "validator.bundle"),
        TEXTFILE_DIR=str(tmp_path / "missing-dir"),
    )
    assert rc == 4 and "cannot write" in err
    assert not os.path.exists(tmp_path / "missing-dir")


def test_textfile_is_audit_only_and_host_label_checked(tmp_path):
    rc, _, err = run(tmp_path, "plan", "--textfile", "--bundle", os.path.join(FIX, "validator.bundle"))
    assert rc == 3 and "audit option" in err
    rc, _, err = run(
        tmp_path, "audit", "--textfile", "--bundle", os.path.join(FIX, "validator.bundle"), HOST_LABEL="Bad Label"
    )
    assert rc == 3 and "bad HOST_LABEL" in err
    assert os.listdir(tdir(tmp_path)) == []


def test_host_label_overrides_role(tmp_path):
    rc, _, _ = run(
        tmp_path, "audit", "--textfile", "--bundle", os.path.join(FIX, "validator.bundle"), HOST_LABEL="val2"
    )
    assert rc == 0
    assert os.listdir(tdir(tmp_path)) == ["pft_fwaudit_val2.prom"]


# ---------- validate / pull ----------
def good_textfile(tmp, role="sentry"):
    run(tmp, "audit", "--textfile", "--bundle", os.path.join(FIX, "sentry-postfix.bundle"), role=role)
    with open(os.path.join(tdir(tmp), f"pft_fwaudit_{role}.prom"), encoding="utf-8") as fh:
        return fh.read()


def validate(tmp, body, host="sentry"):
    p = tmp / "check.prom"
    p.write_text(body, encoding="utf-8")
    return run(tmp, "validate", str(p), host)


def test_validate_accepts_real_textfile(tmp_path):
    rc, out, _ = validate(tmp_path, good_textfile(tmp_path))
    assert (rc, out.strip()) == (0, "OK")


@pytest.mark.parametrize(
    "edit,reason",
    [
        (lambda t: t.replace('host="sentry"', 'host="validator"'), 'first label is not host="sentry"'),
        (lambda t: t + 'node_cpu_seconds_total{host="sentry"} 1\n', "not a pft_fwaudit_ sample"),
        (lambda t: t + 'pft_fwaudit_up{host="sentry"} one\n', "malformed sample"),
        (lambda t: t + 'pft_fwaudit_up{host="sentry",x="}"} 1\n', "malformed sample"),
        (lambda t: "\n".join(x for x in t.splitlines() if not x.startswith("pft_fwaudit_up{")), "no pft_fwaudit_up"),
        (
            lambda t: "\n".join(x for x in t.splitlines() if "last_run" not in x or x.startswith("#")),
            "no pft_fwaudit_last_run_timestamp_seconds",
        ),
        (lambda t: t + "#" * 70000 + "\n", "too big"),
    ],
)
def test_validate_rejects_with_reason(tmp_path, edit, reason):
    rc, out, _ = validate(tmp_path, edit(good_textfile(tmp_path)))
    assert rc == 1 and reason in out, out


def fake_ssh(tmp, remote_dir, fail=False):
    """PULL_SSH stand-in: runs the remote `cat -- PATH` locally against remote_dir (or fails like a dead link)."""
    p = tmp / "fake-ssh"
    body = "#!/bin/sh\nexit 255\n" if fail else '#!/bin/sh\n[ "$1" = cat ] && [ "$2" = -- ] || exit 9\nexec cat "$3"\n'
    p.write_text(body, encoding="utf-8")
    p.chmod(0o755)
    os.makedirs(remote_dir, exist_ok=True)
    return str(p)


def pull(tmp, ssh, remote, **extra):
    return run(tmp, "pull", HOST_LABEL="validator", PEER_LABEL="sentry", PULL_SSH=ssh, REMOTE_DIR=remote, **extra)


def slurp(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def previous_copy(tmp):
    p = os.path.join(tdir(tmp), "pft_fwaudit_sentry.prom")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write('pft_fwaudit_up{host="sentry"} 1\npft_fwaudit_last_run_timestamp_seconds{host="sentry"} 5\n')
    return p


def test_pull_copies_valid_peer_textfile(tmp_path):
    body = good_textfile(tmp_path)
    remote = str(tmp_path / "remote")
    ssh = fake_ssh(tmp_path, remote)
    with open(os.path.join(remote, "pft_fwaudit_sentry.prom"), "w", encoding="utf-8") as fh:
        fh.write(body)
    os.remove(os.path.join(tdir(tmp_path), "pft_fwaudit_sentry.prom"))
    rc, _, err = pull(tmp_path, ssh, remote)
    assert rc == 0, err
    with open(os.path.join(tdir(tmp_path), "pft_fwaudit_sentry.prom"), encoding="utf-8") as fh:
        assert fh.read() == body
    assert oct(os.stat(os.path.join(tdir(tmp_path), "pft_fwaudit_sentry.prom")).st_mode & 0o777) == "0o644"
    assert leftovers(tmp_path) == []


def test_pull_invalid_content_keeps_previous_copy_exit_2(tmp_path):
    remote = str(tmp_path / "remote")
    ssh = fake_ssh(tmp_path, remote)
    with open(os.path.join(remote, "pft_fwaudit_sentry.prom"), "w", encoding="utf-8") as fh:
        fh.write('pft_fwaudit_up{host="validator"} 1\n')  # spoofed host
    prev = previous_copy(tmp_path)
    before = slurp(prev)
    rc, _, err = pull(tmp_path, ssh, remote)
    assert rc == 2 and "validation failed" in err
    assert slurp(prev) == before
    assert leftovers(tmp_path) == []


def test_pull_fetch_failure_keeps_previous_copy_exit_1(tmp_path):
    remote = str(tmp_path / "remote")
    ssh = fake_ssh(tmp_path, remote, fail=True)
    prev = previous_copy(tmp_path)
    before = slurp(prev)
    rc, _, err = pull(tmp_path, ssh, remote)
    assert rc == 1 and "fetch of pft_fwaudit_sentry.prom failed" in err
    assert slurp(prev) == before
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize(
    "extra,reason",
    [
        ({"PULL_SSH": ""}, "PULL_SSH not set"),
        ({"PEER_LABEL": "validator"}, "refusing to pull over this host's own textfile"),
        ({"PEER_LABEL": "Bad"}, "bad PEER_LABEL"),
        ({"PULL_TIMEOUT": "0"}, "bad PULL_TIMEOUT"),
    ],
)
def test_pull_config_refusals_exit_3(tmp_path, extra, reason):
    remote = str(tmp_path / "remote")
    ssh = fake_ssh(tmp_path, remote)
    args = {"PULL_SSH": ssh, **extra}
    rc, _, err = run(
        tmp_path, "pull", HOST_LABEL="validator", PEER_LABEL=args.pop("PEER_LABEL", "sentry"), REMOTE_DIR=remote, **args
    )
    assert rc == 3 and reason in err, err
    assert os.listdir(tdir(tmp_path)) == []


def test_classes_subcommand_lists_every_severity_class():
    r = subprocess.run(["python3", "-I", EVAL, "classes"], check=True, capture_output=True, text=True)
    rows = [x.split() for x in r.stdout.splitlines()]
    assert len(rows) == CLASSES and {s for _, s in rows} == {"FAIL", "WARN", "INFO"}
