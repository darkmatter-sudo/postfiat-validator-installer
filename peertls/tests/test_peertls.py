"""pft-peertls tests: every check against a real weak `openssl s_server` on loopback (or, where OpenSSL cannot build
such a server, a synthetic edit of a real capture), each with the reason it must fail for, plus a clean control.

Run from the peertls folder: TMPDIR=$HOME/.cache python3 -m pytest -q tests
"""

import json
import os
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SH = REPO / "pft-peertls.sh"
EVAL = REPO / "peertls_eval.py"
GOOD = ["-cipher", "ECDHE+AESGCM:ECDHE+CHACHA20"]


def sh(*cmd, **kw):
    return subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=kw.pop("timeout", 120), **kw)


def make_cert(d, bits=2048, digest="sha256", days=30, name="leaf"):
    k, c = d / f"{name}.key", d / f"{name}.pem"
    r = sh(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        f"rsa:{bits}",
        "-nodes",
        "-keyout",
        str(k),
        "-out",
        str(c),
        "-days",
        str(days),
        "-subj",
        "/CN=fixture",
        f"-{digest}",
    )
    assert r.returncode == 0, r.stderr
    return k, c


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """openssl s_server on 127.0.0.1; stdin stays open (s_server exits on EOF)."""

    def __init__(self, d, extra, key=None, cert=None):
        self.port = free_port()
        k, c = (key, cert) if key else make_cert(d)
        self.cert = c
        self.p = subprocess.Popen(
            ["openssl", "s_server", "-accept", f"127.0.0.1:{self.port}", "-key", str(k), "-cert", str(c), *extra],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                if self.p.poll() is not None:
                    raise RuntimeError(f"s_server {extra} exited {self.p.returncode}") from None
                time.sleep(0.05)
        raise RuntimeError("s_server did not start")

    def close(self):
        try:
            os.killpg(self.p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.p.wait()


@pytest.fixture
def work(tmp_path):
    servers = []

    class W:
        dir = tmp_path

        def env(self, targets, **over):
            t = tmp_path / "targets"
            t.write_text("".join(f"{n} 127.0.0.1 {p} local -\n" for n, p in targets))
            e = dict(
                os.environ,
                PFT_PTLS_TEST="1",
                PFT_PTLS_EVAL=str(EVAL),
                PFT_PTLS_CONF="/nonexistent",
                TARGETS=str(t),
                STATE_DIR=str(tmp_path / "state"),
                WAIVERS=str(tmp_path / "waivers"),
                POLICY_DIR=str(REPO / "policy"),
                ROLE="validator",
                PACE_LOCAL="0",
                PROBE_TIMEOUT="5",
                TEXTFILE_DIR=str(tmp_path),
            )
            e.update(over)
            return e

        def server(self, extra, **kw):
            s = Server(tmp_path, extra, **kw)
            servers.append(s)
            return s

        def audit(self, port, *args, **over):
            r = sh(str(SH), "audit", "--json", *args, env=self.env([("fx", port)], **over))
            assert r.returncode in (0, 1, 2), r.stderr
            return r.returncode, json.loads(r.stdout)

    yield W()
    for s in servers:
        s.close()


def check(rep, cid, target="fx"):
    m = [c for c in rep["checks"] if c["id"] == cid and c["target"] == target]
    assert len(m) == 1, (cid, rep["checks"])
    return m[0]


# ---------- control: a clean server passes every check ----------
def test_clean_server_passes(work):
    s = work.server(GOOD)
    rc, rep = work.audit(s.port)
    bad = [c for c in rep["checks"] if c["result"] not in ("PASS", "INFO")]
    assert rc == 0 and rep["verdict"] == "PASS" and not bad, bad
    assert rep["handshakes"] == 21
    assert rep["targets"][0]["posture"]["protocols"] == ["tls1_2", "tls1_3"]
    assert rep["targets"][0]["posture"]["ciphers"] == ["ecdhe_aead"]
    # the self-check: the server really answered every probe (no error results)
    assert all(p["result"] != "error" for p in rep["targets"][0]["probes"].values())
    assert check(rep, "hs.client_reneg")["result"] == "PASS"
    assert check(rep, "hs.fallback_scsv")["reason"].endswith("refused (inappropriate_fallback)")


# ---------- weak live servers: each check fails for its own reason ----------
WEAK = [
    ("proto.tls1", ["-min_protocol", "TLSv1", "-cipher", "DEFAULT:@SECLEVEL=0"], "FAIL", "tls1 accepted"),
    ("proto.tls1_1", ["-min_protocol", "TLSv1.1", "-cipher", "DEFAULT:@SECLEVEL=0"], "FAIL", "tls1_1 accepted"),
    ("proto.tls1_3", ["-no_tls1_3", *GOOD], "WARN", "tls1_3 refused"),
    ("proto.tls1_2", ["-min_protocol", "TLSv1.3"], "FAIL", "tls1_2 refused"),
    ("cipher.kx_rsa", ["-cipher", "AES256-GCM-SHA384:ECDHE+AESGCM"], "WARN", "kx_rsa accepted as AES256-GCM-SHA384"),
    (
        "cipher.cbc_sha2",
        ["-cipher", "ECDHE-RSA-AES256-SHA384:ECDHE+AESGCM"],
        "WARN",
        "cbc_sha2 accepted as ECDHE-RSA-AES256-SHA384",
    ),
    (
        "cipher.cbc_sha1",
        ["-cipher", "ECDHE-RSA-AES128-SHA:ECDHE+AESGCM:@SECLEVEL=0"],
        "FAIL",
        "cbc_sha1 accepted as ECDHE-RSA-AES128-SHA",
    ),
    ("cipher.null", ["-cipher", "NULL-SHA256:ECDHE+AESGCM:@SECLEVEL=0"], "FAIL", "null accepted as NULL-SHA256"),
    (
        "cipher.anull",
        ["-cipher", "ADH-AES256-GCM-SHA384:ECDHE+AESGCM:@SECLEVEL=0"],
        "FAIL",
        "anull accepted as ADH-AES256-GCM-SHA384",
    ),
    ("cipher.ecdhe_aead", ["-cipher", "DHE-RSA-AES256-GCM-SHA384"], "FAIL", "ecdhe_aead refused"),
    ("hs.client_reneg", ["-client_renegotiation", *GOOD], "FAIL", "client-initiated renegotiation accepted"),
]


@pytest.mark.parametrize(("cid", "extra", "result", "reason"), WEAK, ids=[w[0] for w in WEAK])
def test_weak_server_fails_for_reason(work, cid, extra, result, reason):
    s = work.server(extra)
    rc, rep = work.audit(s.port)
    c = check(rep, cid)
    assert c["result"] == result and c["reason"].startswith(reason), c
    assert rc == {"WARN": 1, "FAIL": 2}[rep["verdict"]] and rep["verdict"] in ("WARN", "FAIL")


def test_weak_dh_group(work):
    dh = work.dir / "dh1024.pem"
    assert sh("openssl", "dhparam", "-out", str(dh), "1024").returncode == 0
    s = work.server(["-cipher", "DHE-RSA-AES256-GCM-SHA384:ECDHE+AESGCM:@SECLEVEL=0", "-dhparam", str(dh)])
    _, rep = work.audit(s.port)
    c = check(rep, "kx.dh_bits")
    assert c["result"] == "FAIL" and c["reason"] == "DHE group 1024 bits (min 2048)", c


def test_weak_key(work):
    k, c = make_cert(work.dir, bits=1024, name="k1024")
    s = work.server([*GOOD[:1], GOOD[1] + ":@SECLEVEL=0"], key=k, cert=c)
    _, rep = work.audit(s.port)
    ck = check(rep, "cert.key")
    assert ck["result"] == "FAIL" and ck["reason"] == "rsa 1024 bits (min 2048)", ck


def test_sha1_signature(work):
    k, c = make_cert(work.dir, digest="sha1", name="sha1")
    s = work.server([*GOOD[:1], GOOD[1] + ":@SECLEVEL=0"], key=k, cert=c)
    _, rep = work.audit(s.port)
    ck = check(rep, "cert.sig_hash")
    assert ck["result"] == "FAIL" and ck["reason"].startswith("signature sha1WithRSAEncryption (hash sha1;"), ck


def not_after(pem):
    r = sh("openssl", "x509", "-noout", "-enddate", "-startdate", "-in", str(pem))
    end = re.search(r"notAfter=(.+)", r.stdout).group(1)
    start = re.search(r"notBefore=(.+)", r.stdout).group(1)
    conv = lambda s: int(sh("date", "-u", "-d", s, "+%s").stdout)
    return conv(start), conv(end)


def test_expired_and_not_yet_valid(work):
    s = work.server(GOOD)
    nb, na = not_after(s.cert)
    _, rep = work.audit(s.port, "--no-state", PFT_PTLS_NOW=str(na + 2 * 86400))
    c = check(rep, "cert.validity")
    assert c["result"] == "FAIL" and c["reason"] == "-2 days left (min 14)", c
    _, rep = work.audit(s.port, "--no-state", PFT_PTLS_NOW=str(na - 10 * 86400))
    c = check(rep, "cert.validity")
    assert c["result"] == "FAIL" and c["reason"] == "10 days left (min 14)", c
    _, rep = work.audit(s.port, "--no-state", PFT_PTLS_NOW=str(nb - 3600))
    c = check(rep, "cert.validity")
    assert c["result"] == "FAIL" and c["reason"] == "not yet valid", c
    # control: 15 days left passes
    _, rep = work.audit(s.port, "--no-state", PFT_PTLS_NOW=str(na - 15 * 86400))
    assert check(rep, "cert.validity")["result"] == "PASS"


def test_unreachable_target(work):
    _, rep = work.audit(free_port())
    c = check(rep, "probe.reachable")
    assert c["result"] == "FAIL" and c["reason"].startswith("probes failed to connect: cipher."), c
    assert rep["verdict"] == "FAIL"


# ---------- synthetic edits of a real capture (OpenSSL 3 cannot serve these) ----------
@pytest.fixture
def good_bundle(work):
    s = work.server(GOOD)
    b = work.dir / "good.bundle"
    r = sh(str(SH), "collect", "--out", str(b), env=work.env([("fx", s.port)]))
    assert r.returncode == 0, r.stderr
    return b


def section(text, pid):
    a = text.index(f"### probe {pid} offer=")
    return a, text.index("### rc=", a)


def edited(work, b, pid, old, new, name):
    t = b.read_text()
    a, z = section(t, pid)
    body = t[a:z]
    assert re.search(old, body, re.MULTILINE), (pid, old)
    out = work.dir / name
    out.write_text(t[:a] + re.sub(old, new, body, count=1, flags=re.MULTILINE) + t[z:])
    return out


def grade(work, b):
    r = sh(str(SH), "audit", "--json", "--bundle", str(b), env=work.env([("fx", 1)]))
    assert r.returncode in (0, 1, 2), r.stderr
    return json.loads(r.stdout)


SYNTH = [
    (
        "hs.compression",
        "proto.tls1_2",
        r"^Compression: NONE",
        "Compression: zlib compression",
        "FAIL",
        "compression zlib",
    ),
    (
        "hs.secure_reneg",
        "proto.tls1_2",
        r"^Secure Renegotiation IS supported",
        "Secure Renegotiation IS NOT supported",
        "WARN",
        "RFC 5746 renegotiation_info missing",
    ),
    (
        "hs.ems",
        "proto.tls1_2",
        r"Extended master secret: yes",
        "Extended master secret: no",
        "WARN",
        "extended master secret no",
    ),
    (
        "hs.ticket_lifetime",
        "proto.tls1_2",
        r"TLS session ticket lifetime hint: [0-9]+",
        "TLS session ticket lifetime hint: 172800",
        "WARN",
        "ticket lifetime hint 172800 s (max 86400)",
    ),
    (
        "hs.fallback_scsv",
        "hs.fallback",
        r"^.*SSL alert number 86\n(?:.*\n)*?New, \(NONE\), Cipher is \(NONE\)$",
        "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384",
        "FAIL",
        "TLS 1.2 + FALLBACK_SCSV accepted",
    ),
]


@pytest.mark.parametrize(("cid", "pid", "old", "new", "result", "reason"), SYNTH, ids=[s[0] for s in SYNTH])
def test_synthetic_fails_for_reason(work, good_bundle, cid, pid, old, new, result, reason):
    base = grade(work, good_bundle)
    assert check(base, cid)["result"] == "PASS"  # control: the unedited capture passes this check
    rep = grade(work, edited(work, good_bundle, pid, old, new, cid + ".bundle"))
    c = check(rep, cid)
    assert c["result"] == result and c["reason"].startswith(reason), c


def replace_body(t, pid, body):
    a, z = section(t, pid)
    head = t.index("\n", a) + 1
    return t[:head] + body + t[z:]


def test_one_failed_probe_fails_reachable(work, good_bundle):
    # the certificate is still captured: only the failed probe can turn probe.reachable into FAIL
    assert check(grade(work, good_bundle), "probe.reachable")["result"] == "PASS"
    b = work.dir / "one-error.bundle"
    b.write_text(replace_body(good_bundle.read_text(), "cipher.ecdhe_aead", "connect:errno=111\n"))
    c = check(grade(work, b), "probe.reachable")
    assert c["result"] == "FAIL" and c["reason"] == "probes failed to connect: cipher.ecdhe_aead", c


def test_tls13_without_any_suite_fails(work, good_bundle):
    # TLS 1.3 itself accepted, every single-suite TLS 1.3 probe refused: policy `cipher tls13_suites require`
    base = grade(work, good_bundle)
    assert check(base, "cipher.tls13_suites")["result"] == "PASS"
    t = good_bundle.read_text()
    pids = re.findall(r"^### probe (tls13\.\S+) offer=", t, re.MULTILINE)
    assert len(pids) >= 2, pids
    for pid in pids:
        t = replace_body(t, pid, "SSL alert number 40\nNew, (NONE), Cipher is (NONE)\n")
    b = work.dir / "no-tls13-suite.bundle"
    b.write_text(t)
    rep = grade(work, b)
    assert check(rep, "proto.tls1_3")["result"] == "PASS"
    c = check(rep, "cipher.tls13_suites")
    assert c["result"] == "FAIL" and c["reason"] == "TLS 1.3 suites accepted: none", c


def test_alert_only_answer_is_refused(work, good_bundle):
    # a client that prints only the server's alert (no `New, (NONE)` line) still reads as refused, not as an error
    t = replace_body(good_bundle.read_text(), "proto.tls1", "SSL alert number 70\n")
    b = work.dir / "alert-only.bundle"
    b.write_text(t)
    rep = grade(work, b)
    c = check(rep, "proto.tls1")
    assert c["result"] == "PASS" and c["reason"] == "tls1 refused (protocol_version); policy forbid", c
    assert check(rep, "probe.reachable")["result"] == "PASS"


def test_waiver_for_another_target_does_not_apply(work, good_bundle):
    b = edited(
        work,
        good_bundle,
        "proto.tls1_2",
        r"^Secure Renegotiation IS supported",
        "Secure Renegotiation IS NOT supported",
        "noreneg.bundle",
    )
    (work.dir / "waivers").write_text("hs.secure_reneg other until=2099-01-01 for a different target\n")
    c = check(grade(work, b), "hs.secure_reneg")
    assert c["result"] == "WARN", c
    # control: the same waiver naming this target (and `*`) applies
    for tgt in ("fx", "*"):
        (work.dir / "waivers").write_text(f"hs.secure_reneg {tgt} until=2099-01-01 this target\n")
        c = check(grade(work, b), "hs.secure_reneg")
        assert c["result"] == "WAIVED" and c["waived_from"] == "WARN", (tgt, c)


# ---------- drift ----------
def test_drift_posture_and_cert(work):
    k1, c1 = make_cert(work.dir, name="a")
    s = work.server(GOOD, key=k1, cert=c1)
    _, first = work.audit(s.port)
    assert check(first, "drift.posture")["reason"] == "first run (no state)"
    _, same = work.audit(s.port)
    assert check(same, "drift.posture")["result"] == "PASS" and check(same, "drift.cert")["result"] == "PASS"
    s.close()
    k2, c2 = make_cert(work.dir, name="b")
    s2 = Server(work.dir, ["-cipher", "AES256-GCM-SHA384:ECDHE+AESGCM"], key=k2, cert=c2)
    try:
        port = s2.port
        _, rep = work.audit(port)
    finally:
        s2.close()
    # same target name on a new port: the state key is the target name, so this is the same target
    d = check(rep, "drift.posture")
    assert d["result"] == "WARN" and d["reason"] == "changed: ciphers", d
    c = check(rep, "drift.cert")
    assert c["result"] == "WARN" and c["reason"] == "certificate changed without a node restart", c
    assert {x["item"] for x in rep["drift"]} == {"ciphers", "cert"}


def test_cert_change_with_restart_is_info(work, tmp_path):
    stub = tmp_path / "docker"
    started = tmp_path / "started"
    stub.write_text('#!/bin/sh\ncat "$(dirname "$0")/started"\n')
    stub.chmod(0o755)
    targets = lambda port: [("fx", port)]
    k1, c1 = make_cert(work.dir, name="r1")
    s = work.server(GOOD, key=k1, cert=c1)
    e = work.env(targets(s.port), PFT_PTLS_DOCKER=str(stub))
    (tmp_path / "targets").write_text(f"fx 127.0.0.1 {s.port} local postfiatd\n")
    started.write_text("2026-11-14T10:00:00.000000000Z\n")
    assert sh(str(SH), "audit", "--json", env=e).returncode == 0
    s.close()
    k2, c2 = make_cert(work.dir, name="r2")
    s2 = work.server(GOOD, key=k2, cert=c2)
    (tmp_path / "targets").write_text(f"fx 127.0.0.1 {s2.port} local postfiatd\n")
    started.write_text("2026-11-14T11:00:00.000000000Z\n")
    r = sh(str(SH), "audit", "--json", env=e)
    rep = json.loads(r.stdout)
    c = check(rep, "drift.cert")
    assert (
        r.returncode == 0
        and c["result"] == "INFO"
        and c["reason"].startswith("certificate changed with a node restart")
    )


# ---------- guards: what is probed and how much ----------
def logged_openssl(tmp_path):
    log = tmp_path / "calls"
    stub = tmp_path / "openssl"
    stub.write_text(f'#!/bin/sh\necho "$*" >> {log}\nexit 1\n')
    stub.chmod(0o755)
    return str(stub), log


@pytest.mark.parametrize(
    ("line", "why"),
    [
        ("a 10.0.0.1 2559 local -", "local target a must be loopback"),
        ("a 127.0.0.1 2559 remote -", "remote target a is loopback"),
        ("a 192.0.2.1 22 remote -", "a port 22 is not the peer port 2559"),
        ("a example.org 2559 remote -", "address must be a literal IP"),
        ("a 127.0.0.1 2559 elsewhere -", "scope must be local or remote"),
        ("A 127.0.0.1 2559 local -", "bad name A"),
        ("a 127.0.0.1 2559 local - extra", "too many fields"),
    ],
)
def test_target_guards_refuse_before_any_probe(work, tmp_path, line, why):
    stub, log = logged_openssl(tmp_path)
    e = work.env([], PFT_PTLS_OPENSSL=stub)
    Path(e["TARGETS"]).write_text(line + "\n")
    r = sh(str(SH), "collect", "--target", "a", env=e)
    assert r.returncode == 3 and why in r.stderr, r.stderr
    assert not log.exists()  # no connection was attempted


def test_handshake_cap_refuses_before_any_probe(work, tmp_path):
    stub, log = logged_openssl(tmp_path)
    e = work.env([("a", 2559), ("b", 2559)], PFT_PTLS_OPENSSL=stub)
    r = sh(str(SH), "plan", env=e)
    assert r.returncode == 1 and "total: 42 (max 40)" in r.stdout, r.stdout
    r = sh(str(SH), "collect", env=e)
    assert r.returncode == 3 and "exceeds MAX_HANDSHAKES (40)" in r.stderr, r.stderr
    assert not log.exists()
    r = sh(str(SH), "collect", env=dict(e, MAX_HANDSHAKES="41"))
    assert r.returncode == 3 and "MAX_HANDSHAKES must be an integer <= 40" in r.stderr
    # control: one target fits
    Path(e["TARGETS"]).write_text("a 127.0.0.1 2559 local -\n")
    assert sh(str(SH), "plan", env=e).returncode == 0


def test_remote_pace_floor(work):
    e = work.env([("a", 2559)], PACE_REMOTE="2")
    r = sh(str(SH), "plan", env=e)
    assert r.returncode == 3 and "PACE_REMOTE must be >= 5 s" in r.stderr
    assert sh(str(SH), "plan", env=dict(e, PACE_REMOTE="5")).returncode == 0


def test_remote_only_with_explicit_target(work, tmp_path):
    e = work.env([])
    Path(e["TARGETS"]).write_text("peer 192.0.2.7 2559 remote -\n")
    r = sh(str(SH), "plan", env=e)
    assert r.returncode == 3 and "no target of scope local" in r.stderr
    r = sh(str(SH), "plan", "--target", "peer", env=e)
    assert r.returncode == 0 and "targets: peer" in r.stdout


def test_non_root_owned_targets_refused(work, tmp_path):
    e = work.env([("a", 2559)])
    e.pop("PFT_PTLS_TEST")
    r = sh(str(SH), "plan", env=e)
    # as a normal user the root check refuses first; as root the ownership check would
    assert r.returncode == 3 and ("must run as root" in r.stderr or "not root-owned" in r.stderr)


# ---------- waivers and the public view ----------
def test_waiver_hides_finding_in_public_view(work):
    s = work.server(["-cipher", "AES256-GCM-SHA384:ECDHE+AESGCM"])
    _, full = work.audit(s.port, "--no-state")
    assert check(full, "cipher.kx_rsa")["result"] == "WARN" and full["verdict"] == "WARN"
    (work.dir / "waivers").write_text("cipher.kx_rsa fx until=2099-01-01 upstream default, reported privately\n")
    rc, waived = work.audit(s.port, "--no-state")
    assert rc == 0 and waived["verdict"] == "PASS" and check(waived, "cipher.kx_rsa")["result"] == "WAIVED"
    rc, pub = work.audit(s.port, "--no-state", "--public")
    assert rc == 0 and pub["public"] is True and pub["counts"]["WAIVED"] == 1
    assert not [c for c in pub["checks"] if c["id"] == "cipher.kx_rsa"]
    assert pub["targets"][0]["probes"]["cipher.kx_rsa"] == {"result": "private"}
    assert "kx_rsa" not in pub["targets"][0]["posture"]["ciphers"]
    assert not re.search(r'"AES256-GCM-SHA384"', json.dumps(pub))  # the waived suite's name appears nowhere
    assert re.search(r'"AES256-GCM-SHA384"', json.dumps(full))  # control: it is in the full report
    # an expired waiver no longer applies and is counted
    (work.dir / "waivers").write_text("cipher.kx_rsa fx until=2020-01-01 old\n")
    rc, exp = work.audit(s.port, "--no-state")
    assert rc == 1 and exp["expired_waivers"] == 1 and check(exp, "cipher.kx_rsa")["result"] == "WARN"


# ---------- offline reconstruction, crosscheck, textfile ----------
def test_render_rebuilds_report_byte_identical(work):
    s = work.server(GOOD)
    e = work.env([("fx", s.port)], PFT_PTLS_NOW="1794700000")
    b = work.dir / "b"
    assert sh(str(SH), "collect", "--out", str(b), env=e).returncode == 0
    human = sh(str(SH), "audit", "--bundle", str(b), env=e)
    js = sh(str(SH), "audit", "--bundle", str(b), "--json", env=e)
    (work.dir / "r.json").write_text(js.stdout)
    again = sh(str(SH), "render", str(work.dir / "r.json"), env=e)
    assert human.returncode == js.returncode == 0 and again.returncode == 0
    assert again.stdout == human.stdout and human.stdout.startswith("pft-peertls audit - validator - ")


def test_crosscheck(work):
    s = work.server(GOOD)
    _, own = work.audit(s.port, "--no-state")
    remote = json.loads(json.dumps(own))
    remote["host"], remote["targets"][0]["scope"] = "other", "remote"
    a, b = work.dir / "a.json", work.dir / "b.json"
    a.write_text(json.dumps(own))
    b.write_text(json.dumps(remote))
    e = work.env([])
    r = sh(str(SH), "crosscheck", str(a), str(b), env=e)
    assert r.returncode == 0 and r.stdout.strip().endswith("RESULT: PASS"), r.stdout
    remote["targets"][0]["cert"]["fp_sha256"] = "0" * 16
    remote["targets"][0]["posture"]["ciphers"] = ["ecdhe_aead", "kx_rsa"]
    b.write_text(json.dumps(remote))
    r = sh(str(SH), "crosscheck", str(a), str(b), env=e)
    assert r.returncode == 2 and "FAIL other->fx cert sha256" in r.stdout and "FAIL other->fx ciphers" in r.stdout


def test_textfile_metrics_and_validate(work):
    s = work.server(GOOD)
    e = work.env([("fx", s.port)])
    r = sh(str(SH), "audit", "--textfile", env=e)
    assert r.returncode == 0, r.stderr
    tf = work.dir / "pft_peertls_validator.prom"
    body = tf.read_text()
    assert 'pft_peertls_up{host="validator"} 1' in body and 'pft_peertls_verdict{host="validator"} 0' in body
    assert 'pft_peertls_check{host="validator",target="fx",check="cipher.kx_rsa"} 0' in body
    assert 'pft_peertls_drift{host="validator",target="fx"} 0' in body
    assert not re.search(r'[{,](job|instance)="', body)
    assert len(body) < 65536
    v = sh(str(SH), "validate", str(tf), "validator")
    assert v.returncode == 0 and v.stdout.strip() == "OK"
    v = sh(str(SH), "validate", str(tf), "sentry")
    assert v.returncode == 1 and 'first label is not host="sentry"' in v.stdout
    bad = work.dir / "bad.prom"
    bad.write_text(body.replace("pft_peertls_up", "node_up"))
    v = sh(str(SH), "validate", str(bad), "validator")
    assert v.returncode == 1 and "not a pft_peertls_ sample" in v.stdout


def test_grading_error_writes_up_zero(work, tmp_path):
    s = work.server(GOOD)
    pol = tmp_path / "nopol"
    pol.mkdir()
    r = sh(str(SH), "audit", "--textfile", env=work.env([("fx", s.port)], POLICY_DIR=str(pol)))
    body = (work.dir / "pft_peertls_validator.prom").read_text()
    assert r.returncode == 3 and 'pft_peertls_up{host="validator"} 0' in body and "pft_peertls_verdict" not in body
    # an unreachable port is graded (up 1) and fails probe.reachable
    r = sh(str(SH), "audit", "--textfile", env=work.env([("fx", free_port())]))
    body = (work.dir / "pft_peertls_validator.prom").read_text()
    assert r.returncode == 2 and 'pft_peertls_up{host="validator"} 1' in body
    assert 'check="probe.reachable"} 2' in body


# ---------- policy and bundle errors ----------
@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("protocol tls1 maybe\n", "want `protocol NAME forbid|require|allow`"),
        ("cipher rot13 forbid\n", "unknown cipher rot13"),
        ("bogus 1\n", "unknown key bogus"),
        ("min_rsa_bits x\n", "min_rsa_bits wants one integer"),
        ("severity cert.key INFO\n", "want `severity CHECK FAIL|WARN`"),
    ],
)
def test_bad_policy(work, good_bundle, text, why):
    pol = work.dir / "pol"
    pol.mkdir(exist_ok=True)
    (pol / "validator.policy").write_text((REPO / "policy" / "validator.policy").read_text() + text)
    r = sh(str(SH), "audit", "--bundle", str(good_bundle), env=dict(work.env([]), POLICY_DIR=str(pol)))
    assert r.returncode == 3 and why in r.stderr, r.stderr


def test_truncated_bundle(work, good_bundle):
    t = good_bundle.read_text()
    cut = work.dir / "cut"
    cut.write_text(t[: t.index("### probe hs.reneg")])
    r = sh(str(SH), "audit", "--bundle", str(cut), env=work.env([]))
    assert r.returncode == 4 and "no end line" in r.stderr


def test_bundle_over_handshake_cap(work, good_bundle):
    t = good_bundle.read_text()
    m = re.search(r"^### end handshakes=([0-9]+)$", t, re.MULTILINE)
    assert m and int(m.group(1)) <= 40, m
    over = work.dir / "over"
    over.write_text(t[: m.start()] + "### end handshakes=41" + t[m.end() :])
    r = sh(str(SH), "audit", "--bundle", str(over), env=work.env([]))
    assert r.returncode == 4 and "bundle used 41 handshakes (> 40)" in r.stderr, r.stderr
    at = work.dir / "at-cap"
    at.write_text(t[: m.start()] + "### end handshakes=40" + t[m.end() :])
    assert sh(str(SH), "audit", "--bundle", str(at), env=work.env([])).returncode in (0, 1, 2)


def test_bundle_missing_probe(work, good_bundle):
    t = good_bundle.read_text()
    a, z = section(t, "cipher.kx_rsa")
    z = t.index("\n", z) + 1  # through the probe's rc line
    gone = work.dir / "gone"
    gone.write_text(t[:a] + t[z:])
    assert "### probe cipher.kx_rsa " not in gone.read_text()
    r = sh(str(SH), "audit", "--bundle", str(gone), env=work.env([]))
    assert r.returncode == 4 and "target fx: probe cipher.kx_rsa missing" in r.stderr, r.stderr


def test_root_check_refuses_non_root(work):
    if os.geteuid() == 0:
        pytest.skip("runs as root")
    e = work.env([("a", 2559)])
    e.pop("PFT_PTLS_TEST")
    r = sh(str(SH), "plan", env=e)
    assert r.returncode == 3 and "must run as root" in r.stderr, r.stderr


def test_validate_size_cap(work):
    s = work.server(GOOD)
    assert sh(str(SH), "audit", "--textfile", env=work.env([("fx", s.port)])).returncode == 0
    tf = work.dir / "pft_peertls_validator.prom"
    n = tf.stat().st_size
    v = sh(str(SH), "validate", str(tf), "validator", env=dict(os.environ, MAX_BYTES=str(n - 1)))
    assert v.returncode == 1 and v.stdout.strip() == f"INVALID: too big ({n} bytes)", v.stdout
    v = sh(str(SH), "validate", str(tf), "validator", env=dict(os.environ, MAX_BYTES=str(n)))
    assert v.returncode == 0 and v.stdout.strip() == "OK", v.stdout


def test_shipped_policies_parse_and_match():
    v = (REPO / "policy" / "validator.policy").read_text().splitlines()[2:]
    s = (REPO / "policy" / "sentry.policy").read_text().splitlines()[2:]
    assert v == s  # same build behind both ports: the rules may only differ in the header
    r = sh("python3", "-I", str(EVAL), "checks")
    assert r.returncode == 0 and len(r.stdout.splitlines()) == 28
