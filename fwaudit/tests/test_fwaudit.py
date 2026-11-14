"""Unit tests for fwaudit_eval.py over redacted real captures of both hosts.

Every finding class has a test that injects exactly that fault into an otherwise unchanged capture and asserts the
class (and its reason), plus a control that must NOT raise it.
"""

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import fwaudit_eval as fe

FIX = os.path.join(HERE, "fixtures")
POL = os.path.join(os.path.dirname(HERE), "policy")


def load(host):
    with open(os.path.join(FIX, f"{host}.bundle"), encoding="utf-8") as fh:
        return fh.read()


def policy(host):
    return fe.read_policy(os.path.join(POL, f"{host}.policy"), fe.read_peers(os.path.join(FIX, f"{host}.peers")))


def run(host, text=None):
    return fe.audit(fe.read_bundle(text if text is not None else load(host)), policy(host))


def classes(res):
    return sorted((f["class"], f.get("family"), f.get("port")) for f in res["findings"])


def insert_after(text, anchor, line):
    assert text.count(anchor) >= 1, anchor
    i = text.index(anchor) + len(anchor)
    j = text.index("\n", i)
    return text[: j + 1] + line + "\n" + text[j + 1 :]


def insert_before(text, anchor, line):
    i = text.index(anchor)
    return text[:i] + line + "\n" + text[i:]


def section_bounds(text, stem):
    i = text.index("### $ ")
    while stem not in text[i : text.index("\n", i)]:
        i = text.index("### $ ", i + 1)
    return i, text.index("### rc=", i)


def in_section(text, stem, fn):
    a, b = section_bounds(text, stem)
    return text[:a] + fn(text[a:b]) + text[b:]


def listen(port, addr="0.0.0.0", proc="python3"):
    return f'tcp LISTEN 0      5      {addr}:{port}  0.0.0.0:* users:(("{proc}",pid=4242,fd=3))'


# ------------------------------------------------------------- baselines (real captures)
def test_validator_capture_passes_with_exact_table():
    res = run("validator")
    assert res["verdict"] == "PASS"
    rows = [(e["family"], e["port"], e["state"], e["paths"]) for e in res["exposure"]]
    assert rows == [
        ("v4", 22, "open", ["input"]),
        ("v4", 2559, "limited", ["docker-forward->2559"]),
        ("v4", 19532, "sources", ["input"]),
        ("v6", 22, "open", ["input"]),
        ("v6", 2559, "limited", ["input"]),
    ]
    assert classes(res) == [("ufw-rule-bypassed", "v4", 2559)]


def test_sentry_capture_before_fix_reports_stale_v6_allow():
    # real capture 2026-11-14T00:14Z: ufw allowed 2559/tcp on IPv6 too, nginx listens on IPv4 only
    res = run("sentry")
    assert res["verdict"] == "WARN"
    assert classes(res) == [("stale-allow", "v6", 2559)]
    assert [e["owners"] for e in res["exposure"] if e["port"] == 2559] == [["nginx"]]


def test_sentry_capture_after_fix_passes():
    # real capture 2026-11-14T00:46Z after `ufw delete` of the v6 2559 rule
    res = run("sentry", load("sentry-postfix"))
    assert res["verdict"] == "PASS" and res["findings"] == []
    assert [(e["family"], e["port"]) for e in res["exposure"]] == [("v4", 22), ("v4", 2559), ("v4", 19532), ("v6", 22)]


def test_declared_family_without_listener_warns():
    peer = next(r for r in policy("sentry") if r["port"] == 2559)
    p = [*policy("sentry"), dict(peer, family="v6", line=99)]
    res = fe.audit(fe.read_bundle(load("sentry-postfix")), p)
    assert [(f["class"], f["family"], f["port"]) for f in res["findings"]] == [("declared-unreachable", "v6", 2559)]


def test_sentry_loopback_publish_is_not_exposure():
    res = run("sentry")
    assert all(e["port"] != 2560 for e in res["exposure"])


# ------------------------------------------------------------- undeclared exposure
def test_undeclared_input_listener_allowed_by_ufw_fails():
    t = in_section(load("validator"), "ss -H", lambda s: s + listen(8080) + "\n")
    t = insert_before(
        t,
        "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
        "-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT",
    )
    res = run("validator", t)
    assert res["verdict"] == "FAIL"
    assert ("undeclared-exposure", "v4", 8080) in classes(res)


def test_control_listener_without_allow_is_closed():
    t = in_section(load("validator"), "ss -H", lambda s: s + listen(8080) + "\n")
    res = run("validator", t)
    assert res["verdict"] == "PASS"
    assert all(e["port"] != 8080 for e in res["exposure"])


def test_accept_inserted_before_ufw_chains_fails():
    t = in_section(load("validator"), "ss -H", lambda s: s + listen(8082) + "\n")
    t = insert_before(t, "-A INPUT -j ufw-before-logging-input", "-A INPUT -p tcp -m tcp --dport 8082 -j ACCEPT")
    res = run("validator", t)
    assert ("undeclared-exposure", "v4", 8082) in classes(res)


def test_docker_published_port_bypasses_ufw_and_fails():
    t = load("validator")
    t = insert_before(
        t,
        "-A DOCKER ! -i br-8cedebf23a84 -o br-8cedebf23a84 -j DROP",
        "-A DOCKER -d 172.18.0.2/32 ! -i br-8cedebf23a84 -o br-8cedebf23a84 -p tcp -m tcp --dport 8081 -j ACCEPT",
    )
    t = insert_after(
        t,
        "--dport 50051 -j DNAT --to-destination 172.18.0.2:50051",
        "-A DOCKER ! -i br-8cedebf23a84 -p tcp -m tcp --dport 8081 -j DNAT --to-destination 172.18.0.2:8081",
    )
    res = run("validator", t)
    hit = [f for f in res["findings"] if f["class"] == "undeclared-exposure"]
    assert [(f["port"], f["paths"]) for f in hit] == [(8081, ["docker-forward->8081"])]


def test_control_loopback_published_port_is_not_exposed():
    t = insert_after(
        load("validator"),
        "--dport 50051 -j DNAT --to-destination 172.18.0.2:50051",
        "-A DOCKER -d 127.0.0.1/32 ! -i br-8cedebf23a84 -p tcp -m tcp --dport 8081 -j DNAT "
        "--to-destination 172.18.0.2:8081",
    )
    t = insert_before(
        t,
        "-A DOCKER ! -i br-8cedebf23a84 -o br-8cedebf23a84 -j DROP",
        "-A DOCKER -d 172.18.0.2/32 ! -i br-8cedebf23a84 -o br-8cedebf23a84 -p tcp -m tcp --dport 8081 -j ACCEPT",
    )
    res = run("validator", t)
    assert all(e["port"] != 8081 for e in res["exposure"])


def test_v6_allow_for_v4_only_port_fails_parity():
    t = insert_after(
        load("validator"),
        "-A ufw6-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
        "-A ufw6-user-input -p tcp -m tcp --dport 19532 -j ACCEPT",
    )
    res = run("validator", t)
    assert ("undeclared-exposure", "v6", 19532) in classes(res)
    assert ("undeclared-exposure", "v4", 19532) not in classes(res)


# ------------------------------------------------------------- limits and sources
def drop_docker_user_limits(t):
    for ln in (
        (
            "-A DOCKER-USER -p tcp -m tcp --dport 2559 -m connlimit --connlimit-above 50 --connlimit-mask 32 "
            "--connlimit-saddr -j DROP\n"
        ),
        (
            "-A DOCKER-USER -p tcp -m tcp --dport 2559 -m state --state NEW -m limit --limit 100/sec "
            "--limit-burst 50 -j ACCEPT\n"
        ),
        "-A DOCKER-USER -p tcp -m tcp --dport 2559 -m state --state NEW -j DROP\n",
    ):
        assert ln in t
        t = t.replace(ln, "", 1)
    return t


def test_missing_docker_user_limit_fails():
    res = run("validator", drop_docker_user_limits(load("validator")))
    assert ("missing-limit", "v4", 2559) in classes(res)
    assert ("missing-limit", "v6", 2559) not in classes(res)  # v6 still goes through ufw6 LIMIT
    assert res["verdict"] == "FAIL"


def test_missing_ufw_limit_on_input_path_fails():
    t = load("sentry")
    for ln in t.splitlines():
        if ln.startswith("-A ufw-user-input -p tcp -m tcp --dport 2559") and "recent --update" in ln:
            t = t.replace(ln + "\n", "", 1)
    res = run("sentry", t)
    assert ("missing-limit", "v4", 2559) in classes(res)


def test_control_limits_present_no_missing_limit():
    assert not [f for f in run("validator")["findings"] if f["class"] == "missing-limit"]
    assert not [f for f in run("sentry")["findings"] if f["class"] == "missing-limit"]


def test_source_restriction_removed_fails():
    t = load("validator").replace(
        "-A ufw-user-input -s 203.0.113.1/32 -p tcp -m tcp --dport 19532",
        "-A ufw-user-input -p tcp -m tcp --dport 19532",
        1,
    )
    res = run("validator", t)
    f = [x for x in res["findings"] if x["class"] == "source-too-broad"]
    assert [(x["port"], "from any source" in x["message"]) for x in f] == [(19532, True)]


def test_wrong_source_fails_and_names_it():
    t = load("validator").replace(
        "-s 203.0.113.1/32 -p tcp -m tcp --dport 19532", "-s 198.51.100.9/32 -p tcp -m tcp --dport 19532", 1
    )
    res = run("validator", t)
    f = [x for x in res["findings"] if x["class"] == "source-too-broad"]
    assert len(f) == 1 and "198.51.100.9/32" in f[0]["message"]


def test_fail2ban_source_rejects_do_not_count_as_sources():
    res = run("validator")
    row = next(e for e in res["exposure"] if e["family"] == "v4" and e["port"] == 22)
    assert row["state"] == "open" and row["sources"] == []


# ------------------------------------------------------------- ufw state
def test_ufw_inactive_fails():
    res = run("validator", load("validator").replace("Status: active", "Status: inactive", 1))
    assert ("ufw-inactive", None, None) in classes(res) and res["verdict"] == "FAIL"


def test_default_incoming_allow_fails():
    t = load("validator").replace("Default: deny (incoming)", "Default: allow (incoming)", 1)
    assert ("default-incoming-allow", None, None) in classes(run("validator", t))


def test_stale_allow_warns_and_control():
    t = insert_after(
        load("validator"),
        "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
        "-A ufw-user-input -p tcp -m tcp --dport 9999 -j ACCEPT",
    )
    res = run("validator", t)
    assert ("stale-allow", "v4", 9999) in classes(res) and res["verdict"] == "WARN"
    assert not [f for f in run("validator")["findings"] if f["class"] == "stale-allow"]


# ------------------------------------------------------------- docker / nft
def test_loopback_dnat_without_raw_drop_warns():
    t = load("sentry")
    ln = "-A PREROUTING -d 127.0.0.1/32 ! -i lo -p tcp -m tcp --dport 2560 -j DROP\n"
    assert ln in t
    res = run("sentry", t.replace(ln, "", 1))
    assert ("loopback-dnat-unguarded", "v4", 2560) in classes(res)
    assert ("loopback-dnat-unguarded", "v4", 2560) not in classes(run("sentry"))


def test_foreign_nft_table_warns_and_control():
    extra = "table inet extra {\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n\t}\n}"
    t = in_section(load("validator"), "nft list ruleset", lambda s: s + extra + "\n")
    f = [x for x in run("validator", t)["findings"] if x["class"] == "nft-foreign-table"]
    assert [(x["table"], x["hook"]) for x in f] == [("inet extra", "input")]
    assert not [x for x in run("validator")["findings"] if x["class"] == "nft-foreign-table"]


# ------------------------------------------------------------- CLI, exit codes, errors
def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


@pytest.mark.parametrize(
    "bundle,host,rc", [("validator", "validator", 0), ("sentry", "sentry", 1), ("sentry-postfix", "sentry", 0)]
)
def test_cli_exit_codes(bundle, host, rc, capsys):
    args = [
        "audit",
        os.path.join(FIX, f"{bundle}.bundle"),
        os.path.join(POL, f"{host}.policy"),
        "--peers",
        os.path.join(FIX, f"{host}.peers"),
        "--json",
    ]
    assert fe.main(args) == rc
    assert '"verdict"' in capsys.readouterr().out


def test_cli_fail_exit_2(tmp_path):
    b = write(tmp_path, "b", load("validator").replace("Status: active", "Status: inactive", 1))
    assert (
        fe.main(["audit", b, os.path.join(POL, "validator.policy"), "--peers", os.path.join(FIX, "validator.peers")])
        == 2
    )


def test_missing_section_exit_4(tmp_path, capsys):
    a, b = section_bounds(load("validator"), "ip6tables-save")
    t = load("validator")
    t = t[:a] + t[t.index("\n", b) + 1 :]
    p = write(tmp_path, "b", t)
    assert (
        fe.main(["audit", p, os.path.join(POL, "validator.policy"), "--peers", os.path.join(FIX, "validator.peers")])
        == 4
    )
    assert "section missing: ip6tables-save" in capsys.readouterr().err


def test_failed_section_exit_4(tmp_path, capsys):
    t = load("validator")
    _a, b = section_bounds(t, "ss -H")
    t = t[:b] + "### rc=1" + t[b + len("### rc=0") :]
    assert (
        fe.main(
            [
                "audit",
                write(tmp_path, "b", t),
                os.path.join(POL, "validator.policy"),
                "--peers",
                os.path.join(FIX, "validator.peers"),
            ]
        )
        == 4
    )
    assert "section failed (rc=1): ss -H -tulpn" in capsys.readouterr().err


@pytest.mark.parametrize(
    "line,reason",
    [
        ("allow tcp 22 v5 any", "family must be"),
        ("allow tcp 70000 v4 any", "bad proto/port"),
        ("allow tcp 22 v4 @nobody", "peer @nobody not defined"),
        ("allow tcp 22 v4 any fast", "expected `allow"),
        ("allow tcp 22 v4 not-a-net", "bad source"),
    ],
)
def test_policy_errors_exit_3(tmp_path, capsys, line, reason):
    p = write(tmp_path, "p", line + "\n")
    assert fe.main(["audit", os.path.join(FIX, "validator.bundle"), p]) == 3
    assert reason in capsys.readouterr().err
