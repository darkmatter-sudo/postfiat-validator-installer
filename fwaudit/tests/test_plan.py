"""Unit tests for fwaudit_eval.plan / ufwnum: each finding class maps to the planned UFW change (or to MANUAL), with
controls that must plan nothing. Faults are injected into the real captures with the helpers of test_fwaudit."""

from test_fwaudit import drop_docker_user_limits, in_section, insert_before, listen, load, policy

import fwaudit_eval as fe


def plan(host, text=None):
    b = fe.read_bundle(text if text is not None else load(host))
    pol = policy(host)
    return fe.plan(fe.audit(b, pol), pol, b)


def ops(pl):
    return [(a["op"], a["why"], a.get("family"), a.get("port")) for a in pl["actions"]]


NUMBERED = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] 2559/tcp                   LIMIT IN    Anywhere                   # relay
[ 3] 19532/tcp                  ALLOW IN    203.0.113.7                # pft-logship
[ 4] 19532/tcp                  ALLOW IN    198.51.100.9
[ 5] 2559/tcp                   ALLOW IN    Anywhere
[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # SSH
[ 7] 2559/tcp (v6)              LIMIT IN    Anywhere (v6)
"""


def test_controls_plan_nothing():
    for host in ("validator", "sentry-postfix"):
        h = "sentry" if host.startswith("sentry") else host
        pl = plan(h, load(host))
        assert pl["actions"] == [] and pl["manual"] == []


def test_stale_allow_plans_family_scoped_delete():
    pl = plan("sentry")
    assert ops(pl) == [("delete", "stale-allow", "v6", 2559)]
    assert pl["manual"] == []


def test_undeclared_ufw_allowed_listener_plans_delete():
    t = in_section(load("validator"), "ss -H", lambda s: s + listen(8080) + "\n")
    t = insert_before(
        t,
        "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
        "-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT",
    )
    assert ops(plan("validator", t)) == [("delete", "undeclared-exposure", "v4", 8080)]


def test_undeclared_accept_outside_ufw_is_manual():
    t = in_section(load("validator"), "ss -H", lambda s: s + listen(8082) + "\n")
    t = insert_before(t, "-A INPUT -j ufw-before-logging-input", "-A INPUT -p tcp -m tcp --dport 8082 -j ACCEPT")
    pl = plan("validator", t)
    assert pl["actions"] == []
    assert [m["why"] for m in pl["manual"]] == ["undeclared-exposure"]


def test_docker_user_missing_limit_is_manual():
    pl = plan("validator", drop_docker_user_limits(load("validator")))
    assert pl["actions"] == []
    assert [m["why"] for m in pl["manual"]] == ["missing-limit"]


def test_ufw_missing_limit_plans_limit_then_delete_of_the_allow():
    t = load("sentry-postfix")
    for ln in t.splitlines():
        if ln.startswith("-A ufw-user-input -p tcp -m tcp --dport 2559") and "recent --update" in ln:
            t = t.replace(ln + "\n", "", 1)
    pl = plan("sentry", t)
    assert ops(pl) == [("limit", "missing-limit", "v4", 2559), ("delete", "missing-limit", "v4", 2559)]
    assert pl["actions"][0]["argv"][:6] == ["ufw", "limit", "proto", "tcp", "from", "0.0.0.0/0"]
    assert pl["actions"][1]["keep"] == "LIMIT" and pl["actions"][1]["from_any_only"] is True


def test_source_too_broad_plans_source_allow_then_delete_except_source():
    t = load("validator").replace(
        "-s 203.0.113.1/32 -p tcp -m tcp --dport 19532", "-s 198.51.100.9/32 -p tcp -m tcp --dport 19532", 1
    )
    pl = plan("validator", t)
    assert ops(pl) == [("allow-source", "source-too-broad", "v4", 19532), ("delete", "source-too-broad", "v4", 19532)]
    assert pl["actions"][0]["source"] == "203.0.113.1/32"
    assert pl["actions"][1]["except_from"] == ["203.0.113.1/32"]


def test_default_incoming_allow_plans_default_deny():
    t = load("validator").replace("Default: deny (incoming)", "Default: allow (incoming)", 1)
    assert ops(plan("validator", t)) == [("default-deny", "default-incoming-allow", None, None)]


def test_ufw_inactive_and_foreign_nft_are_manual_never_actions():
    t = load("validator").replace("Status: active", "Status: inactive", 1)
    pl = plan("validator", t)
    assert "ufw-inactive" in [m["why"] for m in pl["manual"]]
    assert all(a["op"] != "enable" for a in pl["actions"])


def test_info_findings_are_neither_action_nor_manual():
    pl = plan("validator")  # carries ufw-rule-bypassed INFO
    assert pl["actions"] == [] and pl["manual"] == []


def test_ufwnum_family_action_and_source_selection():
    assert fe.ufwnum(NUMBERED, "v6", "tcp", 2559) == [7]
    assert fe.ufwnum(NUMBERED, "v4", "tcp", 2559) == [5, 2]  # highest first
    assert fe.ufwnum(NUMBERED, "v4", "tcp", 2559, from_any_only=True, keep="LIMIT") == [5]
    assert fe.ufwnum(NUMBERED, "v4", "tcp", 19532, except_from=["203.0.113.7/32"]) == [4]
    assert fe.ufwnum(NUMBERED, "v4", "tcp", 19532, from_any_only=True) == []
    assert fe.ufwnum(NUMBERED, "v4", "udp", 22) == [] and fe.ufwnum(NUMBERED, "v4", "tcp", 222) == []


def test_ufwnum_cli(capsys, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(NUMBERED))
    assert fe.main(["ufwnum", "v4", "tcp", "19532", "--except-from", "203.0.113.7/32"]) == 0
    assert capsys.readouterr().out.strip() == "4"
    assert fe.main(["ufwnum", "v5", "tcp", "1"]) == 3


def test_plan_cli_exit_codes(capsys):
    import os

    from test_fwaudit import FIX, POL

    def cli(bundle, host):
        return fe.main(
            [
                "plan",
                os.path.join(FIX, bundle),
                os.path.join(POL, f"{host}.policy"),
                "--peers",
                os.path.join(FIX, f"{host}.peers"),
            ]
        )

    assert cli("sentry.bundle", "sentry") == 1
    assert cli("sentry-postfix.bundle", "sentry") == 0
    capsys.readouterr()


def test_ufwnum_never_selects_deny_or_reject():
    text = (
        "[ 1] 2559/tcp                   DENY IN     Anywhere\n[ 2] 2559/tcp                   ALLOW IN    Anywhere\n"
    )
    text += "[ 3] 2559/tcp                   REJECT IN   Anywhere\n"
    assert fe.ufwnum(text, "v4", "tcp", 2559) == [2]


def test_plan_cli_manual_items_exit_2(tmp_path, capsys):
    import os

    from test_fwaudit import FIX, POL, load

    b = tmp_path / "inactive.bundle"
    b.write_text(load("validator").replace("Status: active", "Status: inactive", 1), encoding="utf-8")
    pol = os.path.join(POL, "validator.policy")
    assert fe.main(["plan", str(b), pol, "--peers", os.path.join(FIX, "validator.peers")]) == 2
    assert "MANUAL ufw-inactive" in capsys.readouterr().out
