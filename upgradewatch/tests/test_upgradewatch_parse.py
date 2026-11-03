#!/usr/bin/env python3
"""Unit tests for upgradewatch_parse.py on real fixtures (tests/fixtures, captured by capture_fixtures.sh) and on
copies of them modified per case. Every expected ETA is computed by hand in the test, from the source rules quoted in
the parser's docstring (CloseTime is Ripple-epoch seconds; Unix = CloseTime + 946684800).

Run: python3 upgradewatch/tests/test_upgradewatch_parse.py   (stdlib only; temp files under TEST_TMPDIR or ~/.cache)
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import upgradewatch_parse as up

FX = os.path.join(HERE, "fixtures")
TMPROOT = os.environ.get("TEST_TMPDIR") or os.path.join(
    os.path.expanduser("~"), ".cache"
)
UNSUP = "AB" * 32  # a hash no build knows
SUP_PENDING = None  # filled in setUpModule: a supported, not-enabled, not-obsolete amendment of the real table


def jload(name):
    with open(os.path.join(FX, name), encoding="utf-8") as f:
        return json.load(f)


def setUpModule():
    global SUP_PENDING
    feats = jload("validator_feature.json")["result"]["features"]
    enabled = set(jload("validator_amendments.json")["result"]["node"]["Amendments"])
    SUP_PENDING = min(
        h
        for h, f in feats.items()
        if f["supported"]
        and not f["enabled"]
        and h not in enabled
        and f.get("vetoed") != "Obsolete"
    )  # on these hosts every such one is vetoed=true


class Case:
    """One parser run: real host fixtures, optionally modified, written to a temp dir."""

    def __init__(self, host="validator"):
        self.d = {
            k: jload(f"{host}_{k}.json")
            for k in ("server_info", "feature", "amendments", "peers")
        }
        with open(os.path.join(FX, f"{host}_majority_cfg.txt"), encoding="utf-8") as f:
            self.cfg = f.read()
        self.foundation = jload("foundation_server_info.json")

    @property
    def info(self):
        return self.d["server_info"]["result"]["info"]

    @property
    def node(self):
        return self.d["amendments"]["result"]["node"]

    @property
    def feats(self):
        return self.d["feature"]["result"]["features"]

    def run(self, raw=None):
        t = tempfile.mkdtemp(dir=TMPROOT, prefix="uw-test-")
        try:
            paths = {}
            for k, v in self.d.items():
                paths[k] = os.path.join(t, k + ".json")
                with open(paths[k], "w", encoding="utf-8") as f:
                    f.write(v if isinstance(v, str) else json.dumps(v))
            for k, v in (raw or {}).items():
                with open(paths[k], "w", encoding="utf-8") as f:
                    f.write(v)
            cfg = os.path.join(t, "cfg.txt")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write(self.cfg)
            fp = ""
            if self.foundation is not None:
                fp = os.path.join(t, "foundation.json")
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(
                        self.foundation
                        if isinstance(self.foundation, str)
                        else json.dumps(self.foundation)
                    )
            a = up.argparse.Namespace(
                container="postfiatd",
                info=paths["server_info"],
                feature=paths["feature"],
                amendments=paths["amendments"],
                peers=paths["peers"],
                cfg=cfg,
                foundation=fp,
            )
            return metrics(up.parse(a))
        finally:
            shutil.rmtree(t)


def metrics(text):
    out = {}
    for line in text.splitlines():
        if line.startswith("#") or not line:
            continue
        k, v = line.rsplit(" ", 1)
        out[k] = float(v)
    return out


def m(name, **labels):
    lab = ",".join(
        ['container="postfiatd"'] + [f'{k}="{v}"' for k, v in labels.items()]
    )
    return f"pft_upgradewatch_{name}{{{lab}}}"


class RealFixtures(unittest.TestCase):
    def test_validator_and_sentry_live_values(self):
        for host, peers in (("validator", 19), ("sentry", 16)):
            r = Case(host).run()
            self.assertEqual(r[m("amendment_blocked")], 0)
            self.assertEqual(r[m("majority_amendments", supported="no")], 0)
            self.assertEqual(r[m("majority_amendments", supported="yes")], 0)
            self.assertEqual(r[m("unsupported_activation_eta_seconds")], 0)
            self.assertEqual(
                r[m("majority_time_seconds")], 3 * 86400
            )  # "3 days" in both live configs
            self.assertEqual(r[m("majority_time_from_config")], 1)
            self.assertEqual(r[m("amendments_known")], 101)
            self.assertEqual(r[m("amendments_enabled")], 64)
            self.assertEqual(r[m("build_info", version="1.0.9")], 1)
            self.assertEqual(r[m("peers_versioned")], peers)
            self.assertEqual(r[m("peers_newer")], 0)
            self.assertEqual(r[m("foundation_known")], 1)
            self.assertEqual(r[m("behind_foundation")], 0)

    def test_every_rule_series_always_present(self):
        r = Case().run()
        for name in (
            "amendment_blocked",
            "unsupported_majority_warning",
            "unsupported_activation_eta_seconds",
            "behind_foundation",
            "peers_newer_ratio",
            "peers_versioned",
        ):
            self.assertIn(m(name), r, name)
        self.assertIn(m("majority_amendments", supported="no"), r)


class ETA(unittest.TestCase):
    def majority(self, c, h, close):
        c.node.setdefault("Majorities", []).append(
            {"Majority": {"Amendment": h, "CloseTime": close}}
        )

    def test_unsupported_majority_eta_three_days(self):
        c = Case()
        self.majority(c, UNSUP, 815000000)
        r = c.run()
        # 815000000 + 946684800 + 3 * 86400 = 1761944000
        self.assertEqual(r[m("unsupported_activation_eta_seconds")], 1761944000)
        self.assertEqual(r[m("majority_amendments", supported="no")], 1)
        self.assertEqual(
            r[
                m(
                    "majority_activation_eta_seconds",
                    amendment="unknown_" + UNSUP,
                    supported="no",
                )
            ],
            1761944000,
        )

    def test_default_two_weeks_when_section_absent(self):
        c = Case()
        c.cfg = "[server]\n[network_id]\n"
        self.majority(c, UNSUP, 815000000)
        r = c.run()
        self.assertEqual(r[m("majority_time_from_config")], 0)
        self.assertEqual(r[m("majority_time_seconds")], 1209600)
        self.assertEqual(
            r[m("unsupported_activation_eta_seconds")], 815000000 + 946684800 + 1209600
        )

    def test_earliest_unsupported_wins_and_supported_does_not_count(self):
        c = Case()
        c.cfg = "[amendment_majority_time]\n90 minutes\n"
        self.majority(
            c, SUP_PENDING, 800000000
        )  # supported: earlier, but not an unsupported ETA
        self.majority(c, "CD" * 32, 815000500)
        self.majority(c, UNSUP, 815000100)
        r = c.run()
        self.assertEqual(r[m("majority_amendments", supported="no")], 2)
        self.assertEqual(r[m("majority_amendments", supported="yes")], 1)
        self.assertEqual(
            r[m("unsupported_activation_eta_seconds")], 815000100 + 946684800 + 5400
        )
        name = c.feats[SUP_PENDING]["name"]
        self.assertEqual(
            r[m("majority_activation_eta_seconds", amendment=name, supported="yes")],
            800000000 + 946684800 + 5400,
        )

    def test_known_but_unsupported_amendment_counts_as_unsupported(self):
        c = Case()
        c.feats[UNSUP] = {
            "enabled": False,
            "name": "FutureFeature",
            "supported": False,
            "vetoed": False,
        }
        self.majority(c, UNSUP, 815000000)
        r = c.run()
        self.assertEqual(r[m("majority_amendments", supported="no")], 1)
        self.assertEqual(r[m("unsupported_activation_eta_seconds")], 1761944000)
        self.assertEqual(
            r[
                m(
                    "majority_activation_eta_seconds",
                    amendment="FutureFeature",
                    supported="no",
                )
            ],
            1761944000,
        )

    def test_enabled_amendment_in_majorities_is_ignored(self):
        c = Case()
        self.majority(c, c.node["Amendments"][0], 815000000)
        r = c.run()
        self.assertEqual(r[m("majority_amendments", supported="no")], 0)
        self.assertEqual(r[m("majority_amendments", supported="yes")], 0)

    def test_node_warning_agrees_and_disagrees(self):
        for expected, agrees in (
            (815000000 + 259200, 1),
            (815000000 + 259200 + 3600, 0),
        ):
            c = Case()
            self.majority(c, UNSUP, 815000000)
            c.info["warnings"] = [
                {
                    "id": 1001,
                    "message": "x",
                    "details": {"expected_date": expected, "expected_date_UTC": "x"},
                }
            ]
            r = c.run()
            self.assertEqual(r[m("unsupported_majority_warning")], 1)
            self.assertEqual(r[m("node_expected_date_seconds")], expected + 946684800)
            self.assertEqual(r[m("eta_agrees_with_node")], agrees)

    def test_series_cap(self):
        c = Case()
        for i in range(40):
            self.majority(c, f"{i:064X}", 815000000 + i)
        r = c.run()
        self.assertEqual(r[m("majority_amendments", supported="no")], 40)
        self.assertEqual(
            sum(1 for k in r if "majority_activation_eta_seconds" in k),
            up.MAX_AMENDMENT_SERIES,
        )


class MajorityTime(unittest.TestCase):
    def mt(self, text):
        return up.majority_time(text.splitlines())

    def test_units(self):
        for text, secs in (
            ("15 minutes", 900),
            ("2 hours", 7200),
            ("3 days", 259200),
            ("1 weeks", 604800),
            ("  4 days   # comment-ish tail", 345600),
            ("3days", 259200),
        ):
            self.assertEqual(
                self.mt(f"[amendment_majority_time]\n{text}\n"), (secs, 1), text
            )

    def test_default_cases(self):
        for text in (
            "",
            "[server]\n3 days\n",
            "[amendment_majority_time]\n",
            "[amendment_majority_time]\n3 days\n4 days\n",
            "[amendment_majority_time]\n3 days\n[x]\n[amendment_majority_time]\n2 days\n",
        ):
            self.assertEqual(self.mt(text), (1209600, 0), text)

    def test_comments_blank_and_indented_header(self):
        self.assertEqual(
            self.mt("  [amendment_majority_time]  \n\n# 9 days\n 2 days \n[next]\n"),
            (172800, 1),
        )

    def test_invalid_values_raise(self):
        for v in ("14 minutes", "3 Days", "3 fortnights", "days 3"):
            with self.assertRaises(up.ParseError, msg=v):
                self.mt(f"[amendment_majority_time]\n{v}\n")


class Versions(unittest.TestCase):
    def test_order(self):
        k = up.version_key
        self.assertGreater(k("1.0.10"), k("1.0.9"))
        self.assertGreater(k("1.0.9"), k("1.0.9-rc2"))
        self.assertGreater(k("1.0.9-rc2"), k("1.0.9-rc1"))
        self.assertGreater(k("1.0.9-rc1"), k("1.0.9-b9"))
        self.assertEqual(k("postfiatd-1.0.9"), k("1.0.9"))
        for bad in ("rippled-2.3.0", "1.0", "1.0.9-beta", "", None, 109):
            self.assertIsNone(k(bad), bad)

    def test_peers_newer_and_ratio(self):
        c = Case()
        ps = c.d["peers"]["result"]["peers"]
        for p in ps[:10]:
            p["version"] = "1.0.10"
        ps[10]["version"] = "rippled-2.3.0"  # not counted
        del ps[11]["version"]  # not counted
        r = c.run()
        self.assertEqual(r[m("peers_versioned")], 17)
        self.assertEqual(r[m("peers_newer")], 10)
        self.assertEqual(r[m("peers_newer_ratio")], round(10 / 17, 4))

    def test_behind_foundation(self):
        c = Case()
        c.foundation["result"]["info"]["build_version"] = "1.1.0-rc1"
        r = c.run()
        self.assertEqual(r[m("behind_foundation")], 1)
        self.assertEqual(r[m("foundation_build_info", version="1.1.0-rc1")], 1)

    def test_foundation_unknown_is_not_a_failure(self):
        for f in (
            None,
            "not json",
            json.dumps({"result": {"status": "error", "error": "noNetwork"}}),
            json.dumps(
                {"result": {"status": "success", "info": {"build_version": "x"}}}
            ),
        ):
            c = Case()
            c.foundation = f
            r = c.run()
            self.assertEqual(r[m("foundation_known")], 0, f)
            self.assertEqual(r[m("behind_foundation")], 0, f)


class Blocked(unittest.TestCase):
    def test_flag_and_warning(self):
        c = Case()
        c.info["amendment_blocked"] = True
        self.assertEqual(c.run()[m("amendment_blocked")], 1)
        c = Case()
        c.info["warnings"] = [{"id": 1002, "message": "blocked"}]
        self.assertEqual(c.run()[m("amendment_blocked")], 1)
        c = Case()
        c.info["amendment_blocked"] = False
        self.assertEqual(c.run()[m("amendment_blocked")], 0)

    def test_enabled_unsupported(self):
        c = Case()
        c.node["Amendments"].append(UNSUP)
        self.assertEqual(c.run()[m("amendments_enabled_unsupported")], 1)


class Malformed(unittest.TestCase):
    def bad(self, mutate=None, raw=None, msg=""):
        c = Case()
        if mutate:
            mutate(c)
        with self.assertRaises(up.ParseError) as e:
            c.run(raw)
        self.assertIn(msg, str(e.exception))

    def test_cases(self):
        self.bad(raw={"server_info": "garbage"}, msg="server_info: not readable JSON")
        self.bad(raw={"feature": ""}, msg="feature: not readable JSON")
        self.bad(
            raw={
                "peers": json.dumps(
                    {"result": {"status": "error", "error": "noPermission"}}
                )
            },
            msg="peers: rpc error 'noPermission'",
        )
        self.bad(lambda c: c.info.pop("build_version"), msg="build_version")
        self.bad(
            lambda c: c.info.__setitem__("build_version", "1.0.9 }"),
            msg="is not a version",
        )
        self.bad(
            lambda c: c.info.__setitem__("warnings", {}), msg="warnings is not a list"
        )
        self.bad(
            lambda c: c.d["amendments"]["result"].__setitem__("validated", False),
            msg="not from a validated",
        )
        self.bad(
            lambda c: c.node.__setitem__("LedgerEntryType", "FeeSettings"),
            msg="not the Amendments object",
        )
        self.bad(
            lambda c: c.node.__setitem__(
                "Majorities", [{"Majority": {"Amendment": UNSUP, "CloseTime": "1"}}]
            ),
            msg="malformed Majorities",
        )
        self.bad(
            lambda c: c.node.__setitem__(
                "Majorities", [{"Majority": {"Amendment": "x", "CloseTime": 1}}]
            ),
            msg="malformed Majorities",
        )
        self.bad(
            lambda c: c.feats[next(iter(c.feats))].pop("supported"),
            msg="lacks enabled/supported",
        )
        self.bad(lambda c: c.feats.__setitem__("zz", {}), msg="malformed entry")
        self.bad(
            lambda c: setattr(c, "cfg", "[amendment_majority_time]\n1 minutes\n"),
            msg="15 minute minimum",
        )
        self.bad(lambda c: c.d["peers"]["result"].__setitem__("peers", {}), msg="peers")

    def test_bool_is_not_an_int(self):
        self.bad(
            lambda c: c.node.__setitem__(
                "Majorities", [{"Majority": {"Amendment": UNSUP, "CloseTime": True}}]
            ),
            msg="malformed Majorities",
        )


class CLI(unittest.TestCase):
    def test_main_rc_and_bad_container(self):
        self.assertEqual(
            up.main(
                [
                    "--container",
                    "bad name",
                    "--info",
                    "x",
                    "--feature",
                    "x",
                    "--amendments",
                    "x",
                    "--peers",
                    "x",
                    "--cfg",
                    "x",
                ]
            ),
            1,
        )
        self.assertEqual(
            up.main(
                [
                    "--container",
                    "ok",
                    "--info",
                    "/nonexistent",
                    "--feature",
                    "x",
                    "--amendments",
                    "x",
                    "--peers",
                    "x",
                    "--cfg",
                    "x",
                ]
            ),
            1,
        )


if __name__ == "__main__":
    os.makedirs(TMPROOT, exist_ok=True)
    unittest.main(verbosity=1)
