#!/usr/bin/env python3
"""Offline tests for pft-peerwatch (stdlib unittest). Fixtures: real `peers`/`server_info` captures of both hosts
(2026-11-11, redacted by redact_capture.py); variants are derived from them in each test.

Run: python3 -I tests/test_peerwatch.py   (scratch under $TEST_TMPDIR, default ~/.cache: /tmp is noexec here)
"""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PARSER = os.path.join(ROOT, "peerwatch_parse.py")
SCRIPT = os.path.join(ROOT, "pft-peerwatch.sh")
FIX = os.path.join(HERE, "fixtures")
NOW = 1794397500
BASE = os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache")
SENTRY_KEY = "n9FixtureSentry" + "x" * 37
VALIDATOR_KEY = "n9FixtureValidator" + "x" * 34


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


class Base(unittest.TestCase):
    def setUp(self):
        os.makedirs(BASE, exist_ok=True)
        self.d = tempfile.mkdtemp(prefix="pft-pw-test.", dir=BASE)
        os.chmod(self.d, 0o755)
        self.state = os.path.join(self.d, "state.json")
        self.hist = os.path.join(self.d, "history.jsonl")
        self.conf = os.path.join(self.d, "conf")
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\n")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def write_conf(self, text):
        with open(self.conf, "w", encoding="utf-8") as f:
            f.write(text)

    def dump(self, name, doc):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))
        return p

    def collect(self, peers, info, now=NOW, container="postfiatd", history=True):
        pp = self.dump("peers.json", peers)
        ip = self.dump("info.json", info)
        args = [sys.executable, "-I", PARSER, "collect", "--peers", pp, "--server-info", ip, "--state", self.state]
        args += ["--container", container, "--conf", self.conf, "--now", str(now)]
        if history:
            args += ["--history", self.hist]
        r = subprocess.run(args, check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)
        return r

    def metrics(self, r):
        self.assertEqual(r.returncode, 0, r.stderr)
        out = {}
        for line in r.stdout.splitlines():
            if line and not line.startswith("#"):
                k, v = line.rsplit(" ", 1)
                out[k] = float(v)
        return out

    def checks(self):
        with open(self.state, encoding="utf-8") as f:
            return {k: v[0] for k, v in json.load(f)["checks"].items()}

    def status(self, now=NOW, json_out=False):
        args = [sys.executable, "-I", PARSER, "status", "--state", self.state, "--conf", self.conf, "--now", str(now)]
        if json_out:
            args.append("--json")
        return subprocess.run(args, check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)


def V(m, metric, **labels):
    lab = ",".join(['container="postfiatd"'] + [f'{k}="{v}"' for k, v in labels.items()])
    return m[f"pft_peerwatch_{metric}{{{lab}}}"]


class RealFixtures(Base):
    def test_validator_capture(self):
        m = self.metrics(self.collect(load("validator-peers.json"), load("validator-server_info.json")))
        self.assertEqual(V(m, "peers", direction="inbound"), 4)
        self.assertEqual(V(m, "peers", direction="outbound"), 10)
        self.assertEqual(V(m, "latency_ms", quantile="0.5"), 263)
        self.assertEqual(V(m, "latency_ms", quantile="0.95"), 511)
        self.assertEqual(V(m, "latency_ms", quantile="1"), 511)
        self.assertEqual(V(m, "version_peers", relation="same"), 13)
        self.assertEqual(V(m, "version_peers", relation="older"), 1)
        self.assertEqual(V(m, "outbound_prefixes", len="16"), 10)
        self.assertEqual(V(m, "outbound_prefixes", len="24"), 10)
        self.assertEqual(V(m, "outbound_prefix16_max_share"), 0.1)
        self.assertEqual(V(m, "ledger_agree_ratio"), 1.0)
        self.assertEqual(V(m, "fixed_link_up", link="sentry"), 1)
        self.assertEqual(V(m, "churn_rebaselined"), 1)
        self.assertEqual(V(m, "status"), 0)
        self.assertEqual(set(self.checks().values()), {"PASS"})

    def test_sentry_capture(self):
        m = self.metrics(self.collect(load("sentry-peers.json"), load("sentry-server_info.json")))
        self.assertEqual(V(m, "peers", direction="inbound"), 9)
        self.assertEqual(V(m, "peers", direction="outbound"), 11)
        self.assertEqual(V(m, "latency_ms", quantile="0.5"), 269)
        self.assertEqual(V(m, "latency_ms", quantile="0.95"), 480)
        self.assertEqual(V(m, "outbound_prefixes", len="16"), 11)
        self.assertEqual(V(m, "fixed_link_up", link="validator"), 1)
        self.assertEqual(V(m, "status"), 0)

    def test_inbound_gateway_never_counted(self):
        # the sentry sees all 9 inbound peers as the docker bridge gateway: they must not count as one /16
        m = self.metrics(self.collect(load("sentry-peers.json"), load("sentry-server_info.json")))
        self.assertEqual(V(m, "outbound_prefix16_max_share"), round(1 / 11, 4))

    def test_private_outbound_excluded_by_default(self):
        self.write_conf("")
        m = self.metrics(self.collect(load("validator-peers.json"), load("validator-server_info.json")))
        self.assertEqual(V(m, "outbound_prefixes", len="16"), 0)
        self.assertEqual(self.checks()["diversity"], "PASS")


class Churn(Base):
    def test_joins_leaves_by_key(self):
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        self.metrics(self.collect(p, i, NOW))
        q = copy.deepcopy(p)
        gone = q["result"]["peers"][:2]
        del q["result"]["peers"][:2]
        for n in range(3):
            new = copy.deepcopy(gone[0])
            new["public_key"] = f"n9FixtureNew{n:03d}" + "x" * 37
            q["result"]["peers"].append(new)
        m = self.metrics(self.collect(q, i, NOW + 60))
        self.assertEqual(V(m, "churn_events", kind="join"), 3)
        self.assertEqual(V(m, "churn_events", kind="leave"), 2)
        self.assertEqual(V(m, "churn_rebaselined"), 0)
        with open(self.hist, encoding="utf-8") as f:
            last = json.loads(f.read().splitlines()[-1])
        self.assertEqual((last["joins"], last["leaves"], last["gap"]), (3, 2, False))

    def test_same_address_new_key_is_churn(self):
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        self.metrics(self.collect(p, i, NOW))
        q = copy.deepcopy(p)
        q["result"]["peers"][3]["public_key"] = "n9FixtureRekeyed" + "x" * 36
        m = self.metrics(self.collect(q, i, NOW + 60))
        self.assertEqual((V(m, "churn_events", kind="join"), V(m, "churn_events", kind="leave")), (1, 1))

    def test_gap_rebaselines(self):
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        self.metrics(self.collect(p, i, NOW))
        q = copy.deepcopy(p)
        del q["result"]["peers"][:5]
        m = self.metrics(self.collect(q, i, NOW + 181))  # GAP_SEC 180
        self.assertEqual(V(m, "churn_rebaselined"), 1)
        self.assertEqual(V(m, "churn_events", kind="leave"), 0)
        m = self.metrics(self.collect(p, i, NOW + 180 + 181 - 1))  # within GAP_SEC of the last one: counted
        self.assertEqual(V(m, "churn_events", kind="join"), 5)

    def test_window_expiry_and_thresholds(self):
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\nCHURN_WINDOW_MIN=10\nCHURN_WARN=3\nCHURN_FAIL=7\nFLAP_WARN=0\n")
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        full = p["result"]["peers"]
        self.metrics(self.collect(p, i, NOW))
        q = copy.deepcopy(p)
        q["result"]["peers"] = full[2:]
        self.metrics(self.collect(q, i, NOW + 60))  # 2 leaves
        self.assertEqual(self.checks()["churn"], "PASS")
        self.metrics(self.collect(p, i, NOW + 120))  # 2 joins -> 4 events > 3
        self.assertEqual(self.checks()["churn"], "WARN")
        q["result"]["peers"] = full[4:]
        self.metrics(self.collect(q, i, NOW + 180))  # 4 leaves -> 8 events > 7
        self.assertEqual(self.checks()["churn"], "FAIL")
        # 10-minute window: at NOW+660 the events of NOW+60 (2) have left the window, 6 remain
        m = self.metrics(self.collect(q, i, NOW + 600 + 61 - 0))
        self.assertEqual(V(m, "churn_events", kind="leave") + V(m, "churn_events", kind="join"), 6)
        self.assertEqual(V(m, "churn_rebaselined"), 1)  # 480 s since NOW+180 > GAP_SEC: re-baselined, events kept

    def test_flapping(self):
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\nFLAP_WARN=1\nCHURN_WARN=1000\nCHURN_FAIL=1000\n")
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        q = copy.deepcopy(p)
        q["result"]["peers"] = p["result"]["peers"][1:]
        t = NOW
        for doc in (p, q, p, q):
            self.metrics(self.collect(doc, i, t))
            t += 60
        self.assertEqual(self.checks()["churn"], "WARN")
        with open(self.state, encoding="utf-8") as f:
            self.assertIn("1 peers left twice or more", json.load(f)["checks"]["churn"][1])


class Grades(Base):
    def peers(self):
        return load("validator-peers.json"), load("validator-server_info.json")

    def test_latency_warn_fail_off_centre(self):
        p, i = self.peers()
        lats = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 1500, 4000]
        for peer, lat in zip(p["result"]["peers"], lats, strict=True):
            peer["latency"] = lat
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "latency_ms", quantile="0.5"), 70)  # ceil(0.5*14)=7th
        self.assertEqual(V(m, "latency_ms", quantile="0.95"), 4000)  # ceil(0.95*14)=14th
        self.assertEqual(self.checks()["latency"], "FAIL")
        p["result"]["peers"][-1]["latency"] = 2000
        self.metrics(self.collect(p, i, NOW + 60))
        self.assertEqual(self.checks()["latency"], "WARN")
        p["result"]["peers"][-1]["latency"] = 1000
        p["result"]["peers"][-2]["latency"] = 900
        self.metrics(self.collect(p, i, NOW + 120))
        self.assertEqual(self.checks()["latency"], "PASS")  # > WARN, not >=

    def test_versions(self):
        p, i = self.peers()
        self.assertEqual(p["result"]["peers"][0]["version"], "1.0.4")  # the captured older peer stays
        for peer in p["result"]["peers"][1:5]:
            peer["version"] = "rippled-1.0.8"
        p["result"]["peers"][5]["version"] = "postfiatd-2.0.0"
        p["result"]["peers"][6]["version"] = "weird"
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "version_peers", relation="older"), 5)  # 4 + the captured 1.0.4
        self.assertEqual(V(m, "version_peers", relation="newer"), 1)
        self.assertEqual(V(m, "version_peers", relation="unknown"), 1)
        self.assertEqual(self.checks()["versions"], "WARN")  # 5/14 = 36 % > 25
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\nOUTDATED_FAIL_PCT=35\n")
        self.metrics(self.collect(p, i, NOW + 60))
        self.assertEqual(self.checks()["versions"], "FAIL")

    def test_direction(self):
        p, i = self.peers()
        p["result"]["peers"] = [x for x in p["result"]["peers"] if x.get("inbound")]
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "peers", direction="outbound"), 0)
        self.assertEqual(self.checks()["direction"], "FAIL")
        self.assertEqual(self.checks()["count"], "WARN")  # 4 < 5

    def test_diversity_one_prefix(self):
        p, i = self.peers()
        for n, peer in enumerate(x for x in p["result"]["peers"] if not x.get("inbound")):
            peer["address"] = f"10.77.{n % 2}.{n + 1}:2559"
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "outbound_prefixes", len="16"), 1)
        self.assertEqual(V(m, "outbound_prefixes", len="24"), 2)
        self.assertEqual(V(m, "outbound_prefix16_max_share"), 1.0)
        self.assertEqual(self.checks()["diversity"], "WARN")

    def test_diversity_share_only(self):
        # 10 outbound in 4 /16s (enough prefixes) but 6 in one: only the share rule can fire
        p, i = self.peers()
        out = [x for x in p["result"]["peers"] if not x.get("inbound")]
        for n, peer in enumerate(out):
            peer["address"] = f"10.{50 if n < 6 else 60 + n}.0.{n + 1}:2559"
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "outbound_prefixes", len="16"), 5)
        self.assertEqual(V(m, "outbound_prefix16_max_share"), 0.6)
        self.assertEqual(self.checks()["diversity"], "WARN")

    def test_ledgers_lag_and_network(self):
        p, i = self.peers()
        seq = i["result"]["info"]["validated_ledger"]["seq"]
        for peer in p["result"]["peers"][:6]:
            peer["complete_ledgers"] = f"{seq - 600} - {seq - 9}"
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "ledger_agree_ratio"), round(8 / 14, 4))
        self.assertEqual(V(m, "ledger_lag_max"), 9)
        self.assertEqual(self.checks()["ledgers"], "WARN")  # 57 % < 70
        for peer in p["result"]["peers"][6:11]:
            peer["complete_ledgers"] = f"{seq - 600} - {seq + 9}"  # ahead counts too (abs)
        self.metrics(self.collect(p, i, NOW + 60))
        self.assertEqual(self.checks()["ledgers"], "FAIL")  # 3/14 = 21 % < 30
        p, i = self.peers()
        p["result"]["peers"][0]["network_id"] = 1
        m = self.metrics(self.collect(p, i, NOW + 120))
        self.assertEqual(V(m, "network_mismatch_peers"), 1)
        self.assertEqual(self.checks()["ledgers"], "FAIL")

    def test_ledgers_edge_exact_lag(self):
        p, i = self.peers()
        seq = i["result"]["info"]["validated_ledger"]["seq"]
        for peer in p["result"]["peers"]:
            peer["complete_ledgers"] = f"1-{seq - 8}"
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "ledger_agree_ratio"), 1.0)

    def test_own_not_validated(self):
        p, i = self.peers()
        i["result"]["info"]["validated_ledger"] = None
        i["result"]["info"]["server_state"] = "connected"
        m = self.metrics(self.collect(p, i))
        self.assertEqual(self.checks()["ledgers"], "WARN")
        self.assertEqual(V(m, "local_full"), 0)

    def test_fixed_link_down(self):
        p, i = self.peers()
        p["result"]["peers"] = [x for x in p["result"]["peers"] if x["public_key"] != SENTRY_KEY]
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "fixed_link_up", link="sentry"), 0)
        self.assertEqual(self.checks()["fixed"], "FAIL")
        self.assertEqual(V(m, "status"), 2)

    def test_fixed_links_conf_overrides_cluster(self):
        p, i = self.peers()
        key = p["result"]["peers"][5]["public_key"]
        self.write_conf(f"COUNT_PRIVATE_OUTBOUND=1\nFIXED_LINKS=hub={key} gone=n9Missing{'x' * 40}\n")
        m = self.metrics(self.collect(p, i))
        self.assertEqual(V(m, "fixed_link_up", link="hub"), 1)
        self.assertEqual(V(m, "fixed_link_up", link="gone"), 0)
        self.assertNotIn('pft_peerwatch_fixed_link_up{container="postfiatd",link="sentry"}', m)

    def test_no_links_without_cluster(self):
        p, i = self.peers()
        p["result"].pop("cluster")
        m = self.metrics(self.collect(p, i))
        self.assertEqual(self.checks()["fixed"], "PASS")
        self.assertFalse(any("fixed_link_up" in k for k in m))

    def test_cluster_discovery_off(self):
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\nFIXED_FROM_CLUSTER=0\n")
        p, i = self.peers()
        p["result"]["peers"] = [x for x in p["result"]["peers"] if x["public_key"] != SENTRY_KEY]
        self.metrics(self.collect(p, i))
        self.assertEqual(self.checks()["fixed"], "PASS")

    def test_count_boundary(self):
        p, i = self.peers()
        p["result"]["peers"] = p["result"]["peers"][:5]  # exactly MIN_PEERS_WARN
        self.metrics(self.collect(p, i))
        self.assertEqual(self.checks()["count"], "PASS")
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\nMIN_OUTBOUND_WARN=4\n")
        p, i = self.peers()
        p["result"]["peers"] = [x for x in p["result"]["peers"] if x.get("inbound")] + [
            x for x in p["result"]["peers"] if not x.get("inbound")
        ][:4]
        self.metrics(self.collect(p, i, NOW + 60))
        self.assertEqual(self.checks()["direction"], "PASS")  # outbound 4 == MIN_OUTBOUND_WARN

    def test_count(self):
        p, i = self.peers()
        p["result"]["peers"] = []
        m = self.metrics(self.collect(p, i))
        self.assertEqual(self.checks()["count"], "FAIL")
        self.assertEqual(V(m, "ledger_agree_ratio"), 0)
        self.assertFalse(any("latency_ms" in k for k in m))


class BadInput(Base):
    def assert_rejected(self, peers, info, needle):
        first = self.collect(load("validator-peers.json"), load("validator-server_info.json"))
        self.assertEqual(first.returncode, 0)
        with open(self.state, encoding="utf-8") as f:
            before = f.read()
        r = self.collect(peers, info, NOW + 60)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn(needle, r.stderr)
        self.assertEqual(r.stdout, "")
        with open(self.state, encoding="utf-8") as f:
            self.assertEqual(f.read(), before)  # state untouched
        with open(self.hist, encoding="utf-8") as f:
            self.assertEqual(len(f.read().splitlines()), 1)

    def test_not_json(self):
        self.assert_rejected("{nope", load("validator-server_info.json"), "peers: not JSON")

    def test_rpc_error(self):
        err = {"result": {"error": "noPermission", "status": "error"}}
        self.assert_rejected(
            load("validator-peers.json"), err, "server_info: rpc answer is not a success (noPermission)"
        )

    def test_missing_key(self):
        p = load("validator-peers.json")
        del p["result"]["peers"][2]["public_key"]
        self.assert_rejected(p, load("validator-server_info.json"), "entry 2 has no public_key")

    def test_duplicate_key(self):
        p = load("validator-peers.json")
        p["result"]["peers"][1]["public_key"] = p["result"]["peers"][0]["public_key"]
        self.assert_rejected(p, load("validator-server_info.json"), "duplicate public_key")

    def test_bad_latency(self):
        p = load("validator-peers.json")
        p["result"]["peers"][0]["latency"] = "fast"
        self.assert_rejected(p, load("validator-server_info.json"), "latency 'fast'")

    def test_no_state_field(self):
        i = load("validator-server_info.json")
        del i["result"]["info"]["server_state"]
        self.assert_rejected(load("validator-peers.json"), i, "server_state missing")

    def test_garbage_state_rebaselines(self):
        with open(self.state, "w", encoding="utf-8") as f:
            f.write("[1, 2]")
        r = self.collect(load("validator-peers.json"), load("validator-server_info.json"))
        m = self.metrics(r)
        self.assertEqual(V(m, "churn_rebaselined"), 1)
        self.assertIn("not an object", r.stderr)

    def test_shipped_conf_example(self):
        with open(os.path.join(ROOT, "pft-peerwatch.env.example"), encoding="utf-8") as f:
            self.write_conf(f.read() + "CHURN_WARN=2   # inline comment\nCOUNT_PRIVATE_OUTBOUND=1\n")
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        self.metrics(self.collect(p, i))
        q = copy.deepcopy(p)
        q["result"]["peers"] = p["result"]["peers"][3:]
        self.metrics(self.collect(q, i, NOW + 60))
        self.assertEqual(self.checks()["churn"], "WARN")  # 3 leaves > CHURN_WARN=2 from the appended line
        self.assertEqual(self.checks()["diversity"], "PASS")

    def test_bad_conf(self):
        self.write_conf("CHURN_WARN=lots\n")
        r = self.collect(load("validator-peers.json"), load("validator-server_info.json"))
        self.assertEqual(r.returncode, 3)
        self.assertIn("CHURN_WARN", r.stderr)
        for bad in ("CHURN_WINDOW_MIN=0", "MAX_LEDGER_LAG=100001", "AGREE_WARN_PCT=101"):
            self.write_conf(bad + "\n")
            r = self.collect(load("validator-peers.json"), load("validator-server_info.json"))
            self.assertEqual(r.returncode, 3, bad)
            self.assertIn("want an integer", r.stderr)
        for bad in ("bad-tag=n9abc", "sentry=x9abc", "sentry=n9a/b"):
            self.write_conf(f"FIXED_LINKS={bad}\n")
            r = self.collect(load("validator-peers.json"), load("validator-server_info.json"))
            self.assertEqual(r.returncode, 3, bad)
            self.assertIn("TAG=NODE_PUBKEY", r.stderr)
        self.write_conf("FIXED_LINKS=sentry\n")
        r = self.collect(load("validator-peers.json"), load("validator-server_info.json"))
        self.assertEqual(r.returncode, 3)
        self.assertIn("TAG=NODE_PUBKEY", r.stderr)


class Usage(Base):
    def test_parser_usage_errors_exit_3(self):
        for args in (["status", "--state", self.state], ["collect", "--peers", "x"], ["bogus"]):
            r = subprocess.run(
                [sys.executable, "-I", PARSER, *args],
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=30,
            )
            self.assertEqual(r.returncode, 3, args)  # never 2, which status uses for FAIL


class Summary(Base):
    SUMMARY = os.path.join(ROOT, "summarize_peerwatch.py")

    def test_summary_hand_computed(self):
        rows = [
            {
                "ts": 0,
                "peers": 10,
                "peers_outbound": 6,
                "joins": 0,
                "leaves": 0,
                "gap": True,
                "status": "PASS",
                "latency_p50_ms": 100,
                "latency_p95_ms": 300,
                "ledger_agree_ratio": 1.0,
                "outbound_prefix16": 6,
                "outbound_prefix16_max_share": 0.1667,
                "links": {"sentry": 1},
                "checks": {"count": "PASS", "fixed": "PASS"},
            },
            {
                "ts": 60,
                "peers": 9,
                "peers_outbound": 5,
                "joins": 0,
                "leaves": 1,
                "gap": False,
                "status": "FAIL",
                "latency_p50_ms": 120,
                "latency_p95_ms": 900,
                "ledger_agree_ratio": 0.5,
                "outbound_prefix16": 4,
                "outbound_prefix16_max_share": 0.4,
                "churn_leaves": 1,
                "links": {"sentry": 0},
                "checks": {"count": "PASS", "fixed": "FAIL"},
            },
            {
                "ts": 300,
                "peers": 12,
                "peers_outbound": 7,
                "joins": 3,
                "leaves": 0,
                "gap": True,
                "status": "WARN",
                "latency_p50_ms": 110,
                "latency_p95_ms": 500,
                "ledger_agree_ratio": 0.75,
                "outbound_prefix16": 5,
                "outbound_prefix16_max_share": 0.25,
                "churn_joins": 3,
                "churn_leaves": 1,
                "links": {"sentry": 1},
                "checks": {"count": "WARN", "fixed": "PASS"},
            },
        ]
        h = self.dump("history-postfiatd.jsonl", "\n".join(json.dumps(r) for r in rows) + "\nnot json\n")
        r = subprocess.run(
            [sys.executable, "-I", self.SUMMARY, "--json", h],
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        s = json.loads(r.stdout)[0]
        self.assertEqual(
            (s["container"], s["samples"], s["unparsed_lines"], s["expected_samples"]), ("postfiatd", 3, 1, 6)
        )
        self.assertEqual((s["gaps_over_90s"], s["longest_gap_s"], s["rebaselines"]), (1, 240, 2))
        self.assertEqual((s["joins"], s["leaves"], s["max_churn_window_events"]), (3, 1, 4))
        self.assertEqual(s["peers_min_median_max"], [9, 10, 12])
        self.assertEqual(s["latency_p95_median_max_ms"], [500, 900])
        self.assertEqual(s["latency_p50_median_ms"], 110)
        self.assertEqual(s["ledger_agree_min_median"], [0.5, 0.75])
        self.assertEqual(s["outbound_prefix16_min"], 4)
        self.assertEqual(s["links"], {"sentry": {"samples": 3, "down_samples": 1}})
        self.assertEqual(s["check_samples"]["fixed"], {"PASS": 2, "WARN": 0, "FAIL": 1})
        self.assertEqual(s["status_samples"], {"PASS": 1, "WARN": 1, "FAIL": 1})
        r = subprocess.run(
            [sys.executable, "-I", self.SUMMARY, "--from", "60", "--to", "120", "--json", h],
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        s = json.loads(r.stdout)[0]
        self.assertEqual((s["samples"], s["expected_samples"], s["coverage"]), (1, 2, 0.5))


class StatusAndHistory(Base):
    def test_status_exit_codes(self):
        r = self.status()
        self.assertEqual(r.returncode, 4)
        self.assertIn("no peerwatch state", r.stdout)
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        self.metrics(self.collect(p, i))
        r = self.status(NOW + 10)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("RESULT: PASS", r.stdout)
        p["result"]["peers"] = [x for x in p["result"]["peers"] if x["public_key"] != SENTRY_KEY]
        self.metrics(self.collect(p, i, NOW + 60))
        r = self.status(NOW + 70, json_out=True)
        self.assertEqual(r.returncode, 2)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["status"], "FAIL")
        self.assertEqual(doc["checks"]["fixed"], {"result": "FAIL", "detail": "down: sentry"})
        p["result"]["peers"][0]["latency"] = 2000  # WARN only once the link is back
        p["result"]["peers"].append(load("validator-peers.json")["result"]["peers"][0] | {"public_key": SENTRY_KEY})
        self.metrics(self.collect(p, i, NOW + 120))
        self.assertEqual(self.status(NOW + 130).returncode, 1)
        r = self.status(NOW + 120 + 301)
        self.assertEqual(r.returncode, 4)
        self.assertIn("STALE", r.stdout)
        self.assertEqual(self.status(NOW + 120 + 300).returncode, 1)

    def test_history_bounded(self):
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\nHISTORY_MAX=10\n")
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        for n in range(15):
            self.metrics(self.collect(p, i, NOW + 60 * n))
        with open(self.hist, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 10)
        self.assertEqual(json.loads(lines[0])["ts"], NOW + 60 * 5)
        self.assertEqual(json.loads(lines[-1])["ts"], NOW + 60 * 14)

    def test_events_bounded_by_window(self):
        self.write_conf("COUNT_PRIVATE_OUTBOUND=1\nCHURN_WINDOW_MIN=5\n")
        p, i = load("validator-peers.json"), load("validator-server_info.json")
        q = copy.deepcopy(p)
        q["result"]["peers"] = p["result"]["peers"][1:]
        for n in range(20):
            self.metrics(self.collect(p if n % 2 else q, i, NOW + 60 * n))
        with open(self.state, encoding="utf-8") as f:
            ev = json.load(f)["events"]
        self.assertLessEqual(len(ev), 6)
        self.assertTrue(all(NOW + 60 * 19 - e[0] <= 300 for e in ev))

    def test_no_addresses_or_keys_in_metrics(self):
        r = self.collect(load("validator-peers.json"), load("validator-server_info.json"))
        self.assertIsNone(re.search(r"\b10\.\d+\.\d+\.\d+", r.stdout))  # no (mapped) address
        self.assertNotIn("n9Fixture", r.stdout)
        self.assertNotIn(SENTRY_KEY, r.stdout)


class Shell(Base):
    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.d, "bin")
        os.makedirs(self.bin)
        self.tf = os.path.join(self.d, "textfile")
        self.sd = os.path.join(self.d, "state")
        os.makedirs(self.tf)
        os.makedirs(self.sd)
        self.docker = os.path.join(self.bin, "docker")
        shutil.copy(os.path.join(FIX, "validator-peers.json"), os.path.join(self.d, "peers.json"))
        shutil.copy(os.path.join(FIX, "validator-server_info.json"), os.path.join(self.d, "info.json"))
        self.stub("ok")

    def stub(self, mode):
        # docker exec NAME curl ... -d BODY URL: answer from the fixture matching the method in BODY
        with open(self.docker, "w", encoding="utf-8") as f:
            f.write(
                f"""#!/bin/bash
echo "$*" >> "{self.d}/docker.calls"
[ "$1" = exec ] || exit 9
case "{mode}" in fail) echo "Error: No such container: $2" >&2; exit 1 ;; warn) echo "WARNING: Error loading config file" >&2 ;; esac
case "$*" in *'"method":"peers"'*) cat "{self.d}/peers.json" ;; *'"method":"server_info"'*) cat "{self.d}/info.json" ;; *) exit 8 ;; esac
"""
            )
        os.chmod(self.docker, 0o755)

    def run_sh(self, *args, env_extra=None):
        env = {
            "PATH": os.environ["PATH"],
            "PFT_PW_CONF": os.path.join(self.d, "no-conf"),
            "PFT_PW_DOCKER": self.docker,
            "PFT_PW_PARSER": PARSER,
            "PFT_PW_NOW": str(NOW),
            "TEXTFILE_DIR": self.tf,
            "STATE_DIR": self.sd,
        }
        env.update(env_extra or {})
        return subprocess.run(
            ["bash", SCRIPT, *args],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            stdin=subprocess.DEVNULL,
            timeout=60,
        )

    def test_stub_answers(self):
        r = subprocess.run(
            [self.docker, "exec", "x", "curl", '{"method":"peers"}'], check=False, capture_output=True, text=True
        )
        self.assertIn("n9Fixture", r.stdout)  # the stub, not a real docker, answered

    def test_collect_writes_textfile(self):
        r = self.run_sh("collect", "--container", "postfiatd")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tf, "pft_peerwatch_postfiatd.prom"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn('pft_peerwatch_up{container="postfiatd"} 1', text)
        self.assertIn(f'pft_peerwatch_collect_timestamp_seconds{{container="postfiatd"}} {NOW}', text)
        self.assertIn('pft_peerwatch_fixed_link_up{container="postfiatd",link="sentry"} 1', text)
        self.assertEqual(
            self.run_sh("validate", os.path.join(self.tf, "pft_peerwatch_postfiatd.prom"), "postfiatd").returncode, 0
        )
        with open(os.path.join(self.d, "docker.calls"), encoding="utf-8") as f:
            calls = f.read().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(c.startswith("exec postfiatd curl -s --max-time 8 ") for c in calls), calls)
        self.assertTrue(os.path.exists(os.path.join(self.sd, "state-postfiatd.json")))
        self.assertTrue(os.path.exists(os.path.join(self.sd, "history-postfiatd.jsonl")))
        self.assertEqual([x for x in os.listdir(self.sd) if x.startswith(".")], [])  # work dir removed
        r = self.run_sh("status", "--container", "postfiatd")
        self.assertEqual(r.returncode, 0)
        self.assertIn("RESULT: PASS", r.stdout)

    def test_conf_not_root_owned_ignored(self):
        conf = os.path.join(self.d, "user.env")
        with open(conf, "w", encoding="utf-8") as f:
            f.write("CONTAINER=evil\n")
        self.assertNotEqual(os.stat(conf).st_uid, 0)
        r = self.run_sh("collect", env_extra={"PFT_PW_CONF": conf})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.tf, "pft_peerwatch_postfiatd.prom")))
        self.assertFalse(os.path.exists(os.path.join(self.tf, "pft_peerwatch_evil.prom")))

    def test_status_json_via_shell(self):
        self.assertEqual(self.run_sh("collect").returncode, 0)
        r = self.run_sh("status", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(
            (doc["status"], doc["container"], doc["checks"]["fixed"]["result"]), ("PASS", "postfiatd", "PASS")
        )

    def test_docker_warning_not_glued(self):
        self.stub("warn")
        r = self.run_sh("collect", "--container", "postfiatd")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_collect_failure_up0_only(self):
        self.assertEqual(self.run_sh("collect").returncode, 0)
        self.stub("fail")
        r = self.run_sh("collect", env_extra={"PFT_PW_NOW": str(NOW + 60)})
        self.assertEqual(r.returncode, 1)
        self.assertIn("peers via docker exec postfiatd failed: Error: No such container", r.stderr)
        with open(os.path.join(self.tf, "pft_peerwatch_postfiatd.prom"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn('pft_peerwatch_up{container="postfiatd"} 0', text)
        self.assertEqual(
            [x for x in text.splitlines() if x and not x.startswith("#")],
            [
                'pft_peerwatch_up{container="postfiatd"} 0',
                f'pft_peerwatch_collect_timestamp_seconds{{container="postfiatd"}} {NOW + 60}',
            ],
        )

    def test_parser_reject_up0(self):
        with open(os.path.join(self.d, "info.json"), "w", encoding="utf-8") as f:
            f.write('{"result": {"status": "error", "error": "noNetwork"}}')
        r = self.run_sh("collect", "--stdout")
        self.assertEqual(r.returncode, 1)
        self.assertIn('pft_peerwatch_up{container="postfiatd"} 0', r.stdout)
        self.assertIn("noNetwork", r.stderr)

    def test_bad_names_and_usage(self):
        self.assertEqual(self.run_sh("collect", "--container", "x;rm").returncode, 3)
        self.assertEqual(self.run_sh("bogus").returncode, 3)
        self.assertEqual(self.run_sh("status", "--container", "../x").returncode, 3)
        r = self.run_sh("collect", env_extra={"RPC_TIMEOUT": "0"})
        self.assertEqual(r.returncode, 3)

    def test_status_no_state(self):
        r = self.run_sh("status")
        self.assertEqual(r.returncode, 4)

    def validate(self, text, name="postfiatd-sentry"):
        p = os.path.join(self.d, "v.prom")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return self.run_sh("validate", p, name)

    def test_validate(self):
        good = 'pft_peerwatch_up{container="postfiatd-sentry"} 1\npft_peerwatch_collect_timestamp_seconds{container="postfiatd-sentry"} 1\n'
        self.assertEqual(self.validate(good).returncode, 0)
        r = self.validate(good.replace("postfiatd-sentry", "postfiatd", 1))
        self.assertEqual(r.returncode, 2)
        self.assertIn("first label is not", r.stdout)
        r = self.validate(good + "node_load1 3\n")
        self.assertIn("not a pft_peerwatch_ sample", r.stdout)
        r = self.validate(good + 'node_load1{container="postfiatd-sentry"} 3\n')  # well-formed, foreign name
        self.assertEqual(r.returncode, 2)
        self.assertIn("line 3: not a pft_peerwatch_ sample", r.stdout)
        r = self.validate(good + 'pft_peerwatch_status{container="postfiatd-sentry"} x\n')
        self.assertIn("malformed sample", r.stdout)
        r = self.validate('pft_peerwatch_up{container="postfiatd-sentry"} 1\n')
        self.assertIn("no pft_peerwatch_collect_timestamp_seconds", r.stdout)
        r = self.validate('pft_peerwatch_collect_timestamp_seconds{container="postfiatd-sentry"} 1\n')
        self.assertEqual(r.returncode, 2)
        self.assertIn("no pft_peerwatch_up sample", r.stdout)
        r = self.validate(good + "#" * 20000 + "\n")
        self.assertIn("too big", r.stdout)

    def test_pull(self):
        remote = os.path.join(self.d, "remote")
        os.makedirs(remote)
        good = 'pft_peerwatch_up{container="postfiatd-sentry"} 1\npft_peerwatch_collect_timestamp_seconds{container="postfiatd-sentry"} 5\n'
        with open(os.path.join(remote, "pft_peerwatch_postfiatd-sentry.prom"), "w", encoding="utf-8") as f:
            f.write(good)
        env = {"PULL_SSH": "env", "REMOTE_DIR": remote}
        r = self.run_sh("pull", env_extra=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        dst = os.path.join(self.tf, "pft_peerwatch_postfiatd-sentry.prom")
        with open(dst, encoding="utf-8") as f:
            self.assertEqual(f.read(), good)
        with open(os.path.join(remote, "pft_peerwatch_postfiatd-sentry.prom"), "w", encoding="utf-8") as f:
            f.write("garbage\n")
        r = self.run_sh("pull", env_extra=env)
        self.assertEqual(r.returncode, 2)
        with open(dst, encoding="utf-8") as f:
            self.assertEqual(f.read(), good)  # old copy kept
        self.assertEqual(self.run_sh("pull").returncode, 3)  # PULL_SSH unset
        r = self.run_sh("pull", env_extra={"PULL_SSH": "false", "REMOTE_DIR": remote})
        self.assertEqual(r.returncode, 1)
        self.assertEqual([x for x in os.listdir(self.tf) if x.startswith(".")], [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
