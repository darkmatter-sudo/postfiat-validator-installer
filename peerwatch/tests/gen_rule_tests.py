#!/usr/bin/env python3
"""Generate alerts/peerwatch.tests.yml: hand-written series and eval times, annotation text taken from the rules
with the labels filled in, so every case asserts the exact annotations.
Run from the repo root: python3 peerwatch/tests/gen_rule_tests.py > alerts/peerwatch.tests.yml
"""

import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(ROOT, "alerts", "peerwatch.rules.yml"), encoding="utf-8") as f:
    R = {r["alert"]: r for r in yaml.safe_load(f)["groups"][0]["rules"]}
BASE = {"job": "postfiat", "instance": "node:9877"}
C, CS = "postfiatd", "postfiatd-sentry"
CHECKS = ("count", "churn", "latency", "versions", "direction", "diversity", "ledgers", "fixed")


def ann(alert, **lab):
    out = {}
    for k, v in R[alert]["annotations"].items():
        for lk, lv in lab.items():
            v = v.replace("{{ $labels." + lk + " }}", lv)
        out[k] = v
    return out


def S(metric, values, **lab):
    labels = dict(BASE, **lab)
    return {"series": metric + "{" + ", ".join(f'{k}="{v}"' for k, v in labels.items()) + "}", "values": values}


def exp(alert, sev, **lab):
    labels = dict(BASE, **lab)
    labels["severity"] = sev
    return {"exp_labels": labels, "exp_annotations": ann(alert, **lab)}


class NoAlias(yaml.SafeDumper):  # expected-alert dicts are reused; write them out in full, no &id anchors
    def ignore_aliases(self, data):
        return True


def case(alert, t, *alerts):
    return {"eval_time": t, "alertname": alert, "exp_alerts": list(alerts)}


healthy = [
    S("pft_peerwatch_up", "1x120", container=C),
    S("pft_peerwatch_collect_timestamp_seconds", "0+60x120", container=C),
    S("pft_peerwatch_fixed_link_up", "1x120", container=C, link="sentry"),
] + [S("pft_peerwatch_check_status", "0x120", container=C, check=c) for c in CHECKS]
healthy += [S("pft_peerwatch_check_status", "1x120", container=C, check="diversity2")]
L = exp("PFTPeerFixedLinkDown", "critical", container=CS, link="validator")
Q = exp("PFTPeerQualityDegraded", "warning", container=C, check="latency")
T = exp("PFTPeerwatchStale", "warning", container=C)
TS = exp("PFTPeerwatchStale", "warning", container=CS)
tests = [
    {
        "name": "healthy node for 2h (WARN grades included) fires nothing",
        "interval": "1m",
        "input_series": healthy,
        "alert_rule_test": [case(a, t) for t in ("60m", "120m") for a in R],
    },
    {
        "name": "fixed link down: pending 2m, fires at 3m, recovers when the link is back",
        "interval": "1m",
        "input_series": [
            S("pft_peerwatch_fixed_link_up", "1x10 0x10 1x20", container=CS, link="validator"),
            S("pft_peerwatch_fixed_link_up", "1x40", container=C, link="sentry"),
        ],
        "alert_rule_test": [
            case("PFTPeerFixedLinkDown", "13m"),
            case("PFTPeerFixedLinkDown", "14m", L),
            case("PFTPeerFixedLinkDown", "21m", L),
            case("PFTPeerFixedLinkDown", "22m"),
            case("PFTPeerFixedLinkDown", "40m"),
        ],
    },
    {
        "name": "a check FAIL for 15m fires for that check only; fixed FAIL is left to PFTPeerFixedLinkDown; "
        "WARN never fires",
        "interval": "1m",
        "input_series": [
            S("pft_peerwatch_check_status", "0x10 2x20 0x10", container=C, check="latency"),
            S("pft_peerwatch_check_status", "2x40", container=C, check="fixed"),
            S("pft_peerwatch_check_status", "1x40", container=C, check="churn"),
            S("pft_peerwatch_check_status", "0x10 2x14 0 2x15", container=C, check="ledgers"),
        ],
        "alert_rule_test": [
            case("PFTPeerQualityDegraded", "25m"),
            case("PFTPeerQualityDegraded", "26m", Q),
            case("PFTPeerQualityDegraded", "30m", Q),
            case("PFTPeerQualityDegraded", "32m"),
            case("PFTPeerQualityDegraded", "40m"),
        ],
    },
    {
        "name": "collector up 0: fires after 5m, recovers on the first good sample",
        "interval": "1m",
        "input_series": [
            S("pft_peerwatch_up", "1x10 0x10 1x20", container=C),
            S("pft_peerwatch_collect_timestamp_seconds", "0+60x40", container=C),
        ],
        "alert_rule_test": [
            case("PFTPeerwatchStale", "15m"),
            case("PFTPeerwatchStale", "16m", T),
            case("PFTPeerwatchStale", "22m"),
        ],
    },
    {
        "name": "pull stopped (timestamp frozen at 10m, up still 1): stale after 5 min + 5m for, recovers when it "
        "moves again",
        "interval": "1m",
        "input_series": [
            S("pft_peerwatch_up", "1x60", container=CS),
            S("pft_peerwatch_collect_timestamp_seconds", "0+60x10 600x20 1860+60x29", container=CS),
        ],
        "alert_rule_test": [
            case("PFTPeerwatchStale", "20m"),
            case("PFTPeerwatchStale", "21m", TS),
            case("PFTPeerwatchStale", "30m", TS),
            case("PFTPeerwatchStale", "32m"),
        ],
    },
]
sys.stdout.write(
    "# promtool unit tests for peerwatch.rules.yml (annotations copied from the rules with the labels filled in).\n"
    "# Run: promtool test rules peerwatch.tests.yml\n"
)
yaml.dump(
    {"rule_files": ["peerwatch.rules.yml"], "evaluation_interval": "1m", "tests": tests},
    sys.stdout,
    Dumper=NoAlias,
    sort_keys=False,
    width=200,
)
