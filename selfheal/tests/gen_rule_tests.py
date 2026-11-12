#!/usr/bin/env python3
"""Generate alerts/selfheal.tests.yml: hand-written series and eval times, annotation text taken from the rules with
the labels filled in, so every case asserts the exact annotations.
Run from the repo root: python3 selfheal/tests/gen_rule_tests.py > alerts/selfheal.tests.yml
"""

import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(ROOT, "alerts", "selfheal.rules.yml"), encoding="utf-8") as f:
    R = {r["alert"]: r for r in yaml.safe_load(f)["groups"][0]["rules"]}
BASE = {"job": "postfiat", "instance": "node:9877"}
C, CS = "postfiatd", "postfiatd-sentry"


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


def node(c, n=120, breaker="0", up="1", ts=None):
    return [
        S("pft_selfheal_up", up if up != "1" else f"1x{n}", container=c),
        S("pft_selfheal_run_timestamp_seconds", ts or f"0+60x{n}", container=c),
        S("pft_selfheal_breaker_open", breaker if breaker != "0" else f"0x{n}", container=c),
    ]


B = exp("PFTSelfhealBreakerOpen", "critical", container=CS)
T = exp("PFTSelfhealStale", "warning", container=C)
TS = exp("PFTSelfhealStale", "warning", container=CS)
tests = [
    {
        "name": "healthy validator and sentry for 2h fire nothing",
        "interval": "1m",
        "input_series": node(C) + node(CS),
        "alert_rule_test": [case(a, t) for t in ("60m", "120m") for a in R],
    },
    {
        "name": "breaker opens at 10m: pending 1m, fires at 11m for the sentry only, recovers after reset (0 from 31m: 1x20 is 21 samples, 10m..30m)",
        "interval": "1m",
        "input_series": node(C, 40) + node(CS, 40, breaker="0x9 1x20 0x10"),
        "alert_rule_test": [
            case("PFTSelfhealBreakerOpen", "10m"),
            case("PFTSelfhealBreakerOpen", "11m", B),
            case("PFTSelfhealBreakerOpen", "30m", B),
            case("PFTSelfhealBreakerOpen", "31m"),
            case("PFTSelfhealBreakerOpen", "40m"),
            case("PFTSelfhealStale", "29m"),
        ],
    },
    {
        "name": "run fails (up 0 from 11m, no breaker gauge written): stale fires after 5m, breaker stays quiet, "
        "recovers on the first good run",
        "interval": "1m",
        "input_series": [
            S("pft_selfheal_up", "1x10 0x10 1x20", container=C),
            S("pft_selfheal_run_timestamp_seconds", "0+60x40", container=C),
            S("pft_selfheal_breaker_open", "0x10 _x10 0x20", container=C),
        ],
        "alert_rule_test": [
            case("PFTSelfhealStale", "15m"),
            case("PFTSelfhealStale", "16m", T),
            case("PFTSelfhealStale", "21m", T),
            case("PFTSelfhealBreakerOpen", "21m"),
            case("PFTSelfhealStale", "22m"),
        ],
    },
    {
        "name": "timer stopped (timestamp frozen at 600 from 10m, up still 1): stale after 5 min + 5m for, recovers "
        "when it moves again at 32m (600x20 is 21 samples, 11m..31m)",
        "interval": "1m",
        "input_series": node(CS, 60, ts="0+60x10 600x20 1860+60x29"),
        "alert_rule_test": [
            case("PFTSelfhealStale", "20m"),
            case("PFTSelfhealStale", "21m", TS),
            case("PFTSelfhealStale", "31m", TS),
            case("PFTSelfhealStale", "32m"),
        ],
    },
]
sys.stdout.write(
    "# promtool unit tests for selfheal.rules.yml (annotations copied from the rules with the labels filled in).\n"
    "# Run: promtool test rules selfheal.tests.yml\n"
)
yaml.dump(
    {"rule_files": ["selfheal.rules.yml"], "evaluation_interval": "1m", "tests": tests},
    sys.stdout,
    Dumper=NoAlias,
    sort_keys=False,
    width=200,
)
