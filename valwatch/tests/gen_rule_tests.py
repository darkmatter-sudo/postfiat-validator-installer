#!/usr/bin/env python3
"""Generate alerts/valwatch.tests.yml: hand-written series and eval times, annotation text taken from the rules
with the labels and values filled in, so every case asserts the exact annotations.
Run from the repo root: python3 valwatch/tests/gen_rule_tests.py > alerts/valwatch.tests.yml

Series are per minute (promtool `a+bxN` = N+1 samples, t = 0..N min). Healthy values are the 2026-11-18 captures
of both hosts: participation 1.0 (0.975 worst), p95 delay up to ~1.6 s, quorum margin 8 (25 UNL, quorum 17).
"""

import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(ROOT, "alerts", "valwatch.rules.yml"), encoding="utf-8") as f:
    R = {r["alert"]: r for r in yaml.safe_load(f)["groups"][0]["rules"]}
BASE = {"job": "postfiat", "instance": "node:9877"}
V, SN = "postfiatd", "postfiatd-sentry"
K1, K2 = "nHB6Zc7mhr7swksEgpwTE7Hw7SvZ9cz22T2MECMSXjBeMTeHXQB7", "nHUCEXpC5LhFAm1Mmf8TqrzVGt3QCuwWoW2V8PYynDpjZe8m8mHj"
P = "pft_valwatch_"
N = 60  # minutes per test


def ann(alert, value=None, **lab):
    out = {}
    for k, v in R[alert]["annotations"].items():
        for lk, lv in lab.items():
            v = v.replace("{{ $labels." + lk + " }}", lv)
        if value is not None:
            v = v.replace("{{ $value | humanizePercentage }}", value).replace("{{ $value }}", value)
        out[k] = v
    return out


def S(metric, values, **lab):
    labels = dict(BASE, **lab)
    return {"series": P + metric + "{" + ", ".join(f'{k}="{v}"' for k, v in labels.items()) + "}", "values": values}


def exp(alert, value, sev="warning", **lab):
    labels = dict(BASE, **lab)
    labels["severity"] = sev
    return {"exp_labels": labels, "exp_annotations": ann(alert, value, **lab)}


def node(n, over=None):
    """Healthy series for node n; `over` replaces values by metric (or metric,validator) key."""
    over = over or {}
    base = {
        "up": "1x60",
        "collect_timestamp_seconds": "0+60x60",
        "last_record_age_seconds": "2x60",
        "quorum_margin_min": "8x60",
        "quorum_margin_p50": "8x60",
        "reconnects": "0x60",
        ("validator_participation_ratio", K1): "1x60",
        ("validator_participation_ratio", K2): "0.975x60",
        ("validator_delay_p95_ms", K1): "9x60",
        ("validator_delay_p95_ms", K2): "1586x60",
    }
    base.update(over)
    out = []
    for key, vals in base.items():
        if isinstance(key, tuple):
            out.append(S(key[0], vals, node=n, validator=key[1]))
        else:
            out.append(S(key, vals, node=n))
    return out


def case(name, series, alerts):
    """alerts: list of (eval_min, alertname, [exp...])"""
    return {
        "name": name,
        "interval": "1m",
        "input_series": series,
        "alert_rule_test": [{"eval_time": f"{t}m", "alertname": a, "exp_alerts": e} for t, a, e in alerts],
    }


ALL = list(R)
tests = [
    case(
        "healthy validator and sentry for 1h fire nothing (0.975 participation, 1586 ms p95, margin 8)",
        node(V) + node(SN),
        [(m, a, []) for a in ALL for m in (16, 59)],
    ),
    case(
        "validator K1 at 70% on the sentry only: fires after 15m there, not on the validator",
        node(V) + node(SN, {("validator_participation_ratio", K1): "0.7x60"}),
        [
            (14, "PFTValwatchValidatorLow", []),
            (16, "PFTValwatchValidatorLow", [exp("PFTValwatchValidatorLow", "70%", node=SN, validator=K1)]),
        ],
    ),
    case(
        "participation exactly 0.8 does not fire (boundary)",
        node(V, {("validator_participation_ratio", K1): "0.8x60"}),
        [(30, "PFTValwatchValidatorLow", [])],
    ),
    case(
        "recovery: 0.5 for 20m then 1.0 -> fired, then resolved",
        node(V, {("validator_participation_ratio", K1): "0.5x19 1x40"}),
        [
            (17, "PFTValwatchValidatorLow", [exp("PFTValwatchValidatorLow", "50%", node=V, validator=K1)]),
            (21, "PFTValwatchValidatorLow", []),
        ],
    ),
    case(
        "low participation while up=0 is not graded (Stale fires instead)",
        node(V, {"up": "0x60", ("validator_participation_ratio", K1): "0.1x60"}),
        [(20, "PFTValwatchValidatorLow", []), (11, "PFTValwatchStale", [exp("PFTValwatchStale", None, node=V)])],
    ),
    case(
        "late validator: p95 3500 ms fires after 15m; 3000 ms does not",
        node(V, {("validator_delay_p95_ms", K2): "3500x60"}) + node(SN, {("validator_delay_p95_ms", K2): "3000x60"}),
        [
            (14, "PFTValwatchValidatorLate", []),
            (16, "PFTValwatchValidatorLate", [exp("PFTValwatchValidatorLate", "3500", node=V, validator=K2)]),
        ],
    ),
    case(
        "quorum margin 1 fires after 10m; margin 2 on the other host does not",
        node(V, {"quorum_margin_min": "1x60"}) + node(SN, {"quorum_margin_min": "2x60"}),
        [
            (9, "PFTValwatchQuorumMarginLow", []),
            (11, "PFTValwatchQuorumMarginLow", [exp("PFTValwatchQuorumMarginLow", "1", node=V)]),
        ],
    ),
    case(
        "median margin 0 is critical after 5m; median 1 is not",
        node(V, {"quorum_margin_p50": "0x60", "quorum_margin_min": "0x60"}) + node(SN, {"quorum_margin_p50": "1x60"}),
        [
            (4, "PFTValwatchQuorumMarginCritical", []),
            (
                6,
                "PFTValwatchQuorumMarginCritical",
                [exp("PFTValwatchQuorumMarginCritical", "0", sev="critical", node=V)],
            ),
        ],
    ),
    case(
        "textfile stops updating (timer dead): Stale after 5 min old + 10m",
        node(V, {"collect_timestamp_seconds": "0+60x20 1200x40"}),
        [(25, "PFTValwatchStale", []), (36, "PFTValwatchStale", [exp("PFTValwatchStale", None, node=V)])],
    ),
    case(
        "stream silent (last record 400 s old) -> Stale; 300 s is not",
        node(V, {"last_record_age_seconds": "400x60"}) + node(SN, {"last_record_age_seconds": "300x60"}),
        [(9, "PFTValwatchStale", []), (11, "PFTValwatchStale", [exp("PFTValwatchStale", None, node=V)])],
    ),
    case(
        "4 reconnects per window fires after 15m; 3 does not",
        node(V, {"reconnects": "4x60"}) + node(SN, {"reconnects": "3x60"}),
        [
            (14, "PFTValwatchReconnecting", []),
            (16, "PFTValwatchReconnecting", [exp("PFTValwatchReconnecting", "4", node=V)]),
        ],
    ),
]
# Stale's description has no $value; drop None placeholders the replacement left untouched
doc = {"rule_files": ["valwatch.rules.yml"], "evaluation_interval": "1m", "tests": tests}
sys.stdout.write(
    "# promtool unit tests for valwatch.rules.yml (annotations copied from the rules with the labels filled in).\n"
)
sys.stdout.write("# Generated by ../valwatch/tests/gen_rule_tests.py. Run: promtool test rules valwatch.tests.yml\n")
yaml.safe_dump(doc, sys.stdout, sort_keys=False, width=1000)
