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
    labels.update({k: v for k, v in R[alert]["labels"].items() if k != "severity"})  # notify="digest"
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
            (14, "PFTValwatchHostsDisagree", []),
            (16, "PFTValwatchHostsDisagree", [exp("PFTValwatchHostsDisagree", "70%", node=SN, validator=K1)]),
        ],
    ),
    case(
        "validator K1 silent on BOTH hosts (2026-11-19 external outage): digest-only ValidatorLow, no HostsDisagree",
        node(V, {("validator_participation_ratio", K1): "0x60"})
        + node(SN, {("validator_participation_ratio", K1): "0x60"}),
        [
            (
                16,
                "PFTValwatchValidatorLow",
                [
                    exp("PFTValwatchValidatorLow", "0%", node=V, validator=K1),
                    exp("PFTValwatchValidatorLow", "0%", node=SN, validator=K1),
                ],
            ),
            (16, "PFTValwatchHostsDisagree", []),
            (59, "PFTValwatchHostsDisagree", []),
        ],
    ),
    case(
        "HostsDisagree needs >= 95% on the other node: 0.95 fires, 0.9499 does not",
        node(V, {("validator_participation_ratio", K1): "0.5x60", ("validator_participation_ratio", K2): "0.5x60"})
        + node(
            SN, {("validator_participation_ratio", K1): "0.95x60", ("validator_participation_ratio", K2): "0.9499x60"}
        ),
        [(16, "PFTValwatchHostsDisagree", [exp("PFTValwatchHostsDisagree", "50%", node=V, validator=K1)])],
    ),
    case(
        "HostsDisagree is not graded when the other node is blind (up 0): Stale fires there instead",
        node(V, {("validator_participation_ratio", K1): "0.5x60"}) + node(SN, {"up": "0x60"}),
        [(30, "PFTValwatchHostsDisagree", [])],
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
            (30, "PFTValwatchHostsDisagreeLate", []),
        ],
    ),
    case(
        "HostsDisagreeLate: 3500 ms at the validator vs 2000 ms at the sentry fires after 15m; vs 2001 ms does not",
        node(V, {("validator_delay_p95_ms", K1): "3500x60", ("validator_delay_p95_ms", K2): "3500x60"})
        + node(SN, {("validator_delay_p95_ms", K1): "2000x60", ("validator_delay_p95_ms", K2): "2001x60"}),
        [
            (14, "PFTValwatchHostsDisagreeLate", []),
            (16, "PFTValwatchHostsDisagreeLate", [exp("PFTValwatchHostsDisagreeLate", "3500", node=V, validator=K1)]),
        ],
    ),
    case(
        "late on BOTH hosts (external validator slow): digest-only ValidatorLate, no HostsDisagreeLate",
        node(V, {("validator_delay_p95_ms", K2): "5000x60"}) + node(SN, {("validator_delay_p95_ms", K2): "4000x60"}),
        [
            (
                16,
                "PFTValwatchValidatorLate",
                [
                    exp("PFTValwatchValidatorLate", "5000", node=V, validator=K2),
                    exp("PFTValwatchValidatorLate", "4000", node=SN, validator=K2),
                ],
            ),
            (30, "PFTValwatchHostsDisagreeLate", []),
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

# Cross-host skew (2026-11-26): the sentry textfile reaches Prometheus up to 66 s after the validator's
# (../valwatch/logs/21-skew-replay.log), so a change seen by BOTH nodes first shows on one node only. These cases run
# at 15 s samples (the live scrape and evaluation interval) and assert the rules' own ALERTS series step by step with
# promql_expr_test (alert_rule_test cannot see pending alerts; ALERTS{alertstate="pending"} can). OLD_* are the instant
# expressions of 496470f: each skew case also asserts the old expression matched there, so the fixture really
# reproduces the false pending.
OLD_LATE = (
    "(pft_valwatch_validator_delay_p95_ms > 3000 and on (job, instance, node) pft_valwatch_up == 1)"
    " and on (validator)"
    " (pft_valwatch_validator_delay_p95_ms <= 2000 and on (job, instance, node) pft_valwatch_up == 1)"
)
OLD_DIS = (
    "(pft_valwatch_validator_participation_ratio < 0.8 and on (job, instance, node) pft_valwatch_up == 1)"
    " and on (validator)"
    " (pft_valwatch_validator_participation_ratio >= 0.95 and on (job, instance, node) pft_valwatch_up == 1)"
)
NEW = {a: f'ALERTS{{alertname="{a}"}}' for a in ("PFTValwatchHostsDisagree", "PFTValwatchHostsDisagreeLate")}
Q = 240  # 15 s samples in 60 min (Q + 1 samples, t = 0 .. 60m)
LAT, PART = "validator_delay_p95_ms", "validator_participation_ratio"


def runs(vals):
    """Per-sample values -> promtool notation ('a' repeated n times = 'axN-1')."""
    out, i = [], 0
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and vals[j + 1] == vals[i]:
            j += 1
        out.append(f"{vals[i]}x{j - i}")
        i = j + 1
    return " ".join(out)


def step(good, bad, start=None, end=None, spike=None):
    """Q + 1 samples: `bad` in [start, end) (sample indexes), else `good`; `spike` = {index: value}."""
    v = [bad if (start is not None and i >= start and (end is None or i < end)) else good for i in range(Q + 1)]
    for i, x in (spike or {}).items():
        v[i] = x
    return runs(v)


def node15(n, metric, values):
    """Healthy node at 15 s samples; `values` replaces K1's series of `metric`."""
    base = {
        "up": f"1x{Q}",
        "collect_timestamp_seconds": f"0+15x{Q}",
        "last_record_age_seconds": f"2x{Q}",
        "quorum_margin_min": f"8x{Q}",
        "quorum_margin_p50": f"8x{Q}",
        "reconnects": f"0x{Q}",
        (PART, K1): f"1x{Q}",
        (LAT, K1): f"9x{Q}",
    }
    base[(metric, K1)] = values
    return [S(k[0], v, node=n, validator=k[1]) if isinstance(k, tuple) else S(k, v, node=n) for k, v in base.items()]


def ts(sec):
    return f"{sec // 60}m{sec % 60}s" if sec % 60 else f"{sec // 60}m"


def sample(metric, n, value, named):
    """Old-expression control sample (named: the metric itself, value = the series value)."""
    lab = dict(BASE, node=n, validator=K1)
    body = "{" + ", ".join(f'{k}="{v}"' for k, v in sorted(lab.items())) + "}"
    return {"labels": (P + metric if named else "") + body, "value": value}


def alerts_row(alert, n, state="pending"):
    """ALERTS{...} sample of `alert` for K1 at node n (value 1)."""
    lab = dict(BASE, node=n, validator=K1, alertname=alert, alertstate=state, severity="warning")
    return {"labels": "ALERTS{" + ", ".join(f'{k}="{v}"' for k, v in sorted(lab.items())) + "}", "value": 1}


def case15(name, series, exprs, alerts=()):
    """exprs: list of (eval_sec, expr, [samples]); alerts: list of (eval_sec, alertname, [exp...])."""
    out = {"name": name, "interval": "15s", "input_series": series}
    out["promql_expr_test"] = [{"expr": e, "eval_time": ts(t), "exp_samples": smp} for t, e, smp in exprs]
    if alerts:
        out["alert_rule_test"] = [{"eval_time": ts(t), "alertname": a, "exp_alerts": e} for t, a, e in alerts]
    return out


KINDS = (
    # alert, metric, healthy, faulty, old expression, faulty value as $value renders it
    ("PFTValwatchHostsDisagreeLate", LAT, 1586, 3500, OLD_LATE, "3500"),
    ("PFTValwatchHostsDisagree", PART, 1, 0.5, OLD_DIS, "50%"),
)
T0 = 40  # sample index of the change: 10m
T1 = 120  # 30m
for alert, metric, good, bad, old, shown in KINDS:
    for lag in (15, 30, 60, 90):
        k = lag // 15
        # onset: the validator turns faulty at 10m, the sentry `lag` s later (both see the same faulty validator)
        tests.append(
            case15(
                f"{alert} skew onset: K1 faulty on both nodes, sentry sample {lag} s behind -> new expr empty "
                f"10m .. {ts(T0 * 15 + lag + 150)}; old instant expr matched at 10m (validator side)",
                node15(V, metric, step(good, bad, T0)) + node15(SN, metric, step(good, bad, T0 + k)),
                [(T0 * 15, old, [sample(metric, V, bad, True)])]
                + [(t, NEW[alert], []) for t in range(T0 * 15, T0 * 15 + lag + 165, 15)],
                [(26 * 60, alert, []), (45 * 60, alert, [])],
            )
        )
        # recovery: faulty on both from 0, the validator recovers at 30m, the sentry `lag` s later
        tests.append(
            case15(
                f"{alert} skew recovery: K1 recovers at 30m on the validator, {lag} s later on the sentry -> new "
                f"expr empty 30m .. {ts(T1 * 15 + lag + 150)}; old instant expr matched at 30m (sentry side)",
                node15(V, metric, step(good, bad, 0, T1)) + node15(SN, metric, step(good, bad, 0, T1 + k)),
                [(T1 * 15, old, [sample(metric, SN, bad, True)])]
                + [(t, NEW[alert], []) for t in range(T1 * 15, T1 * 15 + lag + 165, 15)],
            )
        )
    # real one-node fault: faulty on the validator from 10m, sentry healthy throughout. Hand-computed: the [2m]
    # window (left-open in Prometheus 3) holds only faulty samples from 11m45s (9m45s, the last healthy one, drops
    # out), so the expression first matches at 11m45s; for 15m -> firing at 26m45s (old instant rule: 25m00s).
    tests.append(
        case15(
            f"{alert} real one-node fault from 10m (sentry healthy): expr matches from 11m45s, fires at 26m45s",
            node15(V, metric, step(good, bad, T0)) + node15(SN, metric, step(good, good)),
            [(11 * 60 + 30, NEW[alert], []), (11 * 60 + 45, NEW[alert], [alerts_row(alert, V)])],
            [
                (26 * 60 + 30, alert, []),
                (26 * 60 + 45, alert, [exp(alert, shown, node=V, validator=K1)]),
                (59 * 60, alert, [exp(alert, shown, node=V, validator=K1)]),
            ],
        )
    )
    # a lag longer than the window is a real disagreement: lag 120 s matches for exactly one step (11m45s)
    tests.append(
        case15(
            f"{alert} boundary: lag 120 s exceeds the 2m window -> matches at 11m45s only",
            node15(V, metric, step(good, bad, T0)) + node15(SN, metric, step(good, bad, T0 + 8)),
            [
                (11 * 60 + 30, NEW[alert], []),
                (11 * 60 + 45, NEW[alert], [alerts_row(alert, V)]),
                (12 * 60, NEW[alert], []),
            ],
        )
    )
    # window length: one off-value sample at 20m on the HEALTHY side blocks exactly 20m .. 21m45s
    off = 2500 if metric == LAT else 0.9
    tests.append(
        case15(
            f"{alert} window boundary (healthy side): one {off} sample at 20m on the sentry blocks 20m .. 21m45s",
            node15(V, metric, step(good, bad, 0)) + node15(SN, metric, step(good, good, spike={80: off})),
            [
                (19 * 60 + 45, NEW[alert], [alerts_row(alert, V, "firing")]),
                (20 * 60, NEW[alert], []),
                (21 * 60 + 45, NEW[alert], []),
                (22 * 60, NEW[alert], [alerts_row(alert, V)]),
            ],
        )
    )
    # ... and on the FAULTY side (one in-between sample at 20m on the validator)
    dip = 2500 if metric == LAT else 0.9
    tests.append(
        case15(
            f"{alert} window boundary (faulty side): one {dip} sample at 20m on the validator blocks 20m .. 21m45s",
            node15(V, metric, step(good, bad, 0, spike={80: dip})) + node15(SN, metric, step(good, good)),
            [
                (19 * 60 + 45, NEW[alert], [alerts_row(alert, V, "firing")]),
                (20 * 60, NEW[alert], []),
                (21 * 60 + 45, NEW[alert], []),
                (22 * 60, NEW[alert], [alerts_row(alert, V)]),
            ],
        )
    )
# thresholds over the window: 3001 ms fires, 3000 ms does not; 0.7999 fires, 0.8 does not (other node healthy)
for alert, metric, hit, miss, shown in (
    ("PFTValwatchHostsDisagreeLate", LAT, 3001, 3000, "3001"),
    ("PFTValwatchHostsDisagree", PART, 0.7999, 0.8, "79.99%"),
):
    for val, fires in ((hit, True), (miss, False)):
        tests.append(
            case15(
                f"{alert} threshold: {val} on the validator for 60m (sentry healthy) "
                + ("fires at 15m" if fires else "never matches"),
                node15(V, metric, step(val, val)) + node15(SN, metric, step(9 if metric == LAT else 1, 0)),
                [(30 * 60, NEW[alert], [alerts_row(alert, V, "firing")] if fires else [])],
                [
                    (14 * 60 + 45, alert, []),
                    (15 * 60, alert, [exp(alert, shown, node=V, validator=K1)] if fires else []),
                ],
            )
        )
# Stale's description has no $value; drop None placeholders the replacement left untouched
doc = {"rule_files": ["valwatch.rules.yml"], "evaluation_interval": "15s", "tests": tests}
sys.stdout.write(
    "# promtool unit tests for valwatch.rules.yml (annotations copied from the rules with the labels filled in).\n"
)
sys.stdout.write("# Generated by ../valwatch/tests/gen_rule_tests.py. Run: promtool test rules valwatch.tests.yml\n")
yaml.safe_dump(doc, sys.stdout, sort_keys=False, width=1000)
