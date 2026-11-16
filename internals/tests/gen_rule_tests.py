#!/usr/bin/env python3
"""Generate alerts/internals.tests.yml: hand-written series and eval times, annotation text taken from the rules
with the labels filled in, so every case asserts the exact annotations.
Run from the repo root: python3 internals/tests/gen_rule_tests.py > alerts/internals.tests.yml

Series are per minute (promtool `a+bxN` = N+1 samples, t = 0..N min). Healthy values are the 2026-11-16
calibration of the validator: 8 NodeStore reads/s at 0.25 ms, CachedView 2 lookups/s at 0.8 hit ratio.
"""

import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(ROOT, "alerts", "internals.rules.yml"), encoding="utf-8") as f:
    R = {r["alert"]: r for r in yaml.safe_load(f)["groups"][0]["rules"]}
BASE = {"job": "postfiat", "instance": "node:9877"}
C, CS = "postfiatd", "postfiatd-sentry"
P = "pft_internals_"


def ann(alert, **lab):
    out = {}
    for k, v in R[alert]["annotations"].items():
        for lk, lv in lab.items():
            v = v.replace("{{ $labels." + lk + " }}", lv)
        out[k] = v
    return out


def S(metric, values, **lab):
    labels = dict(BASE, **lab)
    return {"series": P + metric + "{" + ", ".join(f'{k}="{v}"' for k, v in labels.items()) + "}", "values": values}


def exp(alert, sev="warning", **lab):
    labels = dict(BASE, **lab)
    labels["severity"] = sev
    return {"exp_labels": labels, "exp_annotations": ann(alert, **lab)}


class NoAlias(yaml.SafeDumper):  # expected-alert dicts are reused; write them out in full, no &id anchors
    def ignore_aliases(self, data):
        return True


def case(alert, t, *alerts):
    return {"eval_time": t, "alertname": alert, "exp_alerts": list(alerts)}


def healthy(c, n):
    return [
        S("up", f"1x{n}", container=c),
        S("collect_timestamp_seconds", f"0+60x{n}", container=c),
        S("node_uptime_seconds", f"7200+60x{n}", container=c),
        S("nodestore_reads_total", f"0+480x{n}", container=c),
        S("nodestore_read_duration_seconds_total", f"0+0.12x{n}", container=c),
        S("cached_view_total", f"0+96x{n}", container=c, result="hit"),
        S("cached_view_total", f"0+24x{n}", container=c, result="miss"),
        S("job_waiting", f"0x{n}", container=c, job_type="ledgerData"),
        S("job_waiting", f"2x{n}", container=c, job_type="clientRPC"),
        S("load_job_peak_ms", f"226x{n}", container=c, job_type="trustedValidation"),
        S("load_job_peak_ms", f"4999x{n}", container=c, job_type="peerCommand"),
        S("counter_anomalies_total", f"0x{n}", container=c),
        S("node_restarts_total", f"0x{n}", container=c),
    ]


SLOW = exp("PFTInternalsNodeStoreSlow", container=C)
CACHE = exp("PFTInternalsCacheCollapse", container=C)
CACHES = exp("PFTInternalsCacheCollapse", container=CS)
BACKLOG = exp("PFTInternalsJobBacklog", container=C)
PEAK = exp("PFTInternalsJobPeak", container=C, job_type="acceptLedger")
STALE = exp("PFTInternalsStale", container=C)
STALES = exp("PFTInternalsStale", container=CS)
ANOM = exp("PFTInternalsCounterAnomaly", container=C)

tests = [
    {
        "name": "healthy validator and sentry for 2h fire nothing (peak 4999 ms stays under 5000)",
        "interval": "1m",
        "input_series": healthy(C, 120) + healthy(CS, 120),
        "alert_rule_test": [case(a, t) for t in ("30m", "60m", "120m") for a in R],
    },
    {
        # A [10m] window at t holds the samples t-9..t (left-open), i.e. 9 intervals, and rate() extrapolates both
        # counters by the same factor, so the ratio is dD/dR over those intervals. Duration +4.8 s/min = 10 ms per
        # read from t=11; with k slow intervals dD = 1.08 + 4.68k > 21.6 (dR = 4320) at k=5: true from t=15,
        # fires 15m later at t=30.
        "name": "NodeStore reads at 10 ms: true from 15m, fires at 30m (for 15m); same latency at 0.2 reads/s never fires",
        "interval": "1m",
        "input_series": [
            S("nodestore_reads_total", "0+480x60", container=C),
            S("nodestore_read_duration_seconds_total", "0+0.12x10 6+4.8x49", container=C),
            S("nodestore_reads_total", "0+12x60", container=CS),
            S("nodestore_read_duration_seconds_total", "0+0.12x60", container=CS),
        ],
        "alert_rule_test": [
            case("PFTInternalsNodeStoreSlow", "14m"),
            case("PFTInternalsNodeStoreSlow", "29m"),
            case("PFTInternalsNodeStoreSlow", "30m", SLOW),
            case("PFTInternalsNodeStoreSlow", "60m", SLOW),
        ],
    },
    {
        "name": "node restart at 31m: every counter starts over, uptime drops; rate() absorbs the reset, nothing fires",
        "interval": "1m",
        "input_series": [
            S("up", "1x80", container=C),
            S("collect_timestamp_seconds", "0+60x80", container=C),
            S("node_uptime_seconds", "7200+60x30 0+60x49", container=C),
            S("nodestore_reads_total", "0+480x30 0+480x49", container=C),
            S("nodestore_read_duration_seconds_total", "0+0.12x30 0+0.12x49", container=C),
            S("cached_view_total", "50000+96x30 0+96x49", container=C, result="hit"),
            S("cached_view_total", "12000+24x30 0+24x49", container=C, result="miss"),
            S("node_restarts_total", "0x30 1x49", container=C),
            S("counter_anomalies_total", "0x80", container=C),
        ],
        "alert_rule_test": [case(a, t) for t in ("31m", "35m", "45m", "80m") for a in R],
    },
    {
        # 0.2 hit ratio from t=31; a [15m] window holds 14 intervals: (1344 - 72k) / 1680 < 0.4 at k=10, i.e. true
        # from t=40, fires at t=70.
        "name": "CachedView hit ratio collapses to 0.2 at 30m: fires 30m after the 15m window crosses 0.4",
        "interval": "1m",
        "input_series": [
            S("node_uptime_seconds", "7200+60x100", container=C),
            S("cached_view_total", "0+96x30 2904+24x70", container=C, result="hit"),
            S("cached_view_total", "0+24x30 816+96x70", container=C, result="miss"),
        ],
        "alert_rule_test": [
            case("PFTInternalsCacheCollapse", "39m"),
            case("PFTInternalsCacheCollapse", "69m"),
            case("PFTInternalsCacheCollapse", "70m", CACHE),
            case("PFTInternalsCacheCollapse", "100m", CACHE),
        ],
    },
    {
        # "7200+60x60 0+60x70": samples t=0..60, then the restart: uptime 0 at t=61 with a cold cache (0.2 ratio).
        # uptime > 1800 only from t=92, so it fires at t=122 and not in the first 30 min after the restart;
        # 0.1 lookups/s at ratio 0 (other container) never fires.
        "name": "cold cache after a restart is ignored for 30 min of uptime; too few lookups never fire",
        "interval": "1m",
        "input_series": [
            S("node_uptime_seconds", "7200+60x60 0+60x70", container=CS),
            S("cached_view_total", "0+96x60 0+24x70", container=CS, result="hit"),
            S("cached_view_total", "0+24x60 0+96x70", container=CS, result="miss"),
            S("node_uptime_seconds", "7200+60x130", container=C),
            S("cached_view_total", "0x130", container=C, result="hit"),
            S("cached_view_total", "0+6x130", container=C, result="miss"),
        ],
        "alert_rule_test": [
            case("PFTInternalsCacheCollapse", "90m"),
            case("PFTInternalsCacheCollapse", "121m"),
            case("PFTInternalsCacheCollapse", "122m", CACHES),
        ],
    },
    {
        "name": "job backlog: 60 + 41 waiting (101 > 100) fires after 10m and clears; 60 + 40 (= 100) never fires",
        "interval": "1m",
        "input_series": [
            S("job_waiting", "0x10 60x30 0x10", container=C, job_type="ledgerData"),
            S("job_waiting", "0x10 41x30 0x10", container=C, job_type="transaction"),
            S("job_waiting", "0x10 60x30 0x10", container=CS, job_type="ledgerData"),
            S("job_waiting", "0x10 40x30 0x10", container=CS, job_type="transaction"),
        ],
        "alert_rule_test": [
            case("PFTInternalsJobBacklog", "20m"),
            case("PFTInternalsJobBacklog", "21m", BACKLOG),
            case("PFTInternalsJobBacklog", "40m", BACKLOG),
            case("PFTInternalsJobBacklog", "42m"),
        ],
    },
    {
        "name": "job peak 5001 ms fires per job type after 10m; 5000 ms never fires",
        "interval": "1m",
        "input_series": [
            S("load_job_peak_ms", "89x10 5001x30 89x10", container=C, job_type="acceptLedger"),
            S("load_job_peak_ms", "5000x50", container=C, job_type="trustedValidation"),
        ],
        "alert_rule_test": [
            case("PFTInternalsJobPeak", "20m"),
            case("PFTInternalsJobPeak", "21m", PEAK),
            case("PFTInternalsJobPeak", "40m", PEAK),
            case("PFTInternalsJobPeak", "42m"),
        ],
    },
    {
        "name": "collector up 0: fires after 5m, recovers on the first good sample",
        "interval": "1m",
        "input_series": [
            S("up", "1x10 0x10 1x20", container=C),
            S("collect_timestamp_seconds", "0+60x40", container=C),
        ],
        "alert_rule_test": [
            case("PFTInternalsStale", "15m"),
            case("PFTInternalsStale", "16m", STALE),
            case("PFTInternalsStale", "22m"),
        ],
    },
    {
        "name": "pull stopped (timestamp frozen at 10m, up still 1): stale after 5 min + 5m for, recovers when it "
        "moves again",
        "interval": "1m",
        "input_series": [
            S("up", "1x60", container=CS),
            S("collect_timestamp_seconds", "0+60x10 600x20 1860+60x29", container=CS),
        ],
        "alert_rule_test": [
            case("PFTInternalsStale", "20m"),
            case("PFTInternalsStale", "21m", STALES),
            case("PFTInternalsStale", "30m", STALES),
            case("PFTInternalsStale", "32m"),
        ],
    },
    {
        "name": "counter anomaly at 11m fires at once and clears when it leaves the 30m window; a collector state "
        "reset (3 -> 0) and node restarts do not fire",
        "interval": "1m",
        "input_series": [
            S("counter_anomalies_total", "0x10 1x50", container=C),
            S("counter_anomalies_total", "3x10 0x50", container=CS),
            S("node_restarts_total", "0x10 1x10 2x40", container=CS),
        ],
        "alert_rule_test": [
            case("PFTInternalsCounterAnomaly", "10m"),
            case("PFTInternalsCounterAnomaly", "11m", ANOM),
            case("PFTInternalsCounterAnomaly", "38m", ANOM),
            case("PFTInternalsCounterAnomaly", "42m"),
            case("PFTInternalsCounterAnomaly", "60m"),
        ],
    },
]
sys.stdout.write(
    "# promtool unit tests for internals.rules.yml (annotations copied from the rules with the labels filled in).\n"
    "# Generated by ../internals/tests/gen_rule_tests.py. Run: promtool test rules internals.tests.yml\n"
)
yaml.dump(
    {"rule_files": ["internals.rules.yml"], "evaluation_interval": "1m", "tests": tests},
    sys.stdout,
    Dumper=NoAlias,
    sort_keys=False,
    width=200,
)
