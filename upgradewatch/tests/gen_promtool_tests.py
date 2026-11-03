#!/usr/bin/env python3
"""Generate ../../alerts/upgradewatch.tests.yml (promtool unit tests for upgradewatch.rules.yml).

Input series, evaluation times and every $value are written by hand below (minute m = time() 60*m in promtool).
Only the annotation TEXT is copied from the rules file, with {{ $labels.container }} rendered and {{ $value ... }}
replaced by the hand-computed string given per case, so a wording change does not need every test edited by hand,
while a wrong value or a wrong label still fails.

Usage: python3 upgradewatch/tests/gen_promtool_tests.py > alerts/upgradewatch.tests.yml
       (cd alerts && promtool test rules upgradewatch.tests.yml)
"""

import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, "..", "..", "alerts", "upgradewatch.rules.yml")
BASE = {"job": "postfiat", "instance": "node:9877"}


def lbl(container, **extra):
    d = dict(BASE, container=container, **extra)
    return "{" + ", ".join(f'{k}="{v}"' for k, v in d.items()) + "}"


def s(name, container, values, **extra):
    return {
        "series": f"pft_upgradewatch_{name}{lbl(container, **extra)}",
        "values": values,
    }


with open(RULES, encoding="utf-8") as f:
    RULE = {r["alert"]: r for r in yaml.safe_load(f)["groups"][0]["rules"]}


def fired(alert, container, value=None, **labels):
    r = RULE[alert]
    ann = {}
    for k, v in r["annotations"].items():
        v = v.replace("{{ $labels.container }}", container)
        if "{{ $value" in v:
            if value is None:
                sys.exit(f"{alert}: annotation needs a hand-computed $value")
            v = re.sub(r"\{\{ \$value[^}]*\}\}", value, v)
        ann[k] = v
    return {
        "exp_labels": dict(
            BASE, container=container, severity=r["labels"]["severity"], **labels
        ),
        "exp_annotations": ann,
    }


def at(m, alert, *alerts):
    return {"eval_time": f"{m}m", "alertname": alert, "exp_alerts": list(alerts)}


ALL = list(RULE)
HEALTHY = [  # real live values (validator, logs/03): no majority, build = foundation, 19 peers none newer
    s("up", "postfiatd", "1x120"),
    s("collect_timestamp_seconds", "postfiatd", "0+60x120"),
    s("amendment_blocked", "postfiatd", "0x120"),
    s("unsupported_majority_warning", "postfiatd", "0x120"),
    s("majority_amendments", "postfiatd", "0x120", supported="no"),
    s("majority_amendments", "postfiatd", "0x120", supported="yes"),
    s("unsupported_activation_eta_seconds", "postfiatd", "0x120"),
    s("behind_foundation", "postfiatd", "0x120"),
    s("peers_newer_ratio", "postfiatd", "0x120"),
    s("peers_versioned", "postfiatd", "19x120"),
]

tests = [
    {
        "name": "healthy node for 2h (live values) fires nothing",
        "input_series": HEALTHY,
        "alert_rule_test": [at(m, a) for m in (30, 120) for a in ALL],
    },
    {
        "name": "PFTAmendmentBlocked: pending at 11m, fires at 12m (for 2m), resolves when the flag clears",
        # minutes 0-9 = 0, 10-30 = 1, 31-50 = 0
        "input_series": [s("amendment_blocked", "postfiatd", "0x9 1x20 0x19")],
        "alert_rule_test": [
            at(9, "PFTAmendmentBlocked"),
            at(11, "PFTAmendmentBlocked"),
            at(12, "PFTAmendmentBlocked", fired("PFTAmendmentBlocked", "postfiatd")),
            at(30, "PFTAmendmentBlocked", fired("PFTAmendmentBlocked", "postfiatd")),
            at(31, "PFTAmendmentBlocked"),
        ],
    },
    {
        "name": "PFTUnsupportedAmendmentMajority: ledger count path fires at 20m, resolves at 41m; supported majority "
        "and a 9-minute majority blip never fire; the node-warning path (from 15m) fires on its own at 25m",
        "input_series": [
            s("majority_amendments", "postfiatd", "0x9 1x30 0x19", supported="no"),
            s("unsupported_majority_warning", "postfiatd", "0x60"),
            s("majority_amendments", "postfiatd-sentry", "0x60", supported="no"),
            s("unsupported_majority_warning", "postfiatd-sentry", "0x14 1x45"),
            s("majority_amendments", "drill-yes", "3x60", supported="yes"),
            s("majority_amendments", "drill-yes", "0x60", supported="no"),
            s("majority_amendments", "drill-blip", "0x9 1x8 0x40", supported="no"),
        ],
        "alert_rule_test": [
            at(19, "PFTUnsupportedAmendmentMajority"),
            at(
                20,
                "PFTUnsupportedAmendmentMajority",
                fired("PFTUnsupportedAmendmentMajority", "postfiatd"),
            ),
            at(
                24,
                "PFTUnsupportedAmendmentMajority",
                fired("PFTUnsupportedAmendmentMajority", "postfiatd"),
            ),
            at(
                25,
                "PFTUnsupportedAmendmentMajority",
                fired("PFTUnsupportedAmendmentMajority", "postfiatd"),
                fired("PFTUnsupportedAmendmentMajority", "postfiatd-sentry"),
            ),
            at(
                41,
                "PFTUnsupportedAmendmentMajority",
                fired("PFTUnsupportedAmendmentMajority", "postfiatd-sentry"),
            ),
        ],
    },
    {
        "name": "PFTUnsupportedAmendmentActivationSoon: ETA 90000 s; inside 24 h from 61m (90000-3660 < 86400), fires "
        "at 66m with 86040 s left, value at 70m = 85800 s; resolves when the series drops to 0 at 81m; "
        "a far ETA and ETA 0 (none) never fire",
        "input_series": [
            s("unsupported_activation_eta_seconds", "postfiatd", "90000x80 0x20"),
            s("unsupported_activation_eta_seconds", "drill-far", "900000x100"),
            s("unsupported_activation_eta_seconds", "drill-none", "0x100"),
        ],
        "alert_rule_test": [
            at(60, "PFTUnsupportedAmendmentActivationSoon"),
            at(65, "PFTUnsupportedAmendmentActivationSoon"),
            at(
                66,
                "PFTUnsupportedAmendmentActivationSoon",
                fired(
                    "PFTUnsupportedAmendmentActivationSoon", "postfiatd", "23h 54m 0s"
                ),
            ),
            at(
                70,
                "PFTUnsupportedAmendmentActivationSoon",
                fired(
                    "PFTUnsupportedAmendmentActivationSoon", "postfiatd", "23h 50m 0s"
                ),
            ),
            at(81, "PFTUnsupportedAmendmentActivationSoon"),
            at(100, "PFTUnsupportedAmendmentActivationSoon"),
        ],
    },
    {
        "name": "PFTUnsupportedAmendmentActivationSoon: an ETA already past still fires (negative time left)",
        "input_series": [
            s("unsupported_activation_eta_seconds", "postfiatd", "600x30")
        ],
        # minute 10: 600 - 600 = 0 < 86400 since minute 0, so firing from minute 5; at 15m: 600 - 900 = -300 s
        "alert_rule_test": [
            at(4, "PFTUnsupportedAmendmentActivationSoon"),
            at(
                15,
                "PFTUnsupportedAmendmentActivationSoon",
                fired("PFTUnsupportedAmendmentActivationSoon", "postfiatd", "-5m 0s"),
            ),
        ],
    },
    {
        "name": "PFTNodeVersionLag: behind the foundation fires at 25m (for 15m) and resolves at 41m; the peer path "
        "fires at exactly 0.5 with 5 peers; 4 peers or a ratio just under 0.5 do not",
        "input_series": [
            s("behind_foundation", "postfiatd", "0x9 1x30 0x19"),
            s("peers_newer_ratio", "postfiatd", "0x60"),
            s("peers_versioned", "postfiatd", "19x60"),
            s("behind_foundation", "postfiatd-sentry", "0x60"),
            s("peers_newer_ratio", "postfiatd-sentry", "0.5x60"),
            s("peers_versioned", "postfiatd-sentry", "5x60"),
            s("behind_foundation", "drill-few", "0x60"),
            s("peers_newer_ratio", "drill-few", "1x60"),
            s("peers_versioned", "drill-few", "4x60"),
            s("behind_foundation", "drill-under", "0x60"),
            s("peers_newer_ratio", "drill-under", "0.4999x60"),
            s("peers_versioned", "drill-under", "19x60"),
        ],
        "alert_rule_test": [
            at(14, "PFTNodeVersionLag"),
            at(15, "PFTNodeVersionLag", fired("PFTNodeVersionLag", "postfiatd-sentry")),
            at(24, "PFTNodeVersionLag", fired("PFTNodeVersionLag", "postfiatd-sentry")),
            at(
                25,
                "PFTNodeVersionLag",
                fired("PFTNodeVersionLag", "postfiatd"),
                fired("PFTNodeVersionLag", "postfiatd-sentry"),
            ),
            at(41, "PFTNodeVersionLag", fired("PFTNodeVersionLag", "postfiatd-sentry")),
        ],
    },
    {
        "name": "PFTUpgradewatchStale: timestamp frozen at 600 -> older than 900 s from 26m, fires at 36m; up 0 for "
        "two runs fires at 20m; one failed run (5 min) does not; recovery resolves",
        "input_series": [
            s("up", "postfiatd", "1x60"),
            s("collect_timestamp_seconds", "postfiatd", "0+60x10 600x50"),
            s("up", "postfiatd-sentry", "1x9 0x15 1x35"),
            s("collect_timestamp_seconds", "postfiatd-sentry", "0+60x60"),
            s("up", "drill-once", "1x9 0x4 1x46"),
            s("collect_timestamp_seconds", "drill-once", "0+60x60"),
        ],
        "alert_rule_test": [
            at(19, "PFTUpgradewatchStale"),
            at(
                20,
                "PFTUpgradewatchStale",
                fired("PFTUpgradewatchStale", "postfiatd-sentry"),
            ),
            at(35, "PFTUpgradewatchStale"),
            at(36, "PFTUpgradewatchStale", fired("PFTUpgradewatchStale", "postfiatd")),
        ],
    },
]

for t in tests:
    t["interval"] = "1m"
print(
    "# promtool unit tests for upgradewatch.rules.yml, generated by ../upgradewatch/tests/gen_promtool_tests.py"
)
print("# Run: promtool test rules upgradewatch.tests.yml")
yaml.safe_dump(
    {
        "rule_files": ["upgradewatch.rules.yml"],
        "evaluation_interval": "1m",
        "tests": tests,
    },
    sys.stdout,
    sort_keys=False,
    width=120,
)
