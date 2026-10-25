#!/usr/bin/env python3
"""Generate tests.yml (promtool unit tests) for slo.rules.yml.

Scenarios are written by hand below; only exp_annotations are copied from the rules
file (with {{ $labels.instance }} rendered), so rewording an annotation needs no test edit.
Input interval is 1m (10m samples blink out of the 5m lookback); rules evaluate every 15s.

Usage: python3 gen_tests.py > tests.yml && promtool test rules tests.yml
"""
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
INST = "node:9877"
LAB = {"job": "postfiat", "instance": INST}


def alert_annotations():
    with open(os.path.join(HERE, "slo.rules.yml")) as f:
        rules = yaml.safe_load(f)
    out = {}
    for g in rules["groups"]:
        for r in g["rules"]:
            if "alert" in r:
                out[r["alert"]] = ({k: v.replace("{{ $labels.instance }}", INST) for k, v in r["annotations"].items()},
                                   r["labels"]["severity"])
    return out


ANN = alert_annotations()


def sel(name, **extra):
    labels = dict(LAB, **extra)
    return "{}{{{}}}".format(name, ", ".join('{}="{}"'.format(*kv) for kv in sorted(labels.items())))


def series(up, pft_up, state, age, maint, state_label="full"):
    s = [("up", up, {}), ("pft_up", pft_up, {}), ("pft_server_state", state, {"state": state_label}),
         ("pft_validated_ledger_age_seconds", age, {}), ("pft_maint_active", maint, {})]
    return [{"series": sel(n, **x), "values": v} for n, v, x in s if v is not None]


def alerts(t, fast, slow):
    out = []
    for name, on in (("PFTSLOFastBurn", fast), ("PFTSLOSlowBurn", slow)):
        ann, sev = ANN[name]
        exp = [{"exp_labels": dict(LAB, severity=sev), "exp_annotations": ann}] if on else []
        out.append({"eval_time": t, "alertname": name, "exp_alerts": exp})
    return out


def expr(t, e, value, labels=None):
    lab = labels if labels is not None else sel(e)
    return {"expr": e, "eval_time": t, "exp_samples": [{"labels": lab, "value": value}]}


def case(name, input_series, alert_tests=(), promql=()):
    t = {"name": name, "interval": "1m", "input_series": input_series}
    if alert_tests:
        t["alert_rule_test"] = list(alert_tests)
    if promql:
        t["promql_expr_test"] = list(promql)
    return t


# RPC down for 20m after 2h healthy; while RPC is down the exporter emits no state/age series
OUTAGE = {"up": "1x159", "pft_up": "1x119 0x19 1x20", "state": "4x119 _x19 4x20", "age": "3x119 _x19 3x20"}
SLOW_AGE = " ".join(["3x13 30"] * 16)  # validated ledger 30s old 1 min in every 15 for 4h = 6.7% errors

TESTS = [
    case("steady-good: 4h healthy, no burn alerts, budget untouched",
         series("1x239", "1x239", "4x239", "3x239", "0x239"),
         alerts("2h", False, False) + alerts("3h55m", False, False),
         [expr("3h", "pft:sli_good:bool", 1), expr("3h", "pft:sli_error:ratio_rate1h", 0),
          expr("3h", "pft:slo_budget_remaining:ratio", 1),
          expr("1m", "pft:slo_objective:ratio", 0.995, labels="pft:slo_objective:ratio")]),
    case("fast-burn: RPC down 20m after 2h healthy; fast quiet at +3m, firing at +10m; slow (for 15m) also at +20m",
         series(maint="0x159", **OUTAGE),
         alerts("2h3m", False, False) + alerts("2h10m", True, False) + alerts("2h20m", True, True),
         [expr("2h3m", "pft:sli_good:bool", 0), expr("2h3m", "pft:sli_bad:bool", 1),
          expr("2h10m", "pft:sli_error:ratio_rate5m", 1)]),
    case("exporter-down: failed scrape, missing component series count as bad",
         series("1x59 0x19", "1x59 _x19", "4x59 _x19", "3x59 _x19", "0x59 _x19"),
         alerts("1h12m", True, False),
         [expr("1h10m", "pft:sli_good:bool", 0), expr("1h10m", "pft:sli_bad:bool", 1)]),
    case("slow-burn: ledger stale 1 min in every 15 for 4h (6.7%): slow fires, fast never",
         series("1x239", "1x239", "4x239", SLOW_AGE, "0x239"),
         alerts("10m", False, False) + alerts("3h", False, True) + alerts("3h55m", False, True)),
    case("maintenance-window: same 20m RPC outage inside an open pft-maint window does not burn",
         series(maint="0x117 1x23 0x18", **OUTAGE),
         alerts("2h10m", False, False) + alerts("2h20m", False, False) + alerts("2h38m", False, False),
         [expr("2h10m", "pft:sli_good:bool", 0), expr("2h10m", "pft:sli_bad:bool", 0),
          expr("2h10m", "pft:sli_eligible:bool", 0), expr("2h20m", "pft:sli_error:ratio_rate1h", 0)]),
    case("state: syncing is bad, proposing is good",
         [{"series": sel("up"), "values": "1x30"}, {"series": sel("pft_up"), "values": "1x30"},
          {"series": sel("pft_server_state", state="syncing"), "values": "2x10 _x20"},
          {"series": sel("pft_server_state", state="proposing"), "values": "_x10 6x20"},
          {"series": sel("pft_validated_ledger_age_seconds"), "values": "3x30"}],
         promql=[expr("5m", "pft:sli_state_ok:bool", 0), expr("25m", "pft:sli_state_ok:bool", 1),
                 expr("25m", "pft:sli_good:bool", 1)]),
]

if __name__ == "__main__":
    sys.stdout.write("# GENERATED by gen_tests.py - do not edit by hand.\n# Run: promtool test rules tests.yml\n")
    yaml.safe_dump({"rule_files": ["slo.rules.yml"], "evaluation_interval": "15s", "tests": TESTS},
                   sys.stdout, sort_keys=False, width=120)
