#!/usr/bin/env python3
"""Generate alerts/statewatch.tests.yml (promtool unit tests) for alerts/statewatch.rules.yml.

Input series, evaluation times and the expected $value strings are written by hand below (one block per case:
fire, no-fire, counter reset, recovery). Only the annotation TEXT is copied from the rules file, with
{{ $labels.container }} and the $value templates replaced by the hand-computed strings given in each case, so a
wrong value or a wrong label still fails the test while a wording change needs no hand edit.

Usage: python3 statewatch/tests/gen_rule_tests.py > alerts/statewatch.tests.yml
       promtool test rules statewatch.tests.yml      (from alerts/)
Sample interval 1m = the collector timer's period. "_" in a series is a missing sample (collector wrote up 0 only,
e.g. while postfiatd restarts). Prometheus 3 ranges are left-open: [10m] at t covers samples in (t-10m, t].
"""
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, "..", "..", "alerts", "statewatch.rules.yml")
C = "postfiatd-sentry"
BASE = 'job="postfiat", instance="node:9877", container="%s"' % C
LBL = {"job": "postfiat", "instance": "node:9877", "container": C}

ALERTS = ["PFTStatewatchCollectorFailing", "PFTStatewatchStale", "PFTNodeBriefFullExit", "PFTNodeStateFlapping",
          "PFTJobQueueOverflow", "PFTIOLatencyHigh", "PFTPeerDisconnectRateHigh"]


def rules():
    doc = yaml.safe_load(open(RULES))
    return {r["alert"]: r for g in doc["groups"] for r in g["rules"]}


R = rules()


def render(alert, value):
    out = {}
    for k, v in R[alert]["annotations"].items():
        v = v.replace("{{ $labels.container }}", C)
        if value is not None:
            v = v.replace('{{ $value | printf "%.0f" }}', value).replace("{{ $value }}", value)
        if "{{" in v:
            sys.exit("unrendered template in %s.%s: %s" % (alert, k, v))
        out[k] = v
    return out


def s(name, values, extra=""):
    return {"series": "%s{%s%s}" % (name, BASE, extra), "values": values}


def state(full_values):  # only the mode-full one-hot series matters to the rules
    return s("pft_statewatch_server_state", full_values, ', state="full"')


def fires(alert, t, value=None, severity="warning"):
    return {"eval_time": t, "alertname": alert,
            "exp_alerts": [{"exp_labels": dict(LBL, severity=severity), "exp_annotations": render(alert, value)}]}


def quiet(alert, t):
    return {"eval_time": t, "alertname": alert, "exp_alerts": []}


def all_quiet(t):
    return [quiet(a, t) for a in ALERTS]


def ts(n):  # collect timestamps of a healthy timer: 0, 60, ... (n+1 samples)
    return s("pft_statewatch_collect_timestamp_seconds", "0+60x%d" % n)


TESTS = [
    ("healthy node for 2h (baseline-like values) fires nothing",
     [s("pft_statewatch_up", "1x120"), ts(120), state("1x120"), s("pft_statewatch_full_exits_total", "0x120"),
      s("pft_statewatch_jq_trans_overflow_total", "0x120"), s("pft_statewatch_io_latency_ms", "1x120"),
      # ~3 disconnects/h, like the baseline
      s("pft_statewatch_peer_disconnects_total", "21x20 22x20 23x20 24x20 25x20 26x20")],
     all_quiet("60m") + all_quiet("120m")),

    # --- collector health
    ("collector failing: up 0 fires after 5m, not before; recovers",
     [s("pft_statewatch_up", "1x5 0x10 1x10"), ts(25)],
     [quiet("PFTStatewatchCollectorFailing", "10m"), fires("PFTStatewatchCollectorFailing", "11m"),
      quiet("PFTStatewatchCollectorFailing", "17m")]),
    ("stale: timestamp stops at 600 s; > 300 s old from 16m, fires 2m later; recovers when it moves again",
     [s("pft_statewatch_collect_timestamp_seconds", "0+60x10 600x15 1560+60x10")],
     [quiet("PFTStatewatchStale", "17m"), fires("PFTStatewatchStale", "18m"), quiet("PFTStatewatchStale", "27m")]),

    # --- brief exit from full (invisible to scrape-time PFTNodeNotFull)
    ("brief exit: exit counter 0 -> 1 at 31m while every sample says full -> fires, resolves after 10m",
     [state("1x60"), s("pft_statewatch_full_exits_total", "0x30 1x30")],
     [quiet("PFTNodeBriefFullExit", "30m"), fires("PFTNodeBriefFullExit", "31m", "1"),
      fires("PFTNodeBriefFullExit", "35m", "1"), quiet("PFTNodeBriefFullExit", "41m"),
      quiet("PFTNodeStateFlapping", "35m")]),
    ("visible exit (state sampled not-full for 5m) is not 'brief': PFTNodeNotFull's job",
     [state("1x25 0x5 1x30"), s("pft_statewatch_full_exits_total", "0x25 1x35")],
     [quiet("PFTNodeBriefFullExit", "31m"), quiet("PFTNodeBriefFullExit", "33m")]),
    # raw transitions after a real start (runlog 05): disconnected 2, connected 2, syncing 1, tracking 1, full 1
    ("restart: all counters reset, collector gap 2m, raw transitions re-enter every mode -> no state alert",
     [state("1x30 _x2 0 1x27"), s("pft_statewatch_full_exits_total", "0x30 _x2 0x28"),
      s("pft_statewatch_state_transitions_total", "1x30 _x2 0 1x27", ', state="full"'),
      s("pft_statewatch_state_transitions_total", "1x30 _x2 0 1x27", ', state="tracking"'),
      s("pft_statewatch_state_transitions_total", "1x30 _x2 1x28", ', state="syncing"'),
      s("pft_statewatch_state_transitions_total", "2x30 _x2 2x28", ', state="connected"'),
      s("pft_statewatch_state_transitions_total", "2x30 _x2 2x28", ', state="disconnected"'),
      s("pft_statewatch_jq_trans_overflow_total", "5x30 _x2 0x28"),
      s("pft_statewatch_peer_disconnects_total", "100x30 _x2 0x28")],
     [quiet(a, t) for t in ("33m", "36m", "45m", "60m")
      for a in ("PFTNodeBriefFullExit", "PFTNodeStateFlapping", "PFTJobQueueOverflow", "PFTPeerDisconnectRateHigh")]),

    # --- flapping
    # "VxN" is N+1 samples: exits at 11m, 22m, 33m
    ("flapping: 3rd exit within 1h (at 33m) fires (value 3); resolves at 70m when the 0->1 step (10m->11m) leaves (t-1h, t]",
     [state("1x103"), s("pft_statewatch_full_exits_total", "0x10 1x10 2x10 3x70")],
     [quiet("PFTNodeStateFlapping", "32m"), fires("PFTNodeStateFlapping", "33m", "3", "critical"),
      fires("PFTNodeStateFlapping", "69m", "3", "critical"), quiet("PFTNodeStateFlapping", "70m")]),
    ("2 exits within 1h is not flapping",
     [state("1x60"), s("pft_statewatch_full_exits_total", "0x10 1x10 2x40")],
     [quiet("PFTNodeStateFlapping", "40m"), quiet("PFTNodeStateFlapping", "60m")]),
    ("exits before and after a restart add up (reset-safe increase): 2 + restart + 1 -> flapping",
     [state("1x20 _x2 0 1x37"), s("pft_statewatch_full_exits_total", "0x5 1x5 2x10 _x2 0x8 1x30")],
     [fires("PFTNodeStateFlapping", "40m", "3", "critical")]),

    # --- job queue overflow
    ("jq overflow 0 -> 3 at 21m fires (15m window: 3 x 15/14 = 3.2 -> '3'), resolves 15m later",
     [s("pft_statewatch_jq_trans_overflow_total", "0x20 3x20")],
     [quiet("PFTJobQueueOverflow", "20m"), fires("PFTJobQueueOverflow", "25m", "3"),
      quiet("PFTJobQueueOverflow", "36m")]),
    ("jq overflow after a restart: reset 7 -> 0, then 2 new drops -> fires on the 2 new ones",
     [s("pft_statewatch_jq_trans_overflow_total", "7x20 _x2 0x5 2x10")],
     [quiet("PFTJobQueueOverflow", "26m"), fires("PFTJobQueueOverflow", "30m", "2")]),

    # --- io latency
    ("io latency 80 ms at 11m..26m fires at 21m (for 10m), not at 20m; recovers at 27m",
     [s("pft_statewatch_io_latency_ms", "1x10 80x15 1x10")],
     [quiet("PFTIOLatencyHigh", "20m"), fires("PFTIOLatencyHigh", "21m", "80"), fires("PFTIOLatencyHigh", "26m", "80"),
      quiet("PFTIOLatencyHigh", "27m")]),
    ("9-minute io latency spike does not fire; 50 ms exactly does not fire",
     [s("pft_statewatch_io_latency_ms", "1x10 80x9 1x5 50x20")],
     [quiet("PFTIOLatencyHigh", "20m"), quiet("PFTIOLatencyHigh", "45m")]),

    # --- peer disconnects
    ("60 disconnects/h fires ((0,60m]: 59 x 60/59 = 60), 30/h does not",
     [s("pft_statewatch_peer_disconnects_total", "0+1x60"),
      {"series": 'pft_statewatch_peer_disconnects_total{job="postfiat", instance="node:9877", container="postfiatd"}',
       "values": "0+0.5x60"}],
     [fires("PFTPeerDisconnectRateHigh", "60m", "60")]),
    ("disconnect counter reset (300 -> 0, no new drops) does not fire; a real burst of 40 after it does",
     [s("pft_statewatch_peer_disconnects_total", "300x30 _x2 0x10 40x20")],
     [quiet("PFTPeerDisconnectRateHigh", "42m"), fires("PFTPeerDisconnectRateHigh", "45m", "40"),
      quiet("PFTPeerDisconnectRateHigh", "105m")]),
]


def main():
    tests = [{"name": n, "interval": "1m", "input_series": series, "alert_rule_test": checks}
             for n, series, checks in TESTS]
    head = ("# GENERATED by statewatch/tests/gen_rule_tests.py - edit the generator, not this file.\n"
            "# promtool unit tests for statewatch.rules.yml. Run: promtool test rules statewatch.tests.yml\n")
    body = yaml.safe_dump({"rule_files": ["statewatch.rules.yml"], "evaluation_interval": "1m", "tests": tests},
                          sort_keys=False, width=200)
    assert not re.search(r"\{\{", body)
    sys.stdout.write(head + body)


if __name__ == "__main__":
    main()
