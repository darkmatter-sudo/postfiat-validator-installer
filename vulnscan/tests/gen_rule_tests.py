#!/usr/bin/env python3
"""Generate alerts/vulnscan.tests.yml (promtool unit tests) for alerts/vulnscan.rules.yml.

Input series and evaluation times are written by hand below (fire, no-fire just before the `for:` ends, recovery,
and the cases that must never fire). Only the annotation TEXT is copied from the rules file, with
{{ $labels.host }} replaced, so a wrong label still fails the test while a wording change needs no hand edit.

Usage: python3 vulnscan/tests/gen_rule_tests.py > alerts/vulnscan.tests.yml
       promtool test rules vulnscan.tests.yml      (from alerts/)
Sample interval 1m (lesson: 10m samples drop out of the 5m lookback and reset `for:`). "VxN" is N+1 samples, so
"0x60 1x10" has value 1 from 61m. "_" is a missing sample (a failed scan drops the affected_usns series).
"""
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, "..", "..", "alerts", "vulnscan.rules.yml")
H = "validator"
BASE = 'job="postfiat", instance="node:9877", host="%s"' % H
LBL = {"job": "postfiat", "instance": "node:9877", "host": H}
ALERTS = ["PFTVulnScanFailing", "PFTVulnScanNotRunning", "PFTVulnFeedStale", "PFTVulnHighCriticalPersistent",
          "PFTVulnRebootOwed"]
R = {r["alert"]: r for g in yaml.safe_load(open(RULES))["groups"] for r in g["rules"]}
missing = set(R) - set(ALERTS)
if missing:
    sys.exit("rules without a test case: %s" % sorted(missing))


def render(alert, host=H):
    out = {}
    for k, v in R[alert]["annotations"].items():
        v = v.replace("{{ $labels.host }}", host)
        if "{{" in v:
            sys.exit("unrendered template in %s.%s: %s" % (alert, k, v))
        out[k] = v
    return out


def s(name, values, extra="", base=BASE):
    return {"series": "%s{%s%s}" % (name, base, extra), "values": values}


def usn(sev, fix, values):
    return s("pft_vulnscan_affected_usns", values, ', severity="%s", fix="%s"' % (sev, fix))


def fires(alert, t):
    return {"eval_time": t, "alertname": alert,
            "exp_alerts": [{"exp_labels": dict(LBL, severity=R[alert]["labels"]["severity"]), "exp_annotations": render(alert)}]}


def quiet(alert, t):
    return {"eval_time": t, "alertname": alert, "exp_alerts": []}


DAY = "0x1439 86400x1439 172800x1439 259200x1439 345600x600"   # a daily scan at 0, 24h, 48h, 72h, 96h
TESTS = [
    ("healthy host, daily scans with a fresh feed, only medium/esm findings, for 4 days: nothing fires",
     [s("pft_vulnscan_up", "1x6360"), s("pft_vulnscan_last_run_timestamp_seconds", DAY),
      s("pft_vulnscan_feed_timestamp_seconds", DAY), usn("medium", "esm", "2x6360"), usn("high", "archive", "0x6360"),
      usn("critical", "esm", "0x6360"), s("pft_vulnscan_reboot_owed", "0x6360")],
     [quiet(a, t) for t in ("30h", "80h", "105h") for a in ALERTS]),

    ("scan failing: up 0 from 11m fires at 21m (for 10m), not at 20m; recovers when a scan succeeds",
     [s("pft_vulnscan_up", "1x10 0x30 1x10")],
     [quiet("PFTVulnScanFailing", "20m"), fires("PFTVulnScanFailing", "21m"), quiet("PFTVulnScanFailing", "42m")]),

    ("not running: last run stays at 0; > 2 days old from 2881m, fires 10m later; a new run at 2900m clears it",
     [s("pft_vulnscan_last_run_timestamp_seconds", "0x2899 174000x100")],
     [quiet("PFTVulnScanNotRunning", "2880m"), quiet("PFTVulnScanNotRunning", "2890m"),
      fires("PFTVulnScanNotRunning", "2891m"), quiet("PFTVulnScanNotRunning", "2901m")]),

    ("feed stale: feed timestamp 0 on the sentry (unknown) never fires; the validator's feed > 3 days old from 4321m "
     "fires 1h later (4381m); a refreshed feed clears it",
     [s("pft_vulnscan_feed_timestamp_seconds", "1x4500 300000x60"),
      s("pft_vulnscan_feed_timestamp_seconds", "0x4560", base='job="postfiat", instance="node:9877", host="sentry"')],
     [quiet("PFTVulnFeedStale", "4320m"), quiet("PFTVulnFeedStale", "4380m"), fires("PFTVulnFeedStale", "4381m"),
      quiet("PFTVulnFeedStale", "4502m")]),

    ("high (archive) USN from 61m fires after 48h (2941m), not at 2940m; a fixed rescan (0) at 3000m clears it",
     [usn("high", "archive", "0x60 1x2939 0x100"), usn("critical", "archive", "0x3100")],
     [quiet("PFTVulnHighCriticalPersistent", "2940m"), fires("PFTVulnHighCriticalPersistent", "2941m"),
      quiet("PFTVulnHighCriticalPersistent", "3001m")]),

    ("critical esm-only USN counts too (fires after 48h)",
     [usn("critical", "esm", "1x2900"), usn("high", "archive", "0x2900")],
     [quiet("PFTVulnHighCriticalPersistent", "2879m"), fires("PFTVulnHighCriticalPersistent", "2880m")]),

    ("medium/low/none findings never fire the high/critical rule, however long",
     [usn("medium", "archive", "3x3000"), usn("low", "esm", "1x3000"), usn("none", "esm", "1x3000")],
     [quiet("PFTVulnHighCriticalPersistent", "2950m")]),

    ("a failed scan (series missing 10m) restarts the 48h clock: no alert at 2900m, fires 48h after the gap",
     [usn("high", "archive", "1x1000 _x10 1x3000")],
     [quiet("PFTVulnHighCriticalPersistent", "2900m"), quiet("PFTVulnHighCriticalPersistent", "3880m"),
      fires("PFTVulnHighCriticalPersistent", "3900m")]),

    ("reboot owed from 11m fires after 72h (4331m), not at 4330m",
     [s("pft_vulnscan_reboot_owed", "0x10 1x4400")],
     [quiet("PFTVulnRebootOwed", "4330m"), fires("PFTVulnRebootOwed", "4331m")]),
]


def main():
    tests = [{"name": n, "interval": "1m", "input_series": series, "alert_rule_test": checks} for n, series, checks in TESTS]
    head = ("# GENERATED by vulnscan/tests/gen_rule_tests.py - edit the generator, not this file.\n"
            "# promtool unit tests for vulnscan.rules.yml. Run: promtool test rules vulnscan.tests.yml\n")
    body = yaml.safe_dump({"rule_files": ["vulnscan.rules.yml"], "evaluation_interval": "1m", "tests": tests},
                          sort_keys=False, width=200)
    assert not re.search(r"\{\{", body)
    sys.stdout.write(head + body)


if __name__ == "__main__":
    main()
