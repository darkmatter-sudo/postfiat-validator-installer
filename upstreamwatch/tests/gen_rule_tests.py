#!/usr/bin/env python3
"""Generate alerts/upstreamwatch.tests.yml (promtool unit tests) for alerts/upstreamwatch.rules.yml and the retuned
PFTVulnFeedStale in alerts/vulnscan.rules.yml.

Series and evaluation times are written by hand below (fire, no-fire just before `for:` ends, recovery, never-fire
controls). Only the annotation TEXT is copied from the rules files with the labels substituted, so a wrong label still
fails while a wording change needs no hand edit.

Usage: python3 upstreamwatch/tests/gen_rule_tests.py > alerts/upstreamwatch.tests.yml
       cd alerts && promtool test rules upstreamwatch.tests.yml
Sample interval 1m; "VxN" is N+1 samples.
"""

import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(HERE, "..", "..", "alerts")
FILES = ["upstreamwatch.rules.yml", "vulnscan.rules.yml"]
R = {}
for fn in FILES:
    with open(os.path.join(ALERTS_DIR, fn), encoding="utf-8") as f:
        for g in yaml.safe_load(f)["groups"]:
            for r in g["rules"]:
                R[r["alert"]] = r
OURS = ["PFTUpstreamFeedLocalStale", "PFTUpstreamFeedFetchFailing", "PFTUpstreamFeedQuiet",
        "PFTUpstreamReleaseAvailable", "PFTUpstreamwatchFailing", "PFTUpstreamwatchNotRunning"]
missing = {a for a in R if a.startswith("PFTUpstream")} - set(OURS)
if missing:
    sys.exit(f"rules without a test case: {sorted(missing)}")
BASE = {"job": "postfiat", "instance": "node:9877"}
STATES = ("ok", "upstream_quiet", "local_stale", "fetch_failing", "unreachable")


def sel(metric, **labels):
    lab = {**BASE, **labels}
    return metric + "{" + ", ".join(f'{k}="{v}"' for k, v in lab.items()) + "}"


def render(alert, labels):
    out = {}
    for k, v in R[alert]["annotations"].items():
        v = re.sub(r"\{\{ \$labels\.(\w+) \}\}", lambda m: labels[m.group(1)], v)
        if "{{" in v:
            sys.exit(f"unrendered template in {alert}.{k}: {v}")
        out[k] = v
    return out


def fired(alert, **labels):
    lab = {**BASE, **labels, **{k: v for k, v in R[alert].get("labels", {}).items()}}
    m = re.search(r'\{state="(\w+)"\} == 1', R[alert]["expr"])  # the one-hot selector keeps its state label
    if m and alert.startswith("PFTUpstream"):
        lab["state"] = m.group(1)
    return {"exp_labels": lab, "exp_annotations": render(alert, lab)}


def feed_series(host, feed, seq):
    """seq: list of (state, minutes) -> one-hot series for every state"""
    out = []
    for s in STATES:
        vals = " ".join(f"{1 if st == s else 0}x{n - 1}" for st, n in seq)
        out.append({"series": sel("pft_upstreamwatch_feed_state", host=host, feed=feed, state=s), "values": vals})
    return out


def run_series(host, minutes, up=1):
    return [
        {"series": sel("pft_upstreamwatch_up", host=host), "values": f"{up}x{minutes - 1}"},
        {"series": sel("pft_upstreamwatch_last_run_timestamp_seconds", host=host),
         "values": " ".join(f"{h * 3600}x59" for h in range(minutes // 60 + 1))},
    ]


def case(name, series, checks):
    return {"name": name, "interval": "1m", "input_series": series,
            "alert_rule_test": [{"eval_time": t, "alertname": a, "exp_alerts": e} for t, a, e in checks]}


T = []
FEED = {"host": "validator", "feed": "usn-host"}
paged = ("PFTUpstreamFeedLocalStale", "PFTUpstreamFeedFetchFailing")

# 1 quiet feed for 6 h: only the digest-only alert fires; nothing paged
T.append(case("upstream_quiet for 6 h: only PFTUpstreamFeedQuiet (notify=digest) fires, never a paged alert",
              feed_series("validator", "usn-host", [("upstream_quiet", 360)]) + run_series("validator", 360),
              [("64m", "PFTUpstreamFeedQuiet", []),
               ("66m", "PFTUpstreamFeedQuiet", [fired("PFTUpstreamFeedQuiet", **FEED)])]
              + [(t, a, []) for t in ("66m", "5h") for a in (*paged, "PFTUpstreamwatchFailing",
                                                           "PFTUpstreamwatchNotRunning")]))

# 2 local_stale: pending until 65 m, fires, resolves after recovery
T.append(case("local_stale for 2 h then ok: PFTUpstreamFeedLocalStale fires after 65 m and resolves",
              feed_series("validator", "usn-host", [("local_stale", 120), ("ok", 120)]) + run_series("validator", 240),
              [("64m", "PFTUpstreamFeedLocalStale", []),
               ("66m", "PFTUpstreamFeedLocalStale", [fired("PFTUpstreamFeedLocalStale", **FEED)]),
               ("119m", "PFTUpstreamFeedLocalStale", [fired("PFTUpstreamFeedLocalStale", **FEED)]),
               ("122m", "PFTUpstreamFeedLocalStale", []),
               ("66m", "PFTUpstreamFeedQuiet", []), ("66m", "PFTUpstreamFeedFetchFailing", [])]))

# 3 one hourly run of local_stale (60 samples) between ok runs never pages
T.append(case("a single run (60 min) of local_stale does not page",
              feed_series("validator", "usn-host", [("ok", 60), ("local_stale", 60), ("ok", 120)])
              + run_series("validator", 240),
              [(t, "PFTUpstreamFeedLocalStale", []) for t in ("100m", "119m", "121m", "200m")]))

# 4 fetch_failing on the sentry feed
SFEED = {"host": "sentry", "feed": "debian"}
T.append(case("fetch_failing on the sentry: PFTUpstreamFeedFetchFailing fires after 65 m, recovers",
              feed_series("sentry", "debian", [("fetch_failing", 90), ("ok", 60)]) + run_series("sentry", 150),
              [("64m", "PFTUpstreamFeedFetchFailing", []),
               ("66m", "PFTUpstreamFeedFetchFailing", [fired("PFTUpstreamFeedFetchFailing", **SFEED)]),
               ("92m", "PFTUpstreamFeedFetchFailing", []),
               ("66m", "PFTUpstreamFeedLocalStale", [])]))

# 5 unreachable has no alert of its own
T.append(case("unreachable for 6 h pages nothing (fetch_failing covers a persisting outage)",
              feed_series("validator", "go", [("unreachable", 360)]) + run_series("validator", 360),
              [(t, a, []) for t in ("2h", "5h") for a in (*paged, "PFTUpstreamFeedQuiet")]))

# 6 release behind: digest-only after 2 h, resolves
REL = {"host": "validator", "container": "postfiatd"}


def rel_series(seq, host="validator", container="postfiatd"):
    return [{"series": sel("pft_upstreamwatch_release_state", host=host, container=container, state=s),
             "values": " ".join(f"{1 if st == s else 0}x{n - 1}" for st, n in seq)}
            for s in ("current", "behind", "unknown")]


T.append(case("release behind for 3 h then current: PFTUpstreamReleaseAvailable (digest) fires after 2 h",
              rel_series([("behind", 180), ("current", 60)]) + run_series("validator", 240),
              [("119m", "PFTUpstreamReleaseAvailable", []),
               ("121m", "PFTUpstreamReleaseAvailable", [fired("PFTUpstreamReleaseAvailable", **REL)]),
               ("182m", "PFTUpstreamReleaseAvailable", [])]))
T.append(case("release unknown for 4 h fires nothing",
              rel_series([("unknown", 240)]) + run_series("validator", 240),
              [("3h", "PFTUpstreamReleaseAvailable", [])]))

# 7 tool health
T.append(case("up 0 for 3 h: PFTUpstreamwatchFailing after 2 h",
              run_series("validator", 180, up=0),
              [("119m", "PFTUpstreamwatchFailing", []),
               ("121m", "PFTUpstreamwatchFailing", [fired("PFTUpstreamwatchFailing", host="validator")])]))
T.append(case("last run frozen at 0: PFTUpstreamwatchNotRunning after 3 h + 15 m",
              [{"series": sel("pft_upstreamwatch_up", host="sentry"), "values": "1x300"},
               {"series": sel("pft_upstreamwatch_last_run_timestamp_seconds", host="sentry"), "values": "0x300"}],
              [("194m", "PFTUpstreamwatchNotRunning", []),
               ("196m", "PFTUpstreamwatchNotRunning", [fired("PFTUpstreamwatchNotRunning", host="sentry")])]))

# 8 retuned PFTVulnFeedStale: a 4-day-old USN feed pages only when upstreamwatch does NOT call it upstream_quiet
DAY4 = 4 * 86400 // 60  # minutes
VS4 = [{"series": sel("pft_vulnscan_feed_timestamp_seconds", host="validator"), "values": f"1x{DAY4 + 200}"}]  # epoch 1 s: > 0 and 4 days old
vs_fired = fired("PFTVulnFeedStale", host="validator")
T.append(case("PFTVulnFeedStale: feed 4 days old and usn-host upstream_quiet -> suppressed",
              VS4 + feed_series("validator", "usn-host", [("upstream_quiet", DAY4 + 201)]),
              [(f"{DAY4 + 120}m", "PFTVulnFeedStale", [])]))
T.append(case("PFTVulnFeedStale control: feed 4 days old, usn-host ok/local_stale -> still pages",
              VS4 + feed_series("validator", "usn-host", [("local_stale", DAY4 + 201)]),
              [(f"{DAY4 + 120}m", "PFTVulnFeedStale", [vs_fired])]))
T.append(case("PFTVulnFeedStale control: no upstreamwatch series at all -> pages as before",
              VS4, [(f"{DAY4 + 120}m", "PFTVulnFeedStale", [vs_fired])]))
T.append(case("PFTVulnFeedStale control: upstream_quiet on the OTHER host does not suppress this host",
              VS4 + feed_series("sentry", "usn-host", [("upstream_quiet", DAY4 + 201)]),
              [(f"{DAY4 + 120}m", "PFTVulnFeedStale", [vs_fired])]))
T.append(case("PFTVulnFeedStale control: an imagescan feed quiet does not suppress the host USN feed",
              VS4 + feed_series("validator", "ubuntu-jammy", [("upstream_quiet", DAY4 + 201)]),
              [(f"{DAY4 + 120}m", "PFTVulnFeedStale", [vs_fired])]))

doc = {"rule_files": FILES, "evaluation_interval": "1m", "tests": T}
sys.stdout.write("# GENERATED by upstreamwatch/tests/gen_rule_tests.py - edit the generator, not this file.\n"
                 "# promtool unit tests for upstreamwatch.rules.yml + the retuned PFTVulnFeedStale. "
                 "Run: promtool test rules upstreamwatch.tests.yml\n")
sys.stdout.write(yaml.safe_dump(doc, sort_keys=False, width=200))
