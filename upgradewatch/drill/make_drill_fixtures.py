#!/usr/bin/env python3
"""Build the upgradewatch drill fixture sets from the real validator answers in ../tests/fixtures.

  python3 -I make_drill_fixtures.py --out DIR --now EPOCH

Writes DIR/<case>/{info,feature,amendments,peers,foundation}.json + cfg.txt for each case, ready for
`pft-upgradewatch replay --fixtures DIR/<case>`. The majority CloseTimes are relative to --now, so the sets are
built at drill start (the drill log records --now and every derived value):

  healthy   the real validator answers, unchanged                      -> no alert
  blocked   server_info amendment_blocked true + warning 1002           -> PFTAmendmentBlocked
  majority  an amendment unknown to this build got a majority 1 day ago -> PFTUnsupportedAmendmentMajority
            (ETA = CloseTime + 3 days = now + 2 days, outside the 24 h window)
  soon      the same amendment, majority 2.5 days ago (ETA = now + 12 h) -> ...Majority + ...ActivationSoon
  lag       the foundation RPC reports build 1.0.10 (node 1.0.9)        -> PFTNodeVersionLag
  failing   server_info is not JSON                                     -> PFTUpgradewatchStale (up 0)

The majority hold time is the node's own `[amendment_majority_time] 3 days` (validator_majority_cfg.txt).
Prints one line per case with the values a reviewer can recompute by hand.
"""

import argparse
import copy
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FX = os.path.join(HERE, "..", "tests", "fixtures")
RIPPLE_EPOCH = 946684800
MAJ_SECS = 3 * 86400  # validator_majority_cfg.txt: [amendment_majority_time] 3 days
# not in this build's feature table: the parser labels it unknown_<hash> and counts it as unsupported
DRILL_AMENDMENT = hashlib.sha256(b"upgradewatch-drill").hexdigest().upper()
WARN_UNSUPPORTED_MAJORITY = 1001
WARN_AMENDMENT_BLOCKED = 1002


def jload(name):
    with open(os.path.join(FX, name), encoding="utf-8") as f:
        return json.load(f)


def base():
    d = {
        k: jload(f"validator_{k2}.json")
        for k, k2 in (
            ("info", "server_info"),
            ("feature", "feature"),
            ("amendments", "amendments"),
            ("peers", "peers"),
        )
    }
    d["foundation"] = jload("foundation_server_info.json")
    return d


def with_majority(d, close_unix):
    close = close_unix - RIPPLE_EPOCH
    d["amendments"]["result"]["node"].setdefault("Majorities", []).append(
        {"Majority": {"Amendment": DRILL_AMENDMENT, "CloseTime": close}}
    )
    # a real node adds warning 1001 with the same expected date (NetClock seconds)
    d["info"]["result"]["info"].setdefault("warnings", []).append(
        {
            "id": WARN_UNSUPPORTED_MAJORITY,
            "message": "One or more unsupported amendments have reached majority.",
            "details": {"expected_date": close + MAJ_SECS},
        }
    )
    return close


def write(out, name, d, raw_info=None):
    p = os.path.join(out, name)
    os.makedirs(p)
    for k, v in d.items():
        with open(os.path.join(p, k + ".json"), "w", encoding="utf-8") as f:
            f.write(
                raw_info if (k == "info" and raw_info is not None) else json.dumps(v)
            )
    shutil.copyfile(
        os.path.join(FX, "validator_majority_cfg.txt"), os.path.join(p, "cfg.txt")
    )


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--now", type=int, required=True)
    a = ap.parse_args(argv)
    if os.path.exists(a.out) and os.listdir(a.out):
        sys.exit("--out must be empty or absent")
    os.makedirs(a.out, exist_ok=True)
    now, b = a.now, base()

    write(a.out, "healthy", b)
    print(
        "healthy: real validator answers (build 1.0.9, foundation 1.0.9, 0 majorities, not blocked)"
    )

    d = copy.deepcopy(b)
    d["info"]["result"]["info"]["amendment_blocked"] = True
    d["info"]["result"]["info"].setdefault("warnings", []).append(
        {
            "id": WARN_AMENDMENT_BLOCKED,
            "message": "This server is amendment blocked, and must be updated to be able to stay in sync with the network.",
        }
    )
    write(a.out, "blocked", d)
    print("blocked: amendment_blocked true + warning 1002 -> amendment_blocked 1")

    for name, ago in (("majority", 86400), ("soon", 216000)):
        d = copy.deepcopy(b)
        close = with_majority(d, now - ago)
        eta = close + RIPPLE_EPOCH + MAJ_SECS
        write(a.out, name, d)
        print(
            f"{name}: unknown_{DRILL_AMENDMENT[:16]}... CloseTime {close} (Ripple) = now-{ago}s;"
            f" ETA {close} + {RIPPLE_EPOCH} + {MAJ_SECS} = {eta} = now+{eta - now}s"
        )

    d = copy.deepcopy(b)
    d["foundation"]["result"]["info"]["build_version"] = "1.0.10"
    write(a.out, "lag", d)
    print("lag: foundation build_version 1.0.10 > node 1.0.9 -> behind_foundation 1")

    write(a.out, "failing", b, raw_info="<html>502 Bad Gateway</html>\n")
    print("failing: server_info is not JSON -> up 0")


if __name__ == "__main__":
    main()
