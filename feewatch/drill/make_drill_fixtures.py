#!/usr/bin/env python3
"""make_drill_fixtures: build the drill's synthetic answers from the REAL validator answers in ../tests/fixtures.

Usage: python3 -I feewatch/drill/make_drill_fixtures.py   (writes feewatch/drill/fixtures/*.json, prints a summary)

Each case changes only the fields it needs, in the field shapes postfiatd 1.0.9 really sends (sizes and levels as
decimal strings in `fee`, load factors as numbers in `server_info`). No answer is sent anywhere: the drill feeds these
files to `pft-feewatch replay`, so no transaction and no network load is generated.

  healthy     the real answers, unchanged                                   -> no alert
  queue       current_queue_size 1800 of max 2000 (fill 0.9 > 0.8)          -> PFTTxQueueNearFull
  escalated   open ledger 40 > expected 32 tx, open_ledger_fee 60 drops      -> PFTFeeEscalated (6x >= 4)
              (level 1536 = 6 x 256), load_factor 6 = fee_escalation 6
  localload   load_factor_local 3, net omitted (= 1), load_factor 3          -> PFTLocalLoadHigh
  failing     server_info cut off mid-answer (not JSON)                      -> PFTFeewatchStale (up 0)
  (the stale case reuses `healthy` with a collect timestamp 10 min in the past -> PFTFeewatchStale (age))
"""

import copy
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "tests", "fixtures")
OUT = os.path.join(HERE, "fixtures")


def load(name):
    with open(os.path.join(SRC, name), encoding="utf-8") as f:
        return json.load(f)


def save(name, doc):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        if isinstance(doc, str):
            f.write(doc)
        else:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")


def main():
    os.makedirs(OUT, exist_ok=True)
    fee0, info0 = load("validator_fee.json"), load("validator_server_info.json")
    assert isinstance(info0["result"]["info"].get("load"), dict), (
        "source server_info must be an admin answer"
    )

    save("healthy_fee.json", fee0)
    save("healthy_info.json", info0)

    fee = copy.deepcopy(fee0)
    fee["result"]["current_queue_size"] = "1800"
    save("queue_fee.json", fee)

    fee = copy.deepcopy(fee0)
    r = fee["result"]
    r["current_ledger_size"] = "40"
    r["drops"]["open_ledger_fee"] = "60"
    r["levels"]["open_ledger_level"] = "1536"
    save("escalated_fee.json", fee)
    info = copy.deepcopy(info0)
    info["result"]["info"]["load_factor"] = 6
    info["result"]["info"]["load_factor_fee_escalation"] = 6
    save("escalated_info.json", info)

    info = copy.deepcopy(info0)
    info["result"]["info"]["load_factor"] = 3
    info["result"]["info"]["load_factor_local"] = 3
    save("localload_info.json", info)

    text = json.dumps(info0)
    save("failing_info.json", text[: len(text) // 2])

    for name in sorted(os.listdir(OUT)):
        print(f"{name:<22} {os.path.getsize(os.path.join(OUT, name)):6d} bytes")


if __name__ == "__main__":
    main()
