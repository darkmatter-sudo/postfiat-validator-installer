#!/usr/bin/env python3
"""Turn a raw admin capture into a committed fixture: get_counts is kept as is (counts only, no identifiers);
server_info keeps only the fields pft-internals reads plus build_version/server_state, so host ids, node public
keys and the port list never reach the repo. The `uptime` string of get_counts is kept (no identifier).

Usage: python3 -I tests/redact_capture.py get_counts|server_info RAW.json > tests/fixtures/NAME.json
"""

import json
import sys

KEEP_INFO = ("build_version", "server_state", "uptime", "load", "counters")


def main():
    kind, path = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if kind == "server_info":
        info = doc["result"]["info"]
        doc["result"]["info"] = {k: info[k] for k in KEEP_INFO if k in info}
    elif kind != "get_counts":
        sys.exit("kind must be get_counts or server_info")
    json.dump(doc, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
