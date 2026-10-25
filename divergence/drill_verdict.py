#!/usr/bin/env python3
"""Pass/fail for the pft-divergence alert drill (divergence/drill.sh).

  drill_verdict.py SAMPLES.jsonl NTFY.jsonl      -> prints one line per criterion, exit 0 only if all pass
  drill_verdict.py ntfy < ntfy.sh JSON stream     -> {"time","title"} per message event (drops the topic)
SAMPLES: one {"t","phase","state":{source: value},"alert":"none|pending|firing"} per poll, phase wrong|fixed.
"""
import json
import sys

ALERT = "PFTLedgerDiverged"


def ntfy_reduce(lines):
    for ln in lines:
        try:
            m = json.loads(ln)
        except ValueError:
            continue
        if m.get("event") == "message":
            yield {"time": m.get("time"), "title": m.get("title", "")}


def verdict(samples, msgs, stub="stub", real=("validator", "sentry")):
    wrong = [s for s in samples if s["phase"] == "wrong"]
    fixed = [s for s in samples if s["phase"] == "fixed"]
    fire = [m["time"] for m in msgs if m["title"] == "[FIRING] " + ALERT]
    res = [m["time"] for m in msgs if m["title"] == "[RESOLVED] " + ALERT]
    first_wrong = min((s["t"] for s in wrong), default=None)
    checks = [
        ("stub source DIVERGED (metric 1) while the stub lies", any(s["state"].get(stub) == 1 for s in wrong)),
        (ALERT + " firing in Prometheus while the stub lies", any(s["alert"] == "firing" for s in wrong)),
        ("[FIRING] " + ALERT + " on the throwaway topic", bool(fire) and first_wrong is not None
         and min(fire) >= first_wrong),
        ("[RESOLVED] " + ALERT + " on the topic after the FIRING", bool(fire) and any(t >= min(fire) for t in res)),
        ("after the fix: stub AGREE (0) and no alert", bool(fixed) and fixed[-1]["state"].get(stub) == 0
         and fixed[-1]["alert"] == "none"),
        ("real sources stayed AGREE (0) in every sample", bool(samples) and all(
            s["state"].get(r) == 0 for s in samples for r in real)),
    ]
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    return all(ok for _, ok in checks)


def main(argv):
    if len(argv) == 2 and argv[1] == "ntfy":
        for m in ntfy_reduce(sys.stdin):
            print(json.dumps(m))
        return 0
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 3
    with open(argv[1]) as f:
        samples = [json.loads(ln) for ln in f if ln.strip()]
    with open(argv[2]) as f:
        msgs = [json.loads(ln) for ln in f if ln.strip()]
    ok = verdict(samples, msgs)
    print("DRILL " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
