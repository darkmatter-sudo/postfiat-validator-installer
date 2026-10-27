#!/usr/bin/env python3
"""Pass/fail for the pft-resources live drill (drill.sh).

  drill_verdict.py SAMPLES.jsonl NTFY.jsonl   -> one PASS/FAIL line per criterion + a timeline, exit 0 only if all pass
  drill_verdict.py ntfy < ntfy.sh JSON stream  -> {"time","title","message"} per message event (drops topic and ids)

SAMPLES: one JSON object per poll, written by drill.sh:
  {"t": unix, "phase": "idle|load|oom|calm", "nodes": {"validator": state, "sentry": state},
   "prom": {CONTAINER: {ALERTNAME: "pending|firing"}}, "am": {CONTAINER: [ALERTNAME, ...]},
   "real": [ALERTNAME, ...],   # pft-resources alerts on the REAL containers (must stay empty)
   "up": {CONTAINER: 0|1|null}}
"""
import json
import sys

CONTAINERS = ("pft-res-drill-v", "pft-res-drill-s")
LOAD_ALERTS = ("PFTFdNearLimit", "PFTPidsNearLimit", "PFTMemoryNearLimit")
OOM_ALERT = "PFTContainerOOMKill"


def ntfy_reduce(lines):
    for ln in lines:
        try:
            m = json.loads(ln)
        except ValueError:
            continue
        if isinstance(m, dict) and m.get("event") == "message":
            yield {"time": m.get("time"), "title": m.get("title", ""), "message": m.get("message", "")}


def msg_times(msgs, status, alert, container):
    """Times of '[STATUS] ALERT' messages whose body names CONTAINER as a whole word (summaries put it at the start,
    or at the end for "OOM kill in NAME")."""
    title = "[%s] %s" % (status, alert)
    return sorted(m["time"] for m in msgs
                  if m.get("title") == title and isinstance(m.get("message"), str)
                  and container in m["message"].split())


def first(samples, pred):
    return next((s["t"] for s in samples if pred(s)), None)


def verdict(samples, msgs, out=print):
    checks = []
    phase_start = {}
    for s in samples:
        phase_start.setdefault(s["phase"], s["t"])
    load0, oom0, calm0 = phase_start.get("load"), phase_start.get("oom"), phase_start.get("calm")
    checks.append(("phases idle -> load -> oom -> calm all sampled, in order",
                   None not in (phase_start.get("idle"), load0, oom0, calm0)
                   and phase_start["idle"] < load0 < oom0 < calm0))
    timeline = []
    for c in CONTAINERS:
        for a in LOAD_ALERTS + (OOM_ALERT,):
            start = oom0 if a == OOM_ALERT else load0
            ph = ("oom", "calm") if a == OOM_ALERT else ("load",)
            fired = first(samples, lambda s, c=c, a=a, ph=ph: s["phase"] in ph
                          and s.get("prom", {}).get(c, {}).get(a) == "firing")
            fmsg = [t for t in msg_times(msgs, "FIRING", a, c) if start is not None and t >= start]
            rmsg = [t for t in msg_times(msgs, "RESOLVED", a, c) if fmsg and t >= fmsg[0]]
            early = [t for t in msg_times(msgs, "FIRING", a, c) if start is None or t < start]
            checks.append(("%s %s firing in Prometheus during %s" % (c, a, "/".join(ph)), fired is not None))
            checks.append(("%s [FIRING] %s on the throwaway topic after the %s phase began" % (c, a, ph[0]),
                           bool(fmsg) and not early))
            checks.append(("%s [RESOLVED] %s on the topic after its FIRING" % (c, a), bool(rmsg)))
            timeline.append("%s %-20s prom firing %s | FIRING msg %s | RESOLVED msg %s" % (
                c, a, fired, fmsg[0] if fmsg else None, rmsg[0] if rmsg else None))
    last = samples[-1] if samples else {}
    checks.append(("last sample (calm): no drill alert in Prometheus or Alertmanager",
                   bool(last) and last.get("phase") == "calm"
                   and not any(last.get("prom", {}).get(c) for c in CONTAINERS)
                   and not any(last.get("am", {}).get(c) for c in CONTAINERS)))
    loaded = [s for s in samples if s["phase"] in ("load", "oom", "calm")]
    checks.append(("collector up 1 for both drill containers in every load/oom/calm sample",
                   bool(loaded) and all(s.get("up", {}).get(c) == 1 for s in loaded for c in CONTAINERS)))
    bad = [(s["t"], k, v) for s in samples for k, v in sorted(s.get("nodes", {}).items()) if v != "full"]
    checks.append(("validator and sentry server_state full in every sample (%d samples)" % len(samples),
                   bool(samples) and not bad
                   and all(set(s.get("nodes", {})) == {"validator", "sentry"} for s in samples)))
    real = sorted({a for s in samples for a in s.get("real", [])})
    checks.append(("no pft-resources alert on the real postfiatd containers in any sample", bool(samples) and not real))
    for name, ok in checks:
        out(("PASS " if ok else "FAIL ") + name)
    if bad:
        out("  not full: " + ", ".join("%s %s=%s" % b for b in bad[:10]))
    if real:
        out("  real-container alerts: " + ", ".join(real))
    out("timeline (unix s):")
    for ln in timeline:
        out("  " + ln)
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
