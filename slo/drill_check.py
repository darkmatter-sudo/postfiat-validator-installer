#!/usr/bin/env python3
"""Pass/fail checker for slo/drill.sh captures (kept separate so it can be tested on synthetic captures).

Usage: drill_check.py SAMPLES.jsonl NTFY.jsonl          check a finished capture
       drill_check.py sample PROM_URL PHASE NODE_STATE   print one SAMPLES line (Prometheus HTTP API, read-only)
       drill_check.py ntfy < ntfy.sh JSON stream         keep {"time","title"} of message events (drops topic)

SAMPLES.jsonl: one object per 15 s poll written by drill.sh
  {"t": epoch, "phase": "B"|"gap"|"A-down"|"A-recover"|"A-resolve", "node": "full"|"unreachable"|...,
   "maint": 0|1|null, "bad": 0|1|null, "r5m": float|null, "r1h": float|null,
   "alerts": {"<alertname>": "pending"|"firing", ...}}        # Prometheus /api/v1/alerts at that poll
NTFY.jsonl: the throwaway topic read back from ntfy.sh, one {"time": epoch, "title": str} per message.

Drill B (planned stop inside a pft-maint window) passes when every B sample has maint == 1 and bad == 0,
no PFTSLO* alert is pending or firing in any B sample, and no PFTSLO* message reached the topic from the first
B sample until the first A-down sample.
Drill A (unplanned stop, no window) passes when bad == 1 is recorded while down, PFTSLOFastBurn goes pending
before firing, a "[FIRING] PFTSLOFastBurn" message arrives no earlier than 60 s before the first firing poll,
and the final A-resolve sample has no PFTSLOFastBurn. PFTSLOSlowBurn and resolved messages are reported, not
required (resolved webhooks can arrive after the script exits). Polls that failed ({"error": ...}) are left out
of the per-sample checks; at least 90 % of polls must have answered. Exit 0 = PASS, 1 = FAIL, 2 = unusable input.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

FAST = "PFTSLOFastBurn"


def load(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{n}: {exc}") from exc
    return out


QUERIES = {"maint": "pft:sli_maint:bool", "bad": "pft:sli_bad:bool",
           "r5m": "pft:sli_error:ratio_rate5m", "r1h": "pft:sli_error:ratio_rate1h"}


def vec_value(resp):
    """First sample value of an instant-query vector response, or None when there is no series."""
    result = (resp.get("data") or {}).get("result") or []
    return float(result[0]["value"][1]) if result else None


def alerts_map(resp):
    """{alertname: state} from /api/v1/alerts; firing wins over pending when several series share a name."""
    out = {}
    for a in (resp.get("data") or {}).get("alerts") or []:
        name, state = a["labels"]["alertname"], a["state"]
        if out.get(name) != "firing":
            out[name] = state
    return out


def build_sample(t, phase, node, vectors, alerts):
    s = {"t": int(t), "phase": phase, "node": node}
    for key in QUERIES:
        v = vec_value(vectors[key])
        s[key] = int(v) if key in ("maint", "bad") and v is not None else v
    s["alerts"] = alerts_map(alerts)
    return s


def get_json(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


def sample(prom, phase, node):
    vectors = {k: get_json("{}/api/v1/query?{}".format(prom, urllib.parse.urlencode({"query": q})))
               for k, q in QUERIES.items()}
    return build_sample(time.time(), phase, node, vectors, get_json(prom + "/api/v1/alerts"))


def ntfy_reduce(lines):
    for line in lines:
        line = line.strip()
        if line:
            m = json.loads(line)
            if m.get("event") == "message":
                yield {"time": m["time"], "title": m.get("title", "")}


def slo_alerts(sample):
    return {k: v for k, v in (sample.get("alerts") or {}).items() if k.startswith("PFTSLO")}


def first(samples, pred):
    return next((s for s in samples if pred(s)), None)


def check(samples, msgs):
    """Return (results, info): results is a list of (name, ok, detail)."""
    res, info = [], []
    errs = [s for s in samples if "error" in s]
    samples = [s for s in samples if "error" not in s]
    total = len(samples) + len(errs)
    res.append(("polls answered >= 90%", total > 0 and len(samples) >= 0.9 * total,
                f"{len(samples)}/{total} answered"))
    b = [s for s in samples if s.get("phase") == "B"]
    a = [s for s in samples if str(s.get("phase", "")).startswith("A-")]
    down = [s for s in a if s["phase"] == "A-down"]
    resolve = [s for s in a if s["phase"] == "A-resolve"]

    # --- drill B
    res.append(("B: samples recorded", len(b) > 0, f"{len(b)} samples"))
    if b:
        notmaint = [s for s in b if s.get("maint") != 1]
        res.append(("B: pft:sli_maint:bool == 1 in every sample", not notmaint,
                    f"{len(notmaint)}/{len(b)} samples not maint"))
        badb = [s for s in b if s.get("bad") != 0]
        res.append(("B: pft:sli_bad:bool == 0 in every sample", not badb,
                    f"{len(badb)}/{len(b)} samples bad or missing"))
        ab = sorted({"{}={}".format(*kv) for s in b for kv in slo_alerts(s).items()})
        res.append(("B: no PFTSLO* alert pending/firing", not ab, ", ".join(ab) or "none"))
        b0 = b[0]["t"]
        b1 = down[0]["t"] if down else b[-1]["t"] + 300
        mb = [m for m in msgs if b0 <= m.get("time", 0) < b1 and "PFTSLO" in m.get("title", "")]
        res.append(("B: no PFTSLO* message on the topic", not mb, f"{len(mb)} messages"))
        info.append("B: node states seen: {}".format(",".join(sorted({str(s.get("node")) for s in b}))))

    # --- drill A
    res.append(("A: down samples recorded", len(down) > 0, f"{len(down)} samples"))
    badd = [s for s in down if s.get("bad") == 1]
    res.append(("A: pft:sli_bad:bool == 1 while down", len(badd) > 0, f"{len(badd)}/{len(down)} down samples bad"))
    pend = first(a, lambda s: s.get("alerts", {}).get(FAST) == "pending")
    fire = first(a, lambda s: s.get("alerts", {}).get(FAST) == "firing")
    res.append(("A: FastBurn pending seen", pend is not None, "t={}".format((pend or {}).get("t"))))
    res.append(("A: FastBurn firing seen", fire is not None, "t={}".format((fire or {}).get("t"))))
    if pend and fire:
        res.append(("A: pending before firing", pend["t"] < fire["t"], f"{fire['t'] - pend['t']}s apart"))
    fm = [m for m in msgs if m.get("title", "") == f"[FIRING] {FAST}"]
    ok = bool(fire) and any(m["time"] >= fire["t"] - 60 for m in fm)
    res.append(("A: [FIRING] PFTSLOFastBurn message delivered", ok, f"{len(fm)} firing messages"))
    last = resolve[-1] if resolve else None
    res.append(("A: FastBurn resolved by the last sample", last is not None and FAST not in (last.get("alerts") or {}),
                "last alerts: %s" % (json.dumps(last.get("alerts")) if last else "no A-resolve sample")))
    slow = sorted({v for s in a for k, v in (s.get("alerts") or {}).items() if k == "PFTSLOSlowBurn"})
    info.append("A: PFTSLOSlowBurn states seen: %s" % (",".join(slow) or "none"))
    info.append(f"A: resolved messages: {sum(1 for m in msgs if m.get('title', '').startswith('[RESOLVED] PFTSLO'))}")
    other = sorted({k for s in samples for k in (s.get("alerts") or {}) if not k.startswith("PFTSLO")})
    info.append("non-SLO alerts seen (silenced in Alertmanager): %s" % (",".join(other) or "none"))
    return res, info


def main(argv):
    if len(argv) == 5 and argv[1] == "sample":
        try:
            print(json.dumps(sample(argv[2], argv[3], argv[4]), sort_keys=True))
        except (OSError, ValueError, KeyError) as exc:   # one failed poll must not end the drill
            print(json.dumps({"t": int(time.time()), "phase": argv[3], "node": argv[4], "error": str(exc)}))
        return 0
    if len(argv) == 2 and argv[1] == "ntfy":
        for m in ntfy_reduce(sys.stdin):
            print(json.dumps(m, sort_keys=True))
        return 0
    if len(argv) != 3:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    try:
        samples, msgs = load(argv[1]), load(argv[2])
    except (OSError, ValueError) as exc:
        print(f"unusable input: {exc}", file=sys.stderr)
        return 2
    res, info = check(samples, msgs)
    for name, ok, detail in res:
        print("[{}] {} ({})".format("PASS" if ok else "FAIL", name, detail))
    for line in info:
        print(f"[INFO] {line}")
    bad = sum(1 for _, ok, _ in res if not ok)
    print(f"RESULT: {'PASS' if not bad else 'FAIL'} - {len(res) - bad}/{len(res)} checks passed")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
