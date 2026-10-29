#!/usr/bin/env python3
"""vulnscan_parse: turn a Canonical USN OVAL feed + an `oscap oval eval --results` file into findings JSON.

Usage: vulnscan_parse.py FEED_XML RESULTS_XML --now EPOCH --max-age-days N

Prints one JSON object on stdout and exits 0, or prints one error line on stderr and exits 2:
  - the feed does not parse, has no <oval:timestamp>, or is older than N days (a stale feed silently drops every
    USN published since, so it is refused, not used);
  - the feed has no inventory definition (def:100 "Ubuntu 22.04 is installed") or no patch definitions;
  - the results do not parse, or do not hold exactly one result for every definition of the feed;
  - the inventory definition is not "true" (wrong feed for this release: every patch check would be skipped);
  - any definition evaluated to "error"/"unknown"/"not evaluated" (an unknown is never read as "not affected").
Only stdlib (xml.etree iterparse; the results file of a real run is ~45 MB).
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

D = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
COMMON = "{http://oval.mitre.org/XMLSchema/oval-common-5}"
LINDEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}"
R = "{http://oval.mitre.org/XMLSchema/oval-results-5}"
LINSYS = "{http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux}"
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "none", "unknown")
# criterion comment, e.g. "python-pip source package in esm-apps/jammy, is affected and has been fixed (note: 'V')."
CRIT_RE = re.compile(r"^(?P<src>\S+) source package in (?P<pocket>\S+), is affected and (?P<state>.+?)\s*(\(note: '(?P<note>[^']*)'\))?\.?$")


class Bad(Exception):
    pass


def localname(tag):
    return tag.rsplit("}", 1)[-1]


def parse_feed(path):
    """-> (timestamp str, defs {id: dict}, tests {test_id: state_id}, states {state_id: evr})"""
    defs, tests, states, ts = {}, {}, {}, None
    try:
        for _, el in ET.iterparse(path, events=("end",)):
            tag = el.tag
            if tag == COMMON + "timestamp" and ts is None:
                ts = (el.text or "").strip()
            elif tag == D + "definition":
                defs[el.get("id")] = definition(el)
                el.clear()
            elif tag == LINDEF + "dpkginfo_test":
                st = el.find(LINDEF + "state")
                tests[el.get("id")] = st.get("state_ref") if st is not None else None
                el.clear()
            elif tag == LINDEF + "dpkginfo_state":
                evr = el.find(LINDEF + "evr")
                states[el.get("id")] = (evr.text or "").strip() if evr is not None else None
                el.clear()
    except (ET.ParseError, OSError) as e:
        raise Bad(f"feed does not parse: {e}")
    if not ts:
        raise Bad("feed has no <oval:timestamp>")
    return ts, defs, tests, states


def definition(el):
    m = el.find(D + "metadata")
    title = (m.findtext(D + "title") or "").strip() if m is not None else ""
    adv = m.find(D + "advisory") if m is not None else None
    sev = (adv.findtext(D + "severity") or "").strip().lower() if adv is not None else ""
    issued = adv.find(D + "issued") if adv is not None else None
    cves = sorted({(c.text or "").strip() for c in adv.findall(D + "cve")} - {""}) if adv is not None else []
    usn = ""
    if m is not None:
        for ref in m.findall(D + "reference"):
            if ref.get("source") == "USN":
                usn = ref.get("ref_id", "")
                break
    crits = {}
    crit_root = el.find(D + "criteria")
    if crit_root is not None:
        for c in crit_root.iter(D + "criterion"):
            crits[c.get("test_ref")] = (c.get("comment") or "").strip()
    return {
        "class": el.get("class", ""),
        "usn": usn,
        "title": title,
        "severity": sev if sev in SEVERITIES else "unknown",
        "issued": issued.get("date", "") if issued is not None else "",
        "cves": cves,
        "criteria": crits,
    }


def parse_results(path):
    """-> (def results {id: result}, true tests {test_id: [item_id]}, items {item_id: (name, evr)})"""
    dres, ttrue, items = {}, {}, {}
    try:
        for _, el in ET.iterparse(path, events=("end",)):
            tag = el.tag
            if tag == R + "definition":
                did = el.get("definition_id")
                if did in dres:
                    raise Bad(f"results hold {did} twice")
                dres[did] = el.get("result", "")
                el.clear()
            elif tag == R + "test":
                if el.get("result") == "true":
                    ttrue[el.get("test_id")] = [t.get("item_id") for t in el.findall(R + "tested_item") if t.get("result") == "true"]
                el.clear()
            elif tag == LINSYS + "dpkginfo_item":
                items[el.get("id")] = (el.findtext(LINSYS + "name") or "", el.findtext(LINSYS + "evr") or "")
                el.clear()
    except (ET.ParseError, OSError) as e:
        raise Bad(f"results do not parse: {e}")
    return dres, ttrue, items


def feed_epoch(ts):
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        raise Bad(f"feed timestamp not ISO 8601: {ts!r}")
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)  # Canonical's generator writes UTC without an offset
    return int(t.timestamp())


def build(feed, results, now, max_age_days):
    ts, defs, tests, states = parse_feed(feed)
    fts = feed_epoch(ts)
    age = now - fts
    if age > max_age_days * 86400:
        raise Bad(f"feed is stale: timestamp {ts} is {age // 86400} days old (limit {max_age_days})")
    inv = [k for k, v in defs.items() if v["class"] == "inventory"]
    patch = [k for k, v in defs.items() if v["class"] == "patch"]
    if not inv or not patch:
        raise Bad(f"feed has {len(inv)} inventory and {len(patch)} patch definitions (need >= 1 of each)")
    dres, ttrue, items = parse_results(results)
    missing = sorted(set(defs) - set(dres))
    extra = sorted(set(dres) - set(defs))
    if missing or extra:
        raise Bad(f"results do not match the feed: {len(missing)} definitions without a result, {len(extra)} unknown")
    if not all(dres[k] == "true" for k in inv):
        raise Bad(f"inventory definition is {dres[inv[0]]!r}, not 'true': this feed is not for this host's release")
    odd = sorted(k for k, v in dres.items() if v not in ("true", "false"))
    if odd:
        raise Bad(f"{len(odd)} definitions evaluated to {dres[odd[0]]!r} (first: {odd[0]}); refusing to read them as not affected")
    findings = []
    for did in patch:
        if dres[did] != "true":
            continue
        d = defs[did]
        pkgs, fix = [], set()
        for test_id, comment in d["criteria"].items():
            if test_id not in ttrue:
                continue
            m = CRIT_RE.match(comment)
            src = m.group("src") if m else ""
            pocket = m.group("pocket") if m else ""
            fix.add("esm" if pocket.startswith("esm") else "archive")
            for iid in ttrue[test_id]:
                name, evr = items.get(iid, ("", ""))
                pkgs.append({"source": src, "binary": name, "installed": evr, "fixed": states.get(tests.get(test_id)) or "",
                             "pocket": pocket})
        findings.append({
            "id": did, "usn": d["usn"], "title": d["title"], "severity": d["severity"], "issued": d["issued"],
            "cves": d["cves"], "fix": "esm" if fix == {"esm"} else ("archive" if fix else "unknown"),
            "packages": sorted(pkgs, key=lambda p: (p["source"], p["binary"])),
        })
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["usn"]))
    by_sev = {s: {"archive": 0, "esm": 0, "unknown": 0} for s in SEVERITIES}
    for f in findings:
        by_sev[f["severity"]][f["fix"]] += 1
    return {
        "feed": {"timestamp": ts, "timestamp_epoch": fts, "age_seconds": age, "definitions": len(defs), "patch_definitions": len(patch)},
        "affected_usns": len(findings),
        "affected_cves": len({c for f in findings for c in f["cves"]}),
        "by_severity": by_sev,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("feed")
    ap.add_argument("results")
    ap.add_argument("--now", type=int, required=True)
    ap.add_argument("--max-age-days", type=int, required=True)
    a = ap.parse_args()
    try:
        out = build(a.feed, a.results, a.now, a.max_age_days)
    except Bad as e:
        print(str(e), file=sys.stderr)
        return 2
    json.dump(out, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
