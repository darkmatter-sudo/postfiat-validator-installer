#!/usr/bin/env python3
"""Gap accounting for postfiatd complete_ledgers inside the [node_db] online_delete window.

Subcommands (inputs are files: the collector saves each RPC answer, tests pass fixtures):
  status  --info server_info.json --cfg cfg.txt --node NAME [--now EPOCH]
          -> pft_backfill_* Prometheus textfile lines on stdout
  plan    --info server_info.json --cfg cfg.txt --max-ledgers N
          -> missing ledger sequences inside the window, newest first, at most N (one per line)
  summary --info server_info.json --cfg cfg.txt
          -> one JSON object (window, ranges, gaps) for logs and the shell script

Source facts (postfiatd 1.0.9, commit 32723c15):
  RangeSet.h:100-111         complete_ledgers = disjoint "a-b" / "a" intervals joined by ",", or "empty"
  SHAMapStoreImp.cpp:331-344 rotate when validated >= lastRotated + online_delete; clearPrior(lastRotated)
                             deletes below the PREVIOUS rotation point, so a complete node always holds at
                             least the newest online_delete ledgers: window = [validated - N + 1, validated]
  SHAMapStoreImp.cpp:151     online_delete >= ledger_history (default 256), so after a restart the node's own
                             backfill can stop short of the window: that shortfall is the "edge" gap below
  RPCHelpers.cpp:1069-1131   ledger_request by index takes the hash from the validated chain (skip list)

Gap kinds inside the window:
  interior  missing ledgers ABOVE the oldest held ledger in the window (a real hole in the history)
  edge      missing ledgers below the oldest held ledger (history not yet acquired after a (re)start)

Exit 0 with output; exit 1 with one error line on stderr if an input is missing or malformed.
"""

import argparse
import itertools
import json
import re
import sys

RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")
MAX_GAP_SERIES = 8  # bounded label cardinality: the largest gaps only
MAX_PLAN = 10000


class InputError(Exception):
    pass


def parse_ranges(text):
    """complete_ledgers string -> sorted list of (lo, hi); 'empty' -> []. Rejects overlaps and disorder."""
    if not isinstance(text, str):
        raise InputError("complete_ledgers is not a string")
    text = text.strip()
    if text == "empty":
        return []
    out = []
    for part in text.split(","):
        m = RANGE_RE.match(part)
        if not m:
            raise InputError(f"bad complete_ledgers interval {part!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) is not None else lo
        if lo > hi or lo <= 0:
            raise InputError(f"bad complete_ledgers interval {part!r}")
        if out and lo <= out[-1][1] + 1:
            raise InputError(
                f"complete_ledgers intervals out of order or touching at {part!r}"
            )
        out.append((lo, hi))
    return out


def online_delete(cfg_text):
    """[node_db] online_delete from the cfg lines; None when absent (full history, nothing to account)."""
    section = None
    value = None
    for raw in cfg_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line.lower()
            continue
        if section == "[node_db]" and "=" in line:
            key, _, val = line.partition("=")
            if key.strip().lower() == "online_delete":
                val = val.strip()
                if not val.isdigit():
                    raise InputError(f"online_delete is not a number: {val!r}")
                value = int(val)
    if value == 0:
        return None
    return value


def load_info(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read server_info {path}: {exc}") from exc
    info = (doc.get("result") or {}).get("info") if isinstance(doc, dict) else None
    if not isinstance(info, dict):
        raise InputError(f"{path}: no result.info")
    return info


def account(info, od):
    """Window and gap accounting; returns a dict (see summary)."""
    state = info.get("server_state", "unknown")
    vl = info.get("validated_ledger") or {}
    seq = vl.get("seq")
    if not isinstance(seq, int) or seq <= 0:
        raise InputError("no validated_ledger.seq")
    ranges = parse_ranges(info.get("complete_ledgers", ""))
    res = {
        "server_state": state,
        "validated": seq,
        "online_delete": od,
        "ranges": [list(r) for r in ranges],
        "window": None,
        "held": 0,
        "missing_interior": 0,
        "missing_edge": 0,
        "gaps": [],
    }
    if od is None:
        return res
    wlo, whi = max(1, seq - od + 1), seq
    res["window"] = [wlo, whi]
    held = []
    for lo, hi in ranges:
        a, b = max(lo, wlo), min(hi, whi)
        if a <= b:
            held.append((a, b))
    res["held"] = sum(b - a + 1 for a, b in held)
    if not held:
        res["missing_edge"] = whi - wlo + 1
        res["gaps"] = [{"kind": "edge", "lo": wlo, "hi": whi, "size": whi - wlo + 1}]
        return res
    gaps = []
    if held[0][0] > wlo:
        gaps.append({"kind": "edge", "lo": wlo, "hi": held[0][0] - 1})
    for (_, b), (c, _) in itertools.pairwise(held):
        gaps.append({"kind": "interior", "lo": b + 1, "hi": c - 1})
    if (
        held[-1][1] < whi
    ):  # newest ledger(s) of the window not held (node behind its own validated seq)
        gaps.append({"kind": "interior", "lo": held[-1][1] + 1, "hi": whi})
    for g in gaps:
        g["size"] = g["hi"] - g["lo"] + 1
    res["gaps"] = gaps
    res["missing_edge"] = sum(g["size"] for g in gaps if g["kind"] == "edge")
    res["missing_interior"] = sum(g["size"] for g in gaps if g["kind"] == "interior")
    return res


def plan(acc, limit):
    """Missing sequences, newest first (interior holes before the edge), at most `limit`."""
    out = []
    for kind in ("interior", "edge"):
        for g in sorted(
            (g for g in acc["gaps"] if g["kind"] == kind), key=lambda g: -g["hi"]
        ):
            s = g["hi"]
            while s >= g["lo"] and len(out) < limit:
                out.append(s)
                s -= 1
    return out


def metrics(acc, node, now):
    lab = f'node="{node}"'
    full = 1 if acc["server_state"] in ("full", "proposing", "validating") else 0
    lines = [
        "# HELP pft_backfill_up 1 if the status run read server_info and the node config.",
        "# TYPE pft_backfill_up gauge",
        f"pft_backfill_up{{{lab}}} 1",
        "# HELP pft_backfill_node_full 1 if server_state is full/proposing/validating.",
        "# TYPE pft_backfill_node_full gauge",
        f"pft_backfill_node_full{{{lab}}} {full}",
        "# HELP pft_backfill_online_delete Configured [node_db] online_delete (0 = unset, full history).",
        "# TYPE pft_backfill_online_delete gauge",
        f"pft_backfill_online_delete{{{lab}}} {acc['online_delete'] or 0}",
        "# HELP pft_backfill_validated_seq Validated ledger sequence at the status run.",
        "# TYPE pft_backfill_validated_seq gauge",
        f"pft_backfill_validated_seq{{{lab}}} {acc['validated']}",
        "# HELP pft_backfill_ranges Number of disjoint complete_ledgers intervals.",
        "# TYPE pft_backfill_ranges gauge",
        f"pft_backfill_ranges{{{lab}}} {len(acc['ranges'])}",
        "# HELP pft_backfill_window_held_ledgers Ledgers held inside the online_delete window.",
        "# TYPE pft_backfill_window_held_ledgers gauge",
        f"pft_backfill_window_held_ledgers{{{lab}}} {acc['held']}",
        "# HELP pft_backfill_missing_ledgers Ledgers missing inside the online_delete window, by gap kind.",
        "# TYPE pft_backfill_missing_ledgers gauge",
        f'pft_backfill_missing_ledgers{{{lab},kind="interior"}} {acc["missing_interior"]}',
        f'pft_backfill_missing_ledgers{{{lab},kind="edge"}} {acc["missing_edge"]}',
        "# HELP pft_backfill_gaps Number of gaps inside the online_delete window, by kind.",
        "# TYPE pft_backfill_gaps gauge",
    ]
    for kind in ("interior", "edge"):
        n = sum(1 for g in acc["gaps"] if g["kind"] == kind)
        lines.append(f'pft_backfill_gaps{{{lab},kind="{kind}"}} {n}')
    lines += [
        f"# HELP pft_backfill_gap_size Size of the largest gaps (at most {MAX_GAP_SERIES} series).",
        "# TYPE pft_backfill_gap_size gauge",
    ]
    for g in sorted(acc["gaps"], key=lambda g: (-g["size"], -g["hi"]))[:MAX_GAP_SERIES]:
        lines.append(
            f'pft_backfill_gap_size{{{lab},kind="{g["kind"]}",first="{g["lo"]}",last="{g["hi"]}"}} {g["size"]}'
        )
    lines += [
        "# HELP pft_backfill_status_timestamp_seconds Unix time of the status run.",
        "# TYPE pft_backfill_status_timestamp_seconds gauge",
        f"pft_backfill_status_timestamp_seconds{{{lab}}} {now}",
    ]
    return "\n".join(lines) + "\n"


NODE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=("status", "plan", "summary"))
    ap.add_argument("--info", required=True)
    ap.add_argument("--cfg", required=True)
    ap.add_argument("--node", default="postfiatd")
    ap.add_argument("--now", type=int, default=None)
    ap.add_argument("--max-ledgers", type=int, default=0)
    a = ap.parse_args(argv)
    try:
        if not NODE_RE.match(a.node):
            raise InputError(f"bad node name {a.node!r}")
        try:
            with open(a.cfg, encoding="utf-8") as fh:
                cfg = fh.read()
        except OSError as exc:
            raise InputError(f"cannot read cfg {a.cfg}: {exc}") from exc
        acc = account(load_info(a.info), online_delete(cfg))
        if a.cmd == "summary":
            print(json.dumps(acc, sort_keys=True))
        elif a.cmd == "plan":
            if not 1 <= a.max_ledgers <= MAX_PLAN:
                raise InputError(f"--max-ledgers must be 1..{MAX_PLAN}")
            for s in plan(acc, a.max_ledgers):
                print(s)
        else:
            if a.now is None:
                import time

                a.now = int(time.time())
            sys.stdout.write(metrics(acc, a.node, a.now))
    except InputError as exc:
        print(f"backfill_parse: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
