#!/usr/bin/env python3
"""feewatch_parse: turn one postfiatd `fee` answer + one `server_info` answer into pft_feewatch_* textfile metrics.

Usage: feewatch_parse.py --container NAME --now EPOCH --fee FILE --info FILE [--threshold X] [--history FILE]

Exit 0 = the metric text is on stdout (without the up/timestamp lines, the caller adds them). Exit 1 = a required
field is missing or malformed, or an answer is not JSON / not status success: nothing on stdout, the reason on stderr,
so the caller writes `pft_feewatch_up 0` and never stale or partial values. Stdlib only.

Required (fee, TxQ::doRPC):  current_ledger_size, current_queue_size, expected_ledger_size (decimal strings),
  drops.{base_fee,median_fee,minimum_fee,open_ledger_fee}, levels.{reference_level,minimum_level,median_level,
  open_ledger_level}, ledger_current_index.  Optional: max_queue_size (absent when the queue has no limit; then
  there is no fill ratio and PFTTxQueueNearFull cannot fire, pft_feewatch_queue_limited 0 says so).
Required (server_info): info.load_factor.

server_info load_factor breakdown (NetworkOPs::getServerInfo, human mode, postfiatd 1.0.9 @32723c15): postfiatd
OMITS a breakdown field when it equals its default, so absence is a value, not missing data:
  load_factor_server        omitted when equal to load_factor          -> = load_factor
  load_factor_fee_queue     omitted when min level == reference level  -> 1
  load_factor_local/_net/_cluster    ADMIN ONLY, omitted when == base  -> 1 (admin), unknown (non-admin)
  load_factor_fee_escalation         omitted when open == reference level (admin) -> 1; on a non-admin answer it
                                     is also omitted when it equals load_factor, so it is unknown there.
An answer is "admin" when info.load (the job queue, admin only) is present. On a non-admin answer the unknown
sources are NOT exported (no guessed 1.0) and pft_feewatch_admin is 0, so PFTLocalLoadHigh stays silent.

Derived:
  pft_feewatch_queue_fill_ratio          current_queue_size / max_queue_size
  pft_feewatch_escalation_multiple       open_ledger_fee / base_fee (drops); when base_fee is 0 postfiatd treats
                                         the base as 1 drop once escalation starts, so the level ratio
                                         open_ledger_level / reference_level is used instead (same value).
  pft_feewatch_local_load_exceeds_net    1 if load_factor_local > load_factor_net (admin answers only)
"""

import argparse
import json
import math
import re
import sys

UINT_RE = re.compile(r"^[0-9]{1,20}$")
SOURCES = ("server", "local", "net", "cluster", "fee_escalation", "fee_queue")


class Bad(Exception):
    pass


def uint(obj, key, where, optional=False):
    """Non-negative integer from a decimal string or an int (TxQ sends sizes and levels as strings)."""
    if not isinstance(obj, dict):
        raise Bad(f"missing {where}")
    if key not in obj:
        if optional:
            return None
        raise Bad(f"missing {where}.{key}")
    v = obj[key]
    if isinstance(v, bool):
        raise Bad(f"malformed {where}.{key}: {v!r}")
    if isinstance(v, int) and v >= 0:
        return v
    if isinstance(v, str) and UINT_RE.match(v):
        return int(v)
    raise Bad(f"malformed {where}.{key}: {str(v)[:40]!r}")


def factor(obj, key, where):
    """Positive load factor (int or float in server_info human mode); None when absent."""
    if key not in obj:
        return None
    v = obj[key]
    if (
        isinstance(v, bool)
        or not isinstance(v, (int, float))
        or math.isnan(v)
        or v <= 0
        or v > 1e12
    ):
        raise Bad(f"malformed {where}.{key}: {str(v)[:40]!r}")
    return float(v)


def result(doc, what):
    if not isinstance(doc, dict) or not isinstance(doc.get("result"), dict):
        raise Bad(f"{what}: no result object")
    res = doc["result"]
    if res.get("status") != "success":
        raise Bad(
            "{}: status {!r} (error {!r})".format(
                what, res.get("status"), res.get("error")
            )
        )
    return res


def parse(fee_doc, info_doc):
    fee = result(fee_doc, "fee")
    p = {
        "ledger_current_index": uint(fee, "ledger_current_index", "fee"),
        "current_ledger_size": uint(fee, "current_ledger_size", "fee"),
        "current_queue_size": uint(fee, "current_queue_size", "fee"),
        "expected_ledger_size": uint(fee, "expected_ledger_size", "fee"),
        "max_queue_size": uint(fee, "max_queue_size", "fee", optional=True),
    }
    drops = fee.get("drops")
    levels = fee.get("levels")
    p["drops"] = {
        k: uint(drops, k, "fee.drops")
        for k in ("base_fee", "median_fee", "minimum_fee", "open_ledger_fee")
    }
    p["levels"] = {
        k: uint(levels, k, "fee.levels")
        for k in (
            "reference_level",
            "minimum_level",
            "median_level",
            "open_ledger_level",
        )
    }
    if p["levels"]["reference_level"] == 0:
        raise Bad("malformed fee.levels.reference_level: 0")
    if p["max_queue_size"] == 0:
        raise Bad("malformed fee.max_queue_size: 0")

    res = result(info_doc, "server_info")
    info = res.get("info")
    if not isinstance(info, dict):
        raise Bad("server_info: missing result.info")
    total = factor(info, "load_factor", "info")
    if total is None:
        raise Bad("server_info: missing info.load_factor")
    admin = isinstance(info.get("load"), dict)
    src = {s: factor(info, "load_factor_" + s, "info") for s in SOURCES}
    if src["server"] is None:
        src["server"] = total
    if src["fee_queue"] is None:
        src["fee_queue"] = 1.0
    for s in ("local", "net", "cluster", "fee_escalation"):
        if src[s] is None and admin:
            src[s] = (
                1.0  # omitted because it equals the base (admin answers always carry it otherwise)
            )
    p["admin"] = admin
    p["load_factor"] = total
    p["sources"] = src

    if p["max_queue_size"] is not None:
        p["queue_fill_ratio"] = p["current_queue_size"] / p["max_queue_size"]
    if p["drops"]["base_fee"] > 0:
        p["escalation_multiple"] = (
            p["drops"]["open_ledger_fee"] / p["drops"]["base_fee"]
        )
    else:
        p["escalation_multiple"] = (
            p["levels"]["open_ledger_level"] / p["levels"]["reference_level"]
        )
    if admin:
        p["local_exceeds_net"] = 1 if src["local"] > src["net"] else 0
    return p


def fmt(x):
    if isinstance(x, int):
        return str(x)
    return (f"{x:.6f}").rstrip("0").rstrip(".") if x != int(x) else str(int(x))


def render(p, container, threshold):
    L = f'container="{container}"'
    lines = []

    def metric(name, helptext, samples, typ="gauge"):
        if not samples:
            return
        lines.append(f"# HELP {name} {helptext}")
        lines.append(f"# TYPE {name} {typ}")
        for labels, value in samples:
            lines.append(f"{name}{{{L}{labels}}} {fmt(value)}")

    metric(
        "pft_feewatch_admin",
        "1 if server_info was an admin answer (load_factor_local/_net/_cluster known)",
        [("", 1 if p["admin"] else 0)],
    )
    metric(
        "pft_feewatch_ledger_current_index",
        "fee: sequence of the open ledger",
        [("", p["ledger_current_index"])],
    )
    metric(
        "pft_feewatch_current_ledger_size",
        "fee: transactions in the open ledger",
        [("", p["current_ledger_size"])],
    )
    metric(
        "pft_feewatch_expected_ledger_size",
        "fee: transactions per ledger before the open-ledger fee escalates",
        [("", p["expected_ledger_size"])],
    )
    metric(
        "pft_feewatch_current_queue_size",
        "fee: transactions in the transaction queue (TxQ)",
        [("", p["current_queue_size"])],
    )
    metric(
        "pft_feewatch_queue_limited",
        "1 if fee reported max_queue_size (the queue has a limit)",
        [("", 0 if p["max_queue_size"] is None else 1)],
    )
    if p["max_queue_size"] is not None:
        metric(
            "pft_feewatch_max_queue_size",
            "fee: transaction queue capacity",
            [("", p["max_queue_size"])],
        )
        metric(
            "pft_feewatch_queue_fill_ratio",
            "current_queue_size / max_queue_size",
            [("", p["queue_fill_ratio"])],
        )
    metric(
        "pft_feewatch_fee_drops",
        "fee: drops.* (base, median, minimum = queue entry, open_ledger)",
        [(f',kind="{k[:-4]}"', v) for k, v in p["drops"].items()],
    )
    metric(
        "pft_feewatch_fee_level",
        "fee: levels.* in fee level units (reference = 256 at the base fee)",
        [(f',kind="{k[:-6]}"', v) for k, v in p["levels"].items()],
    )
    metric(
        "pft_feewatch_escalation_multiple",
        "open_ledger_fee / base_fee (1 = no escalation)",
        [("", p["escalation_multiple"])],
    )
    metric(
        "pft_feewatch_escalation_alert_threshold",
        "PFTFeeEscalated fires when escalation_multiple >= this for 15m (ESCALATION_THRESHOLD)",
        [("", threshold)],
    )
    metric(
        "pft_feewatch_load_factor",
        "server_info load_factor (source=total) and its breakdown, 1 = no load",
        [(',source="total"', p["load_factor"])]
        + [(f',source="{s}"', v) for s, v in p["sources"].items() if v is not None],
    )
    if "local_exceeds_net" in p:
        metric(
            "pft_feewatch_local_load_exceeds_net",
            "1 if load_factor_local > load_factor_net (admin answers only)",
            [("", p["local_exceeds_net"])],
        )
    return "\n".join(lines) + "\n"


def history_line(p, container, now):
    return json.dumps(
        {
            "ts": now,
            "container": container,
            "admin": p["admin"],
            "ledger": p["ledger_current_index"],
            "cur_ledger": p["current_ledger_size"],
            "exp_ledger": p["expected_ledger_size"],
            "queue": p["current_queue_size"],
            "max_queue": p["max_queue_size"],
            "drops": p["drops"],
            "levels": p["levels"],
            "multiple": p["escalation_multiple"],
            "load_factor": p["load_factor"],
            "sources": p["sources"],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def load(path, what):
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read(1 << 20)
    try:
        return json.loads(raw)
    except ValueError as e:
        raise Bad(f"{what}: not JSON ({len(raw)} bytes): {str(e)[:80]}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--container", required=True)
    ap.add_argument("--now", required=True, type=int)
    ap.add_argument("--fee", required=True)
    ap.add_argument("--info", required=True)
    ap.add_argument("--threshold", type=float, default=4.0)
    ap.add_argument("--history")
    a = ap.parse_args(argv)
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", a.container):
        print("feewatch_parse: bad container name", file=sys.stderr)
        return 3
    if not 1.0 < a.threshold <= 1e6:
        print("feewatch_parse: --threshold must be > 1", file=sys.stderr)
        return 3
    try:
        p = parse(load(a.fee, "fee"), load(a.info, "server_info"))
    except (Bad, OSError) as e:
        print(f"feewatch_parse: {e}", file=sys.stderr)
        return 1
    text = render(p, a.container, a.threshold)
    if a.history:  # best-effort: a full disk must not blind the alerts
        try:
            with open(a.history, "a", encoding="utf-8") as f:
                f.write(history_line(p, a.container, a.now) + "\n")
        except OSError as e:
            print(f"feewatch_parse: history not written: {e}", file=sys.stderr)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
