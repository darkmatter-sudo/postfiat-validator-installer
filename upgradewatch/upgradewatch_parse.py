#!/usr/bin/env python3
"""Parse postfiatd RPC answers into pft_upgradewatch_* Prometheus textfile lines (stdout).

Inputs are files (the collector saves each RPC answer; tests and drills pass fixtures):
  --info        server_info answer (admin: carries `warnings` 1001 with details.expected_date)
  --feature     feature answer (admin): supported / enabled / vetoed per amendment
  --amendments  ledger_entry answer for the Amendments singleton (validated): Majorities[].Majority.CloseTime
  --peers       peers answer (admin): peers[].version
  --cfg         the node config lines that are section headers or duration-shaped values (see majority_time())
  --foundation  optional: the foundation public RPC's server_info answer (missing/unreadable = unknown)

Activation ETA, as postfiatd 1.0.9 computes it (commit 32723c15, see README "ETA derivation"):
  AmendmentTable.cpp:918   enable when  majority CloseTime + majorityTime_ <= parent close time (at a flag ledger)
  AmendmentTable.cpp:988   firstUnsupportedExpected_ = earliest unsupported majority + majorityTime_
  Config.cpp:871-899       majorityTime_ = [amendment_majority_time] "<n> minutes|hours|days|weeks" (>= 15 minutes)
  SystemParameters.h:88    default 2 weeks when the section is absent (or does not hold exactly one line, :226)
  CloseTime is in seconds since the Ripple epoch 2000-01-01 (946684800 Unix).

Exit 0 with the metric lines; exit 1 with one error line on stderr if any input is missing or malformed.
"""

import argparse
import json
import re
import sys

RIPPLE_EPOCH = 946684800
DEFAULT_MAJORITY_SECONDS = 14 * 86400
MIN_MAJORITY_SECONDS = 15 * 60
UNIT_SECONDS = {"minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}
SECTION = "amendment_majority_time"
# Config.cpp:876 (boost::regex_match, case-sensitive unit word)
DURATION_RE = re.compile(r"^\s*(\d+)\s*(minutes|hours|days|weeks)\s*(\s+.*)?$")
WARN_UNSUPPORTED_MAJORITY = 1001  # ErrorCodes.h:173
WARN_AMENDMENT_BLOCKED = 1002  # ErrorCodes.h:174
VERSION_RE = re.compile(r"^(?:postfiatd-)?(\d+)\.(\d+)\.(\d+)(?:-(rc|b)(\d+))?$")
NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
HASH_RE = re.compile(r"^[0-9A-F]{64}$")
MAX_AMENDMENT_SERIES = 32
ETA_AGREE_TOLERANCE = 1  # seconds; both sides are whole NetClock seconds


class ParseError(Exception):
    pass


def load(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError) as e:
        raise ParseError(f"{what}: not readable JSON ({e.__class__.__name__})") from e
    if not isinstance(d, dict) or not isinstance(d.get("result"), dict):
        raise ParseError(f"{what}: no result object")
    r = d["result"]
    if r.get("status") != "success" or "error" in r:
        raise ParseError(f"{what}: rpc error {r.get('error', r.get('status'))!r}")
    return r


def want(obj, key, typ, what):
    v = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(v, typ) or isinstance(v, bool) and typ is not bool:
        raise ParseError(f"{what}: field {key!r} missing or not {typ.__name__}")
    return v


def version_key(s):
    """1.0.9 > 1.0.9-rc2 > 1.0.9-b1 (BuildInfo pre-release order); None if not a version string."""
    m = VERSION_RE.match(s) if isinstance(s, str) else None
    if not m:
        return None
    rank = {"rc": 1, "b": 0, None: 2}[m.group(4)]
    return (
        int(m.group(1)),
        int(m.group(2)),
        int(m.group(3)),
        rank,
        int(m.group(5) or 0),
    )


def majority_time(lines):
    """(seconds, from_config) the way Config.cpp reads [amendment_majority_time].

    `lines` are the config lines the collector kept: every section header plus every duration-shaped line
    (grep in the container, so no other config value ever leaves it). Values of a repeated section add up
    (IniFileSections emplace + push_back); exactly one line is used, otherwise the default applies (:226).
    """
    section, values = None, []
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1]
            continue
        if section == SECTION:
            values.append(s)
    if len(values) != 1:
        return DEFAULT_MAJORITY_SECONDS, 0
    m = DURATION_RE.match(values[0])
    if not m:
        raise ParseError(
            f"[{SECTION}] value {values[0][:40]!r} is not '<n> minutes|hours|days|weeks'"
        )
    secs = int(m.group(1)) * UNIT_SECONDS[m.group(2)]
    if secs < MIN_MAJORITY_SECONDS:
        raise ParseError(f"[{SECTION}] below the 15 minute minimum")
    return secs, 1


def parse(a):
    info = want(load(a.info, "server_info"), "info", dict, "server_info")
    features = want(load(a.feature, "feature"), "features", dict, "feature")
    amend = load(a.amendments, "amendments")
    peers = want(load(a.peers, "peers"), "peers", list, "peers")
    try:
        with open(a.cfg, encoding="utf-8") as f:
            cfg_lines = f.read().splitlines()
    except OSError as e:
        raise ParseError(f"cfg: not readable ({e.__class__.__name__})") from e

    build = want(info, "build_version", str, "server_info")
    bkey = version_key(build)
    if bkey is None:
        raise ParseError(f"server_info: build_version {build[:32]!r} is not a version")
    warnings = info.get("warnings", [])
    if not isinstance(warnings, list):
        raise ParseError("server_info: warnings is not a list")
    warn_ids = {w.get("id") for w in warnings if isinstance(w, dict)}
    blocked = (
        info.get("amendment_blocked") is True or WARN_AMENDMENT_BLOCKED in warn_ids
    )
    node_expected = None
    for w in warnings:
        if isinstance(w, dict) and w.get("id") == WARN_UNSUPPORTED_MAJORITY:
            d = w.get("details", {})
            if isinstance(d, dict) and isinstance(d.get("expected_date"), int):
                node_expected = d["expected_date"] + RIPPLE_EPOCH

    for h, f in features.items():
        if not HASH_RE.match(h) or not isinstance(f, dict):
            raise ParseError("feature: malformed entry")
        if not isinstance(f.get("enabled"), bool) or not isinstance(
            f.get("supported"), bool
        ):
            raise ParseError(f"feature: {h[:16]} lacks enabled/supported booleans")

    if amend.get("validated") is not True:
        raise ParseError("amendments: answer is not from a validated ledger")
    node = want(amend, "node", dict, "amendments")
    if node.get("LedgerEntryType") != "Amendments":
        raise ParseError("amendments: node is not the Amendments object")
    enabled_ledger = node.get("Amendments", [])
    majorities = node.get("Majorities", [])
    if not isinstance(enabled_ledger, list) or not isinstance(majorities, list):
        raise ParseError("amendments: Amendments/Majorities not lists")
    enabled_set = set(enabled_ledger)
    maj_secs, from_cfg = majority_time(cfg_lines)

    rows = []
    for m in majorities:
        mm = m.get("Majority") if isinstance(m, dict) else None
        if (
            not isinstance(mm, dict)
            or not HASH_RE.match(str(mm.get("Amendment", "")))
            or not isinstance(mm.get("CloseTime"), int)
            or isinstance(mm.get("CloseTime"), bool)
        ):
            raise ParseError("amendments: malformed Majorities entry")
        h = mm["Amendment"]
        if h in enabled_set:
            continue
        f = features.get(h)
        supported = bool(f and f["supported"])
        name = f.get("name") if f else None
        # unknown to this build: the full hash (a prefix could collide and duplicate a series)
        label = (
            name if isinstance(name, str) and NAME_RE.match(name) else "unknown_" + h
        )
        eta = mm["CloseTime"] + RIPPLE_EPOCH + maj_secs
        rows.append((eta, label, supported))
    rows.sort()
    unsupported = [r for r in rows if not r[2]]
    enabled_unsupported = sum(
        1 for h in enabled_set if not (features.get(h) or {}).get("supported", False)
    )

    versioned = newer = 0
    for p in peers:
        k = version_key(p.get("version")) if isinstance(p, dict) else None
        if k is None:
            continue
        versioned += 1
        newer += k > bkey

    fver = None
    if a.foundation:
        try:
            fi = load(a.foundation, "foundation")
            fv = (
                fi.get("info", {}).get("build_version")
                if isinstance(fi.get("info"), dict)
                else None
            )
            if version_key(fv) is not None:
                fver = fv
        except ParseError as e:
            print(f"warning: {e}; foundation version unknown", file=sys.stderr)

    L = f'container="{a.container}"'
    out = []

    def metric(name, help_, samples):
        out.append(f"# HELP pft_upgradewatch_{name} {help_}")
        out.append(f"# TYPE pft_upgradewatch_{name} gauge")
        for labels, v in samples:
            out.append(f"pft_upgradewatch_{name}{{{L}{labels}}} {v}")

    metric(
        "amendment_blocked",
        "1 if server_info reports amendment_blocked (or warning 1002)",
        [("", int(blocked))],
    )
    metric(
        "unsupported_majority_warning",
        "1 if server_info carries warning 1001 (unsupported majority)",
        [("", int(WARN_UNSUPPORTED_MAJORITY in warn_ids))],
    )
    metric(
        "amendments_known",
        "amendments in this build's feature table",
        [("", len(features))],
    )
    metric(
        "amendments_enabled",
        "amendments enabled in the validated Amendments object",
        [("", len(enabled_set))],
    )
    metric(
        "amendments_enabled_unsupported",
        "enabled amendments this build does not support",
        [("", enabled_unsupported)],
    )
    metric(
        "majority_amendments",
        "not-yet-enabled amendments holding a ledger majority",
        [
            (',supported="yes"', len(rows) - len(unsupported)),
            (',supported="no"', len(unsupported)),
        ],
    )
    metric(
        "majority_time_seconds",
        "hold time used for the ETA (Config.cpp [amendment_majority_time])",
        [("", maj_secs)],
    )
    metric(
        "majority_time_from_config",
        "1 if majority_time_seconds came from the node config, 0 = 2 week default",
        [("", from_cfg)],
    )
    if rows:
        metric(
            "majority_activation_eta_seconds",
            "earliest Unix time the amendment can activate (majority CloseTime + majority time), per amendment",
            [
                (f',amendment="{lab}",supported="{"yes" if s else "no"}"', eta)
                for eta, lab, s in rows[:MAX_AMENDMENT_SERIES]
            ],
        )
    # always written (0 = none), so the alert rule always has a series (../rulecheck grades rules without one DEAD)
    metric(
        "unsupported_activation_eta_seconds",
        "earliest Unix time an UNSUPPORTED majority amendment can activate (0 = none holds a majority)",
        [("", unsupported[0][0] if unsupported else 0)],
    )
    metric(
        "node_expected_date_seconds",
        "the node's own warning 1001 expected_date as Unix time (0 = no warning)",
        [("", node_expected or 0)],
    )
    if node_expected is not None and unsupported:
        metric(
            "eta_agrees_with_node",
            "1 if the derived ETA equals the node's expected_date",
            [("", int(abs(unsupported[0][0] - node_expected) <= ETA_AGREE_TOLERANCE))],
        )
    metric("build_info", "this node's build_version", [(f',version="{build}"', 1)])
    metric("peers_versioned", "peers reporting a parseable version", [("", versioned)])
    metric(
        "peers_newer", "peers reporting a NEWER version than this node", [("", newer)]
    )
    metric(
        "peers_newer_ratio",
        "peers_newer / peers_versioned (0 when no peer reports a version)",
        [("", round(newer / versioned, 4) if versioned else 0)],
    )
    metric(
        "foundation_known",
        "1 if the foundation RPC's build_version was read this run",
        [("", int(bool(fver)))],
    )
    if fver:
        metric(
            "foundation_build_info",
            "the foundation RPC's build_version",
            [(f',version="{fver}"', 1)],
        )
    metric(
        "behind_foundation",
        "1 if this node's build is older than the foundation RPC's (0 also when unknown)",
        [("", int(bool(fver) and version_key(fver) > bkey))],
    )
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--container", required=True)
    for k in ("info", "feature", "amendments", "peers", "cfg"):
        p.add_argument("--" + k, required=True)
    p.add_argument("--foundation", default="")
    a = p.parse_args(argv)
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", a.container):
        print("bad container name", file=sys.stderr)
        return 1
    try:
        print(parse(a))
    except ParseError as e:
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
