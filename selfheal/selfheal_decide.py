#!/usr/bin/env python3
"""selfheal_decide: the decision core of pft-selfheal (pure logic, stdlib only).

Reads one observation (JSON on stdin, built by pft-selfheal.sh), the conf file (KEY=VALUE text) and the state file,
decides at most one action, writes the new state atomically and prints one decision JSON line on stdout.

  selfheal_decide.py decide STATE_FILE [CONF_FILE]   < observation.json
  selfheal_decide.py record STATE_FILE ACTION RC     record the outcome of an action the shell ran
  selfheal_decide.py reset STATE_FILE REASON         close the circuit breaker (manual reset)

Observation keys: now (epoch), container {exists, running, started_at (epoch|null)},
rpc {ok, server_state, validated_seq, peers}, guards {maint_active, locks (list), reference_seq (int|null),
reference_ok (bool)}.

Detectors (first match wins): container_down, rpc_failures, stale_ledger, stuck_state, zero_peers.
Guards (checked in this order, any one suppresses the action): breaker, maintenance, lock, grace, network_stall,
backoff, budget. An action that would exceed MAX_ACTIONS in 24 h opens the breaker instead.
Exit codes: 0 decision printed, 3 usage/config error, 5 state unreadable (refuses to act).
"""

import json
import os
import sys
import tempfile
import time

DEFAULTS = {
    "MODE": "dryrun",  # dryrun | enforce
    "RPC_FAILS": 3,  # consecutive failed RPC samples
    "STALE_SEC": 300,  # validated ledger seq unchanged this long
    "STUCK_SEC": 600,  # server_state not in GOOD_STATES this long
    "ZERO_PEERS_SEC": 600,  # peers == 0 this long
    "GRACE_SEC": 900,  # no RPC-based action this long after the container started
    "BACKOFF_SEC": 600,  # minimum gap after an action, doubled per action in the last 24 h
    "BACKOFF_MAX_SEC": 7200,
    "MAX_ACTIONS": 3,  # K actions per 24 h, the next needed action opens the breaker
    "REF_LAG": 5,  # the reference is "advancing" if it is at most this many ledgers ahead of our stall point
}
GOOD_STATES = ("full", "proposing", "validating")
DAY = 86400
INT_KEYS = [k for k, v in DEFAULTS.items() if isinstance(v, int)]


def load_conf(path):
    conf = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key, val = key.strip(), val.strip().strip("\"'")
                if key in INT_KEYS:
                    if not val.isdigit():
                        raise ValueError(f"{key} must be a non-negative integer")
                    conf[key] = int(val)
                elif key == "MODE":
                    conf[key] = val
    if conf["MODE"] not in ("dryrun", "enforce"):
        raise ValueError("MODE must be dryrun or enforce")
    if conf["MAX_ACTIONS"] < 1 or conf["RPC_FAILS"] < 1:
        raise ValueError("MAX_ACTIONS and RPC_FAILS must be >= 1")
    return conf


def new_state():
    return {
        "v": 1,
        "rpc_fail_streak": 0,
        "last_seq": None,
        "seq_since": None,
        "bad_state_since": None,
        "zero_peers_since": None,
        "actions": [],
        "last_action_ts": None,
        "breaker": {"open": False, "since": None, "reason": ""},
    }


def load_state(path):
    if not os.path.exists(path):
        return new_state()
    with open(path, encoding="utf-8") as fh:
        st = json.load(fh)
    if not isinstance(st, dict) or st.get("v") != 1:
        raise ValueError("unknown state version")
    base = new_state()
    base.update(st)
    return base


def save_state(path, st):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".state.", dir=d)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(st, fh, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def update_tracking(st, obs, now):
    """Advance the streak/since counters from this sample; returns nothing."""
    rpc = obs.get("rpc") or {}
    if not rpc.get("ok"):
        st["rpc_fail_streak"] += 1
        return
    st["rpc_fail_streak"] = 0
    seq = rpc.get("validated_seq")
    if isinstance(seq, int) and seq > 0 and seq != st["last_seq"]:
        st["last_seq"], st["seq_since"] = seq, now
    if rpc.get("server_state") in GOOD_STATES:
        st["bad_state_since"] = None
    elif st["bad_state_since"] is None:
        st["bad_state_since"] = now
    peers = rpc.get("peers")
    if isinstance(peers, int) and peers == 0:
        if st["zero_peers_since"] is None:
            st["zero_peers_since"] = now
    else:
        st["zero_peers_since"] = None


def reset_tracking(st):
    st["rpc_fail_streak"] = 0
    st["seq_since"] = None
    st["last_seq"] = None
    st["bad_state_since"] = None
    st["zero_peers_since"] = None


def detect(st, obs, conf, now):
    """Returns (detector, action, detail) or (None, 'none', '')."""
    c = obs.get("container") or {}
    if not c.get("exists") or not c.get("running"):
        return "container_down", "up", "container missing" if not c.get("exists") else "container not running"
    if st["rpc_fail_streak"] >= conf["RPC_FAILS"]:
        return "rpc_failures", "restart", f"{st['rpc_fail_streak']} consecutive RPC failures"
    if not (obs.get("rpc") or {}).get("ok"):
        return None, "none", ""  # the other detectors only judge a sample that answered
    if st["seq_since"] is not None and now - st["seq_since"] >= conf["STALE_SEC"]:
        return "stale_ledger", "restart", f"validated ledger {st['last_seq']} unchanged for {now - st['seq_since']}s"
    if st["bad_state_since"] is not None and now - st["bad_state_since"] >= conf["STUCK_SEC"]:
        state = (obs.get("rpc") or {}).get("server_state")
        return "stuck_state", "restart", f"server_state {state} for {now - st['bad_state_since']}s"
    if st["zero_peers_since"] is not None and now - st["zero_peers_since"] >= conf["ZERO_PEERS_SEC"]:
        return "zero_peers", "restart", f"0 peers for {now - st['zero_peers_since']}s"
    return None, "none", ""


def network_stalled(st, obs, conf):
    """True when the reference node is not advancing past our stall point either (network-wide stall), or when
    no reference answer is available (fail safe: never restart into a network-wide problem)."""
    g = obs.get("guards") or {}
    ref = g.get("reference_seq")
    if not g.get("reference_ok") or not isinstance(ref, int):
        return True
    ours = st["last_seq"] if isinstance(st["last_seq"], int) else 0
    return ref <= ours + conf["REF_LAG"]


def guard(st, obs, conf, now, detector):
    """Returns the name of the first guard that suppresses the action, or None."""
    g = obs.get("guards") or {}
    c = obs.get("container") or {}
    if st["breaker"]["open"]:
        return "breaker"
    if g.get("maint_active"):
        return "maintenance"
    if g.get("locks"):
        return "lock"
    started = c.get("started_at")
    if detector != "container_down" and isinstance(started, int) and now - started < conf["GRACE_SEC"]:
        return "grace"
    if detector in ("stale_ledger", "stuck_state") and network_stalled(st, obs, conf):
        return "network_stall"
    recent = [t for t in st["actions"] if now - t < DAY]
    if st["last_action_ts"] is not None:
        wait = min(conf["BACKOFF_SEC"] * (2 ** max(len(recent) - 1, 0)), conf["BACKOFF_MAX_SEC"])
        if now - st["last_action_ts"] < wait:
            return "backoff"
    if len(recent) >= conf["MAX_ACTIONS"]:
        return "budget"
    return None


def decide(state_path, conf_path):
    try:
        conf = load_conf(conf_path)
    except (OSError, ValueError) as e:
        print(f"selfheal_decide: conf: {e}", file=sys.stderr)
        return 3
    try:
        st = load_state(state_path)
    except (OSError, ValueError) as e:
        print(f"selfheal_decide: state unreadable, refusing to act: {e}", file=sys.stderr)
        return 5
    try:
        obs = json.load(sys.stdin)
        now = int(obs["now"])
    except (ValueError, KeyError, TypeError) as e:
        print(f"selfheal_decide: bad observation: {e}", file=sys.stderr)
        return 3
    st["actions"] = [t for t in st["actions"] if now - t < DAY]
    update_tracking(st, obs, now)
    detector, action, detail = detect(st, obs, conf, now)
    suppressed = guard(st, obs, conf, now, detector) if detector else None
    if suppressed == "budget":
        st["breaker"] = {"open": True, "since": now, "reason": f"{detector} after {len(st['actions'])} actions/24h"}
    run = bool(detector) and suppressed is None
    if run and conf["MODE"] == "dryrun":
        verdict = "would_act"
    elif run:
        verdict = "act"
    elif detector:
        verdict = "suppressed"
    else:
        verdict = "healthy"
    out = {
        "ts": now,
        "mode": conf["MODE"],
        "verdict": verdict,
        "detector": detector,
        "action": action if detector else "none",
        "detail": detail,
        "suppressed_by": suppressed,
        "actions_24h": len(st["actions"]),
        "max_actions": conf["MAX_ACTIONS"],
        "breaker_open": st["breaker"]["open"],
        "breaker_reason": st["breaker"]["reason"],
        "rpc_fail_streak": st["rpc_fail_streak"],
    }
    try:
        save_state(state_path, st)
    except OSError as e:
        print(f"selfheal_decide: cannot save state, refusing to act: {e}", file=sys.stderr)
        return 5
    print(json.dumps(out, sort_keys=True))
    return 0


def record(state_path, action, rc, now):
    st = load_state(state_path)
    st["actions"] = [t for t in st["actions"] if now - t < DAY] + [now]
    st["last_action_ts"] = now
    reset_tracking(st)
    save_state(state_path, st)
    print(json.dumps({"ts": now, "recorded": action, "rc": rc, "actions_24h": len(st["actions"])}))
    return 0


def reset(state_path, reason, now):
    st = load_state(state_path)
    was = st["breaker"]
    st["breaker"] = {"open": False, "since": None, "reason": ""}
    st["actions"] = []
    st["last_action_ts"] = None
    reset_tracking(st)
    save_state(state_path, st)
    print(
        json.dumps({"ts": now, "reset": True, "was_open": was["open"], "was_reason": was["reason"], "reason": reason})
    )
    return 0


def main(argv):
    now = int(os.environ.get("PFT_SH_NOW") or 0) or None
    if len(argv) >= 2 and argv[0] == "decide":
        return decide(argv[1], argv[2] if len(argv) > 2 else None)
    now = now or int(time.time())
    if len(argv) == 4 and argv[0] == "record" and argv[3].lstrip("-").isdigit():
        return record(argv[1], argv[2], int(argv[3]), now)
    if len(argv) == 3 and argv[0] == "reset":
        return reset(argv[1], argv[2], now)
    print("\n".join(x for x in __doc__.splitlines() if x.startswith("  selfheal_decide.py ")), file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
