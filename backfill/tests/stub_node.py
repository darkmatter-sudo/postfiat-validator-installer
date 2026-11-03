#!/usr/bin/env python3
"""Stub postfiatd for the repair suite: answers the JSON-RPC bodies pft-backfill sends through the stub docker
(`exec CONTAINER curl ... -d BODY URL`) and the stub public-RPC curl, from a JSON state file.

  stub_node.py STATE node BODY     -> local node answer
  stub_node.py STATE public BODY   -> public RPC answer ("" = no answer)

State keys: validated, held [[lo,hi],...], state, arrive_after (ledger polls after the first ledger_request before a
missing ledger becomes servable; -1 = never), mode (see MODES), target (seq the fault applies to), polls {seq: n}.
Ledger hashes are sha256("L<seq>"), so every parent link is checkable.
"""

import hashlib
import json
import sys

MODES = (
    "ok",  # honest node
    "badhash",  # target arrives with a hash that is not the validated-chain hash
    "badlink",  # the HELD ledger target reports a parent_hash that does not match its predecessor
    "lrerror",  # ledger_request answers error "internal"
    "lrnotfound",  # ledger_request always answers lgrNotFound "acquiring" (no hash of the ledger itself)
    "chainflip",  # ledger_request names a different hash for target on the second call
    "pubmismatch",  # public RPC answers a different hash for target
    "pubdown",  # public RPC gives no answer
    "pubnotfound",  # public RPC answers lgrNotFound
    "isolated",  # the held neighbours of target (seq-1, seq+1) are not servable: no parent link can be checked
    "wrongseq",  # the ledger RPC answers target with the header of target+1
)


def h(seq, salt="L"):
    return hashlib.sha256(f"{salt}{seq}".encode()).hexdigest().upper()


def held(st, seq):
    return any(lo <= seq <= hi for lo, hi in st["held"])


def add_held(st, seq):
    rs = sorted(st["held"] + [[seq, seq]])
    out = []
    for lo, hi in rs:
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    st["held"] = out


def ledger_obj(st, seq):
    lh = h(seq, "X") if (st["mode"] == "badhash" and seq == st["target"]) else h(seq)
    ph = (
        h(seq - 1, "Y")
        if (st["mode"] == "badlink" and seq == st["target"])
        else h(seq - 1)
    )
    return {
        "ledger_hash": lh,
        "parent_hash": ph,
        "ledger_index": str(seq),
        "closed": True,
    }


def node(st, req):
    m = req.get("method")
    p = (req.get("params") or [{}])[0]
    seq = p.get("ledger_index")
    if m == "server_info":
        cl = (
            ",".join(f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in st["held"])
            or "empty"
        )
        return {
            "result": {
                "info": {
                    "server_state": st["state"],
                    "complete_ledgers": cl,
                    "validated_ledger": {"seq": st["validated"]},
                },
                "status": "success",
            }
        }
    if m == "ledger_request":
        st.setdefault("lr_calls", {})
        n = st["lr_calls"].get(str(seq), 0) + 1
        st["lr_calls"][str(seq)] = n
        if seq >= st["validated"]:
            return {
                "result": {
                    "error": "invalidParams",
                    "error_message": "Ledger index too large",
                    "status": "error",
                }
            }
        if st["mode"] == "lrerror" and seq == st["target"]:
            return {
                "result": {
                    "error": "internal",
                    "error_message": "Internal error.",
                    "status": "error",
                }
            }
        st["polls"].setdefault(str(seq), 0)
        if st["mode"] == "lrnotfound":
            return {
                "result": {
                    "error": "lgrNotFound",
                    "error_message": "acquiring ledger containing requested index",
                    "acquiring": {"hash": h(seq + 256)},
                    "status": "error",
                }
            }
        hh = (
            h(seq, "Z")
            if (st["mode"] == "chainflip" and seq == st["target"] and n >= 2)
            else h(seq)
        )
        if held(st, seq):
            return {
                "result": {
                    "ledger": ledger_obj(st, seq),
                    "ledger_index": seq,
                    "status": "success",
                }
            }
        return {
            "result": {
                "hash": hh,
                "have_header": False,
                "peers": 5,
                "status": "success",
                "timeouts": 0,
            }
        }
    if m == "ledger":
        if st["mode"] == "isolated" and seq in (st["target"] - 1, st["target"] + 1):
            return {
                "result": {
                    "error": "lgrNotFound",
                    "error_message": "ledgerNotFound",
                    "status": "error",
                }
            }
        if not held(st, seq):
            k = str(seq)
            if k in st["polls"] and st["arrive_after"] >= 0:
                st["polls"][k] += 1
                if st["polls"][k] > st["arrive_after"]:
                    add_held(st, seq)
        if held(st, seq):
            if st["mode"] == "wrongseq" and seq == st["target"]:
                return {
                    "result": {
                        "ledger": ledger_obj(st, seq + 1),
                        "status": "success",
                        "validated": True,
                    }
                }
            return {
                "result": {
                    "ledger": ledger_obj(st, seq),
                    "ledger_hash": ledger_obj(st, seq)["ledger_hash"],
                    "ledger_index": seq,
                    "status": "success",
                    "validated": True,
                }
            }
        return {
            "result": {
                "error": "lgrNotFound",
                "error_message": "ledgerNotFound",
                "status": "error",
            }
        }
    return {"result": {"error": "unknownCmd", "status": "error"}}


def public(st, req):
    seq = (req.get("params") or [{}])[0].get("ledger_index")
    if st["mode"] == "pubdown":
        return None
    if st["mode"] == "pubnotfound":
        return {"result": {"error": "lgrNotFound", "status": "error"}}
    lh = (
        h(seq, "P") if (st["mode"] == "pubmismatch" and seq == st["target"]) else h(seq)
    )
    return {
        "result": {
            "ledger": {"ledger_hash": lh, "ledger_index": str(seq)},
            "status": "success",
        }
    }


def main():
    path, side, body = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(path, encoding="utf-8") as fh:
        st = json.load(fh)
    st.setdefault("polls", {})
    assert st["mode"] in MODES, st["mode"]
    req = json.loads(body)
    st.setdefault("methods", []).append(f"{side}:{req.get('method')}")
    ans = node(st, req) if side == "node" else public(st, req)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(st, fh)
    if ans is not None:
        print(json.dumps(ans))


if __name__ == "__main__":
    main()
