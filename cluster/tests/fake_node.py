#!/usr/bin/env python3
"""Fake postfiatd for run-tests.sh: answers the admin RPC calls pft-cluster makes, from the config the node LOADED at
its last (fake) restart, the way postfiatd does (NodeIdentity.cpp: [node_seed] first line, else wallet.db; Cluster::load:
a malformed [cluster_nodes] entry stops the node from starting; Peers.cpp: `cluster` lists members except self,
`age` only once that member sent a report, which it only sends if it counts us as a member).

State dir S (files):
  cfg            path of the live postfiatd.cfg (what the next restart loads)
  loaded.cfg     the config loaded at the last restart
  started        StartedAt; restart writes a new one
  keys           "seed<TAB>pub" lines created by validation_create (the fake key derivation)
  wallet_pub     the identity from wallet.db (no [node_seed])
  state          server_state (full) when the node runs
  peer_pub       the other node's current key; peer_connected (exists = connected); peer_age (its report age, s)
  peer_lists_us  exists = the other node lists our key in its [cluster_nodes] (it sends reports)
  bad_when_seeded  server_state "connected" while the loaded config has a [node_seed] (a fault apply causes)
  bad_always     server_state "connected" after the next restart (rollback cannot cure it)
  restart_fail   docker restart fails
  no_cluster     the node ignores [cluster_nodes]
  vc_bad         validation_create answers an error
Usage: fake_node.py S rpc METHOD | fake_node.py S restart
"""
import json
import os
import random
import re
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def rd(s, name, default=None):
    p = os.path.join(s, name)
    if not os.path.exists(p):
        return default
    with open(p) as f:
        return f.read().strip()


def sections(path):
    out, cur = {}, None
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1]
                out.setdefault(cur, [])
                continue
            if cur is not None:
                out[cur].append(line)
    return out


def node(s):
    """-> None if the node is not running, else (pubkey, cluster member keys)"""
    loaded = os.path.join(s, "loaded.cfg")
    if not os.path.exists(loaded) or os.path.exists(os.path.join(s, "down")):
        return None
    sec = sections(loaded)
    members = []
    # no_cluster: the node ignores the section (as postfiatd ignores a misspelled section name)
    for v in ([] if os.path.exists(os.path.join(s, "no_cluster")) else sec.get("cluster_nodes", [])):
        m = re.fullmatch(r"\s*([A-Za-z0-9]+)(?:\s+(?:(.*\S)\s*)?)?", v)
        if not m or not re.fullmatch(r"n[%s]{50,51}" % B58, m.group(1)):
            return None  # Cluster::load fails -> the node does not start
        members.append((m.group(1), m.group(2) or ""))
    pub = rd(s, "wallet_pub")
    if sec.get("node_seed"):
        seed = sec["node_seed"][0]
        keys = dict(ln.split("\t") for ln in (rd(s, "keys", "") or "").splitlines() if "\t" in ln)
        if seed not in keys:
            return None  # invalid [node_seed] -> postfiatd throws at startup
        pub = keys[seed]
    return pub, members, bool(sec.get("node_seed"))


def rpc(s, method):
    if method == "validation_create":
        if os.path.exists(os.path.join(s, "vc_bad")):
            print(json.dumps({"result": {"status": "error", "error": "badSeed"}}))
            return 0
        rnd = random.SystemRandom()
        seed = "s" + "".join(rnd.choice(B58) for _ in range(28))
        pub = "n9" + "".join(rnd.choice(B58) for _ in range(50))
        with open(os.path.join(s, "keys"), "a") as f:
            f.write(f"{seed}\t{pub}\n")
        print(json.dumps({"result": {"status": "success", "validation_seed": seed, "validation_public_key": pub,
                                     "validation_private_key": "p" + seed[1:], "validation_key": "WORD WORD"}}))
        return 0
    n = node(s)
    if n is None:
        return 7  # curl: connection refused
    pub, members, seeded = n
    if method == "server_info":
        st = rd(s, "state", "full")
        if (seeded and os.path.exists(os.path.join(s, "bad_when_seeded"))) or os.path.exists(os.path.join(s, "bad_now")):
            st = "connected"
        print(json.dumps({"result": {"info": {"server_state": st, "pubkey_node": pub, "build_version": "1.0.9"}}}))
        return 0
    if method == "peers":
        ppub = rd(s, "peer_pub")
        keys = [k for k, _ in members]
        peers = [{"address": "172.17.0.1:51234", "public_key": "n9VhQhTb4yRCyZnS3D3X2u5RgpSzQjWxuvy6ME7sf6H2hP7HAYGz"}]
        if ppub and os.path.exists(os.path.join(s, "peer_connected")):
            p = {"address": "172.17.0.1:40000", "public_key": ppub}
            if ppub in keys:
                p["cluster"] = True
            peers.append(p)
        cl = {}
        for k, tag in members:
            if k == pub:
                continue
            e = {}
            if tag:
                e["tag"] = tag
            if (k == ppub and os.path.exists(os.path.join(s, "peer_connected"))
                    and os.path.exists(os.path.join(s, "peer_lists_us"))):
                e["age"] = int(rd(s, "peer_age", "3"))
            cl[k] = e
        print(json.dumps({"result": {"cluster": cl, "peers": peers, "status": "success"}}))
        return 0
    print(json.dumps({"result": {"error": "unknownCmd"}}))
    return 0


def restart(s):
    if os.path.exists(os.path.join(s, "restart_fail")):
        return 1
    with open(rd(s, "cfg")) as f:
        body = f.read()
    with open(os.path.join(s, "loaded.cfg"), "w") as f:
        f.write(body)
    n = int(rd(s, "restarts", "0")) + 1
    with open(os.path.join(s, "restarts"), "w") as f:
        f.write(str(n))
    with open(os.path.join(s, "started"), "w") as f:
        f.write("2026-11-02T00:%02d:00.000000001Z\n" % n)
    if os.path.exists(os.path.join(s, "bad_always")):
        open(os.path.join(s, "bad_now"), "w").close()
    return 0


def main():
    s, cmd = sys.argv[1], sys.argv[2]
    if cmd == "rpc":
        return rpc(s, sys.argv[3])
    if cmd == "restart":
        return restart(s)
    return 2


if __name__ == "__main__":
    sys.exit(main())
