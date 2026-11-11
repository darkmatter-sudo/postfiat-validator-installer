#!/usr/bin/env python3
"""Turn real `peers` / `server_info` captures into publishable fixtures (one shared mapping over all inputs).

- every IPv4 peer address -> 10.I.J.K, where I numbers its /16, J its /24 inside that /16 and K the host, so the
  prefix structure the diversity check grades is kept exactly; IPv6 -> fd00:I:J::K the same way; the Docker bridge
  gateway 172.17.0.1 (how a node behind docker-proxy sees every inbound peer) is kept as is;
- every node public key -> a synthetic key (n9FixtureNode<NNN>..., cluster members n9Fixture<Tag>...);
- server_info keeps only the fields peerwatch reads (build_version, server_state, validated_ledger seq/hash,
  network_id, peers, complete_ledgers): no hostid, ports, pubkey_validator, load or io figures.
Latency, uptime, version, complete_ledgers, ledger hash, network_id and inbound flags stay as captured.

Usage: redact_capture.py OUTDIR CAPTURE.json...   (writes OUTDIR/<same name>; prints only counts)
"""

import ipaddress
import json
import os
import sys

KEEP_INFO = ("build_version", "server_state", "network_id", "peers", "complete_ledgers")


class Mapper:
    def __init__(self):
        self.keys, self.n16, self.n24, self.hosts, self.per24 = {}, {}, {}, {}, {}

    def key(self, k, tag=None):
        if k not in self.keys:
            if tag:
                stem = "n9Fixture" + tag.capitalize()
            else:
                stem = f"n9FixtureNode{len(self.keys):03d}"
            self.keys[k] = (stem + "x" * 52)[:52]
        return self.keys[k]

    def ip(self, ip):
        if str(ip) == "172.17.0.1":
            return str(ip)
        if ip.version == 4:
            o = str(ip).split(".")
            a16, a24 = tuple(o[:2]), tuple(o[:3])
        else:
            h = ip.exploded.split(":")
            a16, a24 = tuple(h[:2]), tuple(h[:3])
        i = self.n16.setdefault(a16, len(self.n16) + 1)
        j = self.n24.setdefault(a24, sum(1 for x in self.n24 if x[: len(a16)] == a16))
        if str(ip) not in self.hosts:
            self.per24[a24] = self.per24.get(a24, 0) + 1
            self.hosts[str(ip)] = self.per24[a24]
        k = self.hosts[str(ip)]
        if ip.version == 4:
            return f"10.{i}.{j}.{k}"
        return f"fd00:{i:x}:{j:x}::{k:x}"

    def address(self, a):
        a = str(a)
        if a.startswith("["):
            host, _, port = a[1:].partition("]:")
            return f"[{self.ip(ipaddress.ip_address(host))}]:{port}"
        host, _, port = a.rpartition(":") if a.count(":") == 1 else (a, "", "")
        try:
            m = self.ip(ipaddress.ip_address(host))
        except ValueError:
            return "unparsed.invalid:0"
        return f"{m}:{port}" if port else m


def main():
    out, files = sys.argv[1], sys.argv[2:]
    os.makedirs(out, exist_ok=True)
    mp = Mapper()
    docs = {}
    for f in files:
        with open(f, encoding="utf-8") as fh:
            docs[f] = json.load(fh)
    # cluster members first, so their synthetic names carry the tag in every file
    for d in docs.values():
        for k, v in ((d.get("result") or {}).get("cluster") or {}).items():
            mp.key(k, (v or {}).get("tag"))
    for f, d in docs.items():
        r = d["result"]
        if "peers" in r and isinstance(r["peers"], list):
            for p in r["peers"]:
                p["public_key"] = mp.key(p["public_key"])
                if "address" in p:
                    p["address"] = mp.address(p["address"])
            if isinstance(r.get("cluster"), dict):
                r["cluster"] = {mp.key(k): v for k, v in r["cluster"].items()}
        if isinstance(r.get("info"), dict):
            info = r["info"]
            new = {k: info[k] for k in KEEP_INFO if k in info}
            vl = info.get("validated_ledger") or {}
            new["validated_ledger"] = {k: vl[k] for k in ("seq", "hash") if k in vl}
            if "pubkey_node" in info:
                new["pubkey_node"] = mp.key(info["pubkey_node"])
            r["info"] = new
        with open(os.path.join(out, os.path.basename(f)), "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=1, sort_keys=True)
            fh.write("\n")
    print(
        f"redacted {len(files)} files: {len(mp.keys)} keys, {len(mp.hosts)} addresses in {len(mp.n16)} /16 and {len(mp.n24)} /24"
    )


if __name__ == "__main__":
    main()
