#!/usr/bin/env python3
"""Evaluate inbound exposure of a Post Fiat host from one capture bundle against a declared per-role policy.

A bundle is the text pft-fwaudit.sh writes: one section per command, each started by `### $ CMD` and ended by
`### rc=N` (iptables-save, ip6tables-save, nft list ruleset, ufw status verbose, ss -H -tulpn, docker ps, ip -br addr).
The same parser reads live bundles and the redacted fixtures in tests/fixtures, so tests exercise the live code path.

How exposure is derived (read-only, nothing is probed over the network here):
- every non-loopback listening socket from `ss` is a candidate, per family (`*` = dual-stack, `[::]` = v6 only);
- Docker DNAT rules in the nat DOCKER chain publish host ports on the FORWARD path (container IP:port), which UFW's
  INPUT rules never see; a docker-proxy socket for which no DNAT of that family exists is reached on the INPUT path;
- the filter chains of the right path (INPUT or FORWARD) are walked rule by rule for a NEW connection from an
  arbitrary external source, following jumps/RETURN, giving one of: open (any source), limited (any source, but
  only past a rate/conn limit), sources (only the listed source CIDRs) or closed;
- nftables tables that iptables-nft does not own are reported (their rules are not modelled).

Usage: fwaudit_eval.py audit BUNDLE POLICY [--peers FILE] [--json]
       exit 0 PASS, 1 WARN, 2 FAIL, 3 usage/policy error, 4 bundle unreadable/incomplete
"""

import ipaddress
import json
import re
import shlex
import sys

VERSION = 1
EXIT = {"PASS": 0, "WARN": 1, "FAIL": 2}
SEVERITY = {  # finding class -> verdict it contributes
    "ufw-inactive": "FAIL",
    "default-incoming-allow": "FAIL",
    "undeclared-exposure": "FAIL",
    "source-too-broad": "FAIL",
    "missing-limit": "FAIL",
    "declared-unreachable": "WARN",
    "stale-allow": "WARN",
    "loopback-dnat-unguarded": "WARN",
    "nft-foreign-table": "WARN",
    "ufw-rule-bypassed": "INFO",
}
SECTIONS = {
    "iptables": "iptables-save",
    "ip6tables": "ip6tables-save",
    "nft": "nft list ruleset",
    "ufw": "ufw status verbose",
    "ss": "ss -H -tulpn",
    "docker": "docker ps",
    "addr": "ip -br addr",
}
IPT_NFT_TABLES = {"filter", "nat", "raw", "mangle", "security"}
LIMIT_MODULES = ("limit", "recent", "connlimit", "hashlimit")


class BundleError(Exception):
    pass


class PolicyError(Exception):
    pass


# ---------------------------------------------------------------- bundle
def read_bundle(text):
    """Return {key: (rc, body)} for the known sections; missing or failed required sections raise BundleError."""
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith("### $ "):
            cur, buf = line[6:].strip(), []
        elif line.startswith("### rc=") and cur is not None:
            rc = int(line[7:].strip() or "1")
            for key, stem in SECTIONS.items():
                if stem in cur and key not in out:
                    out[key] = (rc, "\n".join(buf))
            cur = None
        elif cur is not None:
            buf.append(line)
    for key in ("iptables", "ip6tables", "ufw", "ss"):
        if key not in out:
            raise BundleError(f"section missing: {SECTIONS[key]}")
        if out[key][0] != 0:
            raise BundleError(f"section failed (rc={out[key][0]}): {SECTIONS[key]}")
    return out


# ---------------------------------------------------------------- iptables
class Rule:
    __slots__ = ("chain", "mods", "neg", "opts", "raw", "target", "tparam")

    def __init__(self, raw):
        self.raw = raw
        tok = shlex.split(raw)
        if len(tok) < 2 or tok[0] != "-A":
            raise BundleError(f"bad rule: {raw}")
        self.chain, self.opts, self.neg, self.mods = tok[1], {}, set(), []
        self.target, self.tparam = None, []
        i, negate = 2, False
        while i < len(tok):
            t = tok[i]
            if t == "!":
                negate = True
                i += 1
                continue
            if t in ("-j", "-g"):
                self.target = tok[i + 1]
                self.tparam = tok[i + 2 :]
                break
            if t == "-m":
                self.mods.append(tok[i + 1])
                i += 2
                continue
            if t.startswith("-"):
                vals = []
                i += 1
                while i < len(tok) and not tok[i].startswith("-") and tok[i] != "!":
                    vals.append(tok[i])
                    i += 1
                self.opts[t] = " ".join(vals)
                if negate:
                    self.neg.add(t)
                negate = False
                continue
            i += 1


def parse_save(text):
    """iptables-save text -> {table: {"policy": {chain: policy}, "rules": {chain: [Rule]}}}."""
    tables, cur = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("*"):
            cur = tables.setdefault(line[1:], {"policy": {}, "rules": {}})
        elif line.startswith(":") and cur is not None:
            name, pol = line[1:].split()[:2]
            cur["policy"][name] = pol
            cur["rules"].setdefault(name, [])
        elif line.startswith("-A ") and cur is not None:
            r = Rule(line)
            cur["rules"].setdefault(r.chain, []).append(r)
    return tables


def _ports(spec):
    out = []
    for part in spec.split(","):
        a, _, b = part.partition(":")
        out.append((int(a), int(b or a)))
    return out


def _in_ports(port, spec):
    return any(a <= port <= b for a, b in _ports(spec))


class Probe:
    """A NEW connection from an arbitrary external source to (dst, proto, port) arriving on the uplink."""

    def __init__(self, family, proto, port, dst=None, out_if=None):
        self.family, self.proto, self.port, self.dst, self.out_if = family, proto, port, dst, out_if


def _iface_match(pattern, iface):
    if pattern.endswith("+"):
        return iface.startswith(pattern[:-1])
    return pattern == iface


def match(rule, p):
    """True / False / "cond" (matches only some packets of the probe: limits, source lists, unknown modules)."""
    cond, src = False, None
    for opt, val in rule.opts.items():
        neg = opt in rule.neg
        if opt in ("-p", "--protocol"):
            hit = val in (p.proto, "all")
        elif opt in ("--dport", "--dports", "--destination-port"):
            hit = _in_ports(p.port, val)
        elif opt == "-i":  # the probe arrives on the uplink, never lo or a container bridge
            hit = not (val == "lo" or val.startswith(("docker", "br-", "veth")))
        elif opt == "-o":
            hit = p.out_if is not None and _iface_match(val, p.out_if)
        elif opt == "-d":
            net = ipaddress.ip_network(val, strict=False)
            if net.is_multicast or net.is_loopback:
                hit = False
            elif p.dst is not None:
                hit = ipaddress.ip_address(p.dst) in net
            else:
                hit = True  # a host address of this box: assume it can be the probe's destination
        elif opt == "-s":
            net = ipaddress.ip_network(val, strict=False)
            if net.prefixlen == 0:
                hit = True
            elif neg:
                cond = True  # "everyone except X"
                continue
            else:
                src = str(net)
                continue
        elif opt in ("--ctstate", "--state"):
            hit = "NEW" in val.split(",")
        elif opt == "--dst-type":
            hit = "LOCAL" in val.split(",") and p.dst is None
        elif opt in ("--sport", "--sports", "--source-port"):
            cond = True
            continue
        elif opt == "--rt-type":
            hit = False  # matches only packets carrying an IPv6 routing header, never a plain SYN
        elif opt in ("--icmp-type", "--icmpv6-type", "--hl-eq", "--hitcount", "--seconds"):
            continue  # guarded by -p / module lists
        elif opt in (
            "--comment",
            "--name",
            "--mask",
            "--rsource",
            "--set",
            "--update",
            "--rcheck",
            "--limit",
            "--limit-burst",
            "--connlimit-above",
            "--connlimit-mask",
            "--connlimit-saddr",
        ) or opt in ("--reject-with", "--log-prefix", "--to-destination"):
            continue
        else:
            cond = True  # unknown match: may or may not match
            continue
        if neg:
            hit = not hit
        if not hit:
            return False
    for m in rule.mods:
        if m in LIMIT_MODULES:
            if "--set" in rule.opts and rule.target is None:
                continue
            cond = True
        elif m not in (
            "tcp",
            "udp",
            "multiport",
            "conntrack",
            "state",
            "comment",
            "addrtype",
            "icmp",
            "icmp6",
            "rt",
            "hl",
        ):
            cond = True
    if src is not None:
        return ("src", src)
    return "cond" if cond else True


def walk(tables, chain, p, depth=0, trail=None):
    """Walk chain for probe p. Returns (state, sources, trail) with state in open/limited/sources/closed/return."""
    filt = tables["filter"]
    rules = filt["rules"].get(chain, [])
    trail = trail if trail is not None else []
    sources, limited = [], False
    if depth > 20:
        raise BundleError(f"chain depth > 20 at {chain}")
    for r in rules:
        m = match(r, p)
        if m is False or r.target is None or r.target == "LOG":
            continue
        if isinstance(m, tuple):
            if r.target == "ACCEPT" or (r.target in filt["rules"] and _accepts(tables, r.target, p, depth)):
                sources.append(m[1])
                trail.append(r.raw)
            continue
        if r.target == "ACCEPT":
            trail.append(r.raw)
            if m == "cond":
                limited = True
                continue
            return ("limited" if limited else "open"), sources, trail
        if r.target in ("DROP", "REJECT"):
            if m == "cond":
                limited = True
                trail.append(r.raw)
                continue
            return _settle(sources, limited, trail, closed=True)
        if r.target == "RETURN":
            if m == "cond":
                continue
            return _settle(sources, limited, trail, ret=True)
        if r.target in filt["rules"]:
            st, src, _ = walk(tables, r.target, p, depth + 1, trail)
            sources += src
            if st == "return":
                continue
            if m == "cond" and st in ("closed",):
                limited = True
                continue
            if m == "cond" and st in ("open", "limited"):
                limited = True
                continue
            if st == "closed":
                return _settle(sources, limited, trail, closed=True)
            if st in ("open", "limited"):
                return ("limited" if (limited or st == "limited") else "open"), sources, trail
            if st == "sources":
                continue
        # DNAT/MASQUERADE/MARK etc. in filter: ignore
    if depth == 0:
        pol = filt["policy"].get(chain, "ACCEPT")
        if pol == "ACCEPT":
            return ("limited" if limited else "open"), sources, trail
        return _settle(sources, limited, trail, closed=True)
    return _settle(sources, limited, trail, ret=True)


def _accepts(tables, chain, p, depth):
    st, _, _ = walk(tables, chain, p, depth + 1, [])
    return st in ("open", "limited")


def _settle(sources, limited, trail, closed=False, ret=False):
    if ret:
        return "return", sources, trail
    if limited:
        return "limited", sources, trail
    if sources:
        return "sources", sources, trail
    return "closed", sources, trail


# ---------------------------------------------------------------- ss / docker / ufw / nft
SS_RE = re.compile(r"^(tcp|udp)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$")


def parse_ss(text):
    socks = []
    for line in text.splitlines():
        m = SS_RE.match(line.strip())
        if not m:
            continue
        proto, state, local, _peer, users = m.groups()
        if (proto == "tcp" and state != "LISTEN") or (proto == "udp" and state != "UNCONN"):
            continue
        addr, _, port = local.rpartition(":")
        procs = sorted(set(re.findall(r'\("([^"]+)"', users or "")))
        addr = addr.split("%")[0].strip("[]")
        socks.append({"proto": proto, "addr": addr, "port": int(port), "procs": procs})
    return socks


def sock_families(addr):
    """Families a bound socket accepts from the network: [] for loopback."""
    if addr == "*":
        return ["v4", "v6"]
    ip = ipaddress.ip_address(addr)
    if ip.is_loopback:
        return []
    return ["v4" if ip.version == 4 else "v6"]


def parse_dnat(tables):
    """Published ports: nat DOCKER DNAT rules -> [{hport, cport, cip, proto, dst, bridge}]."""
    out = []
    for r in tables.get("nat", {}).get("rules", {}).get("DOCKER", []):
        if r.target != "DNAT":
            continue
        to = r.tparam[r.tparam.index("--to-destination") + 1] if "--to-destination" in r.tparam else ""
        cip, _, cport = to.rpartition(":")
        cip = cip.strip("[]")
        dst = r.opts.get("-d")
        out.append(
            {
                "proto": r.opts.get("-p", "tcp"),
                "hport": int(r.opts["--dport"]),
                "cport": int(cport or r.opts["--dport"]),
                "cip": cip,
                "dst": dst.split("/")[0] if dst else None,
                "bridge": r.opts.get("-i", ""),
            }
        )
    return out


def parse_ufw(text):
    st = {"active": False, "default_in": None, "rules": []}
    for line in text.splitlines():
        if line.startswith("Status:"):
            st["active"] = line.split(":", 1)[1].strip() == "active"
        elif line.startswith("Default:"):
            m = re.search(r"(\w+) \(incoming\)", line)
            st["default_in"] = m.group(1) if m else None
    return st


def ufw_user_ports(tables, family):
    chain = "ufw-user-input" if family == "v4" else "ufw6-user-input"
    out = set()
    for r in tables.get("filter", {}).get("rules", {}).get(chain, []):
        if r.target is None:
            continue
        spec = r.opts.get("--dport") or r.opts.get("--dports")
        proto = r.opts.get("-p")
        if spec and proto:
            for a, b in _ports(spec):
                if b - a < 64:
                    out.update((proto, x) for x in range(a, b + 1))
    return out


def nft_foreign(text):
    out = []
    cur = None
    for line in (text or "").splitlines():
        s = line.strip()
        m = re.match(r"^table (\S+) (\S+) \{", s)
        if m:
            fam, name = m.groups()
            own = fam in ("ip", "ip6") and name in IPT_NFT_TABLES
            cur = None if own else f"{fam} {name}"
            continue
        if cur and "hook" in s:
            hm = re.search(r"hook (\w+)", s)
            out.append({"table": cur, "hook": hm.group(1) if hm else "?"})
    return out


# ---------------------------------------------------------------- policy
def read_peers(path):
    peers = {}
    if not path:
        return peers
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            name, _, val = line.partition("=")
            nets = [str(ipaddress.ip_network(v.strip(), strict=False)) for v in val.split(",") if v.strip()]
            peers[name.strip()] = nets
    return peers


def read_policy(path, peers):
    """Lines: `allow PROTO PORT FAMILY SOURCE [limit] [# purpose]`, FAMILY v4|v6|both, SOURCE any|CIDR|@peer."""
    rules = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            body, _, purpose = line.partition("#")
            tok = body.split()
            if not tok:
                continue
            if tok[0] != "allow" or len(tok) not in (5, 6) or (len(tok) == 6 and tok[5] != "limit"):
                raise PolicyError(f"{path}:{n}: expected `allow PROTO PORT FAMILY SOURCE [limit]`")
            _, proto, port, fam, src = tok[:5]
            if proto not in ("tcp", "udp") or not port.isdigit() or not 0 < int(port) < 65536:
                raise PolicyError(f"{path}:{n}: bad proto/port")
            if fam not in ("v4", "v6", "both"):
                raise PolicyError(f"{path}:{n}: family must be v4, v6 or both")
            if src == "any":
                nets = None
            elif src.startswith("@"):
                if src[1:] not in peers:
                    raise PolicyError(f"{path}:{n}: peer {src} not defined in the peers file")
                nets = peers[src[1:]]
            else:
                try:
                    nets = [str(ipaddress.ip_network(src, strict=False))]
                except ValueError as exc:
                    raise PolicyError(f"{path}:{n}: bad source {src}") from exc
            for f in ("v4", "v6") if fam == "both" else (fam,):
                rules.append(
                    {
                        "line": n,
                        "proto": proto,
                        "port": int(port),
                        "family": f,
                        "source": src,
                        "nets": nets,
                        "limit": len(tok) == 6,
                        "purpose": purpose.strip(),
                    }
                )
    return rules


# ---------------------------------------------------------------- audit
def exposures(bundle):
    t4 = parse_save(bundle["iptables"][1])
    t6 = parse_save(bundle["ip6tables"][1])
    tabs = {"v4": t4, "v6": t6}
    dnat = {"v4": parse_dnat(t4), "v6": parse_dnat(t6)}
    exp = {}  # (family, proto, port) -> record

    def add(fam, proto, port, path, owner, res):
        state, sources, trail = res
        if state == "closed":
            return
        k = (fam, proto, port)
        rec = exp.setdefault(
            k,
            {
                "family": fam,
                "proto": proto,
                "port": port,
                "paths": [],
                "owners": [],
                "state": "closed",
                "sources": [],
                "trail": [],
            },
        )
        rec["paths"].append(path)
        rec["owners"] = sorted(set(rec["owners"]) | set(owner))
        order = ["closed", "sources", "limited", "open"]
        if order.index(state) > order.index(rec["state"]):
            rec["state"] = state
        rec["sources"] = sorted(set(rec["sources"]) | set(sources))
        rec["trail"] += [x for x in trail if x not in rec["trail"]]

    for s in parse_ss(bundle["ss"][1]):
        for fam in sock_families(s["addr"]):
            proxied = "docker-proxy" in s["procs"]
            if proxied and any(d["hport"] == s["port"] and d["proto"] == s["proto"] for d in dnat[fam]):
                continue  # reached through DNAT on the FORWARD path (below), the proxy only serves host-local
            res = walk(tabs[fam], "INPUT", Probe(fam, s["proto"], s["port"]))
            add(fam, s["proto"], s["port"], "input", s["procs"], res)
    for fam in ("v4", "v6"):
        for d in dnat[fam]:
            if d["dst"] and ipaddress.ip_address(d["dst"]).is_loopback:
                continue
            p = Probe(fam, d["proto"], d["cport"], dst=d["cip"], out_if=d["bridge"])
            res = walk(tabs[fam], "FORWARD", p)
            add(fam, d["proto"], d["hport"], f"docker-forward->{d['cport']}", ["docker-dnat"], res)
    return exp, tabs, dnat


def audit(bundle, policy):
    findings = []

    def fnd(cls, msg, **kw):
        findings.append({"class": cls, "severity": SEVERITY[cls], "message": msg, **kw})

    ufw = parse_ufw(bundle["ufw"][1])
    if not ufw["active"]:
        fnd("ufw-inactive", "ufw is not active")
    if ufw["default_in"] not in ("deny", "reject"):
        fnd("default-incoming-allow", f"ufw default incoming policy is {ufw['default_in']}")
    exp, tabs, dnat = exposures(bundle)
    for k, rec in sorted(exp.items()):
        fam, proto, port = k
        decl = [r for r in policy if (r["family"], r["proto"], r["port"]) == k]
        where = {"family": fam, "proto": proto, "port": port}
        if not decl:
            fnd(
                "undeclared-exposure",
                f"{proto}/{port} {fam} reachable ({rec['state']}) but not declared",
                **where,
                state=rec["state"],
                owners=rec["owners"],
                paths=rec["paths"],
            )
            continue
        d = decl[0]
        if d["nets"] is not None:
            allowed = [ipaddress.ip_network(n) for n in d["nets"]]
            extra = [
                s
                for s in rec["sources"]
                if not any(
                    ipaddress.ip_network(s).subnet_of(a)
                    for a in allowed
                    if ipaddress.ip_network(s).version == a.version
                )
            ]
            if rec["state"] in ("open", "limited") or extra:
                fnd(
                    "source-too-broad",
                    f"{proto}/{port} {fam} declared {d['source']} but reachable "
                    f"{'from any source' if rec['state'] in ('open', 'limited') else 'from ' + ','.join(extra)}",
                    **where,
                    state=rec["state"],
                    paths=rec["paths"],
                )
        if d["limit"] and rec["state"] == "open":
            fnd(
                "missing-limit",
                f"{proto}/{port} {fam} declared rate-limited but reachable without a limit",
                **where,
                paths=rec["paths"],
            )
        if any(pth.startswith("docker-forward") for pth in rec["paths"]) and (proto, port) in ufw_user_ports(
            tabs[fam], fam
        ):
            fnd(
                "ufw-rule-bypassed",
                f"{proto}/{port} {fam} is published via Docker DNAT: the ufw rule for it is "
                "not on the path; DOCKER-USER decides",
                **where,
            )
    for d in policy:
        k = (d["family"], d["proto"], d["port"])
        if k not in exp:
            fnd(
                "declared-unreachable",
                f"{d['proto']}/{d['port']} {d['family']} declared (policy line {d['line']}) "
                "but not reachable from outside (no listener on that family, or filtered)",
                family=d["family"],
                proto=d["proto"],
                port=d["port"],
            )
    listening = {(f, s["proto"], s["port"]) for s in parse_ss(bundle["ss"][1]) for f in sock_families(s["addr"])}
    for fam in ("v4", "v6"):
        published = {(d["proto"], d["hport"]) for d in dnat[fam]}
        for proto, port in sorted(ufw_user_ports(tabs[fam], fam)):
            if (fam, proto, port) not in listening and (proto, port) not in published:
                fnd(
                    "stale-allow",
                    f"ufw allows {proto}/{port} {fam} but nothing listens there",
                    family=fam,
                    proto=proto,
                    port=port,
                )
    for fam in ("v4", "v6"):
        raw = tabs[fam].get("raw", {}).get("rules", {}).get("PREROUTING", [])
        for d in dnat[fam]:
            if d["dst"] and ipaddress.ip_address(d["dst"]).is_loopback:
                guarded = any(
                    r.target == "DROP"
                    and r.opts.get("--dport") == str(d["hport"])
                    and r.opts.get("-d", "").split("/")[0] == d["dst"]
                    for r in raw
                )
                if not guarded:
                    fnd(
                        "loopback-dnat-unguarded",
                        f"{d['proto']}/{d['hport']} {fam} DNAT on {d['dst']} has no raw "
                        "PREROUTING drop for non-lo traffic",
                        family=fam,
                        proto=d["proto"],
                        port=d["hport"],
                    )
    for t in nft_foreign(bundle.get("nft", (0, ""))[1]):
        fnd(
            "nft-foreign-table", f"nftables table '{t['table']}' hooks {t['hook']} outside iptables (not modelled)", **t
        )
    verdict = "PASS"
    for f in findings:
        if f["severity"] == "FAIL":
            verdict = "FAIL"
        elif f["severity"] == "WARN" and verdict == "PASS":
            verdict = "WARN"
    table = [{k: v for k, v in rec.items() if k != "trail"} for _, rec in sorted(exp.items())]
    return {"version": VERSION, "verdict": verdict, "exposure": table, "findings": findings}


def render(res):
    out = [f"{'FAMILY':6} {'PROTO':5} {'PORT':>5}  {'STATE':8} {'PATH':22} OWNERS"]
    for e in res["exposure"]:
        st = e["state"] + ("" if e["state"] != "sources" else f" ({len(e['sources'])})")
        out.append(
            f"{e['family']:6} {e['proto']:5} {e['port']:>5}  {st:8} {','.join(e['paths']):22} {','.join(e['owners'])}"
        )
    for f in res["findings"]:
        out.append(f"  [{f['severity']}] {f['class']}: {f['message']}")
    out.append(f"RESULT: {res['verdict']}")
    return "\n".join(out)


def main(argv):
    if len(argv) < 3 or argv[0] != "audit":
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 3
    bundle_path, policy_path = argv[1], argv[2]
    rest = argv[3:]
    as_json = "--json" in rest
    peers_path = (
        rest[rest.index("--peers") + 1] if "--peers" in rest and rest.index("--peers") + 1 < len(rest) else None
    )
    try:
        policy = read_policy(policy_path, read_peers(peers_path))
    except (OSError, PolicyError, ValueError) as exc:
        print(f"fwaudit: policy: {exc}", file=sys.stderr)
        return 3
    try:
        with open(bundle_path, encoding="utf-8") as fh:
            bundle = read_bundle(fh.read())
        res = audit(bundle, policy)
    except (OSError, BundleError, ValueError, KeyError, IndexError) as exc:
        print(f"fwaudit: bundle: {exc}", file=sys.stderr)
        return 4
    print(json.dumps(res, indent=1, sort_keys=True) if as_json else render(res))
    return EXIT[res["verdict"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
