#!/usr/bin/env python3
"""Grade a pft-peertls capture bundle against a per-role TLS policy (read-only, stdlib only).

pft-peertls.sh does every handshake (openssl s_client) and writes the raw output into a bundle; this file only parses
that text, so the same bundle always grades the same way and a committed JSON report renders back byte-identically.

  peertls_eval.py audit BUNDLE --policy FILE [--waivers FILE] [--state FILE] [--write-state FILE] [--host H]
                        [--now EPOCH] [--json] [--public]          exit 0 PASS, 1 WARN, 2 FAIL, 3 policy, 4 bundle
  peertls_eval.py render REPORT.json                               the human report of a JSON report (offline)
  peertls_eval.py crosscheck A.json B.json                         remote view of a host == that host's own view
  peertls_eval.py checks                                           every check id and its class (for metrics)
  peertls_eval.py matrix                                           the probe matrix the collector runs

Bundle sections (written by pft-peertls.sh collect):
  ### target NAME scope=local|remote started=EPOCH|-     one per target, before its probes
  ### probe ID offer=STRING|-                            then `### $ CMD`, the command's output, `### rc=N`
  ### cert                                               `openssl x509 -noout -text -fingerprint -sha256` output
  ### end handshakes=N
"""

import hashlib
import json
import re
import sys
from datetime import datetime, timezone

VERSION = 1
MAX_HANDSHAKES = 40

# Probe matrix: id -> (kind, protocol flag, offer). kind: proto (one protocol, any cipher), cipher (TLS 1.2, one class
# of suites), tls13 (one TLS 1.3 suite), reneg (client-initiated renegotiation after a TLS 1.2 handshake),
# fallback (TLS 1.2 with TLS_FALLBACK_SCSV), cert (fetch the leaf certificate). SECLEVEL=0 lets the client OFFER weak
# suites/protocols so the server's answer is what gets graded.
MATRIX = [
    ("proto.tls1", "proto", "-tls1", "DEFAULT:@SECLEVEL=0"),
    ("proto.tls1_1", "proto", "-tls1_1", "DEFAULT:@SECLEVEL=0"),
    ("proto.tls1_2", "proto", "-tls1_2", "-"),
    ("proto.tls1_3", "proto", "-tls1_3", "-"),
    ("cipher.null", "cipher", "-tls1_2", "eNULL:@SECLEVEL=0"),
    ("cipher.anull", "cipher", "-tls1_2", "aNULL:@SECLEVEL=0"),
    ("cipher.export", "cipher", "-tls1_2", "EXPORT:@SECLEVEL=0"),
    ("cipher.rc4", "cipher", "-tls1_2", "RC4:@SECLEVEL=0"),
    ("cipher.3des", "cipher", "-tls1_2", "3DES:@SECLEVEL=0"),
    ("cipher.cbc_sha1", "cipher", "-tls1_2", "SHA1:!aNULL:!eNULL:@SECLEVEL=0"),
    (
        "cipher.cbc_sha2",
        "cipher",
        "-tls1_2",
        "SHA256:SHA384:!AESGCM:!AESCCM:!CHACHA20:!ARIAGCM:!aNULL:!eNULL:@SECLEVEL=0",
    ),
    ("cipher.kx_rsa", "cipher", "-tls1_2", "kRSA:@SECLEVEL=0"),
    ("cipher.kx_dhe", "cipher", "-tls1_2", "kDHE:!aNULL:@SECLEVEL=0"),
    ("cipher.ecdhe_aead", "cipher", "-tls1_2", "ECDHE+AESGCM:ECDHE+CHACHA20"),
    ("tls13.aes128gcm", "tls13", "-tls1_3", "TLS_AES_128_GCM_SHA256"),
    ("tls13.aes256gcm", "tls13", "-tls1_3", "TLS_AES_256_GCM_SHA384"),
    ("tls13.chacha20", "tls13", "-tls1_3", "TLS_CHACHA20_POLY1305_SHA256"),
    ("hs.reneg", "reneg", "-tls1_2", "-"),
    ("hs.fallback", "fallback", "-tls1_2", "-"),
    ("cert", "cert", "-", "-"),
]
PROBE_IDS = [m[0] for m in MATRIX]

# check id -> class. Every check is graded per target; policy decides the severity of a violation.
CHECKS = {
    "probe.reachable": "probe",
    "proto.tls1": "protocol",
    "proto.tls1_1": "protocol",
    "proto.tls1_2": "protocol",
    "proto.tls1_3": "protocol",
    "cipher.null": "cipher",
    "cipher.anull": "cipher",
    "cipher.export": "cipher",
    "cipher.rc4": "cipher",
    "cipher.3des": "cipher",
    "cipher.cbc_sha1": "cipher",
    "cipher.cbc_sha2": "cipher",
    "cipher.kx_rsa": "cipher",
    "cipher.kx_dhe": "cipher",
    "cipher.ecdhe_aead": "cipher",
    "cipher.tls13_suites": "cipher",
    "kx.dh_bits": "cipher",
    "cert.key": "cert",
    "cert.sig_hash": "cert",
    "cert.validity": "cert",
    "hs.compression": "handshake",
    "hs.secure_reneg": "handshake",
    "hs.client_reneg": "handshake",
    "hs.fallback_scsv": "handshake",
    "hs.ems": "handshake",
    "hs.ticket_lifetime": "handshake",
    "drift.posture": "drift",
    "drift.cert": "drift",
}
SEV = {"PASS": 0, "WARN": 1, "FAIL": 2}
RULES = ("forbid", "require", "allow")
POLICY_KEYS = {
    "protocol": RULES,
    "cipher": RULES,
    "min_rsa_bits": None,
    "min_ec_bits": None,
    "min_dh_bits": None,
    "forbid_sig_hash": None,
    "min_cert_days_left": None,
    "max_ticket_lifetime": None,
    "severity": None,
}


def read_text(path, errors="strict"):
    with open(path, encoding="utf-8", errors=errors) as f:
        return f.read()


def read_json(path):
    return json.loads(read_text(path))


class BundleError(Exception):
    pass


class PolicyError(Exception):
    pass


# ---------- policy and waivers ----------
def load_policy(path):
    """policy lines: `protocol NAME forbid|require|allow`, `cipher CLASS ...`, `min_rsa_bits N`, `min_ec_bits N`,
    `min_dh_bits N`, `forbid_sig_hash H [H...]`, `min_cert_days_left N`, `max_ticket_lifetime SEC`,
    `severity CHECK FAIL|WARN` (severity of a violation; default FAIL)."""
    try:
        text = read_text(path)
    except OSError as e:
        raise PolicyError(f"cannot read policy {path}: {e.strerror}") from e
    pol = {
        "protocol": {},
        "cipher": {},
        "severity": {},
        "forbid_sig_hash": [],
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].split()
        if not line:
            continue
        key, args = line[0], line[1:]
        if key not in POLICY_KEYS:
            raise PolicyError(f"policy line {n}: unknown key {key}")
        if key in ("protocol", "cipher"):
            if len(args) != 2 or args[1] not in RULES:
                raise PolicyError(f"policy line {n}: want `{key} NAME forbid|require|allow`")
            known = f"{'proto' if key == 'protocol' else 'cipher'}.{args[0]}" in CHECKS
            if not known and not (key == "cipher" and args[0] == "tls13_suites"):
                raise PolicyError(f"policy line {n}: unknown {key} {args[0]}")
            pol[key][args[0]] = args[1]
        elif key == "severity":
            if len(args) != 2 or args[0] not in CHECKS or args[1] not in ("FAIL", "WARN"):
                raise PolicyError(f"policy line {n}: want `severity CHECK FAIL|WARN`")
            pol["severity"][args[0]] = args[1]
        elif key == "forbid_sig_hash":
            if not args:
                raise PolicyError(f"policy line {n}: forbid_sig_hash needs at least one hash")
            pol[key] = [a.lower() for a in args]
        else:
            if len(args) != 1 or not re.fullmatch(r"[0-9]+", args[0]):
                raise PolicyError(f"policy line {n}: {key} wants one integer")
            pol[key] = int(args[0])
    for need in ("min_rsa_bits", "min_ec_bits", "min_dh_bits", "min_cert_days_left", "max_ticket_lifetime"):
        if need not in pol:
            raise PolicyError(f"policy has no {need}")
    for p in ("tls1", "tls1_1", "tls1_2", "tls1_3"):
        if p not in pol["protocol"]:
            raise PolicyError(f"policy has no rule for protocol {p}")
    return pol


def load_waivers(path, now):
    """waiver lines (private, root-owned): `CHECK TARGET|* until=YYYY-MM-DD reason...`. Expired waivers are ignored
    and reported; a waiver turns a WARN/FAIL of that check into `waived` (counted, never detailed in --public)."""
    out, expired = [], []
    if not path:
        return out, expired
    try:
        lines = read_text(path).splitlines()
    except FileNotFoundError:
        return out, expired
    except OSError as e:
        raise PolicyError(f"cannot read waivers {path}: {e.strerror}") from e
    for n, raw in enumerate(lines, 1):
        f = raw.split("#", 1)[0].split()
        if not f:
            continue
        if len(f) < 4 or f[0] not in CHECKS or not f[2].startswith("until="):
            raise PolicyError(f"waivers line {n}: want `CHECK TARGET|* until=YYYY-MM-DD reason`")
        try:
            until = datetime.strptime(f[2][6:], "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp() + 86400
        except ValueError as e:
            raise PolicyError(f"waivers line {n}: bad date {f[2][6:]}") from e
        w = {"check": f[0], "target": f[1], "until": int(until)}
        (out if until > now else expired).append(w)
    return out, expired


# ---------- bundle parsing ----------
def parse_bundle(text):
    targets, cur, probe, mode, ended = [], None, None, None, None
    for line in text.splitlines():
        if line.startswith("### target "):
            m = re.fullmatch(r"### target ([a-z][a-z0-9_-]{0,31}) scope=(local|remote) started=([0-9]+|-)", line)
            if not m:
                raise BundleError(f"bad target line: {line}")
            cur = {
                "name": m.group(1),
                "scope": m.group(2),
                "started": None if m.group(3) == "-" else int(m.group(3)),
                "probes": {},
                "cert_text": None,
            }
            targets.append(cur)
            probe = mode = None
        elif line.startswith("### probe "):
            m = re.fullmatch(r"### probe (\S+) offer=(\S+)", line)
            if not m or cur is None or m.group(1) not in PROBE_IDS or m.group(1) == "cert":
                raise BundleError(f"bad probe line: {line}")
            if m.group(1) in cur["probes"]:
                raise BundleError(f"duplicate probe {m.group(1)} for {cur['name']}")
            probe = {"offer": m.group(2), "out": [], "rc": None}
            cur["probes"][m.group(1)] = probe
            mode = "probe"
        elif line == "### cert":
            if cur is None:
                raise BundleError("cert section before any target")
            cur["cert_text"], mode, probe = [], "cert", None
        elif line.startswith("### $ "):
            continue
        elif line.startswith("### rc="):
            if probe is None or not re.fullmatch(r"### rc=[0-9]+", line):
                raise BundleError(f"stray rc line: {line}")
            probe["rc"] = int(line[7:])
            probe, mode = None, None
        elif line.startswith("### end "):
            m = re.fullmatch(r"### end handshakes=([0-9]+)", line)
            if not m:
                raise BundleError(f"bad end line: {line}")
            ended = int(m.group(1))
            mode = None
        elif mode == "probe":
            probe["out"].append(line)
        elif mode == "cert":
            cur["cert_text"].append(line)
    if ended is None:
        raise BundleError("bundle has no end line (capture cut short)")
    if not targets:
        raise BundleError("bundle has no targets")
    if ended > MAX_HANDSHAKES:
        raise BundleError(f"bundle used {ended} handshakes (> {MAX_HANDSHAKES})")
    for t in targets:
        for pid in PROBE_IDS:
            if pid != "cert" and pid not in t["probes"]:
                raise BundleError(f"target {t['name']}: probe {pid} missing")
            if pid != "cert" and t["probes"][pid]["rc"] is None:
                raise BundleError(f"target {t['name']}: probe {pid} has no rc line")
    return targets, ended


ALERTS = {
    "40": "handshake_failure",
    "47": "illegal_parameter",
    "70": "protocol_version",
    "71": "insufficient_security",
    "80": "internal_error",
    "86": "inappropriate_fallback",
    "100": "no_renegotiation",
}


def parse_probe(kind, p):
    """-> dict(result=accepted|refused|untestable|error, protocol, cipher, alert, temp_key, ...)"""
    out = "\n".join(p["out"])
    r = {"result": "error", "protocol": None, "cipher": None, "alert": None, "rc": p["rc"]}
    m = re.search(r"^New, (\S+), Cipher is (\S+)$", out, re.MULTILINE)
    a = re.search(r"SSL alert number ([0-9]+)", out)
    if a:
        r["alert"] = ALERTS.get(a.group(1), "alert_" + a.group(1))
    if re.search(r"no (protocols|ciphers) available|no cipher match|Error with command", out):
        r["result"] = "untestable"
        return r
    if re.search(r"connect:errno=|Connection refused|Name or service not known|connect: Connection timed out", out) or (
        m is None and a is None and p["rc"] in (124, 137)
    ):
        r["result"] = "error"
        return r
    if m and m.group(2) != "(NONE)":
        r.update(result="accepted", protocol=m.group(1), cipher=m.group(2))
    elif a or (m and m.group(2) == "(NONE)"):
        r["result"] = "refused"
    tk = re.search(r"^Server Temp Key: ([A-Za-z0-9-]+), ([0-9]+) bits", out, re.MULTILINE)
    r["temp_key"] = f"{tk.group(1)}-{tk.group(2)}" if tk else None
    c = re.search(r"^Compression: (\S+)", out, re.MULTILINE)
    r["compression"] = c.group(1) if c else None
    r["secure_reneg"] = (
        True
        if "Secure Renegotiation IS supported" in out
        else (False if "Secure Renegotiation IS NOT supported" in out else None)
    )
    e = re.search(r"Extended master secret: (yes|no)", out)
    r["ems"] = None if not e else e.group(1) == "yes"
    t = re.search(r"TLS session ticket lifetime hint: ([0-9]+)", out)
    r["ticket_lifetime"] = int(t.group(1)) if t else None
    if kind == "reneg":
        tail = out.split("RENEGOTIATING", 1)
        if r["result"] != "accepted" or len(tail) == 1:
            r["reneg"] = "untested"
        elif re.search(r"no renegotiation|alert", tail[1]):
            r["reneg"] = "refused"
        elif re.search(r"^depth=|^verify return", tail[1], re.MULTILINE):
            r["reneg"] = "accepted"
        else:
            r["reneg"] = "unknown"
    if kind == "fallback":
        r["fallback"] = "refused" if r["alert"] == "inappropriate_fallback" else r["result"]
    return r


MONTHS = {
    m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)
}


def x509_time(s):
    m = re.fullmatch(r"([A-Z][a-z]{2}) +([0-9]{1,2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4}) GMT", s.strip())
    if not m:
        raise BundleError(f"bad certificate time {s!r}")
    return int(
        datetime(
            int(m.group(6)),
            MONTHS[m.group(1)],
            int(m.group(2)),
            int(m.group(3)),
            int(m.group(4)),
            int(m.group(5)),
            tzinfo=timezone.utc,
        ).timestamp()
    )


def parse_cert(lines):
    if not lines:
        return None
    text = "\n".join(lines)
    fp = re.search(r"^(?:sha256|SHA256) Fingerprint=([0-9A-F:]{95})$", text, re.MULTILINE)
    bits = re.search(r"Public-Key: \(([0-9]+) bit\)", text)
    alg = re.search(r"Public Key Algorithm: (\S+)", text)
    sig = re.search(r"^\s*Signature Algorithm: (\S+)", text, re.MULTILINE)
    nb = re.search(r"Not Before: (.+)$", text, re.MULTILINE)
    na = re.search(r"Not After : (.+)$", text, re.MULTILINE)
    if not (fp and bits and alg and sig and nb and na):
        return None
    subj = re.search(r"^\s*Subject:(.*)$", text, re.MULTILINE)
    iss = re.search(r"^\s*Issuer:(.*)$", text, re.MULTILINE)
    s = sig.group(1).lower()
    h = next(
        (
            x
            for x in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
            if s.startswith(x) or f"-with-{x}" in s or f"with{x}" in s
        ),
        None,
    )
    if h is None and s in ("ed25519", "ed448", "rsassapss"):
        h = s
    return {
        "fp_sha256": fp.group(1).replace(":", "").lower(),
        "key_type": {"rsaEncryption": "rsa", "id-ecPublicKey": "ec", "ED25519": "ed25519"}.get(
            alg.group(1), alg.group(1)
        ),
        "key_bits": int(bits.group(1)),
        "sig_alg": sig.group(1),
        "sig_hash": h or "unknown",
        "not_before": x509_time(nb.group(1)),
        "not_after": x509_time(na.group(1)),
        "self_signed": (subj.group(1).strip() if subj else None) == (iss.group(1).strip() if iss else None),
    }


# ---------- grading ----------
def grade_target(t, pol, now, prev):
    kinds = {m[0]: m[1] for m in MATRIX}
    probes = {pid: parse_probe(kinds[pid], p) for pid, p in t["probes"].items()}
    cert = parse_cert(t["cert_text"])
    checks = []

    def add(cid, bad, reason, evidence, severity=None):
        sev = severity or pol["severity"].get(cid, "FAIL")
        checks.append(
            {"id": cid, "target": t["name"], "result": sev if bad else "PASS", "reason": reason, "evidence": evidence}
        )

    errs = sorted(pid for pid, r in probes.items() if r["result"] == "error")
    add(
        "probe.reachable",
        bool(errs) or cert is None,
        ("probes failed to connect: " + ",".join(errs))
        if errs
        else ("no certificate captured" if cert is None else f"{len(probes)} probes answered"),
        errs or ["cert"],
    )
    for name in ("tls1", "tls1_1", "tls1_2", "tls1_3"):
        cid, r = f"proto.{name}", probes[f"proto.{name}"]
        rule = pol["protocol"][name]
        res = r["result"]
        if res in ("untestable", "error"):
            checks.append(
                {
                    "id": cid,
                    "target": t["name"],
                    "result": "INFO",
                    "reason": f"{res} with this client",
                    "evidence": [cid],
                }
            )
            continue
        bad = (rule == "forbid" and res == "accepted") or (rule == "require" and res != "accepted")
        why = f"{name} {res}" + (f" ({r['alert']})" if r["alert"] else "") + f"; policy {rule}"
        add(cid, bad, why, [cid])
    for pid in PROBE_IDS:
        if not pid.startswith("cipher."):
            continue
        cls, r = pid.split(".", 1)[1], probes[pid]
        rule = pol["cipher"].get(cls, "allow")
        if r["result"] in ("untestable", "error"):
            checks.append(
                {
                    "id": pid,
                    "target": t["name"],
                    "result": "INFO",
                    "reason": f"{r['result']}: this client cannot offer {cls} suites",
                    "evidence": [pid],
                }
            )
            continue
        bad = (rule == "forbid" and r["result"] == "accepted") or (rule == "require" and r["result"] != "accepted")
        why = f"{cls} {r['result']}" + (f" as {r['cipher']}" if r["cipher"] else "") + f"; policy {rule}"
        add(pid, bad, why, [pid])
    t13 = [pid for pid in PROBE_IDS if pid.startswith("tls13.")]
    acc13 = [pid.split(".", 1)[1] for pid in t13 if probes[pid]["result"] == "accepted"]
    rule13 = pol["cipher"].get("tls13_suites", "allow")
    if probes["proto.tls1_3"]["result"] != "accepted":
        checks.append(
            {
                "id": "cipher.tls13_suites",
                "target": t["name"],
                "result": "INFO",
                "reason": "TLS 1.3 not accepted; suites not graded",
                "evidence": t13,
            }
        )
    else:
        add(
            "cipher.tls13_suites",
            rule13 == "require" and not acc13,
            f"TLS 1.3 suites accepted: {','.join(acc13) or 'none'}",
            t13,
        )
    dh = probes["cipher.kx_dhe"]
    if dh["result"] == "accepted" and dh["temp_key"] and dh["temp_key"].startswith("DH-"):
        b = int(dh["temp_key"].split("-")[1])
        add("kx.dh_bits", b < pol["min_dh_bits"], f"DHE group {b} bits (min {pol['min_dh_bits']})", ["cipher.kx_dhe"])
    else:
        checks.append(
            {
                "id": "kx.dh_bits",
                "target": t["name"],
                "result": "INFO",
                "reason": "no DHE handshake to measure",
                "evidence": ["cipher.kx_dhe"],
            }
        )
    if cert:
        need = pol["min_ec_bits"] if cert["key_type"] == "ec" else pol["min_rsa_bits"]
        add("cert.key", cert["key_bits"] < need, f"{cert['key_type']} {cert['key_bits']} bits (min {need})", ["cert"])
        add(
            "cert.sig_hash",
            cert["sig_hash"] in pol["forbid_sig_hash"] or cert["sig_hash"] == "unknown",
            f"signature {cert['sig_alg']} (hash {cert['sig_hash']}; forbidden {','.join(pol['forbid_sig_hash'])})",
            ["cert"],
        )
        left = (cert["not_after"] - now) // 86400
        bad = now < cert["not_before"] or left < pol["min_cert_days_left"]
        why = "not yet valid" if now < cert["not_before"] else f"{left} days left (min {pol['min_cert_days_left']})"
        add("cert.validity", bad, why, ["cert"])
    base = probes["proto.tls1_2"] if probes["proto.tls1_2"]["result"] == "accepted" else None
    if base:
        add(
            "hs.compression",
            base["compression"] not in ("NONE", None),
            f"compression {base['compression']}",
            ["proto.tls1_2"],
        )
        add(
            "hs.secure_reneg",
            base["secure_reneg"] is False,
            "RFC 5746 renegotiation_info "
            + {True: "present", False: "missing", None: "not reported"}[base["secure_reneg"]],
            ["proto.tls1_2"],
        )
        add(
            "hs.ems",
            base["ems"] is False,
            "extended master secret " + {True: "yes", False: "no", None: "not reported"}[base["ems"]],
            ["proto.tls1_2"],
        )
        lt = base["ticket_lifetime"]
        add(
            "hs.ticket_lifetime",
            lt is not None and lt > pol["max_ticket_lifetime"],
            f"ticket lifetime hint {lt if lt is not None else 'none (no ticket)'} s (max {pol['max_ticket_lifetime']})",
            ["proto.tls1_2"],
        )
    rn = probes["hs.reneg"]
    rv = rn.get("reneg", "untested")
    if rv in ("untested", "unknown"):
        checks.append(
            {
                "id": "hs.client_reneg",
                "target": t["name"],
                "result": "INFO",
                "reason": f"client renegotiation {rv}",
                "evidence": ["hs.reneg"],
            }
        )
    else:
        add("hs.client_reneg", rv == "accepted", f"client-initiated renegotiation {rv}", ["hs.reneg"])
    fb = probes["hs.fallback"]
    if probes["proto.tls1_3"]["result"] != "accepted":
        checks.append(
            {
                "id": "hs.fallback_scsv",
                "target": t["name"],
                "result": "INFO",
                "reason": "server tops out below TLS 1.3; fallback not graded",
                "evidence": ["hs.fallback"],
            }
        )
    else:
        add(
            "hs.fallback_scsv",
            fb["fallback"] != "refused",
            f"TLS 1.2 + FALLBACK_SCSV {fb['fallback']}" + (f" ({fb['alert']})" if fb["alert"] else ""),
            ["hs.fallback"],
        )
    posture = {
        "protocols": sorted(
            p.split(".", 1)[1] for p in PROBE_IDS if p.startswith("proto.") and probes[p]["result"] == "accepted"
        ),
        "ciphers": sorted(
            p.split(".", 1)[1] for p in PROBE_IDS if p.startswith("cipher.") and probes[p]["result"] == "accepted"
        ),
        "tls13": sorted(acc13),
        "reneg": rv,
        "dh": dh["temp_key"] if dh["result"] == "accepted" else None,
        "cert_key": f"{cert['key_type']}-{cert['key_bits']}-{cert['sig_hash']}" if cert else None,
    }
    drift = []
    if prev:
        for k in sorted(posture):
            if prev.get("posture", {}).get(k) != posture[k]:
                drift.append(
                    {"target": t["name"], "item": k, "before": prev.get("posture", {}).get(k), "after": posture[k]}
                )
        add(
            "drift.posture",
            bool(drift),
            ("changed: " + ",".join(d["item"] for d in drift)) if drift else "posture unchanged since the last run",
            ["state"],
            severity=pol["severity"].get("drift.posture", "WARN"),
        )
        pf, cf = prev.get("fp_sha256"), cert["fp_sha256"] if cert else None
        if pf and cf and pf != cf:
            restarted = t["started"] is not None and prev.get("started") is not None and t["started"] != prev["started"]
            if restarted:
                checks.append(
                    {
                        "id": "drift.cert",
                        "target": t["name"],
                        "result": "INFO",
                        "reason": "certificate changed with a node restart (postfiatd makes a new one at start)",
                        "evidence": ["cert", "state"],
                    }
                )
            else:
                add(
                    "drift.cert",
                    True,
                    "certificate changed without a node restart",
                    ["cert", "state"],
                    severity=pol["severity"].get("drift.cert", "WARN"),
                )
            drift.append(
                {"target": t["name"], "item": "cert", "before": pf[:16], "after": cf[:16], "restart": restarted}
            )
        else:
            add(
                "drift.cert",
                False,
                "certificate unchanged" if pf else "no earlier certificate",
                ["cert", "state"],
                severity="WARN",
            )
    else:
        for cid in ("drift.posture", "drift.cert"):
            checks.append(
                {
                    "id": cid,
                    "target": t["name"],
                    "result": "INFO",
                    "reason": "first run (no state)",
                    "evidence": ["state"],
                }
            )
    view = {
        pid: {
            k: v
            for k, v in r.items()
            if k in ("result", "protocol", "cipher", "alert", "temp_key", "reneg", "fallback")
        }
        for pid, r in sorted(probes.items())
    }
    state = {"posture": posture, "fp_sha256": cert["fp_sha256"] if cert else None, "started": t["started"]}
    tout = {
        "name": t["name"],
        "scope": t["scope"],
        "probes": view,
        "posture": posture,
        "cert": {k: (v[:16] if k == "fp_sha256" else v) for k, v in cert.items()} if cert else None,
    }
    return tout, checks, drift, state


def apply_waivers(checks, waivers):
    for c in checks:
        if c["result"] in ("WARN", "FAIL"):
            for w in waivers:
                if w["check"] == c["id"] and w["target"] in ("*", c["target"]):
                    c["waived_from"], c["result"] = c["result"], "WAIVED"
                    break


def audit(bundle_text, pol, waivers, expired, prev_state, host, now):
    targets, used = parse_bundle(bundle_text)
    out_t, checks, drift, state = [], [], [], {"targets": {}}
    for t in targets:
        tt, cc, dd, st = grade_target(t, pol, now, (prev_state or {}).get("targets", {}).get(t["name"]))
        out_t.append(tt)
        checks += cc
        drift += dd
        state["targets"][t["name"]] = st
    apply_waivers(checks, waivers)
    worst = max([SEV.get(c["result"], 0) for c in checks] + [0])
    counts = {k: sum(1 for c in checks if c["result"] == k) for k in ("PASS", "WARN", "FAIL", "WAIVED", "INFO")}
    rep = {
        "tool": "pft-peertls",
        "version": VERSION,
        "host": host,
        "generated": now,
        "handshakes": used,
        "policy_sha256": pol["sha256"],
        "verdict": {0: "PASS", 1: "WARN", 2: "FAIL"}[worst],
        "counts": counts,
        "expired_waivers": len(expired),
        "targets": out_t,
        "checks": checks,
        "drift": drift,
    }
    return rep, state


def public_view(rep):
    """Waived findings are open weaknesses nobody here can fix: keep them, and every probe that evidences them, out
    of anything published. Counts stay, so a reader sees that something was waived."""
    r = json.loads(json.dumps(rep))
    hidden = {(c["target"], e) for c in r["checks"] if c["result"] == "WAIVED" for e in c["evidence"]}
    r["checks"] = [c for c in r["checks"] if c["result"] != "WAIVED"]
    for t in r["targets"]:
        for pid in list(t["probes"]):
            if (t["name"], pid) in hidden:
                t["probes"][pid] = {"result": "private"}
        hide_posture = {e.split(".", 1)[1] for (n, e) in hidden if n == t["name"] and e.startswith("cipher.")}
        t["posture"]["ciphers"] = [c for c in t["posture"]["ciphers"] if c not in hide_posture]
        if any(n == t["name"] and e == "cipher.kx_dhe" for (n, e) in hidden):
            t["posture"]["dh"] = "private"
        if any(n == t["name"] and e == "cert" for (n, e) in hidden):
            t["cert"] = "private"
    r["drift"] = [d for d in r["drift"] if not any(n == d["target"] for (n, e) in hidden if e == "state")]
    r["public"] = True
    return r


def render(rep):
    iso = lambda s: datetime.fromtimestamp(s, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    L = [
        f"pft-peertls audit - {rep['host']} - {iso(rep['generated'])}",
        f"policy sha256 {rep['policy_sha256'][:16]} | handshakes {rep['handshakes']}/{MAX_HANDSHAKES}"
        + (" | public view" if rep.get("public") else ""),
    ]
    for t in rep["targets"]:
        p = t["posture"]
        L.append("")
        L.append(f"target {t['name']} ({t['scope']})")
        L.append(f"  protocols accepted: {' '.join(p['protocols']) or 'none'}")
        L.append(f"  TLS 1.2 classes accepted: {' '.join(p['ciphers']) or 'none'}")
        L.append(f"  TLS 1.3 suites accepted: {' '.join(p['tls13']) or 'none'}")
        c = t["cert"]
        if isinstance(c, dict):
            L.append(
                f"  certificate: {c['key_type']} {c['key_bits']} bit, {c['sig_alg']}, valid {iso(c['not_before'])}"
                f" .. {iso(c['not_after'])}, sha256 {c['fp_sha256']}..." + (", self-signed" if c["self_signed"] else "")
            )
        else:
            L.append(f"  certificate: {c or 'none'}")
        for ck in rep["checks"]:
            if ck["target"] == t["name"]:
                L.append(f"  [{ck['result']}] {ck['id']}: {ck['reason']}")
    if rep["drift"]:
        L.append("")
        L.append("drift since the last run:")
        for d in rep["drift"]:
            L.append(f"  {d['target']} {d['item']}: {d['before']} -> {d['after']}")
    n = rep["counts"]
    L.append("")
    L.append(
        f"RESULT: {rep['verdict']} - {n['PASS']} pass, {n['WARN']} warn, {n['FAIL']} fail, {n['WAIVED']} waived,"
        f" {n['INFO']} info" + (f", {rep['expired_waivers']} expired waiver(s)" if rep["expired_waivers"] else "")
    )
    return "\n".join(L) + "\n"


def crosscheck(a, b):
    """A remote target in one report must see the same certificate and posture as the other host's own local view.
    Returns (ok, lines)."""
    lines, ok, pairs = [], True, 0
    for x, y in ((a, b), (b, a)):
        local = {t["name"]: t for t in y["targets"] if t["scope"] == "local"}
        for t in x["targets"]:
            if t["scope"] != "remote":
                continue
            own = next(iter(local.values()), None) if len(local) == 1 else local.get(t["name"])
            if own is None:
                lines.append(f"FAIL {x['host']}:{t['name']}: no local view in {y['host']}'s report")
                ok = False
                continue
            pairs += 1
            for k in ("protocols", "ciphers", "tls13", "reneg", "cert_key"):
                same = t["posture"].get(k) == own["posture"].get(k)
                ok &= same
                lines.append(
                    f"{'PASS' if same else 'FAIL'} {x['host']}->{t['name']} {k}: remote {t['posture'].get(k)}"
                    f" local {own['posture'].get(k)}"
                )
            fa = t["cert"]["fp_sha256"] if isinstance(t["cert"], dict) else None
            fb = own["cert"]["fp_sha256"] if isinstance(own["cert"], dict) else None
            same = fa is not None and fa == fb
            ok &= same
            lines.append(f"{'PASS' if same else 'FAIL'} {x['host']}->{t['name']} cert sha256: remote {fa} local {fb}")
    if pairs == 0:
        ok = False
        lines.append("FAIL no remote target in either report")
    return ok, lines


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 3
    cmd, args = argv[1], argv[2:]
    if cmd == "checks":
        for k, v in CHECKS.items():
            print(k, v)
        return 0
    if cmd == "matrix":
        for pid, kind, flag, offer in MATRIX:
            print(pid, kind, flag, offer)
        return 0
    if cmd == "render":
        if len(args) != 1:
            return 3
        sys.stdout.write(render(read_json(args[0])))
        return 0
    if cmd == "crosscheck":
        if len(args) != 2:
            return 3
        ok, lines = crosscheck(*(read_json(f) for f in args))
        print("\n".join(lines))
        print(f"RESULT: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 2
    if cmd != "audit" or not args:
        sys.stderr.write(__doc__)
        return 3
    bundle, opts, flags, i = args[0], {}, set(), 1
    while i < len(args):
        a = args[i]
        if a in ("--json", "--public"):
            flags.add(a)
            i += 1
        elif a in ("--policy", "--waivers", "--state", "--write-state", "--host", "--now") and i + 1 < len(args):
            opts[a], i = args[i + 1], i + 2
        else:
            sys.stderr.write(f"peertls_eval: unknown option {a}\n")
            return 3
    if "--policy" not in opts:
        sys.stderr.write("peertls_eval: --policy is required\n")
        return 3
    now = int(opts["--now"]) if "--now" in opts else int(datetime.now(timezone.utc).timestamp())
    try:
        pol = load_policy(opts["--policy"])
        waivers, expired = load_waivers(opts.get("--waivers"), now)
    except PolicyError as e:
        sys.stderr.write(f"peertls_eval: {e}\n")
        return 3
    prev = None
    if opts.get("--state"):
        try:
            prev = read_json(opts["--state"])
        except FileNotFoundError:
            prev = None
        except (OSError, ValueError) as e:
            sys.stderr.write(f"peertls_eval: unreadable state {opts['--state']}: {e}\n")
            return 4
    try:
        text = read_text(bundle, errors="replace")
        rep, state = audit(text, pol, waivers, expired, prev, opts.get("--host", "local"), now)
    except (OSError, BundleError) as e:
        sys.stderr.write(f"peertls_eval: {e}\n")
        return 4
    if opts.get("--write-state"):
        with open(opts["--write-state"], "w", encoding="utf-8") as f:
            json.dump(state, f, sort_keys=True)
            f.write("\n")
    if "--public" in flags:
        rep = public_view(rep)
    if "--json" in flags:
        print(json.dumps(rep, indent=1, sort_keys=True))
    else:
        sys.stdout.write(render(rep))
    return SEV[rep["verdict"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
