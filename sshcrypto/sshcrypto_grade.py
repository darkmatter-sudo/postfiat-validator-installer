#!/usr/bin/env python3
"""Grade an sshd effective configuration (`sshd -T`) against the pft-sshcrypto policy.

Called by pft-sshcrypto.sh; reads only files, runs nothing.
  sshcrypto_grade.py plan  --sshd-t FILE --hostkeys TSV  probe plan: KIND<TAB>ALGORITHM<TAB>offered|absent
  sshcrypto_grade.py grade --sshd-t FILE --hostkeys TSV [--probes TSV] [--moduli FILE] [--host L] [--now EPOCH]
                           [--json] [--metrics FILE] [--extra-errors TSV]
  sshcrypto_grade.py table                                policy table (markdown, used in README.md)
hostkeys TSV: TYPE<TAB>BITS (one line per HostKey, from ssh-keygen -l; no paths, no fingerprints)
probes TSV:   KIND<TAB>ALGORITHM<TAB>EXPECTED<TAB>RESULT  (RESULT negotiated|rejected|skipped|error[:reason])
Exit: 0 every graded item OK; 1 at least one WARN or FAIL (incl. probe mismatch); 2 audit error.
"""

import argparse
import json
import sys

OK, WARN, FAIL = "OK", "WARN", "FAIL"

# (kind, sshd -T key, ssh client option) -- the order is the report order
KINDS = [
    ("kex", "kexalgorithms", "KexAlgorithms"),
    ("cipher", "ciphers", "Ciphers"),
    ("mac", "macs", "MACs"),
    ("hostkey", "hostkeyalgorithms", "HostKeyAlgorithms"),
    ("pubkey", "pubkeyacceptedalgorithms", None),
    ("casig", "casignaturealgorithms", None),
]
PROBED = ("kex", "cipher", "mac", "hostkey")

# Policy: (kind, algorithm or prefix*, grade, reason). First match wins; unknown algorithms are WARN.
POLICY = [
    ("kex", "sntrup761x25519-sha512@openssh.com", OK, "hybrid post-quantum + X25519"),
    ("kex", "curve25519-sha256", OK, "X25519"),
    ("kex", "curve25519-sha256@libssh.org", OK, "X25519 (pre-RFC name)"),
    ("kex", "diffie-hellman-group16-sha512", OK, "4096-bit fixed group"),
    ("kex", "diffie-hellman-group18-sha512", OK, "8192-bit fixed group"),
    (
        "kex",
        "diffie-hellman-group-exchange-sha256",
        OK,
        "OK only if every /etc/ssh/moduli entry is >= 3072 bits",
    ),
    ("kex", "diffie-hellman-group14-sha256", WARN, "2048-bit group"),
    ("kex", "ecdh-sha2-nistp*", WARN, "NIST P-curves"),
    ("kex", "*sha1*", FAIL, "SHA-1 exchange hash"),
    ("cipher", "chacha20-poly1305@openssh.com", OK, "AEAD"),
    ("cipher", "aes256-gcm@openssh.com", OK, "AEAD"),
    ("cipher", "aes128-gcm@openssh.com", OK, "AEAD"),
    ("cipher", "aes256-ctr", OK, "CTR (MAC must be EtM)"),
    ("cipher", "aes192-ctr", OK, "CTR (MAC must be EtM)"),
    ("cipher", "aes128-ctr", OK, "CTR (MAC must be EtM)"),
    ("cipher", "*-cbc*", FAIL, "CBC mode"),
    ("cipher", "arcfour*", FAIL, "RC4"),
    ("cipher", "blowfish*", FAIL, "64-bit block"),
    ("cipher", "cast128*", FAIL, "64-bit block"),
    ("mac", "hmac-sha2-512-etm@openssh.com", OK, "encrypt-then-MAC"),
    ("mac", "hmac-sha2-256-etm@openssh.com", OK, "encrypt-then-MAC"),
    ("mac", "umac-128-etm@openssh.com", OK, "encrypt-then-MAC"),
    ("mac", "umac-64-etm@openssh.com", WARN, "64-bit tag"),
    ("mac", "hmac-sha2-512", WARN, "encrypt-and-MAC"),
    ("mac", "hmac-sha2-256", WARN, "encrypt-and-MAC"),
    ("mac", "umac-128@openssh.com", WARN, "encrypt-and-MAC"),
    ("mac", "umac-64@openssh.com", FAIL, "64-bit tag, encrypt-and-MAC"),
    ("mac", "*sha1*", FAIL, "SHA-1"),
    ("mac", "*md5*", FAIL, "MD5"),
    ("mac", "*ripemd*", FAIL, "RIPEMD-160"),
    ("hostkey", "ssh-ed25519", OK, "Ed25519"),
    ("hostkey", "ssh-ed25519-cert-v01@openssh.com", OK, "Ed25519 certificate"),
    ("hostkey", "sk-ssh-ed25519*", OK, "Ed25519 (FIDO)"),
    ("hostkey", "rsa-sha2-512*", OK, "RSA/SHA-512 (key size graded separately)"),
    ("hostkey", "rsa-sha2-256*", OK, "RSA/SHA-256 (key size graded separately)"),
    ("hostkey", "ecdsa-sha2-nistp*", WARN, "NIST P-curves"),
    ("hostkey", "sk-ecdsa-sha2-nistp*", WARN, "NIST P-curves (FIDO)"),
    ("hostkey", "ssh-rsa*", FAIL, "RSA/SHA-1 signature"),
    ("hostkey", "ssh-dss*", FAIL, "DSA"),
    # User keys / CA signatures: only SHA-1 and DSA are graded. Narrowing these lists can lock out existing user
    # keys (e.g. an operator's ECDSA key), so the policy never changes them.
    ("pubkey", "ssh-rsa*", FAIL, "RSA/SHA-1 signature"),
    ("pubkey", "ssh-dss*", FAIL, "DSA"),
    ("pubkey", "*", OK, "user-key algorithms: only SHA-1/DSA graded"),
    ("casig", "ssh-rsa*", FAIL, "RSA/SHA-1 signature"),
    ("casig", "ssh-dss*", FAIL, "DSA"),
    ("casig", "*", OK, "CA signature algorithms: only SHA-1/DSA graded"),
]

# Host key files: graded only when the server offers an algorithm of that key type.
HOSTKEY_FAMILY = {
    "RSA": ("rsa-sha2-", "ssh-rsa"),
    "ECDSA": ("ecdsa-sha2-",),
    "ED25519": ("ssh-ed25519",),
    "DSA": ("ssh-dss",),
    "ECDSA-SK": ("sk-ecdsa-",),
    "ED25519-SK": ("sk-ssh-ed25519",),
}


def match(pattern, name):
    if pattern == "*":
        return True
    if pattern.startswith("*") and pattern.endswith("*"):
        return pattern[1:-1] in name
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def grade_alg(kind, name, moduli_min):
    for k, pat, g, why in POLICY:
        if k == kind and match(pat, name):
            if name == "diffie-hellman-group-exchange-sha256":
                if moduli_min is None:
                    return WARN, "moduli file unreadable"
                if moduli_min < 3071:
                    return WARN, f"group exchange can use {moduli_min + 1}-bit moduli"
                return OK, f"group exchange, smallest modulus {moduli_min + 1} bits"
            return g, why
    return WARN, "not in policy"


def grade_hostkey(ktype, bits):
    if ktype == "RSA":
        if bits < 2048:
            return FAIL, "RSA < 2048 bits"
        if bits < 3072:
            return WARN, "RSA < 3072 bits"
        return OK, "RSA >= 3072 bits"
    if ktype in ("ED25519", "ED25519-SK"):
        return OK, "Ed25519"
    if ktype in ("ECDSA", "ECDSA-SK"):
        return WARN, "NIST P-curve"
    if ktype == "DSA":
        return FAIL, "DSA"
    return WARN, "unknown key type"


def parse_sshd_t(path):
    conf, hostkeys = {}, 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts[0].lower(), parts[1]
            if key == "hostkey":
                hostkeys += 1
            elif key == "listenaddress":
                conf.setdefault("listenaddress", []).append(val)
            elif key not in conf:
                conf[key] = val
    missing = [k for _, k, _ in KINDS if k not in conf]
    return conf, hostkeys, missing


def read_moduli(path):
    if not path:
        return None
    try:
        sizes = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                p = line.split()
                if len(p) >= 7 and not p[0].startswith("#"):
                    sizes.append(int(p[4]))
        return min(sizes) if sizes else None
    except (OSError, ValueError):
        return None


def read_tsv(path, ncols):
    rows = []
    if not path:
        return rows
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line:
                p = line.split("\t")
                if len(p) != ncols:
                    raise ValueError(f"{path}: expected {ncols} columns: {line!r}")
                rows.append(p)
    return rows


def has_key(alg, keys):
    """True if a host key exists that sshd can use for host key algorithm ALG (no certificates, no FIDO keys)."""
    types = {(t, int(b)) for t, b in keys if b.isdigit()}
    if "-cert-" in alg or alg.startswith("sk-"):
        return False
    if alg.startswith("ssh-ed25519"):
        return any(t == "ED25519" for t, _ in types)
    if alg.startswith(("rsa-sha2-", "ssh-rsa")):
        return any(t == "RSA" for t, _ in types)
    if alg.startswith("ecdsa-sha2-nistp"):
        return ("ECDSA", int(alg[len("ecdsa-sha2-nistp") :])) in types
    return False


def plan(conf, keys):
    """Probe plan. A host key algorithm is expected on the wire only if sshd also has a key for it."""
    out = []
    for kind, key, _ in KINDS:
        if kind not in PROBED:
            continue
        offered = conf[key].split(",")
        if kind == "hostkey":
            offered = [a for a in offered if has_key(a, keys)]
        # positive control: the first offered OK algorithm; then every known non-OK algorithm, offered or not
        ok = [
            a
            for a in offered
            if grade_alg(kind, a, 4095)[0] == OK
            and "-cert-" not in a
            and not a.startswith("sk-")
        ]
        if ok:
            out.append((kind, ok[0], "offered"))
        for name in WEAK_PROBES[kind]:
            out.append((kind, name, "offered" if name in offered else "absent"))
    return out


WEAK_PROBES = {
    "kex": [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
    ],
    "cipher": ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"],
    "mac": [
        "hmac-sha1",
        "hmac-sha1-etm@openssh.com",
        "hmac-md5",
        "umac-64@openssh.com",
        "umac-64-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "umac-128@openssh.com",
    ],
    "hostkey": [
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ],
}


def grade(a):
    errors = []
    try:
        conf, n_hostkey_lines, missing = parse_sshd_t(a.sshd_t)
    except OSError as e:
        conf, n_hostkey_lines, missing = {}, 0, [k for _, k, _ in KINDS]
        errors.append(f"sshd -T output unreadable: {e.strerror}")
    if missing and not errors:
        errors.append("sshd -T output lacks: " + ", ".join(missing))
    moduli_min = read_moduli(a.moduli)
    algs = []
    if not errors:
        for kind, key, _ in KINDS:
            for name in conf[key].split(","):
                g, why = grade_alg(kind, name, moduli_min)
                algs.append({"kind": kind, "name": name, "grade": g, "reason": why})
    keys = []
    try:
        hk = read_tsv(a.hostkeys, 2)
    except (OSError, ValueError) as e:
        hk = []
        errors.append(f"host key list unreadable: {e}")
    if not errors and len(hk) != n_hostkey_lines:
        errors.append(f"{n_hostkey_lines} HostKey lines but {len(hk)} keys read")
    offered_hk = conf.get("hostkeyalgorithms", "").split(",")
    for ktype, bits in hk:
        if not bits.isdigit():
            errors.append(f"bad key size for {ktype}")
            continue
        fam = HOSTKEY_FAMILY.get(ktype, ())
        offered = any(x.startswith(fam) for x in offered_hk) if fam else True
        g, why = (
            grade_hostkey(ktype, int(bits))
            if offered
            else ("UNUSED", "no offered algorithm uses this key")
        )
        keys.append(
            {
                "type": ktype,
                "bits": int(bits),
                "offered": offered,
                "grade": g,
                "reason": why,
            }
        )
    if not errors and not any(k["offered"] for k in keys):
        errors.append("no offered host key")
    probes = []
    try:
        pr = read_tsv(a.probes, 4)
    except (OSError, ValueError) as e:
        pr = []
        errors.append(f"probe results unreadable: {e}")
    for kind, name, expected, result in pr:
        if result.startswith("error"):
            errors.append(f"probe {kind} {name} could not run: {result[6:] or '?'}")
            result = "error"
        ok = result == "skipped" or (expected == "offered") == (result == "negotiated")
        probes.append(
            {
                "kind": kind,
                "name": name,
                "expected": expected,
                "result": result,
                "match": ok,
            }
        )
    for kind, why in read_tsv(a.extra_errors, 2) if a.extra_errors else []:
        errors.append(f"{kind}: {why}")
    graded = [x["grade"] for x in algs] + [k["grade"] for k in keys if k["offered"]]
    counts = {g: graded.count(g) for g in (OK, WARN, FAIL)}
    mism = sum(1 for p in probes if not p["match"])
    if errors:
        rc, result = 2, "ERROR"
    elif counts[FAIL] or mism:
        rc, result = 1, "FAIL"
    elif counts[WARN]:
        rc, result = 1, "WARN"
    else:
        rc, result = 0, "OK"
    rep = {
        "host": a.host,
        "generated_at": a.now,
        "result": result,
        "exit": rc,
        "counts": counts,
        "probe_mismatches": mism,
        "probes_run": sum(1 for p in probes if p["result"] != "skipped"),
        "algorithms": algs,
        "hostkeys": keys,
        "probes": probes,
        "errors": errors,
    }
    if a.metrics:
        write_metrics(a.metrics, rep)
    if a.json:
        print(json.dumps(rep, indent=1, sort_keys=True))
    else:
        print_text(rep)
    return rc


def print_text(r):
    for x in r["algorithms"]:
        print(f"  {x['kind']:<8} {x['grade']:<5} {x['name']:<42} {x['reason']}")
    for k in r["hostkeys"]:
        print(
            f"  {'hostkey-file':<8} {k['grade']:<5} {k['type'] + ' ' + str(k['bits']):<42} {k['reason']}"
        )
    for p in r["probes"]:
        verdict = "match" if p["match"] else "MISMATCH"
        print(
            f"  {'probe':<8} {p['kind']:<7} {p['name']:<42} expected {p['expected']}, {p['result']}: {verdict}"
        )
    for e in r["errors"]:
        print(f"  ERROR    {e}")
    c = r["counts"]
    print(
        f"RESULT: {r['result']} - {c[OK]} ok, {c[WARN]} warn, {c[FAIL]} fail, {r['probes_run']} probes, "
        f"{r['probe_mismatches']} probe mismatches, {len(r['errors'])} errors -> exit {r['exit']}"
    )


def write_metrics(path, r):
    h = r["host"]
    up = 0 if r["errors"] else 1
    out = [
        "# HELP pft_sshcrypto_up 1 if the last pft-sshcrypto audit completed (sshd -T, host keys, probes).",
        "# TYPE pft_sshcrypto_up gauge",
        f'pft_sshcrypto_up{{host="{h}"}} {up}',
        "# HELP pft_sshcrypto_last_run_timestamp_seconds Unix time of the last audit run.",
        "# TYPE pft_sshcrypto_last_run_timestamp_seconds gauge",
        f'pft_sshcrypto_last_run_timestamp_seconds{{host="{h}"}} {r["generated_at"]}',
    ]
    if up:
        out += [
            "# HELP pft_sshcrypto_findings Offered algorithms / host keys per kind and grade (WARN/FAIL).",
            "# TYPE pft_sshcrypto_findings gauge",
        ]
        kinds = [k for k, _, _ in KINDS] + ["hostkey-file"]
        for kind in kinds:
            for g in (WARN, FAIL):
                if kind == "hostkey-file":
                    n = sum(
                        1 for k in r["hostkeys"] if k["offered"] and k["grade"] == g
                    )
                else:
                    n = sum(
                        1
                        for x in r["algorithms"]
                        if x["kind"] == kind and x["grade"] == g
                    )
                out.append(
                    f'pft_sshcrypto_findings{{host="{h}",kind="{kind}",grade="{g.lower()}"}} {n}'
                )
        out += [
            "# HELP pft_sshcrypto_probe_mismatches Loopback handshakes whose outcome contradicts sshd -T.",
            "# TYPE pft_sshcrypto_probe_mismatches gauge",
            f'pft_sshcrypto_probe_mismatches{{host="{h}"}} {r["probe_mismatches"]}',
            "# HELP pft_sshcrypto_probes Loopback handshake probes run in the last audit.",
            "# TYPE pft_sshcrypto_probes gauge",
            f'pft_sshcrypto_probes{{host="{h}"}} {r["probes_run"]}',
            "# HELP pft_sshcrypto_hostkey_bits Size of each offered host key.",
            "# TYPE pft_sshcrypto_hostkey_bits gauge",
        ]
        for k in r["hostkeys"]:
            if k["offered"]:
                out.append(
                    f'pft_sshcrypto_hostkey_bits{{host="{h}",type="{k["type"].lower()}"}} {k["bits"]}'
                )
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def table():
    print("| Kind | Algorithm (`*` = prefix/substring) | Grade | Why |")
    print("|---|---|---|---|")
    for k, pat, g, why in POLICY:
        print(f"| {k} | `{pat}` | {g} | {why} |")
    print("| any | anything else | WARN | not in policy |")
    print(
        "| hostkey-file | RSA >= 3072 / 2048-3071 / < 2048 bits | OK / WARN / FAIL | key size |"
    )
    print(
        "| hostkey-file | ED25519 / ECDSA / DSA | OK / WARN / FAIL | key type (graded only if offered) |"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["plan", "grade", "table"])
    ap.add_argument("--sshd-t")
    ap.add_argument("--hostkeys")
    ap.add_argument("--probes")
    ap.add_argument("--moduli")
    ap.add_argument("--extra-errors")
    ap.add_argument("--host", default="validator")
    ap.add_argument("--now", type=int, default=0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--metrics")
    a = ap.parse_args()
    if a.cmd == "table":
        table()
        return 0
    if a.cmd == "plan":
        conf, _, missing = parse_sshd_t(a.sshd_t)
        if missing:
            print("sshd -T output lacks: " + ", ".join(missing), file=sys.stderr)
            return 2
        try:
            keys = read_tsv(a.hostkeys, 2)
        except (OSError, ValueError) as e:
            print(f"host key list unreadable: {e}", file=sys.stderr)
            return 2
        for row in plan(conf, keys):
            print("\t".join(row))
        return 0
    return grade(a)


if __name__ == "__main__":
    sys.exit(main())
