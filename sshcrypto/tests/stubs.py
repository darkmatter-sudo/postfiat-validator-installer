#!/usr/bin/env python3
"""Stand-ins for sshd, ssh, ssh-keygen, systemctl and systemd-run used by run-tests.sh. Nothing real is touched.

State lives under $PFT_SC_ROOT (a temp dir):
  etc/ssh/sshd_config.d/*.conf   drop-ins; `sshd -T` = $STUB_BASE (a fixture) overridden by the drop-ins, first
                                 file (lexical order) that sets a key wins, like sshd
  running                        what the "running daemon" serves: written by `systemctl reload ssh`
  armed                          the transient revert timer exists (systemd-run creates it, systemctl stop removes it)
  calls.log                      one line per systemctl / systemd-run call
Knobs: STUB_SSHD_T_FAIL=1, STUB_RELOAD_NOOP=1 (reload does not update running), STUB_SSH_REFUSE=1 (connection
refused), STUB_CLIENT_LACKS=alg1,alg2, STUB_KEYS="RSA:3072,ECDSA:256,ED25519:256" (by key file name),
STUB_KEYGEN_FAIL=1, STUB_CONFIRM_DENY=1, STUB_RELOAD_FAIL=1, STUB_RUN_FAIL=1.
"""

import glob
import os
import sys

ROOT = os.environ.get("PFT_SC_ROOT", "")
LISTS = ("kexalgorithms", "ciphers", "macs", "hostkeyalgorithms")
CLIENT_DEFAULT = {
    "kexalgorithms": "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,"
    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,"
    "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
    "ciphers": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,"
    "aes256-gcm@openssh.com",
    "macs": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
    "hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,"
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    "hostkeyalgorithms": "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,"
    "rsa-sha2-256",
}
CLIENT_Q = {
    "kex": CLIENT_DEFAULT["kexalgorithms"]
    + ",diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,"
    "diffie-hellman-group-exchange-sha1",
    "cipher": CLIENT_DEFAULT["ciphers"] + ",3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc",
    "mac": CLIENT_DEFAULT["macs"] + ",hmac-md5,hmac-md5-96,hmac-sha1-96",
    "HostKeyAlgorithms": "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,"
    "ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
}
OPT2KEY = {
    "kexalgorithms": "kexalgorithms",
    "ciphers": "ciphers",
    "macs": "macs",
    "hostkeyalgorithms": "hostkeyalgorithms",
}
NOMATCH = {
    "kexalgorithms": "key exchange method",
    "ciphers": "cipher",
    "macs": "MAC",
    "hostkeyalgorithms": "host key type",
}


def log(line):
    with open(os.path.join(ROOT, "calls.log"), "a") as f:
        f.write(line + "\n")


def keys():
    spec = os.environ.get("STUB_KEYS", "RSA:3072,ECDSA:256,ED25519:256")
    return {t: int(b) for t, b in (x.split(":") for x in spec.split(",") if x)}


def effective():
    """sshd -T: base fixture overridden by drop-ins (first file setting a key wins)."""
    base = {}
    order = []
    with open(os.environ["STUB_BASE"]) as f:
        for line in f:
            k, _, v = line.strip().partition(" ")
            order.append((k, v))
    over = {}
    for p in sorted(glob.glob(os.path.join(ROOT, "etc/ssh/sshd_config.d/*.conf"))):
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                k, _, v = line.partition(" ")
                over.setdefault(k.lower(), v.strip())
    out, seen = [], set()
    for k, v in order:
        if k in over:
            if k not in seen:
                out.append(f"{k} {over[k]}")
                seen.add(k)
        else:
            out.append(f"{k} {v}")
    for k, v in over.items():
        if k not in seen and k not in base and not any(k == o for o, _ in order):
            out.append(f"{k} {v}")
    return "\n".join(out) + "\n"


def parse(text):
    d = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if k not in d:
            d[k] = v
    return d


def sshd(args):
    if "-T" in args:
        if os.environ.get("STUB_SSHD_T_FAIL"):
            print("sshd: stub failure", file=sys.stderr)
            return 1
        sys.stdout.write(effective())
        return 0
    if "-t" in args:
        for p in sorted(glob.glob(os.path.join(ROOT, "etc/ssh/sshd_config.d/*.conf"))):
            with open(p) as f:
                if any(line.startswith("Bogus") for line in f):
                    print(
                        f"{p}: line 2: Bad configuration option: Bogus", file=sys.stderr
                    )
                    return 255
        return 0
    return 2


def has_key(alg):
    k = keys()
    if alg.startswith("ssh-ed25519") and "-cert-" not in alg:
        return "ED25519" in k
    if alg.startswith(("rsa-sha2-", "ssh-rsa")) and "-cert-" not in alg:
        return "RSA" in k
    if alg.startswith("ecdsa-sha2-nistp") and "-cert-" not in alg:
        return k.get("ECDSA") == int(alg.rsplit("nistp", 1)[1])
    return False


def ssh(args):
    if args[:1] == ["-Q"]:
        lacks = set(filter(None, os.environ.get("STUB_CLIENT_LACKS", "").split(",")))
        print("\n".join(a for a in CLIENT_Q[args[1]].split(",") if a not in lacks))
        return 0
    opts, ident, port, host = {}, None, "22", None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-o":
            k, _, v = args[i + 1].partition("=")
            opts[k.lower()] = v
            i += 2
        elif a in ("-i", "-p", "-l", "-F"):
            if a == "-i":
                ident = args[i + 1]
            if a == "-p":
                port = args[i + 1]
            i += 2
        else:
            host = host or a
            i += 1
    if os.environ.get("STUB_SSH_REFUSE"):
        print(f"ssh: connect to host {host} port {port}: Connection refused")
        return 255
    try:
        with open(os.path.join(ROOT, "running")) as f:
            run = parse(f.read())
    except OSError:
        print(f"ssh: connect to host {host} port {port}: Connection refused")
        return 255
    for key in LISTS:
        client = opts.get(key, CLIENT_DEFAULT[key]).split(",")
        server = run.get(OPT2KEY[key], "").split(",")
        if key == "hostkeyalgorithms":
            server = [s for s in server if has_key(s)]
        if key == "macs":
            cipher = next(
                (
                    c
                    for c in opts.get("ciphers", CLIENT_DEFAULT["ciphers"]).split(",")
                    if c in run.get("ciphers", "").split(",")
                ),
                "",
            )
            if cipher.startswith(("chacha20", "aes128-gcm", "aes256-gcm")):
                continue  # AEAD: no MAC negotiated
        if not any(c in server for c in client):
            print(
                f"Unable to negotiate with {host} port {port}: no matching {NOMATCH[key]} found. "
                f"Their offer: {','.join(server)}"
            )
            return 255
    if ident and not os.environ.get("STUB_CONFIRM_DENY"):
        print("pft-sshcrypto-confirm-ok")
        return 0
    print(f"{opts.get('user', 'x')}@{host}: Permission denied (publickey).")
    return 255


def keygen(args):
    if os.environ.get("STUB_KEYGEN_FAIL"):
        return 1
    path = args[-1]
    k = keys()
    for t in ("ED25519", "ECDSA", "RSA", "DSA"):
        if f"_{t.lower()}_" in os.path.basename(path) and t in k:
            print(f"{k[t]} SHA256:stubfingerprint root@stubhost ({t})")
            return 0
    print(f"{path} is not a key file.", file=sys.stderr)
    return 1


def systemctl(args):
    log("systemctl " + " ".join(args))
    if args[0] == "reload":
        if os.environ.get("STUB_RELOAD_FAIL"):
            return 1
        if not os.environ.get("STUB_RELOAD_NOOP"):
            with open(os.path.join(ROOT, "running"), "w") as f:
                f.write(effective())
        return 0
    if args[0] == "is-active":
        return 0 if os.path.exists(os.path.join(ROOT, "armed")) else 3
    if args[0] == "stop":
        if os.path.exists(os.path.join(ROOT, "armed")):
            os.remove(os.path.join(ROOT, "armed"))
        return 0
    return 0


def systemd_run(args):
    log("systemd-run " + " ".join(args))
    if os.environ.get("STUB_RUN_FAIL"):
        return 1
    with open(os.path.join(ROOT, "armed"), "w") as f:
        first = next(i for i, a in enumerate(args) if not a.startswith("-"))
        f.write(" ".join(args[first:]) + "\n")
    return 0


if __name__ == "__main__":
    name = sys.argv[1]
    fn = {
        "sshd": sshd,
        "ssh": ssh,
        "ssh-keygen": keygen,
        "systemctl": systemctl,
        "systemd-run": systemd_run,
    }[name]
    sys.exit(fn(sys.argv[2:]))
