#!/usr/bin/env python3
"""pft-valwatch helper: validations/ledger stream collector, deterministic reports, textfile, cross-host compare.

Stdlib only. Read-only: the only commands sent to the node are `subscribe` (streams validations + ledger) and
`server_info` (validation_quorum, server_state). It connects to the node's PUBLIC WebSocket port (wss, self-signed
certificate) on a loopback or private (docker bridge) address only; any other address is refused (exit 3).

  collect  --host H --port P --out DIR --unl-cache FILE [--retain-hours N] [--max-dir-bytes N] [--duration S]
  report   --dir DIR [--from EPOCH] [--to EPOCH] [--json] [thresholds]          deterministic, offline
  textfile --dir DIR --name NAME [--now EPOCH] [--window S] [thresholds]        Prometheus textfile on stdout
  compare  A.json B.json [--tolerance-part F] [--tolerance-delay-ms N] [--tolerance-margin N] [--json]

Records (one compact JSON object per line, hourly files DIR/valwatch-YYYYMMDDTHH.jsonl, UTC):
  {"t":"C","ev":"connect"|"disconnect","why":..,"r":ms}           connection events (reconnect backoff 1..60 s)
  {"t":"U","seq":N,"exp":ripple_s,"pub":hex16,"keys":[...],"r":ms} UNL from the node's own publisher-list cache
  {"t":"Q","q":N,"s":state,"r":ms}                                 server_info sample (every QUORUM_EVERY ledgers)
  {"t":"L","i":N,"h":hash,"lt":ripple_s,"r":ms}                    ledgerClosed (validated ledger)
  {"t":"V","i":N,"h":hash,"k":master_key,"f":bool,"r":ms}           validationReceived
`r` is the receive time on this host (epoch ms). Validation delay = r(V) minus the earliest r of any UNL
validation for the same ledger hash on the same host, so it does not depend on clock offsets between hosts.
"""

import argparse
import base64
import calendar
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time

STREAMS = ["validations", "ledger"]
QUORUM_EVERY = 20  # ledgers between server_info samples (~1 min)
UNL_EVERY_S = 3600
RIPPLE_EPOCH = 946684800
MAX_VALIDATORS = 64  # textfile label cap
MAX_LINE = 65536  # bytes (a U record is ~56 B per UNL key); longer records are counted and skipped
EDGE_MS = 5000  # ledgers closer than this to either end of the window are not graded (validations straddle it)
EXIT_USAGE = 3


def now_ms():
    return int(time.time() * 1000)


def die(msg, code=EXIT_USAGE):
    sys.stderr.write(f"valwatch: {msg}\n")
    sys.exit(code)


def allowed_host(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or (ip.is_private and not ip.is_link_local)


# ---------------------------------------------------------------- WebSocket (RFC 6455 client, TLS)
class WS:
    def __init__(self, host, port, timeout=60, tls=True):
        raw = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # the node's port uses a self-signed certificate; loopback/bridge only
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw)
        self.s = raw
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(
            (
                f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise ConnectionError("closed during handshake")
            buf += chunk
            if len(buf) > 16384:
                raise ConnectionError("handshake too long")
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        status = head.split(b"\r\n")[0]
        if b" 101 " not in status:
            raise ConnectionError("handshake: " + status.decode(errors="replace")[:80])

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send_frame(self, opcode, data):
        mask = os.urandom(4)
        n = len(data)
        if n < 126:
            hdr = struct.pack(">BB", 0x80 | opcode, 0x80 | n)
        elif n < 65536:
            hdr = struct.pack(">BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            hdr = struct.pack(">BBQ", 0x80 | opcode, 0x80 | 127, n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.s.sendall(hdr + mask + masked)

    def send_json(self, obj):
        self._send_frame(0x1, json.dumps(obj).encode())

    def recv_text(self, max_bytes=1 << 22):
        parts, size = [], 0
        while True:
            b0, b1 = self._read(2)
            fin, opcode = b0 & 0x80, b0 & 0x0F
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            size += n
            if size > max_bytes:
                raise ConnectionError("message too large")
            mask = self._read(4) if b1 & 0x80 else None
            payload = self._read(n)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0x8:
                raise ConnectionError("server sent close")
            if opcode in (0x0, 0x1):
                parts.append(payload)
                if fin:
                    return b"".join(parts).decode()


B58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def node_public_b58(hex_key):
    """33-byte public key (hex) -> base58check node public key (type prefix 0x1C, 'n...')."""
    raw = bytes.fromhex(hex_key)
    if len(raw) != 33:
        raise ValueError("public key is not 33 bytes")
    body = b"\x1c" + raw
    data = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return B58[0] * (len(data) - len(data.lstrip(b"\x00"))) + out


# ---------------------------------------------------------------- UNL from the node's publisher-list cache
def read_unl(path):
    """Return a U record (without r) from a postfiatd/rippled `cache.<publisher>` file, or raise ValueError."""
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    blobs = d.get("blobs_v2") or ([{"blob": d["blob"]}] if "blob" in d else [])
    best = None
    for b in blobs:
        j = json.loads(base64.b64decode(b["blob"]))
        if best is None or int(j["sequence"]) > int(best["sequence"]):
            best = j
    if best is None:
        raise ValueError("no blob in cache file")
    keys = sorted(node_public_b58(str(v["validation_public_key"])) for v in best["validators"])
    if not keys or not all(k.startswith("nH") for k in keys):
        raise ValueError("unexpected validator key format")
    return {
        "t": "U",
        "seq": int(best["sequence"]),
        "exp": int(best["expiration"]),
        "pub": str(d.get("public_key", ""))[:16],
        "keys": keys,
    }


# ---------------------------------------------------------------- collector
class Sink:
    """Hourly JSONL files with bounded retention (age and total bytes)."""

    def __init__(self, out, retain_hours, max_dir_bytes):
        self.out, self.retain_s, self.max_bytes = out, retain_hours * 3600, max_dir_bytes
        self.cur_name, self.fh = None, None
        os.makedirs(out, mode=0o750, exist_ok=True)

    def write(self, rec):
        name = time.strftime("valwatch-%Y%m%dT%H.jsonl", time.gmtime(rec["r"] / 1000))
        if name != self.cur_name:
            if self.fh:
                self.fh.close()
            self.fh = open(os.path.join(self.out, name), "a", encoding="utf-8")  # noqa: SIM115 (long-lived handle)
            self.cur_name = name
            self.prune(rec["r"] / 1000)
        self.fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
        self.fh.flush()

    def prune(self, now_s):
        files = sorted(f for f in os.listdir(self.out) if file_hour(f) is not None)
        keep = []
        for f in files:
            p = os.path.join(self.out, f)
            hour = file_hour(f)
            if f != self.cur_name and now_s - (hour + 3600) > self.retain_s:
                os.unlink(p)
            else:
                keep.append(f)
        total = sum(os.path.getsize(os.path.join(self.out, f)) for f in keep)
        for f in keep:
            if total <= self.max_bytes or f == self.cur_name:
                break
            total -= os.path.getsize(os.path.join(self.out, f))
            os.unlink(os.path.join(self.out, f))


def compact(msg, r):
    t = msg.get("type")
    if t == "ledgerClosed":
        return {
            "t": "L",
            "i": int(msg["ledger_index"]),
            "h": str(msg["ledger_hash"]),
            "lt": int(msg.get("ledger_time", 0)),
            "r": r,
        }
    if t == "validationReceived":
        return {
            "t": "V",
            "i": int(msg["ledger_index"]),
            "h": str(msg["ledger_hash"]),
            "k": str(msg.get("master_key") or msg["validation_public_key"]),
            "f": bool(msg.get("full")),
            "r": r,
        }
    return None


def session(ws, sink, unl_cache, deadline, state):
    ws.send_json({"id": "si", "command": "server_info"})
    ws.send_json({"id": "sub", "command": "subscribe", "streams": STREAMS})
    ledgers = 0
    while deadline is None or time.time() < deadline:
        if deadline is not None:  # never block past the end of a bounded capture
            ws.s.settimeout(max(0.2, min(60.0, deadline - time.time())))
        msg = json.loads(ws.recv_text())
        r = now_ms()
        if msg.get("id") == "si":
            info = msg.get("result", {}).get("info", {})
            sink.write(
                {"t": "Q", "q": int(info.get("validation_quorum", 0)), "s": str(info.get("server_state")), "r": r}
            )
            continue
        if msg.get("id") == "sub":
            if msg.get("status") != "success":
                raise ConnectionError("subscribe refused")
            continue
        rec = compact(msg, r)
        if rec is None:
            continue
        sink.write(rec)
        if rec["t"] == "L":
            ledgers += 1
            state["healthy_since"] = state.get("healthy_since") or time.time()
            if ledgers % QUORUM_EVERY == 0:
                ws.send_json({"id": "si", "command": "server_info"})
            if time.time() - state.get("unl_at", 0) >= UNL_EVERY_S:
                write_unl(sink, unl_cache, state)


def write_unl(sink, unl_cache, state):
    state["unl_at"] = time.time()
    try:
        rec = read_unl(unl_cache)
    except (OSError, ValueError, KeyError) as e:
        sink.write({"t": "C", "ev": "unl_error", "why": str(e)[:120], "r": now_ms()})
        return
    rec["r"] = now_ms()
    sink.write(rec)


def cmd_collect(a):
    if not allowed_host(a.host):
        die(f"refusing non-loopback/non-private host {a.host!r}")
    sink = Sink(a.out, a.retain_hours, a.max_dir_bytes)
    deadline = time.time() + a.duration if a.duration else None
    backoff, state = 1, {}
    write_unl(sink, a.unl_cache, state)
    while deadline is None or time.time() < deadline:
        ws = None
        try:
            left = deadline - time.time() if deadline else 60.0
            ws = WS(a.host, a.port, timeout=max(1.0, min(60.0, left)), tls=not a.plain)  # bounded runs end on time
            sink.write({"t": "C", "ev": "connect", "why": "", "r": now_ms()})
            state["healthy_since"] = None
            session(ws, sink, a.unl_cache, deadline, state)
        except (ConnectionError, OSError, ValueError, KeyError) as e:
            sink.write({"t": "C", "ev": "disconnect", "why": f"{type(e).__name__}: {e}"[:160], "r": now_ms()})
            if state.get("healthy_since") and time.time() - state["healthy_since"] > 300:
                backoff = 1
            time.sleep(min(backoff, max(0.0, deadline - time.time())) if deadline else backoff)
            backoff = min(backoff * 2, 60)
        finally:
            if ws:
                ws.close()
    return 0


# ---------------------------------------------------------------- analysis
def file_hour(name):
    """Epoch of the UTC hour a valwatch-YYYYMMDDTHH.jsonl file covers, or None for other names."""
    if not (name.startswith("valwatch-") and name.endswith(".jsonl")):
        return None
    try:
        return calendar.timegm(time.strptime(name[9:20], "%Y%m%dT%H"))
    except ValueError:
        return None


CARRY_HOURS = 2  # U is rewritten every UNL_EVERY_S (and at every collector start), Q every QUORUM_EVERY ledgers


def iter_load(directory, t_from=None, t_to=None, st=None):
    """Yield records with t_from <= r < t_to in (r, t, i, k) order, one hour file at a time, and fill `st` with
    "bad" (unparsable lines) and "carry" (the newest U and Q record from before t_from, carried in so a window
    shorter than the hourly UNL record still knows the UNL and quorum).
    Hour files partition `r` (the collector names each file after its records' receive hour), so sorting each
    file on its own gives the same order as sorting everything, and only one file's records are held at a time.
    Only hour files overlapping [t_from - CARRY_HOURS h, t_to) are opened, and validations from keys that are in
    no UNL seen so far are dropped while reading (they cannot be graded; about 60 % of all validation records on
    the testnet). `carry` is final once the first record is yielded: carry records have r < t_from, so they all
    sit in files before, or in the same file as, the first record of the window."""
    st = {} if st is None else st
    st.setdefault("bad", 0)
    carry = st.setdefault("carry", {})
    unl_union = set()
    for f in sorted(os.listdir(directory)):
        hour = file_hour(f)
        if hour is None:
            continue
        if t_from is not None and hour + 3600 <= t_from - CARRY_HOURS * 3600:
            continue
        if t_to is not None and hour >= t_to:
            continue
        recs = []
        with open(os.path.join(directory, f), encoding="utf-8") as fh:
            for line in fh:
                if len(line) > MAX_LINE:
                    st["bad"] += 1
                    continue
                try:
                    rec = json.loads(line)
                    r = int(rec["r"])
                    t = rec.get("t")
                    if t == "U":
                        unl_union.update(rec["keys"])
                except (ValueError, KeyError, TypeError):
                    st["bad"] += 1  # e.g. a torn last line after a crash
                    continue
                if t == "V" and rec.get("k") not in unl_union:
                    continue
                if t_from is not None and r < t_from * 1000:
                    if t in ("U", "Q") and r >= carry.get(t, {}).get("r", -1):
                        carry[t] = rec
                elif t_to is None or r < t_to * 1000:
                    if t == "V":
                        rec["h"], rec["k"] = sys.intern(rec["h"]), sys.intern(rec["k"])
                    recs.append(rec)
        recs.sort(key=rec_order)
        yield from recs


def rec_order(x):
    return (x["r"], x.get("t", ""), x.get("i", 0), x.get("k", ""))


def load(directory, t_from=None, t_to=None):
    """iter_load as lists: (carried U/Q records, records, bad line count). Used by tests and small windows."""
    st = {}
    recs = list(iter_load(directory, t_from, t_to, st))
    return [st["carry"][t] for t in ("U", "Q") if t in st["carry"]], recs, st["bad"]


def carried_of(st):
    return lambda: [st["carry"][t] for t in ("U", "Q") if t in st["carry"]]


def pct(values, p):
    """Nearest-rank percentile of a list of ints (None if empty)."""
    if not values:
        return None
    s = sorted(values)
    k = max(1, -(-p * len(s) // 100))
    return s[int(k) - 1]


def analyze(recs, bad=0, warn_delay_ms=3000, min_participation=0.9, min_margin=2, detail=False, carried=()):
    """Grade records in (r, t, i, k) order. `recs` may be any iterable (one pass, nothing but per-ledger state is
    kept); `carried` is a list of U/Q records or a callable returning it, called before the first record (or at
    the end if there is none), and `bad` a count or a callable returning it after the pass."""
    unl, quorum = None, None
    cand = []  # (index, hash, r, quorum, UNL keys) of every L record that had a UNL and a quorum before it
    vals = {}  # (index, hash) -> {key: r}
    reconnects, n, first_ms, last_ms, pre = 0, 0, None, None, None
    keysets = {}  # one frozenset per distinct UNL, shared by all its ledgers

    def take(rec):
        nonlocal unl, quorum, reconnects
        t = rec.get("t")
        if t == "U":
            unl = rec
        elif t == "Q":
            quorum = int(rec["q"]) or quorum
        elif t == "C":
            if rec.get("ev") == "disconnect":
                reconnects += 1
        elif t == "L":
            if unl is not None and quorum is not None:
                ks = tuple(unl["keys"])
                cand.append((int(rec["i"]), rec["h"], rec["r"], quorum, keysets.setdefault(ks, frozenset(ks))))
        elif t == "V" and rec.get("f"):
            vals.setdefault((int(rec["i"]), rec["h"]), {}).setdefault(rec["k"], rec["r"])

    for rec in recs:
        if pre is None:
            pre = carried() if callable(carried) else carried
            for c in pre:
                take(c)
        n += 1
        first_ms = rec["r"] if first_ms is None else first_ms
        last_ms = rec["r"]
        take(rec)
    if pre is None:
        for c in carried() if callable(carried) else carried:
            take(c)
    bad = bad() if callable(bad) else bad
    lo = first_ms + EDGE_MS if n else 0
    hi = last_ms - EDGE_MS if n else 0
    ledgers = {}  # index -> {"h":hash, "r":ms, "q":quorum, "keys":set(UNL)}
    for idx, h, r, q, keys in cand:
        if lo <= r <= hi:
            ledgers.setdefault(idx, {"h": h, "r": r, "q": q, "keys": keys})
    cand.clear()
    all_keys = sorted(set().union(*(lg["keys"] for lg in ledgers.values()))) if ledgers else []
    per = {k: {"expected": 0, "agreed": 0, "delays": []} for k in all_keys}
    margins, per_ledger = {}, {}
    for idx in sorted(ledgers):
        lg = ledgers[idx]
        got = vals.get((idx, lg["h"]), {})
        trusted = {k: r for k, r in got.items() if k in lg["keys"]}
        first = min(trusted.values()) if trusted else None
        margins[idx] = len(trusted) - lg["q"]
        if detail:
            per_ledger[str(idx)] = {
                "h": lg["h"],
                "q": lg["q"],
                "m": margins[idx],
                "d": {k: trusted[k] - first for k in sorted(trusted)},
                "miss": sorted(lg["keys"] - set(trusted)),
            }
        for k in lg["keys"]:
            p = per[k]
            p["expected"] += 1
            if k in trusted:
                p["agreed"] += 1
                p["delays"].append(trusted[k] - first)
    validators = {}
    for k in all_keys:
        p = per[k]
        part = round(p["agreed"] / p["expected"], 4) if p["expected"] else None
        p50, p95 = pct(p["delays"], 50), pct(p["delays"], 95)
        flags = []
        if part is not None and part < min_participation:
            flags.append("low_participation")
        if p95 is not None and p95 > warn_delay_ms:
            flags.append("late")
        if p["expected"] and not p["agreed"]:
            flags.append("silent")
        validators[k] = {
            "expected": p["expected"],
            "agreed": p["agreed"],
            "participation": part,
            "delay_ms_p50": p50,
            "delay_ms_p95": p95,
            "flags": flags,
        }
    m = list(margins.values())
    below = sorted(i for i, v in margins.items() if v < min_margin)
    return {
        "records": n,
        "bad_lines": bad,
        "first_ms": first_ms,
        "last_ms": last_ms,
        "ledgers": len(ledgers),
        "first_ledger": min(ledgers) if ledgers else None,
        "last_ledger": max(ledgers) if ledgers else None,
        "missing_ledgers": (max(ledgers) - min(ledgers) + 1 - len(ledgers)) if ledgers else 0,
        "reconnects": reconnects,
        "unl": {"seq": unl["seq"], "expiration_ripple": unl["exp"], "publisher": unl["pub"], "size": len(unl["keys"])}
        if unl
        else None,
        "quorum_last": quorum,
        "quorum_margin": {
            "min": min(m) if m else None,
            "p5": pct(m, 5),
            "p50": pct(m, 50),
            "ledgers_below_min": len(below),
            "below_min_first": below[:20],
        },
        "thresholds": {
            "warn_delay_ms": warn_delay_ms,
            "min_participation": min_participation,
            "min_margin": min_margin,
        },
        "validators": validators,
        "edge_ms": EDGE_MS,
        **({"ledger_detail": per_ledger} if detail else {}),
    }


def fmt_ms(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000)) if ms is not None else "-"


def render_text(rep):
    out = [
        "pft-valwatch report",
        (
            f"window: {fmt_ms(rep['first_ms'])} .. {fmt_ms(rep['last_ms'])}  records {rep['records']}"
            f"  bad_lines {rep['bad_lines']}  reconnects {rep['reconnects']}"
        ),
        f"ledgers: {rep['ledgers']} ({rep['first_ledger']}..{rep['last_ledger']}, missing {rep['missing_ledgers']})",
    ]
    u = rep["unl"]
    out.append(f"unl: seq {u['seq']} size {u['size']} publisher {u['publisher']}" if u else "unl: none")
    q = rep["quorum_margin"]
    out.append(
        f"quorum: {rep['quorum_last']}  margin min {q['min']} p5 {q['p5']} p50 {q['p50']}"
        f"  ledgers below {rep['thresholds']['min_margin']}: {q['ledgers_below_min']}"
    )
    out.append(f"{'validator':<54} {'agreed':>7} {'expect':>7} {'part':>7} {'p50ms':>6} {'p95ms':>6} flags")
    for k, v in rep["validators"].items():
        part = f"{v['participation']:.4f}" if v["participation"] is not None else "-"
        out.append(
            f"{k:<54} {v['agreed']:>7} {v['expected']:>7} {part:>7} "
            f"{v['delay_ms_p50']!s:>6} {v['delay_ms_p95']!s:>6} {','.join(v['flags']) or '-'}"
        )
    flagged = sum(1 for v in rep["validators"].values() if v["flags"])
    out.append(
        f"RESULT: {'WARN' if flagged or q['ledgers_below_min'] else 'OK'} - {flagged} validator(s) flagged,"
        f" {q['ledgers_below_min']} ledger(s) below quorum margin"
    )
    return "\n".join(out) + "\n"


def add_thresholds(p):
    p.add_argument("--warn-delay-ms", type=int, default=3000)
    p.add_argument("--min-participation", type=float, default=0.9)
    p.add_argument("--min-margin", type=int, default=2)


def cmd_report(a):
    st = {}
    recs = iter_load(a.dir, a.from_, a.to, st)
    rep = analyze(
        recs,
        lambda: st["bad"],
        a.warn_delay_ms,
        a.min_participation,
        a.min_margin,
        detail=a.detail,
        carried=carried_of(st),
    )
    if a.json or a.detail:
        json.dump(rep, sys.stdout, sort_keys=True, indent=1)  # streamed: --detail over 24 h is ~50 MB of JSON
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(rep))
    return 0 if rep["ledgers"] else 4


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def cmd_textfile(a):
    now = a.now if a.now is not None else int(time.time())
    st = {}
    recs = iter_load(a.dir, now - a.window, now + 1, st)
    rep = analyze(recs, lambda: st["bad"], a.warn_delay_ms, a.min_participation, a.min_margin, carried=carried_of(st))
    n = esc(a.name)
    lines = []

    def g(metric, value, labels="", help_=None):
        if help_:
            lines.append(f"# HELP pft_valwatch_{metric} {help_}")
            lines.append(f"# TYPE pft_valwatch_{metric} gauge")
        if value is not None:
            lines.append(f'pft_valwatch_{metric}{{node="{n}"{labels}}} {value}')

    ok = 1 if rep["ledgers"] else 0
    g("up", ok, help_="1 if the window holds at least one validated ledger with UNL and quorum known")
    g("collect_timestamp_seconds", now, help_="time this textfile was built")
    g("window_seconds", a.window, help_="analysis window")
    g(
        "last_record_age_seconds",
        max(0, now * 1000 - rep["last_ms"]) // 1000 if rep["last_ms"] else None,
        help_="age of the newest stream record",
    )
    g("ledgers", rep["ledgers"], help_="validated ledgers observed in the window")
    g("missing_ledgers", rep["missing_ledgers"], help_="ledger indexes skipped inside the window")
    g("reconnects", rep["reconnects"], help_="stream disconnects in the window")
    g("bad_lines", rep["bad_lines"], help_="unparsable record lines in the window")
    u = rep["unl"]
    g("unl_size", u["size"] if u else None, help_="validators in the node's cached publisher list")
    g(
        "unl_expiration_seconds",
        u["expiration_ripple"] + RIPPLE_EPOCH if u else None,
        help_="publisher list expiration (unix time)",
    )
    g("quorum", rep["quorum_last"], help_="validation_quorum from server_info")
    q = rep["quorum_margin"]
    g("quorum_margin_min", q["min"], help_="min over ledgers of (UNL validations agreeing) - quorum")
    g("quorum_margin_p50", q["p50"], help_="median quorum margin")
    g("ledgers_below_margin", q["ledgers_below_min"], help_="ledgers with margin below --min-margin")
    vals = list(rep["validators"].items())[:MAX_VALIDATORS]
    g(
        "validators_truncated",
        1 if len(rep["validators"]) > MAX_VALIDATORS else 0,
        help_="1 if per-validator series were capped",
    )
    for metric, field, help_ in (
        (
            "validator_participation_ratio",
            "participation",
            "share of window ledgers this UNL validator validated with the agreed hash",
        ),
        ("validator_delay_p95_ms", "delay_ms_p95", "p95 delay vs the first UNL validation of the same ledger"),
    ):
        lines.append(f"# HELP pft_valwatch_{metric} {help_}")
        lines.append(f"# TYPE pft_valwatch_{metric} gauge")
        for k, v in vals:
            if v[field] is not None:
                lines.append(f'pft_valwatch_{metric}{{node="{n}",validator="{esc(k)}"}} {v[field]}')
    g("validators_flagged", sum(1 for _, v in vals if v["flags"]), help_="UNL validators with any flag")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0 if ok else 1


def compare(ra, rb, tol_part, tol_delay_ms, tol_margin):
    """Grade two detailed reports on the ledger indexes BOTH hosts graded."""
    la, lb = ra.get("ledger_detail"), rb.get("ledger_detail")
    if la is None or lb is None:
        raise ValueError("compare needs reports made with --detail")
    common = sorted(set(la) & set(lb), key=int)
    hash_mismatch = [i for i in common if la[i]["h"] != lb[i]["h"]]
    margin_diff = [abs(la[i]["m"] - lb[i]["m"]) for i in common]
    keys = sorted({k for i in common for side in (la, lb) for k in list(side[i]["d"]) + side[i]["miss"]})
    rows, outside = [], []
    for k in keys:
        cols = {}
        for tag, side in (("a", la), ("b", lb)):
            exp = [i for i in common if k in side[i]["d"] or k in side[i]["miss"]]
            delays = [side[i]["d"][k] for i in exp if k in side[i]["d"]]
            cols[tag] = (len(exp), round(len(delays) / len(exp), 4) if exp else None, pct(delays, 50))
        (ea, pa, da), (eb, pb, db) = cols["a"], cols["b"]
        if ea != eb or pa is None:
            row = {"validator": k, "expected_a": ea, "expected_b": eb, "status": "unl_differs"}
        else:
            dp = round(abs(pa - pb), 4)
            dd = abs(da - db) if da is not None and db is not None else None
            ok = dp <= tol_part and (dd is None or dd <= tol_delay_ms)
            row = {
                "validator": k,
                "expected": ea,
                "part_a": pa,
                "part_b": pb,
                "part_diff": dp,
                "p50_a": da,
                "p50_b": db,
                "p50_diff": dd,
                "status": "ok" if ok else "outside_tolerance",
            }
        rows.append(row)
        if row["status"] != "ok":
            outside.append(k)
    mmax = max(margin_diff) if margin_diff else None
    agree = bool(common) and not hash_mismatch and mmax <= tol_margin and not outside
    return {
        "common_ledgers": len(common),
        "first": int(common[0]) if common else None,
        "last": int(common[-1]) if common else None,
        "hash_mismatch": [int(i) for i in hash_mismatch],
        "margin_absdiff_max": mmax,
        "margin_equal_ledgers": sum(1 for d in margin_diff if d == 0),
        "tolerance": {"part": tol_part, "delay_ms": tol_delay_ms, "margin": tol_margin},
        "validators": rows,
        "validators_outside": outside,
        "result": "AGREE" if agree else "DISAGREE",
    }


def cmd_compare(a):
    with open(a.a, encoding="utf-8") as fa, open(a.b, encoding="utf-8") as fb:
        ra, rb = json.load(fa), json.load(fb)
    try:
        res = compare(ra, rb, a.tolerance_part, a.tolerance_delay_ms, a.tolerance_margin)
    except ValueError as e:
        die(str(e))
    if a.json:
        sys.stdout.write(json.dumps(res, sort_keys=True, indent=1) + "\n")
        return 0 if res["result"] == "AGREE" else 1
    w = sys.stdout.write
    w(
        f"common ledgers: {res['common_ledgers']} ({res['first']}..{res['last']}),"
        f" hash mismatches {len(res['hash_mismatch'])}\n"
    )
    w(
        f"quorum margin: max |A-B| {res['margin_absdiff_max']} (tolerance {a.tolerance_margin}),"
        f" equal on {res['margin_equal_ledgers']}/{res['common_ledgers']}\n"
    )
    for r in res["validators"]:
        if r["status"] == "unl_differs":
            w(f"{r['validator']}  unl_differs (expected {r['expected_a']} vs {r['expected_b']})\n")
        else:
            w(
                f"{r['validator']}  part {r['part_a']:.4f} vs {r['part_b']:.4f} (diff {r['part_diff']:.4f})"
                f"  p50 {r['p50_a']} vs {r['p50_b']} ms  {r['status']}\n"
            )
    w(f"RESULT: {res['result']} - {len(res['validators_outside'])} validator(s) outside tolerance\n")
    return 0 if res["result"] == "AGREE" else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="valwatch.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--host", required=True)
    c.add_argument("--port", type=int, default=6005)
    c.add_argument("--out", required=True)
    c.add_argument("--unl-cache", required=True)
    c.add_argument("--retain-hours", type=int, default=24)
    c.add_argument("--max-dir-bytes", type=int, default=512 * 1024 * 1024)
    c.add_argument("--duration", type=int, default=0)
    c.add_argument("--plain", action="store_true", help="ws:// without TLS (tests)")
    r = sub.add_parser("report")
    r.add_argument("--dir", required=True)
    r.add_argument("--from", dest="from_", type=int)
    r.add_argument("--to", type=int)
    r.add_argument("--json", action="store_true")
    r.add_argument("--detail", action="store_true", help="JSON with per-ledger detail (input for compare)")
    add_thresholds(r)
    t = sub.add_parser("textfile")
    t.add_argument("--dir", required=True)
    t.add_argument("--name", required=True)
    t.add_argument("--now", type=int)
    t.add_argument("--window", type=int, default=900)
    add_thresholds(t)
    m = sub.add_parser("compare")
    m.add_argument("a")
    m.add_argument("b")
    m.add_argument("--tolerance-part", type=float, default=0.02)
    m.add_argument("--tolerance-delay-ms", type=int, default=1000)
    m.add_argument("--tolerance-margin", type=int, default=1)
    m.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd in ("report", "textfile") and not os.path.isdir(a.dir):
        die(f"no such directory: {a.dir}")
    return {"collect": cmd_collect, "report": cmd_report, "textfile": cmd_textfile, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
