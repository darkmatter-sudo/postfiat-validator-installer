#!/usr/bin/env python3
"""histarchive: hash-chained archive of validated Post Fiat ledger history (Python 3 stdlib only).

A node with `[node_db] online_delete=512` keeps only ~512-1024 ledgers. This tool follows the
node's validated ledgers through the PUBLIC JSON-RPC methods `server_info` and `ledger`
(binary=true, transactions expanded), verifies every ledger before it is written, and keeps the
history in daily compressed segments that anyone can re-verify offline.

Layout of --dir:
  active/YYYY-MM-DD.jsonl       the current UTC day (by ledger close time), one line per ledger,
                                flushed and fsynced after every line
  segments/YYYY-MM-DD.jsonl.gz  sealed days (gzip of the exact active bytes)
  MANIFEST.jsonl                one entry per sealed segment, hash-chained: each entry carries
                                prev_entry (the previous entry's hash) and entry =
                                sha256(canonical JSON of the entry without "entry")
  gaps.jsonl                    ledger ranges that could not be archived, with the reason
  gapfills.jsonl                append-only log of verified gap fills (one line per filled gap; the
                                MANIFEST fill entry is the authority, this file mirrors it)
  segments/fill-A-B.jsonl.gz    a sealed fill segment: the ledgers A..B of a recorded gap, verified
                                against both archived neighbours before it was written (fill-gap)
  .lock                         flock: seal and fill-gap hold it exclusively, verify shared
  state.json                    start ledger / start time / window of this archive
  status.json                   follower progress (rewritten atomically every ledger)

Ledger line: {"i": seq, "h": ledger hash, "d": 118-byte header (hex, the node's ledger_data),
              "t": [[tx_blob hex, meta hex], ...] in the node's order}

Checks (at ingest and in `verify`; lib_hashverify.py is a byte-identical copy of
pft-ledger-stats/hashverify/lib_hashverify.py, see README):
  header    the header's own ledger_index equals "i"
  hash      SHA-512Half("LWR\\0" || header) equals "h"
  txroot    the SHAMap root rebuilt from every [tx_blob, meta] equals the header's transaction_hash
  chain     the header's parent_hash equals the previous ledger's "h" (across segments too),
            unless a gaps.jsonl range sits between them
  order     ledger indexes strictly increase by one; any missing index not covered by gaps.jsonl
            is a FAIL ("missing")
  fill      a MANIFEST fill entry covers exactly one recorded gap, at most once; its ledgers are
            spliced into the stream at the gap, so header/hash/txroot/chain run across both ends

Crash safety: lines are appended with one write + fsync, so a SIGKILL can leave at most one
torn last line, which resume cuts (and logs). Sealing writes segments/X.gz.tmp, fsyncs, renames,
fsyncs the dir, appends the MANIFEST entry (fsync) and only then removes active/X; resume
finishes or redoes any half-done seal. Resume always continues at last archived ledger + 1, so
a restart can neither duplicate nor skip a ledger; ledgers the node pruned while the follower
was down are recorded as a gap, never silently skipped.

Exit codes: 0 ok | 1 verification FAIL / mismatch | 2 runtime error (RPC, I/O, bad input) | 3 usage
"""

import argparse
import calendar
import contextlib
import fcntl
import gzip
import hashlib
import json
import os
import random
import signal
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_hashverify as hv

RIPPLE_EPOCH = 946684800
READ_ONLY_METHODS = {"server_info", "ledger"}
VERSION = "1.1.0"
RATE_CAP = 8.0  # req/s; the tests raise it for their fake node

_stop = False


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(fh, msg):
    line = f"{utcnow()} {msg}"
    print(line, flush=True)
    if fh:
        fh.write(line + "\n")
        fh.flush()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def append_line(path, line):
    """One write + fsync per line (a crash leaves at most one torn last line)."""
    with open(path, "ab") as fh:
        fh.write(line.encode() + b"\n")
        fh.flush()
        os.fsync(fh.fileno())


# ---------------------------------------------------------------- header / record checks


def parse_header(d):
    """118-byte header -> dict of its fields (hex upper for hashes)."""
    if len(d) != hv.HEADER_BYTES:
        raise ValueError(f"header is {len(d)} bytes, want {hv.HEADER_BYTES}")
    seq, coins = struct.unpack(">IQ", d[:12])
    pct, ct, res, flags = struct.unpack(">IIBB", d[108:118])
    return {
        "ledger_index": seq,
        "total_coins": coins,
        "parent_hash": d[12:44].hex().upper(),
        "transaction_hash": d[44:76].hex().upper(),
        "account_hash": d[76:108].hex().upper(),
        "parent_close_time": pct,
        "close_time": ct,
        "close_time_resolution": res,
        "close_flags": flags,
    }


def day_of(close_time):
    return time.strftime("%Y-%m-%d", time.gmtime(int(close_time) + RIPPLE_EPOCH))


def check_record(rec):
    """Self-checks of one ledger line. Returns (header dict, [problem strings])."""
    probs = []
    try:
        d = bytes.fromhex(rec["d"])
        hdr = parse_header(d)
    except (KeyError, ValueError, TypeError) as e:
        return None, [f"header unreadable: {e}"]
    if hdr["ledger_index"] != rec.get("i"):
        probs.append(
            f"header: index {hdr['ledger_index']} != line index {rec.get('i')}"
        )
    got = hv.sha512half(hv.PREFIX_LEDGER, d).hex().upper()
    if got != str(rec.get("h", "")).upper():
        probs.append(
            f"hash: recomputed {got[:16]} != recorded {str(rec.get('h'))[:16]}"
        )
    try:
        txs = [{"tx_blob": b, "meta": m} for b, m in rec.get("t", [])]
        root, _ids = hv.tx_tree(txs)
    except (ValueError, TypeError) as e:
        probs.append(f"txroot: transactions unreadable: {e}")
    else:
        if root != hdr["transaction_hash"]:
            probs.append(
                f"txroot: rebuilt {root[:16]} != header {hdr['transaction_hash'][:16]}"
            )
    return hdr, probs


def record_from_rpc(answer):
    """`ledger` (binary, expanded) answer -> archive record."""
    led = answer["ledger"]
    if not answer.get("validated"):
        raise LookupError("ledger not validated")
    return {
        "i": int(answer["ledger_index"]),
        "h": str(answer["ledger_hash"]).upper(),
        "d": str(led["ledger_data"]).upper(),
        "t": [[t["tx_blob"], t["meta"]] for t in led.get("transactions") or []],
    }


def tx_ids(rec):
    return [hv.tx_id(bytes.fromhex(b)).hex().upper() for b, _m in rec.get("t", [])]


# ---------------------------------------------------------------- RPC


class Rpc:
    """JSON-RPC client for read-only methods with a request-rate limit."""

    def __init__(self, url, rate=4.0, timeout=20.0):
        self.url = url
        self.min_gap = 1.0 / rate
        self.timeout = timeout
        self.last = 0.0
        self.count = 0

    def call(self, method, params=None):
        if method not in READ_ONLY_METHODS:
            raise ValueError(f"refusing non read-only method {method}")
        wait = self.min_gap - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.last = time.monotonic()
        self.count += 1
        body = json.dumps({"method": method, "params": [params or {}]}).encode()
        req = urllib.request.Request(
            self.url, body, {"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            res = json.loads(r.read())["result"]
        if res.get("status") != "success":
            raise LookupError(f"{method}: {res.get('error', 'no status')}")
        return res


def oldest_complete(info):
    spans = hv.parse_ranges(info.get("complete_ledgers"))
    return min(a for a, _b in spans) if spans else None


# ---------------------------------------------------------------- archive files


class Archive:
    def __init__(self, root):
        self.root = root
        self.active = os.path.join(root, "active")
        self.segments = os.path.join(root, "segments")
        self.manifest = os.path.join(root, "MANIFEST.jsonl")
        self.gaps = os.path.join(root, "gaps.jsonl")
        self.gapfills = os.path.join(root, "gapfills.jsonl")
        self.state = os.path.join(root, "state.json")
        self.status = os.path.join(root, "status.json")

    def mkdirs(self):
        for p in (self.root, self.active, self.segments):
            os.makedirs(p, exist_ok=True)

    def active_days(self):
        if not os.path.isdir(self.active):
            return []
        return sorted(
            f[:-6]
            for f in os.listdir(self.active)
            if f.endswith(".jsonl") and len(f) == 16
        )

    def active_path(self, day):
        return os.path.join(self.active, f"{day}.jsonl")

    def seg_path(self, day):
        return os.path.join(self.segments, f"{day}.jsonl.gz")

    def manifest_entries(self):
        return read_jsonl(self.manifest)

    def gap_ranges(self):
        return [(int(g["from"]), int(g["to"])) for g in read_jsonl(self.gaps)]


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [json.loads(x) for x in fh if x.strip()]


def drop_torn_tail(path):
    """Cut a last line that has no newline or is not valid JSON. Returns bytes removed."""
    if not os.path.exists(path):
        return 0
    with open(path, "rb+") as fh:
        data = fh.read()
        if not data:
            return 0
        keep = len(data)
        if not data.endswith(b"\n"):
            keep = data.rfind(b"\n") + 1
        else:
            start = data.rfind(b"\n", 0, len(data) - 1) + 1
            try:
                json.loads(data[start:])
            except ValueError:
                keep = start
        if keep == len(data):
            return 0
        fh.truncate(keep)
        fh.flush()
        os.fsync(fh.fileno())
        return len(data) - keep


def last_line_record(path):
    if not os.path.exists(path):
        return None
    last = None
    with open(path, "rb") as fh:
        for x in fh:
            if x.strip():
                last = x
    return json.loads(last) if last else None


def entry_hash(entry):
    return hashlib.sha256(
        canon({k: v for k, v in entry.items() if k != "entry"}).encode()
    ).hexdigest()


@contextlib.contextmanager
def archive_lock(root, exclusive=True, timeout=None):
    """flock on <root>/.lock. Writers of MANIFEST (seal, fill-gap) hold it exclusively; verify
    holds it shared so it never reads a half-committed fill. The follower's appends to active/
    need no lock (nothing else writes there). timeout None = wait forever."""
    path = os.path.join(root, ".lock")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CREAT, 0o644)
    except PermissionError:
        if exclusive:
            raise
        try:  # a reader without write access to the dir: use the lock if it exists
            fd = os.open(path, os.O_RDONLY)
        except FileNotFoundError:
            yield
            return
    try:
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if timeout is None:
            fcntl.flock(fd, mode)
        else:
            end = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, mode | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= end:
                        raise RuntimeError(
                            f"archive busy: {path} held by another writer for {timeout:g} s"
                        ) from None
                    time.sleep(0.2)
        yield
    finally:
        os.close(fd)


def seal_day(ar, day, lf=None):
    """Seal active/<day>.jsonl into segments/<day>.jsonl.gz + a MANIFEST entry (crash-safe)."""
    with archive_lock(ar.root):
        return _seal_day(ar, day, lf)


def _seal_day(ar, day, lf=None):
    src = ar.active_path(day)
    entries = ar.manifest_entries()
    done = {e["day"]: e for e in entries}
    if day in done:
        e = done[day]
        if (
            os.path.exists(ar.seg_path(day))
            and sha256_file(ar.seg_path(day)) == e["sha256_gz"]
        ):
            if os.path.exists(src):
                os.unlink(src)
                fsync_dir(ar.active)
                log(
                    lf,
                    f"RESUME seal {day}: manifest entry and segment present, removed active copy",
                )
            return e
        raise RuntimeError(
            f"seal {day}: MANIFEST has an entry but the segment is missing or differs"
        )
    with open(src, "rb") as fh:
        raw = fh.read()
    lines = [json.loads(x) for x in raw.split(b"\n") if x.strip()]
    if not lines:
        os.unlink(src)
        return None
    tmp = ar.seg_path(day) + ".tmp"
    gz = gzip.compress(raw, compresslevel=9, mtime=0)
    with open(tmp, "wb") as fh:
        fh.write(gz)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, ar.seg_path(day))
    fsync_dir(ar.segments)
    first_hdr = parse_header(bytes.fromhex(lines[0]["d"]))
    prev = entries[-1] if entries else None
    entry = {
        "v": 1,
        "day": day,
        "segment": f"segments/{day}.jsonl.gz",
        "first": lines[0]["i"],
        "last": lines[-1]["i"],
        "count": len(lines),
        "first_parent": first_hdr["parent_hash"],
        "last_hash": lines[-1]["h"],
        "txs": sum(len(x.get("t", [])) for x in lines),
        "bytes_raw": len(raw),
        "bytes_gz": len(gz),
        "sha256_raw": hashlib.sha256(raw).hexdigest(),
        "sha256_gz": hashlib.sha256(gz).hexdigest(),
        "sealed_utc": utcnow(),
        "prev_entry": prev["entry"] if prev else None,
    }
    entry["entry"] = entry_hash(entry)
    append_line(ar.manifest, canon(entry))
    os.unlink(src)
    fsync_dir(ar.active)
    log(
        lf,
        f"SEAL {day} ledgers {entry['first']}-{entry['last']} count={entry['count']} "
        f"raw={entry['bytes_raw']} gz={entry['bytes_gz']} sha256_gz={entry['sha256_gz'][:16]}",
    )
    return entry


def last_archived(ar):
    """(last ledger index, its hash) over active files, manifest and gaps; (None, None) if empty."""
    best = (None, None)
    for day in ar.active_days():
        r = last_line_record(ar.active_path(day))
        if r and (best[0] is None or r["i"] > best[0]):
            best = (r["i"], r["h"])
    for e in ar.manifest_entries():
        if best[0] is None or e["last"] > best[0]:
            best = (e["last"], e["last_hash"])
    for a, b in ar.gap_ranges():
        if best[0] is None or b > best[0]:
            best = (b, None)
    return best


def add_gap(ar, a, b, reason, lf=None):
    append_line(ar.gaps, canon({"from": a, "to": b, "reason": reason, "at": utcnow()}))
    log(lf, f"GAP ledgers {a}-{b} ({b - a + 1}): {reason}")


# ---------------------------------------------------------------- follow


def _handle(_signum, _frame):
    global _stop
    _stop = True


def open_log(path):
    return open(path, "a") if path else contextlib.nullcontext()


def cmd_follow(a):
    with open_log(a.log) as lf:
        return follow(a, lf)


def follow(a, lf):
    ar = Archive(a.dir)
    ar.mkdirs()
    rpc = Rpc(a.rpc, a.rate)
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)

    os.close(os.open(os.path.join(ar.root, ".lock"), os.O_RDONLY | os.O_CREAT, 0o644))
    info = rpc.call("server_info")["info"]
    validated = int(info["validated_ledger"]["seq"])
    log(
        lf,
        f"histarchive {VERSION} follow: node build {info.get('build_version')} state "
        f"{info.get('server_state')} complete_ledgers {info.get('complete_ledgers')}",
    )

    for day in ar.active_days():
        torn = drop_torn_tail(ar.active_path(day))
        if torn:
            log(lf, f"RESUME cut torn last line of active/{day}.jsonl ({torn} bytes)")
    for f in os.listdir(ar.segments):
        if f.endswith(".tmp"):
            os.unlink(os.path.join(ar.segments, f))
            log(lf, f"RESUME removed half-written {f}")
    sealed = {e["day"] for e in ar.manifest_entries()}
    for f in os.listdir(ar.segments):
        day = f[:10]
        if (
            f.endswith(".jsonl.gz")
            and day not in sealed
            and os.path.exists(ar.active_path(day))
        ):
            os.unlink(os.path.join(ar.segments, f))
            log(lf, f"RESUME removed unrecorded segment {f} (seal is redone)")
    days = ar.active_days()
    for day in days[:-1]:
        seal_day(ar, day, lf)
    for day in sealed & set(ar.active_days()):
        seal_day(ar, day, lf)

    last, last_hash = last_archived(ar)
    if os.path.exists(ar.state):
        with open(ar.state) as fh:
            state = json.load(fh)
        nxt = last + 1 if last is not None else state["start_seq"]
        log(
            lf,
            f"RESUME at ledger {nxt} (archive start {state['start_seq']}, node validated {validated})",
        )
    else:
        nxt = a.start if a.start is not None else validated
        state = {
            "v": 1,
            "start_seq": nxt,
            "start_utc": utcnow(),
            "tool": f"histarchive {VERSION}",
        }
        atomic_write(ar.state, canon(state) + "\n")
        log(lf, f"START archive at ledger {nxt}")
    if a.until is not None:
        deadline = calendar.timegm(time.strptime(a.until, "%Y-%m-%dT%H:%M:%SZ"))
        log(lf, f"this run stops at {a.until} (--until)")
    elif a.hours is not None:
        deadline = time.time() + a.hours * 3600
        log(
            lf,
            f"this run stops after {a.hours} h (at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(deadline))})",
        )
    else:
        deadline = None

    prev_hash = last_hash
    cur_day = ar.active_days()[-1] if ar.active_days() else None
    n_this_run = 0
    next_progress = time.monotonic() + a.progress
    while (
        not _stop
        and (a.stop_at is None or nxt <= a.stop_at)
        and (deadline is None or time.time() < deadline)
    ):
        if time.monotonic() >= next_progress:
            log(
                lf,
                f"PROGRESS last={nxt - 1} lag={validated - nxt + 1} archived_this_run={n_this_run} requests={rpc.count}",
            )
            next_progress = time.monotonic() + a.progress
        if nxt > validated:
            try:
                info = rpc.call("server_info")["info"]
                validated = int(info["validated_ledger"]["seq"])
            except Exception as e:  # noqa: BLE001 - a follower must keep running through node restarts
                log(lf, f"WARN server_info failed: {type(e).__name__}: {e}")
                time.sleep(a.poll)
                continue
            if nxt > validated:
                time.sleep(a.poll)
                continue
            oldest = oldest_complete(info)
            if oldest is not None and nxt < oldest:
                add_gap(
                    ar,
                    nxt,
                    oldest - 1,
                    f"pruned on the node before archiving (oldest {oldest})",
                    lf,
                )
                nxt, prev_hash = oldest, None
                continue
        rec, err = None, None
        for attempt in range(1, a.retries + 1):
            try:
                rec = record_from_rpc(
                    rpc.call(
                        "ledger",
                        {
                            "ledger_index": nxt,
                            "transactions": True,
                            "expand": True,
                            "binary": True,
                        },
                    )
                )
                hdr, probs = check_record(rec)
                if rec["i"] != nxt:
                    probs.append(f"asked for {nxt}, got {rec['i']}")
                if (
                    not probs
                    and prev_hash is not None
                    and hdr["parent_hash"] != prev_hash
                ):
                    probs.append(
                        f"chain: parent {hdr['parent_hash'][:16]} != archived {nxt - 1} {prev_hash[:16]}"
                    )
                if probs:
                    raise ValueError("; ".join(probs))
                err = None
                break
            except Exception as e:  # noqa: BLE001
                rec, err = None, f"{type(e).__name__}: {e}"
                log(lf, f"WARN ledger {nxt} attempt {attempt}/{a.retries}: {err}")
                time.sleep(a.retry_sleep)
        if rec is None:
            try:
                oldest = oldest_complete(rpc.call("server_info")["info"])
            except Exception:  # noqa: BLE001
                oldest = None
            if oldest is not None and nxt < oldest:
                add_gap(
                    ar,
                    nxt,
                    oldest - 1,
                    f"pruned on the node before archiving (oldest {oldest})",
                    lf,
                )
                nxt, prev_hash = oldest, None
            elif (
                "chain:" in (err or "")
                or "hash:" in (err or "")
                or "txroot:" in (err or "")
            ):
                add_gap(ar, nxt, nxt, f"verification failed at ingest: {err}", lf)
                nxt, prev_hash = nxt + 1, None
            else:
                log(
                    lf,
                    f"WARN ledger {nxt} unavailable after {a.retries} attempts; waiting {a.poll * 10:.0f} s",
                )
                time.sleep(a.poll * 10)
            continue
        day = day_of(hdr["close_time"])
        if cur_day is not None and day != cur_day:
            if day < cur_day:
                log(
                    lf,
                    f"WARN ledger {nxt} closes on {day}, before active day {cur_day}; kept in {cur_day}",
                )
                day = cur_day
            else:
                seal_day(ar, cur_day, lf)
        cur_day = day
        append_line(ar.active_path(day), canon(rec))
        prev_hash = rec["h"]
        n_this_run += 1
        atomic_write(
            ar.status,
            canon(
                {
                    "last": nxt,
                    "last_hash": rec["h"],
                    "close_time": hdr["close_time"],
                    "ingest_unix": int(time.time()),
                    "validated": validated,
                    "lag": max(0, validated - nxt),
                    "gaps": len(ar.gap_ranges()),
                    "archived_this_run": n_this_run,
                    "pid": os.getpid(),
                }
            )
            + "\n",
        )
        nxt += 1

    reason = (
        "signal"
        if _stop
        else (
            "stop_at reached"
            if a.stop_at is not None and nxt > a.stop_at
            else "run time reached"
        )
    )
    log(
        lf,
        f"STOP ({reason}) last={nxt - 1} archived_this_run={n_this_run} requests={rpc.count}",
    )
    return 0


# ---------------------------------------------------------------- verify


def read_segment(path):
    """Whole-file gzip decode (CRC and length are checked by gzip.decompress)."""
    with open(path, "rb") as fh:
        gz = fh.read()
    return gz, gzip.decompress(gz)


def verify_archive(root, include_active=True):
    """Full offline verification. Returns a result dict; result["fail"] lists every FAIL."""
    ar = Archive(root)
    fails, notes = [], []
    entries = ar.manifest_entries() if os.path.exists(ar.manifest) else []
    gaps = ar.gap_ranges()
    stream = []  # (source, raw bytes)

    prev_entry = None
    for n, e in enumerate(entries, 1):
        if e.get("entry") != entry_hash(e):
            fails.append(
                f"manifest entry {n} ({e.get('day')}): entry hash does not match its content"
            )
        if e.get("prev_entry") != (prev_entry["entry"] if prev_entry else None):
            fails.append(
                f"manifest entry {n} ({e.get('day')}): prev_entry does not link to entry {n - 1}"
            )
        prev_entry = e
        path = os.path.join(root, e.get("segment", ""))
        if not os.path.exists(path):
            fails.append(f"segment {e.get('segment')}: missing")
            continue
        try:
            gz, raw = read_segment(path)
        except (OSError, EOFError, gzip.BadGzipFile) as ex:
            fails.append(
                f"segment {e['segment']}: not readable as gzip ({type(ex).__name__}: {ex})"
            )
            continue
        if hashlib.sha256(gz).hexdigest() != e["sha256_gz"]:
            fails.append(
                f"segment {e['segment']}: sha256 of the file differs from MANIFEST"
            )
        if hashlib.sha256(raw).hexdigest() != e["sha256_raw"]:
            fails.append(
                f"segment {e['segment']}: sha256 of the content differs from MANIFEST"
            )
        stream.append((e["segment"], raw, e))
    listed = {e.get("segment") for e in entries}
    if os.path.isdir(ar.segments):
        for f in sorted(os.listdir(ar.segments)):
            if f"segments/{f}" not in listed and f.endswith(".jsonl.gz"):
                fails.append(f"segment segments/{f}: not listed in MANIFEST")
    if include_active:
        for day in ar.active_days():
            with open(ar.active_path(day), "rb") as fh:
                stream.append((f"active/{day}.jsonl", fh.read(), None))

    # pass 1: parse each source and check it against its MANIFEST entry
    main, fills = (
        [],
        [],
    )  # main: [(src, rec)] in stream order; fills: [(entry, [(src, rec)])]
    for src, raw, e in stream:
        if raw and not raw.endswith(b"\n"):
            fails.append(f"{src}: last line is torn (no newline)")
        recs = []
        for ln, x in enumerate(raw.split(b"\n"), 1):
            if not x.strip():
                continue
            try:
                recs.append(json.loads(x))
            except ValueError:
                fails.append(f"{src} line {ln}: not JSON")
        if e is not None and recs:
            if (recs[0]["i"], recs[-1]["i"], len(recs)) != (
                e["first"],
                e["last"],
                e["count"],
            ):
                fails.append(f"{src}: first/last/count differ from MANIFEST")
            if recs[-1].get("h") != e["last_hash"]:
                fails.append(f"{src}: last ledger hash differs from MANIFEST")
            hdr, _p = check_record(recs[0])
            if hdr is not None and hdr["parent_hash"] != e["first_parent"]:
                fails.append(f"{src}: first_parent differs from MANIFEST")
        if e is not None and e.get("kind") == "fill":
            fills.append((e, [(src, r) for r in recs]))
        else:
            main += [(src, r) for r in recs]

    # fills: each covers exactly one recorded gap, once; splice its ledgers in at the gap
    filled, standalone = set(), []
    have = {r.get("i"): r.get("h") for _s, r in main}
    for e, frecs in fills:
        rng = (e.get("first"), e.get("last"))
        g = e.get("gap") or {}
        if rng not in gaps or (g.get("from"), g.get("to")) != rng:
            fails.append(
                f"{e['segment']}: fill {rng[0]}-{rng[1]} does not match a recorded gap in gaps.jsonl"
            )
        if rng in filled:
            fails.append(f"{e['segment']}: gap {rng[0]}-{rng[1]} filled twice")
        filled.add(rng)
        if e.get("count") != (rng[1] - rng[0] + 1 if None not in rng else None):
            fails.append(f"{e['segment']}: fill count does not cover the whole gap")
        if None in rng or (rng[0] - 1 in have and rng[1] + 1 in have):
            for side, i in (("anchor_below", rng[0] - 1), ("anchor_above", rng[1] + 1)):
                if None not in rng and (e.get(side) or {}).get("h") != have[i]:
                    fails.append(
                        f"{e['segment']}: {side} in MANIFEST differs from archived ledger {i}"
                    )
            at = next(
                (k for k, (_s, r) in enumerate(main) if r.get("i", 0) > rng[0]),
                len(main),
            )
            main[at:at] = frecs
            continue
        # a neighbour is not in this stream: check the fill as its own chain from its recorded anchor
        standalone.append((e, frecs))
        if include_active:
            fails.append(
                f"{e['segment']}: fill {rng[0]}-{rng[1]}: neighbour ledger(s) "
                f"{', '.join(str(i) for i in (rng[0] - 1, rng[1] + 1) if i not in have)} not in the archive"
            )
        else:
            notes.append(
                f"fill {rng[0]}-{rng[1]} checked on its own chain: its neighbours are in active/, "
                "which a sealed-only verify skips"
            )
    log_fills = read_jsonl(os.path.join(root, "gapfills.jsonl"))
    by_entry = {e["entry"]: e for e, _r in fills}
    for n, lf_ in enumerate(log_fills, 1):
        fe = by_entry.get(lf_.get("entry"))
        if fe is None or (fe["first"], fe["last"]) != (lf_.get("from"), lf_.get("to")):
            fails.append(
                f"gapfills.jsonl line {n}: fill {lf_.get('from')}-{lf_.get('to')} has no matching MANIFEST fill entry"
            )
    logged = {x.get("entry") for x in log_fills}
    for e, _r in fills:
        if e["entry"] not in logged:
            notes.append(
                f"fill {e['first']}-{e['last']} is in MANIFEST but not yet in gapfills.jsonl (fill-gap repairs it)"
            )
    open_gaps = [g for g in gaps if g not in filled]

    # pass 2: per-ledger checks, order and chain over the merged stream (+ fills checked on their own)
    count = txs = 0
    first = None
    streams = [(None, main)] + [
        ((e.get("anchor_below") or {}).get("h"), fr) for e, fr in standalone
    ]
    for anchor, stream in streams:
        prev = (stream[0][1].get("i", 0) - 1, anchor) if stream and anchor else None
        for src, r in stream:
            hdr, probs = check_record(r)
            for p in probs:
                fails.append(f"{src} ledger {r.get('i')}: {p}")
            i = r.get("i")
            if prev is not None:
                if i <= prev[0]:
                    fails.append(
                        f"{src} ledger {i}: order: not after {prev[0]} (duplicate or out of order)"
                    )
                    continue
                if i > prev[0] + 1:
                    gap = (prev[0] + 1, i - 1)
                    if not any(a <= gap[0] and gap[1] <= b for a, b in open_gaps):
                        fails.append(
                            f"{src}: missing ledgers {gap[0]}-{gap[1]} (no gaps.jsonl entry)"
                        )
                    else:
                        notes.append(
                            f"recorded gap {gap[0]}-{gap[1]} (chain restarts at {i})"
                        )
                elif hdr is not None and hdr["parent_hash"] != prev[1]:
                    fails.append(
                        f"{src} ledger {i}: chain: parent_hash does not equal ledger {prev[0]}'s hash"
                    )
            prev = (i, r.get("h"))
            count += 1
            txs += len(r.get("t", []))
    first = main[0][1].get("i") if main else None
    prev = (main[-1][1].get("i"), main[-1][1].get("h")) if main else None
    for a, b in sorted(filled):
        if (a, b) not in {(e["first"], e["last"]) for e, _f in standalone}:
            notes.append(
                f"filled gap {a}-{b} ({b - a + 1} ledgers, verified in the chain)"
            )
    return {
        "ok": not fails,
        "segments": len(entries),
        "active": len(ar.active_days()) if include_active else 0,
        "ledgers": count,
        "txs": txs,
        "first": first,
        "last": prev[0] if prev else None,
        "last_hash": prev[1] if prev else None,
        "gaps": len(open_gaps),
        "gap_ledgers": sum(b - a + 1 for a, b in open_gaps),
        "gaps_filled": len(filled),
        "fail": fails,
        "notes": notes,
        "head_entry": entries[-1]["entry"] if entries else None,
    }


def cmd_verify(a):
    with archive_lock(a.dir, exclusive=False):
        res = verify_archive(a.dir, include_active=not a.sealed_only)
    if a.json:
        print(json.dumps(res, indent=1, sort_keys=True))
    else:
        for f in res["fail"][: a.max_lines]:
            print(f"FAIL {f}")
        if len(res["fail"]) > a.max_lines:
            print(f"FAIL ... {len(res['fail']) - a.max_lines} more")
        for n in res["notes"]:
            print(f"NOTE {n}")
        print(
            f"RESULT: {'PASS' if res['ok'] else 'FAIL'} - segments {res['segments']} active {res['active']} "
            f"ledgers {res['ledgers']} ({res['first']}-{res['last']}) txs {res['txs']} gaps {res['gaps']} "
            f"({res['gap_ledgers']} ledgers) filled {res['gaps_filled']} fails {len(res['fail'])}"
        )
    if a.textfile:
        write_prom(a.textfile, verify_metrics(res), a.host)
    return 0 if res["ok"] else 1


def verify_metrics(res):
    # follower freshness (status.json) is exported by `pft-histarchive metrics` into its own file
    m = [
        (
            "pft_histarchive_verify_ok",
            "1 if the last full archive verification passed",
            int(res["ok"]),
        ),
        (
            "pft_histarchive_verify_failures",
            "FAIL items found by the last verification",
            len(res["fail"]),
        ),
        (
            "pft_histarchive_verify_timestamp_seconds",
            "unix time of the last verification",
            int(time.time()),
        ),
        (
            "pft_histarchive_ledgers",
            "ledgers in the archive (sealed + active)",
            res["ledgers"],
        ),
        ("pft_histarchive_segments", "sealed daily segments", res["segments"]),
        ("pft_histarchive_gaps", "recorded gap ranges not filled yet", res["gaps"]),
        (
            "pft_histarchive_gaps_filled",
            "recorded gap ranges repaired by a verified fill",
            res["gaps_filled"],
        ),
        (
            "pft_histarchive_gap_ledgers",
            "ledgers inside recorded gaps",
            res["gap_ledgers"],
        ),
        (
            "pft_histarchive_last_ledger",
            "newest archived ledger index",
            res["last"] or 0,
        ),
    ]
    return m


def write_prom(path, metrics, host="validator"):
    if not all(c.isalnum() or c in "_-" for c in host):
        raise ValueError(f"bad host label {host!r}")
    lines = []
    for name, help_, val in metrics:
        lines += [
            f"# HELP {name} {help_}",
            f"# TYPE {name} gauge",
            f'{name}{{host="{host}"}} {val}',
        ]
    atomic_write(path, "\n".join(lines) + "\n")


# ---------------------------------------------------------------- gap repair (fill-gap, gaps)


def fill_entries(ar):
    return [e for e in ar.manifest_entries() if e.get("kind") == "fill"]


def open_gaps(ar):
    """Recorded gap ranges without a MANIFEST fill entry (the MANIFEST is the authority)."""
    done = {(e["first"], e["last"]) for e in fill_entries(ar)}
    return [g for g in ar.gap_ranges() if g not in done]


def find_records(ar, wanted):
    """{index: record} for the wanted indexes, reading only the sources whose range can hold them."""
    wanted, got = set(wanted), {}
    srcs = []
    for e in ar.manifest_entries():
        if any(e["first"] <= i <= e["last"] for i in wanted):
            srcs.append(("gz", os.path.join(ar.root, e["segment"])))
    for day in ar.active_days():
        srcs.append(("raw", ar.active_path(day)))
    for kind, path in srcs:
        if kind == "gz":
            _gz, raw = read_segment(path)
            lines = raw.split(b"\n")
        else:
            with open(path, "rb") as fh:
                lines = fh.read().split(b"\n")
        for x in lines:
            if not x.strip():
                continue
            try:
                r = json.loads(x)
            except ValueError:
                continue  # a torn active tail; verify reports it
            if r.get("i") in wanted:
                got[r["i"]] = r
        if len(got) == len(wanted):
            break
    return got


def anchors(ar, a, b):
    """(record a-1, record b+1) from the archive; None where missing."""
    got = find_records(ar, {a - 1, b + 1})
    return got.get(a - 1), got.get(b + 1)


def staged_records(path):
    """Staged capture -> ({index: record}, [problems]). Lines are raw `ledger` answers
    ({"result": {...}}), bare answers, or archive records ({"i","h","d","t"})."""
    out, probs = {}, []
    with open(path, "rb") as fh:
        for ln, x in enumerate(fh, 1):
            if not x.strip():
                continue
            try:
                d = json.loads(x)
                if "result" in d:
                    d = d["result"]
                rec = d if "d" in d and "i" in d else record_from_rpc(d)
                rec = {
                    "i": int(rec["i"]),
                    "h": str(rec["h"]).upper(),
                    "d": str(rec["d"]).upper(),
                    "t": [[str(b), str(m)] for b, m in rec.get("t", [])],
                }
            except (ValueError, KeyError, TypeError, LookupError) as e:
                probs.append(f"staged line {ln}: unreadable ({type(e).__name__}: {e})")
                continue
            old = out.get(rec["i"])
            if old is not None and old != rec:
                probs.append(
                    f"staged line {ln}: ledger {rec['i']} appears twice with different content"
                )
            out[rec["i"]] = rec
    return out, probs


def rpc_records(url, a, b, rate, retries, lf=None):
    """Fetch a..b (validated, binary, expanded) from a read-only RPC -> ({index: record}, [problems], info)."""
    rpc = Rpc(url, rate)
    info = rpc.call("server_info")["info"]
    spans = hv.parse_ranges(info.get("complete_ledgers"))
    if not any(x <= a and b <= y for x, y in spans):
        return (
            {},
            [
                f"source does not hold {a}-{b} (complete_ledgers {info.get('complete_ledgers')})"
            ],
            info,
        )
    out, probs = {}, []
    for i in range(a, b + 1):
        for attempt in range(1, retries + 1):
            try:
                out[i] = record_from_rpc(
                    rpc.call(
                        "ledger",
                        {
                            "ledger_index": i,
                            "transactions": True,
                            "expand": True,
                            "binary": True,
                        },
                    )
                )
                break
            except (
                urllib.error.URLError,
                LookupError,
                KeyError,
                ValueError,
                OSError,
            ) as e:
                log(
                    lf,
                    f"RETRY ledger {i} attempt {attempt}/{retries}: {type(e).__name__}: {e}",
                )
                time.sleep(min(30, 2**attempt) if attempt < retries else 0)
        else:
            probs.append(
                f"ledger {i}: no answer from the source after {retries} attempts"
            )
    log(lf, f"source answered {len(out)}/{b - a + 1} ledgers in {rpc.count} requests")
    return out, probs, info


def check_fill(recs, a, b, below, above):
    """All checks a fill must pass before anything is written. Returns [problem strings]."""
    probs = []
    if below is None:
        probs.append(f"anchor: ledger {a - 1} (below the gap) is not in the archive")
    if above is None:
        probs.append(f"anchor: ledger {b + 1} (above the gap) is not in the archive")
    missing = [i for i in range(a, b + 1) if i not in recs]
    if missing:
        probs.append(
            f"source lacks {len(missing)} ledger(s) of the gap, first {missing[0]}"
        )
    extra = sorted(i for i in recs if not a <= i <= b)
    prev_h = below["h"] if below else None
    for i in range(a, b + 1):
        r = recs.get(i)
        if r is None:
            prev_h = None
            continue
        hdr, p = check_record(r)
        probs += [f"ledger {i}: {x}" for x in p]
        if r.get("i") != i:
            probs.append(f"ledger {i}: record says {r.get('i')}")
        if hdr is not None and prev_h is not None and hdr["parent_hash"] != prev_h:
            probs.append(
                f"ledger {i}: chain: parent {hdr['parent_hash'][:16]} != "
                f"{'anchor ' if i == a else ''}ledger {i - 1} {prev_h[:16]}"
            )
        prev_h = r.get("h")
    if above is not None and b in recs:
        up = parse_header(bytes.fromhex(above["d"]))
        if up["parent_hash"] != recs[b].get("h"):
            probs.append(
                f"anchor: archived ledger {b + 1} parent {up['parent_hash'][:16]} != filled ledger {b} "
                f"{str(recs[b].get('h'))[:16]}"
            )
    return probs, extra


def _own_like(path, ref):
    """Files fill-gap creates belong to the archive's owner (the follower), also when run as root."""
    if os.geteuid() == 0:
        st = os.stat(ref)
        os.chown(path, st.st_uid, st.st_gid)


def commit_fill(ar, a, b, gap, recs, below, above, source, lf=None, lock_timeout=60):
    """Write segments/fill-A-B.jsonl.gz + MANIFEST fill entry + gapfills.jsonl line, all-or-nothing."""
    name = f"fill-{a}-{b}"
    seg = os.path.join(ar.segments, f"{name}.jsonl.gz")
    raw = b"".join(canon(recs[i]).encode() + b"\n" for i in range(a, b + 1))
    gz = gzip.compress(raw, compresslevel=9, mtime=0)
    with archive_lock(ar.root, timeout=lock_timeout):
        entries = ar.manifest_entries()
        if any(
            e.get("kind") == "fill" and (e["first"], e["last"]) == (a, b)
            for e in entries
        ):
            raise FillRefused(
                f"gap {a}-{b} is already filled (MANIFEST has a fill entry)"
            )
        # leftovers of an interrupted run that never reached MANIFEST
        for p in (seg + ".tmp", seg):
            if os.path.exists(p):
                os.unlink(p)
                log(
                    lf,
                    f"RESUME removed {os.path.relpath(p, ar.root)} (no MANIFEST entry; fill is redone)",
                )
        with open(seg + ".tmp", "wb") as fh:
            fh.write(gz)
            fh.flush()
            os.fsync(fh.fileno())
        _own_like(seg + ".tmp", ar.root)
        os.replace(seg + ".tmp", seg)
        fsync_dir(ar.segments)
        prev = entries[-1] if entries else None
        entry = {
            "v": 1,
            "kind": "fill",
            "day": name,
            "segment": f"segments/{name}.jsonl.gz",
            "first": a,
            "last": b,
            "count": b - a + 1,
            "first_parent": parse_header(bytes.fromhex(recs[a]["d"]))["parent_hash"],
            "last_hash": recs[b]["h"],
            "txs": sum(len(recs[i].get("t", [])) for i in range(a, b + 1)),
            "bytes_raw": len(raw),
            "bytes_gz": len(gz),
            "sha256_raw": hashlib.sha256(raw).hexdigest(),
            "sha256_gz": hashlib.sha256(gz).hexdigest(),
            "sealed_utc": utcnow(),
            "gap": gap,
            "anchor_below": {"i": a - 1, "h": below["h"]},
            "anchor_above": {"i": b + 1, "h": above["h"]},
            "source": source,
            "tool": f"histarchive {VERSION}",
            "prev_entry": prev["entry"] if prev else None,
        }
        entry["entry"] = entry_hash(entry)
        append_line(ar.manifest, canon(entry))
        new_log = not os.path.exists(ar.gapfills)
        append_line(
            ar.gapfills,
            canon(
                {
                    "from": a,
                    "to": b,
                    "entry": entry["entry"],
                    "segment": entry["segment"],
                    "source": source.get("type"),
                    "at": entry["sealed_utc"],
                }
            ),
        )
        if new_log:
            _own_like(ar.gapfills, ar.root)
    log(
        lf,
        f"FILL {a}-{b} count={entry['count']} txs={entry['txs']} sha256_gz={entry['sha256_gz'][:16]} "
        f"entry={entry['entry'][:16]} source={source.get('type')}",
    )
    return entry


class FillRefused(Exception):
    pass


def repair_gapfills(ar, lf=None, lock_timeout=60):
    """Add gapfills.jsonl lines for fill entries a crash left without one (append-only)."""
    logged = {x.get("entry") for x in read_jsonl(ar.gapfills)}
    if all(e["entry"] in logged for e in fill_entries(ar)):
        return
    with archive_lock(ar.root, timeout=lock_timeout):
        logged = {x.get("entry") for x in read_jsonl(ar.gapfills)}
        for e in fill_entries(ar):
            if e["entry"] not in logged:
                append_line(
                    ar.gapfills,
                    canon(
                        {
                            "from": e["first"],
                            "to": e["last"],
                            "entry": e["entry"],
                            "segment": e["segment"],
                            "source": e["source"].get("type"),
                            "at": e["sealed_utc"],
                            "repaired": utcnow(),
                        }
                    ),
                )
                log(
                    lf,
                    f"RESUME gapfills.jsonl: added the missing line for fill {e['first']}-{e['last']}",
                )


def redact_url(url):
    """Provenance keeps scheme + host name only; IP literals and paths/credentials are dropped."""
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or ""
    except ValueError:
        return "<unparsable>"
    if host.replace(".", "").isdigit() or ":" in host or host in ("localhost",):
        host = (
            "<local>" if host in ("127.0.0.1", "localhost", "::1") else "<redacted-ip>"
        )
    return f"{u.scheme}://{host}"


def cmd_fill_gap(a):
    ar = Archive(a.dir)
    with open_log(a.log) as lf:
        try:
            lo, hi = (int(x) for x in a.gap.split("-", 1))
        except ValueError:
            print(f"ERROR: --gap wants FROM-TO, got {a.gap!r}", file=sys.stderr)
            return 3
        log(
            lf,
            f"histarchive {VERSION} fill-gap {lo}-{hi} source {'rpc ' + redact_url(a.rpc) if a.rpc else 'staged ' + os.path.basename(a.staged)}",
        )
        repair_gapfills(ar, lf, a.lock_timeout)
        gaps = ar.gap_ranges()
        if (lo, hi) not in gaps:
            log(
                lf,
                f"REFUSED: {lo}-{hi} is not a recorded gap (gaps.jsonl: {', '.join(f'{x}-{y}' for x, y in gaps) or 'none'}); nothing written",
            )
            return 1
        if (lo, hi) not in open_gaps(ar):
            log(
                lf,
                f"REFUSED: gap {lo}-{hi} is already filled (MANIFEST has a fill entry); nothing written",
            )
            return 1
        gap = next(
            g for g in read_jsonl(ar.gaps) if (int(g["from"]), int(g["to"])) == (lo, hi)
        )
        below, above = anchors(ar, lo, hi)
        log(
            lf,
            f"anchors: below {lo - 1} {'present ' + below['h'][:16] if below else 'MISSING'}; "
            f"above {hi + 1} {'present ' + above['h'][:16] if above else 'MISSING'}",
        )
        if a.rpc:
            recs, probs, info = rpc_records(a.rpc, lo, hi, a.rate, a.retries, lf)
            source = {
                "type": "rpc",
                "rpc": redact_url(a.rpc),
                "build_version": info.get("build_version"),
                "fetched_utc": utcnow(),
            }
        else:
            recs, probs = staged_records(a.staged)
            source = {
                "type": "staged",
                "file": os.path.basename(a.staged),
                "sha256": sha256_file(a.staged),
                "records": len(recs),
            }
        more, extra = check_fill(recs, lo, hi, below, above)
        probs += more
        if extra:
            log(
                lf,
                f"source also held {len(extra)} ledger(s) outside the gap ({extra[0]}..{extra[-1]}): used only as context, not written",
            )
            for i in (
                lo - 1,
                hi + 1,
            ):  # a staged copy of an anchor must equal the archived one
                anc = below if i == lo - 1 else above
                if i in recs and anc is not None and recs[i] != anc:
                    probs.append(
                        f"anchor: source copy of ledger {i} differs from the archived one"
                    )
        if probs:
            for p in probs[: a.max_lines]:
                log(lf, f"FAIL {p}")
            if len(probs) > a.max_lines:
                log(lf, f"FAIL ... {len(probs) - a.max_lines} more")
            log(lf, f"REFUSED: {len(probs)} check(s) failed; nothing written")
            return 1
        log(
            lf,
            f"checks: {hi - lo + 1} ledgers header+hash+txroot OK, chain {lo - 1}->{hi + 1} unbroken "
            f"({hi - lo + 2} links incl. both anchors)",
        )
        if a.dry_run:
            log(lf, "DRY RUN: every check passed; nothing written")
            return 0
        try:
            commit_fill(ar, lo, hi, gap, recs, below, above, source, lf, a.lock_timeout)
        except FillRefused as e:
            log(lf, f"REFUSED: {e}; nothing written")
            return 1
        return 0


def cmd_gaps(a):
    """List recorded gaps: open/filled, anchors, and (with --rpc) whether the source still holds them."""
    ar = Archive(a.dir)
    rows, info, src_ok = [], None, 1
    fills = {(e["first"], e["last"]): e for e in fill_entries(ar)}
    if a.rpc and any(
        g not in fills for g in ar.gap_ranges()
    ):  # ask only while a gap is open
        src_ok = 0
        try:
            info = Rpc(a.rpc, 1.0, timeout=15).call("server_info")["info"]
            src_ok = 1
        except (urllib.error.URLError, LookupError, KeyError, ValueError, OSError) as e:
            print(f"WARN source {redact_url(a.rpc)}: {type(e).__name__}: {e}")
    spans = hv.parse_ranges(info.get("complete_ledgers")) if info else []
    for g in read_jsonl(ar.gaps):
        lo, hi = int(g["from"]), int(g["to"])
        row = {
            "from": lo,
            "to": hi,
            "ledgers": hi - lo + 1,
            "reason": g.get("reason"),
            "at": g.get("at"),
        }
        fe = fills.get((lo, hi))
        if fe:
            row.update(
                state="filled",
                entry=fe["entry"],
                source=fe["source"].get("type"),
                filled_utc=fe["sealed_utc"],
            )
        else:
            below, above = anchors(ar, lo, hi)
            held = any(x <= lo and hi <= y for x, y in spans)
            row.update(
                state="open",
                anchor_below=below is not None,
                anchor_above=above is not None,
                source_holds=held if info else None,
                fillable=bool(below and above and held),
            )
        rows.append(row)
    if a.json:
        print(
            json.dumps(
                {
                    "gaps": rows,
                    "source": redact_url(a.rpc) if a.rpc else None,
                    "source_complete_ledgers": info.get("complete_ledgers")
                    if info
                    else None,
                },
                indent=1,
                sort_keys=True,
            )
        )
    else:
        for r in rows:
            if r["state"] == "filled":
                print(
                    f"FILLED {r['from']}-{r['to']} ({r['ledgers']}) by {r['source']} at {r['filled_utc']} entry {r['entry'][:16]}"
                )
            else:
                print(
                    f"OPEN   {r['from']}-{r['to']} ({r['ledgers']}) anchors {'ok' if r['anchor_below'] and r['anchor_above'] else 'MISSING'} "
                    f"source {'holds it' if r['source_holds'] else ('lacks it' if info else 'not asked')} "
                    f"-> {'FILLABLE' if r['fillable'] else 'not fillable'} | {r['reason']}"
                )
        n_open = sum(r["state"] == "open" for r in rows)
        print(
            f"RESULT: gaps {len(rows)} open {n_open} filled {len(rows) - n_open} "
            f"fillable {sum(bool(r.get('fillable')) for r in rows)}"
        )
    if a.textfile:
        write_prom(
            a.textfile,
            [
                (
                    "pft_histarchive_gap_open",
                    "recorded gaps not filled yet",
                    sum(r["state"] == "open" for r in rows),
                ),
                (
                    "pft_histarchive_gap_fillable",
                    "open gaps a fill-gap run could repair now (both anchors archived, source holds the range)",
                    sum(bool(r.get("fillable")) for r in rows),
                ),
                (
                    "pft_histarchive_gap_source_up",
                    "1 if the fill source answered server_info (or was not needed: no open gap)",
                    src_ok,
                ),
                (
                    "pft_histarchive_gap_check_timestamp_seconds",
                    "unix time of the last gaps check",
                    int(time.time()),
                ),
            ],
            a.host,
        )
    return 0


# ---------------------------------------------------------------- seal / status


def cmd_seal(a):
    ar = Archive(a.dir)
    days = ar.active_days()
    todo = days if a.all else days[:-1]
    for day in todo:
        seal_day(ar, day)
    print(
        f"sealed {len(todo)} day(s); active now: {', '.join(ar.active_days()) or 'none'}"
    )
    return 0


def cmd_status(a):
    ar = Archive(a.dir)
    st = {}
    if os.path.exists(ar.status):
        with open(ar.status) as fh:
            st = json.load(fh)
    entries = ar.manifest_entries()
    out = {
        "status": st,
        "segments": len(entries),
        "head_entry": entries[-1]["entry"] if entries else None,
        "active_days": ar.active_days(),
        "gaps": len(ar.gap_ranges()),
        "gaps_open": len(open_gaps(ar)),
    }
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


# ---------------------------------------------------------------- replica manifest


def cmd_cipher_index(a):
    """sha256 of every *.age file in a replica dir (what a host without the identity can check)."""
    rows = {}
    for f in sorted(os.listdir(a.dir)):
        if f.endswith(".age"):
            rows[f] = sha256_file(os.path.join(a.dir, f))
    print(canon(rows))
    return 0


def cmd_replica_check(a):
    """Compare a replica's REPLICA.json (expected cipher sha256s) with its files. 0 ok, 1 mismatch."""
    with open(os.path.join(a.dir, "REPLICA.json")) as fh:
        want = json.load(fh)
    fails = []
    have = {f for f in os.listdir(a.dir) if f.endswith(".age")}
    for name, sha in sorted(want["files"].items()):
        p = os.path.join(a.dir, name)
        if name not in have:
            fails.append(f"{name}: missing on replica")
        elif sha256_file(p) != sha:
            fails.append(f"{name}: sha256 differs from REPLICA.json")
    for name in sorted(have - set(want["files"])):
        fails.append(f"{name}: not listed in REPLICA.json")
    for f in fails:
        print(f"FAIL {f}")
    print(
        f"RESULT: {'PASS' if not fails else 'FAIL'} - replica files {len(want['files'])} "
        f"head_entry {str(want.get('head_entry'))[:16]} fails {len(fails)}"
    )
    return 0 if not fails else 1


def cmd_replica_compare(a):
    """Local REPLICA.json vs the peer's `serve index` JSON on stdin. 0 same, 1 differs."""
    with open(a.local) as fh:
        want = json.load(fh)
    got = json.loads(sys.stdin.read())
    rep, cipher = got.get("replica") or {}, got.get("cipher") or {}
    fails = []
    if rep.get("head_entry") != want.get("head_entry"):
        fails.append(
            f"peer REPLICA.json head_entry {str(rep.get('head_entry'))[:16]} != local {str(want.get('head_entry'))[:16]}"
        )
    for name, sha in sorted(want["files"].items()):
        if name not in cipher:
            fails.append(f"{name}: missing on the peer")
        elif cipher[name] != sha:
            fails.append(f"{name}: peer sha256 differs from the local encrypted copy")
    for name in sorted(set(cipher) - set(want["files"])):
        fails.append(f"{name}: on the peer but not in the local REPLICA.json")
    if got.get("check_rc") != 0:
        fails.append(
            f"peer replica-check rc {got.get('check_rc')}: {str(got.get('check', '')).strip()[-200:]}"
        )
    for f in fails:
        print(f"FAIL {f}")
    print(
        f"RESULT: {'PASS' if not fails else 'FAIL'} - local files {len(want['files'])}, "
        f"peer files {len(cipher)}, fails {len(fails)}"
    )
    return 0 if not fails else 1


# ---------------------------------------------------------------- public-RPC crosscheck


def iter_records(root):
    ar = Archive(root)
    for e in ar.manifest_entries():
        _gz, raw = read_segment(os.path.join(root, e["segment"]))
        for x in raw.split(b"\n"):
            if x.strip():
                yield json.loads(x)
    for day in ar.active_days():
        with open(ar.active_path(day), "rb") as fh:
            for x in fh:
                if x.strip():
                    yield json.loads(x)


def cmd_crosscheck(a):
    """Seeded sample of archived ledgers vs a public RPC: ledger hash, tx count and tx ID set."""
    recs = {r["i"]: r for r in iter_records(a.dir)}
    if a.offline:
        answers = {int(x["i"]): x for x in read_jsonl(a.offline)}
        print(f"offline: {len(answers)} recorded public answers from {a.offline}")
    else:
        rpc = Rpc(a.rpc, a.rate, timeout=20)
        info = rpc.call("server_info")["info"]
        spans = hv.parse_ranges(info.get("complete_ledgers"))
        print(
            f"public RPC {a.rpc}: build {info.get('build_version')} complete_ledgers {info.get('complete_ledgers')}"
        )
    pool = sorted(recs)
    if not a.offline:
        pool = [i for i in pool if any(x <= i <= y for x, y in spans)]
        print(
            f"archived ledgers {len(recs)}; checkable (inside public complete_ledgers) {len(pool)}"
        )
    busy = [i for i in pool if recs[i]["t"]]
    idle = [i for i in pool if not recs[i]["t"]]
    rnd = random.Random(a.seed)
    k_busy = min(len(busy), (a.sample * 4 + 4) // 5)
    pick = sorted(
        rnd.sample(busy, k_busy) + rnd.sample(idle, min(len(idle), a.sample - k_busy))
    )
    print(
        f"seed {a.seed}: sample {len(pick)} (with txs {k_busy}, without {len(pick) - k_busy})"
    )
    if not pick:
        print("RESULT: IMPOSSIBLE - nothing to check")
        return 2
    with open(a.record, "w") if a.record else contextlib.nullcontext() as rec_fh:
        return crosscheck_loop(
            a,
            pick,
            recs,
            answers if a.offline else None,
            None if a.offline else rpc,
            rec_fh,
        )


def crosscheck_loop(a, pick, recs, answers, rpc, rec_fh):
    ok = bad = 0
    for k, i in enumerate(pick):
        r = recs[i]
        mine_ids = sorted(tx_ids(r))
        if a.offline:
            ans = answers.get(i)
            if ans is None:
                print(f"MISSING {i} no recorded answer")
                bad += 1
                continue
        else:
            ans = None
            for attempt in range(1, a.retries + 1):
                try:
                    res = rpc.call("ledger", {"ledger_index": i, "transactions": True})
                    led = res["ledger"]
                    if not res.get("validated"):
                        raise LookupError("not validated")
                    ans = {
                        "i": i,
                        "h": str(led["ledger_hash"]).upper(),
                        "ids": sorted(
                            str(t).upper() for t in led.get("transactions") or []
                        ),
                    }
                    break
                except (
                    urllib.error.URLError,
                    LookupError,
                    KeyError,
                    ValueError,
                    OSError,
                ) as e:
                    print(
                        f"RETRY {i} attempt {attempt}/{a.retries}: {type(e).__name__}: {e}"
                    )
                    time.sleep(min(30, 2**attempt))
            if ans is None:
                print(
                    f"UNCHECKED {i} public RPC gave no answer after {a.retries} attempts"
                )
                bad += 1
                continue
            if rec_fh:
                rec_fh.write(canon(ans) + "\n")
        if a.negative and k % 2 == 0:  # even picks: hash altered, tx IDs as answered
            ans = dict(ans, h=ans["h"][:-1] + ("0" if ans["h"][-1] != "0" else "1"))
        elif a.negative:  # odd picks: only the tx ID list altered
            ans = dict(ans, ids=ans["ids"] + ["NEG"])
        same = ans["h"] == r["h"] and ans["ids"] == mine_ids
        print(
            f"{'MATCH' if same else 'MISMATCH'} {i} hash {'same' if ans['h'] == r['h'] else 'differ'} "
            f"({r['h'][:16]} vs {ans['h'][:16]}..{ans['h'][-4:]}) "
            f"txs {len(mine_ids)} vs {len(ans['ids'])} ids {'same' if ans['ids'] == mine_ids else 'differ'}"
        )
        ok += same
        bad += not same
    print(
        f"RESULT: {'PASS' if bad == 0 else 'FAIL'} - {ok}/{len(pick)} MATCH, {bad} not matching"
    )
    return 0 if bad == 0 else 1


# ---------------------------------------------------------------- main


def main(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("follow", help="follow validated ledgers into the archive")
    f.add_argument("--dir", required=True)
    f.add_argument("--rpc", default="http://127.0.0.1:5005/")
    f.add_argument("--rate", type=float, default=4.0, help="max requests/s (default 4)")
    f.add_argument(
        "--start",
        type=int,
        default=None,
        help="first ledger of a NEW archive (default: validated)",
    )
    f.add_argument("--stop-at", type=int, default=None)
    f.add_argument(
        "--until",
        default=None,
        help="stop at this UTC time (YYYY-MM-DDTHH:MM:SSZ); same value across restarts",
    )
    f.add_argument(
        "--hours", type=float, default=None, help="stop this run after H hours"
    )
    f.add_argument("--retries", type=int, default=3)
    f.add_argument("--retry-sleep", type=float, default=2.0)
    f.add_argument("--poll", type=float, default=1.0)
    f.add_argument(
        "--progress", type=float, default=3600.0, help="seconds between PROGRESS lines"
    )
    f.add_argument("--log", default=None)

    v = sub.add_parser("verify", help="offline full verification of an archive dir")
    v.add_argument("--dir", required=True)
    v.add_argument("--json", action="store_true")
    v.add_argument(
        "--sealed-only",
        action="store_true",
        help="skip active/ (e.g. a restored replica)",
    )
    v.add_argument(
        "--textfile", default=None, help="also write Prometheus metrics here"
    )
    v.add_argument(
        "--host",
        default="validator",
        help="host label for the textfile (default validator)",
    )
    v.add_argument("--max-lines", type=int, default=50)

    s = sub.add_parser("seal", help="seal finished days (all active days with --all)")
    s.add_argument("--dir", required=True)
    s.add_argument("--all", action="store_true")

    st = sub.add_parser("status")
    st.add_argument("--dir", required=True)

    ci = sub.add_parser(
        "cipher-index", help="sha256 of every *.age file in a dir (JSON)"
    )
    ci.add_argument("--dir", required=True)

    rcmp = sub.add_parser(
        "replica-compare", help="local REPLICA.json vs a peer index (stdin)"
    )
    rcmp.add_argument("--local", required=True)

    rc = sub.add_parser(
        "replica-check", help="check a replica dir against its REPLICA.json"
    )
    rc.add_argument("--dir", required=True)

    c = sub.add_parser(
        "crosscheck", help="seeded sample vs a public RPC (or a recorded answer file)"
    )
    c.add_argument("--dir", required=True)
    c.add_argument("--rpc", default="https://rpc.testnet.postfiat.org/")
    c.add_argument("--rate", type=float, default=1.0)
    c.add_argument("--seed", type=int, default=20261110)
    c.add_argument("--sample", type=int, default=50)
    c.add_argument("--retries", type=int, default=4)
    c.add_argument(
        "--record", default=None, help="save the public answers (JSONL) for --offline"
    )
    c.add_argument(
        "--offline",
        default=None,
        help="re-check against a recorded answer file, no RPC",
    )
    c.add_argument(
        "--negative",
        action="store_true",
        help="alter every public answer: must all MISMATCH",
    )

    fg = sub.add_parser(
        "fill-gap",
        help="repair one recorded gap from a read-only RPC or a staged capture (verified, all-or-nothing)",
    )
    fg.add_argument("--dir", required=True)
    fg.add_argument(
        "--gap", required=True, help="FROM-TO exactly as recorded in gaps.jsonl"
    )
    src = fg.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--rpc", default=None, help="read-only JSON-RPC that still holds the range"
    )
    src.add_argument(
        "--staged",
        default=None,
        help="JSONL capture (ledger answers or archive records)",
    )
    fg.add_argument("--rate", type=float, default=2.0)
    fg.add_argument("--retries", type=int, default=4)
    fg.add_argument("--lock-timeout", type=float, default=60.0)
    fg.add_argument(
        "--dry-run", action="store_true", help="run every check, write nothing"
    )
    fg.add_argument("--log", default=None)
    fg.add_argument("--max-lines", type=int, default=50)

    gp = sub.add_parser(
        "gaps", help="list recorded gaps: open/filled, anchors, fillable from --rpc"
    )
    gp.add_argument("--dir", required=True)
    gp.add_argument("--rpc", default=None)
    gp.add_argument("--json", action="store_true")
    gp.add_argument("--textfile", default=None)
    gp.add_argument("--host", default="validator")

    a = p.parse_args(argv)
    if getattr(a, "rate", 1.0) > RATE_CAP:
        p.error(f"--rate above {RATE_CAP:g} req/s is not allowed")
    try:
        return {
            "follow": cmd_follow,
            "verify": cmd_verify,
            "seal": cmd_seal,
            "status": cmd_status,
            "cipher-index": cmd_cipher_index,
            "replica-check": cmd_replica_check,
            "replica-compare": cmd_replica_compare,
            "crosscheck": cmd_crosscheck,
            "fill-gap": cmd_fill_gap,
            "gaps": cmd_gaps,
        }[a.cmd](a)
    except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError) as e:
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
