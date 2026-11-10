"""Independent recompute of Post Fiat (XRPL-family) ledger hashes, tx IDs and tx-tree roots.

Python 3 stdlib only. Nothing here trusts an RPC-reported hash: every value is rebuilt from the
serialized bytes and only then compared with what the server says.

Serialization (postfiatd 1.0.9 = rippled ledger format; HashPrefix values from
include/xrpl/protocol/HashPrefix.h, 3 ASCII bytes + 0x00):

  ledger hash  SHA-512Half("LWR\\0" || header)
               header = ledger_index u32 | total_coins u64 | parent_hash 32 | transaction_hash 32 |
                        account_hash 32 | parent_close_time u32 | close_time u32 |
                        close_time_resolution u8 | close_flags u8          (big-endian, 118 bytes)
  tx ID        SHA-512Half("TXN\\0" || tx_blob)
  tx leaf      SHA-512Half("SND\\0" || VL(tx_blob) || tx_blob || VL(meta) || meta || txID)
  inner node   SHA-512Half("MIN\\0" || child_0 || ... || child_15)   (empty child = 32 zero bytes)
  tx root      the root is always an inner node; a leaf sits at the shallowest depth (>= 1) where
               its key's nibble path is unique; a ledger without transactions has root = 32 zeros.

SHA-512Half = the first 32 bytes of SHA-512.
"""

import hashlib
import struct

PREFIX_LEDGER = b"LWR\x00"
PREFIX_TXID = b"TXN\x00"
PREFIX_TXNODE = b"SND\x00"
PREFIX_INNER = b"MIN\x00"
ZERO = bytes(32)
HEADER_BYTES = 118


def sha512half(*parts):
    return hashlib.sha512(b"".join(parts)).digest()[:32]


def h256(hexstr, name):
    b = bytes.fromhex(hexstr)
    if len(b) != 32:
        raise ValueError(f"{name}: expected 32 bytes, got {len(b)}")
    return b


def serialize_header(led):
    """118-byte ledger header from the JSON fields of a `ledger` answer."""
    return (
        struct.pack(">IQ", int(led["ledger_index"]), int(led["total_coins"]))
        + h256(led["parent_hash"], "parent_hash")
        + h256(led["transaction_hash"], "transaction_hash")
        + h256(led["account_hash"], "account_hash")
        + struct.pack(
            ">IIBB",
            int(led["parent_close_time"]),
            int(led["close_time"]),
            int(led["close_time_resolution"]),
            int(led["close_flags"]),
        )
    )


def ledger_hash(led):
    """Upper-case hex ledger hash recomputed from the JSON header fields."""
    return sha512half(PREFIX_LEDGER, serialize_header(led)).hex().upper()


def vl_prefix(n):
    """XRPL variable-length prefix (1-3 bytes) for a blob of n bytes."""
    if n < 0:
        raise ValueError("negative length")
    if n <= 192:
        return bytes([n])
    if n <= 12480:
        n -= 193
        return bytes([193 + (n >> 8), n & 0xFF])
    if n <= 918744:
        n -= 12481
        return bytes([241 + (n >> 16), (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError(f"VL length {n} too large")


def tx_id(tx_blob):
    return sha512half(PREFIX_TXID, tx_blob)


def tx_leaf_hash(tx_blob, meta, key):
    return sha512half(PREFIX_TXNODE, vl_prefix(len(tx_blob)), tx_blob, vl_prefix(len(meta)), meta, key)


def nibble(key, depth):
    b = key[depth // 2]
    return (b >> 4) if depth % 2 == 0 else (b & 0x0F)


def shamap_root(leaves):
    """Root hash of a SHAMap given {key(32 bytes): leaf_hash(32 bytes)}."""

    def node(keys, depth):
        if not keys:
            return ZERO
        if len(keys) == 1 and depth > 0:
            return leaves[keys[0]]
        kids = [[] for _ in range(16)]
        for k in keys:
            kids[nibble(k, depth)].append(k)
        return sha512half(PREFIX_INNER, *(node(c, depth + 1) for c in kids))

    return node(list(leaves), 0)


def tx_tree(txs):
    """(root hex, [tx ID hex]) from a binary `ledger` answer's transactions [{tx_blob, meta}]."""
    leaves, ids = {}, []
    for t in txs:
        blob, meta = bytes.fromhex(t["tx_blob"]), bytes.fromhex(t["meta"])
        k = tx_id(blob)
        if k in leaves:
            raise ValueError(f"duplicate tx ID {k.hex().upper()}")
        leaves[k] = tx_leaf_hash(blob, meta, k)
        ids.append(k.hex().upper())
    return shamap_root(leaves).hex().upper(), ids


def parse_ranges(text):
    """complete_ledgers "a-b,c,d-e" -> [(a, b), (c, c), (d, e)]."""
    spans = []
    for part in str(text or "").split(","):
        a, _, b = part.strip().partition("-")
        if a.isdigit():
            spans.append((int(a), int(b or a)))
    return spans


def overlap(ranges_a, ranges_b):
    """Largest contiguous span present in both range lists, or None."""
    best = None
    for a0, a1 in ranges_a:
        for b0, b1 in ranges_b:
            lo, hi = max(a0, b0), min(a1, b1)
            if lo <= hi and (best is None or hi - lo > best[1] - best[0]):
                best = (lo, hi)
    return best
