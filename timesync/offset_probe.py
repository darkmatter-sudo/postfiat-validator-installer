#!/usr/bin/env python3
"""Independent clock-offset probe (SNTP, RFC 4330 client mode), read-only.

Measures this host's clock against several public NTP servers once per interval,
independent of whichever daemon (timesyncd or chrony) disciplines the clock, so
the before and after windows are measured the same way.

  offset_probe.py --out FILE.csv --duration SEC [--interval SEC] [--server HOST ...]

CSV columns: utc, server, ok, offset_ms, delay_ms, stratum, error
offset > 0 means the local clock is BEHIND the server.
"""
import argparse
import csv
import os
import socket
import struct
import sys
import time

NTP_EPOCH = 2208988800  # 1900-01-01 -> 1970-01-01
DEFAULT_SERVERS = ["time.cloudflare.com", "ptbtime1.ptb.de", "time.google.com"]


def ntp_to_unix(sec, frac):
    return sec - NTP_EPOCH + frac / 2**32


def query(server, timeout=3.0):
    """Return (offset_s, delay_s, stratum) for one SNTP exchange."""
    addr = socket.getaddrinfo(server, 123, proto=socket.IPPROTO_UDP)[0]
    with socket.socket(addr[0], socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t1 = time.time()
        sec = int(t1) + NTP_EPOCH
        frac = int((t1 % 1) * 2**32)
        # LI=0 VN=4 Mode=3 (client); transmit timestamp = t1 (echoed back as origin)
        pkt = struct.pack("!B39xII", 0x23, sec, frac)
        s.sendto(pkt, addr[4])
        data, _ = s.recvfrom(512)
        t4 = time.time()
    if len(data) < 48:
        raise ValueError("short reply (%d bytes)" % len(data))
    first, stratum = data[0], data[1]
    mode, li = first & 7, first >> 6
    osec, ofrac = struct.unpack("!II", data[24:32])
    if mode != 4:
        raise ValueError("not a server reply (mode %d)" % mode)
    if stratum == 0:
        raise ValueError("kiss-o'-death %r" % data[12:16])
    if li == 3:
        raise ValueError("server unsynchronized (LI=3)")
    if (osec, ofrac) != (sec, frac):
        raise ValueError("origin timestamp mismatch")
    t2 = ntp_to_unix(*struct.unpack("!II", data[32:40]))
    t3 = ntp_to_unix(*struct.unpack("!II", data[40:48]))
    offset = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)
    return offset, delay, stratum


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=int, required=True, help="seconds")
    ap.add_argument("--interval", type=int, default=60)
    ap.add_argument("--server", action="append")
    a = ap.parse_args()
    servers = a.server or DEFAULT_SERVERS
    new = not os.path.exists(a.out) or os.path.getsize(a.out) == 0
    end = time.monotonic() + a.duration
    with open(a.out, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["utc", "server", "ok", "offset_ms", "delay_ms", "stratum", "error"])
        while True:
            tick = time.monotonic()
            for srv in servers:
                utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                try:
                    off, dly, st = query(srv)
                    w.writerow([utc, srv, 1, "%.3f" % (off * 1e3), "%.3f" % (dly * 1e3), st, ""])
                except Exception as e:  # recorded, never fatal
                    w.writerow([utc, srv, 0, "", "", "", type(e).__name__ + ": " + str(e)[:80]])
            f.flush()
            os.fsync(f.fileno())
            if time.monotonic() + a.interval > end:
                break
            time.sleep(max(0, a.interval - (time.monotonic() - tick)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
