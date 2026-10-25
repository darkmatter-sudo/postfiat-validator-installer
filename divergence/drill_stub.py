#!/usr/bin/env python3
"""Loopback JSON-RPC stub for the pft-divergence alert drill.

Forwards every POST to UPSTREAM (default the public RPC). While FLAG exists, answers to `ledger` get a wrong
ledger_hash (every hex digit rotated by one); otherwise answers pass through unchanged.
Usage: python3 drill_stub.py --port 18559 --flag /run/pft-div-drill/wrong [--upstream URL]
"""
import argparse
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HEX = "0123456789ABCDEF"


def wrong(h):
    return "".join(HEX[(HEX.index(c) + 1) % 16] for c in h)


def rewrite(body, answer):
    if json.loads(body).get("method") != "ledger":
        return answer
    j = json.loads(answer)
    r = j.get("result", {})
    if isinstance(r.get("ledger"), dict) and "ledger_hash" in r["ledger"]:
        r["ledger"]["ledger_hash"] = wrong(r["ledger"]["ledger_hash"])
        if "ledger_hash" in r:
            r["ledger_hash"] = r["ledger"]["ledger_hash"]
    return json.dumps(j).encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18559)
    ap.add_argument("--flag", required=True)
    ap.add_argument("--upstream", default="https://rpc.testnet.postfiat.org/")
    a = ap.parse_args()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            req = urllib.request.Request(a.upstream, data=body, headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    answer = r.read()
                if os.path.exists(a.flag):
                    answer = rewrite(body, answer)
                code = 200
            except (OSError, ValueError):
                answer, code = b"", 502
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

        def log_message(self, *args):
            pass

    HTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
