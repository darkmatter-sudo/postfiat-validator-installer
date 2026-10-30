#!/usr/bin/env python3
"""Stub Prometheus HTTP API for the pft-rulecheck tests (127.0.0.1, random port).

  stub_prom.py FIXTURE.json PORTFILE QUERYLOG
FIXTURE: {"groups": [...rule groups as /api/v1/rules returns them...],
          "series": {"<selector text>": <count>, ...},          # missing selector = 0 series
          "mode": "ok" | "rules_error" | "query_error" | "http500" | "garbage" | "bad_sample"}
Only /api/v1/rules and /api/v1/query?query=count(last_over_time(SEL[LB])) are served; every query is appended
to QUERYLOG. The fixture is re-read on every request, so a test can switch modes without a restart.
"""
import json
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

FIX, PORTFILE, QLOG = sys.argv[1:4]
Q_RE = re.compile(r"^count\(last_over_time\((.*)\[(\d+[smhd])\]\)\)$", re.S)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        with open(FIX, encoding="utf-8") as fh:
            fx = json.load(fh)
        mode = fx.get("mode", "ok")
        u = urllib.parse.urlparse(self.path)
        if mode == "http500":
            return self.send(500, b"internal error")
        if mode == "garbage":
            return self.send(200, b"<html>not json</html>")
        if u.path == "/api/v1/rules":
            if mode == "rules_error":
                return self.send(503, {"status": "error", "errorType": "unavailable",
                                       "error": "rule manager not ready"})
            return self.send(200, {"status": "success", "data": {"groups": fx.get("groups", [])}})
        if u.path == "/api/v1/query":
            q = urllib.parse.parse_qs(u.query).get("query", [""])[0]
            with open(QLOG, "a", encoding="utf-8") as fh:
                fh.write(q + "\n")
            if mode == "query_error":
                return self.send(400, {"status": "error", "errorType": "bad_data", "error": "parse error"})
            m = Q_RE.match(q)
            if not m:
                return self.send(400, {"status": "error", "errorType": "bad_data", "error": "stub: unexpected query"})
            n = fx.get("series", {}).get(m.group(1), 0)
            if mode == "bad_sample":
                return self.send(200, {"status": "success", "data": {"resultType": "vector",
                                                                     "result": [{"metric": {}, "value": [0]}]}})
            res = [{"metric": {}, "value": [1793340000, str(n)]}] if n else []
            return self.send(200, {"status": "success", "data": {"resultType": "vector", "result": res}})
        return self.send(404, {"status": "error", "error": "not found"})


srv = HTTPServer(("127.0.0.1", 0), H)
with open(PORTFILE + ".tmp", "w") as fh:
    fh.write(str(srv.server_address[1]))
os.replace(PORTFILE + ".tmp", PORTFILE)
srv.serve_forever()
