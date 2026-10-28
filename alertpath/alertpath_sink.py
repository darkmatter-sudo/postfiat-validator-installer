#!/usr/bin/env python3
"""alertpath sink: loopback webhook receiver for the PFTAlertPipelineWatchdog alert (stdlib only).

Alertmanager's "alertpath" route posts the always-firing watchdog here (127.0.0.1:9096/watchdog) about once a
minute. Each delivery that contains the watchdog alert rewrites STATE_DIR/last.json atomically:
  {"v":1, "received":<unix>, "count":<deliveries since start>, "status":"firing"|"resolved", "startsAt":...}
`pft-alertpath push` reads that file, so the sentry can tell how long ago the pipeline last delivered.
A delivery without the watchdog alert (a mis-route) is answered 200 but counted in "unexpected" and logged,
so it can't hide a routing mistake. Nothing is forwarded anywhere; no topic, no secrets.
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ADDR = os.environ.get("SINK_ADDR", "127.0.0.1")
PORT = int(os.environ.get("SINK_PORT", "9096"))
STATE_DIR = os.environ.get("STATE_DIRECTORY", os.environ.get("STATE_DIR", "/var/lib/pft-alertpath"))
MAX_BODY = 1 << 20
WATCHDOG = "PFTAlertPipelineWatchdog"

counts = {"count": 0, "unexpected": 0}


def log(msg):
    print(msg, flush=True)


def write_state(rec):
    path = os.path.join(STATE_DIR, "last.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


class H(BaseHTTPRequestHandler):
    def reply(self, code):
        self.send_response(code)
        self.end_headers()

    def do_POST(self):
        if self.path != "/watchdog":
            return self.reply(404)
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0 or n > MAX_BODY:
            return self.reply(400)
        try:
            payload = json.loads(self.rfile.read(n))
            alerts = payload.get("alerts", [])
        except (ValueError, AttributeError):
            return self.reply(400)
        wd = [a for a in alerts if a.get("labels", {}).get("alertname") == WATCHDOG]
        if not wd:
            counts["unexpected"] += 1
            names = sorted({a.get("labels", {}).get("alertname", "?") for a in alerts})
            log("unexpected delivery without %s: %s" % (WATCHDOG, ",".join(names)))
        else:
            counts["count"] += 1
            a = wd[0]
            rec = {"v": 1, "received": int(time.time()), "count": counts["count"],
                   "unexpected": counts["unexpected"], "status": a.get("status", "?"),
                   "startsAt": a.get("startsAt", "")}
            try:
                write_state(rec)
            except OSError as e:
                log("state write failed: %s" % type(e).__name__)
                return self.reply(500)
            log("delivery %d status=%s" % (rec["count"], rec["status"]))
        return self.reply(200)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    log("alertpath sink listening on %s:%d state=%s" % (ADDR, PORT, STATE_DIR))
    sys.stdout.flush()
    HTTPServer((ADDR, PORT), H).serve_forever()
