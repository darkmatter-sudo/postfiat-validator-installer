#!/usr/bin/env python3
"""Alertmanager webhook -> ntfy bridge (stdlib only, listens on 127.0.0.1).

Logs one line per alert in every webhook (status, alertname, severity, startsAt, endsAt).
If NTFY_URL (e.g. https://ntfy.sh/<topic>) is set (directly or via a file named by NTFY_URL_FILE), also posts to ntfy:
critical -> priority high, resolved -> priority low. NTFY_URL is never logged.

One message per state change: Alertmanager re-sends every alert of a group whenever the group changes and again
after repeat_interval, so the bridge remembers the last status it sent per alert fingerprint and forwards only
transitions (firing -> resolved, resolved -> firing, first sight). Transitions of the same alertname + status in one
webhook are folded into ONE message ("[FIRING] PFTJobFailed x27"), so a burst of series cannot fan out into a
burst of phone notifications. The memory lives in the process: after a bridge restart an alert that is still
firing is sent once more.
"""

import json
import os
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

ADDR = os.environ.get("BRIDGE_ADDR", "127.0.0.1")
PORT = int(os.environ.get("BRIDGE_PORT", "9095"))
MAX_LINES = 8  # summaries listed in a folded message
FORGET_S = 24 * 3600  # resolved fingerprints are forgotten after this long


def ntfy_url():
    """NTFY_URL from the file named by NTFY_URL_FILE (a mounted NTFY_URL=... file), else the environment.

    The file keeps the topic out of `docker inspect` output.
    """
    path = os.environ.get("NTFY_URL_FILE", "")
    if path:
        with open(path) as f:
            for line in f:
                if line.startswith("NTFY_URL="):
                    return line.split("=", 1)[1].strip()
        return ""
    return os.environ.get("NTFY_URL", "")


NTFY_URL = ntfy_url()


def log(msg):
    print(msg, flush=True)


def fingerprint(alert):
    """Alertmanager's fingerprint; falls back to the sorted label set."""
    return alert.get("fingerprint") or json.dumps(
        alert.get("labels", {}), sort_keys=True
    )


class Dedup:
    """Last status sent per fingerprint; picks the alerts of a webhook that changed state."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.sent = {}  # fingerprint -> (status, time)

    def changed(self, alerts):
        now = self.clock()
        for fp, (st, t) in list(self.sent.items()):
            if st == "resolved" and now - t > FORGET_S:
                del self.sent[fp]
        out = []
        for a in alerts:
            st = a.get("status", "?")
            fp = fingerprint(a)
            prev = self.sent.get(fp, (None, 0))[0]
            if prev == st:
                continue
            self.sent[fp] = (st, now)
            out.append(a)
        return out


def messages(alerts):
    """Fold alerts into one message per (status, alertname): [(title, body, priority)], in first-seen order."""
    groups = {}
    for a in alerts:
        lb = a.get("labels", {})
        key = (a.get("status", "?"), lb.get("alertname", "?"))
        groups.setdefault(key, []).append(a)
    out = []
    for (st, name), items in groups.items():
        crit = any(i.get("labels", {}).get("severity") == "critical" for i in items)
        prio = "low" if st == "resolved" else ("high" if crit else "default")
        lines = []
        for i in items:
            s = i.get("annotations", {}).get("summary", name)
            if s not in lines:
                lines.append(s)
        title = f"[{st.upper()}] {name}"
        if len(items) > 1:
            title += f" x{len(items)}"
        body = "\n".join(lines[:MAX_LINES])
        if len(lines) > MAX_LINES:
            body += f"\n... and {len(lines) - MAX_LINES} more"
        out.append((title, body, prio))
    return out


def ntfy(title, body, prio):
    req = urllib.request.Request(
        NTFY_URL,
        data=body.encode(),
        headers={"Title": title, "Priority": prio, "Tags": "rotating_light"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            log(f"ntfy {title} -> HTTP {r.status}")
    except Exception as e:  # noqa: BLE001 - never crash the webhook on delivery errors
        log(f"ntfy {title} -> ERROR {type(e).__name__}")


DEDUP = Dedup()


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(n))
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        alerts = payload.get("alerts", [])
        for a in alerts:
            lb = a.get("labels", {})
            log(
                "webhook status={} alertname={} severity={} startsAt={} endsAt={}".format(
                    a.get("status", "?"),
                    lb.get("alertname"),
                    lb.get("severity"),
                    a.get("startsAt"),
                    a.get("endsAt"),
                )
            )
        new = DEDUP.changed(alerts)
        if len(new) < len(alerts):
            log(
                f"dedup: {len(alerts) - len(new)} of {len(alerts)} alert(s) unchanged since last send, not forwarded"
            )
        if NTFY_URL:
            for title, body, prio in messages(new):
                ntfy(title, body, prio)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    log(f"bridge listening on {ADDR}:{PORT} ntfy={'on' if NTFY_URL else 'off'}")
    sys.stdout.flush()
    HTTPServer((ADDR, PORT), H).serve_forever()
