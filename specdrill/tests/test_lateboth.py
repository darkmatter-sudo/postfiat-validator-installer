"""drill/lateboth.sh against a stub Prometheus: natural cross-host lateness vs a real disagreement (run 14 lesson)."""

import http.server
import json
import os
import subprocess
import threading
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "drill", "lateboth.sh")
V = "nHBmj7zUY2yMc9f5wgNcCuWj79BUieNmc1GG8PqiEP1tgNZZWLVM"
T0 = 1795292733  # run 14: the one pending eval of PFTValwatchHostsDisagreeLate (20:25:33Z)


def vec(metric, values):
    return {"metric": metric, "values": [[t, str(v)] for t, v in values]}


def alerts(evals, node="postfiatd"):
    m = {"__name__": "ALERTS", "alertname": "PFTValwatchHostsDisagreeLate", "alertstate": "pending"}
    return [vec({**m, "node": node, "validator": V}, [(t, 1) for t in evals])] if evals else []


def delays(val, sen):
    m = {"__name__": "pft_valwatch_validator_delay_p95_ms", "validator": V}
    return [vec({**m, "node": "postfiatd"}, val), vec({**m, "node": "postfiatd-sentry"}, sen)]


# run 14 shape (14-outside-attribution.log): the validator sample jumps at 20:25:33Z, the sentry 15 s later
RUN14_VAL = [(T0 - 15, 1396), (T0, 28329), (T0 + 15, 28329), (T0 + 30, 28329)]
RUN14_SEN = [(T0 - 15, 1394), (T0, 1394), (T0 + 15, 28302), (T0 + 30, 28302)]


class Stub:
    def __init__(self, ans, dlys, status="success"):
        self.ans, self.dlys, self.status, self.queries = ans, dlys, status, []
        stub = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"])).decode()
                q = urllib.parse.parse_qs(body)["query"][0]
                stub.queries.append(q)
                res = stub.ans if q.startswith("ALERTS") else stub.dlys
                out = json.dumps({"status": stub.status, "data": {"resultType": "matrix", "result": res}}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def run(url, env=None):
    return subprocess.run(
        ["bash", SCRIPT, url, "600", str(T0 + 300)],
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
        timeout=60,
    )


class TestLateBoth(unittest.TestCase):
    def go(self, ans, dlys, **kw):
        s = Stub(ans, dlys, **kw)
        try:
            return run(s.url), s.queries
        finally:
            s.close()

    def test_run14_both_late_15s_apart_is_natural(self):
        r, qs = self.go(alerts([T0]), delays(RUN14_VAL, RUN14_SEN))
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(r.stdout.split(), [V, "postfiatd", "1", "1"])
        self.assertIn(f'validator=~"{V}"', qs[1])

    def test_real_disagreement_sentry_never_late(self):
        sen = [(t, 1394) for t, _ in RUN14_SEN]
        r, _ = self.go(alerts([T0, T0 + 15]), delays(RUN14_VAL, sen))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.split(), [V, "postfiatd", "2", "0"])

    def test_one_eval_without_both_late_is_not_natural(self):
        # sentry late only around T0, the second eval 3 min later has no sentry sample > 3000 within 60 s
        val = RUN14_VAL + [(T0 + 180, 28329)]
        sen = RUN14_SEN + [(T0 + 120, 1394), (T0 + 180, 1394), (T0 + 240, 1394)]
        sen = [(t, v) for t, v in sen if t <= T0 + 15 or t >= T0 + 120]
        r, _ = self.go(alerts([T0, T0 + 180]), delays(val, sen))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.split()[2:], ["2", "1"])

    def test_skew_boundary(self):
        # sentry late sample exactly 60 s after the eval counts, 61 s does not
        for dt, rc in ((60, 0), (61, 1)):
            sen = [(T0, 1394), (T0 + dt, 28302)]
            r, _ = self.go(alerts([T0]), delays(RUN14_VAL, sen))
            self.assertEqual(r.returncode, rc, (dt, r.stdout))

    def test_threshold_is_strictly_above_3000(self):
        sen = [(T0 + 15, 3000)]
        r, _ = self.go(alerts([T0]), delays(RUN14_VAL, sen))
        self.assertEqual(r.returncode, 1)

    def test_missing_delay_data_fails_closed(self):
        r, _ = self.go(alerts([T0]), [])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.split()[2:], ["1", "0"])

    def test_no_pending_series_is_ok_and_skips_second_query(self):
        r, qs = self.go([], delays(RUN14_VAL, RUN14_SEN))
        self.assertEqual((r.returncode, r.stdout, len(qs)), (0, "", 1))

    def test_prometheus_error_status_fails_closed(self):
        r, _ = self.go(alerts([T0]), [], status="error")
        self.assertEqual((r.returncode, r.stdout.strip()), (1, "query-error"))

    def test_dead_prometheus_fails_closed(self):
        r = run("http://127.0.0.1:9")
        self.assertEqual((r.returncode, r.stdout.strip()), (1, "query-error"))


if __name__ == "__main__":
    unittest.main()
