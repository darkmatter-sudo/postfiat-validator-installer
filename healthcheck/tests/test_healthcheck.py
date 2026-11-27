#!/usr/bin/env python3
"""Fault-injection and mutation tests for the guide's postfiat-healthcheck script.

Usage: python3 -I tests/test_healthcheck.py EXTRACT_DIR [--mutants]
EXTRACT_DIR = extract_healthcheck.py output (uses EXTRACT_DIR/postfiat-healthcheck, unchanged).
The script runs with `sh` and a `docker` shim first in PATH: `docker exec <container> curl ...` fails like Docker
for any container other than $SHIM_CONTAINER, otherwise runs the host curl with the in-container admin URL
(http://localhost:5005/) rewritten to a loopback mock RPC (127.0.0.1, random port) that answers each case's
server_info reply. Every case asserts the exit code and the exact CHECK/RESULT verdict lines, and the mock asserts
the script only ever sent POST server_info (read-only).
--mutants: also run every case against each mutant of the script; a mutant is killed when any case fails.
Exit 0 = every case passed (and every mutant was killed).
"""

import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

SHIM = r"""#!/bin/sh
[ "$1" = exec ] || { echo "shim: only docker exec is supported" >&2; exit 125; }
[ "$2" = "$SHIM_CONTAINER" ] || { echo "Error response from daemon: No such container: $2" >&2; exit 1; }
shift 2
[ "$1" = curl ] || { echo "shim: only curl is supported" >&2; exit 126; }
shift
n=$#; seen=0
for a in "$@"; do
  if [ "$a" = http://localhost:5005/ ]; then a="$SHIM_URL"; seen=1; fi
  set -- "$@" "$a"
done
shift "$n"
[ "$seen" = 1 ] || { echo "shim: admin URL http://localhost:5005/ not used" >&2; exit 127; }
exec curl "$@"
"""

MOCK = {"body": b"", "delay": 0.0, "requests": []}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        MOCK["requests"].append(("POST", self.rfile.read(n).decode()))
        if MOCK["delay"]:
            time.sleep(MOCK["delay"])
        body = MOCK["body"]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        try:
            self.end_headers()
            self.wfile.write(body)
        except BrokenPipeError:  # the RPC_TIMEOUT case: curl gave up before the slow reply
            pass

    def do_GET(self):
        MOCK["requests"].append(("GET", self.path))
        self.send_response(405)
        self.end_headers()

    def log_message(self, *args):
        pass


def info(**kw):
    base = {"server_state": "full", "validated_ledger": {"age": 2, "seq": 1000}, "peers": 20,
            "complete_ledgers": "100-1000"}
    for k, v in kw.items():
        if v is DROP:
            base.pop(k)
        else:
            base[k] = v
    return json.dumps({"result": {"info": base, "status": "success"}})


DROP = object()
OK4 = ["state OK", "validated_ledger_age OK", "peers OK", "complete_ledgers OK", "RESULT OK"]


def verdicts(fail=(), n=None):
    names = ["state", "validated_ledger_age", "peers", "complete_ledgers"]
    lines = [f"{x} {'FAIL' if x in fail else 'OK'}" for x in names]
    return lines + [f"RESULT FAIL {len(fail)}" if fail else "RESULT OK"]


# (name, reply, env, expected rc, expected verdict lines, extra regex the output must match)
CASES = [
    ("healthy full", info(), {}, 0, OK4, r"CHECK state OK full"),
    ("healthy proposing", info(server_state="proposing"), {}, 0, OK4, None),
    ("healthy validating, two ranges", info(server_state="validating", complete_ledgers="5-10,100-1000"), {}, 0,
     OK4, r"newest range 901, min 64"),
    ("state syncing", info(server_state="syncing"), {}, 1, verdicts(["state"]), r"CHECK state FAIL syncing"),
    ("state connected", info(server_state="connected"), {}, 1, verdicts(["state"]), None),
    ("state missing", info(server_state=DROP), {}, 1, verdicts(["state"]), r"CHECK state FAIL None"),
    ("ledger age 120 s", info(validated_ledger={"age": 120}), {}, 1, verdicts(["validated_ledger_age"]),
     r"120 s \(max 60\)"),
    ("ledger age 60 s (boundary)", info(validated_ledger={"age": 60}), {}, 0, OK4, None),
    ("ledger age 61 s", info(validated_ledger={"age": 61}), {}, 1, verdicts(["validated_ledger_age"]), None),
    ("no validated ledger", info(validated_ledger=DROP), {}, 1, verdicts(["validated_ledger_age"]), None),
    ("validated ledger null", info(validated_ledger=None), {}, 1, verdicts(["validated_ledger_age"]), None),
    ("age not a number", info(validated_ledger={"age": "2"}), {}, 1, verdicts(["validated_ledger_age"]), None),
    ("peers 2", info(peers=2), {}, 1, verdicts(["peers"]), r"CHECK peers FAIL 2 \(min 3\)"),
    ("peers 3 (boundary)", info(peers=3), {}, 0, OK4, None),
    ("peers missing", info(peers=DROP), {}, 1, verdicts(["peers"]), None),
    ("peers is a bool", info(peers=True), {"MIN_PEERS": "1"}, 1, verdicts(["peers"]), None),
    ("complete_ledgers empty", info(complete_ledgers="empty"), {}, 1, verdicts(["complete_ledgers"]),
     r"newest range 0"),
    ("complete_ledgers malformed", info(complete_ledgers="100-1000x"), {}, 1, verdicts(["complete_ledgers"]), None),
    ("complete_ledgers missing", info(complete_ledgers=DROP), {}, 1, verdicts(["complete_ledgers"]), None),
    ("newest range short", info(complete_ledgers="1-10000,20000-20009"), {}, 1, verdicts(["complete_ledgers"]),
     r"newest range 10,"),
    ("newest range 64 (boundary)", info(complete_ledgers="937-1000"), {}, 0, OK4, r"newest range 64,"),
    ("newest range 63", info(complete_ledgers="938-1000"), {}, 1, verdicts(["complete_ledgers"]), None),
    ("single ledger", info(complete_ledgers="1000"), {}, 1, verdicts(["complete_ledgers"]), r"newest range 1,"),
    ("everything wrong", info(server_state="disconnected", validated_ledger=DROP, peers=0, complete_ledgers="empty"),
     {}, 1, verdicts(["state", "validated_ledger_age", "peers", "complete_ledgers"]), r"RESULT FAIL 4"),
    ("unknown: RPC down", "<closed>", {}, 2, ["rpc UNKNOWN", "RESULT UNKNOWN"], None),
    ("unknown: container not running", info(), {"CONTAINER": "nosuch"}, 2, ["rpc UNKNOWN", "RESULT UNKNOWN"],
     r"docker exec nosuch failed"),
    ("unknown: not JSON", "<html>bad gateway</html>", {}, 2, ["rpc UNKNOWN", "RESULT UNKNOWN"], None),
    ("unknown: empty reply", "", {}, 2, ["rpc UNKNOWN", "RESULT UNKNOWN"], None),
    ("unknown: RPC error", json.dumps({"result": {"status": "error", "error": "noPermission"}}), {}, 2,
     ["rpc UNKNOWN", "RESULT UNKNOWN"], None),
    ("unknown: info not an object", json.dumps({"result": {"info": []}}), {}, 2, ["rpc UNKNOWN", "RESULT UNKNOWN"],
     None),
    ("unknown: RPC slower than RPC_TIMEOUT", "<slow>", {"RPC_TIMEOUT": "1"}, 2, ["rpc UNKNOWN", "RESULT UNKNOWN"],
     None),
    ("override MIN_PEERS=30", info(), {"MIN_PEERS": "30"}, 1, verdicts(["peers"]), r"20 \(min 30\)"),
    ("override MIN_PEERS=0, 0 peers", info(peers=0), {"MIN_PEERS": "0"}, 0, OK4, None),
    ("override MAX_LEDGER_AGE=1", info(), {"MAX_LEDGER_AGE": "1"}, 1, verdicts(["validated_ledger_age"]), None),
    ("override MAX_LEDGER_AGE=300, age 120", info(validated_ledger={"age": 120}), {"MAX_LEDGER_AGE": "300"}, 0,
     OK4, None),
    ("override OK_STATES=proposing, full", info(), {"OK_STATES": "proposing"}, 1, verdicts(["state"]),
     r"want one of: proposing\)"),
    ("override OK_STATES=proposing, proposing", info(server_state="proposing"), {"OK_STATES": "proposing"}, 0, OK4,
     None),
    ("override MIN_LEDGERS=2000", info(), {"MIN_LEDGERS": "2000"}, 1, verdicts(["complete_ledgers"]), None),
    ("override CONTAINER=postfiatd-sentry", info(), {"CONTAINER": "postfiatd-sentry",
                                                     "SHIM_CONTAINER": "postfiatd-sentry"}, 0, OK4, None),
    ("invalid MIN_PEERS=abc", info(), {"MIN_PEERS": "abc"}, 2, ["config UNKNOWN", "RESULT UNKNOWN"],
     r"MIN_PEERS='abc'"),
    ("invalid MAX_LEDGER_AGE=-1", info(), {"MAX_LEDGER_AGE": "-1"}, 2, ["config UNKNOWN", "RESULT UNKNOWN"], None),
    ("invalid MIN_LEDGERS empty", info(), {"MIN_LEDGERS": ""}, 1, verdicts(["complete_ledgers"]), None),
]
# MIN_LEDGERS="" is not invalid: ${MIN_LEDGERS:-64} treats empty as unset, so the default 64 applies
CASES[-1] = ("empty MIN_LEDGERS falls back to the default 64", info(complete_ledgers="938-1000"),
             {"MIN_LEDGERS": ""}, 1, verdicts(["complete_ledgers"]), r"min 64\)")

MUTANTS = [
    ("age <= limit -> <", "age <= limit", "age < limit"),
    ("peers >= limit -> >", "peers >= limit", "peers > limit"),
    ("span >= limit -> >", "span >= limit", "span > limit"),
    ("range span without +1", "int(last or first) - int(first) + 1", "int(last or first) - int(first)"),
    ("oldest range instead of newest", 'ledgers.split(",")[-1]', 'ledgers.split(",")[0]'),
    ("rpc failure exit 2 -> 1", '  echo "RESULT UNKNOWN"\n  exit 2', '  echo "RESULT UNKNOWN"\n  exit 1'),
    ("FAIL exits 0", "sys.exit(1 if fails else 0)", "sys.exit(0)"),
    ("UNKNOWN exits 1", '    print("RESULT UNKNOWN")\n    sys.exit(2)', '    print("RESULT UNKNOWN")\n    sys.exit(1)'),
    ("failures not counted", "fails += 0 if ok else 1", "fails += 0"),
    ("state check always true", "state in ok_states,", "True,"),
    ("age type check dropped", "whole(age) and age <= limit", "age <= limit"),
    ("negative thresholds accepted", 'r"[0-9]+", value', 'r"-?[0-9]+", value'),
    ("default MIN_PEERS 3 -> 0", "MIN_PEERS:-3", "MIN_PEERS:-0"),
    ("default MAX_LEDGER_AGE 60 -> 600", "MAX_LEDGER_AGE:-60", "MAX_LEDGER_AGE:-600"),
    ("default MIN_LEDGERS 64 -> 1", "MIN_LEDGERS:-64", "MIN_LEDGERS:-1"),
    ("default OK_STATES without full", "OK_STATES:-full proposing validating", "OK_STATES:-proposing validating"),
    ("bools accepted as numbers", "type(v) is int", "isinstance(v, int)"),
    ("no RPC timeout", ' -m "$RPC_TIMEOUT"', ""),
    ("info type guard dropped", "if not isinstance(info, dict):", "if False:"),
    ("complete_ledgers prefix match", 're.fullmatch(r"[0-9]+(-', 're.match(r"[0-9]+(-'),
    ("wrong container default", 'CONTAINER="${CONTAINER:-postfiatd}"', 'CONTAINER="${CONTAINER:-postfiat}"'),
    ("container ignored", 'docker exec "$CONTAINER" curl', "docker exec postfiatd curl"),
]


def run_case(script, shimdir, port, case):
    name, reply, env, rc_want, want, rx = case
    MOCK["requests"] = []
    MOCK["delay"] = 3.0 if reply == "<slow>" else 0.0
    MOCK["body"] = info().encode() if reply == "<slow>" else (reply.encode() if reply != "<closed>" else b"")
    url_port = closed_port() if reply == "<closed>" else port
    e = {"PATH": f"{shimdir}:{os.environ['PATH']}", "SHIM_CONTAINER": "postfiatd",
         "SHIM_URL": f"http://127.0.0.1:{url_port}/", "LC_ALL": "C"}
    e.update(env)
    p = subprocess.run(["sh", script], check=False, env=e, capture_output=True, text=True, timeout=30)
    got = [" ".join(m.group(1, 2)) if m.group(1) else m.group(0)
           for m in re.finditer(r"^CHECK (\S+) (OK|FAIL|UNKNOWN)\b.*$|^RESULT \S+(?: \d+)?$", p.stdout, re.MULTILINE)]
    problems = []
    if p.returncode != rc_want:
        problems.append(f"rc {p.returncode} != {rc_want}")
    if got != want:
        problems.append(f"verdicts {got} != {want}")
    if rx and not re.search(rx, p.stdout):
        problems.append(f"output lacks /{rx}/")
    for method, body in MOCK["requests"]:
        if method != "POST" or json.loads(body or "{}").get("method") != "server_info":
            problems.append(f"non-read-only request {method} {body!r}")
    if reply not in ("<closed>",) and "CONTAINER" not in env and not MOCK["requests"]:
        problems.append("mock saw no request")
    return name, problems, p


def closed_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_all(script, shimdir, port, verbose):
    failed = 0
    for case in CASES:
        name, problems, p = run_case(script, shimdir, port, case)
        if verbose:
            print(f"{'PASS' if not problems else 'FAIL'} case {name}: rc={p.returncode}")
            for line in p.stdout.splitlines():
                print(f"     | {line}")
            for prob in problems:
                print(f"     ! {prob}")
                for line in p.stderr.splitlines()[:5]:
                    print(f"     stderr: {line}")
        failed += bool(problems)
        if problems and not verbose:
            return failed, name
    return failed, None


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    src = os.path.join(argv[1], "postfiat-healthcheck")
    with open(src) as f:
        text = f.read()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    # temp dir inside EXTRACT_DIR: it must be exec-capable (a noexec /tmp would make PATH fall through to the
    # real docker), which the self-check below enforces before any case runs
    with tempfile.TemporaryDirectory(dir=argv[1]) as tmp:
        shim = os.path.join(tmp, "docker")
        with open(shim, "w") as f:
            f.write(SHIM)
        os.chmod(shim, 0o755)
        probe = subprocess.run(["sh", "-c", "command -v docker; docker exec selfcheck true"], check=False,
                               capture_output=True, text=True, env={"PATH": f"{tmp}:{os.environ['PATH']}", "SHIM_CONTAINER": "x"})
        if probe.stdout.strip() != shim or "No such container: selfcheck" not in probe.stderr:
            print(f"ERROR docker shim not used (resolved {probe.stdout.strip()!r}); EXTRACT_DIR must allow exec")
            return 2
        print("docker shim self-check: PATH resolves docker to the shim, unknown container -> Docker-style error")
        print(f"script {src} | mock RPC 127.0.0.1:<port> | {len(CASES)} cases")
        failed, _ = run_all(src, tmp, port, True)
        print(f"cases: {len(CASES) - failed} passed, {failed} failed")
        survived = 0
        if "--mutants" in argv:
            print(f"== mutants ({len(MUTANTS)})")
            for i, (desc, old, new) in enumerate(MUTANTS, 1):
                n = text.count(old)
                if n != 1:
                    print(f"ERROR mutant {i} {desc}: pattern found {n} times (want 1)")
                    survived += 1
                    continue
                m = os.path.join(tmp, f"mutant{i}")
                with open(m, "w") as f:
                    f.write(text.replace(old, new))
                bad, killer = run_all(m, tmp, port, False)
                if bad:
                    print(f"KILLED   mutant {i:2} {desc}  (by case: {killer})")
                else:
                    print(f"SURVIVED mutant {i:2} {desc}")
                    survived += 1
            print(f"mutants: {len(MUTANTS) - survived}/{len(MUTANTS)} killed, {survived} survived")
    srv.shutdown()
    ok = failed == 0 and survived == 0
    print(f"RESULT: {'PASS' if ok else 'FAIL'} - {failed} case(s) failed, {survived} mutant(s) survived")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
