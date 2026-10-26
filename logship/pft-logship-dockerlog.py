#!/usr/bin/env python3
"""pft-logship-dockerlog: copy one container's log stream (docker json-file driver) into journald, resumable.

Both node containers log through docker's json-file driver, so postfiatd's own lines never reach journald and
journal-upload would not ship them. This bridge runs `docker logs -f --timestamps --since <saved>` and writes each
line (without docker's timestamp) to stdout; the systemd unit pft-logship-dockerlog@<container> sends stdout to the
journal under SyslogIdentifier=<container>.

Resume: the state file holds the docker timestamp (integer ns) of the last line written and how many lines carried
exactly that timestamp. On restart, lines older than it and the first <count> lines at it are skipped, so a restart
neither repeats nor drops lines that were already counted. stdout is flushed BEFORE the state is saved, so the state
is never ahead of the journal: a SIGKILL can repeat at most the lines written since the last save (<= 1 s), never
drop any. SIGTERM flushes and saves before exiting. With no state file the bridge starts at "now" (`--tail 0`, no
backfill). Cost of a resume: docker answers `--since` only after reading every rotated json-file log from the oldest,
which took 19 s for 543M of logs on the validator (logs/logship/since-scan.log); lines are delayed, not lost.

Usage: pft-logship-dockerlog CONTAINER
Env:   PFT_LS_DL_STATE  state dir (default /var/lib/pft-logship/dockerlog)
       PFT_LS_DOCKER    docker binary (tests use a stub)
       PFT_LS_DL_SAVE   seconds between state saves (default 1)
Exit:  docker's exit code (non-zero when the container is gone or stopped); systemd restarts the unit.
"""
import calendar
import os
import re
import signal
import subprocess
import sys
import time

TS = re.compile(rb"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z ")


def ts_ns(m):
    """docker RFC3339Nano match -> integer ns. Compared as numbers, never as strings: RFC3339Nano may trim
    trailing zeros, and '...:05Z' sorts after '...:05.5Z' as a string."""
    secs = calendar.timegm(tuple(int(m.group(i)) for i in range(1, 7)) + (0, 0, 0))
    frac = (m.group(7) or b"").decode()
    return secs * 1_000_000_000 + int(frac.ljust(9, "0") or 0)


def ns_rfc(ns):
    s, f = divmod(ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(s)) + f".{f:09d}Z"


def load_state(path):
    try:
        with open(path) as fh:
            ns, count = fh.read().split()
        return int(ns), int(count)
    except (OSError, ValueError):
        return None


def save_state(path, ns, count):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(f"{ns} {count}\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def main(argv):
    if len(argv) != 2 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", argv[1]):
        sys.stderr.write("usage: pft-logship-dockerlog CONTAINER\n")
        return 3
    name = argv[1]
    sdir = os.environ.get("PFT_LS_DL_STATE", "/var/lib/pft-logship/dockerlog")
    every = float(os.environ.get("PFT_LS_DL_SAVE", "1"))
    os.makedirs(sdir, exist_ok=True)
    spath = os.path.join(sdir, name + ".state")
    st = load_state(spath)
    start = ["--since", ns_rfc(st[0])] if st else ["--tail", "0"]
    skip_ns, skip_n = st if st else (-1, 0)
    cmd = [os.environ.get("PFT_LS_DOCKER", "docker"), "logs", "-f", "--timestamps", *start, name]
    sys.stderr.write(f"pft-logship-dockerlog: {name} {' '.join(start)} ({'resume' if st else 'no state: from now'})\n")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def term(_sig, _frm):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, term)

    out = sys.stdout.buffer
    last_ns, last_n = st if st else (None, 0)
    dirty, saved_at, skipped, written = False, time.monotonic(), 0, 0
    rc = 0
    try:
        for raw in p.stdout:
            m = TS.match(raw)
            if not m:  # docker's own messages ("Error: No such container") have no timestamp
                sys.stderr.write("pft-logship-dockerlog: " + raw.decode("utf-8", "replace"))
                continue
            ns = ts_ns(m)
            if ns < skip_ns or (ns == skip_ns and skip_n > 0):
                if ns == skip_ns:
                    skip_n -= 1
                skipped += 1
                continue
            out.write(raw[m.end():] if raw.endswith(b"\n") else raw[m.end():] + b"\n")
            written += 1
            last_n = last_n + 1 if ns == last_ns else 1
            last_ns, dirty = ns, True
            if time.monotonic() - saved_at >= every:
                out.flush()
                save_state(spath, last_ns, last_n)
                dirty, saved_at = False, time.monotonic()
        rc = p.wait()
    finally:
        out.flush()
        if dirty:
            save_state(spath, last_ns, last_n)
        if p.poll() is None:
            p.terminate()
        sys.stderr.write(f"pft-logship-dockerlog: {name} stream ended: {written} written, {skipped} skipped"
                         " (resume overlap)\n")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
