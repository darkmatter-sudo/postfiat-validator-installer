#!/usr/bin/env python3
"""Load generator for the pft-resources live drill (drill.sh). Runs as the MAIN process of a throwaway container
(never postfiatd), stdlib only, and follows the phase named in the read-only file CTL (default /ctl/phase):

  idle  hold nothing (fds closed, threads stopped, memory freed)
  load  open fds until FD_RATIO of the soft RLIMIT_NOFILE, start threads until PIDS_RATIO of the cgroup's pids.max,
        and touch memory in 1 MiB chunks until MEM_RATIO of its memory.max; keep topping up every second
  oom   release threads and memory, then start ONE child process that raises its own oom_score_adj to 1000 and
        allocates until the kernel OOM-kills it inside the container's cgroup (memory.events oom_kill + 1).
        The main process keeps running, so docker State.OOMKilled stays false and the collector stays up.
  done  exit 0

The container needs its own cgroup namespace (docker's default on cgroup v2), so /sys/fs/cgroup is its own cgroup.
Prints one line per state change to stdout (docker logs). Ratios come from the env (defaults below).
"""
import os
import subprocess
import sys
import threading
import time

CTL = os.environ.get("CTL", "/ctl/phase")
CG = os.environ.get("CG", "/sys/fs/cgroup")
FD_RATIO = float(os.environ.get("FD_RATIO", "0.875"))
PIDS_RATIO = float(os.environ.get("PIDS_RATIO", "0.94"))
MEM_RATIO = float(os.environ.get("MEM_RATIO", "0.93"))
CHUNK = 1 << 20

CHILD = r"""
import os, time
with open("/proc/self/oom_score_adj", "w") as f:
    f.write("1000")
hold = []
while True:
    b = bytearray(1 << 20)
    b[::4096] = b"\x01" * 256
    hold.append(b)
"""


def log(msg):
    print("%s drill_load: %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg), flush=True)


def read_int(path):
    with open(path) as f:
        v = f.read().split()[0]
    return None if v == "max" else int(v)


def phase():
    try:
        with open(CTL) as f:
            return f.read().strip() or "idle"
    except OSError:
        return "idle"


class Load:
    def __init__(self):
        self.fds, self.mem, self.threads = [], [], []
        self.stop = threading.Event()
        self.child = None

    def nfds(self):
        return len(os.listdir("/proc/self/fd"))

    def fill_fds(self):
        import resource
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        target = int(soft * FD_RATIO) + 1
        while self.nfds() < target:
            self.fds.append(os.open("/dev/null", os.O_RDONLY))

    def fill_pids(self):
        pmax = read_int(CG + "/pids.max")
        if pmax is None:
            return
        target = int(pmax * PIDS_RATIO)
        while read_int(CG + "/pids.current") < target:
            t = threading.Thread(target=self.stop.wait, daemon=True)
            t.start()
            self.threads.append(t)

    def fill_mem(self):
        mmax = read_int(CG + "/memory.max")
        if mmax is None:
            return
        while read_int(CG + "/memory.current") < mmax * MEM_RATIO:
            b = bytearray(CHUNK)
            b[::4096] = b"\x01" * (CHUNK // 4096)  # touch every page so it is charged to the cgroup
            self.mem.append(b)

    def release(self, fds=True):
        self.stop.set()
        for t in self.threads:
            t.join()
        self.threads, self.stop = [], threading.Event()
        self.mem = []
        if fds:
            for fd in self.fds:
                os.close(fd)
            self.fds = []

    def state(self):
        return "fds=%d threads=%d mem_chunks=%d pids.current=%s memory.current=%s" % (
            self.nfds(), len(self.threads), len(self.mem),
            read_int(CG + "/pids.current"), read_int(CG + "/memory.current"))


def main():
    ld, cur, filled = Load(), None, False
    log("start pid=%d ctl=%s ratios fd=%s pids=%s mem=%s" % (os.getpid(), CTL, FD_RATIO, PIDS_RATIO, MEM_RATIO))
    while True:
        p = phase()
        if p != cur:
            log("phase %s -> %s" % (cur, p))
            if p in ("idle", "oom", "done"):
                ld.release(fds=(p != "oom"))
            if p == "oom" and ld.child is None:
                ld.child = subprocess.Popen([sys.executable, "-c", CHILD])
                log("oom child pid=%d started" % ld.child.pid)
            cur, filled = p, False
            log("state " + ld.state())
        if p == "done":
            return 0
        if p == "load":
            ld.fill_fds()
            ld.fill_pids()
            ld.fill_mem()
            if not filled:
                filled = True
                log("load reached: " + ld.state())
        if ld.child is not None and ld.child.returncode is None and ld.child.poll() is not None:
            log("oom child exited rc=%d (-9 = SIGKILL from the OOM killer)" % ld.child.returncode)
            log("state " + ld.state())
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
