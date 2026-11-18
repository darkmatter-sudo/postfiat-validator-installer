#!/usr/bin/env python3
"""pft-budget helper (stdlib only): per-unit cgroup resource budgets for pft-* systemd units.

Kernel 5.15 (Ubuntu 22.04 GA) has no memory.peak and systemd 249 keeps no per-run peak, so `sample` is a small
polling daemon: every INTERVAL seconds it reads the cgroup v2 files of every CGROUP_ROOT/UNIT_GLOB directory and keeps,
per (unit, invocation id), the peak of memory.current and of the unreclaimable part of memory.stat, the cumulative
cpu.stat usage, io.stat bytes, memory.events oom_kill and the configured memory.max/memory.high. When an invocation's
cgroup disappears (or its invocation id changes) one `final` record is appended to DATA_DIR/samples.jsonl with the
systemd Result/ExecMainStatus/runtime of that invocation; long-running invocations get a `running` checkpoint every
CHECKPOINT_SEC. The JSONL is size-bounded: samples.jsonl rotates to .1 .. .KEEP at MAX_BYTES.

  sample [--once]                 run the sampler (--once: one scan, flush every open invocation as `running`)
  report [--json] [--now EPOCH]   per-unit p50/max peaks, runtime, CPU/IO, OOMs, caps, headroom, 30/90-day projection
  metrics [--now EPOCH]           the report as pft_budget_* textfile metrics on stdout
  plan [--allow-lower]            proposed MemoryMax drop-ins for WARN/FAIL/UNCAPPED units (never excluded units)
  apply [--yes] [--allow-lower]   write the plan's drop-ins (only inside a pft-maint window; dry-run without --yes)
  rollback [--yes]                restore what the last apply replaced (only inside a pft-maint window)

Exit codes: 0 ok, 1 report has a FAIL verdict / apply or rollback check failed, 2 report has WARN (no FAIL),
            3 usage/config error, 4 refused (no maintenance window, excluded unit, nothing to roll back).
"""

import argparse
import fnmatch
import json
import math
import os
import re
import subprocess
import sys
import time

VERSION = 1
MIB = 1024 * 1024
DEFAULTS = {
    "CGROUP_ROOT": "/sys/fs/cgroup/system.slice",
    "UNIT_GLOB": "pft-*.service",
    "EXCLUDE": "postfiatd* docker* containerd* pft-budget-sampler.service",
    "DATA_DIR": "/var/lib/pft-budget",
    "DROPIN_ROOT": "/etc/systemd/system",
    "DROPIN_NAME": "60-pft-budget.conf",
    "INTERVAL": "1",
    "CHECKPOINT_SEC": "900",
    "MAX_BYTES": str(4 * MIB),
    "KEEP": "5",
    "WINDOW_DAYS": "30",
    "MIN_RUNS": "3",
    "WARN_HEADROOM": "2.0",
    "FAIL_FRACTION": "0.9",
    "TARGET_HEADROOM": "2.0",
    "PROJ_MARGIN": "1.25",
    "MIN_CAP_MIB": "64",
    "STALE_SEC": "300",
    "INV_CHECK_SEC": "30",
    "HOST": "local",
}
# memory.stat fields that reclaim cannot free: what an OOM kill is really about (memory.current also counts page
# cache, which the kernel drops before it kills, so a streaming reader sits at its cap without being at risk)
UNRECLAIMABLE = ("anon", "shmem", "kernel_stack", "pagetables", "percpu", "sock", "slab_unreclaimable")
# keys of the same conf file that only pft-budget.sh reads
SHELL_KEYS = ("TEXTFILE_DIR", "PULL_SSH", "REMOTE_DIR", "PULL_TIMEOUT", "TEXT_MAX_BYTES")
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.@\\-]*\.service$")


class ConfError(Exception):
    pass


def load_conf(path):
    conf = dict(DEFAULTS)
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                k, sep, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k in SHELL_KEYS:
                    continue
                if not sep or k not in DEFAULTS:
                    raise ConfError(f"{path}:{n}: unknown or malformed line")
                conf[k] = v
    for k in DEFAULTS:
        if os.environ.get("PFT_BUD_" + k) is not None:
            conf[k] = os.environ["PFT_BUD_" + k]
    num = {}
    for k in ("INTERVAL", "WARN_HEADROOM", "FAIL_FRACTION", "TARGET_HEADROOM", "PROJ_MARGIN"):
        num[k] = _pos_float(conf, k)
    for k in (
        "CHECKPOINT_SEC",
        "MAX_BYTES",
        "KEEP",
        "WINDOW_DAYS",
        "MIN_RUNS",
        "MIN_CAP_MIB",
        "STALE_SEC",
        "INV_CHECK_SEC",
    ):
        num[k] = int(_pos_float(conf, k))
        if num[k] != _pos_float(conf, k):
            raise ConfError(f"{k} must be a positive integer")
    if not 0 < num["FAIL_FRACTION"] <= 1:
        raise ConfError("FAIL_FRACTION must be in (0, 1]")
    if num["MAX_BYTES"] < 4096:
        raise ConfError("MAX_BYTES must be >= 4096")
    conf.update(num)
    conf["EXCLUDE"] = conf["EXCLUDE"].split()
    if not re.match(r"^[a-z][a-z0-9-]{0,31}$", conf["HOST"]):
        raise ConfError("HOST must be a short label like validator or sentry")
    return conf


def _pos_float(conf, k):
    try:
        v = float(conf[k])
    except ValueError:
        raise ConfError(f"{k} must be a number") from None
    if not v > 0 or math.isinf(v):
        raise ConfError(f"{k} must be > 0")
    return v


def now(args=None):
    if args is not None and getattr(args, "now", None) is not None:
        return float(args.now)
    if os.environ.get("PFT_BUD_NOW"):
        return float(os.environ["PFT_BUD_NOW"])
    return time.time()


def excluded(unit, conf):
    return any(fnmatch.fnmatchcase(unit, p) for p in conf["EXCLUDE"])


# ---------------------------------------------------------------- cgroup reading


def _read(path):
    with open(path, encoding="ascii") as f:
        return f.read()


def _kv(text):
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if v.strip().lstrip("-").isdigit():
            out[k] = int(v)
    return out


def _limit(text):
    t = text.strip()
    return None if t == "max" else int(t)


def invocation_id(unit, path):
    """The unit's current InvocationID. systemd also tags the cgroup with the trusted.invocation_id xattr, but reading
    trusted.* needs CAP_SYS_ADMIN, which the sampler does not get; so: xattr if readable, else `systemctl show`, else
    the cgroup dir's inode."""
    try:
        return os.getxattr(path, "trusted.invocation_id").decode("ascii").strip()
    except (OSError, UnicodeDecodeError):
        pass
    try:
        p = subprocess.run(
            systemctl_cmd() + ["show", unit, "-p", "InvocationID", "--value"],
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        inv = p.stdout.strip()
        if p.returncode == 0 and re.fullmatch(r"[0-9a-f]{32}", inv):
            return inv
    except (OSError, subprocess.TimeoutExpired):
        pass
    return f"ino-{os.stat(path).st_ino}"


def read_cgroup(path):
    """One sample of a unit cgroup, or None if it vanished while being read."""
    try:
        stat = _kv(_read(os.path.join(path, "memory.stat")))
        io_r = io_w = 0
        for line in _read(os.path.join(path, "io.stat")).splitlines():
            for field in line.split()[1:]:
                k, _, v = field.partition("=")
                if k == "rbytes":
                    io_r += int(v)
                elif k == "wbytes":
                    io_w += int(v)
        return {
            "ino": os.stat(path).st_ino,
            "current": int(_read(os.path.join(path, "memory.current"))),
            "unrecl": sum(stat.get(k, 0) for k in UNRECLAIMABLE),
            "cpu_usec": _kv(_read(os.path.join(path, "cpu.stat"))).get("usage_usec", 0),
            "io_read": io_r,
            "io_write": io_w,
            "oom_kill": _kv(_read(os.path.join(path, "memory.events"))).get("oom_kill", 0),
            "mem_max": _limit(_read(os.path.join(path, "memory.max"))),
            "mem_high": _limit(_read(os.path.join(path, "memory.high"))),
        }
    except FileNotFoundError:
        return None


def scan(conf):
    root = conf["CGROUP_ROOT"]
    try:
        names = sorted(os.listdir(root))
    except FileNotFoundError:
        raise ConfError(f"CGROUP_ROOT {root} does not exist") from None
    return {
        n: os.path.join(root, n)
        for n in names
        if fnmatch.fnmatchcase(n, conf["UNIT_GLOB"]) and UNIT_RE.match(n) and os.path.isdir(os.path.join(root, n))
    }


def systemctl_cmd():
    return os.environ.get("PFT_BUD_SYSTEMCTL", "systemctl").split()


def unit_result(unit):
    """Result, exit status, runtime and invocation id systemd reports for the unit's last run (dict, maybe empty)."""
    props = "InvocationID,Result,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic"
    try:
        p = subprocess.run(
            systemctl_cmd() + ["show", unit, "-p", props],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if p.returncode != 0:
        return {}
    kv = dict(line.partition("=")[::2] for line in p.stdout.splitlines() if "=" in line)
    out = {"inv": kv.get("InvocationID", ""), "result": kv.get("Result") or None}
    try:
        out["exit_status"] = int(kv.get("ExecMainStatus", ""))
    except ValueError:
        out["exit_status"] = None
    try:
        start, end = int(kv["ExecMainStartTimestampMonotonic"]), int(kv["ExecMainExitTimestampMonotonic"])
        out["runtime_sec"] = round((end - start) / 1e6, 3) if start > 0 and end >= start else None
    except (KeyError, ValueError):
        out["runtime_sec"] = None
    return out


# ---------------------------------------------------------------- bounded JSONL


def append_record(conf, rec):
    d = conf["DATA_DIR"]
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "samples.jsonl")
    line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        size = 0
    if size and size + len(line) > conf["MAX_BYTES"]:
        for i in range(conf["KEEP"], 0, -1):
            src = path if i == 1 else f"{path}.{i - 1}"
            if os.path.exists(src):
                os.replace(src, f"{path}.{i}")
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)


def data_files(conf):
    path = os.path.join(conf["DATA_DIR"], "samples.jsonl")
    files = [f"{path}.{i}" for i in range(conf["KEEP"], 0, -1)] + [path]
    return [f for f in files if os.path.exists(f)]


def load_records(files):
    """Latest record per (host, unit, inv): a final record beats any running checkpoint of the same invocation."""
    best, bad = {}, 0
    for fn in files:
        with open(fn, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    key = (r["host"], r["unit"], r["inv"])
                    float(r["t_last"])
                except (ValueError, KeyError, TypeError):
                    bad += 1  # a torn last line after a crash, or a foreign line: counted, never fatal
                    continue
                old = best.get(key)
                if (
                    old is None
                    or (r["kind"] == "final") > (old["kind"] == "final")
                    or (r["kind"] == old["kind"] and r["t_last"] >= old["t_last"])
                ):
                    best[key] = r
    return list(best.values()), bad


# ---------------------------------------------------------------- sampler


class Tracker:
    def __init__(self, conf, clock=time.time):
        self.conf, self.clock = conf, clock
        self.open = {}  # unit -> state
        self.first_scan = True
        self.last_sample = None

    def _record(self, st, kind, res=None):
        res = res or {}
        rec = {
            "v": VERSION,
            "kind": kind,
            "host": self.conf["HOST"],
            "unit": st["unit"],
            "inv": st["inv"],
            "t_first": round(st["t_first"], 3),
            "t_last": round(st["t_last"], 3),
            "samples": st["samples"],
            "from_start": st["from_start"],
            "peak_bytes": st["peak"],
            "peak_unrecl_bytes": st["peak_unrecl"],
            "cpu_sec": round(st["cpu_usec"] / 1e6, 3),
            "io_read_bytes": st["io_read"],
            "io_write_bytes": st["io_write"],
            "oom_kills": st["oom_kill"],
            "mem_max": st["mem_max"],
            "mem_high": st["mem_high"],
            "result": res.get("result"),
            "exit_status": res.get("exit_status"),
            "runtime_sec": res.get("runtime_sec"),
        }
        if rec["runtime_sec"] is None:
            rec["runtime_sec"] = round(st["t_last"] - st["t_first"], 3)
        append_record(self.conf, rec)
        st["t_checkpoint"] = st["t_last"]
        return rec

    def _finish(self, st):
        res = unit_result(st["unit"])
        if res.get("inv") != st["inv"]:
            res = {}  # the unit already started again: its Result is not this invocation's
        if res.get("result") == "oom-kill":
            st["oom_kill"] = max(st["oom_kill"], 1)
        return self._record(st, "final", res)

    def tick(self):
        t = self.clock()
        out = []
        present = scan(self.conf)
        for unit, path in present.items():
            s = read_cgroup(path)
            if s is None:
                continue
            st = self.open.get(unit)
            # resolve the invocation id for a new cgroup dir, and re-check open ones every INV_CHECK_SEC (a restart
            # that kept the cgroup dir changes only the id)
            if st is None or st["ino"] != s["ino"] or t - st["t_invcheck"] >= self.conf["INV_CHECK_SEC"]:
                s["inv"], s["t_invcheck"] = invocation_id(unit, path), t
            else:
                s["inv"], s["t_invcheck"] = st["inv"], st["t_invcheck"]
            if st is not None and st["inv"] != s["inv"]:
                out.append(self._finish(st))
                st = None
            if st is None:
                st = self.open[unit] = {
                    "unit": unit,
                    "inv": s["inv"],
                    "t_first": t,
                    "t_checkpoint": t,
                    "from_start": not self.first_scan,
                    "samples": 0,
                    "peak": 0,
                    "peak_unrecl": 0,
                }
            st["t_last"] = t
            st["samples"] += 1
            st["peak"] = max(st["peak"], s["current"])
            st["peak_unrecl"] = max(st["peak_unrecl"], s["unrecl"])
            for k in ("ino", "t_invcheck", "cpu_usec", "io_read", "io_write", "oom_kill", "mem_max", "mem_high"):
                st[k] = s[k]
            if t - st["t_checkpoint"] >= self.conf["CHECKPOINT_SEC"]:
                out.append(self._record(st, "running"))
        for unit in [u for u in self.open if u not in present]:
            out.append(self._finish(self.open.pop(unit)))
        self.first_scan = False
        self.last_sample = t
        return out

    def flush(self):
        return [self._record(st, "running") for st in self.open.values()]


def cmd_sample(conf, args):
    tr = Tracker(conf)
    if args.once:
        tr.tick()
        for r in tr.flush():
            print(json.dumps(r, sort_keys=True))
        return 0
    stop = []
    import signal

    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    hb = os.path.join(conf["DATA_DIR"], "heartbeat")
    while not stop:
        t0 = time.monotonic()
        tr.tick()
        try:
            with open(hb + ".tmp", "w", encoding="ascii") as f:
                f.write(f"{int(tr.last_sample)}\n")
            os.replace(hb + ".tmp", hb)
        except OSError:
            pass
        time.sleep(max(0.05, conf["INTERVAL"] - (time.monotonic() - t0)))
    tr.flush()  # a stop keeps what was measured; the next start begins new (from_start false) invocations
    return 0


# ---------------------------------------------------------------- report


def pct(values, q):
    v = sorted(values)
    if not v:
        return None
    k = (len(v) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def fit(points):
    """Least-squares (slope per day, intercept) of (t, y); slope 0 when there is no time spread."""
    n = len(points)
    mt = sum(t for t, _ in points) / n
    my = sum(y for _, y in points) / n
    var = sum((t - mt) ** 2 for t, _ in points)
    if var == 0:
        return 0.0, my, mt
    slope = sum((t - mt) * (y - my) for t, y in points) / var
    return slope * 86400, my, mt


def ceil_mib(x, step):
    return math.ceil(x / (step * MIB)) * step * MIB


def unit_report(unit, recs, conf, t_now):
    peaks = [r["peak_unrecl_bytes"] for r in recs]
    totals = [r["peak_bytes"] for r in recs]
    runtimes = [r["runtime_sec"] for r in recs if r.get("runtime_sec") is not None]
    ooms = sum(1 for r in recs if r.get("oom_kills", 0) > 0 or r.get("result") == "oom-kill")
    failed = sum(1 for r in recs if r["kind"] == "final" and r.get("result") not in (None, "success"))
    latest = max(recs, key=lambda r: r["t_last"])
    cap = latest.get("mem_max")
    max_peak = max(peaks)
    u = {
        "unit": unit,
        "invocations": len(recs),
        "complete": sum(1 for r in recs if r["kind"] == "final" and r.get("from_start")),
        "peak_unrecl_p50": int(pct(peaks, 0.5)),
        "peak_unrecl_max": max_peak,
        "peak_total_max": max(totals),
        "runtime_p50": pct(runtimes, 0.5),
        "runtime_max": max(runtimes) if runtimes else None,
        "cpu_sec_max": max(r.get("cpu_sec", 0) for r in recs),
        "io_read_max": max(r.get("io_read_bytes", 0) for r in recs),
        "io_write_max": max(r.get("io_write_bytes", 0) for r in recs),
        "oom_runs": ooms,
        "failed_runs": failed,
        "cap": cap,
        "headroom": round(cap / max_peak, 3) if cap and max_peak else None,
        "proj30": None,
        "proj90": None,
        "slope_per_day": None,
        "reasons": [],
    }
    if len(recs) >= conf["MIN_RUNS"]:
        slope, my, mt = fit([(r["t_last"], r["peak_unrecl_bytes"]) for r in recs])
        slope = max(0.0, slope)  # shrinking peaks never lower the projection below what was measured
        base = my + slope * (t_now - mt) / 86400
        u["slope_per_day"] = int(slope)
        u["proj30"] = int(max(max_peak, base + slope * 30))
        u["proj90"] = int(max(max_peak, base + slope * 90))
    fail, warn = [], []
    if ooms:
        fail.append(f"{ooms} OOM-killed run(s) in window")
    if cap is None:
        verdict = "UNCAPPED"
    else:
        if max_peak >= conf["FAIL_FRACTION"] * cap:
            fail.append(f"peak {mib(max_peak)} >= {conf['FAIL_FRACTION']:g} x cap {mib(cap)}")
        elif max_peak * conf["WARN_HEADROOM"] > cap:
            warn.append(f"headroom {cap / max_peak:.2f}x < {conf['WARN_HEADROOM']:g}x (peak {mib(max_peak)})")
        if u["proj30"] is not None and u["proj30"] >= cap:
            fail.append(f"30-day projection {mib(u['proj30'])} >= cap {mib(cap)}")
        elif u["proj90"] is not None and u["proj90"] >= cap:
            warn.append(f"90-day projection {mib(u['proj90'])} >= cap {mib(cap)}")
        verdict = "FAIL" if fail else "WARN" if warn else "OK"
    if cap is None and fail:
        verdict = "FAIL"
    if len(recs) < conf["MIN_RUNS"]:
        u["reasons"].append(f"only {len(recs)} run(s) < MIN_RUNS {conf['MIN_RUNS']}: no projection")
    u["reasons"] = fail + warn + u["reasons"]
    u["verdict"] = verdict
    u["target"] = target_cap(u, conf)
    return u


def target_cap(u, conf):
    need = u["peak_unrecl_max"] * conf["TARGET_HEADROOM"]
    if u["proj90"] is not None:
        need = max(need, u["proj90"] * conf["PROJ_MARGIN"])
    return max(conf["MIN_CAP_MIB"] * MIB, ceil_mib(need, conf["MIN_CAP_MIB"]))


def mib(b):
    return "%.0fMiB" % (b / MIB)


def build_report(conf, t_now, files=None):
    recs, bad = load_records(data_files(conf) if files is None else files)
    lo = t_now - conf["WINDOW_DAYS"] * 86400
    recs = [r for r in recs if lo <= r["t_last"] <= t_now]
    hosts = sorted({r["host"] for r in recs})
    units = []
    for host in hosts:
        by_unit = {}
        for r in recs:
            if r["host"] == host:
                by_unit.setdefault(r["unit"], []).append(r)
        for unit in sorted(by_unit):
            u = unit_report(unit, by_unit[unit], conf, t_now)
            u["host"] = host
            units.append(u)
    return {
        "version": VERSION,
        "now": t_now,
        "window_days": conf["WINDOW_DAYS"],
        "records": len(recs),
        "bad_lines": bad,
        "units": units,
        "counts": {v: sum(1 for u in units if u["verdict"] == v) for v in ("OK", "WARN", "FAIL", "UNCAPPED")},
    }


def report_rc(rep):
    return 1 if rep["counts"]["FAIL"] else 2 if rep["counts"]["WARN"] else 0


ROW_HEAD = "%-10s %-44s %5s %9s %9s %9s %9s %8s %9s %9s %8s %4s %s"
ROW = "%-10s %-44s %5d %9s %9s %9s %9s %8s %9s %9s %8s %4d %s"


def fmt_report(rep):
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(rep["now"]))
    out = [
        (
            f"pft-budget report - {iso} - window {rep['window_days']}d, {rep['records']} invocation(s), "
            f"{rep['bad_lines']} unreadable line(s)"
        ),
        ROW_HEAD
        % (
            "host",
            "unit",
            "runs",
            "p50",
            "max",
            "max_tot",
            "cap",
            "headroom",
            "proj30",
            "proj90",
            "rt_max",
            "oom",
            "verdict",
        ),
    ]
    for u in rep["units"]:
        out.append(
            ROW
            % (
                u["host"],
                u["unit"],
                u["invocations"],
                mib(u["peak_unrecl_p50"]),
                mib(u["peak_unrecl_max"]),
                mib(u["peak_total_max"]),
                mib(u["cap"]) if u["cap"] else "-",
                "{:.2f}x".format(u["headroom"]) if u["headroom"] else "-",
                mib(u["proj30"]) if u["proj30"] is not None else "-",
                mib(u["proj90"]) if u["proj90"] is not None else "-",
                "{:.0f}s".format(u["runtime_max"]) if u["runtime_max"] is not None else "-",
                u["oom_runs"],
                u["verdict"],
            )
        )
        for why in u["reasons"]:
            out.append(f"{'':10} {'':44}   - {why}")
        if u["verdict"] == "UNCAPPED":
            out.append(f"{'':10} {'':44}   - recommend MemoryMax={mib(u['target'])[:-3]}M (pft-budget plan)")
    c = rep["counts"]
    out.append(f"RESULT: {c['OK']} OK, {c['WARN']} WARN, {c['FAIL']} FAIL, {c['UNCAPPED']} UNCAPPED")
    return "\n".join(out) + "\n"


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def fmt_metrics(rep, conf, heartbeat):
    h = 'host="{}"'.format(esc(conf["HOST"]))
    code = {"OK": 0, "WARN": 1, "FAIL": 2, "UNCAPPED": 3}
    lines = [
        "# HELP pft_budget_up 1 when the report was built from readable data",
        "# TYPE pft_budget_up gauge",
        f"pft_budget_up{{{h}}} 1",
        "# HELP pft_budget_sampler_heartbeat_timestamp_seconds last sampler scan (0 = never)",
        "# TYPE pft_budget_sampler_heartbeat_timestamp_seconds gauge",
        f"pft_budget_sampler_heartbeat_timestamp_seconds{{{h}}} {int(heartbeat or 0)}",
        "# HELP pft_budget_report_timestamp_seconds when this report was built",
        "# TYPE pft_budget_report_timestamp_seconds gauge",
        f"pft_budget_report_timestamp_seconds{{{h}}} {int(rep['now'])}",
        "# HELP pft_budget_bad_lines unreadable JSONL lines in the window's files",
        "# TYPE pft_budget_bad_lines gauge",
        f"pft_budget_bad_lines{{{h}}} {rep['bad_lines']}",
    ]
    series = [
        ("peak_unrecl_bytes", "max unreclaimable memory of one run in the window", "peak_unrecl_max"),
        ("peak_unrecl_p50_bytes", "median per-run unreclaimable peak", "peak_unrecl_p50"),
        ("peak_total_bytes", "max memory.current (incl. page cache) of one run", "peak_total_max"),
        ("cap_bytes", "configured MemoryMax (absent = uncapped)", "cap"),
        ("headroom_ratio", "cap / max unreclaimable peak", "headroom"),
        ("projected_30d_bytes", "30-day projection of the unreclaimable peak", "proj30"),
        ("projected_90d_bytes", "90-day projection of the unreclaimable peak", "proj90"),
        ("runs", "invocations in the window", "invocations"),
        ("oom_runs", "OOM-killed invocations in the window", "oom_runs"),
        ("failed_runs", "invocations whose Result was not success", "failed_runs"),
        ("runtime_max_seconds", "longest invocation runtime", "runtime_max"),
        ("verdict", "0 OK, 1 WARN, 2 FAIL, 3 UNCAPPED", None),
    ]
    for name, help_, key in series:
        lines += [f"# HELP pft_budget_{name} {help_}", f"# TYPE pft_budget_{name} gauge"]
        for u in rep["units"]:
            v = code[u["verdict"]] if key is None else u[key]
            if v is None:
                continue
            lines.append(f'pft_budget_{name}{{host="{esc(u["host"])}",unit="{esc(u["unit"])}"}} {v}')
    return "\n".join(lines) + "\n"


def read_heartbeat(conf):
    try:
        return int(_read(os.path.join(conf["DATA_DIR"], "heartbeat")).strip())
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- plan / apply / rollback


def build_plan(rep, conf, allow_lower=False, host=None):
    host = host or conf["HOST"]
    plan = []
    for u in rep["units"]:
        if u["host"] != host or excluded(u["unit"], conf):
            continue
        tgt, cap = u["target"], u["cap"]
        if u["verdict"] == "UNCAPPED":
            if u["invocations"] < conf["MIN_RUNS"]:
                continue  # never cap a unit on too few measured runs
            action = "set"
        elif cap is not None and tgt > cap and u["verdict"] in ("WARN", "FAIL"):
            action = "raise"
        elif allow_lower and cap is not None and tgt < cap and u["verdict"] == "OK":  # an OOM run is FAIL
            if u["invocations"] < conf["MIN_RUNS"]:
                continue  # never lower a cap on too few measured runs
            action = "lower"
        else:
            continue
        plan.append(
            {
                "unit": u["unit"],
                "action": action,
                "from": cap,
                "to": tgt,
                "peak": u["peak_unrecl_max"],
                "proj90": u["proj90"],
                "runs": u["invocations"],
            }
        )
    return plan


def dropin_text(p):
    proj = mib(p["proj90"]) if p["proj90"] is not None else "n/a"
    return (
        f"# written by pft-budget apply ({p['action']}): measured unreclaimable peak {mib(p['peak'])} over "
        f"{p['runs']} run(s), 90-day projection {proj}\n"
        "# rollback: sudo pft-budget rollback --yes (inside a pft-maint window)\n"
        f"[Service]\nMemoryMax={p['to']}\n"
    )


def maint_active():
    cmd = os.environ.get("PFT_BUD_MAINT", "pft-maint").split()
    try:
        return (
            subprocess.run(
                cmd + ["active"], stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def systemctl(*a):
    p = subprocess.run(
        systemctl_cmd() + list(a), capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, check=False
    )
    return p.returncode, p.stdout


def shown_memory_max(unit):
    rc, out = systemctl("show", unit, "-p", "MemoryMax", "--value")
    return out.strip() if rc == 0 else None


def cmd_apply(conf, args, rep):
    plan = build_plan(rep, conf, args.allow_lower)
    for p in plan:
        print("{} {} MemoryMax {} -> {}".format("APPLY" if args.yes else "WOULD", p["unit"], p["from"], p["to"]))
    if not plan:
        print("nothing to apply")
        return 0
    if not args.yes:
        print("dry run: add --yes inside a pft-maint window to write {} drop-ins".format(conf["DROPIN_NAME"]))
        return 0
    if not maint_active():
        print("REFUSED: no active pft-maint window (sudo pft-maint start --ttl 30m --reason ...)", file=sys.stderr)
        return 4
    for p in plan:
        if excluded(p["unit"], conf) or not UNIT_RE.match(p["unit"]):
            print(f"REFUSED: {p['unit']} is excluded", file=sys.stderr)
            return 4
    undo = []
    for p in plan:
        d = os.path.join(conf["DROPIN_ROOT"], p["unit"] + ".d")
        f = os.path.join(d, conf["DROPIN_NAME"])
        prev = _read(f) if os.path.exists(f) else None
        undo.append({"unit": p["unit"], "path": f, "previous": prev})
        os.makedirs(d, mode=0o755, exist_ok=True)
        with open(f + ".tmp", "w", encoding="ascii") as fh:
            fh.write(dropin_text(p))
        os.chmod(f + ".tmp", 0o644)
        os.replace(f + ".tmp", f)
    rec = os.path.join(conf["DATA_DIR"], "applied")
    os.makedirs(rec, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now(args)))
    with open(os.path.join(rec, stamp + ".json"), "w", encoding="utf-8") as fh:
        json.dump({"t": now(args), "plan": plan, "undo": undo}, fh, indent=1, sort_keys=True)
    rc, _ = systemctl("daemon-reload")
    bad = 0 if rc == 0 else 1
    for p in plan:
        got = shown_memory_max(p["unit"])
        ok = got == str(p["to"])
        bad += not ok
        print(f"{'OK' if ok else 'FAIL'} {p['unit']} MemoryMax={got} (want {p['to']})")
    return 1 if bad else 0


def cmd_rollback(conf, args):
    rec = os.path.join(conf["DATA_DIR"], "applied")
    done = sorted(f for f in os.listdir(rec) if f.endswith(".json")) if os.path.isdir(rec) else []
    if not done:
        print("REFUSED: nothing to roll back", file=sys.stderr)
        return 4
    with open(os.path.join(rec, done[-1]), encoding="utf-8") as fh:
        j = json.load(fh)
    for u in j["undo"]:
        print(
            "{} {}: {}".format(
                "RESTORE" if args.yes else "WOULD RESTORE",
                u["path"],
                "remove" if u["previous"] is None else "previous content",
            )
        )
    if not args.yes:
        print(f"dry run ({done[-1]}): add --yes inside a pft-maint window")
        return 0
    if not maint_active():
        print("REFUSED: no active pft-maint window", file=sys.stderr)
        return 4
    for u in j["undo"]:
        if u["previous"] is None:
            if os.path.exists(u["path"]):
                os.remove(u["path"])
        else:
            with open(u["path"], "w", encoding="ascii") as fh:
                fh.write(u["previous"])
    rc, _ = systemctl("daemon-reload")
    os.replace(os.path.join(rec, done[-1]), os.path.join(rec, done[-1] + ".rolled-back"))
    bad = 0 if rc == 0 else 1
    for u in j["undo"]:
        prev = next((p["from"] for p in j["plan"] if p["unit"] == u["unit"]), None)
        got = shown_memory_max(u["unit"])
        want = "infinity" if prev is None else str(prev)
        ok = got == want
        bad += not ok
        print("{} {} MemoryMax={} (want {})".format("OK" if ok else "FAIL", u["unit"], got, want))
    return 1 if bad else 0


# ---------------------------------------------------------------- main


def main(argv=None):
    ap = argparse.ArgumentParser(prog="budget.py")
    ap.add_argument("--conf", default=os.environ.get("PFT_BUD_CONF", "/etc/pft-budget.env"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--once", action="store_true")
    for name in ("report", "metrics", "plan", "apply", "rollback"):
        p = sub.add_parser(name)
        p.add_argument("--now", type=float)
        p.add_argument("--data", nargs="*", help="JSONL files to read instead of DATA_DIR")
        if name == "report":
            p.add_argument("--json", action="store_true")
        if name in ("plan", "apply"):
            p.add_argument("--allow-lower", action="store_true")
            p.add_argument("--host")
        if name in ("apply", "rollback"):
            p.add_argument("--yes", action="store_true")
    args = ap.parse_args(argv)
    try:
        conf = load_conf(args.conf)
        if args.cmd == "sample":
            return cmd_sample(conf, args)
        if args.cmd == "rollback":
            return cmd_rollback(conf, args)
        rep = build_report(conf, now(args), args.data)
    except ConfError as e:
        print(f"pft-budget: {e}", file=sys.stderr)
        return 3
    if args.cmd == "report":
        sys.stdout.write(json.dumps(rep, indent=1, sort_keys=True) + "\n" if args.json else fmt_report(rep))
        return report_rc(rep)
    if args.cmd == "metrics":
        sys.stdout.write(fmt_metrics(rep, conf, read_heartbeat(conf)))
        return 0
    if args.cmd == "plan":
        plan = build_plan(rep, conf, args.allow_lower, args.host)
        for p in plan:
            print(json.dumps(p, sort_keys=True))
        print(f"{len(plan)} change(s) planned" + ("" if plan else " - nothing to do"))
        return 0
    return cmd_apply(conf, args, rep)


if __name__ == "__main__":
    sys.exit(main())
