#!/usr/bin/env python3
"""jobwatch_lib: derive scheduled-job health from `systemctl show` output (pft-jobwatch's helper, stdlib only).

Read-only: the only command it runs is `systemctl show` (never start/stop/enable). For every watched timer and the
service it triggers it derives the schedule kind and interval, the last trigger, last success and last result, the
number of consecutive failed runs it has observed, and whether the job is missed (overdue), disabled or removed, and
renders them as Prometheus textfile metrics.

  collect --host H --state FILE --now EPOCH [--glob G ...]   inventory + derive + print the textfile; update FILE
  inventory --host H --state FILE --now EPOCH [--format tsv|json]   same derivation, a table (state not written)
  forget --state FILE JOB.timer                              drop a removed job from the state (exit 1 if unknown)

Exit codes: 0 ok, 1 systemctl failed (nothing printed, state untouched), 3 usage. Test hook: PFT_JW_SYSTEMCTL
(command used instead of `systemctl`, split on spaces).
"""

import calendar
import json
import os
import re
import subprocess
import sys
import time

VERSION = 1
DEFAULT_GLOBS = ("pft-*.timer", "postfiat*.timer")
TIMER_PROPS = (
    "Id,Unit,LoadState,ActiveState,UnitFileState,Result,LastTriggerUSec,NextElapseUSecRealtime,"
    "TimersMonotonic,TimersCalendar,AccuracyUSec,RandomizedDelayUSec,Persistent,ActiveEnterTimestamp"
)
SERVICE_PROPS = (
    "Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,ExecMainStartTimestamp,"
    "ExecMainStartTimestampMonotonic,ExecMainExitTimestamp,NRestarts"
)
# a timer counts as scheduling only if it is active AND its unit file is in one of these states
ENABLED_STATES = {
    "enabled",
    "enabled-runtime",
    "static",
    "linked",
    "linked-runtime",
    "generated",
    "transient",
}
# monotonic settings that repeat (the others fire once per boot/start/activation and give no interval)
REPEATING = ("OnUnitActiveUSec", "OnUnitInactiveUSec")
MISS_GRACE = 300  # s added to interval + accuracy + 2 x randomized delay before a job counts as missed
UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,200}\.timer$")
SPAN = {
    "us": 1e-6,
    "ms": 1e-3,
    "s": 1,
    "min": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
    "M": 2629800,
    "y": 31557600,
}
SPAN_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(us|ms|s|min|h|d|w|M|y)(?![a-z])")
TS_RE = re.compile(
    r"^[A-Z][a-z]{2} (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(\.\d{1,6})? UTC$"
)


def parse_show(text):
    """systemctl show output (blocks separated by blank lines) -> list of {key: [values]} (keys can repeat)."""
    blocks, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        k, sep, v = line.partition("=")
        if not sep:
            continue
        cur.setdefault(k, []).append(v)
    if cur:
        blocks.append(cur)
    return blocks


def one(block, key, default=""):
    v = block.get(key)
    return v[0] if v else default


def parse_span(s):
    """systemd time span ('1min', '1h 30min', '500ms', '0') -> seconds (float); None if unparsable."""
    s = s.strip()
    if s in ("0", ""):
        return 0.0
    total, pos = 0.0, 0
    for m in SPAN_RE.finditer(s):
        if s[pos : m.start()].strip():
            return None
        total += float(m.group(1)) * SPAN[m.group(2)]
        pos = m.end()
    if pos == 0 or s[pos:].strip():
        return None
    return total


def parse_ts(s):
    """'Fri 2026-11-06 16:08:15[.123456] UTC' (TZ=UTC, --timestamp=us+utc) -> epoch float; 0 for n/a/empty."""
    m = TS_RE.match(s.strip())
    if not m:
        return 0.0
    t = time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    frac = float(m.group(2)) if m.group(2) else 0.0
    return float(calendar.timegm(t)) + frac


def schedule(timer):
    """-> (kind, interval_s, spec). kind: monotonic | calendar | mixed | none. interval 0 = no repeating interval
    known from the unit itself (calendar: learned from next - last trigger, see derive())."""
    mono, specs = [], []
    for v in timer.get("TimersMonotonic", []):
        m = re.match(r"^\{ (\w+)=([^;]*) ;", v)
        if not m:
            continue
        specs.append(f"{m.group(1)}={m.group(2).strip()}")
        if m.group(1) in REPEATING:
            sec = parse_span(m.group(2))
            if sec:
                mono.append(sec)
    cal = []
    for v in timer.get("TimersCalendar", []):
        m = re.match(r"^\{ OnCalendar=(.*?) ; ", v)
        if m:
            cal.append(m.group(1).strip())
            specs.append(f"OnCalendar={m.group(1).strip()}")
    kind = (
        "mixed"
        if mono and cal
        else "monotonic"
        if mono
        else "calendar"
        if cal
        else "none"
    )
    return kind, (min(mono) if mono else 0.0), " | ".join(specs)


def derive(timer, service, prev, now):
    """One job. timer/service: parsed show blocks ({} if absent); prev: this job's state entry ({} if new).
    -> (metrics dict, new state entry)."""
    name = one(timer, "Id")
    present = one(timer, "LoadState") == "loaded"
    kind, interval, spec = (
        schedule(timer)
        if present
        else (prev.get("kind", "none"), 0.0, prev.get("spec", ""))
    )
    st = {
        "kind": kind,
        "spec": spec,
        "service": one(timer, "Unit") or prev.get("service", ""),
        "cal_interval": prev.get("cal_interval", 0.0)
        if prev.get("spec") == spec
        else 0.0,
        "last_success": prev.get("last_success", 0.0),
        "consecutive_failures": prev.get("consecutive_failures", 0),
        "seen_run": prev.get("seen_run", ""),
        "failed_runs": prev.get("failed_runs", 0),
        "runs": prev.get("runs", 0),
    }
    last_trigger = parse_ts(one(timer, "LastTriggerUSec"))
    next_rt = parse_ts(one(timer, "NextElapseUSecRealtime"))
    if kind in ("calendar", "mixed") and last_trigger and next_rt > last_trigger:
        gap = next_rt - last_trigger
        # the smallest gap seen is the schedule's period (a gap of 2 periods follows a missed run)
        if not st["cal_interval"] or gap < st["cal_interval"]:
            st["cal_interval"] = gap
    if kind == "monotonic":
        interval_s = interval
    elif kind == "mixed":
        interval_s = (
            min(x for x in (interval, st["cal_interval"]) if x)
            if (interval or st["cal_interval"])
            else 0.0
        )
    elif kind == "calendar":
        interval_s = st["cal_interval"]
    else:
        interval_s = 0.0

    enabled = (
        present
        and one(timer, "ActiveState") == "active"
        and one(timer, "UnitFileState") in ENABLED_STATES
    )
    svc_loaded = one(service, "LoadState") == "loaded"
    running = svc_loaded and one(service, "ActiveState") in (
        "active",
        "activating",
        "reloading",
        "deactivating",
    )
    start_mono = one(service, "ExecMainStartTimestampMonotonic", "0")
    result = one(service, "Result", "") if svc_loaded else ""
    started = start_mono not in ("", "0")
    exit_status = one(service, "ExecMainStatus", "0")
    # Result is authoritative (it honours SuccessExitStatus=); ExecMainStatus alone is not
    failed_now = svc_loaded and (
        one(service, "ActiveState") == "failed" or result not in ("", "success")
    )
    # a finished run we have not counted yet: keyed by its start time + result (start-limit-hit has no new start)
    run_key = f"{start_mono}:{result}:{exit_status}"
    if (
        svc_loaded
        and not running
        and (started or failed_now)
        and run_key != st["seen_run"]
    ):
        st["seen_run"] = run_key
        st["runs"] += 1
        if failed_now:
            st["consecutive_failures"] += 1
            st["failed_runs"] += 1
        else:
            st["consecutive_failures"] = 0
            st["last_success"] = parse_ts(one(service, "ExecMainExitTimestamp")) or now
    never_run = not last_trigger and not started
    ref = last_trigger or parse_ts(one(timer, "ActiveEnterTimestamp"))
    grace = (
        (parse_span(one(timer, "AccuracyUSec", "0")) or 0.0)
        # twice the randomized delay: the learned calendar interval can be one delay short, a real gap one delay long
        + 2 * (parse_span(one(timer, "RandomizedDelayUSec", "0")) or 0.0)
        + MISS_GRACE
    )
    missed = 0
    if enabled and interval_s and ref and now - ref > interval_s + grace:
        missed = 1  # no trigger for longer than one interval (+ grace); a run still going counts too
    if enabled and kind in ("calendar", "mixed") and next_rt and now - next_rt > grace:
        missed = 1  # the next elapse is in the past: the timer did not fire
    m = {
        "job": name,
        "service": st["service"],
        "kind": kind,
        "present": 1 if present else 0,
        "disabled": 0 if enabled else 1,
        "running": 1 if running else 0,
        "never_run": 1 if never_run else 0,
        "failed": 1 if failed_now else 0,
        "consecutive_failures": st["consecutive_failures"],
        "missed": missed,
        "interval_seconds": round(interval_s, 3),
        "last_trigger_timestamp_seconds": last_trigger,
        "last_success_timestamp_seconds": st["last_success"],
        "next_elapse_timestamp_seconds": next_rt,
        "runs_observed_total": st["runs"],
        "failed_runs_observed_total": st["failed_runs"],
        "spec": spec,
    }
    return m, st


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def fmt(v):
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".") if v != int(v) else str(int(v))
    return str(v)


# The per-job label is `timer`, never `job`: Prometheus would rename a textfile `job` label to `exported_job`
# (the scrape job owns `job`), and every `on (host, job)` join in the rules would then match all jobs of a host.
RESERVED_LABELS = ("job", "instance")
GAUGES = (
    (
        "present",
        "1 if the timer unit is loaded (0: removed; kept until `pft-jobwatch forget`)",
    ),
    ("disabled", "1 if the timer will not fire: inactive, disabled, masked or removed"),
    ("running", "1 while the triggered service is running"),
    ("never_run", "1 if the timer has never triggered and the service never started"),
    (
        "failed",
        "1 if the service's last run failed (Result != success or non-zero exit)",
    ),
    (
        "consecutive_failures",
        "failed runs in a row, as observed by jobwatch (runs between two collections can be missed)",
    ),
    (
        "missed",
        "1 if no trigger for longer than interval + accuracy + 2 x randomized delay + 300 s, or next elapse passed",
    ),
    (
        "interval_seconds",
        "repeat interval (monotonic: OnUnitActive/InactiveSec; calendar: smallest next-last gap seen)",
    ),
    (
        "last_trigger_timestamp_seconds",
        "Unix time the timer last triggered (0 = never)",
    ),
    (
        "last_success_timestamp_seconds",
        "Unix time the last successful run ended, as observed by jobwatch (0 = none yet)",
    ),
    (
        "next_elapse_timestamp_seconds",
        "Unix time of the next calendar elapse (0 for monotonic timers)",
    ),
    (
        "runs_observed_total",
        "finished runs counted by jobwatch since its state was created",
    ),
    (
        "failed_runs_observed_total",
        "failed runs counted by jobwatch since its state was created",
    ),
)


def render(host, jobs, now, ok=True, err=""):
    h = esc(host)
    out = [
        "# HELP pft_jobwatch_up 1 if the last systemctl inventory succeeded",
        "# TYPE pft_jobwatch_up gauge",
        f'pft_jobwatch_up{{host="{h}"}} {1 if ok else 0}',
        "# HELP pft_jobwatch_collect_timestamp_seconds Unix time of the last collection attempt",
        "# TYPE pft_jobwatch_collect_timestamp_seconds gauge",
        f'pft_jobwatch_collect_timestamp_seconds{{host="{h}"}} {int(now)}',
        "# HELP pft_jobwatch_version pft-jobwatch helper version",
        "# TYPE pft_jobwatch_version gauge",
        f'pft_jobwatch_version{{host="{h}"}} {VERSION}',
    ]
    if not ok:
        return "\n".join(out) + "\n"
    out += [
        "# HELP pft_jobwatch_jobs Watched timers by state",
        "# TYPE pft_jobwatch_jobs gauge",
    ]
    for state, n in (
        ("total", len(jobs)),
        ("present", sum(j["present"] for j in jobs)),
        ("disabled", sum(j["disabled"] for j in jobs)),
        ("failed", sum(j["failed"] for j in jobs)),
        ("missed", sum(j["missed"] for j in jobs)),
    ):
        out.append(f'pft_jobwatch_jobs{{host="{h}",state="{state}"}} {n}')
    out += [
        "# HELP pft_jobwatch_job_info Watched timer, its service and schedule kind (value 1)",
        "# TYPE pft_jobwatch_job_info gauge",
    ]
    for j in jobs:
        out.append(
            f'pft_jobwatch_job_info{{host="{h}",timer="{esc(j["job"])}",service="{esc(j["service"])}",kind="{j["kind"]}"}} 1'
        )
    for key, help_ in GAUGES:
        typ = "counter" if key.endswith("_total") else "gauge"
        out += [
            f"# HELP pft_jobwatch_job_{key} {help_}",
            f"# TYPE pft_jobwatch_job_{key} {typ}",
        ]
        for j in jobs:
            out.append(
                f'pft_jobwatch_job_{key}{{host="{h}",timer="{esc(j["job"])}"}} {fmt(j[key])}'
            )
    return "\n".join(out) + "\n"


def systemctl(args):
    base = os.environ.get("PFT_JW_SYSTEMCTL", "systemctl").split()
    env = dict(
        os.environ, TZ="UTC", LC_ALL="C", SYSTEMD_PAGER="cat", SYSTEMD_COLORS="0"
    )
    p = subprocess.run(
        base + ["show", "--no-pager", "--timestamp=us+utc"] + args,
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"systemctl show failed (rc {p.returncode}): {p.stderr.strip()[:200]}"
        )
    return parse_show(p.stdout)


def load_state(path):
    try:
        with open(path) as fh:
            d = json.load(fh)
    except FileNotFoundError:
        return {"version": VERSION, "jobs": {}}
    if not isinstance(d, dict) or not isinstance(d.get("jobs"), dict):
        raise TypeError("state file is not a jobwatch state")
    return d


def save_state(path, d):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as fh:
        json.dump(d, fh, sort_keys=True, indent=1)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def inventory(state, globs, now):
    """-> (jobs metrics list, new state). Watched = loaded timers matching globs + every job already in the state
    (so a disabled-and-unloaded or deleted timer stays visible)."""
    names = {
        one(b, "Id")
        for b in systemctl(["-p", "Id,LoadState"] + list(globs))
        if one(b, "LoadState") == "loaded"
    }
    names |= set(state["jobs"])
    names = sorted(n for n in names if UNIT_RE.match(n))
    if not names:
        return [], {"version": VERSION, "jobs": {}}
    timers = {one(b, "Id"): b for b in systemctl(["-p", TIMER_PROPS, "--"] + names)}
    svc_names = sorted(
        {
            one(t, "Unit") or state["jobs"].get(n, {}).get("service", "")
            for n, t in timers.items()
        }
        - {""}
    )
    services = (
        {one(b, "Id"): b for b in systemctl(["-p", SERVICE_PROPS, "--"] + svc_names)}
        if svc_names
        else {}
    )
    jobs, new = [], {"version": VERSION, "jobs": {}}
    for n in names:
        t = timers.get(n, {"Id": [n], "LoadState": ["not-found"]})
        prev = state["jobs"].get(n, {})
        sname = one(t, "Unit") or prev.get("service", "")
        m, st = derive(t, services.get(sname, {}), prev, now)
        jobs.append(m)
        new["jobs"][n] = st
    return jobs, new


def arg(argv, flag, default=None):
    if flag in argv:
        i = argv.index(flag)
        if i + 1 >= len(argv):
            raise SystemExit(3)
        return argv[i + 1]
    return default


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 3
    cmd, rest = argv[0], argv[1:]
    state_path = arg(rest, "--state")
    if cmd == "forget":
        names = [a for a in rest if a.endswith(".timer")]
        if not state_path or len(names) != 1:
            print("usage: forget --state FILE JOB.timer", file=sys.stderr)
            return 3
        d = load_state(state_path)
        if names[0] not in d["jobs"]:
            print(f"{names[0]}: not in the state", file=sys.stderr)
            return 1
        del d["jobs"][names[0]]
        save_state(state_path, d)
        print(f"forgot {names[0]}")
        return 0
    if cmd not in ("collect", "inventory"):
        print(__doc__, file=sys.stderr)
        return 3
    host = arg(rest, "--host")
    now = arg(rest, "--now")
    if (
        not host
        or not state_path
        or not now
        or not re.match(r"^[a-z][a-z0-9_-]{0,30}$", host)
        or not now.isdigit()
    ):
        print(
            "usage: collect|inventory --host H --state FILE --now EPOCH [--glob G ...]",
            file=sys.stderr,
        )
        return 3
    globs = [rest[i + 1] for i, a in enumerate(rest[:-1]) if a == "--glob"] or list(
        DEFAULT_GLOBS
    )
    try:
        state = load_state(state_path)
        jobs, new = inventory(state, globs, int(now))
    except (
        RuntimeError,
        TypeError,
        ValueError,
        OSError,
        subprocess.TimeoutExpired,
    ) as e:
        print(f"jobwatch: {e}", file=sys.stderr)
        return 1
    if cmd == "inventory":
        if arg(rest, "--format", "tsv") == "json":
            print(json.dumps(jobs, indent=1, sort_keys=True))
        else:
            cols = (
                "job",
                "kind",
                "interval_seconds",
                "disabled",
                "failed",
                "consecutive_failures",
                "missed",
                "present",
                "spec",
            )
            print("\t".join(cols))
            for j in jobs:
                print("\t".join(fmt(j[c]) for c in cols))
            print(
                f"# {len(jobs)} jobs, {sum(j['failed'] for j in jobs)} failed, {sum(j['missed'] for j in jobs)} missed, "
                f"{sum(j['disabled'] for j in jobs)} disabled"
            )
        return 0
    sys.stdout.write(render(host, jobs, int(now)))
    save_state(state_path, new)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
