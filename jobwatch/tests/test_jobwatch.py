#!/usr/bin/env python3
"""Offline tests for pft-jobwatch (jobwatch_lib.py + pft-jobwatch.sh) against captured `systemctl show` fixtures and
a stub systemctl (tests/stub_systemctl.py).

Run: TEST_TMPDIR=~/.cache python3 -u jobwatch/tests/test_jobwatch.py   (stdlib only; /tmp is noexec on the hosts, so
the temp dir defaults to ~/.cache). Prints one PASS/FAIL line per check and 'RESULT: PASS|FAIL (n checks)'.
Fixtures: pft-heartbeat (monotonic), pft-kernwatch (calendar), pft-vulnscan (calendar + 30 min RandomizedDelaySec),
pft-egress-reapply@postfiatd (template instance) are captured verbatim from the validator; pft-jwfail (non-zero
exit), pft-jwnever (never run) and pft-jwdis (disable --now) are those captures with only the named fields changed.
"""

import atexit
import calendar
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
JW = os.environ.get("JW_DIR") or os.path.dirname(
    HERE
)  # JW_DIR: a mutant copy (tests/mutate.py)
HELPER = os.path.join(JW, "jobwatch_lib.py")
SCRIPT = os.path.join(JW, "pft-jobwatch.sh")
STUB = os.path.join(HERE, "stub_systemctl.py")
FIX = os.path.join(HERE, "fixtures")
TMP_BASE = os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache")

sys.path.insert(0, JW)
import jobwatch_lib as jl

results = []


def read(path):
    try:
        with open(path) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(
        f"{'PASS' if cond else 'FAIL'} {name}{'' if cond else ' :: ' + str(detail)[:300]}",
        flush=True,
    )


def utc(s):
    return float(calendar.timegm(__import__("time").strptime(s, "%Y-%m-%d %H:%M:%S")))


def load(name):
    with open(os.path.join(FIX, name + ".show")) as fh:
        return jl.parse_show(fh.read())[0]


os.makedirs(TMP_BASE, exist_ok=True)
TMP = tempfile.mkdtemp(prefix="pft-jw-test.", dir=TMP_BASE)
atexit.register(shutil.rmtree, TMP, True)

# ---- parsing ----
check("span 1min", jl.parse_span("1min") == 60)
check("span 1h 30min", jl.parse_span("1h 30min") == 5400)
check("span 500ms", abs(jl.parse_span("500ms") - 0.5) < 1e-9)
check("span 1w 1d 13h", jl.parse_span("1w 1d 13h") == 604800 + 86400 + 13 * 3600)
check("span 0 / empty", jl.parse_span("0") == 0 and jl.parse_span("") == 0)
check(
    "span junk -> None",
    jl.parse_span("soon") is None and jl.parse_span("5min later") is None,
)
check(
    "ts with usec",
    jl.parse_ts("Fri 2026-11-06 16:10:08.461972 UTC")
    == utc("2026-11-06 16:10:08") + 0.461972,
)
check(
    "ts without usec",
    jl.parse_ts("Fri 2026-11-06 16:10:03 UTC") == utc("2026-11-06 16:10:03"),
)
check(
    "ts n/a / empty / local zone -> 0",
    jl.parse_ts("n/a") == 0
    and jl.parse_ts("") == 0
    and jl.parse_ts("Fri 2026-11-06 17:10:03 CET") == 0,
)
blocks = jl.parse_show(
    "Id=a.timer\nTimersMonotonic=x\nTimersMonotonic=y\n\nId=b.timer\n"
)
check(
    "parse_show: blocks + repeated keys",
    len(blocks) == 2 and blocks[0]["TimersMonotonic"] == ["x", "y"],
    blocks,
)

# ---- schedule kinds (captured fixtures) ----
hb_t, hb_s = load("pft-heartbeat.timer"), load("pft-heartbeat.service")
kw_t, kw_s = load("pft-kernwatch.timer"), load("pft-kernwatch.service")
vs_t, vs_s = load("pft-vulnscan.timer"), load("pft-vulnscan.service")
eg_t, eg_s = (
    load("pft-egress-reapply@postfiatd.timer"),
    load("pft-egress-reapply@postfiatd.service"),
)
k, iv, spec = jl.schedule(hb_t)
check(
    "monotonic: OnUnitActiveSec=1min -> 60 s, OnBootSec ignored",
    (k, iv) == ("monotonic", 60.0),
    (k, iv, spec),
)
k, iv, spec = jl.schedule(kw_t)
check(
    "calendar: kind calendar, spec kept",
    k == "calendar" and "OnCalendar=*-*-* *:00/2:15" in spec,
    (k, spec),
)
two = dict(
    hb_t,
    TimersMonotonic=hb_t["TimersMonotonic"]
    + ["{ OnUnitInactiveUSec=5min ; next_elapse=0 }"],
)
k, iv, _ = jl.schedule(two)
check(
    "monotonic: two repeating settings -> the shorter interval",
    (k, iv) == ("monotonic", 60.0),
    (k, iv),
)
k, iv, _ = jl.schedule(eg_t)
check("template instance: monotonic 5 min", (k, iv) == ("monotonic", 300.0), (k, iv))
k, iv, _ = jl.schedule(
    {"Id": ["x.timer"], "TimersMonotonic": ["{ OnBootUSec=1min ; next_elapse=1min }"]}
)
check("boot-only timer: no repeating interval", (k, iv) == ("none", 0.0), (k, iv))

# ---- success (monotonic, captured) ----
T_HB = utc("2026-11-06 16:10:03")
m, st = jl.derive(hb_t, hb_s, {}, int(T_HB) + 30)
check(
    "success: failed 0, consecutive 0, never_run 0, present 1, disabled 0",
    (
        m["failed"],
        m["consecutive_failures"],
        m["never_run"],
        m["present"],
        m["disabled"],
    )
    == (0, 0, 0, 1, 0),
    m,
)
check(
    "success: last_success = ExecMainExitTimestamp",
    m["last_success_timestamp_seconds"]
    == jl.parse_ts(jl.one(hb_s, "ExecMainExitTimestamp")),
    m,
)
check(
    "success: last trigger from LastTriggerUSec",
    m["last_trigger_timestamp_seconds"] == T_HB,
    m,
)
check(
    "success: interval 60, missed 0",
    m["interval_seconds"] == 60 and m["missed"] == 0,
    m,
)
check(
    "success: one run counted",
    m["runs_observed_total"] == 1 and m["failed_runs_observed_total"] == 0,
    m,
)
m2, st2 = jl.derive(hb_t, hb_s, st, int(T_HB) + 90)
check("same run seen twice is counted once", m2["runs_observed_total"] == 1, m2)

# ---- missed (monotonic): threshold interval 60 + accuracy 5 + 2 x 0 + 300 ----
m, _ = jl.derive(hb_t, hb_s, {}, int(T_HB) + 364)
check("monotonic: 364 s after last trigger is not missed", m["missed"] == 0, m)
m, _ = jl.derive(hb_t, hb_s, {}, int(T_HB) + 366)
check("monotonic: 366 s after last trigger is missed", m["missed"] == 1, m)

# ---- calendar (captured kernwatch: 2-min schedule, learned from next - last) ----
T_KW = jl.parse_ts(jl.one(kw_t, "LastTriggerUSec"))
m, st = jl.derive(kw_t, kw_s, {}, int(T_KW) + 30)
# LastTriggerUSec is the real (accuracy-delayed) trigger: 16:10:16 for the :15 slot, so next - last = 119 s
check(
    "calendar: interval learned = next - last (within accuracy 1 s of 120)",
    m["interval_seconds"] == 119 and m["kind"] == "calendar",
    m,
)
check(
    "calendar: next elapse exported",
    m["next_elapse_timestamp_seconds"] == T_KW + 119,
    m,
)
check("calendar: on time -> missed 0", m["missed"] == 0, m)
m, _ = jl.derive(kw_t, kw_s, {}, int(T_KW) + 120 + 1 + 300 + 1)
check(
    "calendar: next elapse passed by > accuracy + grace -> missed", m["missed"] == 1, m
)
m, _ = jl.derive(kw_t, kw_s, {}, int(T_KW) + 120 + 300)
check("calendar: next elapse passed by < grace -> not missed", m["missed"] == 0, m)
big = dict(kw_t, NextElapseUSecRealtime=["Fri 2026-11-06 16:20:15 UTC"])
_, stb = jl.derive(big, kw_s, {}, int(T_KW))
check(
    "calendar: a 2-period gap first, then the 1-period gap wins (min kept)",
    stb["cal_interval"] > 120
    and jl.derive(kw_t, kw_s, stb, int(T_KW))[1]["cal_interval"] == 119,
    stb,
)
_, st_spec = jl.derive(
    kw_t, kw_s, dict(stb, spec="OnCalendar=*:*:00", cal_interval=60.0), int(T_KW)
)
check(
    "calendar: changed spec resets the learned interval",
    st_spec["cal_interval"] == 119,
    st_spec,
)

# ---- calendar + RandomizedDelaySec=30min (captured vulnscan) ----
T_VS = jl.parse_ts(jl.one(vs_t, "LastTriggerUSec"))
m, _ = jl.derive(vs_t, vs_s, {}, int(T_VS) + 3600)
iv = m["interval_seconds"]
check(
    "random delay: learned interval within one delay of 24 h",
    86400 - 1800 <= iv <= 86400 + 1800,
    iv,
)
m, _ = jl.derive(vs_t, vs_s, {}, int(T_VS + iv + 60 + 3600 + 300) - 5)
check(
    "random delay: grace = accuracy + 2 x delay + 300 (not missed just inside)",
    m["missed"] == 0
    or m["next_elapse_timestamp_seconds"] < T_VS + iv + 60 + 3600 + 300 - 5 - 3960,
    m,
)
nofire = dict(vs_t, NextElapseUSecRealtime=[""])
m, _ = jl.derive(
    nofire,
    vs_s,
    {"spec": jl.schedule(vs_t)[2], "cal_interval": iv},
    int(T_VS + iv + 60 + 3600 + 300) + 5,
)
check(
    "random delay: no trigger for interval + full grace -> missed", m["missed"] == 1, m
)

# ---- failed run (non-zero exit) ----
fl_t, fl_s = load("pft-jwfail.timer"), load("pft-jwfail.service")
m, st = jl.derive(fl_t, fl_s, {}, int(T_HB) + 30)
check(
    "failed: failed 1, consecutive 1, failed_runs 1",
    (m["failed"], m["consecutive_failures"], m["failed_runs_observed_total"])
    == (1, 1, 1),
    m,
)
check("failed: no last success", m["last_success_timestamp_seconds"] == 0, m)
m, st = jl.derive(fl_t, fl_s, st, int(T_HB) + 50)
check("failed: same failed run not counted twice", m["consecutive_failures"] == 1, m)
fl_s2 = dict(fl_s, ExecMainStartTimestampMonotonic=["738767438073"])
m, st = jl.derive(fl_t, fl_s2, st, int(T_HB) + 90)
check(
    "failed: next failed run -> consecutive 2",
    m["consecutive_failures"] == 2 and m["failed_runs_observed_total"] == 2,
    m,
)
ok_s = dict(
    hb_s, Id=["pft-jwfail.service"], ExecMainStartTimestampMonotonic=["738827438073"]
)
m, st = jl.derive(fl_t, ok_s, st, int(T_HB) + 150)
check(
    "failed: a successful run resets consecutive to 0 and sets last success",
    m["failed"] == 0
    and m["consecutive_failures"] == 0
    and m["last_success_timestamp_seconds"] > 0,
    m,
)
sl = dict(
    ok_s, Result=["start-limit-hit"], ActiveState=["failed"]
)  # same start as the last (successful) run: only Result changes
m, _ = jl.derive(fl_t, sl, st, int(T_HB) + 160)
check(
    "start-limit-hit (no new start) counts as one failure",
    m["failed"] == 1 and m["consecutive_failures"] == 1,
    m,
)
ar = dict(fl_s, ActiveState=["activating"], SubState=["auto-restart"])
m, _ = jl.derive(fl_t, ar, {}, int(T_HB) + 30)
check(
    "failed run not counted yet (auto-restart) still reports consecutive >= 1, never 0",
    (m["failed"], m["running"], m["consecutive_failures"]) == (1, 1, 1),
    m,
)
to = dict(hb_s, Result=["timeout"])
check(
    "Result=timeout with ActiveState inactive is a failure",
    jl.derive(hb_t, to, {}, int(T_HB))[0]["failed"] == 1,
)
fa = dict(hb_s, ActiveState=["failed"])
check(
    "ActiveState=failed is a failure even if Result reads success",
    jl.derive(hb_t, fa, {}, int(T_HB))[0]["failed"] == 1,
)
sx = dict(hb_s, ExecMainStatus=["2"])
m, _ = jl.derive(hb_t, sx, {}, int(T_HB) + 30)
check(
    "Result=success with exit 2 (SuccessExitStatus=) is not a failure",
    m["failed"] == 0,
    m,
)
sig = dict(fl_s, Result=["signal"], ExecMainStatus=["9"], ExecMainCode=["2"])
m, _ = jl.derive(fl_t, sig, {}, int(T_HB) + 30)
check("killed by signal is a failure", m["failed"] == 1, m)

# ---- running long ----
run_s = dict(hb_s, ActiveState=["activating"], SubState=["start"])
m, st = jl.derive(hb_t, run_s, {}, int(T_HB) + 30)
check(
    "running: running 1, run not counted yet",
    m["running"] == 1 and m["runs_observed_total"] == 0,
    m,
)
m, _ = jl.derive(hb_t, run_s, st, int(T_HB) + 400)
check(
    "running past interval + grace -> missed (no new triggers while it runs)",
    m["missed"] == 1,
    m,
)

# ---- never run ----
nv_t, nv_s = load("pft-jwnever.timer"), load("pft-jwnever.service")
T_ENTER = jl.parse_ts(jl.one(nv_t, "ActiveEnterTimestamp"))
m, _ = jl.derive(nv_t, nv_s, {}, int(T_ENTER) + 60)
check(
    "never run: never_run 1, failed 0, last success 0, runs 0",
    (
        m["never_run"],
        m["failed"],
        m["last_success_timestamp_seconds"],
        m["runs_observed_total"],
    )
    == (1, 0, 0, 0),
    m,
)
check("never run: no learned calendar interval yet", m["interval_seconds"] == 0, m)
T_NEXT = jl.parse_ts(jl.one(nv_t, "NextElapseUSecRealtime"))
m, _ = jl.derive(nv_t, nv_s, {}, int(T_NEXT) + 400)
check("never run: next elapse long past -> missed", m["missed"] == 1, m)

nvm = dict(hb_t, LastTriggerUSec=[""])
nvm_s = dict(
    hb_s,
    ExecMainStartTimestamp=["n/a"],
    ExecMainStartTimestampMonotonic=["0"],
    ExecMainExitTimestamp=["n/a"],
)
T_HB_ENTER = jl.parse_ts(jl.one(hb_t, "ActiveEnterTimestamp"))
m, _ = jl.derive(nvm, nvm_s, {}, int(T_HB_ENTER) + 360)
check(
    "never run (monotonic): not missed within interval + grace of timer activation",
    m["never_run"] == 1 and m["missed"] == 0,
    m,
)
m, _ = jl.derive(nvm, nvm_s, {}, int(T_HB_ENTER) + 370)
check(
    "never run (monotonic): missed after interval + grace from timer activation",
    m["missed"] == 1,
    m,
)
m, _ = jl.derive(nvm, hb_s, {}, int(T_HB) + 10)
check(
    "never triggered but service started by hand: never_run 0", m["never_run"] == 0, m
)

# ---- disabled ----
ds_t, ds_s = load("pft-jwdis.timer"), load("pft-jwdis.service")
m, _ = jl.derive(ds_t, ds_s, {}, int(T_HB) + 3600)
check(
    "disabled: disabled 1, present 1, missed 0 (a disabled job is not also 'missed')",
    (m["disabled"], m["present"], m["missed"]) == (1, 1, 0),
    m,
)
for ufs, want in (
    ("enabled", 0),
    ("static", 0),
    ("masked", 1),
    ("disabled", 1),
    ("enabled-runtime", 0),
):
    t = dict(hb_t, UnitFileState=[ufs])
    check(
        f"UnitFileState {ufs} -> disabled {want}",
        jl.derive(t, hb_s, {}, int(T_HB))[0]["disabled"] == want,
    )
t = dict(hb_t, ActiveState=["inactive"])
check(
    "enabled but stopped -> disabled 1",
    jl.derive(t, hb_s, {}, int(T_HB))[0]["disabled"] == 1,
)

# ---- removed ----
_, st = jl.derive(hb_t, hb_s, {}, int(T_HB))
gone = {
    "Id": ["pft-heartbeat.timer"],
    "LoadState": ["not-found"],
    "ActiveState": ["inactive"],
}
m, st_g = jl.derive(gone, {}, st, int(T_HB) + 600)
check(
    "removed: present 0, disabled 1, failed 0, missed 0",
    (m["present"], m["disabled"], m["failed"], m["missed"]) == (0, 1, 0, 0),
    m,
)
check(
    "removed: kind/service/last success kept from state",
    m["kind"] == "monotonic"
    and m["service"] == "pft-heartbeat.service"
    and m["last_success_timestamp_seconds"] == st["last_success"],
    m,
)

# ---- render ----
jobs = [
    jl.derive(hb_t, hb_s, {}, int(T_HB))[0],
    jl.derive(fl_t, fl_s, {}, int(T_HB))[0],
    jl.derive(ds_t, ds_s, {}, int(T_HB))[0],
]
txt = jl.render("validator", jobs, int(T_HB))
lines = [ln for ln in txt.splitlines() if ln and not ln.startswith("#")]
check(
    "render: up 1 + timestamp",
    'pft_jobwatch_up{host="validator"} 1' in lines
    and f'pft_jobwatch_collect_timestamp_seconds{{host="validator"}} {int(T_HB)}'
    in lines,
)
check(
    "render: jobs totals",
    'pft_jobwatch_jobs{host="validator",state="total"} 3' in lines
    and 'pft_jobwatch_jobs{host="validator",state="failed"} 1' in lines
    and 'pft_jobwatch_jobs{host="validator",state="disabled"} 1' in lines,
    lines[:12],
)
for key, _ in jl.GAUGES:
    n = sum(1 for ln in lines if ln.startswith(f"pft_jobwatch_job_{key}{{"))
    if n != 3:
        check(f"render: {key} has one sample per job", False, n)
check(
    "render: every gauge has one sample per job",
    all(
        sum(1 for ln in lines if ln.startswith(f"pft_jobwatch_job_{k}{{")) == 3
        for k, _ in jl.GAUGES
    ),
)
check(
    "render: first label is host on every sample",
    all(ln.split("{", 1)[1].startswith('host="validator"') for ln in lines),
)
check(
    "render: failed job sample",
    'pft_jobwatch_job_failed{host="validator",timer="pft-jwfail.timer"} 1' in lines,
)
check(
    "render: no sample uses a scrape-reserved label (job, instance): drill run 07",
    not any(
        re.search(r"[{,](" + "|".join(jl.RESERVED_LABELS) + ')="', ln) for ln in lines
    ),
)
check(
    "render: label escaping",
    'timer="a\\"b"' in jl.render("validator", [dict(jobs[0], job='a"b')], 0),
)
check(
    "render: up 0 has no job samples",
    "pft_jobwatch_job_" not in jl.render("validator", jobs, 0, ok=False),
)

# ---- end to end: pft-jobwatch.sh + helper + stub systemctl ----
FDIR = os.path.join(TMP, "fix")
shutil.copytree(FIX, FDIR)
SLOG = os.path.join(TMP, "stub.log")
STATE = os.path.join(TMP, "state")
TEXT = os.path.join(TMP, "text")
os.makedirs(TEXT)
ENV = dict(
    os.environ,
    PFT_JW_CONF="/nonexistent",
    PFT_JW_HELPER=HELPER,
    PFT_JW_SYSTEMCTL=f"{sys.executable} {STUB}",
    JW_STUB_DIR=FDIR,
    JW_STUB_LOG=SLOG,
    STATE_DIR=STATE,
    TEXTFILE_DIR=TEXT,
    HOST_LABEL="validator",
    PFT_JW_NOW=str(int(T_HB) + 30),
    JOB_GLOBS="pft-*.timer postfiat*.timer",
)


def sh(*args, env=None, inp=None):
    p = subprocess.run(
        ["bash", SCRIPT, *args],
        check=False,
        capture_output=True,
        text=True,
        env=env or ENV,
        input=inp,
        timeout=120,
    )
    return p.returncode, p.stdout, p.stderr


rc, out, err = sh("collect")
prom = os.path.join(TEXT, "pft_jobwatch_validator.prom")
check(
    "e2e: stub answered (not the real systemctl)",
    os.path.exists(SLOG) and "show" in read(SLOG),
    err,
)
check(
    "e2e collect: rc 0, textfile written", rc == 0 and os.path.exists(prom), (rc, err)
)
txt = read(prom) if os.path.exists(prom) else ""
check(
    "e2e: 7 fixture jobs inventoried",
    'pft_jobwatch_jobs{host="validator",state="total"} 7' in txt,
    txt[:600],
)
check(
    "e2e: failed/disabled counted",
    'state="failed"} 1' in txt and 'state="disabled"} 1' in txt,
)
check(
    "e2e: textfile 0644, no temp file left",
    stat.S_IMODE(os.stat(prom).st_mode) == 0o644
    and not [f for f in os.listdir(TEXT) if f.startswith(".")],
)
check(
    "e2e: state dir 0700, state 0600",
    stat.S_IMODE(os.stat(STATE).st_mode) == 0o700
    and stat.S_IMODE(os.stat(os.path.join(STATE, "state.json")).st_mode) == 0o600,
)
rc, out, err = sh("validate", prom, "validator")
check("e2e: validate accepts own textfile", rc == 0, (rc, out, err))
rc, out, err = sh("inventory")
check(
    "e2e inventory: table + summary line",
    rc == 0
    and out.splitlines()[0].startswith("job\tkind")
    and "# 7 jobs, 1 failed" in out,
    (rc, out[-300:], err),
)
rc, out, _ = sh("inventory", "--format", "json")
check("e2e inventory json", rc == 0 and len(json.loads(out)) == 7)

# removed job stays visible until forget
os.remove(os.path.join(FDIR, "pft-heartbeat.timer.show"))
rc, out, err = sh("collect", "--stdout")
check(
    "e2e removed: still exported with present 0, disabled 1",
    rc == 0
    and 'pft_jobwatch_job_present{host="validator",timer="pft-heartbeat.timer"} 0'
    in out
    and 'pft_jobwatch_job_disabled{host="validator",timer="pft-heartbeat.timer"} 1'
    in out,
    err,
)
rc, out, err = sh("forget", "pft-heartbeat.timer")
check(
    "e2e forget: rc 0", rc == 0 and "forgot pft-heartbeat.timer" in out, (rc, out, err)
)
rc, out, err = sh("collect", "--stdout")
check(
    "e2e after forget: job gone, 6 jobs",
    'timer="pft-heartbeat.timer"' not in out and 'state="total"} 6' in out,
    err,
)
rc, out, err = sh("forget", "pft-nosuch.timer")
check("e2e forget unknown job: rc 1", rc == 1, (rc, err))
rc, out, err = sh("forget", "../../etc/passwd")
check("e2e forget bad name: rc 3", rc == 3, (rc, err))

# systemctl failure: up 0, state untouched, rc 1
before = read(os.path.join(STATE, "state.json"))
rc, out, err = sh("collect", env=dict(ENV, JW_STUB_FAIL="1"))
txt = read(prom)
check(
    "e2e systemctl fails: rc 1, textfile up 0 with timestamp",
    rc == 1
    and 'pft_jobwatch_up{host="validator"} 0' in txt
    and "pft_jobwatch_collect_timestamp_seconds" in txt
    and "pft_jobwatch_job_" not in txt,
    (rc, txt, err),
)
check(
    "e2e systemctl fails: state untouched",
    read(os.path.join(STATE, "state.json")) == before,
)
rc, out, err = sh("validate", prom, "validator")
check("e2e: the up-0 file still validates (pull can carry it)", rc == 0, (rc, out))

# a helper that prints a partial textfile and then fails must still give up 0
FAKE = os.path.join(TMP, "fake_helper.py")
with open(FAKE, "w") as fh:
    fh.write(
        "import sys\nprint('pft_jobwatch_up{host=\\\"validator\\\"} 1')\nsys.exit(1)\n"
    )
rc, out, err = sh("collect", "--stdout", env=dict(ENV, PFT_JW_HELPER=FAKE))
check(
    "helper prints then fails: rc 1 and up 0 (partial output discarded)",
    rc == 1
    and 'pft_jobwatch_up{host="validator"} 0' in out
    and 'pft_jobwatch_up{host="validator"} 1' not in out,
    (rc, out, err),
)
OKH = os.path.join(TMP, "ok_helper.py")
with open(OKH, "w") as fh:
    fh.write("print('pft_jobwatch_up 1')\n")
rc, out, err = sh(
    "collect", "--stdout", env=dict(ENV, PFT_JW_HELPER=OKH, HOST_LABEL="Bad Host")
)
check(
    "script itself refuses a bad HOST_LABEL (rc 3, helper not run)",
    rc == 3 and out == "",
    (rc, out, err),
)
rc, out, err = sh("forget", "a;b.timer")
check("script itself refuses a job name with metacharacters (rc 3)", rc == 3, (rc, err))

# size guard: a textfile over TEXT_BUDGET is never written (the exporter would drop it whole); up 0 instead
rc, out, err = sh("collect", "--stdout", env=dict(ENV, TEXT_BUDGET="2000"))
check(
    "over TEXT_BUDGET: rc 1, up 0, no job samples, reason on stderr",
    rc == 1
    and 'pft_jobwatch_up{host="validator"} 0' in out
    and "pft_jobwatch_job_" not in out
    and "TEXT_BUDGET" in err,
    (rc, out[:200], err),
)
rc, out, err = sh("collect", "--stdout")
check(
    "default TEXT_BUDGET (61440) leaves room for the fixture inventory",
    rc == 0 and len(out) < 61440,
    (rc, len(out)),
)
check(
    "timestamps exported as whole seconds",
    re.search(r"pft_jobwatch_job_last_success_timestamp_seconds\{[^}]*\} \d+\.", out)
    is None,
)

# usage / config errors
rc, _, _ = sh("collect", env=dict(ENV, HOST_LABEL="Bad Host"))
check("bad HOST_LABEL: rc 3", rc == 3)
rc, _, _ = sh("collect", env=dict(ENV, JOB_GLOBS="pft-*.service"))
check("JOB_GLOBS entry not ending in .timer: rc 3", rc == 3)
rc, _, _ = sh("collect", env=dict(ENV, JOB_GLOBS="$(id).timer"))
check("JOB_GLOBS with shell metacharacters: rc 3", rc == 3)
rc, _, _ = sh("bogus")
check("unknown command: rc 3", rc == 3)
check(
    "read-only: every systemctl call was `show`",
    all(ln.split()[0] == "show" for ln in read(SLOG).splitlines() if ln.strip()),
)

# validate negatives
bad = os.path.join(TMP, "bad.prom")
for name, body in (
    (
        "other host label",
        'pft_jobwatch_up{host="sentry"} 1\npft_jobwatch_collect_timestamp_seconds{host="sentry"} 1\n',
    ),
    (
        "foreign metric",
        'pft_jobwatch_up{host="validator"} 1\nnode_load1{host="validator"} 1\n',
    ),
    ("no timestamp", 'pft_jobwatch_up{host="validator"} 1\n'),
    (
        "malformed value",
        'pft_jobwatch_up{host="validator"} one\npft_jobwatch_collect_timestamp_seconds{host="validator"} 1\n',
    ),
):
    with open(bad, "w") as fh:
        fh.write(body)
    rc, out, _ = sh("validate", bad, "validator")
    check(f"validate rejects: {name}", rc == 2, (rc, out))
with open(bad, "w") as fh:
    fh.write(
        'pft_jobwatch_up{host="validator"} 1\npft_jobwatch_collect_timestamp_seconds{host="validator"} 1\n'
        + "#\n" * 140000
    )
rc, out, _ = sh("validate", bad, "validator")
check("validate rejects: oversize", rc == 2 and "too big" in out, (rc, out))

# pull: PULL_SSH replaced by a local command that prints the "remote" file
REMOTE = os.path.join(TMP, "remote")
os.makedirs(REMOTE)
senv = dict(ENV, HOST_LABEL="sentry", PFT_JW_NOW=str(int(T_HB) + 30))
rc, out, err = sh("collect", "--textfile-dir", REMOTE, env=senv)
penv = dict(ENV, PULL_SSH="env", REMOTE_DIR=REMOTE)
rc, out, err = sh("pull", "--host", "sentry", env=penv)
pulled = os.path.join(TEXT, "pft_jobwatch_sentry.prom")
check(
    "pull: valid peer file installed byte-identical",
    rc == 0
    and os.path.exists(pulled)
    and read(pulled) == read(os.path.join(REMOTE, "pft_jobwatch_sentry.prom")),
    (rc, err),
)
with open(os.path.join(REMOTE, "pft_jobwatch_sentry.prom"), "w") as fh:
    fh.write(
        'pft_jobwatch_up{host="validator"} 1\npft_jobwatch_collect_timestamp_seconds{host="validator"} 1\n'
    )
keep = read(pulled)
rc, out, err = sh("pull", "--host", "sentry", env=penv)
check(
    "pull: invalid peer file refused (rc 2), old copy kept, no temp left",
    rc == 2
    and read(pulled) == keep
    and not [f for f in os.listdir(TEXT) if f.startswith(".")],
    (rc, err),
)
rc, out, err = sh("pull", "--host", "validator", env=penv)
check("pull: refuses to overwrite own textfile", rc == 3, (rc, err))
rc, out, err = sh("pull", "--host", "sentry", env=dict(penv, PULL_SSH="false"))
check(
    "pull: fetch failure rc 1, old copy kept",
    rc == 1 and read(pulled) == keep,
    (rc, err),
)

ok = all(results)
print(
    f"RESULT: {'PASS' if ok else 'FAIL'} ({len(results)} checks, {results.count(False)} failed)"
)
sys.exit(0 if ok else 1)
