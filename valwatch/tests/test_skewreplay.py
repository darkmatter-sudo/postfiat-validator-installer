"""Offline tests for skewreplay.py analyze (no Prometheus): intervals, attribution, exit status."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import skewreplay as sr

LATE = "PFTValwatchHostsDisagreeLate"
DIS = "PFTValwatchHostsDisagree"
K = "nHB6Zc7mhr7swksEgpwTE7Hw7SvZ9cz22T2MECMSXjBeMTeHXQB7"


def test_intervals_split_on_gap():
    assert sr.intervals([0, 15, 30, 60, 75], 15) == [(0, 30), (60, 75)]
    assert sr.intervals([], 15) == []


def write(d, old_steps, new_steps=(), other_points=(), skew=((0, 1.0), (15, 60.0))):
    def series(steps):
        return [{"node": sr.V, "validator": K, "steps": list(steps)}] if steps else []

    files = {
        "meta.json": {
            "start": 0,
            "end": 3600,
            "step": 15,
            "prometheus": "t",
            "old_rules_sha256": "o",
            "new_rules_sha256": "n",
        },
        "skew.json": {"expr": "x", "points": [list(p) for p in skew]},
        "replay.json": {
            LATE: {
                "old": {"expr": "o", "series": series(old_steps)},
                "new": {"expr": "n", "series": series(new_steps)},
            },
            DIS: {"old": {"expr": "o", "series": []}, "new": {"expr": "n", "series": []}},
        },
        "context.json": [{"alert": LATE, "node": sr.SN, "validator": K, "points": [list(p) for p in other_points]}],
    }
    for name, obj in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            json.dump(obj, f)


def run(d, capsys):
    rc = sr.main(["analyze", str(d)])
    return rc, capsys.readouterr().out


def test_old_only_skew_interval_passes(tmp_path, capsys):
    # validator matched alone at 600 s; the sentry crossed 3000 ms one step later -> skew
    write(tmp_path, [600], other_points=[(585, 1500), (600, 1500), (615, 3500)])
    rc, out = run(tmp_path, capsys)
    assert rc == 0
    assert "old-only 1, new-only 0" in out
    assert "(15 s): SKEW - postfiatd-sentry crossed the same threshold at 1970-01-01T00:10:15Z (3500, +15 s)" in out
    assert "RESULT: PASS" in out


def test_old_only_without_other_node_crossing_is_real(tmp_path, capsys):
    write(tmp_path, [600], other_points=[(600, 1500), (615, 1500)])
    rc, out = run(tmp_path, capsys)
    assert rc == 1
    assert ": REAL - postfiatd-sentry never crossed the threshold" in out
    assert "RESULT: FAIL (1 " in out


def test_old_only_longer_than_skew_is_real(tmp_path, capsys):
    # 10 min old-only although the sentry crossed nearby: longer than max skew (60 s) + 1 step
    write(tmp_path, range(600, 1200, 15), other_points=[(1200, 3500)])
    rc, out = run(tmp_path, capsys)
    assert rc == 1
    assert ": REAL - 600 s longer than max skew 60 s + 1 step" in out


def test_overlapping_new_interval_is_not_old_only_and_new_only_fails(tmp_path, capsys):
    write(tmp_path, [600, 615, 630], new_steps=[630])
    rc, out = run(tmp_path, capsys)
    assert "both 1, old-only 0, new-only 0" in out and rc == 0
    write(tmp_path, [], new_steps=[900])
    rc, out = run(tmp_path, capsys)
    assert rc == 1 and "NEW_ONLY PFTValwatchHostsDisagreeLate node=postfiatd" in out


def test_window_coverage_lists_steps_outside(tmp_path, capsys):
    write(tmp_path, [], skew=((0, 1.0), (15, 105.0), (30, 121.0)))
    rc, out = run(tmp_path, capsys)
    assert rc == 0
    assert "absorbs |skew| <= 105 s: 2/3 steps" in out
    assert "SKEW_OUTSIDE 1970-01-01T00:00:30Z 121 s" in out
    assert "SKEW max |skew| of the absorbed steps: 105 s" in out
