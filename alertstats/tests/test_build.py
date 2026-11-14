"""Episode builder, flap rule, silences, hygiene and outputs of alertstats_build.py.

Synthetic bundles use STEP=10 on the window 0..1000 so every expected number can be checked by hand; each check has
a control that must NOT trigger it. Real captures (fixtures/real-*.json, collected from the validator's Prometheus
and Alertmanager with `alertstats_build.py collect --now ... --since 1h`) pin behaviour on actual data.
"""

import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import alertstats_build as ab

FIX = HERE / "fixtures"
STEP, START, END = 10, 0, 1000


def grid(a, b):
    return list(range(a, b + 1, STEP))


def bundle(series=(), up=None, silences=(), for_state=(), rules=(), deliveries=(), **params):
    p = {
        "start": START,
        "end": END,
        "step": STEP,
        "since_s": END - START,
        "flap_window": 300,
        "flap_min": 3,
        "flap_recent": 1000,
        "allow_no_for": ["PFTAlertPipelineWatchdog"],
        "host": "validator",
        "lookback": 300,
        "up_query": "test",
    }
    p.update(params)
    alerts = []
    for labels, state, times in series:
        m = {"__name__": "ALERTS", "alertstate": state, **labels}
        alerts.append({"metric": m, "values": [[t, "1"] for t in times]})
    fs = []
    for labels, pairs in for_state:
        fs.append({"metric": {"__name__": "ALERTS_FOR_STATE", **labels}, "values": [[t, v] for t, v in pairs]})
    return {
        "format": ab.BUNDLE_FORMAT,
        "params": p,
        "alerts": alerts,
        "for_state": fs,
        "up": grid(START, END) if up is None else up,
        "rules": list(rules),
        "silences": list(silences),
        "deliveries": list(deliveries),
        "delivery_log_from": deliveries[0]["ts"] if deliveries else None,
        "sources": {"prometheus": "ok", "alertmanager": "ok", "bridge": "ok"},
    }


A = {"alertname": "PFTX", "host": "validator", "severity": "warning"}


def eps(b):
    return ab.build_episodes(b)


def one(b):
    e = eps(b)
    assert len(e) == 1, e
    return e[0]


# ---------------------------------------------------------------- episodes


def test_fired_episode_pending_then_firing():
    e = one(bundle([(A, "pending", grid(100, 150)), (A, "firing", grid(160, 250))]))
    assert (e["kind"], e["start"], e["firing_start"], e["end"]) == ("fired", 100, 160, 260)
    assert (e["pending_s"], e["firing_s"], e["ttr_s"]) == (60, 100, 100)
    assert not e["open"] and not e["truncated_start"] and e["gap_bridged"] == 0


def test_firing_wins_over_pending_at_the_same_timestamp():
    # at the pending -> firing transition one query step can carry both series; firing must win
    e = one(bundle([(A, "pending", grid(100, 160)), (A, "firing", grid(150, 200))]))
    assert (e["firing_start"], e["pending_s"]) == (150, 50)


def test_single_missing_presence_point_is_a_gap():
    up = [t for t in grid(START, END) if t != 500]
    assert ab.prom_gaps(bundle()["params"], up) == [{"from": 500, "to": 510, "seconds": 10}]
    assert ab.prom_gaps(bundle()["params"], grid(START, END)) == []


def test_pending_only_is_a_near_miss():
    e = one(bundle([(A, "pending", grid(300, 340))]))
    assert (e["kind"], e["pending_s"], e["firing_s"], e["ttr_s"]) == ("pending_only", 50, 0, None)


def test_real_resolve_while_prometheus_up_starts_a_new_episode():
    e = eps(bundle([(A, "firing", grid(100, 200) + grid(300, 400))]))
    assert [(x["start"], x["end"]) for x in e] == [(100, 210), (300, 410)]
    assert not any(x["gap_split_before"] or x["gap_split_after"] or x["gap_bridged"] for x in e)


def test_one_missing_sample_is_not_a_gap():
    # 1.5*STEP tolerance: samples 10 apart are consecutive, a missing one (20 apart) is a gap -> control below
    assert len(eps(bundle([(A, "firing", grid(100, 200))]))) == 1
    assert len(eps(bundle([(A, "firing", [*grid(100, 150), *grid(170, 200)])]))) == 2


def test_outage_with_same_active_at_is_bridged():
    up = [t for t in grid(START, END) if not 210 <= t < 600]
    fs = [(A, [(200, "90"), (600, "90")])]
    e = one(bundle([(A, "firing", grid(100, 200) + grid(600, 700))], up=up, for_state=fs))
    # sample gap 200 -> 600: 39 missing points = 390 s, not counted as firing time
    assert (e["gap_bridged"], e["gap_s"], e["end"]) == (1, 390, 710)
    assert e["firing_s"] == 710 - 100 - 390
    assert e["ttr_s"] == 610


def test_outage_with_new_active_at_splits_and_is_never_a_flap():
    up = [t for t in grid(START, END) if not 210 <= t < 600]
    fs = [(A, [(200, "90"), (600, "600")])]
    e = eps(bundle([(A, "firing", grid(100, 200) + grid(600, 700))], up=up, for_state=fs))
    assert [(x["gap_split_before"], x["gap_split_after"]) for x in e] == [(False, True), (True, False)]
    assert [x["ttr_s"] for x in e] == [None, None]
    flaps, _ = ab.flap_stats(e, bundle()["params"])
    assert flaps["PFTX"] == 0


def test_split_halves_are_not_a_flap_even_inside_the_window():
    up = [t for t in grid(START, END) if not 210 <= t < 600]
    fs = [(A, [(200, "90"), (600, "600")])]
    b = bundle([(A, "firing", grid(100, 200) + grid(600, 700))], up=up, for_state=fs, flap_window=1000)
    flaps, _ = ab.flap_stats(eps(b), b["params"])
    assert flaps["PFTX"] == 0
    # control: the same two episodes with Prometheus up in between are a real flap
    b = bundle([(A, "firing", grid(100, 200) + grid(600, 700))], flap_window=1000)
    assert ab.flap_stats(eps(b), b["params"])[0]["PFTX"] == 1


def test_outage_without_for_state_splits():
    up = [t for t in grid(START, END) if not 210 <= t < 600]
    e = eps(bundle([(A, "firing", grid(100, 200) + grid(600, 700))], up=up))
    assert len(e) == 2 and e[0]["gap_split_after"] and e[1]["gap_split_before"]


def test_far_away_outage_does_not_turn_a_real_resolve_into_a_data_gap():
    # outage 500..550 sits between two episodes 100..200 and 900..950: Prometheus was up for most of the gap
    up = [t for t in grid(START, END) if not 500 <= t < 550]
    e = eps(bundle([(A, "firing", grid(100, 200) + grid(900, 950))], up=up))
    assert not any(x["gap_split_before"] or x["gap_split_after"] for x in e)
    assert [x["ttr_s"] for x in e] == [110, 60]


def test_lookback_filled_outage_counts_as_bridged():
    up = [t for t in grid(START, END) if not 300 <= t < 400]  # 10 points = 100 s
    e = one(bundle([(A, "firing", grid(100, 500))], up=up))
    assert (e["gap_bridged"], e["gap_s"], e["firing_s"]) == (1, 100, 510 - 100 - 100)
    assert ab.prom_gaps(bundle()["params"], up) == [{"from": 300, "to": 400, "seconds": 100}]


def test_open_and_truncated_episodes_have_no_ttr():
    e = one(bundle([(A, "firing", grid(900, 1000))]))
    assert e["open"] and e["end"] is None and e["ttr_s"] is None and e["firing_s"] == 100
    e = one(bundle([(A, "firing", grid(0, 100))]))
    assert e["truncated_start"] and not e["open"] and e["ttr_s"] is None and e["end"] == 110


def test_series_are_split_by_labels_not_alertstate():
    b = bundle(
        [
            (A, "pending", grid(100, 120)),
            (A, "firing", grid(130, 150)),
            ({**A, "host": "sentry"}, "firing", grid(100, 150)),
        ]
    )
    e = eps(b)
    assert sorted(x["series"] for x in e) == ["host=sentry,severity=warning", "host=validator,severity=warning"]


# ---------------------------------------------------------------- silences


def sil(start, end, *matchers):
    ms = [{"name": n, "value": v, "isRegex": r, "isEqual": q} for n, v, r, q in matchers]
    return {"id": f"s{start}", "startsAt": ab.iso(start), "endsAt": ab.iso(end), "comment": "t", "matchers": ms}


def test_silence_overlap_and_notifiable():
    s = [sil(100, 160, ("alertname", "PFT.*", True, True))]
    e = one(bundle([(A, "firing", grid(100, 199))], silences=s))  # firing 100..200
    assert e["silenced_s"] == 60 and not e["notifiable"]  # 60 of 100 s silenced -> mostly silenced
    s = [sil(100, 140, ("alertname", "PFT.*", True, True))]
    e = one(bundle([(A, "firing", grid(100, 199))], silences=s))
    assert e["silenced_s"] == 40 and e["notifiable"]


@pytest.mark.parametrize(
    ("matcher", "hit"),
    [
        (("alertname", "PFTX", False, True), True),
        (("alertname", "PFTY", False, True), False),
        (("alertname", "PFT", True, True), False),  # regex is anchored (fullmatch), like Alertmanager
        (("alertname", "PFT.+", True, True), True),
        (("alertname", "PFTX", False, False), False),  # !=
        (("alertname", "PFTX|PFTZ", True, False), False),  # !~
        (("host", "sentry", True, False), True),
        (("missing", "", False, True), True),  # absent label == ""
    ],
)
def test_silence_matchers(matcher, hit):
    e = one(bundle([(A, "firing", grid(100, 199))], silences=[sil(0, 1000, matcher)]))
    assert (e["silenced_s"] == 100) is hit


def test_overlapping_silences_are_not_double_counted():
    s = [sil(100, 180, ("alertname", "PFTX", False, True)), sil(150, 200, ("host", "validator", False, True))]
    assert one(bundle([(A, "firing", grid(100, 199))], silences=s))["silenced_s"] == 100


# ---------------------------------------------------------------- flaps


def flappy(starts, length=30, **kw):
    times = []
    for s in starts:
        times += grid(s, s + length - STEP)
    return bundle([(A, "firing", times)], **kw)


def test_three_firings_within_the_window_flap():
    b = flappy([100, 200, 300])
    flaps, flapping = ab.flap_stats(eps(b), b["params"])
    assert flaps["PFTX"] == 2 and flapping["PFTX"] is True


def test_two_firings_do_not_flap():
    b = flappy([100, 200])
    flaps, flapping = ab.flap_stats(eps(b), b["params"])
    assert flaps["PFTX"] == 1 and flapping["PFTX"] is False


def test_firings_spread_wider_than_the_window_do_not_flap():
    b = flappy([100, 450, 800])  # gaps 320 s > flap_window 300
    flaps, flapping = ab.flap_stats(eps(b), b["params"])
    assert flaps["PFTX"] == 0 and flapping["PFTX"] is False


def test_silenced_firings_do_not_flap():
    b = flappy([100, 200, 300], silences=[sil(190, 240, ("alertname", "PFTX", False, True))])
    flaps, flapping = ab.flap_stats(eps(b), b["params"])
    # the silenced middle firing is invisible; the operator saw 100..130 and 300..330 (170 s apart): one flap
    assert flapping["PFTX"] is False and flaps["PFTX"] == 1


def test_flapping_only_counts_recent_starts():
    b = flappy([100, 200, 300], flap_recent=750)  # recent window starts at 250
    _, flapping = ab.flap_stats(eps(b), b["params"])
    assert flapping["PFTX"] is False


def test_pending_only_episodes_never_flap():
    times = grid(100, 120) + grid(200, 220) + grid(300, 320)
    b = bundle([(A, "pending", times)])
    flaps, flapping = ab.flap_stats(eps(b), b["params"])
    assert flaps == {} and flapping == {}


def test_nearest_rank():
    assert ab.nearest_rank([40, 10, 30, 20], 0.5) == 20
    assert ab.nearest_rank([40, 10, 30, 20], 0.95) == 40
    assert ab.nearest_rank([5], 0.95) == 5
    assert ab.nearest_rank([], 0.5) is None
    assert ab.nearest_rank(list(range(1, 21)), 0.95) == 19


# ---------------------------------------------------------------- hygiene


def rule(
    name="PFTX",
    duration=300,
    severity="warning",
    annotations=("description", "summary"),
    health="ok",
    interval=15,
    file="x.rules.yml",
):
    labels = {"severity": severity} if severity is not None else {}
    return {
        "group": "g",
        "file": file,
        "interval": interval,
        "name": name,
        "duration": duration,
        "labels": labels,
        "annotations": sorted(annotations),
        "health": health,
        "lastError": "",
    }


def checks(rules, series=()):
    b = bundle(series, rules=rules)
    return sorted((h["check"], h["alertname"]) for h in ab.hygiene(b, eps(b)))


FIRED = [(A, "firing", grid(100, 150))]


def test_hygiene_control_clean_rule_has_no_findings():
    assert checks([rule()], FIRED) == []


@pytest.mark.parametrize(
    ("kw", "check"),
    [
        ({"duration": 0}, "no_for"),
        ({"duration": 15}, "short_for"),
        ({"severity": None}, "bad_severity"),
        ({"severity": "page"}, "bad_severity"),
        ({"annotations": ("description",)}, "no_summary"),
        ({"annotations": ("summary",)}, "no_description"),
        ({"health": "err"}, "unhealthy"),
    ],
)
def test_hygiene_static_checks(kw, check):
    assert checks([rule(**kw)], FIRED) == [(check, "PFTX")]


def test_hygiene_for_exactly_two_intervals_is_fine():
    assert checks([rule(duration=30, interval=15)], FIRED) == []


def test_hygiene_allow_no_for_and_always_firing():
    wd = {"alertname": "PFTAlertPipelineWatchdog", "severity": "none"}
    assert (
        checks([rule("PFTAlertPipelineWatchdog", duration=0, severity="none")], [(wd, "firing", grid(0, 1000))]) == []
    )
    assert checks([rule()], [(A, "firing", grid(0, 1000))]) == [("always_firing", "PFTX")]
    assert checks([rule()], [(A, "firing", grid(0, 880))]) == []  # 890 s < 90% of 1000 -> control


def test_hygiene_duplicate_never_active_no_rule():
    assert checks([rule(), rule(file="y.rules.yml")], FIRED) == [("duplicate_name", "PFTX")]
    assert checks([rule("PFTQuiet")], FIRED) == [("never_active", "PFTQuiet"), ("no_rule", "PFTX")]


# ---------------------------------------------------------------- deliveries and notifications

BRIDGE = """2026-11-14T06:00:00.123456789Z bridge listening on 127.0.0.1:9095 ntfy=on
2026-11-14T06:01:00.5Z webhook status=firing alertname=PFTJobFailed severity=warning startsAt=x endsAt=y
2026-11-14T06:01:00.6Z ntfy [FIRING] PFTJobFailed x3 -> HTTP 200
2026-11-14T07:01:00.6Z ntfy [RESOLVED] PFTJobFailed -> HTTP 200
2026-11-15T00:00:01.0Z ntfy [FIRING] PFTNoPeers -> ERROR URLError
2026-11-15T00:00:02.0Z dedup: 1 of 2 alert(s) unchanged since last send, not forwarded
"""


def test_parse_deliveries_bridge_format():
    d = ab.parse_deliveries(BRIDGE.splitlines())
    assert [(x["kind"], x["status"], x["alertname"], x["count"], x["result"]) for x in d] == [
        ("webhook", "firing", "PFTJobFailed", 1, ""),
        ("ntfy", "firing", "PFTJobFailed", 3, "HTTP 200"),
        ("ntfy", "resolved", "PFTJobFailed", 1, "HTTP 200"),
        ("ntfy", "firing", "PFTNoPeers", 1, "ERROR URLError"),
    ]


def test_notifications_per_utc_day():
    d = ab.parse_deliveries(BRIDGE.splitlines())
    r = ab.analyse(bundle(deliveries=d))
    assert r["notifications"] == [
        {"day": "2026-11-14", "ok": 2, "error": 0, "firing": 1, "resolved": 1},
        {"day": "2026-11-15", "ok": 0, "error": 1, "firing": 1, "resolved": 0},
    ]


def test_redact_any_public_first_octet():
    assert ab.redact("19.1.2.3 8.8.8.8 100.64.1.1 192.0.2.1") == "<redacted-ip> " * 3 + "<redacted-ip>"


def test_redact_public_ip_and_topic_keeps_private():
    s = ab.redact("dial 203.0.113.7:2559 and 10.0.0.2 and 127.0.0.1 and 172.17.0.1 via https://ntfy.sh/abcDEF-12")
    assert s == "dial <redacted-ip>:2559 and 10.0.0.2 and 127.0.0.1 and 172.17.0.1 via https://ntfy.sh/<redacted>"


# ---------------------------------------------------------------- outputs


def test_textfile_every_check_line_and_escaping():
    b = bundle([({**A, "alertname": 'P"X'}, "firing", grid(100, 150))], rules=[rule()])
    t = ab.out_textfile(ab.analyse(b), 1234)
    for c in ab.CHECKS:
        assert f'check="{c}"' in t
    assert 'pft_alertstats_flapping{host="validator",alertname="P\\"X"} 0' in t
    assert 'pft_alertstats_last_run_timestamp_seconds{host="validator"} 1234' in t
    assert "job=" not in t and "instance=" not in t


def test_textfile_budget_truncates_detail_but_keeps_flapping(monkeypatch):
    monkeypatch.setattr(ab, "TEXT_BUDGET", 3000)
    series = [({**A, "alertname": f"PFTA{i:03d}"}, "firing", grid(100, 150)) for i in range(40)]
    t = ab.out_textfile(ab.analyse(bundle(series)), 1)
    assert 'pft_alertstats_truncated{host="validator"} 1' in t
    assert t.count("pft_alertstats_flapping{") == 40 and "pft_alertstats_flaps{" not in t


def test_textfile_up_zero_when_prometheus_failed():
    b = bundle()
    b["sources"]["prometheus"] = "error URLError: x"
    assert 'pft_alertstats_up{host="validator"} 0' in ab.out_textfile(ab.analyse(b), 1)


def test_csv_and_md_are_deterministic(tmp_path):
    b = flappy([100, 200, 300], rules=[rule()])
    p = tmp_path / "b.json"
    p.write_text(json.dumps(b))
    outs = [run_report(p, f) for f in ("md", "json", "csv", "md", "json", "csv")]
    assert outs[:3] == outs[3:]
    assert outs[2].splitlines()[0] == ",".join(ab.EP_COLS)
    assert "| PFTX | warning | 5m00s | 3 | 0 | 0 | 0 | 2 | YES |" in outs[0]


def run_report(path, fmt):
    r = subprocess.run(
        [
            sys.executable,
            "-I",
            str(HERE.parent / "alertstats_build.py"),
            "report",
            "--offline",
            str(path),
            "--format",
            fmt,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_gzip_bundle_reads_like_plain(tmp_path):
    b = flappy([100, 200, 300])
    (tmp_path / "b.json").write_text(json.dumps(b))
    (tmp_path / "b.json.gz").write_bytes(gzip.compress(json.dumps(b).encode(), mtime=0))
    assert run_report(tmp_path / "b.json", "md") == run_report(tmp_path / "b.json.gz", "md")


def test_wrong_format_bundle_is_refused(tmp_path):
    (tmp_path / "b.json").write_text(json.dumps({"format": "other"}))
    r = subprocess.run(
        [
            sys.executable,
            "-I",
            str(HERE.parent / "alertstats_build.py"),
            "report",
            "--offline",
            str(tmp_path / "b.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 3 and "not a pft-alertstats-bundle/1 bundle" in r.stderr


# ---------------------------------------------------------------- real captures


def load(name):
    return json.loads((FIX / name).read_text())


def find(r, alertname, **kw):
    out = [e for e in r["episodes"] if e["alertname"] == alertname and all(e[k] == v for k, v in kw.items())]
    assert out, (alertname, kw)
    return out


def test_real_reboot_capture():
    # validator reboot 2026-11-12T16:24Z (pft-patch): Prometheus has no up sample 16:24:30..16:28:00
    r = ab.analyse(load("real-reboot.json"))
    assert r["prometheus_gaps"] == [
        {"from": ab_ts("2026-11-12T16:24:30Z"), "to": ab_ts("2026-11-12T16:28:15Z"), "seconds": 225}
    ]
    # PFTVulnRebootOwed: pending before, pending again after with a NEW activeAt (the reboot reset it) -> split
    v = find(r, "PFTVulnRebootOwed", start=ab_ts("2026-11-12T16:28:45Z"))
    assert all(e["gap_split_before"] for e in v) and len(v) == 2
    # PFTExporterDown: pending across the outage, filled by the 5m lookback -> one bridged pending-only episode
    (x,) = find(r, "PFTExporterDown")
    assert (x["kind"], x["gap_bridged"], x["gap_s"]) == ("pending_only", 1, 225)
    # PFTContainerRestarted after the boot is fully covered by the pft-patch silence -> not notifiable
    (c,) = find(r, "PFTContainerRestarted")
    assert c["firing_s"] == c["silenced_s"] == 615 and not c["notifiable"]


def test_real_drill_capture():
    # fwaudit exposure drill 2026-11-14T07:12Z: the drill silence excluded PFTFwaudit.* (it was the alert under
    # test, routed to a throwaway topic), so both hosts' PFTFwauditExposure episodes count as unsilenced
    r = ab.analyse(load("real-drill.json"))
    f = find(r, "PFTFwauditExposure")
    assert sorted((e["ttr_s"], e["silenced_s"]) for e in f) == [(120, 0), (135, 0)]
    assert all(e["firing_start"] - e["start"] == 300 for e in f)  # for: 5m


def ab_ts(s):
    return int(ab.parse_iso(s))


@pytest.mark.parametrize("name", ["real-reboot", "real-drill"])
def test_real_capture_golden_reports(name):
    for fmt in ("md", "csv"):
        want = (FIX / f"{name}.expected.{fmt}").read_text()
        assert run_report(FIX / f"{name}.json", fmt) == want, f"{name}.{fmt} drifted"


def test_fixtures_carry_no_public_ip_or_topic():
    for f in FIX.iterdir():
        text = f.read_text() if f.suffix != ".gz" else gzip.decompress(f.read_bytes()).decode()
        assert ab.redact(text) == text, f.name
    assert os.sep + "home" + os.sep not in "".join(f.read_text() for f in FIX.glob("*.json"))
