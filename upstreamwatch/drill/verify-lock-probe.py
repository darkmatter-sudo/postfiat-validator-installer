# verification probe (task_dfa49): lock-held branch of the heal, journal line + heal-state attempts
import json

from test_upstreamwatch import *
from test_upstreamwatch import NOW, H, journal, sh


def _held(henv):
    import subprocess
    import time

    holder = subprocess.Popen(["flock", str(henv["data"] / "heal.lock"), "sleep", "20"])
    try:
        time.sleep(0.5)
        return sh(henv, "run")
    finally:
        holder.kill()
        holder.wait()


def _show(henv, r):
    root = str(henv["data"])
    for ln in r.stdout.splitlines():
        if ln.startswith("heal:"):
            print("STDOUT", ln.replace(root, "DATA_DIR"))
    for e in journal(henv):
        print("JOURNAL", json.dumps(e, sort_keys=True).replace(root, "DATA_DIR"))
    p = henv["data"] / "heal-state.json"
    print("HEAL_STATE", p.read_text().strip().replace("\n", " ") if p.exists() else "absent")


def test_probe_lock_held_no_prior_state(henv):
    henv["data"].mkdir(exist_ok=True)
    r = _held(henv)
    _show(henv, r)
    j = journal(henv)
    assert [e["event"] for e in j] == ["skip"] and j[0]["reason"].startswith("locked: another heal holds ")
    assert not (henv["data"] / "heal-state.json").exists()


def test_probe_lock_held_prior_attempt_unchanged(henv):
    henv["data"].mkdir(exist_ok=True)
    st = {"usn-host": {"attempts": 1, "last_attempt_epoch": NOW - 7 * H, "last_result": "still_lagging",
                       "last_rc": 0, "last_result_epoch": NOW - 7 * H, "note": "probe prior attempt"}}
    (henv["data"] / "heal-state.json").write_text(json.dumps(st, indent=1, sort_keys=True) + "\n")
    before = (henv["data"] / "heal-state.json").read_bytes()
    r = _held(henv)
    _show(henv, r)
    j = journal(henv)
    assert [e["event"] for e in j] == ["skip"] and j[0]["reason"].startswith("locked: another heal holds ")
    assert (henv["data"] / "heal-state.json").read_bytes() == before
    assert json.loads(before)["usn-host"]["attempts"] == 1
