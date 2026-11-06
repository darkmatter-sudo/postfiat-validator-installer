#!/usr/bin/env python3
"""Offline tests for rebuild_lib.py: stack.list ordering, preflight isolation refusals, the
REPRODUCED/MISSING/EXTRA/DIFFERENT classifier and the teardown leftover check.

Run: python3 -u rebuild/tests/test_rebuild.py   (stdlib only). RB_DIR points at a mutant copy (tests/mutate.py).
Prints one PASS/FAIL line per check and 'RESULT: PASS|FAIL (n checks)'.
"""

import atexit
import base64
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RB = os.environ.get("RB_DIR") or os.path.dirname(HERE)
LIB = os.path.join(RB, "rebuild_lib.py")
sys.path.insert(0, RB)
import rebuild_lib as rl

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(
        f"{'PASS' if cond else 'FAIL'} {name}"
        + (f" -- {detail}" if detail and not cond else "")
    )


def raises(fn, *a):
    try:
        fn(*a)
    # a mutant may raise something else: that is a FAIL line, not a crash
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"
    return None


def safe(fn, *a, default=None):
    try:
        return fn(*a)
    # report as a FAIL line, keep running the other checks
    except Exception as e:  # noqa: BLE001
        check(f"{fn.__name__} raised", False, f"{type(e).__name__}: {e}")
        return default


def run(*args):
    p = subprocess.run(
        [sys.executable, LIB, *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.returncode, p.stdout, p.stderr


TMP = tempfile.mkdtemp(
    prefix="rbtest-",
    dir=os.environ.get("TEST_TMPDIR") or os.path.expanduser("~/.cache"),
)
atexit.register(shutil.rmtree, TMP, True)


def tmpf(name, text):
    p = os.path.join(TMP, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p


# ---------- stack.list ----------
GOOD = "# c\n10 base - bash install.sh\n\n20 restore base rb-restore\n30 exp base,restore rb-manifest exporter x\n"
s = safe(rl.parse_stack, GOOD, default=[{}, {}, {}])
check(
    "stack: parses 3 steps in order",
    [x.get("step") for x in s] == ["base", "restore", "exp"],
)
check("stack: command keeps its spaces", s[2].get("cmd") == "rb-manifest exporter x")
check("stack: after list split", s[2].get("after") == ["base", "restore"])
check("stack: '-' means no deps", s[0].get("after") == [])
e = raises(rl.parse_stack, "10 base - a\n10 x base b\n")
check("stack: equal ORDER refused", e and "not greater" in e, e)
e = raises(rl.parse_stack, "20 base - a\n10 x base b\n")
check("stack: decreasing ORDER refused", e and "not greater" in e, e)
e = raises(rl.parse_stack, "10 base - a\n20 x later b\n30 later base c\n")
check("stack: dependency on a LATER step refused", e and "not an earlier step" in e, e)
e = raises(rl.parse_stack, "10 base - a\n20 x nope b\n")
check("stack: unknown dependency refused", e and "'nope'" in e, e)
e = raises(rl.parse_stack, "10 base - a\n20 base - b\n")
check("stack: duplicate step refused", e and "duplicate" in e, e)
e = raises(rl.parse_stack, "10 other - a\n")
check("stack: first step must be base", e and "first step" in e, e)
e = raises(rl.parse_stack, "10 base -\n")
check("stack: missing command refused", e and "need ORDER" in e, e)
e = raises(rl.parse_stack, "x base - a\n")
check("stack: non-integer ORDER refused", e and "not an integer" in e, e)
e = raises(rl.parse_stack, "10 Base - a\n")
check("stack: bad step name refused", e and "bad STEP" in e, e)
e = raises(rl.parse_stack, "# only comments\n")
check("stack: empty stack refused", e and "no steps" in e, e)
e = raises(rl.parse_stack, "10 base - a\n20 x base, b\n")
check("stack: empty dep name refused", e and "not an earlier step" in e, e)

with open(os.path.join(RB, "stack.list"), encoding="utf-8") as fh:
    real = safe(rl.parse_stack, fh.read(), default=[])
names = [x["step"] for x in real]


def idx(n):
    return names.index(n) if n in names else -1


check("stack.list (repo): parses", len(real) >= 30, len(real))
check(
    "stack.list (repo): the integrity manifest is written last (baseline, then only unitguard, the profile applies"
    " and their accepts)",
    names[-1:] == ["rebaseline2"]
    and real[-1]["cmd"].startswith("pft-integrity accept ")
    and real[idx("rebaseline")]["cmd"].startswith("pft-integrity accept ")
    and names[idx("baseline") + 1 :]
    == [
        "firstrun",
        "unitguard",
        "rebaseline",
        "aaapply",
        "scapply",
        "egressfix",
        "rebaseline2",
    ],
    names[-4:],
)
check(
    "stack.list (repo): the profile applies go through their rb-limit, egressfix reapplies pft-egress after them",
    all(idx(n) >= 0 for n in ("aaapply", "scapply", "egressfix"))
    and "rb-limit apparmor-nested pft-apparmor apply" in real[idx("aaapply")]["cmd"]
    and "rb-limit kernel-audit pft-seccomp apply" in real[idx("scapply")]["cmd"]
    and real[idx("egressfix")]["cmd"].startswith(
        "systemctl start pft-egress-reapply@postfiatd.service; rc=$?;"
    )
    and real[idx("egressfix")]["cmd"].endswith(
        "[ \"$rc\" = 0 ] && iptables -S DOCKER-USER | grep -q -- '-j PFT-EGRESS'"
    ),
    [
        real[idx(n)]["cmd"][:80]
        for n in ("aaapply", "scapply", "egressfix")
        if idx(n) >= 0
    ],
)
check(
    "stack.list (repo): egresswait requires the egress dead-man PASS before the profile applies stop the node (run 28)",
    idx("egress") < idx("egresswait") < idx("aaapply")
    and "egresswait" in real[idx("aaapply")]["after"]
    and "systemctl is-active -q pft-egress-deadman@postfiatd || break"
    in real[idx("egresswait")]["cmd"]
    and real[idx("egresswait")]["cmd"].endswith(
        "jq -e -r .deadman_passed_at /var/lib/pft-egress/postfiatd.json"
    ),
    real[idx("egresswait")]["cmd"][-80:] if idx("egresswait") >= 0 else "missing",
)
with open(os.path.join(RB, "pft-rebuild-drill.sh"), encoding="utf-8") as fh:
    _drill = fh.read()
_sec6 = _drill[_drill.find('echo "== 6. diff sandbox vs live"') :]
_pull = _sec6.find("sandbox-manifest.tsv")
_acc = _sec6.find(
    'sx pft-integrity accept --reason "rebuild drill: final sandbox state for the diff"'
)
check(
    "drill: section 6 re-collects the sandbox manifest with accept (baseline refuses an existing one, run 30)"
    " before pulling it",
    0 <= _acc < _pull and "sx pft-integrity baseline" not in _sec6,
    (_acc, _pull),
)
check(
    "stack.list (repo): restore before backup",
    idx("restore") < idx("backup"),
)
check(
    "stack.list (repo): exporter before every textfile collector",
    all(idx("exporter") < idx(x["step"]) for x in real if "exporter" in x["after"]),
)
REPO = os.path.dirname(
    os.path.dirname(HERE)
)  # the repo, also when RB_DIR is a mutant copy
with open(os.path.join(REPO, "fleet", "manifest.tsv"), encoding="utf-8") as fh:
    manifest_addons = {
        ln.split()[0] for ln in fh if ln.strip() and not ln.startswith("#")
    }
check(
    "stack.list (repo): every fleet add-on has a step",
    manifest_addons <= set(names),
    sorted(manifest_addons - set(names)),
)
rc, out, _ = run("stack", os.path.join(RB, "stack.list"), "--json")
check(
    "cli stack --json: exit 0 + JSON list",
    rc == 0 and json.loads(out)[0]["step"] == "base",
    rc,
)
rc, _, err = run("stack", tmpf("bad.list", "10 x - a\n"))
check("cli stack: invalid -> exit 3", rc == 3 and "first step" in err, (rc, err))

BS = "# c\n10 base - bash install.sh\n20 dj base printf '{\"a\":1}\\n' > /etc/x.json &&\tcat /etc/x.json\n"
rc, out, err = run("stack", tmpf("bs.list", BS), "--rows")
rows = [ln.split("\t") for ln in out.splitlines()]
dec = (
    [base64.b64decode(r[2]).decode() for r in rows]
    if rc == 0 and all(len(r) == 3 for r in rows)
    else []
)
check(
    "stack --rows: command bytes (backslash, quotes, tab) survive the step loop encoding",
    [r[:2] for r in rows] == [["10", "base"], ["20", "dj"]]
    and dec[1:] == ["printf '{\"a\":1}\\n' > /etc/x.json &&\tcat /etc/x.json"],
    (rc, out, err),
)

# ---------- preflight ----------
INST = {
    "expanded_config": {
        "security.nesting": "true",
        "limits.cpu": "2",
        "limits.memory": "3GiB",
    },
    "expanded_devices": {
        "root": {"type": "disk", "path": "/", "pool": "pftrb"},
        "eth0": {"type": "nic", "network": "pftrb0", "name": "eth0"},
    },
}
BR = {
    "name": "pftrb0",
    "type": "bridge",
    "managed": True,
    "config": {"ipv4.nat": "true", "ipv6.address": "none"},
}
check(
    "preflight: clean sandbox isolated",
    rl.preflight(INST, BR) == [],
    rl.preflight(INST, BR),
)


def mut(fn):
    i = copy.deepcopy(INST)
    fn(i)
    return rl.preflight(i, BR)


def has(refs, word):
    return any(word in r for r in refs)


VOL = {
    "type": "disk",
    "pool": "pftrb",
    "source": "rb-containerd",
    "path": "/var/lib/containerd",
}
r = mut(lambda i: i["expanded_devices"].update({"rb-containerd": dict(VOL)}))
check("preflight: custom volume on the sandbox pool accepted", r == [], r)
r = mut(
    lambda i: i["expanded_devices"].update({"rb-containerd": dict(VOL, pool="default")})
)
check(
    "preflight: custom volume on another pool refused",
    has(r, "not the sandbox pool"),
    r,
)
r = mut(lambda i: i["expanded_config"].update({"security.privileged": "true"}))
check("preflight: privileged refused", has(r, "privileged"), r)
r = mut(lambda i: i["expanded_config"].pop("security.nesting"))
check("preflight: no nesting refused", has(r, "nesting"), r)
r = mut(lambda i: i["expanded_config"].pop("limits.memory"))
check("preflight: no memory cap refused", has(r, "limits.memory"), r)
r = mut(lambda i: i["expanded_config"].pop("limits.cpu"))
check("preflight: no cpu cap refused", has(r, "limits.cpu"), r)
for src in (
    "/var/lib/docker/volumes/postfiatd_data/_data",
    "/opt/postfiatd",
    "/etc/pft-kernwatch.env",
    "/var/lib/pft-integrity",
    "/",
    "/srv/../opt/postfiatd",
):
    r = mut(
        lambda i, s=src: i["expanded_devices"].update(
            {"d": {"type": "disk", "path": "/x", "source": s}}
        )
    )
    check(f"preflight: live disk source {src} refused", has(r, "live host state"), r)
r = mut(
    lambda i: i["expanded_devices"].update(
        {"d": {"type": "disk", "path": "/x", "source": "/srv/pftrb-cache"}}
    )
)
check("preflight: unrelated disk source allowed", r == [], r)
for listen in (
    "tcp:0.0.0.0:2559",
    "tcp:127.0.0.1:5005",
    "udp:[::]:51235",
    "tcp:0.0.0.0:2500-2600",
):
    r = mut(
        lambda i, l=listen: i["expanded_devices"].update(
            {"p": {"type": "proxy", "listen": l, "connect": "tcp:127.0.0.1:2559"}}
        )
    )
    check(f"preflight: proxy {listen} refused", has(r, "live port"), r)
r = mut(
    lambda i: i["expanded_devices"].update(
        {"p": {"type": "proxy", "listen": "tcp:127.0.0.1:18080"}}
    )
)
check("preflight: proxy on other port allowed", r == [], r)
r = mut(
    lambda i: i["expanded_devices"].update(
        {"eth1": {"type": "nic", "nictype": "macvlan", "parent": "eth0"}}
    )
)
check("preflight: macvlan nic refused", has(r, "bypasses"), r)
r = mut(lambda i: i["expanded_devices"]["eth0"].update({"network": "lxdbr0"}))
check("preflight: nic on another bridge refused", has(r, "not on sandbox bridge"), r)
r = mut(
    lambda i: i["expanded_devices"].update(
        {"g": {"type": "unix-char", "source": "/dev/kvm"}}
    )
)
check("preflight: host device passthrough refused", has(r, "passthrough"), r)
b2 = dict(BR, config={"ipv4.nat": "true", "ipv6.address": "fd42::1/64"})
check("preflight: IPv6 bridge refused", has(rl.preflight(INST, b2), "NAT-only"))
b3 = dict(BR, managed=False)
check("preflight: unmanaged bridge refused", has(rl.preflight(INST, b3), "LXD-managed"))
TOPIC = "pft-live-topic-abc123"
r = rl.preflight(
    INST, BR, [TOPIC], [("/etc/pft-rebuild/ntfy.env", f"NTFY_TOPIC={TOPIC}\n")]
)
check("preflight: live topic in sandbox file refused", has(r, "live ntfy topic"), r)
check(
    "preflight: refusal text does not print the topic",
    not any(TOPIC in x for x in r),
    r,
)
r = rl.preflight(
    INST, BR, [TOPIC], [("/e", "NTFY_URL=https://ntfy.sh/some-other-topic\n")]
)
check("preflight: any ntfy URL in sandbox file refused", has(r, "ntfy URL"), r)
check(
    "preflight: ntfy URL redacted in refusal",
    not any("some-other-topic" in x for x in r),
    r,
)
r = rl.preflight(
    INST, BR, [TOPIC], [("/e", "NTFY_URL=http://127.0.0.1:9/rebuild-blackhole\n")]
)
check("preflight: blackhole sink allowed", r == [], r)
ip, bp = tmpf("i.json", json.dumps(INST)), tmpf("b.json", json.dumps(BR))
rc, out, _ = run("preflight", ip, bp)
check("cli preflight: isolated -> exit 0", rc == 0 and "ISOLATED" in out, (rc, out))
bad = copy.deepcopy(INST)
bad["expanded_devices"]["p"] = {"type": "proxy", "listen": "tcp:0.0.0.0:2559"}
rc, out, _ = run("preflight", tmpf("ib.json", json.dumps(bad)), bp)
check("cli preflight: refused -> exit 4", rc == 4 and "REFUSE" in out, (rc, out))
envf = tmpf("ntfy.env", f"NTFY_TOPIC={TOPIC}\n")
rc, out, _ = run("preflight", ip, bp, "--live-topic", TOPIC, "--sandbox-file", envf)
check(
    "cli preflight: --live-topic/--sandbox-file wired",
    rc == 4 and "live ntfy topic" in out,
    (rc, out),
)

# ---------- diff ----------
LIVE = "# hdr\nbin:a\tsha256\t111\nbin:a\tmtime\t5\nbin:b\tsha256\t222\nunit:x\tenabled\tenabled\nbin:c\tmode\t755\n"
SAND = "bin:a\tsha256\t111\nbin:a\tmtime\t9\nbin:b\tsha256\t999\nbin:d\tsha256\t444\nbin:c\tmode\t755\n"
lm, sm = rl.parse_manifest(LIVE), rl.parse_manifest(SAND)
rows = {r["key"]: r for r in rl.classify(lm, sm)}
check(
    "diff: same bytes, different mtime -> REPRODUCED",
    rows["bin:a"]["class"] == "REPRODUCED",
    rows["bin:a"],
)
check(
    "diff: different sha -> DIFFERENT",
    rows["bin:b"]["class"] == "DIFFERENT" and rows["bin:b"]["attrs"] == ["sha256"],
)
check("diff: live only -> MISSING", rows["unit:x"]["class"] == "MISSING")
check("diff: sandbox only -> EXTRA", rows["bin:d"]["class"] == "EXTRA")
check("diff: identical -> REPRODUCED", rows["bin:c"]["class"] == "REPRODUCED")
lm2, sm2 = rl.parse_manifest("k\ta\t1\n"), rl.parse_manifest("k\ta\t1\nk\tb\t2\n")
check(
    "diff: attr present only in sandbox -> DIFFERENT",
    rl.classify(lm2, sm2)[0]["class"] == "DIFFERENT",
)
sm_ = rl.summarize(rl.classify(lm, sm))
check(
    "diff: summary counts",
    (sm_["REPRODUCED"], sm_["MISSING"], sm_["EXTRA"], sm_["DIFFERENT"], sm_["open"])
    == (2, 1, 1, 1, 2),
    sm_,
)
exc = rl.parse_exceptions(
    "# c\nunit:x * cross-host unit, needs the sentry\nbin:b sha256 host-specific\n"
)
rows = {r["key"]: r for r in rl.classify(lm, sm, exc)}
check(
    "diff: exception covers MISSING item",
    rows["unit:x"]["exception"] == "cross-host unit, needs the sentry",
)
check(
    "diff: exception covers DIFFERENT attr",
    rows["bin:b"]["exception"] == "host-specific",
)
check(
    "diff: excepted items are not open", rl.summarize(list(rows.values()))["open"] == 0
)
exc2 = rl.parse_exceptions("bin:b mode wrong attr\n")
r2 = {r["key"]: r for r in rl.classify(lm, sm, exc2)}
check(
    "diff: exception for another attr does not cover", r2["bin:b"]["exception"] is None
)
lm3 = rl.parse_manifest("k\ta\t1\nk\tb\t1\n")
sm3 = rl.parse_manifest("k\ta\t2\nk\tb\t2\n")
r3 = rl.classify(lm3, sm3, rl.parse_exceptions("k a only a\n"))
check("diff: partial attr exception leaves item open", r3[0]["exception"] is None)
e = raises(rl.parse_manifest, "bin:a sha256 111\n")
check("diff: malformed manifest line refused", e and "KEY<TAB>" in e, e)
e = raises(rl.parse_exceptions, "bin:a sha256\n")
check("diff: exception without reason refused", e and "REASON" in e, e)
FL = {
    "addons": [{"addon": "kernwatch", "state": "CURRENT"}],
    "files": [
        {"path": "/usr/local/bin/pft-kernwatch", "sha256": "aa", "state": "CURRENT"}
    ],
    "units": [
        {"unit": "pft-kernwatch.timer", "enabled": "enabled", "active": "active"}
    ],
}
FS = {
    "addons": [{"addon": "kernwatch", "state": "CURRENT"}],
    "files": [
        {"path": "/usr/local/bin/pft-kernwatch", "sha256": "aa", "state": "CURRENT"}
    ],
    "units": [
        {"unit": "pft-kernwatch.timer", "enabled": "enabled", "active": "inactive"}
    ],
}
fr = {r["key"]: r["class"] for r in rl.classify(rl.fleet_items(FL), rl.fleet_items(FS))}
check("diff: fleet active state not compared", set(fr.values()) == {"REPRODUCED"}, fr)
FS2 = copy.deepcopy(FS)
FS2["addons"][0]["state"] = "MISSING"
fr = {
    r["key"]: r["class"] for r in rl.classify(rl.fleet_items(FL), rl.fleet_items(FS2))
}
check(
    "diff: fleet add-on state change -> DIFFERENT",
    fr["addon:kernwatch"] == "DIFFERENT",
    fr,
)
# add-on state follows its files: excepted only when every differing file of the add-on is excepted
FL3 = copy.deepcopy(FL)
FL3["addons"] = [{"addon": "apparmor", "state": "CURRENT"}]
FL3["files"] = [
    {
        "addon": "apparmor",
        "path": "/usr/local/bin/pft-apparmor",
        "sha256": "aa",
        "state": "CURRENT",
    },
    {
        "addon": "apparmor",
        "path": "/etc/systemd/system/pft-apparmor-pull.timer",
        "sha256": "bb",
        "state": "CURRENT",
    },
]
FS3 = copy.deepcopy(FL3)
FS3["addons"][0]["state"] = "MISSING"
FS3["files"] = FS3["files"][:1]
exc3 = rl.parse_exceptions("file:/etc/systemd/system/pft-*-pull* * cross-host\n")
fr = {r["key"]: r for r in rl.classify(rl.fleet_items(FL3), rl.fleet_items(FS3), exc3)}
check(
    "diff: add-on state excepted when its only differing file is excepted",
    fr["addon:apparmor"]["exception"]
    and "1 differing file" in fr["addon:apparmor"]["exception"],
    fr["addon:apparmor"],
)
fr = {r["key"]: r for r in rl.classify(rl.fleet_items(FL3), rl.fleet_items(FS3))}
check(
    "diff: add-on state stays open when the file is not excepted",
    not fr["addon:apparmor"]["exception"],
    fr,
)
FS4 = copy.deepcopy(FS3)
FS4["files"][0]["sha256"] = "zz"
fr = {r["key"]: r for r in rl.classify(rl.fleet_items(FL3), rl.fleet_items(FS4), exc3)}
check(
    "diff: add-on state stays open when one differing file is open",
    not fr["addon:apparmor"]["exception"]
    and not fr["file:/usr/local/bin/pft-apparmor"]["exception"],
    fr,
)
FS5 = copy.deepcopy(FL3)
FS5["addons"][0]["state"] = "BEHIND"
fr = {r["key"]: r for r in rl.classify(rl.fleet_items(FL3), rl.fleet_items(FS5), exc3)}
check(
    "diff: add-on state with no differing file stays open",
    not fr["addon:apparmor"]["exception"],
    fr,
)
tbl = rl.render_table(rl.classify(lm, sm, exc), rl.summarize(rl.classify(lm, sm, exc)))
check("diff: table hides REPRODUCED by default", "bin:a" not in tbl and "bin:b" in tbl)
check("diff: table shows exception reason", "[exception: host-specific]" in tbl)
check(
    "diff: table summary line",
    tbl.splitlines()[-1].startswith(
        "SUMMARY: REPRODUCED=2 MISSING=1 EXTRA=1 DIFFERENT=1"
    ),
)
lp, sp = tmpf("l.tsv", LIVE), tmpf("s.tsv", SAND)
rc, out, _ = run("diff", lp, sp, "--json")
j = json.loads(out) if rc in (0, 1) else {}
check(
    "cli diff --json: exit 1 with open items",
    rc == 1 and j["summary"]["open"] == 2,
    (rc, out[:200]),
)
check(
    "cli diff --json: every item has a class",
    all(i["class"] in rl.CLASSES for i in j.get("items", [])),
)
ep = tmpf("exc.list", "unit:x * cross-host\nbin:b sha256 host-specific\n")
rc, out, _ = run("diff", lp, sp, "--exceptions", ep)
check(
    "cli diff: all open items excepted -> exit 0",
    rc == 0 and "open=0" in out,
    (rc, out),
)
flp, fsp = tmpf("fl.json", json.dumps(FL)), tmpf("fs.json", json.dumps(FS2))
rc, out, _ = run(
    "diff", lp, sp, "--live-fleet", flp, "--sandbox-fleet", fsp, "--exceptions", ep
)
check("cli diff: fleet items merged", rc == 1 and "addon:kernwatch" in out, (rc, out))
rc, _, err = run("diff", lp, sp, "--live-fleet", flp)
check("cli diff: one-sided fleet refused (exit 3)", rc == 3, (rc, err))

# ---------- teardown ----------
before = "instance none\nnet lxdbr-x\n"
check("teardown: identical -> no leftovers", rl.leftovers(before, before) == [])
check(
    "teardown: new item -> leftover",
    rl.leftovers(before, before + "net pftrb0\n") == ["net pftrb0"],
)
check(
    "teardown: removed item is not a leftover",
    rl.leftovers(before, "instance none\n") == [],
)
rc, out, _ = run(
    "teardown",
    tmpf("b.txt", before),
    tmpf("a.txt", before + "iptables -A DOCKER-USER -i pftrb0\n"),
)
check("cli teardown: leftover -> exit 1", rc == 1 and "INCOMPLETE" in out, (rc, out))
rc, out, _ = run("teardown", tmpf("b2.txt", before), tmpf("a2.txt", before))
check("cli teardown: clean -> exit 0", rc == 0 and "CLEAN" in out, (rc, out))

# ---------- teardown (shell, against stub lxc + iptables) ----------
SCRIPT = os.path.join(RB, "pft-rebuild-drill.sh")
STUB = os.path.join(HERE, "stub_host.py")
for tool in ("lxc", "iptables", "nft"):
    tmpf(tool, f'#!/bin/sh\nexec {sys.executable} {STUB} {tool} "$@"\n')
    os.chmod(os.path.join(TMP, tool), 0o755)
OTHER_FWD = "-j DOCKER-USER"


def teardown_case(state, extra_env=None, args=("teardown", "--yes")):
    sp, cp = tmpf("state.json", json.dumps(state)), tmpf("calls.txt", "")
    env = dict(
        os.environ,
        RB_TEST="1",
        RB_LXC=os.path.join(TMP, "lxc"),
        RB_IPT=os.path.join(TMP, "iptables"),
        RB_NFT=os.path.join(TMP, "nft"),
        RB_STATE=os.path.join(TMP, "rbstate"),
        RB_STUB_STATE=sp,
        RB_STUB_CALLS=cp,
        **(extra_env or {}),
    )
    os.makedirs(env["RB_STATE"], exist_ok=True)
    p = subprocess.run(
        ["bash", SCRIPT, *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    with open(sp, encoding="utf-8") as fh:
        return p.returncode, p.stdout + p.stderr, json.load(fh)


FULL = {
    "instances": ["pftrb-sbx", "other-ct"],
    "networks": ["pftrb0", "lxdbr0"],
    "pools": ["pftrb", "default"],
    "images": ["abc123", "keepme"],
    "chains": {
        "FORWARD": [
            "-o pftrb0 -j PFT-REBUILD",
            "-i pftrb0 -j PFT-REBUILD",
            "-i pftrb0 -j PFT-REBUILD",
            OTHER_FWD,
        ],
        "INPUT": ["-i pftrb0 -j PFT-REBUILD-IN", "-j ufw-before-input"],
        "PFT-REBUILD": ["-j DROP"],
        "PFT-REBUILD-IN": ["-j DROP"],
        "DOCKER-USER": ["-j RETURN"],
    },
    "nft": {"inet lxd": ""},
    "volumes": ["pftrb/rb-docker", "pftrb/rb-containerd", "default/keepvol"],
}
MARK = os.path.join("rbstate", "nft-lxd.created")
os.makedirs(os.path.join(TMP, "rbstate"), exist_ok=True)
tmpf(os.path.join("rbstate", "image.fp"), "abc123\n")  # the image this run downloaded
tmpf(MARK, "")  # the run created table inet lxd
rc, out, st = teardown_case(FULL)
check("teardown: exit 0 on success", rc == 0, (rc, out[-300:]))
check(
    "teardown: sandbox instance/network/pool deleted, others kept",
    (st["instances"], st["networks"], st["pools"])
    == (["other-ct"], ["lxdbr0"], ["default"]),
    st,
)
check(
    "teardown: only the image this run downloaded deleted",
    st["images"] == ["keepme"],
    st["images"],
)
check(
    "teardown: every jump removed (also a duplicate), other rules kept",
    st["chains"]["FORWARD"] == [OTHER_FWD]
    and st["chains"]["INPUT"] == ["-j ufw-before-input"],
    st["chains"],
)
check(
    "teardown: both chains deleted",
    "PFT-REBUILD" not in st["chains"] and "PFT-REBUILD-IN" not in st["chains"],
)
check("teardown: DOCKER-USER untouched", st["chains"]["DOCKER-USER"] == ["-j RETURN"])
check("teardown: reports complete", "teardown complete" in out, out[-200:])
check(
    "teardown: both custom volumes deleted (before the pool), other pool's volume kept",
    st.get("volumes") == ["default/keepvol"],
    st.get("volumes"),
)
check(
    "teardown: empty nft table inet lxd the run created is deleted",
    st.get("nft") == {},
    st.get("nft"),
)
rc, out, st2 = teardown_case(st)
check(
    "teardown: idempotent on a clean host (exit 0)",
    rc == 0 and st2 == st,
    (rc, out[-200:]),
)
rc, out, st3 = teardown_case(json.loads(json.dumps(FULL)), {"RB_STUB_FAIL": "delete"})
check(
    "teardown: instance delete fails -> exit 5 INCOMPLETE",
    rc == 5 and "INCOMPLETE" in out and "instance pftrb-sbx" in out,
    (rc, out[-300:]),
)
rc, out, st4 = teardown_case(
    json.loads(json.dumps(FULL)), {"RB_STUB_FAIL": "X:PFT-REBUILD-IN"}
)
check(
    "teardown: input chain delete fails -> exit 5 INCOMPLETE",
    rc == 5 and "chain PFT-REBUILD-IN" in out,
    (rc, out[-300:]),
)
if os.path.exists(os.path.join(TMP, MARK)):
    os.remove(os.path.join(TMP, MARK))
rc, out, st5 = teardown_case(json.loads(json.dumps(FULL)))
check(
    "teardown: pre-existing nft table inet lxd left alone",
    rc == 0 and st5["nft"] == {"inet lxd": ""},
    (rc, st5.get("nft")),
)
tmpf(MARK, "")
busy = json.loads(json.dumps(FULL))
busy["nft"] = {"inet lxd": "  chain fwd.lxdbr0 {\n  }\n"}
rc, out, st6 = teardown_case(busy)
check(
    "teardown: nft table with chains left alone and reported INCOMPLETE",
    rc == 5 and "inet lxd" in st6["nft"] and "nft table inet lxd" in out,
    (rc, out[-300:]),
)
rc, out, _ = teardown_case(FULL, args=("teardown",))
check("teardown: refuses without --yes (exit 3)", rc == 3, rc)

# ---------- rb-manifest / rb-fleet-conf (shell, stub install/systemctl/chown) ----------
BIN = os.path.join(RB, "bin")
SB = os.path.join(TMP, "stubbin")
os.makedirs(SB, exist_ok=True)
for tool in ("install", "systemctl", "chown"):
    tmpf(f"stubbin/{tool}", f'#!/bin/sh\necho "{tool} $*" >> "$RB_STUB_CALLS"\n')
    os.chmod(os.path.join(SB, tool), 0o755)


def helper(name, repo, extra_env=None, args=()):
    calls = tmpf("hcalls.txt", "")
    env = dict(
        os.environ,
        PATH=SB + ":" + os.environ["PATH"],
        RB_STUB_CALLS=calls,
        **(extra_env or {}),
    )
    p = subprocess.run(
        ["bash", os.path.join(BIN, name), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    with open(calls, encoding="utf-8") as fh:
        return p.returncode, p.stdout + p.stderr, fh.read().splitlines()


MR = os.path.join(TMP, "mrepo")
U = "/etc/systemd/system/"
for f, body in {
    "x/long.service": "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
    "x/tick.service": "[Service]\nType=oneshot\n[Install]\nWantedBy=multi-user.target\n",
    "x/tick.timer": "[Timer]\nOnCalendar=hourly\n",
    "x/static.service": "[Service]\nType=oneshot\n",
    "x/inst@.service": "[Service]\n[Install]\nWantedBy=multi-user.target\n",
    "x/tool.sh": "#!/bin/sh\n",
}.items():
    os.makedirs(os.path.join(MR, "x"), exist_ok=True)
    tmpf(f"mrepo/{f}", body)
os.makedirs(os.path.join(MR, "fleet"), exist_ok=True)
tmpf(
    "mrepo/fleet/manifest.tsv",
    "".join(
        f"x\tx/{n}\t{U}{n}\t0644\tboth\n"
        for n in (
            "long.service",
            "tick.service",
            "tick.timer",
            "static.service",
            "inst@.service",
        )
    )
    + "x\tx/tool.sh\t/usr/local/bin/tool\t0755\tvalidator\ny\tx/tool.sh\t/usr/local/bin/y\t0755\tsentry\n",
)
rc, out, calls = helper("rb-manifest", MR, args=("x",))
en = [c for c in calls if c.startswith("systemctl enable")]
check(
    "rb-manifest: installs every validator/both row (6)",
    rc == 0 and sum(c.startswith("install ") for c in calls) == 6,
    (rc, out[-300:]),
)
check(
    "rb-manifest: enables the timer and the long-running service only",
    sorted(en)
    == ["systemctl enable --now long.service", "systemctl enable --now tick.timer"],
    en,
)
rc, out, _ = helper("rb-manifest", MR, args=("y",))
check(
    "rb-manifest: no validator/both rows -> exit 1",
    rc == 1 and "no validator/both rows" in out,
    (rc, out),
)

FR = os.path.join(TMP, "frepo")
os.makedirs(os.path.join(FR, "fleet"), exist_ok=True)
shutil.copy(
    os.path.join(REPO, "fleet", "fleet.conf.example"),
    os.path.join(FR, "fleet"),
)
shutil.copy(
    os.path.join(REPO, "fleet", "hosts.conf.example"),
    os.path.join(FR, "fleet"),
)
subprocess.run(["git", "init", "-q", FR], check=True)
subprocess.run(
    [
        "git",
        "-C",
        FR,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "t",
    ],
    check=True,
)
head = subprocess.run(
    ["git", "-C", FR, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
).stdout.strip()


def readf(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


FE = os.path.join(TMP, "fleetetc")
os.makedirs(FE, exist_ok=True)  # install -d is stubbed
rc, out, calls = helper("rb-fleet-conf", FR, {"RB_FLEET_ETC": FE})
fc = readf(os.path.join(FE, "fleet.conf")) if rc == 0 else ""
hc = readf(os.path.join(FE, "hosts.conf")) if rc == 0 else ""
check(
    "rb-fleet-conf: REPO = sandbox checkout, REF = its HEAD commit",
    f"\nREPO={os.path.realpath(FR)}\n" in fc and f"\nREF={head}\n" in fc,
    (rc, out[-300:]),
)
hosts = [ln.split() for ln in hc.splitlines() if ln.startswith("host ")]
check(
    "rb-fleet-conf: hosts.conf lists only the local validator",
    hosts == [["host", "validator", "local", "-", "postfiatd", "validator"]],
    hosts,
)
with open(os.path.join(FE, "hosts.conf"), "w", encoding="utf-8") as fh:
    fh.write("host keep local - postfiatd validator\n")
rc, out, _ = helper("rb-fleet-conf", FR, {"RB_FLEET_ETC": FE})
check(
    "rb-fleet-conf: an existing file is left alone",
    rc == 0
    and readf(os.path.join(FE, "hosts.conf"))
    == "host keep local - postfiatd validator\n",
    (rc, out),
)

# rb-limit: only the declared signature, only inside an lxc container, turns a failure into SANDBOX_LIMIT
tmpf(
    "stubbin/systemd-detect-virt",
    '#!/bin/sh\necho "${RB_STUB_VIRT:-none}"\n[ "${RB_STUB_VIRT:-none}" != none ]\n',
)
os.chmod(os.path.join(SB, "systemd-detect-virt"), 0o755)
KMSG = "kernwatch_parse: Data from the specified boot (7ccb0487586944b6aabfccb2eec9699e) is not available: No such boot ID in journal"
lim_cases = (
    ("signature in lxc -> 0 + SANDBOX_LIMIT", "lxc", f"echo '{KMSG}'; exit 1", 0, True),
    ("success passes through", "lxc", "echo fine", 0, False),
    (
        "other failure in lxc keeps rc",
        "lxc",
        "echo 'container postfiatd not running'; exit 3",
        3,
        False,
    ),
    (
        "signature outside a container keeps rc",
        "none",
        f"echo '{KMSG}'; exit 1",
        1,
        False,
    ),
    ("signature on stderr counts", "lxc", f"echo '{KMSG}' >&2; exit 2", 0, True),
)
for name, virt, cmd, want, lim in lim_cases:
    rc, out, _ = helper(
        "rb-limit", TMP, {"RB_STUB_VIRT": virt}, ("kernel-log", "bash", "-c", cmd)
    )
    check(
        f"rb-limit: {name}",
        rc == want and ("SANDBOX_LIMIT kernel-log:" in out) == lim,
        (rc, out),
    )
# the two hardening limits also need the tool's own rollback PASS line (a failed rollback is never a limit)
AA_FAIL = "2026-11-05T21:41:55Z apply: health FAIL after 91 poll(s): server_state none; peers 0 < 1;"
AA_RB = (
    "2026-11-05T21:42:47Z rollback RESULT: PASS - postfiatd back under docker-default"
)
SC_FAIL = "2026-11-05T21:43:41Z apply: gate FAIL - audit log unreadable"
SC_RB = (
    "2026-11-05T21:44:46Z rollback RESULT: PASS - postfiatd back under seccomp default"
)
hard_cases = (
    ("apparmor-nested", "fail + rollback PASS -> limit", [AA_FAIL, AA_RB], 0, True),
    ("apparmor-nested", "fail, rollback not PASS -> rc", [AA_FAIL], 1, False),
    (
        "apparmor-nested",
        "rollback PASS, other failure -> rc",
        ["apply: x", AA_RB],
        1,
        False,
    ),
    (
        "apparmor-nested",
        "server_state syncing is not the signature",
        [AA_FAIL.replace("none", "syncing"), AA_RB],
        1,
        False,
    ),
    (
        "apparmor-nested",
        "seccomp rollback line does not count",
        [AA_FAIL, SC_RB],
        1,
        False,
    ),
    ("kernel-audit", "fail + rollback PASS -> limit", [SC_FAIL, SC_RB], 0, True),
    ("kernel-audit", "fail, rollback not PASS -> rc", [SC_FAIL], 1, False),
    (
        "kernel-audit",
        "apparmor rollback line does not count",
        [SC_FAIL, AA_RB],
        1,
        False,
    ),
)
for lim, name, lines, want, islim in hard_cases:
    body = "".join(f"echo '{x}'; " for x in lines) + "exit 1"
    rc, out, _ = helper(
        "rb-limit", TMP, {"RB_STUB_VIRT": "lxc"}, (lim, "bash", "-c", body)
    )
    check(
        f"rb-limit {lim}: {name}",
        rc == want and (f"SANDBOX_LIMIT {lim}:" in out) == islim,
        (rc, out),
    )
rc, out, _ = helper(
    "rb-limit",
    TMP,
    {"RB_STUB_VIRT": "none"},
    ("kernel-audit", "bash", "-c", f"echo '{SC_FAIL}'; echo '{SC_RB}'; exit 1"),
)
check(
    "rb-limit kernel-audit: outside a container keeps rc",
    rc == 1 and "SANDBOX_LIMIT" not in out,
    (rc, out),
)

rc, out, _ = helper("rb-limit", TMP, {"RB_STUB_VIRT": "lxc"}, ("nope", "true"))
check("rb-limit: unknown limit -> exit 3", rc == 3, (rc, out))

# ---------- aa-nested: host audit records (shapes from the run-22 host audit.log, pids replaced) ----------
NS = 'namespace="root//lxd-pftrb-sbx_<var-snap-lxd-common-lxd>" '


def avc(ts, op, name, ns=NS, prof="pft-postfiatd", verdict="DENIED"):
    return (
        f'type=AVC msg=audit({ts}.674:5547701): apparmor="{verdict}" operation="{op}" {ns}profile="{prof}" '
        f'name="{name}" pid=1 comm="docker-entrypoi" requested_mask="r" denied_mask="r" fsuid=1000000 ouid=1000000'
    )


LIBC = "/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs/usr/lib/x86_64-linux-gnu/libc.so.6"
AUD = [
    avc(1793916797, "file_mprotect", LIBC),
    avc(1793916858, "file_mprotect", LIBC),
    avc(1793916900, "file_mmap", "/usr/bin/bash"),
    avc(1793900000, "file_mmap", "/old"),  # before --since
    avc(1793916901, "open", "/x", prof="docker-default"),  # other profile
    avc(1793916902, "open", "/y", verdict="ALLOWED"),
    'type=SERVICE_STOP msg=audit(1793916903.1:5): pid=1 uid=0 msg="unit=x"',
]
SINCE = 1793916000
r = safe(rl.aa_nested, "\n".join(AUD), "pftrb-sbx", "pft-postfiatd", SINCE, default={})
check(
    "aa-nested: counts only DENIED for the profile in the sandbox namespace since the step start",
    r.get("sandbox") == 3
    and r.get("live") == 0
    and r.get("ops", {}).get(f"file_mprotect {LIBC}") == 2,
    r,
)
r = safe(
    rl.aa_nested,
    "\n".join(AUD + [avc(1793916950, "exec", "/usr/bin/cat", ns="")]),
    "pftrb-sbx",
    "pft-postfiatd",
    SINCE,
    default={},
)
check(
    "aa-nested: a record without namespace is the live node",
    r.get("live") == 1 and r.get("sandbox") == 3,
    r,
)
r = safe(rl.aa_nested, "\n".join(AUD), "pftrb", "pft-postfiatd", SINCE, default={})
check(
    "aa-nested: another instance name's namespace is not the sandbox",
    r.get("sandbox") == 0 and r.get("live") == 3,
    r,
)
af = tmpf("audit.txt", "\n".join(AUD) + "\n")
rc, out, _ = run(
    "aa-nested",
    af,
    "--sandbox",
    "pftrb-sbx",
    "--profile",
    "pft-postfiatd",
    "--since",
    str(SINCE),
)
check(
    "cli aa-nested: sandbox-only denials -> CONFIRMED exit 0",
    rc == 0 and "AA_NESTED: CONFIRMED" in out,
    (rc, out),
)
af2 = tmpf(
    "audit2.txt",
    "\n".join(AUD + [avc(1793916950, "exec", "/usr/bin/cat", ns="")]) + "\n",
)
rc, out, _ = run(
    "aa-nested",
    af2,
    "--sandbox",
    "pftrb-sbx",
    "--profile",
    "pft-postfiatd",
    "--since",
    str(SINCE),
)
check(
    "cli aa-nested: one live denial -> NOT CONFIRMED exit 1",
    rc == 1 and "NOT CONFIRMED" in out,
    (rc, out),
)
rc, out, _ = run(
    "aa-nested",
    af,
    "--sandbox",
    "pftrb-sbx",
    "--profile",
    "pft-postfiatd",
    "--since",
    "1793999999",
)
check(
    "cli aa-nested: no sandbox denial in the span -> exit 1",
    rc == 1 and "sandbox namespace 0" in out,
    (rc, out),
)
rc, _, _ = run("aa-nested", af, "--sandbox", "pftrb-sbx")
check("cli aa-nested: missing options -> exit 3", rc == 3)

# ---------- drill `limits --dir`: every SANDBOX_LIMIT is re-checked on the live host ----------
REPOD = os.path.dirname(RB)
LIM_AA = "SANDBOX_LIMIT apparmor-nested: nested AppArmor namespace (step rc 1)"
LIM_SC = "SANDBOX_LIMIT kernel-audit: no kernel audit log (step rc 1)"
tmpf(
    "rbdocker",
    '#!/bin/sh\ncase "$3" in *AppArmorProfile*) echo "${RB_STUB_AA:-pft-postfiatd}" ;; *SecurityOpt*) echo "${RB_STUB_SECOPT:-[\\"seccomp={}\\"]}" ;; esac\n',
)
os.chmod(os.path.join(TMP, "rbdocker"), 0o755)
same_aa = os.path.join(REPOD, "apparmor/profile/pft-postfiatd")
same_sc = os.path.join(REPOD, "seccomp/profile/pft-postfiatd.json")
other = tmpf("other-profile", "not the committed profile\n")


def limits_case(steps, extra_env=None):
    d = tempfile.mkdtemp(dir=TMP)
    os.makedirs(os.path.join(d, "steps"))
    for name, body in steps.items():
        with open(os.path.join(d, "steps", name + ".log"), "w", encoding="utf-8") as fh:
            fh.write(body)
        if not (extra_env or {}).get("RB_TEST_NOSTART"):
            with open(
                os.path.join(d, "steps", name + ".start"), "w", encoding="utf-8"
            ) as fh:
                fh.write(f"{SINCE}\n")
    env = dict(
        os.environ,
        RB_TEST="1",
        RB_DOCKER=os.path.join(TMP, "rbdocker"),
        RB_AUDIT_LOGS=af,
        RB_AA_LIVE=same_aa,
        RB_SC_LIVE=same_sc,
    )
    env.update(extra_env or {})
    p = subprocess.run(
        ["bash", SCRIPT, "limits", "--dir", d],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    return p.returncode, p.stdout + p.stderr


BOTH = {"342-aaapply": f"x\n{LIM_AA}\n", "344-scapply": f"{LIM_SC}\n"}
rc, out = limits_case(BOTH)
check(
    "drill limits: both limits confirmed on the live host -> exit 0",
    rc == 0
    and "AA_NESTED: CONFIRMED" in out
    and "CHECK FAIL" not in out
    and "2 SANDBOX_LIMIT" in out,
    (rc, out),
)
rc, out = limits_case({"140-kernwatch": "SANDBOX_LIMIT kernel-log: x (step rc 1)\n"})
check(
    "drill limits: kernel-log needs no live proof -> exit 0",
    rc == 0 and "1 SANDBOX_LIMIT" in out,
    (rc, out),
)
rc, out = limits_case({"010-base": "ok\n"})
check(
    "drill limits: no limit lines -> exit 0",
    rc == 0 and "0 SANDBOX_LIMIT" in out,
    (rc, out),
)
for name, env, frag in (
    ("a live denial", {"RB_AUDIT_LOGS": af2}, "DENIED only in the sandbox namespace"),
    (
        "live AppArmor profile bytes differ",
        {"RB_AA_LIVE": other},
        "apparmor-nested: live",
    ),
    (
        "live container not under pft-postfiatd",
        {"RB_STUB_AA": "docker-default"},
        "runs pft-postfiatd",
    ),
    ("live seccomp profile bytes differ", {"RB_SC_LIVE": other}, "kernel-audit: live"),
    (
        "live container without custom seccomp",
        {"RB_STUB_SECOPT": '["no-new-privileges:true"]'},
        "custom seccomp",
    ),
    (
        "no audit file readable",
        {"RB_AUDIT_LOGS": os.path.join(TMP, "nope*")},
        "DENIED only in the sandbox namespace",
    ),
):
    rc, out = limits_case(BOTH, env)
    check(
        f"drill limits: {name} -> exit 2",
        rc == 2 and "CHECK FAIL" in out and frag in out.split("CHECK FAIL", 1)[1],
        (rc, out),
    )
rc, out = limits_case(BOTH, {"RB_TEST_NOSTART": "1"})
check(
    "drill limits: apparmor-nested without a recorded step start -> exit 2",
    rc == 2 and "CHECK FAIL apparmor-nested: step start time recorded" in out,
    (rc, out),
)
rc, out = limits_case({"344-scapply": "SANDBOX_LIMIT made-up: x\n"})
check(
    "drill limits: unknown limit name -> exit 2",
    rc == 2 and "known limit name" in out,
    (rc, out),
)

rc, _, _ = run("nope")
check("cli: unknown subcommand -> exit 3", rc == 3)

print(
    f"RESULT: {'PASS' if all(results) else 'FAIL'} ({len(results)} checks, {results.count(False)} failed)"
)
sys.exit(0 if all(results) else 1)
