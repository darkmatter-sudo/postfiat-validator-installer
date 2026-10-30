#!/usr/bin/env python3
"""pft-fleet helper (stdlib only): repo history index, file/add-on classification, table/JSON/metrics output.

pft-fleet.sh collects the raw inventory (one TSV line per file, unit and host) and calls this module:

  fleet_lib.py report --repo DIR --ref REF --manifest M --inv INV [--mode inventory|skew] [--json]
                      [--metrics FILE --drift-state FILE] [--now EPOCH]
  fleet_lib.py plan   --repo DIR --ref REF --manifest M --inv INV --to COMMIT --addon NAME
  fleet_lib.py files  --manifest M --addon NAME --role ROLE      (repo_path, install_path, mode per line)

Inventory TSV (from pft-fleet.sh):
  host  LABEL ROLE ok|error[:reason]
  file  LABEL ROLE INSTALL_PATH SHA256|-
  unit  LABEL ROLE UNIT ENABLED ACTIVE
Manifest TSV: ADDON REPO_PATH INSTALL_PATH MODE ROLES (validator|sentry|both); '#' starts a comment.

Per file on a host:  expected = the host's role is in ROLES; present = a sha256 was read.
  CURRENT     present, bytes equal REPO_PATH at REF
  BEHIND      present, bytes equal REPO_PATH at an older commit in REF's history (newest match wins)
  MODIFIED    present, bytes match no committed version of REPO_PATH
  MISSING     expected, not present
  UNEXPECTED  present, but this host's role is not in ROLES
An add-on's state on a host is its worst file state (MODIFIED > MISSING > BEHIND > UNEXPECTED > CURRENT).
DIVERGED (cross-host): a file installed on two or more hosts with different bytes.
Exit (report --mode skew): 2 = any MODIFIED or MISSING or a host could not be read, 1 = any BEHIND, UNEXPECTED or
DIVERGED, 0 = everything CURRENT. --mode inventory always exits 0 unless a host could not be read (2).
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

RANK = {"CURRENT": 1, "UNEXPECTED": 2, "BEHIND": 3, "MISSING": 4, "MODIFIED": 5}
STATES = ["CURRENT", "BEHIND", "MODIFIED", "MISSING", "UNEXPECTED"]


def git(repo, *args, binary=False):
    out = subprocess.run(["git", "-c", "safe.directory=*", "-C", repo, *args],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if out.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args), out.stderr.decode(errors="replace").strip()))
    return out.stdout if binary else out.stdout.decode()


def read_manifest(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            f = line.split()
            if len(f) != 5 or f[4] not in ("validator", "sentry", "both"):
                raise ValueError("%s:%d: want ADDON REPO_PATH INSTALL_PATH MODE ROLES" % (path, n))
            rows.append({"addon": f[0], "repo_path": f[1], "path": f[2], "mode": f[3], "roles": f[4]})
    return rows


def role_ok(roles, role):
    return roles == "both" or roles == role


def read_inv(path):
    hosts, files, units = {}, {}, {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if f[0] == "host" and len(f) == 4:
                hosts[f[1]] = {"role": f[2], "status": f[3]}
            elif f[0] == "file" and len(f) == 5:
                files[(f[1], f[3])] = None if f[4] == "-" else f[4]
            elif f[0] == "unit" and len(f) == 6:
                units[(f[1], f[3])] = {"enabled": f[4], "active": f[5]}
    return hosts, files, units


def history(repo, ref, repo_path):
    """-> (sha at ref or None, {sha256: (commit, n_newer_commits, commit_epoch)}) for one path."""
    ref_sha = None
    try:
        ref_sha = hashlib.sha256(git(repo, "show", "%s:%s" % (ref, repo_path), binary=True)).hexdigest()
    except RuntimeError:
        pass
    known = {}
    log = git(repo, "log", "--format=%H %ct", ref, "--", repo_path).split("\n")
    n = 0
    for line in log:
        if not line.strip():
            continue
        commit, ct = line.split()
        try:
            blob = git(repo, "show", "%s:%s" % (commit, repo_path), binary=True)
        except RuntimeError:  # path deleted in this commit
            n += 1
            continue
        s = hashlib.sha256(blob).hexdigest()
        if s not in known:
            known[s] = (commit, n, int(ct))
        n += 1
    return ref_sha, known


def classify_file(expected, sha, ref_sha, known):
    if sha is None:
        return ("MISSING", None, None) if expected else (None, None, None)
    if not expected:
        return "UNEXPECTED", known.get(sha, (None,))[0], None
    if ref_sha is not None and sha == ref_sha:
        return "CURRENT", known.get(sha, (None,))[0], 0
    if sha in known:
        commit, newer, _ = known[sha]
        return "BEHIND", commit, newer
    return "MODIFIED", None, None


def build(args):
    manifest = read_manifest(args.manifest)
    hosts, files, units = read_inv(args.inv)
    ref_commit = git(args.repo, "rev-parse", "%s^{commit}" % args.ref).strip()
    hist = {}
    for m in manifest:
        if m["repo_path"] not in hist:
            hist[m["repo_path"]] = history(args.repo, ref_commit, m["repo_path"])
    rows, addons = [], {}
    for label, h in hosts.items():
        if h["status"] != "ok":
            continue
        for m in manifest:
            sha = files.get((label, m["path"]))
            ref_sha, known = hist[m["repo_path"]]
            st, commit, behind = classify_file(role_ok(m["roles"], h["role"]), sha, ref_sha, known)
            if st is None:
                continue
            rows.append({"host": label, "role": h["role"], "addon": m["addon"], "path": m["path"],
                         "repo_path": m["repo_path"], "sha256": sha, "ref_sha256": ref_sha, "state": st,
                         "commit": commit, "behind": behind})
            key = (label, m["addon"])
            if key not in addons or RANK[st] > RANK[addons[key]]:
                addons[key] = st
    # cross-host: same install path, present on 2+ readable hosts, different bytes
    diverged = {}
    by_path = {}
    for r in rows:
        if r["sha256"] is not None:
            by_path.setdefault((r["addon"], r["path"]), {})[r["host"]] = r["sha256"]
    for (addon, path), per in sorted(by_path.items()):
        if len(per) >= 2 and len(set(per.values())) > 1:
            diverged.setdefault(addon, []).append(path)
    unit_rows = [{"host": k[0], "unit": k[1], **v} for k, v in sorted(units.items())]
    return {"ref": args.ref, "ref_commit": ref_commit, "hosts": hosts, "files": rows,
            "addons": [{"host": k[0], "addon": k[1], "state": v} for k, v in sorted(addons.items())],
            "diverged": [{"addon": a, "paths": p} for a, p in sorted(diverged.items())], "units": unit_rows}


def exit_code(rep, mode):
    if any(h["status"] != "ok" for h in rep["hosts"].values()):
        return 2
    if mode == "inventory":
        return 0
    states = {a["state"] for a in rep["addons"]}
    if states & {"MODIFIED", "MISSING"}:
        return 2
    if states & {"BEHIND", "UNEXPECTED"} or rep["diverged"]:
        return 1
    return 0


def short(s):
    return s[:12] if s else "-"


def table(rep, mode, out):
    w = out.write
    w("ref %s = %s\n" % (rep["ref"], rep["ref_commit"]))
    for label, h in sorted(rep["hosts"].items()):
        w("host %-10s role %-9s %s\n" % (label, h["role"], h["status"]))
    if mode == "inventory":
        w("%-10s %-11s %-46s %-12s %-12s %s\n" % ("HOST", "ADDON", "PATH", "SHA256", "COMMIT", "STATE"))
        for r in rep["files"]:
            w("%-10s %-11s %-46s %-12s %-12s %s\n" % (r["host"], r["addon"], r["path"], short(r["sha256"]),
                                                       short(r["commit"]), r["state"]))
        w("%-10s %-46s %-10s %s\n" % ("HOST", "UNIT", "ENABLED", "ACTIVE"))
        for u in rep["units"]:
            w("%-10s %-46s %-10s %s\n" % (u["host"], u["unit"], u["enabled"], u["active"]))
        return
    w("%-10s %-11s %-10s %s\n" % ("HOST", "ADDON", "STATE", "DETAIL"))
    for a in rep["addons"]:
        bad = [r for r in rep["files"] if r["host"] == a["host"] and r["addon"] == a["addon"]
               and r["state"] != "CURRENT"]
        det = "; ".join("%s %s%s" % (r["path"], r["state"],
                                     " @%s (-%d)" % (short(r["commit"]), r["behind"]) if r["state"] == "BEHIND" else "")
                        for r in bad)
        w("%-10s %-11s %-10s %s\n" % (a["host"], a["addon"], a["state"], det))
    for d in rep["diverged"]:
        w("%-10s %-11s %-10s %s\n" % ("*", d["addon"], "DIVERGED", " ".join(d["paths"])))
    counts = {s: sum(1 for a in rep["addons"] if a["state"] == s) for s in STATES}
    w("SUMMARY %s DIVERGED=%d\n" % (" ".join("%s=%d" % (s, counts[s]) for s in STATES), len(rep["diverged"])))


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def metrics(rep, path, state_path, now, code):
    try:
        with open(state_path, encoding="utf-8") as fh:
            since = json.load(fh)
    except (OSError, ValueError):
        since = {}
    new = {}
    for a in rep["addons"]:
        if a["state"] != "CURRENT":
            k = "%s/%s" % (a["host"], a["addon"])
            new[k] = since.get(k, now)
    for d in rep["diverged"]:
        k = "*/%s" % d["addon"]
        new[k] = since.get(k, now)
    readable = {lab for lab, h in rep["hosts"].items() if h["status"] == "ok"}
    for k, v in since.items():  # keep the clock of hosts that could not be read this time
        if k.split("/", 1)[0] not in readable and k.split("/", 1)[0] != "*":
            new.setdefault(k, v)
    lines = ["# HELP pft_fleet_up 1 when every host was read", "# TYPE pft_fleet_up gauge",
             "pft_fleet_up %d" % (1 if all(h["status"] == "ok" for h in rep["hosts"].values()) else 0),
             "# HELP pft_fleet_last_run_timestamp_seconds end of the last skew run",
             "# TYPE pft_fleet_last_run_timestamp_seconds gauge",
             "pft_fleet_last_run_timestamp_seconds %d" % now,
             "# HELP pft_fleet_exit_code exit code of the last skew run (0 current, 1 drift, 2 modified/missing/error)",
             "# TYPE pft_fleet_exit_code gauge", "pft_fleet_exit_code %d" % code,
             "# HELP pft_fleet_host_up 1 when this host's inventory was read", "# TYPE pft_fleet_host_up gauge"]
    for lab, h in sorted(rep["hosts"].items()):
        lines.append('pft_fleet_host_up{host="%s"} %d' % (esc(lab), 1 if h["status"] == "ok" else 0))
    lines += ["# HELP pft_fleet_addon_state 1 for the add-on's current state on that host",
              "# TYPE pft_fleet_addon_state gauge"]
    for a in rep["addons"]:
        lines.append('pft_fleet_addon_state{host="%s",addon="%s",state="%s"} 1' % (esc(a["host"]), esc(a["addon"]),
                                                                                    a["state"]))
    lines += ["# HELP pft_fleet_addon_diverged 1 when an installed file of the add-on differs between hosts",
              "# TYPE pft_fleet_addon_diverged gauge"]
    div = {d["addon"] for d in rep["diverged"]}
    for addon in sorted({a["addon"] for a in rep["addons"]}):
        lines.append('pft_fleet_addon_diverged{addon="%s"} %d' % (esc(addon), 1 if addon in div else 0))
    lines += ["# HELP pft_fleet_drift_since_timestamp_seconds first run that saw this host/add-on (or */add-on "
              "for DIVERGED) not CURRENT, without a CURRENT run since",
              "# TYPE pft_fleet_drift_since_timestamp_seconds gauge"]
    for k, v in sorted(new.items()):
        h, addon = k.split("/", 1)
        lines.append('pft_fleet_drift_since_timestamp_seconds{host="%s",addon="%s"} %d' % (esc(h), esc(addon), v))
    for p, text in ((state_path, json.dumps(new, sort_keys=True) + "\n"), (path, "\n".join(lines) + "\n")):
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)


def cmd_report(args):
    rep = build(args)
    code = exit_code(rep, args.mode)
    rep["exit_code"] = code
    if args.json:
        json.dump(rep, sys.stdout, indent=1, sort_keys=True)
        sys.stdout.write("\n")
    else:
        table(rep, args.mode, sys.stdout)
    if args.metrics:
        metrics(rep, args.metrics, args.drift_state, int(args.now or time.time()), code)
    return code


def cmd_plan(args):
    """One line per file to write: LABEL ROLE INSTALL_PATH MODE REPO_PATH CUR_SHA|- TARGET_SHA CUR_STATE ACTION."""
    rep = build(args)
    commit = git(args.repo, "rev-parse", "%s^{commit}" % args.to).strip()
    manifest = [m for m in read_manifest(args.manifest) if m["addon"] == args.addon]
    if not manifest:
        print("unknown add-on %s" % args.addon, file=sys.stderr)
        return 3
    cur = {(r["host"], r["path"]): r for r in rep["files"]}
    for label, h in rep["hosts"].items():
        if h["status"] != "ok":
            print("host %s could not be read: %s" % (label, h["status"]), file=sys.stderr)
            return 2
    for label, h in rep["hosts"].items():
        for m in manifest:
            if not role_ok(m["roles"], h["role"]):
                continue
            try:
                blob = git(args.repo, "show", "%s:%s" % (commit, m["repo_path"]), binary=True)
            except RuntimeError:
                print("%s does not exist at %s" % (m["repo_path"], commit), file=sys.stderr)
                return 3
            tgt = hashlib.sha256(blob).hexdigest()
            r = cur.get((label, m["path"]), {})
            sha = r.get("sha256")
            print("\t".join([label, h["role"], m["path"], m["mode"], m["repo_path"], sha or "-", tgt,
                             r.get("state", "MISSING"), "keep" if sha == tgt else "write"]))
    return 0


def cmd_files(args):
    for m in read_manifest(args.manifest):
        if (args.addon in ("", m["addon"])) and (not args.role or role_ok(m["roles"], args.role)):
            print("\t".join([m["addon"], m["repo_path"], m["path"], m["mode"], m["roles"]]))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="fleet_lib.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("report", "plan"):
        s = sub.add_parser(name)
        s.add_argument("--repo", required=True)
        s.add_argument("--ref", default="main")
        s.add_argument("--manifest", required=True)
        s.add_argument("--inv", required=True)
        if name == "report":
            s.add_argument("--mode", choices=["inventory", "skew"], default="skew")
            s.add_argument("--json", action="store_true")
            s.add_argument("--metrics", default="")
            s.add_argument("--drift-state", default="")
            s.add_argument("--now", default="")
        else:
            s.add_argument("--to", required=True)
            s.add_argument("--addon", required=True)
    s = sub.add_parser("files")
    s.add_argument("--manifest", required=True)
    s.add_argument("--addon", default="")
    s.add_argument("--role", default="")
    args = p.parse_args(argv)
    try:
        if args.cmd == "report":
            if args.metrics and not args.drift_state:
                p.error("--metrics needs --drift-state")
            return cmd_report(args)
        if args.cmd == "plan":
            return cmd_plan(args)
        return cmd_files(args)
    except (RuntimeError, ValueError, OSError) as e:
        print("pft-fleet: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
