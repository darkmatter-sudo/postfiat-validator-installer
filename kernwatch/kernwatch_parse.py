#!/usr/bin/env python3
"""pft-kernwatch helper: classify host kernel-log records (journalctl -k -o json) against a versioned catalogue.

  collect --catalogue F --state F --host H [--max N] [--from-boot-start] [--events-json F]
      Incremental: reads the kernel journal after the cursor kept in the state file (bounded by --max records per
      run), classifies every record, updates the per-pattern counters and writes the Prometheus textfile body to
      stdout. A boot change first finishes the old boot after its cursor, then reads the new boot from its start.
      A cursor journald no longer knows (rotation/vacuum) is replaced by a monotonic-time guard on the same boot.
      With no state file the first run only seeds the cursor at the newest record (nothing older is counted)
      unless --from-boot-start. The state file is written atomically only after a successful read.
  report --catalogue F [--since S] [--until S] [--boot B|all] [--format json|tsv] [--max N]
      Read-only summary of a journal range: per pattern count, first/last time (UTC) and one redacted excerpt.
      Never prints a raw kernel line, a host name, an IP or MAC address.
  check-catalogue --catalogue F    exit 0 if the catalogue is valid (prints version and pattern count)

Exit codes: 0 ok, 1 journal read failed (textfile still printed, with up 0), 2 bad input, 3 usage/catalogue error.
Test hooks: PFT_KW_JOURNALCTL (journalctl command, word-split), PFT_KW_BOOT_ID_FILE (/proc/sys/kernel/random/boot_id).
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time

STATE_VERSION = 1
SEVERITIES = ("crit", "warn", "info")
ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{0,20}$")
HOST_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
JOURNAL_TIMEOUT = 60


class CatalogueError(Exception):
    pass


def load_catalogue(path):
    """-> (version, sha256 hex, [(id, severity, class, compiled regex)])"""
    with open(path, "rb") as f:
        raw = f.read()
    version = None
    entries = []
    seen = set()
    for n, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if line.startswith("#"):
            m = re.match(r"^# version\t(\d+)$", line)
            if m:
                version = int(m.group(1))
            continue
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            raise CatalogueError(
                f"line {n}: want 4 tab-separated fields, got {len(parts)}"
            )
        pid, sev, cls, rx = parts
        if not ID_RE.match(pid) or pid in seen:
            raise CatalogueError(f"line {n}: bad or duplicate id {pid!r}")
        if sev not in SEVERITIES:
            raise CatalogueError(f"line {n}: bad severity {sev!r}")
        if not CLASS_RE.match(cls):
            raise CatalogueError(f"line {n}: bad class {cls!r}")
        try:
            crx = re.compile(rx)
        except re.error as e:
            raise CatalogueError(f"line {n}: regex does not compile: {e}") from None
        seen.add(pid)
        entries.append((pid, sev, cls, crx))
    if version is None:
        raise CatalogueError("no '# version<TAB>N' line")
    if not entries:
        raise CatalogueError("no patterns")
    return version, hashlib.sha256(raw).hexdigest(), entries


def classify(entries, msg):
    for e in entries:
        if e[3].search(msg):
            return e
    return None


# --- redaction ---------------------------------------------------------------------------------------------------
BYTES_RE = re.compile(
    r"\b[0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2}){5,}\b"
)  # raw header dumps (ll header: MACs)
MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5,}\b")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_CAND_RE = re.compile(
    r"(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?![\w:])"
)
HEX_RE = re.compile(
    r"\b(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]*\d[0-9A-Fa-f]*[A-Fa-f][0-9A-Fa-f]*|[0-9A-Fa-f]*[A-Fa-f][0-9A-Fa-f]*\d[0-9A-Fa-f]*)\b"
)
HOME_RE = re.compile(r"/home/[^/\s]+|/root\b")
NUM_RE = re.compile(r"\d{4,}")
EXCERPT_MAX = 160


def _v6(m):
    s = m.group(0)
    try:
        ipaddress.IPv6Address(s.split("%")[0])
        return "<ip>"
    except ValueError:
        return s


def _v4(m):
    try:
        ipaddress.IPv4Address(m.group(0))
        return "<ip>"
    except ValueError:
        return m.group(0)


def redact(msg, extra_names=()):
    s = msg
    for name in extra_names:
        if name and len(name) >= 3:
            s = re.sub(re.escape(name), "<host>", s, flags=re.IGNORECASE)
    s = MAC_RE.sub("<mac>", s)
    s = BYTES_RE.sub("<bytes>", s)
    s = IPV6_CAND_RE.sub(_v6, s)
    s = IPV4_RE.sub(_v4, s)
    s = HOME_RE.sub("<home>", s)
    s = HEX_RE.sub(
        lambda m: (
            "<hex>"
            if len(m.group(0)) >= 6 or m.group(0).startswith("0x")
            else m.group(0)
        ),
        s,
    )
    s = NUM_RE.sub("<n>", s)
    s = "".join(c if c.isprintable() else "?" for c in s)
    return s[:EXCERPT_MAX] + ("..." if len(s) > EXCERPT_MAX else "")


# --- journal reading ---------------------------------------------------------------------------------------------
def journalctl_cmd():
    return shlex.split(os.environ.get("PFT_KW_JOURNALCTL", "journalctl"))


class JournalError(Exception):
    pass


class CursorUnknown(JournalError):
    pass


class BootUnknown(JournalError):
    pass


def read_journal(args, limit):
    """Run journalctl -k -o json --no-pager ARGS; yield at most `limit` raw lines, then stop the process.
    Raises CursorUnknown / BootUnknown / JournalError when journalctl fails before any output."""
    cmd = journalctl_cmd() + ["-k", "-o", "json", "--no-pager", "-q"] + args
    with tempfile.TemporaryFile() as err:
        try:
            p = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL
            )
        except OSError as e:
            raise JournalError(f"cannot run journalctl: {e}") from None
        lines = []
        stopped = False
        try:
            for raw in p.stdout:
                if len(lines) >= limit:
                    stopped = True
                    break
                lines.append(raw)
        finally:
            if stopped:
                p.kill()
            p.stdout.close()
            try:
                rc = p.wait(timeout=JOURNAL_TIMEOUT)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                raise JournalError("journalctl did not exit") from None
        err.seek(0)
        msg = err.read().decode("utf-8", "replace").strip()
    if not stopped and rc != 0:
        if "seek to cursor" in msg:
            raise CursorUnknown(msg)
        if (
            "specified boot" in msg
            or "Failed to add match" in msg
            or "boot ID" in msg.lower()
        ):
            raise BootUnknown(msg)
        raise JournalError(f"journalctl exit {rc}: {msg[:200]}")
    return lines, stopped


def parse_record(raw):
    """-> dict(cursor, msg, rt, mono, boot) or None if malformed. `cursor` may be set even when malformed."""
    try:
        d = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None, None
    if not isinstance(d, dict):
        return None, None
    cur = d.get("__CURSOR")
    cur = cur if isinstance(cur, str) and cur else None
    m = d.get("MESSAGE")
    if isinstance(m, list) and all(isinstance(b, int) and 0 <= b < 256 for b in m):
        m = bytes(m).decode("utf-8", "replace")
    rt, mono, boot = (
        d.get("__REALTIME_TIMESTAMP"),
        d.get("__MONOTONIC_TIMESTAMP"),
        d.get("_BOOT_ID"),
    )
    ok = (
        cur
        and isinstance(m, str)
        and isinstance(rt, str)
        and rt.isdigit()
        and isinstance(mono, str)
        and mono.isdigit()
        and isinstance(boot, str)
        and re.fullmatch(r"[0-9a-f]{32}", boot)
    )
    if not ok:
        return None, cur
    return {
        "cursor": cur,
        "msg": m,
        "rt": int(rt),
        "mono": int(mono),
        "boot": boot,
    }, cur


def current_boot_id():
    path = os.environ.get("PFT_KW_BOOT_ID_FILE", "/proc/sys/kernel/random/boot_id")
    with open(path) as f:
        b = f.read().strip().replace("-", "").lower()
    if not re.fullmatch(r"[0-9a-f]{32}", b):
        raise JournalError(f"bad boot id in {path}")
    return b


# --- state -------------------------------------------------------------------------------------------------------
def new_state(boot):
    return {
        "version": STATE_VERSION,
        "boot": boot,
        "cursor": None,
        "mono": 0,
        "rt": 0,
        "counters": {},
        "last": {},
        "records_total": 0,
        "malformed_total": 0,
        "cursor_resets_total": 0,
        "boot_changes_total": 0,
        "state_resets_total": 0,
        "seeded_at": 0,
    }


def load_state(path):
    """-> (state or None, problem or None). A file that exists but is not a valid state is a problem, not 'absent'."""
    try:
        with open(path) as f:
            st = json.load(f)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as e:
        return None, f"unreadable state: {e.__class__.__name__}"
    keys = new_state("0" * 32).keys()
    if (
        not isinstance(st, dict)
        or st.get("version") != STATE_VERSION
        or set(st) != set(keys)
        or not isinstance(st["boot"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", st["boot"])
        or not (st["cursor"] is None or isinstance(st["cursor"], str))
        or not isinstance(st["counters"], dict)
        or not isinstance(st["last"], dict)
        or not all(isinstance(v, int) and v >= 0 for v in st["counters"].values())
        or not all(isinstance(v, int) and v >= 0 for v in st["last"].values())
        or not all(
            isinstance(st[k], int) and st[k] >= 0
            for k in keys
            if k.endswith("_total") or k in ("mono", "rt", "seeded_at")
        )
    ):
        return None, "invalid state structure"
    return st, None


def save_state(path, st):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".state.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(st, f, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# --- collect -----------------------------------------------------------------------------------------------------
def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def textfile(host, now, up, st, cat, run):
    version, sha, entries = cat
    L = f'host="{esc(host)}"'
    out = []

    def metric(name, typ, help_, rows):
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} {typ}")
        for labels, val in rows:
            out.append(f"{name}{{{labels}}} {val}")

    metric(
        "pft_kernwatch_up",
        "gauge",
        "1 if the last kernel journal read succeeded",
        [(L, 1 if up else 0)],
    )
    metric(
        "pft_kernwatch_collect_timestamp_seconds",
        "gauge",
        "Unix time of the last collection attempt",
        [(L, now)],
    )
    metric(
        "pft_kernwatch_catalogue_info",
        "gauge",
        "Pattern catalogue in use",
        [(f'{L},version="{version}",sha256="{sha[:16]}"', 1)],
    )
    if not up or st is None:
        return "\n".join(out) + "\n"
    rows = []
    for pid, sev, cls, _ in entries:
        rows.append(
            (
                f'{L},pattern="{pid}",class="{cls}",severity="{sev}"',
                st["counters"].get(pid, 0),
            )
        )
    metric(
        "pft_kernwatch_matches_total",
        "counter",
        "Kernel log records matching each catalogue pattern",
        rows,
    )
    classes = sorted({(cls, sev) for _, sev, cls, _ in entries})
    rows = [
        (f'{L},class="{c}",severity="{s}"', st["last"].get(f"{c}/{s}", 0))
        for c, s in classes
    ]
    metric(
        "pft_kernwatch_last_match_timestamp_seconds",
        "gauge",
        "Kernel time of the newest match per class and severity (0 = none since seeding)",
        rows,
    )
    for key, help_ in (
        ("records_total", "Kernel journal records read"),
        (
            "malformed_total",
            "Records that were not valid journal JSON or lacked a required field",
        ),
        (
            "cursor_resets_total",
            "Times the saved cursor was unknown to journald (rotation) and a time guard was used",
        ),
        (
            "boot_changes_total",
            "Boot changes seen (old boot finished after its cursor, new boot read from its start)",
        ),
        (
            "state_resets_total",
            "Times an unreadable state file was replaced (counters restart)",
        ),
    ):
        metric(f"pft_kernwatch_{key}", "counter", help_, [(L, st[key])])
    metric(
        "pft_kernwatch_run_records",
        "gauge",
        "Records read by the last run",
        [(L, run["records"])],
    )
    metric(
        "pft_kernwatch_backlog",
        "gauge",
        "1 if the last run stopped at --max records (the next run continues from there)",
        [(L, 1 if run["truncated"] else 0)],
    )
    metric(
        "pft_kernwatch_seeded_timestamp_seconds",
        "gauge",
        "Unix time the cursor was first seeded",
        [(L, st["seeded_at"])],
    )
    return "\n".join(out) + "\n"


def apply_lines(lines, st, entries, boot, run, guard_mono=None):
    """Classify raw journal lines into st (in place). Records of another boot or at/below guard_mono are skipped."""
    for raw in lines:
        rec, cur = parse_record(raw)
        if rec is None:
            st["malformed_total"] += 1
            run["malformed"] += 1
            if cur:
                st["cursor"] = cur
            continue
        if rec["boot"] != boot or (
            guard_mono is not None and rec["mono"] <= guard_mono
        ):
            run["skipped"] += 1
            continue
        st["cursor"], st["mono"], st["rt"] = (
            rec["cursor"],
            rec["mono"],
            rec["rt"] // 1_000_000,
        )
        st["records_total"] += 1
        run["records"] += 1
        e = classify(entries, rec["msg"])
        if e is None:
            continue
        pid, sev, cls, _ = e
        st["counters"][pid] = st["counters"].get(pid, 0) + 1
        ts = rec["rt"] // 1_000_000
        k = f"{cls}/{sev}"
        st["last"][k] = max(st["last"].get(k, 0), ts)
        run["events"].append({"pattern": pid, "class": cls, "severity": sev, "ts": ts})


def read_boot(st, entries, boot, run, budget, from_start):
    """Read one boot after st's cursor (or from its start). Returns True if the read was truncated."""
    base = ["-b", boot]
    guard = None
    if st["cursor"] and not from_start:
        try:
            lines, stopped = read_journal(
                base + ["--after-cursor", st["cursor"]], budget
            )
        except CursorUnknown:
            # journald no longer knows the cursor (rotated/vacuumed): re-read from one second before the last
            # record and skip everything at or below its monotonic time on this boot
            st["cursor_resets_total"] += 1
            run["cursor_reset"] = True
            guard = st["mono"]
            lines, stopped = read_journal(
                base + ["--since", f"@{max(st['rt'] - 1, 0)}"], budget
            )
    else:
        lines, stopped = read_journal(base, budget)
    apply_lines(lines, st, entries, boot, run, guard)
    return stopped


def collect(a, cat):
    _, _, entries = cat
    now = int(a.now) if a.now else int(time.time())
    run = {
        "records": 0,
        "malformed": 0,
        "skipped": 0,
        "events": [],
        "truncated": False,
        "cursor_reset": False,
    }
    run.update(
        {
            "boot_change": False,
            "seeded": False,
            "old_boot_missing": False,
            "state_problem": None,
        }
    )
    try:
        boot = current_boot_id()
        st, problem = load_state(a.state)
        if st is None:
            # no state, or an unreadable one: start over (never trust a half-read file as "nothing seen yet")
            run["seeded"], run["state_problem"] = True, problem
            st = new_state(boot)
            st["seeded_at"] = now
            st["state_resets_total"] = 1 if problem else 0
            if a.from_boot_start:
                run["truncated"] = read_boot(st, entries, boot, run, a.max, True)
            else:
                lines, _ = read_journal(["-b", boot, "-n", "1"], 1)
                rec = parse_record(lines[0])[0] if lines else None
                if rec:
                    st["cursor"], st["mono"], st["rt"] = (
                        rec["cursor"],
                        rec["mono"],
                        rec["rt"] // 1_000_000,
                    )
        else:
            budget = a.max
            if st["boot"] != boot:
                try:
                    run["truncated"] = read_boot(
                        st, entries, st["boot"], run, budget, False
                    )
                except BootUnknown:
                    run["old_boot_missing"] = True
                budget -= run["records"] + run["malformed"] + run["skipped"]
                if not run["truncated"]:
                    st["boot"], st["cursor"], st["mono"], st["rt"] = boot, None, 0, 0
                    st["boot_changes_total"] += 1
                    run["boot_change"] = True
            if not run["truncated"]:
                if budget > 0:
                    run["truncated"] = read_boot(
                        st, entries, boot, run, budget, st["cursor"] is None
                    )
                else:
                    run["truncated"] = True
    except JournalError as e:
        print(f"kernwatch_parse: {e}", file=sys.stderr)
        emit(a, now, False, None, cat, run)
        return 1
    save_state(a.state, st)
    emit(a, now, True, st, cat, run)
    return 0


def emit(a, now, up, st, cat, run):
    sys.stdout.write(textfile(a.host, now, up, st, cat, run))
    if a.events_json:
        summary = {k: v for k, v in run.items() if k != "events"}
        summary["events"] = run["events"][:1000]
        with open(a.events_json, "w") as f:
            json.dump(summary, f, sort_keys=True)
            f.write("\n")


# --- report ------------------------------------------------------------------------------------------------------
def utc(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def report(a, cat):
    version, sha, entries = cat
    args = []
    if a.boot != "all":
        args += ["-b", a.boot]
    if a.since:
        args += ["--since", a.since]
    if a.until:
        args += ["--until", a.until]
    try:
        lines, stopped = read_journal(args, a.max)
    except JournalError as e:
        print(f"kernwatch_parse: {e}", file=sys.stderr)
        return 1
    names = [socket.gethostname(), socket.getfqdn()] + list(a.redact_name or [])
    per = {}
    total = malformed = 0
    first = last = None
    boots = set()
    for raw in lines:
        rec, _ = parse_record(raw)
        if rec is None:
            malformed += 1
            continue
        total += 1
        boots.add(rec["boot"])
        ts = rec["rt"] // 1_000_000
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
        e = classify(entries, rec["msg"])
        if e is None:
            continue
        pid, sev, cls, _ = e
        p = per.setdefault(
            pid,
            {
                "pattern": pid,
                "class": cls,
                "severity": sev,
                "count": 0,
                "first": ts,
                "last": ts,
            },
        )
        p["count"] += 1
        p["first"], p["last"] = min(p["first"], ts), max(p["last"], ts)
        if "excerpt" not in p:
            p["excerpt"] = redact(rec["msg"], names)
    order = {pid: i for i, (pid, *_rest) in enumerate(entries)}
    rows = sorted(
        per.values(),
        key=lambda r: (SEVERITIES.index(r["severity"]), order[r["pattern"]]),
    )
    for r in rows:
        r["first"], r["last"] = utc(r["first"]), utc(r["last"])
    sev_tot = {
        s: sum(r["count"] for r in rows if r["severity"] == s) for s in SEVERITIES
    }
    head = {
        "catalogue_version": version,
        "catalogue_sha256": sha,
        "records": total,
        "malformed": malformed,
        "truncated": stopped,
        "boots": len(boots),
        "first": utc(first) if first is not None else None,
        "last": utc(last) if last is not None else None,
        "by_severity": sev_tot,
    }
    if a.format == "json":
        json.dump({**head, "matches": rows}, sys.stdout, indent=1, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for k, v in head.items():
            print(
                f"# {k}\t{json.dumps(v, sort_keys=True) if isinstance(v, dict) else v}"
            )
        print("severity\tclass\tpattern\tcount\tfirst\tlast\texcerpt")
        for r in rows:
            print(
                "\t".join(
                    str(r[k])
                    for k in (
                        "severity",
                        "class",
                        "pattern",
                        "count",
                        "first",
                        "last",
                        "excerpt",
                    )
                )
            )
    return 2 if stopped else 0


DASH_VALUE_OPTS = ("--since", "--until", "--boot")


def join_dash_values(argv):
    """`--since -15min` is journalctl's own relative syntax, but argparse reads a value starting with "-" as an
    option and stops with "expected one argument" (kernwatch drill run 06). Rewrite it to `--since=-15min`."""
    out, i = [], 0
    while i < len(argv):
        if (
            argv[i] in DASH_VALUE_OPTS
            and i + 1 < len(argv)
            and argv[i + 1].startswith("-")
        ):
            out.append(f"{argv[i]}={argv[i + 1]}")
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="kernwatch_parse.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--catalogue", required=True)
    c.add_argument("--state", required=True)
    c.add_argument("--host", required=True)
    c.add_argument("--max", type=int, default=20000)
    c.add_argument("--from-boot-start", action="store_true")
    c.add_argument("--events-json")
    c.add_argument("--now")
    r = sub.add_parser("report")
    r.add_argument("--catalogue", required=True)
    r.add_argument("--since")
    r.add_argument("--until")
    r.add_argument("--boot", default="all")
    r.add_argument("--format", choices=("json", "tsv"), default="tsv")
    r.add_argument("--max", type=int, default=500000)
    r.add_argument("--redact-name", action="append")
    k = sub.add_parser("check-catalogue")
    k.add_argument("--catalogue", required=True)
    a = ap.parse_args(join_dash_values(sys.argv[1:] if argv is None else argv))
    try:
        cat = load_catalogue(a.catalogue)
    except (OSError, UnicodeDecodeError, CatalogueError) as e:
        print(f"kernwatch_parse: catalogue: {e}", file=sys.stderr)
        return 3
    if a.cmd == "check-catalogue":
        print(f"catalogue version {cat[0]} sha256 {cat[1]} patterns {len(cat[2])}")
        return 0
    if a.cmd == "collect":
        if not HOST_RE.match(a.host) or a.max < 1:
            print("kernwatch_parse: bad --host or --max", file=sys.stderr)
            return 3
        return collect(a, cat)
    if a.boot != "all" and not re.fullmatch(r"-?\d+|[0-9a-f]{32}", a.boot):
        print("kernwatch_parse: bad --boot", file=sys.stderr)
        return 3
    return report(a, cat)


if __name__ == "__main__":
    sys.exit(main())
