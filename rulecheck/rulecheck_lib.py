#!/usr/bin/env python3
"""pft-rulecheck helper (Python 3 stdlib only, read-only).

Finds alert/recording rules whose PromQL selectors match no series (DEAD / PARTIAL) and textfile collector
inputs that stopped being refreshed (STALE / MISSING / LEFTOVER / UNCONFIGURED), so a broken collector or a
renamed metric cannot silently switch monitoring off.

  rulecheck_lib.py check [--prom URL | --no-prom] [--textfile-dir DIR] [--conf FILE] [--host NAME]
                         [--lookback 10m] [--json] [--metrics-out FILE] [--now UNIX] [--timeout S]
  rulecheck_lib.py selectors EXPR        print the selectors found in one PromQL expression (one per line)

Exit: 0 every rule LIVE and every textfile FRESH; 1 at least one finding; 2 the check itself could not run
(Prometheus unreachable or answered an error, unreadable dir, bad config). Nothing is ever written except
--metrics-out (atomic rename in the same directory).
"""
import argparse
import fnmatch
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------- PromQL selector extraction
KEYWORDS = {"and", "or", "unless", "by", "without", "on", "ignoring", "group_left", "group_right", "bool",
            "offset", "atan2"}
LABEL_LIST_KW = {"by", "without", "on", "ignoring", "group_left", "group_right"}
AGG_OPS = {"sum", "min", "max", "avg", "group", "stddev", "stdvar", "count", "count_values", "bottomk", "topk",
           "quantile", "limitk", "limit_ratio"}
ABSENT_FUNCS = {"absent", "absent_over_time"}
NUM_WORDS = {"inf", "nan"}
# series Prometheus itself creates only while an alert is pending/firing: empty is the healthy state
SYNTHETIC = {"ALERTS", "ALERTS_FOR_STATE"}

TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>\#[^\n]*)
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`]*`)
  | (?P<num>0[xX][0-9a-fA-F]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?(?:[a-zA-Z][a-zA-Z0-9]*)*)
  | (?P<ident>[a-zA-Z_:][a-zA-Z0-9_:.]*)
  | (?P<op>=~|!~|!=|==|<=|>=|[-+*/%^<>=,(){}\[\]@:])
""", re.X)


class PromQLError(ValueError):
    pass


def tokenize(expr):
    out, pos = [], 0
    while pos < len(expr):
        m = TOKEN_RE.match(expr, pos)
        if not m:
            raise PromQLError("cannot tokenize at offset %d: %r" % (pos, expr[pos:pos + 20]))
        pos = m.end()
        kind = m.lastgroup
        if kind in ("ws", "comment"):
            continue
        out.append((kind, m.group(kind)))
    return out


def unquote(s):
    if s[0] == "`":
        return s[1:-1]
    body = s[1:-1]
    if s[0] == "'":
        body = body.replace("\\'", "'").replace('"', '\\"')
    try:
        return json.loads('"' + body + '"')
    except ValueError:
        return body


class Selector:
    __slots__ = ("name", "matchers", "absent")

    def __init__(self, name, matchers, absent):
        self.name, self.matchers, self.absent = name, matchers, absent

    def metric(self):
        if self.name:
            return self.name
        for lab, op, val in self.matchers:
            if lab == "__name__" and op == "=":
                return val
        return ""

    def text(self):
        parts = ["%s%s%s" % (lab, op, json.dumps(val)) for lab, op, val in self.matchers]
        name = self.name or ""
        if name and not re.fullmatch(r"[a-zA-Z_:][a-zA-Z0-9_:]*", name):
            parts.insert(0, json.dumps(name))
            name = ""
        return name + "{" + ",".join(parts) + "}" if parts or not name else name

    def __repr__(self):
        return ("absent:" if self.absent else "") + self.text()


def _parse_matchers(toks, i):
    """toks[i] is '{'. Returns (matchers, quoted_name, index after '}')."""
    i += 1
    matchers, qname = [], None
    while True:
        if i >= len(toks):
            raise PromQLError("unclosed {")
        kind, val = toks[i]
        if val == "}" and kind == "op":
            return matchers, qname, i + 1
        if val == "," and kind == "op":
            i += 1
            continue
        if kind in ("ident", "str"):
            lab = val if kind == "ident" else unquote(val)
            nxt = toks[i + 1] if i + 1 < len(toks) else ("op", "}")
            if kind == "str" and nxt[1] in (",", "}"):
                qname = lab          # Prometheus 3: {"metric.name", label="x"}
                i += 1
                continue
            if nxt[0] != "op" or nxt[1] not in ("=", "!=", "=~", "!~"):
                raise PromQLError("bad matcher after %r" % lab)
            if i + 2 >= len(toks) or toks[i + 2][0] != "str":
                raise PromQLError("matcher %s%s needs a string" % (lab, nxt[1]))
            matchers.append((lab, nxt[1], unquote(toks[i + 2][1])))
            i += 3
            continue
        raise PromQLError("unexpected %r in matchers" % val)


def selectors(expr):
    """All vector/range selectors of one PromQL expression, in order of appearance."""
    toks = tokenize(expr)
    out, stack = [], []          # stack of paren kinds: 'labels', 'absent', 'call'
    pending_labels = False
    prev = None
    i = 0
    while i < len(toks):
        kind, val = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else (None, None)
        in_labels = bool(stack) and stack[-1] == "labels"
        absent = "absent" in stack
        if kind == "op":
            if val == "(":
                if pending_labels:
                    stack.append("labels")
                elif prev and prev[0] == "ident" and prev[1].lower() in ABSENT_FUNCS:
                    stack.append("absent")
                else:
                    stack.append("call")
                pending_labels = False
            elif val == ")":
                if not stack:
                    raise PromQLError("unbalanced )")
                stack.pop()
            elif val == "[":
                j = i
                while j < len(toks) and toks[j][1] != "]":
                    j += 1
                if j >= len(toks):
                    raise PromQLError("unclosed [")
                i = j
            elif val == "{":
                m, qname, i2 = _parse_matchers(toks, i)
                if not in_labels:
                    out.append(Selector(qname, m, absent))
                prev = ("op", "}")
                i = i2
                continue
            prev = (kind, val)
            i += 1
            continue
        if kind != "ident" or in_labels:
            prev = (kind, val)
            i += 1
            continue
        low = val.lower()
        if low in LABEL_LIST_KW:
            pending_labels = nxt[1] == "("
        elif low in KEYWORDS:
            pass
        elif nxt[1] == "(":
            pass                                 # function or aggregation call
        elif low in AGG_OPS and nxt[0] == "ident" and nxt[1].lower() in ("by", "without"):
            pass                                 # sum by (x) (...)
        elif low in NUM_WORDS and nxt[1] != "{":
            pass
        elif prev and prev[1] == "@" and low in ("start", "end"):
            pass
        else:
            if nxt[1] == "{":
                m, qname, i2 = _parse_matchers(toks, i + 1)
                out.append(Selector(val, m, absent))
                prev = ("op", "}")
                i = i2
                continue
            out.append(Selector(val, [], absent))
        prev = (kind, val)
        i += 1
    if stack:
        raise PromQLError("unbalanced (")
    return out


# ---------------------------------------------------------------- config
def parse_duration(s):
    m = re.fullmatch(r"(\d+)([smhd]?)", s.strip())
    if not m:
        raise ValueError("bad duration %r" % s)
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


class Conf:
    def __init__(self):
        self.textfiles = []      # (glob, max_age_s, ts_metric or None)
        self.require = []        # file names that must exist
        self.ignore_rules = {}   # "group/rule" -> reason
        self.ignore_metrics = {}  # metric name -> reason (selectors expected to be empty when healthy)
        self.leftover_age = 600


def load_conf(path):
    c = Conf()
    if not path:
        return c
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
            if not line:
                continue
            f = line.split()
            try:
                if f[0] == "textfile" and len(f) in (3, 4):
                    ts = f[3] if len(f) == 4 and f[3] != "-" else None
                    c.textfiles.append((f[1], parse_duration(f[2]), ts))
                elif f[0] == "require" and len(f) == 2:
                    c.require.append(f[1])
                elif f[0] == "ignore-rule" and len(f) >= 3:
                    c.ignore_rules[f[1]] = " ".join(f[2:])
                elif f[0] == "ignore-metric" and len(f) >= 3:
                    c.ignore_metrics[f[1]] = " ".join(f[2:])
                elif f[0] == "leftover-age" and len(f) == 2:
                    c.leftover_age = parse_duration(f[1])
                else:
                    raise ValueError("unknown or malformed line")
            except (ValueError, IndexError) as e:
                raise ValueError("%s:%d: %s: %s" % (path, n, e, line)) from None
    return c


# ---------------------------------------------------------------- Prometheus
class PromError(RuntimeError):
    pass


class Prom:
    def __init__(self, url, timeout):
        self.url, self.timeout = url.rstrip("/"), timeout

    def get(self, path, params=None):
        u = self.url + path + ("?" + urllib.parse.urlencode(params) if params else "")
        try:
            with urllib.request.urlopen(u, timeout=self.timeout) as r:
                body = json.load(r)
        except urllib.error.HTTPError as e:
            try:
                body = json.load(e)
            except ValueError:
                raise PromError("%s: HTTP %d" % (path, e.code)) from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise PromError("%s: %s" % (path, e)) from None
        if not isinstance(body, dict) or body.get("status") != "success":
            raise PromError("%s: %s" % (path, (body or {}).get("error", "status not success")
                                         if isinstance(body, dict) else "bad answer"))
        return body.get("data")

    def rules(self):
        data = self.get("/api/v1/rules")
        groups = (data or {}).get("groups")
        if not isinstance(groups, list):
            raise PromError("/api/v1/rules: no groups list")
        return groups

    def count(self, sel_text, lookback):
        data = self.get("/api/v1/query", {"query": "count(last_over_time(%s[%s]))" % (sel_text, lookback)})
        if not isinstance(data, dict) or data.get("resultType") != "vector":
            raise PromError("query: unexpected result type")
        res = data.get("result") or []
        if not res:
            return 0
        try:
            return int(float(res[0]["value"][1]))
        except (KeyError, IndexError, TypeError, ValueError):
            raise PromError("query: malformed sample") from None


def check_rules(prom, conf, lookback):
    groups = prom.rules()
    cache, rows = {}, []
    for g in groups:
        gname = g.get("name", "")
        for idx, r in enumerate(g.get("rules") or []):
            name = r.get("name", "")
            key = "%s/%s" % (gname, name)
            row = {"group": gname, "rule": name, "idx": idx, "type": r.get("type", ""),
                   "file": os.path.basename(g.get("file", "")), "selectors": [], "dead": [], "note": ""}
            rows.append(row)
            if key in conf.ignore_rules:
                row.update(state="IGNORED", note=conf.ignore_rules[key])
                continue
            if r.get("health") == "err":
                row.update(state="ERROR", note=(r.get("lastError") or "evaluation error")[:200])
                continue
            try:
                sels = selectors(r.get("query", ""))
            except PromQLError as e:
                row.update(state="ERROR", note="cannot parse: %s" % e)
                continue
            counted = []
            for s in sels:
                if s.absent or s.metric() in SYNTHETIC or s.metric() in conf.ignore_metrics:
                    continue
                t = s.text()
                if t in counted:
                    continue
                counted.append(t)
            row["selectors"] = counted
            for t in counted:
                if t not in cache:
                    cache[t] = prom.count(t, lookback)
                if cache[t] == 0:
                    row["dead"].append(t)
            if not counted:
                row.update(state="LIVE", note="no selector to check (constant or absent()-only)")
            elif not row["dead"]:
                row["state"] = "LIVE"
            elif len(row["dead"]) == len(counted):
                row["state"] = "DEAD"
            else:
                row["state"] = "PARTIAL"
    return rows, len(cache)


# ---------------------------------------------------------------- textfiles
PROM_LINE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)(?:\s+\S+)?$")


def content_ts(path, metric):
    """Smallest value of METRIC in a .prom file (the stalest collector it covers), or None."""
    vals = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            m = PROM_LINE.match(line.strip())
            if m and m.group(1) == metric:
                try:
                    vals.append(float(m.group(3)))
                except ValueError:
                    pass
    return min(vals) if vals else None


def check_textfiles(tdir, conf, now):
    try:
        names = sorted(os.listdir(tdir))
    except OSError as e:
        raise PromError("textfile dir %s: %s" % (tdir, e.strerror)) from None
    rows, seen = [], set()
    for n in names:
        p = os.path.join(tdir, n)
        try:
            st = os.lstat(p)
        except OSError:
            continue                       # vanished between listdir and stat (a collector's rename)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        age = max(0, int(now - st.st_mtime))
        if not n.endswith(".prom") or n.startswith("."):
            if age > conf.leftover_age:
                rows.append({"file": n, "state": "LEFTOVER", "age": age, "max_age": conf.leftover_age,
                             "source": "mtime", "note": "temp/non-.prom file older than leftover-age"})
            continue
        seen.add(n)
        rule = next((t for t in conf.textfiles if fnmatch.fnmatchcase(n, t[0])), None)
        if rule is None:
            rows.append({"file": n, "state": "UNCONFIGURED", "age": age, "max_age": None, "source": "mtime",
                         "note": "no textfile line in the config matches"})
            continue
        glob, max_age, ts_metric = rule
        src, cage = "mtime", age
        if ts_metric:
            try:
                ts = content_ts(p, ts_metric)
            except OSError as e:
                rows.append({"file": n, "state": "STALE", "age": age, "max_age": max_age, "source": "mtime",
                             "note": "unreadable: %s" % e.strerror})
                continue
            if ts is None:
                rows.append({"file": n, "state": "STALE", "age": age, "max_age": max_age, "source": ts_metric,
                             "note": "timestamp metric missing from the file"})
                continue
            cage = max(0, int(now - ts))
            if cage > age:
                src = ts_metric        # pulled copy is fresh but its content is old: the peer collector stopped
        worst = max(age, cage)
        rows.append({"file": n, "state": "STALE" if worst > max_age else "FRESH", "age": worst,
                     "max_age": max_age, "source": src, "note": ""})
    for n in conf.require:
        if n not in seen:
            rows.append({"file": n, "state": "MISSING", "age": None, "max_age": None, "source": "-",
                         "note": "required by the config, not present"})
    return rows


# ---------------------------------------------------------------- output
BAD_RULE = ("DEAD", "PARTIAL", "ERROR")
BAD_FILE = ("STALE", "MISSING", "LEFTOVER", "UNCONFIGURED")


def esc(v):
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def metrics_text(host, up, now, dur, rules, files, nsel):
    hl = 'host="%s"' % esc(host)
    L = []

    def h(name, help_, typ="gauge"):
        L.append("# HELP %s %s" % (name, help_))
        L.append("# TYPE %s %s" % (name, typ))
    h("pft_rulecheck_up", "1 if the last check could read Prometheus (unless --no-prom) and the textfile dir")
    L.append("pft_rulecheck_up{%s} %d" % (hl, up))
    h("pft_rulecheck_last_run_timestamp_seconds", "Unix time of the last check")
    L.append("pft_rulecheck_last_run_timestamp_seconds{%s} %d" % (hl, now))
    h("pft_rulecheck_duration_seconds", "Wall time of the last check")
    L.append("pft_rulecheck_duration_seconds{%s} %.3f" % (hl, dur))
    if rules is not None:
        h("pft_rulecheck_rules", "Rules per state in the last check")
        for s in ("LIVE", "PARTIAL", "DEAD", "ERROR", "IGNORED"):
            L.append('pft_rulecheck_rules{%s,state="%s"} %d' % (hl, s, sum(1 for r in rules if r["state"] == s)))
        h("pft_rulecheck_selectors_checked", "Distinct selectors queried in the last check")
        L.append("pft_rulecheck_selectors_checked{%s} %d" % (hl, nsel))
        h("pft_rulecheck_rule_dead", "1 if the rule is DEAD, PARTIAL or ERROR (state label), 0 if LIVE/IGNORED")
        for r in rules:
            L.append('pft_rulecheck_rule_dead{%s,group="%s",rule="%s",idx="%d",state="%s"} %d'
                     % (hl, esc(r["group"]), esc(r["rule"]), r["idx"], r["state"], r["state"] in BAD_RULE))
    if files is not None:
        h("pft_rulecheck_textfiles", "Textfiles per state in the last check")
        for s in ("FRESH",) + BAD_FILE:
            L.append('pft_rulecheck_textfiles{%s,state="%s"} %d' % (hl, s, sum(1 for f in files if f["state"] == s)))
        h("pft_rulecheck_textfile_stale", "1 if the file is STALE, MISSING, LEFTOVER or UNCONFIGURED (state label)")
        for f in files:
            L.append('pft_rulecheck_textfile_stale{%s,file="%s",state="%s"} %d'
                     % (hl, esc(f["file"]), f["state"], f["state"] in BAD_FILE))
        h("pft_rulecheck_textfile_age_seconds", "Age used for the verdict (max of mtime and content timestamp)")
        for f in files:
            if f["age"] is not None:
                L.append('pft_rulecheck_textfile_age_seconds{%s,file="%s"} %d' % (hl, esc(f["file"]), f["age"]))
    return "\n".join(L) + "\n"


def write_atomic(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".rulecheck.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def fmt_age(a):
    if a is None:
        return "-"
    if a >= 86400:
        return "%dd%02dh" % (a // 86400, a % 86400 // 3600)
    if a >= 3600:
        return "%dh%02dm" % (a // 3600, a % 3600 // 60)
    if a >= 60:
        return "%dm%02ds" % (a // 60, a % 60)
    return "%ds" % a


def print_table(rules, files, err):
    if rules is not None:
        print("%-8s %-62s %s" % ("STATE", "GROUP/RULE", "LIVE/TOTAL  DETAIL"))
        for r in rules:
            n = len(r["selectors"])
            det = ", ".join(r["dead"]) if r["dead"] else r["note"]
            print("%-8s %-62s %-11s %s" % (r["state"], (r["group"] + "/" + r["rule"])[:62],
                                           "%d/%d" % (n - len(r["dead"]), n), det))
        print()
    if files is not None:
        print("%-13s %-44s %8s %8s  %s" % ("STATE", "TEXTFILE", "AGE", "MAX", "SOURCE / DETAIL"))
        for f in files:
            print("%-13s %-44s %8s %8s  %s%s" % (f["state"], f["file"][:44], fmt_age(f["age"]), fmt_age(f["max_age"]),
                                                 f["source"], (" - " + f["note"]) if f["note"] else ""))
        print()
    if err:
        print("ERROR %s" % err)


def cmd_check(a):
    t0 = time.time()
    now = int(a.now) if a.now is not None else int(t0)
    rules = files = None
    err, nsel = None, 0
    try:
        conf = load_conf(a.conf)
    except (OSError, ValueError) as e:
        print("ERROR config: %s" % e, file=sys.stderr)
        return 2
    try:
        if not a.no_prom:
            rules, nsel = check_rules(Prom(a.prom, a.timeout), conf, a.lookback)
        if a.textfile_dir:
            files = check_textfiles(a.textfile_dir, conf, now)
    except PromError as e:
        err = str(e)
    if err:
        rc = 2
    elif any(r["state"] in BAD_RULE for r in rules or []) or any(f["state"] in BAD_FILE for f in files or []):
        rc = 1
    else:
        rc = 0
    if a.json:
        summ = {}
        for r in rules or []:
            summ.setdefault("rules", {}).setdefault(r["state"], 0)
            summ["rules"][r["state"]] += 1
        for f in files or []:
            summ.setdefault("textfiles", {}).setdefault(f["state"], 0)
            summ["textfiles"][f["state"]] += 1
        json.dump({"host": a.host, "now": now, "exit": rc, "error": err, "summary": summ,
                   "rules": rules, "textfiles": files}, sys.stdout, indent=1, sort_keys=True)
        print()
    else:
        print_table(rules, files, err)
        print("RESULT %s - rules: %s | textfiles: %s -> exit %d" % (
            {0: "OK", 1: "FINDINGS", 2: "ERROR"}[rc],
            "skipped" if rules is None else " ".join("%s %d" % (s, sum(1 for r in rules if r["state"] == s))
                                                     for s in ("LIVE", "PARTIAL", "DEAD", "ERROR", "IGNORED")),
            "skipped" if files is None else " ".join("%s %d" % (s, sum(1 for f in files if f["state"] == s))
                                                     for s in ("FRESH",) + BAD_FILE), rc))
    if a.metrics_out:
        write_atomic(a.metrics_out, metrics_text(a.host, 0 if err else 1, now, time.time() - t0,
                                                 None if err else rules, None if err else files, nsel))
    return rc


def main(argv=None):
    p = argparse.ArgumentParser(prog="rulecheck_lib.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--prom", default="http://127.0.0.1:9090")
    c.add_argument("--no-prom", action="store_true")
    c.add_argument("--textfile-dir")
    c.add_argument("--conf")
    c.add_argument("--host", default="validator")
    c.add_argument("--lookback", default="10m")
    c.add_argument("--json", action="store_true")
    c.add_argument("--metrics-out")
    c.add_argument("--now", type=float)
    c.add_argument("--timeout", type=float, default=10.0)
    s = sub.add_parser("selectors")
    s.add_argument("expr")
    a = p.parse_args(argv)
    if a.cmd == "selectors":
        try:
            for sel in selectors(a.expr):
                print(repr(sel))
        except PromQLError as e:
            print("ERROR %s" % e, file=sys.stderr)
            return 2
        return 0
    if not re.fullmatch(r"\d+[smhd]", a.lookback):
        print("ERROR --lookback must look like 10m", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", a.host):
        print("ERROR bad --host", file=sys.stderr)
        return 2
    return cmd_check(a)


if __name__ == "__main__":
    sys.exit(main())
