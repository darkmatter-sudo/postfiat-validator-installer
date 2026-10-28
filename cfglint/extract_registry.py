#!/usr/bin/env python3
"""Build the cfglint registry: every postfiatd.cfg section and key the daemon reads, with file:line provenance.

Usage: extract_registry.py <postfiatd-source-dir> > registry.json
The source dir must be a git checkout; its HEAD commit is recorded and must match the running build
(`postfiatd --version` -> "Git commit hash"). Stdlib only, read-only.

Method (regex scan of non-test C++ under src/xrpld and src/libxrpl):
  * section sites: section(X), config[X], exists(SECTION_*), getSingleSection(.., X), getIniFileSection(.., X),
    ConfigSection::nodeDatabase()/importNodeDatabase(); X is a literal or a SECTION_* macro from ConfigSections.h.
  * key sites: set(v, "k", s), get(s, "k"), get<T>(s, "k"), get_if_exists(s, "k", v), s.get("k"), s.exists("k"),
    s.value_or("k", d), populate(s, "k", ...).
  * a key site belongs to the section bound in the same file (FILE_SECTION below, for functions that receive
    the Section as a parameter) or else to the nearest preceding section site in the same file within 60 lines.
    Key sites that read something other than the config (JSON, HTTP headers) are listed in NOT_CONFIG.
  * any key site that cannot be attributed makes the script exit 1 (nothing is silently dropped).
  * a section is "values" (one value per line, no keys), "keys", or "mixed" (keys and .values()/.lines() on the
    section expression or on the variable it is bound to within the window).
  * documented keys: `#   key = ...` lines under `# [section]` in cfg/postfiatd-example.cfg; those the daemon never
    reads are listed as documented_unread (e.g. [vl] enable).
"""

import bisect
import json
import os
import re
import subprocess
import sys

# Files whose key reads take the Section as a function parameter: the caller decides which section it is.
# Each entry names the caller that passes the section (verified by hand at the pinned commit).
FILE_SECTION = {
    "src/libxrpl/server/Port.cpp": (
        "<port>",
        "parse_Port(): called per name in [server] (ServerHandler.cpp setup_ServerHandler)",
    ),
    "src/xrpld/nodestore/backend/RocksDBFactory.cpp": ("node_db", "backend created from ConfigSection::nodeDatabase()"),
    "src/xrpld/nodestore/backend/NuDBFactory.cpp": ("node_db", "backend created from ConfigSection::nodeDatabase()"),
    "src/xrpld/nodestore/backend/MemoryFactory.cpp": ("node_db", "backend created from ConfigSection::nodeDatabase()"),
    "src/xrpld/nodestore/detail/ManagerImp.cpp": ("node_db", "make_Backend(parameters) with the node_db section"),
    "src/xrpld/nodestore/detail/Database.cpp": ("node_db", "Database(config) with the node_db section"),
    "src/xrpld/nodestore/detail/DatabaseNodeImp.h": ("node_db", "DatabaseNodeImp(config) with the node_db section"),
    "src/xrpld/app/misc/SHAMapStoreImp.cpp": ("node_db", "SHAMapStoreImp reads ConfigSection::nodeDatabase()"),
    "src/xrpld/app/main/CollectorManager.cpp": ("insight", "make_CollectorManager(config_->section(SECTION_INSIGHT))"),
    "src/xrpld/perflog/detail/PerfLogImp.cpp": ("perf", 'setup_PerfLog(config_->section("perf"))'),
    "src/xrpld/core/detail/SociDB.cpp": ("sqdb", 'config.section("sqdb")'),
}
# Line-range overrides inside files that read several sections (file, first, last, section, why).
RANGE_SECTION = [
    ("src/xrpld/core/detail/Config.cpp", 1225, 1260, "voting", 'setup_FeeVote(section("voting"))'),
    ("src/xrpld/core/detail/Config.cpp", 436, 445, "<port>", "port names listed in [server]"),
    ("src/xrpld/app/main/Application.cpp", 2260, 2290, "<port>", "port names listed in [server]"),
    ("src/xrpld/core/detail/DatabaseCon.cpp", 100, 270, "sqlite", 'c.section("sqlite")'),
]
NOT_CONFIG = [
    ("src/xrpld/app/misc/detail/Manifest.cpp", "JSON validator token fields"),
    ("src/xrpld/rpc/handlers/ServerInfo.cpp", "string search"),
    ("src/xrpld/overlay/detail/OverlayImpl.h", "HTTP Upgrade header lookup"),
    ("src/xrpld/rpc/detail/ServerHandler.cpp", 'HTTP header lookup (config.exists("server") is a section site)'),
]
NEAREST_WINDOW = 60

LIT = r'(?:"([a-z_][a-z_0-9]*)"|(SECTION_[A-Z_]+))'
SECTION_RES = [
    re.compile(r"\bsection\s*\(\s*" + LIT + r"\s*\)"),
    re.compile(r"\b(?:config|config_|c|conf)\s*(?:\(\))?\s*(?:->|\.)?\s*\[\s*" + LIT + r"\s*\]"),
    re.compile(
        r"\b(?:config|c|config_\(\)|app_\.config\(\)|app\.config\(\)|config\(\))\s*(?:->|\.)\s*exists\s*\(\s*"
        + LIT
        + r"\s*\)"
    ),
    re.compile(r"(?<![.>\w])exists\s*\(\s*()(SECTION_[A-Z_]+)\s*\)"),
    re.compile(r"\bget(?:Single|IniFile)Section\s*\(\s*\w+\s*,\s*" + LIT),
]
KEYQ = r'"([a-z_][a-z_0-9]*)"'
KEY_RES = [
    re.compile(r"\bset\s*\(\s*[\w.\->\[\]]+\s*,\s*(?:[\w.:]+\s*,\s*)?" + KEYQ),
    re.compile(r"\bget(?:_if_exists|_or_throw)?\s*(?:<[^<>;]+>)?\s*\(\s*[\w.\->]+\s*,\s*" + KEYQ),
    re.compile(r"\.\s*(?:get|exists|value_or)\s*(?:<[^<>;]+>)?\s*\(\s*" + KEYQ),
    re.compile(r"\bpopulate\s*\(\s*\w+\s*,\s*" + KEYQ),
]
BIND_RE = re.compile(r"(\w+)\s*(?:=|\{)\s*[\w:>.()\-]*$")
VALUES_RE = re.compile(r"\.\s*(?:values|lines)\s*\(\s*\)")
NAMED_SECTIONS = {"nodeDatabase": "node_db", "importNodeDatabase": "import_db"}


def sh(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def strip_comment(line):
    i = line.find("//")
    return line if i < 0 else line[:i]


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    src = sys.argv[1]
    commit = sh(src, "git", "rev-parse", "HEAD")
    macros = {}
    hdr = os.path.join(src, "src/xrpld/core/ConfigSections.h")
    for n, line in enumerate(open(hdr), 1):
        m = re.match(r'#define (SECTION_[A-Z_]+) "([a-z_]+)"', line)
        if m:
            macros[m.group(1)] = (m.group(2), "src/xrpld/core/ConfigSections.h:%d" % n)
    files = []
    for top in ("src/xrpld", "src/libxrpl"):
        for root, dirs, names in os.walk(os.path.join(src, top)):
            dirs[:] = sorted(d for d in dirs if d != "test")
            files += [os.path.join(root, f) for f in sorted(names) if f.endswith((".cpp", ".h"))]

    sections = {}
    keys_unattributed = []

    def sec(name):
        return sections.setdefault(name, {"kind": None, "sites": [], "keys": {}, "values_read": False})

    for path in sorted(files):
        rel = os.path.relpath(path, src)
        text = open(path, encoding="utf-8", errors="replace").read().splitlines()
        site_lines = []  # (line, section)
        for n, raw in enumerate(text, 1):
            line = strip_comment(raw)
            for i, rx in enumerate(SECTION_RES):
                if i == 2 and rel in FILE_SECTION:
                    continue  # there `config` is a Section and .exists("k") tests a key
                for m in rx.finditer(line):
                    lit, mac = m.group(1), m.group(2)
                    name = lit or (macros[mac][0] if mac in macros else None)
                    if not name:
                        continue
                    sec(name)["sites"].append("%s:%d" % (rel, n))
                    site_lines.append((n, name))
                    if VALUES_RE.search(line[m.end() :]):
                        sec(name)["values_read"] = True
                    # `auto const& v = config.section("x");` then `v.values()` / `v.lines()` within the window
                    b = BIND_RE.search(line[: m.start()])
                    if b:
                        use = re.compile(r"\b" + re.escape(b.group(1)) + r"\s*\.\s*(?:values|lines)\s*\(\s*\)")
                        bind = re.compile(r"\b" + re.escape(b.group(1)) + r"\s*(?:=|\{)")
                        for k, x in enumerate(text[n - 1 : n - 1 + NEAREST_WINDOW]):
                            x = strip_comment(x)
                            if k > 0 and bind.search(x):
                                break  # the name is rebound (e.g. the next `section = config.section(...)`)
                            if use.search(x):
                                sec(name)["values_read"] = True
                                break
            for fn, name in NAMED_SECTIONS.items():
                if re.search(r"ConfigSection::" + fn + r"\s*\(\s*\)", line) and "return" not in line:
                    sec(name)["sites"].append("%s:%d" % (rel, n))
                    site_lines.append((n, name))
        # key calls may span lines: scan the comment-stripped file as one string, map offsets to lines
        body = "\n".join(strip_comment(raw) for raw in text)
        starts = [0]
        for ln in body.split("\n"):
            starts.append(starts[-1] + len(ln) + 1)
        for rx in KEY_RES:
            for m in rx.finditer(body):
                key = m.group(1)
                n = bisect.bisect_right(starts, m.start(1))
                if any(rel == f for f, _ in NOT_CONFIG):
                    continue
                target = None
                for f, a, b, s, _ in RANGE_SECTION:
                    if rel == f and a <= n <= b:
                        target = s
                if target is None and rel in FILE_SECTION:
                    target = FILE_SECTION[rel][0]
                if target is None:
                    prev = [s for ln, s in site_lines if n - NEAREST_WINDOW <= ln <= n]
                    target = prev[-1] if prev else None
                if target is None:
                    keys_unattributed.append("%s:%d %s" % (rel, n, key))
                    continue
                if key == target and rx is KEY_RES[2] and ".exists" in m.group(0).replace(" ", ""):
                    continue  # config.exists("server") style section test, already a section site
                sec(target)["keys"].setdefault(key, [])
                site = "%s:%d" % (rel, n)
                if site not in sec(target)["keys"][key]:
                    sec(target)["keys"][key].append(site)

    if keys_unattributed:
        print("unattributed key sites (fix FILE_SECTION/RANGE_SECTION):", file=sys.stderr)
        for k in keys_unattributed:
            print("  " + k, file=sys.stderr)
        return 1
    # every SECTION_* macro is a section the daemon knows, even when only used through a helper
    for mac, (name, site) in macros.items():
        s = sec(name)
        if site not in s["sites"]:
            s["sites"].insert(0, site)
    for name, s in sections.items():
        if s["keys"] and s["values_read"]:
            s["kind"] = "mixed"
        elif s["keys"]:
            s["kind"] = "keys"
        else:
            s["kind"] = "values"
        del s["values_read"]
        s["sites"] = sorted(set(s["sites"]))
    port = sections.pop("<port>", {"kind": "keys", "sites": [], "keys": {}})
    port["kind"] = "keys"
    port["note"] = FILE_SECTION["src/libxrpl/server/Port.cpp"][1]

    documented = {}
    ex = os.path.join(src, "cfg/postfiatd-example.cfg")
    cur = None
    for n, line in enumerate(open(ex), 1):
        h = re.match(r"^#\s?\[([a-z_]+)\](?:\s+[A-Z][A-Z ]*)?\s*$", line)
        if h:
            cur = h.group(1)
            continue
        k = re.match(r"^#\s{1,4}([a-z][a-z_0-9]*)\s*=", line)
        if k and cur:
            documented.setdefault(cur, {}).setdefault(k.group(1), "cfg/postfiatd-example.cfg:%d" % n)
    unread = []
    for s, ks in sorted(documented.items()):
        known = set(sections.get(s, {}).get("keys", {}))
        if s == "server" or s.startswith("port"):
            known |= set(port["keys"])
        for k, site in sorted(ks.items()):
            if s in sections and sections[s]["kind"] != "values" and k not in known:
                unread.append({"section": s, "key": k, "documented_at": site})

    out = {
        "schema": "pft-cfglint-registry/1",
        "source": {
            "repo": "https://github.com/postfiatorg/postfiatd",
            "commit": commit,
            "generator": "cfglint/extract_registry.py",
        },
        "parser": {
            "site": "src/libxrpl/basics/BasicConfig.cpp:50-105",
            "key_regex": r"^\s*([a-zA-Z][_a-zA-Z0-9]*)\s*=\s*(.*\S+)\s*$",
            "duplicate_key": "last wins (Section::set insert_or_assign, BasicConfig.cpp:43)",
            "duplicate_section": "lines appended to the first (parseIniFile, Config.cpp:195 emplace keeps it, :201 appends)",
            "empty_value": "`key=` does not match key_regex: stored as a plain value, key unset",
        },
        "sections": {k: sections[k] for k in sorted(sections)},
        "port_section": port,
        "documented_unread": unread,
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=False)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
