#!/usr/bin/env python3
"""pft_seccomp.py: stdlib helper for pft-seccomp.sh (profile math only; it never touches Docker or the kernel).

Subcommands (all read files, write stdout):
  table                                           x86_64 syscall table from libseccomp.so.2 (ctypes): "NR<TAB>name"
  census   --table T [--cgroups ID,ID] FILE...    bpftrace map dumps "@[CGROUP_ID, NR]: COUNT" -> JSON {name: count}
  audit    --table T --since EPOCH [--subj LABEL] FILE...   type=SECCOMP records -> TSV action, syscall, comm, exe, count
  allowed  --docker D [--caps C,C] [--kernel X.Y]  syscalls the Docker profile D allows for these caps on amd64 (JSON)
  learnprofile --docker D --table T --census C [--caps ..]   LOG-phase profile: census ∩ Docker-allowed -> ALLOW,
                                                  the rest of the table -> ERRNO (EPERM, logged), default LOG
  generate --docker D --table T --census C [--events E] [--margin M] [--caps ..]   final profile JSON (deterministic)
  diff     (same inputs as generate)             per-syscall table vs the Docker default: kept/removed + why
  canon    PROFILE                                sha256 of the profile as Docker stores it (json.Compact of the file)
  check    PROFILE --table T                      structural checks of a profile apply/audit rely on (exit 1 + reason)

T = `pft_seccomp.py table` output (libseccomp's own x86_64 names, the names Docker/runc resolve: ausyscall says
"pread"/"pwrite" where libseccomp says pread64/pwrite64, which made the first dev learn flood the audit log). D = Docker's default.json (moby/profiles, pinned in ref/). The census keys
are cgroup ids (the throwaway's scope inode before and after its restart); --cgroups selects them.
"""

import argparse
import ctypes
import hashlib
import json
import re
import sys

ARCH = "amd64"  # Docker's arch name for x86_64 (includes/excludes "arches")
EPERM, ENOSYS = 1, 38
# Docker rules whose arguments matter for this container: keep them verbatim (argument filters), never as plain allow.
ARG_RULE_NAMES = {"socket", "personality", "clone"}


SCMP_ARCH_X86_64 = 0xC000003E


def libseccomp_table(max_nr=512):
    """nr -> name for x86_64 from the libseccomp runc uses (Ubuntu's runc links libseccomp.so.2)."""

    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_num_arch.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_num_arch.argtypes = [ctypes.c_uint32, ctypes.c_int]
    libc = ctypes.CDLL(None)
    libc.free.argtypes = [ctypes.c_void_p]
    out = {}
    for nr in range(max_nr):
        ptr = lib.seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, nr)
        if ptr:
            out[nr] = ctypes.string_at(ptr).decode()
            libc.free(ptr)
    return out


def load_table(path):
    """table file ("NR<TAB>name" lines) -> (nr->name, name->nr)."""
    by_nr = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^(\d+)\t([a-z0-9_]+)$", line.strip("\n"))
            if m:
                by_nr[int(m.group(1))] = m.group(2)
    if len(by_nr) < 300:
        raise SystemExit(
            f"pft_seccomp: syscall table {path} has {len(by_nr)} entries (want the x86_64 --dump)"
        )
    return by_nr, {v: k for k, v in by_nr.items()}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def caps_set(s):
    return {c for c in (s or "").split(",") if c}


def kver(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:2]) or (0, 0)


def rule_applies(rule, caps, kernel):
    inc, exc = rule.get("includes") or {}, rule.get("excludes") or {}
    if inc.get("arches") and ARCH not in inc["arches"]:
        return False
    if inc.get("caps") and not any(c in caps for c in inc["caps"]):
        return False
    if inc.get("minKernel") and kver(kernel) < kver(inc["minKernel"]):
        return False
    if exc.get("arches") and ARCH in exc["arches"]:
        return False
    return not (exc.get("caps") and any(c in caps for c in exc["caps"]))


def docker_rules(docker, caps, kernel):
    """The Docker default rules that apply to this container (amd64, these caps), in file order."""
    if docker.get("defaultAction") != "SCMP_ACT_ERRNO":
        raise SystemExit(
            "pft_seccomp: Docker profile defaultAction is not SCMP_ACT_ERRNO (wrong file?)"
        )
    return [r for r in docker["syscalls"] if rule_applies(r, caps, kernel)]


def docker_allowed(docker, caps, kernel):
    """name -> 'plain' | 'args' (allowed only with Docker's argument filter)."""
    out = {}
    for r in docker_rules(docker, caps, kernel):
        if r["action"] != "SCMP_ACT_ALLOW":
            continue
        for n in r["names"]:
            kind = "args" if r.get("args") else "plain"
            if out.get(n) != "plain":
                out[n] = kind
    return out


def docker_errno_rules(docker, caps, kernel):
    """Explicit non-EPERM ERRNO rules (clone3 -> ENOSYS so glibc falls back to clone): kept verbatim."""
    return [
        r for r in docker_rules(docker, caps, kernel) if r["action"] == "SCMP_ACT_ERRNO"
    ]


def parse_census(files, by_nr, cgroups):
    counts = {}
    pat = re.compile(r"^@\[(\d+), (\d+)\]: (\d+)$")
    for path in files:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = pat.match(line.strip())
                if not m:
                    continue
                cg, nr, n = int(m.group(1)), int(m.group(2)), int(m.group(3))
                if cgroups and cg not in cgroups:
                    continue
                name = by_nr.get(nr, f"nr{nr}")
                counts[name] = counts.get(name, 0) + n
    return dict(sorted(counts.items()))


ACTIONS = {
    0x7FFC0000: "log",
    0x00050000: "errno",
    0x7FF00000: "trace",
    0x7FC00000: "notify",
    0x00030000: "trap",
    0x00000000: "kill_thread",
    0x80000000: "kill_process",
}


def unhex(v):
    """audit field: "quoted" or HEX (values with spaces, e.g. thread names "db prefetch #1")."""
    if v.startswith('"'):
        return v.strip('"')
    if re.fullmatch(r"(?:[0-9A-F]{2})+", v):
        return bytes.fromhex(v).decode("utf-8", "replace")
    return v


def parse_audit(files, by_nr, since, subj):
    """type=SECCOMP records since SINCE (optionally subj=LABEL) -> {(action, name, comm, exe): count}.

    subj is the AppArmor label at the time of the call: runc's init runs "unconfined" between loading the filter
    and exec'ing the entrypoint (its openat2 calls), so learn reads every record since T0 (only a filter with
    SECCOMP_FILTER_FLAG_LOG or a LOG action writes records for errno/log actions)."""
    out = {}
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if "type=SECCOMP " not in line:
                    continue
                m = re.search(r"audit\((\d+)\.", line)
                if not m or int(m.group(1)) < since:
                    continue
                if subj and f" subj={subj} " not in line:
                    continue
                f_ = dict(re.findall(r' ([a-z]+)=("[^"]*"|\S+)', line))
                if f_.get("arch") != "c000003e":
                    name = f"arch{f_.get('arch', '?')}:{f_.get('syscall', '?')}"
                else:
                    name = by_nr.get(
                        int(f_.get("syscall", "-1")), f"nr{f_.get('syscall')}"
                    )
                # The record carries the action only (SECCOMP_RET_ACTION_FULL), never the errno value.
                code = int(f_.get("code", "0x0"), 16)
                act = ACTIONS.get(code, f"code{code:#x}")
                key = (act, name, unhex(f_.get("comm", "?")), unhex(f_.get("exe", "?")))
                out[key] = out.get(key, 0) + 1
    return out


def read_events(path):
    """events TSV from `audit` (action, name, comm, exe, count) -> {name: [actions...]}."""
    ev = {}
    if not path:
        return ev
    with open(path, encoding="utf-8") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2 and not line.startswith("#"):
                ev.setdefault(p[1], set()).add(p[0])
    return ev


def read_margin(path):
    """margin TSV: name<TAB>reason (# comments). Every entry needs a reason."""
    m = {}
    if not path:
        return m
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            s = line.rstrip("\n")
            if not s.strip() or s.startswith("#"):
                continue
            p = s.split("\t", 1)
            if len(p) != 2 or not p[1].strip() or not re.match(r"^[a-z0-9_]+$", p[0]):
                raise SystemExit(
                    f"pft_seccomp: margin line {i}: want 'name<TAB>reason'"
                )
            m[p[0]] = p[1].strip()
    return m


def plan(args):
    """Decide every syscall: the single source for generate and diff."""
    docker = load_json(args.docker)
    _, by_name = load_table(args.table)
    caps = caps_set(args.caps)
    allowed = {
        n: k
        for n, k in docker_allowed(docker, caps, args.kernel).items()
        if n in by_name
    }
    census = load_json(args.census) if args.census else {}
    events = read_events(getattr(args, "events", None))
    margin = read_margin(getattr(args, "margin", None))
    bad = sorted(n for n in margin if n not in allowed)
    if bad:
        raise SystemExit(
            f"pft_seccomp: margin names not allowed by the Docker profile (would widen it): {' '.join(bad)}"
        )
    unknown = sorted(n for n in list(census) + list(margin) if n not in by_name)
    if unknown:
        raise SystemExit(
            f"pft_seccomp: names not in the syscall table: {' '.join(unknown)}"
        )
    rows = {}
    for n in sorted(set(allowed) | set(census) | set(events) | set(margin)):
        c = census.get(n, 0)
        logged = any(a == "log" for a in events.get(n, ()))
        denied = "errno" in events.get(n, ())
        if n not in allowed:
            why = (
                "observed, denied by Docker default too: stays denied"
                if (c or logged or denied)
                else ""
            )
            rows[n] = ("deny", why, c)
        elif c:
            rows[n] = ("keep", f"census {c}", c)
        elif logged:
            rows[n] = ("keep", "SCMP_ACT_LOG record (missed by the census)", 0)
        elif n in margin:
            rows[n] = ("keep", f"margin: {margin[n]}", 0)
        else:
            rows[n] = ("remove", "never observed", 0)
    return docker, by_name, caps, allowed, rows


def build_profile(docker, caps, kernel, allowed, keep, default_action, errno_names=()):
    plain = sorted(n for n in keep if allowed.get(n) == "plain")
    rules = []
    if plain:
        rules.append({"names": plain, "action": "SCMP_ACT_ALLOW"})
    for r in docker_rules(
        docker, caps, kernel
    ):  # argument-filtered allows Docker scopes (socket, personality, clone)
        if (
            r["action"] == "SCMP_ACT_ALLOW"
            and r.get("args")
            and any(n in keep for n in r["names"])
        ):
            names = sorted(n for n in r["names"] if n in keep)
            rules.append(
                {"names": names, "action": "SCMP_ACT_ALLOW", "args": r["args"]}
            )
    for r in docker_errno_rules(docker, caps, kernel):
        rules.append(
            {
                "names": sorted(r["names"]),
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": r.get("errnoRet", EPERM),
            }
        )
    if errno_names:
        rules.append(
            {
                "names": sorted(errno_names),
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": EPERM,
            }
        )
    return {
        "defaultAction": default_action,
        "defaultErrnoRet": EPERM,
        "architectures": ["SCMP_ARCH_X86_64"],
        "flags": ["SECCOMP_FILTER_FLAG_LOG"],
        "syscalls": rules,
    }


def canon_sha(path):
    """Docker's CLI stores --security-opt seccomp=FILE as json.Compact(FILE): same key order, no whitespace."""

    with open(path, encoding="utf-8") as f:
        obj = json.load(f)
    compact = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(compact.encode()).hexdigest()


def dump(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def cmd_generate(args):
    docker, _, caps, allowed, rows = plan(args)
    keep = [n for n, r in rows.items() if r[0] == "keep"]
    sys.stdout.write(
        dump(build_profile(docker, caps, args.kernel, allowed, keep, "SCMP_ACT_ERRNO"))
    )


def cmd_diff(args):
    _, _, _, allowed, rows = plan(args)
    print("# syscall\tdocker_default\tpft_profile\twhy")
    for n, (d, why, _) in rows.items():
        dd = {"plain": "allow", "args": "allow(args)"}.get(allowed.get(n), "deny")
        pf = {"keep": dd, "remove": "deny", "deny": "deny"}[d]
        if d == "deny" and not why:
            continue
        print(f"{n}\t{dd}\t{pf}\t{why}")
    k = sum(1 for r in rows.values() if r[0] == "keep")
    rm = sum(1 for r in rows.values() if r[0] == "remove")
    print(
        f"# summary: Docker default allows {len(allowed)} x86_64 syscalls for these caps; profile keeps {k}, removes {rm}"
    )


def cmd_learnprofile(args):
    docker = load_json(args.docker)
    by_nr, _ = load_table(args.table)
    caps = caps_set(args.caps)
    allowed = docker_allowed(docker, caps, args.kernel)
    census = load_json(args.census)
    keep = [n for n in census if n in allowed]
    explicit = {
        n for r in docker_errno_rules(docker, caps, args.kernel) for n in r["names"]
    }
    errno = [n for n in by_nr.values() if n not in allowed and n not in explicit]
    sys.stdout.write(
        dump(
            build_profile(
                docker, caps, args.kernel, allowed, keep, "SCMP_ACT_LOG", errno
            )
        )
    )


def cmd_check(args):
    _, by_name = load_table(args.table)
    try:
        p = load_json(args.profile)
    except (OSError, ValueError) as e:
        print(f"not readable JSON: {e}")
        return 1
    why = []
    if (
        p.get("defaultAction") != "SCMP_ACT_ERRNO"
        or p.get("defaultErrnoRet", EPERM) != EPERM
    ):
        why.append("defaultAction must be SCMP_ACT_ERRNO with EPERM")
    if "SECCOMP_FILTER_FLAG_LOG" not in (p.get("flags") or []):
        why.append("flags must include SECCOMP_FILTER_FLAG_LOG (denials are audited)")
    names = [n for r in p.get("syscalls", []) for n in r.get("names", [])]
    bad = sorted({n for n in names if n not in by_name})
    if bad:
        why.append(f"unknown syscall names: {' '.join(bad)}")
    if any(
        r.get("action") not in ("SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO")
        for r in p.get("syscalls", [])
    ):
        why.append("only SCMP_ACT_ALLOW / SCMP_ACT_ERRNO rules expected")
    n_allow = len(
        {
            n
            for r in p.get("syscalls", [])
            if r.get("action") == "SCMP_ACT_ALLOW"
            for n in r["names"]
        }
    )
    if n_allow < 40:
        why.append(f"only {n_allow} allowed syscalls (truncated profile?)")
    if why:
        print("; ".join(why))
        return 1
    print(f"ok {n_allow} allowed syscalls")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="pft_seccomp.py")
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("table")
    c = sp.add_parser("census")
    c.add_argument("--table", required=True)
    c.add_argument("--cgroups", default="")
    c.add_argument("files", nargs="+")
    a = sp.add_parser("audit")
    a.add_argument("--table", required=True)
    a.add_argument("--since", type=int, required=True)
    a.add_argument("--subj", default="")
    a.add_argument("files", nargs="+")
    al = sp.add_parser("allowed")
    al.add_argument("--docker", required=True)
    for name in ("learnprofile", "generate", "diff"):
        g = sp.add_parser(name)
        g.add_argument("--docker", required=True)
        g.add_argument("--table", required=True)
        g.add_argument("--census", required=True)
        if name != "learnprofile":
            g.add_argument("--events", default="")
            g.add_argument("--margin", default="")
    for p in (
        al,
        sp.choices["learnprofile"],
        sp.choices["generate"],
        sp.choices["diff"],
    ):
        p.add_argument("--caps", default="CAP_SETGID,CAP_SETUID")
        p.add_argument("--kernel", default="5.15")
    cn = sp.add_parser("canon")
    cn.add_argument("profile")
    k = sp.add_parser("check")
    k.add_argument("profile")
    k.add_argument("--table", required=True)
    args = ap.parse_args()

    if args.cmd == "table":
        print("# x86_64 syscall table from libseccomp.so.2")
        for nr, name in sorted(libseccomp_table().items()):
            print(f"{nr}\t{name}")
    elif args.cmd == "census":
        by_nr, _ = load_table(args.table)
        cg = {int(x) for x in args.cgroups.split(",") if x.strip()}
        sys.stdout.write(dump(parse_census(args.files, by_nr, cg)))
    elif args.cmd == "audit":
        by_nr, _ = load_table(args.table)
        ev = parse_audit(args.files, by_nr, args.since, args.subj)
        for (act, name, comm, exe), n in sorted(ev.items()):
            print(f"{act}\t{name}\t{comm}\t{exe}\t{n}")
    elif args.cmd == "allowed":
        docker = load_json(args.docker)
        caps = caps_set(args.caps)
        sys.stdout.write(dump(docker_allowed(docker, caps, args.kernel)))
    elif args.cmd == "learnprofile":
        cmd_learnprofile(args)
    elif args.cmd == "generate":
        cmd_generate(args)
    elif args.cmd == "diff":
        cmd_diff(args)
    elif args.cmd == "canon":
        print(canon_sha(args.profile))
    elif args.cmd == "check":
        return cmd_check(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
