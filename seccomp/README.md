# pft-seccomp: a tailored seccomp allowlist for the postfiatd container

Docker starts every container under its default seccomp profile: about 360 x86_64 syscalls allowed for the
container's capabilities, everything else EPERM. postfiatd and the image's cron/logrotate tools use far fewer.
`pft-seccomp` learns which syscalls the node really makes, on **throwaway** containers only, and builds
`pft-postfiatd.json`: `defaultAction SCMP_ACT_ERRNO` (EPERM), `SECCOMP_FILTER_FLAG_LOG` (every denial leaves an
audit record), x86_64 only, and an allowlist that is always a subset of Docker's default for the same capabilities.
It sits under the confine/ runtime profile (cap_drop ALL + SETGID SETUID, read-only root, noexec tmpfs,
no-new-privileges), the apparmor/ profile and the mounts/ host options; none of them is changed.

Files: [`pft-seccomp.sh`](pft-seccomp.sh) (learn, apply/rollback, audit) · [`pft_seccomp.py`](pft_seccomp.py) (stdlib
helper: syscall table from libseccomp, Docker rule resolution, profile + diff, canonical hash) ·
[`ref/docker-default-29.1.3.json`](ref/docker-default-29.1.3.json) (Docker's default, pinned, see
[`ref/SOURCE.md`](ref/SOURCE.md)) · [`margin.tsv`](margin.tsv) (documented margin) ·
[`../alerts/seccomp.rules.yml`](../alerts/seccomp.rules.yml) + [`seccomp.tests.yml`](../alerts/seccomp.tests.yml) ·
[`tests/`](tests/) · [`systemd/`](systemd/) · [`install.sh`](install.sh).

## Status (2026-11-04T03:30Z)

| Card step | State |
|---|---|
| 1 learn (throwaway, census + SCMP_ACT_LOG) | built (65ab406); dev runs 02-03 on the validator; recorded learn on both hosts running |
| 2 profile + per-syscall diff vs Docker | built (65ab406); final profile from the recorded learn: pending (next commit) |
| 3 guarded apply / rollback | built and tested offline (stub suite); live apply not done yet |
| 4 audit, rules, promtool, tests, mutants | built; promtool SUCCESS; suite 129/129; recorded mutant run pending |
| 5 two-host live proof | not done: the validator holds the growth/ 24 h data-collection lock until 2026-11-05T00:26Z, so `apply` refuses there until then (by design); sentry canary first |

The results table required by the card is added once the live proof has run; it will cite log lines only.

## How it works

```
sudo pft-seccomp learn --out DIR [--minutes 65] [--phase census|log|both]   throwaways only
pft-seccomp generate --learn DIR > pft-postfiatd.json                        deterministic
pft-seccomp diff --learn DIR                                                 per-syscall table vs Docker's default
pft-seccomp check FILE
pft-seccomp audit [--json] [--textfile]                                       read-only
sudo pft-seccomp apply --profile-file FILE --yes                              inside a pft-maint window
sudo pft-seccomp rollback --yes                                               inside a pft-maint window
sudo pft-seccomp ack-denials --reason TEXT [--until EPOCH] --yes
sudo pft-seccomp pull            (validator: the sentry's textfile)    pft-seccomp validate FILE HOST
```

**learn.** Two throwaways built from the live container's own confine arguments (same image by ID, caps, read-only
root, tmpfs, pids/memory limits, no-new-privileges) with fresh anonymous volumes and no published ports, named
`pftsc-learn-*` and started by image ID so tools that auto-detect "the" node never pick them. Each syncs to `full`,
is exercised (RPC, cron's identity switch, cron.hourly/daily, the logrotate cron line and a forced rotation, e2scrub,
and every read-only command a host add-on runs with `docker exec`), restarted, synced again and kept for `--minutes`
so real cron ticks run.
- *census*: under Docker's default profile (what the live node runs today), a system-wide bpftrace counts
  `raw_syscalls:sys_enter` per (cgroup, syscall); only the throwaway's cgroup ids are kept. runc's own pre-filter
  stages are counted apart and left out.
- *log*: under a learn profile with `defaultAction SCMP_ACT_LOG`, census ∩ Docker-allowed as ALLOW, everything
  Docker denies as EPERM. Any syscall the census missed leaves a `type=1326` audit record. A watchdog removes the
  throwaway if more than `LOG_MAX` (2000) records arrive: dev learn 1 found that `ausyscall` names syscall 17/18
  `pread`/`pwrite` while libseccomp says `pread64`/`pwrite64`, so the hottest syscalls were missing and the audit log
  rotated three times in two minutes. The table now comes from libseccomp itself.

**generate / diff.** ALLOW = (census ∪ log-phase LOG records ∪ margin) ∩ Docker-allowed for the container's caps.
Docker's argument-filtered rules (socket, personality, clone) and its `clone3 → ENOSYS` rule are kept verbatim.
`margin.tsv` lists the syscalls on rare or error paths a learn run may not see (signal return, abort/raise, fsync on
rotation...), each with its reason; a margin name Docker does not allow is refused, so the profile can only narrow
Docker's. `diff` prints every syscall as kept/removed with the reason (census count, LOG record, margin, never
observed).

**audit** (hourly timer, textfile `pft_seccomp_*{host=...}`; the sentry's copy is pulled to the validator):

| Check | PASS when |
|---|---|
| kernel / logging | seccomp filter support; `kernel.seccomp.actions_logged` includes `errno` |
| profile | `/etc/pft-seccomp/pft-postfiatd.json` exists and passes `check` |
| container | the profile Docker stored at create time (`HostConfig.SecurityOpt`, `json.Compact` of the file) has the same canonical sha256 as the file. FAIL: Docker's default, `unconfined`, or a different profile (drift: file changed after create) |
| filter | the container's init shows `Seccomp: 2` in `/proc/<pid>/status` |
| recreate | compose: a listed compose file sets `seccomp=/etc/pft-seccomp/pft-postfiatd.json`; docker run: the container was created with it |
| confine:cap_drop / confine:nnp | cap_drop ALL, no-new-privileges still set |
| denials | 0 `type=SECCOMP` records with action errno whose `subj` is the container's AppArmor label in the last 24 h (minus an `ack-denials` range) |

Denials are attributed by the AppArmor label (`subj=pft-postfiatd`): learn throwaways run under `docker-default`, so
their records are never counted; `apply` refuses a container without its own label.

## Alerts

`PFTSeccompDrift`: any non-denial check FAIL for 30 min (longer than an apply/rollback window).
`PFTSeccompDenied`: `pft_seccomp_denied_events > 0` on one sample (the audit already counts a 24 h window). Clear it
with `ack-denials` after investigating, or widen `margin.tsv` and re-apply. A stopped audit is caught by pft-rulecheck
(`textfile pft_seccomp_*.prom 3h`). The rules are listed in `../alerts/prometheus.yml` only when the collector is
installed (a rule without series is graded dead by pft-rulecheck).

## apply / rollback

`apply` refuses (exit 4, nothing changed) without `--yes`, outside an active pft-maint window holding
2×`HEALTH_BUDGET`+`MAINT_MARGIN` s, while a data-collection lock is held, when the node is not `full`, not confined,
has no AppArmor label, when the candidate fails `check` or is already applied, or when the last apply is still in
place. Then it installs the file to `/etc/pft-seccomp/` (the previous one backed up) and re-creates the container with
`seccomp=/etc/pft-seccomp/pft-postfiatd.json`: compose = `docker-compose.seccomp.yml` appended to `COMPOSE_FILE` in
`.env` (both backed up); docker run = the old container stopped, renamed `NAME-presc-<id>`, kept with restart=no, and
a new one run from the old one's own arguments. The gate polls until the container is new, its stored profile equals
the file, init is in filter mode, the node is `full` with peers, the confine signature (everything but the seccomp
option, including the AppArmor label) is unchanged and every running pft-* service is still active; then it runs the
live exercise and requires 0 denials since T0. Any failure, failed step or SIGINT/SIGTERM rolls back automatically.
`rollback` restores the previous profile file first (a compose re-create reads it), then `.env` and any previous
override (or removes ours), or the kept container, and runs the same gate for the previous seccomp state (exit 5 if
that gate fails). pft-integrity's baseline is accepted only if every changed item is the container or its compose
files.

## Tests

`tests/run-tests.sh`: 129 offline checks against a fake host (`PFT_SC_ROOT`) and a stateful docker stub
(`tests/stub_docker.py`: `docker run` builds the container from its arguments; `seccomp=FILE` is stored as
`json.Compact`, as Docker does): every audit check in both directions, `--json`/`--textfile`/`validate`, `ack-denials`,
`pull`, apply/rollback for compose and docker run, every refusal (nothing changed), every automatic rollback trigger,
integrity acceptance, and the helper's unit tests (`tests/test_pft_seccomp.py`, hand-computed fixtures).
`tests/mutate.py`: 54 mutants of the gates and rollback paths, each suite in its own process group, SIGKILLed on
timeout, with an orphan check at the end. Temp files go under `TEST_TMPDIR` (default `~/.cache`): `/tmp` is noexec on
the hardened hosts.
