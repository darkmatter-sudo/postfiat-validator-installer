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

## Status (2026-11-04T04:00Z)

| Card step | State |
|---|---|
| 1 learn (throwaway, census + SCMP_ACT_LOG) | done: recorded learn on both hosts ([05](logs/05-learn-validator.log), [06](logs/06-learn-sentry.log)) |
| 2 profile + per-syscall diff vs Docker | done: [`profile/pft-postfiatd.json`](profile/pft-postfiatd.json) + [`profile/diff.tsv`](profile/diff.tsv) from [08](logs/08-generate-two-host.log) |
| 3 guarded apply / rollback | built and tested offline (stub suite); live apply not done yet |
| 4 audit, rules, promtool, tests, mutants | built; promtool SUCCESS; suite 136/136; recorded mutant run in progress (log 04, next commit) |
| 5 two-host live proof | not done: the validator holds the growth/ 24 h data-collection lock until 2026-11-05T00:26Z, so `apply` refuses there until then (by design); sentry canary first |

The results table required by the card is added once the live proof has run; it will cite log lines only.

## Learn result (2026-11-04, both hosts)

| | validator ([05](logs/05-learn-validator.log)) | sentry ([06](logs/06-learn-sentry.log)) |
|---|---|---|
| auto-detection still picks the live node, not the throwaway | l.20, l.289 | l.20, l.285 |
| throwaway full, then full again after its restart (both phases) | l.21, l.91; l.290, l.360 | l.21, l.91; l.286, l.356 |
| census (Docker default profile, 65 min): distinct syscalls / calls | 120 / 9 231 715 (l.164) | 116 / 12 762 662 (l.164) |
| log phase (SCMP_ACT_LOG, 65 min): records / distinct | 254 / 4 (l.431-435) | 509 / 8 (l.427-435) |
| audit records lost before / after; leftover throwaways | 0 / 0; 0 (l.9, l.438-439) | 0 / 0; 0 (l.9, l.438-439) |

The log phase is the safety net for the census: on the sentry the census missed cron's identity switch
(`setuid setgid getpriority setpriority`, a :17 cron tick fell into the log phase only) and the LOG records caught
it; on the validator the census had them. `openat2` (runc after the filter is loaded) and `sched_yield` appear only
as LOG records on both; `clone3` is EPERM-logged by Docker's own ENOSYS rule (glibc falls back to `clone`).

**Bug found in the recorded run, fixed:** the offline tail of `drill/learn-run.sh` wrote `x bash ... generate >
profile.json`, so the logging wrapper's `$ ...` and `(exit 0)` lines went into the JSON: `check` failed (05/06
l.442-461) but the script still printed `RESULT: PASS` (l.592). Fixed in 850bfb0 (direct writes, RESULT gated on
generate/check/diff). The learn data itself was unaffected; the profile is built from it offline:
[`drill/generate-run.sh`](drill/generate-run.sh), log [08](logs/08-generate-two-host.log): validator-only,
sentry-only and merged profiles are byte-identical (l.20), `check` ok, 129 allowed syscalls (l.22); Docker's default
allows 294 for these caps, the profile keeps 129 and removes 165 (l.324). File sha256 `8568e172…2457`, canonical
(Docker-stored) sha256 `f533d504…` (l.19). Log [07](logs/07-generate-two-host-superseded.log) is the same build
before 5 margin entries were added (124 syscalls): `clock_gettime gettimeofday time clock_getres` (vDSO calls a learn
never sees; real syscalls if the kernel falls back from kvm-clock to hpet/acpi_pm, both available on these hosts) and
`kill` (`timeout 5 bash -c` in an add-on probe signals its child only on a hang).

Dev logs: [01 bpftrace install](logs/01-bpftrace-install.log) · [02 dev learn 1](logs/02-dev-learn-validator-flood.log)
(ausyscall's `pread`/`pwrite` names missed `pread64`/`pwrite64`: ~80k LOG records in 2 min, guard stopped it; table now
from libseccomp) · [03 dev learn 2](logs/03-dev-learn-validator.log) (256 records).

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

`tests/run-tests.sh`: 136 offline checks against a fake host (`PFT_SC_ROOT`) and a stateful docker stub
(`tests/stub_docker.py`: `docker run` builds the container from its arguments; `seccomp=FILE` is stored as
`json.Compact`, as Docker does): every audit check in both directions, `--json`/`--textfile`/`validate`, `ack-denials`,
`pull`, apply/rollback for compose and docker run, every refusal (nothing changed), every automatic rollback trigger,
integrity acceptance, generate/diff over two learn dirs, and the helper's unit tests (`tests/test_pft_seccomp.py`, hand-computed fixtures).
`tests/mutate.py`: 54 mutants of the gates and rollback paths, each suite in its own process group, SIGKILLed on
timeout, with an orphan check at the end. Temp files go under `TEST_TMPDIR` (default `~/.cache`): `/tmp` is noexec on
the hardened hosts.
