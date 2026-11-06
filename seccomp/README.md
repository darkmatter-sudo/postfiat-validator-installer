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

## Status (2026-11-05T11:55Z)

| Card step | State |
|---|---|
| 1 learn (throwaway, census + SCMP_ACT_LOG) | done: recorded learn on both hosts ([05](logs/05-learn-validator.log), [06](logs/06-learn-sentry.log)) |
| 2 profile + per-syscall diff vs Docker | done: [`profile/pft-postfiatd.json`](profile/pft-postfiatd.json) + [`profile/diff.tsv`](profile/diff.tsv) from [08](logs/08-generate-two-host.log) |
| 3 guarded apply / rollback | done: live on both hosts in [19](logs/19-live-run-pass.log) (sentry canary, then validator, inside one pft-maint window; see [Results](#results-live-run-19-2026-11-05-pass)). Built and tested offline first (stub suite). Found before any live apply (2026-11-04): a re-create would have dropped both nodes' `CpuShares`/`MemoryReservation` (set by `docker update`, not in compose/run args) and the gate did not compare them; fixed: kept through every re-create and part of the gate signature (see apply / rollback), offline tests + mutants M55-M60 |
| 4 audit, rules, promtool, tests, mutants | done offline: recorded [10](logs/10-lint-suite-mutants.log) at 80d944a (git archive, script sha256 in l.3-11): shellcheck/ruff/ruff format/promtool clean (l.12-35), suite 147 passed, 0 failed (l.185), mutants 59 caught, 0 survived, 0 not applied, 0 broken of 59 + M54 documented equivalent, 0 orphans (l.249-250). Replaces [04](logs/04-lint-suite-mutants.log) (its 54 CAUGHT lines all read `[0 failing: ]`: the mutant copies lacked `pft_seccomp.py`, so no check ever ran; harness fixed, see Tests) and [09](logs/09-lint-suite-mutants-superseded.log) (56 caught / 4 survived at fffc1d6: M16, M19, M37 got tests in 80d944a, M54 is equivalent because no caller reads `lx`'s status) |
| 5 two-host live proof | **done: live run [19](logs/19-live-run-pass.log) (2026-11-05T10:12-11:52Z, run commit 7ef49b4) PASS, 0 checks failed**, see [Results](#results-live-run-19-2026-11-05-pass). Earlier runs that stopped at the canary (kept as evidence): first live run [11](logs/11-live-run-stopped-at-canary.log) (2026-11-05T01:14Z, run commit 72b614f) stopped at the sentry canary, by design: the apply gate counted 2 `clone3` records as denials and rolled the sentry back automatically; the validator was never changed. Found → fixed → verified offline, see [Live run 11](#live-run-11-2026-11-05-stopped-at-the-sentry-canary). Second live run [16](logs/16-live-run-stopped-at-canary-drill-counter.log) (2026-11-05T09:10Z, run commit 5e62fb3) passed the gate this time but stopped at the canary on the drill script's own denial counter, see [Live run 16](#live-run-16-2026-11-05-stopped-at-the-sentry-canary-drill-counter) | |

## Fix (2026-11-06): `pselect6` for the container's cron.daily

Found: at the first cron.daily after the live apply (2026-11-06T06:25Z) both nodes' audits graded 1 denial,
`pselect6 (run-parts)`, and PFTSeccompDenied fired. The image's crontab runs `run-parts --report /etc/cron.daily`
(logrotate, dpkg, apt-compat), which waits on job output with `select()` (glibc: `pselect6`). Neither learn ran
cron.daily, so the profile did not allow it. A throwaway probe ([20](logs/20-pselect6-probe.log)) shows the effect:
under the live profile `run-parts --report` exits 1 with `select: Operation not permitted` and runs no job (l.4-6),
so the daily jobs stopped running after the apply; with `pselect6` added the job runs, exit 0 (l.7-10). (The echoed
`docker run` lines in that log shorten the scratch paths of `old.json`/`new.json`/`jobs` and omit `--name pft-scprobe-*`.)

Fixed: `pselect6` added to [`margin.tsv`](margin.tsv) with its reason (Docker's default allows it); profile rebuilt
with `drill/generate-run.sh`: 130 allowed, canonical sha256 `b636b6b802555fa30c31d20e194aecb22969cd6fecb73d8dda51e20a0f1e7524`
(= the probe's `new.json`). New test `TestShippedProfile` asserts the shipped profile allows `pselect6` and that the
margin gives a reason; suite 188 passed, 0 failed, and the same test FAILs on the pre-fix profile
([22](logs/22-pselect6-lint-suite-control.log) l.7-14, l.15-23). The investigated denial was acknowledged on both
hosts ([21](logs/21-pselect6-ack.log)). Re-applied on both hosts with `drill/live-run.sh`: live run [23](logs/23-live-run-pass.log) PASS, see below.

## Results: live run 23 (2026-11-06): PASS (re-apply with `pselect6`)

Every row cites a line of [`logs/23-live-run-pass.log`](logs/23-live-run-pass.log) (run commit
`e2a3a59c3df8a77577e2c05a30f1df792c8490d0`, clean tree, l.2). The log is the run's own output, already redacted by
the run; nothing was changed when publishing it. Same drill as run 19, so the rows are the same checks.

| Check | Result | log 23 |
|---|---|---|
| earlier apply rolled back first | rollback PASS on sentry and validator (the run starts from Docker's default) | l.74, l.89 |
| profile sha256: repo = both hosts | file `44958496…4b09`, canonical `b636b6b8…7524` (the profile with `pselect6`) | l.10, l.152, l.158 |
| apply gate (sentry, validator) | `seccomp denials since T0: 0`, clone3 shown as by-design ENOSYS | l.270, l.698 |
| SecurityOpt after apply | `seccomp=<inline profile, sha256 b636b6b8…7524>` on both | l.275, l.703 |
| negative controls (EPERM + record) | symlinkat, linkat, inotify_init on both hosts | l.325-337, l.753-765 |
| alert drill FIRING → RESOLVED (throwaway topic) | sentry and validator | l.393-395, l.593-595, l.817-818, l.937-939 |
| host runs | sentry pre 23/0, post 21/0; validator pre 20/0, post 19/0 (PASS/FAIL) | l.378, l.581, l.806, l.929 |
| 60-min hold | 13 polls 08:53:31Z-09:54:23Z, both full, 11 peers, container PASS, denied=0 | l.941-956 |
| metrics, alerts, fleet, rules, integrity | findings 0 on both, no PFTSeccomp* alert, fleet skew 0 (seccomp CURRENT on both), rulecheck OK, integrity PASS after accept | l.973, l.977, l.1082-1095 |
| zero operator-topic messages, end state | env files restored byte-identical, 0 messages on both operator topics, integrity PASS, both nodes full; `0 check(s) failed -> PASS` | l.1110, l.1123-1132 |

Limit: the run's positive controls run `/etc/cron.hourly`, not cron.daily. The `pselect6` fix itself is shown by
probe [20](logs/20-pselect6-probe.log); the first real cron.daily under this profile is 2026-11-07T06:25Z and is
checked after it runs.

## Results: live run 19 (2026-11-05): PASS

Every row cites a line of [`logs/19-live-run-pass.log`](logs/19-live-run-pass.log) (run commit
`7ef49b47995e8612122f2aabce26b9fd44f5c400`, clean tree, l.2). The log is the run's own output, already redacted by the
run (l.27-47: redaction control 18/18). One change was made when publishing it: `docker compose` printed two warning
lines with a local-time timestamp (l.620-621), and that timestamp is replaced by `<redacted-local-time>`. Nothing else
differs from the raw run log.

| Card requirement | Result | log 19 |
|---|---|---|
| script hashes match the log header | header sha256 of live-run.sh, host-run.sh, denied-lib.sh, stop-lib.sh, pft-seccomp.sh, pft_seccomp.py, install.sh, the profile, seccomp.rules.yml and redact.py = `git show 7ef49b4:<file> \| sha256sum` | l.3-12 |
| profile sha256: repo = both hosts | file sha256 `8568e172…2457` in the repo and on both hosts; canonical sha256 `f533d504…4398` | l.16-18, l.134-138 |
| `docker inspect` SecurityOpt before (sentry / validator) | `["no-new-privileges", "apparmor=pft-postfiatd"]` / `["no-new-privileges:true", "apparmor=pft-postfiatd"]` (Docker's default seccomp) | l.162, l.605 |
| SecurityOpt after apply (sentry / validator) | `... "seccomp=<inline profile, sha256 f533d504…4398>"` on both | l.261, l.689 |
| installed profile = repo profile | byte-identical, stored canonical sha256 = profile, init `Seccomp 2` | l.266-267, l.694-695 |
| apply gate: 0 denials during the exercise | `seccomp denials since T0: 0` (clone3 → ENOSYS shown as a by-design answer, not a denial) | l.256, l.684 |
| every negative control returns EPERM + a SECCOMP record (sentry) | symlink (symlinkat), hard link (linkat), inotify (inotify_init) | l.311, l.317, l.323 |
| every negative control returns EPERM + a SECCOMP record (validator) | the same three | l.739, l.745, l.751 |
| forced rollback with prior-profile restoration | injected gate failure → apply exit 1, automatic rollback → Docker's default, profile file removed, node full | l.171-190 |
| explicit rollback, then re-apply | rollback PASS (SecurityOpt back to the prior value), audit shows the finding again, re-apply PASS | l.467-468, l.475, l.543 |
| alert drill FIRING → RESOLVED (throwaway topic) | PFTSeccompDenied sentry FIRING / RESOLVED; validator FIRING / RESOLVED | l.380, l.581, l.804, l.925 |
| host runs | sentry pre 23/0, post 21/0; validator pre 20/0, post 19/0 (PASS/FAIL) | l.364, l.567, l.792, l.915 |
| both nodes full for at least 1 hour, normal peers, 0 normal-operation denials | 13 polls 10:46:33Z-11:47:47Z, every poll full on both, peers 11-13, container PASS, denied=0 (enforced since 10:31Z sentry / 10:33Z validator) | l.927-942 |
| no alert left, baselines, fleet | pft_seccomp_findings 0 on both, no PFTSeccomp* alert, integrity accepted + PASS on both, fleet skew 0, rulecheck OK | l.959, l.963, l.1078-1091 |
| zero operator-topic messages | 2 operator topics, 0 messages each; the 9 throwaway-topic messages listed | l.1107-1119 |
| end state | notifier envs restored byte-identical, integrity PASS on both, both nodes full; `0 check(s) failed -> PASS` | l.1106, l.1121-1127 |

Aftercare after the run (not in the log): both nodes' `pft-keyescrow` textfiles still held `drift_items` 2 from
11:04Z, while the drill's redirected ntfy env files were in place (lesson from keyescrow: they fingerprint those files).
`pft-keyescrow.service` was re-run on both hosts at 11:53:56Z (validator) and 11:53:58Z (sentry), per their journals (drift 0, alert was only pending, `for: 2h`); the restore
step of `drill/live-run.sh` does not re-run it yet.

## Live run 11 (2026-11-05): stopped at the sentry canary

What happened, from [11](logs/11-live-run-stopped-at-canary.log):

| | log 11 |
|---|---|
| preflight clean, notifiers + bridge redirected to a throwaway topic, catch-all silence (watchdog and PFTSeccompDenied excluded) | l.12-61 |
| install on both hosts + the validator's pull, rules loaded (`PFTSeccompDrift ok`, `PFTSeccompDenied ok`), profile sha256 `8568e172…` equal on both hosts and in the repo | l.67-133 |
| sentry: injected gate failure → automatic rollback, previous state restored (Docker's default, file removed, full) | l.166-183 |
| sentry: real apply healthy (full, peers 11, confine signature unchanged), then the gate's denial check: `gate FAIL - 2 seccomp denial(s) since T0: clone3 (postfiatd) x1; clone3 (postfiatd: rpc) x1` → automatic rollback PASS | l.187-260 |
| canary rule: `sentry canary did not pass - validator NOT changed; stopping`; window ended, every notifier env restored byte-identical, bridge back on the operator env | l.267-280 |

**Finding 1, `clone3` is not a denial.** The profile keeps Docker's own `clone3 → ERRNO 38 (ENOSYS)` rule, so
glibc's `pthread_create` gets ENOSYS and falls back to `clone`. That is why the node stayed full. But with
`SECCOMP_FILTER_FLAG_LOG` the kernel audits *every* errno answer as `code=0x50000`, and the errno value is not in
the record, so the counter read the designed ENOSYS answers as EPERM denials. Fix (`pft-seccomp.sh`
`expected_errno`/`denials`): syscalls the applied profile answers with an unconditional, argument-free ERRNO rule
whose errno is not EPERM are counted apart as "expected errno answers by design" and shown next to the result,
never as denials. EPERM rules, argument-filtered rules and caps-conditional rules do not qualify. Without a
profile file (Docker's default), every record counts. Tests: 7 new checks in `tests/run-tests.sh` (audit WARN/PASS,
`--json`, ack-denials, the apply gate with a stub that writes the node's clone3 records on every `curl` exec, and
the three non-qualifying rule shapes). With the parent commit's script, 6 of them fail, including `gate clone3:
rc=1`, which is the live failure reproduced offline. Mutants M61-M67 cover each new guard.

**Finding 2, an exercise command no add-on runs.** `exercise_addons` ran `sha256sum` inside the container (l.195,
`sh: 1: sha256sum: Permission denied`). AppArmor's pft-postfiatd profile correctly denies it, and that left 2
DENIED records on the sentry. No installed tool runs that: pft-integrity hashes the config volume from the host
(`collect_cfgvol`). The line was removed. The 2 records were acknowledged with `pft-apparmor ack-denials` right
after the run, and the 3 clone3 records with `pft-seccomp ack-denials`
([12](logs/12-ack-after-11.log)).

**Finding 3, the stop path of `drill/live-run.sh`.** A run that stops after install but before both nodes are
enforced leaves the hourly audit grading Docker's default FAIL. PFTSeccompDrift would then have paged once the
catch-all silence went. In run 11 the alerts were still `pending` when a PFTSeccompDrift silence was posted by
hand. The install items were also left out of the integrity baseline, and the stop path skipped the operator-topic
read-back. Fixed: the stop path now holds a narrow PFTSeccompDrift silence (`DRIFT_HOLD`, 24 h) before the catch-all
expires, accepts the integrity baseline only when every changed item is pft-seccomp's own binary/units (tested on
the real verify lines of [13](logs/13-integrity-after-11.log)), and always reads back the operator topics. For run
11 these steps were done by hand: [12](logs/12-ack-after-11.log), [13](logs/13-integrity-after-11.log), and
[14](logs/14-operator-readback-after-11.log) (2 operator topics, 0 messages since the run start).

## Live run 16 (2026-11-05): stopped at the sentry canary (drill counter)

From [16](logs/16-live-run-stopped-at-canary-drill-counter.log):

| | log 16 |
|---|---|
| sentry: injected gate failure → automatic rollback PASS | l.177 |
| sentry: `0 denials during the drill` FAIL (1) | l.180 |
| sentry: real apply PASS with the da341ce gate (clone3 no longer fails it) | l.248 |
| positive controls 0 denials; negative controls symlinkat / linkat / inotify_init each EPERM + record | l.293, l.301, l.307, l.313 |
| `sentry host-run pre RESULT: PASS (22 PASS, 1 FAIL)` → canary stop, validator not changed | l.354-356 |
| every notifier env restored byte-identical, bridge back on the operator env | l.360-367 |
| stop path: PFTSeccompDrift held 24 h, PFTContainerRestarted 25 min, catch-all expired | l.368-370 |
| stop path: validator install items accepted; sentry NOT accepted (container changed) | l.372-373 |
| operator topics: 0 messages each | l.375-376 |

**Finding 4, the drill's own counter counted clone3.** `drill/host-run.sh` counts errno records with its own awk, so
that it stays independent of the tool it tests. The da341ce fix went into `pft-seccomp.sh` (audit, ack-denials,
gate) but not into this counter. The only record in the drill window was the clone3 → ENOSYS answer from the
injected apply's container start (`tests/fixtures/drill-audit-run16.txt` holds the 6 real records of the run).
Fix: the counter moved to `drill/denied-lib.sh` (`expected_list` + `count_records`). It skips the syscalls the
profile answers with an unconditional, argument-free, non-EPERM ERRNO rule. This is the same selection as
`expected_errno`, but implemented separately. A named syscall (the negative controls) is always counted. Each
`0 denials` check now shows the expected answers it left out.

**Finding 5, the stop path refused its own enforced container.** Run 16 stopped *after* a passed apply, so the
sentry stayed enforced (healthy, full, 11 peers). The stop path accepted only pft-seccomp's own files, so
`container:postfiatd-sentry changed security_opt` was left out of the baseline. The hourly verify would have
paged. Fix (`drill/stop-lib.sh` `install_only`): the node container is accepted too, but only when `security_opt`
is its only change and the host's audit grades it `[PASS] container` (under the installed profile). For run 16
the aftercare was done by hand ([17](logs/17-aftercare-after-16.log)): `ack-denials` for the 3 negative-control
records, audit PASS, then `pft-integrity accept` on the sentry, verify PASS.

Tests (`tests/run-tests.sh`, sections "drill counter" and "stop path"): the real run 16 records and verify lines
(plus log 13's), with the run 16 FAIL reproduced as a control. Mutants L01-L06 (denied-lib) and S01-S04
(stop-lib) are run on lib copies through `DRILL_LIB` / `STOP_LIB`.

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

**`apt-compat` (cron.daily) is not exercised, by decision:** the exercise loop skips it (`pft-seccomp.sh` exercise(), the `[ "${j##*/}" = apt-compat ] && continue` line) because it sleeps up to 30 min and calls apt. Since the apparmor/ cron.daily fix (c1af4e9) the container's AppArmor profile refuses its exec (quiet `deny x` on `/etc/cron.daily/apt-compat` and `apt.systemd.daily`), so under the full stack the job never runs and makes no syscalls; seccomp needs no rule for it. If AppArmor is not in use, `apt-compat` would need a learn of its own.

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
live exercise and requires 0 denials since T0. Any failure, failed step or SIGINT/SIGTERM rolls back automatically
(exit 1; exit 5 if that rollback itself fails).
Both nodes run with a raised CPU weight (`CpuShares` 8192) and `MemoryReservation` (memory.low), set live with
`docker update` after host load starved postfiatd; the compose files do not carry them. A re-create therefore keeps
them explicitly: docker run passes `--cpu-shares`/`--memory-reservation` from the old container, and after every
compose `up` (apply and rollback) `docker update` puts the pre-apply values back. Both values are part of the confine
signature, so a re-create that loses either one fails the gate and rolls back.
`rollback` restores the previous profile file first (a compose re-create reads it), then `.env` and any previous
override (or removes ours), or the kept container, and runs the same gate for the previous seccomp state (exit 5 if
that gate fails). pft-integrity's baseline is accepted only if every changed item is the container or its compose
files.

## Tests

`tests/run-tests.sh`: 147 offline checks against a fake host (`PFT_SC_ROOT`) and a stateful docker stub
(`tests/stub_docker.py`: `docker run` builds the container from its arguments; `seccomp=FILE` is stored as
`json.Compact`, as Docker does): every audit check in both directions, `--json`/`--textfile`/`validate`, `ack-denials`,
`pull`, apply/rollback for compose and docker run, every refusal (nothing changed), every automatic rollback trigger,
integrity acceptance, generate/diff over two learn dirs, and the helper's unit tests (`tests/test_pft_seccomp.py`, hand-computed fixtures).
`tests/mutate.py`: 60 mutants of the gates and rollback paths (CAUGHT only with a RESULT line and at least one FAIL line), each suite in its own process group, SIGKILLed on
timeout, with an orphan check at the end. Temp files go under `TEST_TMPDIR` (default `~/.cache`): `/tmp` is noexec on
the hardened hosts.
