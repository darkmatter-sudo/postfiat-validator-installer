# coredump — keep postfiatd memory (key material) out of core dumps

`pft-coredump.sh` answers one question for a Post Fiat validator (compose container `postfiatd`) or sentry
(`docker run` container `postfiatd-sentry`): **if postfiatd crashed now, or after the next reboot or container
re-create, could the kernel write its process memory to disk?** postfiatd holds the node key (and on a validator
the validator token) in memory, so a core file is a copy of those secrets in a file that backup, log-shipping or a
support upload can pick up.

Status: `audit`, `apply`, `rollback` with offline tests and a mutation harness; the throwaway-container crash drill
`drill/crash-drill.sh`. Two-host results are added under [Results](#results) when recorded.

Two independent layers stop a dump, and the tool sets both:

1. **host core handler** `kernel.core_pattern = |/bin/false`: the kernel pipes any dump to a program that reads
   nothing and exits, so no file is written for any process on the host. The stock Ubuntu value `core` (with apport
   disabled) writes a file named `core[.PID]` into the crashing process's working directory — for a container, inside
   its filesystem or a bind-mounted volume.
2. **process limit** `RLIMIT_CORE = 0:0` for every process of the node container: set live with `prlimit`
   (no restart) and persistently with a container ulimit (`core: 0`), so a file pattern restored by someone later
   still produces nothing for postfiatd. A pipe handler ignores RLIMIT_CORE (core(5)), which is why layer 1 must be a
   handler that stores nothing.

## audit (read-only)

```
sudo pft-coredump audit [--json]
```

One line per check, then `RESULT`. Core files are counted and sized only — never opened, names never printed.

| id | check | PASS | otherwise |
|----|-------|------|-----------|
| CD01 | live `kernel.core_pattern` | pipe to `/bin/false`/`/bin/true` (or systemd-coredump with CD05 PASS) | FAIL: file pattern, or a pipe to a handler that stores dumps (apport) |
| CD02 | value the next boot sets | last `kernel.core_pattern` over sysctl.d in systemd-sysctl order (`/etc` > `/run` > `/usr/local/lib` > `/usr/lib` > `/lib` per file name, names sorted) is non-writing, and apport is not enabled (its init script rewrites the pattern) | FAIL |
| CD03 | `fs.suid_dumpable` | 0 | WARN |
| CD04 | apport | not installed, or `enabled=0` | FAIL (default when the line is missing is enabled) |
| CD05 | systemd-coredump | not installed, or `Storage=none` and `ProcessSizeMax=0` (last drop-in wins) | FAIL |
| CD06 | live RLIMIT_CORE of every process in the container's cgroup | soft and hard 0 | WARN soft 0 / hard > 0 (can be raised); FAIL soft > 0 |
| CD07 | `coredump_filter` of PID 1 | INFO when CD06 passes | WARN when a dump is possible and anonymous memory (bits 0/1: heap) is included |
| CD08 | running container `HostConfig.Ulimits` core | `0:0` | WARN "pending re-create" when CD09 passes (overlay written, container not yet re-created); else FAIL |
| CD09 | what the next re-create gives | compose: `docker compose config` ulimits core 0/0; docker run: core 0:0 **and** every installed recreate tool copies `HostConfig.Ulimits` | FAIL (names the tool that would drop it) |
| CD10 | docker/containerd `LimitCORE`, daemon `default-ulimits` | INFO only (what a container without its own ulimit inherits) | — |
| CD11 | swap | none, or only dm-crypt | WARN plain swap |
| CD12 | hibernation | no swap, `/sys/power/disk` `[disabled]`, or `AllowHibernation=no` | WARN |
| CD13 | existing core/crash files (`core`, `core.N`, `*.core`, `*.crash`) in `/var/crash`, `/var/lib/systemd/coredump`, `/root`, `/tmp`, `/var/tmp`, `/opt/postfiatd` and the container's mount sources (depth `SCAN_DEPTH`=3) | 0 | FAIL with count and bytes |

Exit: 0 PASS (INFO allowed), 1 WARN, 2 FAIL, 3 error (container missing, `/proc` unreadable), 65 usage.
`--json` prints `{tool, time, container, exit, checks:[{status,id,check,detail}]}`.

## apply / rollback / re-apply

```
sudo pft-coredump apply --yes [--recreate]
sudo pft-coredump rollback --yes
```

`apply` refuses (exit 4, nothing changed) without `--yes`, without root, or while an earlier apply is not rolled back.
It first snapshots the exact current state to `/var/lib/pft-coredump/snap-<UTC>/` (mode 700): live core_pattern,
the drop-in files or their absence, the soft:hard RLIMIT_CORE of every container process, the container inspect,
and for compose the `.env` and overlay. Then:

1. writes `/etc/sysctl.d/60-pft-coredump.conf` (`kernel.core_pattern = |/bin/false`) and sets it live;
2. if systemd-coredump is installed, `/etc/systemd/coredump.conf.d/60-pft-coredump.conf` (`Storage=none`,
   `ProcessSizeMax=0`);
3. `prlimit --pid P --core=0:0` for every process of the container — live, no restart;
4. persistent core 0:0:
   - **compose (validator)**: writes `docker-compose.coredump.yml` (`ulimits: core: {soft: 0, hard: 0}`), appends it
     to `COMPOSE_FILE` in `.env` (mode kept), validates with `docker compose config` — and **never runs `up`**. The
     running container keeps working with the live limit from step 3; the ulimit takes effect at the next planned
     re-create. Until then CD08 reports WARN "pending re-create" and the audit exits 1.
   - **docker run (sentry)**, only with `--recreate` inside an active `pft-maint` window and with the node full: stops
     the container, keeps it as `NAME-precd-<id>-apply` (restart=no), `docker run` with the same arguments plus
     `--ulimit core=0:0`, then a gate: re-created, Ulimits exactly core 0:0, every other setting unchanged (image, cmd,
     env, user, stop timeout, restart, logging, network, ports, mounts, caps, read-only, tmpfs, limits, security_opt
     incl. the stored seccomp profile), `server_state` full within `RECOVER_TIMEOUT`. Gate failure → the previous
     container is put back under its name with its restart policy. On PASS it is removed (volumes kept).

Any failed step rolls everything back automatically (exit 1). `rollback` restores the last snapshot exactly: drop-ins
back byte-for-byte or removed, live core_pattern, each process's previous soft:hard limit (a process that no longer
exists is reported), compose files, and a re-created container is re-created with its previous Ulimits (same gate).
A second `apply` after a rollback is the re-apply: it takes a new snapshot.

The sentry's own recreate tools (`pft-seccomp`, `pft-apparmor`, `pft-shutdown`) now copy `HostConfig.Ulimits` in
their `docker run` arguments, so a later profile change keeps `core=0:0` (CD09 checks this by grep, the test suite by
running each tool's `run_args`).

Exit (apply/rollback): 0 PASS or nothing to do, 1 failed and rolled back, 4 refused, 5 rollback failed, 6 interrupted
(rolled back), 64 error.

## crash drill (throwaway containers only)

```
sudo coredump/drill/crash-drill.sh STAGE [EXPECT_A EXPECT_B]     # EXPECT = core | none
```

Never touches the node. Runs two `--rm --network none --memory 64m` containers of the node's **own image by ID** (no
pull) with the entrypoint replaced by `sh`; a child `sleep` gets SIGSEGV with its cwd on a scratch bind mount.
Probe A uses `--ulimit core=-1` (tests the host pattern alone), probe B `--ulimit core=0:0` (tests the container
layer). Files are counted, sized and deleted unread.

## tests

```
bash coredump/tests/run-tests.sh                 # fixture /proc + stub docker/prlimit/sysctl, no root
python3 -u coredump/tests/mutate.py --jobs 2     # every check CD01..CD13 and apply/rollback has mutants
shellcheck coredump/pft-coredump.sh coredump/drill/crash-drill.sh coredump/tests/run-tests.sh coredump/tests/stubs/*
```

Temp files go under `TEST_TMPDIR` (default `~/.cache`; `/tmp` is noexec on hardened hosts).

## Results

Recorded 2026-11-26 (UTC). Line numbers refer to the files in [`logs/`](logs/).

| What | Result | Log lines |
|---|---|---|
| offline tests | 103 passed, 0 failed | `05-tests-shellcheck.log:122` |
| shellcheck (tool, tests, drill, runner) | 0 findings | `05-tests-shellcheck.log:11` |
| mutants (CD01..CD13 + apply/rollback) | control PASS; 70 caught, 0 survived, 0 not applied | `06-mutants.log:4,76` |
| sentry found -> apply -> rollback -> re-apply | audit exit 2 -> 0 -> 2 -> 0; drill A/B core/none -> none/none -> core/none -> none/none | `04-live-run-two-host.log:92,190,228,238,275,285,327,337` |
| validator found -> apply -> rollback -> re-apply | audit exit 2 -> 1 -> 2 -> 1 (CD08 WARN pending re-create, below); drill core/none -> none/none -> core/none -> none/none | `04-live-run-two-host.log:357,455,490,500,533,543,582,592` |
| second apply refused while applied | exit 4 on both hosts | `04-live-run-two-host.log:309,564` |
| both nodes `full` after every step; validator postfiatd not restarted | StartedAt unchanged, uptime grew | `04-live-run-two-host.log:208,210,255,257,303,305,470,472,513,515,558,560,654,656` |
| pft-integrity | intended changes accepted, PASS 299 / 174 unchanged | `04-live-run-two-host.log:620,624,626,627,629` |
| silent run | silence expired after a clean drain; operator topics 0 messages | `04-live-run-two-host.log:662,670` |

Validator deviation (by design, operator rule until after 2026-12-01): its postfiatd container was not re-created, so
the persistent container ulimit (`docker-compose.coredump.yml`, CD08) only takes effect at the next planned re-create.
Until then the running processes are held at `RLIMIT_CORE 0` live by `prlimit` (CD06 PASS) and the host handler no
longer writes cores (CD01/CD02 PASS); the validator crash drill shows no core for either probe after apply.

Before run 04, two unpublished dry runs found one runner/tool bug: the sentry re-create gate reported "configuration
changed" on an identical re-create and rolled back automatically; fixed in a2bfafd05b5de340f913cf6f2fbddb151b442eaf.
