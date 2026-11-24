# shutdown — graceful-stop budget audit and crash-recovery tooling for postfiatd in Docker

`pft-shutdown.sh` answers one question for a Post Fiat validator (compose container `postfiatd`) or sentry
(`docker run` container `postfiatd-sentry`): **does every stop path give postfiatd enough time to shut down
cleanly before Docker or systemd sends SIGKILL?** postfiatd is PID 1 in the official image (the entrypoint
`exec`s it), so the container's stop signal reaches the daemon directly.

Status: `audit`, `measure`, `kill-drill`, `apply` and `rollback` with their offline tests, and the recorded two-host
runs (see [Results](#results-two-hosts-2026-11-24)). Both hosts now run with the measured stop budget applied.

## audit (read-only)

```
pft-shutdown audit [--json] [--required SEC]
```

One line per finding, then `RESULT`. The required budget is `max(MIN_TIMEOUT, ceil(p100 x SAFETY_FACTOR))`,
where p100 is the slowest **clean** stop recorded by `measure` (`/var/lib/pft-shutdown/measure-<container>.json`);
without measurements it is `MIN_TIMEOUT` (30 s) and the basis line says so.

| id | exit bit | checks | why |
|----|----------|--------|-----|
| F1 | 1  | effective stop signal (container, else image, else SIGTERM) is SIGTERM/SIGINT | anything else is not a clean shutdown request |
| F2 | 2  | running container `StopTimeout` (unset = Docker's 10 s) >= required | budget of `docker stop`, `docker restart`, `docker compose stop/up/down` without `-t` |
| F3 | 4  | what the next re-creation gives: compose `stop_grace_period` (unset = 10 s); for a `docker run` container a recreate tool that carries `--stop-timeout` | a fix that lives only in the running container is lost on the next recreate |
| F4 | 8  | dockerd `shutdown-timeout` (default 15 s) >= required when live-restore is off | with live-restore off, stopping dockerd stops every container within this limit |
| F5 | 16 | `docker.service` `TimeoutStopUSec` >= required (`infinity` passes) | systemd's limit on dockerd's own stop |
| F6 | 32 | reboot budget: with live-restore on, systemd stops the container's `docker-<id>.scope` itself (KillSignal, SIGKILL after its `TimeoutStopUSec`); with live-restore off, `min(StopTimeout, shutdown-timeout, docker.service)` | host shutdown is a stop path too |

Exit code: 0 PASS, otherwise the OR of the failed findings' bits (1..63); 64 error; 65 usage.
`--json` prints `{container, required_s, required_basis, result, exit, checks:[{id,status,message}]}`.

## measure and kill-drill (one guarded stop of the live node)

```
sudo pft-shutdown measure --yes [--timeout SEC] [--json]     # docker stop -t SEC (default 120)
sudo pft-shutdown kill-drill --yes [--json]                 # docker kill -s KILL (crash recovery)
```

Both stop the local postfiatd container **once**, so they refuse (exit 4, nothing touched) unless `--yes` is given,
a `pft-maint` window is active (the caller has silenced alerting and pointed notifiers at a throwaway topic), the
container is running and `server_state` is `full`/`proposing`. One cycle:

1. `server_info` before (complete_ledgers, validated seq) and the byte offset of the host-side `debug.log`.
2. `docker stop -t SEC` (or `docker kill -s KILL`), wall time, container `ExitCode` / `OOMKilled` / `FinishedAt`.
3. Shutdown markers postfiatd wrote to `debug.log` after the offset: `Received signal`, `Server stopping`,
   `Application stopping` (strings of the 1.0.9 binary). Read before the restart because the image entrypoint
   rotates `debug.log` at every start.
4. `docker start`, poll `server_info` every `POLL_SEC` until full/proposing (`RECOVER_TIMEOUT`, 900 s), wait
   `SETTLE_SEC` (60 s), then the holes of `complete_ledgers` at/above the first ledger held before the stop, and
   database error lines (FTL, corrupt, NodeStore/SQLite errors, malformed) in the startup log.

A stop is **clean** when `docker stop` returned 0, exit code 0, not OOM-killed, it finished before the timeout and
`Received signal` was logged. Every run is appended to `/var/lib/pft-shutdown/measure-<container>.json`; `audit`
derives the required budget from the slowest clean `measure` run only (`kill-drill` runs are mode `sigkill`, never
clean). Exit: 0 PASS; 1 stop not clean (measure) or database errors after restart (both); 2 not back to full in time
(the container is started either way); 4 refused; 64 error.

## apply and rollback (one re-create of the live node)

```
sudo pft-shutdown apply --yes [--required SEC]   # StopTimeout := required budget (measured p100 x SAFETY_FACTOR)
sudo pft-shutdown rollback --yes                 # the previous StopTimeout back
```

Refused (exit 4, nothing touched) without `--yes`, root, an active `pft-maint` window, a running `full` node, at
least `MIN_RUNS` (3) clean measured stops (or `--required`), when the image tag no longer names the running image (a
re-create would be an upgrade), or while an earlier apply with another value is still in place. **Idempotent**: when
`StopTimeout` already equals the required budget it prints `nothing to do` and exits 0.

- **compose container** (validator): `.env` (and an existing overlay) are backed up to
  `/var/lib/pft-shutdown/backup/`; `docker-compose.shutdown.yml` (`stop_grace_period: <required>s`) is written and
  appended to `COMPOSE_FILE` (every other overlay kept, `.env` mode kept); `docker compose config` must report that
  value, else the files are restored without touching the container. Then one `docker compose up -d --timeout <budget>`;
  CPU weight / memory.low set live with `docker update` (not in the compose files) are put back.
- **`docker run` container** (sentry): stop with the measured budget, rename to `<name>-preshutdown-<id>-apply`
  (restart=no), `docker run` with the same configuration plus `--stop-timeout`. Docker keeps a seccomp profile inline,
  so it is passed again as `seccomp=SECCOMP_FILE` and the gate proves the stored bytes did not change.
- **Gate** after the re-create: new container (StartedAt changed), `StopTimeout` = wanted, a signature of every other
  setting unchanged (image + image id, cmd, entrypoint, user, env, stop signal, caps, read-only, tmpfs, pids/memory/
  CPU limits, AppArmor label, security_opt incl. the stored seccomp profile, mounts, ports, network, log, restart), and
  `server_state` full within `RECOVER_TIMEOUT`. A configuration difference fails at once; only "not full yet" is waited
  for. Gate failure, an error or INT/TERM roll back automatically (`docker run`: the stopped previous container is
  renamed back and started). On PASS the previous container is removed (`docker rm`, named volumes kept).
- **rollback**: compose restores `.env` + overlay from the backups and runs `compose up`; `docker run` re-creates with
  the previous value (unset: no `--stop-timeout`). Same gate. A second rollback is a no-op.

Exit (apply/rollback): 0 PASS or nothing to do; 1 failed and rolled back; 4 refused; 5 rollback failed; 6
interrupted (rolled back). State: `/var/lib/pft-shutdown/apply-<container>.json`. `PFT_SHUTDOWN_INJECT=gate` makes
apply's gate fail (automatic-rollback drill). The caller accepts the intended changes into `pft-integrity`
(container, `.env`, `docker-compose.shutdown.yml`) after the run.

The other tools that re-create the sentry (`pft-seccomp`, `pft-apparmor`, `pft-confine`, `cluster/drill/recreate.sh`)
carry the container's `StopTimeout` over with `--stop-timeout` and include it in their own gate signature, so a later
re-create by any of them keeps the applied budget. F3 for a `docker run` container passes only when **every**
installed recreate tool does so.

## Tests

```
bash shutdown/tests/run-tests.sh
```

Offline, no root, no Docker: stub `docker` (inspect, image inspect, compose config) and `systemctl show`. A good
compose host and a good `docker run` host pass with no FAIL line; each finding fails on its own fixture with its named
reason and exactly the expected exit bits; controls cover combined findings (bits OR), the live-restore-off reboot
chain, a missing container (64), invalid daemon.json (64), bad usage (65), the required budget from measurement
state (p100 x factor, unclean runs ignored, floor, `--required`), `--json`, and the systemd/compose duration parsers.
`measure`/`kill-drill` run against a stub `docker stop/kill/start/inspect`, a scripted `server_info` sequence and a
stub `pft-maint active`: a clean stop with all markers passes and is recorded; SIGKILL after the timeout (137), exit 0
without a marker, OOM-kill, a database error in the startup log and a node that never returns to full each fail with
their named reason; every guard (no `--yes`, no window, not full, RPC unreachable, not running) refuses with nothing
stopped; unclean and sigkill runs never enter the required budget; `holes()` on gaps, clipping and `empty`.
`apply`/`rollback` (`tests/apply-tests.inc.sh`) run against a stateful stub (`tests/stub_docker.py`: containers,
rename/update/rm/run, `compose config/up` reading `COMPOSE_FILE`) for a compose validator and a `docker run` sentry:
apply sets StopTimeout 31 (p100 10.1 s x 3) with one re-create and every other setting unchanged, a second apply is a
no-op, audit F2/F3 pass afterwards, rollback restores the exact previous container and `.env`, re-apply passes; a
failing `compose up`, an injected gate failure, a `docker run` that loses a setting (tmpfs) or the stop timeout, and a
failing `docker run` each roll back to the previous container; a compose config that does not report the value
restores the files with nothing re-created; every refusal (no `--yes`, no window, no/too few measurements, tag moved,
not full, seccomp file missing, another value applied) leaves container, `.env` and overlay untouched.


## Results (two hosts, 2026-11-24)

Recorded with `drill/live-run.sh` (one Alertmanager silence of everything but the watchdog and digest-only alerts,
a `pft-maint` window on both hosts, `[MAINT]` notices to a throwaway topic only, sentry first, then drain and read
back). Raw runner output; only the sentry's `--publish` address is redacted.

| log | what | result |
|-----|------|--------|
| [`logs/04-measure-n3.log`](logs/04-measure-n3.log) | 3 clean `measure` stops per host | PASS, 0 checks failed |
| [`logs/06-apply-cycle.log`](logs/06-apply-cycle.log) | per host: audit, apply, audit, rollback, audit, re-apply, no-op apply, audit | PASS, 0 checks failed |
| [`logs/07-kill-drill.log`](logs/07-kill-drill.log) | 1 SIGKILL `kill-drill` per host | every drill check PASS; 1 FAIL: drain (outside alert, below) |
| [`logs/07b-post-run07-cleanup.log`](logs/07b-post-run07-cleanup.log) | run 07 silence expired by hand, final state | both full, integrity PASS |

Clean stops (`docker stop -t 120`, all with `Received signal 15` + `Server stopping`, exit code 0, holes 0, database
error lines 0):

| host | stop wall time (s) | back to full (s) | p100 | required = max(30, ceil(p100 x 3)) |
|------|--------------------|------------------|------|-------------------------------------|
| sentry (`docker run`) | 5.0, 7.1, 19.7 | 53.5, 51.5, 44.3 | 19.7 | 60 s |
| validator (compose) | 3.2, 3.8, 10.1 | 48.5, 49.1, 40.6 | 10.1 | 31 s |

The sentry's slowest clean stop (19.7 s) is about twice Docker's default 10 s, so an unconfigured `docker stop`
can SIGKILL it mid-shutdown.

Audit before / after (`logs/06`): validator exit 6 (F2 StopTimeout unset, F3 compose `stop_grace_period` unset) -> 0
after apply -> 6 after rollback -> 0 after re-apply; sentry exit 2 (F2) -> 0 -> 2 -> 0. A second apply on each host
printed `nothing to do`. Every apply/rollback gate: re-created, configuration signature unchanged, `full` in 43-52 s.
The sentry's F3 failed in the first dev audit too (its installed `pft-seccomp` / `pft-apparmor` recreate paths dropped
`--stop-timeout`); fixed in those tools and deployed before run 06, so run 06 starts at exit 2.

Crash vs clean (`logs/07` vs `logs/04`):

| host | SIGKILL: exit code, wall | back to full | holes | db error lines | clean stops: back to full |
|------|--------------------------|--------------|-------|----------------|---------------------------|
| sentry | 137, 6.1 s | 54.7 s | 0 | 0 | 44.3-53.5 s |
| validator | 137, 1.4 s | 49.1 s | 0 | 0 | 40.6-49.1 s |

No shutdown markers after SIGKILL (as expected). On 1.0.9 recovery after a crash was as fast as after a clean stop,
with no database errors and no `complete_ledgers` holes on either host. The validator's local history archive
recorded the ledgers it missed while down (8331327-8331340) as a gap, and `pft-histarchive fill-gap` filled it from
public RPC (verify rc 0).

Run 07's one FAIL: at 16:30Z, during the drain, `PFTBudgetCapReached` for `pft-budget-collect.service` (pft-budget's
own 30-day memory projection, cap 128 MiB, peak about 37 MiB) went pending on both hosts. The drill did not cause it:
it started when the unit's history first spanned `PROJ_MIN_SPAN_DAYS` (3 d after its 2026-11-21 reset). It kept the
drain from finishing within 4500 s, so the runner left its silence in place. The silence was then expired by hand
once that alert, the only one remaining, was covered by its own narrow silence (`logs/07b`). The operator topics got
no message during the run.

Integrity: each run accepted its own re-creates into `pft-integrity`; at the end both hosts PASS, AppArmor and
seccomp audits PASS, both nodes `full`. File hashes: [`SHA256SUMS`](SHA256SUMS) (`sha256sum -c SHA256SUMS` from this
folder).
