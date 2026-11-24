# shutdown — graceful-stop budget audit and crash-recovery tooling for postfiatd in Docker

`pft-shutdown.sh` answers one question for a Post Fiat validator (compose container `postfiatd`) or sentry
(`docker run` container `postfiatd-sentry`): **does every stop path give postfiatd enough time to shut down
cleanly before Docker or systemd sends SIGKILL?** postfiatd is PID 1 in the official image (the entrypoint
`exec`s it), so the container's stop signal reaches the daemon directly.

Status: `audit`, `measure` and `kill-drill` with their offline tests are in place. `apply`/`rollback` and the
recorded two-host runs are added in follow-up commits of this folder.

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
